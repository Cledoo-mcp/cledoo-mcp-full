# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Native MCP endpoint. Speaks MCP JSON-RPC 2.0 over HTTP.

Gated by the `cledoo_mcp_full.enabled` system parameter (Settings toggle,
404 when off). Auth is a native Odoo API key or an OAuth access token
(see lib/auth.py resolve_bearer). Tool dispatch goes through the
`mcp.gateway` AbstractModel seam (models/gateway.py) so MCP Pro can
`_inherit` it and layer governance without touching this controller.
"""
import json
import logging
import uuid

from psycopg2 import OperationalError
from urllib.parse import urlsplit

from odoo import http
from odoo.http import request

from odoo.addons.cledoo_mcp_full.lib.jsonrpc import make_error, make_result, parse_request

_logger = logging.getLogger(__name__)
PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-11-25")
# tools/call responses beyond this many serialized chars get their record
# list truncated: LLM context is the scarce resource this endpoint burns,
# and claude.ai additionally times out on multi-MB tool results.
MAX_RESULT_CHARS = 100_000
RATE_LIMIT_DEFAULT = 120  # requests/min per principal; 0 disables


def _load_module_version():
    """Read the installed version from __manifest__.py at import time.

    Avoids a per-`initialize`-request DB hit (searching ir.module.module)
    for a value that's fixed for the lifetime of the process. Falls back
    to the older `load_manifest` name for Odoo versions that don't expose
    `get_manifest` (verified present on 18/19)."""
    try:
        from odoo.modules.module import get_manifest
        manifest = get_manifest("cledoo_mcp_full")
    except ImportError:
        from odoo.modules.module import load_manifest
        manifest = load_manifest("cledoo_mcp_full")
    return manifest.get("version", "1.0.0")


_MODULE_VERSION = _load_module_version()


def _content_blocks(data, serialize):
    """tools/call content blocks. Tools that build their own MCP blocks
    (read_resource: image/audio/resource) return them under the
    `__mcp_content__` sentinel and bypass JSON text serialization."""
    if isinstance(data, dict) and "__mcp_content__" in data:
        return data["__mcp_content__"]
    return [{"type": "text", "text": serialize(data)}]


def _tool_error_result(req_id, exc):
    """MCP tool-execution error: an isError result the LLM can read and
    self-correct from (2025-06-18 tool errors; SEP-1303 extends this to
    input-validation errors). Protocol errors (unknown method/tool,
    malformed JSON-RPC) do NOT go through here."""
    payload = {
        "content": [{"type": "text", "text": json.dumps(
            {"error": exc.message, "code": exc.code})}],
        "isError": True,
    }
    # Optional MCP Apps hint (e.g. Pro's policy-denial explainer card):
    # only set on the free wire when a caller explicitly attaches one, so
    # a plain ToolError still produces the exact byte-for-byte result it
    # always has.
    if getattr(exc, "meta", None):
        payload["_meta"] = exc.meta
    return make_result(req_id, payload)


class McpController(http.Controller):
    # readonly=False: tools include create/update/delete; on a read-only
    # cursor (the 18/19 default for http routes) every write tool would
    # die with ReadOnlySqlTransaction inside our catch-all, which hides
    # the error from Odoo's own rw-retry machinery.
    @http.route("/mcp", type="http", auth="none", methods=["POST"], csrf=False,
                save_session=False, readonly=False)
    def mcp(self, **kw):
        from odoo.addons.cledoo_mcp_full.lib.params import is_enabled
        if not is_enabled(request.env):
            return request.not_found()

        if not self._origin_ok():
            return request.make_response("Invalid Origin", status=403)

        from odoo.addons.cledoo_mcp_full.lib.auth import resolve_bearer_details
        from odoo.addons.cledoo_mcp_full.lib.params import get_int_param
        from odoo.addons.cledoo_mcp_full.lib.ratelimit import check as rl_check

        auth = request.httprequest.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else None
        details = resolve_bearer_details(request.env, token)
        if details is None:
            self._notify("auth_failure", None, None, "unauthorized")
            return self._unauth()
        uid = details["uid"]
        # Bucket per credential, not per user: an admin's runaway agent
        # must not lock out their other (well-behaved) connections.
        principal = self._principal(details)
        limit = get_int_param(
            request.env, "cledoo_mcp_full.rate_limit", RATE_LIMIT_DEFAULT)
        allowed, retry_after = rl_check(principal, limit)
        if not allowed:
            self._notify("rate_limited", uid, None, "throttled")
            return request.make_response(
                json.dumps(make_error(None, -32000, "Rate limit exceeded")),
                headers=[("Content-Type", "application/json"),
                         ("Retry-After", str(int(retry_after) + 1))],
                status=429)
        # A9 sessions: after auth AND after the (cheap, in-memory) rate
        # limiter, so a revoked runaway client is throttled before it can
        # hammer the per-request mcp.session lookup. A revoked session
        # answers 404 so the client re-initializes (MCP spec); an unknown
        # session id is ignored (old clients / restarts keep working).
        gate = self._session_gate(details, principal)
        if gate is not None:
            return gate

        try:
            payload = json.loads(request.httprequest.get_data() or b"{}")
        except ValueError:
            return self._json(make_error(None, -32700, "Parse error"))
        if not isinstance(payload, dict):
            # JSON-RPC batch arrays (and bare scalars) are not supported.
            return self._json(make_error(None, -32600, "Invalid request"))
        req = parse_request(payload)
        if not isinstance(req.params, dict):
            # A non-object `params` (e.g. a JSON array) would blow up
            # req.params.get(...) with an opaque -32603; report it as the
            # invalid request it is.
            return self._json(make_error(
                req.id, -32602, "params must be an object"))
        hdr = request.httprequest.headers.get("MCP-Protocol-Version")
        if hdr and hdr not in SUPPORTED_PROTOCOL_VERSIONS:
            return request.make_response(
                json.dumps(make_error(
                    req.id, -32600,
                    "Unsupported MCP-Protocol-Version: %s" % hdr)),
                headers=[("Content-Type", "application/json")], status=400)
        try:
            result = self._dispatch(req, details)
        except OperationalError:
            # Concurrency/serialization errors belong to Odoo's retrying
            # machinery (service_model.retrying); swallowing them here
            # would turn a transparent retry into a client-facing error.
            raise
        except Exception:  # never leak internals to the LLM
            _logger.exception("mcp internal error")
            # A tool may have flushed writes before failing; without this
            # rollback Odoo would still COMMIT them at end of request.
            request.env.cr.rollback()
            self._notify("internal_error", uid, req.method, "error")
            self._track(details, principal, error=True)
            return self._json(make_error(req.id, -32603, "Internal error"))
        is_error = isinstance(result, dict) and (
            "error" in result
            or (isinstance(result.get("result"), dict)
                and bool(result["result"].get("isError"))))
        self._track(details, principal, error=is_error)
        if result is None:  # notification
            return request.make_response("", status=202)
        return self._json(result)

    @http.route("/mcp", type="http", auth="none", methods=["GET", "DELETE"],
                csrf=False, save_session=False, readonly=True)
    def mcp_method_not_allowed(self, **kw):
        """No SSE stream (GET) and no client-side session termination
        (DELETE) — deliberate: plain JSON-RPC POST, aligned with the
        stateless direction of the 2026-07-28 spec. Explicit 405 + Allow
        per the Streamable HTTP transport spec."""
        from odoo.addons.cledoo_mcp_full.lib.params import is_enabled
        if not is_enabled(request.env):
            return request.not_found()
        return request.make_response("", status=405, headers=[("Allow", "POST")])

    @staticmethod
    def _principal(details):
        return ("token:%d" % details["token_id"]
                if details["kind"] == "oauth"
                else "apikey:%d" % details["uid"])

    def _origin_ok(self):
        """MCP Streamable-HTTP MUST-validate-Origin (DNS-rebinding guard;
        2025-11-25 requires 403). Non-browser MCP clients send no Origin
        header — absence is allowed."""
        origin = request.httprequest.headers.get("Origin")
        if not origin or origin == "null":
            return not origin  # explicit "null" origin is rejected
        parts = urlsplit(origin)
        if parts.hostname in ("localhost", "127.0.0.1"):
            return True
        # host_url is only right behind a proxy when proxy_mode=True; web.base.url below covers the common misconfig.
        allowed = {request.httprequest.host_url.rstrip("/")}
        base = (request.env["ir.config_parameter"].sudo()
                .get_param("web.base.url") or "").rstrip("/")
        if base:
            allowed.add(base)
        return origin.rstrip("/") in allowed

    def _session_gate(self, details, principal):
        """A9 session gate + touch for requests carrying an Mcp-Session-Id
        header. Returns a 404 response for a revoked session, None
        otherwise. Session bookkeeping must never break transport: own
        savepoint + catch-all, same contract as _track()."""
        sid = request.httprequest.headers.get("Mcp-Session-Id")
        if not sid:
            return None
        try:
            with request.env.cr.savepoint():
                Session = request.env["mcp.session"].sudo()
                rec = Session.search([("name", "=", sid)], limit=1)
                if rec and rec.revoked:
                    return request.make_response(
                        json.dumps(
                            make_error(None, -32001, "Session terminated")),
                        headers=[("Content-Type", "application/json")],
                        status=404)
                if rec:
                    Session._touch(sid, details["uid"], principal,
                                   request.httprequest.remote_addr)
        except Exception:
            _logger.exception("mcp session gate failed")
        return None

    def _session_create(self, sid, details):
        """Record the session minted on `initialize`; never break
        transport (mirrors _track())."""
        try:
            with request.env.cr.savepoint():
                request.env["mcp.session"].sudo()._touch(
                    sid, details["uid"], self._principal(details),
                    request.httprequest.remote_addr)
        except Exception:
            _logger.exception("mcp session creation failed")

    def _track(self, details, principal, error=False):
        """Bump the per-principal usage counters; never break transport.
        Own savepoint: a failed counter write must not roll back (or be
        rolled back with) the tool's own writes."""
        try:
            with request.env.cr.savepoint():
                request.env["mcp.endpoint.activity"].sudo()._bump(
                    principal, details["kind"], details["token_id"],
                    details["uid"], error=error)
        except Exception:
            _logger.exception("mcp activity tracking failed")

    def _notify(self, event, uid, method, outcome):
        """Feed seam-bypassing events (401s, unknown methods, internal
        errors) to the mcp.gateway observation hook so a governance module
        can audit every request; an observer must never break transport."""
        try:
            request.env["mcp.gateway"]._on_request(event, uid, method, outcome)
        except Exception:
            _logger.exception("mcp.gateway._on_request observer failed")

    def _request_context(self, req, details):
        return {
            "session_id": request.httprequest.headers.get("Mcp-Session-Id"),
            "remote_addr": request.httprequest.remote_addr,
            "request_id": req.id,
            # Additive seam field (see SPEC-licensing-and-pro.md Phase 3):
            # lets governance overrides bind audit/quota/consent decisions
            # to the actual credential, and lite stamp chatter messages.
            "principal": {"kind": details["kind"], "uid": details["uid"],
                          "token_id": details["token_id"],
                          "apikey_id": details.get("apikey_id")},
        }

    def _dispatch(self, req, details):
        uid = details["uid"]
        from odoo.addons.cledoo_mcp_full.lib.tools import ToolError, normalize_tool_args
        from odoo.addons.cledoo_mcp_full.models.gateway import UnknownToolError

        if req.method == "initialize":
            sid = uuid.uuid4().hex
            self._session_create(sid, details)
            requested = req.params.get("protocolVersion")
            version = (requested if requested in SUPPORTED_PROTOCOL_VERSIONS
                       else PROTOCOL_VERSION)
            resp = make_result(req.id, {
                "protocolVersion": version,
                "capabilities": request.env["mcp.gateway"]._capabilities(),
                "serverInfo": {"name": "cledoo-mcp", "version": _MODULE_VERSION},
            })
            resp["_session"] = sid
            return resp
        if req.method == "notifications/initialized":
            return None
        if req.method == "ping":
            return make_result(req.id, {})
        if req.method == "tools/list":
            return make_result(req.id, {"tools": request.env["mcp.gateway"]._list_tools(uid)})
        if req.method == "resources/list":
            return make_result(req.id, {
                "resources": request.env["mcp.gateway"]._list_resources(uid)})
        if req.method == "resources/read":
            uri = req.params.get("uri")
            doc = request.env["mcp.gateway"]._read_resource(uid, uri)
            if doc is None:
                return make_error(req.id, -32602,
                                  "Unknown resource: %s" % uri)
            return make_result(req.id, {"contents": [doc]})
        if req.method == "tools/call":
            name = req.params.get("name")
            args = req.params.get("arguments") or {}
            try:
                # Ingress-side hygiene: rehydrate array/object params that
                # LLM clients serialized as JSON strings, BEFORE governance
                # overrides (MCP Pro policy/masking) inspect the args.
                args = normalize_tool_args(name, args)
                # No savepoint here (Odoo commits the request cursor on
                # any non-error HTTP response, JSON-RPC error responses
                # included): `mcp.gateway._execute_tool` protects the
                # tool's own write with its own tightly-scoped savepoint
                # (models/gateway.py), so a failed tool's half-applied
                # writes are still discarded, but bookkeeping an override
                # layers around that call (MCP Pro's audit rows, quota
                # counters) lives outside that savepoint and is not
                # wiped out by it — a savepoint wrapped around this
                # whole call would discard that bookkeeping too on every
                # denial/error, which is exactly what used to happen.
                data = request.env["mcp.gateway"]._execute_tool(
                    uid, name, args,
                    context=self._request_context(req, details))
            except UnknownToolError:
                return make_error(req.id, -32602, "Unknown tool: %s" % name)
            except ToolError as exc:
                # ToolInvalidParamsError included: SEP-1303 wants input
                # validation surfaced as a tool result, not a protocol error.
                self._notify("tool_error", uid, req.method, exc.code)
                return _tool_error_result(req.id, exc)
            meta = data.pop("__mcp_meta__", None) if isinstance(data, dict) else None
            payload = {"content": _content_blocks(data, self._serialize_result)}
            if meta:
                payload["_meta"] = meta
            return make_result(req.id, payload)
        if req.id is None:
            # A notification (id-less request): JSON-RPC forbids answering,
            # even for methods we don't know (notifications/cancelled,
            # notifications/progress, ...). Observed, then dropped.
            self._notify("unknown_notification", uid, req.method, "ignored")
            return None
        self._notify("unknown_method", uid, req.method, "not_found")
        return make_error(req.id, -32601, "Method not found: %s" % req.method)

    def _serialize_result(self, data):
        """JSON-encode a tool result, halving the record list of oversized
        payloads until it fits MAX_RESULT_CHARS (the truncated/hint keys
        tell the LLM to narrow fields or paginate instead of retrying the
        same call). Non-record payloads are only logged: chopping an
        arbitrary JSON document would corrupt it."""
        text = json.dumps(data, default=str)
        if len(text) <= MAX_RESULT_CHARS:
            return text
        if isinstance(data, dict) and isinstance(data.get("records"), list) \
                and data["records"]:
            while data["records"] and len(text) > MAX_RESULT_CHARS:
                data["records"] = data["records"][:len(data["records"]) // 2]
                text = json.dumps(data, default=str)
            data["truncated"] = True
            data["hint"] = ("Result exceeded %dkB and was truncated. Request"
                            " fewer fields with fields=[...], or paginate"
                            " with a smaller limit."
                            % (MAX_RESULT_CHARS // 1000))
            return json.dumps(data, default=str)
        _logger.warning("mcp: oversized non-record tool result (%d chars)",
                        len(text))
        return text

    def _json(self, body):
        headers = [("Content-Type", "application/json")]
        # _session is a controller-internal reserved key (popped into the Mcp-Session-Id header),
        # not tool-namespace-safe.
        sid = body.pop("_session", None) if isinstance(body, dict) else None
        if sid:
            headers.append(("Mcp-Session-Id", sid))
        return request.make_response(json.dumps(body, default=str), headers=headers)

    def _unauth(self):
        host = request.httprequest.host_url.rstrip("/")
        headers = [
            ("Content-Type", "application/json"),
            ("WWW-Authenticate",
             'Bearer resource_metadata="%s/.well-known/oauth-protected-resource"' % host),
        ]
        return request.make_response(
            json.dumps(make_error(None, -32001, "Authentication required")),
            headers=headers, status=401)

    # Hints keyed by check name; only sent to authenticated callers.
    _HEALTH_HINTS = {
        "enabled": "Turn on the MCP Server toggle in Settings > General"
                   " Settings > MCP Server (and restart Odoo if freshly"
                   " installed).",
        "https": "web.base.url is not https:// — OAuth clients (claude.ai)"
                 " refuse plain http. Behind a reverse proxy, set"
                 " proxy_mode = True in odoo.conf.",
        "host_match": "web.base.url does not match the host you reached"
                      " this server on — OAuth discovery will publish URLs"
                      " pointing elsewhere.",
        "base_url_frozen": "Set the web.base.url.freeze system parameter to"
                           " True so admin logins cannot rewrite the public"
                           " URL.",
        "proxy_mode": "proxy_mode is off in odoo.conf; required behind any"
                      " reverse proxy so Odoo sees the public scheme/host.",
        "single_db": "This server exposes several databases; set dbfilter"
                     " (or db_name) so the unauthenticated MCP/OAuth routes"
                     " resolve to exactly one.",
    }

    @http.route("/mcp/health", type="http", auth="none", methods=["GET"],
                csrf=False, save_session=False, readonly=True)
    def mcp_health(self, **kw):
        """Self-diagnosis endpoint for the six known deployment failures.

        Deliberately answers even when the module toggle is off — a 404
        here IS one of the failure modes we are diagnosing. Anonymous
        callers get booleans only; a valid Bearer adds actionable hints
        and instance details."""
        from odoo.addons.cledoo_mcp_full.lib.auth import resolve_bearer_details
        from odoo.addons.cledoo_mcp_full.lib.params import get_int_param, is_enabled
        from odoo.tools import config

        icp = request.env["ir.config_parameter"].sudo()
        base = (icp.get_param("web.base.url") or "").rstrip("/")
        from urllib.parse import urlsplit
        enabled = is_enabled(request.env)
        checks = {
            "enabled": enabled,
            "https": base.startswith("https://"),
            "host_match": urlsplit(base).netloc == request.httprequest.host,
            "base_url_frozen":
                icp.get_param("web.base.url.freeze") == "True",
            "proxy_mode": bool(config.get("proxy_mode")),
        }
        try:
            from odoo.service.db import list_dbs
            checks["single_db"] = len(list_dbs(force=False)) == 1
        except Exception:
            # DB listing disabled (list_db=False) — can't tell, and a
            # hardened server most likely has dbfilter sorted anyway.
            checks["single_db"] = None
        status = ("disabled" if not enabled else
                  "ok" if all(v in (True, None) for v in checks.values())
                  else "warning")
        # Anonymous callers get the overall status only. The per-check
        # booleans reveal deployment posture (proxy_mode, multi-db,
        # base_url freeze...) — recon we don't hand out unauthenticated on
        # a security product. The operator adds a Bearer to see the
        # breakdown, actionable hints and instance details.
        body = {"status": status}

        auth = request.httprequest.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else None
        details = resolve_bearer_details(request.env, token) if token else None
        if details:
            user = request.env["res.users"].sudo().browse(details["uid"])
            body.update({
                "checks": checks,
                "version": _MODULE_VERSION,
                "protocol_version": PROTOCOL_VERSION,
                "auth": details["kind"],
                "user": user.login,
                "companies": user.company_ids.mapped("name"),
                "rate_limit_per_minute": get_int_param(
                    request.env, "cledoo_mcp_full.rate_limit",
                    RATE_LIMIT_DEFAULT),
                "hints": [self._HEALTH_HINTS[k]
                          for k, v in checks.items() if v is False],
            })
        return request.make_response(
            json.dumps(body),
            headers=[("Content-Type", "application/json"),
                     ("Cache-Control", "no-store")])
