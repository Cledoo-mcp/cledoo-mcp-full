# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""OAuth 2.1 authorization server for the native MCP endpoint.

Discovery (RFC 8414/9728), open Dynamic Client Registration (RFC 7591,
public clients only — no secret), the consent authorize endpoint, and the
token endpoint. Every route 404s when the module toggle is off. All
metadata URLs derive from web.base.url at request time."""
import json
import logging
from urllib.parse import urlencode, urlsplit

from psycopg2 import OperationalError

from odoo import http
from odoo.http import request

from odoo.addons.cledoo_mcp_full.lib.params import is_enabled

_logger = logging.getLogger(__name__)

MAX_REDIRECT_URIS = 5
MAX_REDIRECT_URI_LEN = 2000
# Hosts whose consent page skips the "(unverified application)" caution.
# The check is on the *redirect host* — the only registrant-controlled
# value that actually decides where the authorization code goes — never
# on the self-declared client_name. Override with the
# cledoo_mcp_full.trusted_redirect_hosts parameter (comma-separated).
TRUSTED_REDIRECT_HOSTS_DEFAULT = "claude.ai,claude.com"


def _client_ip():
    """Best-effort client IP for the register throttle.

    When proxy_mode is on, Odoo already resolves remote_addr from the
    forwarded headers and this returns it. When proxy_mode is OFF (a
    common misconfig the health check nags about), remote_addr is the
    proxy's own IP, so *every* client would share one throttle bucket and
    one bot could starve legitimate registrations — we fall back to the
    first X-Forwarded-For hop to recover per-client granularity.

    Advisory only: XFF is client-spoofable, so this is NOT a security
    boundary. The real anti-abuse guards on /register are the hard
    per-row caps and the dormant-client GC; this throttle just keeps a
    dumb loop from filling the table."""
    fwd = request.httprequest.headers.get("X-Forwarded-For")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.httprequest.remote_addr


def _redirect_host_trusted(redirect_uri):
    host = (urlsplit(redirect_uri).hostname or "").lower()
    raw = request.env["ir.config_parameter"].sudo().get_param(
        "cledoo_mcp_full.trusted_redirect_hosts",
        TRUSTED_REDIRECT_HOSTS_DEFAULT)
    trusted = {h.strip().lower() for h in (raw or "").split(",") if h.strip()}
    return any(host == t or host.endswith("." + t) for t in trusted)


def _enabled():
    return is_enabled(request.env)


def _base_url():
    return (request.env["ir.config_parameter"].sudo().get_param(
        "web.base.url") or "").rstrip("/")


def _json(body, status=200, no_store=False):
    headers = [("Content-Type", "application/json")]
    if no_store:
        # RFC 6749 §5.1: responses carrying tokens/credentials MUST NOT be
        # cached by any intermediary.
        headers += [("Cache-Control", "no-store"), ("Pragma", "no-cache")]
    return request.make_response(
        json.dumps(body), headers=headers, status=status)


def _redirect_uri_allowed(uri):
    if not uri or not isinstance(uri, str) or len(uri) > MAX_REDIRECT_URI_LEN:
        return False
    parts = urlsplit(uri)
    if parts.scheme == "https":
        return True
    return parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1")


def _resource_allowed(value):
    """RFC 8707: when the client names a target resource it must be this
    server's MCP endpoint. Absent = fine (single-RS deployment)."""
    if not value:
        return True
    base = _base_url()
    return value.rstrip("/") in (base, base + "/mcp")


class McpOAuthController(http.Controller):
    @http.route("/.well-known/oauth-authorization-server", type="http",
                auth="none", methods=["GET"], csrf=False)
    def as_metadata(self, **kw):
        if not _enabled():
            return request.not_found()
        base = _base_url()
        return _json({
            "issuer": base,
            "authorization_endpoint": base + "/mcp/oauth/authorize",
            "token_endpoint": base + "/mcp/oauth/token",
            "registration_endpoint": base + "/mcp/oauth/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
        })

    @http.route("/.well-known/oauth-protected-resource", type="http",
                auth="none", methods=["GET"], csrf=False)
    def rs_metadata(self, **kw):
        if not _enabled():
            return request.not_found()
        base = _base_url()
        return _json({
            "resource": base + "/mcp",
            "authorization_servers": [base],
        })

    # readonly=False on every route that persists OAuth state (register
    # creates the client, authorize issues the code, token mints/rotates
    # pairs): the 18/19 default readonly cursor would make each first
    # attempt die on ReadOnlySqlTransaction and rely on Odoo's rw-retry.
    @http.route("/mcp/oauth/register", type="http", auth="none",
                methods=["POST"], csrf=False, readonly=False)
    def register(self, **kw):
        if not _enabled():
            return request.not_found()
        # Per-IP throttle: open DCR means bots can enroll clients freely;
        # the caps below bound each row, this bounds the row *rate*.
        # (remote_addr is the proxy's IP when proxy_mode is off — one more
        # reason the health check insists on it.)
        from odoo.addons.cledoo_mcp_full.lib.params import get_int_param
        from odoo.addons.cledoo_mcp_full.lib.ratelimit import check as rl_check
        limit = get_int_param(
            request.env, "cledoo_mcp_full.register_rate_limit", 10)
        allowed, retry_after = rl_check(
            "register:%s" % _client_ip(), limit)
        if not allowed:
            return request.make_response(
                json.dumps({"error": "rate_limited"}),
                headers=[("Content-Type", "application/json"),
                         ("Retry-After", str(int(retry_after) + 1))],
                status=429)
        try:
            body = json.loads(request.httprequest.get_data() or b"{}")
        except ValueError:
            return _json({"error": "invalid_client_metadata"}, status=400)
        uris = body.get("redirect_uris") or []
        if not isinstance(uris, list) or not uris or len(uris) > MAX_REDIRECT_URIS:
            return _json({"error": "invalid_redirect_uri"}, status=400)
        if not all(_redirect_uri_allowed(u) for u in uris):
            return _json({"error": "invalid_redirect_uri"}, status=400)
        client_name = body.get("client_name")
        if client_name is not None and not isinstance(client_name, str):
            return _json({"error": "invalid_client_metadata"}, status=400)
        client = request.env["mcp.oauth.client"].sudo()._register_client(
            client_name, uris)
        return _json({
            "client_id": client.client_id,
            "client_name": client.client_name,
            "redirect_uris": uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
        }, status=201, no_store=True)

    @http.route("/mcp/oauth/authorize", type="http", auth="user",
                methods=["GET", "POST"], csrf=True, website=False,
                readonly=False)
    def authorize(self, **kw):
        if not _enabled():
            return request.not_found()
        # Internal users only: portal/public users can hold API keys, but
        # letting a portal customer wire an autonomous agent into the
        # database is a decision the admin should make deliberately (it is
        # a consent-scope feature in MCP Pro), not a silent default.
        if not request.env.user._is_internal():
            return _json({"error": "access_denied",
                          "error_description":
                          "MCP OAuth is available to internal users only"},
                         status=403)
        client = request.env["mcp.oauth.client"].sudo()._get(kw.get("client_id"))
        redirect_uri = kw.get("redirect_uri") or ""
        if not client or not client._redirect_ok(redirect_uri):
            return _json({"error": "invalid_client"}, status=400)
        if kw.get("code_challenge_method") != "S256" or not kw.get("code_challenge"):
            return _json({"error": "invalid_request",
                          "error_description": "PKCE S256 required"}, status=400)
        if not _resource_allowed(kw.get("resource")):
            return _json({"error": "invalid_target",
                          "error_description":
                              "resource must be %s/mcp" % _base_url()},
                         status=400)

        if request.httprequest.method == "GET":
            # Permission bullets derive from the gateway's tool annotations
            # (single source of truth): hand-written consent copy drifted
            # from the actual toolset once already.
            _t = request.env._
            annotations = [t.get("annotations") or {}
                           for t in request.env["mcp.gateway"]._list_tools(
                               request.env.user.id)]
            permissions = []
            if any(a.get("readOnlyHint") for a in annotations):
                permissions.append(_t("Read data you have access to"))
            if any(not a.get("readOnlyHint") and not a.get("destructiveHint")
                   for a in annotations):
                permissions.append(_t("Create and modify records"))
            if any(a.get("destructiveHint") for a in annotations):
                permissions.append(_t("Delete records"))
            response = request.render("cledoo_mcp_full.oauth_consent", {
                "permissions": permissions,
                "client_trusted": _redirect_host_trusted(redirect_uri),
                "client_name": client.client_name,
                # Host the authorization code will be sent to — shown on the
                # page so the user sees where the grant actually goes
                # (client_name is self-declared by the registrant, the
                # redirect host is the only trustworthy identity signal).
                "redirect_host": urlsplit(redirect_uri).netloc,
                "user_name": request.env.user.name,
                "form_action": "/mcp/oauth/authorize",
                "client_id": client.client_id, "redirect_uri": redirect_uri,
                "state": kw.get("state") or "",
                "code_challenge": kw.get("code_challenge"),
                "code_challenge_method": "S256",
                "resource": kw.get("resource") or "",
                "csrf_token": request.csrf_token(),
            })
            # An OAuth consent page is the canonical clickjacking target:
            # never let it render inside a frame.
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
            return response

        # POST = consent decision
        state = kw.get("state") or ""
        sep = "&" if "?" in redirect_uri else "?"
        if kw.get("decision") != "allow":
            qs = urlencode({"error": "access_denied", "state": state})
            return request.redirect(
                "%s%s%s" % (redirect_uri, sep, qs), local=False)
        raw_code = request.env["mcp.oauth.code"].sudo()._issue(
            client.client_id, request.env.user.id, redirect_uri,
            kw.get("code_challenge"), kw.get("resource"),
            scope_vals=request.env["mcp.gateway"]._consent_scope_vals(kw))
        qs = urlencode({"code": raw_code, "state": state})
        return request.redirect(
            "%s%s%s" % (redirect_uri, sep, qs), local=False)

    @http.route("/mcp/oauth/token", type="http", auth="none",
                methods=["POST"], csrf=False, readonly=False)
    def token(self, **kw):
        if not _enabled():
            return request.not_found()
        try:
            return self._token(kw)
        except OperationalError:
            # Concurrency/serialization errors belong to Odoo's retrying
            # machinery (same posture as the /mcp controller); swallowing
            # them would turn a transparent retry into a client 500.
            raise
        except Exception:  # never leak internals
            _logger.exception("oauth token endpoint internal error")
            request.env.cr.rollback()
            return _json({"error": "server_error"}, status=500, no_store=True)

    def _token(self, kw):
        from odoo.addons.cledoo_mcp_full.lib.oauth_tokens import verify_pkce
        from odoo.addons.cledoo_mcp_full.models.oauth import access_ttl
        if not _resource_allowed(kw.get("resource")):
            return _json({"error": "invalid_target",
                          "error_description":
                              "resource must be %s/mcp" % _base_url()},
                         status=400, no_store=True)
        grant = kw.get("grant_type")
        Token = request.env["mcp.oauth.token"].sudo()
        if grant == "authorization_code":
            # Missing fields are a 400 invalid_request, not a traceback:
            # broken clients and vuln scanners POST partial bodies all day.
            required = ("code", "client_id", "redirect_uri", "code_verifier")
            if not all(isinstance(kw.get(f), str) and kw.get(f) for f in required):
                return _json({"error": "invalid_request"}, status=400, no_store=True)
            code = request.env["mcp.oauth.code"].sudo()._consume(
                kw["code"], kw["client_id"], kw["redirect_uri"])
            if not code or not verify_pkce(kw["code_verifier"], code.code_challenge):
                return _json({"error": "invalid_grant"}, status=400, no_store=True)
            access, refresh = Token._issue_pair(
                code.client_id, code.user_id.id,
                scope_vals=code._scope_vals())
            return _json({"access_token": access, "token_type": "Bearer",
                          "expires_in": access_ttl(request.env),
                          "refresh_token": refresh},
                         no_store=True)
        if grant == "refresh_token":
            required = ("refresh_token", "client_id")
            if not all(isinstance(kw.get(f), str) and kw.get(f) for f in required):
                return _json({"error": "invalid_request"}, status=400, no_store=True)
            pair = Token._rotate(kw["refresh_token"], kw["client_id"])
            if not pair:
                return _json({"error": "invalid_grant"}, status=400, no_store=True)
            access, refresh = pair
            return _json({"access_token": access, "token_type": "Bearer",
                          "expires_in": access_ttl(request.env),
                          "refresh_token": refresh},
                         no_store=True)
        return _json({"error": "unsupported_grant_type"}, status=400, no_store=True)
