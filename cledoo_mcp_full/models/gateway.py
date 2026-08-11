# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Extension seam between the MCP transport and tool execution.

MCP Pro _inherit's this model and wraps _execute_tool/_list_tools with its
governance stack (policy engine, masking, audit). The lite implementation
dispatches straight to the direct-ORM registry.

Seam contract (the error ABI the controller relies on):
- `_execute_tool` must raise `UnknownToolError` for a missing tool
  (mapped to a JSON-RPC -32602 protocol error — unknown tool IS a
  protocol error). Every other `lib.tools.ToolError` subclass, including
  `ToolInvalidParamsError` for bad arguments, becomes an `isError: true`
  tool result (2025-06-18 tool errors; SEP-1303) carrying
  `{"error": message, "code": exc.code}` in the result content, NOT a
  JSON-RPC error object — the LLM must be able to read and self-correct
  from it. Any other exception becomes an opaque -32603 and rolls the
  request back.
- `context` carries per-request transport info
  (`session_id`/`remote_addr`/`request_id`) so an override can bind
  audit entries or confirmation tokens to a session, plus `principal`
  ({kind: "apikey"|"oauth", uid, token_id}) so governance overrides can
  bind decisions (audit, quotas, consent scopes) to the actual
  credential. The lite implementation only uses `principal` to stamp
  chatter messages (mcp_name); everything else ignores it.
- `_on_request` observes events that never reach `_execute_tool`
  (auth failures, unknown JSON-RPC methods, internal errors); overrides
  must stay cheap and must not raise.
"""
from odoo import models

from odoo.addons.cledoo_mcp_full.lib.tools import TOOLS


class UnknownToolError(KeyError):
    """Raised when a registry lookup misses a tool name.

    Subclasses KeyError so existing callers that only check for KeyError
    keep working, but lets the controller distinguish "no such tool"
    (-32602) from a plain KeyError raised *inside* a tool's own code
    (which should fall through to -32603 + logging instead)."""


class McpGateway(models.AbstractModel):
    _name = "mcp.gateway"
    _description = "MCP tool gateway (lite: direct ORM under Odoo ACLs)"

    def _list_tools(self, uid=None):
        """Tools advertised to the client. `uid` lets an override tailor
        the list per user/policy; the lite registry is the same for all.

        The description is the full docstring (whitespace-collapsed): it
        is the main steering surface for the LLM, so tools.py writes
        multi-line usage guidance there. `annotations` follow the MCP
        2025-06-18 spec (readOnlyHint/destructiveHint/...) — clients use
        them for trust UI, and the consent page derives its permission
        list from them."""
        return [{
            "name": name,
            "description": " ".join((fn.__doc__ or name).split()),
            "inputSchema": schema,
            "annotations": annotations,
        } for name, (fn, schema, annotations) in TOOLS.items()]

    def _execute_tool(self, uid, tool_name, arguments, context=None):
        try:
            fn, _schema, annotations = TOOLS[tool_name]
        except KeyError:
            raise UnknownToolError(tool_name) from None
        env = self.env
        if not annotations.get("readOnlyHint"):
            label = self._principal_label(context)
            if label:
                # Namespaced context key (not a bare `mcp_name`): it rides
                # env.context into everything the tool triggers, so it must
                # not collide with other modules' keys. mail.message.create
                # scopes which messages it actually stamps.
                env = env(context=dict(env.context, cledoo_mcp_name=label))
        # Own savepoint (flushes on exit, so deferred ORM constraint
        # violations surface here): a failing tool must not leave
        # half-applied writes behind. Scoped tightly to the tool's own
        # call — NOT the whole seam — so governance bookkeeping an
        # override layers around this call (audit rows, quota counters)
        # lives outside this savepoint and survives the tool's failure
        # instead of being discarded along with it.
        with env.cr.savepoint():
            return fn(env, uid, **(arguments or {}))

    def _principal_label(self, context):
        """Human label of the calling MCP principal for chatter
        attribution (mail.message.mcp_name): the OAuth client name, or
        the API-key user's login. None when the annotate toggle is off or
        the transport gave no principal."""
        icp = self.env["ir.config_parameter"].sudo()
        if icp.get_param("cledoo_mcp_full.annotate_messages", "True") == "False":
            return None
        principal = (context or {}).get("principal") or {}
        if principal.get("kind") == "oauth" and principal.get("token_id"):
            token = self.env["mcp.oauth.token"].sudo().browse(
                principal["token_id"])
            return (token.client_name or "MCP") if token.exists() else "MCP"
        if principal.get("uid"):
            user = self.env["res.users"].sudo().browse(principal["uid"])
            return user.login if user.exists() else None
        return None

    def _consent_scope_vals(self, kw):
        """Seam hook: map OAuth consent-form POST fields to extra values
        stored on the authorization code (and copied to its tokens).
        Lite has no consent scopes; MCP Pro overrides."""
        return {}

    def _capabilities(self):
        """Initialize capabilities seam: the `capabilities` object sent in
        the MCP `initialize` response. Lite advertises nothing beyond bare
        tools/resources; MCP Pro overrides to advertise extensions (e.g.
        `experimental["mcp/apps"]`)."""
        return {"tools": {}, "resources": {}}

    def _list_resources(self, uid=None):
        """MCP resources advertised to the client (resources/list).
        Lite serves none; MCP Pro serves ui:// app documents."""
        return []

    def _read_resource(self, uid, uri):
        """Resolve one resource for resources/read. Returns
        {"uri", "mimeType", "text"} or None for unknown URIs."""
        return None

    def _on_request(self, event, uid, method, outcome):
        """Observation hook for seam-bypassing transport events.

        `event` in ("auth_failure", "unknown_method", "internal_error",
        "rate_limited", "tool_error", "unknown_notification"); lite does
        nothing. Overrides must not raise and must not assume an
        authenticated uid (None on auth failures)."""
