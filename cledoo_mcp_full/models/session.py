# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Optional stateful MCP sessions for the /mcp endpoint (A9).

One row per `Mcp-Session-Id` handed out on `initialize`. Sessions give
the admin visibility ("who is connected right now?") and a kill switch
(revoke -> the endpoint answers 404 so the client re-initializes, per
MCP spec). Statelessness is preserved: an unknown session id is ignored,
so old clients and server restarts keep working."""
from datetime import timedelta

from odoo import api, fields, models

SESSION_TTL_HOURS = 24
# Refresh last_activity at most once a minute: sessions exist for
# visibility, not auditing, and a write per request would be pure churn.
TOUCH_THROTTLE_SECONDS = 60


class McpSession(models.Model):
    _name = "mcp.session"
    _description = "MCP endpoint session"
    _order = "last_activity desc"

    name = fields.Char(
        string="Session ID", required=True, index=True)
    user_id = fields.Many2one("res.users", required=True, ondelete="cascade")
    principal = fields.Char()  # e.g. "apikey:2" / "token:5"
    remote_addr = fields.Char(string="Remote address")
    last_activity = fields.Datetime(
        required=True, default=fields.Datetime.now)
    revoked = fields.Boolean(default=False)

    def init(self):
        # Unique index created by hand, NOT via _sql_constraints: Odoo 19
        # dropped the legacy _sql_constraints loader (new Constraint API)
        # and this source runs on both series (same pattern as activity.py).
        self.env.cr.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS mcp_session_name_uniq"
            " ON mcp_session (name)")

    def action_revoke(self):
        self.write({"revoked": True})

    @api.model
    def _touch(self, session_id, uid, principal, remote_addr):
        """Find-or-create the session row and keep last_activity roughly
        current. Runs sudo (called from the controller before any user
        env exists). Returns the record."""
        Session = self.sudo()
        rec = Session.search([("name", "=", session_id)], limit=1)
        if not rec:
            return Session.create({
                "name": session_id,
                "user_id": uid,
                "principal": principal,
                "remote_addr": remote_addr,
            })
        threshold = fields.Datetime.now() - timedelta(
            seconds=TOUCH_THROTTLE_SECONDS)
        if rec.last_activity < threshold:
            rec.write({"last_activity": fields.Datetime.now()})
        return rec

    @api.model
    def _gc_sessions(self):
        """Drop sessions idle for more than 24h (daily cron)."""
        cutoff = fields.Datetime.now() - timedelta(hours=SESSION_TTL_HOURS)
        self.sudo().search([("last_activity", "<", cutoff)]).unlink()
