# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Per-principal usage counters for the /mcp endpoint.

One row per connected principal (an OAuth token or an API-key user) with
last_used_at / call_count / error_count. This is deliberately NOT an
audit trail: no per-call rows, no payloads, no tool names — the audit
product is MCP Pro. These counters answer the free-tier admin questions
("is this agent still used?", "is something erroring?") and feed the
Connected AI clients view."""
from datetime import timedelta

from odoo import api, fields, models
from odoo.fields import Datetime

ACTIVITY_RETENTION_DAYS = 180


class McpEndpointActivity(models.Model):
    _name = "mcp.endpoint.activity"
    _description = "MCP endpoint usage counters"
    _order = "last_used_at desc"

    principal = fields.Char(required=True, index=True)
    kind = fields.Selection(
        [("oauth", "OAuth"), ("apikey", "API key")], required=True)
    token_id = fields.Many2one("mcp.oauth.token", ondelete="cascade")
    user_id = fields.Many2one("res.users", required=True, ondelete="cascade")
    last_used_at = fields.Datetime()
    call_count = fields.Integer(default=0)
    error_count = fields.Integer(default=0)

    def init(self):
        # Unique index created by hand, NOT via _sql_constraints: Odoo 19
        # dropped the legacy _sql_constraints loader (new Constraint API),
        # and _bump()'s ON CONFLICT (principal) hard-requires this index on
        # both series.
        self.env.cr.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS"
            " mcp_endpoint_activity_principal_uniq"
            " ON mcp_endpoint_activity (principal)")

    def _bump(self, principal, kind, token_id, uid, error=False):
        """Upsert one hit. Raw SQL: this runs on every /mcp request and an
        ORM write would drag the whole cache-invalidation machinery along;
        the caller wraps it in its own savepoint so a failure here can
        never roll back tool writes."""
        self.env.cr.execute(
            """
            INSERT INTO mcp_endpoint_activity
                (principal, kind, token_id, user_id, last_used_at,
                 call_count, error_count, create_date, write_date)
            VALUES (%s, %s, %s, %s, (now() at time zone 'UTC'),
                    1, %s, (now() at time zone 'UTC'),
                    (now() at time zone 'UTC'))
            ON CONFLICT (principal) DO UPDATE SET
                last_used_at = EXCLUDED.last_used_at,
                call_count = mcp_endpoint_activity.call_count + 1,
                error_count = mcp_endpoint_activity.error_count
                              + EXCLUDED.error_count,
                write_date = EXCLUDED.write_date
            """,
            (principal, kind, token_id, uid, 1 if error else 0))
        self.env["mcp.endpoint.activity"].invalidate_model()

    @api.autovacuum
    def _gc_stale_activity(self):
        # Token rows go with their token (ondelete=cascade); API-key rows
        # have no anchor, so age them out after the retention window.
        cutoff = Datetime.now() - timedelta(days=ACTIVITY_RETENTION_DAYS)
        self.sudo().search([("last_used_at", "<", cutoff)]).unlink()
