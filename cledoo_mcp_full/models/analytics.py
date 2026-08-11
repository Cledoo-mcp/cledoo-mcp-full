# SPDX-License-Identifier: OPL-1.0
# Copyright (c) 2026 Cledoo
"""Read-only SQL view over the audit spine for graph/pivot dashboards."""
from odoo import fields, models
from odoo.tools import drop_view_if_exists


class McpAuditReport(models.Model):
    _name = "mcp.audit.report"
    _description = "MCP usage analytics"
    _auto = False
    _order = "date desc"

    date = fields.Date(readonly=True)
    principal_key = fields.Char(readonly=True)
    user_id = fields.Many2one("res.users", readonly=True)
    tool = fields.Char(readonly=True)
    model = fields.Char(readonly=True)
    operation = fields.Char(readonly=True)
    outcome = fields.Char(readonly=True)
    calls = fields.Integer(readonly=True)
    avg_duration_ms = fields.Float(readonly=True)

    def init(self):
        drop_view_if_exists(self.env.cr, self._table)
        self.env.cr.execute("""
            CREATE OR REPLACE VIEW %s AS (
                SELECT MIN(id) AS id,
                       create_date::date AS date,
                       principal_key,
                       user_id,
                       tool,
                       model,
                       operation,
                       outcome,
                       COUNT(*) AS calls,
                       AVG(duration_ms) AS avg_duration_ms
                  FROM mcp_audit_log
              GROUP BY create_date::date, principal_key, user_id, tool,
                       model, operation, outcome
            )""" % self._table)
