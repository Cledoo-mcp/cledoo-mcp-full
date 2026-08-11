# SPDX-License-Identifier: OPL-1.0
# Copyright (c) 2026 Cledoo
"""mcp.audit.log — the data spine. Every governed MCP call lands here
(allowed, denied, error, pending), and the policy simulator, quotas,
analytics and behavior radar all read from it. Writing is bookkeeping:
it must never break the transport (callers wrap in savepoint)."""
from datetime import timedelta

from odoo import api, fields, models
from odoo.fields import Datetime

RETENTION_DEFAULT_DAYS = 180


class McpAuditLog(models.Model):
    _name = "mcp.audit.log"
    _description = "MCP audit trail"
    _order = "id desc"

    principal_key = fields.Char(required=True, index=True)
    kind = fields.Selection([("apikey", "API key"), ("oauth", "OAuth")])
    token_id = fields.Integer()
    apikey_id = fields.Integer()
    user_id = fields.Many2one("res.users", ondelete="set null", index=True)
    tool = fields.Char(required=True, index=True)
    model = fields.Char(index=True)
    operation = fields.Selection(
        [("read", "Read"), ("write", "Write"), ("unlink", "Delete")])
    res_ids = fields.Char(help="Record ids touched, comma-separated.")
    arg_fields = fields.Char(
        help="Names of the argument keys / requested fields — never "
             "values (the audit log must not itself leak data).")
    duration_ms = fields.Integer()
    outcome = fields.Selection(
        [("ok", "OK"), ("denied", "Denied"), ("error", "Error"),
         ("pending", "Pending approval")], required=True, index=True)
    code = fields.Char()
    policy_rule_id = fields.Many2one("mcp.policy", ondelete="set null")
    would_deny_rule_id = fields.Many2one(
        "mcp.policy", ondelete="set null",
        help="Dry-run rule that WOULD have denied this call.")
    session_id = fields.Char()
    remote_addr = fields.Char()

    @api.autovacuum
    def _gc_expired(self):
        days = int(self.env["ir.config_parameter"].sudo().get_param(
            "cledoo_mcp_full.audit_retention_days", RETENTION_DEFAULT_DAYS))
        if days <= 0:
            return
        cutoff = Datetime.now() - timedelta(days=days)
        self.sudo().search([("create_date", "<", cutoff)]).unlink()
