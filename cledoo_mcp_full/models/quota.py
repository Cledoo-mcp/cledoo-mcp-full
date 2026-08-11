# SPDX-License-Identifier: OPL-1.0
# Copyright (c) 2026 Cledoo
"""Per-principal daily budgets on top of the base per-minute rate limit.
Counters = today's audit rows (no separate counter table to drift)."""
from fnmatch import fnmatchcase

from odoo import fields, models


class McpQuota(models.Model):
    _name = "mcp.quota"
    _description = "MCP daily quota"

    name = fields.Char(required=True)
    principal_pattern = fields.Char(default="*", required=True)
    daily_calls = fields.Integer(
        default=0, help="Max MCP calls per UTC day. 0 = unlimited.")
    daily_writes = fields.Integer(
        default=0, help="Max write/delete calls per UTC day. 0 = unlimited.")
    active = fields.Boolean(default=True)

    def _for_principal(self, principal_key):
        return self.sudo().search([("active", "=", True)]).filtered(
            lambda q: fnmatchcase(principal_key, q.principal_pattern or "*"))
