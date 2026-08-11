# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Replay recorded audit traffic through the REAL policy matching
(mcp.policy._first_match — first active rule by sequence wins, the
same semantics the live pipeline applies): 'under the current rules,
X of Y calls would be blocked, Z paused for approval'. Kills the
deploy-fear of default-deny.

Simulation previews rules AS IF ENFORCED: dry-run rules count with
their verdict — that is exactly the promotion question this wizard
answers."""
from datetime import timedelta
from types import SimpleNamespace

from odoo import fields, models
from odoo.fields import Datetime


class McpPolicySimulate(models.TransientModel):
    _name = "mcp.policy.simulate"
    _description = "Simulate an MCP policy rule against the audit log"

    policy_id = fields.Many2one("mcp.policy", required=True)
    days = fields.Integer(default=7, required=True)
    total_calls = fields.Integer(readonly=True)
    would_block = fields.Integer(
        readonly=True,
        help="Calls whose first-matching rule has verdict Deny, plus "
             "unmatched calls when global default-deny is on.")
    would_pause = fields.Integer(
        readonly=True,
        help="Calls whose first-matching rule requires approval — "
             "paused for a human, not blocked.")
    hit_ids = fields.Many2many(
        "mcp.audit.log", readonly=True,
        help="Calls the selected rule wins (first match by sequence). "
             "Field-level rules (fields_deny on an Allow verdict) are "
             "counted as model matches — stored rows keep no values.")

    def action_simulate(self):
        self.ensure_one()
        rule = self.policy_id
        Policy = self.env["mcp.policy"]
        default_deny = self.env["ir.config_parameter"].sudo().get_param(
            "cledoo_mcp_full.policy_default_deny") == "True"
        cutoff = Datetime.now() - timedelta(days=self.days)
        rows = self.env["mcp.audit.log"].sudo().search(
            [("create_date", ">=", cutoff), ("model", "!=", False)])
        blocked = paused = 0
        hits = []
        for row in rows:
            # Pseudo-request exposing exactly the attributes _match
            # reads (principal_key, model, operation) — ONE matching
            # path shared with the pipeline semantics, not a re-roll.
            req = SimpleNamespace(
                principal_key=row.principal_key or "",
                model=row.model or "",
                operation=row.operation or "read")
            winner = Policy._first_match(self.env, req)
            if winner == rule:
                hits.append(row.id)
            if not winner:
                if default_deny:
                    blocked += 1
            elif winner.verdict == "deny":
                blocked += 1
            elif winner.verdict == "approval":
                paused += 1
            # verdict == "allow": allowed. fields_deny on an allow rule
            # only shapes strips / write denials, which stored rows
            # cannot replay (no values kept) — disclosed model-level
            # approximation, see hit_ids help.
        self.write({"total_calls": len(rows), "would_block": blocked,
                    "would_pause": paused, "hit_ids": [(6, 0, hits)]})
        return {"type": "ir.actions.act_window", "res_model": self._name,
                "res_id": self.id, "view_mode": "form", "target": "new"}

    def action_view_hits(self):
        self.ensure_one()
        return {"type": "ir.actions.act_window",
                "res_model": "mcp.audit.log", "view_mode": "list",
                "domain": [("id", "in", self.hit_ids.ids)],
                "name": "Calls this rule wins"}
