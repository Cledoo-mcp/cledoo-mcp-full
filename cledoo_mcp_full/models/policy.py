# SPDX-License-Identifier: OPL-1.0
# Copyright (c) 2026 Cledoo
"""mcp.policy — ordered allow/deny/approval rules on top of Odoo ACLs.
First matching rule (by sequence) decides; optional global default-deny
when nothing matches. `mode=dry_run` evaluates and stamps the audit row
(would_deny) without blocking — see the simulator (Task 9)."""
from fnmatch import fnmatchcase

from odoo import fields, models


class McpPolicy(models.Model):
    _name = "mcp.policy"
    _description = "MCP access policy rule"
    _order = "sequence, id"

    name = fields.Char(required=True)
    sequence = fields.Integer(default=10)
    active = fields.Boolean(default=True)
    mode = fields.Selection(
        [("enforce", "Enforce"), ("dry_run", "Dry run")],
        default="enforce", required=True,
        help="Dry run: the rule is evaluated and logged in the audit "
             "trail (would-deny) but never blocks. Promote to Enforce "
             "once the simulator shows no false positives.")
    verdict = fields.Selection(
        [("allow", "Allow"), ("deny", "Deny"),
         ("approval", "Require approval")],
        default="deny", required=True)
    principal_pattern = fields.Char(
        default="*", required=True,
        help='Glob on the principal key: "token:12", "apikey:*", "*".')
    model_pattern = fields.Char(
        default="*", required=True,
        help='Glob on the model: "res.partner", "hr.*", "*".')
    operation = fields.Selection(
        [("any", "Any"), ("read", "Read"), ("write", "Write"),
         ("unlink", "Delete")], default="any", required=True)
    fields_deny = fields.Char(
        help="Comma-separated field names. Writes touching one of them "
             "are denied; reads get the field stripped from results. "
             "Nested x2many create/update commands (e.g. child_ids: "
             "[(0, 0, {...})] or (1, id, {...})) are inspected "
             "recursively, so a denied field written through a nested "
             "command on a related record is caught too. Known "
             "limitation: image/binary variant fields are distinct "
             "fields — denying `image_1920` does not also cover "
             "`image_128`, `image_256`, etc., each variant must be "
             "listed explicitly.")

    def _match(self, req):
        self.ensure_one()
        if not fnmatchcase(req.principal_key, self.principal_pattern or "*"):
            return False
        if not fnmatchcase(req.model or "", self.model_pattern or "*"):
            return False
        if self.operation != "any" and self.operation != req.operation:
            return False
        return True

    def _first_match(self, env, req):
        """First active rule (by sequence) whose pattern matches req, or
        an empty recordset if none does."""
        rules = env["mcp.policy"].sudo().search([("active", "=", True)])
        for rule in rules:
            if rule._match(req):
                return rule
        return env["mcp.policy"]

    def _denied_fields(self, req=None):
        self.ensure_one()
        return {f.strip() for f in (self.fields_deny or "").split(",")
                if f.strip()}

    def action_promote(self):
        self.write({"mode": "enforce"})

    def action_simulate(self):
        self.ensure_one()
        wiz = self.env["mcp.policy.simulate"].create({"policy_id": self.id})
        return {"type": "ir.actions.act_window",
                "res_model": "mcp.policy.simulate", "res_id": wiz.id,
                "view_mode": "form", "target": "new"}
