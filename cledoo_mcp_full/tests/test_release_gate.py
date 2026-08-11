# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Cross-feature invariants the spec calls non-negotiable."""
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib.tools import ToolAccessError
from odoo.addons.cledoo_mcp_full.tests.common import LicenseMixin

ALL = ["scopes", "audit", "masking", "policy", "approvals", "quotas",
       "outbound", "analytics", "apps"]


@tagged("post_install", "-at_install")
class TestReleaseGate(LicenseMixin, TransactionCase):
    def setUp(self):
        super().setUp()
        self.gw = self.env["mcp.gateway"]
        self.Audit = self.env["mcp.audit.log"].sudo()
        self.ctx = {"principal": {"kind": "apikey", "uid": self.env.uid,
                                  "token_id": None, "apikey_id": None}}

    def test_masking_runs_before_audit_capture(self):
        """The audit row for a masked read must not contain the PII."""
        self.install_license(ALL)
        partner = self.env["res.partner"].create(
            {"name": "Order", "email": "order@leak.test"})
        self.env["mcp.mask.rule"].sudo().create(
            {"model_name": "res.partner", "field_name": "email"})
        self.gw._execute_tool(self.env.uid, "get_record",
                              {"model": "res.partner",
                               "record_id": partner.id,
                               "fields": ["email"]}, context=self.ctx)
        row = self.Audit.search([], order="id desc", limit=1)
        self.assertNotIn("order@leak.test", str(row.read()))

    def test_denial_is_audited_with_rule(self):
        self.install_license(ALL)
        rule = self.env["mcp.policy"].sudo().create(
            {"name": "deny users", "model_pattern": "res.users",
             "verdict": "deny"})
        # NB: plain try/except, not self.assertRaises() — Odoo's
        # TransactionCase.assertRaises wraps the block in its own
        # savepoint that rolls back on the expected exception, which
        # would also discard the audit row this test needs to inspect.
        try:
            self.gw._execute_tool(self.env.uid, "count_records",
                                  {"model": "res.users"}, context=self.ctx)
            self.fail("expected ToolAccessError")
        except ToolAccessError:
            pass
        row = self.Audit.search([], order="id desc", limit=1)
        self.assertEqual(row.outcome, "denied")
        self.assertEqual(row.policy_rule_id.id, rule.id)

    def test_full_licence_full_pipeline_smoke(self):
        """One call through every licensed stage without error."""
        self.install_license(ALL)
        res = self.gw._execute_tool(self.env.uid, "search_records",
                                    {"model": "res.partner", "limit": 2},
                                    context=self.ctx)
        self.assertIn("records", res)

    def test_tools_list_includes_pro_tools(self):
        names = {t["name"] for t in self.gw._list_tools(self.env.uid)}
        self.assertIn("check_approval", names)
