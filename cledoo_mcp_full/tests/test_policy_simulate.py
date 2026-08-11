# SPDX-License-Identifier: OPL-1.0
# Copyright (c) 2026 Cledoo
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.tests.common import LicenseMixin


@tagged("post_install", "-at_install")
class TestPolicySimulate(LicenseMixin, TransactionCase):
    def setUp(self):
        super().setUp()
        self.Audit = self.env["mcp.audit.log"].sudo()
        self.Audit.create([
            {"principal_key": "apikey:1", "tool": "count_records",
             "model": "hr.employee", "operation": "read", "outcome": "ok"},
            {"principal_key": "apikey:1", "tool": "count_records",
             "model": "res.partner", "operation": "read", "outcome": "ok"},
            {"principal_key": "token:2", "tool": "create_record",
             "model": "hr.employee", "operation": "write", "outcome": "ok"},
        ])
        self.rule = self.env["mcp.policy"].sudo().create({
            "name": "no hr", "model_pattern": "hr.*", "verdict": "deny",
            "mode": "dry_run"})
        self.env["ir.config_parameter"].sudo().set_param(
            "cledoo_mcp_full.policy_default_deny", "False")

    def _simulate(self, rule, days=30):
        wiz = self.env["mcp.policy.simulate"].create(
            {"policy_id": rule.id, "days": days})
        wiz.action_simulate()
        return wiz

    def test_simulate_counts_hits(self):
        wiz = self._simulate(self.rule)
        self.assertEqual(wiz.total_calls, 3)
        self.assertEqual(wiz.would_block, 2)
        self.assertEqual(len(wiz.hit_ids), 2)
        self.assertEqual(wiz.would_pause, 0)

    def test_allow_rule_hits_but_never_blocks(self):
        self.rule.verdict = "allow"
        wiz = self._simulate(self.rule)
        self.assertEqual(wiz.total_calls, 3)
        self.assertEqual(len(wiz.hit_ids), 2)   # rule still wins hr rows
        self.assertEqual(wiz.would_block, 0)    # ...but allow blocks nothing
        self.assertEqual(wiz.would_pause, 0)

    def test_approval_rule_pauses_not_blocks(self):
        self.rule.verdict = "approval"
        wiz = self._simulate(self.rule)
        self.assertEqual(len(wiz.hit_ids), 2)
        self.assertEqual(wiz.would_pause, 2)
        self.assertEqual(wiz.would_block, 0)

    def test_earlier_rule_intercepts_first_match(self):
        self.env["mcp.policy"].sudo().create({
            "name": "hr ok", "model_pattern": "hr.*", "verdict": "allow",
            "sequence": 1})
        self.rule.sequence = 10
        wiz = self._simulate(self.rule)
        # the earlier allow rule wins every hr row: the deny rule gets
        # no hits and nothing is blocked
        self.assertEqual(len(wiz.hit_ids), 0)
        self.assertEqual(wiz.would_block, 0)
        self.assertEqual(wiz.would_pause, 0)

    def test_default_deny_counts_unmatched_as_blocked(self):
        self.env["ir.config_parameter"].sudo().set_param(
            "cledoo_mcp_full.policy_default_deny", "True")
        wiz = self._simulate(self.rule)
        # 2 hr rows blocked by the rule + the unmatched res.partner
        # row blocked by default-deny
        self.assertEqual(wiz.would_block, 3)
        self.assertEqual(len(wiz.hit_ids), 2)

    def test_dry_run_call_is_stamped_not_blocked(self):
        self.install_license(["policy", "audit"])
        ctx = {"principal": {"kind": "apikey", "uid": self.env.uid,
                             "token_id": None, "apikey_id": None}}
        # hr.employee may not be installed on the test db; use a model
        # that always exists and a fresh dry-run rule for it
        rule = self.env["mcp.policy"].sudo().create({
            "name": "dry partners", "model_pattern": "res.partner",
            "verdict": "deny", "mode": "dry_run", "sequence": 1})
        res = self.env["mcp.gateway"]._execute_tool(
            self.env.uid, "count_records", {"model": "res.partner"},
            context=ctx)
        self.assertGreaterEqual(res["count"], 0)  # NOT blocked
        row = self.Audit.search([], order="id desc", limit=1)
        self.assertEqual(row.would_deny_rule_id.id, rule.id)
        self.assertEqual(row.outcome, "ok")

    def test_promote(self):
        self.rule.action_promote()
        self.assertEqual(self.rule.mode, "enforce")
