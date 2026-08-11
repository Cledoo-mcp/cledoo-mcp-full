# SPDX-License-Identifier: OPL-1.0
# Copyright (c) 2026 Cledoo
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib.tools import ToolAccessError
from odoo.addons.cledoo_mcp_full.tests.common import LicenseMixin


@tagged("post_install", "-at_install")
class TestBehaviorRadar(LicenseMixin, TransactionCase):
    def setUp(self):
        super().setUp()
        self.install_license(["analytics"])
        self.gw = self.env["mcp.gateway"]
        self.Audit = self.env["mcp.audit.log"].sudo()
        self.Rule = self.env["mcp.behavior.rule"].sudo()
        self.Alert = self.env["mcp.behavior.alert"].sudo()
        self.ctx = {"principal": {"kind": "apikey", "uid": self.env.uid,
                                  "token_id": None, "apikey_id": None}}

    def _flood(self, n, outcome="ok", operation="read"):
        self.Audit.create([
            {"principal_key": "apikey:%d" % self.env.uid,
             "tool": "search_records", "model": "res.partner",
             "operation": operation, "outcome": outcome}
            for _ in range(n)])

    def test_mass_read_raises_alert(self):
        rule = self.Rule.create({"name": "scrape", "kind": "mass_read",
                                 "threshold": 5, "window_minutes": 10})
        self._flood(6)
        self.Rule._cron_scan()
        alert = self.Alert.search([("rule_id", "=", rule.id)])
        self.assertEqual(len(alert), 1)
        self.assertGreaterEqual(alert.count, 6)

    def test_alert_dedup_within_window(self):
        rule = self.Rule.create({"name": "scrape", "kind": "mass_read",
                                 "threshold": 5, "window_minutes": 10})
        self._flood(6)
        self.Rule._cron_scan()
        self.Rule._cron_scan()  # second scan, same breach
        self.assertEqual(self.Alert.search_count(
            [("rule_id", "=", rule.id)]), 1)

    def test_denial_probing_detector(self):
        rule = self.Rule.create({"name": "probing",
                                 "kind": "denial_probing",
                                 "threshold": 3, "window_minutes": 10})
        self._flood(4, outcome="denied")
        self.Rule._cron_scan()
        self.assertTrue(self.Alert.search([("rule_id", "=", rule.id)]))

    def test_suspend_action_blocks_principal(self):
        rule = self.Rule.create({"name": "kill", "kind": "mass_read",
                                 "threshold": 5, "window_minutes": 10,
                                 "action": "suspend"})
        self._flood(6)
        self.Rule._cron_scan()
        with self.assertRaises(ToolAccessError) as ctx:
            self.gw._execute_tool(self.env.uid, "count_records",
                                  {"model": "res.partner"}, context=self.ctx)
        self.assertIn("suspended", ctx.exception.message.lower())
        # one-click reversibility
        susp = self.env["mcp.principal.suspension"].sudo().search(
            [("principal_key", "=", "apikey:%d" % self.env.uid)])
        susp.write({"active": False})
        res = self.gw._execute_tool(self.env.uid, "count_records",
                                    {"model": "res.partner"},
                                    context=self.ctx)
        self.assertGreaterEqual(res["count"], 0)

    def test_digest_renders(self):
        self._flood(3)
        body = self.env["mcp.behavior.rule"]._digest_body()
        self.assertIn("calls", body)

    def test_suspended_principal_no_self_amplification(self):
        """A suspended principal's own denied traffic (blocked at
        _check_suspension, still audited) must not re-trip the
        denial_probing detector on later windows, nor mint duplicate
        suspension rows."""
        Susp = self.env["mcp.principal.suspension"].sudo()
        probe = self.Rule.create({"name": "probing",
                                  "kind": "denial_probing",
                                  "threshold": 3, "window_minutes": 10,
                                  "action": "suspend"})
        self._flood(4, outcome="denied")
        self.Rule._cron_scan()  # first breach: alert + suspension
        key = "apikey:%d" % self.env.uid
        alert = self.Alert.search([("rule_id", "=", probe.id)])
        self.assertEqual(len(alert), 1)
        self.assertEqual(Susp.search_count(
            [("principal_key", "=", key), ("active", "=", True)]), 1)
        # Next window: age the first alert past the dedup cutoff (test
        # transactions freeze now(), so simulate the window advancing),
        # while the suspended principal keeps hammering -> denied rows.
        self.env.cr.execute(
            "UPDATE mcp_behavior_alert SET create_date = "
            "create_date - interval '20 minutes' WHERE id = %s",
            (alert.id,))
        self._flood(4, outcome="denied")
        self.Rule._cron_scan()
        self.assertEqual(self.Alert.search_count(
            [("rule_id", "=", probe.id)]), 1,
            "no new alert while the principal is already suspended")
        self.assertEqual(Susp.search_count(
            [("principal_key", "=", key)]), 1,
            "at most one suspension row per principal")

    def test_single_suspension_per_principal_lift_unblocks(self):
        """Two suspend-action rules breached by the same principal
        create ONE suspension row; lifting it unblocks the next call."""
        Susp = self.env["mcp.principal.suspension"].sudo()
        self.Rule.create({"name": "kill-a", "kind": "mass_read",
                          "threshold": 5, "window_minutes": 10,
                          "action": "suspend"})
        self.Rule.create({"name": "kill-b", "kind": "denial_probing",
                          "threshold": 3, "window_minutes": 10,
                          "action": "suspend"})
        self._flood(6)
        self._flood(4, outcome="denied")
        self.Rule._cron_scan()
        key = "apikey:%d" % self.env.uid
        susp = Susp.search([("principal_key", "=", key)])
        self.assertEqual(len(susp), 1)
        with self.assertRaises(ToolAccessError):
            self.gw._execute_tool(self.env.uid, "count_records",
                                  {"model": "res.partner"}, context=self.ctx)
        susp.write({"active": False})  # one-click lift, really lifts
        res = self.gw._execute_tool(self.env.uid, "count_records",
                                    {"model": "res.partner"},
                                    context=self.ctx)
        self.assertGreaterEqual(res["count"], 0)
