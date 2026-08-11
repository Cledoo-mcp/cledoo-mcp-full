# SPDX-License-Identifier: OPL-1.0
# Copyright (c) 2026 Cledoo
from odoo.tests import tagged
from odoo.tests.common import TransactionCase


@tagged("post_install", "-at_install")
class TestAnalytics(TransactionCase):
    def test_report_aggregates_audit_rows(self):
        self.env["mcp.audit.log"].sudo().create([
            {"principal_key": "apikey:7", "tool": "count_records",
             "model": "res.partner", "operation": "read", "outcome": "ok",
             "duration_ms": 10},
            {"principal_key": "apikey:7", "tool": "count_records",
             "model": "res.partner", "operation": "read", "outcome": "ok",
             "duration_ms": 30},
            {"principal_key": "apikey:7", "tool": "create_record",
             "model": "res.partner", "operation": "write",
             "outcome": "denied", "code": "access_denied"},
        ])
        self.env.flush_all()
        rows = self.env["mcp.audit.report"].sudo().search(
            [("principal_key", "=", "apikey:7"),
             ("tool", "=", "count_records")])
        self.assertTrue(rows)
        self.assertEqual(sum(rows.mapped("calls")), 2)
        self.assertAlmostEqual(rows[0].avg_duration_ms, 20.0, places=1)
        denied = self.env["mcp.audit.report"].sudo().search(
            [("principal_key", "=", "apikey:7"),
             ("outcome", "=", "denied")])
        self.assertEqual(sum(denied.mapped("calls")), 1)
