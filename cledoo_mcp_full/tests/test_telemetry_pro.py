# SPDX-License-Identifier: OPL-1.0
# Copyright (c) 2026 Cledoo
import json

from odoo.tests.common import TransactionCase


class TestProTelemetry(TransactionCase):
    def test_pro_props_present_and_anonymous(self):
        props = self.env["mcp.telemetry"]._extra_telemetry_props()
        self.assertTrue(props.get("pro_installed"))
        for key in ("pro_audit_rows", "pro_policies_active",
                    "pro_approvals_total"):
            self.assertIn(key, props)
            self.assertIsInstance(props[key], int)
        # never leak raw identifiers
        self.assertNotIn("dbuuid", json.dumps(props))
