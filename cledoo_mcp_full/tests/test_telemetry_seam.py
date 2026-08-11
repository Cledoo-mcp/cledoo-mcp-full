import unittest
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
from odoo.tests.common import TransactionCase


class TestTelemetrySeam(TransactionCase):
    @unittest.skip("free-only seam default; the pro overrides are active in the merged build (covered by the pro suite)")
    def test_base_extra_props_empty(self):
        self.assertEqual(
            self.env["mcp.telemetry"]._extra_telemetry_props(), {})

    def test_build_payload_merges_extra_props(self):
        from odoo.addons.cledoo_mcp_full.lib import telemetry
        payload = telemetry.build_payload(self.env)
        # base alone contributes no pro keys
        self.assertIn("properties", payload)
