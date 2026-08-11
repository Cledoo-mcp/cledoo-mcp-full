# SPDX-License-Identifier: OPL-1.0
# Copyright (c) 2026 Cledoo
from odoo.tests import tagged
from odoo.tests.common import TransactionCase


@tagged("post_install", "-at_install")
class TestProVersionInSettings(TransactionCase):
    def test_settings_expose_pro_module_version(self):
        # the Settings page must show which code is deployed; the manifest
        # is the truth for the running code
        from odoo.modules.module import get_manifest
        s = self.env["res.config.settings"].create({})
        self.assertEqual(s.pro_module_version,
                         get_manifest("cledoo_mcp_full")["version"])

    def test_version_field_is_in_the_pro_settings_view(self):
        arch = self.env.ref(
            "cledoo_mcp_full.res_config_settings_view_form_pro").arch_db
        self.assertIn("pro_module_version", arch)
