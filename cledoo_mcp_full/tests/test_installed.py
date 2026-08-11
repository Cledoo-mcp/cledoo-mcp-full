# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
from odoo.tests import tagged
from odoo.tests.common import TransactionCase


@tagged("post_install", "-at_install")
class TestInstalled(TransactionCase):
    def test_module_installed(self):
        mod = self.env["ir.module.module"].search([("name", "=", "cledoo_mcp_full")])
        self.assertEqual(mod.state, "installed")
