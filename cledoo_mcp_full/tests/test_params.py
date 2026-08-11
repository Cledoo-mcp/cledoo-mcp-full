# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib.params import is_enabled


@tagged("post_install", "-at_install")
class TestIsEnabled(TransactionCase):
    def _set(self, val):
        self.env["ir.config_parameter"].sudo().set_param(
            "cledoo_mcp_full.enabled", val)

    def test_truthy_spellings(self):
        # integrators set ir.config_parameter by hand in every casing
        for val in ("True", "true", "TRUE", "1", "yes", "on", " true "):
            self._set(val)
            self.assertTrue(is_enabled(self.env), "should accept %r" % val)

    def test_falsy_spellings(self):
        for val in ("False", "false", "0", "", "no", "off", "banana"):
            self._set(val)
            self.assertFalse(is_enabled(self.env), "should reject %r" % val)

    def test_absent_param_is_disabled(self):
        self.env["ir.config_parameter"].sudo().search(
            [("key", "=", "cledoo_mcp_full.enabled")]).unlink()
        self.assertFalse(is_enabled(self.env))
