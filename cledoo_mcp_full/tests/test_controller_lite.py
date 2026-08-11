# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Active-path purity gate: the lite controller/tools/gateway stack must
never import the dormant vendored/runtime_factory stack."""
import sys

from odoo.tests import tagged
from odoo.tests.common import TransactionCase


@tagged("post_install", "-at_install")
class TestActivePathPurity(TransactionCase):
    def test_controller_module_does_not_import_vendor(self):
        import odoo.addons.cledoo_mcp_full.controllers.mcp as ctrl  # noqa: F401
        import odoo.addons.cledoo_mcp_full.lib.tools  # noqa: F401
        import odoo.addons.cledoo_mcp_full.lib.auth  # noqa: F401
        import odoo.addons.cledoo_mcp_full.models.gateway  # noqa: F401
        src = open(ctrl.__file__).read()
        self.assertNotIn("vendor", src)
        for mod in ("lib.tools", "lib.auth", "models.gateway"):
            f = sys.modules["odoo.addons.cledoo_mcp_full." + mod].__file__
            self.assertNotIn("vendor", open(f).read())
