# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib import tools as T


@tagged("post_install", "-at_install")
class TestListModules(TransactionCase):
    def call(self, **kw):
        fn, _s, _a = T.TOOLS["list_modules"]
        return fn(self.env, self.env.uid, **kw)

    def test_installed_modules(self):
        res = self.call()
        names = [m["name"] for m in res["modules"]]
        self.assertIn("cledoo_mcp_full", names)
        self.assertIn("base", names)
        for m in res["modules"]:
            self.assertEqual(m["state"], "installed")
        self.assertEqual(res["total"], len(res["modules"]))

    def test_all_modules_includes_uninstalled(self):
        res = self.call(installed_only=False)
        states = {m["state"] for m in res["modules"]}
        self.assertIn("uninstalled", states)

    def test_read_only_annotation(self):
        _fn, _s, ann = T.TOOLS["list_modules"]
        self.assertTrue(ann["readOnlyHint"])

    def test_pattern_filters(self):
        res = self.call(pattern="cledoo")
        names = [m["name"] for m in res["modules"]]
        self.assertIn("cledoo_mcp_full", names)
        self.assertNotIn("base", names)

    def test_default_output_is_slim(self):
        res = self.call(pattern="cledoo_mcp_full")
        self.assertEqual(set(res["modules"][0]), {"name", "state"})

    def test_verbose_restores_version_and_summary(self):
        res = self.call(pattern="cledoo_mcp_full", verbose=True)
        row = res["modules"][0]
        self.assertIn("version", row)
        self.assertIn("summary", row)
