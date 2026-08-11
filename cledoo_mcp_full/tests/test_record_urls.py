# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""create/get/update responses carry a clickable web URL and the
display_name, so the LLM can hand the user a link without hunting
through ir.actions / ir.ui.menu, and without a verification get_record
after every create."""
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib import tools as T


@tagged("post_install", "-at_install")
class TestRecordUrls(TransactionCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.env["ir.config_parameter"].sudo().set_param(
            "web.base.url", "https://erp.example.com")

    def call(self, name, **kw):
        fn, _s, _a = T.TOOLS[name]
        return fn(self.env, self.env.uid, **kw)

    def test_create_returns_display_name_and_url(self):
        res = self.call("create_record", model="res.partner",
                        values={"name": "Linky Co"})
        self.assertEqual(res["display_name"], "Linky Co")
        self.assertEqual(
            res["url"],
            "https://erp.example.com/odoo/res.partner/%d" % res["id"])

    def test_get_returns_url(self):
        p = self.env["res.partner"].create({"name": "Get Co"})
        res = self.call("get_record", model="res.partner", record_id=p.id)
        self.assertEqual(
            res["url"], "https://erp.example.com/odoo/res.partner/%d" % p.id)

    def test_update_returns_display_name_and_url(self):
        p = self.env["res.partner"].create({"name": "Old"})
        res = self.call("update_record", model="res.partner",
                        record_id=p.id, values={"name": "New"})
        self.assertEqual(res["display_name"], "New")
        self.assertTrue(res["url"].endswith("/odoo/res.partner/%d" % p.id))
