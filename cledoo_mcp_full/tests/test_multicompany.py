# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Multi-company scoping: tools must mirror the UI with every allowed
company enabled, and company_id must narrow (never widen) that scope."""
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib import tools as T


@tagged("post_install", "-at_install")
class TestMultiCompany(TransactionCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.company_a = cls.env.ref("base.main_company")
        cls.company_b = cls.env["res.company"].create({"name": "Beta Corp"})
        gf = "group_ids" if "group_ids" in cls.env["res.users"]._fields else "groups_id"
        cls.user = cls.env["res.users"].create({
            "name": "Multi Co", "login": "mcp-multico",
            gf: [(6, 0, [cls.env.ref("base.group_user").id,
                         cls.env.ref("base.group_partner_manager").id])],
            "company_id": cls.company_a.id,
            "company_ids": [(6, 0, [cls.company_a.id, cls.company_b.id])],
        })
        cls.partner_b = cls.env["res.partner"].create(
            {"name": "Beta Partner", "company_id": cls.company_b.id})

    def call(self, name, **kw):
        fn, _schema, _annotations = T.TOOLS[name]
        return fn(self.env, self.user.id, **kw)

    def test_default_scope_sees_all_allowed_companies(self):
        # with_user() alone would hide company-B records (main-company-only
        # record rules); the tools must behave like the UI with both
        # companies enabled.
        res = self.call("search_records", model="res.partner",
                        domain=[["id", "=", self.partner_b.id]],
                        fields=["name"])
        self.assertEqual(len(res["records"]), 1)

    def test_company_id_narrows_scope(self):
        res = self.call("search_records", model="res.partner",
                        domain=[["id", "=", self.partner_b.id]],
                        fields=["name"], company_id=self.company_a.id)
        self.assertEqual(res["records"], [])
        res = self.call("search_records", model="res.partner",
                        domain=[["id", "=", self.partner_b.id]],
                        fields=["name"], company_id=self.company_b.id)
        self.assertEqual(len(res["records"]), 1)

    def test_foreign_company_id_is_invalid_params(self):
        outsider = self.env["res.company"].create({"name": "Gamma Corp"})
        with self.assertRaises(T.ToolInvalidParamsError):
            self.call("search_records", model="res.partner",
                      fields=["name"], company_id=outsider.id)

    def test_whoami_lists_allowed_companies(self):
        res = self.call("whoami")
        ids = [c["id"] for c in res["allowed_companies"]]
        self.assertIn(self.company_a.id, ids)
        self.assertIn(self.company_b.id, ids)
        self.assertEqual(res["company"]["id"], self.company_a.id)

    def test_describe_access_reports_company_scope(self):
        res = self.call("describe_access", model="res.partner")
        self.assertIn(self.company_b.id, res["company_ids"])
