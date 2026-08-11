# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib import tools as T


@tagged("post_install", "-at_install")
class TestAggregateRecords(TransactionCase):
    def call(self, **kw):
        fn, _s, _a = T.TOOLS["aggregate_records"]
        return fn(self.env, self.env.uid, **kw)

    def test_count_by_group(self):
        res = self.call(model="res.partner", groupby=["is_company"])
        self.assertEqual(res["model"], "res.partner")
        self.assertTrue(res["groups"])
        for g in res["groups"]:
            self.assertIn("is_company", g)
            self.assertIsInstance(g["__count"], int)

    def test_aggregate_sum(self):
        res = self.call(model="res.partner", groupby=["is_company"],
                        aggregates=["color:sum"])
        self.assertIn("color:sum", res["groups"][0])

    def test_many2one_group_is_id_name_dict(self):
        res = self.call(model="res.users", groupby=["company_id"])
        g = res["groups"][0]["company_id"]
        self.assertIsInstance(g, dict)
        self.assertIn("id", g)
        self.assertIn("display_name", g)

    def test_date_granularity(self):
        res = self.call(model="res.partner", groupby=["create_date:month"])
        self.assertTrue(res["groups"])
        self.assertIn("create_date:month", res["groups"][0])

    def test_groupby_required(self):
        with self.assertRaises(T.ToolInvalidParamsError):
            self.call(model="res.partner", groupby=[])

    def test_bad_aggregate_spec(self):
        with self.assertRaises(T.ToolInvalidParamsError) as ctx:
            self.call(model="res.partner", groupby=["is_company"],
                      aggregates=["color:median"])
        self.assertIn("field:func", ctx.exception.message)

    def test_unknown_groupby_field(self):
        with self.assertRaises(T.ToolInvalidParamsError):
            self.call(model="res.partner", groupby=["nope_field"])

    def test_registered_read_only(self):
        _fn, schema, ann = T.TOOLS["aggregate_records"]
        self.assertTrue(ann["readOnlyHint"])
        self.assertIn("groupby", schema["required"])
