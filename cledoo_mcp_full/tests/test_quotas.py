# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib.tools import ToolAccessError
from odoo.addons.cledoo_mcp_full.tests.common import LicenseMixin


@tagged("post_install", "-at_install")
class TestQuotas(LicenseMixin, TransactionCase):
    def setUp(self):
        super().setUp()
        self.gw = self.env["mcp.gateway"]
        self.ctx = {"principal": {"kind": "apikey", "uid": self.env.uid,
                                  "token_id": None, "apikey_id": None}}

    def test_daily_call_budget(self):
        self.install_license(["quotas"])
        self.env["mcp.quota"].sudo().create(
            {"name": "tiny", "daily_calls": 2})
        for _ in range(2):
            self.gw._execute_tool(self.env.uid, "count_records",
                                  {"model": "res.partner"}, context=self.ctx)
        with self.assertRaises(ToolAccessError) as ctx:
            self.gw._execute_tool(self.env.uid, "count_records",
                                  {"model": "res.partner"}, context=self.ctx)
        self.assertEqual(ctx.exception.code, "access_denied")
        self.assertIn("quota", ctx.exception.message.lower())

    def test_write_budget_blocks_writes_only(self):
        self.install_license(["quotas"])
        self.env["mcp.quota"].sudo().create(
            {"name": "no writes today", "daily_writes": 1})
        self.gw._execute_tool(self.env.uid, "create_record",
                              {"model": "res.partner",
                               "values": {"name": "Q1"}}, context=self.ctx)
        with self.assertRaises(ToolAccessError):
            self.gw._execute_tool(self.env.uid, "create_record",
                                  {"model": "res.partner",
                                   "values": {"name": "Q2"}},
                                  context=self.ctx)
        # reads still fine
        res = self.gw._execute_tool(self.env.uid, "count_records",
                                    {"model": "res.partner"},
                                    context=self.ctx)
        self.assertGreaterEqual(res["count"], 0)

    def test_principal_pattern_is_case_sensitive(self):
        # fnmatch.fnmatch case-folds on macOS/Windows but not on Linux;
        # fnmatchcase makes _for_principal's matching deterministic on
        # every platform. Principal keys are lowercase in practice
        # ("apikey:9"), so an uppercase-lettered pattern must NOT match.
        quota = self.env["mcp.quota"].sudo().create(
            {"name": "wrong case", "principal_pattern": "APIKEY:*"})
        self.assertFalse(quota._for_principal("apikey:9"))
