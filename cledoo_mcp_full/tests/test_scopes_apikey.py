# SPDX-License-Identifier: OPL-1.0
# Copyright (c) 2026 Cledoo
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib.tools import ToolAccessError
from odoo.addons.cledoo_mcp_full.tests.common import LicenseMixin


@tagged("post_install", "-at_install")
class TestApikeyScopes(LicenseMixin, TransactionCase):
    def setUp(self):
        super().setUp()
        self.gw = self.env["mcp.gateway"]
        Keys = self.env["res.users.apikeys"].with_user(self.env.uid)
        Keys._generate(None, "scope-test", None)
        self.key = self.env["res.users.apikeys"].sudo().search(
            [("name", "=", "scope-test")], limit=1)

    def _ctx(self):
        return {"principal": {"kind": "apikey", "uid": self.env.uid,
                              "token_id": None, "apikey_id": self.key.id}}

    def test_readonly_key_blocks_writes(self):
        self.install_license(["scopes"])
        self.key.sudo().write({"mcp_readonly": True})
        with self.assertRaises(ToolAccessError):
            self.gw._execute_tool(self.env.uid, "create_record",
                                  {"model": "res.partner",
                                   "values": {"name": "K"}},
                                  context=self._ctx())

    def test_model_limited_key(self):
        self.install_license(["scopes"])
        self.key.sudo().write({"mcp_models": "res.partner"})
        with self.assertRaises(ToolAccessError):
            self.gw._execute_tool(self.env.uid, "count_records",
                                  {"model": "res.users"}, context=self._ctx())
        res = self.gw._execute_tool(self.env.uid, "count_records",
                                    {"model": "res.partner"},
                                    context=self._ctx())
        self.assertGreaterEqual(res["count"], 0)

    def test_unscoped_key_unrestricted(self):
        self.install_license(["scopes"])
        res = self.gw._execute_tool(self.env.uid, "count_records",
                                    {"model": "res.users"},
                                    context=self._ctx())
        self.assertGreaterEqual(res["count"], 0)
