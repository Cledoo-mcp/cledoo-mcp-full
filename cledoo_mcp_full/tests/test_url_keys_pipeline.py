# SPDX-License-Identifier: OPL-1.0
# Copyright (c) 2026 Cledoo
"""The Pro result pipeline (masking + audit) must preserve the
url/display_name keys the base tools now return; scope denials keep
raising ToolAccessError at the gateway seam (the base controller ships
those as isError:true results - wire shape covered in base
test_tool_error_results.py)."""
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib.tools import ToolAccessError
from odoo.addons.cledoo_mcp_full.tests.common import LicenseMixin


@tagged("post_install", "-at_install")
class TestUrlKeysPipeline(LicenseMixin, TransactionCase):
    def setUp(self):
        super().setUp()
        self.gw = self.env["mcp.gateway"]
        self.Rule = self.env["mcp.mask.rule"].sudo()
        self.ctx = {"principal": {"kind": "apikey", "uid": self.env.uid,
                                  "token_id": None, "apikey_id": None}}

    def test_masked_get_record_keeps_url(self):
        self.install_license(["masking"])
        self.Rule.create({"model_name": "res.partner",
                          "field_name": "email", "strategy": "redact"})
        p = self.env["res.partner"].create(
            {"name": "Masky Co", "email": "masky@example.com"})
        res = self.gw._execute_tool(
            self.env.uid, "get_record",
            {"model": "res.partner", "record_id": p.id,
             "fields": ["name", "email"]}, context=self.ctx)
        self.assertNotIn("masky@example.com", str(res))
        self.assertIn("url", res)
        self.assertIn("/odoo/res.partner/%d" % p.id, res["url"])

    def test_create_through_pipeline_returns_url_and_display_name(self):
        self.install_license(["masking"])
        res = self.gw._execute_tool(
            self.env.uid, "create_record",
            {"model": "res.partner", "values": {"name": "Piped Co"}},
            context=self.ctx)
        self.assertEqual(res["display_name"], "Piped Co")
        self.assertIn("url", res)

    def test_readonly_scope_still_denies_create(self):
        self.install_license(["scopes"])
        self.env["mcp.oauth.token"].sudo()._issue_pair(
            "client-d1", self.env.uid, scope_vals={"scope_readonly": True})
        tok = self.env["mcp.oauth.token"].sudo().search(
            [("kind", "=", "access")], order="id desc", limit=1)
        ctx = {"principal": {"kind": "oauth", "uid": self.env.uid,
                             "token_id": tok.id, "apikey_id": None}}
        with self.assertRaises(ToolAccessError):
            self.gw._execute_tool(self.env.uid, "create_record",
                                  {"model": "res.partner",
                                   "values": {"name": "Denied Co"}},
                                  context=ctx)
