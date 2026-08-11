# SPDX-License-Identifier: OPL-1.0
# Copyright (c) 2026 Cledoo
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib.tools import ToolAccessError
from odoo.addons.cledoo_mcp_full.tests.common import LicenseMixin


@tagged("post_install", "-at_install")
class TestOauthScopes(LicenseMixin, TransactionCase):
    def setUp(self):
        super().setUp()
        self.gw = self.env["mcp.gateway"]
        self.Token = self.env["mcp.oauth.token"].sudo()

    def _ctx(self, token_rec):
        return {"principal": {"kind": "oauth", "uid": self.env.uid,
                              "token_id": token_rec.id, "apikey_id": None}}

    def _make_token(self, **scope_vals):
        self.Token._issue_pair("client-s", self.env.uid,
                               scope_vals=scope_vals)
        return self.Token.search([("kind", "=", "access")],
                                 order="id desc", limit=1)

    def test_readonly_token_blocks_writes(self):
        self.install_license(["scopes"])
        tok = self._make_token(scope_readonly=True)
        with self.assertRaises(ToolAccessError) as ctx:
            self.gw._execute_tool(self.env.uid, "create_record",
                                  {"model": "res.partner",
                                   "values": {"name": "X"}},
                                  context=self._ctx(tok))
        self.assertIn("read-only", ctx.exception.message)

    def test_readonly_token_allows_reads(self):
        self.install_license(["scopes"])
        tok = self._make_token(scope_readonly=True)
        res = self.gw._execute_tool(self.env.uid, "count_records",
                                    {"model": "res.partner"},
                                    context=self._ctx(tok))
        self.assertGreaterEqual(res["count"], 0)

    def test_model_scoped_token_blocks_other_models(self):
        self.install_license(["scopes"])
        tok = self._make_token(scope_models="res.partner")
        with self.assertRaises(ToolAccessError):
            self.gw._execute_tool(self.env.uid, "count_records",
                                  {"model": "res.users"},
                                  context=self._ctx(tok))
        res = self.gw._execute_tool(self.env.uid, "count_records",
                                    {"model": "res.partner"},
                                    context=self._ctx(tok))
        self.assertGreaterEqual(res["count"], 0)

    def test_unscoped_token_unrestricted(self):
        self.install_license(["scopes"])
        tok = self._make_token()
        res = self.gw._execute_tool(self.env.uid, "count_records",
                                    {"model": "res.users"},
                                    context=self._ctx(tok))
        self.assertGreaterEqual(res["count"], 0)

    def test_consent_scope_vals_mapping(self):
        self.install_license(["scopes"])
        vals = self.gw._consent_scope_vals({
            "pro_scope": "readonly", "pro_scope_models": "res.partner,crm.lead"})
        self.assertEqual(vals, {"scope_readonly": True,
                                "scope_models": "res.partner,crm.lead"})
        self.assertEqual(self.gw._consent_scope_vals({"pro_scope": "full"}),
                         {"scope_readonly": False, "scope_models": False})

    def test_rotation_preserves_scopes(self):
        self.install_license(["scopes"])
        access, refresh = self.Token._issue_pair(
            "client-r", self.env.uid,
            scope_vals={"scope_readonly": True})
        pair = self.Token._rotate(refresh, "client-r")
        self.assertTrue(pair)
        new_access = self.Token.search(
            [("kind", "=", "access"), ("revoked", "=", False),
             ("client_id", "=", "client-r")], order="id desc", limit=1)
        self.assertTrue(new_access.scope_readonly)
