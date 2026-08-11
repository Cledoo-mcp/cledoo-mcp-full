# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
import datetime
import json

from odoo.tests import tagged
from odoo.tests.common import HttpCase

from odoo.addons.cledoo_mcp_full.lib import ratelimit


@tagged("post_install", "-at_install")
class TestEndpointActivity(HttpCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        icp = cls.env["ir.config_parameter"].sudo()
        icp.set_param("cledoo_mcp_full.enabled", "True")
        icp.set_param("cledoo_mcp_full.rate_limit", "0")
        gf = "group_ids" if "group_ids" in cls.env["res.users"]._fields else "groups_id"
        cls.user = cls.env["res.users"].create({
            "name": "Act User", "login": "mcp-act-user",
            gf: [(6, 0, [cls.env.ref("base.group_user").id])]})
        expiration = datetime.datetime.now() + datetime.timedelta(days=1)
        cls.key = cls.env["res.users.apikeys"].with_user(cls.user)._generate(
            None, "act-key", expiration)
        cls.env.flush_all()

    def setUp(self):
        super().setUp()
        ratelimit.reset()

    def _post(self, body, key=None):
        return self.url_open("/mcp", data=json.dumps(body), headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer %s" % (key or self.key)})

    def _row(self, principal):
        return self.env["mcp.endpoint.activity"].sudo().search(
            [("principal", "=", principal)])

    def test_apikey_calls_are_counted(self):
        principal = "apikey:%d" % self.user.id
        self._post({"jsonrpc": "2.0", "id": 1, "method": "ping"})
        self._post({"jsonrpc": "2.0", "id": 2, "method": "ping"})
        row = self._row(principal)
        self.assertEqual(row.call_count, 2)
        self.assertEqual(row.error_count, 0)
        self.assertEqual(row.kind, "apikey")
        self.assertEqual(row.user_id, self.user)
        self.assertTrue(row.last_used_at)

    def test_error_calls_bump_error_count(self):
        self._post({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "no_such_tool", "arguments": {}}})
        row = self._row("apikey:%d" % self.user.id)
        self.assertEqual(row.error_count, 1)
        self.assertEqual(row.call_count, 1)

    def test_oauth_token_gets_its_own_row(self):
        Token = self.env["mcp.oauth.token"]
        access, _refresh = Token._issue_pair("act-cid", self.user.id)
        self.env.flush_all()
        self._post({"jsonrpc": "2.0", "id": 1, "method": "ping"}, key=access)
        rec = Token.sudo().search(
            [("client_id", "=", "act-cid"), ("kind", "=", "access")], limit=1)
        row = self._row("token:%d" % rec.id)
        self.assertEqual(row.kind, "oauth")
        self.assertEqual(row.call_count, 1)
        self.assertEqual(row.token_id, rec)

    def test_activity_row_cascades_with_token(self):
        Token = self.env["mcp.oauth.token"]
        access, _refresh = Token._issue_pair("act-cid2", self.user.id)
        self.env.flush_all()
        self._post({"jsonrpc": "2.0", "id": 1, "method": "ping"}, key=access)
        rec = Token.sudo().search(
            [("client_id", "=", "act-cid2"), ("kind", "=", "access")], limit=1)
        principal = "token:%d" % rec.id
        self.assertTrue(self._row(principal))
        rec.sudo().unlink()
        self.assertFalse(self._row(principal))
