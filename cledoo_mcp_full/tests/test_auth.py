import unittest
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""End-to-end coverage for `controllers/mcp.py`'s API-key auth + enable gate.

Auth now resolves against native Odoo API keys (lib/auth.resolve_api_key),
not the retired `dev_tokens` static map. We drive it through the real
`/mcp` controller with `HttpCase.url_open` to prove the whole path: the
`cledoo_mcp_full.enabled` 404 gate (checked before auth), header parsing,
`Bearer ` prefix stripping, API-key lookup, and the 401 response shape --
matching how a real MCP client would hit the endpoint.
"""
import datetime
import json

from odoo.tests import tagged
from odoo.tests.common import HttpCase


@tagged("post_install", "-at_install")
class TestMcpHttpAuth(HttpCase):
    # Class-level setup (mirrors the retired dev_tokens HttpCase suite,
    # TestResolveBearer): HttpCase puts the registry in "test mode"
    # (registry_enter_test_mode_cls), so the HTTP worker's TestCursor wraps
    # the SAME underlying cursor as cls.cr. Data created in setUpClass and
    # flushed is visible to that worker without any commit -- TransactionCase
    # only opens the per-test savepoint (and blocks cr.commit/rollback)
    # inside setUp, which runs *after* setUpClass. Calling cr.commit() here
    # (or in setUp) would hit that guard ("Cannot commit or rollback a
    # cursor from inside a test").
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.env["ir.config_parameter"].sudo().set_param(
            "cledoo_mcp_full.enabled", "True")
        gf = "group_ids" if "group_ids" in cls.env["res.users"]._fields else "groups_id"
        cls.user = cls.env["res.users"].create({
            "name": "HTTP MCP", "login": "mcp-http-user",
            gf: [(6, 0, [cls.env.ref("base.group_user").id])]})
        # Spike-pinned call shape (see lib/auth.py docstring and
        # tests/test_auth_lib.py): _generate(scope, name, expiration_date)
        # is positional on both Odoo 18 and 19; UI-created keys always pass
        # scope=None (a global key).
        cls.key = cls.env["res.users.apikeys"].with_user(cls.user)._generate(
            *cls._generate_args())
        cls.env.flush_all()

    @classmethod
    def _generate_args(cls):
        expiration = datetime.datetime.now() + datetime.timedelta(days=1)
        return (None, "test-key", expiration)

    def _set_enabled(self, value):
        self.env["ir.config_parameter"].sudo().set_param(
            "cledoo_mcp_full.enabled", value)
        self.env.flush_all()

    def _post(self, body, key=None):
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = "Bearer %s" % key
        return self.url_open("/mcp", data=json.dumps(body), headers=headers)

    def test_no_token_401_with_discovery_header(self):
        r = self._post({"jsonrpc": "2.0", "id": 1, "method": "ping"})
        self.assertEqual(r.status_code, 401)
        self.assertIn("resource_metadata", r.headers.get("WWW-Authenticate", ""))

    def test_bad_token_401(self):
        r = self._post({"jsonrpc": "2.0", "id": 1, "method": "ping"}, key="wrong")
        self.assertEqual(r.status_code, 401)

    @unittest.skip("free-only seam default; the pro overrides are active in the merged build (covered by the pro suite)")
    def test_valid_key_tools_list_matches_registry(self):
        from odoo.addons.cledoo_mcp_full.lib.tools import TOOLS
        r = self._post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, key=self.key)
        self.assertEqual(r.status_code, 200)
        tools = r.json()["result"]["tools"]
        self.assertEqual(len(tools), len(TOOLS))
        # MCP 2025-06-18 annotations must reach the wire (trust UI + the
        # consent page derive from them)
        by_name = {t["name"]: t for t in tools}
        self.assertTrue(by_name["search_records"]["annotations"]["readOnlyHint"])
        self.assertTrue(by_name["delete_record"]["annotations"]["destructiveHint"])

    def test_valid_key_initialize_reports_manifest_version(self):
        from odoo.modules.module import get_manifest
        manifest_version = get_manifest("cledoo_mcp_full")["version"]

        r = self._post(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, key=self.key)
        self.assertEqual(r.status_code, 200)
        server_info = r.json()["result"]["serverInfo"]
        self.assertNotEqual(server_info["version"], "1.0.0")
        self.assertEqual(server_info["version"], manifest_version)

    def test_disabled_module_404(self):
        self._set_enabled("False")
        r = self._post({"jsonrpc": "2.0", "id": 1, "method": "ping"}, key=self.key)
        self.assertEqual(r.status_code, 404)

    def test_disabled_module_404_before_auth_check(self):
        # 404 must win even with no Authorization header at all -- the
        # enable gate runs before auth, not after.
        self._set_enabled("False")
        r = self._post({"jsonrpc": "2.0", "id": 1, "method": "ping"})
        self.assertEqual(r.status_code, 404)
