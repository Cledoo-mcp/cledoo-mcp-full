import unittest
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Additive seam hooks for MCP Pro: consent scope_vals pass-through and
apikey identity in bearer details. Lite behavior must be unchanged."""
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib.auth import resolve_bearer_details


@tagged("post_install", "-at_install")
class TestSeamScopeHooks(TransactionCase):
    @unittest.skip("free-only seam default; the pro overrides are active in the merged build (covered by the pro suite)")
    def test_gateway_consent_scope_vals_default_empty(self):
        self.assertEqual(
            self.env["mcp.gateway"]._consent_scope_vals({"scope": "x"}), {})

    def test_code_scope_vals_default_empty(self):
        raw = self.env["mcp.oauth.code"]._issue(
            "client-a", self.env.uid, "https://x/cb", "chal", None)
        rec = self.env["mcp.oauth.code"].sudo().search(
            [], order="id desc", limit=1)
        self.assertTrue(raw)
        self.assertEqual(rec._scope_vals(), {})

    def test_issue_accepts_scope_vals_kwarg(self):
        # unknown-column scope_vals would crash create(); empty dict is
        # the lite contract — the kwarg must exist and default to None
        self.env["mcp.oauth.code"]._issue(
            "client-a", self.env.uid, "https://x/cb", "chal", None,
            scope_vals={})
        self.env["mcp.oauth.token"]._issue_pair(
            "client-a", self.env.uid, scope_vals={})

    def test_apikey_details_carry_key_id(self):
        # uid=2 ("admin") is the real, active seed user in the test DB --
        # self.env.uid (uid=1, "__system__") is inactive by design in a
        # fresh Odoo DB (see test_auth_resolve_bearer.py), so API-key
        # resolution correctly refuses it; that's unrelated to this seam.
        import datetime
        expiration = datetime.datetime.now() + datetime.timedelta(days=1)
        key = self.env["res.users.apikeys"].with_user(2)
        # _generate(scope, name, expiration_date) — positional on 18+19
        raw = key._generate(None, "seam-test", expiration)
        details = resolve_bearer_details(self.env, raw)
        self.assertEqual(details["kind"], "apikey")
        rec = self.env["res.users.apikeys"].sudo().search(
            [("name", "=", "seam-test")], limit=1)
        self.assertEqual(details["apikey_id"], rec.id)

    def test_oauth_details_apikey_id_is_none(self):
        access, _refresh = self.env["mcp.oauth.token"]._issue_pair(
            "client-b", 2)
        details = resolve_bearer_details(self.env, access)
        self.assertEqual(details["kind"], "oauth")
        self.assertIsNone(details["apikey_id"])
