# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Coverage for `lib/auth.py`'s `resolve_bearer`.

`resolve_bearer` widens what a `/mcp` bearer token can be: it tries the
native Odoo API key path first (`resolve_api_key`, unchanged), then falls
back to an OAuth access token (`mcp.oauth.token._resolve_access`). Both
`resolve_api_key` and the OAuth token model already refuse inactive users
on their own, so this wrapper adds no extra active-user check -- it only
composes the two lookups with API-key-first ordering, preserving all
existing `/mcp` API-key auth behavior (see tests/test_auth.py).
"""
import datetime

from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib.auth import resolve_bearer


@tagged("post_install", "-at_install")
class TestResolveBearer(TransactionCase):
    def test_oauth_access_token_resolves(self):
        # uid=2 ("admin") is the real, active seed user in the test DB --
        # matches the convention in tests/test_oauth_models.py. self.env.uid
        # (uid=1, "__system__") is NOT usable here: that user is inactive
        # by design in a fresh Odoo DB, so _resolve_access's active-user
        # check would correctly refuse it -- an unrelated behavior, not a
        # resolve_bearer bug.
        access, _refresh = self.env["mcp.oauth.token"]._issue_pair("cid", 2)
        self.assertEqual(resolve_bearer(self.env, access), 2)

    def test_api_key_still_resolves(self):
        gf = "group_ids" if "group_ids" in self.env["res.users"]._fields else "groups_id"
        user = self.env["res.users"].create({
            "name": "K", "login": "rb-apikey-user",
            gf: [(6, 0, [self.env.ref("base.group_user").id])]})
        expiration = datetime.datetime.now() + datetime.timedelta(days=1)
        key = self.env["res.users.apikeys"].with_user(user)._generate(
            None, "rb", expiration)
        self.assertEqual(resolve_bearer(self.env, key), user.id)

    def test_garbage_and_empty_return_none(self):
        self.assertIsNone(resolve_bearer(self.env, "not-a-token"))
        self.assertIsNone(resolve_bearer(self.env, ""))
        self.assertIsNone(resolve_bearer(self.env, None))
