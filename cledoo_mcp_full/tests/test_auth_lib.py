# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Coverage for `lib/auth.py`'s `resolve_api_key`.

`resolve_api_key` maps a bearer token straight onto Odoo's native
`res.users.apikeys` model -- no custom token storage. Odoo owns hashing,
indexing and constant-time comparison of the key itself; this module only
adapts `_check_credentials`'s uid-or-False return into `uid | None` and
adds the inactive-user refusal that `_check_credentials` does not perform
on its own (it only validates the key, not the user's `active` flag).

The key literal argument shapes below are spike-pinned in
docs/superpowers/lite-wiring-notes.md against both Odoo 18 and Odoo 19
container sources (`res.users.apikeys._generate` /
`._check_credentials`), confirmed identical across both versions.
"""
import datetime

from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib.auth import resolve_api_key


@tagged("post_install", "-at_install")
class TestResolveApiKey(TransactionCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        gf = "group_ids" if "group_ids" in cls.env["res.users"]._fields else "groups_id"
        cls.user = cls.env["res.users"].create({
            "name": "MCP User", "login": "mcp-auth-user",
            gf: [(6, 0, [cls.env.ref("base.group_user").id])],
        })
        # Spike-pinned: _generate(scope, name, expiration_date) is positional
        # on both 18 and 19. UI-created keys ("New API Key" wizard, see
        # res.users.apikeys.description.make_key) always call with
        # scope=None -- a global key -- so that's what we replicate here to
        # match how a real user's key would look. A non-system user must
        # supply an expiration_date within their group's api_key_duration
        # ceiling (_check_expiration_date) -- base.group_user defaults to
        # 90 days, so 1 day out is always safe.
        cls.key = cls.env["res.users.apikeys"].with_user(cls.user)._generate(
            *cls._generate_args())

    @classmethod
    def _generate_args(cls):
        expiration = datetime.datetime.now() + datetime.timedelta(days=1)
        return (None, "test-key", expiration)

    def test_valid_key_resolves_uid(self):
        self.assertEqual(resolve_api_key(self.env, self.key), self.user.id)

    def test_bad_key_returns_none(self):
        self.assertIsNone(resolve_api_key(self.env, "not-a-key"))

    def test_empty_and_none_return_none(self):
        self.assertIsNone(resolve_api_key(self.env, ""))
        self.assertIsNone(resolve_api_key(self.env, None))

    def test_inactive_user_rejected(self):
        self.user.active = False
        self.assertIsNone(resolve_api_key(self.env, self.key))
