# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
import base64
import hashlib

from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib import oauth_tokens as T


@tagged("post_install", "-at_install")
class TestOAuthTokens(TransactionCase):
    def test_secret_unique_and_urlsafe(self):
        a, b = T.new_secret(), T.new_secret()
        self.assertNotEqual(a, b)
        self.assertNotIn("/", a)
        self.assertNotIn("+", a)

    def test_hash_is_sha256_hex(self):
        self.assertEqual(T.hash_secret("x"),
                         hashlib.sha256(b"x").hexdigest())

    def test_verify_pkce_s256_ok(self):
        verifier = "verifier-abc-123"
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        self.assertTrue(T.verify_pkce(verifier, challenge))

    def test_verify_pkce_rejects_mismatch_and_empty(self):
        self.assertFalse(T.verify_pkce("a", "wrong"))
        self.assertFalse(T.verify_pkce("", "x"))
        self.assertFalse(T.verify_pkce("a", ""))
