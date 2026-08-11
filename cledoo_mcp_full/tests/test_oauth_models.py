# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
import base64
import hashlib

from odoo.tests import tagged
from odoo.tests.common import TransactionCase


@tagged("post_install", "-at_install")
class TestOAuthModels(TransactionCase):
    def _challenge(self, verifier):
        return base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()

    def test_client_register_and_redirect_check(self):
        c = self.env["mcp.oauth.client"]._register_client("Claude", ["https://c.ai/cb"])
        self.assertTrue(c.client_id)
        self.assertTrue(c._redirect_ok("https://c.ai/cb"))
        self.assertFalse(c._redirect_ok("https://evil/cb"))
        self.assertEqual(self.env["mcp.oauth.client"]._get(c.client_id), c)

    def test_code_single_use_and_match(self):
        Code = self.env["mcp.oauth.code"]
        raw = Code._issue("cid", 2, "https://c.ai/cb", self._challenge("v"), None)
        self.assertIsNone(Code._consume(raw, "cid", "https://evil"))   # wrong redirect
        self.assertIsNone(Code._consume(raw, "other", "https://c.ai/cb"))  # wrong client
        rec = Code._consume(raw, "cid", "https://c.ai/cb")
        self.assertTrue(rec)
        self.assertIsNone(Code._consume(raw, "cid", "https://c.ai/cb"))  # single-use

    def test_token_issue_resolve_and_rotate_family_revocation(self):
        Tok = self.env["mcp.oauth.token"]
        access, refresh = Tok._issue_pair("cid", 2)
        self.assertEqual(Tok._resolve_access(access), 2)
        new_access, new_refresh = Tok._rotate(refresh, "cid")
        self.assertEqual(Tok._resolve_access(new_access), 2)
        self.assertIsNone(Tok._resolve_access(access))  # old access revoked by rotation
        # reuse of the now-rotated refresh -> whole new family revoked
        self.assertIsNone(Tok._rotate(refresh, "cid"))
        self.assertIsNone(Tok._resolve_access(new_access))

    def test_multiple_sequential_rotations_work(self):
        Tok = self.env["mcp.oauth.token"]
        access0, refresh0 = Tok._issue_pair("cid", 2)
        # rotate 3 times in sequence, each new refresh must keep working
        a1, r1 = Tok._rotate(refresh0, "cid")
        self.assertEqual(Tok._resolve_access(a1), 2)
        a2, r2 = Tok._rotate(r1, "cid")
        self.assertEqual(Tok._resolve_access(a2), 2)
        self.assertIsNone(Tok._resolve_access(a1))  # prior generation dead
        a3, r3 = Tok._rotate(r2, "cid")
        self.assertEqual(Tok._resolve_access(a3), 2)
        # reuse of any stale ancestor refresh (r1) now nukes the whole family
        self.assertIsNone(Tok._rotate(r1, "cid"))
        self.assertIsNone(Tok._resolve_access(a3))
