# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
from odoo.tests import tagged
from odoo.tests.common import TransactionCase


@tagged("post_install", "-at_install")
class TestOAuthAdmin(TransactionCase):
    def test_action_revoke_sets_flag_and_blocks_access(self):
        Tok = self.env["mcp.oauth.token"]
        access, _r = Tok._issue_pair("cid", self.env.uid)
        rec = Tok.sudo().search([("kind", "=", "access")], limit=1)
        rec.action_revoke()
        self.assertTrue(rec.revoked)
        self.assertIsNone(Tok._resolve_access(access))

    def test_action_revoke_kills_sibling_refresh_token(self):
        """Admin revoke must cut off the whole family: the list view only
        shows access tokens, and a surviving refresh token would let the
        client mint a fresh pair right after the admin clicked Revoke."""
        Tok = self.env["mcp.oauth.token"]
        access, refresh = Tok._issue_pair("cid2", self.env.uid)
        rec = Tok.sudo().search(
            [("kind", "=", "access"), ("client_id", "=", "cid2")], limit=1)
        rec.action_revoke()
        family = Tok.sudo().search([("pair_id", "=", rec.pair_id)])
        self.assertEqual(len(family), 2)
        self.assertTrue(all(family.mapped("revoked")))
        self.assertIsNone(Tok._rotate(refresh, "cid2"))

    def test_client_name_displayed_on_token(self):
        client = self.env["mcp.oauth.client"]._register_client(
            "Claude", ["https://claude.ai/cb"])
        Tok = self.env["mcp.oauth.token"]
        Tok._issue_pair(client.client_id, self.env.uid)
        rec = Tok.sudo().search(
            [("client_id", "=", client.client_id)], limit=1)
        self.assertEqual(rec.client_name, "Claude")
