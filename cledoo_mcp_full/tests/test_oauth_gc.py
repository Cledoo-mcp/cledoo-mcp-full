# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
from datetime import timedelta

from odoo.fields import Datetime
from odoo.tests import tagged
from odoo.tests.common import TransactionCase


@tagged("post_install", "-at_install")
class TestOAuthGc(TransactionCase):
    def test_gc_expired_codes(self):
        Code = self.env["mcp.oauth.code"]
        Code._issue("cid", self.env.uid, "https://c.ai/cb", "chal", None)
        rec = Code.sudo().search([("client_id", "=", "cid")], limit=1)
        rec.sudo().write({"expires_at": Datetime.now() - timedelta(minutes=1)})
        Code._gc_expired_codes()
        self.assertFalse(rec.exists())

    def test_gc_keeps_live_codes(self):
        Code = self.env["mcp.oauth.code"]
        Code._issue("cid-live", self.env.uid, "https://c.ai/cb", "chal", None)
        Code._gc_expired_codes()
        self.assertTrue(Code.sudo().search([("client_id", "=", "cid-live")]))

    def test_gc_tokens_grace_period(self):
        Tok = self.env["mcp.oauth.token"]
        Tok._issue_pair("cid-gc", self.env.uid)
        family = Tok.sudo().search([("client_id", "=", "cid-gc")])
        self.assertEqual(len(family), 2)
        # freshly revoked -> kept (reuse-detection needs it)
        family.write({"revoked": True})
        Tok._gc_dead_tokens()
        self.assertEqual(len(family.exists()), 2)
        # revoked past the grace period -> collected
        self.env.cr.execute(
            "UPDATE mcp_oauth_token SET write_date = %s WHERE id IN %s",
            (Datetime.now() - timedelta(days=31), tuple(family.ids)))
        family.invalidate_recordset()
        Tok._gc_dead_tokens()
        self.assertFalse(family.exists())

    def test_gc_long_expired_tokens(self):
        Tok = self.env["mcp.oauth.token"]
        Tok._issue_pair("cid-exp", self.env.uid)
        family = Tok.sudo().search([("client_id", "=", "cid-exp")])
        family.write({"expires_at": Datetime.now() - timedelta(days=31)})
        Tok._gc_dead_tokens()
        self.assertFalse(family.exists())

    def test_gc_dormant_clients(self):
        Client = self.env["mcp.oauth.client"]
        dormant = Client._register_client("Bot", ["https://spam.example/cb"])
        active = Client._register_client("Claude", ["https://claude.ai/cb"])
        self.env["mcp.oauth.token"]._issue_pair(active.client_id, self.env.uid)
        old = Datetime.now() - timedelta(days=31)
        self.env.cr.execute(
            "UPDATE mcp_oauth_client SET create_date = %s WHERE id IN %s",
            (old, tuple((dormant | active).ids)))
        (dormant | active).invalidate_recordset()
        Client._gc_dormant_clients()
        self.assertFalse(dormant.exists())   # no token, no code -> collected
        self.assertTrue(active.exists())     # has a token -> kept
