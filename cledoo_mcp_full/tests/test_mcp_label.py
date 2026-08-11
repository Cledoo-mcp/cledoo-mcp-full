# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""A8 MCP label: write-tool calls carry the principal in the seam context;
mail.message rows created inside them are stamped with the client name so
the chatter badge can render it."""
from datetime import timedelta

from odoo.fields import Datetime
from odoo.tests import tagged
from odoo.tests.common import TransactionCase


@tagged("post_install", "-at_install")
class TestMcpLabel(TransactionCase):
    def setUp(self):
        super().setUp()
        self.partner = self.env["res.partner"].create({"name": "Label Co"})
        self.gw = self.env["mcp.gateway"]
        self.icp = self.env["ir.config_parameter"].sudo()
        self.ctx = {"session_id": "s", "remote_addr": "127.0.0.1",
                    "request_id": 1,
                    "principal": {"kind": "apikey", "uid": self.env.uid,
                                  "token_id": None}}

    def _post(self, context):
        res = self.gw._execute_tool(
            self.env.uid, "post_message",
            {"model": "res.partner", "record_id": self.partner.id,
             "body": "labelled"}, context=context)
        return self.env["mail.message"].browse(res["message_id"])

    def test_apikey_label_stamped(self):
        msg = self._post(self.ctx)
        self.assertEqual(msg.mcp_name, self.env.user.login)

    def test_oauth_label_is_client_name(self):
        client = self.env["mcp.oauth.client"].sudo()._register_client(
            "Claude", ["https://claude.ai/api/mcp/auth_callback"])
        tok = self.env["mcp.oauth.token"].sudo().create({
            "token_hash": "x" * 64, "kind": "access", "pair_id": "p1",
            "client_id": client["client_id"], "user_id": self.env.uid,
            "expires_at": Datetime.now() + timedelta(hours=1)})
        ctx = dict(self.ctx, principal={"kind": "oauth",
                                        "uid": self.env.uid,
                                        "token_id": tok.id})
        msg = self._post(ctx)
        self.assertEqual(msg.mcp_name, "Claude")

    def test_toggle_off_no_label(self):
        self.icp.set_param("cledoo_mcp_full.annotate_messages", "False")
        msg = self._post(self.ctx)
        self.assertFalse(msg.mcp_name)
        self.icp.set_param("cledoo_mcp_full.annotate_messages", "True")

    def test_no_principal_no_label(self):
        msg = self._post({"session_id": None})
        self.assertFalse(msg.mcp_name)

    def test_ui_message_untouched(self):
        self.partner.message_post(body="human note")
        msg = self.partner.message_ids[0]
        self.assertFalse(msg.mcp_name)

    def test_field_tracking_also_stamped(self):
        # tracking messages created inside the same write-tool call must
        # carry the label too (create override, not message_post plumbing)
        ctx_env_msg = self._post(self.ctx)
        self.assertTrue(ctx_env_msg.mcp_name)
        res = self.gw._execute_tool(
            self.env.uid, "update_record",
            {"model": "res.partner", "record_id": self.partner.id,
             "values": {"name": "Label Co Renamed"}}, context=self.ctx)
        self.assertTrue(res["updated"])

    def test_only_comments_and_notifications_stamped(self):
        # The namespaced context key rides into every message created
        # during the call. Only agent-authored types (comment, notification)
        # get stamped; a side-effect outbound email must stay blank.
        Msg = self.env["mail.message"].with_context(cledoo_mcp_name="Claude")
        comment = Msg.create({"model": "res.partner",
                              "res_id": self.partner.id,
                              "message_type": "comment", "body": "c"})
        notif = Msg.create({"model": "res.partner",
                            "res_id": self.partner.id,
                            "message_type": "notification", "body": "n"})
        email = Msg.create({"model": "res.partner",
                            "res_id": self.partner.id,
                            "message_type": "email", "body": "e"})
        self.assertEqual(comment.mcp_name, "Claude")
        self.assertEqual(notif.mcp_name, "Claude")
        self.assertFalse(email.mcp_name)

    def test_old_bare_context_key_ignored(self):
        # The pre-namespacing key must no longer stamp (guards against a
        # stale caller silently leaking the badge).
        msg = self.env["mail.message"].with_context(mcp_name="Ghost").create(
            {"model": "res.partner", "res_id": self.partner.id,
             "message_type": "comment", "body": "x"})
        self.assertFalse(msg.mcp_name)
