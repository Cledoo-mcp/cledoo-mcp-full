# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib import tools as T


@tagged("post_install", "-at_install")
class TestGetMessages(TransactionCase):
    def call(self, name, **kw):
        fn, _s, _a = T.TOOLS[name]
        return fn(self.env, self.env.uid, **kw)

    def setUp(self):
        super().setUp()
        self.partner = self.env["res.partner"].create({"name": "Chatter Co"})
        self.partner.message_post(body="first note",
                                  subtype_xmlid="mail.mt_note")
        self.partner.message_post(body="second note",
                                  subtype_xmlid="mail.mt_note")

    def test_messages_newest_first(self):
        res = self.call("get_messages", model="res.partner",
                        record_id=self.partner.id)
        bodies = [m["body"] for m in res["messages"]]
        self.assertTrue(any("second note" in b for b in bodies[:1]))
        for m in res["messages"]:
            for key in ("id", "date", "author", "type", "body"):
                self.assertIn(key, m)

    def test_limit_clamped(self):
        res = self.call("get_messages", model="res.partner",
                        record_id=self.partner.id, limit=1)
        self.assertEqual(len(res["messages"]), 1)

    def test_model_without_chatter(self):
        with self.assertRaises(T.ToolUserError) as ctx:
            self.call("get_messages", model="ir.model",
                      record_id=self.env["ir.model"].search([], limit=1).id)
        self.assertIn("chatter", ctx.exception.message)

    def test_missing_record(self):
        with self.assertRaises(T.ToolUserError):
            self.call("get_messages", model="res.partner", record_id=99999999)


@tagged("post_install", "-at_install")
class TestPostMessage(TransactionCase):
    def call(self, **kw):
        fn, _s, _a = T.TOOLS["post_message"]
        return fn(self.env, self.env.uid, **kw)

    def setUp(self):
        super().setUp()
        self.partner = self.env["res.partner"].create({"name": "Post Co"})

    def test_post_note(self):
        res = self.call(model="res.partner", record_id=self.partner.id,
                        body="agent was here")
        msg = self.env["mail.message"].browse(res["message_id"])
        self.assertIn("agent was here", str(msg.body))
        self.assertEqual(msg.message_type, "comment")
        self.assertEqual(msg.subtype_id, self.env.ref("mail.mt_note"))

    def test_body_required(self):
        with self.assertRaises(T.ToolInvalidParamsError):
            self.call(model="res.partner", record_id=self.partner.id,
                      body="  ")

    def test_no_chatter_model(self):
        rec = self.env["ir.model"].search([], limit=1)
        with self.assertRaises(T.ToolUserError):
            self.call(model="ir.model", record_id=rec.id, body="x")

    def test_missing_record(self):
        with self.assertRaises(T.ToolUserError):
            self.call(model="res.partner", record_id=99999999, body="x")

    def test_is_write_tool(self):
        _fn, _s, ann = T.TOOLS["post_message"]
        self.assertFalse(ann["readOnlyHint"])
