# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
import base64

from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib import tools as T

# Real 1x1 transparent PNG (valid magic bytes, decodable by image.mixin).
PNG_B64 = ("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"
           "YPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")
PNG_BYTES = base64.b64decode(PNG_B64)


@tagged("post_install", "-at_install")
class TestReadResource(TransactionCase):
    def call(self, **kw):
        fn, _s, _a = T.TOOLS["read_resource"]
        return fn(self.env, self.env.uid, **kw)

    def _attach(self, name, raw, mimetype):
        return self.env["ir.attachment"].create(
            {"name": name, "raw": raw, "mimetype": mimetype})

    def test_text_attachment_roundtrip(self):
        att = self._attach("notes.txt", b"hello resource", "text/plain")
        res = self.call(uri="odoo://attachment/%d" % att.id)
        self.assertEqual(res["mimetype"], "text/plain")
        self.assertEqual(res["size_bytes"], len(b"hello resource"))
        self.assertEqual(res["name"], "notes.txt")
        self.assertEqual(res["uri"], "odoo://attachment/%d" % att.id)
        blocks = res["__mcp_content__"]
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0]["type"], "text")
        self.assertEqual(blocks[0]["text"], "hello resource")

    def test_text_attachment_truncated(self):
        big = b"x" * 150_000
        att = self._attach("big.txt", big, "text/plain")
        res = self.call(uri="odoo://attachment/%d" % att.id)
        block = res["__mcp_content__"][0]
        self.assertEqual(block["type"], "text")
        self.assertLess(len(block["text"]), 150_000)
        self.assertIn("truncated", block["text"])
        self.assertIn("150000", block["text"])
        self.assertEqual(res["size_bytes"], 150_000)

    def test_image_attachment_image_block(self):
        att = self._attach("dot.png", PNG_BYTES, "image/png")
        res = self.call(uri="odoo://attachment/%d" % att.id)
        block = res["__mcp_content__"][0]
        self.assertEqual(block["type"], "image")
        self.assertEqual(block["mimeType"], "image/png")
        self.assertEqual(base64.b64decode(block["data"]), PNG_BYTES)

    def test_audio_attachment_audio_block(self):
        att = self._attach("beep.mp3", b"\xff\xfb\x90\x00" + b"\x00" * 32,
                           "audio/mpeg")
        res = self.call(uri="odoo://attachment/%d" % att.id)
        block = res["__mcp_content__"][0]
        self.assertEqual(block["type"], "audio")
        self.assertEqual(block["mimeType"], "audio/mpeg")

    def test_binary_attachment_resource_block(self):
        att = self._attach("data.bin", b"\x00\x01\x02\x03binary",
                           "application/octet-stream")
        uri = "odoo://attachment/%d" % att.id
        res = self.call(uri=uri)
        block = res["__mcp_content__"][0]
        self.assertEqual(block["type"], "resource")
        self.assertEqual(block["resource"]["uri"], uri)
        self.assertEqual(block["resource"]["mimeType"],
                         "application/octet-stream")
        self.assertEqual(base64.b64decode(block["resource"]["blob"]),
                         b"\x00\x01\x02\x03binary")

    def test_record_binary_field(self):
        partner = self.env["res.partner"].create(
            {"name": "Res Co", "image_1920": PNG_B64})
        res = self.call(
            uri="odoo://record/res.partner/%d/image_1920" % partner.id)
        block = res["__mcp_content__"][0]
        self.assertEqual(block["type"], "image")
        self.assertEqual(block["mimeType"], "image/png")
        self.assertEqual(res["mimetype"], "image/png")
        self.assertTrue(base64.b64decode(block["data"]).startswith(
            b"\x89PNG"))

    def test_unknown_attachment(self):
        with self.assertRaises(T.ToolUserError):
            self.call(uri="odoo://attachment/999999999")

    def test_unknown_record(self):
        with self.assertRaises(T.ToolUserError):
            self.call(uri="odoo://record/res.partner/999999999/image_1920")

    def test_malformed_uri(self):
        for uri in ("http://x/1", "odoo://foo/1", "odoo://attachment",
                    "odoo://record/res.partner/1", "", "odoo://attachment/x/y"):
            with self.assertRaises(T.ToolInvalidParamsError, msg=uri):
                self.call(uri=uri)

    def test_malformed_uri_names_accepted_forms(self):
        with self.assertRaises(T.ToolInvalidParamsError) as cm:
            self.call(uri="odoo://nope/1")
        self.assertIn("odoo://attachment/<id>", cm.exception.message)
        self.assertIn("odoo://record/<model>/<id>/<field>", cm.exception.message)

    def test_non_binary_field(self):
        partner = self.env["res.partner"].create({"name": "Txt Co"})
        with self.assertRaises(T.ToolInvalidParamsError) as cm:
            self.call(uri="odoo://record/res.partner/%d/name" % partner.id)
        self.assertIn("char", cm.exception.message)

    def test_unknown_field(self):
        partner = self.env["res.partner"].create({"name": "Fld Co"})
        with self.assertRaises(T.ToolInvalidParamsError):
            self.call(uri="odoo://record/res.partner/%d/nope" % partner.id)

    def test_empty_binary_field(self):
        partner = self.env["res.partner"].create({"name": "Empty Co"})
        with self.assertRaises(T.ToolUserError):
            self.call(uri="odoo://record/res.partner/%d/image_1920"
                          % partner.id)

    def test_too_large(self):
        att = self._attach("huge.bin", b"z" * (5 * 1024 * 1024 + 1),
                           "application/octet-stream")
        with self.assertRaises(T.ToolUserError) as cm:
            self.call(uri="odoo://attachment/%d" % att.id)
        self.assertIn("limit", cm.exception.message)

    def test_configured_limit_enforced(self):
        # A 2 MB attachment: allowed under the 5 MB default, refused once
        # the admin lowers the ceiling to 1 MB.
        att = self._attach("mid.bin", b"z" * (2 * 1024 * 1024),
                           "application/octet-stream")
        self.assertTrue(self.call(uri="odoo://attachment/%d" % att.id))
        self.env["ir.config_parameter"].sudo().set_param(
            "cledoo_mcp_full.max_inline_mb", "1")
        with self.assertRaises(T.ToolUserError):
            self.call(uri="odoo://attachment/%d" % att.id)

    def test_reject_helper_reads_param(self):
        icp = self.env["ir.config_parameter"].sudo()
        icp.set_param("cledoo_mcp_full.max_inline_mb", "1")
        with self.assertRaises(T.ToolUserError):
            T._reject_if_too_large(self.env, 2 * 1024 * 1024, "Export")
        T._reject_if_too_large(self.env, 500, "Export")  # under limit: ok

    def test_reject_helper_ignores_zero(self):
        # A 0/negative override must not silently refuse everything.
        self.env["ir.config_parameter"].sudo().set_param(
            "cledoo_mcp_full.max_inline_mb", "0")
        T._reject_if_too_large(self.env, 2 * 1024 * 1024)  # default 5 MB

    def test_gateway_returns_sentinel(self):
        att = self._attach("gw.txt", b"via gateway", "text/plain")
        data = self.env["mcp.gateway"]._execute_tool(
            self.env.uid, "read_resource",
            {"uri": "odoo://attachment/%d" % att.id})
        self.assertIn("__mcp_content__", data)
        self.assertEqual(data["__mcp_content__"][0]["type"], "text")

    def test_controller_content_blocks_passthrough(self):
        from odoo.addons.cledoo_mcp_full.controllers.mcp import _content_blocks
        blocks = [{"type": "image", "data": "aGk=", "mimeType": "image/png"}]
        out = _content_blocks({"__mcp_content__": blocks, "size_bytes": 2},
                              lambda d: self.fail("must not serialize"))
        self.assertEqual(out, blocks)

    def test_controller_content_blocks_default(self):
        from odoo.addons.cledoo_mcp_full.controllers.mcp import _content_blocks
        out = _content_blocks({"a": 1}, lambda d: "SERIALIZED")
        self.assertEqual(out, [{"type": "text", "text": "SERIALIZED"}])

    def test_tool_registered(self):
        fn, schema, ann = T.TOOLS["read_resource"]
        self.assertEqual(schema["required"], ["uri"])
        self.assertTrue(ann["readOnlyHint"])
        self.assertTrue(ann["idempotentHint"])
