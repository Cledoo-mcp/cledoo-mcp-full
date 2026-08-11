# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Files must leave the server as download links, not inline base64.

Live sessions showed why: a 24 KB invoice PDF becomes ~32k base64 chars
that the LLM must stream token by token into the conversation (minutes of
wall clock), then re-read on every following turn. A tokenized
/web/content URL costs a few dozen tokens and the client sandbox (or the
user's browser) fetches the bytes directly. inline=true keeps the old
behavior for clients that need the raw payload."""
import base64
from urllib.parse import urlparse

from odoo.tests import tagged
from odoo.tests.common import HttpCase, TransactionCase

from odoo.addons.cledoo_mcp_full.lib import tools as T


def _call(case, name, **kw):
    fn, _schema, _annotations = T.TOOLS[name]
    return fn(case.env, case.env.uid, **kw)


@tagged("post_install", "-at_install")
class TestExportDownloadUrl(TransactionCase):
    def test_export_returns_download_url_by_default(self):
        res = _call(self, "export_records", model="res.partner",
                    fields=["name"], limit=2)
        self.assertNotIn("content_base64", res)
        self.assertIn("access_token=", res["download_url"])
        self.assertIn("download=true", res["download_url"])
        self.assertGreater(res["size_bytes"], 0)
        self.assertEqual(res["mimetype"], "text/csv")

    def test_export_download_url_serves_the_csv_bytes(self):
        res = _call(self, "export_records", model="res.partner",
                    fields=["name"], limit=2)
        path = urlparse(res["download_url"]).path
        att_id = int(path.rsplit("/", 1)[-1])
        att = self.env["ir.attachment"].browse(att_id)
        self.assertTrue(att.exists())
        self.assertEqual(att.mimetype, "text/csv")
        self.assertIn(b"name", base64.b64decode(att.datas))

    def test_export_inline_true_returns_base64(self):
        res = _call(self, "export_records", model="res.partner",
                    fields=["name"], limit=2, inline=True)
        self.assertIn("content_base64", res)
        self.assertNotIn("download_url", res)


@tagged("post_install", "-at_install")
class TestReportDownloadUrl(TransactionCase):
    def _base_report(self):
        # the module-reference report action ships with every db (renders
        # as html when wkhtmltopdf is absent — both paths are fine here)
        rep = self.env.ref("base.ir_module_reference_print")
        target = self.env["ir.module.module"].sudo().search(
            [("name", "=", "base")], limit=1)
        return rep, target

    def test_print_report_returns_download_url_by_default(self):
        rep, target = self._base_report()
        res = _call(self, "print_report", report_ref=rep.id,
                    ids=[target.id])
        self.assertNotIn("content_base64", res)
        self.assertIn("access_token=", res["download_url"])
        self.assertGreater(res["size_bytes"], 0)

    def test_print_report_inline_true_returns_base64(self):
        rep, target = self._base_report()
        res = _call(self, "print_report", report_ref=rep.id,
                    ids=[target.id], inline=True)
        self.assertIn("content_base64", res)
        self.assertNotIn("download_url", res)


@tagged("post_install", "-at_install")
class TestDownloadUrlOverHttp(HttpCase):
    def test_tokenized_url_serves_bytes_without_session(self):
        fn, _s, _a = T.TOOLS["export_records"]
        res = fn(self.env, self.env.uid, model="res.partner",
                 fields=["name"], limit=2)
        # test mode routes HTTP requests onto the test cursor — no commit
        self.env.flush_all()
        parsed = urlparse(res["download_url"])
        r = self.url_open("%s?%s" % (parsed.path, parsed.query))
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.content.startswith(b"\xef\xbb\xbf\"name\""),
                        r.content[:40])


@tagged("post_install", "-at_install")
class TestModelFieldsPattern(TransactionCase):
    def test_pattern_filters_by_name_or_label(self):
        res = _call(self, "get_model_fields", model="res.partner",
                    pattern="email")
        self.assertIn("email", res["fields"])
        self.assertNotIn("name", res["fields"])
        for fname, meta in res["fields"].items():
            self.assertTrue(
                "email" in fname.lower()
                or "email" in (meta.get("string") or "").lower(),
                "%s does not match pattern" % fname)
        # the model's real size stays visible so the LLM knows it filtered
        self.assertGreater(res["total_fields"], len(res["fields"]))

    def test_no_pattern_returns_all_fields(self):
        res = _call(self, "get_model_fields", model="res.partner")
        self.assertIn("name", res["fields"])
        self.assertIn("email", res["fields"])
