# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
import base64
import csv
import io

from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib import tools as T


@tagged("post_install", "-at_install")
class TestExportRecords(TransactionCase):
    def call(self, **kw):
        # content-inspecting suite: force the inline payload (the
        # download-link default is covered by test_download_urls)
        kw.setdefault("inline", True)
        fn, _s, _a = T.TOOLS["export_records"]
        return fn(self.env, self.env.uid, **kw)

    def setUp(self):
        super().setUp()
        self.p = self.env["res.partner"].create(
            {"name": "Export Co", "email": "x@example.com"})

    def _rows(self, res):
        raw = base64.b64decode(res["content_base64"]).decode("utf-8-sig")
        return list(csv.reader(io.StringIO(raw)))

    def test_csv_by_ids(self):
        res = self.call(model="res.partner", fields=["name", "email"],
                        ids=[self.p.id])
        self.assertEqual(res["row_count"], 1)
        rows = self._rows(res)
        self.assertEqual(rows[0], ["name", "email"])
        self.assertEqual(rows[1], ["Export Co", "x@example.com"])
        self.assertTrue(res["filename"].endswith(".csv"))

    def test_csv_relational_path(self):
        self.p.country_id = self.env.ref("base.fr")
        res = self.call(model="res.partner", fields=["name", "country_id/name"],
                        ids=[self.p.id])
        self.assertIn("France", self._rows(res)[1])

    def test_csv_by_domain(self):
        res = self.call(model="res.partner", fields=["name"],
                        domain=[["id", "=", self.p.id]])
        self.assertEqual(res["row_count"], 1)

    def test_formula_injection_guarded(self):
        self.p.name = "=cmd()"
        res = self.call(model="res.partner", fields=["name"], ids=[self.p.id])
        self.assertEqual(self._rows(res)[1][0], "'=cmd()")

    def test_xlsx(self):
        res = self.call(model="res.partner", fields=["name"],
                        ids=[self.p.id], format="xlsx")
        content = base64.b64decode(res["content_base64"])
        self.assertEqual(content[:2], b"PK")  # zip magic
        self.assertTrue(res["filename"].endswith(".xlsx"))

    def test_fields_required(self):
        with self.assertRaises(T.ToolInvalidParamsError):
            self.call(model="res.partner", fields=[])

    def test_bad_format(self):
        with self.assertRaises(T.ToolInvalidParamsError):
            self.call(model="res.partner", fields=["name"], format="pdf")

    def test_unknown_field(self):
        with self.assertRaises(T.ToolInvalidParamsError):
            self.call(model="res.partner", fields=["nmae"], ids=[self.p.id])
