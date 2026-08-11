# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
import base64

from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib import tools as T


@tagged("post_install", "-at_install")
class TestPrintReport(TransactionCase):
    def call(self, **kw):
        # content-inspecting suite: force the inline payload (the
        # download-link default is covered by test_download_urls)
        kw.setdefault("inline", True)
        fn, _s, _a = T.TOOLS["print_report"]
        return fn(self.env, self.env.uid, **kw)

    def _any_report(self):
        """First qweb report whose model has at least one record."""
        for rep in self.env["ir.actions.report"].sudo().search(
                [("report_type", "in", ("qweb-pdf", "qweb-html"))], limit=20):
            rec = self.env[rep.model].sudo().search([], limit=1)
            if rec:
                return rep, rec
        return None, None

    def test_render_by_report_name(self):
        rep, rec = self._any_report()
        if not rep:
            self.skipTest("no renderable qweb report on this db")
        res = self.call(report_ref=rep.report_name, ids=[rec.id])
        self.assertTrue(base64.b64decode(res["content_base64"]))
        self.assertIn(res["report_type"], ("pdf", "html", "text"))

    def test_render_by_id(self):
        rep, rec = self._any_report()
        if not rep:
            self.skipTest("no renderable qweb report on this db")
        res = self.call(report_ref=rep.id, ids=[rec.id])
        self.assertTrue(res["filename"])

    def test_unknown_report(self):
        with self.assertRaises(T.ToolUserError) as ctx:
            self.call(report_ref="nope.not_a_report", ids=[1])
        self.assertIn("not found", ctx.exception.message)

    def test_ids_required(self):
        with self.assertRaises(T.ToolInvalidParamsError):
            self.call(report_ref="whatever", ids=[])
