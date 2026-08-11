# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""B1 (Task 8 review finding): read_resource/print_report carry no
`model` argument, so without deriving one from their own arguments they
evaded every model-scoped check (policy model-scope, field-deny,
default-deny). These tests pin the fix in the Pro pipeline."""
import base64

from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib.tools import ToolAccessError
from odoo.addons.cledoo_mcp_full.tests.common import LicenseMixin

PNG_B64 = ("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"
           "YPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")


@tagged("post_install", "-at_install")
class TestReadResourcePolicy(LicenseMixin, TransactionCase):
    def setUp(self):
        super().setUp()
        self.gw = self.env["mcp.gateway"]
        self.Policy = self.env["mcp.policy"].sudo()
        self.ctx = {"principal": {"kind": "apikey", "uid": self.env.uid,
                                  "token_id": None, "apikey_id": None}}
        self.icp = self.env["ir.config_parameter"].sudo()
        self.icp.set_param("cledoo_mcp_full.policy_default_deny", "False")
        self.partner = self.env["res.partner"].create(
            {"name": "RR Co", "image_1920": PNG_B64})

    def _uri(self):
        return "odoo://record/res.partner/%d/image_1920" % self.partner.id

    def test_model_scoped_deny_blocks_read_resource(self):
        self.install_license(["policy"])
        self.Policy.create({"name": "no partners",
                            "model_pattern": "res.partner",
                            "verdict": "deny"})
        with self.assertRaises(ToolAccessError):
            self.gw._execute_tool(self.env.uid, "read_resource",
                                  {"uri": self._uri()}, context=self.ctx)

    def test_field_denied_blocks_read_resource(self):
        self.install_license(["policy"])
        self.Policy.create({"name": "hide image", "verdict": "allow",
                            "model_pattern": "res.partner",
                            "fields_deny": "image_1920"})
        with self.assertRaises(ToolAccessError):
            self.gw._execute_tool(self.env.uid, "read_resource",
                                  {"uri": self._uri()}, context=self.ctx)

    def test_field_denied_blocks_attachment_backdoor(self):
        # Binary(attachment=True)/image fields live in ir.attachment rows
        # (res_field set): odoo://attachment/<id> is a second door to the
        # same denied bytes and must be blocked like the record uri.
        self.install_license(["policy"])
        self.Policy.create({"name": "hide image", "verdict": "allow",
                            "model_pattern": "res.partner",
                            "fields_deny": "image_1920"})
        att = self.env["ir.attachment"].sudo().search(
            [("res_model", "=", "res.partner"),
             ("res_id", "=", self.partner.id),
             ("res_field", "=", "image_1920")], limit=1)
        self.assertTrue(att, "image_1920 should be attachment-stored")
        with self.assertRaises(ToolAccessError):
            self.gw._execute_tool(
                self.env.uid, "read_resource",
                {"uri": "odoo://attachment/%d" % att.id}, context=self.ctx)

    def test_attachment_not_backing_denied_field_still_readable(self):
        # A plain document attached to the same record does not carry the
        # denied field's bytes — it must stay readable.
        self.install_license(["policy"])
        self.Policy.create({"name": "hide image", "verdict": "allow",
                            "model_pattern": "res.partner",
                            "fields_deny": "image_1920"})
        att = self.env["ir.attachment"].create(
            {"name": "doc.txt", "raw": b"plain document",
             "res_model": "res.partner", "res_id": self.partner.id})
        res = self.gw._execute_tool(
            self.env.uid, "read_resource",
            {"uri": "odoo://attachment/%d" % att.id}, context=self.ctx)
        self.assertIn("__mcp_content__", res)

    def test_default_deny_blocks_read_resource(self):
        self.install_license(["policy"])
        self.icp.set_param("cledoo_mcp_full.policy_default_deny", "True")
        with self.assertRaises(ToolAccessError):
            self.gw._execute_tool(self.env.uid, "read_resource",
                                  {"uri": self._uri()}, context=self.ctx)

    def test_allowed_read_resource_still_works(self):
        self.install_license(["policy"])
        self.Policy.create({"name": "allow partners", "verdict": "allow",
                            "model_pattern": "res.partner"})
        res = self.gw._execute_tool(self.env.uid, "read_resource",
                                    {"uri": self._uri()}, context=self.ctx)
        self.assertIn("__mcp_content__", res)

    def _any_report(self):
        """First qweb report whose model has at least one record (mirrors
        cledoo_mcp_full/tests/test_tools_report.py's helper)."""
        for rep in self.env["ir.actions.report"].sudo().search(
                [("report_type", "in", ("qweb-pdf", "qweb-html"))], limit=20):
            rec = self.env[rep.model].sudo().search([], limit=1)
            if rec:
                return rep, rec
        return None, None

    def test_print_report_default_deny_blocked(self):
        self.install_license(["policy"])
        self.icp.set_param("cledoo_mcp_full.policy_default_deny", "True")
        rep, rec = self._any_report()
        if not rep:
            self.skipTest("no renderable qweb report on this db")
        with self.assertRaises(ToolAccessError):
            self.gw._execute_tool(
                self.env.uid, "print_report",
                {"report_ref": rep.report_name, "ids": [rec.id]},
                context=self.ctx)

    def test_read_resource_unresolvable_model_default_deny(self):
        # A malformed/unresolvable target still falls under default-deny
        # rather than silently skipping policy (fail closed).
        self.install_license(["policy"])
        self.icp.set_param("cledoo_mcp_full.policy_default_deny", "True")
        att = self.env["ir.attachment"].create(
            {"name": "loose.txt", "raw": b"no res_model here"})
        with self.assertRaises(ToolAccessError):
            self.gw._execute_tool(
                self.env.uid, "read_resource",
                {"uri": "odoo://attachment/%d" % att.id}, context=self.ctx)
