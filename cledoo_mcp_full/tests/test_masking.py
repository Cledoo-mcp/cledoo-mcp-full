# SPDX-License-Identifier: OPL-1.0
# Copyright (c) 2026 Cledoo
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.tests.common import LicenseMixin


@tagged("post_install", "-at_install")
class TestMasking(LicenseMixin, TransactionCase):
    def setUp(self):
        super().setUp()
        self.gw = self.env["mcp.gateway"]
        self.Rule = self.env["mcp.mask.rule"].sudo()
        self.ctx = {"principal": {"kind": "apikey", "uid": self.env.uid,
                                  "token_id": None, "apikey_id": None}}
        self.partner = self.env["res.partner"].create({
            "name": "Masky", "email": "masky@example.com",
            "phone": "+33999888777"})

    def _get(self, fields):
        return self.gw._execute_tool(
            self.env.uid, "get_record",
            {"model": "res.partner", "record_id": self.partner.id,
             "fields": fields}, context=self.ctx)

    def test_redact_masks_value(self):
        self.install_license(["masking"])
        self.Rule.create({"model_name": "res.partner",
                          "field_name": "email", "strategy": "redact"})
        res = self._get(["name", "email"])
        self.assertNotIn("masky@example.com", str(res))
        self.assertIn("Masky", str(res))

    def test_partial_keeps_prefix(self):
        self.install_license(["masking"])
        self.Rule.create({"model_name": "res.partner",
                          "field_name": "phone", "strategy": "partial"})
        res = self._get(["phone"])
        flat = str(res)
        self.assertNotIn("+33999888777", flat)
        self.assertIn("+3", flat)  # prefix survives

    def test_derived_field_is_masked_too(self):
        """The email_normalized-class leak: any field computed FROM a
        masked field is masked with it. res.partner.email_normalized
        exists when mail is installed (it is: base module depends)."""
        self.install_license(["masking"])
        self.Rule.create({"model_name": "res.partner",
                          "field_name": "email", "strategy": "redact"})
        res = self._get(["email_normalized"])
        self.assertNotIn("masky@example.com", str(res))

    def test_search_records_results_masked(self):
        self.install_license(["masking"])
        self.Rule.create({"model_name": "res.partner",
                          "field_name": "email", "strategy": "redact"})
        res = self.gw._execute_tool(
            self.env.uid, "search_records",
            {"model": "res.partner", "domain": [["id", "=", self.partner.id]],
             "fields": ["name", "email"]}, context=self.ctx)
        self.assertNotIn("masky@example.com", str(res))

    def test_hash_is_stable(self):
        from odoo.addons.cledoo_mcp_full.models.mask_rule import _mask_value
        a = _mask_value("masky@example.com", "hash")
        b = _mask_value("masky@example.com", "hash")
        self.assertEqual(a, b)
        self.assertNotIn("masky", a)

    def test_sentinel_untouched(self):
        self.install_license(["masking"])
        att = self.env["ir.attachment"].create(
            {"name": "s.txt", "raw": b"raw bytes here"})
        res = self.gw._execute_tool(
            self.env.uid, "read_resource",
            {"uri": "odoo://attachment/%d" % att.id}, context=self.ctx)
        self.assertIn("__mcp_content__", res)
