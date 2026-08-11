# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Actionable error messages for the #1 real-world mistake: wrong field
names in domains/fields/values/order. These used to surface as a generic
-32603 Internal error; they must name the field, suggest close matches
and point at get_model_fields."""
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib import tools as T


@tagged("post_install", "-at_install")
class TestToolErrorMessages(TransactionCase):
    def call(self, name, **kw):
        fn, _schema, _annotations = T.TOOLS[name]
        return fn(self.env, self.env.uid, **kw)

    def test_unknown_domain_field_suggests_close_match(self):
        # the exact field mix-up from live testing: ir.attachment stores
        # the related model in res_model, not model
        with self.assertRaises(T.ToolInvalidParamsError) as ctx:
            self.call("search_records", model="ir.attachment",
                      domain=[["model", "=", "account.move"]],
                      fields=["name"])
        msg = ctx.exception.message
        self.assertIn("Unknown field 'model' on ir.attachment", msg)
        self.assertIn("res_model", msg)          # close-match suggestion
        self.assertIn("get_model_fields", msg)   # actionable next step

    def test_unknown_field_in_fields_arg(self):
        with self.assertRaises(T.ToolInvalidParamsError) as ctx:
            self.call("search_records", model="res.partner",
                      fields=["name", "emial"])
        msg = ctx.exception.message
        self.assertIn("Unknown field 'emial'", msg)
        self.assertIn("email", msg)

    def test_unknown_field_in_create_values(self):
        with self.assertRaises(T.ToolInvalidParamsError) as ctx:
            self.call("create_record", model="res.partner",
                      values={"nmae": "Typo Co"})
        self.assertIn("Unknown field 'nmae'", ctx.exception.message)
        self.assertIn("values", ctx.exception.message)

    def test_unknown_field_in_order(self):
        with self.assertRaises(T.ToolInvalidParamsError) as ctx:
            self.call("search_records", model="res.partner",
                      fields=["name"], order="nmae desc")
        self.assertIn("Unknown field 'nmae'", ctx.exception.message)

    def test_dotted_path_validates_target_model(self):
        # valid relational path passes...
        res = self.call("search_records", model="res.partner",
                        domain=[["country_id.code", "=", "FR"]],
                        fields=["name"], limit=1)
        self.assertIn("records", res)
        # ...and a typo after the relation names the *comodel*
        with self.assertRaises(T.ToolInvalidParamsError) as ctx:
            self.call("search_records", model="res.partner",
                      domain=[["country_id.coed", "=", "FR"]],
                      fields=["name"])
        self.assertIn("Unknown field 'coed' on res.country",
                      ctx.exception.message)

    def test_count_records_validates_domain_too(self):
        with self.assertRaises(T.ToolInvalidParamsError):
            self.call("count_records", model="ir.attachment",
                      domain=[["model", "=", "account.move"]])

    def test_malformed_domain_term_is_invalid_params(self):
        with self.assertRaises(T.ToolInvalidParamsError) as ctx:
            self.call("search_records", model="res.partner",
                      domain=[["name", "="]], fields=["name"])
        self.assertIn("[field, operator, value]", ctx.exception.message)

    def test_domain_must_be_a_list(self):
        with self.assertRaises(T.ToolInvalidParamsError):
            self.call("search_records", model="res.partner",
                      domain={"name": "x"}, fields=["name"])

    def test_orm_valueerror_is_user_error_not_internal(self):
        # errors the static validation can't see (bad operator) must still
        # come back as a client error, never a -32603
        with self.assertRaises(T.ToolUserError):
            self.call("search_records", model="res.partner",
                      domain=[["name", "===", "x"]], fields=["name"])
