# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib import tools as T


@tagged("post_install", "-at_install")
class TestDirectOrmTools(TransactionCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        gf = "group_ids" if "group_ids" in cls.env["res.users"]._fields else "groups_id"
        cls.user = cls.env["res.users"].create({
            "name": "Restricted", "login": "mcp-restricted",
            # partner_manager: CRUD tests need a group whose ACLs allow
            # res.partner create/write/unlink (group_user alone is read-only).
            gf: [(6, 0, [cls.env.ref("base.group_user").id,
                         cls.env.ref("base.group_partner_manager").id])],
        })
        cls.partner = cls.env["res.partner"].create(
            {"name": "Lite Co", "email": "lite@ex.test"})

    def call(self, name, **kw):
        fn, _schema, _annotations = T.TOOLS[name]
        return fn(self.env, self.user.id, **kw)

    def test_registry_has_exactly_the_v14_tools(self):
        self.assertEqual(sorted(T.TOOLS), sorted([
            "whoami", "list_models", "get_model_fields", "search_records",
            "get_record", "count_records", "describe_access", "create_record",
            "update_record", "delete_record", "aggregate_records",
            "get_messages", "post_message", "export_records", "print_report",
            "list_modules", "read_resource"]))

    def test_search_read_roundtrip_with_acl_user(self):
        res = self.call("search_records", model="res.partner",
                        domain=[["name", "=", "Lite Co"]], fields=["name", "email"])
        self.assertEqual(res["records"][0]["email"], "lite@ex.test")  # NO masking in lite

    def test_search_limit_clamped_to_500(self):
        # explicit fields: this test asserts the clamp; fields=None would drag
        # in related-comodel ACL traversal unrelated to what is under test.
        res = self.call("search_records", model="res.partner",
                        fields=["name"], limit=99999)
        self.assertLessEqual(res["limit"], 500)

    def test_crud_roundtrip(self):
        created = self.call("create_record", model="res.partner",
                            values={"name": "Lite CRUD"})
        rid = created["id"]
        self.call("update_record", model="res.partner", record_id=rid,
                  values={"name": "Lite CRUD v2"})
        got = self.call("get_record", model="res.partner", record_id=rid,
                        fields=["name"])
        self.assertEqual(got["record"]["name"], "Lite CRUD v2")
        self.call("delete_record", model="res.partner", record_id=rid)
        self.assertEqual(self.call("count_records", model="res.partner",
                                   domain=[["id", "=", rid]])["count"], 0)

    def test_acl_denied_write_raises_tool_access_error(self):
        # base_user cannot create res.groups
        with self.assertRaises(T.ToolAccessError):
            self.call("create_record", model="res.groups", values={"name": "nope"})

    def test_denied_error_message_is_sanitized(self):
        try:
            self.call("create_record", model="res.groups", values={"name": "nope"})
        except T.ToolAccessError as e:
            self.assertNotIn("Traceback", e.message)
            self.assertNotIn("odoo.exceptions", e.message)

    def test_describe_access_shape(self):
        res = self.call("describe_access", model="res.partner")
        self.assertIn(res["read"], (True, False))
        for k in ("read", "write", "create", "unlink"):
            self.assertIn(k, res)

    def test_list_models_only_readable_and_pattern(self):
        res = self.call("list_models", pattern="res.part")
        names = [m["model"] for m in res["models"]]
        self.assertIn("res.partner", names)

    def test_unknown_model_is_tool_error_not_crash(self):
        with self.assertRaises(T.ToolUserError):
            self.call("count_records", model="no.such.model")

    def _denied_model(self):
        """First base model this user cannot read (guarded, version-proof)."""
        for model in ("ir.mail_server", "res.users.apikeys", "ir.config_parameter"):
            if model in self.env and not T._can(
                    self.env[model].with_user(self.user.id), "read"):
                return model
        self.skipTest("no read-denied candidate model on this version")

    def test_get_model_fields_denied_model_raises_access_error(self):
        denied = self._denied_model()
        with self.assertRaises(T.ToolAccessError):
            self.call("get_model_fields", model=denied)

    def test_list_models_excludes_denied_model(self):
        denied = self._denied_model()
        # all=true: the featured default would exclude the denied model for
        # the wrong reason (not being featured) and mask an ACL regression.
        res = self.call("list_models", all=True)
        self.assertNotIn(denied, [m["model"] for m in res["models"]])

    def test_negative_limit_clamped_not_sql_error(self):
        res = self.call("search_records", model="res.partner",
                        fields=["name"], limit=-5)
        self.assertGreaterEqual(res["limit"], 1)

    def test_non_integer_record_id_is_invalid_params(self):
        with self.assertRaises(T.ToolInvalidParamsError):
            self.call("get_record", model="res.partner", record_id="abc")

    def test_list_values_is_invalid_params(self):
        with self.assertRaises(T.ToolInvalidParamsError):
            self.call("create_record", model="res.partner",
                      values=[{"name": "A"}, {"name": "B"}])

    def test_unexpected_kwarg_is_invalid_params(self):
        with self.assertRaises(T.ToolInvalidParamsError):
            self.call("search_records", model="res.partner", order_by="name")
