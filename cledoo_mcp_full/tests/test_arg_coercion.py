# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""LLM clients routinely serialize array/object params as JSON strings
('fields': '["name"]' instead of ["name"]). Untyped ({}) schema slots made
this worse (no signal to send an array), and the server then iterated the
string character by character — "Unknown field '[' on res.partner". Two
guarantees below: every fields/domain slot advertises a real array type,
and stringified JSON is coerced back at the transport ingress."""
import datetime
import json

from odoo.tests import tagged
from odoo.tests.common import HttpCase, TransactionCase

from odoo.addons.cledoo_mcp_full.lib import tools as T


@tagged("post_install", "-at_install")
class TestSchemasAreTyped(TransactionCase):
    def test_fields_and_domain_slots_declare_array_type(self):
        for name, (_fn, schema, _ann) in T.TOOLS.items():
            for pname in ("fields", "domain"):
                prop = schema["properties"].get(pname)
                if prop is None:
                    continue
                self.assertEqual(
                    prop.get("type"), "array",
                    "%s.%s must declare type=array — an untyped {} slot is "
                    "exactly why clients sent stringified JSON" % (name, pname))


@tagged("post_install", "-at_install")
class TestNormalizeToolArgs(TransactionCase):
    def test_stringified_fields_is_coerced_to_list(self):
        args = T.normalize_tool_args("search_records", {
            "model": "res.partner",
            "fields": '["name", "email"]', "limit": 5})
        self.assertEqual(args["fields"], ["name", "email"])

    def test_stringified_domain_is_coerced_to_list(self):
        args = T.normalize_tool_args("count_records", {
            "model": "res.partner",
            "domain": '[["is_company", "=", true]]'})
        self.assertEqual(args["domain"], [["is_company", "=", True]])

    def test_stringified_values_is_coerced_to_dict(self):
        args = T.normalize_tool_args("create_record", {
            "model": "res.partner", "values": '{"name": "Coerced Co"}'})
        self.assertEqual(args["values"], {"name": "Coerced Co"})

    def test_native_types_pass_through_unchanged(self):
        original = {"model": "res.partner", "fields": ["name"],
                    "domain": [["id", ">", 0]], "limit": 3}
        args = T.normalize_tool_args("search_records", dict(original))
        self.assertEqual(args, original)

    def test_invalid_json_string_raises_invalid_params(self):
        with self.assertRaises(T.ToolInvalidParamsError) as ctx:
            T.normalize_tool_args("search_records", {
                "model": "res.partner", "fields": "[name, email]"})
        self.assertIn("fields", ctx.exception.message)
        self.assertIn("JSON array", ctx.exception.message)

    def test_json_of_wrong_type_raises_invalid_params(self):
        # decodes fine but to an object where an array is declared
        with self.assertRaises(T.ToolInvalidParamsError) as ctx:
            T.normalize_tool_args("search_records", {
                "model": "res.partner", "fields": '{"name": 1}'})
        self.assertIn("fields", ctx.exception.message)

    def test_plain_string_field_name_is_not_silently_wrapped(self):
        # 'fields': "name" is ambiguous; it must error, not guess
        with self.assertRaises(T.ToolInvalidParamsError):
            T.normalize_tool_args("search_records", {
                "model": "res.partner", "fields": "name"})

    def test_unknown_tool_returns_args_unchanged(self):
        args = {"whatever": "[1]"}
        self.assertEqual(
            T.normalize_tool_args("no_such_tool", dict(args)), args)

    def test_none_arguments_return_empty_dict(self):
        self.assertEqual(T.normalize_tool_args("whoami", None), {})


@tagged("post_install", "-at_install")
class TestCoercionOverHttp(HttpCase):
    """The exact failing call from live claude.ai sessions, end to end
    through the /mcp transport (the ingress where coercion must happen so
    governance overrides — MCP Pro's policy pipeline — see clean args)."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.env["ir.config_parameter"].sudo().set_param(
            "cledoo_mcp_full.enabled", "True")
        gf = ("group_ids" if "group_ids" in cls.env["res.users"]._fields
              else "groups_id")
        cls.user = cls.env["res.users"].create({
            "name": "Coercion MCP", "login": "mcp-coercion-user",
            gf: [(6, 0, [cls.env.ref("base.group_user").id,
                         cls.env.ref("base.group_partner_manager").id])]})
        expiration = datetime.datetime.now() + datetime.timedelta(days=1)
        cls.key = cls.env["res.users.apikeys"].with_user(cls.user)._generate(
            None, "coercion-key", expiration)
        cls.env.flush_all()

    def _call_tool(self, name, arguments):
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": name, "arguments": arguments}}
        return self.url_open("/mcp", data=json.dumps(body), headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer %s" % self.key})

    def test_stringified_fields_and_limit_succeeds(self):
        # verbatim reproduction of the live failure
        r = self._call_tool("search_records", {
            "model": "res.partner",
            "fields": '["name", "email", "phone", "city"]', "limit": 5})
        self.assertEqual(r.status_code, 200)
        j = r.json()
        self.assertNotIn("error", j, j.get("error"))

    def test_stringified_domain_succeeds(self):
        r = self._call_tool("count_records", {
            "model": "res.partner",
            "domain": '[["is_company", "=", true]]'})
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("error", r.json())

    def test_garbage_fields_string_is_clean_invalid_params(self):
        r = self._call_tool("search_records", {
            "model": "res.partner", "fields": "[name"})
        self.assertEqual(r.status_code, 200)
        j = r.json()
        self.assertTrue(j["result"]["isError"])
        payload = json.loads(j["result"]["content"][0]["text"])
        self.assertEqual(payload["code"], "invalid_params")
        self.assertIn("fields", payload["error"])
