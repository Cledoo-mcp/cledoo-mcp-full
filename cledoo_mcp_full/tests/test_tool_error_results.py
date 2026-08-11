# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Tool execution/validation failures must surface as isError:true tool
results (MCP 2025-06-18 tool errors + SEP-1303), NOT JSON-RPC protocol
errors — protocol errors are reserved for unknown method/tool and
malformed requests."""
import datetime
import json

from odoo.tests import tagged
from odoo.tests.common import HttpCase, TransactionCase

from odoo.addons.cledoo_mcp_full.controllers.mcp import _tool_error_result
from odoo.addons.cledoo_mcp_full.lib.tools import ToolUserError


@tagged("post_install", "-at_install")
class TestToolErrorsWire(HttpCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.env["ir.config_parameter"].sudo().set_param(
            "cledoo_mcp_full.enabled", "True")
        gf = "group_ids" if "group_ids" in cls.env["res.users"]._fields else "groups_id"
        cls.user = cls.env["res.users"].create({
            "name": "IsError MCP", "login": "mcp-iserror-user",
            gf: [(6, 0, [cls.env.ref("base.group_user").id,
                         cls.env.ref("base.group_partner_manager").id])]})
        expiration = datetime.datetime.now() + datetime.timedelta(days=1)
        cls.key = cls.env["res.users.apikeys"].with_user(cls.user)._generate(
            None, "iserror-key", expiration)
        cls.env.flush_all()

    def _call_tool(self, name, arguments):
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": name, "arguments": arguments}}
        return self.url_open("/mcp", data=json.dumps(body), headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer %s" % self.key})

    def test_validation_error_is_iserror_result(self):
        # Unknown model = ToolUserError (execution error) -> isError result.
        r = self._call_tool("get_record",
                            {"model": "no.such.model", "record_id": 1})
        self.assertEqual(r.status_code, 200)
        j = r.json()
        self.assertNotIn("error", j)
        self.assertTrue(j["result"]["isError"])
        payload = json.loads(j["result"]["content"][0]["text"])
        self.assertEqual(payload["code"], "validation_error")
        self.assertIn("no.such.model", payload["error"])

    def test_invalid_params_is_iserror_result(self):
        # SEP-1303: input validation errors are Tool Execution Errors so
        # the model can self-correct.
        r = self._call_tool("search_records",
                            {"model": "res.partner", "order_by": "name"})
        j = r.json()
        self.assertNotIn("error", j)
        self.assertTrue(j["result"]["isError"])
        payload = json.loads(j["result"]["content"][0]["text"])
        self.assertEqual(payload["code"], "invalid_params")

    def test_unknown_tool_stays_protocol_error(self):
        r = self._call_tool("no_such_tool", {})
        j = r.json()
        self.assertEqual(j["error"]["code"], -32602)

    def test_unknown_method_stays_protocol_error(self):
        body = {"jsonrpc": "2.0", "id": 2, "method": "prompts/list",
                "params": {}}
        r = self.url_open("/mcp", data=json.dumps(body), headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer %s" % self.key})
        self.assertEqual(r.json()["error"]["code"], -32601)


@tagged("post_install", "-at_install")
class TestToolErrorResultMeta(TransactionCase):
    """`_tool_error_result` optionally carries the exception's `_meta`
    (e.g. Pro's MCP Apps denial-explainer hint). The free tier never sets
    it, so a plain ToolError must keep producing the exact same wire
    shape it always has -- no `_meta` key at all."""

    def test_meta_included_when_exception_carries_one(self):
        exc = ToolUserError("boom", meta={"ui": {
            "resourceUri": "ui://cledoo/denial-explainer"}})
        res = _tool_error_result(7, exc)
        self.assertEqual(res["result"]["_meta"],
                         {"ui": {"resourceUri": "ui://cledoo/denial-explainer"}})

    def test_meta_absent_by_default(self):
        exc = ToolUserError("boom")
        res = _tool_error_result(7, exc)
        self.assertNotIn("_meta", res["result"])
        self.assertEqual(set(res["result"]), {"content", "isError"})
