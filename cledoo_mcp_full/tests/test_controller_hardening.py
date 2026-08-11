# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""HTTP-level coverage of the review-hardening fixes: transactional
integrity on failed tools, non-dict payload handling, and invalid_params
isError mapping for invalid tool arguments."""
import datetime
import json

from odoo.tests import tagged
from odoo.tests.common import HttpCase


@tagged("post_install", "-at_install")
class TestControllerHardening(HttpCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.env["ir.config_parameter"].sudo().set_param(
            "cledoo_mcp_full.enabled", "True")
        gf = "group_ids" if "group_ids" in cls.env["res.users"]._fields else "groups_id"
        cls.user = cls.env["res.users"].create({
            "name": "Hardening MCP", "login": "mcp-hardening-user",
            gf: [(6, 0, [cls.env.ref("base.group_user").id,
                         cls.env.ref("base.group_partner_manager").id])]})
        expiration = datetime.datetime.now() + datetime.timedelta(days=1)
        cls.key = cls.env["res.users.apikeys"].with_user(cls.user)._generate(
            None, "hardening-key", expiration)
        cls.partner = cls.env["res.partner"].create({"name": "Savepoint Co"})
        cls.env.flush_all()

    def _call_tool(self, name, arguments):
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": name, "arguments": arguments}}
        return self.url_open("/mcp", data=json.dumps(body), headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer %s" % self.key})

    def _rpc(self, body, extra_headers=None):
        headers = {"Content-Type": "application/json",
                   "Authorization": "Bearer %s" % self.key}
        headers.update(extra_headers or {})
        return self.url_open("/mcp", data=json.dumps(body), headers=headers)

    def test_failed_tool_write_is_rolled_back(self):
        # parent_id = self trips res.partner's recursion constraint AFTER
        # the write has been flushed; without the savepoint the invalid
        # write would be committed at end of request despite the error.
        r = self._call_tool("update_record", {
            "model": "res.partner", "record_id": self.partner.id,
            "values": {"parent_id": self.partner.id}})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["result"]["isError"])
        self.env.invalidate_all()
        self.assertFalse(self.partner.parent_id)

    def test_batch_payload_is_invalid_request_not_500(self):
        body = [{"jsonrpc": "2.0", "id": 1, "method": "ping"}]
        r = self.url_open("/mcp", data=json.dumps(body), headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer %s" % self.key})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["error"]["code"], -32600)

    def test_non_object_params_is_invalid_params_not_500(self):
        # A JSON array as `params` used to blow up req.params.get() with an
        # opaque -32603; it must be a clean -32602.
        body = {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                "params": [1, 2, 3]}
        r = self.url_open("/mcp", data=json.dumps(body), headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer %s" % self.key})
        self.assertEqual(r.status_code, 200)
        j = r.json()
        self.assertEqual(j["error"]["code"], -32602)
        self.assertEqual(j["id"], 7)

    def test_unexpected_kwarg_maps_to_invalid_params(self):
        r = self._call_tool("search_records",
                            {"model": "res.partner", "order_by": "name"})
        self.assertEqual(r.status_code, 200)
        j = r.json()
        self.assertTrue(j["result"]["isError"])
        payload = json.loads(j["result"]["content"][0]["text"])
        self.assertEqual(payload["code"], "invalid_params")

    def test_non_integer_record_id_maps_to_invalid_params(self):
        r = self._call_tool("get_record",
                            {"model": "res.partner", "record_id": "abc"})
        j = r.json()
        self.assertTrue(j["result"]["isError"])
        payload = json.loads(j["result"]["content"][0]["text"])
        self.assertEqual(payload["code"], "invalid_params")

    def test_list_values_rejected_and_not_created(self):
        r = self._call_tool("create_record", {
            "model": "res.partner",
            "values": [{"name": "Batch A"}, {"name": "Batch B"}]})
        j = r.json()
        self.assertTrue(j["result"]["isError"])
        payload = json.loads(j["result"]["content"][0]["text"])
        self.assertEqual(payload["code"], "invalid_params")
        self.env.invalidate_all()
        self.assertFalse(self.env["res.partner"].search(
            [("name", "in", ["Batch A", "Batch B"])]))

    def test_cross_origin_post_is_403(self):
        body = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        r = self.url_open("/mcp", data=json.dumps(body), headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer %s" % self.key,
            "Origin": "https://evil.example.com"})
        self.assertEqual(r.status_code, 403)

    def test_same_origin_and_localhost_post_ok(self):
        body = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        base = self.env["ir.config_parameter"].sudo().get_param("web.base.url")
        for origin in (base, "http://localhost:8069", "http://127.0.0.1:3000"):
            r = self.url_open("/mcp", data=json.dumps(body), headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer %s" % self.key,
                "Origin": origin})
            self.assertEqual(r.status_code, 200, "origin %s" % origin)

    def test_null_origin_post_is_403(self):
        body = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        r = self.url_open("/mcp", data=json.dumps(body), headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer %s" % self.key,
            "Origin": "null"})
        self.assertEqual(r.status_code, 403)

    def test_initialize_echoes_supported_version(self):
        r = self._rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2025-11-25",
                                  "capabilities": {},
                                  "clientInfo": {"name": "t", "version": "1"}}})
        self.assertEqual(r.json()["result"]["protocolVersion"], "2025-11-25")

    def test_initialize_falls_back_on_unknown_version(self):
        r = self._rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "1999-01-01"}})
        self.assertEqual(r.json()["result"]["protocolVersion"], "2025-06-18")

    def test_unsupported_protocol_header_is_400(self):
        r = self._rpc({"jsonrpc": "2.0", "id": 1, "method": "ping"},
                      {"MCP-Protocol-Version": "1999-01-01"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["error"]["code"], -32600)

    def test_supported_protocol_header_ok(self):
        for v in ("2025-06-18", "2025-11-25"):
            r = self._rpc({"jsonrpc": "2.0", "id": 1, "method": "ping"},
                          {"MCP-Protocol-Version": v})
            self.assertEqual(r.status_code, 200, v)

    def test_unknown_notification_gets_202_no_body(self):
        # id-less request = notification; JSON-RPC forbids responding.
        r = self._rpc({"jsonrpc": "2.0", "method": "notifications/cancelled",
                       "params": {"requestId": 42}})
        self.assertEqual(r.status_code, 202)
        self.assertEqual(r.content, b"")

    def test_get_mcp_is_405_with_allow(self):
        r = self.url_open("/mcp")
        self.assertEqual(r.status_code, 405)
        self.assertEqual(r.headers.get("Allow"), "POST")
