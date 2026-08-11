import unittest
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib.tools import TOOLS, ToolAccessError
from odoo.addons.cledoo_mcp_full.models.gateway import UnknownToolError


@tagged("post_install", "-at_install")
class TestGateway(TransactionCase):
    @unittest.skip("free-only seam default; the pro overrides are active in the merged build (covered by the pro suite)")
    def test_list_tools_shape(self):
        tools = self.env["mcp.gateway"]._list_tools()
        self.assertEqual(len(tools), len(TOOLS))
        for t in tools:
            self.assertIn("name", t)
            self.assertIn("description", t)
            self.assertIn("inputSchema", t)
            self.assertIn("annotations", t)
            # full docstring, whitespace-collapsed (LLM steering surface)
            self.assertNotIn("\n", t["description"])

    def test_execute_tool_dispatches(self):
        res = self.env["mcp.gateway"]._execute_tool(
            self.env.uid, "count_records", {"model": "res.partner"})
        self.assertGreaterEqual(res["count"], 0)

    def test_unknown_tool_raises_keyerror(self):
        # UnknownToolError subclasses KeyError, so this still holds -- but
        # see test_unknown_tool_raises_unknown_tool_error below for the
        # assertion that actually distinguishes it from a plain KeyError.
        with self.assertRaises(KeyError):
            self.env["mcp.gateway"]._execute_tool(self.env.uid, "nope", {})

    def test_unknown_tool_raises_unknown_tool_error(self):
        with self.assertRaises(UnknownToolError):
            self.env["mcp.gateway"]._execute_tool(self.env.uid, "nope", {})

    def test_in_tool_keyerror_is_not_unknown_tool_error(self):
        # A KeyError raised *inside* a tool's own code (e.g. malformed
        # values-dict indexing, a deep ORM path) must NOT be conflated
        # with a registry miss -- it should surface as a plain KeyError
        # so the controller lets it fall through to -32603 + logging
        # instead of masking it as "Unknown tool" (-32602).
        def _boom(env, uid, **kwargs):
            raise KeyError("boom")

        sentinel = "__test_in_tool_keyerror__"
        TOOLS[sentinel] = (_boom, {}, {})
        try:
            try:
                self.env["mcp.gateway"]._execute_tool(self.env.uid, sentinel, {})
                self.fail("expected KeyError")
            except UnknownToolError:
                self.fail(
                    "in-tool KeyError must not be raised/caught as UnknownToolError")
            except KeyError as exc:
                self.assertEqual(exc.args[0], "boom")
        finally:
            del TOOLS[sentinel]

    def test_execute_tool_accepts_request_context(self):
        res = self.env["mcp.gateway"]._execute_tool(
            self.env.uid, "count_records", {"model": "res.partner"},
            context={"session_id": "s1", "remote_addr": "127.0.0.1",
                     "request_id": 7})
        self.assertGreaterEqual(res["count"], 0)

    def test_on_request_hook_is_noop_and_safe(self):
        self.assertIsNone(self.env["mcp.gateway"]._on_request(
            "auth_failure", None, None, "unauthorized"))

    @unittest.skip("free-only seam default; the pro overrides are active in the merged build (covered by the pro suite)")
    def test_list_tools_accepts_uid(self):
        tools = self.env["mcp.gateway"]._list_tools(self.env.uid)
        self.assertEqual(len(tools), len(TOOLS))

    def test_governed_failure_propagates_tool_error(self):
        gf = "group_ids" if "group_ids" in self.env["res.users"]._fields else "groups_id"
        u = self.env["res.users"].create({
            "name": "GW Restricted", "login": "mcp-gw-restricted",
            gf: [(6, 0, [self.env.ref("base.group_user").id])]})
        with self.assertRaises(ToolAccessError):
            self.env["mcp.gateway"]._execute_tool(
                u.id, "create_record", {"model": "res.groups", "values": {"name": "x"}})

    @unittest.skip("free-only seam default; the pro overrides are active in the merged build (covered by the pro suite)")
    def test_resources_seam_defaults(self):
        gw = self.env["mcp.gateway"]
        self.assertEqual(gw._list_resources(self.env.uid), [])
        self.assertIsNone(gw._read_resource(self.env.uid, "ui://x"))

    def test_capabilities_free_wire_unchanged(self):
        # Free wire output (the `capabilities` object in the initialize
        # response) must stay {"tools": {}, "resources": {}} at its core.
        # On a DB with cledoo_mcp_full co-installed, `mcp.gateway` is the
        # Pro-inherited model and its _capabilities() override legitimately
        # adds an "experimental" key (mcp/apps) -- tolerate that one extra
        # key rather than asserting byte-for-byte equality, so this test
        # doesn't flag Pro's own (already-tested) behaviour as a base-wire
        # regression.
        caps = self.env["mcp.gateway"]._capabilities()
        self.assertEqual(caps["tools"], {})
        self.assertEqual(caps["resources"], {})
        extra = set(caps) - {"tools", "resources"}
        if extra:
            self.assertEqual(extra, {"experimental"})
            self.assertIn("mcp/apps", caps["experimental"])
        else:
            self.assertEqual(caps, {"tools": {}, "resources": {}})
