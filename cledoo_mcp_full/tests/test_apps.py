# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib.tools import ToolAccessError
from odoo.addons.cledoo_mcp_full.tests.common import LicenseMixin


@tagged("post_install", "-at_install")
class TestMcpApps(LicenseMixin, TransactionCase):
    def setUp(self):
        super().setUp()
        self.gw = self.env["mcp.gateway"]

    def test_resources_listed_when_licensed(self):
        self.install_license(["apps"])
        uris = {r["uri"] for r in self.gw._list_resources(self.env.uid)}
        self.assertIn("ui://cledoo/approval-card", uris)
        self.assertIn("ui://cledoo/analytics-snapshot", uris)
        self.assertIn("ui://cledoo/denial-explainer", uris)

    def test_read_resource_returns_html(self):
        self.install_license(["apps"])
        doc = self.gw._read_resource(self.env.uid,
                                     "ui://cledoo/approval-card")
        self.assertEqual(doc["mimeType"], "text/html;profile=mcp-app")
        self.assertIn("<html", doc["text"].lower())

    def test_list_resources_mime_carries_mcp_app_profile(self):
        self.install_license(["apps"])
        resources = self.gw._list_resources(self.env.uid)
        by_uri = {r["uri"]: r for r in resources}
        self.assertEqual(
            by_uri["ui://cledoo/approval-card"]["mimeType"],
            "text/html;profile=mcp-app")

    def test_capabilities_advertise_mcp_apps(self):
        # Pro has no runtime licence gate (see lib/license.py): "apps" is
        # always in active_features() once the module is installed, same
        # gate the ui:// resources themselves use.
        caps = self.gw._capabilities()
        self.assertIn("mcp/apps", caps.get("experimental", {}))

    def test_check_approval_descriptor_carries_ui_meta(self):
        self.install_license(["policy", "approvals", "apps"])
        tools = {t["name"]: t for t in self.gw._list_tools(self.env.uid)}
        self.assertEqual(
            tools["check_approval"].get("_meta", {}).get("ui", {})
            .get("resourceUri"), "ui://cledoo/approval-card")

    def test_check_approval_result_carries_ui_meta(self):
        self.install_license(["policy", "approvals", "apps"])
        ctx = {"principal": {"kind": "apikey", "uid": self.env.uid,
                             "token_id": None, "apikey_id": None}}
        self.env["mcp.policy"].sudo().create({
            "name": "gate", "model_pattern": "res.partner",
            "operation": "write", "verdict": "approval"})
        res = self.gw._execute_tool(
            self.env.uid, "create_record",
            {"model": "res.partner", "values": {"name": "AppCard"}},
            context=ctx)
        out = self.gw._execute_tool(self.env.uid, "check_approval",
                                    {"ticket_id": res["ticket_id"]},
                                    context=ctx)
        self.assertEqual(
            out.get("__mcp_meta__", {}).get("ui", {}).get("resourceUri"),
            "ui://cledoo/approval-card")

    def test_mcp_analytics_descriptor_carries_ui_meta(self):
        self.install_license(["analytics", "apps"])
        tools = {t["name"]: t for t in self.gw._list_tools(self.env.uid)}
        self.assertIn("mcp_analytics", tools)
        self.assertEqual(
            tools["mcp_analytics"].get("_meta", {}).get("ui", {})
            .get("resourceUri"), "ui://cledoo/analytics-snapshot")

    def test_mcp_analytics_result_carries_ui_meta(self):
        self.install_license(["analytics", "apps"])
        ctx = {"principal": {"kind": "apikey", "uid": self.env.uid,
                             "token_id": None, "apikey_id": None}}
        out = self.gw._execute_tool(self.env.uid, "mcp_analytics", {},
                                    context=ctx)
        self.assertEqual(
            out.get("__mcp_meta__", {}).get("ui", {}).get("resourceUri"),
            "ui://cledoo/analytics-snapshot")

    def test_mcp_analytics_stats_correctness(self):
        self.install_license(["analytics", "apps"])
        ctx = {"principal": {"kind": "apikey", "uid": self.env.uid,
                             "token_id": None, "apikey_id": None}}
        self.env["mcp.audit.log"].sudo().create([
            {"principal_key": "apikey:1", "tool": "count_records",
             "model": "res.partner", "operation": "read", "outcome": "ok"},
            {"principal_key": "apikey:1", "tool": "count_records",
             "model": "res.partner", "operation": "read", "outcome": "ok"},
            {"principal_key": "apikey:2", "tool": "create_record",
             "model": "res.partner", "operation": "write",
             "outcome": "denied", "code": "access_denied"},
        ])
        self.env.flush_all()
        out = self.gw._execute_tool(self.env.uid, "mcp_analytics", {},
                                    context=ctx)
        # The mcp_analytics call itself is audited AFTER it computes its
        # stats (finally block), so only the 3 seeded rows are counted.
        self.assertEqual(out["total"], 3)
        self.assertEqual(out["denied"], 1)
        self.assertEqual(out["allowed"], 2)
        self.assertEqual(out["active_principals"], 2)
        top = {t["tool"]: t["calls"] for t in out["top_tools"]}
        self.assertEqual(top.get("count_records"), 2)
        self.assertEqual(top.get("create_record"), 1)

    def test_mcp_analytics_days_capped(self):
        self.install_license(["analytics", "apps"])
        ctx = {"principal": {"kind": "apikey", "uid": self.env.uid,
                             "token_id": None, "apikey_id": None}}
        out = self.gw._execute_tool(self.env.uid, "mcp_analytics",
                                    {"days": 10000}, context=ctx)
        self.assertEqual(out["days"], 365)
        out = self.gw._execute_tool(self.env.uid, "mcp_analytics",
                                    {"days": -5}, context=ctx)
        self.assertEqual(out["days"], 1)

    def test_policy_denial_carries_denial_explainer_meta(self):
        # T2: a policy-rule denial must stamp the same ui:// hint apps.py
        # serves as a resource, so MCP Apps clients can render the
        # denial-explainer card instead of bare error text.
        self.install_license(["policy", "apps"])
        ctx = {"principal": {"kind": "apikey", "uid": self.env.uid,
                             "token_id": None, "apikey_id": None}}
        self.env["mcp.policy"].sudo().create({
            "name": "block partner reads", "model_pattern": "res.partner",
            "operation": "read", "verdict": "deny"})
        with self.assertRaises(ToolAccessError) as cm:
            self.gw._execute_tool(
                self.env.uid, "search_records",
                {"model": "res.partner", "domain": []}, context=ctx)
        self.assertEqual(
            cm.exception.meta,
            {"ui": {"resourceUri": "ui://cledoo/denial-explainer"}})

    def test_policy_denial_wire_result_carries_meta(self):
        # End-to-end through the base controller's error-result builder:
        # confirms the base _tool_error_result plumbing (T2's LGPL half)
        # actually surfaces the meta Pro attaches, not just that the
        # exception object carries it.
        from odoo.addons.cledoo_mcp_full.controllers.mcp import _tool_error_result
        self.install_license(["policy", "apps"])
        ctx = {"principal": {"kind": "apikey", "uid": self.env.uid,
                             "token_id": None, "apikey_id": None}}
        self.env["mcp.policy"].sudo().create({
            "name": "block partner reads", "model_pattern": "res.partner",
            "operation": "read", "verdict": "deny"})
        with self.assertRaises(ToolAccessError) as cm:
            self.gw._execute_tool(
                self.env.uid, "search_records",
                {"model": "res.partner", "domain": []}, context=ctx)
        res = _tool_error_result(1, cm.exception)
        self.assertEqual(
            res["result"]["_meta"],
            {"ui": {"resourceUri": "ui://cledoo/denial-explainer"}})
