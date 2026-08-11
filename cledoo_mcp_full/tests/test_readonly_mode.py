# SPDX-License-Identifier: OPL-1.0
# Copyright (c) 2026 Cledoo
"""T3: the global read-only kill-switch, moved here from the free module
(fine-grained governance is paid-only). Same system parameter
(`cledoo_mcp_full.readonly`), same annotation-driven blocking at the gateway
seam, plus a filtered tools/list — now enforced in the Pro pipeline
(`_check_readonly`, models/gateway.py) instead of the base one."""
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib.tools import ToolAccessError
from odoo.addons.cledoo_mcp_full.tests.common import LicenseMixin


@tagged("post_install", "-at_install")
class TestReadonlyMode(LicenseMixin, TransactionCase):
    def setUp(self):
        super().setUp()
        self.icp = self.env["ir.config_parameter"].sudo()
        self.gw = self.env["mcp.gateway"]

    def set_ro(self, value):
        self.icp.set_param("cledoo_mcp_full.readonly", "True" if value else "False")

    def test_write_tool_blocked_when_on(self):
        self.set_ro(True)
        with self.assertRaises(ToolAccessError) as ctx:
            self.gw._execute_tool(self.env.uid, "create_record",
                                  {"model": "res.partner",
                                   "values": {"name": "RO Co"}})
        self.assertIn("read-only", ctx.exception.message)

    def test_read_tool_allowed_when_on(self):
        self.set_ro(True)
        res = self.gw._execute_tool(self.env.uid, "count_records",
                                    {"model": "res.partner"})
        self.assertGreaterEqual(res["count"], 0)

    def test_write_tool_allowed_when_off(self):
        self.set_ro(False)
        res = self.gw._execute_tool(self.env.uid, "create_record",
                                    {"model": "res.partner",
                                     "values": {"name": "RW Co"}})
        self.assertTrue(res["id"])

    def test_default_is_off(self):
        self.icp.set_param("cledoo_mcp_full.readonly", False)
        res = self.gw._execute_tool(self.env.uid, "create_record",
                                    {"model": "res.partner",
                                     "values": {"name": "Default Co"}})
        self.assertTrue(res["id"])

    def test_tools_list_filtered_when_on(self):
        self.set_ro(True)
        tools = {t["name"]: t for t in self.gw._list_tools(self.env.uid)}
        names = set(tools)
        self.assertNotIn("create_record", names)
        self.assertNotIn("delete_record", names)
        self.assertIn("search_records", names)
        # Pro read-only tools stay visible: mcp_analytics is genuinely
        # read-only (readOnlyHint True). check_approval stays visible via
        # an explicit by-name carve-out in _list_tools, NOT because its
        # annotation says readOnlyHint — the wire annotation must stay
        # honest (clients use it for trust UI, e.g. auto-invoke without
        # confirmation) since check_approval can land an approved write.
        self.assertIn("mcp_analytics", names)
        self.assertIn("check_approval", names)
        self.assertFalse(
            tools["check_approval"]["annotations"].get("readOnlyHint"),
            "check_approval's wire annotation must stay honest (False): "
            "it can land a write, even though it's pollable under readonly.")
        self.set_ro(False)
        names = {t["name"] for t in self.gw._list_tools(self.env.uid)}
        self.assertIn("create_record", names)

    def test_settings_field_roundtrip(self):
        s = self.env["res.config.settings"].create({"pro_mcp_readonly": True})
        s.execute()
        self.assertEqual(self.icp.get_param("cledoo_mcp_full.readonly"), "True")

    def test_approved_ticket_write_still_blocked_when_on(self):
        """check_approval itself stays listed/callable in read-only mode,
        but the write it would replay for an approved ticket is still
        blocked — the nested `_execute_tool` call re-checks readonly
        against the real tool's (non-readOnlyHint) annotation."""
        ctx = {"principal": {"kind": "apikey", "uid": self.env.uid,
                             "token_id": None, "apikey_id": None}}
        self.env["mcp.policy"].sudo().create({
            "name": "writes need approval", "model_pattern": "res.partner",
            "operation": "write", "verdict": "approval"})
        field = ("group_ids" if "group_ids" in self.env["res.users"]._fields
                 else "groups_id")
        approver = self.env["res.users"].create({
            "name": "Approver", "login": "ro_approver@test",
            field: [(6, 0, [
                self.env.ref("base.group_user").id,
                self.env.ref("cledoo_mcp_full.group_approver").id])]})
        pending = self.gw._execute_tool(
            self.env.uid, "create_record",
            {"model": "res.partner", "values": {"name": "NeedsOK"}},
            context=ctx)
        ticket = self.env["mcp.approval"].sudo().browse(pending["ticket_id"])
        ticket.with_user(approver).action_approve()
        self.set_ro(True)
        with self.assertRaises(ToolAccessError):
            self.gw._execute_tool(self.env.uid, "check_approval",
                                  {"ticket_id": ticket.id}, context=ctx)
