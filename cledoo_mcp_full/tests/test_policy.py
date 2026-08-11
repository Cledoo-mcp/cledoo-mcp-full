# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
import base64

from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib.tools import ToolAccessError
from odoo.addons.cledoo_mcp_full.tests.common import LicenseMixin


@tagged("post_install", "-at_install")
class TestPolicy(LicenseMixin, TransactionCase):
    def setUp(self):
        super().setUp()
        self.gw = self.env["mcp.gateway"]
        self.Policy = self.env["mcp.policy"].sudo()
        self.ctx = {"principal": {"kind": "apikey", "uid": self.env.uid,
                                  "token_id": None, "apikey_id": None}}
        self.icp = self.env["ir.config_parameter"].sudo()
        self.icp.set_param("cledoo_mcp_full.policy_default_deny", "False")

    def test_deny_rule_blocks_matching_call(self):
        self.install_license(["policy"])
        rule = self.Policy.create({
            "name": "no hr", "model_pattern": "hr.*", "verdict": "deny"})
        with self.assertRaises(ToolAccessError) as ctx:
            self.gw._execute_tool(self.env.uid, "count_records",
                                  {"model": "hr.employee"}, context=self.ctx)
        self.assertIn(rule.name, ctx.exception.message)

    def test_first_match_wins_by_sequence(self):
        self.install_license(["policy"])
        self.Policy.create({"name": "allow partners", "sequence": 1,
                            "model_pattern": "res.partner",
                            "verdict": "allow"})
        self.Policy.create({"name": "deny all", "sequence": 5,
                            "model_pattern": "*", "verdict": "deny"})
        res = self.gw._execute_tool(self.env.uid, "count_records",
                                    {"model": "res.partner"},
                                    context=self.ctx)
        self.assertGreaterEqual(res["count"], 0)
        with self.assertRaises(ToolAccessError):
            self.gw._execute_tool(self.env.uid, "count_records",
                                  {"model": "res.users"}, context=self.ctx)

    def test_operation_filter(self):
        self.install_license(["policy"])
        self.Policy.create({"name": "no writes", "model_pattern": "*",
                            "operation": "write", "verdict": "deny"})
        res = self.gw._execute_tool(self.env.uid, "count_records",
                                    {"model": "res.partner"},
                                    context=self.ctx)
        self.assertGreaterEqual(res["count"], 0)
        with self.assertRaises(ToolAccessError):
            self.gw._execute_tool(self.env.uid, "create_record",
                                  {"model": "res.partner",
                                   "values": {"name": "P"}},
                                  context=self.ctx)

    def test_default_deny(self):
        self.install_license(["policy"])
        self.icp.set_param("cledoo_mcp_full.policy_default_deny", "True")
        with self.assertRaises(ToolAccessError):
            self.gw._execute_tool(self.env.uid, "count_records",
                                  {"model": "res.partner"},
                                  context=self.ctx)
        self.Policy.create({"name": "allow partners",
                            "model_pattern": "res.partner",
                            "verdict": "allow"})
        res = self.gw._execute_tool(self.env.uid, "count_records",
                                    {"model": "res.partner"},
                                    context=self.ctx)
        self.assertGreaterEqual(res["count"], 0)

    def test_field_deny_blocks_write_touching_field(self):
        self.install_license(["policy"])
        self.Policy.create({"name": "protect credit", "verdict": "allow",
                            "model_pattern": "res.partner",
                            "fields_deny": "credit_limit"})
        with self.assertRaises(ToolAccessError):
            self.gw._execute_tool(self.env.uid, "create_record",
                                  {"model": "res.partner",
                                   "values": {"name": "F",
                                              "credit_limit": 9}},
                                  context=self.ctx)

    def test_field_deny_strips_reads(self):
        self.install_license(["policy"])
        partner = self.env["res.partner"].create(
            {"name": "Strippy", "phone": "+331234"})
        self.Policy.create({"name": "hide phones", "verdict": "allow",
                            "model_pattern": "res.partner",
                            "fields_deny": "phone"})
        res = self.gw._execute_tool(self.env.uid, "get_record",
                                    {"model": "res.partner",
                                     "record_id": partner.id,
                                     "fields": ["name", "phone"]},
                                    context=self.ctx)
        flat = str(res)
        self.assertNotIn("+331234", flat)

    def test_field_deny_sanitizes_export_blob(self):
        self.install_license(["policy"])
        self.env["res.partner"].create(
            {"name": "Blobby", "phone": "+335555"})
        self.Policy.create({"name": "hide phones", "verdict": "allow",
                            "model_pattern": "res.partner",
                            "fields_deny": "phone"})
        res = self.gw._execute_tool(self.env.uid, "export_records",
                                    {"model": "res.partner",
                                     "fields": ["name", "phone"],
                                     "format": "csv", "inline": True},
                                    context=self.ctx)
        blob = base64.b64decode(res["content_base64"]).decode("utf-8-sig")
        self.assertIn("Blobby", blob)
        self.assertNotIn("+335555", blob)
        self.assertNotIn("phone", blob)

    def test_export_only_denied_fields_is_denied(self):
        self.install_license(["policy"])
        self.Policy.create({"name": "hide phones", "verdict": "allow",
                            "model_pattern": "res.partner",
                            "fields_deny": "phone"})
        with self.assertRaises(ToolAccessError):
            self.gw._execute_tool(self.env.uid, "export_records",
                                  {"model": "res.partner",
                                   "fields": ["phone"], "format": "csv"},
                                  context=self.ctx)

    def test_aggregate_denied_field_is_denied(self):
        self.install_license(["policy"])
        self.Policy.create({"name": "hide phones", "verdict": "allow",
                            "model_pattern": "res.partner",
                            "fields_deny": "phone"})
        base = {"model": "res.partner"}
        with self.assertRaises(ToolAccessError):  # in aggregates
            self.gw._execute_tool(self.env.uid, "aggregate_records",
                                  dict(base, groupby=["id"],
                                       aggregates=["phone:max"]),
                                  context=self.ctx)
        with self.assertRaises(ToolAccessError):  # in groupby
            self.gw._execute_tool(self.env.uid, "aggregate_records",
                                  dict(base, groupby=["phone"]),
                                  context=self.ctx)
        with self.assertRaises(ToolAccessError):  # dotted path
            self.gw._execute_tool(self.env.uid, "aggregate_records",
                                  dict(base, groupby=["id"],
                                       aggregates=["parent_id.phone:max"]),
                                  context=self.ctx)
        res = self.gw._execute_tool(self.env.uid, "aggregate_records",
                                    dict(base, groupby=["is_company"]),
                                    context=self.ctx)
        self.assertGreaterEqual(res["group_count"], 0)

    def test_domain_and_order_oracle_denied(self):
        self.install_license(["policy"])
        self.Policy.create({"name": "hide phones", "verdict": "allow",
                            "model_pattern": "res.partner",
                            "fields_deny": "phone"})
        with self.assertRaises(ToolAccessError):  # domain probe
            self.gw._execute_tool(self.env.uid, "count_records",
                                  {"model": "res.partner",
                                   "domain": [["phone", "like", "+3312%"]]},
                                  context=self.ctx)
        with self.assertRaises(ToolAccessError):  # order probe
            self.gw._execute_tool(self.env.uid, "search_records",
                                  {"model": "res.partner",
                                   "fields": ["name"],
                                   "order": "phone desc"},
                                  context=self.ctx)
        res = self.gw._execute_tool(self.env.uid, "count_records",
                                    {"model": "res.partner",
                                     "domain": [["name", "!=", False]]},
                                    context=self.ctx)
        self.assertGreaterEqual(res["count"], 0)

    def test_domain_nested_any_oracle_denied(self):
        self.install_license(["policy"])
        self.Policy.create({"name": "hide phones", "verdict": "allow",
                            "model_pattern": "res.partner",
                            "fields_deny": "phone"})
        with self.assertRaises(ToolAccessError):  # nested any-domain probe
            self.gw._execute_tool(
                self.env.uid, "count_records",
                {"model": "res.partner",
                 "domain": [["child_ids", "any",
                            [["phone", "like", "+3312%"]]]]},
                context=self.ctx)
        res = self.gw._execute_tool(
            self.env.uid, "count_records",
            {"model": "res.partner",
             "domain": [["child_ids", "any",
                        [["name", "!=", False]]]]},
            context=self.ctx)
        self.assertGreaterEqual(res["count"], 0)

    def test_domain_nested_not_any_oracle_denied(self):
        self.install_license(["policy"])
        self.Policy.create({"name": "hide phones", "verdict": "allow",
                            "model_pattern": "res.partner",
                            "fields_deny": "phone"})
        with self.assertRaises(ToolAccessError):  # nested not-any probe
            self.gw._execute_tool(
                self.env.uid, "count_records",
                {"model": "res.partner",
                 "domain": [["child_ids", "not any",
                            [["phone", "like", "+3312%"]]]]},
                context=self.ctx)

    def test_approval_verdict_read_passes_through(self):
        # Approval is a write gate: a read matched by an approval-verdict
        # rule is neither paused nor blocked (Task 11).
        self.install_license(["policy"])
        self.Policy.create({"name": "needs a human",
                            "model_pattern": "res.partner",
                            "verdict": "approval"})
        res = self.gw._execute_tool(self.env.uid, "count_records",
                                    {"model": "res.partner"},
                                    context=self.ctx)
        self.assertGreaterEqual(res["count"], 0)


    def test_model_pattern_is_case_sensitive(self):
        # fnmatch.fnmatch case-folds on macOS/Windows but not on Linux,
        # so a dev laptop and prod could silently disagree on whether
        # "Res.*" matches "res.partner". Switching to fnmatchcase makes
        # matching deterministic everywhere: this pattern must NOT match.
        self.install_license(["policy"])
        self.Policy.create({"name": "wrong case", "model_pattern": "Res.*",
                            "verdict": "deny"})
        res = self.gw._execute_tool(self.env.uid, "count_records",
                                    {"model": "res.partner"},
                                    context=self.ctx)
        self.assertGreaterEqual(res["count"], 0)

    def test_field_deny_blocks_nested_x2many_create_command(self):
        # [B3] `touched` used to only look at top-level `values` keys, so
        # values:{child_ids:[(0,0,{denied_field:...})]} wrote a denied
        # field on a related record without tripping the deny.
        self.install_license(["policy"])
        self.Policy.create({"name": "hide phones", "verdict": "allow",
                            "model_pattern": "res.partner",
                            "fields_deny": "phone"})
        with self.assertRaises(ToolAccessError):
            self.gw._execute_tool(
                self.env.uid, "create_record",
                {"model": "res.partner",
                 "values": {"name": "Parent",
                            "child_ids": [(0, 0, {"name": "Kid",
                                                  "phone": "+3319"})]}},
                context=self.ctx)

    def test_field_deny_blocks_nested_x2many_update_command(self):
        self.install_license(["policy"])
        partner = self.env["res.partner"].create({"name": "Parent2"})
        child = self.env["res.partner"].create(
            {"name": "Kid2", "parent_id": partner.id})
        self.Policy.create({"name": "hide phones", "verdict": "allow",
                            "model_pattern": "res.partner",
                            "fields_deny": "phone"})
        with self.assertRaises(ToolAccessError):
            self.gw._execute_tool(
                self.env.uid, "create_record",
                {"model": "res.partner",
                 "values": {"name": "Parent2b",
                            "child_ids": [(1, child.id,
                                          {"phone": "+3320"})]}},
                context=self.ctx)

    def test_field_deny_allows_nested_x2many_non_denied_field(self):
        self.install_license(["policy"])
        self.Policy.create({"name": "hide phones", "verdict": "allow",
                            "model_pattern": "res.partner",
                            "fields_deny": "phone"})
        res = self.gw._execute_tool(
            self.env.uid, "create_record",
            {"model": "res.partner",
             "values": {"name": "Parent3",
                        "child_ids": [(0, 0, {"name": "Kid3"})]}},
            context=self.ctx)
        self.assertTrue(res["id"])
