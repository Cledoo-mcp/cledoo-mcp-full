# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Token-efficiency behaviors: featured catalog, compact field metadata,
heavy-type exclusion, binary placeholders, pagination probes, whoami."""
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib import tools as T


@tagged("post_install", "-at_install")
class TestToolsContext(TransactionCase):
    def call(self, name, uid=None, **kw):
        fn, _schema, _annotations = T.TOOLS[name]
        return fn(self.env, uid or self.env.uid, **kw)

    # -- list_models / featured catalog --------------------------------
    def test_list_models_default_is_featured_catalog(self):
        # a profile whose model is not installed must be silently ignored
        self.env["mcp.model.profile"].create(
            {"model_name": "not.installed.model", "llm_hint": "ghost"})
        res = self.call("list_models")
        self.assertTrue(res["featured_only"])
        models = [m["model"] for m in res["models"]]
        self.assertIn("res.partner", models)            # installed + featured
        self.assertNotIn("ir.model.access", models)     # readable, not featured
        self.assertNotIn("not.installed.model", models)  # featured, not installed
        self.assertTrue(all("hint" in m for m in res["models"]))
        self.assertIn("all=true", res["hint"])

    def test_list_models_all_returns_everything(self):
        res = self.call("list_models", all=True)
        self.assertNotIn("featured_only", res)
        self.assertIn("ir.model", [m["model"] for m in res["models"]])

    def test_list_models_pattern_searches_all(self):
        res = self.call("list_models", pattern="ir.model")
        self.assertNotIn("featured_only", res)
        self.assertIn("ir.model", [m["model"] for m in res["models"]])

    def test_unfeatured_profile_drops_out(self):
        self.env["mcp.model.profile"].search(
            [("model_name", "=", "res.partner")]).write({"featured": False})
        res = self.call("list_models")
        self.assertNotIn("res.partner", [m["model"] for m in res["models"]])

    # -- get_model_fields compact ---------------------------------------
    def test_fields_compact_by_default(self):
        res = self.call("get_model_fields", model="res.partner")
        self.assertTrue(res["compact"])
        name = res["fields"]["name"]
        self.assertEqual(name["type"], "char")
        self.assertIn("string", name)
        # compact projection must strip the heavy fields_get keys
        self.assertNotIn("searchable", name)
        self.assertNotIn("sortable", name)
        # selection values only (labels live in verbose mode)
        type_field = res["fields"].get("type") or {}
        if "selection" in type_field:
            self.assertTrue(
                all(isinstance(s, str) for s in type_field["selection"]))

    def test_fields_verbose_is_full_fields_get(self):
        res = self.call("get_model_fields", model="res.partner", verbose=True)
        self.assertNotIn("compact", res)
        self.assertIn("searchable", res["fields"]["name"])

    def test_fields_compact_is_much_smaller(self):
        import json
        compact = json.dumps(self.call("get_model_fields", model="res.partner"))
        verbose = json.dumps(self.call("get_model_fields", model="res.partner",
                                       verbose=True))
        self.assertLess(len(compact), len(verbose) / 2)

    # -- search/get defaults & binary masking ---------------------------
    def test_search_default_excludes_heavy_types(self):
        p = self.env["res.partner"].create(
            {"name": "Ctx Co", "comment": "<p>html noise</p>"})
        res = self.call("search_records", model="res.partner",
                        domain=[["id", "=", p.id]])
        row = res["records"][0]
        self.assertIn("name", row)
        self.assertNotIn("image_1920", row)     # binary
        self.assertNotIn("comment", row)        # html
        self.assertNotIn("category_id", row)    # many2many
        self.assertNotIn("child_ids", row)      # one2many

    def test_requested_binary_comes_back_as_placeholder(self):
        import base64
        # ir.attachment.datas: a real binary field with no image validation
        att = self.env["ir.attachment"].create(
            {"name": "blob.bin",
             "datas": base64.b64encode(b"x" * 3000).decode()})
        res = self.call("get_record", model="ir.attachment",
                        record_id=att.id, fields=["name", "datas"])
        val = res["record"]["datas"]
        self.assertTrue(val["__binary__"])
        self.assertGreater(val["size_bytes"], 0)

    def test_search_has_more_pagination_probe(self):
        for i in range(5):
            self.env["res.partner"].create({"name": "Page %d" % i})
        res = self.call("search_records", model="res.partner",
                        domain=[["name", "like", "Page %"]],
                        fields=["name"], limit=2)
        self.assertTrue(res["has_more"])
        self.assertEqual(res["next_offset"], 2)
        last = self.call("search_records", model="res.partner",
                         domain=[["name", "like", "Page %"]],
                         fields=["name"], limit=2, offset=4)
        self.assertFalse(last["has_more"])
        self.assertNotIn("next_offset", last)

    # -- whoami ----------------------------------------------------------
    def test_whoami_identity(self):
        res = self.call("whoami")
        user = self.env.user
        self.assertEqual(res["login"], user.login)
        self.assertEqual(res["company"]["id"], user.company_id.id)
        self.assertIn(user.company_id.id,
                      [c["id"] for c in res["allowed_companies"]])
        self.assertIn("lang", res)
        self.assertIn("tz", res)


@tagged("post_install", "-at_install")
class TestResultTruncation(TransactionCase):
    """Oversized tools/call results get their record list halved until they
    fit, with a truncated/hint marker — exercised through the controller's
    serializer (the transport-level guard, tool-agnostic)."""

    def test_oversized_records_payload_is_truncated_with_hint(self):
        from odoo.addons.cledoo_mcp_full.controllers.mcp import (
            MAX_RESULT_CHARS, McpController)
        data = {"model": "res.partner", "has_more": False,
                "records": [{"id": i, "name": "x" * 8000}
                            for i in range(40)]}  # ~320kB
        text = McpController()._serialize_result(data)
        self.assertLessEqual(len(text), MAX_RESULT_CHARS + 2000)
        import json
        out = json.loads(text)
        self.assertTrue(out["truncated"])
        self.assertIn("fields", out["hint"])
        self.assertLess(len(out["records"]), 40)
        self.assertGreater(len(out["records"]), 0)

    def test_small_payload_untouched(self):
        from odoo.addons.cledoo_mcp_full.controllers.mcp import McpController
        import json
        data = {"records": [{"id": 1}], "has_more": False}
        out = json.loads(McpController()._serialize_result(data))
        self.assertNotIn("truncated", out)
