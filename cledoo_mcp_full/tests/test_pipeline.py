# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib.tools import ToolUserError
from odoo.addons.cledoo_mcp_full.tests.common import LicenseMixin


@tagged("post_install", "-at_install")
class TestPipeline(LicenseMixin, TransactionCase):
    def setUp(self):
        super().setUp()
        self.gw = self.env["mcp.gateway"]
        self.Audit = self.env["mcp.audit.log"].sudo()
        self.ctx = {"session_id": "s1", "remote_addr": "10.0.0.1",
                    "request_id": 1,
                    "principal": {"kind": "apikey", "uid": self.env.uid,
                                  "token_id": None}}

    def test_features_always_on_without_licence(self):
        # No install_license() call: possession = licence, all features on.
        from odoo.addons.cledoo_mcp_full.lib import license as lic
        self.assertEqual(lic.active_features(self.env), lic.FEATURES)
        self.assertEqual(len(lic.FEATURES), 9)

    def test_licensed_call_writes_audit_row(self):
        self.install_license(["audit"])
        self.gw._execute_tool(self.env.uid, "count_records",
                              {"model": "res.partner"}, context=self.ctx)
        row = self.Audit.search([], order="id desc", limit=1)
        self.assertEqual(row.tool, "count_records")
        self.assertEqual(row.model, "res.partner")
        self.assertEqual(row.outcome, "ok")
        self.assertEqual(row.operation, "read")
        self.assertEqual(row.principal_key, "apikey:%d" % self.env.uid)
        self.assertEqual(row.session_id, "s1")
        self.assertGreaterEqual(row.duration_ms, 0)

    def test_error_is_audited_and_reraised(self):
        # Deliberately not `with self.assertRaises(...)`: Odoo's assertRaises
        # wraps its body in `self.env.cr.savepoint()` and rolls it back
        # whenever *any* exception (including the expected one) escapes the
        # block — see `TransactionCase._assertRaises`. That would also
        # discard the audit row this test exists to check, since it rides
        # the same cursor as the tool call (see `_audit`'s docstring). A
        # plain try/except keeps the DB writes made during the call.
        self.install_license(["audit"])
        try:
            self.gw._execute_tool(self.env.uid, "count_records",
                                  {"model": "no.such.model"},
                                  context=self.ctx)
            self.fail("ToolUserError was not raised")
        except ToolUserError:
            pass
        row = self.Audit.search([], order="id desc", limit=1)
        self.assertEqual(row.outcome, "error")
        self.assertEqual(row.code, "validation_error")

    def test_seam_error_abi_unchanged(self):
        from odoo.addons.cledoo_mcp_full.models.gateway import UnknownToolError
        self.install_license(["audit"])
        with self.assertRaises(UnknownToolError):
            self.gw._execute_tool(self.env.uid, "no_such_tool", {},
                                  context=self.ctx)

    def test_content_sentinel_metadata_only(self):
        self.install_license(["audit"])
        att = self.env["ir.attachment"].create({
            "name": "t.txt", "raw": b"hello sentinel"})
        self.gw._execute_tool(self.env.uid, "read_resource",
                              {"uri": "odoo://attachment/%d" % att.id},
                              context=self.ctx)
        row = self.Audit.search([], order="id desc", limit=1)
        self.assertEqual(row.outcome, "ok")
        # arg_fields records call metadata, never blob payloads
        self.assertNotIn("hello sentinel", row.arg_fields or "")
