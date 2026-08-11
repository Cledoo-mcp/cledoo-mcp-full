# SPDX-License-Identifier: OPL-1.0
# Copyright (c) 2026 Cledoo
import base64
import json

from odoo.tests import tagged
from odoo.tests.common import TransactionCase


@tagged("post_install", "-at_install")
class TestAuditExport(TransactionCase):
    def setUp(self):
        super().setUp()
        self.Audit = self.env["mcp.audit.log"].sudo()
        self.rows = self.Audit.create([
            {"principal_key": "apikey:1", "tool": "count_records",
             "model": "res.partner", "operation": "read", "outcome": "ok"},
            {"principal_key": "token:9", "tool": "create_record",
             "model": "res.partner", "operation": "write",
             "outcome": "denied", "code": "access_denied"},
        ])

    def test_export_jsonl(self):
        wiz = self.env["mcp.audit.export"].create({"format": "jsonl"})
        wiz.action_export()
        lines = base64.b64decode(wiz.file).decode().strip().splitlines()
        self.assertGreaterEqual(len(lines), 2)
        rec = json.loads(lines[0])
        self.assertIn("principal_key", rec)
        self.assertIn("outcome", rec)

    def test_export_csv_has_header(self):
        wiz = self.env["mcp.audit.export"].create({"format": "csv"})
        wiz.action_export()
        text = base64.b64decode(wiz.file).decode("utf-8-sig")
        self.assertTrue(text.startswith("id,"))
        self.assertIn("count_records", text)

    def test_export_preserves_falsy_values(self):
        # duration_ms == 0 is a real measurement, not an absent value:
        # it must export as 0, never as "" (compliance-grade export).
        self.Audit.create(
            {"principal_key": "apikey:7", "tool": "get_record",
             "model": "res.partner", "operation": "read",
             "outcome": "ok", "duration_ms": 0})
        wiz = self.env["mcp.audit.export"].create({"format": "jsonl"})
        wiz.action_export()
        lines = base64.b64decode(wiz.file).decode().strip().splitlines()
        recs = [json.loads(line) for line in lines]
        zero = next(r for r in recs if r["principal_key"] == "apikey:7")
        self.assertEqual(zero["duration_ms"], 0)
        # Absent Char/Selection values still serialize as "".
        self.assertEqual(zero["code"], "")
        wiz_csv = self.env["mcp.audit.export"].create({"format": "csv"})
        wiz_csv.action_export()
        text = base64.b64decode(wiz_csv.file).decode("utf-8-sig")
        row = next(l for l in text.splitlines() if "apikey:7" in l)
        # ...,outcome,code,duration_ms,... -> ok,,0
        self.assertIn("ok,,0,", row)

    def test_csv_export_escapes_formula_injection(self):
        # A CSV cell starting with =, +, -, @ (or leading tab/CR) is a
        # live formula in Excel/Sheets when opened; an agent-controlled
        # "tool"/"model" string must not be able to plant one in the
        # DPO's spreadsheet. The JSONL export carries real strings and
        # must stay byte-for-byte unquoted.
        self.Audit.create(
            {"principal_key": "apikey:9",
             "tool": '=HYPERLINK("http://evil",  "x")',
             "model": "+cmd", "operation": "read", "outcome": "ok"})
        wiz = self.env["mcp.audit.export"].create({"format": "csv"})
        wiz.action_export()
        text = base64.b64decode(wiz.file).decode("utf-8-sig")
        row = next(l for l in text.splitlines() if "apikey:9" in l)
        self.assertIn("'=HYPERLINK", row)
        self.assertIn("'+cmd", row)

        wiz_jsonl = self.env["mcp.audit.export"].create({"format": "jsonl"})
        wiz_jsonl.action_export()
        lines = base64.b64decode(wiz_jsonl.file).decode().strip().splitlines()
        recs = [json.loads(line) for line in lines]
        rec = next(r for r in recs if r["principal_key"] == "apikey:9")
        self.assertEqual(rec["tool"], '=HYPERLINK("http://evil",  "x")')
        self.assertEqual(rec["model"], "+cmd")

    def test_retention_setting_roundtrip(self):
        s = self.env["res.config.settings"].create(
            {"pro_audit_retention_days": 30})
        s.execute()
        self.assertEqual(self.env["ir.config_parameter"].sudo().get_param(
            "cledoo_mcp_full.audit_retention_days"), "30")
