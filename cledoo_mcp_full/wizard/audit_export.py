# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
import base64
import csv
import io
import json

from odoo import fields, models

COLUMNS = ["id", "create_date", "principal_key", "kind", "user_id", "tool",
           "model", "operation", "res_ids", "outcome", "code",
           "duration_ms", "session_id", "remote_addr"]


class McpAuditExport(models.TransientModel):
    _name = "mcp.audit.export"
    _description = "Export MCP audit trail"

    date_from = fields.Date()
    date_to = fields.Date()
    format = fields.Selection([("csv", "CSV"), ("jsonl", "JSONL")],
                              default="csv", required=True)
    file = fields.Binary(readonly=True)
    filename = fields.Char(readonly=True)

    def action_export(self):
        self.ensure_one()
        domain = []
        if self.date_from:
            domain.append(("create_date", ">=", self.date_from))
        if self.date_to:
            domain.append(("create_date", "<=", self.date_to))
        rows = self.env["mcp.audit.log"].sudo().search(domain, order="id")

        # Cell prefixes that a spreadsheet app (Excel/Sheets) interprets
        # as the start of a live formula when a CSV cell is opened.
        FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

        def cell(record, column, csv_safe=False):
            value = record[column]
            if column == "user_id":
                return value.id if value else ""
            if column == "create_date":
                return str(value)
            # Absent values (Odoo yields False for empty Char/Selection,
            # None never but guard anyway) -> "". Real falsy values such
            # as duration_ms == 0 must survive; identity checks only,
            # since `0 in (False, None)` would be True (0 == False).
            if value is False or value is None:
                return ""
            if csv_safe and isinstance(value, str) and value.startswith(
                    FORMULA_PREFIXES):
                # Agent-controlled strings (tool, model, session_id,
                # res_ids, remote_addr...) land verbatim in this export;
                # neutralize CSV formula injection by prefixing a single
                # quote, same as Google Sheets/Excel's own escaping.
                # JSONL is untouched: it preserves real types/strings for
                # machine consumers, not spreadsheet apps.
                return "'" + value
            return value

        records = [{c: cell(r, c) for c in COLUMNS} for r in rows]
        if self.format == "jsonl":
            payload = "\n".join(json.dumps(rec) for rec in records)
            raw, ext = payload.encode(), "jsonl"
        else:
            csv_records = [{c: cell(r, c, csv_safe=True) for c in COLUMNS}
                           for r in rows]
            buf = io.StringIO()
            writer = csv.DictWriter(buf, fieldnames=COLUMNS)
            writer.writeheader()
            writer.writerows(csv_records)
            raw, ext = buf.getvalue().encode("utf-8-sig"), "csv"
        self.write({"file": base64.b64encode(raw),
                    "filename": "mcp_audit.%s" % ext})
        return {"type": "ir.actions.act_window", "res_model": self._name,
                "res_id": self.id, "view_mode": "form", "target": "new"}
