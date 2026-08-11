# SPDX-License-Identifier: OPL-1.0
# Copyright (c) 2026 Cledoo
"""Pro contributes anonymous aggregate usage to the base mcp_ping event
(no raw dbuuid, no per-purchase join — opt-out via the base toggle)."""
from odoo import models


class McpTelemetryPro(models.AbstractModel):
    _inherit = "mcp.telemetry"

    def _extra_telemetry_props(self):
        vals = super()._extra_telemetry_props()
        Audit = self.env["mcp.audit.log"].sudo()
        Policy = self.env["mcp.policy"].sudo()
        Approval = self.env["mcp.approval"].sudo()
        vals.update({
            "pro_installed": True,
            "pro_audit_rows": Audit.search_count([]),
            "pro_policies_active": Policy.search_count([("active", "=", True)]),
            "pro_approvals_total": Approval.search_count([]),
        })
        return vals
