# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
from datetime import timedelta

from odoo import fields, models
from odoo.fields import Datetime

from odoo.addons.cledoo_mcp_full.lib import telemetry

GRACE_HOURS = 24


class McpTelemetry(models.AbstractModel):
    _name = "mcp.telemetry"
    _description = "MCP anonymous telemetry (opt-in in Settings > MCP Server)"

    def _extra_telemetry_props(self):
        """Seam: add-ons (Pro) merge extra anonymous aggregate properties
        into the mcp_ping event. Base contributes nothing."""
        return {}

    def _cron_send(self):
        """Weekly cron entry point.

        Telemetry is opt-in, so `telemetry.send` already refuses to
        transmit unless the admin enabled it. The first-seen grace period
        is kept as a second safety net: even after an opt-in, the first
        cron run only records a timestamp and sends nothing."""
        icp = self.env["ir.config_parameter"].sudo()
        first = icp.get_param("cledoo_mcp_full.telemetry_first_seen")
        now = Datetime.now()
        if not first:
            icp.set_param("cledoo_mcp_full.telemetry_first_seen",
                          fields.Datetime.to_string(now))
            return False
        if Datetime.to_datetime(first) > now - timedelta(hours=GRACE_HOURS):
            return False
        return telemetry.send(self.env)
