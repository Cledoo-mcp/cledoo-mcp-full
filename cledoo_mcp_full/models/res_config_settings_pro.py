# SPDX-License-Identifier: OPL-1.0
# Copyright (c) 2026 Cledoo
from odoo import fields, models


class ResConfigSettings(models.TransientModel):
    _inherit = "res.config.settings"

    pro_module_version = fields.Char(
        compute="_compute_pro_module_version",
        string="MCP Pro module version")

    def _compute_pro_module_version(self):
        """Manifest version of the RUNNING Pro code (see the classic
        mcp_module_version for why the manifest, not ir.module.module)."""
        try:
            from odoo.modules.module import get_manifest
            version = get_manifest("cledoo_mcp_full").get("version", "?")
        except ImportError:
            from odoo.modules.module import load_manifest
            version = load_manifest("cledoo_mcp_full").get("version", "?")
        for rec in self:
            rec.pro_module_version = version

    pro_audit_retention_days = fields.Integer(
        string="Audit retention (days)", default=180,
        config_parameter="cledoo_mcp_full.audit_retention_days",
        help="Audit rows older than this are dropped by autovacuum. "
             "0 keeps everything forever.")
    pro_policy_default_deny = fields.Boolean(
        string="Policy: deny by default",
        config_parameter="cledoo_mcp_full.policy_default_deny",
        help="When on, an MCP call on a model that no policy rule "
             "explicitly allows is denied. Build the allow-list with "
             "dry-run rules and the simulator first.")
    pro_digest_email = fields.Char(
        string="Monthly digest recipient",
        config_parameter="cledoo_mcp_full.digest_email",
        help="Email address that receives the monthly AI activity report "
             "(calls, writes, denials, alerts, approvals). Empty disables "
             "the digest.")
    pro_mcp_readonly = fields.Boolean(
        string="MCP read-only mode", default=False,
        config_parameter="cledoo_mcp_full.readonly",
        help="Block every write tool for all AI clients at once — the "
             "global kill-switch. Per-connection scopes offer finer "
             "control.")
