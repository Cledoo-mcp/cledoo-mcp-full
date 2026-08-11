# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
from odoo import api, fields, models

from odoo.addons.cledoo_mcp_full.lib import telemetry


class ResConfigSettings(models.TransientModel):
    _inherit = "res.config.settings"

    mcp_enabled = fields.Boolean(
        string="Enable MCP Server",
        config_parameter="cledoo_mcp_full.enabled")
    mcp_rate_limit = fields.Integer(
        string="Rate limit (requests/minute)", default=120,
        config_parameter="cledoo_mcp_full.rate_limit",
        help="Per-connection request budget on /mcp. 0 disables the"
             " limiter. Approximate across workers; put a hard limit on"
             " your reverse proxy if you need a guarantee.")
    mcp_max_inline_mb = fields.Integer(
        string="Max inline size (MB)", default=5,
        config_parameter="cledoo_mcp_full.max_inline_mb",
        help="Ceiling for tools that inline a whole payload into the"
             " response (read_resource attachments/binaries, export_records"
             " files, print_report documents). Requests over this size are"
             " refused instead of loading the payload into memory — a guard"
             " against OOM and blown LLM context. Default 5 MB.")
    mcp_annotate_messages = fields.Boolean(
        string="Tag MCP chatter messages", default=True,
        config_parameter="cledoo_mcp_full.annotate_messages",
        help="Chatter messages created through MCP get a small 'MCP'"
             " badge with the client name, so humans can tell AI-written"
             " notes from human ones.")
    mcp_telemetry = fields.Boolean(
        string="Anonymous usage statistics (opt-in)", default=False,
        config_parameter="cledoo_mcp_full.telemetry",
        help="OFF by default — nothing is ever sent unless you enable"
             " this. When enabled: weekly anonymous ping to PostHog (EU)"
             " with version numbers and aggregate counters only — never"
             " your data, model names or hostnames. The exact payload is"
             " documented in the README (Privacy section) and at"
             " https://cledoo.com/privacy.")
    mcp_module_version = fields.Char(
        compute="_compute_mcp_module_version",
        string="MCP module version")
    mcp_endpoint_url = fields.Char(compute="_compute_mcp_endpoint_url")
    mcp_base_url_insecure = fields.Boolean(compute="_compute_mcp_endpoint_url")
    mcp_base_url_unfrozen = fields.Boolean(compute="_compute_mcp_endpoint_url")
    mcp_pro_url = fields.Char(compute="_compute_mcp_pro_url")

    def _compute_mcp_module_version(self):
        """Manifest version of the RUNNING code — the truth the admin
        needs when checking what is deployed (ir.module.module's stored
        version goes stale after a code sync without -u)."""
        try:
            from odoo.modules.module import get_manifest
            version = get_manifest("cledoo_mcp_full").get("version", "?")
        except ImportError:
            from odoo.modules.module import load_manifest
            version = load_manifest("cledoo_mcp_full").get("version", "?")
        for rec in self:
            rec.mcp_module_version = version

    @api.depends("mcp_enabled")
    def _compute_mcp_endpoint_url(self):
        icp = self.env["ir.config_parameter"].sudo()
        base = (icp.get_param("web.base.url") or "").rstrip("/")
        # Common on-prem misconfigurations that silently break the OAuth
        # discovery flow (metadata URLs derive from web.base.url):
        # - reverse proxy without proxy_mode -> base url stays http://
        # - no web.base.url.freeze -> each admin login rewrites the base url
        #   (e.g. to an internal IP), so the OAuth issuer changes under the
        #   client's feet. Surface both in Settings instead of letting the
        #   customer discover them as an opaque Claude connection failure.
        insecure = base.startswith("http://") and not any(
            h in base for h in ("localhost", "127.0.0.1"))
        unfrozen = icp.get_param("web.base.url.freeze") != "True"
        for rec in self:
            rec.mcp_endpoint_url = base + "/mcp"
            rec.mcp_base_url_insecure = insecure
            rec.mcp_base_url_unfrozen = unfrozen

    @api.depends("mcp_telemetry")
    def _compute_mcp_pro_url(self):
        base = "https://cledoo.com/pro"
        for rec in self:
            if telemetry.telemetry_enabled(rec.env):
                rec.mcp_pro_url = "%s?cid=%s" % (
                    base, telemetry.instance_hash(rec.env))
            else:
                rec.mcp_pro_url = base

    def action_open_mcp_pro_url(self):
        """Return an ir.actions.act_url action to open the MCP Pro link.

        This is necessary because form views forbid owl/QWeb directives in
        arch XML, so we cannot bind href dynamically. The action carries
        the computed mcp_pro_url (which includes the anonymous hash if
        telemetry is enabled) and opens it in a new tab.
        """
        return {
            "type": "ir.actions.act_url",
            "url": self.mcp_pro_url,
            "target": "new",
        }

    def _action_open_site(self, path):
        """act_url to a cledoo.com page in the user's language (the site
        serves English at / and French under /fr)."""
        lang = self.env.user.lang or ""
        prefix = "/fr" if lang.startswith("fr") else ""
        return {
            "type": "ir.actions.act_url",
            "url": "https://cledoo.com%s%s" % (prefix, path),
            "target": "new",
        }

    def action_open_mcp_guide_url(self):
        return self._action_open_site("/guide")
