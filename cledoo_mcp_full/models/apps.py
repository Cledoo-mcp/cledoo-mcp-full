# SPDX-License-Identifier: OPL-1.0
# Copyright (c) 2026 Cledoo
"""MCP Apps (feature 'apps'): self-contained HTML documents served as
ui:// resources; clients with MCP Apps support render them in-chat.
Documents receive their data via the MCP Apps postMessage bridge — the
HTML itself is static and safe to cache."""
from odoo import models
from odoo.tools.misc import file_open

from odoo.addons.cledoo_mcp_full.lib import license as lic

APPS = {
    "ui://cledoo/approval-card": ("cledoo_mcp_full/static/apps/approval_card.html",
                                  "Approval ticket status"),
    "ui://cledoo/analytics-snapshot": (
        "cledoo_mcp_full/static/apps/analytics_snapshot.html",
        "MCP analytics snapshot"),
    "ui://cledoo/denial-explainer": (
        "cledoo_mcp_full/static/apps/denial_explainer.html",
        "Policy denial explainer"),
}


# MCP Apps profile suffix (SEP UI extension): tells a client the
# text/html body is an MCP Apps document (postMessage bridge), not a
# plain HTML resource to render/download as-is.
_UI_MIME = "text/html;profile=mcp-app"


class McpGatewayApps(models.AbstractModel):
    _inherit = "mcp.gateway"

    def _capabilities(self):
        vals = super()._capabilities()
        if "apps" in lic.active_features(self.env):
            vals.setdefault("experimental", {})["mcp/apps"] = {}
        return vals

    def _list_resources(self, uid=None):
        resources = super()._list_resources(uid=uid)
        if "apps" not in lic.active_features(self.env):
            return resources
        resources.extend({
            "uri": uri, "name": name, "mimeType": _UI_MIME,
        } for uri, (_path, name) in APPS.items())
        return resources

    def _read_resource(self, uid, uri):
        # Deliberately outside the governance pipeline/audit: these ui://
        # cards are static HTML templates shipped with the module — zero
        # tenant data (the host injects data client-side via postMessage).
        doc = super()._read_resource(uid, uri)
        if doc is not None or "apps" not in lic.active_features(self.env):
            return doc
        entry = APPS.get(uri)
        if not entry:
            return None
        with file_open(entry[0], "r") as handle:
            return {"uri": uri, "mimeType": _UI_MIME,
                    "text": handle.read()}
