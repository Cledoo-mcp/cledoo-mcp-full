# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Stamp chatter messages written through MCP with the client identity.

The gateway injects the namespaced `cledoo_mcp_name` context key for
write tools. That key rides env.context into every operation the tool
triggers (comments, field-tracking, but also downstream automations and
outbound mail templates), so create() stamps ONLY the messages the agent
genuinely authored — comments (post_message) and field-tracking
notifications (update_record) — and leaves side-effect emails blank. The
OWL patch renders `mcp_name` as a small MCP badge next to the author."""
from odoo import api, fields, models
from odoo.release import version_info

# Message types the agent genuinely authors; downstream side effects
# (outbound 'email' to customers, mail-template sends) are other types and
# must NOT inherit the MCP stamp just because they fired during the call.
_STAMPED_MESSAGE_TYPES = ("comment", "notification")


class MailMessage(models.Model):
    _inherit = "mail.message"

    mcp_name = fields.Char(
        string="MCP client", readonly=True,
        help="Set when this message was created through the MCP endpoint;"
             " holds the AI client name (OAuth) or the user login (API"
             " key).")

    @api.model_create_multi
    def create(self, vals_list):
        if name := self.env.context.get("cledoo_mcp_name"):
            for vals in vals_list:
                if vals.get("message_type") in _STAMPED_MESSAGE_TYPES:
                    vals.setdefault("mcp_name", name)
        return super().create(vals_list)

    # The discuss store API diverged between the two supported series:
    # 19 asks each model for its default store fields, 18 only exposes
    # the imperative _to_store hook.
    if version_info[0] >= 19:
        def _to_store_defaults(self, target):
            return super()._to_store_defaults(target) + ["mcp_name"]
    else:
        def _to_store(self, store, /, *args, **kwargs):
            super()._to_store(store, *args, **kwargs)
            for message in self:
                store.add(message, {"mcp_name": message.mcp_name or False})
