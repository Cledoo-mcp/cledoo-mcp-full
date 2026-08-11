# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Consent scopes: extra columns on the OAuth code and token, filled by
the consent page via the base scope_vals seam (Task 5)."""
from odoo import fields, models


class McpOAuthCode(models.Model):
    _inherit = "mcp.oauth.code"

    scope_readonly = fields.Boolean(default=False)
    scope_models = fields.Char(
        help="Comma-separated model names this grant is limited to. "
             "Empty = every model the user's ACLs allow.")

    def _scope_vals(self):
        # Inject keys only when a scope is actually set: the lite contract
        # (base test_seam_scope_hooks) expects {} for an unscoped record,
        # and create() column defaults make the omission identical.
        vals = super()._scope_vals()
        if self.scope_readonly or self.scope_models:
            vals.update({"scope_readonly": self.scope_readonly,
                         "scope_models": self.scope_models or False})
        return vals


class McpOAuthToken(models.Model):
    _inherit = "mcp.oauth.token"

    scope_readonly = fields.Boolean(default=False)
    scope_models = fields.Char()

    def _rotation_scope_vals(self):
        # Same empty-dict contract as _scope_vals: unscoped tokens rotate
        # with no extra keys (column defaults apply).
        vals = super()._rotation_scope_vals()
        if self.scope_readonly or self.scope_models:
            vals.update({"scope_readonly": self.scope_readonly,
                         "scope_models": self.scope_models or False})
        return vals
