# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Curated model catalog for the LLM.

`list_models` without arguments returns only the featured entries below
(with their one-line hints) instead of the full readable-model dump —
a mid-size database has 500+ models, which costs the agent a screenful
of tokens on the very first call of every session. This is a *guidance*
layer, not an access-control one: ACLs still decide what is readable,
and pattern=/all=true still search everything (deny-by-default policy
is an MCP Pro feature)."""
from odoo import fields, models


class McpModelProfile(models.Model):
    _name = "mcp.model.profile"
    _description = "MCP featured model (LLM catalog entry)"
    _order = "sequence, id"

    sequence = fields.Integer(default=100)
    model_name = fields.Char(
        required=True, index=True,
        help="Technical model name (e.g. sale.order). Entries for modules"
             " that are not installed are ignored at runtime.")
    llm_hint = fields.Char(
        help="One line telling the AI what this model stores,"
             " e.g. 'Sales orders and quotations'.")
    featured = fields.Boolean(
        default=True,
        help="Featured models are what list_models returns by default.")

    def init(self):
        # See activity.py: hand-made unique index instead of the legacy
        # _sql_constraints, which Odoo 19 no longer loads.
        self.env.cr.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS"
            " mcp_model_profile_model_name_uniq"
            " ON mcp_model_profile (model_name)")
