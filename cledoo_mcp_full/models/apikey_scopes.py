# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
from odoo import fields, models
from odoo.tools import SQL


class ResUsersApikeys(models.Model):
    _inherit = "res.users.apikeys"

    mcp_readonly = fields.Boolean(
        string="MCP read-only",
        help="This key may only call read tools on /mcp.")
    mcp_models = fields.Char(
        string="MCP models",
        help="Comma-separated model names this key is limited to on "
             "/mcp. Empty = every model the user's ACLs allow.")

    def init(self):
        # Base declares res.users.apikeys with _auto = False (it manages
        # its own table by hand, to keep the secret `key` column out of
        # ORM auto-migration). The ORM therefore never adds columns for
        # fields we bolt on here — do it ourselves, idempotently.
        super().init()
        self.env.cr.execute(SQL(
            "ALTER TABLE %(table)s "
            "ADD COLUMN IF NOT EXISTS mcp_readonly boolean, "
            "ADD COLUMN IF NOT EXISTS mcp_models varchar",
            table=SQL.identifier(self._table)))
