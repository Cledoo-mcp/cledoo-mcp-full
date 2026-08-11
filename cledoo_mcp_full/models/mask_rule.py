# SPDX-License-Identifier: OPL-1.0
# Copyright (c) 2026 Cledoo
"""PII masking rules, applied post-execute on tool results (before the
audit capture). Derived-field expansion closes the email_normalized
class of leak: a rule on `email` also masks every field whose compute
depends on it or whose related chain ends in it."""
import hashlib

from odoo import fields, models


def _mask_value(value, strategy):
    if not isinstance(value, str) or not value:
        return "***" if value else value
    if strategy == "partial":
        return value[:2] + "***"
    if strategy == "hash":
        return "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:12]
    return "***"  # redact


class McpMaskRule(models.Model):
    _name = "mcp.mask.rule"
    _description = "MCP PII masking rule"

    model_name = fields.Char(required=True, index=True)
    field_name = fields.Char(required=True)
    strategy = fields.Selection(
        [("redact", "Redact (***)"), ("partial", "Partial (ab***)"),
         ("hash", "Hash (stable pseudonym)")],
        default="redact", required=True)
    active = fields.Boolean(default=True)

    def _masked_fields(self, model_name):
        """{field_name: strategy} for a model, expanded to derived
        fields. Expansion sources:
        - compute dependencies: registry.field_depends[g] mentions the
          masked field as a direct dependency on the same model;
        - related chains: g.related's last segment is the masked field.
        One level is enough in practice (email -> email_normalized);
        deeper chains re-enter through the next rule the admin adds."""
        rules = self.sudo().search([("model_name", "=", model_name),
                                    ("active", "=", True)])
        if not rules or model_name not in self.env:
            return {}
        model = self.env[model_name]
        out = {}
        for rule in rules:
            out[rule.field_name] = rule.strategy
            for name, field in model._fields.items():
                if name == rule.field_name:
                    continue
                related = getattr(field, "related", None)
                if related and related.split(".")[-1] == rule.field_name:
                    out.setdefault(name, rule.strategy)
                    continue
                try:
                    deps = self.env.registry.field_depends[field]
                except Exception:
                    deps = ()
                if any(d == rule.field_name or
                       d.split(".")[-1] == rule.field_name for d in deps):
                    out.setdefault(name, rule.strategy)
        return out
