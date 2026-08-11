# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""System-parameter helpers shared by the MCP controllers."""

# The Settings toggle writes the literal "True", but integrators routinely
# set ir.config_parameter by hand ("true", "1", "yes"); treat every common
# truthy spelling as enabled instead of failing closed on a case mismatch.
_TRUTHY = ("true", "1", "yes", "on")


def is_enabled(env):
    val = env["ir.config_parameter"].sudo().get_param("cledoo_mcp_full.enabled")
    return str(val or "").strip().lower() in _TRUTHY


def get_int_param(env, key, default):
    """An ir.config_parameter as int, falling back on absent/garbage values."""
    val = env["ir.config_parameter"].sudo().get_param(key)
    try:
        return int(str(val).strip())
    except (TypeError, ValueError):
        return default
