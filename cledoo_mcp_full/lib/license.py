# SPDX-License-Identifier: OPL-1.0
# Copyright (c) 2026 Cledoo
"""Feature set for the Pro governance pipeline.

Cledoo MCP Pro is sold as code (possession = licence, OPL-1) — there is
NO runtime licence check. `active_features()` always reports the full
set, so every governance feature is enforced whenever this module is
installed. The name is kept so existing pipeline call sites are
unchanged."""

FEATURES = frozenset({
    "scopes", "audit", "masking", "policy", "approvals", "quotas",
    "outbound", "analytics", "apps",
})


def active_features(env):  # noqa: ARG001 - env kept for call-site compat
    """All Pro features, always. (Was: offline JWT verification.)"""
    return FEATURES
