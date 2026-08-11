# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Anonymous usage telemetry — OPT-IN, stdlib-only, nothing nameable.

Pings go to PostHog (EU) as `mcp_ping` events: no receiver service to
build or operate, dashboards for free. The project API key below is a
PUBLIC write-only ingestion key (PostHog's client-side design — it can
create events, never read them), so shipping it in the module source is
fine.

The exact payload is documented in the README (Privacy section) and must
stay boring: a salted hash of the database uuid (not reversible, not
joinable with anything else Odoo sends anywhere), version strings, and a
handful of aggregate integers. NO model names, NO hostnames, NO user or
company data, NO tool arguments. If a future field can identify an
instance or its contents, it does not ship."""
import hashlib
import json
import logging
from urllib import request as urlrequest

from odoo import release

from odoo.addons.cledoo_mcp_full.lib.params import is_enabled

_logger = logging.getLogger(__name__)

DEFAULT_URL = "https://eu.i.posthog.com/capture/"
# "Cledoo Module" PostHog organization (project 216612) — dedicated to
# module telemetry, separate from any other product analytics.
POSTHOG_API_KEY = "phc_tfUitktmfGuHHDXmyLxxueWVpNDEmLQyX4HYAMpvjpiq"
EVENT_NAME = "mcp_ping"
_SALT = "cledoo_mcp_full:v1"
_TRUTHY = ("true", "1", "yes", "on")


def instance_hash(env):
    """One-way, non-reversible id derived from database.uuid. Shared by
    the telemetry payload and the MCP Pro upsell link so the same
    anonymous identity can be recognised in both places, without
    exposing or storing the raw database uuid anywhere else."""
    dbuuid = env["ir.config_parameter"].sudo().get_param("database.uuid") or ""
    return hashlib.sha256(("%s:%s" % (_SALT, dbuuid)).encode()).hexdigest()


def telemetry_enabled(env):
    """Default OFF (opt-in): an absent parameter means disabled — nothing
    is transmitted until the admin explicitly enables it via the Settings
    checkbox (Odoo Apps opt-in requirement)."""
    val = env["ir.config_parameter"].sudo().get_param(
        "cledoo_mcp_full.telemetry")
    if val in (None, False, ""):
        return False
    return str(val).strip().lower() in _TRUTHY


def build_payload(env):
    """PostHog capture-API shape: one `mcp_ping` event per instance.
    distinct_id is the salted instance hash; $process_person_profile is
    off so PostHog keeps these as cheap anonymous events (no person
    profiles for ERP servers)."""
    icp = env["ir.config_parameter"].sudo()
    Token = env["mcp.oauth.token"].sudo()
    Activity = env["mcp.endpoint.activity"].sudo()
    from odoo.modules.module import get_manifest
    props = {
        "$process_person_profile": False,
        "module_version": get_manifest("cledoo_mcp_full").get("version"),
        "odoo_series": release.major_version,
        "enabled": is_enabled(env),
        "oauth_clients": env["mcp.oauth.client"].sudo().search_count([]),
        "oauth_tokens_active": Token.search_count(
            [("kind", "=", "access"), ("revoked", "=", False)]),
        "principals": Activity.search_count([]),
        "calls_total": sum(Activity.search([]).mapped("call_count")),
    }
    # Add-ons (Pro) contribute extra anonymous aggregate properties.
    props.update(env["mcp.telemetry"].sudo()._extra_telemetry_props())
    return {
        "api_key": POSTHOG_API_KEY,
        "event": EVENT_NAME,
        "distinct_id": instance_hash(env),
        "properties": props,
    }


def send(env):
    """One ping. Never raises; returns True iff the POST went out."""
    if not telemetry_enabled(env):
        return False
    url = (env["ir.config_parameter"].sudo().get_param(
        "cledoo_mcp_full.telemetry_url") or DEFAULT_URL)
    try:
        req = urlrequest.Request(
            url, data=json.dumps(build_payload(env)).encode(),
            headers={"Content-Type": "application/json"})
        urlrequest.urlopen(req, timeout=5)
        return True
    except Exception:
        # A telemetry failure must never surface anywhere user-visible.
        _logger.debug("mcp telemetry ping failed", exc_info=True)
        return False
