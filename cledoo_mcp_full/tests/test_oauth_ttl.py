# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Access-token lifetime is configurable (default 8h). The 1h default
proved too short in the field: when the token dies between two claude.ai
conversations, the next conversation starts with the connector silently
absent (no failing tool call = no inline reconnect prompt) and the model
invents explanations. A longer window makes that gap rare; the rotating
90-day refresh token is unchanged."""
import base64
import hashlib
from datetime import timedelta

from odoo import fields as ofields
from odoo.tests import tagged
from odoo.tests.common import HttpCase, TransactionCase

from odoo.addons.cledoo_mcp_full.models import oauth as O


@tagged("post_install", "-at_install")
class TestAccessTtl(TransactionCase):
    def _set(self, val):
        self.env["ir.config_parameter"].sudo().set_param(
            "cledoo_mcp_full.oauth_access_ttl_hours", val)

    def test_default_is_eight_hours(self):
        self.env["ir.config_parameter"].sudo().search(
            [("key", "=", "cledoo_mcp_full.oauth_access_ttl_hours")]).unlink()
        self.assertEqual(O.access_ttl(self.env), 8 * 3600)

    def test_param_override_in_hours(self):
        self._set("2")
        self.assertEqual(O.access_ttl(self.env), 2 * 3600)

    def test_garbage_and_nonpositive_fall_back_to_default(self):
        for val in ("banana", "0", "-3"):
            self._set(val)
            self.assertEqual(O.access_ttl(self.env), 8 * 3600,
                             "should reject %r" % val)

    def test_issued_access_token_expiry_follows_param(self):
        self._set("2")
        self.env["mcp.oauth.token"]._issue_pair("ttl-test-client", 2)
        rec = self.env["mcp.oauth.token"].sudo().search(
            [("client_id", "=", "ttl-test-client"), ("kind", "=", "access")],
            limit=1)
        expected = ofields.Datetime.now() + timedelta(hours=2)
        self.assertLess(abs((rec.expires_at - expected).total_seconds()), 60)


@tagged("post_install", "-at_install")
class TestTokenEndpointExpiresIn(HttpCase):
    def test_expires_in_matches_configured_ttl(self):
        self.env["ir.config_parameter"].sudo().set_param(
            "cledoo_mcp_full.enabled", "True")
        self.env["ir.config_parameter"].sudo().set_param(
            "cledoo_mcp_full.oauth_access_ttl_hours", "2")
        client = self.env["mcp.oauth.client"]._register_client(
            "Claude", ["https://claude.ai/cb"])
        verifier = "verifier-abc-1234567890"
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        code = self.env["mcp.oauth.code"]._issue(
            client.client_id, 2, "https://claude.ai/cb", challenge, None)
        self.env.flush_all()
        r = self.url_open("/mcp/oauth/token", data={
            "grant_type": "authorization_code", "code": code,
            "client_id": client.client_id,
            "redirect_uri": "https://claude.ai/cb",
            "code_verifier": verifier})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["expires_in"], 2 * 3600)
