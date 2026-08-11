# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
import base64
import hashlib
import json
from urllib.parse import urlparse, parse_qs

from odoo.tests import tagged
from odoo.tests.common import HttpCase


@tagged("post_install", "-at_install")
class TestOAuthAuthorize(HttpCase):
    def setUp(self):
        super().setUp()
        self.env["ir.config_parameter"].sudo().set_param("cledoo_mcp_full.enabled", "True")
        self.client = self.env["mcp.oauth.client"]._register_client(
            "Claude", ["https://claude.ai/cb"])
        self.env.flush_all()
        self.verifier = "verifier-abc-1234567890"
        self.challenge = base64.urlsafe_b64encode(
            hashlib.sha256(self.verifier.encode()).digest()).rstrip(b"=").decode()

    def _authorize_url(self, **over):
        p = {"response_type": "code", "client_id": self.client.client_id,
             "redirect_uri": "https://claude.ai/cb", "state": "xyz",
             "code_challenge": self.challenge, "code_challenge_method": "S256"}
        p.update(over)
        from werkzeug.urls import url_encode
        return "/mcp/oauth/authorize?" + url_encode(p)

    def test_authorize_requires_login_then_shows_consent(self):
        # Not logged in -> Odoo redirects to /web/login (302 or login page).
        r = self.url_open(self._authorize_url(), allow_redirects=False)
        self.assertIn(r.status_code, (302, 303, 200))
        # Logged in -> consent page renders.
        self.authenticate("admin", "admin")
        r = self.url_open(self._authorize_url())
        self.assertEqual(r.status_code, 200)
        self.assertIn("Authorize", r.text)
        # consent must show where the grant goes + refuse framing
        self.assertIn("claude.ai", r.text)
        # permission bullets derive from the gateway's tool annotations
        self.assertIn("Read data you have access to", r.text)
        self.assertIn("Delete records", r.text)
        self.assertEqual(r.headers.get("X-Frame-Options"), "DENY")
        self.assertIn("frame-ancestors",
                      r.headers.get("Content-Security-Policy", ""))

    def test_consent_allow_issues_code_to_redirect(self):
        self.authenticate("admin", "admin")
        # Fetch consent page to obtain csrf_token from the rendered form.
        page = self.url_open(self._authorize_url()).text
        import re
        csrf = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page).group(1)
        r = self.url_open("/mcp/oauth/authorize", allow_redirects=False, data={
            "csrf_token": csrf, "decision": "allow",
            "client_id": self.client.client_id, "redirect_uri": "https://claude.ai/cb",
            "state": "xyz", "code_challenge": self.challenge,
            "code_challenge_method": "S256", "resource": ""})
        self.assertIn(r.status_code, (302, 303))
        q = parse_qs(urlparse(r.headers["Location"]).query)
        self.assertEqual(q["state"][0], "xyz")
        self.assertIn("code", q)

    def test_trusted_redirect_host_hides_unverified_caution(self):
        # claude.ai is in the default trusted list: the anxiety-inducing
        # "(unverified application)" must not show for the nominal flow.
        self.authenticate("admin", "admin")
        r = self.url_open(self._authorize_url())
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("unverified application", r.text)

    def test_unknown_redirect_host_shows_unverified_caution(self):
        other = self.env["mcp.oauth.client"]._register_client(
            "Claude", ["https://agent.unknown-vendor.example/cb"])
        self.env.flush_all()
        self.authenticate("admin", "admin")
        r = self.url_open(self._authorize_url(
            client_id=other.client_id,
            redirect_uri="https://agent.unknown-vendor.example/cb"))
        self.assertEqual(r.status_code, 200)
        self.assertIn("unverified application", r.text)

    def test_trusted_host_subdomain_matches(self):
        sub = self.env["mcp.oauth.client"]._register_client(
            "Claude", ["https://connector.claude.ai/cb"])
        self.env.flush_all()
        self.authenticate("admin", "admin")
        r = self.url_open(self._authorize_url(
            client_id=sub.client_id,
            redirect_uri="https://connector.claude.ai/cb"))
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("unverified application", r.text)

    def test_lookalike_host_is_not_trusted(self):
        # suffix matching must not accept evil-claude.ai lookalikes
        evil = self.env["mcp.oauth.client"]._register_client(
            "Claude", ["https://evilclaude.ai/cb"])
        self.env.flush_all()
        self.authenticate("admin", "admin")
        r = self.url_open(self._authorize_url(
            client_id=evil.client_id,
            redirect_uri="https://evilclaude.ai/cb"))
        self.assertEqual(r.status_code, 200)
        self.assertIn("unverified application", r.text)

    def test_trusted_hosts_param_override(self):
        self.env["ir.config_parameter"].sudo().set_param(
            "cledoo_mcp_full.trusted_redirect_hosts", "other-ai.example")
        self.env.flush_all()
        self.authenticate("admin", "admin")
        r = self.url_open(self._authorize_url())
        self.assertEqual(r.status_code, 200)
        self.assertIn("unverified application", r.text)  # claude.ai no longer listed

    def test_portal_user_cannot_authorize(self):
        # Wiring an autonomous agent into the DB is internal-users-only in
        # the free module (granular consent scopes are an MCP Pro feature).
        gf = "group_ids" if "group_ids" in self.env["res.users"]._fields else "groups_id"
        self.env["res.users"].create({
            "name": "Portal Paul", "login": "portal.paul",
            "password": "portal.paul.pwd12",
            gf: [(6, 0, [self.env.ref("base.group_portal").id])],
        })
        self.env.flush_all()
        self.authenticate("portal.paul", "portal.paul.pwd12")
        r = self.url_open(self._authorize_url())
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.json()["error"], "access_denied")

    def test_bad_redirect_uri_rejected(self):
        self.authenticate("admin", "admin")
        r = self.url_open(self._authorize_url(redirect_uri="https://evil/cb"))
        self.assertEqual(r.status_code, 400)

    def test_plain_pkce_rejected(self):
        self.authenticate("admin", "admin")
        r = self.url_open(self._authorize_url(code_challenge_method="plain"))
        self.assertEqual(r.status_code, 400)

    def test_consent_deny_redirects_access_denied_no_code(self):
        self.authenticate("admin", "admin")
        import re
        page = self.url_open(self._authorize_url()).text
        csrf = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page).group(1)
        r = self.url_open("/mcp/oauth/authorize", allow_redirects=False, data={
            "csrf_token": csrf, "decision": "deny",
            "client_id": self.client.client_id, "redirect_uri": "https://claude.ai/cb",
            "state": "xyz", "code_challenge": self.challenge,
            "code_challenge_method": "S256", "resource": ""})
        self.assertIn(r.status_code, (302, 303))
        from urllib.parse import urlparse, parse_qs
        q = parse_qs(urlparse(r.headers["Location"]).query)
        self.assertEqual(q["error"][0], "access_denied")
        self.assertNotIn("code", q)
        self.assertEqual(q["state"][0], "xyz")

    def test_state_with_special_chars_is_encoded_not_injected(self):
        self.authenticate("admin", "admin")
        import re
        from urllib.parse import urlparse, parse_qs
        page = self.url_open(self._authorize_url()).text
        csrf = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page).group(1)
        evil = "xyz&code=INJECTED"
        r = self.url_open("/mcp/oauth/authorize", allow_redirects=False, data={
            "csrf_token": csrf, "decision": "allow",
            "client_id": self.client.client_id, "redirect_uri": "https://claude.ai/cb",
            "state": evil, "code_challenge": self.challenge,
            "code_challenge_method": "S256", "resource": ""})
        self.assertIn(r.status_code, (302, 303))
        q = parse_qs(urlparse(r.headers["Location"]).query)
        # the injected 'code=INJECTED' must NOT become a separate param — the real
        # code is the only 'code', and state round-trips intact (decoded).
        self.assertEqual(q["state"][0], evil)
        self.assertNotEqual(q["code"][0], "INJECTED")
        self.assertEqual(len(q["code"]), 1)

    def test_authorize_rejects_foreign_resource(self):
        self.authenticate("admin", "admin")
        r = self.url_open(self._authorize_url(
            resource="https://other-rs.example.com/mcp"))
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["error"], "invalid_target")

    def test_authorize_accepts_own_resource(self):
        self.authenticate("admin", "admin")
        base = self.env["ir.config_parameter"].sudo().get_param("web.base.url")
        r = self.url_open(self._authorize_url(resource=base + "/mcp"))
        self.assertEqual(r.status_code, 200)
        self.assertIn("Authorize", r.text)
