# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
import base64
import hashlib
import json

from odoo.tests import tagged
from odoo.tests.common import HttpCase


@tagged("post_install", "-at_install")
class TestOAuthToken(HttpCase):
    def setUp(self):
        super().setUp()
        self.env["ir.config_parameter"].sudo().set_param("cledoo_mcp_full.enabled", "True")
        self.client = self.env["mcp.oauth.client"]._register_client("Claude", ["https://claude.ai/cb"])
        self.verifier = "verifier-abc-1234567890"
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(self.verifier.encode()).digest()).rstrip(b"=").decode()
        # Mint a code directly via the model (authorize flow covered elsewhere).
        self.code = self.env["mcp.oauth.code"]._issue(
            self.client.client_id, 2, "https://claude.ai/cb", challenge, None)
        self.env.flush_all()

    def _token(self, **params):
        return self.url_open("/mcp/oauth/token", data=params)

    def test_code_exchange_with_good_pkce(self):
        r = self._token(grant_type="authorization_code", code=self.code,
                        client_id=self.client.client_id,
                        redirect_uri="https://claude.ai/cb", code_verifier=self.verifier)
        self.assertEqual(r.status_code, 200)
        b = r.json()
        self.assertEqual(b["token_type"], "Bearer")
        self.assertIn("access_token", b)
        self.assertIn("refresh_token", b)
        from odoo.addons.cledoo_mcp_full.models.oauth import access_ttl
        self.assertEqual(b["expires_in"], access_ttl(self.env))

    def test_bad_pkce_rejected(self):
        r = self._token(grant_type="authorization_code", code=self.code,
                        client_id=self.client.client_id,
                        redirect_uri="https://claude.ai/cb", code_verifier="wrong")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["error"], "invalid_grant")

    def test_code_single_use(self):
        ok = self._token(grant_type="authorization_code", code=self.code,
                         client_id=self.client.client_id,
                         redirect_uri="https://claude.ai/cb", code_verifier=self.verifier)
        self.assertEqual(ok.status_code, 200)
        again = self._token(grant_type="authorization_code", code=self.code,
                            client_id=self.client.client_id,
                            redirect_uri="https://claude.ai/cb", code_verifier=self.verifier)
        self.assertEqual(again.status_code, 400)

    def test_refresh_rotation_and_reuse_detection(self):
        first = self._token(grant_type="authorization_code", code=self.code,
                            client_id=self.client.client_id,
                            redirect_uri="https://claude.ai/cb",
                            code_verifier=self.verifier).json()
        rot = self._token(grant_type="refresh_token",
                          refresh_token=first["refresh_token"],
                          client_id=self.client.client_id)
        self.assertEqual(rot.status_code, 200)
        self.assertIn("access_token", rot.json())
        reuse = self._token(grant_type="refresh_token",
                            refresh_token=first["refresh_token"],
                            client_id=self.client.client_id)
        self.assertEqual(reuse.status_code, 400)  # reuse -> family revoked

    def test_admin_revoke_blocks_refresh_grant(self):
        """Regression for the P0: admin revoke of the access token must also
        kill the sibling refresh token, otherwise the client silently mints
        a new pair and the revocation is cosmetic."""
        first = self._token(grant_type="authorization_code", code=self.code,
                            client_id=self.client.client_id,
                            redirect_uri="https://claude.ai/cb",
                            code_verifier=self.verifier).json()
        rec = self.env["mcp.oauth.token"].sudo().search(
            [("kind", "=", "access"),
             ("client_id", "=", self.client.client_id)], limit=1)
        rec.action_revoke()
        self.env.flush_all()
        r = self._token(grant_type="refresh_token",
                        refresh_token=first["refresh_token"],
                        client_id=self.client.client_id)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["error"], "invalid_grant")

    def test_missing_params_return_400_not_500(self):
        # no code
        r = self._token(grant_type="authorization_code",
                        client_id=self.client.client_id,
                        redirect_uri="https://claude.ai/cb",
                        code_verifier=self.verifier)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["error"], "invalid_request")
        # no refresh_token
        r = self._token(grant_type="refresh_token",
                        client_id=self.client.client_id)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["error"], "invalid_request")
        # no grant_type at all (a non-empty body so url_open POSTs)
        r = self._token(foo="bar")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["error"], "unsupported_grant_type")

    def test_non_ascii_verifier_is_invalid_grant_not_500(self):
        r = self._token(grant_type="authorization_code", code=self.code,
                        client_id=self.client.client_id,
                        redirect_uri="https://claude.ai/cb",
                        code_verifier="vérifieur-avec-accents-é")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["error"], "invalid_grant")

    def test_token_response_is_no_store(self):
        # RFC 6749 §5.1: token responses must not be cacheable.
        r = self._token(grant_type="authorization_code", code=self.code,
                        client_id=self.client.client_id,
                        redirect_uri="https://claude.ai/cb",
                        code_verifier=self.verifier)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers.get("Cache-Control"), "no-store")

    def test_token_rejects_foreign_resource(self):
        r = self._token(grant_type="authorization_code", code=self.code,
                        client_id=self.client.client_id,
                        redirect_uri="https://claude.ai/cb",
                        code_verifier=self.verifier,
                        resource="https://other-rs.example.com/mcp")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["error"], "invalid_target")
        # The rejected attempt must NOT consume the single-use code.
        ok = self._token(grant_type="authorization_code", code=self.code,
                         client_id=self.client.client_id,
                         redirect_uri="https://claude.ai/cb",
                         code_verifier=self.verifier)
        self.assertEqual(ok.status_code, 200)
