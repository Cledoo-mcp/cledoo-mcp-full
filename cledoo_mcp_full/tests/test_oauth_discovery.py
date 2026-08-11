# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
import json

from odoo.tests import tagged
from odoo.tests.common import HttpCase


@tagged("post_install", "-at_install")
class TestOAuthDiscovery(HttpCase):
    def setUp(self):
        super().setUp()
        self.env["ir.config_parameter"].sudo().set_param("cledoo_mcp_full.enabled", "True")
        self.env.flush_all()
        # the register endpoint is IP-throttled and buckets are process-
        # global: without a reset, register calls accumulate across tests
        from odoo.addons.cledoo_mcp_full.lib import ratelimit
        ratelimit.reset()

    def test_as_metadata(self):
        r = self.url_open("/.well-known/oauth-authorization-server")
        self.assertEqual(r.status_code, 200)
        m = r.json()
        self.assertIn("issuer", m)
        self.assertTrue(m["authorization_endpoint"].endswith("/mcp/oauth/authorize"))
        self.assertTrue(m["token_endpoint"].endswith("/mcp/oauth/token"))
        self.assertTrue(m["registration_endpoint"].endswith("/mcp/oauth/register"))
        self.assertEqual(m["code_challenge_methods_supported"], ["S256"])
        self.assertIn("authorization_code", m["grant_types_supported"])
        self.assertIn("refresh_token", m["grant_types_supported"])
        self.assertEqual(m["token_endpoint_auth_methods_supported"], ["none"])

    def test_protected_resource_metadata(self):
        r = self.url_open("/.well-known/oauth-protected-resource")
        self.assertEqual(r.status_code, 200)
        m = r.json()
        self.assertTrue(m["resource"].endswith("/mcp"))
        self.assertTrue(any(a.endswith("") for a in m["authorization_servers"]))

    def test_register_returns_client_id_no_secret(self):
        r = self.url_open("/mcp/oauth/register", data=json.dumps({
            "client_name": "Claude", "redirect_uris": ["https://claude.ai/cb"]}),
            headers={"Content-Type": "application/json"})
        self.assertEqual(r.status_code, 201)
        body = r.json()
        self.assertIn("client_id", body)
        self.assertNotIn("client_secret", body)
        self.assertEqual(body["token_endpoint_auth_method"], "none")

    def test_disabled_returns_404(self):
        self.env["ir.config_parameter"].sudo().set_param("cledoo_mcp_full.enabled", "False")
        self.env.flush_all()
        self.assertEqual(self.url_open(
            "/.well-known/oauth-authorization-server").status_code, 404)

    def test_register_rejects_bad_redirect_uris(self):
        for bad in ["http://evil.com/cb", "http://localhost.evil.com/cb",
                    "http://localhostx.attacker.net/cb", "ftp://localhost/cb"]:
            r = self.url_open("/mcp/oauth/register", data=json.dumps({
                "client_name": "x", "redirect_uris": [bad]}),
                headers={"Content-Type": "application/json"})
            self.assertEqual(r.status_code, 400, "should reject %s" % bad)

    def test_register_caps_abuse(self):
        # too many redirect URIs
        r = self.url_open("/mcp/oauth/register", data=json.dumps({
            "client_name": "x",
            "redirect_uris": ["https://claude.ai/cb%d" % i for i in range(6)]}),
            headers={"Content-Type": "application/json"})
        self.assertEqual(r.status_code, 400)
        # redirect_uris must be a list
        r = self.url_open("/mcp/oauth/register", data=json.dumps({
            "client_name": "x", "redirect_uris": "https://claude.ai/cb"}),
            headers={"Content-Type": "application/json"})
        self.assertEqual(r.status_code, 400)
        # oversized URI
        r = self.url_open("/mcp/oauth/register", data=json.dumps({
            "client_name": "x",
            "redirect_uris": ["https://claude.ai/" + "a" * 3000]}),
            headers={"Content-Type": "application/json"})
        self.assertEqual(r.status_code, 400)
        # attacker-controlled client_name is truncated, not stored verbatim
        r = self.url_open("/mcp/oauth/register", data=json.dumps({
            "client_name": "A" * 500, "redirect_uris": ["https://claude.ai/cb"]}),
            headers={"Content-Type": "application/json"})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(len(r.json()["client_name"]), 64)
        # non-string client_name rejected
        r = self.url_open("/mcp/oauth/register", data=json.dumps({
            "client_name": {"x": 1}, "redirect_uris": ["https://claude.ai/cb"]}),
            headers={"Content-Type": "application/json"})
        self.assertEqual(r.status_code, 400)

    def test_register_response_is_no_store(self):
        r = self.url_open("/mcp/oauth/register", data=json.dumps({
            "client_name": "Claude", "redirect_uris": ["https://claude.ai/cb"]}),
            headers={"Content-Type": "application/json"})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.headers.get("Cache-Control"), "no-store")

    def test_register_accepts_https_and_loopback(self):
        for good in ["https://claude.ai/cb", "http://localhost:8080/cb",
                     "http://127.0.0.1/cb"]:
            r = self.url_open("/mcp/oauth/register", data=json.dumps({
                "client_name": "x", "redirect_uris": [good]}),
                headers={"Content-Type": "application/json"})
            self.assertEqual(r.status_code, 201, "should accept %s" % good)
