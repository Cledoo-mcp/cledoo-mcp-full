# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
import datetime
import json

from odoo.tests import tagged
from odoo.tests.common import HttpCase, TransactionCase

from odoo.addons.cledoo_mcp_full.lib import ratelimit


@tagged("post_install", "-at_install")
class TestRateLimitLib(TransactionCase):
    def setUp(self):
        super().setUp()
        ratelimit.reset()

    def test_fixed_window_allows_then_blocks(self):
        now = 1_000_000.0
        for _ in range(3):
            allowed, _r = ratelimit.check("p1", 3, now=now)
            self.assertTrue(allowed)
        allowed, retry = ratelimit.check("p1", 3, now=now)
        self.assertFalse(allowed)
        self.assertGreater(retry, 0)
        self.assertLessEqual(retry, 60)

    def test_window_reset(self):
        now = 1_000_000.0
        for _ in range(4):
            ratelimit.check("p1", 3, now=now)
        allowed, _r = ratelimit.check("p1", 3, now=now + 61)
        self.assertTrue(allowed)

    def test_zero_limit_disables(self):
        for _ in range(50):
            allowed, _r = ratelimit.check("p1", 0)
            self.assertTrue(allowed)

    def test_principals_are_isolated(self):
        now = 1_000_000.0
        for _ in range(4):
            ratelimit.check("p1", 3, now=now)
        allowed, _r = ratelimit.check("p2", 3, now=now)
        self.assertTrue(allowed)

    def test_bucket_overflow_fails_open(self):
        now = 1_000_000.0
        for i in range(ratelimit.MAX_BUCKETS + 10):
            allowed, _r = ratelimit.check("flood-%d" % i, 5, now=now)
            self.assertTrue(allowed)


@tagged("post_install", "-at_install")
class TestRateLimitHttp(HttpCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        icp = cls.env["ir.config_parameter"].sudo()
        icp.set_param("cledoo_mcp_full.enabled", "True")
        icp.set_param("cledoo_mcp_full.rate_limit", "3")
        gf = "group_ids" if "group_ids" in cls.env["res.users"]._fields else "groups_id"
        cls.user = cls.env["res.users"].create({
            "name": "RL User", "login": "mcp-rl-user",
            gf: [(6, 0, [cls.env.ref("base.group_user").id])]})
        expiration = datetime.datetime.now() + datetime.timedelta(days=1)
        cls.key = cls.env["res.users.apikeys"].with_user(cls.user)._generate(
            None, "rl-key", expiration)
        cls.env.flush_all()

    def setUp(self):
        super().setUp()
        ratelimit.reset()

    def _ping(self):
        return self.url_open("/mcp", data=json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "ping"}),
            headers={"Content-Type": "application/json",
                     "Authorization": "Bearer %s" % self.key})

    def test_burst_gets_429_with_retry_after(self):
        for _ in range(3):
            self.assertEqual(self._ping().status_code, 200)
        r = self._ping()
        self.assertEqual(r.status_code, 429)
        self.assertTrue(int(r.headers["Retry-After"]) >= 1)
        self.assertEqual(r.json()["error"]["message"], "Rate limit exceeded")

    def test_zero_disables_limiter(self):
        self.env["ir.config_parameter"].sudo().set_param(
            "cledoo_mcp_full.rate_limit", "0")
        self.env.flush_all()
        for _ in range(10):
            self.assertEqual(self._ping().status_code, 200)

    def test_register_endpoint_is_throttled_per_ip(self):
        self.env["ir.config_parameter"].sudo().set_param(
            "cledoo_mcp_full.register_rate_limit", "2")
        self.env.flush_all()
        body = json.dumps({"client_name": "T",
                           "redirect_uris": ["https://claude.ai/cb"]})
        headers = {"Content-Type": "application/json"}
        for _ in range(2):
            self.assertEqual(self.url_open(
                "/mcp/oauth/register", data=body, headers=headers
            ).status_code, 201)
        r = self.url_open("/mcp/oauth/register", data=body, headers=headers)
        self.assertEqual(r.status_code, 429)
        self.assertIn("Retry-After", r.headers)

    def test_register_throttle_is_per_forwarded_ip(self):
        # Without proxy_mode, remote_addr is the proxy for every caller;
        # the throttle must fall back to X-Forwarded-For so one client's
        # burst does not starve another's registrations.
        self.env["ir.config_parameter"].sudo().set_param(
            "cledoo_mcp_full.register_rate_limit", "1")
        self.env.flush_all()
        body = json.dumps({"client_name": "T",
                           "redirect_uris": ["https://claude.ai/cb"]})

        def _reg(ip):
            return self.url_open("/mcp/oauth/register", data=body, headers={
                "Content-Type": "application/json", "X-Forwarded-For": ip})

        self.assertEqual(_reg("203.0.113.1").status_code, 201)
        # same client, second hit -> throttled
        self.assertEqual(_reg("203.0.113.1").status_code, 429)
        # a different client IP still gets through
        self.assertEqual(_reg("203.0.113.2").status_code, 201)
