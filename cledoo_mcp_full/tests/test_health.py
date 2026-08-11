# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
import datetime

from odoo.tests import tagged
from odoo.tests.common import HttpCase


@tagged("post_install", "-at_install")
class TestHealth(HttpCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.env["ir.config_parameter"].sudo().set_param(
            "cledoo_mcp_full.enabled", "True")
        gf = "group_ids" if "group_ids" in cls.env["res.users"]._fields else "groups_id"
        cls.user = cls.env["res.users"].create({
            "name": "Health User", "login": "mcp-health-user",
            gf: [(6, 0, [cls.env.ref("base.group_user").id])]})
        expiration = datetime.datetime.now() + datetime.timedelta(days=1)
        cls.key = cls.env["res.users.apikeys"].with_user(cls.user)._generate(
            None, "health-key", expiration)
        cls.env.flush_all()

    def test_anonymous_gets_status_only(self):
        # Unauthenticated callers must see the overall status but NOT the
        # per-check deployment posture (proxy_mode, multi-db, ...) nor any
        # instance detail.
        r = self.url_open("/mcp/health")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertIn(body["status"], ("ok", "warning", "disabled"))
        self.assertEqual(set(body), {"status"})
        for leak in ("checks", "version", "user", "companies", "hints"):
            self.assertNotIn(leak, body)

    def test_disabled_module_still_answers(self):
        # /mcp/health is the ONLY route that answers when the toggle is
        # off: a 404 here is one of the failure modes it diagnoses.
        self.env["ir.config_parameter"].sudo().set_param(
            "cledoo_mcp_full.enabled", "False")
        self.env.flush_all()
        r = self.url_open("/mcp/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["status"], "disabled")

    def test_bearer_gets_details_and_hints(self):
        icp = self.env["ir.config_parameter"].sudo()
        icp.set_param("web.base.url", "http://erp.internal.lan")
        icp.set_param("web.base.url.freeze", "False")
        self.env.flush_all()
        r = self.url_open("/mcp/health", headers={
            "Authorization": "Bearer %s" % self.key})
        body = r.json()
        self.assertEqual(body["status"], "warning")
        self.assertEqual(body["user"], "mcp-health-user")
        self.assertEqual(body["auth"], "apikey")
        self.assertIn("version", body)
        self.assertIn("rate_limit_per_minute", body)
        # failing checks must come with actionable hints
        self.assertFalse(body["checks"]["https"])
        self.assertTrue(any("proxy_mode" in h for h in body["hints"]))
        self.assertTrue(any("freeze" in h for h in body["hints"]))

    def test_invalid_bearer_downgrades_to_anonymous(self):
        r = self.url_open("/mcp/health", headers={
            "Authorization": "Bearer not-a-real-token"})
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("user", r.json())
