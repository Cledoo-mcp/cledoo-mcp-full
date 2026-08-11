# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""A9 MCP sessions: model unit tests + end-to-end endpoint flow.

TestSessions covers the `mcp.session` model helpers in isolation
(_touch create/throttle, action_revoke, _gc_sessions). TestSessionEndpoint
drives the real /mcp controller (HttpCase, API-key auth bootstrapped like
tests/test_auth.py) to prove the wire contract: `initialize` mints an
Mcp-Session-Id header AND a session row, a revoked session answers 404
(MCP spec: dead session -> client must re-initialize), and unknown session
ids stay harmless for old clients / server restarts.
"""
import datetime
import json
import uuid
from datetime import timedelta

from odoo.fields import Datetime
from odoo.tests import tagged
from odoo.tests.common import HttpCase, TransactionCase


@tagged("post_install", "-at_install")
class TestSessions(TransactionCase):
    def _touch(self, sid="sid-test-1"):
        return self.env["mcp.session"]._touch(
            sid, self.env.uid, "apikey:%d" % self.env.uid, "127.0.0.1")

    def test_touch_creates(self):
        rec = self._touch()
        self.assertTrue(rec.exists())
        self.assertEqual(rec.name, "sid-test-1")
        self.assertEqual(rec.user_id.id, self.env.uid)
        self.assertEqual(rec.principal, "apikey:%d" % self.env.uid)
        self.assertEqual(rec.remote_addr, "127.0.0.1")
        self.assertFalse(rec.revoked)
        self.assertTrue(rec.last_activity)

    def test_touch_throttles_fresh_sessions(self):
        rec = self._touch()
        fresh = Datetime.now() - timedelta(seconds=10)
        rec.sudo().write({"last_activity": fresh})
        again = self._touch()
        self.assertEqual(again.id, rec.id)
        # < 60s stale -> no write per request
        self.assertEqual(again.last_activity, fresh)

    def test_touch_updates_stale_sessions(self):
        rec = self._touch()
        stale = Datetime.now() - timedelta(seconds=120)
        rec.sudo().write({"last_activity": stale})
        again = self._touch()
        self.assertEqual(again.id, rec.id)
        self.assertGreater(again.last_activity, stale)

    def test_action_revoke(self):
        rec = self._touch()
        self.assertFalse(rec.revoked)
        rec.action_revoke()
        self.assertTrue(rec.revoked)

    def test_gc_unlinks_only_stale_sessions(self):
        Session = self.env["mcp.session"]
        old = Session._touch("sid-old", self.env.uid, "apikey:1", "127.0.0.1")
        old.sudo().write(
            {"last_activity": Datetime.now() - timedelta(hours=25)})
        live = Session._touch("sid-live", self.env.uid, "apikey:1", "127.0.0.1")
        Session._gc_sessions()
        self.assertFalse(old.exists())
        self.assertTrue(live.exists())


@tagged("post_install", "-at_install")
class TestSessionEndpoint(HttpCase):
    # setUpClass data is visible to the HTTP worker without commit: HttpCase
    # test mode wraps the same underlying cursor (see tests/test_auth.py).
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.env["ir.config_parameter"].sudo().set_param(
            "cledoo_mcp_full.enabled", "True")
        gf = ("group_ids" if "group_ids" in cls.env["res.users"]._fields
              else "groups_id")
        cls.user = cls.env["res.users"].create({
            "name": "HTTP MCP Session", "login": "mcp-session-user",
            gf: [(6, 0, [cls.env.ref("base.group_user").id])]})
        expiration = datetime.datetime.now() + datetime.timedelta(days=1)
        cls.key = cls.env["res.users.apikeys"].with_user(cls.user)._generate(
            None, "session-test-key", expiration)
        cls.env.flush_all()

    def _post(self, body, session_id=None):
        headers = {"Content-Type": "application/json",
                   "Authorization": "Bearer %s" % self.key}
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        return self.url_open("/mcp", data=json.dumps(body), headers=headers)

    def _initialize(self):
        return self._post({"jsonrpc": "2.0", "id": 1,
                           "method": "initialize", "params": {}})

    def test_initialize_returns_header_and_creates_row(self):
        r = self._initialize()
        self.assertEqual(r.status_code, 200)
        sid = r.headers.get("Mcp-Session-Id")
        self.assertTrue(sid)
        rec = self.env["mcp.session"].sudo().search([("name", "=", sid)])
        self.assertEqual(len(rec), 1)
        self.assertEqual(rec.user_id.id, self.user.id)
        self.assertEqual(rec.principal, "apikey:%d" % self.user.id)
        self.assertFalse(rec.revoked)

    def test_ping_with_session_ok_then_404_after_revoke(self):
        sid = self._initialize().headers.get("Mcp-Session-Id")
        self.assertTrue(sid)
        r = self._post({"jsonrpc": "2.0", "id": 2, "method": "ping"},
                       session_id=sid)
        self.assertEqual(r.status_code, 200)

        rec = self.env["mcp.session"].sudo().search([("name", "=", sid)])
        rec.action_revoke()
        self.env.flush_all()

        r = self._post({"jsonrpc": "2.0", "id": 3, "method": "ping"},
                       session_id=sid)
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.json()["error"]["code"], -32001)
        self.assertIn("Session terminated", r.json()["error"]["message"])

    def test_ping_with_unknown_session_still_200(self):
        # Old clients / server restarts: an unknown session id must not
        # break the transport.
        r = self._post({"jsonrpc": "2.0", "id": 4, "method": "ping"},
                       session_id=uuid.uuid4().hex)
        self.assertEqual(r.status_code, 200)
