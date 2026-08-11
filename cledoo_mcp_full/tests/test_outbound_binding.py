# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
from odoo.exceptions import UserError
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.models.outbound import _sha
from odoo.addons.cledoo_mcp_full.tests.common import LicenseMixin


@tagged("post_install", "-at_install")
class TestOutboundBinding(LicenseMixin, TransactionCase):
    def setUp(self):
        super().setUp()
        self.install_license(["outbound"])
        self.partner = self.env["res.partner"].create(
            {"name": "Bind", "email": "b@example.com"})
        field = ("group_ids" if "group_ids" in self.env["res.users"]._fields
                 else "groups_id")
        self.approver = self.env["res.users"].create({
            "name": "B Approver", "login": "b-approver@test",
            field: [(6, 0, [self.env.ref("base.group_user").id,
                            self.env.ref("cledoo_mcp_full.group_approver").id])]})
        self.agent_env = self.env(context=dict(
            self.env.context, cledoo_mcp_agent="apikey:1"))

    def _issue(self, body):
        return self.env["mcp.outbound.confirmation"].with_user(
            self.approver).issue(
                "res.partner", "message_post", [self.partner.id],
                {"body": body, "subject": False,
                 "partner_ids": [self.partner.id]})

    def test_bound_content_sends(self):
        raw = self._issue("exact approved text")
        msg = self.agent_env["res.partner"].browse(self.partner.id) \
            .with_context(outbound_token=raw).message_post(
                body="exact approved text", partner_ids=[self.partner.id])
        self.assertTrue(msg.id)

    def test_edited_content_denied_indistinguishably(self):
        raw = self._issue("exact approved text")
        with self.assertRaises(UserError) as ctx:
            self.agent_env["res.partner"].browse(self.partner.id) \
                .with_context(outbound_token=raw).message_post(
                    body="EDITED text", partner_ids=[self.partner.id])
        # same message as a missing token — no oracle
        self.assertIn("AGENT_CONFIRMATION_REQUIRED", str(ctx.exception))

    def test_scheduling_blocked_for_agent(self):
        if "mail.scheduled.message" not in self.env:
            self.skipTest("mail.scheduled.message not in this series")
        with self.assertRaises(UserError) as ctx:
            self.agent_env["mail.scheduled.message"].create({
                "model": "res.partner", "res_id": self.partner.id,
                "body": "later", "scheduled_date": "2030-01-01 00:00:00"})
        self.assertIn("AGENT_SCHEDULING_BLOCKED", str(ctx.exception))

    def test_scheduling_fine_for_humans(self):
        if "mail.scheduled.message" not in self.env:
            self.skipTest("mail.scheduled.message not in this series")
        rec = self.env["mail.scheduled.message"].create({
            "model": "res.partner", "res_id": self.partner.id,
            "author_id": self.env.user.partner_id.id,
            "body": "later", "scheduled_date": "2030-01-01 00:00:00"})
        self.assertTrue(rec.id)

    # --- B7: alternate outbound entry points must also be gated ---

    def test_agent_mail_mail_create_blocked(self):
        """base create_record on mail.mail is a bypass of message_post's
        guard (queue cron flushes it unguarded) — must be hard-blocked
        under agent context, same posture as scheduling."""
        with self.assertRaises(UserError) as ctx:
            self.agent_env["mail.mail"].create({
                "body_html": "hi", "email_to": "x@example.com"})
        self.assertIn("AGENT_MAIL_CREATE_BLOCKED", str(ctx.exception))

    def test_human_mail_mail_create_fine(self):
        rec = self.env["mail.mail"].create({
            "body_html": "hi", "email_to": "x@example.com"})
        self.assertTrue(rec.id)

    def test_agent_template_send_mail_blocked(self):
        """mail.template.send_mail funnels into mail.mail.sudo().create,
        so it is closed transitively by the mail.mail create guard."""
        template = self.env["mail.template"].create({
            "name": "T", "model_id": self.env.ref("base.model_res_partner").id,
            "subject": "hi", "body_html": "<p>hi</p>",
            "email_to": "x@example.com"})
        with self.assertRaises(UserError) as ctx:
            self.agent_env["mail.template"].browse(template.id).send_mail(
                self.partner.id, force_send=False)
        self.assertIn("AGENT_MAIL_CREATE_BLOCKED", str(ctx.exception))

    def test_human_template_send_mail_fine(self):
        template = self.env["mail.template"].create({
            "name": "T2", "model_id": self.env.ref("base.model_res_partner").id,
            "subject": "hi", "body_html": "<p>hi</p>",
            "email_to": "x@example.com"})
        mail_id = template.send_mail(self.partner.id, force_send=False)
        self.assertTrue(mail_id)

    def test_agent_internal_note_with_email_follower_succeeds(self):
        """Regression: an internal note (unguarded by design) must not
        trip the mail.mail create guard when a follower is notified by
        email — the notification pipeline creates mail.mail rows INSIDE
        message_post, which must therefore run with the agent context
        stripped even on the unguarded branch."""
        field = ("group_ids" if "group_ids" in self.env["res.users"]._fields
                 else "groups_id")
        follower = self.env["res.users"].create({
            "name": "Note Follower", "login": "note-follower@test",
            "notification_type": "email",
            field: [(6, 0, [self.env.ref("base.group_user").id])]})
        self.partner.message_subscribe(
            partner_ids=follower.partner_id.ids,
            subtype_ids=[self.env.ref("mail.mt_note").id])
        msg = self.agent_env["res.partner"].browse(self.partner.id) \
            .message_post(body="internal note",
                          subtype_xmlid="mail.mt_note")
        self.assertTrue(msg.id)
        # prove the guard was actually on the path: the note produced
        # an email notification (mail.mail.create ran inside the post)
        self.assertTrue(msg.notification_ids.filtered(
            lambda n: n.notification_type == "email"))

    def test_agent_mail_mail_write_blocked(self):
        """Same rationale as create: the queue cron flushes unguarded,
        so rewriting email_to/body on a queued row = attacker content."""
        mail = self.env["mail.mail"].create({
            "body_html": "hi", "email_to": "x@example.com"})
        with self.assertRaises(UserError) as ctx:
            self.agent_env["mail.mail"].browse(mail.id).write(
                {"email_to": "evil@example.com"})
        self.assertIn("AGENT_MAIL_CREATE_BLOCKED", str(ctx.exception))

    def test_human_mail_mail_write_fine(self):
        mail = self.env["mail.mail"].create({
            "body_html": "hi", "email_to": "x@example.com"})
        mail.write({"email_to": "y@example.com"})
        self.assertEqual(mail.email_to, "y@example.com")

    def test_agent_mail_mail_create_with_token_allowed(self):
        """Escape hatch: a valid token scoped (mail.mail, create, [])
        permits agent-context direct mail creation (single-use)."""
        raw = self.env["mcp.outbound.confirmation"].with_user(
            self.approver).issue("mail.mail", "create", [], {})
        rec = self.agent_env["mail.mail"].with_context(
            outbound_token=raw).create({
                "body_html": "hi", "email_to": "x@example.com"})
        self.assertTrue(rec.id)
        # single-use: replay is denied
        with self.assertRaises(UserError):
            self.agent_env["mail.mail"].with_context(
                outbound_token=raw).create({
                    "body_html": "again", "email_to": "x@example.com"})

    def test_content_fingerprint_injective(self):
        """Serialization must not collide on values containing the
        old joiner characters."""
        from odoo.addons.cledoo_mcp_full.models.outbound import (
            content_fingerprint)
        # old "k=v|k=v" join collided on these two:
        a = content_fingerprint({"body": "x|subject=y"})
        b = content_fingerprint({"body": "x", "subject": "y"})
        self.assertNotEqual(a, b)

    # --- B8: consume() single-use claim must be atomic (TOCTOU) ---

    def test_claim_is_atomic_single_winner(self):
        """Deterministic unit test of the TOCTOU-closing claim helper:
        two "concurrent" claims on the same unused token must yield
        exactly one winner. Sequential calls already prove it, since
        the guarantee comes from the conditional UPDATE being a single
        atomic statement (mirrors McpApproval._claim_execution test)."""
        raw = self._issue("claim me")
        Conf = self.env["mcp.outbound.confirmation"]
        rec = Conf.sudo().search([("token_hash", "=", _sha(raw))], limit=1)
        self.assertFalse(rec.used)
        first = rec._claim()
        second = rec._claim()
        self.assertTrue(first)
        self.assertFalse(second)
        self.assertTrue(rec.used)

    # --- snapshot_compose helper ---

    def test_snapshot_compose_requires_approver(self):
        compose = self.env["mail.compose.message"].with_context(
            default_res_ids=[self.partner.id],
            default_model="res.partner").create({
                "body": "snap body", "subject": "snap subject",
                "partner_ids": [(6, 0, [self.partner.id])]})
        from odoo.exceptions import AccessError
        with self.assertRaises(AccessError):
            self.env["mcp.outbound.confirmation"].snapshot_compose(compose.id)

    def test_snapshot_compose_returns_real_state(self):
        compose = self.env["mail.compose.message"].with_context(
            default_res_ids=[self.partner.id],
            default_model="res.partner").create({
                "body": "snap body", "subject": "snap subject",
                "partner_ids": [(6, 0, [self.partner.id])]})
        snap = self.env["mcp.outbound.confirmation"].with_user(
            self.approver).snapshot_compose(compose.id)
        self.assertIn("snap body", snap["body"])
        self.assertEqual(snap["subject"], "snap subject")
        self.assertEqual(snap["partner_ids"], [self.partner.id])
