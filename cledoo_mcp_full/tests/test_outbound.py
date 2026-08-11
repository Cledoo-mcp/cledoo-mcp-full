# SPDX-License-Identifier: OPL-1.0
# Copyright (c) 2026 Cledoo
from odoo.exceptions import AccessError, UserError
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.tests.common import LicenseMixin


@tagged("post_install", "-at_install")
class TestOutboundGuard(LicenseMixin, TransactionCase):
    def setUp(self):
        super().setUp()
        self.partner = self.env["res.partner"].create(
            {"name": "Recipient", "email": "r@example.com"})
        field = ("group_ids" if "group_ids" in self.env["res.users"]._fields
                 else "groups_id")
        self.approver = self.env["res.users"].create({
            "name": "OB Approver", "login": "ob-approver@test",
            field: [(6, 0, [self.env.ref("base.group_user").id,
                            self.env.ref("cledoo_mcp_full.group_approver").id])]})
        self.agent_env = self.env(context=dict(
            self.env.context, cledoo_mcp_agent="apikey:1"))

    def _issue(self, content=None, method="message_post", ids=None):
        Conf = self.env["mcp.outbound.confirmation"].with_user(self.approver)
        return Conf.issue("res.partner", method, ids or [self.partner.id],
                          content or {})

    def test_agent_post_to_partners_blocked_without_token(self):
        self.install_license(["outbound"])
        with self.assertRaises(UserError) as ctx:
            self.agent_env["res.partner"].browse(self.partner.id) \
                .message_post(body="hi", partner_ids=[self.partner.id])
        self.assertIn("AGENT_CONFIRMATION_REQUIRED", str(ctx.exception))

    def test_internal_note_not_guarded(self):
        self.install_license(["outbound"])
        msg = self.agent_env["res.partner"].browse(self.partner.id) \
            .message_post(body="internal note")  # mt_note, no partner_ids
        self.assertTrue(msg.id)

    def test_human_never_guarded(self):
        self.install_license(["outbound"])
        msg = self.env["res.partner"].browse(self.partner.id).message_post(
            body="human", partner_ids=[self.partner.id])
        self.assertTrue(msg.id)

    def test_token_allows_then_single_use(self):
        self.install_license(["outbound"])
        raw = self._issue()
        rec = self.agent_env["res.partner"].browse(self.partner.id)
        msg = rec.with_context(outbound_token=raw).message_post(
            body="approved", partner_ids=[self.partner.id])
        self.assertTrue(msg.id)
        with self.assertRaises(UserError):  # replay blocked
            rec.with_context(outbound_token=raw).message_post(
                body="approved", partner_ids=[self.partner.id])

    def test_agent_cannot_self_issue(self):
        self.install_license(["outbound"])
        field = ("group_ids" if "group_ids" in self.env["res.users"]._fields
                 else "groups_id")
        agent_user = self.env["res.users"].create({
            "name": "Agent", "login": "agent@test",
            field: [(6, 0, [self.env.ref("base.group_user").id])]})
        with self.assertRaises(AccessError):
            self.env["mcp.outbound.confirmation"].with_user(
                agent_user).issue("res.partner", "message_post",
                                  [self.partner.id], {})

    def test_wrong_scope_denied(self):
        self.install_license(["outbound"])
        raw = self._issue(ids=[self.partner.id + 999])
        with self.assertRaises(UserError):
            self.agent_env["res.partner"].browse(self.partner.id) \
                .with_context(outbound_token=raw).message_post(
                    body="x", partner_ids=[self.partner.id])

