# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
import json
from datetime import timedelta

from odoo.exceptions import AccessError
from odoo.fields import Datetime
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib.tools import ToolAccessError, ToolUserError
from odoo.addons.cledoo_mcp_full.tests.common import LicenseMixin


@tagged("post_install", "-at_install")
class TestApprovals(LicenseMixin, TransactionCase):
    def setUp(self):
        super().setUp()
        self.gw = self.env["mcp.gateway"]
        self.ctx = {"principal": {"kind": "apikey", "uid": self.env.uid,
                                  "token_id": None, "apikey_id": None}}
        self.env["mcp.policy"].sudo().create({
            "name": "writes need approval", "model_pattern": "res.partner",
            "operation": "write", "verdict": "approval"})
        field = ("group_ids" if "group_ids" in self.env["res.users"]._fields
                 else "groups_id")
        self.approver = self.env["res.users"].create({
            "name": "Approver", "login": "approver@test",
            field: [(6, 0, [
                self.env.ref("base.group_user").id,
                self.env.ref("cledoo_mcp_full.group_approver").id])]})

    def _propose(self):
        self.install_license(["policy", "approvals"])
        return self.gw._execute_tool(
            self.env.uid, "create_record",
            {"model": "res.partner", "values": {"name": "NeedsOK"}},
            context=self.ctx)

    def test_gated_write_returns_ticket(self):
        res = self._propose()
        self.assertTrue(res.get("pending"))
        ticket = self.env["mcp.approval"].sudo().browse(res["ticket_id"])
        self.assertEqual(ticket.state, "pending")
        self.assertEqual(ticket.tool_name, "create_record")
        # nothing was created
        self.assertFalse(self.env["res.partner"].search(
            [("name", "=", "NeedsOK")]))

    def test_check_approval_pending(self):
        res = self._propose()
        out = self.gw._execute_tool(self.env.uid, "check_approval",
                                    {"ticket_id": res["ticket_id"]},
                                    context=self.ctx)
        self.assertEqual(out["state"], "pending")

    def test_approved_ticket_executes_bound_content(self):
        res = self._propose()
        ticket = self.env["mcp.approval"].sudo().browse(res["ticket_id"])
        ticket.with_user(self.approver).action_approve()
        out = self.gw._execute_tool(self.env.uid, "check_approval",
                                    {"ticket_id": ticket.id},
                                    context=self.ctx)
        self.assertEqual(out["state"], "approved")
        self.assertTrue(out["result"]["id"])
        self.assertTrue(self.env["res.partner"].browse(
            out["result"]["id"]).name == "NeedsOK")
        # single-shot: second check does not re-execute
        out2 = self.gw._execute_tool(self.env.uid, "check_approval",
                                     {"ticket_id": ticket.id},
                                     context=self.ctx)
        self.assertNotIn("result", out2)

    def test_tampered_args_denied(self):
        res = self._propose()
        ticket = self.env["mcp.approval"].sudo().browse(res["ticket_id"])
        ticket.with_user(self.approver).action_approve()
        # attacker rewrites the stored call after approval
        ticket.sudo().write({"args_json": json.dumps(
            {"model": "res.partner", "values": {"name": "EVIL"}})})
        with self.assertRaises(ToolAccessError):
            self.gw._execute_tool(self.env.uid, "check_approval",
                                  {"ticket_id": ticket.id}, context=self.ctx)

    def test_non_approver_cannot_approve(self):
        res = self._propose()
        ticket = self.env["mcp.approval"].sudo().browse(res["ticket_id"])
        field = ("group_ids" if "group_ids" in self.env["res.users"]._fields
                 else "groups_id")
        plain = self.env["res.users"].create({
            "name": "Plain", "login": "plain@test",
            field: [(6, 0, [self.env.ref("base.group_user").id])]})
        with self.assertRaises(AccessError):
            ticket.with_user(plain).action_approve()

    def test_expiry(self):
        res = self._propose()
        ticket = self.env["mcp.approval"].sudo().browse(res["ticket_id"])
        ticket.sudo().write(
            {"expires_at": Datetime.now() - timedelta(hours=1)})
        out = self.gw._execute_tool(self.env.uid, "check_approval",
                                    {"ticket_id": ticket.id},
                                    context=self.ctx)
        self.assertEqual(out["state"], "expired")

    def test_claim_execution_is_atomic_single_winner(self):
        """Deterministic unit test of the TOCTOU-closing claim helper:
        two "concurrent" claims on the same approved, not-yet-executed
        ticket must yield exactly one winner. Real thread/process
        concurrency isn't needed -- the guarantee comes from the
        conditional UPDATE being a single atomic statement, so calling
        it twice in sequence already proves only the first call can
        win."""
        res = self._propose()
        ticket = self.env["mcp.approval"].sudo().browse(res["ticket_id"])
        ticket.with_user(self.approver).action_approve()
        self.assertFalse(ticket.executed)
        first = ticket._claim_execution()
        second = ticket._claim_execution()
        self.assertTrue(first)
        self.assertFalse(second)
        self.assertTrue(ticket.executed)

    def test_claim_execution_requires_approved_state(self):
        res = self._propose()
        ticket = self.env["mcp.approval"].sudo().browse(res["ticket_id"])
        self.assertEqual(ticket.state, "pending")
        self.assertFalse(ticket._claim_execution())
        self.assertFalse(ticket.executed)

    def test_failed_execution_does_not_burn_ticket(self):
        """A failed approved-ticket execution must NOT consume the
        ticket: the atomic claim precedes the dispatch on the main
        cursor, so without an un-claim on failure the claim would be
        committed (executed=true) while the write itself rolled back —
        the human-approved action silently lost and every retry
        answering {"state": "approved"} with no result. The error must
        surface AND the ticket must stay claimable/retryable."""
        res = self._propose()
        ticket = self.env["mcp.approval"].sudo().browse(res["ticket_id"])
        ticket.with_user(self.approver).action_approve()
        # Make the re-execution fail: a deny rule that outranks the
        # approval rule (lower sequence, first match wins) at the time
        # the approved call is actually dispatched.
        deny = self.env["mcp.policy"].sudo().create({
            "name": "deny partners now", "sequence": 1,
            "model_pattern": "res.partner", "verdict": "deny"})
        # Plain try/except, not assertRaises: Odoo's assertRaises wraps
        # the block in a savepoint that would roll back claim AND
        # un-claim together, hiding the very bug this test guards.
        try:
            self.gw._execute_tool(self.env.uid, "check_approval",
                                  {"ticket_id": ticket.id},
                                  context=self.ctx)
            self.fail("expected ToolAccessError from the denied dispatch")
        except ToolAccessError:
            pass
        # error surfaced, write did not happen, ticket NOT burned
        self.assertFalse(self.env["res.partner"].search(
            [("name", "=", "NeedsOK")]))
        self.assertEqual(ticket.state, "approved")
        self.assertFalse(ticket.executed)
        # retryable: lift the deny, same ticket now executes for real
        deny.active = False
        out = self.gw._execute_tool(self.env.uid, "check_approval",
                                    {"ticket_id": ticket.id},
                                    context=self.ctx)
        self.assertEqual(out["state"], "approved")
        self.assertTrue(out["result"]["id"])
        self.assertTrue(ticket.executed)

    def test_foreign_ticket_invisible(self):
        res = self._propose()
        other_ctx = {"principal": {"kind": "oauth", "uid": self.env.uid,
                                   "token_id": 424242, "apikey_id": None}}
        with self.assertRaises(ToolUserError):
            self.gw._execute_tool(self.env.uid, "check_approval",
                                  {"ticket_id": res["ticket_id"]},
                                  context=other_ctx)
