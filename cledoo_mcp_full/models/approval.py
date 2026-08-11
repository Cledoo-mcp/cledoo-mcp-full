# SPDX-License-Identifier: OPL-1.0
# Copyright (c) 2026 Cledoo
"""Human-approved writes. A policy rule with verdict 'approval' turns a
write call into a pending ticket; a human in group_approver approves in
Odoo (activity on the ticket); the agent polls check_approval, which
executes the STORED, hash-bound call — the agent can neither change the
payload after approval (TOCTOU closed) nor execute someone else's
ticket."""
import hashlib
import json
from datetime import timedelta

from odoo import api, fields, models
from odoo.exceptions import AccessError
from odoo.fields import Datetime

TICKET_TTL_HOURS = 24


def content_hash(args):
    return hashlib.sha256(
        json.dumps(args, sort_keys=True, default=str).encode()).hexdigest()


class McpApproval(models.Model):
    _name = "mcp.approval"
    _description = "MCP write approval ticket"
    _order = "id desc"

    principal_key = fields.Char(required=True, index=True)
    user_id = fields.Many2one("res.users", required=True)
    tool_name = fields.Char(required=True)
    args_json = fields.Text(required=True)
    content_hash = fields.Char(required=True)
    state = fields.Selection(
        [("pending", "Pending"), ("approved", "Approved"),
         ("refused", "Refused"), ("expired", "Expired")],
        default="pending", required=True, index=True)
    executed = fields.Boolean(default=False)
    expires_at = fields.Datetime(required=True)
    approver_id = fields.Many2one("res.users")
    policy_rule_id = fields.Many2one("mcp.policy", ondelete="set null")

    @api.model
    def _open_ticket(self, req, rule):
        args = req.args if isinstance(req.args, dict) else {}
        ticket = self.sudo().create({
            "principal_key": req.principal_key,
            "user_id": req.uid,
            "tool_name": req.tool,
            "args_json": json.dumps(args, default=str),
            "content_hash": content_hash(args),
            "expires_at": Datetime.now() + timedelta(hours=TICKET_TTL_HOURS),
            "policy_rule_id": rule.id if rule else False,
        })
        ticket._notify_approvers()
        return ticket

    def _notify_approvers(self):
        """Activity to every approver; bookkeeping — never raise."""
        try:
            group = self.env.ref("cledoo_mcp_full.group_approver")
            for user in group.users:
                self.env["mail.activity"].sudo().create({
                    "res_model_id": self.env["ir.model"].sudo()._get_id(
                        self._name),
                    "res_id": self.id,
                    "user_id": user.id,
                    "activity_type_id": self.env.ref(
                        "mail.mail_activity_data_todo").id,
                    "summary": "MCP write awaiting approval: %s"
                               % self.tool_name,
                })
        except Exception:
            pass

    def _check_approver(self):
        if not self.env.user.has_group("cledoo_mcp_full.group_approver"):
            raise AccessError("Only MCP Approvers can decide tickets.")

    def action_approve(self):
        self._check_approver()
        for rec in self.sudo():
            rec._expire_if_due()
            if rec.state == "pending":
                rec.write({"state": "approved",
                           "approver_id": self.env.uid})

    def action_refuse(self):
        self._check_approver()
        self.sudo().filtered(lambda r: r.state == "pending").write(
            {"state": "refused", "approver_id": self.env.uid})

    def _claim_execution(self):
        """Atomically claim this approved ticket for execution.

        check_approval reads ticket.state/executed, then (if it looks
        runnable) writes executed=True and dispatches the stored call.
        That read-then-write is a TOCTOU: two concurrent pollers can
        both observe executed=False before either write lands, and
        both would dispatch the same approved write twice. A single
        conditional UPDATE closes the window — Postgres serializes
        concurrent UPDATEs to the same row, so only one statement can
        flip False->True; the other sees zero rows matched and knows
        it lost the race. Returns True for the poller that won the
        claim (must execute), False for a loser (ticket already
        claimed by another poll -- do not execute)."""
        self.ensure_one()
        # Raw SQL bypasses the ORM cache: flush any pending ORM writes
        # (e.g. action_approve()'s state="approved") so this statement
        # sees them, and so its own effect is visible to a later ORM
        # read without a stale cached value winning.
        self.env.flush_all()
        self.env.cr.execute(
            "UPDATE mcp_approval SET executed = true "
            "WHERE id = %s AND state = 'approved' AND executed = false "
            "RETURNING id", (self.id,))
        won = self.env.cr.fetchone() is not None
        # The UPDATE bypassed the ORM cache; drop the stale cached value
        # so a subsequent read (in this transaction or after) reflects it.
        self.invalidate_recordset(["executed"])
        return won

    def _unclaim_execution(self):
        """Release a claim taken by `_claim_execution` because the
        dispatched call FAILED. Same raw-SQL style so cache semantics
        match the claim. Without this, a failed execution would leave
        executed=true committed (JSON-RPC error responses still commit
        the request cursor) while the write itself was rolled back by
        the tool-call savepoint: the human-approved action would be
        silently burned — non-retryable, no result, `check_approval`
        forever answering {"state": "approved"} with nothing done.

        Exclusivity note: the claim's row UPDATE keeps the row locked
        for the rest of this transaction, so a concurrent poller's
        claim UPDATE blocks until we commit or roll back — the winner
        stays exclusive while executing. If we un-claim (failure), the
        waiter then sees executed=false and may retry the ticket; if
        the execution succeeded, it sees executed=true and loses."""
        self.ensure_one()
        self.env.cr.execute(
            "UPDATE mcp_approval SET executed = false WHERE id = %s",
            (self.id,))
        self.invalidate_recordset(["executed"])

    def _expire_if_due(self):
        for rec in self:
            if rec.state == "pending" and rec.expires_at < Datetime.now():
                rec.sudo().write({"state": "expired"})

    @api.autovacuum
    def _gc_old_tickets(self):
        cutoff = Datetime.now() - timedelta(days=90)
        self.sudo().search([("create_date", "<", cutoff)]).unlink()
