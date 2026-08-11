# SPDX-License-Identifier: OPL-1.0
# Copyright (c) 2026 Cledoo
"""Agent outbound guard (feature 'outbound'): agent-triggered outbound
communication (chatter posts reaching partners/followers, composer
sends) requires a single-use scoped token issued by a human in
group_approver.

Trust boundary: the `cledoo_mcp_agent` context key is stamped by the
Pro gateway pipeline (the trusted layer). Human UI sessions never carry
it. An attacker able to strip env context is outside this threat model
(by design, same as the original agent_outbound_guard).

V1 limitation (deliberate, fail-closed): under agent context, ANY path
that creates or edits a mail.mail row directly — base create_record on
mail.mail, mail.template.send_mail, activity "send email" actions, and
indirect business flows whose automations email externally as a side
effect of a record write — is denied unless the create carries a valid
token scoped to ("mail.mail", "create", []) (issue with content={} —
the rows don't exist yet, so there is nothing stable to content-bind).
Agent edits of queued mail are always denied (the queue cron flushes
them unguarded, so a post-approval rewrite would send attacker
content). SMS (sms.sms / sms.composer) is out of scope in V1."""
import hashlib
import json
import secrets
from datetime import timedelta

from odoo import api, fields, models
from odoo.exceptions import AccessError, UserError
from odoo.fields import Datetime

from odoo.addons.cledoo_mcp_full.lib import license as lic

MAX_TTL = 86400


def _sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def _scope_hash(model, method, record_ids):
    return _sha("%s|%s|%s" % (model, method,
                              ",".join(str(i) for i in sorted(record_ids))))


def content_fingerprint(content):
    """Canonical, injective hash of outbound content. False and None
    hash the same (Odoo returns False for unset Char over RPC).
    json.dumps of the normalized mapping is injective — a plain
    "k=v|k=v" join would collide on values containing the separators
    (e.g. {"body": "x|subject=y"} vs {"body": "x", "subject": "y"})."""
    normalized = {}
    for key in sorted(content or {}):
        value = content[key]
        if value in (False, None):
            value = ""
        if isinstance(value, (list, tuple)):
            value = [str(v) for v in sorted(value)]
        else:
            value = str(value)
        normalized[key] = value
    return _sha(json.dumps(normalized, sort_keys=True,
                           separators=(",", ":")))


class McpOutboundConfirmation(models.Model):
    _name = "mcp.outbound.confirmation"
    _description = "MCP outbound confirmation token"

    token_hash = fields.Char(required=True, index=True)
    scope_hash = fields.Char(required=True)
    content_hash = fields.Char()
    approver_id = fields.Many2one("res.users", required=True)
    expires_at = fields.Datetime(required=True)
    used = fields.Boolean(default=False)

    def issue(self, model, method, record_ids, content, ttl=3600):
        """Approver-only. Returns the raw token (never stored)."""
        if not self.env.user.has_group("cledoo_mcp_full.group_approver"):
            raise AccessError(
                "Only MCP Approvers can issue outbound confirmations.")
        raw = secrets.token_urlsafe(32)
        self.sudo().create({
            "token_hash": _sha(raw),
            "scope_hash": _scope_hash(model, method, record_ids),
            "content_hash": content_fingerprint(content) if content else False,
            "approver_id": self.env.uid,
            "expires_at": Datetime.now() + timedelta(
                seconds=min(int(ttl), MAX_TTL)),
        })
        return raw

    def consume(self, raw, model, method, record_ids, content_hash=None):
        """Single deny path — every failure is indistinguishable (no
        oracle for which check failed)."""
        if not raw:
            return False
        rec = self.sudo().search([("token_hash", "=", _sha(raw))], limit=1)
        if (not rec or rec.used or rec.expires_at < Datetime.now()
                or rec.scope_hash != _scope_hash(model, method, record_ids)
                or (rec.content_hash and rec.content_hash != content_hash)):
            return False
        return rec._claim()

    def _claim(self):
        """Atomically flip used False->True for this single token.

        The pre-check above (rec.used) is a TOCTOU: two concurrent
        requests can both read used=False before either write lands,
        and both would be honoured as valid single-use tokens — double
        send. A single conditional UPDATE closes the window (Postgres
        serializes concurrent UPDATEs to the same row): only the first
        caller's statement can flip False->True, the other sees zero
        rows matched. Mirrors McpApproval._claim_execution. Returns
        True for the caller that won the claim, False for a loser."""
        self.ensure_one()
        self.env.flush_all()
        self.env.cr.execute(
            "UPDATE mcp_outbound_confirmation SET used = true "
            "WHERE id = %s AND used = false RETURNING id", (self.id,))
        won = self.env.cr.fetchone() is not None
        self.invalidate_recordset(["used"])
        return won

    def revoke(self, confirmation_id):
        if not self.env.user.has_group("cledoo_mcp_full.group_approver"):
            raise AccessError("Only MCP Approvers can revoke confirmations.")
        self.sudo().browse(confirmation_id).write({"used": True})

    def snapshot_compose(self, compose_id):
        """Approver helper: sudo-read a composer wizard's REAL state so
        the approver binds what Odoo will actually send (render-time
        transforms happen after enforcement, so DB state == bound state
        for honest sends)."""
        if not self.env.user.has_group("cledoo_mcp_full.group_approver"):
            raise AccessError("Only MCP Approvers can snapshot composers.")
        wizard = self.env["mail.compose.message"].sudo().browse(compose_id)
        return {"body": wizard.body, "subject": wizard.subject,
                "partner_ids": wizard.partner_ids.ids}

    @api.autovacuum
    def _gc_expired(self):
        self.sudo().search(
            [("expires_at", "<", Datetime.now() - timedelta(days=7))]).unlink()


def _agent_key(env):
    """The stamped principal, or None. Also gates on the licence so an
    expired licence cleanly disables guarding (never brick mail)."""
    key = env.context.get("cledoo_mcp_agent")
    if not key:
        return None
    if "outbound" not in lic.active_features(env):
        return None
    return key


class MailThread(models.AbstractModel):
    _inherit = "mail.thread"

    def message_post(self, **kwargs):
        if _agent_key(self.env):
            if self._outbound_guarded(kwargs):
                self._outbound_enforce("message_post", kwargs)
            # Strip the agent context on BOTH branches: for approved
            # sends so nested internal posts don't demand a second
            # token; for unguarded internal notes so the notification
            # pipeline's own mail.mail creation (email-notified
            # followers) doesn't trip the mail.mail guard. Internal
            # notes never reach external partners, so stripping is safe.
            return super(MailThread, self.with_context(
                cledoo_mcp_agent=False)).message_post(**kwargs)
        return super().message_post(**kwargs)

    def _outbound_guarded(self, kwargs):
        """Recipient-first predicate (landmine 3): explicit partner_ids
        => always guarded; else a non-internal resolved subtype (comment
        reaching followers) => guarded; internal notes pass."""
        if kwargs.get("partner_ids"):
            return True
        subtype_xmlid = kwargs.get("subtype_xmlid")
        if subtype_xmlid and subtype_xmlid != "mail.mt_note":
            subtype = self.env.ref(subtype_xmlid, raise_if_not_found=False)
            if subtype is not None and not subtype.internal:
                return True
        subtype_id = kwargs.get("subtype_id")
        if subtype_id:
            subtype = self.env["mail.message.subtype"].browse(subtype_id)
            if subtype.exists() and not subtype.internal:
                return True
        return False

    def _outbound_enforce(self, method, kwargs):
        fingerprint = content_fingerprint({
            "body": kwargs.get("body"),
            "subject": kwargs.get("subject"),
            "partner_ids": list(kwargs.get("partner_ids") or []),
        })
        token = self.env.context.get("outbound_token")
        ok = self.env["mcp.outbound.confirmation"].consume(
            token, self._name, method, self.ids, fingerprint)
        if not ok:
            raise UserError(
                "AGENT_CONFIRMATION_REQUIRED: this outbound message needs "
                "a confirmation token issued by an MCP Approver, bound to "
                "this exact content. Ask a human to approve, then retry "
                "with confirmation_token.")

    def message_notify(self, **kwargs):
        if _agent_key(self.env) and kwargs.get("partner_ids"):
            self._outbound_enforce("message_notify", kwargs)
            return super(MailThread, self.with_context(
                cledoo_mcp_agent=False)).message_notify(**kwargs)
        return super().message_notify(**kwargs)


class MailComposeMessage(models.TransientModel):
    _inherit = "mail.compose.message"

    def action_send_mail(self):
        if _agent_key(self.env):
            for wizard in self:
                self.env["mail.thread"].browse()  # noop anchor
                token = self.env.context.get("outbound_token")
                # Scope-only for now (content_hash=None): a composer
                # token issued WITH content would be DENIED here until
                # snapshot_compose is wired into the issue flow — issue
                # composer tokens with content={} in the meantime.
                ok = self.env["mcp.outbound.confirmation"].consume(
                    token, "mail.compose.message", "action_send_mail",
                    wizard.ids, None)
                if not ok:
                    raise UserError(
                        "AGENT_CONFIRMATION_REQUIRED: composer sends by an "
                        "agent always need an approver token.")
            return super(MailComposeMessage, self.with_context(
                cledoo_mcp_agent=False)).action_send_mail()
        return super().action_send_mail()


class MailScheduledMessage(models.Model):
    _inherit = "mail.scheduled.message"

    @api.model_create_multi
    def create(self, vals_list):
        if _agent_key(self.env):
            # No token path: the deferred cron send runs context-free, so
            # nothing could honestly bind it. Hard block (covers the
            # composer's schedule action and copy() too).
            raise UserError("AGENT_SCHEDULING_BLOCKED: agents cannot "
                            "schedule messages for later delivery.")
        return super().create(vals_list)

    def write(self, vals):
        if _agent_key(self.env):
            raise UserError("AGENT_SCHEDULING_BLOCKED: agents cannot "
                            "modify scheduled messages.")
        return super().write(vals)
    # unlink() deliberately open: cancelling a human's scheduled send is
    # sabotage/DoS, not outbound injection (original V2 decision).


class MailMail(models.Model):
    _inherit = "mail.mail"

    @api.model_create_multi
    def create(self, vals_list):
        """[B7] Closes the base create_record / mail.template.send_mail
        bypass: creating a mail.mail record directly (or via a template
        send, which funnels into mail.mail.sudo().create()) skips
        message_post's guard entirely and the queue cron flushes it
        unguarded. Escape hatch: a valid single-use token scoped to
        ("mail.mail", "create", []) permits the create — content
        binding is optional for this scope (the rows don't exist yet,
        so there is nothing stable to fingerprint; issue with
        content={}). No/invalid token stays a hard block.
        Approver note: because the token is scoped to the call and not
        to row count, one token authorizes ONE create() invocation of
        ARBITRARY batch size — a single approved token lets an agent
        create N mail.mail rows to N recipients in that one call. This
        is coarser-grained than message_post tokens (which bind to one
        message's content) and should be issued with that in mind."""
        if _agent_key(self.env):
            token = self.env.context.get("outbound_token")
            ok = self.env["mcp.outbound.confirmation"].consume(
                token, "mail.mail", "create", [], None)
            if not ok:
                raise UserError(
                    "AGENT_MAIL_CREATE_BLOCKED: agents cannot create "
                    "outgoing mail directly; send via the guarded "
                    "message_post/composer flow, or ask an MCP Approver "
                    "for a token scoped to mail.mail create.")
            return super(MailMail, self.with_context(
                cledoo_mcp_agent=False)).create(vals_list)
        return super().create(vals_list)

    def write(self, vals):
        """Same rationale as create: the queue cron flushes unguarded,
        so an agent rewriting email_to/body_html/state on a queued or
        exception row would make the cron send attacker content. No
        token path (mirrors mail.scheduled.message: block both)."""
        if _agent_key(self.env):
            raise UserError(
                "AGENT_MAIL_CREATE_BLOCKED: agents cannot modify queued "
                "outgoing mail.")
        return super().write(vals)
