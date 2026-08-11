# SPDX-License-Identifier: OPL-1.0
# Copyright (c) 2026 Cledoo
"""Behavior radar: cron-evaluated detectors over recent audit rows.
Breach -> mcp.behavior.alert (+ admin activity); rules with
action='suspend' also create a reversible mcp.principal.suspension that
the pipeline checks first. Detection is bookkeeping (never raises);
suspension enforcement is governance (fails closed in the pipeline).

The radar itself is gated on the 'analytics' licence feature: without
it, _cron_scan is a no-op (no alerts, no suspensions). The pipeline's
_check_suspension hook still runs for any other licensed feature set —
that's fine, it will simply never find a suspension row to enforce."""
import logging
from datetime import timedelta

from odoo import api, fields, models
from odoo.fields import Datetime

from odoo.addons.cledoo_mcp_full.lib import license as lic

_logger = logging.getLogger(__name__)


class McpPrincipalSuspension(models.Model):
    _name = "mcp.principal.suspension"
    _description = "MCP principal suspension (kill-switch)"

    principal_key = fields.Char(required=True, index=True)
    reason = fields.Char()
    active = fields.Boolean(default=True)
    alert_id = fields.Many2one("mcp.behavior.alert", ondelete="set null")


class McpBehaviorRule(models.Model):
    _name = "mcp.behavior.rule"
    _description = "MCP dangerous-behavior detector"

    name = fields.Char(required=True)
    kind = fields.Selection([
        ("mass_read", "Mass read / scraping"),
        ("off_hours", "Off-hours activity"),
        ("denial_probing", "Repeated denials (probing)"),
        ("export_spike", "Export volume spike"),
    ], required=True)
    threshold = fields.Integer(
        required=True, default=100,
        help="Calls within the window that trip the detector. For "
             "off_hours: any activity between 22:00 and 06:00 UTC counts "
             "once the count passes this.")
    window_minutes = fields.Integer(default=10, required=True)
    action = fields.Selection(
        [("alert", "Alert only"), ("suspend", "Alert + suspend principal")],
        default="alert", required=True)
    active = fields.Boolean(default=True)

    def _domain_for(self, cutoff):
        self.ensure_one()
        base = [("create_date", ">=", cutoff)]
        if self.kind == "mass_read":
            return base + [("operation", "=", "read"),
                           ("outcome", "=", "ok")]
        if self.kind == "denial_probing":
            return base + [("outcome", "=", "denied")]
        if self.kind == "export_spike":
            return base + [("tool", "in", ("export_records", "print_report",
                                           "read_resource"))]
        return base  # off_hours filters by clock below

    @api.model
    def _cron_scan(self):
        if "analytics" not in lic.active_features(self.env):
            # Unlicensed: no detection, no alerts, no suspensions.
            return
        Audit = self.env["mcp.audit.log"].sudo()
        Alert = self.env["mcp.behavior.alert"].sudo()
        Susp = self.env["mcp.principal.suspension"].sudo()
        now = Datetime.now()
        suspended = set(Susp.search(
            [("active", "=", True)]).mapped("principal_key"))
        for rule in self.sudo().search([("active", "=", True)]):
            if rule.kind == "off_hours" and not (
                    now.hour >= 22 or now.hour < 6):
                continue
            cutoff = now - timedelta(minutes=rule.window_minutes)
            groups = Audit._read_group(
                rule._domain_for(cutoff), ["principal_key"], ["__count"])
            for principal_key, count in groups:
                if count < rule.threshold:
                    continue
                if (rule.kind == "denial_probing"
                        and principal_key in suspended):
                    # A suspended principal that keeps calling produces
                    # denied audit rows by construction (blocked at
                    # _check_suspension, still audited); re-alerting on
                    # those every window would spam admins forever. The
                    # kill-switch is already on — nothing new to say.
                    continue
                # dedup: one open alert per rule+principal per window
                dup = Alert.search([
                    ("rule_id", "=", rule.id),
                    ("principal_key", "=", principal_key),
                    ("create_date", ">=", cutoff)], limit=1)
                if dup:
                    continue
                alert = Alert.create({
                    "rule_id": rule.id, "principal_key": principal_key,
                    "count": count})
                alert._notify_admins()
                if (rule.action == "suspend"
                        and principal_key not in suspended):
                    # At most ONE active suspension per principal: a
                    # second row would break one-click lift (unsuspend
                    # flips one row; enforcement searches limit=1).
                    Susp.create({
                        "principal_key": principal_key,
                        "reason": "%s (%d calls in %d min)"
                                  % (rule.name, count, rule.window_minutes),
                        "alert_id": alert.id})
                    suspended.add(principal_key)

    @api.model
    def _digest_body(self):
        """Plain-text monthly summary — the DPO artifact."""
        Audit = self.env["mcp.audit.log"].sudo()
        cutoff = Datetime.now() - timedelta(days=30)
        domain = [("create_date", ">=", cutoff)]
        total = Audit.search_count(domain)
        denied = Audit.search_count(domain + [("outcome", "=", "denied")])
        writes = Audit.search_count(
            domain + [("operation", "in", ("write", "unlink"))])
        alerts = self.env["mcp.behavior.alert"].sudo().search_count(
            [("create_date", ">=", cutoff)])
        pending = self.env["mcp.approval"].sudo().search_count(
            [("create_date", ">=", cutoff)])
        return ("Cledoo MCP Pro — last 30 days\n"
                "AI calls: %d (writes: %d, denied: %d)\n"
                "Behavior alerts: %d\n"
                "Approval tickets: %d\n"
                % (total, writes, denied, alerts, pending))

    @api.model
    def _cron_digest(self):
        email = self.env["ir.config_parameter"].sudo().get_param(
            "cledoo_mcp_full.digest_email")
        if not email:
            return
        try:
            self.env["mail.mail"].sudo().create({
                "subject": "Cledoo MCP Pro — monthly AI activity report",
                "email_to": email,
                "body_html": "<pre>%s</pre>" % self._digest_body(),
            }).send()
        except Exception:
            _logger.exception("mcp pro digest failed (ignored)")


class McpBehaviorAlert(models.Model):
    _name = "mcp.behavior.alert"
    _description = "MCP behavior alert"
    _order = "id desc"

    rule_id = fields.Many2one("mcp.behavior.rule", required=True,
                              ondelete="cascade")
    principal_key = fields.Char(required=True, index=True)
    count = fields.Integer()
    state = fields.Selection([("new", "New"), ("ack", "Acknowledged")],
                             default="new", required=True)
    suspension_ids = fields.One2many("mcp.principal.suspension", "alert_id")

    def _notify_admins(self):
        try:
            admins = self.env.ref("base.group_system").users.filtered(
                lambda u: u.active and u.id != self.env.ref("base.user_root").id)
            for user in admins[:5]:
                self.env["mail.activity"].sudo().create({
                    "res_model_id": self.env["ir.model"].sudo()._get_id(
                        self._name),
                    "res_id": self.id, "user_id": user.id,
                    "activity_type_id": self.env.ref(
                        "mail.mail_activity_data_todo").id,
                    "summary": "MCP behavior alert: %s (%s)"
                               % (self.rule_id.name, self.principal_key),
                })
        except Exception:
            pass

    def action_ack(self):
        self.write({"state": "ack"})
