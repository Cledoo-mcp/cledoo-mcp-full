# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""OAuth 2.1 authorization-server state: clients, codes, tokens.

All records are managed exclusively via sudo() from the OAuth controllers;
there is no user-facing ACL to create/write these (see ir.model.access:
only base.group_system gets read/unlink for the admin revoke view).
Secrets are persisted as SHA-256 hashes; raw values live only in the HTTP
response that mints them."""
from datetime import timedelta

from odoo import api, fields, models
from odoo.fields import Datetime

from odoo.addons.cledoo_mcp_full.lib import oauth_tokens as T

CODE_TTL = 600
# Access-token default lifetime. 1h proved too short in the field: when
# the token dies between two claude.ai conversations, the next one starts
# with the connector silently absent (no failing tool call = no inline
# reconnect prompt). Admin-tunable via cledoo_mcp_full.oauth_access_ttl_hours.
DEFAULT_ACCESS_TTL_HOURS = 8
REFRESH_TTL = 7776000


def access_ttl(env):
    """Configured access-token lifetime in seconds (>=1h steps; absent,
    garbage or non-positive values fall back to the default)."""
    from odoo.addons.cledoo_mcp_full.lib.params import get_int_param
    hours = get_int_param(env, "cledoo_mcp_full.oauth_access_ttl_hours",
                          DEFAULT_ACCESS_TTL_HOURS)
    if hours <= 0:
        hours = DEFAULT_ACCESS_TTL_HOURS
    return hours * 3600
# Grace period before autovacuum drops dead records. Revoked refresh tokens
# take part in reuse-detection (_rotate's theft signal), so they must survive
# long enough that replaying a recently-stolen ancestor still nukes the live
# family; 30 days is far beyond any realistic replay window while keeping the
# tables bounded.
GC_GRACE_DAYS = 30


class McpOAuthClient(models.Model):
    _name = "mcp.oauth.client"
    _description = "MCP OAuth client (dynamically registered)"

    client_id = fields.Char(required=True, index=True, readonly=True)
    client_name = fields.Char()
    redirect_uris = fields.Text(help="One redirect URI per line.")

    def _register_client(self, client_name, redirect_uris):
        # client_name is attacker-controlled metadata (open dynamic
        # registration); cap it so a hostile registrant can't stuff the
        # consent page or the DB. URI count/length are validated (rejected)
        # at the controller; the truncation here is a backstop.
        name = (client_name or "MCP Client").strip()[:64] or "MCP Client"
        return self.sudo().create({
            "client_id": T.new_secret(),
            "client_name": name,
            "redirect_uris": "\n".join(redirect_uris or []),
        })

    def _get(self, client_id):
        if not client_id:
            return self.browse()
        return self.sudo().search([("client_id", "=", client_id)], limit=1)

    def _redirect_ok(self, redirect_uri):
        self.ensure_one()
        registered = [u.strip() for u in (self.redirect_uris or "").splitlines() if u.strip()]
        return redirect_uri in registered

    @api.autovacuum
    def _gc_dormant_clients(self):
        """Drop registrations that never obtained (or no longer hold) any
        token and any pending code, after the grace period. Open dynamic
        registration means bots can create rows freely; a legit client that
        gets collected simply re-registers (that's the DCR flow anyway)."""
        cutoff = Datetime.now() - timedelta(days=GC_GRACE_DAYS)
        stale = self.sudo().search([("create_date", "<", cutoff)])
        if not stale:
            return
        live_ids = set()
        for model in ("mcp.oauth.token", "mcp.oauth.code"):
            groups = self.env[model].sudo()._read_group(
                [("client_id", "in", stale.mapped("client_id"))],
                ["client_id"], [])
            live_ids.update(g[0] for g in groups)
        stale.filtered(lambda c: c.client_id not in live_ids).unlink()


class McpOAuthCode(models.Model):
    _name = "mcp.oauth.code"
    _description = "MCP OAuth authorization code (single use)"

    code_hash = fields.Char(required=True, index=True)
    client_id = fields.Char(required=True)
    user_id = fields.Many2one("res.users", required=True, ondelete="cascade")
    redirect_uri = fields.Char(required=True)
    code_challenge = fields.Char(required=True)
    resource = fields.Char()
    expires_at = fields.Datetime(required=True)
    used = fields.Boolean(default=False)

    def _issue(self, client_id, uid, redirect_uri, code_challenge, resource,
               scope_vals=None):
        raw = T.new_secret()
        self.sudo().create(dict({
            "code_hash": T.hash_secret(raw),
            "client_id": client_id,
            "user_id": uid,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "resource": resource or False,
            "expires_at": Datetime.now() + timedelta(seconds=CODE_TTL),
        }, **(scope_vals or {})))
        return raw

    def _scope_vals(self):
        """Consent-scope values to copy onto the tokens minted from this
        code. Lite: none; MCP Pro overrides (scope columns live there)."""
        return {}

    def _consume(self, raw_code, client_id, redirect_uri):
        if not raw_code or not client_id:
            return None
        rec = self.sudo().search([("code_hash", "=", T.hash_secret(raw_code))], limit=1)
        if (not rec or rec.used or rec.client_id != client_id
                or rec.redirect_uri != redirect_uri
                or rec.expires_at < Datetime.now()):
            return None
        rec.used = True
        return rec

    @api.autovacuum
    def _gc_expired_codes(self):
        # Codes live 10 minutes (CODE_TTL) and are single-use; anything past
        # its expiry — used or not — is dead weight.
        self.sudo().search([("expires_at", "<", Datetime.now())]).unlink()


class McpOAuthToken(models.Model):
    _name = "mcp.oauth.token"
    _description = "MCP OAuth access/refresh token"

    token_hash = fields.Char(required=True, index=True)
    kind = fields.Selection([("access", "Access"), ("refresh", "Refresh")], required=True)
    pair_id = fields.Char(required=True, index=True)
    client_id = fields.Char(required=True)
    client_name = fields.Char(compute="_compute_client_name")
    user_id = fields.Many2one("res.users", required=True, ondelete="cascade")
    expires_at = fields.Datetime(required=True)
    revoked = fields.Boolean(default=False)

    def _compute_client_name(self):
        # client_id is a Char (opaque DCR identifier), not a Many2one: the
        # client row may be GC'd while its tokens survive, and tokens must
        # never dangle. Resolve the display name in bulk instead.
        clients = self.env["mcp.oauth.client"].sudo().search(
            [("client_id", "in", [t.client_id for t in self])])
        names = {c.client_id: c.client_name for c in clients}
        for rec in self:
            rec.client_name = names.get(rec.client_id) or rec.client_id

    def _issue_pair(self, client_id, uid, pair_id=None, scope_vals=None):
        pair = pair_id or T.new_secret()
        raw_access, raw_refresh = T.new_secret(), T.new_secret()
        now = Datetime.now()
        extra = scope_vals or {}
        self.sudo().create([
            dict({"token_hash": T.hash_secret(raw_access), "kind": "access",
                  "pair_id": pair, "client_id": client_id, "user_id": uid,
                  "expires_at": now + timedelta(seconds=access_ttl(self.env))},
                 **extra),
            dict({"token_hash": T.hash_secret(raw_refresh), "kind": "refresh",
                  "pair_id": pair, "client_id": client_id, "user_id": uid,
                  "expires_at": now + timedelta(seconds=REFRESH_TTL)}, **extra),
        ])
        return raw_access, raw_refresh

    def _resolve_access_rec(self, raw_access):
        """The validated token record for a raw access token, or None."""
        if not raw_access:
            return None
        rec = self.sudo().search([
            ("token_hash", "=", T.hash_secret(raw_access)),
            ("kind", "=", "access"), ("revoked", "=", False)], limit=1)
        if not rec or rec.expires_at < Datetime.now():
            return None
        user = rec.user_id
        if not user.exists() or not user.active:
            return None
        return rec

    def _resolve_access(self, raw_access):
        rec = self._resolve_access_rec(raw_access)
        return rec.user_id.id if rec else None

    def action_revoke(self):
        """Admin-facing revoke (Settings > Connected AI clients button).

        Revokes the whole token family (same pair_id), not just the selected
        records: the admin list shows access tokens only, and revoking an
        access token while leaving its sibling refresh token alive would let
        the client mint a fresh pair within seconds — the admin's "Revoke"
        must actually cut the client off.

        Uses sudo() because base.group_system only has read/unlink on this
        model (see class docstring); revocation must work regardless of the
        clicking user's own write ACL on mcp.oauth.token."""
        pair_ids = self.mapped("pair_id")
        if not pair_ids:
            return
        self.sudo().search(
            [("pair_id", "in", pair_ids)]).write({"revoked": True})

    def _rotate(self, raw_refresh, client_id):
        if not raw_refresh or not client_id:
            return None
        rec = self.sudo().search([
            ("token_hash", "=", T.hash_secret(raw_refresh)),
            ("kind", "=", "refresh")], limit=1)
        if not rec or rec.client_id != client_id:
            return None
        if rec.revoked or rec.expires_at < Datetime.now():
            # reuse of an already-rotated/expired refresh -> revoke whole family,
            # including any descendants minted by later rotations (theft signal)
            self.sudo().search([("pair_id", "=", rec.pair_id)]).write({"revoked": True})
            return None
        # revoke this generation, issue a fresh pair under the same family id so
        # that a later reuse of any ancestor token still nukes the newest tokens
        # pair_id is stable across the lineage: revoking the family here only hits the
        # current generation (older ones are already revoked), so sequential rotation
        # works while replay of any stale ancestor still nukes the live family
        self.sudo().search([("pair_id", "=", rec.pair_id)]).write({"revoked": True})
        return self._issue_pair(client_id, rec.user_id.id,
                                 pair_id=rec.pair_id,
                                 scope_vals=rec._rotation_scope_vals())

    def _rotation_scope_vals(self):
        """Scope values to carry over when this refresh token rotates.
        Lite: none; MCP Pro overrides."""
        return {}

    @api.autovacuum
    def _gc_dead_tokens(self):
        """Purge tokens that have been expired or revoked for GC_GRACE_DAYS.

        The grace period is deliberate: revoked refresh tokens power the
        reuse-detection in _rotate (replaying a rotated ancestor revokes the
        live family). Collecting them immediately would downgrade that theft
        signal to a plain invalid_grant. After 30 days the trade-off flips:
        an unbounded table costs every install, a month-old replay is not a
        realistic theft window."""
        cutoff = Datetime.now() - timedelta(days=GC_GRACE_DAYS)
        self.sudo().search([
            "|",
            ("expires_at", "<", cutoff),
            "&", ("revoked", "=", True), ("write_date", "<", cutoff),
        ]).unlink()
