# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Bearer-token resolution against native Odoo API keys.

No custom token storage: the bearer IS a standard Odoo API key
(user preferences > Account Security). Odoo hashes, indexes and
constant-time-compares keys itself; we only map key -> uid and refuse
inactive users.

Call shape (pinned by spike, identical on Odoo 18 and Odoo 19 -- see
docs/superpowers/lite-wiring-notes.md for the exact source lines):

    res.users.apikeys._check_credentials(*, scope, key) -> uid | False

`scope` is keyword-only on both versions. We pass ``scope="rpc"``: the
'rpc' scope does not really exist as stored data (see Odoo core's own
`res_users._check_credentials`, which does the same thing to authenticate
XML-RPC/JSON-RPC callers). The underlying SQL match is
``scope IS NULL OR scope = %(scope)s``, so any *global* key -- the kind
created through the standard "New API Key" UI wizard
(`res.users.apikeys.description.make_key`, which always calls
`_generate(None, name, expiration_date)`) -- matches regardless of the
scope we ask for. A key deliberately scoped to something other than
'rpc' would correctly NOT match here.
"""


def resolve_api_key(env, token):
    if not token:
        return None
    uid = env["res.users.apikeys"].sudo()._check_credentials(
        scope="rpc", key=token)
    if not uid:
        return None
    user = env["res.users"].sudo().browse(uid)
    if not user.exists() or not user.active:
        return None
    return uid


def resolve_bearer(env, token):
    """Resolve a bearer to a uid: native Odoo API key first, then an
    OAuth access token. Returns the uid of an active user, else None."""
    details = resolve_bearer_details(env, token)
    return details["uid"] if details else None


def resolve_bearer_details(env, token):
    """Like resolve_bearer but keeps the principal identity:
    {"uid": int, "kind": "apikey"|"oauth", "token_id": int|None,
     "apikey_id": int|None}.
    The controller uses kind/token_id for rate-limit bucketing and the
    per-principal activity counters (one bucket per token, not per user).
    apikey_id: Odoo's _check_credentials returns only the uid, so the
    key row is re-identified by (index-prefix, uid). The index column
    stores the key's first 8 chars — a same-user prefix collision is
    astronomically unlikely and, worst case, attributes the call to the
    user's OTHER key (never to another user). `index` is a DB-only
    column (deliberately excluded from the ORM field list alongside the
    secret `key` column, see base's res.users.apikeys.init()), so it is
    looked up with raw SQL rather than a search() domain."""
    if not token:
        return None
    uid = resolve_api_key(env, token)
    if uid is not None:
        env.cr.execute(
            "SELECT id FROM res_users_apikeys WHERE index = %s"
            " AND user_id = %s LIMIT 1", (token[:8], uid))
        row = env.cr.fetchone()
        return {"uid": uid, "kind": "apikey", "token_id": None,
                "apikey_id": row[0] if row else None}
    rec = env["mcp.oauth.token"].sudo()._resolve_access_rec(token)
    if rec is None:
        return None
    return {"uid": rec.user_id.id, "kind": "oauth", "token_id": rec.id,
            "apikey_id": None}
