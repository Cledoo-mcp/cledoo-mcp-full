# Cledoo MCP Pro

Governance layer for [Cledoo MCP](../cledoo_mcp_full/README.md): consent scopes,
allow/deny policies with a dry-run simulator, PII masking, human-approved
writes, per-principal quotas, a full audit trail, an agent outbound-comms
guard, and AI usage analytics + a behavior radar.

Cledoo MCP Pro is a paid add-on — **€189, one-time** (per Odoo major
version). It is sold as code: possession is the licence (LGPL-3), there is
no runtime licence key. Every feature below is active whenever
`cledoo_mcp_full` is installed. Support and updates are provided to
purchasers.

## Install

After purchase you receive `cledoo-mcp-pro.zip`. Prerequisite: the free base
module `cledoo_mcp_full` must be installed first (same steps, same archive layout).

1. Unzip the archive — you get a `cledoo_mcp_full/` folder.
2. Copy that folder into an addons directory of your server: any path listed
   in `addons_path` in your `odoo.conf` (on the official Docker image,
   `/mnt/extra-addons` mounted as a volume works out of the box).
3. Restart the Odoo service.
4. Enable developer mode, then go to **Apps → Update Apps List**.
5. Search for *Cledoo MCP Pro* and click **Install**.
6. Go to **Settings → General Settings → MCP Server** — a new "MCP Pro"
   section appears below the base MCP settings.

Do **not** use the **Apps → Import Module** upload screen: that importer only
handles data-only modules and cannot load this module's Python code — always
go through the addons path as described above.

On **Odoo.sh**: no zip to upload — commit the `cledoo_mcp_full/` folder to the
GitHub repository linked to your project; the next build installs it.

### Installation (français)

Après l'achat vous recevez `cledoo-mcp-pro.zip`. Prérequis : le module de
base gratuit `cledoo_mcp_full` doit être installé d'abord (mêmes étapes, même
structure d'archive).

1. Dézippez l'archive — vous obtenez un dossier `cledoo_mcp_full/`.
2. Copiez ce dossier dans un répertoire d'addons de votre serveur : n'importe
   quel chemin listé dans `addons_path` de votre `odoo.conf` (sur l'image
   Docker officielle, `/mnt/extra-addons` monté en volume fonctionne
   directement).
3. Redémarrez le service Odoo.
4. Activez le mode développeur, puis **Apps → Mettre à jour la liste des
   applications**.
5. Cherchez *Cledoo MCP Pro* et cliquez sur **Installer**.
6. Ouvrez **Réglages → Paramètres généraux → MCP Server** — une nouvelle
   section « MCP Pro » apparaît sous les réglages MCP de base.

N'utilisez **pas** l'écran **Apps → Importer un module** : cet importeur ne
gère que les modules de données et ne peut pas charger le code Python de ce
module — passez toujours par l'addons path comme décrit ci-dessus.

Sur **Odoo.sh** : pas de zip à téléverser — commitez le dossier
`cledoo_mcp_full/` dans le dépôt GitHub lié à votre projet ; le build suivant
l'installe.

There is no licence key, activation step or phone-home: possession of the
code is the licence (LGPL-3). Every governance feature (`scopes`, `policy`,
`masking`, `approvals`, `quotas`, `outbound`, `analytics`, `apps`, `audit`)
is active as soon as the module is installed.

## Feature-by-feature admin guide

### Consent scopes (`scopes`)

OAuth consent and API-key generation gain extra controls: a **read-only**
toggle and a **model allow-list** ("only these models"), stored per token
or per key. A scoped OAuth client or API key can only call the tools/models
its grant allows — enforced at every `/mcp` call, not just at consent time.

### Policies + the dry-run simulator (`policy`)

**Settings → MCP Pro → Policies** is an ordered list of rules
(`sequence`, `model_pattern` glob like `res.partner` / `hr.*` / `*`,
optional `principal_pattern`, optional `operation` filter, `fields_deny`,
and a `verdict`: **Allow**, **Deny**, or **Require approval**). The first
matching rule wins; with **no** matching rule, the "Policy: deny by
default" toggle decides the outcome (off by default until you've built
your rule set).

Before enforcing a new rule, put it in **Dry run** mode and use
**Simulate** (`mcp.policy.simulate`) to replay it against the existing
audit trail: it reports how many recorded calls the rule would have hit,
blocked, or paused for approval, with **zero** effect on production
traffic. Only once the simulator shows no false positives do you flip the
rule to **Enforce** — a one-click **Promote** action does this transition.
`fields_deny` on an Allow-verdict rule additionally strips those fields
from read results and blocks writes touching them — including from
CSV/XLSX exports, aggregate/group-by responses, and domain/order clauses
that would otherwise leak a denied field's values through an oracle (a
`["phone", "like", "..."]` filter is just as much a read of `phone` as
returning it in the payload).

**`fields_deny` known limitations:** (a) nested x2many command tuples
(e.g. `child_ids: [(0, 0, {...})]`) are not inspected — only top-level
`values` keys are checked, so a denied field written through a nested
command on a related record is not caught; (b) image/binary variant
fields are distinct fields — denying `image_1920` does not also cover
`image_128`/`image_256`/etc., each variant must be listed explicitly.

### PII masking (`masking`)

**Settings → MCP Pro → PII Masking**: pick a model + field and a strategy
(**Redact** `***`, **Partial** `ab***`, or **Hash** — a stable pseudonym
so the same value always masks to the same token, useful for joins without
exposing the value itself). Masking runs on the *result* side, after the
policy engine and after the underlying tool executes, and — critically —
**before** the call is written to the audit trail: a masked field's real
value never touches the audit log, even transiently. Masking also expands
to *derived* fields (e.g. masking `email` on `res.partner` also catches
`email_normalized` and similar computed/related fields that would
otherwise leak the same PII under a different name).

### Human-approved writes (`approvals`)

A policy rule with verdict **Require approval** doesn't execute the write
immediately: it creates a hash-bound `mcp.approval` ticket (visible to
members of the **MCP Approver** group only — the AI agent's own Odoo user
must never be in this group, it is the human trust boundary) and returns
a `pending` outcome to the caller. Once a human **Approve**s the ticket
in the UI, the agent calls the `check_approval` tool with the ticket id;
the *exact same* call (hash-bound to its original arguments, so an
approver can't be tricked into approving a different write than the one
they reviewed) executes and its real result is returned. Refuse/Expire are
the other terminal states. Read operations are never gated by an approval
rule — it is a write-only mechanism.

### Quotas (`quotas`)

**Settings → MCP Pro → Quotas**: per-principal daily caps on total calls
and on write/delete calls, counted straight from the audit spine (so a
quota is only ever as trustworthy as what actually got audited — see
below). `0` means unlimited. Denials don't consume budget.

### Agent outbound guard (`outbound`)

Blocks an AI agent from sending customer-facing communications (chatter
notifications to followers, `mail.mail` create/write, template sends,
scheduled/delayed messages) without a human-issued, content-bound
confirmation token: the token is bound to a hash of the *exact* message
content at issue time, so editing the message after approval invalidates
the token (closes the classic TOCTOU gap where an agent gets approval for
one message and sends a different one). Internal notes (not visible to
customers) are exempt. A human user sending mail through the normal Odoo
UI is never affected — the guard only triggers for calls attributed to an
MCP agent principal.

**Known open item (V3 backlog):** attachments are not yet content-bound —
an agent-composed message with a swapped attachment after token issuance
is not currently detected. This is inherited from the original outbound
guard module's own known-open item; see "V3 backlog" below.

**Approver note on `mail.mail` create tokens:** the escape hatch that
lets an agent create `mail.mail` rows directly (bypassing message_post,
e.g. via template sends) is scoped to `("mail.mail", "create", [])` with
no content binding — one issued token authorizes **one** `create()` call
of arbitrary batch size, i.e. N mails to N recipients in that single
call. This is coarser than a `message_post` token, which is bound to one
message's content; approvers should weigh that before issuing it.

### Analytics + behavior radar (`analytics`)

**MCP Pro → Analytics** is a graph/pivot view over the audit trail
(calls, denials, approvals, by tool/model/day) for spotting usage patterns
at a glance. Layered on top, the **behavior radar** runs a set of
detectors (mass read/scraping, off-hours activity, repeated denials i.e.
policy probing, export volume spikes) against the same audit data and can
either just alert, or alert **and** suspend the offending principal via a
reversible kill-switch (**Suspensions**) — one active suspension per
principal at a time, so repeated detector hits don't stack punitive
effects. A monthly digest email (configurable recipient) summarises calls,
writes, denials, alerts and approvals for the period.

### MCP Apps (`apps`)

Three `ui://` resource cards (approval-ticket status, an analytics
snapshot, and a policy-denial explainer) are served over `resources/list`
/ `resources/read` and stamped into relevant tool results via `_meta` so
MCP-Apps-aware clients render rich, live status instead of plain JSON.
Clients without MCP Apps support simply ignore `_meta` and see the normal
tool response — this is strictly progressive, never required.

## Threat-model notes

**Agent context boundary.** Every governance decision in this module is
keyed off the *principal* the transport resolved for the call (API key or
OAuth token, plus the human `uid` behind it) — never off client-supplied
data. An agent cannot claim to be a different principal, widen its own
scope, or approve its own writes: scopes/policy/quotas/outbound all read
`context["principal"]` from the seam the base module's controller builds
from the authenticated credential, not from the tool call's arguments.

**Fail-open bookkeeping, fail-closed governance.** Governance *checks*
(policy, scopes, quotas, approval gating) fail **closed**: any error in
evaluating them raises a `ToolError` subclass and blocks the call. Pure
*bookkeeping* (audit-row writes, quota counters, session/activity
tracking) fails **open**: a DB error while writing an audit row is caught,
logged, and never aborts or blocks the tool call itself — a broken audit
write must not turn into a broken MCP server. Each bookkeeping write uses
its own savepoint so a failure there can't corrupt the surrounding
transaction. Separately — and this is a real, previously-broken
interaction that this release's live E2E gate caught and fixed — a
*denied or erroring* tool call must still be audited: the base seam
(`cledoo_mcp_full/models/gateway.py`) now scopes its own protective savepoint
tightly around the underlying tool's write, one level below Pro's
governance/audit pipeline, so audit rows for denials/errors are no longer
silently discarded together with the failed tool's half-applied writes.

**Annotation honesty for read-only scopes.** MCP tool annotations
(`readOnlyHint`, `destructiveHint`, ...) are what MCP clients show users
as the trust/consent surface for a tool. A read-only-scoped API key or
OAuth grant is enforced against the *same* annotation the client saw at
consent time — Pro doesn't silently allow a write tool through a
read-only scope because it happens to also satisfy some read-shaped
policy rule; the scope check is annotation-driven and runs before policy,
so the client's consent screen stays an honest description of what the
credential can actually do.

## V3 backlog

- **Outbound guard: attachments unbound.** Content-binding today covers
  the message body/subject but not attachments; an agent could in
  principle swap an attachment after a human approved the message text.
  Inherited from the original standalone `agent_outbound_guard` module's
  own known-open item — closing it needs a content hash that also covers
  attachment bytes, and a decision on how to handle attachments added
  *after* the approval token was issued (deny outright vs. re-approval).
