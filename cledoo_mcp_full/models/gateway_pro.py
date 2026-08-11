# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""The Pro governance pipeline. ONE ordered override of the seam:

    licence -> suspension -> scopes -> policy -> approvals -> quotas
        -> super()._execute_tool() -> masking -> (finally) audit

Cross-feature rules live HERE, visibly:
- audit records everything, including denials and errors;
- masking runs before audit capture (the log must not leak PII);
- results carrying the __mcp_content__ sentinel bypass masking and are
  audited as metadata only;
- governance checks fail CLOSED (ToolError subclasses, stable codes,
  seam ABI unchanged); bookkeeping fails OPEN (savepoint + log).
Feature hooks are no-ops until their task lands; each is gated on its
licence feature claim inside the hook itself."""
import json
import logging
import time
from datetime import timedelta

from odoo import fields, models

from odoo.addons.cledoo_mcp_full.lib.tools import TOOLS, ToolError, ToolAccessError
from odoo.addons.cledoo_mcp_full.models.gateway import UnknownToolError
from odoo.addons.cledoo_mcp_full.lib import license as lic

_logger = logging.getLogger(__name__)

# Pro-only tools (filled by Task 11: check_approval).
# name -> (fn(gateway, req) -> dict, inputSchema, annotations)
PRO_TOOLS = {}

# Base tools that inline field data into an encoded payload
# (content_base64) the result-side key-strip cannot reach. Their
# request must be sanitized instead (drop denied fields from the
# explicit `fields` arg) or the call denied.
BLOB_TOOLS = frozenset({"export_records"})

# print_report/read_resource take no `model` argument by design (see
# lib/tools.py); _derive_blob_model() below resolves one from their own
# arguments so model-scope/field-deny/default-deny policy still applies
# to them ([B1], Task 8 review). When resolution fails (malformed uri,
# unknown report, an attachment not linked to any record...) req.model
# stays None — these two must still fail CLOSED under default-deny
# rather than silently skip policy like a genuinely model-less tool
# (whoami, list_models...) is allowed to.
BLOB_MODEL_LESS_TOOLS = frozenset({"read_resource", "print_report"})


def _touched_fields(values):
    """[B3] Top-level keys of a `values` dict, plus field names touched
    by nested x2many create/update commands: (0, _, {...}) and
    (1, _, {...}) carry a nested values dict that a denied field can
    hide in (e.g. child_ids: [(0, 0, {"phone": "..."})]) — recursed,
    since a nested create can itself nest further x2many commands.
    Delete/link/unlink commands ((2,_,_), (3,_,_), (4,_,_), (5,_,_),
    (6,_,ids)) carry no field dict and are not inspected."""
    touched = set()
    if not isinstance(values, dict):
        return touched
    for key, val in values.items():
        touched.add(key)
        if isinstance(val, (list, tuple)):
            for cmd in val:
                if (isinstance(cmd, (list, tuple)) and len(cmd) == 3
                        and cmd[0] in (0, 1) and isinstance(cmd[2], dict)):
                    touched |= _touched_fields(cmd[2])
    return touched


class ProRequest:
    """Mutable per-call state threaded through the pipeline stages."""

    def __init__(self, uid, tool, args, context, features, annotations):
        self.uid = uid
        self.tool = tool
        self.args = args or {}
        self.context = context or {}
        self.features = features
        self.annotations = annotations or {}
        self.principal = (context or {}).get("principal") or {}
        self.model = (args or {}).get("model")
        self.outcome = "ok"
        self.code = None
        self.rule_id = None            # enforcing policy rule that denied
        self.would_deny_rule_id = None  # dry-run rule that would have
        self.approval_rule_id = None    # approval-verdict rule that matched
        self.pending_id = None          # approval ticket id
        self.duration_ms = 0
        self.strip_fields = set()       # field names policy strips from results
        self.blob_field = None          # read_resource's target field, if derivable

    @property
    def principal_key(self):
        p = self.principal
        if p.get("kind") == "oauth" and p.get("token_id"):
            return "token:%s" % p["token_id"]
        return "apikey:%s" % (p.get("apikey_id") or p.get("uid"))

    @property
    def operation(self):
        if self.annotations.get("readOnlyHint"):
            return "read"
        if self.annotations.get("destructiveHint"):
            return "unlink"
        return "write"


class McpGatewayPro(models.AbstractModel):
    _inherit = "mcp.gateway"

    # -- pipeline ---------------------------------------------------------

    def _execute_tool(self, uid, tool_name, arguments, context=None):
        features = lic.active_features(self.env)  # always all features
        annotations = self._pro_annotations(tool_name)
        req = ProRequest(uid, tool_name, arguments, context, features,
                         annotations)
        self._derive_blob_model(req)
        started = time.monotonic()
        try:
            self._check_suspension(req)
            self._check_readonly(req)
            self._check_scopes(req)
            try:
                self._check_policy(req)
            except ToolAccessError as exc:
                # Stamp the denial-explainer ui:// hint on every policy
                # denial (feature 'apps', same gate apps.py uses to serve
                # the resource at all) so MCP Apps clients can render a
                # "denied by rule X" card instead of bare error text.
                # Suspension/scope denials above are deliberately not
                # covered — those aren't policy-rule outcomes the card
                # explains.
                if "apps" in req.features:
                    exc.meta = {"ui": {
                        "resourceUri": "ui://cledoo/denial-explainer"}}
                raise
            pending = self._gate_approval(req)
            if pending is not None:
                req.outcome = "pending"
                return pending
            self._check_quota(req)
            self._sanitize_strips(req)
            result = self._pro_dispatch(uid, tool_name, arguments, context,
                                        req)
            return self._mask(req, result)
        except ToolError as exc:
            req.outcome = ("denied" if isinstance(exc, ToolAccessError)
                           else "error")
            req.code = exc.code
            raise
        except UnknownToolError:
            req.outcome = "error"
            req.code = "unknown_tool"
            raise
        except Exception:
            req.outcome = "error"
            req.code = "internal"
            raise
        finally:
            req.duration_ms = int((time.monotonic() - started) * 1000)
            self._audit(req)

    def _derive_blob_model(self, req):
        """[B1] read_resource/print_report carry no `model` argument, so
        without this step they evade every model-scoped check downstream
        (scopes' model list, policy's model_pattern/field-deny/default-
        deny). Parse what's derivable from the tool's own arguments;
        `req.model`/`req.blob_field` stay None when it truly can't be
        resolved (BLOB_MODEL_LESS_TOOLS then still fails closed under
        default-deny in `_check_policy`, see its docstring)."""
        if req.tool == "read_resource":
            uri = str(req.args.get("uri") or "")
            prefix = "odoo://"
            if not uri.startswith(prefix):
                return
            parts = uri[len(prefix):].split("/")
            if parts[0] == "record" and len(parts) == 4:
                req.model = parts[1]
                req.blob_field = parts[3]
            elif parts[0] == "attachment" and len(parts) == 2 \
                    and parts[1].isdigit():
                att = self.env["ir.attachment"].sudo().browse(
                    int(parts[1])).exists()
                if att and att.res_model:
                    req.model = att.res_model
                    if att.res_field:
                        # Binary(attachment=True)/image fields are stored
                        # as ir.attachment rows with res_field set: the
                        # attachment uri is a second door to the same
                        # field bytes, so the field-deny blob guard must
                        # see the field here too.
                        req.blob_field = att.res_field
        elif req.tool == "print_report":
            # Same resolution as the tool itself will use (lib/tools.py):
            # reimplementing it here would let the two drift and reopen
            # the policy gap for uri forms only one of them understands.
            from odoo.addons.cledoo_mcp_full.lib.tools import _resolve_report
            rep = _resolve_report(self.env, req.args.get("report_ref") or "")
            if rep:
                req.model = rep.model

    def _pro_annotations(self, tool_name):
        if tool_name in PRO_TOOLS:
            return PRO_TOOLS[tool_name][2]
        entry = TOOLS.get(tool_name)
        return entry[2] if entry else {}

    def _pro_dispatch(self, uid, tool_name, arguments, context, req):
        if tool_name in PRO_TOOLS:
            return PRO_TOOLS[tool_name][0](self, req)
        gw = self
        if "outbound" in req.features and req.operation != "read":
            args = arguments or {}
            gw = self.with_context(
                cledoo_mcp_agent=req.principal_key,
                outbound_token=args.pop("confirmation_token", None))
        return super(McpGatewayPro, gw)._execute_tool(
            uid, tool_name, arguments, context=context)

    def _list_tools(self, uid=None):
        tools = super()._list_tools(uid=uid)
        # The base gateway no longer filters (readonly moved to Pro): do
        # it here so a readonly instance's tools/list stays consistent
        # with what _check_readonly will actually let through.
        readonly = self._readonly_mode()
        if readonly:
            tools = [t for t in tools if t["annotations"].get("readOnlyHint")]
        if not lic.active_features(self.env):
            return tools
        has_apps = "apps" in lic.active_features(self.env)
        for name, (fn, schema, annotations) in PRO_TOOLS.items():
            # By-name carve-out, same reasoning as _check_readonly:
            # check_approval's readOnlyHint stays False (honest for
            # client trust UI) but it must stay visible under readonly —
            # the actual write it may replay is still blocked when it
            # runs, via the nested _execute_tool call's own readonly
            # check on the real tool.
            if readonly and name != "check_approval" \
                    and not annotations.get("readOnlyHint"):
                continue
            descriptor = {
                "name": name,
                "description": " ".join((fn.__doc__ or name).split()),
                "inputSchema": schema,
                "annotations": annotations,
            }
            # Descriptor-side ui hint (feature 'apps'), only for tools with
            # a stable 1:1 result->template mapping. check_approval always
            # renders the approval card; other ui:// templates (analytics
            # snapshot, denial explainer) are result-conditional and are
            # stamped on the result itself via _with_app_meta instead.
            if has_apps and name == "check_approval":
                descriptor["_meta"] = {
                    "ui": {"resourceUri": "ui://cledoo/approval-card"}}
            elif has_apps and name == "mcp_analytics":
                descriptor["_meta"] = {
                    "ui": {"resourceUri": "ui://cledoo/analytics-snapshot"}}
            tools.append(descriptor)
        return tools

    # -- feature hooks (each task replaces its no-op) ----------------------

    def _check_suspension(self, req):
        """Kill-switch: an active suspension blocks the principal for
        every tool. First check in the pipeline — a suspended scraper
        must not even reach policy evaluation. Any licensed feature set
        enforces this (the radar that creates suspensions is licence-
        gated on its own side)."""
        susp = self.env["mcp.principal.suspension"].sudo().search(
            [("principal_key", "=", req.principal_key),
             ("active", "=", True)], limit=1)
        if susp:
            raise ToolAccessError(
                "This MCP connection is suspended (%s). An administrator "
                "can lift the suspension in Odoo: MCP Pro > Alerts."
                % (susp.reason or "behavior alert"))

    def _readonly_mode(self):
        """Same system parameter the free module used to read before this
        global kill-switch moved to Pro (fine-grained governance is
        paid-only). Keeping the exact param name (`cledoo_mcp_full.readonly`)
        means a database that had it enabled keeps the same protection
        the moment Pro is installed — no migration script needed."""
        return self.env["ir.config_parameter"].sudo().get_param(
            "cledoo_mcp_full.readonly") == "True"

    def _check_readonly(self, req):
        """Global kill-switch for write tools (Settings > MCP Pro >
        Read-only mode). Annotation-driven like the free implementation
        it replaces: a tool is a write tool unless its MCP annotation
        says readOnlyHint. Checked right after suspension, before scopes,
        so a readonly instance never reaches per-connection scope/policy
        evaluation for a call it is going to refuse anyway.

        check_approval is let through BY NAME, not by annotation: its
        wire `readOnlyHint` stays False (honest — it CAN land an
        approved write, and clients use that hint for trust UI like
        auto-invoke-without-confirmation) even though it must stay
        pollable/callable under readonly. Pollability here is a pipeline
        decision, not a tool property — the actual write it may replay
        re-enters this same pipeline via a nested `_execute_tool` call on
        the real tool name, which re-checks readonly against THAT tool's
        own (non-readOnlyHint) annotation and blocks it there."""
        if req.tool == "check_approval" or req.annotations.get("readOnlyHint"):
            return
        if self._readonly_mode():
            raise ToolAccessError(
                "MCP is in read-only mode: write tools are disabled by"
                " the administrator (Odoo Settings > MCP Pro >"
                " Read-only mode).")

    def _check_scopes(self, req):
        """OAuth-token and API-key consent scopes (feature 'scopes').
        Readonly grant blocks write/unlink tools; a model list blocks
        out-of-list models. Tools without a model argument (whoami,
        list_models...) pass the model check."""
        if "scopes" not in req.features:
            return
        readonly, models_csv = self._principal_scopes(req)
        if readonly and req.operation != "read":
            raise ToolAccessError(
                "This connection was granted read-only access on the "
                "consent screen; write tools are not available.")
        if models_csv and req.model:
            allowed = {m.strip() for m in models_csv.split(",") if m.strip()}
            if req.model not in allowed:
                raise ToolAccessError(
                    "This connection is limited to: %s."
                    % ", ".join(sorted(allowed)))

    def _principal_scopes(self, req):
        """(readonly: bool, models_csv: str|False) for the principal."""
        p = req.principal
        if p.get("kind") == "oauth" and p.get("token_id"):
            tok = self.env["mcp.oauth.token"].sudo().browse(p["token_id"])
            if tok.exists():
                return tok.scope_readonly, tok.scope_models
        if p.get("kind") == "apikey" and p.get("apikey_id"):
            key = self.env["res.users.apikeys"].sudo().browse(p["apikey_id"])
            if key.exists():
                return key.mcp_readonly, key.mcp_models
        return False, False

    def _consent_scope_vals(self, kw):
        """Map the Pro consent-form fields (radio pro_scope=full|readonly,
        hidden pro_scope_models csv) to oauth-code columns."""
        vals = super()._consent_scope_vals(kw)
        if "scopes" not in lic.active_features(self.env):
            return vals
        scope = kw.get("pro_scope") or "full"
        vals.update({
            "scope_readonly": scope == "readonly",
            "scope_models": (kw.get("pro_scope_models") or "").strip() or False,
        })
        return vals

    def _check_policy(self, req):
        """First matching mcp.policy rule decides (feature 'policy').
        Model-less tools (whoami, list_models, health) are never policy-
        blocked: rules are about data access, and denying the catalog
        would only blind the LLM. read_resource/print_report LOOK
        model-less (no `model` argument) but are not — _derive_blob_model
        resolves their target model upfront; when it truly can't be
        resolved they still fall under default-deny below rather than
        skipping like a genuinely model-less tool ([B1])."""
        if "policy" not in req.features:
            return
        default_deny = self.env["ir.config_parameter"].sudo().get_param(
            "cledoo_mcp_full.policy_default_deny") == "True"
        if not req.model:
            if default_deny and req.tool in BLOB_MODEL_LESS_TOOLS:
                raise ToolAccessError(
                    "Denied by policy: could not determine the target "
                    "model for %s (default-deny is on)." % req.tool)
            return
        rules = self.env["mcp.policy"].sudo().search([("active", "=", True)])
        matched = None
        for rule in rules:
            if rule._match(req):
                matched = rule
                break
        if matched is None:
            if default_deny:
                raise ToolAccessError(
                    "Denied by policy: no rule allows %s on %s "
                    "(default-deny is on)." % (req.operation, req.model))
            return
        would_deny = None
        if matched.verdict == "deny":
            would_deny = matched
        elif matched.verdict == "approval" and req.operation != "read":
            # A matched approval rule neither allows nor denies; it
            # pauses the write for a human. Reads matched by an approval
            # rule pass through — approval is a write gate.
            if matched.mode == "dry_run":
                # Early return skips this rule's fields_deny strip on
                # purpose: in dry-run the rule must observably change
                # NOTHING — enforcing its field strips would already be
                # enforcement.
                req.would_deny_rule_id = matched.id
                return
            req.approval_rule_id = matched.id
        elif matched.verdict == "allow":
            denied = matched._denied_fields()
            if denied:
                if req.operation == "read":
                    req.strip_fields |= denied
                else:
                    touched = _touched_fields(req.args.get("values") or {})
                    hit = denied & touched
                    if hit:
                        would_deny = matched
        if would_deny is not None:
            if would_deny.mode == "dry_run":
                req.would_deny_rule_id = would_deny.id
                return
            req.rule_id = would_deny.id
            raise ToolAccessError(
                'Denied by policy rule "%s".' % would_deny.name)
        if req.blob_field and req.blob_field in req.strip_fields:
            # A binary field pulled through read_resource has no result
            # dict for the field-strip to reach into (it comes back as
            # __mcp_content__ raw bytes, masking/strips are sentinel-
            # skipped) — a field-denied blob must be refused pre-
            # execution instead of leaking through the blob ([B1]).
            req.rule_id = matched.id
            raise ToolAccessError(
                'Denied by policy: field "%s" is blocked on %s and '
                "cannot be redacted from a binary read."
                % (req.blob_field, req.model))
        req.rule_id = matched.id if matched.verdict != "allow" else None

    def _gate_approval(self, req):
        """Open a ticket for approval-gated writes (feature 'approvals').
        Returns the pending-ticket result dict, or None to continue the
        pipeline. Skipped when this call IS an approved-ticket execution."""
        if "approvals" not in req.features or not req.approval_rule_id:
            return None
        if self.env.context.get("mcp_pro_approved_ticket"):
            return None
        rule = self.env["mcp.policy"].sudo().browse(req.approval_rule_id)
        ticket = self.env["mcp.approval"]._open_ticket(req, rule)
        req.pending_id = ticket.id
        return {
            "pending": True, "ticket_id": ticket.id,
            "expires_at": str(ticket.expires_at),
            "message": "This write requires human approval. A ticket was "
                       "sent to the approvers. Poll check_approval with "
                       "ticket_id=%d; when approved, the original call "
                       "executes exactly as proposed." % ticket.id,
        }

    def _check_quota(self, req):
        """Daily budgets (feature 'quotas'), counted from today's audit
        rows for this principal. Denials don't consume budget (outcome
        filter keeps ok/pending/error rows only — a blocked client
        retrying must not dig itself deeper)."""
        if "quotas" not in req.features:
            return
        quotas = self.env["mcp.quota"]._for_principal(req.principal_key)
        if not quotas:
            return
        Audit = self.env["mcp.audit.log"].sudo()
        base_domain = [
            ("principal_key", "=", req.principal_key),
            ("create_date", ">=", fields.Date.today().strftime(
                "%Y-%m-%d 00:00:00")),
            ("outcome", "in", ("ok", "pending", "error")),
        ]
        calls_today = Audit.search_count(base_domain)
        writes_today = Audit.search_count(
            base_domain + [("operation", "in", ("write", "unlink"))])
        for quota in quotas:
            if quota.daily_calls and calls_today >= quota.daily_calls:
                raise ToolAccessError(
                    'Daily MCP quota "%s" reached (%d calls). Resets at '
                    'midnight UTC.' % (quota.name, quota.daily_calls))
            if (quota.daily_writes and req.operation != "read"
                    and writes_today >= quota.daily_writes):
                raise ToolAccessError(
                    'Daily MCP write quota "%s" reached (%d writes). '
                    'Resets at midnight UTC.' % (quota.name,
                                                 quota.daily_writes))

    def _mask(self, req, result):
        result = self._apply_strips(req, result)
        result = self._apply_masks(req, result)
        return result

    def _apply_masks(self, req, result):
        """PII masking, RESULT side (feature 'masking'), post-execute /
        pre-audit: the audit log must never store an unmasked value.
        Sentinel-safe like _apply_strips. Reuses the Task 8 tree-walker
        (_walk_tree) rather than a second recursive walker."""
        if "masking" not in req.features or not req.model:
            return result
        if isinstance(result, dict) and "__mcp_content__" in result:
            return result
        from odoo.addons.cledoo_mcp_full.models.mask_rule import _mask_value
        masked = self.env["mcp.mask.rule"]._masked_fields(req.model)
        if not masked:
            return result
        return self._walk_tree(
            result, lambda k, v: (True, _mask_value(v, masked[k])
                                  if k in masked else v))

    def _sanitize_strips(self, req):
        """Policy field-strip, REQUEST side (runs just before dispatch).
        The result-side key-strip only reaches dict keys, so any request
        shape that can carry a denied field's data (or act as an oracle
        on it) must be handled here, fail closed:

        - blob payloads (export_records CSV/XLSX): denied fields are
          removed from the explicit `fields` list before the tool runs;
          if nothing remains, or a blob tool has no `fields` list to
          sanitize, the call is denied;
        - aggregation (aggregate_records): result keys are the SPEC
          strings ("phone:max" != "phone"), so the result-strip never
          matches, and max/min on a char field returns exact values —
          any `groupby`/`aggregates` spec whose base field path touches
          a denied field (dotted paths included) denies the call.
          Denying rather than trimming is deliberate: silently dropping
          an aggregate would change analytics semantics;
        - `domain`/`order` oracle: domain=[["phone","like","+3312%"]]
          reconstructs a denied value character by character — any
          domain triplet or order term referencing a denied field path
          denies the call.

        The result-side strip stays on as defense in depth."""
        if not req.strip_fields:
            return
        for arg in ("groupby", "aggregates"):
            specs = req.args.get(arg)
            if isinstance(specs, (list, tuple)):
                for spec in specs:
                    self._deny_if_path_stripped(
                        req, str(spec).split(":")[0], arg)
        self._check_domain_oracle(req, req.args.get("domain"))
        order = req.args.get("order")
        if isinstance(order, str):
            for part in order.split(","):
                token = part.strip().split(" ")[0].split(":")[0]
                if token:
                    self._deny_if_path_stripped(req, token, "order")
        fields_arg = req.args.get("fields")
        if isinstance(fields_arg, list):
            kept = [f for f in fields_arg
                    if not isinstance(f, str) or f not in req.strip_fields]
            if kept != fields_arg:
                if not kept:
                    raise ToolAccessError(
                        "Denied by policy: every requested field on %s "
                        "is blocked." % req.model)
                # req.args aliases the dict handed to _pro_dispatch, so
                # the executed tool sees the sanitized list.
                req.args["fields"] = kept
        elif req.tool in BLOB_TOOLS:
            raise ToolAccessError(
                "Denied by policy: %s inlines field data in its payload "
                "and there is no fields list to sanitize." % req.tool)

    def _check_domain_oracle(self, req, domain):
        """Walk a domain (list of triplets, possibly with prefix
        operators "&"/"|"/"!") and deny on any denied-field reference,
        recursing into nested sub-domains carried by "any"/"not any"
        triplets (e.g. [["child_ids", "any", [["phone", "like",
        "..."]]]]) — otherwise the sub-domain evades the check entirely
        while still oracle-probing the denied field."""
        if not isinstance(domain, (list, tuple)):
            return
        for term in domain:
            # skip prefix operators "&" "|" "!"
            if not (isinstance(term, (list, tuple)) and term
                    and isinstance(term[0], str)):
                continue
            self._deny_if_path_stripped(req, term[0], "domain")
            if len(term) >= 3 and isinstance(term[2], (list, tuple)):
                self._check_domain_oracle(req, term[2])

    def _deny_if_path_stripped(self, req, path, where):
        """Deny when any component of a (possibly dotted) field path is
        a policy-denied field: "phone", "parent_id.phone"..."""
        if any(part in req.strip_fields for part in path.split(".")):
            raise ToolAccessError(
                "Denied by policy: %s references a blocked field on %s."
                % (where, req.model))

    def _apply_strips(self, req, result):
        """Remove policy-denied fields from read results. Sentinel-safe:
        binary content blocks pass through untouched."""
        if not req.strip_fields:
            return result
        if isinstance(result, dict) and "__mcp_content__" in result:
            return result
        return self._walk_tree(
            result, lambda k, v: (k not in req.strip_fields, v))

    def _walk_tree(self, node, visit):
        """Generic dict/list recursive-descent walker, reused by Task
        10's `_apply_masks`. `visit(key, value) -> (keep, new_value)` is
        called for every dict entry: `keep=False` drops the key
        (field-strip use), `keep=True` with a transformed `new_value`
        rewrites it in place (masking use). Lists are walked
        element-wise; scalars pass through untouched."""
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                keep, v = visit(k, v)
                if keep:
                    out[k] = self._walk_tree(v, visit)
            return out
        if isinstance(node, list):
            return [self._walk_tree(v, visit) for v in node]
        return node

    # -- audit -------------------------------------------------------------

    def _audit(self, req):
        """Bookkeeping: never raises, own savepoint. Runs when any
        audit-consuming feature is licensed (quotas count and analytics
        aggregate over these rows).

        Same savepoint + catch-all contract as base `_track()`: the row
        rides the same cursor/transaction as the tool call it describes,
        so it is committed together with the request once this method
        returns (or rolled back if something later in the SAME request
        rolls the whole transaction back). It deliberately runs OUTSIDE
        the tool's own write-protecting savepoint (base
        `mcp.gateway._execute_tool`, models/gateway.py in cledoo_mcp_full) —
        that savepoint only wraps the actual tool call, not this
        pipeline's governance/bookkeeping stages — so a denied or failed
        call still gets audited even though the tool's own half-applied
        writes were discarded. This method's own nested savepoint exists
        only so an unexpected DB error while writing the audit row can't
        abort the caller's transaction; a plain unprotected `create()`
        here would risk exactly that."""
        if not req.features & {"audit", "quotas", "analytics"}:
            return
        try:
            with self.env.cr.savepoint():
                args = req.args if isinstance(req.args, dict) else {}
                res_ids = args.get("record_id") or args.get("ids") or ""
                if isinstance(res_ids, list):
                    res_ids = ",".join(str(i) for i in res_ids)
                arg_fields = sorted(args)
                fields_arg = args.get("fields")
                if isinstance(fields_arg, list):
                    arg_fields += ["fields:%s" % f for f in fields_arg]
                p = req.principal
                self.env["mcp.audit.log"].sudo().create({
                    "principal_key": req.principal_key,
                    "kind": p.get("kind"),
                    "token_id": p.get("token_id") or 0,
                    "apikey_id": p.get("apikey_id") or 0,
                    "user_id": req.uid,
                    "tool": req.tool,
                    "model": req.model,
                    "operation": req.operation or "read",
                    "res_ids": str(res_ids),
                    "arg_fields": json.dumps(arg_fields)[:2000],
                    "duration_ms": req.duration_ms,
                    "outcome": req.outcome,
                    "code": req.code,
                    "policy_rule_id": req.rule_id,
                    "would_deny_rule_id": req.would_deny_rule_id,
                    "session_id": req.context.get("session_id"),
                    "remote_addr": req.context.get("remote_addr"),
                })
        except Exception:
            _logger.exception("mcp pro audit write failed (ignored)")


# -- Task 11: check_approval pro tool ---------------------------------------

def _with_app_meta(gw, payload, uri):
    """Stamp a tool result with the MCP Apps `_meta.ui.resourceUri`
    (feature 'apps'): clients that support MCP Apps render the ui://
    document referenced here in-chat; others ignore `_meta` and show the
    plain text/JSON content — strictly progressive."""
    if "apps" in lic.active_features(gw.env):
        payload["__mcp_meta__"] = {"ui": {"resourceUri": uri}}
    return payload


def _tool_check_approval(gw, req):
    """Check an approval ticket. If approved and not yet executed, run
    the stored, hash-bound call and return its result. Tickets are only
    visible to the principal that opened them."""
    from odoo.addons.cledoo_mcp_full.lib.tools import (
        ToolAccessError as _Denied, ToolUserError as _UserErr)
    from odoo.addons.cledoo_mcp_full.models.approval import content_hash
    ticket_id = req.args.get("ticket_id")
    try:
        ticket_id = int(ticket_id)
    except (TypeError, ValueError):
        raise _UserErr("ticket_id must be an integer")
    ticket = gw.env["mcp.approval"].sudo().browse(ticket_id)
    if not ticket.exists() or ticket.principal_key != req.principal_key:
        raise _UserErr("Unknown ticket %s" % ticket_id)
    ticket._expire_if_due()
    if ticket.state == "approved" and not ticket.executed:
        import json as _json
        args = _json.loads(ticket.args_json)
        if content_hash(args) != ticket.content_hash:
            raise _Denied("Ticket content mismatch: the stored call was "
                          "modified after approval. Ask for a new ticket.")
        # Atomic claim (see McpApproval._claim_execution): closes the
        # race where two concurrent polls both see executed=False and
        # both try to dispatch the same approved write.
        if not ticket._claim_execution():
            return {"ticket_id": ticket.id, "state": ticket.state}
        # A failed execution must NOT burn the ticket: the claim above
        # rides the main cursor and would be committed together with the
        # JSON-RPC error response (executed=true persisted, the write
        # itself rolled back by the tool-call savepoint, every retry
        # answering {"state": "approved"} with nothing done — the
        # human-approved action silently lost). Un-claim on ANY failure
        # and re-raise so the ticket stays claimable/retryable.
        # Exclusivity is preserved: the claim's row UPDATE keeps the row
        # locked for the rest of this transaction, so a concurrent
        # poller's claim blocks until we commit — nobody else can run
        # the ticket while this execution is in flight.
        try:
            result = gw.with_context(mcp_pro_approved_ticket=ticket.id) \
                ._execute_tool(req.uid, ticket.tool_name, args,
                               context=req.context)
        except Exception:
            ticket._unclaim_execution()
            raise
        return _with_app_meta(gw, {"ticket_id": ticket.id, "state": "approved",
                                   "result": result}, "ui://cledoo/approval-card")
    return _with_app_meta(gw, {"ticket_id": ticket.id, "state": ticket.state},
                          "ui://cledoo/approval-card")


PRO_TOOLS["check_approval"] = (
    _tool_check_approval,
    {"type": "object",
     "properties": {"ticket_id": {"type": "integer",
                                  "description": "Ticket id returned by a "
                                                 "gated write."}},
     "required": ["ticket_id"]},
    # readOnlyHint stays False: this is the MCP wire annotation clients
    # use for trust UI (e.g. auto-invoking a tool without a confirmation
    # prompt), and check_approval CAN land an approved write (the nested
    # replay below) — the annotation must stay honest about that, even
    # though it also needs to stay reachable under the readonly
    # kill-switch (see the by-name carve-out in _check_readonly/
    # _list_tools instead of flipping this hint).
    {"title": "Check approval ticket", "readOnlyHint": False,
     "destructiveHint": False, "idempotentHint": False,
     "openWorldHint": False},
)


# -- Task T1: mcp_analytics pro tool -----------------------------------------

ANALYTICS_DEFAULT_DAYS = 30
ANALYTICS_MAX_DAYS = 365


def _tool_mcp_analytics(gw, req):
    """Get a snapshot of recent MCP/AI activity on this Odoo instance:
    total calls, allowed vs denied, behavior alerts, the busiest tools
    and the number of distinct AI connections (principals) active in
    the window. Call this when the user asks to see how AI agents have
    been using this system, wants a health check of MCP usage, or asks
    something like "show me AI activity" / "what has the AI been
    doing" — in clients that support MCP Apps the result renders as a
    dashboard card, not just numbers in text. Optional `days` (default
    30, capped at 365) sets the lookback window."""
    days = req.args.get("days")
    try:
        days = int(days) if days is not None else ANALYTICS_DEFAULT_DAYS
    except (TypeError, ValueError):
        days = ANALYTICS_DEFAULT_DAYS
    days = max(1, min(days, ANALYTICS_MAX_DAYS))
    Audit = gw.env["mcp.audit.log"].sudo()
    cutoff = fields.Datetime.now() - timedelta(days=days)
    domain = [("create_date", ">=", cutoff)]
    total = Audit.search_count(domain)
    denied = Audit.search_count(domain + [("outcome", "=", "denied")])
    alerts = gw.env["mcp.behavior.alert"].sudo().search_count(
        [("create_date", ">=", cutoff)])
    per_day = [
        {"date": str(day), "calls": count}
        for day, count in Audit._read_group(
            domain, groupby=["create_date:day"], aggregates=["__count"])
    ]
    top_tools = [
        {"tool": tool, "calls": count}
        for tool, count in Audit._read_group(
            domain, groupby=["tool"], aggregates=["__count"],
            order="__count desc")[:5]
    ]
    principals = len(Audit._read_group(domain, groupby=["principal_key"]))
    return _with_app_meta(gw, {
        "days": days,
        "total": total,
        "denied": denied,
        "allowed": total - denied,
        "alerts": alerts,
        "active_principals": principals,
        "top_tools": top_tools,
        "per_day": per_day,
    }, "ui://cledoo/analytics-snapshot")


PRO_TOOLS["mcp_analytics"] = (
    _tool_mcp_analytics,
    {"type": "object",
     "properties": {"days": {
         "type": "integer",
         "description": "Lookback window in days (default 30, capped at "
                        "365)."}},
     "required": []},
    {"title": "MCP analytics snapshot", "readOnlyHint": True,
     "destructiveHint": False, "idempotentHint": True,
     "openWorldHint": False},
)
