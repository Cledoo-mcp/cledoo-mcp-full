# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Direct-ORM MCP tools. Security = Odoo ACLs, record rules and field
groups=, enforced by with_user(uid). No policy, no masking, no audit —
that is the MCP Pro product. Guardrails here are about transport hygiene
only: search limit clamp, binary/html exclusion by default (token cost),
company scoping (mirror the UI with all allowed companies enabled).

Docstrings double as the MCP tool descriptions sent to the LLM (the
gateway serializes the full docstring, whitespace-collapsed) — write
them as instructions to the model, not as code comments."""
import base64
import csv
import datetime
import difflib
import io
import json
import logging

from odoo import models
from odoo.exceptions import AccessError, MissingError, UserError, ValidationError
from odoo.tools.mimetypes import guess_mimetype

from odoo.addons.cledoo_mcp_full.lib.sanitize import sanitize_error_message

_logger = logging.getLogger(__name__)
MAX_LIMIT = 500
# Field types excluded from default projections: binaries blow up the
# response (base64 images), html is noisy markup, x2many drag unbounded
# id lists. All remain available by naming them in `fields`.
_HEAVY_TYPES = ("binary", "html", "one2many", "many2many")
_SELECTION_CAP = 20
_HELP_CAP = 100


class ToolError(Exception):
    code = "server_error"

    def __init__(self, message, meta=None):
        self.message = sanitize_error_message(message)
        # Optional MCP result `_meta` (e.g. an MCP Apps ui:// hint) to
        # surface alongside the isError result. None by default so the
        # free-tier wire (no meta) is unchanged; Pro stamps it on select
        # denial paths — see _tool_error_result in controllers/mcp.py.
        self.meta = meta
        super().__init__(self.message)


class ToolAccessError(ToolError):
    code = "access_denied"


class ToolUserError(ToolError):
    code = "validation_error"


class ToolInvalidParamsError(ToolError):
    """Arguments don't match the tool's signature/schema. Surfaces as an
    isError: true tool result with code "invalid_params" (SEP-1303), not
    a JSON-RPC protocol error."""
    code = "invalid_params"


def _user(env, uid):
    return env["res.users"].sudo().browse(uid)


def _model(env, uid, model, company_id=None):
    if model not in env:
        raise ToolUserError("Unknown model: %s" % model)
    user = _user(env, uid)
    # Mirror the UI with every allowed company enabled: with_user() alone
    # would scope company record rules to the main company only, silently
    # hiding data the user can see in the web client.
    cids = user.company_ids.ids or [user.company_id.id]
    if company_id is not None:
        company_id = _int(company_id, "company_id")
        if company_id not in cids:
            raise ToolInvalidParamsError(
                "company_id %s is not one of your allowed companies (use the"
                " whoami tool to list them)" % company_id)
        cids = [company_id]
    return env[model].with_user(uid).with_context(allowed_company_ids=cids)


def _run(fn):
    """Translate raw ORM exceptions; let programming errors propagate."""
    def wrapper(env, uid, **kwargs):
        try:
            return fn(env, uid, **kwargs)
        except AccessError as exc:
            raise ToolAccessError(str(exc)) from exc
        except (ValidationError, UserError, MissingError) as exc:
            raise ToolUserError(str(exc)) from exc
        except TypeError as exc:
            # The advertised inputSchema is not enforced upstream; an
            # unexpected/missing keyword lands here, not in the tool body.
            raise ToolInvalidParamsError(str(exc)) from exc
        except ValueError as exc:
            # The ORM reports malformed user input as ValueError (bad
            # domain operator, invalid selection value, unparsable date…).
            # Field-name mistakes are caught with a better message by the
            # _validate_* helpers before the ORM runs; this net turns the
            # remainder into an actionable client error instead of an
            # opaque -32603 "Internal error". KeyError deliberately stays
            # out: an in-tool KeyError is a programming bug and must keep
            # propagating (see test_gateway).
            raise ToolUserError(str(exc)) from exc
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


def _int(value, name):
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ToolInvalidParamsError("%s must be an integer" % name) from None


def _dict(value, name):
    if not isinstance(value, dict):
        raise ToolInvalidParamsError("%s must be an object" % name)
    return value


def _can(records, operation):
    # Odoo 19 removed check_access_rights in favor of check_access/has_access.
    if hasattr(records, "has_access"):
        return records.has_access(operation)
    return records.check_access_rights(operation, raise_exception=False)


def _unknown_field(model_rec, name, where):
    """A wrong field name is the #1 user error on these tools (e.g.
    'model' instead of 'res_model' on ir.attachment); without this it
    surfaced as a generic Internal error. Name the field, suggest close
    matches, point to get_model_fields."""
    msg = "Unknown field '%s' on %s (in %s)." % (name, model_rec._name, where)
    suggestions = difflib.get_close_matches(
        name, list(model_rec._fields), n=3, cutoff=0.6)
    if suggestions:
        msg += " Did you mean: %s?" % ", ".join(suggestions)
    msg += " Use get_model_fields('%s') to list valid fields." % model_rec._name
    return ToolInvalidParamsError(msg)


def _validate_field_path(m, path, where):
    """Validate 'field' or 'relation.field' paths against the model chain."""
    model = m
    parts = str(path).split(".")
    for i, part in enumerate(parts):
        field = model._fields.get(part)
        if field is None:
            raise _unknown_field(model, part, where)
        if i < len(parts) - 1:
            if not getattr(field, "comodel_name", None):
                # deep path into a non-relational field (json/properties
                # style) — beyond static validation, let the ORM decide
                return
            model = model.env[field.comodel_name]


def _validate_domain(m, domain):
    if not domain:
        return
    if not isinstance(domain, (list, tuple)):
        raise ToolInvalidParamsError(
            "domain must be a list like [[\"field\", \"=\", value], ...]")
    for term in domain:
        if isinstance(term, str):  # '&' / '|' / '!' prefix operators
            continue
        if not isinstance(term, (list, tuple)) or len(term) != 3:
            raise ToolInvalidParamsError(
                "Invalid domain term %r: expected [field, operator, value]"
                % (term,))
        left = term[0]
        # (1, '=', 1) truthy leaves are legal; only validate string paths
        if isinstance(left, str):
            _validate_field_path(m, left, "domain")


def _validate_fields_arg(m, fields):
    for name in fields or []:
        if isinstance(name, str):
            _validate_field_path(m, name, "fields")


def _validate_values(m, values):
    for name in values:
        if name not in m._fields:
            raise _unknown_field(m, name, "values")


def _validate_order(m, order):
    if not order:
        return
    for part in str(order).split(","):
        name = part.strip().split(" ")[0]
        if name:
            _validate_field_path(m, name, "order")


def _default_fields(m):
    """Stored fields minus token-heavy types — the safe default projection."""
    return [n for n, f in m._fields.items()
            if f.store and f.type not in _HEAVY_TYPES]


def _mask_binaries(m, rows, requested):
    """Explicitly-requested binary fields come back as a size placeholder,
    never inline base64 (a single product image is ~100k tokens)."""
    bins = [n for n in (requested or [])
            if n in m._fields and m._fields[n].type == "binary"]
    for row in rows:
        for n in bins:
            val = row.get(n)
            if val:
                row[n] = {"__binary__": True,
                          "size_bytes": len(val) * 3 // 4}


@_run
def whoami(env, uid):
    """Who is connected: name, login, language, timezone, current and
    allowed companies. Call this once at the start of a session so you can
    address the user in their language, use their timezone for dates, and
    pass the right company_id to other tools on multi-company databases."""
    user = _user(env, uid)
    return {
        "name": user.name,
        "login": user.login,
        "lang": user.lang,
        "tz": user.tz or "UTC",
        "company": {"id": user.company_id.id, "name": user.company_id.name},
        "allowed_companies": [
            {"id": c.id, "name": c.name} for c in user.company_ids],
        "is_admin": user._is_admin(),
    }


@_run
def list_models(env, uid, pattern=None, all=False):
    """List available models. By default returns a small curated catalog of
    common business models, each with a hint of what it stores — start
    there. Use pattern='sale' to search everything the user can read, or
    all=true for the complete list (can be very long)."""
    domain = [("transient", "=", False)]
    if pattern:
        domain += ["|", ("model", "ilike", pattern), ("name", "ilike", pattern)]
    # One ACL query instead of a has_access() probe per ir.model row
    # (thousands of checks per call on a mid-size DB). Model-level read
    # is exactly what ir.model.access encodes; record rules don't apply
    # to model listing.
    user = _user(env, uid)
    if not user._is_superuser():
        # Odoo 19 renamed groups_id -> group_ids and moved the implied-group
        # closure to all_group_ids; 18 stores the closure in groups_id.
        groups = (user.all_group_ids if "all_group_ids" in user._fields
                  else user.groups_id)
        rows = env["ir.model.access"].sudo().search_read(
            ["&", ("perm_read", "=", True),
             "|", ("group_id", "=", False),
             ("group_id", "in", groups.ids)],
            ["model_id"])
        domain.append(("id", "in", [r["model_id"][0] for r in rows]))
    out = [{"model": im.model, "name": im.name}
           for im in env["ir.model"].sudo().search(domain, order="model")
           if im.model in env]
    if not pattern and not all:
        profiles = env["mcp.model.profile"].sudo().search(
            [("featured", "=", True)])
        featured_meta = {p.model_name: (p.sequence, p.llm_hint or "")
                         for p in profiles}
        featured = sorted(
            (dict(o, hint=featured_meta[o["model"]][1])
             for o in out if o["model"] in featured_meta),
            key=lambda o: featured_meta[o["model"]][0])
        if featured:
            return {
                "models": featured, "total": len(featured),
                "featured_only": True,
                "hint": "Curated catalog only. Use pattern='...' to search"
                        " all %d readable models, or all=true to list"
                        " everything." % len(out),
            }
    return {"models": out, "total": len(out)}


def _check_read(m, model):
    if not _can(m, "read"):
        raise ToolAccessError("You are not allowed to access model %s" % model)


@_run
def get_model_fields(env, uid, model, fields=None, verbose=False,
                     pattern=None):
    """Field metadata for a model — call before building search domains or
    create/update payloads. Big models (account.move has ~200 fields) are
    expensive to read in full: pass pattern='invoice' to keep only fields
    whose name or label contains it (total_fields tells you what you
    filtered out). Compact by default (type, label, relation, required,
    selection values); pass verbose=true only if you need full metadata
    (defaults, domains, selection labels)."""
    m = _model(env, uid, model)
    # fields_get() itself performs no model-level ACL check: without this
    # gate any authenticated key could introspect the schema of models the
    # user cannot read.
    _check_read(m, model)
    meta = m.fields_get(fields)
    total = len(meta)
    if pattern:
        pat = str(pattern).lower()
        meta = {n: f for n, f in meta.items()
                if pat in n.lower()
                or pat in (f.get("string") or "").lower()}
    if verbose:
        return {"model": model, "fields": meta, "total_fields": total}
    compact = {}
    for name, f in meta.items():
        entry = {"type": f["type"], "string": f.get("string")}
        if f.get("relation"):
            entry["relation"] = f["relation"]
        if f.get("required"):
            entry["required"] = True
        if f.get("readonly"):
            entry["readonly"] = True
        if not f.get("store", True):
            entry["computed"] = True
        sel = f.get("selection")
        if sel:
            entry["selection"] = [s[0] for s in sel[:_SELECTION_CAP]]
            if len(sel) > _SELECTION_CAP:
                entry["selection_truncated"] = len(sel)
        help_txt = f.get("help")
        if help_txt:
            entry["help"] = help_txt[:_HELP_CAP]
        compact[name] = entry
    return {"model": model, "fields": compact, "compact": True,
            "total_fields": total,
            "hint": "verbose=true returns full metadata; pattern='...'"
                    " filters by field name/label"}


@_run
def search_records(env, uid, model, domain=None, fields=None, limit=80,
                   offset=0, order=None, company_id=None):
    """Search and read records under the user's ACLs. ALWAYS pass
    fields=[...] with only the fields you need — the default projection
    skips binary/html/x2many fields but can still be wide. Filter with an
    Odoo domain like [["customer_rank",">",0]]; paginate with limit/offset
    (the response tells you has_more/next_offset); call count_records first
    when the result set could be large. On multi-company databases pass
    company_id to scope to one company."""
    limit = max(1, min(_int(limit or 80, "limit"), MAX_LIMIT))
    offset = max(0, _int(offset or 0, "offset"))
    m = _model(env, uid, model, company_id)
    _validate_domain(m, domain)
    _validate_fields_arg(m, fields)
    _validate_order(m, order)
    projection = fields or _default_fields(m)
    # limit+1 probe: tells the model whether to paginate without a second
    # count query on every call.
    recs = m.search_read(domain or [], projection,
                         offset=offset, limit=limit + 1, order=order)
    has_more = len(recs) > limit
    recs = recs[:limit]
    _mask_binaries(m, recs, fields)
    out = {"model": model, "records": recs, "limit": limit,
           "offset": offset, "has_more": has_more}
    if has_more:
        out["next_offset"] = offset + limit
    return out


@_run
def get_record(env, uid, model, record_id, fields=None, company_id=None):
    """Read one record by id. Pass fields=[...] to keep the response small;
    the default projection skips binary/html/x2many fields. Binary fields
    are never inlined — they come back as a size placeholder."""
    m = _model(env, uid, model, company_id)
    _validate_fields_arg(m, fields)
    projection = fields or _default_fields(m)
    rows = m.browse(_int(record_id, "record_id")).read(projection)
    if not rows:
        raise ToolUserError("Record %s/%s not found" % (model, record_id))
    _mask_binaries(m, rows, fields)
    return {"model": model, "record": rows[0],
            "url": _record_url(env, model, rows[0]["id"])}


@_run
def count_records(env, uid, model, domain=None, company_id=None):
    """Count records matching a domain — cheap; use it before a broad
    search_records to decide how to paginate."""
    m = _model(env, uid, model, company_id)
    _validate_domain(m, domain)
    return {"model": model, "count": m.search_count(domain or [])}


@_run
def describe_access(env, uid, model):
    """The user's effective rights on a model (read/write/create/unlink,
    ACL truth). Use it before attempting writes to avoid failed calls."""
    m = _model(env, uid, model)
    return {"model": model,
            "company_ids": m.env.context.get("allowed_company_ids") or [],
            **{op: bool(_can(m, op)) for op in ("read", "write", "create", "unlink")}}


_AGG_FUNCS = ("sum", "avg", "min", "max", "count", "count_distinct")


def _agg_value(value):
    """JSON-shape a _read_group cell: recordset -> {id, display_name};
    dates/datetimes pass through (the transport serializes with str)."""
    if isinstance(value, models.BaseModel):
        return ({"id": value.id, "display_name": value.display_name}
                if value else None)
    return value


@_run
def aggregate_records(env, uid, model, groupby, aggregates=None, domain=None,
                      limit=None, offset=0, order=None, company_id=None):
    """Grouped aggregation (SQL GROUP BY) — use this for stats and
    dashboards ("revenue by month", "top customers by orders") instead of
    pulling raw rows. groupby is a list like ["state"] or
    ["date_order:month"] (date granularities: :year :quarter :month :week
    :day). aggregates entries are "field:func" like ["amount_total:sum",
    "partner_id:count_distinct"] (functions: sum, avg, min, max, count,
    count_distinct); the per-group row count __count is always included.
    Optionally filter with domain and sort with order (e.g.
    "amount_total:sum desc")."""
    if not groupby:
        raise ToolInvalidParamsError("groupby is required")
    if not isinstance(groupby, (list, tuple)):
        groupby = [groupby]
    m = _model(env, uid, model, company_id)
    _validate_domain(m, domain)
    for spec in groupby:
        _validate_field_path(m, str(spec).split(":")[0], "groupby")
    aggregates = [str(a) for a in (aggregates or [])]
    for spec in aggregates:
        field, sep, func = spec.rpartition(":")
        if not sep or func not in _AGG_FUNCS:
            raise ToolInvalidParamsError(
                "Invalid aggregate %r: expected 'field:func' with func one"
                " of %s" % (spec, ", ".join(_AGG_FUNCS)))
        _validate_field_path(m, field, "aggregates")
    specs = aggregates + ["__count"]
    limit = min(_int(limit, "limit"), MAX_LIMIT) if limit is not None else None
    offset = max(0, _int(offset or 0, "offset"))
    # _read_group: same signature and semantics on Odoo 18 and 19 (the
    # formatted variant only exists on 19), returns one tuple per group
    # ordered [groupby values..., aggregate values...].
    rows = m._read_group(domain or [], groupby=list(groupby),
                         aggregates=specs, offset=offset, limit=limit,
                         order=order or None)
    keys = list(groupby) + specs
    groups = [{k: _agg_value(v) for k, v in zip(keys, row)} for row in rows]
    return {"model": model, "groups": groups, "group_count": len(groups)}


@_run
def get_messages(env, uid, model, record_id, limit=20, company_id=None):
    """Read the chatter history of a record (comments, internal notes,
    tracking messages), newest first. Returns author, date, type and body
    (HTML, truncated to 4000 chars). Use it to understand what happened
    on a record before acting on it."""
    rec = _model(env, uid, model, company_id).browse(
        _int(record_id, "record_id"))
    if "message_ids" not in rec._fields:
        raise ToolUserError(
            "Model %s has no chatter (it does not inherit mail.thread)"
            % model)
    if not rec.exists():
        raise ToolUserError("Record %s/%s not found" % (model, record_id))
    limit = max(1, min(_int(limit or 20, "limit"), 100))
    msgs = rec.message_ids[:limit]
    return {"model": model, "id": rec.id, "messages": [
        {"id": m.id, "date": str(m.date),
         "author": m.author_id.display_name or m.email_from or "",
         "type": m.message_type, "subtype": m.subtype_id.name or "",
         "body": str(m.body or "")[:4000]} for m in msgs]}


EXPORT_MAX_ROWS = 10000


def _csv_cell(value):
    if value is None or value is False:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    value = value if isinstance(value, str) else str(value)
    # Spreadsheet apps execute leading =, + and - as formulas.
    if value.startswith(("=", "-", "+")):
        return "'" + value
    return value


@_run
def export_records(env, uid, model, fields, domain=None, ids=None,
                   format="csv", limit=1000, order=None, company_id=None,
                   inline=False):
    """Export records as a CSV or XLSX file and return a temporary
    download link (give it to the user as a clickable link; a sandbox can
    also fetch it with curl). Use it when the user asks for a file,
    spreadsheet or download — not for reading data yourself. Field paths
    use '/' to traverse relations, e.g. 'partner_id/name'. Respects the
    user's access rights. Only pass inline=true if you truly need the
    raw base64 in the conversation — it is slow and floods the context."""
    if not fields:
        raise ToolInvalidParamsError("fields is required")
    if format not in ("csv", "xlsx"):
        raise ToolInvalidParamsError("format must be 'csv' or 'xlsx'")
    m = _model(env, uid, model, company_id)
    fields = [str(f) for f in fields]
    for f in fields:
        _validate_field_path(m, f.replace("/", "."), "fields")
    if ids:
        recs = m.browse([_int(i, "id") for i in ids]).exists()
    else:
        _validate_domain(m, domain)
        _validate_order(m, order)
        limit = max(1, min(_int(limit or 1000, "limit"), EXPORT_MAX_ROWS))
        recs = m.search(domain or [], limit=limit, order=order or None)
    rows = recs.export_data(fields).get("datas") or []
    if format == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf, quoting=csv.QUOTE_ALL)
        writer.writerow(fields)
        for row in rows:
            writer.writerow([_csv_cell(c) for c in row])
        content = buf.getvalue().encode("utf-8-sig")
        mimetype = "text/csv"
    else:
        try:
            import xlsxwriter
        except ImportError:
            raise ToolUserError(
                "XLSX export needs the 'xlsxwriter' Python package on the"
                " server; use format='csv' instead") from None
        out = io.BytesIO()
        workbook = xlsxwriter.Workbook(out, {"in_memory": True})
        sheet = workbook.add_worksheet()
        bold = workbook.add_format({"bold": True})
        for col, header in enumerate(fields):
            sheet.write(0, col, header, bold)
        for r, row in enumerate(rows, start=1):
            for c, cell in enumerate(row):
                if isinstance(cell, (datetime.date, datetime.datetime)):
                    cell = str(cell)
                elif isinstance(cell, bytes):
                    cell = cell.decode(errors="replace")
                sheet.write(r, c, "" if cell is False or cell is None else cell)
        workbook.close()
        content = out.getvalue()
        mimetype = ("application/vnd.openxmlformats-officedocument"
                    ".spreadsheetml.sheet")
    payload = _file_payload(
        env, uid, "%s.%s" % (model.replace(".", "_"), format),
        mimetype, content, inline, "Export")
    return {"model": model, "row_count": len(rows), **payload}


@_run
def list_modules(env, uid, pattern=None, installed_only=True, verbose=False):
    """List the Odoo modules on this database. Use pattern='spreadsheet'
    to check one module instead of pulling the whole list — the full
    list is long. Use it to know which apps are available before
    guessing at models — e.g. no 'sale' module means no sale.order.
    installed_only=false also lists installable-but-not-installed
    modules; verbose=true adds version and summary."""
    dom = [("state", "=", "installed")] if installed_only else []
    if pattern:
        dom += ["|", ("name", "ilike", pattern), ("shortdesc", "ilike", pattern)]
    mods = env["ir.module.module"].sudo().search(dom, order="name")
    rows = []
    for mo in mods:
        row = {"name": mo.name, "state": mo.state}
        if verbose:
            row["version"] = mo.installed_version or mo.latest_version
            row["summary"] = mo.shortdesc or ""
        rows.append(row)
    return {"modules": rows, "total": len(rows)}


@_run
def create_record(env, uid, model, values, company_id=None):
    """Create one record (runs under the user's ACLs). Check required
    fields with get_model_fields first. On multi-company databases pass
    company_id to create in a specific allowed company. The response
    already confirms the create (display_name) — no verification
    get_record needed; give the url to the user as a clickable link."""
    # A list would batch-create then crash on rec.id — single record only.
    m = _model(env, uid, model, company_id)
    _validate_values(m, _dict(values, "values"))
    rec = m.create(values)
    return {"model": model, "id": rec.id, "display_name": rec.display_name,
            "url": _record_url(env, model, rec.id)}


@_run
def update_record(env, uid, model, record_id, values, company_id=None):
    """Update one record by id (runs under the user's ACLs). To iterate on
    a record you just created, prefer update_record over
    delete_record+create_record — it keeps the id and the chatter."""
    record_id = _int(record_id, "record_id")
    m = _model(env, uid, model, company_id)
    _validate_values(m, _dict(values, "values"))
    rec = m.browse(record_id)
    rec.write(values)
    return {"model": model, "id": record_id, "updated": True,
            "display_name": rec.display_name,
            "url": _record_url(env, model, record_id)}


@_run
def delete_record(env, uid, model, record_id, company_id=None):
    """Permanently delete one record by id (runs under the user's ACLs).
    Irreversible — confirm with the user before deleting anything they did
    not explicitly ask to delete."""
    record_id = _int(record_id, "record_id")
    _model(env, uid, model, company_id).browse(record_id).unlink()
    return {"model": model, "id": record_id, "deleted": True}


@_run
def post_message(env, uid, model, record_id, body, subtype=None,
                 company_id=None):
    """Post a note on a record's chatter to log what you did or leave a
    human-readable trace (body is plain text; HTML is escaped). Default
    is an internal note (mail.mt_note) that does not email anyone; pass
    subtype='mail.mt_comment' to notify the record's followers."""
    if not body or not str(body).strip():
        raise ToolInvalidParamsError("body is required")
    rec = _model(env, uid, model, company_id).browse(
        _int(record_id, "record_id"))
    if not hasattr(rec, "message_post"):
        raise ToolUserError(
            "Model %s has no chatter (it does not inherit mail.thread)"
            % model)
    if not rec.exists():
        raise ToolUserError("Record %s/%s not found" % (model, record_id))
    msg = rec.message_post(body=body, message_type="comment",
                           subtype_xmlid=subtype or "mail.mt_note")
    return {"model": model, "id": rec.id, "message_id": msg.id}


def _resolve_report(env, report_ref):
    """report_ref may be a numeric id, an xmlid (module.name), or a
    report_name. Resolution runs sudo (report DEFINITIONS are metadata);
    rendering runs with_user so record access is enforced."""
    Report = env["ir.actions.report"].sudo()
    ref = str(report_ref)
    if ref.isdigit():
        rep = Report.browse(int(ref)).exists()
        return rep or None
    if "." in ref:
        rec = env.ref(ref, raise_if_not_found=False)
        if rec is not None and rec._name == "ir.actions.report":
            return rec.sudo()
    return Report.search([("report_name", "=", ref)], limit=1) or None


@_run
def print_report(env, uid, report_ref, ids, company_id=None, inline=False):
    """Render an Odoo report (PDF/HTML/text) for one or more record ids
    and return a temporary download link (give it to the user as a
    clickable link; a sandbox can also fetch it with curl). report_ref is
    an xmlid (e.g. 'sale.action_report_saleorder'), a report_name, or the
    numeric id of an ir.actions.report — find them with
    search_records('ir.actions.report', domain=[["model","=","sale.order"]]).
    Use it when the user asks for a printable document (quotation,
    invoice, delivery slip...). Only pass inline=true if you truly need
    the raw base64 in the conversation — it is slow and floods the
    context."""
    id_list = ids if isinstance(ids, list) else [ids]
    target_ids = [_int(i, "id") for i in id_list]
    if not target_ids:
        raise ToolInvalidParamsError("ids is required")
    report = _resolve_report(env, report_ref)
    if report is None:
        raise ToolUserError(
            "Report %r not found. Search ir.actions.report to list the"
            " reports available for a model." % report_ref)
    content, rtype = report.with_user(uid)._render(
        report.report_name, target_ids)
    ext = {"pdf": "pdf", "text": "txt", "html": "html"}.get(rtype, rtype)
    mimetype = {"pdf": "application/pdf", "text": "text/plain",
                "html": "text/html"}.get(rtype, "application/octet-stream")
    if isinstance(content, str):
        content = content.encode()
    payload = _file_payload(
        env, uid, "%s.%s" % ((report.name or "report").replace(" ", "_"), ext),
        mimetype, content, inline, "Report")
    return {"report_type": rtype, **payload}


# Any tool that materializes a whole payload in memory and base64-inlines
# it into the response (read_resource, export_records, print_report) can
# OOM a worker or blow the LLM context on a large record set/file. They
# all gate on one admin-configurable ceiling: the cledoo_mcp_full.max_inline_mb
# system parameter (Settings > MCP Server), default 5 MB.
DEFAULT_MAX_INLINE_MB = 5
RESOURCE_TEXT_MAX_CHARS = 100_000
_TEXTUAL_MIMETYPES = ("application/json", "application/xml")


def _record_url(env, model, rec_id):
    """Clickable back-office URL (Odoo 18/19 /odoo/<model>/<id> scheme).
    Returned by create/get/update so the LLM can hand the user a link
    instead of hunting through ir.actions / ir.ui.menu."""
    base = (env["ir.config_parameter"].sudo()
            .get_param("web.base.url") or "").rstrip("/")
    return "%s/odoo/%s/%d" % (base, model, rec_id)


def _max_inline_bytes(env):
    from odoo.addons.cledoo_mcp_full.lib.params import get_int_param
    mb = get_int_param(env, "cledoo_mcp_full.max_inline_mb", DEFAULT_MAX_INLINE_MB)
    if mb <= 0:  # a 0/negative override would refuse everything; ignore it
        mb = DEFAULT_MAX_INLINE_MB
    return mb * 1024 * 1024


def _reject_if_too_large(env, size, what="Resource"):
    limit = _max_inline_bytes(env)
    if size > limit:
        raise ToolUserError(
            "%s is %.1f MB — over the %d MB inline limit (Settings > MCP"
            " Server > Max inline size). Narrow it (fewer fields/rows, a"
            " tighter domain) or fetch the file out of band instead."
            % (what, size / 1048576.0, limit // (1024 * 1024)))


def _file_payload(env, uid, filename, mimetype, content, inline,
                  what="File"):
    """Package a generated file (report, export) for the tool response.

    Default is a tokenized /web/content download link: inline base64
    forces the LLM to stream the whole payload token by token (a 24 KB
    PDF is ~32k base64 chars — minutes of wall clock in a live session)
    and re-enters the context on every later turn, while a link costs a
    few dozen tokens and the bytes travel out of band (the user clicks
    it, or a client sandbox curls it). inline=true restores the old
    behavior, still gated by the max_inline_mb ceiling.

    The attachment is deliberately created with no res_model: Odoo's
    mail GC treats such records as orphaned uploads and removes them
    after ~1 day, which is exactly the lifetime a download link needs —
    no custom cron. The access token gates the URL; created with_user so
    ownership and audit stay on the calling user."""
    if inline:
        _reject_if_too_large(env, len(content), what)
        return {"filename": filename, "mimetype": mimetype,
                "size_bytes": len(content),
                "content_base64": base64.b64encode(content).decode()}
    att = env["ir.attachment"].with_user(uid).create({
        "name": filename, "type": "binary", "raw": content,
        "mimetype": mimetype,
        "description": "Generated by MCP (temporary download)"})
    token = att.generate_access_token()[0]
    base = env["ir.config_parameter"].sudo().get_param("web.base.url") or ""
    return {"filename": filename, "mimetype": mimetype,
            "size_bytes": len(content),
            "download_url": "%s/web/content/%d?access_token=%s&download=true"
                            % (base, att.id, token),
            "expires": "temporary link, removed after ~1 day"}


def _resource_blocks(uri, data, mimetype):
    """Shape raw bytes into the MCP content block the client renders
    natively: text inline, image/audio as media blocks, anything else as
    an embedded resource blob."""
    if (mimetype.startswith("text/") or mimetype in _TEXTUAL_MIMETYPES):
        text = data.decode("utf-8", errors="replace")
        if len(text) > RESOURCE_TEXT_MAX_CHARS:
            text = (text[:RESOURCE_TEXT_MAX_CHARS]
                    + "\n... [truncated: %d bytes total]" % len(data))
        return [{"type": "text", "text": text}]
    b64 = base64.b64encode(data).decode()
    if mimetype.startswith("image/"):
        return [{"type": "image", "data": b64, "mimeType": mimetype}]
    if mimetype.startswith("audio/"):
        return [{"type": "audio", "data": b64, "mimeType": mimetype}]
    return [{"type": "resource", "resource":
             {"uri": uri, "mimeType": mimetype, "blob": b64}}]


@_run
def read_resource(env, uid, uri, company_id=None):
    """Fetch the actual bytes behind an attachment or a binary field and
    return them as native MCP content (text inline, images/audio as
    media, other files as an embedded resource). Binary fields in other
    tools come back as size placeholders — this is the tool to fetch
    their content. Two uri forms: 'odoo://attachment/<id>' for an
    ir.attachment (find ids with search_records on ir.attachment, e.g.
    domain [["res_model","=","sale.order"],["res_id","=",42]]), and
    'odoo://record/<model>/<id>/<field>' for a binary field on any
    record. Respects the user's access rights. Resources over 5 MB are
    refused; text is truncated at 100k chars."""
    uri = str(uri or "")
    malformed = ToolInvalidParamsError(
        "Malformed uri %r. Accepted forms: odoo://attachment/<id> and"
        " odoo://record/<model>/<id>/<field>" % uri)
    prefix = "odoo://"
    if not uri.startswith(prefix):
        raise malformed
    parts = uri[len(prefix):].split("/")
    if parts[0] == "attachment" and len(parts) == 2:
        if not parts[1].isdigit():
            raise malformed
        # with_user: reading raw/datas triggers ir.attachment's ACL
        # (res_model/res_id access check), unlike a sudo read.
        att = env["ir.attachment"].with_user(uid).browse(
            int(parts[1])).exists()
        if not att:
            raise ToolUserError("Attachment %s not found" % parts[1])
        # Reject on the stored file_size BEFORE reading .raw: att.raw
        # materializes the whole file (filestore/DB) into the worker's
        # memory, so checking size only afterwards lets a huge attachment
        # OOM the worker before we ever refuse it.
        _reject_if_too_large(env, att.file_size or 0)
        data = att.raw or b""
        mimetype = att.mimetype or "application/octet-stream"
        name = att.name or ""
    elif parts[0] == "record" and len(parts) == 4:
        model, rec_id, field_name = parts[1], parts[2], parts[3]
        if not rec_id.isdigit():
            raise malformed
        m = _model(env, uid, model, company_id)
        field = m._fields.get(field_name)
        if field is None:
            raise _unknown_field(m, field_name, "uri")
        if field.type != "binary":
            raise ToolInvalidParamsError(
                "Field %s.%s is of type '%s', not binary; read_resource"
                " only serves binary fields" % (model, field_name, field.type))
        rec = m.browse(int(rec_id))
        rows = rec.read([field_name])
        if not rows:
            raise ToolUserError("Record %s/%s not found" % (model, rec_id))
        value = rows[0][field_name]
        if not value:
            raise ToolUserError(
                "Field %s.%s is empty on record %s" % (model, field_name, rec_id))
        data = base64.b64decode(value)
        mimetype = guess_mimetype(data)
        name = "%s-%s-%s" % (model, rec_id, field_name)
    else:
        raise malformed
    # Authoritative post-load check (file_size can be stale/unset, and the
    # record path has no cheap size field to gate on up front).
    size = len(data)
    _reject_if_too_large(env, size)
    return {"__mcp_content__": _resource_blocks(uri, data, mimetype),
            "uri": uri, "mimetype": mimetype, "size_bytes": size,
            "name": name}


def _obj(props, required):
    return {"type": "object", "properties": props, "required": required}


def _ann(title, read_only=False, destructive=False, idempotent=False):
    """MCP tool annotations (2025-06-18 spec). claude.ai uses these to
    display trust hints and gate confirmations on destructive tools; the
    consent page derives its permission list from them (single source of
    truth — hand-written permission copy drifted once already)."""
    return {"title": title, "readOnlyHint": read_only,
            "destructiveHint": destructive, "idempotentHint": idempotent,
            "openWorldHint": False}


_M = {"model": {"type": "string"}}
_C = {"company_id": {"type": "integer"}}
# fields/domain used to be untyped ({}) schema slots; with no declared
# type, LLM clients routinely sent them as stringified JSON
# ('fields': '["name"]'), which then failed validation character by
# character ("Unknown field '['"). The typed schema is the steering
# signal; normalize_tool_args() below is the safety net.
_FIELDS = {"type": "array", "items": {"type": "string"},
           "description": "Field names to return, e.g. [\"name\", \"email\"]."}
_DOMAIN = {"type": "array",
           "description": "Odoo search domain as a JSON array, e.g. "
                          "[[\"is_company\", \"=\", true]]."}
TOOLS = {
    "whoami": (whoami, _obj({}, []),
        _ann("Who am I", read_only=True, idempotent=True)),
    "list_models": (list_models, _obj({"pattern": {"type": "string"},
        "all": {"type": "boolean"}}, []),
        _ann("List models", read_only=True, idempotent=True)),
    "get_model_fields": (get_model_fields, _obj({**_M, "fields": _FIELDS,
        "verbose": {"type": "boolean"},
        "pattern": {"type": "string",
                    "description": "Keep only fields whose name or label"
                                   " contains this (big models are wide)."}},
        ["model"]),
        _ann("Model fields", read_only=True, idempotent=True)),
    "search_records": (search_records, _obj({**_M, "domain": _DOMAIN,
        "fields": _FIELDS,
        "limit": {"type": "integer"}, "offset": {"type": "integer"},
        "order": {"type": "string"}, **_C}, ["model"]),
        _ann("Search records", read_only=True, idempotent=True)),
    "get_record": (get_record, _obj({**_M, "record_id": {"type": "integer"},
        "fields": _FIELDS, **_C}, ["model", "record_id"]),
        _ann("Get record", read_only=True, idempotent=True)),
    "count_records": (count_records, _obj({**_M, "domain": _DOMAIN, **_C},
        ["model"]),
        _ann("Count records", read_only=True, idempotent=True)),
    "describe_access": (describe_access, _obj(_M, ["model"]),
        _ann("Describe access", read_only=True, idempotent=True)),
    "aggregate_records": (aggregate_records, _obj({**_M,
        "groupby": {"type": "array", "items": {"type": "string"}},
        "aggregates": {"type": "array", "items": {"type": "string"}},
        "domain": _DOMAIN, "limit": {"type": "integer"},
        "offset": {"type": "integer"}, "order": {"type": "string"}, **_C},
        ["model", "groupby"]),
        _ann("Aggregate records", read_only=True, idempotent=True)),
    "get_messages": (get_messages, _obj({**_M,
        "record_id": {"type": "integer"}, "limit": {"type": "integer"},
        **_C}, ["model", "record_id"]),
        _ann("Read chatter", read_only=True, idempotent=True)),
    "export_records": (export_records, _obj({**_M,
        "fields": _FIELDS,
        "domain": _DOMAIN,
        "ids": {"type": "array", "items": {"type": "integer"}},
        "format": {"type": "string", "enum": ["csv", "xlsx"]},
        "limit": {"type": "integer"}, "order": {"type": "string"},
        "inline": {"type": "boolean",
                   "description": "true returns raw base64 in the response instead of a download link — slow, only when a link cannot work."},
        **_C},
        ["model", "fields"]),
        _ann("Export records", read_only=True, idempotent=True)),
    "print_report": (print_report, _obj({
        "report_ref": {"type": "string"},
        "ids": {"type": "array", "items": {"type": "integer"}},
        "inline": {"type": "boolean",
                   "description": "true returns raw base64 in the response instead of a download link — slow, only when a link cannot work."},
        **_C},
        ["report_ref", "ids"]),
        _ann("Print report", read_only=True, idempotent=True)),
    "read_resource": (read_resource, _obj({"uri": {"type": "string"}, **_C},
        ["uri"]),
        _ann("Read resource", read_only=True, idempotent=True)),
    "list_modules": (list_modules, _obj(
        {"pattern": {"type": "string",
                     "description": "Filter by technical name or title"
                                    " (the full list is long)."},
         "installed_only": {"type": "boolean"},
         "verbose": {"type": "boolean"}}, []),
        _ann("List modules", read_only=True, idempotent=True)),
    "create_record": (create_record, _obj({**_M, "values": {"type": "object"},
        **_C}, ["model", "values"]),
        _ann("Create record")),
    "update_record": (update_record, _obj({**_M, "record_id": {"type": "integer"},
        "values": {"type": "object"}, **_C}, ["model", "record_id", "values"]),
        _ann("Update record", idempotent=True)),
    "delete_record": (delete_record, _obj({**_M, "record_id": {"type": "integer"},
        **_C}, ["model", "record_id"]),
        _ann("Delete record", destructive=True, idempotent=True)),
    "post_message": (post_message, _obj({**_M,
        "record_id": {"type": "integer"}, "body": {"type": "string"},
        "subtype": {"type": "string"}, **_C},
        ["model", "record_id", "body"]),
        _ann("Post chatter message")),
}

# JSON-schema types the transport can safely rehydrate from a string.
_COERCIBLE = {"array": (list, "JSON array"), "object": (dict, "JSON object")}


def normalize_tool_args(name, arguments, registry=None):
    """Rehydrate stringified JSON arguments before anything inspects them.

    Even with typed schemas, LLM clients sometimes serialize array/object
    params as strings ('fields': '["name"]' instead of ["name"]); the
    downstream validators then iterate the string character by character
    ("Unknown field '[' on res.partner"). Keyed on the tool's own
    inputSchema: any declared array/object param that arrives as a str is
    json.loads'ed, and must decode to the declared type — no guessing, a
    bare 'name' fails with an actionable message instead of being wrapped.

    Called at the transport ingress (controllers/mcp.py), NOT inside
    _execute_tool: governance overrides (MCP Pro's policy pipeline)
    inspect the args *around* _execute_tool and must see clean values
    too. Unknown tool names pass through untouched — the registry lookup
    raises UnknownToolError later with the right error code."""
    args = dict(arguments or {})
    entry = (registry or TOOLS).get(name)
    if entry is None:
        return args
    props = entry[1].get("properties", {})
    for pname, val in args.items():
        if not isinstance(val, str):
            continue
        coercible = _COERCIBLE.get(props.get(pname, {}).get("type"))
        if coercible is None:
            continue
        pytype, label = coercible
        try:
            decoded = json.loads(val)
        except ValueError:
            raise ToolInvalidParamsError(
                "'%s' must be a %s, but arrived as the string %r. Send the"
                " raw JSON value, not its string serialization."
                % (pname, label, val)) from None
        if not isinstance(decoded, pytype):
            raise ToolInvalidParamsError(
                "'%s' must be a %s, but arrived as the string %r which"
                " decodes to %s. Send the raw JSON value."
                % (pname, label, val, type(decoded).__name__))
        args[pname] = decoded
    return args
