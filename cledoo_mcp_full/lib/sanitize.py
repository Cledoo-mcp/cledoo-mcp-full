# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Strip tracebacks/SQL noise from error text before it reaches an MCP client."""
import re

_TRACEBACK_RE = re.compile(r"Traceback \(most recent call last\).*", re.S)
_ODOO_EXC_RE = re.compile(r"odoo\.exceptions\.\w+:\s*")
_SQL_NOISE_RE = re.compile(r"^(DETAIL|HINT|CONTEXT|LINE \d+):.*$", re.M)
_CONSTRAINT_RE = re.compile(r'violates .*constraint "[^"]+"')


def sanitize_error_message(text):
    if not text:
        return "Operation failed."
    text = str(text)
    m = _TRACEBACK_RE.search(text)
    if m:  # keep only the exception message if a traceback leaked in:
        # last line that looks like "SomeError: ..." (chained tracebacks
        # can end with note/marker lines that aren't the message).
        lines = [l.strip() for l in text[m.start():].strip().splitlines() if l.strip()]
        text = next((l for l in reversed(lines)
                     if re.match(r"[\w.]+(Error|Exception|Warning)?\s*:", l)),
                    lines[-1])
    text = _ODOO_EXC_RE.sub("", text)
    text = _SQL_NOISE_RE.sub("", text)
    text = _CONSTRAINT_RE.sub("violates a database constraint", text)
    return " ".join(text.split()) or "Operation failed."
