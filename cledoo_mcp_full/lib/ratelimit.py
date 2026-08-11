# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Fixed-window rate limiter, in-memory, per worker process.

Deliberately approximate: stock Odoo has no shared cache, and a SQL
counter per request would be write amplification on the hot path. With N
workers each holding its own buckets, a client can burst up to N× the
configured limit in the worst case — good enough to stop a looping agent
from hammering the ORM. The hard guarantee belongs to the reverse proxy
(see README for a Caddy/nginx recipe)."""
import time

# Bounded memory: on overflow, drop buckets from past windows; if a hostile
# principal-cardinality flood still overflows (register spam with spoofed
# IPs), fail open by clearing — rate limiting is a hygiene layer here, not
# a security boundary.
MAX_BUCKETS = 10_000

_buckets = {}


def check(principal, limit, window=60.0, now=None):
    """Count one hit for `principal`. Returns (allowed, retry_after_s).

    limit <= 0 disables the limiter (always allowed). `now` is injectable
    for tests."""
    if limit <= 0:
        return True, 0.0
    if now is None:
        now = time.time()
    win = int(now // window)
    prev_win, count = _buckets.get(principal, (win, 0))
    if prev_win != win:
        count = 0
    count += 1
    _buckets[principal] = (win, count)
    if len(_buckets) > MAX_BUCKETS:
        for key in [k for k, (w, _c) in _buckets.items() if w != win]:
            _buckets.pop(key, None)
        if len(_buckets) > MAX_BUCKETS:
            _buckets.clear()
    if count > limit:
        return False, window - (now % window)
    return True, 0.0


def reset():
    """Test helper: forget all buckets."""
    _buckets.clear()
