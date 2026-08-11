# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Pure crypto helpers for the OAuth server — stdlib only, no ORM."""
import base64
import hashlib
import hmac
import secrets


def new_secret():
    return secrets.token_urlsafe(32)


def hash_secret(raw):
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def verify_pkce(verifier, challenge):
    """True iff BASE64URL(SHA256(verifier)) == challenge (S256, no padding)."""
    if not verifier or not challenge:
        return False
    try:
        # RFC 7636 §4.1 restricts verifiers to unreserved ASCII; anything
        # else is an invalid verifier, not a server error.
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
    except UnicodeEncodeError:
        return False
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return hmac.compare_digest(computed, challenge)
