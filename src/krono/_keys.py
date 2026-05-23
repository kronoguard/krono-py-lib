"""Shared HMAC key resolution per FR-02.

Both `audit.AuditLog` and `verify.verify` need the same key-resolution
logic; living here means the verifier does not import a private symbol
from the writer module.

FR-02 contract:
    - Order: explicit ``key=`` argument wins; otherwise read the named
      env var and hex-decode.
    - Decoded key MUST be >= 32 raw bytes.
    - Raise ``MissingKeyError`` on any defect.
    - NEVER generate an ephemeral key (the ChronoGuard
      ``secret_key or secrets.token_bytes(32)`` anti-pattern is forbidden).
    - Exception messages reference only the env var name OR the literal
      string ``"explicit key argument"`` — NEVER the key material itself.
"""

from __future__ import annotations

import os

from krono.exceptions import MissingKeyError

MIN_KEY_BYTES: int = 32


def resolve_key(key: bytes | None, key_env: str) -> bytes:
    """Resolve the HMAC key per FR-02.

    Args:
        key: explicit raw-bytes key. If non-``None``, it must be >=
            ``MIN_KEY_BYTES`` bytes long; the env var is not consulted.
        key_env: name of the env var to read when ``key`` is ``None``.

    Returns:
        The validated raw-bytes key (>= ``MIN_KEY_BYTES`` bytes).

    Raises:
        MissingKeyError: when no valid key is available. The message
            distinguishes between the explicit-arg case and the env-var
            case so callers passing ``key=`` directly don't see a
            misleading ``KRONO_AUDIT_KEY shorter than 32 bytes`` message.
    """
    if key is not None:
        if len(key) < MIN_KEY_BYTES:
            raise MissingKeyError(f"explicit key argument shorter than {MIN_KEY_BYTES} bytes")
        return key
    raw = os.environ.get(key_env)
    if raw is None or raw == "":
        raise MissingKeyError(f"{key_env} is not set")
    try:
        decoded = bytes.fromhex(raw)
    except ValueError as exc:
        raise MissingKeyError(f"{key_env} is not valid hex") from exc
    if len(decoded) < MIN_KEY_BYTES:
        raise MissingKeyError(f"{key_env} shorter than {MIN_KEY_BYTES} bytes")
    return decoded
