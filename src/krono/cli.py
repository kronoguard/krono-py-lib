"""Command-line entry point: ``krono verify`` (FR-26 through FR-29).

Exit codes (FR-27):
    0 — verified (what is present)
    1 — tampering detected
    2 — usage error (argparse default)
    3 — configuration or I/O error (missing key, unreadable file)
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from krono.exceptions import ConfigError, MissingKeyError
from krono.verify import FailureKind, VerifyFailure, VerifyResult, verify

_TAIL_NOTE: str = "tail truncation not detectable from log alone (see HONEST-CLAIMS.md)"
_KINDS_WITH_EXPECTED_ACTUAL: frozenset[FailureKind] = frozenset(
    {FailureKind.CONTENT_TAMPERED, FailureKind.SEQUENCE_GAP, FailureKind.CHAIN_BREAK}
)


def _build_parser() -> argparse.ArgumentParser:
    """Return the top-level argparse parser for the ``krono`` command."""
    parser = argparse.ArgumentParser(
        prog="krono",
        description="Tamper-evident audit records for MCP tool-call decisions.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    verify_p = sub.add_parser(
        "verify",
        help="Verify the integrity of a krono audit log.",
        description=(
            "Verify the integrity of a krono audit log. "
            "Reads the HMAC key from $KRONO_AUDIT_KEY (or --key-env). "
            "NOTE: tail truncation cannot be detected from the log alone."
        ),
    )
    verify_p.add_argument(
        "--key-env",
        default="KRONO_AUDIT_KEY",
        metavar="VAR",
        help="Env var holding the hex-encoded HMAC key. Default: KRONO_AUDIT_KEY.",
    )
    verify_p.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit machine-readable JSON instead of text.",
    )
    verify_p.add_argument(
        "log_path",
        metavar="<log_path>",
        help="Path to the audit log file to verify.",
    )
    return parser


def _failure_to_json(failure: VerifyFailure) -> dict[str, object]:
    """Convert a ``VerifyFailure`` to a JSON-serializable dict (FR-29).

    Field-presence rules from §Interfaces: ``expected``/``actual`` are
    OMITTED (not ``null``) for kinds that don't carry them.
    """
    out: dict[str, object] = {
        "line": failure.line,
        "sequence_number": failure.sequence_number,
        "kind": failure.kind.value,
        "message": failure.message,
    }
    if failure.kind in _KINDS_WITH_EXPECTED_ACTUAL:
        out["expected"] = failure.expected
        out["actual"] = failure.actual
    return out


def _print_text_success(result: VerifyResult) -> None:
    """Print the FR-28 success message including the tail-truncation note."""
    n = result.entries_checked
    # Edge case: empty log produces "0..-1"; spec doesn't cover this
    # explicitly. Keeps the parenthetical column structure stable for
    # log-parsing operators.
    last = -1 if n == 0 else n - 1
    print(f"✓ krono audit verified: {n} entries (sequence 0..{last})")
    print(f"  note: {_TAIL_NOTE}")


def _print_text_failure(failure: VerifyFailure) -> None:
    """Print the FR-28 failure message; ``(sequence -)`` when None (FR-39)."""
    seq = "-" if failure.sequence_number is None else str(failure.sequence_number)
    print(f"✗ krono audit FAILED at line {failure.line} (sequence {seq}): {failure.kind.value}")
    print(f"  {failure.message}")
    if failure.kind in _KINDS_WITH_EXPECTED_ACTUAL:
        print(f"  expected: {failure.expected}")
        print(f"  actual:   {failure.actual}")


def _run_verify(args: argparse.Namespace) -> int:
    """Execute the ``verify`` subcommand. Returns the FR-27 exit code."""
    try:
        result = verify(args.log_path, key_env=args.key_env)
    except MissingKeyError as exc:
        # FR-27 code 3 + stderr literal var name.
        print(f"krono: {exc}", file=sys.stderr)
        return 3
    except ConfigError as exc:
        print(f"krono: {exc}", file=sys.stderr)
        return 3

    if args.as_json:
        payload: dict[str, object] = {
            "ok": result.ok,
            "entries_checked": result.entries_checked,
            "failure": _failure_to_json(result.failure) if result.failure is not None else None,
        }
        print(json.dumps(payload))
        return 0 if result.ok else 1

    if result.ok:
        _print_text_success(result)
        return 0
    # result.failure is non-None when ok is False (FR-17 contract).
    assert result.failure is not None
    _print_text_failure(result.failure)
    return 1


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point used by ``[project.scripts]``.

    Parses ``argv`` (default ``sys.argv[1:]``) and dispatches to the
    appropriate subcommand. Returns the FR-27 exit code.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "verify":
        return _run_verify(args)
    # argparse with required=True already rejects unknown commands;
    # this branch is defensive.
    parser.error(f"unknown command: {args.command}")
    return 2  # pragma: no cover — parser.error exits before returning


if __name__ == "__main__":  # pragma: no cover - exercised via the console script
    raise SystemExit(main())
