"""Exception hierarchy for krono.

Per FR-24: ``KronoError`` is the base; v1 subclasses are
``MissingKeyError``, ``ConfigError``, ``WriteError``. As of v0.2.0
(FR-43), ``VerifyError`` is exported as an opt-in wrapper for callers
that want exception-style flow; ``verify()`` itself still returns a
``VerifyResult`` and never raises ``VerifyError``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Import from the leaf ``krono.results`` module (not ``krono.verify``) to
    # avoid a static import cycle with ``verify.py`` — which imports
    # ``ConfigError`` from this module at runtime. ``krono.results`` is a
    # leaf with no krono dependencies, so the TYPE_CHECKING import is cycle-
    # free under both runtime and static analysis (CodeQL ``py/import-cycle``).
    from krono.results import VerifyFailure


class KronoError(Exception):
    """Base class for all krono-raised exceptions."""


class MissingKeyError(KronoError):
    """The HMAC key is absent, malformed, or shorter than 32 bytes.

    Raised by ``AuditLog.__init__`` and ``verify()`` per FR-02 when the
    key cannot be sourced from the explicit ``key=`` argument or the
    named environment variable.
    """


class ConfigError(KronoError):
    """Invalid path, unreadable file, or unwritable parent directory.

    Raised by ``AuditLog.__init__`` (FR-01) and ``verify()`` (FR-22)
    on filesystem-level configuration problems.
    """


class WriteError(KronoError):
    """An I/O error or chain-state inconsistency prevented an append.

    Raised by ``AuditLog.record`` (FR-25), by ``AuditLog.__init__``
    on a torn-resume condition (FR-16 step 3), and by
    ``AuditLog.record`` calls made after ``close()`` (FR-15).
    """


class VerifyError(KronoError):
    """Opt-in exception wrapper around a :class:`VerifyFailure` (FR-43).

    ``verify()`` itself never raises this — it always returns a
    :class:`krono.verify.VerifyResult`. Callers that prefer exception
    flow may construct and raise ``VerifyError`` from a failure
    explicitly::

        from krono import verify, VerifyError

        result = verify(path)
        if not result.ok:
            raise VerifyError(result.failure)

    The wrapped failure is exposed as ``self.failure`` so handlers can
    branch on ``failure.kind`` without re-parsing the message string.
    """

    def __init__(self, failure: VerifyFailure) -> None:
        """Store ``failure`` and forward the FR-43 ``_format`` string to :class:`Exception`."""
        self.failure: VerifyFailure = failure
        super().__init__(self._format(failure))

    @staticmethod
    def _format(failure: VerifyFailure) -> str:
        """Render ``failure`` as the FR-43 one-line summary used by ``str(err)``.

        Shape: ``krono verify failed at line <L> (sequence <S>): <kind>: <message>``.
        When ``failure.sequence_number is None`` (``PARSE_ERROR``, or
        ``MISSING_FIELD`` where ``sequence_number`` is itself missing per FR-39),
        ``<S>`` is rendered as the literal hyphen ``-`` for log-column stability.
        """
        seq = "-" if failure.sequence_number is None else str(failure.sequence_number)
        return (
            f"krono verify failed at line {failure.line} "
            f"(sequence {seq}): {failure.kind.value}: {failure.message}"
        )
