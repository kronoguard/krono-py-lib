"""Unit tests for `AuditLog` concurrency (FR-12).

Spec: AC-10, UT-Concurrency.
100 threads each call `record(...)` once against ONE AuditLog instance,
synchronized by a Barrier so they hit the lock simultaneously. The resulting
file MUST contain exactly 100 lines with sequence numbers `0..99` (each
appearing exactly once), and `verify()` MUST return `ok=True`.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from krono.audit import AuditLog
from krono.verify import verify

from .conftest import make_record_kwargs, read_jsonl_lines

THREAD_COUNT = 100


class TestConcurrency:
    """UT-Concurrency."""

    def test_100_threads_one_record_each(self, key_env: str, log_path: Path) -> None:
        # Use a Barrier with a 5s timeout to bound test duration without
        # depending on pytest-timeout.
        barrier = threading.Barrier(THREAD_COUNT)
        errors: list[BaseException] = []
        errors_lock = threading.Lock()

        with AuditLog(log_path) as audit:

            def worker(i: int) -> None:
                try:
                    # All threads wait at the barrier so they hit record()
                    # at maximum contention.
                    barrier.wait(timeout=5)
                    audit.record(
                        **make_record_kwargs(
                            tool_name=f"tool_{i}",
                            reason=f"thread {i}",
                        )
                    )
                except BaseException as e:
                    with errors_lock:
                        errors.append(e)

            threads = [
                threading.Thread(target=worker, args=(i,), name=f"krono-t{i}")
                for i in range(THREAD_COUNT)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5)

        # No worker raised.
        assert not errors, f"workers raised: {errors!r}"

        # Exactly THREAD_COUNT lines.
        lines = read_jsonl_lines(log_path)
        assert len(lines) == THREAD_COUNT, f"expected {THREAD_COUNT} lines, got {len(lines)}"

        # Sequence numbers = {0..99} exactly (set equality, no dupes, no gaps).
        seq_nums = [json.loads(line)["sequence_number"] for line in lines]
        assert set(seq_nums) == set(range(THREAD_COUNT))
        assert len(seq_nums) == len(set(seq_nums)), "duplicate sequence numbers"

        # verify() passes — chain is intact.
        result = verify(log_path)
        assert result.ok is True
        assert result.entries_checked == THREAD_COUNT

    def test_chain_is_linked_in_order(self, key_env: str, log_path: Path) -> None:
        """After concurrent appends, file-position order must yield a valid chain.

        This is a tighter check than just "sequence numbers form a set" — it
        proves that the lock serializes the read-of-prev-hash + write of new
        line atomically: each line's previous_hash matches the prior line's
        current_hash by file position, not just by sequence number.
        """
        barrier = threading.Barrier(THREAD_COUNT)

        with AuditLog(log_path) as audit:

            def worker(i: int) -> None:
                barrier.wait(timeout=5)
                audit.record(**make_record_kwargs(reason=f"t{i}"))

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(THREAD_COUNT)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5)

        lines = read_jsonl_lines(log_path)
        parsed = [json.loads(line) for line in lines]
        # File order: each entry's previous_hash equals previous entry's current_hash.
        assert parsed[0]["previous_hash"] == "genesis"
        for i in range(1, len(parsed)):
            assert parsed[i]["previous_hash"] == parsed[i - 1]["current_hash"], (
                f"chain break at file position {i}"
            )

        # And the same chain holds under verify().
        assert verify(log_path).ok is True
