"""Structural check for `docs/USAGE.md` (FR-36, AC-34).

UT-Docs-Usage-Structure:
- Exactly the five H2 headings from FR-36 appear in order, no other H2 headings
  between them.
- Each of the four `examples/<name>.py` literal filenames appears at least once
  in the body.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
USAGE_PATH = REPO_ROOT / "docs" / "USAGE.md"


# The five required H2 sections per FR-36, in order. We match each by a
# substring of the canonical heading title to keep the test resilient to
# stylistic phrasing while still enforcing semantic order.
REQUIRED_H2_KEYWORDS: list[str] = [
    "Quickstart",
    "Integration Pattern",  # "The four Integration Patterns"
    "Identity",  # "Identity model"
    "Operating",  # "Operating notes"
    "Failure",  # "Failure-response patterns"
]


REQUIRED_EXAMPLE_FILES: list[str] = [
    "examples/note_server.py",
    "examples/audit_singleton.py",
    "examples/fastmcp_dispatch.py",
    "examples/with_bearer_auth.py",
]


@pytest.fixture
def usage_text() -> str:
    if not USAGE_PATH.exists():
        pytest.skip(f"docs/USAGE.md not present yet at {USAGE_PATH}")
    return USAGE_PATH.read_text(encoding="utf-8")


def _h2_headings(text: str) -> list[str]:
    """Extract H2 heading titles (lines starting with `## `, not `### ` etc.)."""
    out: list[str] = []
    for raw in text.splitlines():
        # `^## ` exactly — two hashes followed by space, NOT three.
        m = re.match(r"^##\s+(.*?)\s*$", raw)
        if m and not raw.startswith("###"):
            out.append(m.group(1))
    return out


class TestUsageDocStructure:
    """UT-Docs-Usage-Structure."""

    def test_usage_md_exists_in_docs(self) -> None:
        assert USAGE_PATH.exists(), f"docs/USAGE.md missing at {USAGE_PATH}"
        # And specifically under docs/, not at the repo root.
        assert USAGE_PATH.parent.name == "docs"

    def test_five_h2_sections_in_order(self, usage_text: str) -> None:
        headings = _h2_headings(usage_text)
        # Exactly 5 H2 sections — no more, no fewer.
        assert len(headings) == 5, f"expected 5 H2 sections, got {len(headings)}: {headings}"

        # Each heading contains its required keyword, in order.
        for i, (heading, keyword) in enumerate(zip(headings, REQUIRED_H2_KEYWORDS, strict=True)):
            assert keyword.lower() in heading.lower(), (
                f"H2 section #{i + 1} ({heading!r}) does not contain keyword {keyword!r}"
            )

    @pytest.mark.parametrize("example_file", REQUIRED_EXAMPLE_FILES)
    def test_each_example_referenced(self, usage_text: str, example_file: str) -> None:
        assert example_file in usage_text, f"docs/USAGE.md does not reference {example_file!r}"
