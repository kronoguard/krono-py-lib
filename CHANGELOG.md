# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.2.0 (2026-05-25)

Changes since `v0.1.1`.

### Features

- feat(pypi): publish as 'krono-py' via Trusted Publishing (OIDC) (45dd3c9)
- feat: Identity dataclass + VerifyError exception (FR-41/42/43) (3bcb8a0)

### Bug fixes

- fix(ci): correct wheel filename in release.yml verify step (c395521)

### Refactors

- refactor: extract verify result types into krono.results (breaks codeql import cycle) (52ca9d5)

### Documentation

- docs: README + USAGE + CHANGELOG for v0.2.0 (Identity, VerifyError) (0124d3e)
- docs(readme): resolve v0.2.0 doc-consistency drift (261477f)

### Chores

- chore: sync uv.lock to v0.1.1 (05f0af1)
- chore: gitignore .understand-anything/ tool output (0a7fbca)

### CI

- ci: PyPI publish workflow + PUBLISHING.md + README install section (cc110d8)
- ci(pypi): name the kronoguard PyPI account explicitly (3a59509)

### Other

- Merge pull request #2 from kronoguard/feat/pypi-publishing (1f020cc)
- Merge pull request #3 from kronoguard/feat/publish-as-krono-py (093204e)
- test+fix: Identity, VerifyError, AC-44 cross-version compat (FR-41/42/43) (52c2cf2)
- Merge pull request #5 from kronoguard/feat/v0.2.0 (16e34a1)
- Merge pull request #6 from kronoguard/fix/release-wheel-filename (b57522f)

### Coverage and gates

- `make quality` clean
- `make test` passes with statement + branch coverage gate

### Artifacts

Wheel and sdist attached below.

## v0.2.0 (2026-05-25)

Lifts the two v1 "mystery API" deviations (Identity, VerifyError) into a defined, tested v0.2.0 surface. On-disk format unchanged from v0.1.x — logs written under v0.1.x verify byte-identically under v0.2.0 (AC-44).

### Added

- feat: `Identity(declared, authenticated=None)` frozen dataclass at `krono.identity` (FR-41) — a constructor-side convenience for the two-field identity contract.
- feat: `AuditLog.record(..., identity=Identity(...))` kwarg (FR-42) — mutually exclusive with `declared_identity=`/`authenticated_identity=`. `TypeError` is raised BEFORE any file work when both shapes are passed together, so a misuse never leaves the chain in a partial state.
- feat: `VerifyError(KronoError)` opt-in exception wrapper at `krono.exceptions` (FR-43). `verify()` still does NOT raise on tampering — `VerifyError` is reachable only via an explicit caller-side `raise VerifyError(r.failure)`. `str(VerifyError(f))` emits a one-line summary in the FR-43 `_format` shape: `krono verify failed at line <L> (sequence <S>): <kind>: <message>`, with literal `-` when `sequence_number is None`.

### Changed

- `AuditLog.record()` signature: `declared_identity` and `authenticated_identity` now default to `None` to permit the `identity=`-only shape. v0.1.x callers passing the two strings continue to work byte-identically — no migration required.

### Unchanged (load-bearing invariant)

- On-disk JSONL schema: same 11 top-level fields, same canonical-JSON encoding, same HMAC-SHA256 input field set. `Identity` is decomposed inside `record()` and never reaches disk. Logs written under v0.1.x verify under v0.2.0 with `ok=True`. Regression-pinned by `tests/test_regression.py::test_ac44_v01x_format_log_verifies_under_v020` and `::test_ac44_v01x_log_with_identity_kwarg_decomposes_identically`.

### Tests

- 25 new tests across `tests/test_identity.py`, `tests/test_verify.py`, `tests/test_regression.py`. Total suite: 207 tests, 98.92% coverage (gate 97%).

### Migration notes

- No source changes required for v0.1.x callers. To adopt the v0.2.0 surface incrementally:
  - Replace `declared_identity=D, authenticated_identity=A` call sites with `identity=Identity(D, A)` for readability — bytes on disk are identical.
  - Wrap `verify()` callers that want exception flow: `if not (r := verify(p)).ok: raise VerifyError(r.failure)`.

## v0.1.1 (2026-05-23)

Initial release.

### Features

- feat(canonical): canonical JSON encoder (FR-09) (67d5272)
- feat(hash): arguments_hash + current_hash HMAC helpers (FR-07, FR-10) (db7e941)
- feat(exceptions): KronoError hierarchy (FR-24) (af65028)
- feat(events): Decision enum + AuditEvent frozen dataclass (FR-08, FR-40) (5560c18)
- feat(audit): AuditLog class — full record + resume + concurrency (16a2fda)
- feat(verify): verify() + VerifyResult + FailureKind (FR-17..23, FR-37..39) (bad2421)
- feat(cli): krono verify subcommand (FR-26..29) (8fc298f)
- feat(api): wire public re-exports + release-gate test scaffolding (44cae1b)
- feat(examples): four runnable integration patterns (FR-30, FR-35) (4d457dc)

### Bug fixes

- fix(security): resolve 14 CodeQL alerts (1 error, 13 notes) (e93ede6)

### Refactors

- refactor: extract resolve_key to shared _keys module (7c3ef28)

### Tests

- test(regression): byte-layout + key-order + 1000-entry smoke (8717a18)

### Documentation

- docs: README + HONEST-CLAIMS + USAGE (FR-31, FR-32, FR-36) (9663766)
- docs(readme): make CI badge static while repo is private (5ab908d)

### Chores

- chore: adding some guard rails to not commit unwanted files (9859798)
- chore: project scaffold (Phase 0) (491b0e7)
- chore: point repo URLs at kronoguard/krono-py-lib (149fa8f)

### CI

- ci: GitHub Actions (CI + Release) + CHANGELOG + README badges (e5be2fa)
- ci: add CodeQL workflow for Python security scanning (fbb6e48)

### Other

- Initial commit (d04d0b5)
- test+refactor: strict UTF-8 in verify + e2e tests + explicit-key message tests (f40bdfa)
- Revert "docs(readme): make CI badge static while repo is private" (fc95f32)
- Create CodeQL workflow for security analysis (3ce1261)
- Merge origin/main into feat/mvp — keep advanced CodeQL, drop default (1d19f83)
- Merge pull request #1 from kronoguard/feat/mvp (6356016)

### Coverage and gates

- `make quality` clean
- `make test` passes with statement + branch coverage gate

### Artifacts

Wheel and sdist attached below.

## [Unreleased]

Initial v1 implementation on the `feat/mvp` branch (PR #1).
Use the `Release` workflow (`Actions → Release → Run workflow`) to cut
v0.1.0 — that run will prepend its release notes here automatically.
