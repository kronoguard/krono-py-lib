# Publishing `krono` to PyPI

End-to-end reference for releasing `krono` to PyPI (and TestPyPI for dry runs).
This document is normative for the v0.x line; if you migrate to Trusted
Publishing (recommended — see §6), revise this doc.

---

## 1. Pipeline overview

Three workflows participate in a release:

```
  Actions → Release (workflow_dispatch)
        │   inputs: version, prerelease, dry-run
        │
        ├─► bumps pyproject.toml + __init__.py + README version badge
        ├─► generates release notes from Conventional Commit log
        ├─► prepends CHANGELOG.md
        ├─► uv build (wheel + sdist)
        ├─► commits + tags v<X.Y.Z>
        └─► creates GitHub Release with artifacts attached
                │
                │   (release event: 'published')
                ▼
  Actions → Publish to PyPI (auto, on release:published)
        │
        ├─► checkout the tagged tree
        ├─► make quality
        ├─► make test (97% coverage gate)
        ├─► uv build (fresh; ignores the Release-attached artifacts)
        ├─► twine check --strict dist/*
        └─► pypa/gh-action-pypi-publish → PyPI

  Actions → Publish to PyPI (manual, workflow_dispatch)
        │   inputs: test-pypi (default true), ref
        └─► same as above but routes to TestPyPI by default
```

The Publish job intentionally **rebuilds from the tagged source** rather than
re-using the wheels attached to the GitHub Release. Reasons:

- The Release-attached wheel is built once by `release.yml`. Rebuilding here
  is the second independent confirmation the source state is publishable.
- PyPI does not allow overwriting an existing version. A bad first build
  would mean burning the version number; the second build gate reduces that
  risk to near-zero.

---

## 2. One-time setup (PyPI Trusted Publishing / OIDC)

**PyPI account:** `kronoguard` (<https://pypi.org/user/kronoguard/>). This
is a regular PyPI user account, not a PyPI Organization. The same account
name is also registered on TestPyPI (<https://test.pypi.org/user/kronoguard/>) —
the prod and TestPyPI accounts are independent even when the username
matches.

**Distribution name:** `krono-py` on both registries. The bare `krono`
name on PyPI is owned by a different user. The Python import name remains
`krono` regardless (`pip install krono-py` → `from krono import …`).

**Auth method:** PyPI Trusted Publishing (OIDC). No long-lived secret in
the repo. The `pypi.yml` workflow uses GitHub Actions OIDC; PyPI verifies
the OIDC token from each run against a registered trusted-publisher entry
and accepts the upload if owner+repo+workflow (+optional environment)
match.

### 2.1 Register the trusted publisher on PyPI

Sign in to <https://pypi.org/manage/account/publishing/> as `kronoguard` →
**Add a new pending publisher** (or for an existing project, use the
project's **Publishing** tab):

| Field | Value |
|---|---|
| PyPI Project Name | `krono-py` |
| Owner             | `kronoguard` (the GitHub org) |
| Repository name   | `krono-py-lib` |
| Workflow name     | `pypi.yml` |
| Environment name  | `(Any)` — or `pypi` if you want to lock prod uploads to a named environment |

For the FIRST release, this is a "pending publisher" (no project exists
yet). The first successful upload via OIDC creates the project and the
entry transitions from "Pending" to active.

### 2.2 Register the trusted publisher on TestPyPI

Same flow at <https://test.pypi.org/manage/account/publishing/>. TestPyPI
is a separate registry and requires its own publisher entry. Same
fields:

| Field | Value |
|---|---|
| TestPyPI Project Name | `krono-py` |
| Owner             | `kronoguard` |
| Repository name   | `krono-py-lib` |
| Workflow name     | `pypi.yml` |
| Environment name  | `(Any)` or `test-pypi` |

### 2.3 (Optional) Configure GitHub Environments for review gates

OIDC doesn't NEED GitHub Environments — the workflow runs and PyPI
verifies. But Environments are the right place to add a **required
reviewer gate** for prod releases:

1. Repo → **Settings → Environments → New environment** → name `pypi`.
2. **Deployment protection rules** → **Required reviewers** (your own
   handle is fine for a solo project) and **Deployment branches and
   tags** → "Selected branches" → `main`.
3. Repeat for `test-pypi` with optional/no protection.

The `pypi.yml` workflow already references these environments; you can
configure them whenever you want the review gate.

### 2.4 Remove the legacy `PYPI_API_KEY` secret

If a `PYPI_API_KEY` secret was added during the earlier API-token-based
configuration, **delete it now**. OIDC supersedes it, and a dead secret
is a permanent exfiltration target. From the repo:

```bash
gh secret delete PYPI_API_KEY --env pypi || true
gh secret delete PYPI_API_KEY --env test-pypi || true
gh secret delete PYPI_API_KEY || true   # repo-level fallback if it existed
```

---

## 3. Cutting a release

```bash
# In the GitHub UI:
# 1. Actions → Release → Run workflow
# 2. Branch: main (or any branch — release.yml supports it)
# 3. Inputs:
#      version = "0.1.2"    (no leading 'v', valid semver)
#      prerelease = false   (true for 0.1.2-rc.1, 1.0.0-beta.3, etc.)
#      dry-run = false      (true to validate + build without pushing/tagging)
# 4. Run.
```

When `release.yml` succeeds it creates a GitHub Release with the tag
`v0.1.2`. The `release:published` event fires `pypi.yml`, which gates on
`make quality && make test`, builds fresh, validates with `twine check`,
authenticates to PyPI via OIDC, and uploads.

The end state:

- `https://pypi.org/project/krono-py/0.1.2/` exists with wheel + sdist.
- `pip install krono-py==0.1.2` works.
- `pip install krono-py` (no version) resolves to `0.1.2` if it's the
  latest non-prerelease.
- `import krono` still works (distribution name and import name differ
  by design — `krono-py` is the wheel, `krono` is the package).

---

## 4. Dry-running against TestPyPI

Before doing any production release, validate the pipeline end-to-end with
TestPyPI:

```bash
# UI: Actions → Publish to PyPI → Run workflow
#   - test-pypi = true       (this is the default)
#   - ref       = main       (or any branch/tag)
```

This skips `release.yml` entirely — it just builds + uploads to TestPyPI
under the current version in `pyproject.toml`. To verify:

```bash
pip install \
  --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ \
  krono-py==<version>

python -c "import krono; print(krono.__version__)"
krono verify --help
```

`--extra-index-url https://pypi.org/simple/` is required because TestPyPI
does NOT mirror real PyPI; your transitive deps (none for `krono`, but
e.g. `mcp` extra) come from real PyPI.

TestPyPI also does not allow overwriting an existing version. If you need
to re-test the same version number, bump the `dev` segment of the version
in `pyproject.toml` (e.g. `0.1.2.dev1`, `0.1.2.dev2`).

---

## 5. Failure modes and what to do

| Symptom | Cause | Fix |
|---|---|---|
| `403 The user 'X' isn't allowed to upload to project 'Y'` | Distribution name in `pyproject.toml` differs from what the kronoguard PyPI account owns, OR a different PyPI user owns that name (the prior `krono` failure was exactly this — `krono` is owned by another user; we use `krono-py`) | Confirm `name = "krono-py"` in `pyproject.toml`; if you want a new name, register a trusted-publisher entry for it on PyPI first |
| `Trusted publisher mismatch` / `invalid_grant` | Workflow filename, repo, owner, or environment doesn't match the publisher entry on PyPI | Inspect <https://pypi.org/manage/account/publishing/> — fields must match exactly. Common mistakes: workflow filename includes the path (`.github/workflows/pypi.yml` instead of `pypi.yml`); environment name set to a value when the publisher entry expects `(Any)` |
| `400: File already exists` | Re-upload of an existing version | Bump the version. PyPI does not permit re-uploads, ever. |
| `twine check` fails on `Description` | `README.md` not packaged as long-description, or bad markdown | Confirm `readme = "README.md"` in `pyproject.toml`; check rendering on TestPyPI before PyPI |
| Wheel installs but `import krono` fails | Source layout mismatch in `[tool.hatch.build.targets.wheel] packages` | We package `src/krono`. The import name is `krono`; the distribution name (`krono-py`) is different and that's OK |
| `pip install krono-py` resolves to an older version | New version was uploaded as pre-release | Either release a non-prerelease, or users need `pip install --pre krono-py` |
| GitHub Environment "Required reviewers" never approves | Approver is the same person who dispatched, and GitHub disallows self-approval | Add a second reviewer, or temporarily relax the rule for this release |

---

## 6. Trusted Publishing (OIDC) — current setup

The repo currently uses Trusted Publishing. The migration from API tokens
(used briefly in the initial v0.1.x setup) happened when PyPI's trusted-
publisher entry for `kronoguard/krono-py-lib` → `pypi.yml` was registered.
Confirm at <https://pypi.org/manage/account/publishing/> (and the
TestPyPI equivalent).

If you ever need to go back to API tokens (don't, but if): re-add
`PYPI_API_KEY` to the relevant environment and set
`password: ${{ secrets.PYPI_API_KEY }}` on the `pypa/gh-action-pypi-publish`
step. The action accepts either auth method; OIDC is preferred whenever
both are configured.

The earlier (historical) trusted-publisher setup:

1. Sign in to PyPI as `kronoguard` → **Publishing** → **Add a new
   pending publisher** → GitHub:
   - PyPI Project Name: `krono-py`
   - Owner: `kronoguard`
   - Repository: `krono-py-lib`
   - Workflow filename: `pypi.yml`
   - Environment: `pypi` (or `test-pypi` for the TestPyPI publisher)
2. In `pypi.yml`, replace `password: ${{ secrets.PYPI_API_KEY }}` with
   nothing (remove the line) and add `permissions: id-token: write` at the
   job level.
3. Delete the `PYPI_API_KEY` secret from the GitHub Environment.
4. Update this doc.

See <https://docs.pypi.org/trusted-publishers/> for the full procedure.

---

## 7. What does NOT publish to PyPI

For the avoidance of doubt:

- **Pre-release dispatch builds to TestPyPI** are NOT mirrored to PyPI.
- **Failed `make quality` or `make test` runs** abort before the upload
  step — never partially published.
- **The `mcp` optional extra** is a marker only; PyPI does not host a
  separate sub-package. Users get it via `pip install "krono-py[mcp]"`.
- **Spec files under `spec/`** are gitignored and excluded from the wheel
  by virtue of `[tool.hatch.build.targets.wheel] packages = ["src/krono"]`
  scoping only the library.
- **`tests/`, `examples/`, and `docs/`** are NOT packaged into the wheel.
  They live in the repo and the sdist (since the sdist includes everything
  in the source tree by default), but consumers installing via wheel get
  only `src/krono`.

If you need to ship examples or docs to users, either:
- Add them to the package data in `pyproject.toml`, or
- Tell users to `git clone` the repo (currently what `README.md`
  recommends for the four example scripts).

---

## 8. Reference

- PyPI project: <https://pypi.org/project/krono-py/>
- PyPI account: <https://pypi.org/user/kronoguard/>
- PyPI publishing settings: <https://pypi.org/manage/account/publishing/>
- TestPyPI project: <https://test.pypi.org/project/krono-py/>
- TestPyPI account: <https://test.pypi.org/user/kronoguard/>
- Release workflow: [`/.github/workflows/release.yml`](../.github/workflows/release.yml)
- PyPI workflow: [`/.github/workflows/pypi.yml`](../.github/workflows/pypi.yml)
- CI workflow: [`/.github/workflows/ci.yml`](../.github/workflows/ci.yml)
- Spec for what the library does: [`SPEC_KRONO_PY_LIB.md`](../spec/SPEC_KRONO_PY_LIB.md) (local-only; gitignored)
