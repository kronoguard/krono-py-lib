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

## 2. One-time setup

### 2.1 Generate the PyPI API token

1. Sign in to <https://pypi.org/manage/account/token/>.
2. **Create API token** → name it `krono-py-lib-ci` → scope it to the
   project `krono` (NOT account-wide; project-scoped tokens limit blast
   radius if the secret leaks).
3. Copy the `pypi-...` token. You will see it exactly once.

### 2.2 Generate the TestPyPI API token

Same flow at <https://test.pypi.org/manage/account/token/>. TestPyPI is a
separate registry and requires its own token. Project scope, name
`krono-py-lib-testci`.

### 2.3 Configure GitHub Environments

The `pypi.yml` workflow uses **GitHub Environments** to scope secrets and
add reviewer rules. Two environments:

| Environment | Secret name | Holds | Recommended protection |
|---|---|---|---|
| `pypi`      | `PYPI_API_KEY` | the **production** PyPI token from 2.1   | Required reviewers (1+ org admin); deployment branches: `main` only |
| `test-pypi` | `PYPI_API_KEY` | the **TestPyPI** token from 2.2          | No reviewers (low-stakes); deployment branches: any |

Configure:

1. Repo → **Settings → Environments → New environment** → name it `pypi`.
2. Under **Environment secrets** → **Add secret** → name `PYPI_API_KEY`,
   value the token from 2.1.
3. Under **Deployment protection rules** → add **Required reviewers** (your
   own GitHub handle is fine for a solo project) and **Deployment branches
   and tags** → "Selected branches" → `main`.
4. Repeat for `test-pypi`: secret = TestPyPI token from 2.2, protection
   rules optional.

Without these, the workflow falls back to a repo-level `PYPI_API_KEY`
secret if one exists, but the environment-scoped path is the only one that
gives you the review gate. Configure both.

### 2.4 Reserve the project name on PyPI

The very first upload claims the name. If you want to claim `krono`
without releasing yet, run the manual workflow once against TestPyPI with
a `0.0.0a0` pre-release version (after updating `pyproject.toml` to match)
so you can confirm the pipeline works end-to-end before pushing v0.1.x to
real PyPI.

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
and uploads to PyPI.

The end state:

- `https://pypi.org/project/krono/0.1.2/` exists with wheel + sdist.
- `pip install krono==0.1.2` works.
- `pip install krono` (no version) resolves to `0.1.2` if it's the latest
  non-prerelease.

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
  krono==<version>

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
| `403 Forbidden` from `twine` | `PYPI_API_KEY` missing, malformed, or scoped to a different project | Verify the secret in the Environment; rotate if old |
| `400: File already exists` | Trying to re-upload an existing version | Bump the version. PyPI does not permit re-uploads, ever. |
| `twine check` fails on `Description` | `README.md` not packaged as long-description, or has bad markdown | Confirm `readme = "README.md"` in `pyproject.toml`; check rendering on TestPyPI before re-cutting on PyPI |
| Wheel installs but `import krono` fails | Source layout mismatch in `pyproject.toml`'s `[tool.hatch.build.targets.wheel] packages` | We package `src/krono`. If you restructure, update this. |
| `pip install krono` resolves to an older version | New version was uploaded as pre-release (1.0.0-rc.1) | Either release a non-prerelease, or users need `pip install --pre krono` |
| GitHub Environment "Required reviewers" never approves | Approver is the same person who dispatched the workflow, and GitHub disallows self-approval on protected environments | Either add a second reviewer to the environment, or temporarily relax the rule for this release |

---

## 6. Future work: switch to Trusted Publishing (OIDC)

API tokens are the v0.x default because they're simple to set up. **In a
future revision, switch to Trusted Publishing** — PyPI's OIDC-based
mechanism that lets GitHub Actions authenticate without any long-lived
secret in the repo. Benefits:

- No `PYPI_API_KEY` secret to leak, rotate, or accidentally print.
- Per-workflow, per-environment authorization configured on PyPI itself.
- Audit trail on PyPI shows the exact workflow run + commit SHA that
  uploaded each release.

Migration when ready (do NOT do this and the API-token approach together —
PyPI accepts both, but the token becomes dead config):

1. Sign in to PyPI → project `krono` → **Publishing** → **Add a new
   trusted publisher** → GitHub:
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
  separate sub-package. Users get it via `pip install "krono[mcp]"`.
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

- PyPI: <https://pypi.org/project/krono/>
- TestPyPI: <https://test.pypi.org/project/krono/>
- Release workflow: [`/.github/workflows/release.yml`](../.github/workflows/release.yml)
- PyPI workflow: [`/.github/workflows/pypi.yml`](../.github/workflows/pypi.yml)
- CI workflow: [`/.github/workflows/ci.yml`](../.github/workflows/ci.yml)
- Spec for what the library does: [`SPEC_KRONO_PY_LIB.md`](../spec/SPEC_KRONO_PY_LIB.md) (local-only; gitignored)
