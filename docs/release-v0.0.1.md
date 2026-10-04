# v0.0.1 release readiness

Local release-readiness checks passed on 2026-10-04.
Check the current PR and post-merge CI results before publishing a specific revision.
No release tag or registry publication is authorized by this checklist.
The package metadata targets `0.0.1`. That value alone does not mean a release exists.

## Scope and evidence

The [approved v0.1 brief](brief-v0.1.md) defines the release scope.
The first release uses version `0.0.1` instead of `0.1.0`. The scope is unchanged.
The [changelog](../CHANGELOG.md) describes the proposed release.

| Requirement | Evidence in the repository |
|---|---|
| Offline report from saved XML | README report command, `examples/report.md`, CLI report tests |
| No-change result without a safety verdict | Identical/unchanged comparison and report tests |
| Explicit changes and newly observed ports | Comparison and report tests for both categories |
| Missing evidence never becomes closure | Missing/grouped observation tests |
| Invalid/incompatible inputs fail clearly | XML, metadata, scan-window, completion, and timeout tests |
| Three documented scenarios | `docs/scenarios.md`, `examples/incomplete.xml` |
| Repeatable findings | Deterministic output and sample-report equality tests |
| Existing reports and notes stay intact | Existing destination, symlink, race, and I/O-failure tests |

## Preparation changes

- Set package version to `0.0.1` and update the lockfile.
- Add the user-selected MIT license and package license metadata.
- Require Setuptools 77.0.3 or newer for modern license metadata.
- Include the license, changelog, lockfile, and release checklist in the source archive.
- Add repository, documentation, and issue links to package metadata.
- Add an installed-wheel build/smoke check to the existing Python CI matrix.
- Link the public GitHub wiki from the README.

No runtime behavior or runtime dependencies change in this preparation step.
The build-tool minimum changes, but dependency installation remains separate from offline application use.

## Verification commands

From the repository root:

```bash
uv sync --locked --dev --python 3.11
uv run --offline python -m unittest discover -s tests -v
uv run --offline pytest
uv run --offline ruff format --check .
uv run --offline ruff check .
```

Repeat the unittest suite on Python 3.12 and 3.13:

```bash
uv run --offline --isolated --python 3.12 python -m unittest discover -s tests -v
uv run --offline --isolated --python 3.13 python -m unittest discover -s tests -v
```

Build fresh artifacts in a new temporary directory:

```bash
build_dir="$(mktemp -d)"
uv build --out-dir "$build_dir"
```

Before release, inspect both archives for version/license metadata and unexpected files.
The source archive must contain the synthetic examples, tests, docs, license, changelog, and lockfile.
It must not contain `scans/`, `reports/`, credentials, or local environment files.
Install the wheel in a fresh environment outside the checkout.
Check help, inspection, comparison, report creation, rejected inputs, and preservation of existing notes.
Run the tests from an extracted source archive as well.

The CI build step checks installed version/license metadata and runs the wheel outside the source checkout.
Build and dependency installation can use the network. Watchpost must not use it at runtime.

## Audit status

Release-preparation results for `0.0.1` on 2026-10-04:

| Check | Result |
|---|---|
| Unittest suite | 51 tests passed on Python 3.11, 3.12, and 3.13 |
| Pytest | 51 tests and 125 subtests passed |
| Ruff format and lint | Passed |
| Locked dependency installation | Passed in the checkout and extracted source archive |
| Source archive and wheel | Built successfully, version `0.0.1`, MIT license present |
| Twine metadata check | `twine check --strict` passed for both archives |
| Archive contents | Required docs/examples/tests/lock present, no private data directories |
| Extracted source archive | All 51 tests passed |
| Installed wheel outside checkout | Help, invalid arguments, inspect, compare, and report checks passed |
| Report safety | Sample bytes matched, existing notes preserved, timeout created no report |
| Offline behavior | Installed-code comparison passed with network entry points disabled |
| Package consistency | `uv pip check` passed for the installed wheel environment |
| Dependency advisory check | No known vulnerabilities reported for seven locked Linux runtime/dev dependencies |
| Self-review | No release-blocking correctness, security, performance, or clarity findings identified |

The same checks passed on 2026-10-03 when the metadata targeted `0.1.0`.
Only version metadata and release documentation changed for `0.0.1`.

The advisory check used `pip-audit` with the PyPI service and made no dependency changes.
It sent package names and versions, not scan data. It does not cover every build tool or platform-specific dependency.
To repeat that separate, network-enabled maintenance check:

```bash
audit_dir="$(mktemp -d)"
uv export --locked --offline --no-emit-project --format requirements-txt \
  --output-file "$audit_dir/requirements.txt"
uvx pip-audit --disable-pip --require-hashes --progress-spinner off \
  --requirement "$audit_dir/requirements.txt"
```

The self-review covered XML parsing, evidence interpretation, report-path escaping, non-replacing output, and package boundaries.
The runtime modules are unchanged by release preparation.
Independent reviewer tools were unavailable. This is not a comprehensive independent security audit or a guarantee of safety.

## Registry preparation follow-up

The user selected `watchpost-cli` because `watchpost` is occupied on both PyPI and TestPyPI.
The repository, command, and import module retain the Watchpost name.
The name correction adds an installed-metadata/entry-point regression test: 51 tests pass on Python 3.11–3.13.
The new `publish.yml` workflow is manual-only, with publishing identity permission limited to the environment-approved upload job.
Its YAML, shell syntax, ref/name rejection cases, build, Twine checks, wheel smoke, and checksum steps passed local checks.
No upload or OIDC exchange ran during those checks. Docker/act and independent reviewer tools were unavailable.
Successful trusted publishing still requires the account-side configuration and an approved live upload.
See [the exact publisher settings and sequence](publishing.md).

## Before tagging or publishing

1. Review and merge the release-preparation PR through the normal repository workflow.
2. Wait for successful post-merge CI and sync a clean local `main`.
3. Obtain explicit approval for the release tag and publication destination.
4. Confirm that the release notes accurately describe the approved version.
5. Rebuild and verify artifacts from the exact approved release commit.
6. Create and verify the signed `v0.0.1` tag only after approval.
7. Publish the approved release notes and artifacts, then confirm the public result.
8. Update the wiki's status to match the published release.

Do not reuse artifacts built before the final commit.
Registry uploads need the account setup in [publishing.md](publishing.md) and separate explicit approval.
The registry workflows do not run automatically when a tag or GitHub Release is created.
