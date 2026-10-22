# v0.0.2 release readiness

Local release-readiness checks ran on 2026-10-21 for the `browser-offline-release` branch.
Check the PR and post-merge CI results before publishing a specific revision.
No release tag or registry publication is authorized by this checklist.
The package metadata targets `0.0.2`. That value alone does not mean a release exists.

## Scope

The [changelog](../CHANGELOG.md) lists everything in `0.0.2`. In short:

- Richer evidence: host status, Nmap's reasons, and grouped counts as labeled context.
- Clearer refusals and an `inspect` pre-flight.
- Review tools: context notes, SHA-256 hashes, finding keys, `verify`, reviewer expectations,
  `history`, and JSON output.
- A streaming parser with a 100 MiB limit.
- Platform honesty: Windows CI, LF checkouts, and documented Windows differences.
- The browser page: in-memory comparison and inspection, synthetic examples, and offline use.

The [v0.1 brief](brief-v0.1.md)'s non-negotiable rules still hold. Watchpost never scans, and the
CLI makes no network calls. The browser page loads only its own files from the site that serves
it, and scan files never leave the tab. Missing observations never become closures, and port
numbers never identify applications. Context is confirmed by a human, and existing reports are
never overwritten. New review features follow the [expectations milestone](expectations-milestone.md).

## Verification commands

From the repository root:

```bash
uv sync --locked --dev --python 3.11
uv run --offline python -m unittest discover -s tests -v
uv run --offline pytest
uv run --offline ruff format --check .
uv run --offline ruff check .
uv run --isolated --python 3.12 python -m unittest discover -s tests
uv run --isolated --python 3.13 python -m unittest discover -s tests
```

Build fresh artifacts in a new temporary directory, check their metadata, and inspect their
contents:

```bash
build_dir="$(mktemp -d)"
uv build --out-dir "$build_dir"
uvx --from 'twine==7.0.0' twine check --strict "$build_dir"/*
tar tzf "$build_dir"/*.tar.gz
```

Install the wheel in a fresh environment outside the checkout and run `--help`, `inspect`,
`compare` with and without `--output`, `verify`, `history`, and `--format json` against the
synthetic examples. Run the tests from an extracted source archive as well.

## Audit status

Results for `0.0.2` on 2026-10-21:

| Check | Result |
|---|---|
| Unittest suite | 100 tests passed on Python 3.11, 3.12, and 3.13 (Linux) |
| Pytest | 100 tests and 205 subtests passed |
| Windows, local run | 100 tests ran on Windows 11 with Python 3.11: 97 passed, and 3 Linux-only tests were skipped |
| Windows, CI | The `windows` job on GitHub's `windows-latest` runner with Python 3.13 passed the tests and a synthetic comparison at commit `42588d6` |
| Ruff format and lint | Passed |
| Source archive and wheel | Built as `0.0.2`; `twine check --strict` passed for both |
| Archive contents | Required docs, examples, tests, license, changelog, and lockfile present; no `scans/`, `reports/`, `.venv`, `site`, or `.env` entries |
| Extracted source archive | All tests passed |
| Installed wheel outside checkout | Help, installed version, inspect, compare, report, verify, history, and JSON passed; the incomplete scan exited 2 and an existing notes file was preserved |
| Package consistency | `uv pip check` passed for the installed wheel environment |
| Browser build | Node smoke test passed; offline reload, examples, comparison, and inspection checked in a browser |
| Parser robustness | 20,000 mutated inputs through three entry points raised only `ValueError` refusals; parsing time stays linear in the number of root children |
| Dependency advisory check | `pip-audit` found no known vulnerabilities in the locked dependencies |

The advisory check sent package names and versions to the PyPI service, not scan data.
This is not an independent security audit or a guarantee of safety.

## Publication steps for the maintainer

Follow [publishing setup](publishing.md). Each upload needs your approval in GitHub.

1. Merge this PR after CI passes, including the new Windows job.
2. Run **Actions → Publish Python package** from `main` with registry `testpypi`, approve the
   `testpypi` environment, and verify the TestPyPI install as `publishing.md` describes.
3. Create and verify the signed tag `v0.0.2` on the release commit, then publish a GitHub
   Release with the `0.0.2` changelog notes.
4. Run the workflow at tag `v0.0.2` with registry `pypi` and approve the `pypi` environment.
5. Confirm `pip install watchpost-cli==0.0.2` works, then update the wiki's install instructions.
