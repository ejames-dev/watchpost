# Watchpost

Watchpost is a standalone Python CLI, not part of the adjacent AgentEase SDK.
Read `docs/brief-v0.1.md`, `docs/scan-milestone.md`, and the current README before changing code.

## Commands

- Setup: `uv sync --dev --python 3.11`
- Inspect demo: `uv run watchpost inspect examples/baseline.xml`
- Compare demo: `uv run watchpost compare examples/baseline.xml examples/after.xml --confirm-same-context`
- Report demo: create `reports/`, then add `--output reports/review.md` to the compare command. Use a new filename each time.
- Scan check (needs Nmap; loopback only): create `scans/`, then `uv run watchpost scan 127.0.0.1 --ports 22,80 --confirm-authorized`
- Tests: `uv run python -m unittest discover -s tests -v`
- Alternate test runner: `uv run pytest`
- Format check: `uv run ruff format --check .`
- Lint: `uv run ruff check .`
- Browser build: `bash web/build.sh site`, then `node web/smoke.mjs site`

## Conventions

- Keep Python 3.11+ compatibility and a 100-character line limit.
- Use plain functions and typed standard-library containers before adding abstractions.
- Keep tests in unittest and use synthetic data only.
- Keep report rendering in `watchpost_report.py`. Reuse the existing parser and comparison gate.
- Keep process and network code in `watchpost_scan.py`, loaded only by the `scan` command.
- If report wording changes, regenerate `examples/report.md` into a new file and review the diff.
- Use short, imperative commit messages for one logical change.
- Verify behavior with tests before claiming a milestone is complete.
- Keep the README honest about features that do not exist yet.

## Boundaries

- Only `watchpost scan` may start a process or cause network traffic. It runs Nmap once with the
  fixed profile in `watchpost_scan.py`, against explicit IPv4 targets, after `--confirm-authorized`.
  Never add host discovery, DNS lookups, hostnames, service or version detection, scripts, UDP,
  IPv6, or user-supplied Nmap options.
- Never run, repeat, or schedule scans from Watchpost itself. Scheduling stays with the user's tools.
- Never upload data or add other runtime network calls. Every other command and `web/` stay offline.
- During development, never scan anything but loopback. Tests replace Nmap with a fake runner.
- In `web/`, serve every runtime file from the same origin. Never add a CDN, analytics,
  or any endpoint that receives scan data. Keep `connect-src 'self'` in `web/_headers`.
- Parse XML with defusedxml. Never enable entities or external references.
- Never interpret missing observations as confirmed closures or device removal.
- Require human confirmation of scan context. Never claim metadata alone proves comparable conditions.
  `compare --exit-code` still requires `--confirm-same-context`; never add a way around it.
- Never identify an application by port number alone.
- Never silently overwrite reports, saved scans, or human notes.
- Never commit credentials, private inventories, or real scan results.
- Do not change other repositories or global Git settings.
