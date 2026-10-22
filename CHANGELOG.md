# Changelog

## 0.0.2

Second version: richer evidence, review tools, and the browser build, all within the
[v0.1 project brief](docs/brief-v0.1.md)'s rules.
See [the release-readiness checklist](docs/release-v0.0.2.md).
This changelog entry alone does not establish tag or registry publication.

### Added

- `compare_report` and `parse_snapshot` validate and compare snapshots held in memory.
- Static browser build in `web/` using self-hosted Pyodide, with a same-origin-only
  content security policy and a Node smoke test. See [the browser build guide](docs/web.md).
- `inspect`, `compare`, and reports show each host's recorded status and the reason Nmap
  recorded for each port state. They are evidence only and never change findings or counts.
- `inspect` ends with a comparison pre-flight: the scan metadata that `compare` checks, and
  whether the file passes the checks that need only one snapshot.
- Refused comparisons name the differing scan methods, Nmap versions, port coverage (as ranges),
  scan windows, declared port counts, and ports outside the declared coverage.
- Port observations show each snapshot's grouped `<extraports>` counts for the host as labeled
  context. The counts are never expanded into per-port states or compared.
- `compare --context-note TEXT` and an optional browser field record the user's own description
  of the scan context as an escaped literal. Watchpost cannot verify it.
- Reports record each input file's SHA-256 hash and a stable key for each finding,
  such as `192.0.2.10/tcp/3000`.
- `watchpost verify REPORT BEFORE AFTER` regenerates a saved report and lists the generated lines
  that differ, skipping source path labels, the context note, and review fields. It exits 0 on a
  match, 1 on differences, and 2 on unusable input.
- `.gitattributes` keeps the bundled examples byte-identical on every platform, so their
  recorded hashes match.
- `compare --expect FILE` checks the reviewer's own expected later port states, written in TOML,
  against explicit later records: matches, differs, or cannot be checked. Absence never matches.
  Reports gain a "Your expectations" section, and `verify` takes the same `--expect` file.
  See [the expectations milestone](docs/expectations-milestone.md).
- `watchpost history` follows explicit observations across 2 to 50 saved snapshots and checks
  each consecutive pair with the comparison gate.
- `compare --format json` prints or saves the comparison as JSON. A missing record is the string
  `"not observed"`, never `null`.
- Synthetic expectation files for scenarios 1 and 2, and a third snapshot, `examples/rollback.xml`.
- `inspect_text` returns `inspect` output for in-memory XML. The browser page uses it to inspect
  one scan with the same pre-flight, and it can load the synthetic examples from the site itself.
- The browser page works offline after the first visit. A same-origin service worker caches the
  site's own files; the content security policy still blocks every other origin.
- A Windows CI job runs the full test suite. Tests that depend on Linux-only behavior are skipped
  on Windows with the reason stated.

### Changed

- Snapshots are parsed in one streaming pass that keeps records instead of the XML tree, and the
  size limit rises from 10 MiB to 100 MiB. Error priority is unchanged.
- In-memory source names are platform-independent labels, so reports match on every platform.
- Text files check out with LF line endings everywhere.
- The inspect pre-flight's last line no longer names a CLI flag, so it reads the same in the
  browser.
- Malformed host status, reason, or grouped port records are rejected like other malformed records.
- `examples/report.md` is regenerated with the new evidence lines.

## 0.0.1

Initial version for local-first review of saved Nmap XML.
Delivers the scope of the [v0.1 project brief](docs/brief-v0.1.md).
See [GitHub Releases](https://github.com/ejames-dev/watchpost/releases) for publication dates and assets.
This changelog entry alone does not establish tag or registry publication.

### Included

- Inspect explicit IPv4/TCP observations in one saved scan.
- Compare completed TCP connect or SYN scans with matching Nmap versions and declared port coverage.
- Require human confirmation of scan location, intended targets, and remaining settings.
- Preserve missing observations as `not observed`, never assumed closed.
- Generate deterministic Markdown reports with evidence, limitations, suggested checks, and blank review fields.
- Protect existing report files and notes with non-replacing output.
- Reject unsafe XML, unsupported inputs, incompatible scans, and reported host timeouts.
- Provide three synthetic walkthroughs and a [user wiki](https://github.com/ejames-dev/watchpost/wiki).
- Distribute Watchpost under the MIT license.
- Use `watchpost-cli` as the distribution name, retaining the `watchpost` command and module.
- Provide a manual, environment-approved Trusted Publishing workflow for TestPyPI and PyPI.

### Boundaries

Python 3.11+ on Linux or Ubuntu WSL. CI covers Python 3.11, 3.12, and 3.13.
Inputs are limited to 10 MiB per snapshot. Report output requires a trusted directory with hard-link support.
Watchpost does not scan, upload data, or make runtime network calls.
It does not infer device/application identity or declare a network secure or compromised.

No live scanning, scheduling, dashboard, packet capture, UDP/IPv6 support, AI verdicts, or automatic remediation.

### Verification

See [the release-readiness checklist](docs/release-v0.0.1.md).
The package version alone does not prove publication.
Published releases, when available, appear on [GitHub Releases](https://github.com/ejames-dev/watchpost/releases).
