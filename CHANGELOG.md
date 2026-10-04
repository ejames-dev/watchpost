# Changelog

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
