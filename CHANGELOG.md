# Changelog

## 0.1.0 — prepared, not yet released

Initial release candidate for local-first review of saved Nmap XML.
This entry describes the proposed v0.1.0 release, not an existing tag or registry publication.

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

### Boundaries

Python 3.11+ on Linux or Ubuntu WSL. CI covers Python 3.11, 3.12, and 3.13.
Inputs are limited to 10 MiB per snapshot. Report output requires a trusted directory with hard-link support.
Watchpost does not scan, upload data, or make runtime network calls.
It does not infer device/application identity or declare a network secure or compromised.

No live scanning, scheduling, dashboard, packet capture, UDP/IPv6 support, AI verdicts, or automatic remediation.

### Verification

See [the release-readiness checklist](docs/release-v0.1.0.md).
The package version alone does not prove publication.
Published releases, when available, appear on [GitHub Releases](https://github.com/ejames-dev/watchpost/releases).
