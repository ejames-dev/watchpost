# Watchpost

Local-first, evidence-backed reviews of changes between saved Nmap scans.

**Status: inspection, comparison, Markdown reporting, and synthetic walkthroughs implemented.**
Two saved XML files can produce a change-review report. The [three walkthroughs](docs/scenarios.md)
cover expected deployment, unintended backend exposure, and an incomplete scan.
[Published releases](https://github.com/ejames-dev/watchpost/releases) are listed on GitHub.
A source checkout can contain unreleased changes.
See the [release notes](CHANGELOG.md) and [release-readiness checklist](docs/release-v0.0.1.md).

**[User wiki](https://github.com/ejames-dev/watchpost/wiki)** — setup, report interpretation,
scenarios, troubleshooting, and safety.

## Package name

The distribution name for PyPI and TestPyPI is **`watchpost-cli`**.
The command and Python module remain `watchpost`. The GitHub repository remains `ejames-dev/watchpost`.
The registry package named `watchpost` belongs to an unrelated project. Do not install it for this tool.
See [publishing setup](docs/publishing.md) for the maintainer workflow.

## Install from PyPI

Version `0.0.1` is published on [PyPI](https://pypi.org/project/watchpost-cli/0.0.1/).
With Python 3.11+, install it into a virtual environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install 'watchpost-cli==0.0.1'
.venv/bin/watchpost --help
```

The package does not include the synthetic example files.
To run the demos below, use a source checkout.

## Scope

Watchpost is for students and home-lab operators working on authorized networks.
Inspect a saved Nmap XML file or compare two snapshots of explicit IPv4/TCP observations.
Watchpost does not launch Nmap, discover devices, or make network requests.

The approved target is in [the v0.1 project brief](docs/brief-v0.1.md).

## Try the synthetic demo

With Python 3.11+ and [uv](https://docs.astral.sh/uv/) installed:

```bash
git clone https://github.com/ejames-dev/watchpost.git
cd watchpost
uv sync --locked --dev --python 3.11
uv run --offline watchpost inspect examples/baseline.xml
```

```text
IPv4/TCP observations (not a security verdict)
192.0.2.10
  22/tcp  open
  80/tcp  closed
  443/tcp  open
  3000/tcp  closed
192.0.2.20
  22/tcp  open
Only explicit port observations are listed; missing ports are not classified.
```

Nmap is not required. These addresses and states are fictional.
For an existing checkout, run the final two commands from its root directory.

## Compare two snapshots

```bash
uv run --offline watchpost compare examples/baseline.xml examples/after.xml \
  --confirm-same-context
```

The synthetic second scan is one minute later. Its only explicit state change is:

```text
STATE CHANGE 192.0.2.10 3000/tcp: closed -> open
```

The output includes both source paths, UTC scan windows, Nmap version, scan method,
declared port count, differences, and limitations. Without `--output`, the command prints
only to the terminal.

**Before using real inputs, confirm the same scan location, intended targets, and remaining
Nmap settings.** The flag records your confirmation. It does not let Watchpost verify the
network location, reconstruct the full command line, or override failed metadata checks.
Do not use it to force a comparison you know is incompatible.

Comparison currently requires:

- One TCP connect or SYN scan per snapshot, with the same method and Nmap version.
- Identical declared TCP port coverage. Equivalent lists and ranges are normalized.
- A declared port count that matches that coverage, with all explicit ports inside it.
- Successful scan completion and valid start/end timestamps.
- Earlier and later scan windows that do not overlap. Equal windows with identical supported
  observations are allowed, so comparing a snapshot with itself produces no observed changes.

| Evidence | Output |
|---|---|
| Explicit states differ | `STATE CHANGE ... closed -> open` |
| A port has no earlier explicit record | `PORT OBSERVATION ... not observed -> open` |
| A port has no later explicit record | `PORT OBSERVATION ... open -> not observed` |
| An address appears in only one snapshot | `ADDRESS OBSERVATION`, not a device addition/removal claim |
| Supported explicit observations match | `No observed changes in explicit IPv4/TCP records.` |

A newly observed port is not proof that a service just started. A missing port is not proof of
closure. Grouped records and uncertain states do not become guessed open/closed results.
See the [comparison milestone](docs/compare-milestone.md) for boundaries and verification.

## Save a Markdown report

Create the output directory, then generate a report:

```bash
mkdir -p reports
uv run --offline watchpost compare examples/baseline.xml examples/after.xml \
  --confirm-same-context --output reports/review.md
```

Open `reports/review.md` in a text editor or Markdown viewer.
See [the synthetic sample report](examples/report.md) for the expected result.

Each report includes:

- Source paths, UTC scan windows, scan metadata, and user-confirmed assumptions.
- Separate counts for changed states, newly observed records, and records not observed later.
- Each finding's address, numeric TCP port ID where applicable, and earlier/later source evidence.
- Fixed-rule explanations and suggested checks. No AI verdicts or vulnerability scores.
- Evidence limitations and blank fields for investigation notes and conclusions.

**Existing files and notes are never overwritten.** If `reports/review.md` exists, choose a
new filename, such as `reports/review-02.md`. There is no force-overwrite option.
The same input paths and contents produce the same report content.

Validation finishes before any report is created. Watchpost writes a private temporary file,
then publishes the complete report with a non-replacing hard link. This also protects a destination
created by another writer. The output directory must exist and its filesystem must support hard links.
If it does not, the command fails instead of using an unsafe overwrite fallback.
This workflow targets Linux and Ubuntu WSL. Use a trusted output directory.

Keep the original XML files with your report. Reports reference the supplied files but do not embed
or authenticate them. Paths appear as escaped literals so filename markup stays plain text.
Review real reports before sharing: they contain network details and are not anonymous.
See [the reporting milestone](docs/reporting-milestone.md) for the safety checks and boundaries.

## Practice the three scenarios

Follow the [synthetic review walkthroughs](docs/scenarios.md). No live scan is required.

1. **Expected deployment:** compare an observed change with an approved lab deployment plan.
2. **Unintended backend exposure:** interpret the same evidence against a different access policy.
3. **Incomplete scan:** confirm that a reported host timeout prevents report creation.

The first two scenarios use the same XML pair deliberately. Watchpost reports evidence, not intent.
The walkthroughs supply fictional context and clearly labeled example review notes.

## How inspection works

1. Read the selected local file and reject inputs larger than 10 MiB.
2. Parse XML with entity expansion and external entities disabled.
3. Check the Nmap root, completion marker, TCP scan metadata, and explicit IPv4/TCP records.
4. Print addresses and ports in numerical order.

The command rejects malformed XML, unsupported encodings, failed scans, reported host timeouts,
UDP/IPv6 data, invalid addresses or ports, and duplicate observations.
Errors exit with code 2, without partial inventory output.

Only explicit `<port>` records are listed. This milestone does not expand grouped
`<extraports>` records, even when additional metadata is present. Hostnames, service names,
script output, and other free-text scan fields are not printed.

This is not full Nmap schema validation. `inspect` focuses on individual records;
`compare` adds the stronger metadata checks described above. Host status, service names,
script output, and grouped states are not compared. Matching metadata does not prove identical
scan conditions, and no-change output is not a safety verdict.

## Development

Python 3.11+ and [uv](https://docs.astral.sh/uv/) are required for these commands.
Dependency installation can need internet access. The application and tests run offline afterward.

```bash
uv sync --dev --python 3.11
uv run python -m unittest discover -s tests -v
uv run ruff format --check .
uv run ruff check .
```

The runtime uses `defusedxml` to reject XML entities instead of maintaining a custom XML parser.
The tests use the standard library's `unittest`. Pytest is an optional development runner.

## Data handling

- Only inspect data from networks you own or have permission to assess.
- All bundled XML examples and the sample report are synthetic and use documentation-only IP addresses.
- Keep real inputs in `scans/` and reports in `reports/`. Both directories are ignored by Git.
- Reports are not automatically anonymous. Review files before publishing them.
- Missing observations do not prove closed ports or removed devices.
- IP addresses are not device identities. Port numbers are not application identities.
- An observed change does not prove vulnerability or compromise.

## License

Watchpost is licensed under the [MIT License](LICENSE).
Third-party dependencies retain their own licenses.

## Roadmap

- [x] Safely inspect one saved IPv4/TCP scan.
- [x] Validate and compare two snapshots without inventing missing evidence.
- [x] Produce Markdown reports with evidence, limitations, and human review notes.
- [x] Document the three scenarios in the brief.

No dashboard, live scanning, scheduling, AI verdicts, or automatic remediation is planned in the v0.1 brief.
