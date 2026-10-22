# Watchpost

Local-first, evidence-backed reviews of changes between saved Nmap scans.

**Status: inspection, comparison, Markdown reporting, synthetic walkthroughs, and an opt-in scan
command implemented.**
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

Published versions are listed on [PyPI](https://pypi.org/project/watchpost-cli/).
With Python 3.11+, install the latest one into a virtual environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install watchpost-cli
.venv/bin/watchpost --help
```

A source checkout can include changes that are not published yet; see the
[changelog](CHANGELOG.md). The package does not include the synthetic example files.
To run the demos below, use a source checkout.

## Browser version

**Try it: <https://getwatchpost.dev>**
No install needed. Use only scans of networks you are authorized to assess.

`web/` builds a static page that runs the same comparison and inspection in the browser with
[Pyodide](https://pyodide.org/). Scan files stay in the browser tab: everything is served
from one origin, and a content security policy blocks requests to other sites.
The page can load the synthetic examples, and after the first visit it also works offline.
It deploys to Cloudflare as an assets-only Worker. See [the browser build guide](docs/web.md).

## Scope

Watchpost is for students and home-lab operators working on authorized networks.
Inspect a saved Nmap XML file or compare snapshots of explicit IPv4/TCP observations.
`inspect`, `compare`, `history`, and `verify` read files you already saved and make no network
requests. The browser version only loads its own code from the site that serves it.
Watchpost never sends scan data anywhere.

One command is different: the opt-in `watchpost scan` runs Nmap once, with one fixed TCP connect
profile, against IPv4 targets you list and confirm you are authorized to scan. It never runs on
its own. See [Run a scan](#run-a-scan-optional).

The approved target is in [the v0.1 project brief](docs/brief-v0.1.md). The
[scan milestone](docs/scan-milestone.md) records the one later change to the brief's rules.

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
192.0.2.10  host status: up (user-set)
  22/tcp  open (syn-ack)
  80/tcp  closed (conn-refused)
  443/tcp  open (syn-ack)
  3000/tcp  closed (conn-refused)
192.0.2.20  host status: up (user-set)
  3 grouped as closed, not listed individually
  22/tcp  open (syn-ack)
Only explicit port observations are listed; missing ports are not classified.
Host status and reasons are shown as Nmap recorded them, not as verdicts.
Comparison pre-flight (this file only):
  UTC window: 2026-01-01T00:00:00+00:00 -> 2026-01-01T00:00:01+00:00
  Scan: TCP connect; Nmap 7.95; 4 declared ports: 22, 80, 443, 3000
  Ready to compare: yes. Comparing still checks the other file and needs you to confirm the scan context.
```

Nmap is not required. These addresses and states are fictional.
For an existing checkout, run the final two commands from its root directory.

Each address shows the host status Nmap recorded, and each port shows Nmap's recorded reason.
The pre-flight runs the comparison checks that need only this file, so you can catch an
unsuitable snapshot before comparing. A failed pre-flight prints `Ready to compare: no` with
the reason; `inspect` still lists the records and exits 0.

## Compare two snapshots

```bash
uv run --offline watchpost compare examples/baseline.xml examples/after.xml \
  --confirm-same-context
```

The synthetic second scan is one minute later. Its only explicit state change is:

```text
STATE CHANGE 192.0.2.10 3000/tcp: closed (conn-refused) -> open (syn-ack)
  Host status: up (user-set) -> up (user-set)
```

The output includes both source paths, UTC scan windows, Nmap version, scan method,
declared port count, differences with Nmap's recorded reasons and host status, and limitations.
Without `--output`, the command prints only to the terminal.

**Before using real inputs, confirm the same scan location, intended targets, and remaining
Nmap settings.** The flag records your confirmation. It does not let Watchpost verify the
network location, reconstruct the full command line, or override failed metadata checks.
Do not use it to force a comparison you know is incompatible.

To record what you confirmed, add `--context-note "scanner on the users VLAN"` (up to 500
characters). Watchpost prints and saves the note as an escaped literal. It stays your own
statement, which Watchpost cannot verify.

Comparison currently requires:

- One TCP connect or SYN scan per snapshot, with the same method and Nmap version.
- Identical declared TCP port coverage. Equivalent lists and ranges are normalized.
- A declared port count that matches that coverage, with all explicit ports inside it.
- Successful scan completion and valid start/end timestamps.
- Earlier and later scan windows that do not overlap. Equal windows with identical supported
  observations are allowed, so comparing a snapshot with itself produces no observed changes.

When a requirement fails, the error names what differs, such as both Nmap versions, the ports
that only one scan covers, or both scan windows.

| Evidence | Output |
|---|---|
| Explicit states differ | `STATE CHANGE ... closed (conn-refused) -> open (syn-ack)` |
| A port has no earlier explicit record | `PORT OBSERVATION ... not observed -> open (syn-ack)` |
| A port has no later explicit record | `PORT OBSERVATION ... open (syn-ack) -> not observed` |
| An address appears in only one snapshot | `ADDRESS OBSERVATION`, not a device addition/removal claim |
| Supported explicit observations match | `No observed changes in explicit IPv4/TCP records.` |

Each difference is followed by a `Host status:` line, such as `up (user-set) -> down (no-response)`.
Reasons and host status are copied from the XML as evidence. They never turn a missing record into
a closure, and a change in them alone is not counted as a difference.

A port observation also gets a `Grouped records:` line with the host's grouped `<extraports>`
counts in each snapshot, such as `none -> 3 grouped as closed`. Watchpost never expands those
counts into per-port states, so they are context for the reviewer, not evidence for that port.

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

- Source paths, each input file's SHA-256 hash, UTC scan windows, scan metadata, and
  user-confirmed assumptions, including your context note if you gave one.
- Separate counts for changed states, newly observed records, and records not observed later.
- A stable key for each finding, such as `192.0.2.10/tcp/3000`, for referring to it across reports.
- Each finding's address, numeric TCP port ID where applicable, earlier/later source evidence with
  Nmap's recorded reasons, and the host status recorded in each snapshot.
- Grouped port counts beside findings for ports without an explicit record, labeled as context.
- Fixed-rule explanations and suggested checks. No AI verdicts or vulnerability scores.
- With `--expect`, your own expected later states and whether each explicit record matches.
- Evidence limitations and blank fields for investigation notes and conclusions.

**Existing files and notes are never overwritten.** If `reports/review.md` exists, choose a
new filename, such as `reports/review-02.md`. There is no force-overwrite option.
The same input paths and contents produce the same report content.

Validation finishes before any report is created. Watchpost writes a private temporary file,
then publishes the complete report with a non-replacing hard link. This also protects a destination
created by another writer. The output directory must exist and its filesystem must support hard links.
If it does not, the command fails instead of using an unsafe overwrite fallback.
Use a trusted output directory.

### Platforms

Linux and Ubuntu WSL are the main targets. Native Windows also runs the full test suite in CI,
with two differences:

- Watchpost makes saved reports readable only by your account (mode `0600`) on Linux and WSL.
  Windows ignores that mode, so the output folder's permissions decide who can read a report.
  For private reports on Windows, save them in a folder only you can open, or use WSL.
- Paths appear as Windows spells them, such as `'examples\\baseline.xml'`. The rest of a report
  is byte-for-byte the same on every platform.

The repository checks out text files with LF line endings on every platform.

Keep the original XML files with your report. Reports record each file's SHA-256 hash but do not
embed the files. Paths appear as escaped literals so filename markup stays plain text.
Review real reports before sharing: they contain network details and are not anonymous.
See [the reporting milestone](docs/reporting-milestone.md) for the safety checks and boundaries.

## Verify a saved report

Check that a report still matches the two snapshots it was made from:

```bash
uv run --offline watchpost verify reports/review.md examples/baseline.xml examples/after.xml
```

`verify` regenerates the report from the snapshots and compares every generated line: the SHA-256
hashes, scan metadata, counts, findings, and fixed wording. It skips the source path labels, the
context note, and the review fields, so a report still verifies after you fill in your notes.
Keep notes inside those fields.

Exit code 0 means the evidence matches. Exit code 1 lists the lines that differ. Exit code 2 means an
input could not be used, for example because the snapshots are given in the wrong order.
A matching hash identifies the exact files. It does not prove who created them, when, or where.

## Record your expectations

Write your own expected later port states in a TOML file:

```toml
[expect."192.0.2.10/tcp/3000"]
state = "open"
label = "Demo app approved in the lab deployment plan"

[expect."192.0.2.20/tcp/3000"]
state = ["closed", "filtered"]
```

Then pass it to `compare`:

```bash
uv run --offline watchpost compare examples/baseline.xml examples/after.xml \
  --confirm-same-context --expect examples/expected-deployment.toml
```

Each expectation is checked against the later snapshot's explicit record. The result is
`matches`, `differs`, or `cannot be checked` when there is no explicit later record or the later
scan did not cover the port. Absence never matches `closed`, and grouped counts never count as a
record. Expectations and labels are your own statements: a match is not a safety verdict, and a
difference is not proof of a problem.

Reports add a "Your expectations" section with the file's SHA-256 hash, and `verify` needs the
same file through `--expect`. See the [expectations milestone](docs/expectations-milestone.md).

## Follow a series of snapshots

```bash
uv run --offline watchpost history examples/baseline.xml examples/after.xml \
  examples/rollback.xml --confirm-same-context
```

```text
192.0.2.10/tcp/3000: closed (conn-refused) -> open (syn-ack) -> closed (conn-refused)
```

`history` takes 2 to 50 saved snapshots, earliest first, and checks every consecutive pair with
the same rules as `compare`. A refusal names the pair. It prints one timeline for each record
whose explicit observations differ anywhere in the series, with `not observed` wherever a snapshot
has no record. There is no scheduling or database: you supply files you already saved.

## JSON output

Add `--format json` to `compare` to print the same evidence as JSON, or save it with `--output`.
Saved files follow the same never-overwrite rule as reports.

Each finding has its key, category, address, port, and both sides' records with reasons, host
status, and grouped counts, plus the fixed explanation and suggested check. A side without an
explicit record has `"record": "not observed"`, never `null`, so scripts cannot mistake absence
for a closed port. The document also carries the notice, scan metadata with SHA-256 hashes, your
context note and expectations, and the limitations.

## Run a scan (optional)

`watchpost scan` needs [Nmap](https://nmap.org/) and runs it once:

```bash
mkdir -p scans
uv run watchpost scan 192.0.2.10 192.0.2.32/28 --ports 22,80,443 --confirm-authorized
```

Watchpost runs `nmap -sT -Pn -n --no-stylesheet -p PORTS -oX - TARGETS` and nothing else. You
choose only the targets and ports, so scans from the same command can be compared. Targets must be
IPv4 addresses or networks, at most 256 addresses in total. Hostnames are refused, so nothing
depends on DNS. `--ports` is required, and `--confirm-authorized` records that you are authorized
to scan every target. Watchpost cannot check that.

The XML is saved as a new file such as `scans/scan-20261022T142857Z.xml`, the same
never-overwrite way as reports. Use `--output-dir` for another existing directory. Nothing is
saved if Nmap fails or is interrupted. The command then pre-flights the new file like `inspect`
and checks that it records the requested ports and addresses. If the file cannot be compared or
does not match, it stays saved and the command exits 2 with the reason.

Host discovery is off, so every listed address is recorded as `up (user-set)`. That status means
Nmap was told to scan the address, not that a device answered.

### Scheduling and scripts

Watchpost never schedules or repeats scans. To scan regularly, use your own scheduler: the
[scan milestone](docs/scan-milestone.md) has cron, systemd, and Windows Task Scheduler examples.
Keep one output directory per target and port list, so every file in it can be compared.

In a script, `compare --exit-code` exits 1 when the snapshots differ in explicit records and 0 when
they do not. It still requires `--confirm-same-context`, and refusals still exit 2.

**A confirmation written into a schedule or script stands for every run.** Re-check it whenever
the targets, the scanner's network location, or your authorization changes.

| Exit code | Meaning |
|---|---|
| 0 | Success. With `--exit-code`, no differences in explicit records. |
| 1 | `verify` found differences, or `compare --exit-code` found differences. |
| 2 | Invalid input, a refusal, or a scan that failed or cannot be compared. |

## Practice the three scenarios

Follow the [synthetic review walkthroughs](docs/scenarios.md). No live scan is required.

1. **Expected deployment:** compare an observed change with an approved lab deployment plan.
2. **Unintended backend exposure:** interpret the same evidence against a different access policy.
3. **Incomplete scan:** confirm that a reported host timeout prevents report creation.

The first two scenarios use the same XML pair deliberately. Watchpost reports evidence, not intent.
The walkthroughs supply fictional context and clearly labeled example review notes.

## How inspection works

1. Read the selected local file and reject inputs larger than 100 MiB.
2. Parse XML in one streaming pass with entity expansion and external entities disabled.
   Each host's elements are dropped once its records are read, so memory follows the number of
   explicit records rather than the size of the file.
3. Check the Nmap root, completion marker, TCP scan metadata, and explicit IPv4/TCP records.
4. Print addresses and ports in numerical order, with recorded host status, reasons, and
   grouped counts.
5. Run the comparison checks that need only this file, and print the result as a pre-flight.

The command rejects malformed XML, unsupported encodings, failed scans, reported host timeouts,
UDP/IPv6 data, invalid addresses or ports, duplicate observations, and malformed host status,
reason, or grouped records. Errors exit with code 2, without partial inventory output.

Only explicit `<port>` records are listed individually. Grouped `<extraports>` records appear only
as counts per state, even when additional metadata names their ports. Hostnames, service names,
script output, and other free-text scan fields are not printed. Host status and reasons are
printed only as simple Nmap tokens, such as `up` or `syn-ack`.

This is not full Nmap schema validation. The pre-flight covers single-file metadata; `compare`
adds the checks that need both files and your confirmation. Host status and grouped counts are
shown but not compared. Service names and script output are not compared. Matching metadata
does not prove identical scan conditions, and no-change output is not a safety verdict.

## Development

Python 3.11+ and [uv](https://docs.astral.sh/uv/) are required for these commands.
Dependency installation can need internet access. The tests and every command except `scan` run
offline afterward.

```bash
uv sync --dev --python 3.11
uv run python -m unittest discover -s tests -v
uv run ruff format --check .
uv run ruff check .
```

The runtime uses `defusedxml` to reject XML entities instead of maintaining a custom XML parser.
The tests use the standard library's `unittest`. Pytest is an optional development runner.

## Data handling

- Only scan or inspect networks you own or have permission to assess.
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

Beyond the v0.1 brief:

- [x] Run comparisons in the browser without uploading scans. The CLI still needs no account
  or cloud service; the hosted page needs only the static site that serves it.
- [x] Show recorded host status and reasons as evidence, name the values behind refused
  comparisons, and pre-flight single snapshots with `inspect`.
- [x] Show grouped counts as host context, record an optional context note, and tie reports to
  their input files with SHA-256 hashes, finding keys, and `watchpost verify`.
- [x] Check reviewer-written expectations, follow a series of snapshots with `history`, and print
  or save comparisons as JSON.
- [x] Run one fixed, opt-in Nmap profile with `watchpost scan`, and report differences to scripts
  with `compare --exit-code`. Scheduling stays with your own tools.
