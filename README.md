# Watchpost

Local-first, evidence-backed reviews of changes between saved Nmap scans.

**Status: first milestone implemented — inspect one saved scan.** The v0.1 target is two XML
files in and one understandable Markdown report out. Comparison and report generation are
not implemented yet. This is not a completed v0.1 release.

## Scope

Watchpost is for students and home-lab operators working on authorized networks.
The first milestone reads one saved Nmap XML file and lists explicit IPv4/TCP observations.
It does not launch Nmap, discover devices, or make network requests.

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

## How the first milestone works

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

This is not full Nmap schema validation. Checks for cross-snapshot coverage, timestamps,
scan location, and comparison compatibility belong to the next milestone.

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
- `examples/baseline.xml` is synthetic and uses documentation-only IP addresses.
- Keep real inputs in `scans/` and reports in `reports/`. Both directories are ignored by Git.
- Reports are not automatically anonymous. Review files before publishing them.
- Missing observations do not prove closed ports or removed devices.
- IP addresses are not device identities. Port numbers are not application identities.
- An observed change does not prove vulnerability or compromise.

## Roadmap

- [x] Safely inspect one saved IPv4/TCP scan.
- [ ] Validate and compare two snapshots without inventing missing evidence.
- [ ] Produce Markdown reports with evidence, limitations, and human review notes.
- [ ] Document the three scenarios in the brief.

No dashboard, live scanning, scheduling, AI verdicts, or automatic remediation is planned for v0.1.
