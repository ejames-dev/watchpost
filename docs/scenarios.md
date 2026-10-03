# Three synthetic review walkthroughs

Use these exercises to practice the workflow in the [v0.1 brief](brief-v0.1.md).
Validate saved evidence. Read the changes. Then record a human interpretation.
No exercise launches a scan or changes a network.

All addresses, scan times, deployment plans, and review notes here are fictional.
The XML files use RFC 5737 documentation addresses. They are not real scan results.

## Before you start

Complete the [README setup](../README.md#try-the-synthetic-demo).
Run all commands from the repository root on Linux or Ubuntu WSL.
Create a directory for your reports:

```bash
mkdir -p reports
```

The commands run offline after dependency installation. Nmap is not required.
For repeat runs, choose new output filenames. Watchpost never overwrites existing reports or notes.

Each exercise assumes the same scan location, intended targets, and remaining settings within its scan pair.
The `--confirm-same-context` flag records that assumption. It never bypasses metadata checks.
For real inputs, confirm those conditions before you use the flag.

| File | Role |
|---|---|
| [baseline.xml](../examples/baseline.xml) | Earlier completed scan, 2026-01-01 at 00:00:00–00:00:01 UTC |
| [after.xml](../examples/after.xml) | Later completed scan, 00:01:00–00:01:01 UTC |
| [incomplete.xml](../examples/incomplete.xml) | Alternative later scan with a reported host timeout |

All three declare Nmap 7.95, TCP connect scanning, and ports 22, 80, 443, and 3000.
Those matching fields alone do not make the incomplete file suitable for comparison.

## 1. Expected deployment

### Fictional context

An approved lab change permits users to reach a demo application on TCP port 3000 at `192.0.2.10`.
The scanner sits in the lab's users segment. Both snapshots use that location.
The deployment plan supplies the application role. Watchpost cannot infer it from port 3000.
The exercise assumes that separate asset records confirm the address assignment.

### Generate and read the report

```bash
uv run --offline watchpost compare examples/baseline.xml examples/after.xml \
  --confirm-same-context --output reports/expected-deployment.md
```

Expected exit code: **0**. Open `reports/expected-deployment.md` in a text editor.
The report matches the [bundled sample](../examples/report.md).

| Report field | Expected evidence |
|---|---|
| Total observation differences | 1 |
| Port state changed | 1 |
| All other observation categories | 0 |
| Record | IPv4 `192.0.2.10`, TCP port `3000` |
| Earlier evidence | `closed` |
| Later evidence | `open` |

Both values come from explicit `<port>` records, not grouped counts.
The report does not say when the change happened or which process caused it.

### Review the finding

1. Compare the finding with the approved deployment plan and permitted source networks.
2. Confirm the address assignment in the lab inventory.
3. Check the application's listening interface and the applicable firewall rules.
4. Record the evidence and unresolved questions in the report's investigation fields.

**Example notes — fictional exercise only:**

> The deployment plan permits TCP 3000 from the users segment at this address.
> The later open observation matches that intended change.
> The application identity comes from the plan, not the port number.

**Example conclusion:**

> Consistent with the expected deployment from this scan location.
> Confirm the listening interface and firewall scope before closing the review.
> This is not a verdict that the application or network is secure.

## 2. Unintended backend exposure

### Alternative fictional context

This exercise deliberately reuses the same XML pair with a different deployment policy.
The backend at `192.0.2.10` must accept only local connections behind a reverse proxy.
Users must not connect directly to TCP port 3000. The scanner sits in the users segment.
The policy supplies the backend role and access restriction. Neither fact comes from the XML.
The exercise again assumes separately confirmed address assignments and matching scan conditions.

### Generate and read the report

```bash
uv run --offline watchpost compare examples/baseline.xml examples/after.xml \
  --confirm-same-context --output reports/backend-exposure.md
```

Expected exit code: **0**. Open `reports/backend-exposure.md`.
The evidence and generated report content are identical to scenario 1, before you add notes.
The report does not contain an automatic "unintended exposure" classification.

### Review the finding

1. Compare the later `open` observation with the policy that prohibits direct backend access.
2. Confirm the host's address assignment and the scanner's network location.
3. Check listening interfaces, container port publishing, and host/network firewall rules.
4. Record the discrepancy without guessing its cause.
5. Refer any correction to the lab owner through the approved change process.

**Example notes — fictional exercise only:**

> The policy allows backend access only through the local reverse proxy.
> The later snapshot reports TCP 3000 open from the users segment, contrary to that policy.
> The cause is unknown. Listening interfaces, container publishing, and firewall rules need review.

**Example conclusion:**

> Unexpected backend exposure from the stated lab scan location requires investigation.
> The snapshots do not prove Internet exposure, a vulnerable application, or compromise.

Watchpost does not apply firewall changes or close ports.
After an authorized correction, a separate completed scan can supply new evidence.
Keep the original snapshots and review notes. Use a new report filename for the follow-up.

**Lesson from scenarios 1 and 2:** the evidence stays the same, but the intended access policy changes the human interpretation.

## 3. Incomplete scan

### Fictional context

The alternative later file contains `timedout="true"` for `192.0.2.10` and no ports for that host.
It still contains observations for `192.0.2.20` and a successful run-finish marker.
A finished run does not guarantee that every host scan completed.

### Attempt the report

Use a fresh output filename. Run these commands in Bash:

```bash
uv run --offline watchpost compare examples/baseline.xml examples/incomplete.xml \
  --confirm-same-context --output reports/incomplete-review.md
printf 'Exit code: %s\n' "$?"
test ! -e reports/incomplete-review.md && echo 'No report created'
```

Expected error on stderr:

```text
watchpost: error: Host scan is incomplete (timeout). Use a completed snapshot.
```

Expected shell checks:

```text
Exit code: 2
No report created
```

There is no comparison output and no partial Markdown report.
The host timeout invalidates the input even though its other metadata matches the baseline.

### Handle the failed comparison

1. Keep the incomplete XML as evidence of the failed attempt.
2. Record the timeout in separate investigation notes, not as a port closure.
3. Investigate the scan interruption and host reachability within your authorized lab.
4. Obtain a completed export before another comparison.
5. Reconfirm the scan context and use a new report filename.

**Example note — fictional exercise only:**

> Comparison refused because the later snapshot reports a host timeout.
> No conclusion about port closures is supported. A completed scan is required.

Do not remove the timeout marker or change it to make the file pass validation.
Watchpost also rejects malformed/truncated XML and scans without a successful completion marker.

### Incomplete scan versus missing observation

These are different cases:

- **Reported timeout or failed/incomplete export:** Watchpost refuses the input and creates no report.
- **Valid completed export without an explicit port record:** Watchpost uses `not observed` for the missing side of a difference.

For example, an earlier explicit `open` record without a later explicit record becomes `open → not observed`, never `open → closed`.
Grouped `<extraports>` counts do not supply explicit per-port evidence.
The existing comparison and report tests cover that distinction.

## Verify the walkthroughs

Run the regression checks:

```bash
uv run --offline python -m unittest discover -s tests -v
uv run --offline ruff format --check .
uv run --offline ruff check .
```

The tests check the sample report against generated bytes and confirm that the incomplete fixture creates no report.
They also cover missing observations, incompatible inputs, and protection of existing notes.

For real reviews, keep input XML and reports local unless you have approval to share them.
Reports contain network details and are not automatically anonymous.
