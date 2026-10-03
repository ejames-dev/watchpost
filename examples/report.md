# Watchpost change review

> Observations, not a security verdict. Changes do not prove vulnerability or compromise.

## Comparison context

- Context: same location, intended targets, and other settings confirmed by user.
- Watchpost checked completion, timestamps, Nmap version, scan method, and port coverage.
- Matching metadata does not independently establish matching scan conditions.

### Earlier snapshot

Source path (escaped literal):

    'examples/baseline.xml'

- UTC start: `2026-01-01T00:00:00+00:00`
- UTC finish: `2026-01-01T00:00:01+00:00`
- Nmap version: `7.95`
- Scan method: TCP `connect`
- Declared TCP ports: 4
- IPv4 address records: 2
- Explicit TCP port records: 5

### Later snapshot

Source path (escaped literal):

    'examples/after.xml'

- UTC start: `2026-01-01T00:01:00+00:00`
- UTC finish: `2026-01-01T00:01:01+00:00`
- Nmap version: `7.95`
- Scan method: TCP `connect`
- Declared TCP ports: 4
- IPv4 address records: 2
- Explicit TCP port records: 5

## Summary

Total observation differences: **1**

| Observation category | Count |
|---|---:|
| Port state changed | 1 |
| Port newly observed | 0 |
| Port not observed later | 0 |
| Address newly observed | 0 |
| Address not observed later | 0 |

Address and port differences are counted separately, not as distinct incidents or devices.

## Findings

Source names below refer to the Earlier and Later snapshot sections above. Port evidence is the explicit XML state for the listed IPv4 address and numeric TCP port ID. Address evidence records presence only, not host status or device identity.

`not observed` means no explicit record in the parsed inventory; it is not an Nmap state.

### 1. Port state changed

- **Record:** IPv4 `192.0.2.10`, TCP port `3000` (numeric ID)
- **Earlier evidence:** `closed` — Earlier snapshot
- **Later evidence:** `open` — Later snapshot

**Explanation:** Both scans contain explicit states, and the later scan reports this port as open. This does not identify the application or prove Internet exposure or compromise.

**Suggested check:** Check expected service changes, listening interfaces, and firewall rules. Confirm the intended result from the authorized scan location.

**Investigation notes:**

**Conclusion:**

## Limitations

- Missing and grouped port records are not classified as closed.
- IP addresses are not device identities; port numbers are not application identities.
- Filtered and uncertain states are preserved, not treated as confirmed open or closed.
- Host status, hostnames, service names, scripts, and grouped states are not compared.
- These are scan-window observations, not proof of when or why a change happened.
- User confirmation is not independently verified by Watchpost.
- Keep the original XML files with this report; references do not embed or authenticate them.
- Reports contain network details and are not anonymous. Review before sharing.

## Human review

**Reviewer:**

**Reviewed at (UTC):**

**Overall investigation notes:**

**Overall conclusion:**
