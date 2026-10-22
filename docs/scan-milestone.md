# Scan milestone

Status: implemented after 0.0.2. Not yet in a published release.

## Scope change

The [v0.1 brief](brief-v0.1.md) ruled out scans and scheduling. After 0.0.2, the project owner
approved two opt-in exceptions for unattended use:

1. `watchpost scan` runs one fixed Nmap profile against targets the user lists.
2. `compare --exit-code` tells a script whether two snapshots differ.

Every other rule in the brief still applies. Watchpost still never schedules or repeats scans,
uploads data, or makes any other network request. `inspect`, `compare`, `history`, `verify`, and
the browser page stay offline. All process and network code lives in `watchpost_scan.py`, which only
the `scan` command loads.

## `watchpost scan`

```bash
mkdir -p scans
watchpost scan 192.0.2.10 192.0.2.32/28 --ports 22,80,443 --confirm-authorized
```

Watchpost runs exactly this command, with no shell:

```text
nmap -sT -Pn -n --no-stylesheet -p PORTS -oX - TARGETS
```

| Option | Why it is fixed |
|---|---|
| `-sT` | TCP connect scan. It works the same with or without administrator rights. |
| `-Pn` | No host discovery. Every listed address is scanned, however the scanner is privileged. |
| `-n` | No DNS lookups: no traffic to name servers, and no hostnames in the saved file. |
| `--no-stylesheet` | The saved file does not reference a local Nmap install path. |
| `-oX -` | XML goes to a private temporary file through standard output, never to a path Nmap opens. |

Users choose only the targets and ports, so every scan from the same command can be compared:

- **Targets** are IPv4 addresses or networks, such as `192.0.2.10` or `192.0.2.32/28`, at most 256
  addresses in total. Hostnames, IPv6, Nmap range syntax, host bits in a network, repeated or
  overlapping targets, and multicast, reserved, or unspecified addresses are refused.
- **`--ports`** is required and uses the coverage syntax, such as `22,80,443-445`. Repeats are
  refused. Watchpost passes the ports to Nmap as sorted ranges.
- **`--confirm-authorized`** is required. It records your statement that you are authorized to
  scan every target. Watchpost cannot check it.
- **`--output-dir`** must already exist. It defaults to `scans`, which Git ignores in this
  repository. `--nmap PATH` picks the Nmap executable when it is not on `PATH`.

Before starting Nmap, Watchpost prints the exact command. Nmap's own messages go to the terminal.
While Nmap runs, its XML goes to a private temporary file in the output directory. When Nmap
succeeds, the complete file is published with a non-replacing hard link as
`scan-YYYYMMDDTHHMMSSZ.xml`, named after the UTC time the command started. As with reports, an
existing file is never replaced, and the saved file is readable only by your account on Linux
and WSL. Nothing is saved when Nmap cannot start, is interrupted, exits with an error, or writes
nothing.

The command then runs the inspect pre-flight on the saved file and checks that it records a
connect scan of the requested ports, with no records for addresses you did not list. It prints the
file's SHA-256 hash, UTC window, scan metadata, and how many addresses have records. If the file
cannot be compared or does not match the request, for example because a host timed out, it stays
saved as evidence and the command exits 2 with the reason.

### Reading scan results

Because host discovery is off, every listed address is recorded as `up (user-set)`. That status
means Nmap was told to scan the address, not that a device answered. An address with nothing behind
it is still recorded, usually with its ports filtered. Watchpost shows those records as Nmap
classified them; they are not evidence that a device exists or does not.

### What scan never does

- Discover hosts, look up names, detect services, versions, or operating systems, or run scripts.
- Scan UDP or IPv6, or accept other Nmap options.
- Repeat itself, run in the background, or create a schedule.
- Upload anything. The XML stays where you saved it.

## Scheduling it yourself

Use one output directory per target and port list, so every file in it can be compared with the
others. File names sort in time order.

**A confirmation written into a schedule stands for every run.** That includes both
`--confirm-authorized` and `--confirm-same-context`. Re-check them whenever the targets, the
scanner's network location, or your authorization changes, and remove the schedule when the
authorization ends.

This script scans, then compares the two newest scans and saves a report:

```sh
#!/bin/sh
# Every confirmation below stands for each scheduled run. Re-check it whenever the targets,
# the scanner's network location, or your authorization changes.
set -eu
cd "$HOME/lab"
watchpost="$HOME/lab/.venv/bin/watchpost"
"$watchpost" scan 192.0.2.10 192.0.2.20 --ports 22,80,443,3000 --confirm-authorized \
  --output-dir scans/lab
set -- $(ls scans/lab/scan-*.xml | tail -n 2)
[ "$#" -eq 2 ] || exit 0
"$watchpost" compare "$1" "$2" --confirm-same-context --exit-code \
  --output "reports/lab-$(date -u +%Y%m%dT%H%M%SZ).md"
```

`scans/lab` and `reports` must exist. The script exits with compare's code, so a scheduler shows a
run with differences (1) or a refusal (2) as failed. The first run saves one scan and stops.

**cron.** Run it daily at 03:00 with `crontab -e`:

```text
0 3 * * * /home/you/lab/scan-and-compare.sh
```

Use absolute paths: cron starts with a minimal `PATH`. Keep `date` formats inside the script,
because cron treats `%` in a crontab line as a newline.

**systemd.** Save two user units in `~/.config/systemd/user/`:

```ini
# watchpost-lab.service
[Unit]
Description=Watchpost lab scan and comparison

[Service]
Type=oneshot
ExecStart=%h/lab/scan-and-compare.sh
```

```ini
# watchpost-lab.timer
[Unit]
Description=Daily Watchpost lab scan

[Timer]
OnCalendar=*-*-* 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

Enable the timer with `systemctl --user enable --now watchpost-lab.timer`. User timers run only
while you are logged in unless you enable lingering with `loginctl enable-linger`.

**Windows Task Scheduler.** In PowerShell:

```powershell
$lab = "$env:USERPROFILE\lab"
$scan = "scan 192.0.2.10 192.0.2.20 --ports 22,80,443,3000 --confirm-authorized"
$action = New-ScheduledTaskAction -Execute "$lab\.venv\Scripts\watchpost.exe" `
  -Argument "$scan --output-dir scans\lab" -WorkingDirectory $lab
$trigger = New-ScheduledTaskTrigger -Daily -At 3am
Register-ScheduledTask -TaskName "Watchpost lab scan" -Action $action -Trigger $trigger
```

Then follow the saved scans, earliest first:

```powershell
watchpost history (Get-ChildItem scans\lab\scan-*.xml).FullName --confirm-same-context
```

## `compare --exit-code`

With `--exit-code`, `compare` exits 1 when the snapshots differ in explicit records, which is the
same count as `Observation differences` in the summary and `total_differences` in JSON. It exits 0
when they do not. Expectation results, host status, reasons, and grouped counts do not change the
exit code, just as they never count as differences. Output, saved reports, and JSON are unchanged.

The flag does not replace review. It still requires `--confirm-same-context`, refusals still exit
2, and a difference is not proof of a problem.

| Exit code | Meaning |
|---|---|
| 0 | Success. With `--exit-code`, no differences in explicit records. |
| 1 | `verify` found differences, or `compare --exit-code` found differences. |
| 2 | Invalid input, a refusal, or a scan that failed or cannot be compared. |

## Verification

- `tests/test_scan.py` replaces Nmap with a fake runner, so no test starts a scan. It checks the
  exact argument list, target and port rules, required confirmation, the never-overwrite publish
  (including a competing writer), that failed, interrupted, and empty scans save nothing, that an
  unusable or mismatched scan stays saved and is named, that the offline commands never load the
  scan module, and every `--exit-code` outcome.
- Manual check on Windows 11 with Nmap 7.992: two loopback scans of ports 1 and 135 were saved and
  pre-flighted, compared with `--exit-code` (exit 0), and followed with `history`.
- The script above ran twice under WSL with a stand-in `nmap` that prints the synthetic examples.
  The first run saved one scan and exited 0. The second saved another, compared the pair, saved a
  report that `verify` accepts, and exited 1. `systemd-analyze verify` accepted both units.
