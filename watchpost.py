"""Inspect, compare, and report saved Nmap observations without network requests."""

import argparse
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import IPv4Address
from itertools import groupby
from pathlib import Path
from xml.etree.ElementTree import Element, ParseError

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from watchpost_report import render_markdown, write_report

# ponytail: cap snapshots at 10 MiB for small labs; stream if larger inputs are needed.
MAX_XML_BYTES = 10 * 1024 * 1024
PORT_STATES = {"open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered"}
HOST_STATES = {"up", "down", "unknown", "skipped"}

# Address -> TCP port -> a value copied from that explicit <port> record.
PortRecords = dict[str, dict[int, str]]
# Address -> (status, reason) copied from the host's <status> record, when there is one.
HostStatus = dict[str, tuple[str, str | None]]


@dataclass(frozen=True)
class Snapshot:
    source: Path
    started: datetime
    finished: datetime
    method: str
    version: str
    coverage: frozenset[int]
    inventory: dict[str, dict[int, str]]
    # Evidence shown beside findings. It never changes how observations are compared.
    port_reasons: PortRecords = field(default_factory=dict)
    host_status: HostStatus = field(default_factory=dict)


@dataclass(frozen=True)
class Change:
    address: str
    port: int | None
    before: str | None
    after: str | None


def _read_root(path: Path) -> Element:
    """Safely load a completed TCP Nmap export file without resolving external content."""
    if not path.is_file():
        raise ValueError("Snapshot must be an existing regular file. Check the input path.")
    with path.open("rb") as source:
        return _parse_root(source.read(MAX_XML_BYTES + 1))


def _parse_root(data: bytes) -> Element:
    """Safely parse completed TCP Nmap XML bytes without resolving external content."""
    if len(data) > MAX_XML_BYTES:
        raise ValueError("Snapshot exceeds the 10 MiB limit. Use a smaller lab snapshot.")
    try:
        root = ElementTree.fromstring(data, forbid_entities=True, forbid_external=True)
    except DefusedXmlException as exc:
        raise ValueError(
            "Unsafe XML. Entity declarations and external entities are not allowed."
        ) from exc
    except (ParseError, LookupError, ValueError) as exc:
        raise ValueError(
            "Malformed XML or unsupported encoding. Use a complete UTF-8 Nmap export."
        ) from exc

    if root.tag != "nmaprun" or root.get("scanner") != "nmap":
        raise ValueError("Expected an Nmap XML export with an nmaprun root.")
    finished = root.findall("runstats/finished")
    if len(finished) != 1 or finished[0].get("exit") != "success":
        raise ValueError("Scan is not confirmed complete. Use a successfully finished Nmap export.")
    scan_info = root.findall("scaninfo")
    if not scan_info or any(info.get("protocol") != "tcp" for info in scan_info):
        raise ValueError("Only scans with TCP scaninfo are supported. Use a TCP-only export.")

    return root


def _reason(element: Element, record: str) -> str | None:
    """Return Nmap's recorded reason token. Reasons are evidence, never classifications."""
    reason = element.get("reason")
    if reason is not None and not re.fullmatch(r"[a-z][a-z-]{0,39}", reason):
        raise ValueError(f"Unrecognized Nmap reason for {record}. Expected a token like syn-ack.")
    return reason


def _records_from_xml(root: Element) -> tuple[PortRecords, PortRecords, HostStatus]:
    """Read explicit port states, plus the reasons and host status Nmap recorded with them."""
    inventory: PortRecords = {}
    port_reasons: PortRecords = {}
    host_status: HostStatus = {}
    for host in root.findall("host"):
        if host.get("timedout") not in (None, "false", "0"):
            raise ValueError("Host scan is incomplete (timeout). Use a completed snapshot.")
        if host.find("address[@addrtype='ipv6']") is not None:
            raise ValueError("Only IPv4 addresses are supported. Use an IPv4-only export.")
        addresses = host.findall("address[@addrtype='ipv4']")
        if len(addresses) != 1:
            raise ValueError("Each host must have exactly one IPv4 address.")
        try:
            address = str(IPv4Address(addresses[0].get("addr", "")))
        except ValueError as exc:
            raise ValueError("Invalid IPv4 address. Check the host address in the export.") from exc
        if address in inventory:
            raise ValueError(f"Duplicate IPv4 host {address}. Use an unambiguous snapshot.")
        statuses = host.findall("status")
        if len(statuses) > 1 or any(status.get("state") not in HOST_STATES for status in statuses):
            raise ValueError(
                f"Host {address} must have at most one status: up, down, unknown, or skipped."
            )
        if statuses:
            reason = _reason(statuses[0], f"host {address}")
            host_status[address] = (statuses[0].attrib["state"], reason)

        ports, reasons = {}, {}
        for port in host.findall("ports/port"):
            if port.get("protocol") != "tcp":
                raise ValueError("Only TCP port observations are supported.")
            port_id = port.get("portid", "")
            if not port_id.isascii() or not port_id.isdecimal() or len(port_id) > 5:
                raise ValueError("Invalid TCP port number. Expected a number from 0 to 65535.")
            number = int(port_id)
            if number > 65535:
                raise ValueError("Invalid TCP port number. Expected a number from 0 to 65535.")
            if number in ports:
                raise ValueError(f"Duplicate TCP port {number} for {address}.")
            states = port.findall("state")
            if len(states) != 1 or states[0].get("state") not in PORT_STATES:
                raise ValueError("Each explicit port must have one recognized Nmap port state.")
            ports[number] = states[0].attrib["state"]
            reason = _reason(states[0], f"{address} {number}/tcp")
            if reason is not None:
                reasons[number] = reason
        inventory[address] = ports
        port_reasons[address] = reasons
    return inventory, port_reasons, host_status


def read_inventory(path: Path) -> dict[str, dict[int, str]]:
    """Read explicit IPv4/TCP observations. Do not expand aggregated port counts."""
    return _records_from_xml(_read_root(path))[0]


def _scan_time(value: str) -> datetime:
    if not re.fullmatch(r"[0-9]{1,12}", value):
        raise ValueError("Comparison requires valid Unix start and finish timestamps.")
    try:
        return datetime.fromtimestamp(int(value), UTC)
    except (ValueError, OverflowError, OSError) as exc:
        raise ValueError("Scan timestamp is outside the supported calendar range.") from exc


def _port_coverage(services: str) -> frozenset[int]:
    ports: set[int] = set()
    for token in services.split(","):
        if not re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?", token):
            raise ValueError(
                "Invalid TCP coverage. Expected ports or ranges such as 22,80,443-445."
            )
        bounds = [int(value) for value in token.split("-")]
        first, last = bounds[0], bounds[-1]
        if first > last or last > 65535:
            raise ValueError("Invalid TCP coverage range. Ports must be between 0 and 65535.")
        for number in range(first, last + 1):
            if number in ports:
                raise ValueError("Duplicate or overlapping ports in declared TCP coverage.")
            ports.add(number)
    return frozenset(ports)


def _port_ranges(ports: Iterable[int], limit: int = 10) -> str:
    """Name ports as numeric ranges such as 22, 80, 443-445, listing at most `limit` ranges."""
    ranges = []
    for _, run in groupby(enumerate(sorted(ports)), key=lambda item: item[1] - item[0]):
        numbers = [number for _, number in run]
        ranges.append(str(numbers[0]) if len(numbers) == 1 else f"{numbers[0]}-{numbers[-1]}")
    hidden = len(ranges) - limit
    if hidden > 0:
        return ", ".join(ranges[:limit]) + f", and {hidden} more range{'s' if hidden > 1 else ''}"
    return ", ".join(ranges)


def read_snapshot(path: Path) -> Snapshot:
    """Read the stronger metadata needed for a conservative comparison."""
    return _snapshot_from_root(_read_root(path), path)


def parse_snapshot(data: bytes, source: Path) -> Snapshot:
    """Validate snapshot bytes already in memory; source is only a label for output."""
    return _snapshot_from_root(_parse_root(data), source)


def _snapshot_from_root(root: Element, source: Path) -> Snapshot:
    inventory, port_reasons, host_status = _records_from_xml(root)
    scans = root.findall("scaninfo")
    if len(scans) != 1 or scans[0].get("type") not in {"connect", "syn"}:
        raise ValueError("Comparison supports exactly one TCP connect or SYN scan per snapshot.")
    version = root.get("version", "")
    if not re.fullmatch(r"[0-9][A-Za-z0-9._+-]{0,63}", version):
        raise ValueError("Comparison requires a valid Nmap version in each snapshot.")
    started = _scan_time(root.get("start", ""))
    finished = _scan_time(root.findall("runstats/finished")[0].get("time", ""))
    if finished < started:
        raise ValueError(
            "Scan finish time is before its start time. Check the snapshot timestamps."
        )
    coverage = _port_coverage(scans[0].get("services", ""))
    count = scans[0].get("numservices", "")
    if not re.fullmatch(r"[0-9]{1,5}", count):
        raise ValueError(
            "Declared TCP port count is missing or invalid. Check the scaninfo numservices value."
        )
    if int(count) != len(coverage):
        raise ValueError(
            f"Declared TCP port count ({int(count)}) does not match the port coverage "
            f"({len(coverage)} ports)."
        )
    for address, ports in inventory.items():
        outside = ports.keys() - coverage
        if outside:
            raise ValueError(
                f"Explicit observations for {address} fall outside the declared TCP coverage: "
                f"{_port_ranges(outside)}."
            )
    return Snapshot(
        source,
        started,
        finished,
        scans[0].attrib["type"],
        version,
        coverage,
        inventory,
        port_reasons,
        host_status,
    )


def compare_snapshots(
    before: Snapshot, after: Snapshot, *, same_context_confirmed: bool = False
) -> list[Change]:
    """Compare supported observations; None means not observed, never closed."""
    if not same_context_confirmed:
        raise ValueError(
            "Confirm the same scan location, intended targets, and other scan settings."
        )
    if before.method != after.method:
        raise ValueError(
            f"Scan methods differ: earlier {before.method}, later {after.method}. "
            "Compare snapshots from the same scan method."
        )
    if before.version != after.version:
        raise ValueError(
            f"Nmap versions differ: earlier {before.version}, later {after.version}. "
            "Compare snapshots from the same Nmap version."
        )
    if before.coverage != after.coverage:
        only = (
            f"only the {label} scan covers {_port_ranges(ports)}"
            for label, ports in (
                ("earlier", before.coverage - after.coverage),
                ("later", after.coverage - before.coverage),
            )
            if ports
        )
        raise ValueError(
            f"TCP port coverage differs: {'; '.join(only)}. "
            "Compare snapshots with identical port coverage."
        )
    if after.started < before.started:
        raise ValueError(
            f"Snapshots are reversed: the first file starts {before.started.isoformat()} "
            f"and the second starts {after.started.isoformat()}. Supply the earlier scan first."
        )
    repeat_observations = (
        before.started == after.started
        and before.finished == after.finished
        and before.inventory == after.inventory
    )
    if after.started < before.finished and not repeat_observations:
        raise ValueError(
            f"Scan windows overlap: earlier {_window(before)}, later {_window(after)}. "
            "Use non-overlapping earlier and later scans."
        )

    changes = []
    for address in sorted(before.inventory.keys() | after.inventory.keys(), key=IPv4Address):
        if (address in before.inventory) != (address in after.inventory):
            changes.append(
                Change(
                    address,
                    None,
                    "observed" if address in before.inventory else None,
                    "observed" if address in after.inventory else None,
                )
            )
        old_ports = before.inventory.get(address, {})
        new_ports = after.inventory.get(address, {})
        for port in sorted(old_ports.keys() | new_ports.keys()):
            old_state, new_state = old_ports.get(port), new_ports.get(port)
            if old_state != new_state:
                changes.append(Change(address, port, old_state, new_state))
    return changes


def compare_report(
    before_xml: bytes,
    after_xml: bytes,
    *,
    before_name: str,
    after_name: str,
    same_context_confirmed: bool = False,
) -> str:
    """Return the Markdown report for two in-memory snapshots. No file or network access."""
    if not same_context_confirmed:
        raise ValueError(
            "Confirm the same scan location, intended targets, and other scan settings."
        )
    before = parse_snapshot(before_xml, Path(before_name))
    after = parse_snapshot(after_xml, Path(after_name))
    changes = compare_snapshots(before, after, same_context_confirmed=same_context_confirmed)
    return render_markdown(before, after, changes)


def _window(snapshot: Snapshot) -> str:
    return f"{snapshot.started.isoformat()} -> {snapshot.finished.isoformat()}"


def _with_reason(value: str, reason: str | None) -> str:
    return f"{value} ({reason or 'no reason recorded'})"


def _status_text(host_status: HostStatus, address: str) -> str:
    return _with_reason(*host_status[address]) if address in host_status else "not recorded"


def _evidence_text(snapshot: Snapshot, change: Change, value: str | None) -> str:
    """Describe one side of a difference. Absence stays not observed, never closed."""
    if value is None:
        return "not observed"
    if change.port is None:
        return value
    return _with_reason(value, snapshot.port_reasons.get(change.address, {}).get(change.port))


def _host_text(snapshot: Snapshot, address: str) -> str:
    if address not in snapshot.inventory:
        return "not observed"
    return _status_text(snapshot.host_status, address)


def _format_inspection(root: Element, source: Path) -> str:
    inventory, port_reasons, host_status = _records_from_xml(root)
    lines = ["IPv4/TCP observations (not a security verdict)"]
    if not inventory:
        lines.append("No IPv4 host observations.")
    for address in sorted(inventory, key=IPv4Address):
        lines.append(f"{address}  host status: {_status_text(host_status, address)}")
        ports, reasons = inventory[address], port_reasons[address]
        if not ports:
            lines.append("  No explicit TCP port observations.")
        for number, state in sorted(ports.items()):
            lines.append(f"  {number}/tcp  {_with_reason(state, reasons.get(number))}")
    lines.extend(
        [
            "Only explicit port observations are listed; missing ports are not classified.",
            "Host status and reasons are shown as Nmap recorded them, not as verdicts.",
            "Comparison pre-flight (this file only):",
        ]
    )
    # The records above already passed, so any failure here is comparison metadata.
    try:
        snapshot = _snapshot_from_root(root, source)
    except ValueError as exc:
        lines.append(f"  Ready to compare: no. {exc}")
    else:
        lines.extend(
            [
                f"  UTC window: {_window(snapshot)}",
                f"  Scan: TCP {snapshot.method}; Nmap {snapshot.version}; "
                f"{len(snapshot.coverage)} declared ports: {_port_ranges(snapshot.coverage)}",
                "  Ready to compare: yes. compare also checks the other file and requires "
                "--confirm-same-context.",
            ]
        )
    return "\n".join(lines)


def _format_comparison(before: Snapshot, after: Snapshot, changes: list[Change]) -> str:
    lines = [
        "Snapshot comparison (not a security verdict)",
        f"Earlier: {str(before.source)!a}",
        f"  UTC window: {_window(before)}",
        f"Later: {str(after.source)!a}",
        f"  UTC window: {_window(after)}",
        f"Scan: TCP {before.method}; Nmap {before.version}; {len(before.coverage)} declared ports",
        "Context: same location, intended targets, and other settings confirmed by user.",
        f"Observation differences: {len(changes)}",
    ]
    if not changes:
        lines.append("No observed changes in explicit IPv4/TCP records.")
    for change in changes:
        target = change.address
        if change.port is None:
            label = "ADDRESS OBSERVATION"
        else:
            target += f" {change.port}/tcp"
            label = (
                "STATE CHANGE"
                if change.before is not None and change.after is not None
                else "PORT OBSERVATION"
            )
        lines.append(
            f"{label} {target}: {_evidence_text(before, change, change.before)} -> "
            f"{_evidence_text(after, change, change.after)}"
        )
        lines.append(
            f"  Host status: {_host_text(before, change.address)} -> "
            f"{_host_text(after, change.address)}"
        )
    lines.extend(
        [
            "Missing and grouped port records are not classified as closed.",
            "IP addresses are not device identities; port numbers are not application identities.",
            "Host status and reasons show how Nmap classified records, not why anything changed.",
            "Context is user-confirmed, not independently verified by Watchpost.",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="watchpost",
        description="Inspect and compare saved Nmap XML locally. No scans or network requests.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser(
        "inspect", help="List explicit IPv4/TCP observations in one scan."
    )
    inspect.add_argument("snapshot", type=Path, help="Path to a completed Nmap XML export.")
    compare = commands.add_parser("compare", help="Compare two saved IPv4/TCP scans.")
    compare.add_argument("before", type=Path, help="Earlier completed Nmap XML export.")
    compare.add_argument("after", type=Path, help="Later completed Nmap XML export.")
    compare.add_argument(
        "--confirm-same-context",
        action="store_true",
        required=True,
        help="Confirm the same scan location, intended targets, and other Nmap settings.",
    )
    compare.add_argument(
        "--output", type=Path, help="Save a Markdown report to a new file; never overwrite."
    )
    args = parser.parse_args(argv)
    try:
        if args.command == "compare":
            before, after = read_snapshot(args.before), read_snapshot(args.after)
            changes = compare_snapshots(
                before, after, same_context_confirmed=args.confirm_same_context
            )
            if args.output is None:
                print(_format_comparison(before, after, changes))
            else:
                write_report(args.output, render_markdown(before, after, changes))
                print(f"Report saved to {str(args.output)!a}")
            return 0
        inspection = _format_inspection(_read_root(args.snapshot), args.snapshot)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"watchpost: error: {exc}\n")

    print(inspection)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
