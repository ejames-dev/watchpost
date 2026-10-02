"""Inspect saved Nmap observations without scanning or making network requests."""

import argparse
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path
from xml.etree.ElementTree import Element, ParseError

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

# ponytail: cap snapshots at 10 MiB for small labs; stream if larger inputs are needed.
MAX_XML_BYTES = 10 * 1024 * 1024
PORT_STATES = {"open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered"}


@dataclass(frozen=True)
class Snapshot:
    source: Path
    started: datetime
    finished: datetime
    method: str
    version: str
    coverage: frozenset[int]
    inventory: dict[str, dict[int, str]]


@dataclass(frozen=True)
class Change:
    address: str
    port: int | None
    before: str | None
    after: str | None


def _read_root(path: Path) -> Element:
    """Safely load a completed TCP Nmap export without resolving external content."""
    if not path.is_file():
        raise ValueError("Snapshot must be an existing regular file. Check the input path.")
    with path.open("rb") as source:
        data = source.read(MAX_XML_BYTES + 1)
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


def _inventory_from_xml(root: Element) -> dict[str, dict[int, str]]:
    inventory = {}
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

        ports = {}
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
        inventory[address] = ports
    return inventory


def read_inventory(path: Path) -> dict[str, dict[int, str]]:
    """Read explicit IPv4/TCP observations. Do not expand aggregated port counts."""
    return _inventory_from_xml(_read_root(path))


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


def read_snapshot(path: Path) -> Snapshot:
    """Read the stronger metadata needed for a conservative comparison."""
    root = _read_root(path)
    inventory = _inventory_from_xml(root)
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
    if not re.fullmatch(r"[0-9]{1,5}", count) or int(count) != len(coverage):
        raise ValueError("Declared TCP port count does not match the port coverage.")
    for ports in inventory.values():
        if not set(ports).issubset(coverage):
            raise ValueError("Explicit port observations fall outside the declared TCP coverage.")
    return Snapshot(path, started, finished, scans[0].attrib["type"], version, coverage, inventory)


def compare_snapshots(
    before: Snapshot, after: Snapshot, *, same_context_confirmed: bool = False
) -> list[Change]:
    """Compare supported observations; None means not observed, never closed."""
    if not same_context_confirmed:
        raise ValueError(
            "Confirm the same scan location, intended targets, and other scan settings."
        )
    if before.method != after.method:
        raise ValueError("Scan methods differ. Compare snapshots from the same scan method.")
    if before.version != after.version:
        raise ValueError("Nmap versions differ. Compare snapshots from the same Nmap version.")
    if before.coverage != after.coverage:
        raise ValueError(
            "TCP port coverage differs. Compare snapshots with identical port coverage."
        )
    if after.started < before.started:
        raise ValueError("Snapshots are reversed. Supply the earlier scan first.")
    repeat_observations = (
        before.started == after.started
        and before.finished == after.finished
        and before.inventory == after.inventory
    )
    if after.started < before.finished and not repeat_observations:
        raise ValueError("Scan windows overlap. Use non-overlapping earlier and later scans.")

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


def _format_comparison(before: Snapshot, after: Snapshot, changes: list[Change]) -> str:
    lines = [
        "Snapshot comparison (not a security verdict)",
        f"Earlier: {str(before.source)!a}",
        f"  UTC window: {before.started.isoformat()} -> {before.finished.isoformat()}",
        f"Later: {str(after.source)!a}",
        f"  UTC window: {after.started.isoformat()} -> {after.finished.isoformat()}",
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
            f"{label} {target}: {change.before or 'not observed'} -> "
            f"{change.after or 'not observed'}"
        )
    lines.extend(
        [
            "Missing and grouped port records are not classified as closed.",
            "IP addresses are not device identities; port numbers are not application identities.",
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
    args = parser.parse_args(argv)
    try:
        if args.command == "compare":
            before, after = read_snapshot(args.before), read_snapshot(args.after)
            changes = compare_snapshots(
                before, after, same_context_confirmed=args.confirm_same_context
            )
            print(_format_comparison(before, after, changes))
            return 0
        inventory = read_inventory(args.snapshot)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"watchpost: error: {exc}\n")

    print("IPv4/TCP observations (not a security verdict)")
    if not inventory:
        print("No IPv4 host observations.")
    for address in sorted(inventory, key=IPv4Address):
        print(address)
        ports = inventory[address]
        if not ports:
            print("  No explicit TCP port observations.")
        for number, state in sorted(ports.items()):
            print(f"  {number}/tcp  {state}")
    print("Only explicit port observations are listed; missing ports are not classified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
