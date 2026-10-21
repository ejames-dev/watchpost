"""Inspect, compare, and report saved Nmap observations without network requests."""

import argparse
import hashlib
import io
import re
import tomllib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import IPv4Address
from itertools import groupby, pairwise, zip_longest
from pathlib import Path, PurePath, PurePosixPath
from typing import BinaryIO
from xml.etree.ElementTree import Element, ParseError

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from watchpost_report import (
    EXPECT_HEADING,
    NOTE_LABEL,
    evidence_lines,
    expectation_result,
    expectation_tally,
    render_json,
    render_markdown,
    write_report,
)

# Snapshots are streamed, so memory follows the number of explicit records, not the file size.
MAX_XML_MIB = 100
MAX_XML_BYTES = MAX_XML_MIB * 1024 * 1024
SIZE_ERROR = f"Snapshot exceeds the {MAX_XML_MIB} MiB limit. Use a smaller lab snapshot."
MAX_EXPECT_BYTES = 1024 * 1024
MAX_HISTORY = 50
PORT_STATES = {"open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered"}
HOST_STATES = {"up", "down", "unknown", "skipped"}
MAX_NOTE_CHARS = 500
# Labels appear inside Markdown code spans and table cells, so backticks and pipes are excluded.
LABEL_PATTERN = r"[\w .,;:()'/&+-]{1,120}"

# Address -> TCP port -> a value copied from that explicit <port> record.
PortRecords = dict[str, dict[int, str]]
# Address -> (status, reason) copied from the host's <status> record, when there is one.
HostStatus = dict[str, tuple[str, str | None]]
# Address -> Nmap state -> count from the host's grouped <extraports> records.
GroupedCounts = dict[str, dict[str, int]]
Records = tuple[PortRecords, PortRecords, HostStatus, GroupedCounts]
# The nmaprun element without its hosts, the records read from them, and the input's SHA-256.
Document = tuple[Element, Records, str]
# (report line number, report line, expected line); None marks a missing line.
Mismatch = tuple[int | None, str | None, str | None]


@dataclass(frozen=True)
class Snapshot:
    # A label for output: a local path, or a name supplied with in-memory XML.
    source: PurePath
    started: datetime
    finished: datetime
    method: str
    version: str
    coverage: frozenset[int]
    inventory: dict[str, dict[int, str]]
    # Evidence shown beside findings. It never changes how observations are compared.
    port_reasons: PortRecords = field(default_factory=dict)
    host_status: HostStatus = field(default_factory=dict)
    grouped_ports: GroupedCounts = field(default_factory=dict)
    # Identifies the exact input bytes. It does not prove who made the file, when, or where.
    sha256: str = ""


@dataclass(frozen=True)
class Change:
    address: str
    port: int | None
    before: str | None
    after: str | None


@dataclass(frozen=True)
class Expectation:
    """A reviewer's own statement about a later port state. Watchpost cannot verify it."""

    key: str
    address: str
    port: int
    states: tuple[str, ...]
    label: str | None


@dataclass(frozen=True)
class Expectations:
    source: PurePath
    sha256: str
    entries: tuple[Expectation, ...]


def _read_bytes(path: Path, kind: str = "Snapshot") -> bytes:
    """Read at most one byte past the size limit so oversized files are always rejected."""
    if not path.is_file():
        raise ValueError(f"{kind} must be an existing regular file. Check the input path.")
    with path.open("rb") as source:
        return source.read(MAX_XML_BYTES + 1)


def _read_document(path: Path) -> Document:
    """Stream a saved Nmap export from disk. The file is never held in memory whole."""
    if not path.is_file():
        raise ValueError("Snapshot must be an existing regular file. Check the input path.")
    if path.stat().st_size > MAX_XML_BYTES:
        raise ValueError(SIZE_ERROR)
    with path.open("rb") as source:
        return _parse_stream(source)


def _parse_bytes(data: bytes) -> Document:
    """Validate Nmap XML bytes already in memory with the same streaming parser."""
    if len(data) > MAX_XML_BYTES:
        raise ValueError(SIZE_ERROR)
    return _parse_stream(io.BytesIO(data))


class _HashingReader:
    """Hash bytes as the parser reads them, and stop once the size limit is passed."""

    def __init__(self, source: BinaryIO) -> None:
        self.source, self.size, self.digest = source, 0, hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        chunk = self.source.read(size)
        self.size += len(chunk)
        if self.size > MAX_XML_BYTES:
            raise ValueError(SIZE_ERROR)
        self.digest.update(chunk)
        return chunk


def _xml_events(reader: _HashingReader) -> Iterator[tuple[str, Element]]:
    """Parse with entities and external references refused, translating parser failures."""
    try:
        yield from ElementTree.iterparse(
            reader, events=("start", "end"), forbid_entities=True, forbid_external=True
        )
    except DefusedXmlException as exc:
        raise ValueError(
            "Unsafe XML. Entity declarations and external entities are not allowed."
        ) from exc
    except (ParseError, LookupError, ValueError) as exc:
        if reader.size > MAX_XML_BYTES:
            raise ValueError(SIZE_ERROR) from None
        raise ValueError(
            "Malformed XML or unsupported encoding. Use a complete UTF-8 Nmap export."
        ) from exc


def _parse_stream(source: BinaryIO) -> Document:
    """Validate a completed TCP Nmap export in one pass, keeping records instead of the tree.

    Each host element is dropped once its records are read. Errors keep the priority of a
    whole-document parse: malformed XML, then the document checks, then the first bad host.
    """
    reader = _HashingReader(source)
    records: Records = ({}, {}, {}, {})
    root: Element | None = None
    host_error: ValueError | None = None
    depth = 0
    for event, element in _xml_events(reader):
        if event == "start":
            depth += 1
            root = element if root is None else root
            continue
        depth -= 1
        if depth != 1 or root is None:
            continue
        # A direct child of the root is complete. Keep only the small metadata elements.
        if element.tag == "host" and host_error is None:
            try:
                _add_host(element, records)
            except ValueError as exc:
                host_error = exc
        if element.tag not in ("scaninfo", "runstats"):
            root.remove(element)

    if root is None or root.tag != "nmaprun" or root.get("scanner") != "nmap":
        raise ValueError("Expected an Nmap XML export with an nmaprun root.")
    finished = root.findall("runstats/finished")
    if len(finished) != 1 or finished[0].get("exit") != "success":
        raise ValueError("Scan is not confirmed complete. Use a successfully finished Nmap export.")
    scan_info = root.findall("scaninfo")
    if not scan_info or any(info.get("protocol") != "tcp" for info in scan_info):
        raise ValueError("Only scans with TCP scaninfo are supported. Use a TCP-only export.")
    if host_error is not None:
        raise host_error
    return root, records, reader.digest.hexdigest()


def _reason(element: Element, record: str) -> str | None:
    """Return Nmap's recorded reason token. Reasons are evidence, never classifications."""
    reason = element.get("reason")
    if reason is not None and not re.fullmatch(r"[a-z][a-z-]{0,39}", reason):
        raise ValueError(f"Unrecognized Nmap reason for {record}. Expected a token like syn-ack.")
    return reason


def _add_host(host: Element, records: Records) -> None:
    """Add one host's explicit port states, reasons, host status, and grouped counts."""
    inventory, port_reasons, host_status, grouped_ports = records
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
    # Counts only: grouped records are never expanded into per-port states.
    grouped = {}
    for record in host.findall("ports/extraports"):
        state, count = record.get("state", ""), record.get("count", "")
        if state not in PORT_STATES or state in grouped or not re.fullmatch(r"[0-9]{1,5}", count):
            raise ValueError(
                f"Unrecognized grouped port record for {address}. "
                "Expected one count for each recognized Nmap state."
            )
        grouped[state] = int(count)
    inventory[address] = ports
    port_reasons[address] = reasons
    grouped_ports[address] = grouped


def read_inventory(path: Path) -> dict[str, dict[int, str]]:
    """Read explicit IPv4/TCP observations. Do not expand aggregated port counts."""
    return _read_document(path)[1][0]


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
    return _snapshot_from_document(_read_document(path), path)


def parse_snapshot(data: bytes, source: PurePath) -> Snapshot:
    """Validate snapshot bytes already in memory; source is only a label for output."""
    return _snapshot_from_document(_parse_bytes(data), source)


def _snapshot_from_document(document: Document, source: PurePath) -> Snapshot:
    root, (inventory, port_reasons, host_status, grouped_ports), sha256 = document
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
        grouped_ports,
        sha256,
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


def history_timelines(
    snapshots: list[Snapshot], *, same_context_confirmed: bool = False
) -> list[tuple[str, list[str | None]]]:
    """Gate each consecutive pair, then list records whose explicit observations differ.

    Each timeline holds one value per snapshot; None means not observed, never closed.
    """
    if not same_context_confirmed:
        raise ValueError(
            "Confirm the same scan location, intended targets, and other scan settings."
        )
    if not 2 <= len(snapshots) <= MAX_HISTORY:
        raise ValueError(f"History needs 2 to {MAX_HISTORY} snapshots, earliest first.")
    for number, (earlier, later) in enumerate(pairwise(snapshots), 1):
        try:
            compare_snapshots(earlier, later, same_context_confirmed=True)
        except ValueError as exc:
            raise ValueError(f"Snapshots {number} and {number + 1}: {exc}") from exc
    timelines: list[tuple[str, list[str | None]]] = []
    addresses = set().union(*(snapshot.inventory for snapshot in snapshots))
    for address in sorted(addresses, key=IPv4Address):
        presence = ["observed" if address in snapshot.inventory else None for snapshot in snapshots]
        if len(set(presence)) > 1:
            timelines.append((address, presence))
        records = [snapshot.inventory.get(address, {}) for snapshot in snapshots]
        for port in sorted(set().union(*records)):
            states = [ports.get(port) for ports in records]
            if len(set(states)) > 1:
                timelines.append((f"{address}/tcp/{port}", states))
    return timelines


def _context_note(note: str | None) -> str | None:
    """Check the user's optional context note. Watchpost records it but cannot verify it."""
    if note is None:
        return None
    if not note.strip():
        raise ValueError("Context note is empty. Describe the scan context or leave it out.")
    if len(note) > MAX_NOTE_CHARS:
        raise ValueError(f"Context note is longer than {MAX_NOTE_CHARS} characters. Shorten it.")
    return note


def read_expectations(path: Path) -> Expectations:
    """Read the reviewer's own expected later port states from a TOML file."""
    return parse_expectations(_read_bytes(path, "Expectations file"), path)


def parse_expectations(data: bytes, source: Path) -> Expectations:
    """Validate expectations held in memory; source is only a label for output."""
    if len(data) > MAX_EXPECT_BYTES:
        raise ValueError("Expectations file exceeds the 1 MiB limit.")
    try:
        document = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"Expectations file is not valid UTF-8 TOML: {exc}") from exc
    tables = document.get("expect")
    if set(document) != {"expect"} or not isinstance(tables, dict) or not tables:
        raise ValueError(
            "Expectations file needs one or more "
            '[expect."ADDRESS/tcp/PORT"] tables and nothing else.'
        )
    entries = sorted(
        (_expectation(key, entry) for key, entry in tables.items()),
        key=lambda item: (IPv4Address(item.address), item.port),
    )
    return Expectations(source, hashlib.sha256(data).hexdigest(), tuple(entries))


def _expectation(key: str, entry: object) -> Expectation:
    # Canonical address and port only, so every key equals the finding key it describes.
    match = re.fullmatch(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})/tcp/(0|[1-9][0-9]{0,4})", key)
    try:
        valid = bool(match) and str(IPv4Address(match[1])) == match[1] and int(match[2]) < 65536
    except ValueError:
        valid = False
    if not valid:
        raise ValueError(f"Expectation key {key!a} must look like 192.0.2.10/tcp/3000.")
    if not isinstance(entry, dict) or "state" not in entry or set(entry) - {"state", "label"}:
        raise ValueError(f"Expectation {key} needs a state and may have a label, nothing else.")
    states = entry["state"] if isinstance(entry["state"], list) else [entry["state"]]
    if not states or not all(isinstance(state, str) and state in PORT_STATES for state in states):
        raise ValueError(
            f'Expectation {key} needs Nmap port states, such as "open" or ["closed", "filtered"].'
        )
    if len(set(states)) != len(states):
        raise ValueError(f"Expectation {key} lists the same state twice.")
    label = entry.get("label")
    if label is not None and not (
        isinstance(label, str) and label.strip() and re.fullmatch(LABEL_PATTERN, label)
    ):
        raise ValueError(
            f"Expectation {key} label must be 1 to 120 letters, digits, spaces, "
            "or . , ; : ( ) ' / & + - characters."
        )
    return Expectation(key, match[1], int(match[2]), tuple(sorted(states)), label)


def compare_report(
    before_xml: bytes,
    after_xml: bytes,
    *,
    before_name: str,
    after_name: str,
    same_context_confirmed: bool = False,
    context_note: str | None = None,
) -> str:
    """Return the Markdown report for two in-memory snapshots. No file or network access."""
    if not same_context_confirmed:
        raise ValueError(
            "Confirm the same scan location, intended targets, and other scan settings."
        )
    note = _context_note(context_note)
    # Names are labels, not local paths, so they read the same on every platform.
    before = parse_snapshot(before_xml, PurePosixPath(before_name))
    after = parse_snapshot(after_xml, PurePosixPath(after_name))
    changes = compare_snapshots(before, after, same_context_confirmed=same_context_confirmed)
    return render_markdown(before, after, changes, context_note=note)


def verify_report(
    report: Path, before: Path, after: Path, expect: Path | None = None
) -> list[Mismatch]:
    """Regenerate a saved report from its snapshots and list the evidence lines that differ."""
    data = _read_bytes(report, "Report")
    if len(data) > MAX_XML_BYTES:
        raise ValueError("Report exceeds the 10 MiB limit. Use a report saved by compare.")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("Report is not UTF-8 text. Use a report saved by compare.") from exc
    lines = text.splitlines()
    if EXPECT_HEADING in lines and expect is None:
        raise ValueError("This report records expectations. Pass the same file with --expect.")
    expectations = None if expect is None else read_expectations(expect)
    earlier, later = read_snapshot(before), read_snapshot(after)
    # The report already records the user's confirmation; verify makes no new comparison.
    changes = compare_snapshots(earlier, later, same_context_confirmed=True)
    # The note is a user label like the source paths, so only its presence is compared.
    note = "(not checked)" if NOTE_LABEL in lines else None
    expected = render_markdown(
        earlier, later, changes, context_note=note, expectations=expectations
    )
    problems: list[Mismatch] = []
    for found, wanted in zip_longest(evidence_lines(text), evidence_lines(expected)):
        number, line = found if found is not None else (None, None)
        expected_line = wanted[1] if wanted is not None else None
        if line != expected_line:
            problems.append((number, line, expected_line))
    return problems


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


def _grouped_text(counts: dict[str, int]) -> str:
    groups = (f"{count} grouped as {state}" for state, count in sorted(counts.items()))
    return "; ".join(groups) or "none"


def _grouped_side(snapshot: Snapshot, address: str) -> str:
    if address not in snapshot.inventory:
        return "not observed"
    return _grouped_text(snapshot.grouped_ports.get(address, {}))


def inspect_text(snapshot_xml: bytes, *, name: str) -> str:
    """Return the inspect output for one in-memory snapshot. No file or network access."""
    return _format_inspection(_parse_bytes(snapshot_xml), PurePosixPath(name))


def _format_inspection(document: Document, source: PurePath) -> str:
    _, (inventory, port_reasons, host_status, grouped_ports), _ = document
    lines = ["IPv4/TCP observations (not a security verdict)"]
    if not inventory:
        lines.append("No IPv4 host observations.")
    for address in sorted(inventory, key=IPv4Address):
        lines.append(f"{address}  host status: {_status_text(host_status, address)}")
        if grouped_ports[address]:
            lines.append(f"  {_grouped_text(grouped_ports[address])}, not listed individually")
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
        snapshot = _snapshot_from_document(document, source)
    except ValueError as exc:
        lines.append(f"  Ready to compare: no. {exc}")
    else:
        lines.extend(
            [
                f"  UTC window: {_window(snapshot)}",
                f"  Scan: TCP {snapshot.method}; Nmap {snapshot.version}; "
                f"{len(snapshot.coverage)} declared ports: {_port_ranges(snapshot.coverage)}",
                "  Ready to compare: yes. Comparing still checks the other file and needs you "
                "to confirm the scan context.",
            ]
        )
    return "\n".join(lines)


def _format_expectations(expectations: Expectations, after: Snapshot) -> list[str]:
    lines = [f"Expectations (your own statements, not verified): {str(expectations.source)!a}"]
    for item in expectations.entries:
        state = after.inventory.get(item.address, {}).get(item.port)
        reason = after.port_reasons.get(item.address, {}).get(item.port)
        later = "not observed" if state is None else _with_reason(state, reason)
        label = f" [{item.label}]" if item.label else ""
        lines.append(
            f"  {item.key}: expected {' or '.join(item.states)}; later {later} -> "
            f"{expectation_result(item, after)}{label}"
        )
    tally = expectation_tally(expectations, after)
    lines.append(
        f"Expectation results: matches {tally['matches']}; differs {tally['differs']}; "
        f"cannot be checked {tally['cannot be checked']}"
    )
    return lines


def _format_history(
    snapshots: list[Snapshot], timelines: list[tuple[str, list[str | None]]]
) -> str:
    first = snapshots[0]
    lines = ["Snapshot history (not a security verdict)"]
    for number, snapshot in enumerate(snapshots, 1):
        lines.extend([f"{number}: {str(snapshot.source)!a}", f"  UTC window: {_window(snapshot)}"])
    lines.extend(
        [
            f"Scan: TCP {first.method}; Nmap {first.version}; {len(first.coverage)} declared ports",
            "Context: same location, intended targets, and other settings confirmed by user.",
            f"Records with differences: {len(timelines)}",
        ]
    )
    if not timelines:
        lines.append("No observed changes in explicit IPv4/TCP records across the series.")
    for key, values in timelines:
        address, _, port = key.partition("/tcp/")
        steps = []
        for snapshot, value in zip(snapshots, values, strict=True):
            if value is None or not port:
                steps.append(value or "not observed")
            else:
                reason = snapshot.port_reasons.get(address, {}).get(int(port))
                steps.append(_with_reason(value, reason))
        lines.append(f"{key}: {' -> '.join(steps)}")
    lines.extend(
        [
            "Missing and grouped port records are not classified as closed.",
            "IP addresses are not device identities; port numbers are not application identities.",
            "Each step passed the same checks as compare. Compare a pair for host context.",
            "Context is user-confirmed, not independently verified by Watchpost.",
        ]
    )
    return "\n".join(lines)


def _format_comparison(
    before: Snapshot,
    after: Snapshot,
    changes: list[Change],
    note: str | None = None,
    expectations: Expectations | None = None,
) -> str:
    lines = [
        "Snapshot comparison (not a security verdict)",
        f"Earlier: {str(before.source)!a}",
        f"  UTC window: {_window(before)}",
        f"Later: {str(after.source)!a}",
        f"  UTC window: {_window(after)}",
        f"Scan: TCP {before.method}; Nmap {before.version}; {len(before.coverage)} declared ports",
        "Context: same location, intended targets, and other settings confirmed by user.",
    ]
    if note is not None:
        lines.append(f"Context note (user's statement, not verified): {note!a}")
    lines.append(f"Observation differences: {len(changes)}")
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
        if label == "PORT OBSERVATION":
            lines.append(
                f"  Grouped records: {_grouped_side(before, change.address)} -> "
                f"{_grouped_side(after, change.address)} (not evidence for this port)"
            )
    if expectations is not None:
        lines.extend(_format_expectations(expectations, after))
    lines.extend(
        [
            "Missing and grouped port records are not classified as closed.",
            "IP addresses are not device identities; port numbers are not application identities.",
            "Host status and reasons show how Nmap classified records, not why anything changed.",
            "Context is user-confirmed, not independently verified by Watchpost.",
        ]
    )
    if expectations is not None:
        lines.append("A match is not a safety verdict, and a difference is not proof of a problem.")
    return "\n".join(lines)


def _printable(text: str | None) -> str:
    """Escape terminal controls in report text while keeping ordinary punctuation readable."""
    if text is None:
        return "(nothing)"
    return "".join(char if char.isprintable() else ascii(char)[1:-1] for char in text)


def _format_verification(problems: list[Mismatch]) -> str:
    if not problems:
        return "\n".join(
            [
                "Report evidence matches both snapshots.",
                "Checked: SHA-256 hashes, scan metadata, counts, findings, and fixed wording.",
                "Not checked: source path labels, the context note, and human review fields.",
                "Matching hashes identify the files, not who made them, when, or where.",
            ]
        )
    lines = ["Report evidence does not match these snapshots."]
    for number, found, wanted in problems[:5]:
        lines.extend(
            [
                f"  Line {number}:" if number is not None else "  After the last line:",
                f"    found:    {_printable(found)}",
                f"    expected: {_printable(wanted)}",
            ]
        )
    hidden = len(problems) - 5
    if hidden > 0:
        lines.append(f"  ...and {hidden} more difference{'s' if hidden > 1 else ''}")
    return "\n".join(lines)


def _run_compare(args: argparse.Namespace) -> int:
    note = _context_note(args.context_note)
    expectations = None if args.expect is None else read_expectations(args.expect)
    before, after = read_snapshot(args.before), read_snapshot(args.after)
    changes = compare_snapshots(before, after, same_context_confirmed=args.confirm_same_context)
    options = {"context_note": note, "expectations": expectations}
    if args.format == "json":
        content = render_json(before, after, changes, **options)
    elif args.output is not None:
        content = render_markdown(before, after, changes, **options)
    else:
        print(_format_comparison(before, after, changes, note, expectations))
        return 0
    if args.output is None:
        print(content, end="")
    else:
        write_report(args.output, content)
        print(f"Report saved to {str(args.output)!a}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="watchpost",
        description="Inspect and compare saved Nmap XML locally. No scans or network requests.",
        epilog="Exit codes: 0 success; 1 verify found differences; 2 invalid input or refusal.",
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
        "--output", type=Path, help="Save the report to a new file; never overwrite."
    )
    compare.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="text prints a summary or saves Markdown with --output; json prints or saves JSON.",
    )
    compare.add_argument(
        "--context-note",
        metavar="TEXT",
        help="Record your own description of the scan context. Watchpost cannot verify it.",
    )
    compare.add_argument(
        "--expect",
        type=Path,
        metavar="FILE",
        help="TOML file of your own expected later port states, compared with explicit records.",
    )
    history = commands.add_parser(
        "history", help="Follow explicit observations across a series of saved scans."
    )
    history.add_argument(
        "snapshots", type=Path, nargs="+", help="Completed Nmap XML exports, earliest first."
    )
    history.add_argument(
        "--confirm-same-context",
        action="store_true",
        required=True,
        help="Confirm every scan used the same location, intended targets, and Nmap settings.",
    )
    verify = commands.add_parser(
        "verify", help="Check a saved report against the two snapshots it was made from."
    )
    verify.add_argument("report", type=Path, help="Markdown report saved by compare --output.")
    verify.add_argument("before", type=Path, help="Earlier Nmap XML export used for the report.")
    verify.add_argument("after", type=Path, help="Later Nmap XML export used for the report.")
    verify.add_argument(
        "--expect", type=Path, metavar="FILE", help="The expectations file the report used."
    )
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            problems = verify_report(args.report, args.before, args.after, args.expect)
            print(_format_verification(problems))
            return 1 if problems else 0
        if args.command == "history":
            if not 2 <= len(args.snapshots) <= MAX_HISTORY:
                raise ValueError(f"History needs 2 to {MAX_HISTORY} snapshots, earliest first.")
            snapshots = [read_snapshot(path) for path in args.snapshots]
            timelines = history_timelines(
                snapshots, same_context_confirmed=args.confirm_same_context
            )
            print(_format_history(snapshots, timelines))
            return 0
        if args.command == "compare":
            return _run_compare(args)
        inspection = _format_inspection(_read_document(args.snapshot), args.snapshot)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"watchpost: error: {exc}\n")

    print(inspection)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
