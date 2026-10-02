"""Inspect saved Nmap observations without scanning or making network requests."""

import argparse
from ipaddress import IPv4Address
from pathlib import Path
from xml.etree.ElementTree import ParseError

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

# ponytail: cap snapshots at 10 MiB for small labs; stream if larger inputs are needed.
MAX_XML_BYTES = 10 * 1024 * 1024
PORT_STATES = {"open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered"}


def read_inventory(path: Path) -> dict[str, dict[int, str]]:
    """Read explicit IPv4/TCP observations. Do not expand aggregated port counts."""
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="watchpost",
        description="Inspect saved Nmap XML locally. No scans or network requests.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser(
        "inspect", help="List explicit IPv4/TCP observations in one scan."
    )
    inspect.add_argument("snapshot", type=Path, help="Path to a completed Nmap XML export.")
    args = parser.parse_args(argv)
    try:
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
