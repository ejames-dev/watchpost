"""Run Watchpost's one fixed Nmap profile and save its XML as a new file.

This is the only module that starts a process or causes network traffic. It runs only when the
user types or schedules `watchpost scan`; Watchpost never repeats or schedules scans itself.
"""

import os
import shutil
import subprocess
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import BinaryIO

MAX_SCAN_ADDRESSES = 256
# Fixed so that saved scans stay comparable. Users choose targets and ports, nothing else.
# -sT: TCP connect scan, the same with or without administrator rights.
# -Pn --disable-arp-ping: no host discovery, not even Nmap's implicit ARP on a local network, so
# every listed address is scanned and recorded the same way however the scanner is privileged.
# -n: no DNS lookups, so no traffic to name servers and no hostnames in the saved file.
# --no-stylesheet: no reference to a local Nmap install path in the saved file.
NMAP_PROFILE = ("-sT", "-Pn", "--disable-arp-ping", "-n", "--no-stylesheet")


def scan_targets(values: list[str]) -> list[str]:
    """Accept explicit IPv4 addresses and networks only, so nothing depends on DNS."""
    addresses: set[IPv4Address] = set()
    targets = []
    for value in values:
        try:
            network = IPv4Network(value)
        except ValueError as exc:
            raise ValueError(
                f"Scan target {value!a} must be an IPv4 address or network, "
                "such as 192.0.2.10 or 192.0.2.0/28. Hostnames are not accepted."
            ) from exc
        first = network.network_address
        if first.is_multicast or first.is_reserved or first.is_unspecified:
            raise ValueError(
                f"Scan target {value!a} is a multicast, reserved, or unspecified address."
            )
        if len(addresses) + network.num_addresses > MAX_SCAN_ADDRESSES:
            raise ValueError(
                f"Scan targets cover more than {MAX_SCAN_ADDRESSES} addresses. "
                "List fewer addresses or a smaller network."
            )
        listed = set(network)
        if listed & addresses:
            raise ValueError(f"Scan target {value!a} repeats or overlaps another target.")
        addresses |= listed
        targets.append(str(first) if network.prefixlen == 32 else network.with_prefixlen)
    return targets


def nmap_command(nmap: str, targets: list[str], port_ranges: list[str]) -> list[str]:
    """Build the fixed argument list. Nmap writes XML to standard output, never to a path."""
    return [nmap, *NMAP_PROFILE, "-p", ",".join(port_ranges), "-oX", "-", *targets]


def find_nmap(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise ValueError(f"Nmap was not found as {name!a}. Install Nmap or pass --nmap PATH.")
    return path


def check_destination(destination: Path) -> None:
    """Refuse before scanning when the result could not be saved as a new file."""
    if not destination.parent.is_dir():
        raise ValueError(
            f"Scan output directory does not exist: {str(destination.parent)!a}. Create it first."
        )
    if os.path.lexists(destination):
        raise _exists(destination)


def run_scan(command: list[str], destination: Path) -> None:
    """Run Nmap once and publish its XML as a new file without replacing any existing file.

    Nothing is saved if Nmap cannot start, is interrupted, exits with an error, or writes nothing.
    """
    check_destination(destination)
    try:
        with NamedTemporaryFile(dir=destination.parent, prefix=".watchpost-") as temporary:
            _run_nmap(command, temporary)
            if os.fstat(temporary.fileno()).st_size == 0:
                raise ValueError("Nmap wrote no XML. Nothing was saved.")
            os.fsync(temporary.fileno())
            # Unlike replace/rename, link refuses even a concurrently created destination.
            os.link(temporary.name, destination)
    except FileExistsError as exc:
        raise _exists(destination) from exc
    except OSError as exc:
        raise ValueError(
            f"Cannot save scan to {str(destination)!a}: "
            f"{exc.strerror or 'file operation failed'}. "
            "Use an existing, writable directory on a filesystem that supports hard links."
        ) from exc


def _run_nmap(command: list[str], output: BinaryIO) -> None:
    # A list of arguments and no shell: targets and ports are validated values, never parsed.
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output, check=False)
    except KeyboardInterrupt:
        raise ValueError("Scan interrupted. Nothing was saved.") from None
    except OSError as exc:
        raise ValueError(f"Cannot start Nmap: {exc.strerror or exc}.") from exc
    if result.returncode != 0:
        raise ValueError(
            f"Nmap exited with code {result.returncode}. Nothing was saved. "
            "See Nmap's message above."
        )


def _exists(destination: Path) -> ValueError:
    return ValueError(
        f"Scan destination already exists: {str(destination)!a}. "
        "Existing files are never overwritten; wait a second or use another --output-dir."
    )
