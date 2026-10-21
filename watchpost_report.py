"""Deterministic Markdown for validated comparisons; no scanning or network access."""

from __future__ import annotations

import os
import re
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from watchpost import Change, Snapshot

# Each label introduces an indented, escaped literal: text the user supplied, never markup.
SOURCE_LABEL = "Source path (escaped literal):"
NOTE_LABEL = "User's context note (escaped literal, not verified by Watchpost):"
# Reviewers fill these in after generation, so verification skips their contents.
REVIEW_FIELDS = ("**Investigation notes:**", "**Conclusion:**")


def finding_key(change: Change) -> str:
    """Name a finding by its evidence, so notes can refer to it across reports."""
    return change.address if change.port is None else f"{change.address}/tcp/{change.port}"


def _with_reason(value: str, reason: str | None) -> str:
    return f"`{value}`, " + (f"reason `{reason}`" if reason else "no reason recorded")


def _evidence(snapshot: Snapshot, change: Change, value: str | None) -> str:
    """Quote one side of a difference. Absence stays `not observed`, never closed."""
    if value is None:
        return "`not observed`"
    if change.port is None:
        return f"`{value}`"
    return _with_reason(value, snapshot.port_reasons.get(change.address, {}).get(change.port))


def _host_status(snapshot: Snapshot, address: str) -> str:
    if address not in snapshot.inventory:
        return "`not observed`"
    if address not in snapshot.host_status:
        return "status not recorded"
    return _with_reason(*snapshot.host_status[address])


def _grouped(snapshot: Snapshot, address: str) -> str:
    if address not in snapshot.inventory:
        return "`not observed`"
    counts = sorted(snapshot.grouped_ports.get(address, {}).items())
    return "; ".join(f"{count} grouped as `{state}`" for state, count in counts) or "none"


def _finding_text(change: Change) -> tuple[str, str, str]:
    """Return a category, explanation, and suggested human check."""
    if change.port is None:
        return (
            "Address newly observed" if change.before is None else "Address not observed later",
            "This address has a record in only one snapshot. This does not prove a device "
            "was added or removed, or that the same device held this address in both scans. "
            "A record alone does not show that the host responded; see its host status.",
            "Confirm target scope, address assignments, host availability, and scan reachability.",
        )
    if change.before is None:
        return (
            "Port newly observed",
            "There is no earlier explicit port record. The later state is observed, but the "
            "earlier state is unknown. This is not proof that a service just started.",
            "Review earlier grouped or omitted records and confirm whether the later "
            "service and exposure are expected from the scan location.",
        )
    if change.after is None:
        return (
            "Port not observed later",
            "There is no later explicit port record. Absence is not a confirmed closure, "
            "even if the later XML contains grouped closed-port counts.",
            "Check the host status, grouped records, and scan conditions before "
            "concluding that the port closed.",
        )
    if change.after == "open":
        explanation = (
            "Both scans contain explicit states, and the later scan reports this port as open. "
            "This does not identify the application or prove Internet exposure or compromise."
        )
    elif change.after == "closed":
        explanation = (
            "Both scans contain explicit states, and the later scan reports this port as closed. "
            "This observation does not prove it is inaccessible from every network location."
        )
    else:
        explanation = (
            "Both scans contain explicit states, but the later state does not establish open "
            "or closed. Filtered and uncertain states must not be relabeled as either."
        )
    return (
        "Port state changed",
        explanation,
        "Check expected service changes, listening interfaces, and firewall rules. "
        "Confirm the intended result from the authorized scan location.",
    )


def _source_section(label: str, snapshot: Snapshot) -> list[str]:
    # Indentation makes all filename markup literal; ascii escapes controls and newlines.
    return [
        f"### {label} snapshot",
        "",
        SOURCE_LABEL,
        "",
        f"    {str(snapshot.source)!a}",
        "",
        f"- SHA-256: `{snapshot.sha256}`",
        f"- UTC start: `{snapshot.started.isoformat()}`",
        f"- UTC finish: `{snapshot.finished.isoformat()}`",
        f"- Nmap version: `{snapshot.version}`",
        f"- Scan method: TCP `{snapshot.method}`",
        f"- Declared TCP ports: {len(snapshot.coverage)}",
        f"- IPv4 address records: {len(snapshot.inventory)}",
        f"- Explicit TCP port records: {sum(len(ports) for ports in snapshot.inventory.values())}",
        "",
    ]


def render_markdown(
    before: Snapshot,
    after: Snapshot,
    changes: list[Change],
    *,
    context_note: str | None = None,
) -> str:
    """Render read_snapshot/compare_snapshots results after the comparison gate passes."""
    note = [] if context_note is None else [NOTE_LABEL, "", f"    {context_note!a}", ""]
    counts = dict.fromkeys(
        (
            "Port state changed",
            "Port newly observed",
            "Port not observed later",
            "Address newly observed",
            "Address not observed later",
        ),
        0,
    )
    findings = []
    for number, change in enumerate(changes, 1):
        category, explanation, check = _finding_text(change)
        counts[category] += 1
        record = f"IPv4 `{change.address}`"
        if change.port is not None:
            record += f", TCP port `{change.port}` (numeric ID)"
        evidence = [
            f"- **Key:** `{finding_key(change)}`",
            f"- **Record:** {record}",
            f"- **Earlier evidence:** {_evidence(before, change, change.before)} "
            "— Earlier snapshot",
            f"- **Later evidence:** {_evidence(after, change, change.after)} — Later snapshot",
            f"- **Host status:** Earlier {_host_status(before, change.address)}; "
            f"Later {_host_status(after, change.address)}",
        ]
        if change.port is not None and None in (change.before, change.after):
            evidence.append(
                f"- **Grouped records on this host:** Earlier {_grouped(before, change.address)}; "
                f"Later {_grouped(after, change.address)}. Watchpost does not expand grouped "
                "counts, so they are not evidence for this port."
            )
        findings.extend(
            [
                f"### {number}. {category}",
                "",
                *evidence,
                "",
                f"**Explanation:** {explanation}",
                "",
                f"**Suggested check:** {check}",
                "",
                "**Investigation notes:**",
                "",
                "**Conclusion:**",
                "",
            ]
        )

    lines = [
        "# Watchpost change review",
        "",
        "> Observations, not a security verdict. Changes do not prove vulnerability or compromise.",
        "",
        "## Comparison context",
        "",
        "- Context: same location, intended targets, and other settings confirmed by user.",
        "- Watchpost checked completion, timestamps, Nmap version, scan method, and port coverage.",
        "- Matching metadata does not independently establish matching scan conditions.",
        "",
        *note,
        *_source_section("Earlier", before),
        *_source_section("Later", after),
        "## Summary",
        "",
        f"Total observation differences: **{len(changes)}**",
        "",
        "| Observation category | Count |",
        "|---|---:|",
        *(f"| {category} | {count} |" for category, count in counts.items()),
        "",
        "Address and port differences are counted separately, "
        "not as distinct incidents or devices.",
        "",
        "## Findings",
        "",
        "Source names below refer to the Earlier and Later snapshot sections above. "
        "Port evidence is the explicit XML state, with the reason Nmap recorded, for the listed "
        "IPv4 address and numeric TCP port ID. Address evidence records presence only, not "
        "device identity. Host status repeats what Nmap recorded about the host in each snapshot.",
        "",
        "`not observed` means no explicit record in the parsed inventory; it is not an Nmap state. "
        "Reasons and host status show how Nmap classified a record, not why anything changed.",
        "",
        *(
            findings
            or [
                "No observed changes in explicit IPv4/TCP records. This is not a safety verdict.",
                "",
            ]
        ),
        "## Limitations",
        "",
        "- Missing and grouped port records are not classified as closed.",
        "- IP addresses are not device identities; port numbers are not application identities.",
        "- Filtered and uncertain states are preserved, not treated as confirmed open or closed.",
        "- Host status and reasons are shown as recorded evidence. They are not compared or used "
        "to reclassify any record.",
        "- Grouped port counts are shown as host context. They are not compared or expanded into "
        "per-port states.",
        "- Hostnames, service names, and scripts are not compared.",
        "- These are scan-window observations, not proof of when or why a change happened.",
        "- User confirmation is not independently verified by Watchpost.",
        "- Keep the original XML files with this report. The SHA-256 hashes identify them, and "
        "`watchpost verify` rechecks the evidence. A hash does not prove who made a file, when, "
        "or where.",
        "- Reports contain network details and are not anonymous. Review before sharing.",
        "",
        "## Human review",
        "",
        "**Reviewer:**",
        "",
        "**Reviewed at (UTC):**",
        "",
        "**Overall investigation notes:**",
        "",
        "**Overall conclusion:**",
        "",
    ]
    return "\n".join(lines)


def evidence_lines(markdown: str) -> list[tuple[int, str]]:
    """Return a report's generated lines by number, without user labels or review notes.

    Source paths and the context note are labels the user supplied; review fields are filled in
    after generation. Neither is evidence, so a report still verifies after a review.
    """
    kept: list[tuple[int, str]] = []
    in_field = label_next = False
    for number, line in enumerate(markdown.splitlines(), 1):
        if line == "## Human review":
            kept.append((number, line))
            break
        field = next((name for name in REVIEW_FIELDS if line.startswith(name)), None)
        if field is not None:
            kept.append((number, field))
            in_field = True
            continue
        if in_field:
            if not (re.match(r"### [0-9]+\. ", line) or line == "## Limitations"):
                continue
            in_field = False
        if line in (SOURCE_LABEL, NOTE_LABEL):
            label_next = True
        elif label_next and line.startswith("    "):
            line, label_next = "    (label)", False
        kept.append((number, line))
    return kept


def write_report(path: Path, content: str) -> None:
    """Publish a complete new file without replacing any existing destination."""
    try:
        with NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", dir=path.parent, prefix=".watchpost-"
        ) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            # Unlike replace/rename, link refuses even a concurrently created destination.
            os.link(temporary.name, path)
    except FileExistsError as exc:
        raise ValueError(
            f"Report destination already exists: {str(path)!a}. "
            "Choose a new filename; existing files and notes are never overwritten."
        ) from exc
    except OSError as exc:
        raise ValueError(
            f"Cannot save report to {str(path)!a}: {exc.strerror or 'file operation failed'}. "
            "Use an existing, writable directory on a filesystem that supports hard links."
        ) from exc
