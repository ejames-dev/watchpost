"""Deterministic Markdown for validated comparisons; no scanning or network access."""

from __future__ import annotations

import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from watchpost import Change, Snapshot


def _finding_text(change: Change) -> tuple[str, str, str]:
    """Return a category, explanation, and suggested human check."""
    if change.port is None:
        return (
            "Address newly observed" if change.before is None else "Address not observed later",
            "This address has a record in only one snapshot. This does not prove a device "
            "was added or removed, or that the same device held this address in both scans.",
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
            "Check host availability, grouped records, and scan conditions before "
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
        "Source path (escaped literal):",
        "",
        f"    {str(snapshot.source)!a}",
        "",
        f"- UTC start: `{snapshot.started.isoformat()}`",
        f"- UTC finish: `{snapshot.finished.isoformat()}`",
        f"- Nmap version: `{snapshot.version}`",
        f"- Scan method: TCP `{snapshot.method}`",
        f"- Declared TCP ports: {len(snapshot.coverage)}",
        f"- IPv4 address records: {len(snapshot.inventory)}",
        f"- Explicit TCP port records: {sum(len(ports) for ports in snapshot.inventory.values())}",
        "",
    ]


def render_markdown(before: Snapshot, after: Snapshot, changes: list[Change]) -> str:
    """Render read_snapshot/compare_snapshots results after the comparison gate passes."""
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
        findings.extend(
            [
                f"### {number}. {category}",
                "",
                f"- **Record:** {record}",
                f"- **Earlier evidence:** `{change.before or 'not observed'}` — Earlier snapshot",
                f"- **Later evidence:** `{change.after or 'not observed'}` — Later snapshot",
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
        "Port evidence is the explicit XML state for the listed IPv4 address and numeric TCP "
        "port ID. Address evidence records presence only, not host status or device identity.",
        "",
        "`not observed` means no explicit record in the parsed inventory; it is not an Nmap state.",
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
        "- Host status, hostnames, service names, scripts, and grouped states are not compared.",
        "- These are scan-window observations, not proof of when or why a change happened.",
        "- User confirmation is not independently verified by Watchpost.",
        "- Keep the original XML files with this report; "
        "references do not embed or authenticate them.",
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
