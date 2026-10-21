"""Deterministic Markdown and JSON for validated comparisons; no scanning or network access."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from watchpost import Change, Expectation, Expectations, Snapshot

# Each label introduces an indented, escaped literal: text the user supplied, never markup.
SOURCE_LABEL = "Source path (escaped literal):"
NOTE_LABEL = "User's context note (escaped literal, not verified by Watchpost):"
EXPECT_LABEL = "Expectations file (escaped literal):"
EXPECT_HEADING = "## Your expectations"
# Reviewers fill these in after generation, so verification skips their contents.
REVIEW_FIELDS = ("**Investigation notes:**", "**Conclusion:**")

NOTICE = "Observations, not a security verdict. Changes do not prove vulnerability or compromise."
CATEGORIES = (
    "Port state changed",
    "Port newly observed",
    "Port not observed later",
    "Address newly observed",
    "Address not observed later",
)
LIMITATIONS = (
    "Missing and grouped port records are not classified as closed.",
    "IP addresses are not device identities; port numbers are not application identities.",
    "Filtered and uncertain states are preserved, not treated as confirmed open or closed.",
    "Host status and reasons are shown as recorded evidence. They are not compared or used "
    "to reclassify any record.",
    "Grouped port counts are shown as host context. They are not compared or expanded into "
    "per-port states.",
    "Hostnames, service names, and scripts are not compared.",
    "These are scan-window observations, not proof of when or why a change happened.",
    "User confirmation is not independently verified by Watchpost.",
    "Keep the original XML files with this report. The SHA-256 hashes identify them, and "
    "`watchpost verify` rechecks the evidence. A hash does not prove who made a file, when, "
    "or where.",
    "Reports contain network details and are not anonymous. Review before sharing.",
)
EXPECT_NOTICE = (
    "Expectations are your own statements about the later snapshot. Watchpost compares them "
    "with explicit later records only. A match is not a safety verdict, and a difference is "
    "not proof of a problem."
)
EXPECT_LIMITATION = (
    "Expectations and their labels are your own statements. Watchpost cannot verify them."
)


def finding_key(change: Change) -> str:
    """Name a finding by its evidence, so notes can refer to it across reports."""
    return change.address if change.port is None else f"{change.address}/tcp/{change.port}"


def expectation_result(expectation: Expectation, after: Snapshot) -> str:
    """Compare an expectation with the later explicit record. Absence never matches."""
    state = after.inventory.get(expectation.address, {}).get(expectation.port)
    if state is not None:
        return "matches" if state in expectation.states else "differs"
    if expectation.port not in after.coverage:
        return "cannot be checked: the later scan did not cover this port"
    return "cannot be checked: no explicit later record"


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


def _expected(expectation: Expectation) -> str:
    return " or ".join(f"`{state}`" for state in expectation.states)


def expectation_tally(expectations: Expectations, after: Snapshot) -> dict[str, int]:
    tally = {"matches": 0, "differs": 0, "cannot be checked": 0}
    for item in expectations.entries:
        tally[expectation_result(item, after).split(":")[0]] += 1
    return tally


def _expectations_section(expectations: Expectations, after: Snapshot) -> list[str]:
    rows = []
    for item in expectations.entries:
        state = after.inventory.get(item.address, {}).get(item.port)
        reason = after.port_reasons.get(item.address, {}).get(item.port)
        later = "`not observed`" if state is None else _with_reason(state, reason)
        label = f"`{item.label}`" if item.label else "none"
        result = expectation_result(item, after).capitalize()
        rows.append(f"| `{item.key}` | {_expected(item)} | {later} | {result} | {label} |")
    tally = expectation_tally(expectations, after)
    return [
        EXPECT_HEADING,
        "",
        EXPECT_LABEL,
        "",
        f"    {str(expectations.source)!a}",
        "",
        f"- SHA-256: `{expectations.sha256}`",
        f"- Results: matches {tally['matches']}; differs {tally['differs']}; "
        f"cannot be checked {tally['cannot be checked']}",
        "",
        EXPECT_NOTICE,
        "",
        "| Key | Expected later state | Later evidence | Result | Your label |",
        "|---|---|---|---|---|",
        *rows,
        "",
    ]


def render_markdown(
    before: Snapshot,
    after: Snapshot,
    changes: list[Change],
    *,
    context_note: str | None = None,
    expectations: Expectations | None = None,
) -> str:
    """Render read_snapshot/compare_snapshots results after the comparison gate passes."""
    note = [] if context_note is None else [NOTE_LABEL, "", f"    {context_note!a}", ""]
    expected_by_key = {item.key: item for item in expectations.entries} if expectations else {}
    counts = dict.fromkeys(CATEGORIES, 0)
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
        expected = expected_by_key.get(finding_key(change))
        if expected is not None:
            label = f" Your label: `{expected.label}`." if expected.label else ""
            evidence.append(
                f"- **Your expectation:** {_expected(expected)} — "
                f"{expectation_result(expected, after)}.{label}"
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

    limitations = LIMITATIONS + ((EXPECT_LIMITATION,) if expectations else ())
    lines = [
        "# Watchpost change review",
        "",
        f"> {NOTICE}",
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
        *(_expectations_section(expectations, after) if expectations else []),
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
        *(f"- {line}" for line in limitations),
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


def _snapshot_json(snapshot: Snapshot) -> dict[str, object]:
    return {
        "source": str(snapshot.source),
        "sha256": snapshot.sha256,
        "utc_start": snapshot.started.isoformat(),
        "utc_finish": snapshot.finished.isoformat(),
        "nmap_version": snapshot.version,
        "scan_method": snapshot.method,
        "declared_tcp_ports": len(snapshot.coverage),
        "ipv4_address_records": len(snapshot.inventory),
        "explicit_tcp_port_records": sum(len(ports) for ports in snapshot.inventory.values()),
    }


def _side_json(snapshot: Snapshot, change: Change, value: str | None) -> dict[str, object]:
    observed = change.address in snapshot.inventory
    status, status_reason = snapshot.host_status.get(change.address, ("not recorded", None))
    reason = None
    if value is not None and change.port is not None:
        reason = snapshot.port_reasons.get(change.address, {}).get(change.port)
    grouped = sorted(snapshot.grouped_ports.get(change.address, {}).items())
    return {
        "record": value or "not observed",
        "reason": reason,
        "host_status": status if observed else "not observed",
        "host_status_reason": status_reason if observed else None,
        "grouped_counts": dict(grouped) if observed else None,
    }


def _expectations_json(expectations: Expectations, after: Snapshot) -> dict[str, object]:
    entries = []
    for item in expectations.entries:
        state = after.inventory.get(item.address, {}).get(item.port)
        reason = after.port_reasons.get(item.address, {}).get(item.port) if state else None
        entries.append(
            {
                "key": item.key,
                "expected_later_states": list(item.states),
                "label": item.label,
                "later": {"record": state or "not observed", "reason": reason},
                "result": expectation_result(item, after),
            }
        )
    return {
        "source": str(expectations.source),
        "sha256": expectations.sha256,
        "notice": EXPECT_NOTICE,
        "results": expectation_tally(expectations, after),
        "entries": entries,
    }


def render_json(
    before: Snapshot,
    after: Snapshot,
    changes: list[Change],
    *,
    context_note: str | None = None,
    expectations: Expectations | None = None,
) -> str:
    """Render the same evidence as render_markdown for scripts.

    A missing record is the string "not observed", never null, so it cannot be read as closed.
    """
    counts = dict.fromkeys(CATEGORIES, 0)
    findings = []
    for change in changes:
        category, explanation, check = _finding_text(change)
        counts[category] += 1
        findings.append(
            {
                "key": finding_key(change),
                "kind": "address" if change.port is None else "port",
                "category": category,
                "address": change.address,
                "port": change.port,
                "earlier": _side_json(before, change, change.before),
                "later": _side_json(after, change, change.after),
                "explanation": explanation,
                "suggested_check": check,
            }
        )
    document = {
        "format": "watchpost-comparison",
        "format_version": 1,
        "notice": NOTICE,
        "context": {"confirmed_by_user": True, "note": context_note},
        "snapshots": {"earlier": _snapshot_json(before), "later": _snapshot_json(after)},
        "summary": {"total_differences": len(changes), "by_category": counts},
        "findings": findings,
        "expectations": _expectations_json(expectations, after) if expectations else None,
        "limitations": [*LIMITATIONS, *((EXPECT_LIMITATION,) if expectations else ())],
    }
    # ensure_ascii escapes controls and non-ASCII text from paths, notes, and labels.
    return json.dumps(document, indent=2, ensure_ascii=True) + "\n"


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
        if line in (SOURCE_LABEL, NOTE_LABEL, EXPECT_LABEL):
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
