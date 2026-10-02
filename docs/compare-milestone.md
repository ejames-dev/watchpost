# Snapshot comparison milestone

## Goal

Add `watchpost compare BEFORE AFTER --confirm-same-context` without changing the existing inspect output.
Print a deterministic, evidence-linked terminal comparison. Markdown reports remain the next milestone.

## Impact and implementation

- Reuse the existing safe XML parser and inventory validation in `watchpost.py`.
- Preserve `read_inventory(Path)` for its existing CLI and test callers.
- Add typed snapshot metadata and change records with standard-library dataclasses.
- Add a second synthetic example and comparison tests. No new dependencies or network calls.
- Extend the current CI demo and source archive to include the second example.

## Comparison gate

- Require explicit confirmation of the same scan location, intended target scope, and remaining Nmap settings.
- Support one TCP connect or SYN scan per snapshot for this milestone.
- Require matching Nmap versions, scan methods, and normalized TCP port sets.
- Require a valid declared port count and explicit observations within the declared coverage.
- Require valid UTC start/end times with start <= end.
- Reject reversed or overlapping scan windows. Equal windows with identical supported observations are allowed for repeat-input checks.
- Retain the existing failures for malformed XML, unsafe entities, unsupported addresses/protocols, timeouts, duplicates, and unsuccessful scans.

## Difference semantics

- Compare addresses by IP, not by claimed device identity.
- Report addresses appearing in only one snapshot as newly observed or not observed.
- Compare the union of explicit TCP port records for each address.
- Report an explicit state change only when both snapshots contain a state for that port.
- Missing or grouped records remain not observed. Never infer a closure from absence.
- Preserve uncertain states such as open|filtered without relabeling them as open.
- Sort addresses and ports numerically. Display source paths safely and scan times in UTC.
- For identical supported observations, say "No observed changes in explicit IPv4/TCP records", not "safe".

## Verification

`uv run --offline python -m unittest discover -s tests -v`

Cover metadata parsing and rejection, port ranges/counts, chronological ordering, identical inputs,
explicit state changes, missing ports/addresses, newly observed ports/addresses, uncertain states,
mandatory confirmation, deterministic output, safe source-path display, and no partial output on failure.
Run the existing suite, Ruff, package checks, and Python 3.11/3.12/3.13 CI.

## Limits and prior art

This milestone does not parse or compare the entire Nmap command line. Human confirmation covers
settings and environment that the automated checks do not establish. Equal metadata is not proof
of an equivalent measurement. Hostnames, application identities, grouped port states, and script
output remain outside the diff. No automatic scans, output files, or security verdicts.

Nmap already provides scanning and Ndiff provides raw comparisons. This project adds conservative
validation, explicit limitations, and a review workflow rather than a replacement scanner.
Reference: https://nmap.org/book/output-formats-xml-output.html
