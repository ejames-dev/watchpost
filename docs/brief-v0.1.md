# Watchpost v0.1 project brief

Status: approved scope. Implementation starts with single-snapshot inspection.
Watchpost is the working name. This document describes the target, not completed features.

## Purpose

Turn two saved network scans into one clear, evidence-backed change report.
Serve students and home-lab operators working on networks they own or have permission to assess.
Explain what changed, what evidence supports the finding, and what to check next.
Do not decide that a network is secure or compromised.

## Target workflow

Earlier Nmap XML + later Nmap XML → validate → compare → Markdown report → human review.
Use Python 3.11+ on Linux or Ubuntu WSL. Support IPv4 addresses and TCP ports first.
No account, API key, or cloud service is required at runtime.

## Inputs

Accept two saved Nmap XML files with results and scan metadata.
Validate completion status and relevant settings, including port coverage.
Reject malformed, failed, incomplete, or incompatible inputs with an actionable explanation.
If required comparison metadata is missing, do not claim a reliable comparison.
The user confirms the same scan location and intended target scope.
XML alone cannot establish these facts.
Use synthetic bundled files so the demo does not need Nmap installed.

## Report

- Source files, scan times, and comparison assumptions.
- Counts of observed changes and missing observations.
- Address, TCP port, earlier state, later state, and source evidence per finding.
- Fixed-rule explanations and suggested checks, not AI verdicts.
- Limitations of the available evidence.
- Blank fields for human investigation notes and conclusions.

## Non-negotiable rules

- Missing observations stay unknown or not observed, not confirmed closed or removed.
- An IP address is not proof of a device identity.
- Changes are not proof of vulnerability or compromise.
- Port numbers alone do not identify applications.
- Input stays local. No scans, uploads, telemetry, or external XML requests.
- Reports are not automatically anonymous. Public examples must be synthetic.
- Never silently overwrite existing reports or investigation notes.

## Completion criteria

- A documented command generates a report from example files entirely offline after installation.
- Identical snapshots produce "no observed changes", not a safety verdict.
- Tests cover newly observed ports and explicit, supported port-state changes.
- Missing observations never become invented closures.
- Unsuitable inputs fail with clear explanations.
- Three scenarios document an expected deployment, unintended backend exposure, and an incomplete scan.
- The same inputs produce repeatable findings.

Planned and current test command: `python -m unittest discover -s tests -v`.
This command alone does not prove all target features exist. Check the README milestone status.

## Outside v0.1

Dashboard, live scans, scheduling, packet capture, database, AI analysis, vulnerability scoring,
automatic fixes, UDP, and IPv6.

## First milestone

1. Safely read one synthetic XML file.
2. Validate that it is a completed IPv4/TCP Nmap scan.
3. List explicit address and port-state observations in a stable order.
4. Test normal input, unsafe XML, unsupported input, and incomplete scans.
5. Document an offline demo and limitations before publishing.

Comparison and Markdown reporting follow this milestone.
