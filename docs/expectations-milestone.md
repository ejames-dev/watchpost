# Expectations milestone

## Goal

Let a reviewer record their own expected later port states in a TOML file, and show next to the
evidence whether each explicit later record matches. Watchpost compares; it never decides whether
a network is safe, secure, or compliant.

## File format

```toml
[expect."192.0.2.10/tcp/3000"]
state = "open"
label = "Demo app approved in the lab deployment plan"

[expect."192.0.2.20/tcp/3000"]
state = ["closed", "filtered"]
```

- Keys use the finding-key form `ADDRESS/tcp/PORT`, with a canonical IPv4 address.
- `state` is one Nmap port state or a list of acceptable states.
- `label` is optional: 1 to 120 letters, digits, spaces, or `. , ; : ( ) ' / & + -` characters.
  It is the reviewer's own description, such as a role from a deployment plan.
- Anything else is rejected: unknown fields, malformed keys, duplicate states, and files that are
  not UTF-8 TOML or are larger than 1 MiB.

## Semantics

- Expectations describe the later snapshot only.
- `matches`: the later snapshot has an explicit record whose state is one of the expected states.
- `differs`: the later explicit state is not one of them.
- `cannot be checked`: there is no explicit later record, or the later scan did not cover the
  port. Absence never matches `closed`, and grouped counts never stand in for a record.
- Expectations never change findings, counts, or the comparison gate.

## Output

- Terminal: an expectations block after the findings, ending with a results line.
- Markdown: a "Your expectations" section with the file's SHA-256 hash, a results line, and a
  table. Findings that have an expectation get a "Your expectation" line.
- JSON: an `expectations` object with the same entries and results.
- `watchpost verify` needs the same file through `--expect` to recheck a report that used one.

## Boundaries

- Never describe a result as safe, secure, compliant, approved, or a violation. A match is not a
  safety verdict, and a difference is not proof of a problem.
- Labels are the reviewer's statements. Port numbers still do not identify applications.
- The file is parsed with the standard library's `tomllib`. It is never executed or fetched.

## Verification

`uv run --offline python -m unittest discover -s tests -v` covers parsing and rejection, every
result, report and terminal wording, JSON entries, and `verify` with and without `--expect`.
Scenarios 1 and 2 run the same XML pair with `examples/expected-deployment.toml` and
`examples/backend-policy.toml`.
