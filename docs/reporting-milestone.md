# Markdown reporting milestone

## Goal and scope

Add `--output FILE` to the existing comparison command. Without it, preserve terminal output.
Reuse the validated snapshots and ordered changes; do not create a second comparison engine.
Keep Python 3.11+, offline operation, and the existing runtime dependency set.
This milestone does not complete the three scenario walkthroughs required for v0.1.

## Implementation plan

1. Test and implement a pure Markdown renderer for the existing `Snapshot` and `Change` records.
   Include source paths, UTC windows, scan metadata, user-confirmed assumptions, category counts,
   per-finding evidence, fixed-rule explanations, suggested checks, and blank reviewer fields.
2. Test and implement non-overwriting output and wire it to `compare --output FILE`.
   Parse and compare successfully before creating any report. Keep errors on stderr with exit 2.
3. Cover missing/grouped observations, uncertain states, identical inputs, unsafe filenames,
   existing destinations, symlinks, competing writers, and I/O failures with offline tests.
4. Publish a synthetic sample report, document usage, and verify tests, Ruff, package builds,
   installed-wheel operation, and the existing Python 3.11/3.12/3.13 CI matrix.

## Evidence and interpretation

- Refer to the two named source sections for each finding. Identify the IPv4 address and, for
  ports, the numeric TCP port ID. State values come from explicit XML records, not guesses.
- Count changed states, newly observed ports/addresses, and ports/addresses not observed later
  separately. An address difference and its port differences are separate observations, not
  separate incidents or proof of device additions/removals.
- Never interpret grouped records as explicit states. Preserve `filtered`, `unfiltered`,
  `open|filtered`, and `closed|filtered` without relabeling them.
- Give fixed-rule suggestions, not vulnerability scores, application identities, or AI verdicts.
- Use input scan times only: no generation timestamp or random identifiers in report content.
- Keep original XML files with the report. Source references do not embed or authenticate them.

## Output safety

- Display filenames as escaped literals in indented Markdown code blocks. Newlines, terminal
  controls, backticks, pipes, links, and HTML in names must not become report structure or markup.
- Create a private temporary file in the destination directory. Write UTF-8 with LF newlines,
  flush and sync it, then publish with an atomic, non-replacing hard link. Remove the temporary
  name on success or an ordinary failure. No copy/replace fallback and no `--force` option.
- Existing files, directories, hard links, and symlinks (including dangling ones) must remain
  untouched. A destination created by a competing writer must also be preserved.
- The destination directory must already exist and its filesystem must support hard links.
  This targets Linux/Ubuntu WSL. Use a trusted directory; this is not a multi-user sandbox.
- Reports are not anonymous. Keep real reports in the Git-ignored `reports/` directory.

## Verification

Run `uv run --offline python -m unittest discover -s tests -v`, `uv run --offline pytest`,
`uv run --offline ruff format --check .`, and `uv run --offline ruff check .`.
Regenerate the bundled synthetic report into a new temporary destination and compare bytes.
Verify the source archive includes the examples/tests/docs and the installed wheel contains
both runtime modules. Do not rely on the checkout being on Python's import path.
