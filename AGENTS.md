# Watchpost

Watchpost is a standalone Python CLI, not part of the adjacent AgentEase SDK.
Read `docs/brief-v0.1.md` and the current README before changing code.

## Commands

- Setup: `uv sync --dev --python 3.11`
- Inspect demo: `uv run watchpost inspect examples/baseline.xml`
- Compare demo: `uv run watchpost compare examples/baseline.xml examples/after.xml --confirm-same-context`
- Report demo: create `reports/`, then add `--output reports/review.md` to the compare command. Use a new filename each time.
- Tests: `uv run python -m unittest discover -s tests -v`
- Alternate test runner: `uv run pytest`
- Format check: `uv run ruff format --check .`
- Lint: `uv run ruff check .`

## Conventions

- Keep Python 3.11+ compatibility and a 100-character line limit.
- Use plain functions and typed standard-library containers before adding abstractions.
- Keep tests in unittest and use synthetic data only.
- Keep report rendering in `watchpost_report.py`. Reuse the existing parser and comparison gate.
- If report wording changes, regenerate `examples/report.md` into a new file and review the diff.
- Use short, imperative commit messages for one logical change.
- Verify behavior with tests before claiming a milestone is complete.
- Keep the README honest about features that do not exist yet.

## Boundaries

- Never scan, upload data, or make runtime network calls.
- Parse XML with defusedxml. Never enable entities or external references.
- Never interpret missing observations as confirmed closures or device removal.
- Require human confirmation of scan context. Never claim metadata alone proves comparable conditions.
- Never identify an application by port number alone.
- Never silently overwrite reports or human notes.
- Never commit credentials, private inventories, or real scan results.
- Do not change other repositories or global Git settings.
