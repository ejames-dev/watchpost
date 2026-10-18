# Submission draft

Adjust to the real form fields once you see them.

## One-paragraph description

Watchpost is a local-first CLI that turns two saved Nmap scans into an evidence-backed change review. It validates that the scans are comparable, refuses incomplete input, and writes a Markdown report that separates what was observed from what a human concludes. It never launches scans, makes network calls, or issues security verdicts. It was built with AI coding agents under explicit guardrails (`AGENTS.md`, a fixed scope brief, and one tested PR per milestone) so the tool and its development process both avoid claiming more than the evidence supports.

## Short version (about 25 words)

A local-first CLI that turns two saved Nmap scans into an evidence-only change report, built with AI agents under explicit guardrails. No scanning, no AI verdicts.

## Links

- Repo: https://github.com/ejames-dev/watchpost
- Install: `pip install watchpost-cli` (command: `watchpost`)
- Wiki: https://github.com/ejames-dev/watchpost/wiki
- Demo video: _add the link once recorded_

## Try it in 60 seconds

```bash
git clone https://github.com/ejames-dev/watchpost.git
cd watchpost
uv sync --locked --dev --python 3.11
scripts/demo.sh
```

## Tech and AI use

Python 3.11+, standard library plus `defusedxml`, unittest and pytest, ruff. Built with Claude Code and other coding agents, with the agents bound by repo rules.
