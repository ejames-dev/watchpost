# Demo plan: AI builders demo night

Goal: a 5-minute live walkthrough (3-minute cut available) plus a short submission form with a link to the build.

## Pitch

Watchpost turns two saved Nmap scans into an evidence-only change review. It never guesses,
never scores, and says when it does not know.

For an AI builders audience, the angle is restraint: the tool makes no AI verdicts by design.
Add a short segment on how it was built with AI agents and which guardrails kept it honest
(`AGENTS.md`, the v0.1 brief, one PR per milestone).

## Run the demo

```bash
scripts/demo.sh          # pauses before each step
scripts/demo.sh --auto   # no pauses, for recording
```

Offline, synthetic data, writes reports to a temp directory only.

## Flow

| Time | Step | Point |
|---|---|---|
| 0:30 | Problem | "New port" is not "new service". "Missing" is not "closed". |
| 1:00 | Inspect, then compare `baseline` vs `after` | `closed (conn-refused) -> open (syn-ack)` on 3000/tcp; report has fixed-rule explanations and blank investigation fields |
| 0:45 | Same evidence, different policy | Interpretation comes from the human, not the tool |
| 1:00 | Compare against `incomplete.xml` | Exit code 2, no report: refusal over over-claiming |
| 1:00 | How it was built | Guardrails, PR history, tests |
| 0:30 | Close | Repo, wiki, `watchpost-cli` (only if the registry publish is confirmed) |

Cut order if short on time: the "different policy" step first.

## Checklist

- [ ] Confirm the submission form fields (short form plus a link to the build)
- [ ] Rehearse `scripts/demo.sh` at least 3 times with a timer
- [ ] Large terminal font, clean prompt, high contrast
- [ ] Record a 2-3 minute fallback video of `--auto`; keep a local copy for offline use
- [x] `watchpost-cli` 0.0.1 is on PyPI and `inspect`/`compare` work from a clean venv (checked 2026-10-16). The bundled example XML is only in the repo, so the demo still needs a checkout
- [ ] Speaker script: `docs/demo-script.md`. Submission text: `docs/submission-draft.md`
- [ ] README quick-start verified from a fresh clone
- [ ] Draft the form text: one-paragraph description, repo link, video link
- [ ] Test screen share or HDMI at the venue; bring the video offline

## Timeline

| When | Milestone |
|---|---|
| Week 1 | Get submission requirements; rehearse the script; settle the AI-build segment |
| Week 2 | Record fallback video; draft form text and slides; fix rough edges found in rehearsal |
| Week 3 | Submit form and repo link before the deadline; tag a release if needed |
| Demo week | Three timed rehearsals; venue check |

## Risks and answers

- Overrun: cut the policy step.
- Legibility: large font, high contrast.
- "Why not `ndiff`?": the difference is metadata validation, refusal on incomplete input, and no inference from missing data.
