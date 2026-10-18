# Demo script (about 5 minutes)

Run `scripts/demo.sh` and press enter at each step. Spoken lines are suggestions. Rewrite them in your own words.

## 0:00 Problem (30s)

> When you rescan a network, the diff looks simple: a new port, a missing port. But "new port" is not "new service," and "missing" is not "closed." Tools that guess here produce confident wrong answers. Watchpost is built to refuse to guess.

## 0:30 Step 1: inspect (20s)

> One saved Nmap scan, listed as explicit observations only. Note the footer: "not a security verdict." Everything here is synthetic. Nothing is scanned and nothing touches the network.

## 0:50 Step 2: compare (80s)

> Two scans, one minute apart. Port 3000 on 192.0.2.10 went from closed to open. The report records both scan windows, the Nmap version, the scan method, and the evidence for each side.
>
> I had to pass `--confirm-same-context`. Watchpost can't verify that both scans came from the same place with the same targets, so it makes me say so, and records that I did.
>
> Scroll the report: fixed-rule explanations, a limitations section, and blank fields for the human conclusion. The tool provides the evidence and the person writes the verdict.

## 2:10 Step 3: same evidence, different policy (45s)

> If port 3000 is an approved demo app, this is expected. If it's a backend that must be reachable only through a reverse proxy, it's a problem. Same XML, same report. The report contains no "unintended exposure" label, because only the policy knows that. (cut this step first if short on time)

## 2:55 Step 4: incomplete scan (60s)

> Now a later scan where one host timed out. The tool exits with code 2 and writes no report. A finished run doesn't mean every host finished. A partial report that looks complete is worse than none.

## 3:55 How it was built (60s)

> I built this with AI coding agents, and the guardrails are in the repo. `AGENTS.md` lists hard rules: never scan, never make network calls, never treat missing data as closed, never overwrite a report. The v0.1 brief fixed the scope before any code. Each milestone is its own PR with tests. The agent works fast, but the repo's rules decide what it's allowed to claim.

## 4:55 Close (20s)

> `pip install watchpost-cli`, repo and wiki at github.com/ejames-dev/watchpost. It's a CLI for students and home-lab people. I'm happy to take questions.

## Likely questions

- **Why not `ndiff`?** `ndiff` shows what differs. Watchpost also validates that the comparison is legitimate, refuses incomplete input, and keeps "not observed" separate from "closed."
- **Why no AI in the tool itself?** A fixed-rule report can be audited line by line. Missing evidence stays missing instead of being filled in by a model.
- **What's next?** UDP and IPv6 are explicitly out of v0.1 scope. They are the natural candidates, but nothing is committed. Say what you actually plan.
