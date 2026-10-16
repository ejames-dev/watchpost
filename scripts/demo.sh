#!/usr/bin/env bash
# Scripted Watchpost walkthrough for live demos. Offline; uses synthetic data only.
# Usage: scripts/demo.sh [--auto]   (--auto skips pauses, e.g. for recording)
set -euo pipefail

cd "$(dirname "$0")/.."
auto=0
[ "${1:-}" = "--auto" ] && auto=1

out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

step() {
  printf '\n\033[1;36m== %s ==\033[0m\n' "$1"
  [ "$auto" -eq 1 ] || read -r -p "(enter to run) " _
}

run() {
  printf '\033[2m$ %s\033[0m\n' "$*"
  "$@"
}

step "1. Inspect one saved scan"
run uv run --offline watchpost inspect examples/baseline.xml

step "2. Compare two scans: expected deployment"
run uv run --offline watchpost compare examples/baseline.xml examples/after.xml \
  --confirm-same-context --output "$out/review.md"
run cat "$out/review.md"

step "3. Same evidence, different policy: the tool does not classify"
grep -ci 'unintended' "$out/review.md" || echo "0 matches: no automatic exposure verdict"

step "4. Incomplete scan: the tool refuses"
set +e
run uv run --offline watchpost compare examples/baseline.xml examples/incomplete.xml \
  --confirm-same-context --output "$out/incomplete.md"
printf 'exit code: %s\n' "$?"
set -e
test ! -e "$out/incomplete.md" && echo "No report created"

printf '\n\033[1;32mDone.\033[0m\n'
