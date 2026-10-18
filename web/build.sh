#!/usr/bin/env bash
# Assemble the static browser build. Every runtime file is served from the same origin.
set -euo pipefail

PYODIDE_VERSION="314.0.7"
PYODIDE_INTEGRITY="sha512-0YvXxEhfEdpLfb/XkM2BFAeMROq0iMUX2bzzH9pOttyMcWkwq+HbE5uyuGD82LN7y2q+SNvi/6V5JEsOlD2R1A=="

root="$(cd "$(dirname "$0")/.." && pwd)"
out="${1:-$root/site}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

rm -rf "$out"
mkdir -p "$out/pyodide" "$out/py" "$out/wheels"

cp "$root/web/index.html" "$root/web/app.js" "$root/web/runtime.js" "$root/web/style.css" "$root/web/_headers" "$out/"
cp "$root/watchpost.py" "$root/watchpost_report.py" "$out/py/"

# Verify the exact Pyodide tarball before unpacking it.
(cd "$tmp" && npm pack "pyodide@$PYODIDE_VERSION" --silent >/dev/null)
actual="sha512-$(openssl dgst -sha512 -binary "$tmp/pyodide-$PYODIDE_VERSION.tgz" | base64 -w0)"
if [ "$actual" != "$PYODIDE_INTEGRITY" ]; then
  echo "Pyodide integrity mismatch: $actual" >&2
  exit 1
fi
tar xzf "$tmp/pyodide-$PYODIDE_VERSION.tgz" -C "$tmp"
for file in pyodide.mjs pyodide.asm.mjs pyodide.asm.wasm python_stdlib.zip pyodide-lock.json; do
  cp "$tmp/package/$file" "$out/pyodide/"
done

# Same pinned wheel hash as uv.lock.
python3 -m pip download --quiet --no-deps --only-binary=:all: --require-hashes \
  -r "$root/web/requirements.txt" -d "$out/wheels"

echo "Built $out"
