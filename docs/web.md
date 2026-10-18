# Browser build

The browser build runs the same `compare_report` function as the CLI inside
[Pyodide](https://pyodide.org/) (CPython compiled to WebAssembly). Scan files are read
with the File API and passed to Python in memory. Nothing is uploaded.

## How it stays local

- Every runtime file is served from the same origin: the page, Watchpost's two modules,
  Pyodide, and the `defusedxml` wheel. No CDN is used.
- `web/_headers` sets a content security policy with `connect-src 'self'` and
  `default-src 'none'`, so the browser blocks requests to any other origin.
  The static site has no endpoint that accepts data.
- The build verifies the Pyodide tarball against a pinned SHA-512 and installs the
  `defusedxml` wheel with the same SHA-256 as `uv.lock`.
- Source names in reports are bare filenames from the browser, never local paths.

## Build and test locally

Requires Node.js 18+, Python 3, `pip`, and `openssl`.

```bash
bash web/build.sh site
node web/smoke.mjs site
python3 -m http.server -d site 8000
```

The smoke test loads the built Pyodide runtime in Node and checks that the browser report is
byte-identical to `examples/report.md`. `http.server` does not apply `_headers`, so use it
only for a quick look. Cloudflare Pages applies the headers on deployment.

## Deploy to Cloudflare Pages

1. In the Cloudflare dashboard, open **Workers & Pages → Create → Pages → Connect to Git**
   and select `ejames-dev/watchpost`.
2. Framework preset: **None**.
3. Build command: `bash web/build.sh site`
4. Build output directory: `site`
5. Deploy, then add a custom domain under the project's **Custom domains** tab if wanted.

Keep Cloudflare Web Analytics and other injected scripts disabled for this project.
The content security policy blocks them, and they would weaken the "no third parties" claim.

## Updating pinned versions

- Pyodide: change `PYODIDE_VERSION` and `PYODIDE_INTEGRITY` in `web/build.sh`.
  Get the integrity with `npm view pyodide@<version> dist.integrity`.
- defusedxml: update `web/requirements.txt` from the wheel hash in `uv.lock` and the
  wheel filename in `web/app.js`. The smoke test fails if they drift.
