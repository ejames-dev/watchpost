# Browser build

The browser build runs the same `compare_report` and `inspect_text` functions as the CLI inside
[Pyodide](https://pyodide.org/) (CPython compiled to WebAssembly). Scan files are read
with the File API and passed to Python in memory. Nothing is uploaded.

The page compares two scans, inspects one scan with the same pre-flight as `watchpost inspect`,
and can load the two synthetic example scans that the site serves. Loading the examples leaves the
scan-context confirmation unticked: the user still confirms it before comparing.

## How it stays local

- Every runtime file is served from the same origin: the page, Watchpost's two modules,
  Pyodide, and the `defusedxml` wheel. No CDN is used.
- `web/_headers` sets a content security policy with `connect-src 'self'` and
  `default-src 'none'`, so the browser blocks requests to any other origin.
  The static site has no endpoint that accepts data.
- The build verifies the Pyodide tarball against a pinned SHA-512 and installs the
  `defusedxml` wheel with the same SHA-256 as `uv.lock`.
- Source names in reports are bare filenames from the browser, never local paths.
- The optional context note is only written into the report, as an escaped literal.
- A service worker (`sw.js`, allowed by `worker-src 'self'`) caches the site's own files after
  the first visit, so the page also works offline. It answers only same-origin GET requests.
  The build fills in its file list and a cache name tied to the files' contents, so a new
  deployment replaces the old cache.

## Build and test locally

Requires Node.js 18+, Python 3, `pip`, and `openssl`.

```bash
bash web/build.sh site
node web/smoke.mjs site
python3 -m http.server -d site 8000
```

The smoke test loads the built Pyodide runtime in Node and checks that the browser report is
byte-identical to `examples/report.md`. It also checks inspection, the served examples, and that
the service worker's file list matches the build. `http.server` does not apply `_headers`, so use
it only for a quick look. Cloudflare applies the headers on deployment. On Windows, Python's
server can send `.mjs` files as `text/plain`, which browsers refuse; serve the site from WSL.

## Deploy to Cloudflare

`wrangler.jsonc` deploys `site/` as an assets-only Worker. No Worker script runs, so
`_headers` applies to every response. Static asset requests are free on the Workers Free plan.

1. In the Cloudflare dashboard, open **Workers & Pages → Create → Import a repository**
   and select `ejames-dev/watchpost`.
2. Project name: `watchpost` (must match `name` in `wrangler.jsonc`).
3. Build command: `bash web/build.sh site`
4. Deploy command: `npx wrangler deploy` (the default).
5. Deploy, then add a custom domain under the Worker's **Settings → Domains & Routes**.

Keep Cloudflare Web Analytics, Real User Measurements (**Speed → Real user monitoring →
Disable completely**), and other injected scripts disabled for this project. A new custom
domain starts with RUM in a default mode that injects Cloudflare's beacon script.
The content security policy blocks them, and they would weaken the "no third parties" claim.

## Updating pinned versions

- Pyodide: change `PYODIDE_VERSION` and `PYODIDE_INTEGRITY` in `web/build.sh`.
  Get the integrity with `npm view pyodide@<version> dist.integrity`.
- defusedxml: update `web/requirements.txt` from the wheel hash in `uv.lock` and the
  wheel filename in `web/app.js`. The smoke test fails if they drift.
