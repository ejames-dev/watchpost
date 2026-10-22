// Node smoke test for a built site: node web/smoke.mjs site
import assert from "node:assert/strict";
import { access, readFile, readdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const site = resolve(process.argv[2] ?? "site");
const root = resolve(site, "..");
const { loadPyodide } = await import(pathToFileURL(join(site, "pyodide/pyodide.mjs")).href);
const { startWatchpost } = await import(pathToFileURL(join(site, "runtime.js")).href);

const [wheelName] = (await readdir(join(site, "wheels"))).filter((n) => n.endsWith(".whl"));
const { compare, inspect, maxBytes } = await startWatchpost(loadPyodide, {
  indexURL: join(site, "pyodide") + "/",
  sources: {
    "watchpost.py": await readFile(join(site, "py/watchpost.py"), "utf8"),
    "watchpost_report.py": await readFile(join(site, "py/watchpost_report.py"), "utf8"),
  },
  wheel: (await readFile(join(site, "wheels", wheelName))).buffer,
});

const example = (name) => readFile(join(root, "examples", name)).then((b) => new Uint8Array(b));
const before = await example("baseline.xml");
const after = await example("after.xml");
const expected = await readFile(join(root, "examples/report.md"), "utf8");

const ok = compare(before, after, "examples/baseline.xml", "examples/after.xml", true);
assert.deepEqual(ok, { ok: true, text: expected }, "browser report must match the CLI report");

const note = "users VLAN\n# not a heading";
const noted = compare(before, after, "examples/baseline.xml", "examples/after.xml", true, note);
assert.equal(noted.ok, true);
assert.ok(noted.text.includes("    'users VLAN\\n# not a heading'"), "note must be an escaped literal");
assert.ok(!noted.text.includes("\n# not a heading"), "note must not become report structure");

const unconfirmed = compare(before, after, "a.xml", "b.xml", false);
assert.equal(unconfirmed.ok, false);
assert.match(unconfirmed.text, /Confirm the same scan location/);

const reversed = compare(after, before, "a.xml", "b.xml", true);
assert.equal(reversed.ok, false);
assert.match(reversed.text, /Snapshots are reversed/);

const unsafe = new TextEncoder().encode('<!DOCTYPE x [<!ENTITY a "b">]><nmaprun>&a;</nmaprun>');
assert.match(compare(before, unsafe, "a.xml", "b.xml", true).text, /Unsafe XML/);

const inspected = inspect(before, "baseline.xml");
assert.equal(inspected.ok, true);
assert.match(inspected.text, /^192\.0\.2\.10 {2}host status: up \(user-set\)$/m);
assert.match(inspected.text, /Ready to compare: yes/);
const incomplete = inspect(await example("incomplete.xml"), "incomplete.xml");
assert.equal(incomplete.ok, false);
assert.match(incomplete.text, /Host scan is incomplete/);
assert.equal(maxBytes, 100 * 1024 * 1024, "the page must read up to the Python size limit");

// The examples button loads these files from the site itself.
for (const name of ["baseline.xml", "after.xml"]) {
  const served = await readFile(join(site, "examples", name));
  assert.ok(served.equals(await readFile(join(root, "examples", name))), `examples/${name}`);
}

// The service worker must precache exactly the files that exist in the build.
const worker = await readFile(join(site, "sw.js"), "utf8");
assert.ok(!/__(BUILD|FILES)__/.test(worker), "build must fill in the service worker");
const listed = JSON.parse(worker.match(/const FILES = (\[.*\]);/)[1]);
for (const name of ["./", "index.html", "app.js", "pyodide/pyodide.asm.wasm", wheelName]) {
  assert.ok(listed.some((path) => path === name || path === `wheels/${name}`), name);
}
for (const path of listed.filter((path) => path !== "./")) {
  await access(join(site, path));
}

console.log("Browser runtime smoke test passed.");
