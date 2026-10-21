// Node smoke test for a built site: node web/smoke.mjs site
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const site = resolve(process.argv[2] ?? "site");
const root = resolve(site, "..");
const { loadPyodide } = await import(pathToFileURL(join(site, "pyodide/pyodide.mjs")).href);
const { startWatchpost } = await import(pathToFileURL(join(site, "runtime.js")).href);

const [wheelName] = (await readdir(join(site, "wheels"))).filter((n) => n.endsWith(".whl"));
const compare = await startWatchpost(loadPyodide, {
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

console.log("Browser runtime smoke test passed.");
