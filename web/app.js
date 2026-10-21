import { loadPyodide } from "./pyodide/pyodide.mjs";
import { startWatchpost } from "./runtime.js";

const WHEEL = "wheels/defusedxml-0.7.1-py2.py3-none-any.whl";
const MAX_BYTES = 10 * 1024 * 1024;

const form = document.getElementById("compare");
const submit = form.querySelector("button[type=submit]");
const status = document.getElementById("status");
const result = document.getElementById("result");
const report = document.getElementById("report");
const error = document.getElementById("error");
const errorText = document.getElementById("error-text");
const files = { before: null, after: null };
let compare = null;

function refresh() {
  submit.disabled = !(compare && files.before && files.after && form.confirmed.checked);
}

function setFile(slot, file) {
  files[slot] = file ?? null;
  const drop = form.querySelector(`[data-slot=${slot}]`);
  const label = drop.querySelector(".drop-file");
  label.textContent = file ? file.name : label.dataset.empty;
  drop.classList.toggle("filled", Boolean(file));
  result.hidden = error.hidden = true;
  refresh();
}

for (const drop of form.querySelectorAll(".drop")) {
  const slot = drop.dataset.slot;
  const input = drop.querySelector("input");
  input.addEventListener("change", () => setFile(slot, input.files[0]));
  drop.addEventListener("dragover", (event) => {
    event.preventDefault();
    drop.classList.add("over");
  });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (event) => {
    event.preventDefault();
    drop.classList.remove("over");
    setFile(slot, event.dataTransfer.files[0]);
  });
}
form.confirmed.addEventListener("change", refresh);
form.note.addEventListener("input", () => (result.hidden = error.hidden = true));

// Read at most one byte past the limit so Python reports the size error, not the browser.
async function bytesOf(file) {
  return new Uint8Array(await file.slice(0, MAX_BYTES + 1).arrayBuffer());
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (submit.disabled) return;
  submit.disabled = true;
  status.textContent = "Comparing…";
  let outcome;
  try {
    outcome = compare(
      await bytesOf(files.before),
      await bytesOf(files.after),
      files.before.name,
      files.after.name,
      form.confirmed.checked,
      form.note.value,
    );
  } catch (reason) {
    outcome = { ok: false, text: `Unexpected error: ${reason?.message ?? reason}` };
  }
  result.hidden = !outcome.ok;
  error.hidden = outcome.ok;
  if (outcome.ok) {
    report.textContent = outcome.text;
    status.textContent = "Done. Review the report before sharing it: it contains network details.";
    result.scrollIntoView({ behavior: "smooth", block: "start" });
  } else {
    errorText.textContent = outcome.text;
    status.textContent = "";
  }
  refresh();
});

document.getElementById("download").addEventListener("click", () => {
  const url = URL.createObjectURL(new Blob([report.textContent], { type: "text/markdown" }));
  const link = Object.assign(document.createElement("a"), {
    href: url,
    download: "watchpost-report.md",
  });
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
});

document.getElementById("copy").addEventListener("click", async (event) => {
  try {
    await navigator.clipboard.writeText(report.textContent);
    event.target.textContent = "Copied";
  } catch {
    event.target.textContent = "Copy failed";
  }
  setTimeout(() => (event.target.textContent = "Copy"), 1500);
});

async function boot() {
  const text = (path) => fetch(path).then((r) => (r.ok ? r.text() : Promise.reject(r.status)));
  const [watchpost, watchpostReport, wheel] = await Promise.all([
    text("py/watchpost.py"),
    text("py/watchpost_report.py"),
    fetch(WHEEL).then((r) => (r.ok ? r.arrayBuffer() : Promise.reject(r.status))),
  ]);
  compare = await startWatchpost(loadPyodide, {
    indexURL: new URL("pyodide/", import.meta.url).href,
    sources: { "watchpost.py": watchpost, "watchpost_report.py": watchpostReport },
    wheel,
  });
  status.textContent = "Ready. Nothing you select leaves this tab.";
  refresh();
}

boot().catch((reason) => {
  status.textContent = `Could not load the Python runtime (${reason}). Reload to try again.`;
});
