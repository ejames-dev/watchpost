import { loadPyodide } from "./pyodide/pyodide.mjs";
import { startWatchpost } from "./runtime.js";

const WHEEL = "wheels/defusedxml-0.7.1-py2.py3-none-any.whl";

const form = document.getElementById("compare");
const submit = form.querySelector("button[type=submit]");
const status = document.getElementById("status");
const result = document.getElementById("result");
const report = document.getElementById("report");
const error = document.getElementById("error");
const errorText = document.getElementById("error-text");
const inspectForm = document.getElementById("inspect");
const inspectSubmit = inspectForm.querySelector("button[type=submit]");
const inspection = document.getElementById("inspection");
const inspectError = document.getElementById("inspect-error");
const inspectErrorText = document.getElementById("inspect-error-text");
const files = { before: null, after: null, single: null };
let watchpost = null;

function refresh() {
  submit.disabled = !(watchpost && files.before && files.after && form.confirmed.checked);
  inspectSubmit.disabled = !(watchpost && files.single);
}

function hideComparison() {
  result.hidden = error.hidden = true;
}

function setFile(slot, file) {
  files[slot] = file ?? null;
  const drop = document.querySelector(`.drop[data-slot=${slot}]`);
  const label = drop.querySelector(".drop-file");
  label.textContent = file ? file.name : label.dataset.empty;
  drop.classList.toggle("filled", Boolean(file));
  if (slot === "single") {
    inspection.hidden = inspectError.hidden = true;
  } else {
    hideComparison();
  }
  refresh();
}

for (const drop of document.querySelectorAll(".drop")) {
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
form.note.addEventListener("input", hideComparison);

// Read at most one byte past the limit so Python reports the size error, not the browser.
async function bytesOf(file) {
  return new Uint8Array(await file.slice(0, watchpost.maxBytes + 1).arrayBuffer());
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (submit.disabled) return;
  submit.disabled = true;
  status.textContent = "Comparing…";
  let outcome;
  try {
    outcome = watchpost.compare(
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

inspectForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (inspectSubmit.disabled) return;
  inspectSubmit.disabled = true;
  let outcome;
  try {
    outcome = watchpost.inspect(await bytesOf(files.single), files.single.name);
  } catch (reason) {
    outcome = { ok: false, text: `Unexpected error: ${reason?.message ?? reason}` };
  }
  inspection.hidden = !outcome.ok;
  inspectError.hidden = outcome.ok;
  (outcome.ok ? inspection : inspectErrorText).textContent = outcome.text;
  refresh();
});

// The examples are synthetic files served by this site. The context checkbox stays unticked.
document.getElementById("examples").addEventListener("click", async () => {
  const load = async (name) => {
    const response = await fetch(`examples/${name}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return new File([await response.blob()], name, { type: "application/xml" });
  };
  try {
    const [before, after] = await Promise.all([load("baseline.xml"), load("after.xml")]);
    setFile("before", before);
    setFile("after", after);
    status.textContent = "Synthetic examples loaded. Confirm the scan context, then compare.";
  } catch (reason) {
    status.textContent = `Could not load the examples (${reason?.message ?? reason}).`;
  }
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
  const [watchpostSource, reportSource, wheel] = await Promise.all([
    text("py/watchpost.py"),
    text("py/watchpost_report.py"),
    fetch(WHEEL).then((r) => (r.ok ? r.arrayBuffer() : Promise.reject(r.status))),
  ]);
  watchpost = await startWatchpost(loadPyodide, {
    indexURL: new URL("pyodide/", import.meta.url).href,
    sources: { "watchpost.py": watchpostSource, "watchpost_report.py": reportSource },
    wheel,
  });
  status.textContent = "Ready. Nothing you select leaves this tab.";
  refresh();
}

boot().catch((reason) => {
  status.textContent = `Could not load the Python runtime (${reason}). Reload to try again.`;
});

// Keep a copy of this site's own files so the page also works offline after this visit.
if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("sw.js").catch(() => {});
}
