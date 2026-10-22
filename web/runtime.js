// Shared by the page and the Node smoke test. Runs Watchpost's own Python inside Pyodide.

const GLUE = `
import sys

sys.path.insert(0, "/watchpost")
from watchpost import MAX_XML_BYTES, compare_report, inspect_text


def watchpost_compare(before, after, before_name, after_name, confirmed, note):
    try:
        report = compare_report(
            before.to_bytes(),
            after.to_bytes(),
            before_name=before_name,
            after_name=after_name,
            same_context_confirmed=confirmed,
            context_note=note or None,
        )
    except ValueError as exc:
        return False, str(exc)
    return True, report


def watchpost_inspect(data, name):
    try:
        return True, inspect_text(data.to_bytes(), name=name)
    except ValueError as exc:
        return False, str(exc)
`;

/**
 * @param {Function} loadPyodide
 * @param {{indexURL: string, sources: Record<string, string>, wheel: ArrayBuffer}} assets
 */
export async function startWatchpost(loadPyodide, { indexURL, sources, wheel }) {
  const pyodide = await loadPyodide({ indexURL, stdout: () => {}, stderr: () => {} });
  pyodide.FS.mkdirTree("/watchpost");
  for (const [name, text] of Object.entries(sources)) {
    pyodide.FS.writeFile(`/watchpost/${name}`, text);
  }
  pyodide.unpackArchive(wheel, "wheel", { extractDir: "/watchpost" });
  pyodide.runPython(GLUE);

  // Each Python function returns (ok, text); copy it out and free the proxy.
  const wrap = (name) => {
    const call = pyodide.globals.get(name);
    return (...args) => {
      const result = call(...args);
      try {
        const [ok, text] = result.toJs();
        return { ok, text };
      } finally {
        result.destroy();
      }
    };
  };
  const compare = wrap("watchpost_compare");
  return {
    compare: (before, after, beforeName, afterName, confirmed, note = "") =>
      compare(before, after, beforeName, afterName, confirmed, note),
    inspect: wrap("watchpost_inspect"),
    maxBytes: pyodide.globals.get("MAX_XML_BYTES"),
  };
}
