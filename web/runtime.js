// Shared by the page and the Node smoke test. Runs Watchpost's own Python inside Pyodide.

const GLUE = `
import sys

sys.path.insert(0, "/watchpost")
from watchpost import compare_report


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
  const compare = pyodide.globals.get("watchpost_compare");

  return (before, after, beforeName, afterName, confirmed, note = "") => {
    const result = compare(before, after, beforeName, afterName, confirmed, note);
    try {
      const [ok, text] = result.toJs();
      return { ok, text };
    } finally {
      result.destroy();
    }
  };
}
