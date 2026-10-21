"""JSON output checks use synthetic inputs and temporary files only."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from defusedxml import ElementTree

from watchpost import main, read_snapshot
from watchpost_report import LIMITATIONS

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
BEFORE, AFTER = EXAMPLES / "baseline.xml", EXAMPLES / "after.xml"


def run_watchpost(*args):
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        try:
            code = main([str(arg) for arg in args])
        except SystemExit as exc:
            code = exc.code
    return code, stdout.getvalue(), stderr.getvalue()


class JsonTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def compare_json(self, *extra, before=BEFORE, after=AFTER):
        code, stdout, stderr = run_watchpost(
            "compare", before, after, "--confirm-same-context", "--format", "json", *extra
        )
        self.assertEqual((code, stderr), (0, ""))
        return stdout

    def test_json_carries_the_same_evidence_and_limitations(self):
        output = self.compare_json()
        self.assertEqual(output, self.compare_json())
        document = json.loads(output)
        self.assertEqual(
            (document["format"], document["format_version"]), ("watchpost-comparison", 1)
        )
        self.assertIn("not a security verdict", document["notice"])
        self.assertEqual(document["context"], {"confirmed_by_user": True, "note": None})
        self.assertEqual(document["snapshots"]["earlier"]["sha256"], read_snapshot(BEFORE).sha256)
        self.assertEqual(document["summary"]["total_differences"], 1)
        self.assertEqual(document["summary"]["by_category"]["Port state changed"], 1)
        [finding] = document["findings"]
        self.assertEqual(
            (finding["key"], finding["kind"], finding["address"], finding["port"]),
            ("192.0.2.10/tcp/3000", "port", "192.0.2.10", 3000),
        )
        self.assertEqual(finding["earlier"]["record"], "closed")
        self.assertEqual(finding["earlier"]["reason"], "conn-refused")
        self.assertEqual(finding["later"]["record"], "open")
        self.assertEqual(finding["later"]["host_status"], "up")
        self.assertIn("does not identify the application", finding["explanation"])
        self.assertIsNone(document["expectations"])
        self.assertEqual(document["limitations"], list(LIMITATIONS))

    def test_absence_is_the_string_not_observed_never_null(self):
        root = ElementTree.fromstring(AFTER.read_text(encoding="utf-8"))
        root.findall("host")[1].find("address").set("addr", "192.0.2.30")
        moved = self.directory / "moved.xml"
        moved.write_text(ElementTree.tostring(root, encoding="unicode"), encoding="utf-8")
        findings = json.loads(self.compare_json(after=moved))["findings"]
        records = {finding["key"]: finding for finding in findings}
        self.assertEqual(records["192.0.2.20"]["later"]["record"], "not observed")
        self.assertEqual(records["192.0.2.20"]["later"]["host_status"], "not observed")
        self.assertIsNone(records["192.0.2.20"]["later"]["grouped_counts"])
        self.assertEqual(records["192.0.2.20/tcp/22"]["later"]["record"], "not observed")
        self.assertEqual(records["192.0.2.30/tcp/22"]["earlier"]["record"], "not observed")
        for finding in findings:
            for side in (finding["earlier"], finding["later"]):
                self.assertIsInstance(side["record"], str)
                if finding["kind"] == "port" and side["record"] == "not observed":
                    self.assertIsNone(side["reason"])

    def test_saved_json_is_never_overwritten_and_escapes_user_text(self):
        output = self.directory / "review.json"
        note = "users VLAN\n\x1b[31m café"
        code, stdout, stderr = run_watchpost(
            "compare", BEFORE, AFTER, "--confirm-same-context", "--format", "json",
            "--context-note", note, "--output", output,
        )  # fmt: skip
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("Report saved to", stdout)
        saved = output.read_bytes()
        self.assertTrue(saved.isascii())
        self.assertNotIn(b"\x1b", saved)
        self.assertEqual(json.loads(saved)["context"]["note"], note)
        code, _, stderr = run_watchpost(
            "compare", BEFORE, AFTER, "--confirm-same-context", "--format", "json",
            "--output", output,
        )  # fmt: skip
        self.assertEqual(code, 2)
        self.assertIn("already exists", stderr)
        self.assertEqual(output.read_bytes(), saved)

    def test_expectations_are_included_as_the_reviewer_statements(self):
        expect = EXAMPLES / "expected-deployment.toml"
        document = json.loads(self.compare_json("--expect", expect))
        expectations = document["expectations"]
        self.assertEqual(
            expectations["results"], {"matches": 2, "differs": 0, "cannot be checked": 1}
        )
        entries = {entry["key"]: entry for entry in expectations["entries"]}
        self.assertEqual(entries["192.0.2.10/tcp/3000"]["expected_later_states"], ["open"])
        self.assertEqual(entries["192.0.2.10/tcp/3000"]["result"], "matches")
        self.assertEqual(
            entries["192.0.2.20/tcp/3000"]["later"], {"record": "not observed", "reason": None}
        )
        self.assertIn("A match is not a safety verdict", expectations["notice"])
        self.assertEqual(len(document["limitations"]), len(LIMITATIONS) + 1)


if __name__ == "__main__":
    unittest.main()
