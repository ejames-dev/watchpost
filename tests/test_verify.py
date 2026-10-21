"""Report verification checks using synthetic inputs and temporary reports only."""

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from watchpost import main

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
BEFORE, AFTER = EXAMPLES / "baseline.xml", EXAMPLES / "after.xml"


class VerifyTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.report = self.directory / "review.md"

    def run_watchpost(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                code = main([str(arg) for arg in args])
            except SystemExit as exc:
                code = exc.code
        return code, stdout.getvalue(), stderr.getvalue()

    def save_report(self, before=BEFORE, after=AFTER, *extra):
        code, _, stderr = self.run_watchpost(
            "compare", before, after, "--confirm-same-context", "--output", self.report, *extra
        )
        self.assertEqual(code, 0, stderr)
        return self.report.read_text(encoding="utf-8")

    def verify(self, before=BEFORE, after=AFTER):
        return self.run_watchpost("verify", self.report, before, after)

    def test_saved_report_matches_its_snapshots(self):
        self.save_report()
        code, stdout, stderr = self.verify()
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("Report evidence matches both snapshots.", stdout)
        self.assertIn("Not checked: source path labels, the context note, and human", stdout)

    def test_review_notes_labels_and_line_endings_do_not_affect_verification(self):
        report = self.save_report(BEFORE, AFTER, "--context-note", "users VLAN")
        report = report.replace(
            "**Investigation notes:**\n",
            "**Investigation notes:** Plan allows TCP 3000.\n\n- Firewall checked.\n# Aside\n",
        )
        report = report.replace("**Conclusion:**\n", "**Conclusion:** Matches the plan.\n")
        report = report.replace("**Reviewer:**\n", "**Reviewer:** A. Student\n")
        report = report.replace("'users VLAN'", "'lab bench'")
        report = report.replace(ascii(str(BEFORE)), "'renamed.xml'")
        self.report.write_bytes(report.replace("\n", "\r\n").encode("utf-8-sig"))
        code, stdout, stderr = self.verify()
        self.assertEqual((code, stderr), (0, ""), stdout)

    def test_changed_evidence_is_reported_by_line_with_controls_escaped(self):
        report = self.save_report()
        number = next(
            index
            for index, line in enumerate(report.splitlines(), 1)
            if line.startswith("- **Later evidence:** `open`")
        )
        tampered = report.replace(
            "`open`, reason `syn-ack` —", "`closed\x1b[31m`, reason `syn-ack` —"
        )
        self.report.write_text(tampered, encoding="utf-8")
        code, stdout, stderr = self.verify()
        self.assertEqual((code, stderr), (1, ""))
        self.assertIn("Report evidence does not match these snapshots.", stdout)
        self.assertIn(
            f"  Line {number}:\n    found:    - **Later evidence:** `closed\\x1b[31m`", stdout
        )
        self.assertIn("    expected: - **Later evidence:** `open`, reason `syn-ack` —", stdout)
        self.assertNotIn("\x1b", stdout)

    def test_different_input_bytes_fail_on_the_hash(self):
        self.save_report()
        resaved = self.directory / "after.xml"
        resaved.write_bytes(AFTER.read_bytes() + b"\n<!-- re-saved -->\n")
        code, stdout, _ = self.verify(after=resaved)
        self.assertEqual(code, 1)
        self.assertIn("    found:    - SHA-256: `", stdout)

    def test_truncated_report_lists_missing_lines(self):
        report = self.save_report()
        self.report.write_text("\n".join(report.splitlines()[:20]) + "\n", encoding="utf-8")
        code, stdout, _ = self.verify()
        self.assertEqual(code, 1)
        self.assertIn("  After the last line:\n    found:    (nothing)\n", stdout)
        self.assertRegex(stdout, r"\.\.\.and [0-9]+ more differences\n$")

    def test_identical_snapshots_report_verifies(self):
        self.save_report(BEFORE, BEFORE)
        code, stdout, _ = self.verify(BEFORE, BEFORE)
        self.assertEqual(code, 0, stdout)

    def test_unusable_inputs_exit_2_without_output(self):
        self.save_report()
        not_utf8 = self.directory / "binary.md"
        not_utf8.write_bytes(b"\xff\xfe not UTF-8")
        cases = (
            ((self.directory / "missing.md", BEFORE, AFTER), "Report must be an existing"),
            ((not_utf8, BEFORE, AFTER), "UTF-8"),
            ((self.report, AFTER, BEFORE), "reversed"),
            ((self.report, BEFORE, EXAMPLES / "incomplete.xml"), "incomplete"),
        )
        for args, message in cases:
            with self.subTest(message=message):
                code, stdout, stderr = self.run_watchpost("verify", *args)
                self.assertEqual((code, stdout), (2, ""))
                self.assertIn(message, stderr)
                self.assertNotIn("Traceback", stderr)


if __name__ == "__main__":
    unittest.main()
