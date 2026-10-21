"""History checks use synthetic snapshots and temporary files only."""

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from defusedxml import ElementTree

from watchpost import history_timelines, main, read_snapshot

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
SERIES = [EXAMPLES / name for name in ("baseline.xml", "after.xml", "rollback.xml")]


def run_watchpost(*args):
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        try:
            code = main([str(arg) for arg in args])
        except SystemExit as exc:
            code = exc.code
    return code, stdout.getvalue(), stderr.getvalue()


class HistoryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def without_second_host(self):
        root = ElementTree.fromstring((EXAMPLES / "after.xml").read_text(encoding="utf-8"))
        root.remove(root.findall("host")[1])
        path = self.directory / "after-one-host.xml"
        path.write_text(ElementTree.tostring(root, encoding="unicode"), encoding="utf-8")
        return path

    def test_timelines_follow_each_changed_record(self):
        snapshots = [read_snapshot(path) for path in SERIES]
        self.assertEqual(
            history_timelines(snapshots, same_context_confirmed=True),
            [("192.0.2.10/tcp/3000", ["closed", "open", "closed"])],
        )
        code, stdout, stderr = run_watchpost("history", *SERIES, "--confirm-same-context")
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("Records with differences: 1\n", stdout)
        self.assertIn(
            "192.0.2.10/tcp/3000: closed (conn-refused) -> open (syn-ack) -> closed (conn-refused)",
            stdout,
        )
        self.assertIn("not a security verdict", stdout)

    def test_missing_records_stay_not_observed(self):
        series = [SERIES[0], self.without_second_host(), SERIES[2]]
        snapshots = [read_snapshot(path) for path in series]
        self.assertEqual(
            history_timelines(snapshots, same_context_confirmed=True),
            [
                ("192.0.2.10/tcp/3000", ["closed", "open", "closed"]),
                ("192.0.2.20", ["observed", None, "observed"]),
                ("192.0.2.20/tcp/22", ["open", None, "open"]),
            ],
        )
        code, stdout, _ = run_watchpost("history", *series, "--confirm-same-context")
        self.assertEqual(code, 0)
        self.assertIn("192.0.2.20: observed -> not observed -> observed\n", stdout)
        self.assertIn(
            "192.0.2.20/tcp/22: open (syn-ack) -> not observed -> open (syn-ack)\n", stdout
        )

    def test_unchanged_series_is_not_a_safety_verdict(self):
        code, stdout, _ = run_watchpost("history", SERIES[0], SERIES[0], "--confirm-same-context")
        self.assertEqual(code, 0)
        self.assertIn("Records with differences: 0\n", stdout)
        self.assertIn("No observed changes in explicit IPv4/TCP records across the series.", stdout)

    def test_each_pair_must_pass_the_comparison_gate(self):
        newer = self.directory / "newer-nmap.xml"
        newer.write_text(
            SERIES[2].read_text(encoding="utf-8").replace('version="7.95"', 'version="7.96"'),
            encoding="utf-8",
        )
        cases = (
            ((SERIES[0], SERIES[1], newer), "Snapshots 2 and 3: Nmap versions differ"),
            ((SERIES[0], SERIES[2], SERIES[1]), "Snapshots 2 and 3: Snapshots are reversed"),
            ((SERIES[0],), "History needs 2 to 50 snapshots"),
            ((SERIES[0], EXAMPLES / "incomplete.xml"), "incomplete"),
        )
        for paths, message in cases:
            with self.subTest(message=message):
                code, stdout, stderr = run_watchpost("history", *paths, "--confirm-same-context")
                self.assertEqual((code, stdout), (2, ""))
                self.assertIn(message, stderr)
                self.assertNotIn("Traceback", stderr)

    def test_confirmation_is_required(self):
        code, stdout, stderr = run_watchpost("history", *SERIES)
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("--confirm-same-context", stderr)
        with self.assertRaisesRegex(ValueError, "Confirm"):
            history_timelines([read_snapshot(path) for path in SERIES])


if __name__ == "__main__":
    unittest.main()
