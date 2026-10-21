"""Expectation checks use synthetic inputs and fictional reviewer statements only."""

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from watchpost import (
    compare_snapshots,
    main,
    parse_expectations,
    read_expectations,
    read_snapshot,
)
from watchpost_report import EXPECT_HEADING, expectation_result, render_markdown

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
BEFORE, AFTER = EXAMPLES / "baseline.xml", EXAMPLES / "after.xml"


def parse(text):
    data = text if isinstance(text, bytes) else text.encode("utf-8")
    return parse_expectations(data, Path("expect.toml"))


def run_watchpost(*args):
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        try:
            code = main([str(arg) for arg in args])
        except SystemExit as exc:
            code = exc.code
    return code, stdout.getvalue(), stderr.getvalue()


class ParseTests(unittest.TestCase):
    def test_reads_states_lists_and_labels_in_numerical_order(self):
        parsed = parse(
            '[expect."192.0.2.20/tcp/80"]\nstate = ["filtered", "closed"]\n'
            '[expect."192.0.2.10/tcp/3000"]\nstate = "open"\nlabel = "Demo app (plan v2)"\n'
        )
        self.assertEqual(
            [item.key for item in parsed.entries], ["192.0.2.10/tcp/3000", "192.0.2.20/tcp/80"]
        )
        self.assertEqual(parsed.entries[0].label, "Demo app (plan v2)")
        self.assertEqual(parsed.entries[1].states, ("closed", "filtered"))
        self.assertIsNone(parsed.entries[1].label)
        self.assertRegex(parsed.sha256, r"^[0-9a-f]{64}$")

    def test_rejects_malformed_files_and_entries(self):
        key = '[expect."192.0.2.10/tcp/22"]\n'
        cases = {
            "not TOML": ("expect = [", "TOML"),
            "not UTF-8": (b"\xff", "UTF-8"),
            "no tables": ("", "one or more"),
            "extra top-level key": (f'version = 1\n{key}state = "open"\n', "nothing else"),
            "bad key": ('[expect."host/tcp/22"]\nstate = "open"\n', "must look like"),
            "leading zero": ('[expect."192.0.2.010/tcp/22"]\nstate = "open"\n', "must look like"),
            "UDP key": ('[expect."192.0.2.10/udp/53"]\nstate = "open"\n', "must look like"),
            "port too large": ('[expect."192.0.2.10/tcp/65536"]\nstate = "open"\n', "must look"),
            "missing state": (f'{key}label = "SSH"\n', "needs a state"),
            "unknown field": (f'{key}state = "open"\nnote = "x"\n', "nothing else"),
            "invalid state": (f'{key}state = "safe"\n', "Nmap port states"),
            "empty state list": (f"{key}state = []\n", "Nmap port states"),
            "nested state": (f'{key}state = [["open"]]\n', "Nmap port states"),
            "duplicate state": (f'{key}state = ["open", "open"]\n', "twice"),
            "markup label": (f'{key}state = "open"\nlabel = "`x` | y"\n', "label"),
            "blank label": (f'{key}state = "open"\nlabel = "  "\n', "label"),
            "long label": (f'{key}state = "open"\nlabel = "{"x" * 121}"\n', "label"),
        }
        for name, (text, message) in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, message):
                parse(text)

    def test_rejects_oversized_and_missing_files(self):
        with self.assertRaisesRegex(ValueError, "1 MiB"):
            parse(b" " * (1024 * 1024 + 1))
        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaisesRegex(ValueError, "existing regular file"),
        ):
            read_expectations(Path(directory) / "missing.toml")


class ResultTests(unittest.TestCase):
    def setUp(self):
        self.before, self.after = read_snapshot(BEFORE), read_snapshot(AFTER)

    def test_results_use_explicit_later_records_only(self):
        parsed = parse(
            '[expect."192.0.2.10/tcp/3000"]\nstate = "open"\n'
            '[expect."192.0.2.10/tcp/80"]\nstate = "open"\n'
            '[expect."192.0.2.20/tcp/80"]\nstate = "closed"\n'
            '[expect."192.0.2.10/tcp/8080"]\nstate = "closed"\n'
            '[expect."192.0.2.99/tcp/22"]\nstate = ["closed", "filtered"]\n'
        )
        results = {item.key: expectation_result(item, self.after) for item in parsed.entries}
        self.assertEqual(
            results,
            {
                "192.0.2.10/tcp/80": "differs",
                "192.0.2.10/tcp/3000": "matches",
                "192.0.2.10/tcp/8080": "cannot be checked: the later scan did not cover this port",
                # Grouped closed counts cover this port, but they are not an explicit record.
                "192.0.2.20/tcp/80": "cannot be checked: no explicit later record",
                "192.0.2.99/tcp/22": "cannot be checked: no explicit later record",
            },
        )

    def test_report_section_and_finding_line_quote_the_reviewer(self):
        changes = compare_snapshots(self.before, self.after, same_context_confirmed=True)
        parsed = read_expectations(EXAMPLES / "backend-policy.toml")
        report = render_markdown(self.before, self.after, changes, expectations=parsed)
        label = "`Backend reachable only through the local reverse proxy`"
        for expected in (
            f"{EXPECT_HEADING}\n\nExpectations file (escaped literal):\n\n"
            f"    {str(parsed.source)!a}\n\n- SHA-256: `{parsed.sha256}`\n"
            "- Results: matches 0; differs 1; cannot be checked 0\n",
            f"| `192.0.2.10/tcp/3000` | `closed` or `filtered` | `open`, reason `syn-ack` "
            f"| Differs | {label} |",
            f"- **Your expectation:** `closed` or `filtered` — differs. Your label: {label}.",
            "A match is not a safety verdict, and a difference is not proof of a problem.",
            "- Expectations and their labels are your own statements.",
        ):
            with self.subTest(expected=expected[:40]):
                self.assertIn(expected, report)
        for verdict in ("compliant", "violation"):
            self.assertNotIn(verdict, report.lower())
        self.assertNotIn(EXPECT_HEADING, render_markdown(self.before, self.after, changes))


class CommandTests(unittest.TestCase):
    def test_same_evidence_different_expectations(self):
        outputs = {}
        for name in ("expected-deployment", "backend-policy"):
            expect = EXAMPLES / f"{name}.toml"
            code, stdout, stderr = run_watchpost(
                "compare", BEFORE, AFTER, "--confirm-same-context", "--expect", expect
            )
            self.assertEqual((code, stderr), (0, ""))
            outputs[name] = stdout
        deployment, policy = outputs["expected-deployment"], outputs["backend-policy"]
        self.assertIn(
            "  192.0.2.10/tcp/3000: expected open; later open (syn-ack) -> matches "
            "[Demo app approved in the lab deployment plan]\n",
            deployment,
        )
        self.assertIn(
            "  192.0.2.20/tcp/3000: expected closed or filtered; later not observed -> "
            "cannot be checked: no explicit later record",
            deployment,
        )
        self.assertIn("Expectation results: matches 2; differs 0; cannot be checked 1", deployment)
        self.assertIn(
            "  192.0.2.10/tcp/3000: expected closed or filtered; later open (syn-ack) -> differs",
            policy,
        )
        self.assertEqual(deployment.split("Expectations (")[0], policy.split("Expectations (")[0])

    def test_unusable_expectations_stop_before_any_output(self):
        with tempfile.TemporaryDirectory() as directory:
            broken = Path(directory) / "broken.toml"
            broken.write_text("expect = [", encoding="utf-8")
            code, stdout, stderr = run_watchpost(
                "compare", BEFORE, AFTER, "--confirm-same-context", "--expect", broken
            )
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("not valid UTF-8 TOML", stderr)

    def test_verify_needs_the_same_expectations_file(self):
        expect = EXAMPLES / "expected-deployment.toml"
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "review.md"
            code, _, stderr = run_watchpost(
                "compare", BEFORE, AFTER, "--confirm-same-context", "--expect", expect,
                "--output", report,
            )  # fmt: skip
            self.assertEqual(code, 0, stderr)
            code, stdout, stderr = run_watchpost("verify", report, BEFORE, AFTER)
            self.assertEqual((code, stdout), (2, ""))
            self.assertIn("Pass the same file with --expect", stderr)
            self.assertEqual(
                run_watchpost("verify", report, BEFORE, AFTER, "--expect", expect)[0], 0
            )
            other = EXAMPLES / "backend-policy.toml"
            code, stdout, _ = run_watchpost("verify", report, BEFORE, AFTER, "--expect", other)
            self.assertEqual(code, 1)
            self.assertIn("found:    - SHA-256: `", stdout)


if __name__ == "__main__":
    unittest.main()
