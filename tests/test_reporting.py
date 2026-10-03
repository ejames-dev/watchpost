"""Offline Markdown reporting checks using synthetic inputs and temporary outputs."""

import errno
import io
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from watchpost import compare_snapshots, main, read_snapshot
from watchpost_report import render_markdown, write_report

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


class ReportTests(unittest.TestCase):
    def report_for(self, old_inventory, new_inventory):
        before = replace(read_snapshot(EXAMPLES / "baseline.xml"), inventory=old_inventory)
        after = replace(read_snapshot(EXAMPLES / "after.xml"), inventory=new_inventory)
        changes = compare_snapshots(before, after, same_context_confirmed=True)
        return render_markdown(before, after, changes)

    def test_report_has_source_evidence_counts_and_blank_review_fields(self):
        before = read_snapshot(EXAMPLES / "baseline.xml")
        after = read_snapshot(EXAMPLES / "after.xml")
        changes = compare_snapshots(before, after, same_context_confirmed=True)
        report = render_markdown(before, after, changes)
        for expected in (
            "# Watchpost change review",
            "not a security verdict",
            f"    {str(before.source)!a}",
            f"    {str(after.source)!a}",
            "2026-01-01T00:00:00+00:00",
            "2026-01-01T00:01:01+00:00",
            "Nmap version: `7.95`",
            "Scan method: TCP `connect`",
            "Declared TCP ports: 4",
            "same location, intended targets, and other settings confirmed by user",
            "Total observation differences: **1**",
            "| Port state changed | 1 |",
            "| Port not observed later | 0 |",
            "IPv4 `192.0.2.10`, TCP port `3000` (numeric ID)",
            "**Earlier evidence:** `closed` — Earlier snapshot",
            "**Later evidence:** `open` — Later snapshot",
            "**Explanation:**",
            "**Suggested check:**",
            "**Investigation notes:**\n\n**Conclusion:**\n",
            "## Limitations",
            "**Reviewer:**\n\n**Reviewed at (UTC):**\n",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, report)
        self.assertTrue(report.endswith("\n"))
        self.assertEqual(report, render_markdown(before, after, changes))

    def test_new_and_missing_ports_do_not_invent_states(self):
        present, absent = {"192.0.2.10": {3000: "open"}}, {"192.0.2.10": {}}
        for old, new, category, earlier, later, explanation in (
            (absent, present, "Port newly observed", "not observed", "open", "no earlier"),
            (present, absent, "Port not observed later", "open", "not observed", "no later"),
        ):
            with self.subTest(category=category):
                report = self.report_for(old, new)
                self.assertIn(f"| {category} | 1 |", report)
                self.assertIn("| Port state changed | 0 |", report)
                self.assertIn(f"**Earlier evidence:** `{earlier}`", report)
                self.assertIn(f"**Later evidence:** `{later}`", report)
                self.assertIn(explanation, report)
                self.assertNotIn("**Earlier evidence:** `closed`", report)
                self.assertNotIn("**Later evidence:** `closed`", report)

    def test_address_and_port_counts_are_separate_observations(self):
        report = self.report_for({"192.0.2.100": {22: "open"}}, {"192.0.2.3": {80: "open"}})
        self.assertIn("Total observation differences: **4**", report)
        for category in (
            "Address newly observed",
            "Address not observed later",
            "Port newly observed",
            "Port not observed later",
        ):
            self.assertIn(f"| {category} | 1 |", report)
        self.assertIn("| Port state changed | 0 |", report)
        self.assertIn("not as distinct incidents or devices", report)
        self.assertIn("does not prove a device", report)
        self.assertLess(report.index("IPv4 `192.0.2.3`"), report.index("IPv4 `192.0.2.100`"))

    def test_explicit_closed_and_uncertain_states_retain_their_meaning(self):
        for state in ("closed", "filtered", "unfiltered", "open|filtered", "closed|filtered"):
            with self.subTest(state=state):
                report = self.report_for({"192.0.2.10": {22: "open"}}, {"192.0.2.10": {22: state}})
                self.assertIn("| Port state changed | 1 |", report)
                self.assertIn(f"**Later evidence:** `{state}`", report)
                explanation = (
                    "reports this port as closed"
                    if state == "closed"
                    else "does not establish open or closed"
                )
                self.assertIn(explanation, report)

    def test_identical_and_empty_observations_are_not_safety_verdicts(self):
        before = read_snapshot(EXAMPLES / "baseline.xml")
        for snapshot in (before, replace(before, inventory={})):
            with self.subTest(inventory=snapshot.inventory):
                changes = compare_snapshots(snapshot, snapshot, same_context_confirmed=True)
                report = render_markdown(snapshot, snapshot, changes)
                self.assertIn("Total observation differences: **0**", report)
                self.assertIn("No observed changes in explicit IPv4/TCP records.", report)
                self.assertIn("not a safety verdict", report)
                self.assertIn("**Overall investigation notes:**\n", report)
                self.assertNotIn("### 1.", report)

    def test_finding_order_stays_numerical(self):
        before = {"192.0.2.100": {443: "open", 22: "open"}, "192.0.2.20": {80: "open"}}
        after = {address: dict.fromkeys(ports, "closed") for address, ports in before.items()}
        report = self.report_for(before, after)
        self.assertLess(report.index("IPv4 `192.0.2.20`"), report.index("IPv4 `192.0.2.100`"))
        self.assertLess(report.index("TCP port `22`"), report.index("TCP port `443`"))
        self.assertEqual(report.count("**Investigation notes:**"), 3)

    def test_source_names_are_indented_escaped_literals_not_markdown(self):
        before = read_snapshot(EXAMPLES / "baseline.xml")
        name = "evil\n# INJECTED\n``` | ![image](x) <img src=x> \x1b[31m \u202e.xml"
        after = replace(read_snapshot(EXAMPLES / "after.xml"), source=Path(name))
        report = render_markdown(
            before, after, compare_snapshots(before, after, same_context_confirmed=True)
        )
        self.assertIn(f"\n    {str(after.source)!a}\n", report)
        self.assertNotIn("\n# INJECTED", report)
        self.assertNotIn("\x1b", report)
        self.assertNotIn("\u202e", report)
        for line in report.splitlines():
            if "INJECTED" in line or "<img" in line or "![image]" in line:
                self.assertTrue(line.startswith("    "), line)


class ReportCommandTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.output = self.directory / "review.md"

    def run_report(self, before=None, after=None, *, confirmed=True):
        args = [
            "compare",
            str(before or EXAMPLES / "baseline.xml"),
            str(after or EXAMPLES / "after.xml"),
            "--output",
            str(self.output),
        ]
        if confirmed:
            args.append("--confirm-same-context")
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                code = main(args)
            except SystemExit as exc:
                code = exc.code
        return code, stdout.getvalue(), stderr.getvalue()

    def test_compare_output_creates_utf8_report(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "review.md"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "watchpost",
                    "compare",
                    "examples/baseline.xml",
                    "examples/after.xml",
                    "--confirm-same-context",
                    "--output",
                    str(output),
                ],
                cwd=EXAMPLES.parent,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            self.assertIn("Report saved to", result.stdout)
            self.assertIn("# Watchpost change review", output.read_text(encoding="utf-8"))
            self.assertEqual(output.read_bytes(), (EXAMPLES / "report.md").read_bytes())
            self.assertNotIn(b"\r", output.read_bytes())
            self.assertEqual(list(Path(directory).iterdir()), [output])

    def test_confirmation_and_bad_inputs_fail_before_creating_reports(self):
        code, stdout, stderr = self.run_report(confirmed=False)
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("--confirm-same-context", stderr)
        self.assertEqual(list(self.directory.iterdir()), [])
        after_xml = (EXAMPLES / "after.xml").read_text(encoding="utf-8")
        bad = self.directory / "bad.xml"
        cases = (
            ("<nmaprun>", "Malformed XML"),
            (after_xml.replace('exit="success"', 'exit="error"'), "complete"),
            (after_xml.replace('type="connect"', 'type="syn"'), "methods differ"),
            (after_xml.replace('version="7.95"', 'version="7.96"'), "versions differ"),
            (
                after_xml.replace('services="22,80,443,3000"', 'services="22,80,443,3001"'),
                "coverage",
            ),
            (
                after_xml.replace('start="1767225660"', 'start="1767225600"'),
                "overlap",
            ),
            (
                after_xml.replace(
                    "<!DOCTYPE nmaprun>", '<!DOCTYPE nmaprun [<!ENTITY injected "unsafe">]>'
                ),
                "Unsafe XML",
            ),
        )
        for xml, error in cases:
            with self.subTest(error=error):
                bad.write_text(xml, encoding="utf-8")
                code, stdout, stderr = self.run_report(after=bad)
                self.assertEqual(code, 2)
                self.assertEqual(stdout, "")
                self.assertIn(error, stderr)
                self.assertNotIn("Traceback", stderr)
                self.assertEqual(list(self.directory.iterdir()), [bad])

    def test_existing_notes_and_input_aliases_are_not_overwritten(self):
        for content in (
            "Human investigation notes: keep this conclusion.\n",
            (EXAMPLES / "baseline.xml").read_text(encoding="utf-8"),
        ):
            with self.subTest(content=content[:20]):
                self.output.write_text(content, encoding="utf-8")
                before = self.output if content.startswith("<?xml") else None
                code, stdout, stderr = self.run_report(before=before)
                self.assertEqual(code, 2)
                self.assertEqual(stdout, "")
                self.assertIn("already exists", stderr)
                self.assertIn("Choose a new filename", stderr)
                self.assertEqual(self.output.read_text(encoding="utf-8"), content)
                self.assertEqual(list(self.directory.iterdir()), [self.output])

    def test_missing_parent_is_actionable_and_is_not_created(self):
        self.output = self.directory / "missing" / "report.md"
        code, stdout, stderr = self.run_report()
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("existing, writable directory", stderr)
        self.assertNotIn("Traceback", stderr)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_grouped_states_and_untrusted_xml_text_are_not_report_evidence(self):
        before_xml = (EXAMPLES / "baseline.xml").read_text(encoding="utf-8")
        after_xml = (EXAMPLES / "after.xml").read_text(encoding="utf-8")
        before_xml = before_xml.replace(
            '<port protocol="tcp" portid="3000"><state state="closed"',
            '<port protocol="tcp" portid="3000"><state state="open"',
        )
        port_line = next(line for line in after_xml.splitlines() if 'portid="3000"' in line)
        after_xml = after_xml.replace(port_line, '<extraports state="closed" count="1"/>')
        after_xml = after_xml.replace(
            "<ports>",
            '<hostnames><hostname name="UNTRUSTED_HOSTNAME"/></hostnames><ports>'
            '<script id="test" output="UNTRUSTED_SCRIPT"/>',
        )
        before, after = self.directory / "before.xml", self.directory / "after.xml"
        before.write_text(before_xml, encoding="utf-8")
        after.write_text(after_xml, encoding="utf-8")
        self.assertEqual(self.run_report(before, after)[0], 0)
        report = self.output.read_text(encoding="utf-8")
        self.assertIn("| Port not observed later | 1 |", report)
        self.assertIn("**Later evidence:** `not observed`", report)
        self.assertNotIn("**Later evidence:** `closed`", report)
        self.assertNotIn("UNTRUSTED_", report)

    def test_report_runs_repeatably_offline_and_escapes_terminal_output_path(self):
        reports = []
        with (
            patch("socket.socket", side_effect=AssertionError("Network access forbidden")),
            patch("socket.create_connection", side_effect=AssertionError("Network forbidden")),
            patch("urllib.request.urlopen", side_effect=AssertionError("Network forbidden")),
        ):
            for name in ("first.md", "second\n\x1b[31m.md"):
                self.output = self.directory / name
                code, stdout, stderr = self.run_report()
                self.assertEqual(code, 0, stderr)
                self.assertEqual(stderr, "")
                self.assertIn(ascii(str(self.output)), stdout)
                self.assertNotIn("\x1b", stdout)
                reports.append(self.output.read_bytes())
        self.assertEqual(reports[0], reports[1])


class ReportFileTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.output = self.directory / "report.md"

    def test_new_report_is_private_and_complete(self):
        content = "# Review\n\nEarlier → later.\n"
        write_report(self.output, content)
        self.assertEqual(self.output.read_bytes(), content.encode("utf-8"))
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode) & 0o077, 0)
        self.assertEqual(list(self.directory.iterdir()), [self.output])

    def test_existing_files_directories_and_links_are_preserved(self):
        notes = self.directory / "notes.md"
        notes.write_text("Keep my notes.", encoding="utf-8")
        folder = self.directory / "folder"
        folder.mkdir()
        linked = self.directory / "linked.md"
        linked.symlink_to(notes)
        dangling = self.directory / "dangling.md"
        target = self.directory / "not-created.md"
        dangling.symlink_to(target)
        hard_link = self.directory / "hard-link.md"
        os.link(notes, hard_link)
        existing = set(self.directory.iterdir())
        for destination in (notes, folder, linked, dangling, hard_link):
            with self.subTest(destination=destination):
                with self.assertRaisesRegex(ValueError, "already exists"):
                    write_report(destination, "replacement")
                self.assertEqual(set(self.directory.iterdir()), existing)
                self.assertEqual(notes.read_text(encoding="utf-8"), "Keep my notes.")
                self.assertEqual(hard_link.read_text(encoding="utf-8"), "Keep my notes.")
                self.assertTrue(linked.is_symlink())
                self.assertTrue(dangling.is_symlink())
                self.assertFalse(target.exists())
                self.assertTrue(folder.is_dir())

    def test_competing_writer_is_not_overwritten(self):
        def competing_link(source, destination):
            Path(destination).write_text("Another writer's notes.", encoding="utf-8")
            raise FileExistsError(errno.EEXIST, "File exists")

        with (
            patch("watchpost_report.os.link", side_effect=competing_link),
            self.assertRaisesRegex(ValueError, "already exists"),
        ):
            write_report(self.output, "Generated report")
        self.assertEqual(self.output.read_text(encoding="utf-8"), "Another writer's notes.")
        self.assertEqual(list(self.directory.iterdir()), [self.output])

    def test_failed_sync_or_publish_leaves_no_report_or_temporary_file(self):
        for operation in ("fsync", "link"):
            with self.subTest(operation=operation):
                with (
                    patch(
                        f"watchpost_report.os.{operation}",
                        side_effect=OSError(errno.EIO, "Simulated I/O error"),
                    ),
                    self.assertRaisesRegex(ValueError, "Cannot save report"),
                ):
                    write_report(self.output, "Generated report")
                self.assertEqual(list(self.directory.iterdir()), [])

    def test_partial_write_failure_does_not_publish_a_report(self):
        @contextmanager
        def failing_temporary(*args, **kwargs):
            with tempfile.NamedTemporaryFile(*args, **kwargs) as temporary:
                real_write = temporary.write

                def partial_write(content):
                    real_write(content[:5])
                    raise OSError(errno.ENOSPC, "Simulated disk full")

                temporary.write = partial_write
                yield temporary

        with (
            patch("watchpost_report.NamedTemporaryFile", side_effect=failing_temporary),
            self.assertRaisesRegex(ValueError, "Simulated disk full"),
        ):
            write_report(self.output, "Generated report")
        self.assertEqual(list(self.directory.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
