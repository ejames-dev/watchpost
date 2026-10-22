"""Opt-in scan and exit-code checks. A fake runner stands in for Nmap; no test starts a scan."""

import errno
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from watchpost import main
from watchpost_scan import NMAP_PROFILE, nmap_command, run_scan, scan_targets

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
BASELINE = (EXAMPLES / "baseline.xml").read_bytes()
NMAP = "/opt/nmap/bin/nmap"
TARGETS = ["192.0.2.10", "192.0.2.20"]
COMMAND = [NMAP, "-sT", "-Pn", "-n", "--no-stylesheet", "-p", "22,80,443,3000", "-oX", "-"]


def run_watchpost(*args):
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        try:
            code = main([str(arg) for arg in args])
        except SystemExit as exc:
            code = exc.code
    return code, stdout.getvalue(), stderr.getvalue()


class FakeNmap:
    """Record each call and write prepared XML where Nmap would write its output."""

    def __init__(self, xml=BASELINE, returncode=0, error=None):
        self.xml, self.returncode, self.error, self.calls = xml, returncode, error, []

    def __call__(self, command, **options):
        self.calls.append((command, options))
        if self.error is not None:
            raise self.error
        options["stdout"].write(self.xml)
        options["stdout"].flush()
        return subprocess.CompletedProcess(command, self.returncode)


class TargetTests(unittest.TestCase):
    def test_accepts_explicit_ipv4_addresses_and_networks(self):
        self.assertEqual(
            scan_targets(["192.0.2.10", "192.0.2.32/28", "198.51.100.0/255.255.255.240"]),
            ["192.0.2.10", "192.0.2.32/28", "198.51.100.0/28"],
        )
        self.assertEqual(scan_targets(["192.0.2.10/32", "127.0.0.1"]), ["192.0.2.10", "127.0.0.1"])

    def test_rejects_names_ipv6_ranges_and_options(self):
        for value in ("router.lan", "2001:db8::1", "192.0.2.1-20", "192.0.2.10/24", "-oX", ""):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "IPv4 address"):
                scan_targets([value])

    def test_rejects_multicast_reserved_and_unspecified_addresses(self):
        for value in ("224.0.0.1", "240.0.0.1", "255.255.255.255", "0.0.0.0"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "multicast"):
                scan_targets([value])

    def test_rejects_repeated_overlapping_and_oversized_targets(self):
        for values in (["192.0.2.10", "192.0.2.10"], ["192.0.2.0/28", "192.0.2.5"]):
            with self.subTest(values=values), self.assertRaisesRegex(ValueError, "overlaps"):
                scan_targets(values)
        self.assertEqual(len(scan_targets(["192.0.2.0/24"])), 1)
        for values in (["192.0.2.0/24", "198.51.100.1"], ["10.0.0.0/8"]):
            with self.subTest(values=values), self.assertRaisesRegex(ValueError, "more than 256"):
                scan_targets(values)

    def test_command_is_the_fixed_profile_with_xml_on_standard_output(self):
        self.assertEqual(NMAP_PROFILE, ("-sT", "-Pn", "-n", "--no-stylesheet"))
        self.assertEqual(
            nmap_command(NMAP, TARGETS, ["22", "80", "443", "3000"]), [*COMMAND, *TARGETS]
        )


class ScanCommandTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        which = patch("watchpost_scan.shutil.which", return_value=NMAP)
        which.start()
        self.addCleanup(which.stop)

    def scan(self, nmap, *extra, targets=TARGETS, ports="3000,22,80,443"):
        with patch("watchpost_scan.subprocess.run", side_effect=nmap):
            return run_watchpost(
                "scan", *targets, "--ports", ports, "--output-dir", self.directory, *extra
            )

    def confirmed(self, nmap, **options):
        return self.scan(nmap, "--confirm-authorized", **options)

    def saved(self):
        return sorted(self.directory.iterdir())

    def test_scan_saves_nmap_xml_as_a_new_file_and_preflights_it(self):
        nmap = FakeNmap()
        with patch("socket.socket", side_effect=AssertionError("Network access forbidden")):
            code, stdout, stderr = self.confirmed(nmap)
        self.assertEqual((code, stderr), (0, ""))
        [(command, options)] = nmap.calls
        self.assertEqual(command, [*COMMAND, *TARGETS])
        self.assertIs(options["stdin"], subprocess.DEVNULL)
        self.assertNotIn("shell", options)
        [path] = self.saved()
        self.assertRegex(path.name, r"^scan-[0-9]{8}T[0-9]{6}Z\.xml$")
        self.assertEqual(path.read_bytes(), BASELINE)
        self.assertIn(f"Running: {NMAP} -sT -Pn -n --no-stylesheet -p 22,80,443,3000", stdout)
        self.assertIn(f"Scan saved to {str(path)!a}", stdout)
        self.assertIn(f"SHA-256: {hashlib.sha256(BASELINE).hexdigest()}", stdout)
        self.assertIn("4 declared ports: 22, 80, 443, 3000", stdout)
        self.assertIn("IPv4 addresses with records: 2", stdout)
        self.assertIn("Ready to compare: yes.", stdout)
        self.assertIn("not evidence that a device answered", stdout)

    @unittest.skipUnless(os.name == "posix", "Windows ignores POSIX modes; folder access applies.")
    def test_saved_scan_is_private_on_posix(self):
        self.confirmed(FakeNmap())
        [path] = self.saved()
        self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0)

    def test_scan_requires_authorization_ports_and_valid_targets_before_running(self):
        cases = [
            (("--output-dir", self.directory), "--confirm-authorized"),
            (("--confirm-authorized", "--ports", "22"), "TARGET"),
        ]
        for args, message in cases:
            with self.subTest(args=args):
                nmap = FakeNmap()
                with patch("watchpost_scan.subprocess.run", side_effect=nmap):
                    code, _, stderr = run_watchpost("scan", *args)
                self.assertEqual(code, 2)
                self.assertIn(message, stderr)
                self.assertEqual(nmap.calls, [])
        for ports in ("22,22", "80-22", "http", "70000", ""):
            with self.subTest(ports=ports):
                nmap = FakeNmap()
                code, _, stderr = self.confirmed(nmap, ports=ports)
                self.assertEqual(code, 2)
                self.assertIn("--ports must list TCP ports", stderr)
                self.assertEqual(nmap.calls, [])
        nmap = FakeNmap()
        code, _, stderr = self.confirmed(nmap, targets=["router.lan"])
        self.assertEqual((code, nmap.calls), (2, []))
        self.assertIn("Hostnames are not accepted", stderr)
        self.assertEqual(self.saved(), [])

    def test_missing_nmap_or_output_directory_runs_nothing(self):
        nmap = FakeNmap()
        with patch("watchpost_scan.shutil.which", return_value=None):
            code, _, stderr = self.confirmed(nmap)
        self.assertEqual((code, nmap.calls), (2, []))
        self.assertIn("Nmap was not found", stderr)
        self.directory.rmdir()
        code, stdout, stderr = self.confirmed(nmap)
        self.assertEqual((code, stdout, nmap.calls), (2, "", []))
        self.assertIn("output directory does not exist", stderr)
        self.assertFalse(self.directory.exists())

    def test_failed_interrupted_or_empty_scans_save_nothing(self):
        cases = [
            (FakeNmap(returncode=1), "Nmap exited with code 1. Nothing was saved."),
            (FakeNmap(xml=b""), "Nmap wrote no XML. Nothing was saved."),
            (FakeNmap(error=FileNotFoundError(errno.ENOENT, "No such file")), "Cannot start Nmap"),
            (FakeNmap(error=KeyboardInterrupt()), "Scan interrupted. Nothing was saved."),
        ]
        for nmap, message in cases:
            with self.subTest(message=message):
                code, _, stderr = self.confirmed(nmap)
                self.assertEqual(code, 2)
                self.assertIn(message, stderr)
                self.assertNotIn("Traceback", stderr)
                self.assertEqual(self.saved(), [])

    def test_saved_scan_that_cannot_be_compared_is_kept_and_named(self):
        nmap = FakeNmap(xml=(EXAMPLES / "incomplete.xml").read_bytes())
        code, _, stderr = self.confirmed(nmap)
        [path] = self.saved()
        self.assertEqual(code, 2)
        self.assertIn(f"Scan saved to {str(path)!a}, but it is not ready to compare.", stderr)
        self.assertIn("Host scan is incomplete (timeout)", stderr)

    def test_saved_scan_must_record_the_requested_scan(self):
        syn = BASELINE.replace(b'type="connect"', b'type="syn"')
        cases = [
            (BASELINE, TARGETS, "22,80", "declared ports 22, 80, 443, 3000, not 22, 80"),
            (BASELINE, ["192.0.2.10"], "22,80,443,3000", "unlisted addresses, such as 192.0.2.20"),
            (syn, TARGETS, "22,80,443,3000", "scan type syn, not connect"),
        ]
        parent = self.directory
        for number, (xml, targets, ports, message) in enumerate(cases):
            with self.subTest(message=message):
                # Each case gets its own directory: file names only change once a second.
                self.directory = parent / str(number)
                self.directory.mkdir()
                code, stdout, stderr = self.confirmed(FakeNmap(xml), targets=targets, ports=ports)
                [path] = self.saved()
                self.assertEqual(code, 2)
                self.assertNotIn("Ready to compare", stdout)
                self.assertIn(f"Scan saved to {str(path)!a}, but it does not match", stderr)
                self.assertIn(message, stderr)

    def test_existing_or_concurrent_destinations_are_never_replaced(self):
        destination = self.directory / "scan.xml"
        destination.write_text("Keep this scan.", encoding="utf-8")
        nmap = FakeNmap()
        with (
            patch("watchpost_scan.subprocess.run", side_effect=nmap),
            self.assertRaisesRegex(ValueError, "already exists"),
        ):
            run_scan([NMAP], destination)
        self.assertEqual(nmap.calls, [])
        destination.unlink()

        def competing_link(source, target):
            Path(target).write_text("Another writer's scan.", encoding="utf-8")
            raise FileExistsError(errno.EEXIST, "File exists")

        with (
            patch("watchpost_scan.subprocess.run", side_effect=FakeNmap()),
            patch("watchpost_scan.os.link", side_effect=competing_link),
            self.assertRaisesRegex(ValueError, "already exists"),
        ):
            run_scan([NMAP], destination)
        self.assertEqual(destination.read_text(encoding="utf-8"), "Another writer's scan.")
        self.assertEqual(self.saved(), [destination])

    def test_offline_commands_do_not_load_the_scan_module(self):
        code = (
            "import sys, watchpost; "
            "watchpost.main(['inspect', 'examples/baseline.xml']); "
            "assert 'watchpost_scan' not in sys.modules"
        )
        result = subprocess.run(
            [sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)


class ExitCodeTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def compare(self, before, after, *extra):
        return run_watchpost(
            "compare", EXAMPLES / before, EXAMPLES / after, "--confirm-same-context", *extra
        )

    def test_differences_exit_1_only_when_asked(self):
        self.assertEqual(self.compare("baseline.xml", "after.xml")[0], 0)
        code, stdout, stderr = self.compare("baseline.xml", "after.xml", "--exit-code")
        self.assertEqual((code, stderr), (1, ""))
        self.assertIn("Observation differences: 1", stdout)
        code, stdout, _ = self.compare("baseline.xml", "baseline.xml", "--exit-code")
        self.assertEqual(code, 0)
        self.assertIn("No observed changes", stdout)

    def test_saved_and_json_output_keep_the_exit_code(self):
        report = self.directory / "review.md"
        code, stdout, _ = self.compare(
            "baseline.xml", "after.xml", "--exit-code", "--output", report
        )
        self.assertEqual(code, 1)
        self.assertIn("Report saved to", stdout)
        self.assertTrue(report.is_file())
        code, stdout, _ = self.compare(
            "baseline.xml", "after.xml", "--exit-code", "--format", "json"
        )
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(stdout)["summary"]["total_differences"], 1)

    def test_exit_code_still_requires_confirmation_and_refuses_bad_pairs(self):
        before, after = EXAMPLES / "baseline.xml", EXAMPLES / "after.xml"
        code, stdout, stderr = run_watchpost("compare", before, after, "--exit-code")
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("--confirm-same-context", stderr)
        code, stdout, stderr = self.compare("after.xml", "baseline.xml", "--exit-code")
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("Snapshots are reversed", stderr)

    def test_help_lists_the_exit_codes(self):
        code, stdout, _ = run_watchpost("--help")
        self.assertEqual(code, 0)
        self.assertRegex(" ".join(stdout.split()), re.escape("1 differences found by verify"))


if __name__ == "__main__":
    unittest.main()
