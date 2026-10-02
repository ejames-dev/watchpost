"""Comparison tests use synthetic documentation addresses, never live scans."""

import io
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from defusedxml import ElementTree

from watchpost import Change, compare_snapshots, main, read_snapshot

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "baseline.xml"


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "later.xml"
        self.later_xml = (
            EXAMPLE.read_text()
            .replace("1767225600", "1767225660")
            .replace("1767225601", "1767225661")
        )

    def snapshot(self, xml, name="later.xml"):
        path = self.path.with_name(name)
        path.write_text(xml, encoding="utf-8")
        return read_snapshot(path)

    def test_reads_comparison_metadata_and_explicit_observations(self):
        snapshot = read_snapshot(EXAMPLE)
        self.assertEqual(snapshot.source, EXAMPLE)
        self.assertEqual(snapshot.started, datetime(2026, 1, 1, tzinfo=UTC))
        self.assertEqual(snapshot.finished, datetime(2026, 1, 1, 0, 0, 1, tzinfo=UTC))
        self.assertEqual(snapshot.method, "connect")
        self.assertEqual(snapshot.version, "7.95")
        self.assertEqual(snapshot.coverage, frozenset({22, 80, 443, 3000}))
        self.assertEqual(snapshot.inventory["192.0.2.10"][3000], "closed")
        self.assertEqual(snapshot.inventory["192.0.2.20"], {22: "open"})

    def test_compares_an_explicit_state_change(self):
        later = self.snapshot(
            self.later_xml.replace(
                '<port protocol="tcp" portid="3000"><state state="closed"',
                '<port protocol="tcp" portid="3000"><state state="open"',
            )
        )
        self.assertEqual(
            compare_snapshots(read_snapshot(EXAMPLE), later, same_context_confirmed=True),
            [Change("192.0.2.10", 3000, "closed", "open")],
        )

    def test_rejects_missing_or_invalid_comparison_metadata(self):
        scan_line = next(line for line in self.later_xml.splitlines() if "<scaninfo " in line)
        cases = {
            "missing start": (self.later_xml.replace('start="1767225660"', ""), "timestamps"),
            "missing finish": (
                self.later_xml.replace('time="1767225661" elapsed', "elapsed"),
                "timestamps",
            ),
            "negative timestamp": (
                self.later_xml.replace('start="1767225660"', 'start="-1"'),
                "timestamps",
            ),
            "nonnumeric timestamp": (
                self.later_xml.replace('start="1767225660"', 'start="tomorrow"'),
                "timestamps",
            ),
            "out of range timestamp": (
                self.later_xml.replace('start="1767225660"', 'start="253402300800"'),
                "calendar",
            ),
            "finish before start": (
                self.later_xml.replace('time="1767225661" elapsed', 'time="1767225600" elapsed'),
                "before its start",
            ),
            "missing version": (self.later_xml.replace('version="7.95"', ""), "version"),
            "control character in version": (
                self.later_xml.replace('version="7.95"', 'version="7.95&#10;injected"'),
                "version",
            ),
            "missing method": (self.later_xml.replace('type="connect"', ""), "exactly one"),
            "unsupported method": (
                self.later_xml.replace('type="connect"', 'type="ack"'),
                "exactly one",
            ),
            "multiple scans": (
                self.later_xml.replace(scan_line, scan_line + scan_line),
                "exactly one",
            ),
            "missing coverage": (
                self.later_xml.replace('services="22,80,443,3000"', ""),
                "coverage",
            ),
            "missing count": (self.later_xml.replace('numservices="4"', ""), "count"),
            "wrong count": (self.later_xml.replace('numservices="4"', 'numservices="5"'), "count"),
            "outside coverage": (
                self.later_xml.replace(
                    'services="22,80,443,3000"', 'services="80,443,3000"'
                ).replace('numservices="4"', 'numservices="3"'),
                "outside",
            ),
            "failed scan": (self.later_xml.replace('exit="success"', 'exit="error"'), "complete"),
            "host timeout": (
                self.later_xml.replace("<host starttime", '<host timedout="true" starttime'),
                "incomplete",
            ),
            "unsafe entity": (
                self.later_xml.replace(
                    "<!DOCTYPE nmaprun>",
                    '<!DOCTYPE nmaprun [<!ENTITY example SYSTEM "file:///watchpost-example">]>',
                ),
                "Unsafe XML",
            ),
        }
        for name, (xml, message) in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, message):
                self.snapshot(xml)

    def test_normalizes_port_lists_and_ranges(self):
        for services, count, expected in (
            ("3000,443,80,22", "4", {22, 80, 443, 3000}),
            ("22,80,443,3000-3001", "5", {22, 80, 443, 3000, 3001}),
            ("0-65535", "65536", set(range(65536))),
        ):
            with self.subTest(services=services):
                xml = self.later_xml.replace('services="22,80,443,3000"', f'services="{services}"')
                snapshot = self.snapshot(xml.replace('numservices="4"', f'numservices="{count}"'))
                self.assertEqual(snapshot.coverage, frozenset(expected))

    def test_rejects_invalid_or_overlapping_port_ranges(self):
        for services in (
            "",
            "-1",
            "65536",
            "80-22",
            "22,22",
            "22-80,80-443",
            "22,,80",
            "ssh",
            "22-",
            "22, 80",
            "22-80-443",
        ):
            with self.subTest(services=services), self.assertRaisesRegex(ValueError, "coverage"):
                self.snapshot(
                    self.later_xml.replace('services="22,80,443,3000"', f'services="{services}"')
                )

    def test_requires_context_confirmation(self):
        with self.assertRaisesRegex(ValueError, "Confirm"):
            compare_snapshots(read_snapshot(EXAMPLE), self.snapshot(self.later_xml))

    def test_rejects_incompatible_scans_even_when_user_confirms_context(self):
        cases = {
            "methods": self.later_xml.replace('type="connect"', 'type="syn"'),
            "versions": self.later_xml.replace('version="7.95"', 'version="7.96"'),
            "coverage": self.later_xml.replace(
                'services="22,80,443,3000"', 'services="22,80,443,3000-3001"'
            ).replace('numservices="4"', 'numservices="5"'),
        }
        for message, xml in cases.items():
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                compare_snapshots(
                    read_snapshot(EXAMPLE), self.snapshot(xml), same_context_confirmed=True
                )

    def test_rejects_reversed_and_overlapping_windows(self):
        before = read_snapshot(EXAMPLE)
        after = self.snapshot(self.later_xml)
        with self.assertRaisesRegex(ValueError, "reversed"):
            compare_snapshots(after, before, same_context_confirmed=True)
        overlapping = EXAMPLE.read_text().replace(
            'time="1767225601" elapsed', 'time="1767225602" elapsed'
        )
        with self.assertRaisesRegex(ValueError, "overlap"):
            compare_snapshots(before, self.snapshot(overlapping), same_context_confirmed=True)
        conflicting = EXAMPLE.read_text().replace('state="closed"', 'state="open"')
        with self.assertRaisesRegex(ValueError, "overlap"):
            compare_snapshots(before, self.snapshot(conflicting), same_context_confirmed=True)

    def test_identical_and_later_unchanged_observations_have_no_changes(self):
        before = read_snapshot(EXAMPLE)
        for xml in (
            EXAMPLE.read_text(),
            self.later_xml,
            self.later_xml.replace('services="22,80,443,3000"', 'services="3000,443,80,22"'),
        ):
            with self.subTest(xml=xml):
                self.assertEqual(
                    compare_snapshots(before, self.snapshot(xml), same_context_confirmed=True), []
                )

    def test_missing_port_is_not_inferred_closed_from_grouped_records(self):
        before_xml = EXAMPLE.read_text().replace(
            '<port protocol="tcp" portid="3000"><state state="closed"',
            '<port protocol="tcp" portid="3000"><state state="open"',
        )
        port_line = next(
            line for line in self.later_xml.splitlines(keepends=True) if 'portid="3000"' in line
        )
        later_xml = self.later_xml.replace(port_line, '<extraports state="closed" count="1"/>\n')
        changes = compare_snapshots(
            self.snapshot(before_xml, "before.xml"),
            self.snapshot(later_xml),
            same_context_confirmed=True,
        )
        self.assertEqual(changes, [Change("192.0.2.10", 3000, "open", None)])

    def test_new_port_observation_does_not_invent_its_previous_state(self):
        before_xml = EXAMPLE.read_text()
        port_line = next(
            line for line in before_xml.splitlines(keepends=True) if 'portid="3000"' in line
        )
        before_xml = before_xml.replace(port_line, '<extraports state="closed" count="1"/>\n')
        changes = compare_snapshots(
            self.snapshot(before_xml, "before.xml"),
            self.snapshot(self.later_xml),
            same_context_confirmed=True,
        )
        self.assertEqual(changes, [Change("192.0.2.10", 3000, None, "closed")])

    def test_address_changes_are_observations_not_device_additions_or_removals(self):
        later = self.snapshot(self.later_xml.replace("192.0.2.20", "192.0.2.30"))
        self.assertEqual(
            compare_snapshots(read_snapshot(EXAMPLE), later, same_context_confirmed=True),
            [
                Change("192.0.2.20", None, "observed", None),
                Change("192.0.2.20", 22, "open", None),
                Change("192.0.2.30", None, None, "observed"),
                Change("192.0.2.30", 22, None, "open"),
            ],
        )

    def test_explicit_closures_and_uncertain_states_are_preserved(self):
        for state in ("closed", "filtered", "unfiltered", "open|filtered", "closed|filtered"):
            with self.subTest(state=state):
                after = self.snapshot(self.later_xml.replace('state="open"', f'state="{state}"'))
                changes = compare_snapshots(
                    read_snapshot(EXAMPLE), after, same_context_confirmed=True
                )
                self.assertEqual(
                    changes,
                    [
                        Change("192.0.2.10", 22, "open", state),
                        Change("192.0.2.10", 443, "open", state),
                        Change("192.0.2.20", 22, "open", state),
                    ],
                )

    def test_compare_command_shows_sources_times_and_evidence(self):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "watchpost",
                "compare",
                "examples/baseline.xml",
                "examples/after.xml",
                "--confirm-same-context",
            ],
            cwd=EXAMPLE.parents[1],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertIn("Earlier: 'examples/baseline.xml'", result.stdout)
        self.assertIn("Later: 'examples/after.xml'", result.stdout)
        self.assertIn("2026-01-01T00:00:00+00:00", result.stdout)
        self.assertIn("2026-01-01T00:01:01+00:00", result.stdout)
        self.assertIn("confirmed by user", result.stdout)
        self.assertIn("STATE CHANGE 192.0.2.10 3000/tcp: closed -> open", result.stdout)
        self.assertIn("not a security verdict", result.stdout)

    def test_compare_command_requires_confirmation_before_reading_files(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            redirect_stdout(stdout),
            redirect_stderr(stderr),
            self.assertRaises(SystemExit) as error,
        ):
            main(["compare", "missing-before.xml", "missing-after.xml"])
        self.assertEqual(error.exception.code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("--confirm-same-context", stderr.getvalue())
        self.assertNotIn("regular file", stderr.getvalue())

    def test_incompatible_command_has_no_partial_output(self):
        self.snapshot(self.later_xml.replace('type="connect"', 'type="syn"'))
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            redirect_stdout(stdout),
            redirect_stderr(stderr),
            self.assertRaises(SystemExit) as error,
        ):
            main(["compare", str(EXAMPLE), str(self.path), "--confirm-same-context"])
        self.assertEqual(error.exception.code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("methods differ", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_comparison_output_is_repeatable_offline_and_escapes_source_names(self):
        path = self.path.with_name("later\n\x1b[31m.xml")
        path.write_text(self.later_xml, encoding="utf-8")
        outputs = []
        with patch("socket.socket", side_effect=AssertionError("Network access forbidden")):
            for _ in range(2):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(
                        main(["compare", str(EXAMPLE), str(path), "--confirm-same-context"]), 0
                    )
                outputs.append(output.getvalue())
        self.assertEqual(outputs[0], outputs[1])
        self.assertIn(ascii(str(path)), outputs[0])
        self.assertNotIn("\x1b", outputs[0])
        self.assertIn("No observed changes in explicit IPv4/TCP records.", outputs[0])
        self.assertIn("not a security verdict", outputs[0])

    def test_command_labels_missing_observations_without_claiming_closures(self):
        root = ElementTree.fromstring(self.later_xml)
        host = root.findall("host")[1]
        host.find("address").set("addr", "192.0.2.30")
        host.remove(host.find("ports"))
        self.snapshot(ElementTree.tostring(root, encoding="unicode"))
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(
                main(["compare", str(EXAMPLE), str(self.path), "--confirm-same-context"]), 0
            )
        self.assertIn("ADDRESS OBSERVATION 192.0.2.20: observed -> not observed", output.getvalue())
        self.assertIn("PORT OBSERVATION 192.0.2.20 22/tcp: open -> not observed", output.getvalue())
        self.assertIn("ADDRESS OBSERVATION 192.0.2.30: not observed -> observed", output.getvalue())
        self.assertNotIn("STATE CHANGE", output.getvalue())

    def test_changes_sort_addresses_and_ports_numerically(self):
        before_xml = EXAMPLE.read_text().replace("192.0.2.10", "192.0.2.100")
        after_xml = self.later_xml.replace("192.0.2.10", "192.0.2.100").replace(
            'state="open"', 'state="filtered"'
        )
        changes = compare_snapshots(
            self.snapshot(before_xml, "before.xml"),
            self.snapshot(after_xml),
            same_context_confirmed=True,
        )
        self.assertEqual(
            [(change.address, change.port) for change in changes],
            [("192.0.2.20", 22), ("192.0.2.100", 22), ("192.0.2.100", 443)],
        )


if __name__ == "__main__":
    unittest.main()
