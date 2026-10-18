"""In-memory comparison checks for the browser build, using synthetic inputs only."""

import unittest
from pathlib import Path
from unittest.mock import patch

from watchpost import MAX_XML_BYTES, compare_report, parse_snapshot, read_snapshot

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


class InMemoryTests(unittest.TestCase):
    def setUp(self):
        self.before = (EXAMPLES / "baseline.xml").read_bytes()
        self.after = (EXAMPLES / "after.xml").read_bytes()

    def report(self, before=None, after=None, **kwargs):
        options = {
            "before_name": "examples/baseline.xml",
            "after_name": "examples/after.xml",
            "same_context_confirmed": True,
        }
        options.update(kwargs)
        return compare_report(
            self.before if before is None else before,
            self.after if after is None else after,
            **options,
        )

    def test_matches_the_committed_cli_report_exactly(self):
        expected = (EXAMPLES / "report.md").read_text(encoding="utf-8")
        self.assertEqual(self.report(), expected)

    def test_parsed_bytes_match_the_file_reader(self):
        from_bytes = parse_snapshot(self.before, EXAMPLES / "baseline.xml")
        self.assertEqual(from_bytes, read_snapshot(EXAMPLES / "baseline.xml"))

    def test_requires_confirmation_before_parsing(self):
        with (
            patch("watchpost._parse_root") as parse,
            self.assertRaisesRegex(ValueError, "Confirm the same scan location"),
        ):
            self.report(same_context_confirmed=False)
        parse.assert_not_called()

    def test_applies_the_same_validation_gate_as_the_cli(self):
        incomplete = (EXAMPLES / "incomplete.xml").read_bytes()
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.report(after=incomplete)
        with self.assertRaisesRegex(ValueError, "Snapshots are reversed"):
            self.report(before=self.after, after=self.before)

    def test_rejects_oversized_and_unsafe_input(self):
        with self.assertRaisesRegex(ValueError, "10 MiB limit"):
            self.report(after=b" " * (MAX_XML_BYTES + 1))
        entity = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><nmaprun>&a;</nmaprun>'
        with self.assertRaisesRegex(ValueError, "Unsafe XML"):
            self.report(after=entity)

    def test_source_names_are_escaped_labels_only(self):
        report = self.report(before_name="lab\n# injected.xml")
        self.assertIn("    'lab\\n# injected.xml'", report)
        self.assertNotIn("\n# injected", report)


if __name__ == "__main__":
    unittest.main()
