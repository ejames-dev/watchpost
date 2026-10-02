"""Offline behavior tests using synthetic scan data only."""

import io
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from watchpost import MAX_XML_BYTES, main, read_inventory

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "baseline.xml"


class InventoryTests(unittest.TestCase):
    def test_reads_only_explicit_ipv4_tcp_observations(self):
        self.assertEqual(
            read_inventory(EXAMPLE),
            {
                "192.0.2.10": {22: "open", 80: "closed", 443: "open", 3000: "closed"},
                "192.0.2.20": {22: "open"},
            },
        )

    def test_rejects_invalid_or_unsupported_snapshots(self):
        baseline = EXAMPLE.read_text()
        cases = {
            "wrong document": ("<anything/>", "Nmap"),
            "wrong scanner": (baseline.replace('scanner="nmap"', 'scanner="other"'), "Nmap"),
            "missing completion": (baseline.replace('exit="success"', ""), "complete"),
            "failed scan": (baseline.replace('exit="success"', 'exit="error"'), "complete"),
            "missing scan info": (baseline.replace("<scaninfo ", "<other "), "TCP"),
            "UDP scan": (baseline.replace('protocol="tcp"', 'protocol="udp"'), "TCP"),
            "IPv6 address": (
                baseline.replace(
                    'addr="192.0.2.10" addrtype="ipv4"', 'addr="2001:db8::10" addrtype="ipv6"'
                ),
                "IPv4",
            ),
            "bad address": (baseline.replace("192.0.2.10", "999.0.2.10"), "IPv4"),
            "missing address": (baseline.replace('addrtype="ipv4"', 'addrtype="mac"'), "IPv4"),
            "duplicate host": (baseline.replace("192.0.2.20", "192.0.2.10"), "Duplicate"),
            "duplicate port": (baseline.replace('portid="443"', 'portid="22"'), "Duplicate"),
            "negative port": (baseline.replace('portid="22"', 'portid="-1"'), "port"),
            "port too large": (baseline.replace('portid="22"', 'portid="65536"'), "port"),
            "nonnumeric port": (baseline.replace('portid="22"', 'portid="ssh"'), "port"),
            "invalid state": (baseline.replace('state="open"', 'state="vulnerable"'), "state"),
            "missing state": (baseline.replace('state="open"', ""), "state"),
            "host timeout": (
                baseline.replace("<host starttime", '<host timedout="true" starttime'),
                "complete",
            ),
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.xml"
            for name, (xml, message) in cases.items():
                with self.subTest(name=name):
                    path.write_text(xml)
                    with self.assertRaisesRegex(ValueError, message):
                        read_inventory(path)

    def test_rejects_malformed_and_empty_xml(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.xml"
            for content in (
                b"",
                b"<nmaprun>",
                b"not XML",
                b"\xff\xfe\x00",
                b'<?xml version="1.0" encoding="unknown-encoding"?><nmaprun/>',
            ):
                with self.subTest(content=content):
                    path.write_bytes(content)
                    with self.assertRaisesRegex(ValueError, "Malformed XML"):
                        read_inventory(path)

    def test_rejects_entities_in_utf8_and_utf16(self):
        baseline = EXAMPLE.read_text().replace('<?xml version="1.0" encoding="UTF-8"?>', "")
        declarations = (
            '<!ENTITY example "expanded text">',
            '<!ENTITY example SYSTEM "file:///watchpost-example-secret">',
            '<!ENTITY example SYSTEM "https://example.invalid/entity">',
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.xml"
            for declaration in declarations:
                for encoding in ("utf-8", "utf-16"):
                    with self.subTest(declaration=declaration, encoding=encoding):
                        xml = baseline.replace(
                            "<!DOCTYPE nmaprun>", f"<!DOCTYPE nmaprun [{declaration}]>"
                        )
                        path.write_bytes(xml.encode(encoding))
                        with self.assertRaisesRegex(ValueError, "Unsafe XML"):
                            read_inventory(path)

    def test_does_not_fetch_stylesheets_or_external_dtds(self):
        xml = EXAMPLE.read_text().replace(
            "<!DOCTYPE nmaprun>",
            '<?xml-stylesheet href="https://example.invalid/style.xsl" type="text/xsl"?>'
            '<!DOCTYPE nmaprun SYSTEM "https://example.invalid/nmap.dtd">',
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.xml"
            path.write_text(xml)
            with (
                patch("socket.socket", side_effect=AssertionError("Network access forbidden")),
                patch(
                    "socket.create_connection",
                    side_effect=AssertionError("Network access forbidden"),
                ),
                patch(
                    "urllib.request.urlopen", side_effect=AssertionError("Network access forbidden")
                ),
            ):
                self.assertEqual(read_inventory(path), read_inventory(EXAMPLE))

    def test_size_limit_accepts_boundary_and_rejects_one_extra_byte(self):
        data = EXAMPLE.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.xml"
            path.write_bytes(data + b" " * (MAX_XML_BYTES - len(data)))
            self.assertEqual(read_inventory(path), read_inventory(EXAMPLE))
            with path.open("ab") as source:
                source.write(b" ")
            with self.assertRaisesRegex(ValueError, "10 MiB"):
                read_inventory(path)

    def test_rejects_missing_files_and_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            for path in (Path(directory), Path(directory) / "missing.xml"):
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, "regular file"):
                    read_inventory(path)

    def test_accepts_port_boundaries_and_uncertain_states_without_relabeling(self):
        baseline = EXAMPLE.read_text()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.xml"
            for state in ("filtered", "unfiltered", "open|filtered", "closed|filtered"):
                with self.subTest(state=state):
                    xml = baseline.replace('portid="80"', 'portid="0"')
                    xml = xml.replace('portid="3000"', 'portid="65535"')
                    path.write_text(xml.replace('state="closed"', f'state="{state}"'))
                    ports = read_inventory(path)["192.0.2.10"]
                    self.assertEqual(ports[0], state)
                    self.assertEqual(ports[65535], state)


class CommandTests(unittest.TestCase):
    def test_inspect_command_lists_observations(self):
        result = subprocess.run(
            [sys.executable, "-m", "watchpost", "inspect", str(EXAMPLE)],
            capture_output=True,
            text=True,
            check=False,
            cwd=EXAMPLE.parents[1],
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(
            result.stdout,
            "IPv4/TCP observations (not a security verdict)\n"
            "192.0.2.10\n"
            "  22/tcp  open\n"
            "  80/tcp  closed\n"
            "  443/tcp  open\n"
            "  3000/tcp  closed\n"
            "192.0.2.20\n"
            "  22/tcp  open\n"
            "Only explicit port observations are listed; missing ports are not classified.\n",
        )

    def test_invalid_input_has_no_partial_output_or_traceback(self):
        xml = EXAMPLE.read_text().replace('addr="192.0.2.20"', 'addr="invalid"')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.xml"
            path.write_text(xml)
            stdout, stderr = io.StringIO(), io.StringIO()
            with (
                redirect_stdout(stdout),
                redirect_stderr(stderr),
                self.assertRaises(SystemExit) as error,
            ):
                main(["inspect", str(path)])
            self.assertEqual(error.exception.code, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("Invalid IPv4 address", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_numerical_order_and_repeatable_output(self):
        xml = EXAMPLE.read_text().replace("192.0.2.10", "192.0.2.100")
        xml = xml.replace('portid="22"', 'portid="65000"')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.xml"
            path.write_text(xml)
            outputs = []
            for _ in range(2):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(main(["inspect", str(path)]), 0)
                outputs.append(output.getvalue())
            self.assertEqual(outputs[0], outputs[1])
            self.assertLess(outputs[0].index("192.0.2.20"), outputs[0].index("192.0.2.100"))
            host_output = outputs[0].split("192.0.2.100\n")[1]
            self.assertLess(host_output.index("80/tcp"), host_output.index("65000/tcp"))

    def test_empty_scan_and_host_without_explicit_ports_are_not_safety_verdicts(self):
        baseline = EXAMPLE.read_text()
        empty_scan = (
            baseline[: baseline.index("  <host ")] + baseline[baseline.index("  <runstats>") :]
        ).replace('<hosts up="2" down="0" total="2"/>', '<hosts up="0" down="0" total="0"/>')
        empty_host = (
            baseline[: baseline.index("    <ports>")] + baseline[baseline.index("  </host>") :]
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.xml"
            for xml, expected in (
                (empty_scan, "No IPv4 host observations."),
                (empty_host, "No explicit TCP port observations."),
            ):
                with self.subTest(expected=expected):
                    path.write_text(xml)
                    output = io.StringIO()
                    with redirect_stdout(output):
                        self.assertEqual(main(["inspect", str(path)]), 0)
                    self.assertIn(expected, output.getvalue())
                    self.assertIn("not a security verdict", output.getvalue())
                    self.assertIn("missing ports are not classified", output.getvalue())


if __name__ == "__main__":
    unittest.main()
