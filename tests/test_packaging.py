"""Keep the distribution identity distinct from the CLI and import module."""

import tomllib
import unittest
from importlib.metadata import distribution
from pathlib import Path


class PackagingTests(unittest.TestCase):
    def test_installed_distribution_keeps_the_watchpost_command(self):
        project = tomllib.loads(
            (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
        )["project"]
        self.assertEqual(project["name"], "watchpost-cli")
        installed = distribution(project["name"])
        self.assertEqual(installed.version, project["version"])
        self.assertEqual(installed.metadata["License-Expression"], "MIT")
        commands = {
            entry.name: entry.value
            for entry in installed.entry_points
            if entry.group == "console_scripts"
        }
        self.assertEqual(commands, {"watchpost": "watchpost:main"})


if __name__ == "__main__":
    unittest.main()
