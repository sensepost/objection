import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from objection import __version__


class TestsModuleEntrypoint(unittest.TestCase):
    def test_module_entrypoint_runs_cli(self):
        with tempfile.TemporaryDirectory() as home:
            Path(home, ".objection").mkdir()
            env = os.environ.copy()
            env["HOME"] = home
            env["USERPROFILE"] = home

            result = subprocess.run(
                [sys.executable, "-m", "objection", "version"],
                capture_output=True,
                check=False,
                text=True,
                env=env,
            )

        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stdout.endswith(f"objection: {__version__}\n"))
        self.assertEqual(result.stderr, "")
