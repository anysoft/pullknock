import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ReleaseToolingTest(unittest.TestCase):
    def test_check_release_tag_accepts_current_version(self):
        completed = subprocess.run(
            [sys.executable, "scripts/check_release_tag.py", "--tag", "v0.1.0", "--require-tag"],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("release tag OK", completed.stdout)

    def test_generate_sbom_writes_cyclonedx_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "sbom.json"

            completed = subprocess.run(
                [sys.executable, "scripts/generate_sbom.py", "--output", str(output)],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            sbom = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(sbom["metadata"]["component"]["name"], "pullknock")
        self.assertGreaterEqual(len(sbom["components"]), 3)

    def test_verify_systemd_hardening(self):
        completed = subprocess.run(
            [sys.executable, "scripts/verify_systemd_hardening.py"],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("systemd hardening OK", completed.stdout)


if __name__ == "__main__":
    unittest.main()
