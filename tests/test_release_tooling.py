import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    import tomli as tomllib  # Python 3.10

ROOT = Path(__file__).resolve().parents[1]


def current_version() -> str:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return pyproject["project"]["version"]


class ReleaseToolingTest(unittest.TestCase):
    def run_release_tag(
        self,
        *args: str,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        process_env = os.environ.copy()
        process_env.pop("GITHUB_REF_NAME", None)
        process_env.pop("GITHUB_REF_TYPE", None)

        if env:
            process_env.update(env)

        return subprocess.run(
            [sys.executable, "scripts/check_release_tag.py", *args],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=process_env,
        )

    def test_check_release_tag_accepts_current_version(self):
        tag = f"v{current_version()}"
        completed = self.run_release_tag("--tag", tag, "--require-tag")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("release tag OK", completed.stdout)

    def test_check_release_tag_rejects_mismatched_version(self):
        completed = self.run_release_tag("--tag", "v0.0.0", "--require-tag")

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("tag/version mismatch", completed.stderr)

    def test_check_release_tag_ignores_branch_ref_name_without_require_tag(self):
        for ref_name in ("main", "1/merge"):
            with self.subTest(ref_name=ref_name):
                completed = self.run_release_tag(
                    env={
                        "GITHUB_REF_TYPE": "branch",
                        "GITHUB_REF_NAME": ref_name,
                    }
                )

                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn("tag check skipped", completed.stdout)

    def test_check_release_tag_uses_github_ref_name_only_for_tag_refs(self):
        completed = self.run_release_tag(
            env={
                "GITHUB_REF_TYPE": "tag",
                "GITHUB_REF_NAME": "main",
            }
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("release tag must start with v", completed.stderr)

    def test_check_release_tag_requires_tag_when_requested(self):
        completed = self.run_release_tag(
            "--require-tag",
            env={
                "GITHUB_REF_TYPE": "branch",
                "GITHUB_REF_NAME": "main",
            },
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("release tag is required", completed.stderr)

    def test_generate_sbom_writes_cyclonedx_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "sbom.json"

            completed = subprocess.run(
                [
                    sys.executable,
                    "scripts/generate_sbom.py",
                    "--output",
                    str(output),
                ],
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
