import ast
import json
import os
import subprocess
import sys
import tempfile
import unittest
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


class ReleaseToolingTest(unittest.TestCase):
    def run_release_tag(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
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
        completed = self.run_release_tag("--tag", "v0.1.0", "--require-tag")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("release tag OK", completed.stdout)

    def test_check_release_tag_ignores_branch_ref_name_without_require_tag(self):
        for ref_name in ("main", "1/merge"):
            with self.subTest(ref_name=ref_name):
                completed = self.run_release_tag(env={"GITHUB_REF_TYPE": "branch", "GITHUB_REF_NAME": ref_name})

                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn("tag check skipped", completed.stdout)

    def test_check_release_tag_uses_github_ref_name_only_for_tag_refs(self):
        completed = self.run_release_tag(env={"GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "main"})

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("release tag must start with v", completed.stderr)

    def test_check_release_tag_requires_tag_when_requested(self):
        completed = self.run_release_tag("--require-tag", env={"GITHUB_REF_TYPE": "branch", "GITHUB_REF_NAME": "main"})

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("release tag is required", completed.stderr)

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

    def test_release_scripts_use_toml_compat_import(self):
        offenders = []
        for path in sorted(SCRIPTS.glob("*.py")):
            if path.name == "_toml_compat.py":
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import) and any(alias.name == "tomllib" for alias in node.names):
                    offenders.append(str(path.relative_to(ROOT)))
                if isinstance(node, ast.ImportFrom) and node.module == "tomllib":
                    offenders.append(str(path.relative_to(ROOT)))

        self.assertEqual(offenders, [])

    def test_toml_compat_declares_python310_fallback(self):
        source = (SCRIPTS / "_toml_compat.py").read_text(encoding="utf-8")

        self.assertIn("except ModuleNotFoundError", source)
        self.assertIn("import tomli as tomllib", source)

    def test_security_scan_loads_only_runtime_dependencies(self):
        sys.path.insert(0, str(SCRIPTS))
        try:
            spec = importlib.util.spec_from_file_location("security_scan", SCRIPTS / "security_scan.py")
            self.assertIsNotNone(spec)
            self.assertIsNotNone(spec.loader)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        finally:
            try:
                sys.path.remove(str(SCRIPTS))
            except ValueError:
                pass

        dependencies = module.load_runtime_dependencies(ROOT / "pyproject.toml")

        self.assertEqual(dependencies, ["click>=8.1", "PyYAML>=6.0", "requests>=2.31"])
        self.assertNotIn("pip-audit>=2.7", dependencies)


if __name__ == "__main__":
    unittest.main()
