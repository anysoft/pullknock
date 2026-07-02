import subprocess
import sys
import unittest


class CommandTest(unittest.TestCase):
    def test_agent_check_config(self):
        completed = subprocess.run(
            [sys.executable, "-m", "pullknock.agent", "--config", "examples/agent.yaml", "--check-config"],
            check=True,
            capture_output=True,
            text=True,
        )

        self.assertIn("Agent config OK.", completed.stdout)

    def test_pr_title_check_accepts_conventional_title(self):
        completed = subprocess.run(
            [sys.executable, "scripts/check_pr_title.py", "feat(agent): add nftables backend"],
            check=True,
            capture_output=True,
            text=True,
        )

        self.assertIn("PR title OK", completed.stdout)

    def test_pr_title_check_rejects_plain_title(self):
        completed = subprocess.run(
            [sys.executable, "scripts/check_pr_title.py", "add stuff"],
            capture_output=True,
            text=True,
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("Invalid PR title", completed.stderr)


if __name__ == "__main__":
    unittest.main()
