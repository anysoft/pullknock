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

    def run_pr_title_check(self, title):
        return subprocess.run(
            [sys.executable, "scripts/check_pr_title.py", title],
            capture_output=True,
            text=True,
        )

    def test_pr_title_check_accepts_allowed_titles(self):
        cases = [
            ("feat(agent): add nftables backend", "PR title OK"),
            ("fix(protocol): reject malformed source IP", "PR title OK"),
            ("docs: update deployment guide", "PR title OK"),
            (
                "Potential fix for code scanning alert no. 7: Uncontrolled data used in path expression",
                "Accepted GitHub code scanning autofix PR title.",
            ),
        ]
        for title, message in cases:
            with self.subTest(title=title):
                completed = self.run_pr_title_check(title)

                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn(message, completed.stdout)

    def test_pr_title_check_rejects_plain_title(self):
        completed = self.run_pr_title_check("random invalid title")

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("Invalid PR title", completed.stderr)


if __name__ == "__main__":
    unittest.main()
