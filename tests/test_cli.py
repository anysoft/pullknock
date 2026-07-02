import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from pullknock.cli import main


def write_cli_config(temp_dir: str, *, envelope_version: int) -> str:
    key_id = '    key_id: "x162-age-2026q3"\n' if envelope_version == 2 else ""
    path = Path(temp_dir) / "cli.yaml"
    path.write_text(
        f"""
defaults:
  principal: "jonhy"
  private_key: "~/.ssh/pullknock"
  age:
    envelope_version: {envelope_version}
{key_id}    recipients:
      - "age1exampleonlyreplacewithvalidrecipient000000000000000000000000000"
publishers:
  local:
    type: "file"
    path: "{temp_dir}/command.json"
targets:
  x162:
    target: "x162"
    grant_id: "ssh"
    publisher: "local"
""",
        encoding="utf-8",
    )
    return str(path)


class CliEnvelopeTest(unittest.TestCase):
    @patch("pullknock.cli.time.time", return_value=1000)
    @patch("pullknock.cli.age_encrypt", return_value=b"age-ciphertext")
    @patch("pullknock.cli.sshsig_sign", return_value=b"signature")
    def test_open_dry_run_outputs_envelope_v2_by_config(self, sign, encrypt, now):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = write_cli_config(temp_dir, envelope_version=2)

            result = CliRunner().invoke(
                main,
                ["open", "x162", "--config", config_path, "--source-ip", "203.0.113.7", "--dry-run"],
            )

        self.assertEqual(result.exit_code, 0, result.output)
        envelope = json.loads(result.output)
        self.assertEqual(envelope["envelope_version"], 2)
        self.assertEqual(envelope["encoding"], "age")
        self.assertEqual(envelope["encryption_alg"], "age-v1")
        self.assertEqual(envelope["encryption_key_id"], "x162-age-2026q3")
        self.assertEqual(envelope["inner_envelope_version"], 1)
        self.assertEqual(envelope["inner_encoding"], "plain+sshsig")
        sign.assert_called_once()
        encrypt.assert_called_once()

    @patch("pullknock.cli.time.time", return_value=1000)
    @patch("pullknock.cli.age_encrypt", return_value=b"age-ciphertext")
    @patch("pullknock.cli.sshsig_sign", return_value=b"signature")
    def test_open_dry_run_can_output_legacy_encrypted_envelope_v1(self, sign, encrypt, now):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = write_cli_config(temp_dir, envelope_version=1)

            result = CliRunner().invoke(
                main,
                ["open", "x162", "--config", config_path, "--source-ip", "203.0.113.7", "--dry-run"],
            )

        self.assertEqual(result.exit_code, 0, result.output)
        envelope = json.loads(result.output)
        self.assertEqual(envelope["envelope_version"], 1)
        self.assertEqual(envelope["encoding"], "age+plain+sshsig")
        self.assertNotIn("encryption_key_id", envelope)
        sign.assert_called_once()
        encrypt.assert_called_once()


if __name__ == "__main__":
    unittest.main()
