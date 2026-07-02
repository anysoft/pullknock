import subprocess
import unittest
from unittest.mock import Mock, patch

from pullknock.config import AgeConfig
from pullknock.crypto import age_decrypt, age_encrypt
from pullknock.errors import EncryptionError


class CryptoTest(unittest.TestCase):
    @patch("pullknock.crypto.subprocess.run")
    def test_age_encrypt_uses_recipients_and_recipient_files(self, run):
        run.return_value = Mock(returncode=0, stdout=b"ciphertext", stderr=b"")
        config = AgeConfig(
            age_cmd="age",
            recipients=("age1example",),
            recipient_files=("/etc/pullknock/recipients.txt",),
        )

        ciphertext = age_encrypt(b"plain", config)

        self.assertEqual(ciphertext, b"ciphertext")
        run.assert_called_once_with(
            ["age", "-r", "age1example", "-R", "/etc/pullknock/recipients.txt"],
            input=b"plain",
            check=False,
            capture_output=True,
        )

    @patch("pullknock.crypto.subprocess.run")
    def test_age_decrypt_uses_all_identity_files(self, run):
        run.return_value = Mock(returncode=0, stdout=b"plain", stderr=b"")
        config = AgeConfig(age_cmd="age", identity_files=("/old.key", "/new.key"))

        plaintext = age_decrypt(b"ciphertext", config)

        self.assertEqual(plaintext, b"plain")
        run.assert_called_once_with(
            ["age", "-d", "-i", "/old.key", "-i", "/new.key"],
            input=b"ciphertext",
            check=False,
            capture_output=True,
        )

    @patch("pullknock.crypto.subprocess.run")
    def test_age_decrypt_reports_failure(self, run):
        run.return_value = subprocess.CompletedProcess(["age"], 1, stdout=b"", stderr=b"no identity")

        with self.assertRaisesRegex(EncryptionError, "age_decrypt_failed"):
            age_decrypt(b"ciphertext", AgeConfig(age_cmd="age", identity_files=("/missing.key",)))


if __name__ == "__main__":
    unittest.main()
