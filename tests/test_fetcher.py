import unittest
import os
from unittest.mock import Mock, patch

from pullknock.errors import FetchError
from pullknock.fetcher import fetch_control_url, fetch_control_urls


class FetcherTest(unittest.TestCase):
    @patch("pullknock.fetcher.FTP")
    def test_ftp_fetch_retrieves_text(self, ftp_cls):
        ftp = Mock()
        ftp_cls.return_value.__enter__.return_value = ftp

        def retrbinary(command, callback):
            self.assertEqual(command, "RETR /pub/pullknock-command.json")
            callback(b'{"ok":true}\n')

        ftp.retrbinary.side_effect = retrbinary

        data = fetch_control_url("ftp://user:pass@ftp.example.com/pub/pullknock-command.json")

        self.assertEqual(data, '{"ok":true}\n')
        ftp.connect.assert_called_once_with("ftp.example.com", 21, timeout=5)
        ftp.login.assert_called_once_with("user", "pass")

    @patch("pullknock.fetcher.FTP")
    def test_ftp_fetch_expands_environment_variables_in_url(self, ftp_cls):
        ftp = Mock()
        ftp_cls.return_value.__enter__.return_value = ftp
        ftp.retrbinary.side_effect = lambda command, callback: callback(b"{}\n")
        old_user = os.environ.get("PULLKNOCK_TEST_FTP_USER")
        old_password = os.environ.get("PULLKNOCK_TEST_FTP_PASSWORD")
        os.environ["PULLKNOCK_TEST_FTP_USER"] = "env-user"
        os.environ["PULLKNOCK_TEST_FTP_PASSWORD"] = "env-pass"
        try:
            data = fetch_control_url(
                "ftp://${PULLKNOCK_TEST_FTP_USER}:${PULLKNOCK_TEST_FTP_PASSWORD}@ftp.example.com/file.json"
            )
        finally:
            if old_user is None:
                os.environ.pop("PULLKNOCK_TEST_FTP_USER", None)
            else:
                os.environ["PULLKNOCK_TEST_FTP_USER"] = old_user
            if old_password is None:
                os.environ.pop("PULLKNOCK_TEST_FTP_PASSWORD", None)
            else:
                os.environ["PULLKNOCK_TEST_FTP_PASSWORD"] = old_password

        self.assertEqual(data, "{}\n")
        ftp.login.assert_called_once_with("env-user", "env-pass")

    def test_fetch_rejects_control_characters_in_url(self):
        with self.assertRaisesRegex(FetchError, "control characters"):
            fetch_control_url("ftp://ftp.example.com/bad\nfile.json")

    @patch("pullknock.fetcher.fetch_control_url")
    def test_fetch_control_urls_uses_later_non_empty_location(self, fetch_one):
        fetch_one.side_effect = [None, FetchError("temporary"), "{}\n"]

        data = fetch_control_urls(("file:///missing.json", "https://bad.example/file.json", "file:///ok.json"))

        self.assertEqual(data, "{}\n")
        self.assertEqual(fetch_one.call_count, 3)

    @patch("pullknock.fetcher.fetch_control_url")
    def test_fetch_control_urls_reports_all_failures(self, fetch_one):
        fetch_one.side_effect = [FetchError("first"), FetchError("second")]

        with self.assertRaisesRegex(FetchError, "all_control_urls_failed"):
            fetch_control_urls(("https://one.example/file.json", "https://two.example/file.json"))


if __name__ == "__main__":
    unittest.main()
