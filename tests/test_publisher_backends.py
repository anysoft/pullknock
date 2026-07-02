import os
import unittest
from unittest.mock import Mock, patch

from pullknock.config import PublisherConfig
from pullknock.errors import PublishError
from pullknock.protocol import build_envelope, build_payload, canonical_json
from pullknock.publisher import publish_envelope


def sample_envelope():
    payload = build_payload(
        principal="jonhy",
        target="x162",
        grant_id="ssh",
        source_ip="203.0.113.7",
        requested_timeout=60,
        issued_at=100,
        not_before=100,
        expires_at=160,
    )
    payload_bytes = canonical_json(payload)
    return build_envelope(payload_bytes, b"signature", kid="jonhy", created_at=100)


class PublisherBackendsTest(unittest.TestCase):
    @patch("pullknock.publisher.requests.put")
    def test_http_put_expands_queue_context_placeholders(self, put):
        put.return_value = Mock(status_code=200, text="")
        publisher = PublisherConfig(
            name="queue",
            type="http_put",
            options={"url": "https://publisher.example.com/commands/{target}/{command_id}.json"},
        )

        location = publish_envelope(
            sample_envelope(),
            publisher,
            context={
                "target": "x162",
                "command_id": "4ca1165b-37d3-4534-af9e-b4c2f5232b19",
            },
        )

        self.assertEqual(
            location,
            "https://publisher.example.com/commands/x162/4ca1165b-37d3-4534-af9e-b4c2f5232b19.json",
        )
        self.assertEqual(put.call_args.args[0], location)

    @patch("pullknock.publisher.requests.put")
    def test_webdav_put_supports_basic_auth_and_headers(self, put):
        put.return_value = Mock(status_code=201, text="")
        old_password = os.environ.get("WEBDAV_PASSWORD")
        os.environ["WEBDAV_PASSWORD"] = "secret"
        try:
            publisher = PublisherConfig(
                name="dav",
                type="webdav_put",
                options={
                    "url": "https://dav.example.com/path/pullknock-command.json",
                    "username": "jonhy",
                    "password": "${WEBDAV_PASSWORD}",
                    "headers": {"X-Test": "yes"},
                },
            )

            location = publish_envelope(sample_envelope(), publisher)
        finally:
            if old_password is None:
                os.environ.pop("WEBDAV_PASSWORD", None)
            else:
                os.environ["WEBDAV_PASSWORD"] = old_password

        self.assertEqual(location, "https://dav.example.com/path/pullknock-command.json")
        _, kwargs = put.call_args
        self.assertEqual(kwargs["auth"], ("jonhy", "secret"))
        self.assertEqual(kwargs["headers"]["X-Test"], "yes")
        self.assertEqual(kwargs["headers"]["Content-Type"], "application/json")

    @patch("pullknock.publisher.FTP")
    def test_ftp_upload_logs_in_creates_dirs_and_stores_file(self, ftp_cls):
        ftp = Mock()
        ftp_cls.return_value.__enter__.return_value = ftp
        publisher = PublisherConfig(
            name="ftpbox",
            type="ftp_upload",
            options={
                "url": "ftp://ftp.example.com/pub/pullknock-command.json",
                "username": "anonymous",
                "password": "anonymous@",
            },
        )

        location = publish_envelope(sample_envelope(), publisher)

        self.assertEqual(location, "ftp://ftp.example.com/pub/pullknock-command.json")
        ftp.connect.assert_called_once_with("ftp.example.com", 21, timeout=10)
        ftp.login.assert_called_once_with("anonymous", "anonymous@")
        ftp.mkd.assert_called_with("pub")
        ftp.cwd.assert_called_with("pub")
        self.assertEqual(ftp.storbinary.call_args.args[0], "STOR pullknock-command.json")

    @patch("pullknock.publisher.FTP_TLS")
    def test_ftps_upload_enables_private_data_channel(self, ftp_cls):
        ftp = Mock()
        ftp_cls.return_value.__enter__.return_value = ftp
        publisher = PublisherConfig(
            name="ftpsbox",
            type="ftps_upload",
            options={"url": "ftps://ftp.example.com/pullknock-command.json"},
        )

        publish_envelope(sample_envelope(), publisher)

        ftp.connect.assert_called_once_with("ftp.example.com", 990, timeout=10)
        ftp.prot_p.assert_called_once_with()

    def test_webdav_rejects_non_http_url(self):
        publisher = PublisherConfig(
            name="dav",
            type="webdav_put",
            options={"url": "ftp://example.com/file.json"},
        )

        with self.assertRaisesRegex(PublishError, "http:// or https://"):
            publish_envelope(sample_envelope(), publisher)

    def test_ftp_rejects_control_characters_in_url(self):
        publisher = PublisherConfig(
            name="ftpbox",
            type="ftp_upload",
            options={"url": "ftp://ftp.example.com/pub/bad\nfile.json"},
        )

        with self.assertRaisesRegex(PublishError, "control characters"):
            publish_envelope(sample_envelope(), publisher)

    @patch("pullknock.publisher.requests.post")
    def test_ipfs_http_adds_and_publishes_ipns(self, post):
        add_response = Mock(status_code=200, text='{"Hash":"bafyabc"}')
        add_response.json.return_value = {"Hash": "bafyabc"}
        publish_response = Mock(status_code=200, text='{"Name":"pullknock"}')
        post.side_effect = [add_response, publish_response]
        publisher = PublisherConfig(
            name="ipfs",
            type="ipfs_http",
            options={
                "api_url": "http://127.0.0.1:5001",
                "filename": "pullknock-command.json",
                "ipns_key": "pullknock",
            },
        )

        location = publish_envelope(sample_envelope(), publisher)

        self.assertEqual(location, "ipns://pullknock/bafyabc")
        self.assertEqual(post.call_args_list[0].args[0], "http://127.0.0.1:5001/api/v0/add")
        self.assertEqual(post.call_args_list[1].kwargs["params"]["arg"], "/ipfs/bafyabc")

    @patch("pullknock.publisher.requests.put")
    def test_s3_put_signs_v4_request(self, put):
        put.return_value = Mock(status_code=200, text="")
        publisher = PublisherConfig(
            name="s3",
            type="s3_put",
            options={
                "endpoint_url": "https://s3.example.com",
                "region": "us-east-1",
                "bucket": "pullknock",
                "key": "commands/x162.json",
                "access_key_id": "AKIAEXAMPLE",
                "secret_access_key": "secret",
            },
        )

        location = publish_envelope(sample_envelope(), publisher)

        self.assertEqual(location, "https://s3.example.com/pullknock/commands/x162.json")
        _, kwargs = put.call_args
        self.assertIn("Authorization", kwargs["headers"])
        self.assertIn("AWS4-HMAC-SHA256", kwargs["headers"]["Authorization"])
        self.assertEqual(kwargs["headers"]["X-Amz-Content-Sha256"], kwargs["headers"]["X-Amz-Content-Sha256"].lower())


if __name__ == "__main__":
    unittest.main()
