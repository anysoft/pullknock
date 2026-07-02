import json
import os
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import patch

from pullknock.config import (
    PublisherServiceAuthConfig,
    PublisherServiceConfig,
    PublisherServiceHttpConfig,
    PublisherServiceStorageConfig,
    load_publisher_service_config,
)
from pullknock.protocol import build_envelope, build_envelope_v2, build_payload, canonical_json
from pullknock.publisher import envelope_json_bytes
from pullknock.publisher_server import create_http_server


class PublisherServerTest(unittest.TestCase):
    def test_config_loader_expands_token_env(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            old_value = os.environ.get("PULLKNOCK_TEST_TOKEN")
            os.environ["PULLKNOCK_TEST_TOKEN"] = "secret-token"
            try:
                path = f"{temp_dir}/publisher.yaml"
                with open(path, "w", encoding="utf-8") as file:
                    file.write(
                        f"""
server:
  host: "127.0.0.1"
  port: 0
storage:
  mode: "queue"
  envelope_file: "{temp_dir}/command.json"
  queue_dir: "{temp_dir}/commands"
auth:
  write_bearer_tokens:
    - "${{PULLKNOCK_TEST_TOKEN}}"
  require_auth_for_read: true
"""
                    )

                config = load_publisher_service_config(path)
            finally:
                if old_value is None:
                    os.environ.pop("PULLKNOCK_TEST_TOKEN", None)
                else:
                    os.environ["PULLKNOCK_TEST_TOKEN"] = old_value

        self.assertEqual(config.auth.write_bearer_tokens, ("secret-token",))
        self.assertEqual(config.auth.read_bearer_tokens, ("secret-token",))
        self.assertEqual(config.storage.mode, "queue")
        self.assertEqual(config.storage.queue_dir, f"{temp_dir}/commands")

    def test_put_requires_bearer_token(self):
        with self._running_server() as base_url:
            body = self._sample_envelope_body()
            request = Request(f"{base_url}/pullknock-command.json", data=body, method="PUT")

            with self.assertRaises(HTTPError) as raised:
                urlopen(request, timeout=5)

        self.assertEqual(raised.exception.code, 401)

    def test_put_then_get_envelope(self):
        with self._running_server() as base_url:
            body = self._sample_envelope_body()
            put_request = Request(
                f"{base_url}/pullknock-command.json",
                data=body,
                method="PUT",
                headers={
                    "Authorization": "Bearer secret-token",
                    "Content-Type": "application/json",
                },
            )

            with urlopen(put_request, timeout=5) as response:
                put_result = json.loads(response.read().decode("utf-8"))

            with urlopen(f"{base_url}/pullknock-command.json", timeout=5) as response:
                stored = json.loads(response.read().decode("utf-8"))

        self.assertTrue(put_result["stored"])
        self.assertEqual(stored["encoding"], "plain+sshsig")
        self.assertIn("payload_b64", stored)

    def test_put_then_get_envelope_v2(self):
        with self._running_server() as base_url:
            body = envelope_json_bytes(
                build_envelope_v2(
                    b"age-ciphertext",
                    kid="jonhy",
                    encryption_key_id="x162-age-2026q3",
                    created_at=100,
                )
            )
            put_request = Request(
                f"{base_url}/pullknock-command.json",
                data=body,
                method="PUT",
                headers={
                    "Authorization": "Bearer secret-token",
                    "Content-Type": "application/json",
                },
            )

            with urlopen(put_request, timeout=5) as response:
                put_result = json.loads(response.read().decode("utf-8"))

            with urlopen(f"{base_url}/pullknock-command.json", timeout=5) as response:
                stored = json.loads(response.read().decode("utf-8"))

        self.assertTrue(put_result["stored"])
        self.assertEqual(stored["envelope_version"], 2)
        self.assertEqual(stored["encoding"], "age")
        self.assertEqual(stored["encryption_key_id"], "x162-age-2026q3")

    def test_queue_mode_stores_multiple_commands_without_overwrite(self):
        with self._running_server(queue=True) as base_url:
            first = self._sample_envelope_body(command_id="4ca1165b-37d3-4534-af9e-b4c2f5232b19")
            second = self._sample_envelope_body(command_id="bc2d5226-aa37-4a92-ae51-617e54dcb529")
            for command_id, body in [
                ("4ca1165b-37d3-4534-af9e-b4c2f5232b19", first),
                ("bc2d5226-aa37-4a92-ae51-617e54dcb529", second),
            ]:
                request = Request(
                    f"{base_url}/commands/x162/{command_id}.json",
                    data=body,
                    method="PUT",
                    headers={
                        "Authorization": "Bearer secret-token",
                        "Content-Type": "application/json",
                    },
                )
                with urlopen(request, timeout=5) as response:
                    self.assertTrue(json.loads(response.read().decode("utf-8"))["stored"])

            with urlopen(f"{base_url}/commands/x162/index.json", timeout=5) as response:
                index = json.loads(response.read().decode("utf-8"))

        self.assertEqual(index["queue_version"], 1)
        self.assertEqual([item["command_id"] for item in index["commands"]], [
            "4ca1165b-37d3-4534-af9e-b4c2f5232b19",
            "bc2d5226-aa37-4a92-ae51-617e54dcb529",
        ])

    def test_requests_are_logged_as_json_events(self):
        with patch("pullknock.publisher_server.click.echo") as echo:
            with self._running_server() as base_url:
                with urlopen(f"{base_url}/healthz", timeout=5) as response:
                    response.read()

        logged = [call.kwargs for call in echo.call_args_list if call.kwargs.get("err")]
        self.assertTrue(logged)
        self.assertIn('"event": "publisher_request"', echo.call_args_list[-1].args[0])
        self.assertIn('"status": 200', echo.call_args_list[-1].args[0])

    def _running_server(self, *, queue=False):
        return RunningPublisherServer(queue=queue)

    def _sample_envelope_body(self, *, command_id=None):
        payload = build_payload(
            principal="jonhy",
            target="x162",
            grant_id="ssh",
            source_ip="203.0.113.7",
            requested_timeout=60,
            issued_at=100,
            not_before=100,
            expires_at=160,
            command_id=command_id,
        )
        payload_bytes = canonical_json(payload)
        envelope = build_envelope(payload_bytes, b"dummy-signature", kid="jonhy", created_at=100)
        return envelope_json_bytes(envelope)


class RunningPublisherServer:
    def __init__(self, *, queue=False):
        self.queue = queue

    def __enter__(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        config = PublisherServiceConfig(
            http=PublisherServiceHttpConfig(host="127.0.0.1", port=0),
            storage=PublisherServiceStorageConfig(
                envelope_file=f"{self.temp_dir.name}/command.json",
                mode="queue" if self.queue else "latest",
            ),
            auth=PublisherServiceAuthConfig(write_bearer_tokens=("secret-token",)),
        )
        self.server = create_http_server(config)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    def __exit__(self, exc_type, exc, tb):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()
        self.temp_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
