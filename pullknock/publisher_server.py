"""Small HTTP bulletin-board service for PullKnock envelopes."""

from __future__ import annotations

import hmac
import json
import os
import re
import tempfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import click

from .config import PublisherServiceConfig, load_publisher_service_config
from .errors import ConfigError, ProtocolError
from .protocol import validate_publishable_envelope
from .publisher import envelope_json_bytes
from .util import utc_iso

SAFE_QUEUE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}$")


def create_http_server(config: PublisherServiceConfig) -> ThreadingHTTPServer:
    handler = make_handler(config)
    return ThreadingHTTPServer((config.http.host, config.http.port), handler)


def make_handler(config: PublisherServiceConfig):
    class PullKnockPublisherHandler(BaseHTTPRequestHandler):
        server_version = "PullKnockPublisher/0.1"

        def do_GET(self) -> None:
            if self.path == config.http.health_path:
                self._send_json(HTTPStatus.OK, {"ok": True})
                return
            try:
                queue_target = _parse_queue_index_path(self.path)
                queue_item = _parse_queue_item_path(self.path)
            except ProtocolError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_queue_path", "message": str(exc)})
                return
            if queue_target is not None:
                if config.storage.mode != "queue":
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "queue_disabled"})
                    return
                if not self._authorized_for_read():
                    self._unauthorized()
                    return
                self._send_json(HTTPStatus.OK, _queue_index(config, queue_target))
                return
            if queue_item is not None:
                if config.storage.mode != "queue":
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "queue_disabled"})
                    return
                if not self._authorized_for_read():
                    self._unauthorized()
                    return
                target, command_id = queue_item
                path = _queue_item_file(config, target, command_id)
                try:
                    body = path.read_bytes()
                except FileNotFoundError:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "no_envelope"})
                    return
                except OSError as exc:
                    self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "read_failed", "message": str(exc)})
                    return
                self._send_bytes(HTTPStatus.OK, body, content_type="application/json")
                return
            if self.path != config.http.path:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            if not self._authorized_for_read():
                self._unauthorized()
                return
            envelope_path = Path(config.storage.envelope_file)
            try:
                body = envelope_path.read_bytes()
            except FileNotFoundError:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "no_envelope"})
                return
            except OSError as exc:
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "read_failed", "message": str(exc)})
                return
            self._send_bytes(HTTPStatus.OK, body, content_type="application/json")

        def do_HEAD(self) -> None:
            if self.path == config.http.health_path:
                self._send_headers(HTTPStatus.OK, content_type="application/json", content_length=0)
                return
            if self.path != config.http.path:
                self._send_headers(HTTPStatus.NOT_FOUND, content_type="application/json", content_length=0)
                return
            if not self._authorized_for_read():
                self._send_headers(HTTPStatus.UNAUTHORIZED, content_type="application/json", content_length=0)
                return
            envelope_path = Path(config.storage.envelope_file)
            if not envelope_path.exists():
                self._send_headers(HTTPStatus.NOT_FOUND, content_type="application/json", content_length=0)
                return
            self._send_headers(
                HTTPStatus.OK,
                content_type="application/json",
                content_length=envelope_path.stat().st_size,
            )

        def do_PUT(self) -> None:
            try:
                queue_item = _parse_queue_item_path(self.path)
            except ProtocolError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_queue_path", "message": str(exc)})
                return
            if queue_item is not None:
                if config.storage.mode != "queue":
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "queue_disabled"})
                    return
                if not self._authorized(config.auth.write_bearer_tokens):
                    self._unauthorized()
                    return
                self._put_body(config, queue_item=queue_item)
                return
            if self.path != config.http.path:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            if not self._authorized(config.auth.write_bearer_tokens):
                self._unauthorized()
                return
            self._put_body(config, queue_item=None)

        def _put_body(self, config: PublisherServiceConfig, *, queue_item: tuple[str, str] | None) -> None:
            content_length = self.headers.get("Content-Length")
            if content_length is None:
                self._send_json(HTTPStatus.LENGTH_REQUIRED, {"error": "content_length_required"})
                return
            try:
                body_length = int(content_length)
            except ValueError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_content_length"})
                return
            if body_length <= 0:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "empty_body"})
                return
            if body_length > config.http.max_body_bytes:
                self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "body_too_large"})
                return
            body = self.rfile.read(body_length)
            try:
                envelope = validate_publishable_envelope(body)
            except ProtocolError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_envelope", "message": str(exc)})
                return
            try:
                stored_bytes = envelope_json_bytes(envelope)
                if queue_item is None:
                    _atomic_write(Path(config.storage.envelope_file), stored_bytes)
                else:
                    target, command_id = queue_item
                    _atomic_write(_queue_item_file(config, target, command_id), stored_bytes)
            except OSError as exc:
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "write_failed", "message": str(exc)})
                return
            self._send_json(
                HTTPStatus.OK,
                {
                    "stored": True,
                    "path": self.path,
                    "mode": "queue" if queue_item else "latest",
                    "bytes": len(stored_bytes),
                },
            )

        def do_OPTIONS(self) -> None:
            self._send_headers(
                HTTPStatus.NO_CONTENT,
                content_type="application/json",
                content_length=0,
                extra_headers={"Allow": "GET, HEAD, PUT, OPTIONS"},
            )

        def _authorized_for_read(self) -> bool:
            if not config.auth.require_auth_for_read:
                return True
            return self._authorized(config.auth.read_bearer_tokens)

        def _authorized(self, tokens: tuple[str, ...]) -> bool:
            authorization = self.headers.get("Authorization", "")
            return any(hmac.compare_digest(authorization, f"Bearer {token}") for token in tokens)

        def _unauthorized(self) -> None:
            body = b'{"error":"unauthorized"}\n'
            self._send_headers(
                HTTPStatus.UNAUTHORIZED,
                content_type="application/json",
                content_length=len(body),
                extra_headers={"WWW-Authenticate": 'Bearer realm="pullknock-publisher"'},
            )
            self.wfile.write(body)

        def _send_json(self, status: HTTPStatus, body: dict[str, Any]) -> None:
            encoded = (json.dumps(body, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
            self._send_bytes(status, encoded, content_type="application/json")

        def _send_bytes(self, status: HTTPStatus, body: bytes, *, content_type: str) -> None:
            self._send_headers(status, content_type=content_type, content_length=len(body))
            self.wfile.write(body)

        def _send_headers(
            self,
            status: HTTPStatus,
            *,
            content_type: str,
            content_length: int,
            extra_headers: dict[str, str] | None = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(content_length))
            self.send_header("Cache-Control", "no-store")
            for key, value in (extra_headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self._log_structured_request(status=status, content_length=content_length)

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _log_structured_request(self, *, status: HTTPStatus, content_length: int) -> None:
            payload = {
                "timestamp": utc_iso(),
                "event": "publisher_request",
                "result": "success" if int(status) < 400 else "failure",
                "method": self.command,
                "path": urlsplit(self.path).path,
                "status": int(status),
                "response_bytes": content_length,
                "remote_ip": self.client_address[0],
                "user_agent": self.headers.get("User-Agent"),
            }
            click.echo(json.dumps(payload, sort_keys=True, ensure_ascii=False), err=True)

    return PullKnockPublisherHandler


def _queue_root(config: PublisherServiceConfig) -> Path:
    if config.storage.queue_dir:
        return Path(config.storage.queue_dir)
    return Path(config.storage.envelope_file).parent / "commands"


def _queue_item_file(config: PublisherServiceConfig, target: str, command_id: str) -> Path:
    _validate_queue_id(target, "target")
    _validate_queue_id(command_id, "command_id")
    return _queue_root(config) / target / f"{command_id}.json"


def _queue_index(config: PublisherServiceConfig, target: str) -> dict[str, Any]:
    _validate_queue_id(target, "target")
    directory = _queue_root(config) / target
    commands = []
    if directory.exists():
        for path in sorted(directory.glob("*.json")):
            command_id = path.stem
            if not SAFE_QUEUE_ID_RE.fullmatch(command_id):
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            commands.append(
                {
                    "command_id": command_id,
                    "url": f"/commands/{target}/{command_id}.json",
                    "size": stat.st_size,
                    "mtime": int(stat.st_mtime),
                }
            )
    return {"queue_version": 1, "target": target, "commands": commands}


def _parse_queue_index_path(path_value: str) -> str | None:
    path = urlsplit(path_value).path
    parts = [unquote(part) for part in path.split("/") if part]
    if len(parts) == 3 and parts[0] == "commands" and parts[2] == "index.json":
        _validate_queue_id(parts[1], "target")
        return parts[1]
    return None


def _parse_queue_item_path(path_value: str) -> tuple[str, str] | None:
    path = urlsplit(path_value).path
    parts = [unquote(part) for part in path.split("/") if part]
    if len(parts) == 3 and parts[0] == "commands" and parts[2].endswith(".json") and parts[2] != "index.json":
        target = parts[1]
        command_id = parts[2][:-5]
        _validate_queue_id(target, "target")
        _validate_queue_id(command_id, "command_id")
        return target, command_id
    return None


def _validate_queue_id(value: str, name: str) -> None:
    if not SAFE_QUEUE_ID_RE.fullmatch(value):
        raise ProtocolError(f"invalid_queue_{name}")


def _atomic_write(path: Path, body: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile("wb", delete=False, dir=str(path.parent), prefix=f".{path.name}.") as temp_file:
            temp_name = temp_file.name
            temp_file.write(body)
        os.replace(temp_name, path)
        os.chmod(path, 0o600)
    except OSError:
        if temp_name:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
        raise


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--config",
    "config_path",
    default="/etc/pullknock/publisher.yaml",
    show_default=True,
    help="Publisher service YAML config.",
)
@click.option("--check-config", is_flag=True, help="Validate config and exit.")
def main(config_path: str, check_config: bool) -> None:
    """Run a tiny PullKnock envelope bulletin-board HTTP service."""
    try:
        config = load_publisher_service_config(config_path)
    except ConfigError as exc:
        raise click.ClickException(str(exc)) from exc
    if check_config:
        click.echo("Publisher config OK.")
        return
    server = create_http_server(config)
    host, port = server.server_address
    click.echo(f"pullknock-publisher listening on http://{host}:{port}{config.http.path}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        click.echo("stopping pullknock-publisher")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
