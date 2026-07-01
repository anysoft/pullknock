"""Envelope publishers used by the CLI."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

import requests

from .config import PublisherConfig
from .errors import PublishError
from .util import expand_env_value, expand_path


def publish_envelope(envelope: dict[str, Any], publisher: PublisherConfig) -> str:
    if publisher.type == "file":
        return _publish_file(envelope, publisher)
    if publisher.type == "http_put":
        return _publish_http_put(envelope, publisher)
    raise PublishError(f"unsupported_publisher_type: {publisher.type}")


def envelope_json_bytes(envelope: dict[str, Any]) -> bytes:
    return (json.dumps(envelope, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _publish_file(envelope: dict[str, Any], publisher: PublisherConfig) -> str:
    path_value = publisher.options.get("path")
    if not isinstance(path_value, str) or not path_value:
        raise PublishError(f"publishers.{publisher.name}.path must be a non-empty string")
    path = Path(expand_path(path_value))
    path.parent.mkdir(parents=True, exist_ok=True)
    body = envelope_json_bytes(envelope)
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile("wb", delete=False, dir=str(path.parent), prefix=f".{path.name}.") as temp_file:
            temp_name = temp_file.name
            temp_file.write(body)
        os.replace(temp_name, path)
    except OSError as exc:
        if temp_name:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
        raise PublishError(f"file_publish_failed: {path}: {exc}") from exc
    return str(path)


def _publish_http_put(envelope: dict[str, Any], publisher: PublisherConfig) -> str:
    url = publisher.options.get("url")
    if not isinstance(url, str) or not url:
        raise PublishError(f"publishers.{publisher.name}.url must be a non-empty string")
    headers = expand_env_value(publisher.options.get("headers", {}))
    if not isinstance(headers, dict):
        raise PublishError(f"publishers.{publisher.name}.headers must be a mapping")
    request_headers = {str(key): str(value) for key, value in headers.items()}
    request_headers.setdefault("Content-Type", "application/json")
    timeout = publisher.options.get("timeout_seconds", 10)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout <= 0:
        raise PublishError(f"publishers.{publisher.name}.timeout_seconds must be a positive integer")
    try:
        response = requests.put(url, data=envelope_json_bytes(envelope), headers=request_headers, timeout=timeout)
    except requests.RequestException as exc:
        raise PublishError(f"http_put_failed: {url}: {exc}") from exc
    if response.status_code < 200 or response.status_code >= 300:
        raise PublishError(f"http_put_failed: {url}: status={response.status_code} body={response.text[:200]}")
    return url
