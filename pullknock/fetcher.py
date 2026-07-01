"""Control URL fetchers used by the agent."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import unquote, urlparse

import requests

from .errors import FetchError
from .util import expand_env_value, expand_path


def fetch_control_url(control_url: str, *, timeout_seconds: int = 5, headers: dict[str, str] | None = None) -> str | None:
    parsed = urlparse(control_url)
    if parsed.scheme in {"http", "https"}:
        return _fetch_http(control_url, timeout_seconds=timeout_seconds, headers=headers)
    if parsed.scheme == "file":
        return _fetch_file(unquote(parsed.path))
    if parsed.scheme == "":
        return _fetch_file(control_url)
    raise FetchError(f"unsupported_control_url_scheme: {parsed.scheme}")


def _fetch_file(path_value: str) -> str | None:
    path = Path(expand_path(path_value))
    try:
        data = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise FetchError(f"file_fetch_failed: {path}: {exc}") from exc
    if not data.strip():
        return None
    return data


def _fetch_http(control_url: str, *, timeout_seconds: int, headers: dict[str, str] | None = None) -> str | None:
    request_headers = expand_env_value(headers or {})
    try:
        response = requests.get(control_url, headers=request_headers, timeout=timeout_seconds)
    except requests.RequestException as exc:
        raise FetchError(f"http_fetch_failed: {control_url}: {exc}") from exc
    if response.status_code in {204, 404}:
        return None
    if response.status_code < 200 or response.status_code >= 300:
        raise FetchError(f"http_fetch_failed: {control_url}: status={response.status_code} body={response.text[:200]}")
    if not response.text.strip():
        return None
    return response.text
