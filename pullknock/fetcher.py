"""Control URL fetchers used by the agent."""

from __future__ import annotations

from ftplib import FTP, FTP_TLS, all_errors as FTP_ERRORS
from io import BytesIO
from pathlib import Path
from urllib.parse import unquote, urlparse

import requests

from .errors import FetchError
from .util import expand_env_value, expand_path


def fetch_control_url(control_url: str, *, timeout_seconds: int = 5, headers: dict[str, str] | None = None) -> str | None:
    control_url = expand_env_value(control_url)
    _validate_no_control_chars(control_url, "control_url")
    parsed = urlparse(control_url)
    if parsed.scheme in {"http", "https"}:
        return _fetch_http(control_url, timeout_seconds=timeout_seconds, headers=headers)
    if parsed.scheme in {"ftp", "ftps"}:
        return _fetch_ftp(control_url, timeout_seconds=timeout_seconds, use_tls=parsed.scheme == "ftps")
    if parsed.scheme == "file":
        return _fetch_file(unquote(parsed.path))
    if parsed.scheme == "":
        return _fetch_file(control_url)
    raise FetchError(f"unsupported_control_url_scheme: {parsed.scheme}")


def fetch_control_urls(
    control_urls: tuple[str, ...] | list[str],
    *,
    timeout_seconds: int = 5,
    headers: dict[str, str] | None = None,
) -> str | None:
    result = fetch_control_urls_with_source(control_urls, timeout_seconds=timeout_seconds, headers=headers)
    return result[0] if result else None


def fetch_control_urls_with_source(
    control_urls: tuple[str, ...] | list[str],
    *,
    timeout_seconds: int = 5,
    headers: dict[str, str] | None = None,
) -> tuple[str, str] | None:
    errors: list[str] = []
    for control_url in control_urls:
        try:
            data = fetch_control_url(control_url, timeout_seconds=timeout_seconds, headers=headers)
        except FetchError as exc:
            errors.append(str(exc))
            continue
        if data is not None:
            return data, expand_env_value(control_url)
    if errors:
        raise FetchError("all_control_urls_failed: " + " | ".join(errors))
    return None


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


def _fetch_ftp(control_url: str, *, timeout_seconds: int, use_tls: bool) -> str | None:
    parsed = urlparse(control_url)
    if not parsed.hostname:
        raise FetchError("ftp_fetch_failed: control_url must include a host")
    remote_path = unquote(parsed.path or "")
    _validate_no_control_chars(remote_path, "control_url.path")
    if not remote_path or remote_path.endswith("/"):
        raise FetchError("ftp_fetch_failed: control_url must include a remote file path")
    username = unquote(parsed.username or "anonymous")
    password = unquote(parsed.password or "anonymous@")
    _validate_no_control_chars(username, "control_url.username")
    _validate_no_control_chars(password, "control_url.password")
    ftp_cls = FTP_TLS if use_tls else FTP
    body = BytesIO()
    try:
        with ftp_cls(timeout=timeout_seconds) as ftp:
            ftp.connect(parsed.hostname, parsed.port or (990 if use_tls else 21), timeout=timeout_seconds)
            ftp.login(username, password)
            if use_tls:
                ftp.prot_p()
            ftp.retrbinary(f"RETR {remote_path}", body.write)
    except FTP_ERRORS as exc:
        message = str(exc)
        if "550" in message:
            return None
        raise FetchError(f"ftp_fetch_failed: {control_url}: {exc}") from exc
    data = body.getvalue().decode("utf-8")
    if not data.strip():
        return None
    return data


def _validate_no_control_chars(value: str, name: str) -> None:
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise FetchError(f"{name} contains invalid control characters")
