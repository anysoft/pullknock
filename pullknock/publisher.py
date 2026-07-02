"""Envelope publishers used by the CLI."""

from __future__ import annotations

import json
import os
import tempfile
import hashlib
import hmac
from datetime import datetime, timezone
from ftplib import FTP, FTP_TLS, all_errors as FTP_ERRORS
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlparse

import requests

from .config import PublisherConfig
from .errors import PublishError
from .util import expand_env_value, expand_path


def publish_envelope(envelope: dict[str, Any], publisher: PublisherConfig, *, context: dict[str, str] | None = None) -> str:
    if publisher.type == "file":
        return _publish_file(envelope, publisher)
    if publisher.type == "http_put":
        return _publish_http_put(envelope, publisher, context=context)
    if publisher.type == "webdav_put":
        return _publish_webdav_put(envelope, publisher)
    if publisher.type in {"ftp_upload", "ftps_upload"}:
        return _publish_ftp(envelope, publisher, use_tls=publisher.type == "ftps_upload")
    if publisher.type == "ipfs_http":
        return _publish_ipfs_http(envelope, publisher)
    if publisher.type == "s3_put":
        return _publish_s3_put(envelope, publisher)
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


def _publish_http_put(envelope: dict[str, Any], publisher: PublisherConfig, *, context: dict[str, str] | None = None) -> str:
    url = publisher.options.get("url")
    if not isinstance(url, str) or not url:
        raise PublishError(f"publishers.{publisher.name}.url must be a non-empty string")
    url = _format_context_url(expand_env_value(url), context or {})
    _validate_http_url(url, publisher.name)
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


def _format_context_url(url: str, context: dict[str, str]) -> str:
    if "{" not in url:
        return url
    allowed = {"target", "grant_id", "command_id", "principal"}
    values: dict[str, str] = {}
    for key in allowed:
        value = context.get(key)
        if value is not None:
            values[key] = quote(value, safe="")
    try:
        return url.format(**values)
    except KeyError as exc:
        raise PublishError(f"http_put_url_missing_context: {exc.args[0]}") from exc


def _publish_webdav_put(envelope: dict[str, Any], publisher: PublisherConfig) -> str:
    url = _required_option_str(publisher, "url")
    _validate_http_url(url, publisher.name)
    headers = expand_env_value(publisher.options.get("headers", {}))
    if not isinstance(headers, dict):
        raise PublishError(f"publishers.{publisher.name}.headers must be a mapping")
    request_headers = {str(key): str(value) for key, value in headers.items()}
    request_headers.setdefault("Content-Type", "application/json")
    timeout = _positive_option_int(publisher, "timeout_seconds", 10)
    auth = _requests_auth(publisher)
    if bool(publisher.options.get("create_collections", False)):
        _webdav_create_collections(url, headers=request_headers, auth=auth, timeout=timeout)
    try:
        response = requests.put(url, data=envelope_json_bytes(envelope), headers=request_headers, auth=auth, timeout=timeout)
    except requests.RequestException as exc:
        raise PublishError(f"webdav_put_failed: {url}: {exc}") from exc
    if response.status_code < 200 or response.status_code >= 300:
        raise PublishError(f"webdav_put_failed: {url}: status={response.status_code} body={response.text[:200]}")
    return url


def _webdav_create_collections(url: str, *, headers: dict[str, str], auth, timeout: int) -> None:
    parsed = urlparse(url)
    parts = [part for part in parsed.path.split("/")[:-1] if part]
    current_path = ""
    for part in parts:
        current_path += "/" + part
        collection_url = parsed._replace(path=current_path).geturl()
        try:
            response = requests.request("MKCOL", collection_url, headers=headers, auth=auth, timeout=timeout)
        except requests.RequestException as exc:
            raise PublishError(f"webdav_mkcol_failed: {collection_url}: {exc}") from exc
        if response.status_code not in {200, 201, 204, 405}:
            raise PublishError(
                f"webdav_mkcol_failed: {collection_url}: status={response.status_code} body={response.text[:200]}"
            )


def _publish_ftp(envelope: dict[str, Any], publisher: PublisherConfig, *, use_tls: bool) -> str:
    url = _required_option_str(publisher, "url")
    _validate_no_control_chars(url, f"publishers.{publisher.name}.url")
    parsed = urlparse(url)
    expected_scheme = "ftps" if use_tls else "ftp"
    if parsed.scheme != expected_scheme:
        raise PublishError(f"publishers.{publisher.name}.url must use {expected_scheme}://")
    if not parsed.hostname:
        raise PublishError(f"publishers.{publisher.name}.url must include a host")
    remote_path = unquote(parsed.path or "")
    _validate_no_control_chars(remote_path, f"publishers.{publisher.name}.url.path")
    if not remote_path or remote_path.endswith("/"):
        raise PublishError(f"publishers.{publisher.name}.url must include a remote file path")
    username = _ftp_option(publisher, "username", unquote(parsed.username or "anonymous"))
    password = _ftp_option(publisher, "password", unquote(parsed.password or "anonymous@"))
    _validate_no_control_chars(username, f"publishers.{publisher.name}.username")
    _validate_no_control_chars(password, f"publishers.{publisher.name}.password")
    timeout = _positive_option_int(publisher, "timeout_seconds", 10)
    passive = bool(publisher.options.get("passive", True))
    create_dirs = bool(publisher.options.get("create_dirs", True))
    ftp_cls = FTP_TLS if use_tls else FTP
    try:
        with ftp_cls(timeout=timeout) as ftp:
            ftp.connect(parsed.hostname, parsed.port or (990 if use_tls else 21), timeout=timeout)
            ftp.login(username, password)
            if use_tls:
                ftp.prot_p()
            ftp.set_pasv(passive)
            directory, filename = remote_path.rsplit("/", 1)
            if not filename or "/" in filename:
                raise PublishError(f"publishers.{publisher.name}.url must include a valid remote file name")
            if create_dirs and directory:
                _ftp_ensure_dirs(ftp, directory)
            elif directory:
                ftp.cwd(directory)
            ftp.storbinary(f"STOR {filename}", BytesIO(envelope_json_bytes(envelope)))
    except FTP_ERRORS as exc:
        raise PublishError(f"ftp_upload_failed: {url}: {exc}") from exc
    return url


def _publish_ipfs_http(envelope: dict[str, Any], publisher: PublisherConfig) -> str:
    api_url = _option_str(publisher, "api_url", "http://127.0.0.1:5001")
    api_url = api_url.rstrip("/")
    _validate_http_url(api_url, publisher.name)
    filename = _option_str(publisher, "filename", "pullknock-command.json")
    _validate_no_control_chars(filename, f"publishers.{publisher.name}.filename")
    timeout = _positive_option_int(publisher, "timeout_seconds", 30)
    pin = bool(publisher.options.get("pin", True))
    add_url = f"{api_url}/api/v0/add"
    try:
        response = requests.post(
            add_url,
            params={"pin": str(pin).lower(), "cid-version": str(publisher.options.get("cid_version", 1))},
            files={"file": (filename, envelope_json_bytes(envelope), "application/json")},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise PublishError(f"ipfs_add_failed: {add_url}: {exc}") from exc
    if response.status_code < 200 or response.status_code >= 300:
        raise PublishError(f"ipfs_add_failed: {add_url}: status={response.status_code} body={response.text[:200]}")
    try:
        result = response.json()
    except ValueError as exc:
        raise PublishError(f"ipfs_add_failed: invalid JSON response: {response.text[:200]}") from exc
    cid = result.get("Hash")
    if not isinstance(cid, str) or not cid:
        raise PublishError("ipfs_add_failed: response missing Hash")
    ipns_key = publisher.options.get("ipns_key")
    if ipns_key is None:
        return f"ipfs://{cid}"
    if not isinstance(ipns_key, str) or not ipns_key:
        raise PublishError(f"publishers.{publisher.name}.ipns_key must be a non-empty string")
    _validate_no_control_chars(ipns_key, f"publishers.{publisher.name}.ipns_key")
    publish_url = f"{api_url}/api/v0/name/publish"
    try:
        publish_response = requests.post(
            publish_url,
            params={"arg": f"/ipfs/{cid}", "key": ipns_key},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise PublishError(f"ipns_publish_failed: {publish_url}: {exc}") from exc
    if publish_response.status_code < 200 or publish_response.status_code >= 300:
        raise PublishError(
            f"ipns_publish_failed: {publish_url}: status={publish_response.status_code} body={publish_response.text[:200]}"
        )
    return f"ipns://{ipns_key}/{cid}"


def _publish_s3_put(envelope: dict[str, Any], publisher: PublisherConfig) -> str:
    endpoint_url = _required_option_str(publisher, "endpoint_url").rstrip("/")
    parsed_endpoint = urlparse(endpoint_url)
    if parsed_endpoint.scheme not in {"http", "https"} or not parsed_endpoint.netloc:
        raise PublishError(f"publishers.{publisher.name}.endpoint_url must be an http:// or https:// URL")
    region = _option_str(publisher, "region", "us-east-1")
    bucket = _required_option_str(publisher, "bucket")
    key = _required_option_str(publisher, "key").lstrip("/")
    access_key_id = _required_expanded_option_str(publisher, "access_key_id")
    secret_access_key = _required_expanded_option_str(publisher, "secret_access_key")
    session_token = _expanded_option_str(publisher, "session_token", "")
    timeout = _positive_option_int(publisher, "timeout_seconds", 30)
    path_style = bool(publisher.options.get("path_style", True))
    body = envelope_json_bytes(envelope)
    url = _s3_object_url(endpoint_url, bucket=bucket, key=key, path_style=path_style)
    headers = expand_env_value(publisher.options.get("headers", {}))
    if not isinstance(headers, dict):
        raise PublishError(f"publishers.{publisher.name}.headers must be a mapping")
    request_headers = {str(k): str(v) for k, v in headers.items()}
    request_headers.setdefault("Content-Type", "application/json")
    _sign_s3_v4_put(
        url,
        body,
        headers=request_headers,
        region=region,
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        session_token=session_token or None,
    )
    try:
        response = requests.put(url, data=body, headers=request_headers, timeout=timeout)
    except requests.RequestException as exc:
        raise PublishError(f"s3_put_failed: {url}: {exc}") from exc
    if response.status_code < 200 or response.status_code >= 300:
        raise PublishError(f"s3_put_failed: {url}: status={response.status_code} body={response.text[:200]}")
    return url


def _ftp_ensure_dirs(ftp, directory: str) -> None:
    for part in [item for item in directory.split("/") if item]:
        _validate_no_control_chars(part, "ftp directory")
        try:
            ftp.mkd(part)
        except FTP_ERRORS:
            pass
        ftp.cwd(part)


def _requests_auth(publisher: PublisherConfig):
    username = publisher.options.get("username")
    password = publisher.options.get("password")
    if username is None and password is None:
        return None
    if not isinstance(username, str) or not isinstance(password, str):
        raise PublishError(f"publishers.{publisher.name}.username/password must both be strings")
    username = expand_env_value(username)
    password = expand_env_value(password)
    _validate_no_control_chars(username, f"publishers.{publisher.name}.username")
    _validate_no_control_chars(password, f"publishers.{publisher.name}.password")
    return (username, password)


def _ftp_option(publisher: PublisherConfig, key: str, default: str) -> str:
    value = publisher.options.get(key, default)
    if not isinstance(value, str):
        raise PublishError(f"publishers.{publisher.name}.{key} must be a string")
    return expand_env_value(value)


def _option_str(publisher: PublisherConfig, key: str, default: str) -> str:
    value = publisher.options.get(key, default)
    if not isinstance(value, str) or not value:
        raise PublishError(f"publishers.{publisher.name}.{key} must be a non-empty string")
    value = expand_env_value(value)
    _validate_no_control_chars(value, f"publishers.{publisher.name}.{key}")
    return value


def _required_option_str(publisher: PublisherConfig, key: str) -> str:
    value = publisher.options.get(key)
    if not isinstance(value, str) or not value:
        raise PublishError(f"publishers.{publisher.name}.{key} must be a non-empty string")
    value = expand_env_value(value)
    _validate_no_control_chars(value, f"publishers.{publisher.name}.{key}")
    return value


def _required_expanded_option_str(publisher: PublisherConfig, key: str) -> str:
    value = _required_option_str(publisher, key)
    if "$" in value:
        raise PublishError(f"publishers.{publisher.name}.{key} contains unresolved environment variables")
    return value


def _expanded_option_str(publisher: PublisherConfig, key: str, default: str) -> str:
    value = publisher.options.get(key, default)
    if not isinstance(value, str):
        raise PublishError(f"publishers.{publisher.name}.{key} must be a string")
    value = expand_env_value(value)
    _validate_no_control_chars(value, f"publishers.{publisher.name}.{key}")
    if "$" in value:
        raise PublishError(f"publishers.{publisher.name}.{key} contains unresolved environment variables")
    return value


def _positive_option_int(publisher: PublisherConfig, key: str, default: int) -> int:
    value = publisher.options.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise PublishError(f"publishers.{publisher.name}.{key} must be a positive integer")
    return value


def _validate_http_url(url: str, publisher_name: str) -> None:
    _validate_no_control_chars(url, f"publishers.{publisher_name}.url")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise PublishError(f"publishers.{publisher_name}.url must be an http:// or https:// URL")


def _validate_no_control_chars(value: str, name: str) -> None:
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise PublishError(f"{name} contains invalid control characters")


def _s3_object_url(endpoint_url: str, *, bucket: str, key: str, path_style: bool) -> str:
    quoted_key = quote(key, safe="/-_.~")
    if path_style:
        return f"{endpoint_url.rstrip('/')}/{quote(bucket, safe='-_.~')}/{quoted_key}"
    parsed = urlparse(endpoint_url)
    return parsed._replace(netloc=f"{bucket}.{parsed.netloc}", path=f"/{quoted_key}").geturl()


def _sign_s3_v4_put(
    url: str,
    body: bytes,
    *,
    headers: dict[str, str],
    region: str,
    access_key_id: str,
    secret_access_key: str,
    session_token: str | None,
) -> None:
    parsed = urlparse(url)
    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body).hexdigest()
    headers["Host"] = parsed.netloc
    headers["X-Amz-Date"] = amz_date
    headers["X-Amz-Content-Sha256"] = payload_hash
    if session_token:
        headers["X-Amz-Security-Token"] = session_token
    canonical_uri = quote(parsed.path or "/", safe="/-_.~")
    canonical_query = parsed.query
    canonical_headers_items = sorted((key.lower(), " ".join(value.strip().split())) for key, value in headers.items())
    canonical_headers = "".join(f"{key}:{value}\n" for key, value in canonical_headers_items)
    signed_headers = ";".join(key for key, _ in canonical_headers_items)
    canonical_request = "\n".join(
        ["PUT", canonical_uri, canonical_query, canonical_headers, signed_headers, payload_hash]
    )
    credential_scope = f"{date_stamp}/{region}/s3/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    signing_key = _aws_v4_signing_key(secret_access_key, date_stamp, region, "s3")
    signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    headers["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access_key_id}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )


def _aws_v4_signing_key(secret_key: str, date_stamp: str, region: str, service: str) -> bytes:
    key_date = hmac.new(("AWS4" + secret_key).encode("utf-8"), date_stamp.encode("utf-8"), hashlib.sha256).digest()
    key_region = hmac.new(key_date, region.encode("utf-8"), hashlib.sha256).digest()
    key_service = hmac.new(key_region, service.encode("utf-8"), hashlib.sha256).digest()
    return hmac.new(key_service, b"aws4_request", hashlib.sha256).digest()
