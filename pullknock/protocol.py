"""PullKnock payload and envelope handling."""

from __future__ import annotations

import base64
import json
import re
import uuid
from typing import Any

from .errors import ProtocolError
from .util import parse_ip

PAYLOAD_VERSION = 1
PAYLOAD_TYPE = "pullknock.open"
ENVELOPE_VERSION = 1
ENVELOPE_V2_VERSION = 2
ENVELOPE_ENCODING = "plain+sshsig"
ENCRYPTED_ENVELOPE_ENCODING = "age+plain+sshsig"
ENVELOPE_V2_ENCODING = "age"
ENVELOPE_V2_CONTENT_TYPE = "pullknock.envelope"
ENVELOPE_V2_ENCRYPTION_ALG = "age-v1"
MAX_ENVELOPE_BYTES = 128 * 1024
MAX_PAYLOAD_BYTES = 16 * 1024
MAX_SIGNATURE_BYTES = 64 * 1024
MAX_B64_CHARS = 192 * 1024
MAX_REASON_CHARS = 512
MAX_ID_CHARS = 128
MAX_TIMEOUT_SECONDS = 86400
MAX_UNIX_TIMESTAMP = 4102444800
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}$")

_REQUIRED_PAYLOAD_FIELDS = {
    "version",
    "type",
    "command_id",
    "principal",
    "target",
    "grant_id",
    "source_ip",
    "requested_timeout",
    "issued_at",
    "not_before",
    "expires_at",
}
_OPTIONAL_PAYLOAD_FIELDS = {"reason"}
_ALLOWED_PAYLOAD_FIELDS = _REQUIRED_PAYLOAD_FIELDS | _OPTIONAL_PAYLOAD_FIELDS
_REQUIRED_ENVELOPE_FIELDS = {
    "envelope_version",
    "encoding",
    "payload_b64",
    "signature_b64",
    "kid",
    "created_at",
}
_ALLOWED_ENVELOPE_FIELDS = _REQUIRED_ENVELOPE_FIELDS
_REQUIRED_ENCRYPTED_ENVELOPE_FIELDS = {
    "envelope_version",
    "encoding",
    "ciphertext_b64",
    "kid",
    "created_at",
}
_ALLOWED_ENCRYPTED_ENVELOPE_FIELDS = _REQUIRED_ENCRYPTED_ENVELOPE_FIELDS
_REQUIRED_ENVELOPE_V2_FIELDS = {
    "envelope_version",
    "content_type",
    "encoding",
    "encryption_alg",
    "encryption_key_id",
    "inner_envelope_version",
    "inner_encoding",
    "ciphertext_b64",
    "kid",
    "created_at",
}
_ALLOWED_ENVELOPE_V2_FIELDS = _REQUIRED_ENVELOPE_V2_FIELDS


def canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def build_payload(
    *,
    principal: str,
    target: str,
    grant_id: str,
    source_ip: str,
    requested_timeout: int,
    issued_at: int,
    not_before: int,
    expires_at: int,
    reason: str = "",
    command_id: str | None = None,
) -> dict[str, Any]:
    payload = {
        "version": PAYLOAD_VERSION,
        "type": PAYLOAD_TYPE,
        "command_id": command_id or str(uuid.uuid4()),
        "principal": principal,
        "target": target,
        "grant_id": grant_id,
        "source_ip": source_ip,
        "requested_timeout": requested_timeout,
        "issued_at": issued_at,
        "not_before": not_before,
        "expires_at": expires_at,
    }
    if reason:
        payload["reason"] = reason
    validate_payload_schema(payload)
    return payload


def build_envelope(payload_bytes: bytes, signature_bytes: bytes, *, kid: str, created_at: int) -> dict[str, Any]:
    _validate_safe_id(kid, "kid")
    return {
        "envelope_version": ENVELOPE_VERSION,
        "encoding": ENVELOPE_ENCODING,
        "payload_b64": base64.b64encode(payload_bytes).decode("ascii"),
        "signature_b64": base64.b64encode(signature_bytes).decode("ascii"),
        "kid": kid,
        "created_at": created_at,
    }


def build_encrypted_envelope(ciphertext_bytes: bytes, *, kid: str, created_at: int) -> dict[str, Any]:
    _validate_safe_id(kid, "kid")
    if not ciphertext_bytes:
        raise ProtocolError("empty_ciphertext")
    if len(ciphertext_bytes) > MAX_ENVELOPE_BYTES:
        raise ProtocolError("ciphertext_too_large")
    return {
        "envelope_version": ENVELOPE_VERSION,
        "encoding": ENCRYPTED_ENVELOPE_ENCODING,
        "ciphertext_b64": base64.b64encode(ciphertext_bytes).decode("ascii"),
        "kid": kid,
        "created_at": created_at,
    }


def build_envelope_v2(
    ciphertext_bytes: bytes,
    *,
    kid: str,
    encryption_key_id: str,
    created_at: int,
    encryption_alg: str = ENVELOPE_V2_ENCRYPTION_ALG,
    inner_envelope_version: int = ENVELOPE_VERSION,
    inner_encoding: str = ENVELOPE_ENCODING,
) -> dict[str, Any]:
    _validate_safe_id(kid, "kid")
    _validate_safe_id(encryption_key_id, "encryption_key_id")
    if encryption_alg != ENVELOPE_V2_ENCRYPTION_ALG:
        raise ProtocolError("unsupported_encryption_alg")
    if inner_envelope_version != ENVELOPE_VERSION or inner_encoding != ENVELOPE_ENCODING:
        raise ProtocolError("unsupported_inner_envelope")
    if not ciphertext_bytes:
        raise ProtocolError("empty_ciphertext")
    if len(ciphertext_bytes) > MAX_ENVELOPE_BYTES:
        raise ProtocolError("ciphertext_too_large")
    return {
        "envelope_version": ENVELOPE_V2_VERSION,
        "content_type": ENVELOPE_V2_CONTENT_TYPE,
        "encoding": ENVELOPE_V2_ENCODING,
        "encryption_alg": encryption_alg,
        "encryption_key_id": encryption_key_id,
        "inner_envelope_version": inner_envelope_version,
        "inner_encoding": inner_encoding,
        "ciphertext_b64": base64.b64encode(ciphertext_bytes).decode("ascii"),
        "kid": kid,
        "created_at": created_at,
    }


def parse_envelope(envelope_data: str | bytes | dict[str, Any]) -> tuple[bytes, bytes, dict[str, Any]]:
    if isinstance(envelope_data, bytes):
        if len(envelope_data) > MAX_ENVELOPE_BYTES:
            raise ProtocolError("envelope_too_large")
        envelope_data = envelope_data.decode("utf-8")
    if isinstance(envelope_data, str):
        if len(envelope_data.encode("utf-8")) > MAX_ENVELOPE_BYTES:
            raise ProtocolError("envelope_too_large")
        try:
            envelope = json.loads(envelope_data, object_pairs_hook=_reject_duplicate_pairs)
        except json.JSONDecodeError as exc:
            raise ProtocolError(f"invalid_envelope_json: {exc}") from exc
    elif isinstance(envelope_data, dict):
        envelope = envelope_data
    else:
        raise ProtocolError("envelope must be JSON text or mapping")
    if not isinstance(envelope, dict):
        raise ProtocolError("envelope must be a mapping")
    if is_encrypted_envelope_mapping(envelope):
        raise ProtocolError("encrypted_envelope_requires_decryption")
    _validate_allowed_keys(envelope, _ALLOWED_ENVELOPE_FIELDS, "envelope")
    missing = sorted(_REQUIRED_ENVELOPE_FIELDS.difference(envelope))
    if missing:
        raise ProtocolError(f"envelope_missing_fields: {','.join(missing)}")
    if envelope.get("envelope_version") != ENVELOPE_VERSION:
        raise ProtocolError("unsupported_envelope_version")
    if envelope.get("encoding") != ENVELOPE_ENCODING:
        raise ProtocolError("unsupported_envelope_encoding")
    payload_b64 = _required_str(envelope, "payload_b64")
    signature_b64 = _required_str(envelope, "signature_b64")
    if len(payload_b64) > MAX_B64_CHARS or len(signature_b64) > MAX_B64_CHARS:
        raise ProtocolError("base64_field_too_large")
    _validate_safe_id(_required_str(envelope, "kid"), "kid")
    if not _is_int(envelope.get("created_at")):
        raise ProtocolError("created_at must be an integer")
    _validate_timestamp(envelope["created_at"], "created_at")
    try:
        payload_bytes = base64.b64decode(payload_b64.encode("ascii"), validate=True)
        signature_bytes = base64.b64decode(signature_b64.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ProtocolError("invalid_base64") from exc
    if not payload_bytes:
        raise ProtocolError("empty_payload")
    if not signature_bytes:
        raise ProtocolError("empty_signature")
    if len(payload_bytes) > MAX_PAYLOAD_BYTES:
        raise ProtocolError("payload_too_large")
    if len(signature_bytes) > MAX_SIGNATURE_BYTES:
        raise ProtocolError("signature_too_large")
    return payload_bytes, signature_bytes, envelope


def parse_encrypted_envelope(envelope_data: str | bytes | dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    envelope = _parse_envelope_mapping(envelope_data)
    if envelope.get("envelope_version") == ENVELOPE_V2_VERSION:
        return parse_envelope_v2(envelope)
    _validate_allowed_keys(envelope, _ALLOWED_ENCRYPTED_ENVELOPE_FIELDS, "envelope")
    missing = sorted(_REQUIRED_ENCRYPTED_ENVELOPE_FIELDS.difference(envelope))
    if missing:
        raise ProtocolError(f"envelope_missing_fields: {','.join(missing)}")
    if envelope.get("envelope_version") != ENVELOPE_VERSION:
        raise ProtocolError("unsupported_envelope_version")
    if envelope.get("encoding") != ENCRYPTED_ENVELOPE_ENCODING:
        raise ProtocolError("not_encrypted_envelope")
    ciphertext_b64 = _required_str(envelope, "ciphertext_b64")
    if len(ciphertext_b64) > MAX_B64_CHARS:
        raise ProtocolError("base64_field_too_large")
    _validate_safe_id(_required_str(envelope, "kid"), "kid")
    if not _is_int(envelope.get("created_at")):
        raise ProtocolError("created_at must be an integer")
    _validate_timestamp(envelope["created_at"], "created_at")
    try:
        ciphertext_bytes = base64.b64decode(ciphertext_b64.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ProtocolError("invalid_base64") from exc
    if not ciphertext_bytes:
        raise ProtocolError("empty_ciphertext")
    if len(ciphertext_bytes) > MAX_ENVELOPE_BYTES:
        raise ProtocolError("ciphertext_too_large")
    return ciphertext_bytes, envelope


def parse_envelope_v2(envelope_data: str | bytes | dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    envelope = _parse_envelope_mapping(envelope_data)
    _validate_allowed_keys(envelope, _ALLOWED_ENVELOPE_V2_FIELDS, "envelope")
    missing = sorted(_REQUIRED_ENVELOPE_V2_FIELDS.difference(envelope))
    if missing:
        raise ProtocolError(f"envelope_missing_fields: {','.join(missing)}")
    if envelope.get("envelope_version") != ENVELOPE_V2_VERSION:
        raise ProtocolError("unsupported_envelope_version")
    if envelope.get("content_type") != ENVELOPE_V2_CONTENT_TYPE:
        raise ProtocolError("unsupported_content_type")
    if envelope.get("encoding") != ENVELOPE_V2_ENCODING:
        raise ProtocolError("unsupported_envelope_encoding")
    if envelope.get("encryption_alg") != ENVELOPE_V2_ENCRYPTION_ALG:
        raise ProtocolError("unsupported_encryption_alg")
    _validate_safe_id(_required_str(envelope, "encryption_key_id"), "encryption_key_id")
    if envelope.get("inner_envelope_version") != ENVELOPE_VERSION:
        raise ProtocolError("unsupported_inner_envelope_version")
    if envelope.get("inner_encoding") != ENVELOPE_ENCODING:
        raise ProtocolError("unsupported_inner_envelope_encoding")
    ciphertext_b64 = _required_str(envelope, "ciphertext_b64")
    if len(ciphertext_b64) > MAX_B64_CHARS:
        raise ProtocolError("base64_field_too_large")
    _validate_safe_id(_required_str(envelope, "kid"), "kid")
    if not _is_int(envelope.get("created_at")):
        raise ProtocolError("created_at must be an integer")
    _validate_timestamp(envelope["created_at"], "created_at")
    try:
        ciphertext_bytes = base64.b64decode(ciphertext_b64.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ProtocolError("invalid_base64") from exc
    if not ciphertext_bytes:
        raise ProtocolError("empty_ciphertext")
    if len(ciphertext_bytes) > MAX_ENVELOPE_BYTES:
        raise ProtocolError("ciphertext_too_large")
    return ciphertext_bytes, envelope


def validate_publishable_envelope(envelope_data: str | bytes | dict[str, Any]) -> dict[str, Any]:
    envelope = _parse_envelope_mapping(envelope_data)
    if is_encrypted_envelope_mapping(envelope):
        _, parsed = parse_encrypted_envelope(envelope)
        return parsed
    payload_bytes, _, parsed = parse_envelope(envelope)
    parse_payload(payload_bytes)
    return parsed


def envelope_encoding(envelope_data: str | bytes | dict[str, Any]) -> str | None:
    envelope = _parse_envelope_mapping(envelope_data)
    encoding = envelope.get("encoding")
    return encoding if isinstance(encoding, str) else None


def is_encrypted_envelope(envelope_data: str | bytes | dict[str, Any]) -> bool:
    envelope = _parse_envelope_mapping(envelope_data)
    return is_encrypted_envelope_mapping(envelope)


def is_encrypted_envelope_mapping(envelope: dict[str, Any]) -> bool:
    version = envelope.get("envelope_version")
    encoding = envelope.get("encoding")
    return (version == ENVELOPE_VERSION and encoding == ENCRYPTED_ENVELOPE_ENCODING) or (
        version == ENVELOPE_V2_VERSION and encoding == ENVELOPE_V2_ENCODING
    )


def _parse_envelope_mapping(envelope_data: str | bytes | dict[str, Any]) -> dict[str, Any]:
    if isinstance(envelope_data, bytes):
        if len(envelope_data) > MAX_ENVELOPE_BYTES:
            raise ProtocolError("envelope_too_large")
        envelope_data = envelope_data.decode("utf-8")
    if isinstance(envelope_data, str):
        if len(envelope_data.encode("utf-8")) > MAX_ENVELOPE_BYTES:
            raise ProtocolError("envelope_too_large")
        try:
            envelope = json.loads(envelope_data, object_pairs_hook=_reject_duplicate_pairs)
        except json.JSONDecodeError as exc:
            raise ProtocolError(f"invalid_envelope_json: {exc}") from exc
    elif isinstance(envelope_data, dict):
        envelope = envelope_data
    else:
        raise ProtocolError("envelope must be JSON text or mapping")
    if not isinstance(envelope, dict):
        raise ProtocolError("envelope must be a mapping")
    return envelope


def parse_payload(payload_bytes: bytes) -> dict[str, Any]:
    if len(payload_bytes) > MAX_PAYLOAD_BYTES:
        raise ProtocolError("payload_too_large")
    try:
        payload = json.loads(payload_bytes.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"invalid_payload_json: {exc}") from exc
    if not isinstance(payload, dict):
        raise ProtocolError("payload must be a mapping")
    validate_payload_schema(payload)
    if canonical_json(payload) != payload_bytes:
        raise ProtocolError("payload_not_canonical")
    return payload


def validate_payload_schema(payload: dict[str, Any]) -> None:
    _validate_allowed_keys(payload, _ALLOWED_PAYLOAD_FIELDS, "payload")
    missing = sorted(_REQUIRED_PAYLOAD_FIELDS.difference(payload))
    if missing:
        raise ProtocolError(f"payload_missing_fields: {','.join(missing)}")
    if payload["version"] != PAYLOAD_VERSION:
        raise ProtocolError("unsupported_payload_version")
    if payload["type"] != PAYLOAD_TYPE:
        raise ProtocolError("unsupported_payload_type")
    for key in ("command_id", "principal", "target", "grant_id", "source_ip"):
        _required_str(payload, key)
    for key in ("principal", "target", "grant_id"):
        _validate_safe_id(payload[key], key)
    try:
        parsed_uuid = uuid.UUID(payload["command_id"])
    except ValueError as exc:
        raise ProtocolError("invalid_command_id") from exc
    if str(parsed_uuid) != payload["command_id"].lower():
        raise ProtocolError("invalid_command_id")
    parse_ip(payload["source_ip"])
    for key in ("requested_timeout", "issued_at", "not_before", "expires_at"):
        if not _is_int(payload.get(key)):
            raise ProtocolError(f"{key} must be an integer")
    for key in ("issued_at", "not_before", "expires_at"):
        _validate_timestamp(payload[key], key)
    if payload["requested_timeout"] <= 0:
        raise ProtocolError("requested_timeout must be positive")
    if payload["requested_timeout"] > MAX_TIMEOUT_SECONDS:
        raise ProtocolError("requested_timeout too large")
    if payload["expires_at"] < payload["not_before"]:
        raise ProtocolError("expires_at_before_not_before")
    if "reason" in payload and not isinstance(payload["reason"], str):
        raise ProtocolError("reason must be a string")
    if "reason" in payload and len(payload["reason"]) > MAX_REASON_CHARS:
        raise ProtocolError("reason_too_long")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError(f"duplicate_json_key: {key}")
        result[key] = value
    return result


def _required_str(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ProtocolError(f"{key} must be a non-empty string")
    if "\x00" in value or "\r" in value or "\n" in value:
        raise ProtocolError(f"{key} contains invalid control characters")
    return value


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_allowed_keys(data: dict[str, Any], allowed: set[str], scope: str) -> None:
    for key in data:
        if not isinstance(key, str):
            raise ProtocolError(f"{scope}_key_must_be_string")
        if key not in allowed:
            raise ProtocolError(f"{scope}_unknown_field: {key}")


def _validate_safe_id(value: str, field: str) -> None:
    if len(value) > MAX_ID_CHARS or not SAFE_ID_RE.fullmatch(value):
        raise ProtocolError(f"{field}_invalid")


def _validate_timestamp(value: int, field: str) -> None:
    if value < 0 or value > MAX_UNIX_TIMESTAMP:
        raise ProtocolError(f"{field}_out_of_range")
