"""PullKnock v1 payload and envelope handling."""

from __future__ import annotations

import base64
import json
import uuid
from typing import Any

from .errors import ProtocolError
from .util import parse_ip

PAYLOAD_VERSION = 1
PAYLOAD_TYPE = "pullknock.open"
ENVELOPE_VERSION = 1
ENVELOPE_ENCODING = "plain+sshsig"

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
    return {
        "envelope_version": ENVELOPE_VERSION,
        "encoding": ENVELOPE_ENCODING,
        "payload_b64": base64.b64encode(payload_bytes).decode("ascii"),
        "signature_b64": base64.b64encode(signature_bytes).decode("ascii"),
        "kid": kid,
        "created_at": created_at,
    }


def parse_envelope(envelope_data: str | bytes | dict[str, Any]) -> tuple[bytes, bytes, dict[str, Any]]:
    if isinstance(envelope_data, bytes):
        envelope_data = envelope_data.decode("utf-8")
    if isinstance(envelope_data, str):
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
    if envelope.get("envelope_version") != ENVELOPE_VERSION:
        raise ProtocolError("unsupported_envelope_version")
    if envelope.get("encoding") != ENVELOPE_ENCODING:
        raise ProtocolError("unsupported_envelope_encoding")
    payload_b64 = _required_str(envelope, "payload_b64")
    signature_b64 = _required_str(envelope, "signature_b64")
    _required_str(envelope, "kid")
    if not _is_int(envelope.get("created_at")):
        raise ProtocolError("created_at must be an integer")
    try:
        payload_bytes = base64.b64decode(payload_b64.encode("ascii"), validate=True)
        signature_bytes = base64.b64decode(signature_b64.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ProtocolError("invalid_base64") from exc
    if not payload_bytes:
        raise ProtocolError("empty_payload")
    if not signature_bytes:
        raise ProtocolError("empty_signature")
    return payload_bytes, signature_bytes, envelope


def parse_payload(payload_bytes: bytes) -> dict[str, Any]:
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
    missing = sorted(_REQUIRED_PAYLOAD_FIELDS.difference(payload))
    if missing:
        raise ProtocolError(f"payload_missing_fields: {','.join(missing)}")
    if payload["version"] != PAYLOAD_VERSION:
        raise ProtocolError("unsupported_payload_version")
    if payload["type"] != PAYLOAD_TYPE:
        raise ProtocolError("unsupported_payload_type")
    for key in ("command_id", "principal", "target", "grant_id", "source_ip"):
        _required_str(payload, key)
    try:
        uuid.UUID(payload["command_id"])
    except ValueError as exc:
        raise ProtocolError("invalid_command_id") from exc
    parse_ip(payload["source_ip"])
    for key in ("requested_timeout", "issued_at", "not_before", "expires_at"):
        if not _is_int(payload.get(key)):
            raise ProtocolError(f"{key} must be an integer")
    if payload["requested_timeout"] <= 0:
        raise ProtocolError("requested_timeout must be positive")
    if payload["expires_at"] < payload["not_before"]:
        raise ProtocolError("expires_at_before_not_before")
    if "reason" in payload and not isinstance(payload["reason"], str):
        raise ProtocolError("reason must be a string")


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
    return value


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)
