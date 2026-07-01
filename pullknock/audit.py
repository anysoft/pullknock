"""JSON audit logging."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from .util import utc_iso

LOGGER_NAME = "pullknock.audit"


def configure_logging(*, log_file: str | None = None, level: str = "INFO") -> None:
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    kwargs: dict[str, Any] = {"level": numeric_level, "format": "%(message)s"}
    if log_file:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        kwargs["filename"] = str(path)
    logging.basicConfig(**kwargs)


def log_event(event: str, *, result: str, level: int = logging.INFO, **fields: Any) -> None:
    payload = {
        "timestamp": utc_iso(),
        "event": event,
        "result": result,
    }
    for key, value in fields.items():
        if value is not None:
            payload[key] = value
    logging.getLogger(LOGGER_NAME).log(level, json.dumps(payload, sort_keys=True, ensure_ascii=False))
