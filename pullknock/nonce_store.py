"""SQLite-backed nonce store."""

from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path

from .errors import DuplicateCommand


class NonceStore:
    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            parent = Path(path).parent
            parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    def contains(self, command_id: str) -> bool:
        with self._connect() as conn:
            row = conn.execute("SELECT 1 FROM used_nonces WHERE command_id = ?", (command_id,)).fetchone()
        return row is not None

    def assert_unused(self, command_id: str) -> None:
        if self.contains(command_id):
            raise DuplicateCommand("duplicate_command")

    def mark_used(
        self,
        *,
        command_id: str,
        principal: str,
        grant_id: str,
        source_ip: str,
        issued_at: int,
        expires_at: int,
        processed_at: int | None = None,
    ) -> None:
        processed_at = int(time.time()) if processed_at is None else processed_at
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO used_nonces (
                        command_id, principal, grant_id, source_ip, issued_at, expires_at, processed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (command_id, principal, grant_id, source_ip, issued_at, expires_at, processed_at),
                )
        except sqlite3.IntegrityError as exc:
            raise DuplicateCommand("duplicate_command") from exc

    def cleanup(self, *, retention_seconds: int, now: int | None = None) -> int:
        now = int(time.time()) if now is None else now
        cutoff = now - retention_seconds
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM used_nonces WHERE processed_at < ?", (cutoff,))
            return cursor.rowcount

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS used_nonces (
                    command_id TEXT PRIMARY KEY,
                    principal TEXT NOT NULL,
                    grant_id TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    processed_at INTEGER NOT NULL
                )
                """
            )
            if self.path != ":memory:":
                try:
                    os.chmod(self.path, 0o600)
                except OSError:
                    pass

    def _connect(self):
        return sqlite3.connect(self.path)
