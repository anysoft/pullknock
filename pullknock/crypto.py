"""Envelope encryption helpers."""

from __future__ import annotations

import subprocess

from .config import AgeConfig
from .errors import EncryptionError


def age_encrypt(plaintext: bytes, config: AgeConfig) -> bytes:
    args = [config.age_cmd]
    for recipient in config.recipients:
        args.extend(["-r", recipient])
    for recipient_file in config.recipient_files:
        args.extend(["-R", recipient_file])
    completed = subprocess.run(args, input=plaintext, check=False, capture_output=True)
    if completed.returncode != 0:
        raise EncryptionError(_format_age_error("age_encrypt_failed", completed))
    if not completed.stdout:
        raise EncryptionError("age_encrypt_failed: empty ciphertext")
    return completed.stdout


def age_decrypt(ciphertext: bytes, config: AgeConfig) -> bytes:
    args = [config.age_cmd, "-d"]
    for identity_file in config.identity_files:
        args.extend(["-i", identity_file])
    completed = subprocess.run(args, input=ciphertext, check=False, capture_output=True)
    if completed.returncode != 0:
        raise EncryptionError(_format_age_error("age_decrypt_failed", completed))
    if not completed.stdout:
        raise EncryptionError("age_decrypt_failed: empty plaintext")
    return completed.stdout


def _format_age_error(prefix: str, completed: subprocess.CompletedProcess) -> str:
    stderr = completed.stderr
    stdout = completed.stdout
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", errors="replace")
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", errors="replace")
    message = (stderr or stdout or "").strip()
    if message:
        return f"{prefix}: {message}"
    return f"{prefix}: command exited {completed.returncode}"
