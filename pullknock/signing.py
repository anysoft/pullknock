"""OpenSSH SSHSIG signing and verification helpers."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from .errors import SignatureVerificationError, SigningError
from .util import expand_path


def sshsig_sign(
    payload_bytes: bytes,
    *,
    private_key: str,
    namespace: str = "pullknock-v1",
    ssh_keygen: str = "ssh-keygen",
) -> bytes:
    private_key = expand_path(private_key)
    with tempfile.TemporaryDirectory(prefix="pullknock-sign-") as temp_dir:
        payload_path = Path(temp_dir) / "payload.json"
        payload_path.write_bytes(payload_bytes)
        args = [ssh_keygen, "-Y", "sign", "-f", private_key, "-n", namespace, str(payload_path)]
        completed = subprocess.run(args, check=False, capture_output=True, text=True)
        if completed.returncode != 0:
            raise SigningError(_format_process_error("sshsig_sign_failed", completed))
        signature_path = Path(f"{payload_path}.sig")
        try:
            return signature_path.read_bytes()
        except OSError as exc:
            raise SigningError(f"sshsig_signature_missing: {signature_path}") from exc


def sshsig_verify(
    payload_bytes: bytes,
    signature_bytes: bytes,
    *,
    principal: str,
    signer_file_content: str | bytes,
    namespace: str = "pullknock-v1",
    ssh_keygen: str = "ssh-keygen",
) -> None:
    with tempfile.TemporaryDirectory(prefix="pullknock-verify-") as temp_dir:
        signer_file_path = Path(temp_dir) / "signers"
        if isinstance(signer_file_content, str):
            signer_file_content = signer_file_content.encode("utf-8")
        signer_file_path.write_bytes(signer_file_content)
        signature_path = Path(temp_dir) / "signature.sig"
        signature_path.write_bytes(signature_bytes)
        args = [
            ssh_keygen,
            "-Y",
            "verify",
            "-f",
            str(signer_file_path),
            "-I",
            principal,
            "-n",
            namespace,
            "-s",
            str(signature_path),
        ]
        completed = subprocess.run(args, input=payload_bytes, check=False, capture_output=True)
        if completed.returncode != 0:
            raise SignatureVerificationError(_format_process_error("signature_verify_failed", completed))


def _format_process_error(prefix: str, completed: subprocess.CompletedProcess) -> str:
    stderr = completed.stderr
    stdout = completed.stdout
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", errors="replace")
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", errors="replace")
    message = (stderr or stdout or "").strip()
    command = " ".join(os.path.basename(str(part)) if index == 0 else str(part) for index, part in enumerate(completed.args))
    if message:
        return f"{prefix}: {message}"
    return f"{prefix}: command exited {completed.returncode}: {command}"
