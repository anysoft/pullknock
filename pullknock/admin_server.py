"""Small local Web admin UI for PullKnock agent configs."""

from __future__ import annotations

import difflib
import base64
import hmac
import json
import shlex
import secrets
import subprocess
import tempfile
from datetime import datetime, timezone
from dataclasses import asdict, is_dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import click
import yaml

from .config import AgentConfig, load_agent_config
from .errors import ConfigError, PullKnockError
from .util import expand_path


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--config", "config_path", default="/etc/pullknock/agent.yaml", show_default=True)
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8765, show_default=True, type=int)
@click.option("--allow-write", is_flag=True, help="Allow saving validated YAML back to --config.")
@click.option("--allow-reload", is_flag=True, help="Allow running the reload command from the UI.")
@click.option("--reload-command", default="systemctl reload pullknock-agent", show_default=True)
@click.option("--auth-token", default=None, help="Require Authorization: Bearer TOKEN for all requests.")
@click.option("--basic-auth", default=None, metavar="USER:PASS", help="Require HTTP Basic auth.")
@click.option("--trusted-user-header", default=None, help="Trust this reverse-proxy header as authenticated user.")
@click.option("--history-dir", default=None, help="Directory for saved config history snapshots.")
@click.option("--audit-log", default=None, help="Audit log path to show in the UI; defaults to audit.log_file.")
def main(
    config_path: str,
    host: str,
    port: int,
    allow_write: bool,
    allow_reload: bool,
    reload_command: str,
    auth_token: str | None,
    basic_auth: str | None,
    trusted_user_header: str | None,
    history_dir: str | None,
    audit_log: str | None,
) -> None:
    """Run the local PullKnock Web admin UI."""
    state = AdminState(
        config_path=Path(expand_path(config_path)),
        allow_write=allow_write,
        allow_reload=allow_reload,
        reload_command=tuple(shlex.split(reload_command)),
        auth_token=auth_token,
        basic_auth=parse_basic_auth(basic_auth),
        trusted_user_header=trusted_user_header,
        history_dir=Path(expand_path(history_dir)) if history_dir else None,
        audit_log_path=Path(expand_path(audit_log)) if audit_log else None,
    )
    server = ThreadingHTTPServer((host, port), make_handler(state))
    click.echo(f"PullKnock admin listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        click.echo("Stopping PullKnock admin.")
    finally:
        server.server_close()


class AdminState:
    def __init__(
        self,
        *,
        config_path: Path,
        allow_write: bool,
        allow_reload: bool,
        reload_command: tuple[str, ...],
        auth_token: str | None = None,
        basic_auth: tuple[str, str] | None = None,
        trusted_user_header: str | None = None,
        history_dir: Path | None = None,
        audit_log_path: Path | None = None,
    ):
        self.config_path = config_path
        self.allow_write = allow_write
        self.allow_reload = allow_reload
        self.reload_command = reload_command
        self.auth_token = auth_token
        self.basic_auth = basic_auth
        self.trusted_user_header = trusted_user_header
        self.history_dir = history_dir or (config_path.parent / ".pullknock-history")
        self.audit_log_path = audit_log_path
        self.csrf_token = secrets.token_urlsafe(32)


def make_handler(state: AdminState):
    class AdminHandler(BaseHTTPRequestHandler):
        server_version = "PullKnockAdmin/0.1"

        def do_GET(self) -> None:
            if not self._authorized():
                return
            if self.path == "/" or self.path.startswith("/?"):
                self._send_html(APP_HTML)
                return
            if self.path == "/api/state":
                self._send_json(build_state(state))
                return
            if self.path.startswith("/api/audit"):
                self._send_json(read_audit_log(state, limit=_query_limit(self.path, default=200)))
                return
            if self.path == "/api/history":
                self._send_json({"ok": True, "items": list_history(state)})
                return
            self.send_error(HTTPStatus.NOT_FOUND)

        def do_POST(self) -> None:
            if not self._authorized():
                return
            if not self._valid_mutation_request():
                return
            try:
                if self.path == "/api/validate":
                    payload = self._read_json()
                    raw = _require_raw(payload)
                    self._send_json(validate_agent_yaml_text(raw))
                    return
                if self.path == "/api/save":
                    payload = self._read_json()
                    raw = _require_raw(payload)
                    self._send_json(save_agent_yaml(state, raw))
                    return
                if self.path == "/api/check-config":
                    self._send_json(run_check_config(state))
                    return
                if self.path == "/api/reload":
                    self._send_json(run_reload(state))
                    return
                if self.path == "/api/history/diff":
                    payload = self._read_json()
                    self._send_json(history_diff(state, _require_history_name(payload)))
                    return
                if self.path == "/api/history/restore":
                    payload = self._read_json()
                    self._send_json(restore_history(state, _require_history_name(payload)))
                    return
            except PullKnockError as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return
            self.send_error(HTTPStatus.NOT_FOUND)

        def log_message(self, format: str, *args) -> None:
            return

        def _authorized(self) -> bool:
            ok, user = authorize_request(state, self.headers)
            if ok:
                self.authenticated_user = user
                return True
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("WWW-Authenticate", 'Basic realm="PullKnock Admin"')
            self.end_headers()
            self.wfile.write(b'{"ok":false,"error":"unauthorized"}')
            return False

        def _valid_mutation_request(self) -> bool:
            if not hmac.compare_digest(self.headers.get("X-PullKnock-CSRF", ""), state.csrf_token):
                self._send_json({"ok": False, "error": "csrf_token_invalid"}, status=HTTPStatus.FORBIDDEN)
                return False
            if not _same_origin(self.headers):
                self._send_json({"ok": False, "error": "origin_mismatch"}, status=HTTPStatus.FORBIDDEN)
                return False
            return True

        def _read_json(self) -> dict[str, Any]:
            content_type = self.headers.get("Content-Type", "")
            if content_type.split(";", 1)[0].strip().lower() != "application/json":
                raise ConfigError("content_type_must_be_application_json")
            length = int(self.headers.get("Content-Length", "0"))
            if length > 2 * 1024 * 1024:
                raise ConfigError("request_body_too_large")
            raw = self.rfile.read(length)
            try:
                data = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError as exc:
                raise ConfigError(f"invalid_json: {exc}") from exc
            if not isinstance(data, dict):
                raise ConfigError("request body must be a JSON object")
            return data

        def _send_html(self, html: str) -> None:
            body = html.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, payload: dict[str, Any], *, status: HTTPStatus = HTTPStatus.OK) -> None:
            body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    return AdminHandler


def build_state(state: AdminState) -> dict[str, Any]:
    raw = read_text(state.config_path)
    validation = validate_agent_yaml_text(raw)
    current = read_current_config(state.config_path)
    return {
        "ok": validation["ok"],
        "config_path": str(state.config_path),
        "allow_write": state.allow_write,
        "allow_reload": state.allow_reload,
        "auth": auth_summary(state),
        "history_dir": str(state.history_dir),
        "audit_log_path": str(resolve_audit_log_path(state) or ""),
        "csrf_token": state.csrf_token,
        "raw": raw,
        "validation": validation,
        "summary": summarize_config(current) if current is not None else {},
    }


def validate_agent_yaml_text(raw: str) -> dict[str, Any]:
    try:
        parsed = yaml.safe_load(raw) or {}
        if not isinstance(parsed, dict):
            raise ConfigError("agent YAML root must be a mapping")
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".yaml") as temp_file:
            temp_file.write(raw)
            temp_file.flush()
            config = load_agent_config(temp_file.name)
        return {"ok": True, "error": "", "summary": summarize_config(config)}
    except (ConfigError, yaml.YAMLError) as exc:
        return {"ok": False, "error": str(exc), "summary": {}}


def save_agent_yaml(state: AdminState, raw: str) -> dict[str, Any]:
    if not state.allow_write:
        raise ConfigError("write_disabled: restart with --allow-write to enable saving")
    validation = validate_agent_yaml_text(raw)
    if not validation["ok"]:
        return validation
    before = read_text(state.config_path)
    diff = list(
        difflib.unified_diff(
            before.splitlines(),
            raw.splitlines(),
            fromfile=str(state.config_path),
            tofile=f"{state.config_path} (edited)",
            lineterm="",
        )
    )
    snapshot = write_history_snapshot(state, before)
    write_text_atomic(state.config_path, raw)
    return {"ok": True, "error": "", "diff": diff, "history": str(snapshot), "summary": validation["summary"]}


def run_check_config(state: AdminState) -> dict[str, Any]:
    args = ["python3", "-m", "pullknock.agent", "--config", str(state.config_path), "--check-config"]
    completed = subprocess.run(args, check=False, capture_output=True, text=True)
    return {
        "ok": completed.returncode == 0,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def run_reload(state: AdminState) -> dict[str, Any]:
    if not state.allow_reload:
        raise ConfigError("reload_disabled: restart with --allow-reload to enable reload")
    if not state.reload_command:
        raise ConfigError("reload_command_empty")
    completed = subprocess.run(list(state.reload_command), check=False, capture_output=True, text=True)
    return {
        "ok": completed.returncode == 0,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "command": list(state.reload_command),
    }


def parse_basic_auth(value: str | None) -> tuple[str, str] | None:
    if value is None:
        return None
    if ":" not in value:
        raise click.BadParameter("--basic-auth must use USER:PASS")
    username, password = value.split(":", 1)
    if not username or not password:
        raise click.BadParameter("--basic-auth user and password must be non-empty")
    return username, password


def authorize_request(state: AdminState, headers) -> tuple[bool, str | None]:
    if state.trusted_user_header:
        user = headers.get(state.trusted_user_header)
        if user:
            return True, user
    if state.auth_token:
        expected = f"Bearer {state.auth_token}"
        candidate = headers.get("Authorization", "")
        if hmac.compare_digest(candidate, expected):
            return True, "bearer"
        return False, None
    if state.basic_auth:
        candidate = headers.get("Authorization", "")
        prefix = "Basic "
        if not candidate.startswith(prefix):
            return False, None
        try:
            decoded = base64.b64decode(candidate[len(prefix) :].encode("ascii"), validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return False, None
        username, password = decoded.split(":", 1) if ":" in decoded else ("", "")
        expected_user, expected_password = state.basic_auth
        if hmac.compare_digest(username, expected_user) and hmac.compare_digest(password, expected_password):
            return True, username
        return False, None
    return True, None


def auth_summary(state: AdminState) -> dict[str, Any]:
    mode = "none"
    if state.trusted_user_header:
        mode = "trusted_header"
    elif state.auth_token:
        mode = "bearer"
    elif state.basic_auth:
        mode = "basic"
    return {"mode": mode, "trusted_user_header": state.trusted_user_header or ""}


def _same_origin(headers) -> bool:
    host = headers.get("Host", "")
    if not host:
        return False
    origin = headers.get("Origin")
    if origin:
        return urlsplit(origin).netloc == host
    referer = headers.get("Referer")
    if referer:
        return urlsplit(referer).netloc == host
    return False


def resolve_audit_log_path(state: AdminState) -> Path | None:
    if state.audit_log_path is not None:
        return state.audit_log_path
    config = read_current_config(state.config_path)
    if config and config.audit.log_file:
        return Path(config.audit.log_file)
    return None


def read_audit_log(state: AdminState, *, limit: int = 200) -> dict[str, Any]:
    path = resolve_audit_log_path(state)
    if path is None:
        return {"ok": True, "path": "", "entries": [], "error": ""}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return {"ok": True, "path": str(path), "entries": [], "error": "audit log does not exist yet"}
    except OSError as exc:
        return {"ok": False, "path": str(path), "entries": [], "error": str(exc)}
    entries: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            item = {"event": "unparsed_log_line", "message": line}
        if isinstance(item, dict):
            entries.append(item)
    entries.reverse()
    return {"ok": True, "path": str(path), "entries": entries, "error": ""}


def write_history_snapshot(state: AdminState, raw: str) -> Path:
    state.history_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_name = state.config_path.name.replace("/", "_")
    path = state.history_dir / f"{stamp}-{safe_name}"
    counter = 1
    while path.exists():
        path = state.history_dir / f"{stamp}-{counter}-{safe_name}"
        counter += 1
    path.write_text(raw, encoding="utf-8")
    return path


def list_history(state: AdminState) -> list[dict[str, Any]]:
    if not state.history_dir.exists():
        return []
    items = []
    for path in sorted(state.history_dir.glob(f"*-{state.config_path.name}"), reverse=True):
        try:
            stat = path.stat()
        except OSError:
            continue
        items.append({"name": path.name, "path": str(path), "size": stat.st_size, "mtime": int(stat.st_mtime)})
    return items


def history_diff(state: AdminState, name: str) -> dict[str, Any]:
    history_path = resolve_history_path(state, name)
    old = read_text(history_path)
    current = read_text(state.config_path)
    diff = list(
        difflib.unified_diff(
            old.splitlines(),
            current.splitlines(),
            fromfile=name,
            tofile=str(state.config_path),
            lineterm="",
        )
    )
    return {"ok": True, "name": name, "diff": diff, "raw": old}


def restore_history(state: AdminState, name: str) -> dict[str, Any]:
    if not state.allow_write:
        raise ConfigError("write_disabled: restart with --allow-write to enable restore")
    history_path = resolve_history_path(state, name)
    raw = read_text(history_path)
    validation = validate_agent_yaml_text(raw)
    if not validation["ok"]:
        return validation
    before = read_text(state.config_path)
    snapshot = write_history_snapshot(state, before)
    write_text_atomic(state.config_path, raw)
    return {"ok": True, "error": "", "restored": name, "history": str(snapshot), "summary": validation["summary"]}


def resolve_history_path(state: AdminState, name: str) -> Path:
    if "/" in name or "\\" in name or name.startswith("."):
        raise ConfigError("invalid_history_name")
    path = state.history_dir / name
    try:
        path.resolve().relative_to(state.history_dir.resolve())
    except ValueError as exc:
        raise ConfigError("invalid_history_name") from exc
    if not path.exists():
        raise ConfigError(f"unknown_history_snapshot: {name}")
    return path


def read_current_config(path: Path) -> AgentConfig | None:
    try:
        return load_agent_config(str(path))
    except PullKnockError:
        return None


def summarize_config(config: AgentConfig) -> dict[str, Any]:
    return {
        "server": {
            "id": config.server.id,
            "control_urls": list(config.server.control_urls),
            "poll_interval_seconds": config.server.poll_interval_seconds,
        },
        "security": {
            "signature_namespace": config.security.signature_namespace,
            "nonce_db": config.security.nonce_db,
            "age_enabled": config.security.age is not None,
        },
        "firewall": _dataclass_dict(config.firewall),
        "audit": _dataclass_dict(config.audit),
        "users": [_dataclass_dict(user) for user in config.users.values()],
        "groups": [_dataclass_dict(group) for group in (config.groups or {}).values()],
        "grants": [_grant_summary(grant) for grant in config.grants.values()],
        "counts": {
            "users": len(config.users),
            "groups": len(config.groups or {}),
            "grants": len(config.grants),
            "control_urls": len(config.server.control_urls),
        },
    }


def _grant_summary(grant) -> dict[str, Any]:
    data = _dataclass_dict(grant)
    data["ports"] = [f"{port['protocol']}/{port['port']}" for port in data.get("ports", [])]
    return data


def _dataclass_dict(value: Any) -> dict[str, Any]:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, dict):
        return value
    raise TypeError(f"not a dataclass or dict: {type(value)!r}")


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot_read_config: {path}: {exc}") from exc


def write_text_atomic(path: Path, raw: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.tmp")
    try:
        temp_path.write_text(raw, encoding="utf-8")
        temp_path.replace(path)
    except OSError as exc:
        raise ConfigError(f"cannot_write_config: {path}: {exc}") from exc


def _require_raw(payload: dict[str, Any]) -> str:
    raw = payload.get("raw")
    if not isinstance(raw, str):
        raise ConfigError("raw must be a string")
    return raw


def _require_history_name(payload: dict[str, Any]) -> str:
    name = payload.get("name")
    if not isinstance(name, str) or not name:
        raise ConfigError("name must be a non-empty string")
    return name


def _query_limit(path: str, *, default: int) -> int:
    if "?" not in path:
        return default
    query = path.split("?", 1)[1]
    for part in query.split("&"):
        key, _, value = part.partition("=")
        if key == "limit":
            try:
                return max(1, min(1000, int(value)))
            except ValueError:
                return default
    return default


APP_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PullKnock Admin</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --line: #dce1e8;
      --text: #17202a;
      --muted: #687386;
      --accent: #126b5d;
      --accent-2: #3d6a9f;
      --danger: #b42318;
      --warn: #b76e00;
      --ok: #16803f;
      --shadow: 0 18px 45px rgba(17, 24, 39, .08);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background:
        linear-gradient(135deg, rgba(18,107,93,.08), transparent 34%),
        linear-gradient(225deg, rgba(61,106,159,.09), transparent 30%),
        var(--bg);
      color: var(--text);
    }
    button, textarea, input { font: inherit; }
    .shell { min-height: 100vh; display: grid; grid-template-columns: 248px 1fr; }
    aside {
      padding: 24px 18px;
      border-right: 1px solid var(--line);
      background: rgba(255,255,255,.72);
      backdrop-filter: blur(18px);
      position: sticky;
      top: 0;
      height: 100vh;
    }
    .brand { display: flex; align-items: center; gap: 12px; margin-bottom: 28px; }
    .mark {
      width: 42px; height: 42px; border-radius: 10px;
      display: grid; place-items: center;
      background: linear-gradient(135deg, var(--accent), var(--accent-2));
      color: white; font-weight: 800;
      box-shadow: var(--shadow);
    }
    .brand h1 { font-size: 17px; margin: 0; letter-spacing: 0; }
    .brand small { color: var(--muted); display: block; margin-top: 2px; }
    nav { display: grid; gap: 6px; }
    nav button {
      border: 0; background: transparent; color: var(--muted);
      text-align: left; padding: 10px 12px; border-radius: 8px;
      display: flex; gap: 10px; align-items: center; cursor: pointer;
    }
    nav button.active { background: #e9f2ef; color: var(--accent); font-weight: 700; }
    main { padding: 26px; max-width: 1420px; width: 100%; }
    header { display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; margin-bottom: 22px; }
    header h2 { margin: 0; font-size: 28px; letter-spacing: 0; }
    header p { margin: 6px 0 0; color: var(--muted); }
    .status { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; justify-content: flex-end; }
    .pill {
      border: 1px solid var(--line); border-radius: 999px; padding: 7px 10px;
      background: rgba(255,255,255,.76); color: var(--muted); font-size: 13px;
    }
    .pill.ok { color: var(--ok); border-color: rgba(22,128,63,.25); background: #edf8f1; }
    .pill.warn { color: var(--warn); border-color: rgba(183,110,0,.25); background: #fff7e6; }
    .pill.bad { color: var(--danger); border-color: rgba(180,35,24,.25); background: #fff1f0; }
    .grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; margin-bottom: 18px; }
    .card, .panel {
      background: rgba(255,255,255,.88);
      border: 1px solid rgba(220,225,232,.9);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }
    .card { padding: 16px; min-height: 104px; }
    .card .label { color: var(--muted); font-size: 13px; }
    .card .value { font-size: 30px; font-weight: 800; margin-top: 8px; }
    .card .hint { color: var(--muted); margin-top: 8px; font-size: 13px; overflow-wrap: anywhere; }
    .panel { padding: 18px; margin-bottom: 16px; }
    .panel h3 { margin: 0 0 14px; font-size: 17px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 11px 10px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
    th { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
    td { font-size: 14px; }
    code {
      background: #eef1f5; border-radius: 6px; padding: 2px 5px;
      color: #263241; overflow-wrap: anywhere;
    }
    .toolbar { display: flex; gap: 10px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }
    .btn {
      border: 1px solid var(--line); background: white; color: var(--text);
      border-radius: 8px; padding: 9px 12px; cursor: pointer;
      display: inline-flex; align-items: center; gap: 8px;
    }
    .btn.primary { background: var(--accent); border-color: var(--accent); color: white; }
    .btn.danger { background: #fff1f0; border-color: rgba(180,35,24,.25); color: var(--danger); }
    .btn:disabled { opacity: .45; cursor: not-allowed; }
    .editor {
      width: 100%; min-height: 520px; resize: vertical;
      border: 1px solid var(--line); border-radius: 8px; padding: 14px;
      background: #101820; color: #e7edf3;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 13px; line-height: 1.55;
    }
    .output {
      white-space: pre-wrap; background: #f0f3f7; border: 1px solid var(--line);
      border-radius: 8px; padding: 12px; min-height: 56px; overflow: auto;
    }
    .split { display: grid; grid-template-columns: minmax(0, 1.4fr) minmax(320px, .6fr); gap: 16px; }
    .section { display: none; }
    .section.active { display: block; }
    .empty { color: var(--muted); padding: 18px; text-align: center; border: 1px dashed var(--line); border-radius: 8px; }
    .search { max-width: 320px; width: 100%; border: 1px solid var(--line); border-radius: 8px; padding: 9px 12px; }
    @media (max-width: 980px) {
      .shell { grid-template-columns: 1fr; }
      aside { height: auto; position: static; }
      nav { grid-template-columns: repeat(3, 1fr); }
      .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .split { grid-template-columns: 1fr; }
    }
    @media (max-width: 620px) {
      main { padding: 18px; }
      header { display: block; }
      .grid, nav { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <aside>
      <div class="brand"><div class="mark">PK</div><div><h1>PullKnock</h1><small>Admin Console</small></div></div>
      <nav id="nav">
        <button class="active" data-view="overview">◇ 总览</button>
        <button data-view="users">◎ 用户与组</button>
        <button data-view="grants">□ Grants</button>
        <button data-view="security">△ 安全与通道</button>
        <button data-view="audit">◷ 审计日志</button>
        <button data-view="history">▤ 配置历史</button>
        <button data-view="editor">✎ YAML 编辑</button>
        <button data-view="ops">⚙ 运维操作</button>
      </nav>
    </aside>
    <main>
      <header>
        <div><h2 id="title">总览</h2><p id="subtitle">读取本机 agent 配置，校验后再保存或重载。</p></div>
        <div class="status" id="status"></div>
      </header>

      <section class="section active" id="overview">
        <div class="grid" id="cards"></div>
        <div class="panel"><h3>控制通道</h3><div id="controlUrls"></div></div>
      </section>

      <section class="section" id="users">
        <div class="toolbar"><input class="search" id="userSearch" placeholder="筛选用户或组"></div>
        <div class="panel"><h3>用户</h3><div id="usersTable"></div></div>
        <div class="panel"><h3>用户组</h3><div id="groupsTable"></div></div>
      </section>

      <section class="section" id="grants">
        <div class="toolbar"><input class="search" id="grantSearch" placeholder="筛选 grant"></div>
        <div class="panel"><h3>Grant 策略</h3><div id="grantsTable"></div></div>
      </section>

      <section class="section" id="security">
        <div class="grid" id="securityCards"></div>
        <div class="panel"><h3>防火墙</h3><div id="firewallTable"></div></div>
      </section>

      <section class="section" id="audit">
        <div class="toolbar">
          <button class="btn" id="auditRefreshBtn">↻ 刷新</button>
          <input class="search" id="auditSearch" placeholder="筛选 event / principal / result">
        </div>
        <div class="panel"><h3>最近审计事件</h3><div id="auditTable"></div></div>
      </section>

      <section class="section" id="history">
        <div class="toolbar">
          <button class="btn" id="historyRefreshBtn">↻ 刷新</button>
          <button class="btn" id="historyDiffBtn">⇄ 查看 diff</button>
          <button class="btn danger" id="historyRestoreBtn">↥ 恢复选中</button>
        </div>
        <div class="split">
          <div class="panel"><h3>历史快照</h3><div id="historyTable"></div></div>
          <div class="panel"><h3>快照内容 / Diff</h3><div class="output" id="historyOutput"></div></div>
        </div>
      </section>

      <section class="section" id="editor">
        <div class="split">
          <div class="panel">
            <div class="toolbar">
              <button class="btn primary" id="validateBtn">✓ 校验</button>
              <button class="btn" id="saveBtn">↧ 保存</button>
              <button class="btn" id="resetBtn">↺ 还原</button>
            </div>
            <textarea class="editor" id="yamlEditor" spellcheck="false"></textarea>
          </div>
          <div class="panel"><h3>校验结果</h3><div class="output" id="validateOutput"></div></div>
        </div>
      </section>

      <section class="section" id="ops">
        <div class="panel">
          <h3>操作</h3>
          <div class="toolbar">
            <button class="btn" id="refreshBtn">↻ 刷新</button>
            <button class="btn" id="checkBtn">✓ check-config</button>
            <button class="btn danger" id="reloadBtn">↯ reload agent</button>
          </div>
          <div class="output" id="opsOutput"></div>
        </div>
      </section>
    </main>
  </div>
  <script>
    const $ = (id) => document.getElementById(id);
    let state = null;
    let originalRaw = "";

    const labels = {
      overview: ["总览", "读取本机 agent 配置，校验后再保存或重载。"],
      users: ["用户与组", "查看 principal、公钥、组策略和用户级限制。"],
      grants: ["Grant 策略", "端口、来源 CIDR、继承和授权主体集中在这里。"],
      security: ["安全与通道", "签名 namespace、age、nonce、防火墙和审计路径。"],
      audit: ["审计日志", "查看 agent JSON Lines 审计事件。"],
      history: ["配置历史", "每次保存前自动创建快照，可查看 diff 或恢复。"],
      editor: ["YAML 编辑", "保存前会跑完整 agent 配置校验。"],
      ops: ["运维操作", "执行 check-config 或受控 reload。"]
    };
    let auditEntries = [];
    let historyItems = [];
    let selectedHistory = "";

    document.querySelectorAll("nav button").forEach(btn => btn.addEventListener("click", () => show(btn.dataset.view)));
    $("refreshBtn").onclick = loadState;
    $("validateBtn").onclick = validateEditor;
    $("saveBtn").onclick = saveEditor;
    $("resetBtn").onclick = () => { $("yamlEditor").value = originalRaw; validateEditor(); };
    $("checkBtn").onclick = () => post("/api/check-config", {}).then(showOps);
    $("reloadBtn").onclick = () => post("/api/reload", {}).then(showOps);
    $("auditRefreshBtn").onclick = loadAudit;
    $("historyRefreshBtn").onclick = loadHistory;
    $("historyDiffBtn").onclick = showHistoryDiff;
    $("historyRestoreBtn").onclick = restoreHistory;
    $("userSearch").oninput = render;
    $("grantSearch").oninput = render;
    $("auditSearch").oninput = renderAudit;

    function show(view) {
      document.querySelectorAll("nav button").forEach(b => b.classList.toggle("active", b.dataset.view === view));
      document.querySelectorAll(".section").forEach(s => s.classList.toggle("active", s.id === view));
      $("title").textContent = labels[view][0];
      $("subtitle").textContent = labels[view][1];
    }

    async function loadState() {
      state = await fetch("/api/state").then(r => r.json());
      originalRaw = state.raw || "";
      $("yamlEditor").value = originalRaw;
      render();
    }

    function render() {
      if (!state) return;
      const s = state.summary || {};
      const valid = state.validation && state.validation.ok;
      $("status").innerHTML = [
        pill(valid ? "配置有效" : "配置错误", valid ? "ok" : "bad"),
        pill(state.allow_write ? "可保存" : "只读", state.allow_write ? "warn" : ""),
        pill(state.allow_reload ? "可 reload" : "reload 关闭", state.allow_reload ? "warn" : ""),
        pill(`auth: ${state.auth?.mode || "none"}`, state.auth?.mode === "none" ? "warn" : "ok")
      ].join("");
      $("saveBtn").disabled = !state.allow_write;
      $("reloadBtn").disabled = !state.allow_reload;
      $("cards").innerHTML = cards([
        ["服务器", s.server?.id || "-"],
        ["用户", s.counts?.users ?? 0],
        ["用户组", s.counts?.groups ?? 0],
        ["Grants", s.counts?.grants ?? 0]
      ]);
      $("controlUrls").innerHTML = list((s.server?.control_urls || []).map(x => `<code>${escapeHtml(x)}</code>`));
      $("usersTable").innerHTML = table(filter(s.users || [], $("userSearch").value, ["principal", "display_name"]), ["principal", "display_name", "groups", "allowed_grants", "max_timeout_seconds", "expires_at"]);
      $("groupsTable").innerHTML = table(filter(s.groups || [], $("userSearch").value, ["name", "display_name"]), ["name", "display_name", "allowed_grants", "max_timeout_seconds", "expires_at"]);
      $("grantsTable").innerHTML = table(filter(s.grants || [], $("grantSearch").value, ["id", "description"]), ["id", "description", "inherits", "allowed_principals", "allowed_groups", "ports", "max_timeout_seconds", "zone", "allow_source_cidrs"]);
      $("securityCards").innerHTML = cards([
        ["Namespace", s.security?.signature_namespace || "-"],
        ["Age", s.security?.age_enabled ? "enabled" : "disabled"],
        ["Nonce DB", s.security?.nonce_db || "-"],
        ["审计日志", s.audit?.log_file || "journald/stderr"]
      ]);
      $("firewallTable").innerHTML = table([s.firewall || {}], ["backend", "firewall_cmd", "default_zone", "nft_cmd", "nft_table", "nft_set_prefix"]);
      $("validateOutput").textContent = valid ? "OK" : (state.validation?.error || "");
      $("opsOutput").textContent ||= `config: ${state.config_path}`;
      renderAudit();
      renderHistory();
    }

    async function validateEditor() {
      const res = await post("/api/validate", { raw: $("yamlEditor").value });
      $("validateOutput").textContent = res.ok ? "OK" : res.error;
    }

    async function saveEditor() {
      const res = await post("/api/save", { raw: $("yamlEditor").value });
      $("validateOutput").textContent = res.ok ? `Saved\n${(res.diff || []).join("\n")}` : res.error;
      if (res.ok) await loadState();
      await loadHistory();
    }

    function showOps(res) {
      $("opsOutput").textContent = JSON.stringify(res, null, 2);
      if (res.ok) loadState();
    }

    async function loadAudit() {
      const res = await fetch("/api/audit?limit=300").then(r => r.json());
      auditEntries = res.entries || [];
      if (!res.ok || res.error) {
        $("auditTable").innerHTML = `<div class="empty">${escapeHtml(res.error || "无审计日志")}</div>`;
        return;
      }
      renderAudit();
    }

    function renderAudit() {
      const q = $("auditSearch") ? $("auditSearch").value.toLowerCase() : "";
      const rows = auditEntries.filter(row => !q || JSON.stringify(row).toLowerCase().includes(q));
      $("auditTable").innerHTML = table(rows, ["timestamp", "event", "result", "principal", "grant_id", "source_ip", "reason", "error_message"]);
    }

    async function loadHistory() {
      const res = await fetch("/api/history").then(r => r.json());
      historyItems = res.items || [];
      selectedHistory = historyItems[0]?.name || "";
      renderHistory();
    }

    function renderHistory() {
      if (!historyItems.length) {
        $("historyTable").innerHTML = `<div class="empty">暂无历史快照</div>`;
        $("historyOutput").textContent = "";
        return;
      }
      $("historyTable").innerHTML = `<table><thead><tr><th></th><th>name</th><th>size</th><th>mtime</th></tr></thead><tbody>${historyItems.map(item => `<tr><td><input type="radio" name="history" ${item.name === selectedHistory ? "checked" : ""} onclick="selectedHistory='${escapeHtml(item.name)}'"></td><td><code>${escapeHtml(item.name)}</code></td><td>${item.size}</td><td>${new Date(item.mtime * 1000).toLocaleString()}</td></tr>`).join("")}</tbody></table>`;
    }

    async function showHistoryDiff() {
      if (!selectedHistory) return;
      const res = await post("/api/history/diff", { name: selectedHistory });
      $("historyOutput").textContent = res.ok ? (res.diff || []).join("\n") || "无差异" : res.error;
    }

    async function restoreHistory() {
      if (!selectedHistory) return;
      const res = await post("/api/history/restore", { name: selectedHistory });
      $("historyOutput").textContent = JSON.stringify(res, null, 2);
      if (res.ok) {
        await loadState();
        await loadHistory();
      }
    }

    async function post(url, body) {
      const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json", "X-PullKnock-CSRF": state?.csrf_token || "" }, body: JSON.stringify(body) });
      return r.json();
    }

    function cards(items) {
      return items.map(([label, value]) => `<div class="card"><div class="label">${escapeHtml(label)}</div><div class="value">${escapeHtml(String(value))}</div><div class="hint">${escapeHtml(String(value)).slice(0, 96)}</div></div>`).join("");
    }
    function table(rows, cols) {
      if (!rows.length) return `<div class="empty">无数据</div>`;
      return `<table><thead><tr>${cols.map(c => `<th>${escapeHtml(c)}</th>`).join("")}</tr></thead><tbody>${rows.map(row => `<tr>${cols.map(c => `<td>${format(row[c])}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
    }
    function list(items) { return items.length ? `<table><tbody>${items.map(x => `<tr><td>${x}</td></tr>`).join("")}</tbody></table>` : `<div class="empty">无数据</div>`; }
    function filter(rows, q, keys) {
      q = (q || "").toLowerCase();
      if (!q) return rows;
      return rows.filter(row => keys.some(k => String(row[k] || "").toLowerCase().includes(q)));
    }
    function format(v) {
      if (Array.isArray(v)) return v.length ? v.map(x => `<code>${escapeHtml(String(x))}</code>`).join(" ") : "";
      if (v === null || v === undefined) return "";
      if (typeof v === "object") return `<code>${escapeHtml(JSON.stringify(v))}</code>`;
      return `<code>${escapeHtml(String(v))}</code>`;
    }
    function pill(text, kind) { return `<span class="pill ${kind || ""}">${escapeHtml(text)}</span>`; }
    function escapeHtml(v) { return String(v).replace(/[&<>"']/g, m => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m])); }
    loadState().then(() => { loadAudit(); loadHistory(); });
  </script>
</body>
</html>
"""


if __name__ == "__main__":
    main()
