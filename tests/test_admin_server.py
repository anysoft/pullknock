import tempfile
import unittest
from pathlib import Path

from pullknock.admin_server import (
    AdminState,
    authorize_request,
    build_state,
    _same_origin,
    history_diff,
    list_history,
    read_audit_log,
    restore_history,
    save_agent_yaml,
    validate_agent_yaml_text,
)
from pullknock.errors import ConfigError


def sample_agent_yaml(temp_dir: str) -> str:
    return f"""
server:
  id: "x162"
  control_url: "{temp_dir}/command.json"
security:
  nonce_db: "{temp_dir}/nonces.sqlite3"
groups:
  ops:
    allowed_grants: ["ssh"]
    allow_source_cidrs: ["0.0.0.0/0"]
grants:
  ssh:
    allowed_groups: ["ops"]
    ports:
      - protocol: "tcp"
        port: 22
    max_timeout_seconds: 60
    allow_source_cidrs: ["0.0.0.0/0"]
users:
  jonhy:
    groups: ["ops"]
    keys:
      - id: "jonhy-laptop"
        public_key: "ssh-ed25519 AAAAExample jonhy-key"
"""


class AdminServerTest(unittest.TestCase):
    def test_validate_agent_yaml_text_returns_summary(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = validate_agent_yaml_text(sample_agent_yaml(temp_dir))

        self.assertTrue(result["ok"])
        self.assertEqual(result["summary"]["server"]["id"], "x162")
        self.assertEqual(result["summary"]["counts"]["users"], 1)

    def test_build_state_marks_invalid_config(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "agent.yaml"
            path.write_text("server: []\n", encoding="utf-8")
            state = AdminState(config_path=path, allow_write=False, allow_reload=False, reload_command=())

            result = build_state(state)

        self.assertFalse(result["ok"])
        self.assertIn("server", result["validation"]["error"])

    def test_save_requires_allow_write(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "agent.yaml"
            raw = sample_agent_yaml(temp_dir)
            path.write_text(raw, encoding="utf-8")
            state = AdminState(config_path=path, allow_write=False, allow_reload=False, reload_command=())

            with self.assertRaisesRegex(ConfigError, "write_disabled"):
                save_agent_yaml(state, raw)

    def test_save_valid_yaml_when_write_enabled(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "agent.yaml"
            raw = sample_agent_yaml(temp_dir)
            path.write_text(raw, encoding="utf-8")
            edited = raw.replace('id: "x162"', 'id: "x163"')
            state = AdminState(
                config_path=path,
                allow_write=True,
                allow_reload=False,
                reload_command=(),
                history_dir=Path(temp_dir) / "history",
            )

            result = save_agent_yaml(state, edited)

            self.assertTrue(result["ok"])
            self.assertIn('id: "x163"', path.read_text(encoding="utf-8"))
            self.assertTrue(result["diff"])
            self.assertEqual(len(list_history(state)), 1)

    def test_auth_supports_bearer_basic_and_trusted_header(self):
        state = AdminState(
            config_path=Path("/tmp/agent.yaml"),
            allow_write=False,
            allow_reload=False,
            reload_command=(),
            auth_token="secret",
        )

        self.assertEqual(authorize_request(state, {"Authorization": "Bearer secret"}), (True, "bearer"))
        self.assertEqual(authorize_request(state, {"Authorization": "Bearer wrong"}), (False, None))

        basic = "Basic am9uaHk6cGFzcw=="
        state = AdminState(
            config_path=Path("/tmp/agent.yaml"),
            allow_write=False,
            allow_reload=False,
            reload_command=(),
            basic_auth=("jonhy", "pass"),
        )
        self.assertEqual(authorize_request(state, {"Authorization": basic}), (True, "jonhy"))

        state = AdminState(
            config_path=Path("/tmp/agent.yaml"),
            allow_write=False,
            allow_reload=False,
            reload_command=(),
            trusted_user_header="X-Remote-User",
        )
        self.assertEqual(authorize_request(state, {"X-Remote-User": "alice"}), (True, "alice"))

    def test_state_exposes_csrf_token_and_origin_must_match(self):
        state = AdminState(
            config_path=Path("/tmp/agent.yaml"),
            allow_write=True,
            allow_reload=False,
            reload_command=(),
        )

        self.assertTrue(state.csrf_token)
        self.assertTrue(_same_origin({"Host": "127.0.0.1:8765", "Origin": "http://127.0.0.1:8765"}))
        self.assertFalse(_same_origin({"Host": "127.0.0.1:8765", "Origin": "http://evil.example"}))

    def test_audit_log_view_reads_json_lines(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "audit.log"
            log_path.write_text(
                '{"event":"grant_opened","result":"success","principal":"jonhy"}\nnot-json\n',
                encoding="utf-8",
            )
            state = AdminState(
                config_path=Path(temp_dir) / "agent.yaml",
                allow_write=False,
                allow_reload=False,
                reload_command=(),
                audit_log_path=log_path,
            )

            result = read_audit_log(state)

        self.assertTrue(result["ok"])
        self.assertEqual(result["entries"][1]["event"], "grant_opened")
        self.assertEqual(result["entries"][0]["event"], "unparsed_log_line")

    def test_history_diff_and_restore(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "agent.yaml"
            raw = sample_agent_yaml(temp_dir)
            path.write_text(raw, encoding="utf-8")
            state = AdminState(
                config_path=path,
                allow_write=True,
                allow_reload=False,
                reload_command=(),
                history_dir=Path(temp_dir) / "history",
            )
            save_agent_yaml(state, raw.replace('id: "x162"', 'id: "x163"'))
            item = list_history(state)[0]

            diff = history_diff(state, item["name"])
            restored = restore_history(state, item["name"])
            restored_text = path.read_text(encoding="utf-8")

        self.assertTrue(diff["ok"])
        self.assertTrue(restored["ok"])
        self.assertIn('id: "x162"', restored_text)


if __name__ == "__main__":
    unittest.main()
