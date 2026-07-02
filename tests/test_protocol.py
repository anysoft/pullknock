import base64
import json
import unittest

from pullknock.errors import ProtocolError
from pullknock.protocol import (
    MAX_ENVELOPE_BYTES,
    build_encrypted_envelope,
    build_envelope_v2,
    build_envelope,
    build_payload,
    canonical_json,
    parse_encrypted_envelope,
    parse_envelope_v2,
    parse_envelope,
    parse_payload,
)


class ProtocolTest(unittest.TestCase):
    def test_payload_must_be_canonical(self):
        payload = build_payload(
            principal="jonhy",
            target="x162",
            grant_id="ssh",
            source_ip="203.0.113.7",
            requested_timeout=60,
            issued_at=100,
            not_before=100,
            expires_at=160,
        )
        payload_bytes = canonical_json(payload)

        self.assertEqual(parse_payload(payload_bytes), payload)

        pretty = json.dumps(payload, indent=2).encode()
        with self.assertRaisesRegex(ProtocolError, "payload_not_canonical"):
            parse_payload(pretty)

    def test_envelope_decodes_payload_and_signature(self):
        payload_bytes = b'{"type":"test"}'
        signature_bytes = b"signature"
        envelope = build_envelope(payload_bytes, signature_bytes, kid="jonhy", created_at=100)

        decoded_payload, decoded_signature, parsed = parse_envelope(envelope)

        self.assertEqual(decoded_payload, payload_bytes)
        self.assertEqual(decoded_signature, signature_bytes)
        self.assertEqual(parsed["encoding"], "plain+sshsig")

    def test_envelope_rejects_invalid_base64(self):
        envelope = {
            "envelope_version": 1,
            "encoding": "plain+sshsig",
            "payload_b64": base64.b64encode(b"payload").decode(),
            "signature_b64": "not base64!",
            "kid": "jonhy",
            "created_at": 100,
        }

        with self.assertRaisesRegex(ProtocolError, "invalid_base64"):
            parse_envelope(envelope)

    def test_payload_rejects_unknown_command_field(self):
        payload = build_payload(
            principal="jonhy",
            target="x162",
            grant_id="ssh",
            source_ip="203.0.113.7",
            requested_timeout=60,
            issued_at=100,
            not_before=100,
            expires_at=160,
        )
        payload["cmd"] = "firewall-cmd --add-port=22/tcp"

        with self.assertRaisesRegex(ProtocolError, "payload_unknown_field"):
            parse_payload(canonical_json(payload))

    def test_payload_rejects_shell_like_principal(self):
        payload = {
            "version": 1,
            "type": "pullknock.open",
            "command_id": "4ca1165b-37d3-4534-af9e-b4c2f5232b19",
            "principal": "jonhy;rm",
            "target": "x162",
            "grant_id": "ssh",
            "source_ip": "203.0.113.7",
            "requested_timeout": 60,
            "issued_at": 100,
            "not_before": 100,
            "expires_at": 160,
        }

        with self.assertRaisesRegex(ProtocolError, "principal_invalid"):
            parse_payload(canonical_json(payload))

    def test_payload_rejects_long_reason(self):
        payload = build_payload(
            principal="jonhy",
            target="x162",
            grant_id="ssh",
            source_ip="203.0.113.7",
            requested_timeout=60,
            issued_at=100,
            not_before=100,
            expires_at=160,
        )
        payload["reason"] = "x" * 600

        with self.assertRaisesRegex(ProtocolError, "reason_too_long"):
            parse_payload(canonical_json(payload))

    def test_envelope_rejects_unknown_field(self):
        envelope = build_envelope(b"{}", b"sig", kid="jonhy", created_at=100)
        envelope["extra"] = "nope"

        with self.assertRaisesRegex(ProtocolError, "envelope_unknown_field"):
            parse_envelope(envelope)

    def test_envelope_rejects_oversized_input(self):
        with self.assertRaisesRegex(ProtocolError, "envelope_too_large"):
            parse_envelope(" " * (MAX_ENVELOPE_BYTES + 1))

    def test_encrypted_envelope_wraps_ciphertext(self):
        envelope = build_encrypted_envelope(b"age-ciphertext", kid="jonhy", created_at=100)

        ciphertext, parsed = parse_encrypted_envelope(envelope)

        self.assertEqual(ciphertext, b"age-ciphertext")
        self.assertEqual(parsed["encoding"], "age+plain+sshsig")
        with self.assertRaisesRegex(ProtocolError, "encrypted_envelope_requires_decryption"):
            parse_envelope(envelope)

    def test_envelope_v2_declares_age_algorithm_and_key_id(self):
        envelope = build_envelope_v2(
            b"age-ciphertext",
            kid="jonhy",
            encryption_key_id="x162-age-2026q3",
            created_at=100,
        )

        ciphertext, parsed = parse_envelope_v2(envelope)

        self.assertEqual(ciphertext, b"age-ciphertext")
        self.assertEqual(parsed["envelope_version"], 2)
        self.assertEqual(parsed["encoding"], "age")
        self.assertEqual(parsed["encryption_alg"], "age-v1")
        self.assertEqual(parsed["encryption_key_id"], "x162-age-2026q3")
        self.assertEqual(parsed["inner_encoding"], "plain+sshsig")
        with self.assertRaisesRegex(ProtocolError, "encrypted_envelope_requires_decryption"):
            parse_envelope(envelope)


if __name__ == "__main__":
    unittest.main()
