import base64
import json
import unittest

from pullknock.errors import ProtocolError
from pullknock.protocol import build_envelope, build_payload, canonical_json, parse_envelope, parse_payload


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


if __name__ == "__main__":
    unittest.main()
