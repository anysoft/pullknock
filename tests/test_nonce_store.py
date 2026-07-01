import unittest
import tempfile

from pullknock.errors import DuplicateCommand
from pullknock.nonce_store import NonceStore


class NonceStoreTest(unittest.TestCase):
    def test_nonce_store_rejects_duplicate(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = NonceStore(f"{temp_dir}/nonces.sqlite3")
            store.mark_used(
                command_id="4ca1165b-37d3-4534-af9e-b4c2f5232b19",
                principal="jonhy",
                grant_id="ssh",
                source_ip="203.0.113.7",
                issued_at=100,
                expires_at=160,
                processed_at=170,
            )

            with self.assertRaises(DuplicateCommand):
                store.assert_unused("4ca1165b-37d3-4534-af9e-b4c2f5232b19")


if __name__ == "__main__":
    unittest.main()
