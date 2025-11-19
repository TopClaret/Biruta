import unittest
import base64
from security_manager import SecurityManager

class TestCryptoManager(unittest.TestCase):
    def setUp(self):
        self.sm = SecurityManager()

    def test_hash_and_verify_password(self):
        rec = self.sm.hash_password("P@ssw0rd!123")
        self.assertTrue(self.sm.verify_password("P@ssw0rd!123", rec))
        self.assertFalse(self.sm.verify_password("wrong", rec))

    def test_dpapi_encrypt_decrypt(self):
        try:
            secret = b"segredo"
            blob = self.sm.encrypt_secret(secret)
            plain = self.sm.decrypt_secret(blob)
            self.assertEqual(plain, secret)
        except RuntimeError:
            self.skipTest("DPAPI indisponível")

if __name__ == '__main__':
    unittest.main()
