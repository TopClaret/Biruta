import unittest
from security_manager import SecurityManager

class TestSecurityManager(unittest.TestCase):
    def setUp(self):
        self.sm = SecurityManager()

    # Criptografia Fernet removida

    def test_validate_username(self):
        self.assertTrue(self.sm.validate_username("user_name-1"))
        self.assertFalse(self.sm.validate_username(None))
        self.assertFalse(self.sm.validate_username("invalid!"))

    def test_validate_password(self):
        self.assertTrue(self.sm.validate_password("abc"))
        self.assertFalse(self.sm.validate_password("ab"))

    def test_validate_remote_host(self):
        self.assertTrue(self.sm.validate_remote_host("host-1"))
        self.assertFalse(self.sm.validate_remote_host("bad host"))

    def test_sanitize_string(self):
        val = self.sm.sanitize_string("  HOST-1  ")
        self.assertEqual(val, "HOST-1")

    def test_csrf_token(self):
        t = self.sm.generate_csrf_token()
        self.assertEqual(len(t), 32)
        self.assertTrue(self.sm.validate_csrf(t, t))
        self.assertFalse(self.sm.validate_csrf(t, None))

    def test_rate_limit(self):
        store = {}
        key = "rl:test"
        ok = True
        for _ in range(5):
            ok = self.sm.rate_limit(key, limit=5, window_sec=60, store=store)
        self.assertTrue(ok)
        ok = self.sm.rate_limit(key, limit=5, window_sec=60, store=store)
        self.assertFalse(ok)

    def test_enforce_remote_policy(self):
        sm2 = SecurityManager()
        self.assertTrue(sm2.enforce_remote_policy("10.0.0.1"))
        self.assertTrue(sm2.enforce_remote_policy(None))

if __name__ == "__main__":
    unittest.main()
