import time
import secrets
import os
import base64
import hashlib
import re
from typing import Optional, Dict
try:
    import win32crypt
except Exception:
    win32crypt = None

class SecurityManager:
    def generate_csrf_token(self) -> str:
        return secrets.token_hex(16)

    def generate_auth_token(self) -> str:
        return secrets.token_hex(16)

    def validate_csrf(self, cookie_token: Optional[str], header_token: Optional[str]) -> bool:
        return bool(cookie_token) and bool(header_token) and cookie_token == header_token

    def validate_username(self, user: Optional[str]) -> bool:
        if not user or len(user) > 128:
            return False
        allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_\\"
        return all(c in allowed for c in user)

    def validate_password(self, pwd: Optional[str]) -> bool:
        if not pwd or len(pwd) < 12:
            return False
        
        # Verifica complexidade da senha
        has_upper = any(c.isupper() for c in pwd)
        has_lower = any(c.islower() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?/' for c in pwd)
        
        # Requer pelo menos 3 dos 4 tipos de caracteres
        complexity_score = sum([has_upper, has_lower, has_digit, has_special])
        
        # Previne senhas comuns e padrões simples
        common_passwords = {'password', '123456', 'admin', 'welcome', 'senha', '123456789', 'qwerty'}
        if pwd.lower() in common_passwords:
            return False
        
        # Previne apenas repetições excessivas (4+ caracteres idênticos consecutivos)
        if re.search(r'(.)\1{3,}', pwd):  # 4 ou mais caracteres repetidos consecutivos
            return False
        
        return complexity_score >= 3 and len(pwd) >= 12

    def validate_remote_host(self, host: Optional[str]) -> bool:
        if not host or len(host) > 255:
            return False
        allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_"
        return all(c in allowed for c in host)

    def sanitize_string(self, value: Optional[str], allowed: Optional[str] = None) -> str:
        if not isinstance(value, str):
            return ""
        s = value.strip()
        if allowed is None:
            return s
        return "".join(c for c in s if c in allowed)

    def rate_limit(self, key: str, limit: int, window_sec: int, store: Dict[str, list]) -> bool:
        now = time.time()
        bucket = store.get(key, [])
        bucket = [t for t in bucket if now - t < window_sec]
        if len(bucket) >= limit:
            store[key] = bucket
            return False
        bucket.append(now)
        store[key] = bucket
        return True

    def enforce_remote_policy(self, remote_host: Optional[str]) -> bool:
        return True

    def is_authorized(self, action: str, context: Optional[dict] = None) -> bool:
        return True

    def hash_password(self, pwd: str, iterations: int = 200000) -> Dict[str, str]:
        salt = secrets.token_bytes(16)
        dk = hashlib.pbkdf2_hmac("sha256", pwd.encode("utf-8"), salt, iterations, dklen=32)
        return {
            "algo": "pbkdf2_hmac_sha256",
            "iterations": str(iterations),
            "salt_b64": base64.b64encode(salt).decode("ascii"),
            "hash_b64": base64.b64encode(dk).decode("ascii"),
        }

    def verify_password(self, pwd: str, record: Dict[str, str]) -> bool:
        try:
            if record.get("algo") != "pbkdf2_hmac_sha256":
                return False
            iterations = int(record.get("iterations", "0"))
            salt = base64.b64decode(record.get("salt_b64", ""))
            expected = base64.b64decode(record.get("hash_b64", ""))
            dk = hashlib.pbkdf2_hmac("sha256", pwd.encode("utf-8"), salt, iterations, dklen=32)
            return secrets.compare_digest(dk, expected)
        except Exception:
            return False

    def encrypt_secret(self, data: bytes, description: str = "Biruta") -> bytes:
        if win32crypt is None:
            raise RuntimeError("DPAPI indisponível")
        return win32crypt.CryptProtectData(data, description, None)

    def decrypt_secret(self, blob: bytes) -> bytes:
        if win32crypt is None:
            raise RuntimeError("DPAPI indisponível")
        res = win32crypt.CryptUnprotectData(blob, None)
        if isinstance(res, tuple) and len(res) == 2:
            return res[1]
        return res
