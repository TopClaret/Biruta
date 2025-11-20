import os
from typing import Any, Dict

def _default_config() -> Dict[str, Any]:
    return {
        "csrf": {
            "enforce_origin": False,
            "monitor_only": True
        },
        "csp": {
            "override_fallback": True,
            "policy": "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        },
        "rate_limit": {
            "enabled": True,
            "requests_per_minute": 120
        },
        "alerts": {
            "webhook_url": os.getenv("SECURITY_ALERT_WEBHOOK", ""),
            "enabled": False
        },
        "metrics": {
            "enabled": True,
            "path": "/metrics"
        },
        "redaction": {
            "enable_token_redaction": True
        }
    }

def load_config() -> Dict[str, Any]:
    path = os.getenv("SECURITY_CONFIG_PATH", os.path.join("config", "security.yaml"))
    if not os.path.exists(path):
        return _default_config()
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        base = _default_config()
        def merge(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
            for k, v in b.items():
                if isinstance(v, dict) and isinstance(a.get(k), dict):
                    a[k] = merge(a[k], v)
                else:
                    a[k] = v
            return a
        return merge(base, data)
    except Exception:
        return _default_config()