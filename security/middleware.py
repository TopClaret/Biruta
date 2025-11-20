import io
import json
import time
from typing import Callable, Iterable, Tuple

class SecurityMiddleware:
    def __init__(self, app: Callable, config: dict):
        self.app = app
        self.config = config

    def __call__(self, environ, start_response):
        start = time.time()
        method = environ.get("REQUEST_METHOD", "")
        path = environ.get("PATH_INFO", "")
        client_ip = environ.get("HTTP_X_FORWARDED_FOR") or environ.get("REMOTE_ADDR") or ""
        csrf_header = environ.get("HTTP_X_CSRF_TOKEN", "")
        origin = environ.get("HTTP_ORIGIN", "")
        host = environ.get("HTTP_HOST", "")

        monitor_only = bool(self.config.get("csrf", {}).get("monitor_only", True))
        enforce_origin = bool(self.config.get("csrf", {}).get("enforce_origin", False))

        body_bytes = b""
        content_type = environ.get("CONTENT_TYPE", "")
        if method in {"POST", "PUT", "PATCH"}:
            try:
                length = int(environ.get("CONTENT_LENGTH") or 0)
            except ValueError:
                length = 0
            if length > 0:
                body_bytes = environ["wsgi.input"].read(length)
                try:
                    if "json" in content_type.lower():
                        data = json.loads(body_bytes.decode("utf-8"))
                        if isinstance(data, dict):
                            username = data.get("username") or data.get("user")
                            domain = data.get("domain")
                            if (not domain) and isinstance(username, str) and "\\" in username:
                                parts = username.split("\\", 1)
                                if len(parts) == 2 and parts[0] and parts[1]:
                                    data["domain"] = parts[0].upper()
                            elif isinstance(domain, str) and domain:
                                data["domain"] = domain.upper()
                            body_bytes = json.dumps(data).encode("utf-8")
                            environ["CONTENT_LENGTH"] = str(len(body_bytes))
                except Exception:
                    pass
                environ["wsgi.input"] = io.BytesIO(body_bytes)

        alerts = []
        if method in {"POST", "PUT", "PATCH"}:
            if enforce_origin and origin and host and origin.split("//")[-1] != host:
                alerts.append("origin_mismatch")
            if not csrf_header:
                alerts.append("missing_csrf_header")

        if path == "/restart_service" and body_bytes:
            try:
                data = json.loads(body_bytes.decode("utf-8"))
                service_name = str(data.get("service_name") or "")
                deny = {
                    "RpcSs",
                    "LanmanServer",
                    "Dnscache",
                    "EventLog",
                    "WinDefend",
                    "wuauserv"
                }
                if service_name in deny:
                    if monitor_only:
                        alerts.append("critical_service_requested")
                    else:
                        def forbidden_start(status, headers, exc_info=None):
                            return start_response(status, headers, exc_info)
                        start_response("403 FORBIDDEN", [("Content-Type", "application/json")])
                        return [json.dumps({"error": "service not allowed"}).encode("utf-8")]
            except Exception:
                pass

        headers_holder = {}
        def capturing_start_response(status: str, headers: Iterable[Tuple[str, str]], exc_info=None):
            for k, v in headers:
                headers_holder.setdefault(k, v)
            return start_response(status, headers, exc_info)

        result = self.app(environ, capturing_start_response)

        pass

        end = time.time()
        duration_ms = int((end - start) * 1000)

        if alerts:
            import logging
            logging.getLogger("security").warning("event=security_alert path=%s method=%s ip=%s alerts=%s duration_ms=%d", path, method, client_ip, ",".join(alerts), duration_ms)

        return result