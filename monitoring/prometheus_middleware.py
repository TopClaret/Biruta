from typing import Callable, Iterable, Tuple
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

class MetricsMiddleware:
    def __init__(self, app: Callable, path: str = "/metrics"):
        self.app = app
        self.path = path
        self.requests_total = Counter("http_requests_total", "Total de requisições", ["method", "path", "status"])
        self.latency = Histogram("http_request_latency_seconds", "Latência das requisições", ["method", "path"])

    def __call__(self, environ, start_response):
        method = environ.get("REQUEST_METHOD", "")
        path = environ.get("PATH_INFO", "")
        if path == self.path:
            data = generate_latest()
            start_response("200 OK", [("Content-Type", CONTENT_TYPE_LATEST)])
            return [data]

        status_holder = {"status": "200"}
        def capturing_start_response(status: str, headers: Iterable[Tuple[str, str]], exc_info=None):
            status_holder["status"] = status.split(" ")[0]
            return start_response(status, headers, exc_info)

        with self.latency.labels(method=method, path=path).time():
            result = self.app(environ, capturing_start_response)
        self.requests_total.labels(method=method, path=path, status=status_holder["status"]).inc()
        return result