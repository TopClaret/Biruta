import logging
import os
from logging import StreamHandler

from app import app
from security.config import load_config
from security.logging_filter import RedactFilter
from security.middleware import SecurityMiddleware
from monitoring.prometheus_middleware import MetricsMiddleware

config = load_config()

logger = logging.getLogger()
structured_handler = StreamHandler()
formatter = logging.Formatter("{\"ts\":%(asctime)s,\"level\":%(levelname)s,\"name\":%(name)s,\"message\":%(message)s}")
structured_handler.setFormatter(formatter)
structured_handler.addFilter(RedactFilter())
logger.addHandler(structured_handler)
logger.setLevel(logging.INFO)
for h in logger.handlers:
    try:
        h.addFilter(RedactFilter())
    except Exception:
        pass

if config.get("metrics", {}).get("enabled", True):
    app.wsgi_app = MetricsMiddleware(app.wsgi_app, path=config.get("metrics", {}).get("path", "/metrics"))

app.wsgi_app = SecurityMiddleware(app.wsgi_app, config)

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5001"))
    app.run(host="127.0.0.1", port=port, debug=False)