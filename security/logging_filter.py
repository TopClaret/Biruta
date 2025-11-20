import re
from logging import Filter, LogRecord

class RedactFilter(Filter):
    def filter(self, record: LogRecord) -> bool:
        try:
            raw = record.msg
            if isinstance(raw, str):
                try:
                    formatted = raw % record.args if record.args else raw
                except Exception:
                    formatted = raw
            else:
                formatted = str(raw)

            redacted = re.sub(r"(token\s*[=:]\s*)([A-Za-z0-9._-]{6,})", r"\1[REDACTED]", formatted, flags=re.IGNORECASE)
            redacted = re.sub(r"(XSRF-TOKEN\s*[=:]\s*)([A-Za-z0-9._-]{6,})", r"\1[REDACTED]", redacted, flags=re.IGNORECASE)

            record.msg = redacted
            record.args = ()
        except Exception:
            pass
        return True