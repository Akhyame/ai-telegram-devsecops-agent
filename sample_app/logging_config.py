"""Structured JSON logging for the sample application."""

import json
import logging
from datetime import UTC, datetime

_RESERVED_LOG_RECORD_FIELDS = frozenset(
    {
        *logging.makeLogRecord({}).__dict__,
        "asctime",
        "message",
    }
)


class JsonFormatter(logging.Formatter):
    """Serialize application log records as compact JSON."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(
                record.created,
                tz=UTC,
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        for key in sorted(record.__dict__):
            if key not in _RESERVED_LOG_RECORD_FIELDS and not key.startswith("_"):
                payload[key] = record.__dict__[key]

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )


def configure_application_logger(level: str) -> logging.Logger:
    """Create one isolated JSON logger for application events."""

    logger = logging.getLogger("sample_app")
    logger.setLevel(level)
    logger.handlers.clear()
    logger.propagate = False

    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)

    return logger
