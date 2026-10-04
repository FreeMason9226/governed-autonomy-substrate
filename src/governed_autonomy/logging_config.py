"""Structured (JSON) logging configuration."""

import json
import logging
import os
import sys
from datetime import UTC, datetime

_RESERVED = set(logging.makeLogRecord({}).__dict__) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    """Render each record as a single-line JSON object; extras become fields."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                entry[key] = value
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, sort_keys=True, default=str)


def configure_logging(level: str | None = None, fmt: str | None = None) -> None:
    """Configure the ``governed_autonomy`` logger from args or environment.

    ``GOVERNED_AUTONOMY_LOG_LEVEL`` (default INFO) and
    ``GOVERNED_AUTONOMY_LOG_FORMAT`` (``json`` default, or ``text``).
    """
    level = (level or os.environ.get("GOVERNED_AUTONOMY_LOG_LEVEL") or "INFO").upper()
    fmt = (fmt or os.environ.get("GOVERNED_AUTONOMY_LOG_FORMAT") or "json").lower()
    if level not in logging.getLevelNamesMapping():
        raise ValueError(f"invalid log level: {level}")
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        JsonFormatter() if fmt == "json" else logging.Formatter("%(levelname)s %(name)s %(message)s")
    )
    logger = logging.getLogger("governed_autonomy")
    logger.handlers[:] = [handler]
    logger.setLevel(level)
    logger.propagate = False
