"""Structured logging helpers with credential redaction."""

from __future__ import annotations

import logging
import re
from typing import Any


SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "session",
    "csrf",
    "x-api-key",
}

_REDACT = "[REDACTED]"

_HEADER_PATTERN = re.compile(
    r"(?i)(authorization|cookie|set-cookie|x-api-key)\s*[:=]\s*([^\r\n]+)"
)
_QUERY_SECRET_PATTERN = re.compile(
    r"(?i)([?&](?:password|passwd|token|secret|api_key|access_token)=)([^&]*)"
)


def redact_text(text: str) -> str:
    if not text:
        return text
    text = _HEADER_PATTERN.sub(lambda m: f"{m.group(1)}: {_REDACT}", text)
    text = _QUERY_SECRET_PATTERN.sub(lambda m: f"{m.group(1)}{_REDACT}", text)
    return text


def redact_mapping(data: dict[str, Any] | None) -> dict[str, Any]:
    if not data:
        return {}
    out: dict[str, Any] = {}
    for key, value in data.items():
        if str(key).lower() in SENSITIVE_KEYS:
            out[key] = _REDACT
        elif isinstance(value, dict):
            out[key] = redact_mapping(value)
        elif isinstance(value, str):
            out[key] = redact_text(value)
        else:
            out[key] = value
    return out


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        return redact_text(original)


def setup_logger(name: str = "web_vuln", verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger(name)
    level = logging.DEBUG if verbose else logging.WARNING
    if logger.handlers:
        logger.setLevel(level)
        return logger

    handler = logging.StreamHandler()
    handler.setFormatter(
        RedactingFormatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger
