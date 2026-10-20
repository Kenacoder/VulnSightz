import logging

from scanner.logging_utils import RedactingFormatter, redact_mapping, redact_text


def test_credentials_redacted_from_text():
    text = "Authorization: Bearer supersecret Cookie: session=abc"
    out = redact_text(text)
    assert "supersecret" not in out
    assert "session=abc" not in out
    assert "[REDACTED]" in out


def test_credentials_redacted_from_mapping():
    data = {"Authorization": "Bearer tok", "X-Other": "ok", "password": "hunter2"}
    out = redact_mapping(data)
    assert out["Authorization"] == "[REDACTED]"
    assert out["password"] == "[REDACTED]"
    assert out["X-Other"] == "ok"


def test_logger_formatter_redacts():
    fmt = RedactingFormatter("%(message)s")
    record = logging.LogRecord(
        name="t",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="Cookie: sid=deadbeef",
        args=(),
        exc_info=None,
    )
    assert "deadbeef" not in fmt.format(record)
