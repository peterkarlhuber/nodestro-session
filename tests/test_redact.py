"""Secrets never reach a log record (ported from nodestro-api tests/test_launch.py)."""

from __future__ import annotations

import io
import logging

from nodestro_session import SecretRedactor

SECRET = "s" * 43


def _logger(name: str, redactor: SecretRedactor) -> tuple[logging.Logger, io.StringIO]:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    out = io.StringIO()
    logger.addHandler(logging.StreamHandler(out))
    logger.addFilter(redactor)
    return logger, out


def test_the_launch_token_never_reaches_the_access_log() -> None:
    logger, out = _logger("test.redact.access", SecretRedactor([SECRET]))
    # Formatters such as uvicorn's AccessFormatter unpack the arguments (client, method, path, version, status).
    logger.info('%s - "%s %s HTTP/%s" %d', "127.0.0.1:5", "GET", f"/api/launch?token={SECRET}&x=1", "1.1", 200)
    logger.info("anything with %s", SECRET)
    logger.info(f"or in the message {SECRET}")
    logger.info("as a mapping %(value)s", {"value": SECRET})
    text = out.getvalue()
    assert '127.0.0.1:5 - "GET /api/launch?token=[redacted]&x=1 HTTP/1.1" 200' in text
    assert text.count("[redacted]") == 4
    assert SECRET not in text


def test_query_tokens_are_redacted_without_knowing_them() -> None:
    redactor = SecretRedactor(query_params=("token", "key"))
    assert redactor.redact("GET /launch?token=abc&key=def&x=1") == "GET /launch?token=[redacted]&key=[redacted]&x=1"
    assert SecretRedactor(query_params=()).redact("/x?token=abc") == "/x?token=abc"


def test_short_lived_secrets_are_bounded_and_lasting_ones_kept() -> None:
    redactor = SecretRedactor(kept=2)
    redactor.add("lasting-key", lasting=True)
    for value in ("first-token", "second-token", "third-token"):
        redactor.add(value)
    redactor.add("abc")  # too short to redact safely
    text = redactor.redact("lasting-key first-token second-token third-token abc")
    assert text == "[redacted] first-token [redacted] [redacted] abc"


def test_a_secret_inside_another_is_replaced_whole() -> None:
    redactor = SecretRedactor(["token-part", "token-part-and-more"], marker="***")
    assert redactor.redact("x token-part-and-more y") == "x *** y"
