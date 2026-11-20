"""Session cookies: names per port, fixed flags, and reading every value of a name.

Cookies are not port-scoped: every server on ``127.0.0.1`` receives the cookies of every other one, and can set
cookies for it. Hence:

- the cookie name holds the port (:func:`cookie_name`), so two instances on one host never overwrite each other's
  cookie;
- the flags are fixed (:func:`set_cookie`): ``HttpOnly`` (no script reads it), ``SameSite=Strict`` (no other site's
  request carries it), ``Path=/``, no ``Domain`` (host-only), and no ``Max-Age`` unless asked for (it ends with the
  browser session). ``Secure`` only on https, which loopback servers do not use;
- :func:`cookie_values` returns **every** value of a name, because another local server may have set a second cookie
  with the same name. A guard accepts the request if one of them is a valid session.
"""

from __future__ import annotations

from collections.abc import Iterable
import re

#: RFC 6265 ``token`` for names and ``cookie-octet`` for values: nothing that could end the header or add an attribute.
_NAME = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_VALUE = re.compile(r"[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*")
_FLAGS = "HttpOnly; SameSite=Strict; Path=/"


def cookie_name(prefix: str, port: int | None = None) -> str:
    """The session cookie name: ``prefix`` followed by the port, if one is given (``app_session_8080``)."""
    name = prefix if port is None else f"{prefix}{int(port)}"
    if _NAME.fullmatch(name) is None:
        raise ValueError(f"not a valid cookie name: {name!r}")
    return name


def set_cookie(name: str, value: str, *, max_age: float | None = None, secure: bool = False) -> str:
    """The ``Set-Cookie`` value of a session cookie: ``name=value; HttpOnly; SameSite=Strict; Path=/``, then
    ``; Max-Age=<seconds>`` with ``max_age`` and ``; Secure`` with ``secure``."""
    if _NAME.fullmatch(name) is None:
        raise ValueError(f"not a valid cookie name: {name!r}")
    if _VALUE.fullmatch(value) is None:
        raise ValueError("not a valid cookie value")
    cookie = f"{name}={value}; {_FLAGS}"
    if max_age is not None:
        cookie += f"; Max-Age={int(max_age)}"
    if secure:
        cookie += "; Secure"
    return cookie


def clear_cookie(name: str, *, secure: bool = False) -> str:
    """The ``Set-Cookie`` value that deletes the session cookie ``name``."""
    return set_cookie(name, "", max_age=0, secure=secure)


def cookie_values(headers: Iterable[tuple[bytes | str, bytes | str]], name: str) -> list[str]:
    """Every value of the cookie ``name`` in the ``Cookie`` headers of ``headers`` (ASGI pairs or decoded pairs)."""
    values = []
    for key, value in headers:
        key_text = key.decode("latin-1") if isinstance(key, bytes) else key
        if key_text.lower() != "cookie":
            continue
        text = value.decode("latin-1") if isinstance(value, bytes) else value
        for part in text.split(";"):
            cookie, sep, content = part.strip().partition("=")
            if sep and cookie == name:
                values.append(content.strip().strip('"'))
    return values
