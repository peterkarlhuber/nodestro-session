"""Loopback names, ``Host`` header values and origins.

A browser sends the name it connected to in ``Host``. A page that rebinds its own name to ``127.0.0.1`` (DNS
rebinding) still sends that name, so a server on loopback recognizes such requests by their ``Host``.
"""

from __future__ import annotations

import ipaddress

#: Headers that a reverse proxy adds to the requests it forwards. A local app is never meant to sit behind one.
FORWARDING_HEADERS: tuple[str, ...] = (
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
)
_WILDCARD_HOSTS = frozenset({"", "0.0.0.0", "::", "*"})  # noqa: S104 (recognized here, never bound)


def is_loopback(host: str) -> bool:
    """``localhost``, ``*.localhost`` and loopback addresses (``127.0.0.0/8``, ``::1``)."""
    host = host.strip("[]").lower().rstrip(".")
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def split_host(value: str) -> str:
    """The host name of a ``Host`` header value (``name:port``, ``[::1]:port``), lower case."""
    value = value.strip().lower()
    if value.startswith("["):
        return value[1 : value.find("]")] if "]" in value else value[1:]
    if value.count(":") == 1:
        return value.split(":", 1)[0]
    return value


def split_port(value: str) -> int | None:
    """The port of a ``Host`` header value; ``None`` without one, ``-1`` for one that is not a number."""
    value = value.strip()
    if value.startswith("["):
        rest = value[value.find("]") + 1 :] if "]" in value else ""
    elif value.count(":") == 1:
        rest = value[value.find(":") :]
    else:
        return None
    if not rest:
        return None
    digits = rest[1:] if rest.startswith(":") else ""
    return int(digits) if digits.isdigit() and len(digits) <= 5 else -1


def is_ip_address(host: str) -> bool:
    """Whether ``host`` is an IP address (IPv6 with or without brackets)."""
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def listens_everywhere(bind_host: str | None) -> bool:
    """``0.0.0.0``, ``::``, ``*`` or an empty address: the server is reachable under every address of the computer."""
    return bind_host is not None and bind_host.strip() in _WILDCARD_HOSTS


def loopback_origin(port: int, host: str = "127.0.0.1") -> str:
    """The origin ``http://<host>:<port>`` of a server on ``host`` (IPv6 addresses in brackets)."""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"http://{host}:{port}"
