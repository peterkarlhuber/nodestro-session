"""Listening on loopback only.

:func:`require_loopback` refuses a configuration that would offer the app to the network: a bind address that is not
loopback (``0.0.0.0``, ``::``, a LAN address, a host name) and extra host names that are not loopback names (which a
reverse proxy could use). An app without a login uses it before it opens anything.

:func:`bind_loopback` opens the listening socket:

- on a random ``127.a.b.c`` address, chosen anew for every start, so that the origin of an instance cannot be guessed
  in advance and nothing that another program left in the browser for an earlier origin (storage, a service worker)
  applies to it. Where only ``127.0.0.1`` exists (macOS by default) it falls back to that address;
- with a bound but not listening ``[::1]`` socket on the same port, so that no other program can answer
  ``http://localhost:<port>/`` over IPv6 while the app runs;
- with exclusive sockets: ``SO_EXCLUSIVEADDRUSE`` on Windows (otherwise another program could bind the same address
  with ``SO_REUSEADDR`` and take over connections), never ``SO_REUSEPORT``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
import contextlib
from dataclasses import dataclass
import errno
import logging
import secrets
import socket
import sys

from .hosts import is_loopback, listens_everywhere, split_host

LOOPBACK = "127.0.0.1"
LOOPBACK_V6 = "::1"
_PORT_ATTEMPTS = 20
#: How many random ``127.a.b.c`` addresses are tried when one is taken with a fixed port.
_ADDRESS_ATTEMPTS = 8
#: "Cannot assign requested address": the address is not configured on this host (macOS: only 127.0.0.1).
_NOT_CONFIGURED_ERRNOS = frozenset({errno.EADDRNOTAVAIL, 10049})  # 10049 = WSAEADDRNOTAVAIL
_NO_IPV6 = {errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL, getattr(errno, "EPROTONOSUPPORT", errno.EAFNOSUPPORT)}

_log = logging.getLogger(__name__)


class LoopbackRequired(ValueError):
    """The configuration would offer the app to the network. ``host`` is the bind address, ``hosts`` the refused extra
    host names, ``refused`` says what was refused (for the message)."""

    def __init__(self, host: str, hosts: list[str], refused: list[str]) -> None:
        super().__init__(f"only loopback is allowed; refused: {'; '.join(refused)}")
        self.host = host
        self.hosts = hosts
        self.refused = refused


class PortUnavailableError(RuntimeError):
    """The requested port cannot be bound on the loopback address."""


def loopback_refusals(bind_host: str | None, extra_hosts: Iterable[str] = ()) -> tuple[bool, list[str]]:
    """Whether ``bind_host`` must be refused (empty, a wildcard or not loopback), and the extra host names that must
    be refused (``*`` and every name that is not a loopback name)."""
    host = (bind_host or "").strip()
    bad_host = not host or listens_everywhere(host) or not is_loopback(host)
    names = [item.strip() for item in extra_hosts if item.strip()]
    others = [name for name in names if name == "*" or not is_loopback(split_host(name))]
    return bad_host, others


def require_loopback(bind_host: str | None, extra_hosts: Iterable[str] = ()) -> None:
    """Raise :class:`LoopbackRequired` unless ``bind_host`` and every name of ``extra_hosts`` are loopback."""
    bad_host, others = loopback_refusals(bind_host, extra_hosts)
    host = (bind_host or "").strip()
    refused: list[str] = []
    if bad_host:
        refused.append(f"listening on {host or '(every interface)'!r}")
    if others:
        refused.append(f"host names {','.join(others)}")
    if refused:
        raise LoopbackRequired(host, others, refused)


def random_loopback() -> str:
    """A random IPv4 loopback address ``127.a.b.c`` other than ``127.0.0.1``, with ``c`` in 1..254."""
    while True:
        a, b, c = secrets.randbelow(256), secrets.randbelow(256), 1 + secrets.randbelow(254)
        address = f"127.{a}.{b}.{c}"
        if address != LOOPBACK:
            return address


@dataclass
class LoopbackSockets:
    """The listening IPv4 socket and, if IPv6 is available, the bound but not listening ``[::1]`` socket."""

    listener: socket.socket
    v6_guard: socket.socket | None

    @property
    def host(self) -> str:
        return str(self.listener.getsockname()[0])

    @property
    def port(self) -> int:
        return int(self.listener.getsockname()[1])

    def close(self) -> None:
        for sock in (self.listener, self.v6_guard):
            if sock is not None:
                with contextlib.suppress(OSError):
                    sock.close()


def _exclusive_socket(family: socket.AddressFamily) -> socket.socket:
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.set_inheritable(False)
    if sys.platform == "win32":
        # Without it, another program could bind the same address with SO_REUSEADDR and take over connections.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    return sock


def _bind_v4(host: str, port: int) -> socket.socket:
    sock = _exclusive_socket(socket.AF_INET)
    try:
        if sys.platform != "win32":
            # POSIX only: lets a restart reuse a port in TIME_WAIT; never lets two listeners share it.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(128)
    except BaseException:
        sock.close()
        raise
    return sock


def _guard_v6(port: int) -> socket.socket | None:
    """Bind ``[::1]:port`` without listening; None if this host has no IPv6 loopback. Raises if the port is taken."""
    if not socket.has_ipv6:
        return None
    try:
        sock = _exclusive_socket(socket.AF_INET6)
    except OSError as exc:
        if exc.errno in _NO_IPV6 or getattr(exc, "winerror", None) == 10047:  # WSAEAFNOSUPPORT
            return None
        raise
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((LOOPBACK_V6, port))
    except OSError as exc:
        sock.close()
        if exc.errno in _NO_IPV6 or getattr(exc, "winerror", None) in (10047, 10049):  # WSAEADDRNOTAVAIL
            return None
        raise
    return sock


def _not_configured(exc: OSError) -> bool:
    return exc.errno in _NOT_CONFIGURED_ERRNOS or getattr(exc, "winerror", None) == 10049


def _listen_v4(port: int, choose: Callable[[], str]) -> socket.socket:
    """Listen on a random loopback address, or on ``127.0.0.1`` where only that one is configured."""
    for attempt in range(1, _ADDRESS_ATTEMPTS + 1):
        try:
            return _bind_v4(choose(), port)
        except OSError as exc:
            if _not_configured(exc):
                break  # macOS and others: only 127.0.0.1 exists; fall back to it below
            if port and attempt < _ADDRESS_ATTEMPTS:
                continue  # the fixed port is taken on this random address only: try another address
            raise PortUnavailableError(
                f"cannot listen on 127.0.0.0/8 port {port or 'any'}: {exc.strerror or exc}"
            ) from exc
    try:
        listener = _bind_v4(LOOPBACK, port)
    except OSError as exc:
        raise PortUnavailableError(f"cannot listen on {LOOPBACK}:{port}: {exc.strerror or exc}") from exc
    _log.info("only %s is available as a loopback address", LOOPBACK)
    return listener


def bind_loopback(port: int = 0, choose: Callable[[], str] = random_loopback) -> LoopbackSockets:
    """Listen on ``127.a.b.c:port`` and hold ``[::1]:port`` (``port`` 0: a port that is free on both).

    ``127.a.b.c`` is a fresh random loopback address (``choose``), or ``127.0.0.1`` where no other one is configured.
    Pass ``choose=lambda: "127.0.0.1"`` for a fixed address.
    """
    attempts = 1 if port else _PORT_ATTEMPTS
    last: OSError | None = None
    for _ in range(attempts):
        listener = _listen_v4(port, choose)
        chosen = int(listener.getsockname()[1])
        try:
            guard = _guard_v6(chosen)
        except OSError as exc:
            listener.close()
            last = exc
            continue  # [::1] has this port in use by another program: with port 0, try another free port
        return LoopbackSockets(listener, guard)
    detail = last.strerror if last is not None and last.strerror else last
    raise PortUnavailableError(
        f"port {port or 'any'}: [{LOOPBACK_V6}] is used by another program ({detail}); "
        "both loopback addresses are held so that no other program can answer for localhost"
    )
