"""Browser sessions: a session ID for the cookie and a CSRF value for the page.

:meth:`SessionStore.create` opens a session with two random 256-bit values:

* the **session ID**, for an ``HttpOnly; SameSite=Strict`` cookie (:mod:`nodestro_session.cookies`) whose name holds
  the port;
* the **CSRF value**, which the app returns once in its JSON answer. The page keeps it in ``sessionStorage`` (scoped
  to the origin including the port) and sends it in a header with every API request.

A program on another local port that the browser visits receives the cookie (cookies are not port-scoped), but never
the CSRF value, so the cookie alone is useless (:class:`nodestro_session.guard.SessionGuard` checks both).

Only SHA-256 digests of the session IDs are kept, and sessions are looked up by digest, so the lookup time says
nothing about a stored ID. The CSRF value is compared in constant time. The store lives in memory only: a restart
ends every session. It is bounded (the oldest session is dropped beyond ``max_sessions``), and a session can end
after ``idle`` seconds without a request and ``max_age`` seconds after it was opened.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
import secrets
import threading
import time

MAX_SESSIONS = 32
#: Longer cookie or header values are refused without hashing.
MAX_VALUE_LENGTH = 128


@dataclass
class _Entry:
    csrf: bytes
    opened: float
    last: float


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def session_digest(session_id: str) -> str:
    """The hex SHA-256 of a session ID: what a route may keep to bind something to a session, never the ID itself."""
    return _digest(session_id).hex()


class SessionStore:
    """The open sessions of this process.

    ``idle`` and ``max_age`` are seconds (``None``: no limit); a session whose last request is more than ``idle``
    seconds ago, or that was opened more than ``max_age`` seconds ago, has ended. ``clock`` is monotonic seconds.
    ``on_secret`` gets every new session ID and CSRF value (log redaction).
    """

    def __init__(
        self,
        max_sessions: int = MAX_SESSIONS,
        *,
        idle: float | None = None,
        max_age: float | None = None,
        clock: Callable[[], float] = time.monotonic,
        on_secret: Callable[[str], None] | None = None,
    ) -> None:
        if max_sessions < 1:
            raise ValueError("max_sessions must be at least 1")
        self.max_sessions = max_sessions
        self.idle = idle
        self.max_age = max_age
        self._clock = clock
        self._on_secret = on_secret
        self._entries: OrderedDict[bytes, _Entry] = OrderedDict()
        self._lock = threading.Lock()

    def __len__(self) -> int:
        """How many sessions are stored (ended ones that were not looked up since may still be counted)."""
        return len(self._entries)

    def create(self) -> tuple[str, str]:
        """Open a session; returns (session ID for the cookie, CSRF value for the page)."""
        session_id, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        if self._on_secret is not None:
            self._on_secret(session_id)
            self._on_secret(csrf)
        now = self._clock()
        with self._lock:
            self._entries[_digest(session_id)] = _Entry(csrf.encode("ascii"), now, now)
            while len(self._entries) > self.max_sessions:
                self._entries.popitem(last=False)
        return session_id, csrf

    def _live(self, session_id: str | None, touch: bool) -> _Entry | None:
        """The open session ``session_id`` names, refreshed with ``touch``; an ended one is removed. Holds the lock."""
        if not session_id or len(session_id) > MAX_VALUE_LENGTH:
            return None
        key = _digest(session_id)
        entry = self._entries.get(key)
        if entry is None:
            return None
        now = self._clock()
        if (self.idle is not None and now - entry.last > self.idle) or (
            self.max_age is not None and now - entry.opened > self.max_age
        ):
            del self._entries[key]
            return None
        if touch:
            entry.last = now
        return entry

    def known(self, session_id: str | None, *, touch: bool = True) -> bool:
        """Whether ``session_id`` names an open session (the CSRF value is not checked). ``touch`` counts it as
        activity for the idle time."""
        with self._lock:
            return self._live(session_id, touch) is not None

    def check(self, session_id: str | None, csrf: str | None, *, touch: bool = True) -> bool:
        """Whether ``session_id`` names an open session and ``csrf`` is its CSRF value. Only a match counts as
        activity (with ``touch``)."""
        if not csrf or len(csrf) > MAX_VALUE_LENGTH:
            return False
        with self._lock:
            entry = self._live(session_id, touch=False)
            if entry is None or not hmac.compare_digest(entry.csrf, csrf.encode("utf-8")):
                return False
            if touch:
                entry.last = self._clock()
            return True

    def end(self, session_id: str | None) -> bool:
        """End the session ``session_id``; whether it was stored."""
        if not session_id or len(session_id) > MAX_VALUE_LENGTH:
            return False
        with self._lock:
            return self._entries.pop(_digest(session_id), None) is not None

    def end_all(self) -> int:
        """End every session; returns how many were stored."""
        with self._lock:
            count = len(self._entries)
            self._entries.clear()
        return count
