"""One-time launch tokens, redirect files and secret comparison.

A launch URL ``http://<address>:<port>/launch#<token>`` carries a random 256-bit token in its **fragment**. A browser
never sends the fragment to a server, so the token never reaches a server log or a ``Referer``. The page at the
launch path sends the token to the app (for example ``POST /api/session``), which redeems it once
(:meth:`LaunchTokens.redeem`) and opens a session (:class:`nodestro_session.sessions.SessionStore`). A token works once
(a second use gives ``used``) and only for ``ttl`` seconds (``expired``).

The browser must never be started with that URL: the command line of ``xdg-open``, ``open`` or the browser is
readable by every local user. :meth:`LaunchTokens.issue` with ``redirect=True`` writes a **redirect file** instead,
0600 in a private directory (:func:`nodestro_session.private.ensure_private_dir`)::

    <meta http-equiv="refresh" content="0;url=http://<address>:<port>/launch#<token>">

and the browser is opened with its ``file://`` path, which holds no secret. The file is deleted as soon as its token
is redeemed, when the token expires (:meth:`LaunchTokens.sweep`, also run by every :meth:`LaunchTokens.issue`), when
more than ``max_pending`` tokens wait (the oldest is dropped) and when the server stops (:meth:`LaunchTokens.close`).

Only SHA-256 digests of the tokens are kept. ``on_secret`` is called with every new token, for log redaction
(:class:`nodestro_session.redact.SecretRedactor`).
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
import contextlib
from dataclasses import dataclass
import hashlib
import hmac
import html
from pathlib import Path
import re
import secrets
import threading
import time
from typing import Literal

from .private import check_private_dir, remove_file, write_private_file

LAUNCH_PATH = "/launch"
LAUNCH_TTL_SECONDS = 120.0
#: Shorter secrets are refused by :func:`check_secret_length` (256-bit secrets have 43 to 64 characters).
MIN_SECRET_LENGTH = 32
#: The form of the tokens :meth:`LaunchTokens.issue` creates (``secrets.token_urlsafe(32)``).
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")
_SPENT_KEPT = 256
#: At most this many issued tokens wait for redemption; :meth:`LaunchTokens.issue` drops the oldest beyond it.
MAX_PENDING = 32

Redemption = Literal["ok", "used", "expired", "invalid"]


class WeakSecretError(ValueError):
    """A configured secret is too short to protect anything."""

    def __init__(self, length: int, minimum: int) -> None:
        super().__init__(f"the secret must have at least {minimum} characters")
        self.length = length
        self.minimum = minimum


def secret_equals(given: str | bytes, expected: str | bytes) -> bool:
    """Compare two secrets in constant time (for equal lengths); strings are compared as UTF-8."""
    a = given.encode("utf-8") if isinstance(given, str) else given
    b = expected.encode("utf-8") if isinstance(expected, str) else expected
    return hmac.compare_digest(a, b)


def check_secret_length(secret: str | None, minimum: int = MIN_SECRET_LENGTH) -> None:
    """Raise :class:`WeakSecretError` for a secret shorter than ``minimum``; ``None`` (no secret) passes."""
    if secret is not None and len(secret) < minimum:
        raise WeakSecretError(len(secret), minimum)


def redirect_page(url: str, name: str = "the app") -> bytes:
    """The content of a redirect file that sends the browser to ``url``; ``name`` is shown while it opens."""
    target = html.escape(url, quote=True)
    title = html.escape(name)
    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="referrer" content="no-referrer">'
        f'<meta http-equiv="refresh" content="0;url={target}">'
        f"<title>{title}</title></head>"
        f"<body><p>Opening {title}…</p></body></html>\n"
    ).encode()


def redirect_file_pattern(prefix: str) -> re.Pattern[str]:
    """The names of the redirect files that :class:`LaunchTokens` with ``prefix`` writes (to remove leftovers)."""
    return re.compile(re.escape(prefix) + r"-launch-[0-9a-f]{16}\.html")


@dataclass(frozen=True)
class Launch:
    """An issued launch: the URL with the token, and the redirect file if one was written."""

    url: str
    redirect: Path | None


@dataclass
class _Pending:
    expires: float
    redirect: Path | None


def _digest(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


class LaunchTokens:
    """The launch tokens of one server: issued, redeemed once, expired after ``ttl`` seconds.

    ``origin`` is ``http://<address>:<port>`` and ``path`` the launch page. Redirect files go to ``redirect_dir`` (a
    private directory) with names that start with ``prefix``; ``name`` is the app's name on the redirect page.
    ``clock`` is monotonic seconds. ``on_secret`` gets every new token (log redaction). At most ``max_pending``
    tokens wait for redemption: a new one drops the oldest (it counts as expired and its redirect file is deleted).
    """

    def __init__(
        self,
        origin: str,
        redirect_dir: Path | None = None,
        prefix: str = "session",
        ttl: float = LAUNCH_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        *,
        path: str = LAUNCH_PATH,
        name: str = "the app",
        on_secret: Callable[[str], None] | None = None,
        max_pending: int = MAX_PENDING,
    ) -> None:
        if max_pending < 1:
            raise ValueError("max_pending must be at least 1")
        self.origin = origin.rstrip("/")
        self.max_pending = max_pending
        self.redirect_dir = redirect_dir
        self.prefix = prefix
        self.ttl = ttl
        self.path = path
        self.name = name
        self._clock = clock
        self._on_secret = on_secret
        self._pending: dict[bytes, _Pending] = {}
        self._spent: OrderedDict[bytes, Redemption] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def pending(self) -> int:
        """How many issued tokens are neither redeemed nor expired yet."""
        return len(self._pending)

    def issue(self, *, redirect: bool) -> Launch:
        """A new one-time launch URL; with ``redirect``, also a redirect file that opens it. Expired tokens are swept
        first, and the oldest pending token is dropped when more than ``max_pending`` would wait."""
        self.sweep()
        token = secrets.token_urlsafe(32)
        if self._on_secret is not None:
            self._on_secret(token)
        url = f"{self.origin}{self.path}#{token}"
        file: Path | None = None
        if redirect:
            if self.redirect_dir is None:
                raise RuntimeError("no directory for redirect files")
            # Checked again before each write: the directory may have been swapped since it was created.
            check_private_dir(self.redirect_dir)
            file = self.redirect_dir / f"{self.prefix}-launch-{secrets.token_hex(8)}.html"
            write_private_file(file, redirect_page(url, self.name))
        dropped: list[_Pending] = []
        with self._lock:
            self._pending[_digest(token)] = _Pending(self._clock() + self.ttl, file)
            while len(self._pending) > self.max_pending:
                key = next(iter(self._pending))
                dropped.append(self._pending.pop(key))
                self._remember(key, "expired")
        for entry in dropped:
            self._remove(entry.redirect)
        return Launch(url, file)

    def redeem(self, token: object) -> Redemption:
        """Use ``token`` once: ``ok``, or why it is refused (``used``, ``expired``, ``invalid``)."""
        if not isinstance(token, str) or TOKEN_PATTERN.fullmatch(token) is None:
            return "invalid"
        key = _digest(token)
        with self._lock:
            entry = self._pending.pop(key, None)
            if entry is None:
                return self._spent.get(key, "invalid")
            result: Redemption = "ok" if self._clock() < entry.expires else "expired"
            self._remember(key, "used" if result == "ok" else "expired")
        self._remove(entry.redirect)
        return result

    def sweep(self) -> int:
        """Expire old tokens and delete their redirect files; returns how many expired."""
        now = self._clock()
        with self._lock:
            expired = [(key, entry) for key, entry in self._pending.items() if now >= entry.expires]
            for key, _ in expired:
                del self._pending[key]
                self._remember(key, "expired")
        for _, entry in expired:
            self._remove(entry.redirect)
        return len(expired)

    def close(self) -> None:
        """Invalidate every pending token and delete every redirect file (the server stops)."""
        with self._lock:
            entries = list(self._pending.items())
            self._pending.clear()
            for key, _ in entries:
                self._remember(key, "expired")
        for _, entry in entries:
            self._remove(entry.redirect)

    def _remember(self, key: bytes, reason: Redemption) -> None:
        self._spent[key] = reason
        while len(self._spent) > _SPENT_KEPT:
            self._spent.popitem(last=False)

    @staticmethod
    def _remove(path: Path | None) -> None:
        if path is not None:
            # A leftover file holds a dead token; the product removes it at its next start (redirect_file_pattern).
            with contextlib.suppress(OSError):
                remove_file(path)
