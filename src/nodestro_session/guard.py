"""``SessionGuard``: the ASGI middleware that every request passes before any route sees it.

The checks, in this order (the first that fails answers; its neutral code in brackets):

1. **Host (DNS rebinding).** Exactly one ``Host`` header, equal to ``<address>:<port>`` of the app's origin, on every
   path (``host_not_allowed``, 403). ``localhost``, other loopback addresses, other ports and every other name are
   refused: a page that rebinds its own name to a loopback address sends that name.
2. **Forwarded headers.** ``Forwarded``, ``X-Forwarded-*`` and ``X-Real-IP`` are refused (``forwarded_not_allowed``,
   403): a local app is never meant to sit behind a proxy.
3. **Origin.** An ``Origin`` other than the app's own is refused (``origin_not_allowed``, 403).
4. **Unusual paths.** A path with a ``.`` or ``..`` segment, an empty segment (``//``), a backslash, a NUL or a
   percent sign that still encodes a dot, slash, backslash, percent sign or NUL (``%2e``, ``%2f``, ``%5c``, ``%25``,
   ``%00``, any case) is refused (``not_found``, 404), on every path, not only under the API prefix: a later mount,
   router, path normalization or second percent-decoding could otherwise turn ``/static/../api/control/shutdown``,
   ``//api/x`` or ``/x/%2e%2e/api/x`` into a guarded route that skipped the session or control checks. The same holds
   for the path's NFKC form (fullwidth full stops and solidi). The API and control prefixes are matched
   case-insensitively the way ``re.IGNORECASE`` does it, which also folds U+0131 (dotless i), U+017F (long s) and
   U+212A (Kelvin sign) to ``i``, ``s`` and ``k``, and also after ``str.casefold`` and NFKC normalization. A path that
   any of these maps under a prefix is treated as under it, so an app that routes case-insensitively or normalizes
   Unicode gets no unguarded path either. Such a path is only ever classified more strictly.
5. **Control endpoints** (only with ``control_prefix``): any ``Origin`` or ``Sec-Fetch-*`` header is refused
   (``browser_not_allowed``, 403). A command line client never sends them and every current browser does, so a page
   can never drive the control channel, even with the token.
6. **Fetch metadata.** Other API requests with ``Sec-Fetch-Site`` other than ``same-origin`` or ``none`` are refused
   (``cross_site``, 403). ``same-site`` matters: a page on another port of ``127.0.0.1`` is same-site.
7. **Origin required.** Unsafe methods outside the control endpoints must carry the app's ``Origin``
   (``origin_required``, 403). Browsers send it with every ``POST``, ``PUT``, ``PATCH`` and ``DELETE``.
8. **JSON only.** Unsafe API requests need ``Content-Type: application/json`` (``json_only``, 415), which a form or a
   ``fetch`` without preflight cannot send.
9. **Control token.** Every control path except ``GET`` and ``HEAD`` of ``control_open_paths`` needs
   ``Authorization: Bearer <control_token>`` (``control_denied``, 401), compared in constant time. An empty token
   opens nothing.
10. **Session and CSRF.** Every API path except ``open_paths`` and the control endpoints needs the session cookie
    (``session_required``, 401) **and** the session's CSRF value in ``csrf_header`` (``csrf_invalid``, 403). The
    session's digest goes to ``scope["state"][state_key]`` and ``on_activity`` is called.

Paths outside ``api_prefix`` (the pages and static files) pass after checks 1 to 3 and 7, so that a navigation from
another site (a link, the redirect file) can open them; they must hold no data.

WebSockets are refused (close code 1008). Every answer, refusals and the app's own answers included, gets
``security_headers`` (a strict ``Content-Security-Policy``, ``Cache-Control: no-store``, ``nosniff``,
``Referrer-Policy: no-referrer``, ``X-Frame-Options: DENY``, same-origin opener and resource policies); headers of the
same name from the app are replaced.

A refusal is sent with ``refuse(scope, send, refusal)``; the default :func:`send_problem` sends a problem document
with the neutral code. A product passes its own sender to keep its codes and format.

This middleware is not a user login: it keeps other web pages, other local programs and DNS rebinding away from a
single-user app on loopback.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass
import json
import re
import unicodedata
from urllib.parse import urlsplit

from ._asgi import ASGIApp, Message, Receive, Scope, Send
from .cookies import cookie_values
from .hosts import FORWARDING_HEADERS, is_loopback
from .sessions import SessionStore, session_digest
from .tokens import secret_equals

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)
SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("content-security-policy", CONTENT_SECURITY_POLICY),
    ("cache-control", "no-store"),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
    ("x-frame-options", "DENY"),
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-resource-policy", "same-origin"),
)

#: Every refusal: code -> (status, fixed text). The texts never quote the request.
REFUSALS: dict[str, tuple[int, str]] = {
    "host_not_allowed": (403, "Requests for this host name are not answered"),
    "forwarded_not_allowed": (403, "Requests forwarded by a proxy are not answered"),
    "origin_not_allowed": (403, "Requests from other web pages are not accepted"),
    "not_found": (404, "Not found"),
    "browser_not_allowed": (403, "The control endpoints do not answer browsers"),
    "cross_site": (403, "Requests from other sites are not accepted"),
    "origin_required": (403, "This request needs the app's own Origin"),
    "json_only": (415, "The request body must be JSON"),
    "control_denied": (401, "The control endpoints need the control token"),
    "session_required": (401, "Open the app with its launch link first"),
    "csrf_invalid": (403, "The request lacks the session's CSRF value"),
}


@dataclass(frozen=True)
class Refusal:
    """Why a request is refused: a code of :data:`REFUSALS`, its status and its fixed text."""

    code: str
    status: int
    detail: str

    @classmethod
    def of(cls, code: str) -> Refusal:
        status, detail = REFUSALS[code]
        return cls(code, status, detail)


RefusalSender = Callable[[Scope, Send, Refusal], Awaitable[None]]


async def send_problem(scope: Scope, send: Send, refusal: Refusal) -> None:
    """Send ``refusal`` as ``application/problem+json``: ``type``, ``title``, ``status`` and ``code``."""
    body = json.dumps(
        {"type": "about:blank", "title": refusal.detail, "status": refusal.status, "code": refusal.code}
    ).encode()
    await send(
        {
            "type": "http.response.start",
            "status": refusal.status,
            "headers": [
                (b"content-type", b"application/problem+json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def with_security_headers(send: Send, headers: Sequence[tuple[str, str]] = SECURITY_HEADERS) -> Send:
    """``send`` that replaces the given headers of every answer (and ``Pragma``, ``Expires``) with ``headers``."""
    added = [(name.encode("latin-1"), value.encode("latin-1")) for name, value in headers]
    replaced = {name for name, _ in added} | {b"pragma", b"expires"}

    async def wrapped(message: Message) -> None:
        if message["type"] == "http.response.start":
            kept = [(key, value) for key, value in message.get("headers", []) if key.lower() not in replaced]
            message = {**message, "headers": kept + added}
        await send(message)

    return wrapped


#: Percent-encodings that a second decoding would turn into a dot, slash, backslash, percent sign or NUL.
_ENCODED = re.compile(r"%(?:2e|2f|5c|25|00)", re.IGNORECASE)


def _prefix_pattern(prefix: str, *, segment: bool) -> re.Pattern[str]:
    """``prefix`` at the start of a path, case-insensitive as ``re.IGNORECASE`` routers match it; with ``segment``,
    followed by ``/`` or the end."""
    return re.compile(re.escape(prefix) + (r"(?=/|$)" if segment else ""), re.IGNORECASE)


def _forms(path: str) -> tuple[str, ...]:
    """``path`` as a case-insensitive or Unicode-normalizing router may see it."""
    return (path, path.casefold(), unicodedata.normalize("NFKC", path).casefold())


def unusual_path(path: str) -> bool:
    """Whether ``path`` or its NFKC form (fullwidth full stop and solidus become ``.`` and ``/``) is unusual
    (:func:`_unusual`)."""
    return _unusual(path) or _unusual(unicodedata.normalize("NFKC", path))


def _unusual(path: str) -> bool:
    """Whether ``path`` has a ``.`` or ``..`` segment, an empty segment (``//``; a trailing ``/`` is fine), a
    backslash, a NUL or an encoded ``%2e``, ``%2f``, ``%5c``, ``%25`` or ``%00``: anything that a later normalization
    or a second percent-decoding could map onto another path. ``/`` is a usual path."""
    if not path.startswith("/") or "\\" in path or "\x00" in path or _ENCODED.search(path):
        return True
    segments = path[1:].split("/")
    return any(segment in (".", "..") for segment in segments) or "" in segments[:-1]


class SessionGuard:
    """Applies the checks of this module to every HTTP request and the security headers to every answer.

    ``origin`` is the app's ``http://<loopback address>:<port>``. ``sessions`` and ``cookie`` name the session store
    and the session cookie; ``csrf_header`` the header with the CSRF value. ``api_prefix`` marks the API paths, of
    which ``open_paths`` need no session (a health check, the launch exchange). ``control_prefix``,
    ``control_token`` and ``control_open_paths`` describe an optional control channel for a command line client.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        origin: str,
        sessions: SessionStore,
        cookie: str,
        csrf_header: str = "X-CSRF-Token",
        api_prefix: str = "/api",
        open_paths: Iterable[str] = (),
        control_prefix: str | None = None,
        control_token: str = "",
        control_open_paths: Iterable[str] = (),
        security_headers: Sequence[tuple[str, str]] = SECURITY_HEADERS,
        refuse: RefusalSender = send_problem,
        on_activity: Callable[[], None] = lambda: None,
        state_key: str = "session",
    ) -> None:
        parts = urlsplit(origin)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.port is None:
            raise ValueError("origin must be scheme://host:port")
        if not is_loopback(parts.hostname):
            raise ValueError("origin must be a loopback address or name")
        if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username or parts.password:
            raise ValueError("origin must be scheme://host:port")
        self.app = app
        self.origin = f"{parts.scheme}://{parts.netloc}".lower()
        self.host = parts.netloc.lower()
        self.sessions = sessions
        self.cookie = cookie
        self.csrf_header = csrf_header.lower()
        self.api_prefix = api_prefix.rstrip("/").lower()
        self._api_pattern = _prefix_pattern(self.api_prefix, segment=True) if self.api_prefix else None
        self.open_paths = frozenset(open_paths)
        self.control_prefix = control_prefix.rstrip("/").lower() + "/" if control_prefix else None
        self._control_pattern = _prefix_pattern(self.control_prefix, segment=False) if self.control_prefix else None
        # An empty token opens nothing: every control path but the open ones is then refused.
        self._control_token = control_token.encode("utf-8")
        self.control_open_paths = frozenset(control_open_paths)
        self.security_headers = tuple(security_headers)
        self.refuse = refuse
        self.on_activity = on_activity
        self.state_key = state_key

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        send = with_security_headers(send, self.security_headers)
        refusal = self.refusal(scope)
        if refusal is not None:
            await self.refuse(scope, send, Refusal.of(refusal))
            return
        await self.app(scope, receive, send)

    def refusal(self, scope: Scope) -> str | None:
        """The code of the first check that ``scope`` fails, or ``None``; a passing session request is recorded."""
        headers = [(key.decode("latin-1").lower(), value.decode("latin-1")) for key, value in scope["headers"]]
        path: str = scope.get("path", "")
        method: str = scope.get("method", "GET")
        hosts = [value.strip().lower() for key, value in headers if key == "host"]
        if hosts != [self.host]:
            return "host_not_allowed"
        if any(key in FORWARDING_HEADERS for key, _ in headers):
            return "forwarded_not_allowed"
        origins = [value.strip().lower() for key, value in headers if key == "origin"]
        if any(origin != self.origin for origin in origins):
            return "origin_not_allowed"
        if unusual_path(path):
            return "not_found"
        # The prefixes match in every form a case-insensitive or normalizing router may see (_forms, re.IGNORECASE).
        forms = _forms(path)
        api_pattern, control_pattern = self._api_pattern, self._control_pattern
        api = any(api_pattern.match(form) for form in forms) if api_pattern is not None else True
        control = control_pattern is not None and any(control_pattern.match(form) for form in forms)
        unsafe = method not in SAFE_METHODS
        if control:
            if origins or any(key.startswith("sec-fetch-") for key, _ in headers):
                return "browser_not_allowed"
        else:
            if api:
                sites = {value.strip().lower() for key, value in headers if key == "sec-fetch-site"}
                if sites - {"same-origin", "none"}:
                    return "cross_site"
            if unsafe and not origins:
                return "origin_required"
        if api and unsafe:
            content_types = [value.split(";", 1)[0].strip().lower() for key, value in headers if key == "content-type"]
            if content_types != ["application/json"]:
                return "json_only"
        open_control = path in self.control_open_paths and method in ("GET", "HEAD")
        if control and not open_control and not self._control_authorized(headers):
            return "control_denied"
        if api and not control and path not in self.open_paths:
            known = [value for value in cookie_values(headers, self.cookie) if self.sessions.known(value, touch=False)]
            if not known:
                return "session_required"
            csrf = [value for key, value in headers if key == self.csrf_header]
            matched = [value for value in known if len(csrf) == 1 and self.sessions.check(value, csrf[0])]
            if not matched:
                return "csrf_invalid"
            # Routes get the session's digest, never the cookie value.
            scope.setdefault("state", {})[self.state_key] = session_digest(matched[0])
            self.on_activity()
        return None

    def _control_authorized(self, headers: list[tuple[str, str]]) -> bool:
        values = [value for key, value in headers if key == "authorization"]
        if len(values) != 1 or not self._control_token:
            return False
        scheme, _, token = values[0].partition(" ")
        return scheme.lower() == "bearer" and secret_equals(token.encode("utf-8"), self._control_token)
