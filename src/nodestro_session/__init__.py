"""Protection of a single-user app that serves HTTP on loopback (``docs/design.md``).

The building blocks keep other web pages (DNS rebinding, cross-site requests), other local programs and other OS users
away from the app: loopback binding (:mod:`.bind`), the ``Host`` and origin rules (:mod:`.hosts`), one-time launch
tokens (:mod:`.tokens`), sessions with a CSRF value (:mod:`.sessions`), session cookies (:mod:`.cookies`), the ASGI
middleware that applies them (:mod:`.guard`), secrets from a pipe (:mod:`.handoff`), private state files
(:mod:`.private`) and log redaction (:mod:`.redact`). Standard library only.
"""

from __future__ import annotations

from ._version import __version__
from .bind import (
    LoopbackRequired,
    LoopbackSockets,
    PortUnavailableError,
    bind_loopback,
    loopback_refusals,
    random_loopback,
    require_loopback,
)
from .cookies import clear_cookie, cookie_name, cookie_values, set_cookie
from .guard import CONTENT_SECURITY_POLICY, REFUSALS, SECURITY_HEADERS, Refusal, SessionGuard, send_problem
from .handoff import HandoffError, read_secrets_fd
from .hosts import (
    FORWARDING_HEADERS,
    is_ip_address,
    is_loopback,
    listens_everywhere,
    loopback_origin,
    split_host,
    split_port,
)
from .private import (
    UnsafePathError,
    check_private_dir,
    ensure_private_dir,
    read_private_file,
    remove_file,
    write_private_file,
)
from .redact import SecretRedactor
from .sessions import SessionStore, session_digest
from .tokens import (
    Launch,
    LaunchTokens,
    Redemption,
    WeakSecretError,
    check_secret_length,
    redirect_file_pattern,
    redirect_page,
    secret_equals,
)

__all__ = [
    "CONTENT_SECURITY_POLICY",
    "FORWARDING_HEADERS",
    "REFUSALS",
    "SECURITY_HEADERS",
    "HandoffError",
    "Launch",
    "LaunchTokens",
    "LoopbackRequired",
    "LoopbackSockets",
    "PortUnavailableError",
    "Redemption",
    "Refusal",
    "SecretRedactor",
    "SessionGuard",
    "SessionStore",
    "UnsafePathError",
    "WeakSecretError",
    "__version__",
    "bind_loopback",
    "check_private_dir",
    "check_secret_length",
    "clear_cookie",
    "cookie_name",
    "cookie_values",
    "ensure_private_dir",
    "is_ip_address",
    "is_loopback",
    "listens_everywhere",
    "loopback_origin",
    "loopback_refusals",
    "random_loopback",
    "read_private_file",
    "read_secrets_fd",
    "redirect_file_pattern",
    "redirect_page",
    "remove_file",
    "require_loopback",
    "secret_equals",
    "send_problem",
    "session_digest",
    "set_cookie",
    "split_host",
    "split_port",
    "write_private_file",
]
