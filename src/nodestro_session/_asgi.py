"""The ASGI types this package uses (structurally the same as Starlette's), so that it needs no ASGI framework."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


def header_values(scope: Scope, name: str) -> list[str]:
    """Every value of the request header ``name`` (lower case), decoded as Latin-1, in order."""
    key = name.encode("latin-1")
    return [value.decode("latin-1") for found, value in scope.get("headers", []) if found.lower() == key]
