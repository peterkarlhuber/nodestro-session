"""Keeping secrets out of log records.

:class:`SecretRedactor` is a ``logging.Filter``. Add it to a logger (for example ``uvicorn.access``, which prints the
full request line) or to a handler. It replaces every registered secret and the values of the named query parameters
(``?token=...``) in the message and in its arguments. The parameter names match without regard to case and also
percent-encoded (``?Token=``, ``?%74oken=``, ``?token%3D...``), as a server may decode them either way. Formatters
such as uvicorn's ``AccessFormatter`` unpack the arguments, so they are kept as arguments, redacted.

Long-lived secrets (``lasting=True``: an access key, a control token) are kept until the process ends. Short-lived
ones (launch tokens, session IDs, CSRF values) share a bounded store where the oldest go first, so that a long-running
app does not grow without limit.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable
import logging
import re
import threading

REDACTED = "[redacted]"
_KEPT = 1024


def _encodable(name: str) -> str:
    """A pattern for ``name`` in which every character may also be percent-encoded (matched with IGNORECASE)."""
    parts = []
    for char in name:
        codes = {f"%{ord(variant):02x}" for variant in (char.lower(), char.upper()) if ord(variant) < 128}
        parts.append("(?:" + "|".join([re.escape(char), *sorted(codes)]) + ")")
    return "".join(parts)


class SecretRedactor(logging.Filter):
    """Replace registered secrets and ``query_params`` values with ``marker`` in every record it sees."""

    def __init__(
        self,
        secrets: Iterable[str] = (),
        *,
        query_params: Iterable[str] = ("token",),
        marker: str = REDACTED,
        kept: int = _KEPT,
    ) -> None:
        super().__init__()
        self.marker = marker
        self._kept = kept
        self._lasting: set[str] = set()
        self._recent: OrderedDict[str, None] = OrderedDict()
        self._lock = threading.Lock()
        names = [_encodable(name) for name in query_params if name]
        self._query = (
            re.compile(rf"((?:[?&;]|%3f|%26)(?:{'|'.join(names)})(?:=|%3d))[^&\s\"]*", re.IGNORECASE) if names else None
        )
        for secret in secrets:
            self.add(secret, lasting=True)

    def add(self, value: str, *, lasting: bool = False) -> None:
        """Redact ``value`` from now on (values shorter than 4 characters are ignored)."""
        if len(value) < 4:
            return
        with self._lock:
            if lasting:
                self._lasting.add(value)
                return
            self._recent[value] = None
            self._recent.move_to_end(value)
            while len(self._recent) > self._kept:
                self._recent.popitem(last=False)

    def redact(self, text: str) -> str:
        """``text`` without the registered secrets and the query parameter values."""
        if self._query is not None:
            text = self._query.sub(lambda match: match[1] + self.marker, text)
        with self._lock:
            values = [*self._lasting, *self._recent]
        # Longer values first, so that a secret that contains another one is replaced whole.
        for value in sorted(values, key=len, reverse=True):
            if value in text:
                text = text.replace(value, self.marker)
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = tuple(self.redact(arg) if isinstance(arg, str) else arg for arg in record.args)
        elif isinstance(record.args, dict):
            record.args = {key: self.redact(arg) if isinstance(arg, str) else arg for key, arg in record.args.items()}
        if isinstance(record.msg, str):
            record.msg = self.redact(record.msg)
        return True
