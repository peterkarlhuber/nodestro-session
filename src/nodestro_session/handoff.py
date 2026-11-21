"""Secrets from a launcher through an inherited pipe, never through the command line or the environment.

Any process of the same OS user can read another process's initial command line and environment: on Linux in
``/proc/<pid>/cmdline`` and ``/proc/<pid>/environ``, on macOS with ``sysctl`` ``KERN_PROCARGS2``, on Windows through
WMI. Removing a variable from ``os.environ`` later does not change what they show. So a launcher starts the app with
a pipe on a descriptor (standard input, or 3 and higher on POSIX), writes the secrets and closes its end.

:func:`read_secrets_fd` is the first thing the app does with it: it makes the descriptor non-inheritable, reads it to
its end (at most ``max_bytes``) and closes it. Descriptor 0 is replaced by the null device, so no process the app
starts inherits the pipe. The format of the payload is the product's (for example one JSON object).
"""

from __future__ import annotations

import contextlib
import os

#: A handoff is a few hundred bytes; anything much larger is refused.
MAX_BYTES = 64 * 1024


class HandoffError(ValueError):
    """The descriptor cannot be used. ``reason`` never quotes what was read: it holds secrets."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def read_secrets_fd(fd: int, *, max_bytes: int = MAX_BYTES) -> bytes:
    """Read and close descriptor ``fd`` and return what it held; descriptor 0 is replaced by the null device.

    The descriptor is made non-inheritable before anything else, so a process started while it is read cannot get it
    either. It is closed also when what it held is refused."""
    if fd in (1, 2) or fd < 0:
        raise HandoffError("the descriptor must be 0 (standard input) or 3 and higher")
    try:
        os.set_inheritable(fd, False)
    except OSError as error:
        raise HandoffError(f"descriptor {fd} is not open ({error.strerror})") from None
    chunks: list[bytes] = []
    size = 0
    try:
        while True:
            chunk = os.read(fd, 8192)
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                raise HandoffError(f"more than {max_bytes} bytes")
            chunks.append(chunk)
    except OSError as error:
        raise HandoffError(f"descriptor {fd} cannot be read ({error.strerror})") from None
    finally:
        _release(fd)
    return b"".join(chunks)


def _release(fd: int) -> None:
    if fd == 0:
        # Standard input stays a valid descriptor (the null device) for everything that expects one.
        null = os.open(os.devnull, os.O_RDONLY)
        try:
            os.dup2(null, 0)
        finally:
            os.close(null)
        return
    with contextlib.suppress(OSError):
        os.close(fd)
