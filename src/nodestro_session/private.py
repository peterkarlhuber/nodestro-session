"""Private directories and files for state that holds secrets.

Directories are created with mode 0700 and files with mode 0600; symlinks are refused on every platform that
supports ``O_NOFOLLOW``.

An existing directory is checked, never repaired behind the user's back: one that another user owns, or that the
group or others may write to, is refused (:class:`UnsafePathError`), because another user may already have placed
files in it. Read and search bits for group and others are removed, since nothing secret has been written yet.

The parents count too (POSIX): a parent that another user (other than root) owns, or that the group or others may
write to without the sticky bit, lets that user rename the private directory away and put its own in its place, and
then replace the files written there (a redirect file with its own page). Such a path is refused, on the path as given
and on the path its symlinks resolve to; a symlink on the way must belong to the user or to root.

On Windows the modes are not enforced by the OS. There the directory and every one of its parents must not be a
symlink, junction or other reparse point. Whether the directory is inside the user's profile is decided on the path as
given (not on where it resolves to), and a directory outside the profile, or one whose resolved path differs from the
path as given, is accepted only if its access control list is private to the user (:mod:`nodestro_session._winsec`).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
import contextlib
import os
from pathlib import Path
import stat
import sys
import time
from typing import TypeVar

T = TypeVar("T")

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_BINARY = getattr(os, "O_BINARY", 0)
_POSIX = sys.platform != "win32"
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class UnsafePathError(RuntimeError):
    """A private path is a symlink or junction, belongs to another user or is accessible by others."""


def _retry_on_sharing_violation(action: Callable[[], T]) -> T:
    """Run ``action``; on Windows retry briefly while another process has the file open (sharing violation)."""
    for _ in range(20):
        try:
            return action()
        except PermissionError:
            if _POSIX:
                raise
            time.sleep(0.05)
    return action()


def _getuid() -> int:
    return os.getuid()  # type: ignore[attr-defined,unused-ignore]  # POSIX only


def ensure_private_dir(path: Path) -> Path:
    """Create ``path`` (and parents) with mode 0700 and check that only this user can use it.

    Raises :class:`UnsafePathError` for a symlink or junction, a directory owned by another user or one that the group
    or others may write to (POSIX), and on Windows for a directory outside the user's profile without a private ACL.
    """
    if _POSIX:
        # Before anything is created: a parent another user controls could swap what is created below it.
        _check_posix_parents(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if _POSIX:
        _check_posix_parents(path)
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or _is_reparse_point(info):
        raise UnsafePathError(f"the directory is not a plain directory: {path}")
    if _POSIX:
        if info.st_uid != _getuid():
            raise UnsafePathError(f"the directory belongs to another user: {path}")
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o022:
            raise UnsafePathError(
                f"the directory can be written by other users (mode {mode:o}): {path}; "
                "remove it or run chmod 700 on it after checking its content"
            )
        if mode != 0o700:
            os.chmod(path, 0o700)  # only read or search bits for others were set
    else:
        _check_windows_dir(path)
    return path


def check_private_dir(path: Path) -> None:
    """Check, without creating or changing it, that an existing ``path`` passes :func:`ensure_private_dir`'s rules.

    A missing ``path`` passes (nothing can be read from it). Raises :class:`UnsafePathError`.
    """
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or _is_reparse_point(info):
        raise UnsafePathError(f"the directory is not a plain directory: {path}")
    if _POSIX:
        if info.st_uid != _getuid():
            raise UnsafePathError(f"the directory belongs to another user: {path}")
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o022:
            raise UnsafePathError(f"the directory can be written by other users (mode {mode:o}): {path}")
        _check_posix_parents(path)
    else:
        _check_windows_dir(path)


def _check_posix_parents(path: Path) -> None:
    """Refuse a path with a parent that another user could use to swap the private directory (module docstring).

    Checked: every existing parent of the path as given (``lstat``; a symlink must belong to the user or root) and of
    the path its symlinks resolve to. Parents that do not exist yet are created by this user."""
    uid = _getuid()
    absolute = Path(os.path.abspath(path))
    resolved = Path(os.path.realpath(path))
    for folder in (*absolute.parents, *resolved.parents):
        try:
            info = os.lstat(folder)
        except FileNotFoundError:
            continue
        if info.st_uid not in (uid, 0):
            raise UnsafePathError(f"a parent directory belongs to another user: {folder}")
        if stat.S_ISLNK(info.st_mode):
            continue  # its target is a parent of the resolved path, checked as well
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o022 and not mode & stat.S_ISVTX:
            raise UnsafePathError(
                f"a parent directory can be written by other users without the sticky bit (mode {mode:o}): {folder}"
            )


def _is_reparse_point(info: os.stat_result) -> bool:
    """A Windows junction, mount point or other reparse point (``os.lstat`` does not report junctions as links)."""
    return bool(getattr(info, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT)


def is_within(path: Path, roots: Iterable[Path]) -> bool:
    """Whether ``path`` is one of ``roots`` or inside one (compared case-normalized, as Windows does)."""
    target = os.path.normcase(str(path))
    for root in roots:
        base = os.path.normcase(str(root)).rstrip("\\/")
        if base and (target == base or target.startswith(base + os.sep)):
            return True
    return False


def profile_roots() -> list[Path]:
    """The user's profile folders (Windows): ``%USERPROFILE%`` and ``%LOCALAPPDATA%``, as given and resolved."""
    roots: list[Path] = []
    for name in ("USERPROFILE", "LOCALAPPDATA"):
        value = os.environ.get(name)
        if value:
            roots += [Path(os.path.abspath(value)), Path(value).resolve()]
    return roots


def _check_windows_dir(path: Path) -> None:
    roots = profile_roots()
    absolute = Path(os.path.abspath(path))
    # The directory itself and every one of its parents must be plain directories: a junction anywhere on the way (also
    # above the profile, or in a parent outside it) could redirect the state into a folder that other users control.
    for folder in (absolute, *absolute.parents):
        try:
            info = os.lstat(folder)
        except FileNotFoundError:
            continue
        if _is_reparse_point(info):
            raise UnsafePathError(f"the directory path contains a junction or link: {folder}")
    # Inside the profile is decided on the path as given; a path that resolves somewhere else is checked like one
    # outside the profile (the ACL must be private), wherever it resolves to.
    resolved = path.resolve()
    if is_within(absolute, roots) and os.path.normcase(str(resolved)) == os.path.normcase(str(absolute)):
        return
    if sys.platform == "win32":
        from ._winsec import dacl_problem

        problem = dacl_problem(path)
        if problem is not None:
            raise UnsafePathError(
                f"the directory is outside your user profile and not private: {path} ({problem}); "
                "use a folder in your profile or restrict its access to your account"
            )


def write_private_file(path: Path, data: bytes) -> None:
    """Write ``data`` atomically to ``path`` with mode 0600 (temporary file in the same directory, then replace)."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with contextlib.suppress(FileNotFoundError):
        tmp.unlink()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _BINARY, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        _retry_on_sharing_violation(lambda: os.replace(tmp, path))
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise


def read_private_file(path: Path) -> bytes | None:
    """The content of ``path``, or None if it is missing. Raises :class:`UnsafePathError` for an unsafe file."""
    if not _NOFOLLOW and path.is_symlink():
        # Windows has no O_NOFOLLOW; the directory is per-user, so the check before opening suffices there.
        raise UnsafePathError(f"refusing to follow a symlink: {path}")
    try:
        fd = _retry_on_sharing_violation(lambda: os.open(path, os.O_RDONLY | _NOFOLLOW | _BINARY))
    except FileNotFoundError:
        return None
    except OSError as exc:
        if path.is_symlink():
            raise UnsafePathError(f"refusing to follow a symlink: {path}") from exc
        raise
    with os.fdopen(fd, "rb") as fh:
        info = os.fstat(fh.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise UnsafePathError(f"not a regular file: {path}")
        if _POSIX and (info.st_uid != _getuid() or stat.S_IMODE(info.st_mode) & 0o077):
            raise UnsafePathError(f"the file belongs to another user or is accessible by others: {path}")
        return fh.read()


def remove_file(path: Path) -> None:
    """Remove ``path`` if it exists."""
    with contextlib.suppress(FileNotFoundError):
        _retry_on_sharing_violation(path.unlink)
