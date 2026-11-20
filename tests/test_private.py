"""Private directories and files (ported from Tabrion Studio tests/unit/test_paths.py)."""

from __future__ import annotations

import os
from pathlib import Path
import secrets
import shutil
import stat
import subprocess
import sys

import pytest

from nodestro_session import (
    UnsafePathError,
    check_private_dir,
    ensure_private_dir,
    read_private_file,
    remove_file,
    write_private_file,
)
from nodestro_session import private as paths

POSIX = sys.platform != "win32"


def test_private_dir_and_file(tmp_path: Path) -> None:
    folder = ensure_private_dir(tmp_path / "a" / "state")
    target = folder / "info.json"
    write_private_file(target, b"one")
    write_private_file(target, b"two")  # replaces atomically
    assert read_private_file(target) == b"two"
    assert [p.name for p in folder.iterdir()] == ["info.json"]  # no temporary file left
    if POSIX:
        assert stat.S_IMODE(os.stat(folder).st_mode) == 0o700
        assert stat.S_IMODE(os.stat(target).st_mode) == 0o600


def test_missing_file_reads_as_none(tmp_path: Path) -> None:
    assert read_private_file(tmp_path / "missing") is None
    remove_file(tmp_path / "missing")  # no error
    check_private_dir(tmp_path / "missing")  # nothing to read from it


def test_existing_dir_readable_by_others_is_tightened(tmp_path: Path) -> None:
    # Nothing secret is in it yet, and nobody else could have written to it: removing the read bits is safe.
    folder = tmp_path / "loose"
    folder.mkdir()
    os.chmod(folder, 0o755)
    ensure_private_dir(folder)
    if POSIX:
        assert stat.S_IMODE(os.stat(folder).st_mode) == 0o700


@pytest.mark.parametrize("mode", [0o777, 0o775, 0o757, 0o720, 0o702])
def test_existing_dir_writable_by_others_is_refused(tmp_path: Path, mode: int) -> None:
    # Another user may already have placed files in it: refused instead of tightened.
    folder = tmp_path / "shared"
    folder.mkdir()
    os.chmod(folder, mode)
    if POSIX:
        with pytest.raises(UnsafePathError, match="written by other users"):
            ensure_private_dir(folder)
        with pytest.raises(UnsafePathError, match="written by other users"):
            check_private_dir(folder)
        assert stat.S_IMODE(os.stat(folder).st_mode) == mode  # left as it was
    else:
        # Windows ignores POSIX modes (only the read-only flag); its ACL checks are tested below.
        os.chmod(folder, 0o777)
        ensure_private_dir(folder)


def test_dir_of_another_user_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    folder = tmp_path / "theirs"
    folder.mkdir(mode=0o700)
    if POSIX:
        owner = os.stat(folder).st_uid
        monkeypatch.setattr(os, "getuid", lambda: owner + 1)
        with pytest.raises(UnsafePathError, match="belongs to another user"):
            ensure_private_dir(folder)
        with pytest.raises(UnsafePathError, match="belongs to another user"):
            check_private_dir(folder)
    else:
        assert ensure_private_dir(folder) == folder


def test_file_of_another_user_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "file"
    write_private_file(target, b"x")
    if POSIX:
        owner = os.stat(target).st_uid
        monkeypatch.setattr(os, "getuid", lambda: owner + 1)
        with pytest.raises(UnsafePathError, match="another user"):
            read_private_file(target)


def test_is_within() -> None:
    root = Path(os.path.abspath("profile-root"))
    assert paths.is_within(root, [root])
    assert paths.is_within(root / "a" / "b", [root])
    assert not paths.is_within(Path(str(root) + "-other"), [root])
    assert not paths.is_within(root.parent, [root])
    assert not paths.is_within(root / "a", [])
    assert paths.is_within(root / "a", [Path("/nowhere"), root])


def test_reparse_points_are_detected(tmp_path: Path) -> None:
    class Info:
        st_file_attributes = 0x400

    assert paths._is_reparse_point(Info())  # type: ignore[arg-type]
    assert not paths._is_reparse_point(os.lstat(tmp_path))


def test_profile_roots(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "home" / "AppData" / "Local"))
    roots = paths.profile_roots()
    assert Path(os.path.abspath(tmp_path / "home")) in roots
    assert paths.is_within(tmp_path / "home" / "AppData" / "Local" / "app", roots)
    monkeypatch.delenv("USERPROFILE")
    monkeypatch.delenv("LOCALAPPDATA")
    assert paths.profile_roots() == []


def _run(*args: str) -> None:
    subprocess.run(list(args), check=True, capture_output=True, text=True)


def test_windows_dir_outside_the_profile_needs_a_private_acl(tmp_path: Path) -> None:
    # POSIX has no profile rule (modes and owner are checked instead); a folder outside the home directory is fine.
    if POSIX:
        assert ensure_private_dir(tmp_path / "anywhere") == tmp_path / "anywhere"
        return
    drive = Path(os.environ.get("SYSTEMDRIVE", "C:") + "\\")
    outside = drive / f"session-test-{secrets.token_hex(4)}"
    try:
        # The drive root's ACL differs between machines, so grant BUILTIN Users read access explicitly: every local
        # user could then read the secrets.
        outside.mkdir()
        _run("icacls", str(outside), "/grant", "*S-1-5-32-545:(OI)(CI)RX")
        with pytest.raises(UnsafePathError, match="outside your user profile and not private"):
            ensure_private_dir(outside)
        # Owner-only: no inheritance, no Users entry, full control for the current user.
        _run("icacls", str(outside), "/remove:g", "*S-1-5-32-545")
        _run("icacls", str(outside), "/inheritance:r", "/grant:r", f"{os.environ['USERNAME']}:(OI)(CI)F")
        assert ensure_private_dir(outside) == outside
        _run("icacls", str(outside), "/grant", "*S-1-5-11:(OI)(CI)M")  # Authenticated Users: modify
        with pytest.raises(UnsafePathError, match="grants access to S-1-5-11"):
            ensure_private_dir(outside)
    finally:
        shutil.rmtree(outside, ignore_errors=True)


def test_windows_junction_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "junction"
    if POSIX:
        link.symlink_to(target, target_is_directory=True)  # the POSIX counterpart of a junction
        with pytest.raises(UnsafePathError, match="not a plain directory"):
            ensure_private_dir(link)
        return
    _run("cmd", "/c", "mklink", "/J", str(link), str(target))
    with pytest.raises(UnsafePathError, match=r"not a plain directory|junction"):
        ensure_private_dir(link)
    with pytest.raises(UnsafePathError, match="junction or link"):
        ensure_private_dir(link / "state")


def test_files_accessible_by_others_are_refused_on_posix(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.write_bytes(b"x")
    os.chmod(real, 0o644)
    if POSIX:
        with pytest.raises(UnsafePathError, match="accessible by others"):
            read_private_file(real)
    else:
        # Windows has no POSIX modes; the per-user profile ACL of the directory protects the file.
        assert read_private_file(real) == b"x"


def test_symlinks_are_refused(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.write_bytes(b"x")
    os.chmod(real, 0o600)
    link = tmp_path / "link"
    linked_dir = tmp_path / "linked"
    link.symlink_to(real)  # GitHub's Windows runners allow symlinks (administrator)
    linked_dir.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(UnsafePathError, match="symlink"):
        read_private_file(link)
    with pytest.raises(UnsafePathError, match="not a plain directory"):
        ensure_private_dir(linked_dir)
