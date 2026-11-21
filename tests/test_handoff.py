"""Secrets through an inherited pipe (ported from nodestro-api tests/test_handoff.py)."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest

from nodestro_session import HandoffError, read_secrets_fd
from nodestro_session.handoff import MAX_BYTES

SECRET = b'{"launch_secret": "' + b"a1" * 32 + b'"}'


def pipe_with(payload: bytes) -> int:
    """The read end of a pipe that holds ``payload``; the write end is closed."""
    read_end, write_end = os.pipe()
    os.write(write_end, payload)
    os.close(write_end)
    return read_end


def closed(fd: int) -> bool:
    try:
        os.fstat(fd)
    except OSError:
        return True
    return False


def test_the_payload_is_read_and_the_descriptor_closed() -> None:
    fd = pipe_with(SECRET)
    assert read_secrets_fd(fd) == SECRET
    assert closed(fd)


def test_a_missing_or_unusable_descriptor_is_refused() -> None:
    fd = pipe_with(SECRET)
    os.close(fd)
    for unusable in (fd, 1, 2, -1):
        with pytest.raises(HandoffError) as caught:
            read_secrets_fd(unusable)
        assert "descriptor" in caught.value.reason


def test_an_oversized_payload_is_refused_and_the_descriptor_still_closed(tmp_path: Path) -> None:
    big = tmp_path / "big"
    big.write_bytes(b" " * (MAX_BYTES + 1))
    fd = os.open(big, os.O_RDONLY)
    with pytest.raises(HandoffError, match="more than"):
        read_secrets_fd(fd)
    assert closed(fd)
    small = pipe_with(b"x" * 11)
    with pytest.raises(HandoffError, match="more than 10 bytes"):
        read_secrets_fd(small, max_bytes=10)


def test_the_refusal_never_quotes_the_payload(tmp_path: Path) -> None:
    big = tmp_path / "big"
    big.write_bytes(SECRET * 2000)
    fd = os.open(big, os.O_RDONLY)
    with pytest.raises(HandoffError) as caught:
        read_secrets_fd(fd)
    assert b"a1a1".decode() not in str(caught.value)


@pytest.mark.skipif(sys.platform == "win32", reason="standard input as a pipe in a child process (POSIX shell)")
def test_standard_input_is_replaced_by_the_null_device() -> None:
    # In a child process: descriptor 0 is a pipe with the secret; afterwards it reads as empty and is no pipe.
    script = textwrap.dedent(
        """
        import os, stat, sys
        from nodestro_session import read_secrets_fd
        data = read_secrets_fd(0)
        assert data == sys.argv[1].encode(), data
        assert not stat.S_ISFIFO(os.fstat(0).st_mode)
        assert os.read(0, 10) == b""
        print("ok")
        """
    )
    src = str(Path(__file__).resolve().parents[1] / "src")
    env = {**os.environ, "PYTHONPATH": src + os.pathsep + os.environ.get("PYTHONPATH", "")}
    done = subprocess.run(
        [sys.executable, "-c", script, "payload"], input=b"payload", capture_output=True, env=env, check=False
    )
    assert done.returncode == 0, done.stderr.decode()
    assert done.stdout.strip() == b"ok"
