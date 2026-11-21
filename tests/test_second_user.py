"""A second OS user gets no access: the redirect file is 0600 in a 0700 directory (Linux CI, job "second user").

Runs only when ``NODESTRO_SESSION_OTHER_USER`` names another local user that ``sudo -n -u`` can switch to; CI creates
one. A positive control first shows that the other user can read a world-readable file in the same place, so a
refusal below is the file mode at work, not a broken setup.
"""

from __future__ import annotations

from collections.abc import Iterator
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import pytest

from nodestro_session import LaunchTokens, SessionStore, ensure_private_dir, write_private_file

OTHER = os.environ.get("NODESTRO_SESSION_OTHER_USER", "")
pytestmark = pytest.mark.skipif(
    not OTHER or not sys.platform.startswith("linux"), reason="needs a second OS user (NODESTRO_SESSION_OTHER_USER)"
)


def as_other(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["sudo", "-n", "-u", OTHER, *args], capture_output=True, text=True, check=False)


@pytest.fixture
def shared() -> Iterator[Path]:
    """A directory that every user may enter (``tmp_path`` is private to the test user)."""
    base = Path(tempfile.mkdtemp(prefix="session-second-user-"))
    os.chmod(base, 0o755)
    try:
        yield base
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_the_setup_works(shared: Path) -> None:
    public = shared / "public.txt"
    public.write_text("public", encoding="utf-8")
    os.chmod(public, 0o644)
    seen = as_other("cat", str(public))
    assert seen.returncode == 0, seen.stderr
    assert seen.stdout == "public"
    assert as_other("id", "-un").stdout.strip() == OTHER


def test_the_other_user_cannot_read_the_redirect_file(shared: Path) -> None:
    state = ensure_private_dir(shared / "state")
    launches = LaunchTokens("http://127.0.0.1:5000", state, "app")
    launch = launches.issue(redirect=True)
    assert launch.redirect is not None
    token = launch.url.rsplit("#", 1)[1]
    for command in (("cat", str(launch.redirect)), ("ls", str(state))):
        refused = as_other(*command)
        assert refused.returncode != 0
        assert token not in refused.stdout
    # Even in a directory the other user may enter, the 0600 file itself stays closed.
    os.chmod(state, 0o711)
    refused = as_other("cat", str(launch.redirect))
    assert refused.returncode != 0 and "Permission denied" in refused.stderr
    assert token not in refused.stdout
    # And the token is useless to anyone who saw it after it was redeemed.
    assert launches.redeem(token) == "ok"
    assert not launch.redirect.exists()


def test_the_other_user_cannot_read_private_state(shared: Path) -> None:
    state = ensure_private_dir(shared / "state")
    session_id, _ = SessionStore().create()
    write_private_file(state / "secret", session_id.encode())
    os.chmod(state, 0o711)
    refused = as_other("cat", str(state / "secret"))
    assert refused.returncode != 0
    assert session_id not in refused.stdout
