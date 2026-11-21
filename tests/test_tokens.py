"""One-time launch tokens and redirect files (ported from Tabrion Studio's tests/security/test_launch.py)."""

from __future__ import annotations

from pathlib import Path
import re
import stat
import sys

import pytest

from nodestro_session import (
    LaunchTokens,
    WeakSecretError,
    check_secret_length,
    ensure_private_dir,
    redirect_file_pattern,
    redirect_page,
    secret_equals,
)
from nodestro_session.tokens import LAUNCH_TTL_SECONDS

POSIX = sys.platform != "win32"
LAUNCH_URL = re.compile(r"http://127\.\d{1,3}\.\d{1,3}\.\d{1,3}:(\d+)/launch#([A-Za-z0-9_-]{43})")


class Clock:
    now = 50.0

    def __call__(self) -> float:
        return self.now


def test_launch_tokens_and_redirect_files(tmp_path: Path) -> None:
    clock = Clock()
    ensure_private_dir(tmp_path / "s")
    launches = LaunchTokens("http://127.0.0.1:5000", tmp_path / "s", "app-k", clock=clock)
    plain = launches.issue(redirect=False)
    assert plain.redirect is None and LAUNCH_URL.fullmatch(plain.url)
    with_file = launches.issue(redirect=True)
    assert with_file.redirect is not None
    assert with_file.redirect.read_bytes() == redirect_page(with_file.url)
    assert redirect_file_pattern("app-k").fullmatch(with_file.redirect.name)
    if POSIX:
        assert stat.S_IMODE(with_file.redirect.stat().st_mode) == 0o600
    assert plain.url != with_file.url
    assert launches.redeem(with_file.url.rsplit("#", 1)[1]) == "ok"
    assert not with_file.redirect.exists()  # deleted once redeemed
    assert launches.redeem(with_file.url.rsplit("#", 1)[1]) == "used"
    expiring = launches.issue(redirect=True)
    clock.now += LAUNCH_TTL_SECONDS
    assert launches.sweep() == 2
    assert expiring.redirect is not None and not expiring.redirect.exists()  # deleted after the timeout
    assert launches.redeem(plain.url.rsplit("#", 1)[1]) == "expired"
    last = launches.issue(redirect=True)
    launches.close()
    assert last.redirect is not None and not last.redirect.exists()  # deleted when the server stops
    assert launches.redeem(last.url.rsplit("#", 1)[1]) == "expired"
    assert launches.pending == 0


def test_launch_token_works_once() -> None:
    launches = LaunchTokens("http://127.0.0.1:5000")
    token = launches.issue(redirect=False).url.rsplit("#", 1)[1]
    assert launches.redeem(token) == "ok"
    assert launches.redeem(token) == "used"
    assert launches.redeem(token) == "used"


def test_launch_token_expires() -> None:
    clock = Clock()
    launches = LaunchTokens("http://127.0.0.1:5000", ttl=10, clock=clock)
    token = launches.issue(redirect=False).url.rsplit("#", 1)[1]
    clock.now += 10
    assert launches.redeem(token) == "expired"
    assert launches.redeem(token) == "expired"


@pytest.mark.parametrize(
    "token", ["", "x" * 43, "a" * 42, "a" * 44, None, 5, ["a" * 43], "../../etc/passwd", "a" * 42 + "="]
)
def test_malformed_tokens_are_invalid(token: object) -> None:
    launches = LaunchTokens("http://127.0.0.1:5000")
    launches.issue(redirect=False)
    assert launches.redeem(token) == "invalid"
    assert launches.pending == 1


def test_the_token_is_in_the_fragment_and_only_its_digest_is_kept() -> None:
    registered: list[str] = []
    launches = LaunchTokens("http://127.0.0.1:5000/", path="/start", on_secret=registered.append)
    url = launches.issue(redirect=False).url
    base, _, token = url.partition("#")
    assert base == "http://127.0.0.1:5000/start" and "?" not in url
    assert registered == [token]
    kept = repr(vars(launches))
    assert token not in kept


def test_a_redirect_needs_a_directory() -> None:
    with pytest.raises(RuntimeError, match="no directory"):
        LaunchTokens("http://127.0.0.1:5000").issue(redirect=True)


def test_redirect_page_escapes_the_url_and_the_name() -> None:
    page = redirect_page('http://127.0.0.1:1/launch#a"><script>x</script>', name="<b>App</b>").decode()
    assert "<script>" not in page and "&quot;" in page and "<b>" not in page
    assert '<meta name="referrer" content="no-referrer">' in page


def test_redirect_page_names_the_app() -> None:
    page = redirect_page("http://127.0.0.1:1/launch#x", name="Example App")
    assert page.endswith(
        b"<title>Example App</title></head><body><p>Opening Example App\xe2\x80\xa6</p></body></html>\n"
    )


def test_secret_equals() -> None:
    assert secret_equals("a" * 43, "a" * 43)
    assert secret_equals(b"key", "key")
    assert not secret_equals("a" * 43, "a" * 42 + "b")
    assert not secret_equals("", "x")
    assert not secret_equals("ä", "a")


def test_short_secrets_are_refused() -> None:
    check_secret_length(None)
    check_secret_length("s" * 32)
    with pytest.raises(WeakSecretError) as caught:
        check_secret_length("short")
    assert (caught.value.length, caught.value.minimum) == (5, 32)
    with pytest.raises(WeakSecretError):
        check_secret_length("s" * 40, minimum=43)


# Review N-02 L4: the pending tokens stay bounded; issue() sweeps expired ones and drops the oldest beyond the cap.


def test_pending_tokens_are_bounded_and_the_oldest_is_dropped_with_its_file(tmp_path: Path) -> None:
    from nodestro_session.tokens import MAX_PENDING

    ensure_private_dir(tmp_path / "s")
    launches = LaunchTokens("http://127.0.0.1:5000", tmp_path / "s", "app-k")
    first = launches.issue(redirect=True)
    issued = [launches.issue(redirect=False) for _ in range(MAX_PENDING * 3)]
    assert launches.pending == MAX_PENDING
    assert first.redirect is not None and not first.redirect.exists()  # dropped, and its file deleted
    assert launches.redeem(first.url.rsplit("#", 1)[1]) == "expired"
    assert launches.redeem(issued[-1].url.rsplit("#", 1)[1]) == "ok"
    many = LaunchTokens("http://127.0.0.1:1")
    for _ in range(5000):
        many.issue(redirect=False)
    assert many.pending == MAX_PENDING


def test_issue_sweeps_expired_tokens(tmp_path: Path) -> None:
    clock = Clock()
    ensure_private_dir(tmp_path / "s")
    launches = LaunchTokens("http://127.0.0.1:5000", tmp_path / "s", "app-k", clock=clock, max_pending=8)
    old = launches.issue(redirect=True)
    clock.now += LAUNCH_TTL_SECONDS
    launches.issue(redirect=False)
    assert launches.pending == 1
    assert old.redirect is not None and not old.redirect.exists()
    with pytest.raises(ValueError):
        LaunchTokens("http://127.0.0.1:5000", max_pending=0)


@pytest.mark.skipif(not POSIX, reason="POSIX modes")
def test_issue_checks_the_redirect_directory_again(tmp_path: Path) -> None:
    from nodestro_session import UnsafePathError

    state = ensure_private_dir(tmp_path / "s")
    launches = LaunchTokens("http://127.0.0.1:5000", state, "app-k")
    state.chmod(0o777)  # swapped or opened since it was created
    with pytest.raises(UnsafePathError):
        launches.issue(redirect=True)
    assert list(state.iterdir()) == []
    assert launches.pending == 0
