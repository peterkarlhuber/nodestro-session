"""Sessions: digests only, bounded, CSRF bound to its session, idle time and max age, logout."""

from __future__ import annotations

import pytest

from nodestro_session import SessionStore, session_digest


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_sessions_are_bounded() -> None:
    sessions = SessionStore(max_sessions=2)
    first = sessions.create()
    second = sessions.create()
    third = sessions.create()
    assert not sessions.check(*first)
    assert sessions.check(*second) and sessions.check(*third)
    assert not sessions.check(second[0], third[1])
    assert not sessions.check(None, None) and not sessions.check("x" * 200, second[1])
    assert not sessions.check(second[0], "x" * 200)
    with pytest.raises(ValueError):
        SessionStore(max_sessions=0)


def test_only_digests_are_kept() -> None:
    registered: list[str] = []
    sessions = SessionStore(on_secret=registered.append)
    session_id, csrf = sessions.create()
    assert registered == [session_id, csrf]
    assert session_id not in repr(vars(sessions))
    assert sessions.known(session_id) and not sessions.known(session_id[:-1]) and not sessions.known(None)
    assert session_digest(session_id) != session_id and len(session_digest(session_id)) == 64


def test_every_session_gets_new_values() -> None:
    sessions = SessionStore()
    values = [value for _ in range(50) for value in sessions.create()]
    assert len(set(values)) == 100
    assert all(len(value) == 43 for value in values)


def test_a_session_ends_after_the_idle_time() -> None:
    # Ported from nodestro-api tests/test_local_container.py (eight idle hours).
    clock = Clock()
    sessions = SessionStore(idle=8 * 3600, max_age=24 * 3600, clock=clock)
    session_id, csrf = sessions.create()
    clock.now += 7.9 * 3600
    assert sessions.known(session_id)
    clock.now += 7.9 * 3600
    assert sessions.check(session_id, csrf)
    clock.now += 8.1 * 3600
    assert not sessions.known(session_id)
    clock.now -= 8.1 * 3600  # an ended session does not come back
    assert not sessions.known(session_id)
    assert len(sessions) == 0


def test_a_session_ends_at_its_max_age_although_it_is_used() -> None:
    clock = Clock()
    sessions = SessionStore(idle=8 * 3600, max_age=24 * 3600, clock=clock)
    session_id, csrf = sessions.create()
    for _ in range(4):
        clock.now += 6 * 3600
        assert sessions.check(session_id, csrf)
    clock.now += 60
    assert not sessions.check(session_id, csrf)


def test_a_look_without_touch_is_no_activity() -> None:
    clock = Clock()
    sessions = SessionStore(idle=10, clock=clock)
    session_id, _ = sessions.create()
    clock.now = 9
    assert sessions.known(session_id, touch=False)
    assert not sessions.check(session_id, "wrong")  # a failed check is no activity either
    clock.now = 11
    assert not sessions.known(session_id)


def test_end_and_end_all() -> None:
    sessions = SessionStore()
    first, _ = sessions.create()
    second, _ = sessions.create()
    assert sessions.end(first) and not sessions.end(first) and not sessions.end(None)
    assert not sessions.known(first) and sessions.known(second)
    sessions.create()
    assert sessions.end_all() == 2
    assert not sessions.known(second) and len(sessions) == 0
