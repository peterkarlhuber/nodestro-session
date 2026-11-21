"""Session cookies: port namespace, fixed flags, every value of a name, no header injection."""

from __future__ import annotations

import pytest

from nodestro_session import clear_cookie, cookie_name, cookie_values, set_cookie


def test_the_cookie_name_holds_the_port() -> None:
    assert cookie_name("app_session_", 8080) == "app_session_8080"
    assert cookie_name("app_session") == "app_session"
    assert cookie_name("app_session_", 8080) != cookie_name("app_session_", 8081)
    for bad in ("", "a b", "a;b", "a=b", "ä"):
        with pytest.raises(ValueError):
            cookie_name(bad)


def test_the_flags_are_fixed() -> None:
    assert set_cookie("s", "v") == "s=v; HttpOnly; SameSite=Strict; Path=/"
    assert set_cookie("s", "v", max_age=86400.5) == "s=v; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400"
    assert set_cookie("s", "v", secure=True).endswith("; Secure")
    assert clear_cookie("s") == "s=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"


@pytest.mark.parametrize("value", ["a;b", "a b", "a,b", 'a"b', "a\\b", "a\r\nSet-Cookie: x=1", "ä"])
def test_values_cannot_inject_attributes_or_headers(value: str) -> None:
    with pytest.raises(ValueError):
        set_cookie("s", value)
    with pytest.raises(ValueError):
        set_cookie(value, "v")


def test_every_value_of_the_name_is_read() -> None:
    # Ported from Tabrion Studio (test_session_cookie_parsing): another local server may have set a second cookie.
    name = "app_session_1234"
    headers = [("cookie", f"a=1; {name}=one; b=2"), ("cookie", f'{name}="two"'), ("x", f"{name}=three")]
    assert cookie_values(headers, name) == ["one", "two"]
    assert cookie_values([("cookie", f"{name}x=1; {name}")], name) == []
    raw = [(b"cookie", f"{name}=one".encode()), (b"Cookie", f"{name}=two".encode())]
    assert cookie_values(raw, name) == ["one", "two"]
