"""Loopback only: host names, bind addresses and the listening sockets (ported from nodestro-api
tests/test_local_access.py and Tabrion Studio tests/unit/test_server.py)."""

from __future__ import annotations

import errno
import ipaddress
import socket
import sys

import pytest

from nodestro_session import (
    LoopbackRequired,
    PortUnavailableError,
    bind_loopback,
    is_ip_address,
    is_loopback,
    listens_everywhere,
    loopback_origin,
    loopback_refusals,
    random_loopback,
    require_loopback,
    split_host,
    split_port,
)
from nodestro_session import bind as bind_module


def _ipv6_loopback_available() -> bool:
    if not socket.has_ipv6:
        return False
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
            probe.bind(("::1", 0))
    except OSError:
        return False
    return True


def _random_loopback_available() -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.61.7.8", 0))
    except OSError:
        return False
    return True


def test_loopback_names_and_host_headers() -> None:
    assert all(is_loopback(name) for name in ("localhost", "127.0.0.1", "127.4.5.6", "::1", "[::1]", "app.localhost"))
    assert not any(is_loopback(name) for name in ("evil.example", "192.168.1.20", "localhost.evil.example", ""))
    assert split_host("127.0.0.1:8000") == "127.0.0.1"
    assert split_host("[::1]:8000") == "::1"
    assert split_host("App.Example:443") == "app.example"
    assert split_port("127.0.0.1:8000") == 8000
    assert split_port("[::1]:8000") == 8000
    assert split_port("127.0.0.1") is None and split_port("[::1]") is None
    assert split_port("127.0.0.1:x") == -1 and split_port("127.0.0.1:123456") == -1
    assert all(is_ip_address(host) for host in ("192.168.1.20", "10.0.0.1", "::1", "[fe80::1]", "0.0.0.0"))
    assert not any(is_ip_address(host) for host in ("evil.example", "192.168.1.20.evil.example", "", "1.2.3"))
    assert all(listens_everywhere(bind) for bind in ("0.0.0.0", "::", "", "*"))
    assert not any(listens_everywhere(bind) for bind in (None, "127.0.0.1", "192.168.1.20"))
    assert loopback_origin(8080) == "http://127.0.0.1:8080"
    assert loopback_origin(8080, "::1") == "http://[::1]:8080"


NETWORK_BINDINGS = ("0.0.0.0", "::", "", "*", "192.168.1.20", "10.0.0.5", "fe80::1", "app.example", "werkstatt")


@pytest.mark.parametrize("host", NETWORK_BINDINGS)
def test_binding_to_the_network_is_refused(host: str) -> None:
    """Host and Origin checks are no login: listening anywhere but loopback is refused."""
    with pytest.raises(LoopbackRequired) as caught:
        require_loopback(host)
    assert caught.value.host == host
    assert caught.value.hosts == []
    with pytest.raises(LoopbackRequired):
        require_loopback(None)


@pytest.mark.parametrize("host", ("127.0.0.1", "127.0.0.2", "::1", "[::1]", "localhost", "LOCALHOST", "app.localhost"))
def test_loopback_addresses_are_accepted(host: str) -> None:
    require_loopback(host)
    assert loopback_refusals(host) == (False, [])


@pytest.mark.parametrize("names", (["app.example"], ["*"], ["app.localhost", "app.home.arpa"], ["10.0.0.5"]))
def test_reverse_proxy_host_names_are_refused(names: list[str]) -> None:
    """A proxy would pass the network through to the app, whatever address it forwards to."""
    with pytest.raises(LoopbackRequired) as caught:
        require_loopback("127.0.0.1", names)
    assert caught.value.hosts == [name for name in names if name != "app.localhost"]
    assert loopback_refusals("127.0.0.1", [" ", "localhost:8000", "[::1]"]) == (False, [])


def test_bind_loopback_holds_both_loopback_addresses() -> None:
    sockets = bind_loopback(0)
    try:
        host = sockets.listener.getsockname()[0]
        assert host == sockets.host
        assert ipaddress.IPv4Address(host) in ipaddress.IPv4Network("127.0.0.0/8")
        assert not sockets.listener.get_inheritable()
        if _ipv6_loopback_available():
            assert sockets.v6_guard is not None
            assert sockets.v6_guard.getsockname()[:2] == ("::1", sockets.port)
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as rival, pytest.raises(OSError):
                rival.bind(("::1", sockets.port))
        else:
            assert sockets.v6_guard is None
    finally:
        sockets.close()


def test_a_second_listener_cannot_take_over_the_port() -> None:
    sockets = bind_loopback(0, choose=lambda: "127.0.0.1")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as rival:
            # SO_REUSEADDR: on Windows it would share a port that is not held with SO_EXCLUSIVEADDRUSE.
            rival.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            with pytest.raises(OSError):
                rival.bind(("127.0.0.1", sockets.port))
                rival.listen()
        if hasattr(socket, "SO_REUSEPORT"):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as rival:
                rival.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                with pytest.raises(OSError):
                    rival.bind(("127.0.0.1", sockets.port))
                    rival.listen()
    finally:
        sockets.close()


def test_every_start_gets_a_fresh_loopback_address() -> None:
    """The origin of an instance is not predictable and not the one of an earlier instance."""
    if sys.platform.startswith("linux") or sys.platform == "win32":
        assert _random_loopback_available()
    if not _random_loopback_available():
        # macOS by default: only 127.0.0.1 exists, the documented fallback (design.md section 7).
        sockets = bind_loopback(0)
        try:
            assert sockets.host == "127.0.0.1"
        finally:
            sockets.close()
        return
    hosts = set()
    for _ in range(4):
        sockets = bind_loopback(0)
        try:
            hosts.add(sockets.host)
            assert sockets.host != "127.0.0.1"
        finally:
            sockets.close()
    assert len(hosts) == 4


def test_random_loopback_addresses() -> None:
    seen = {random_loopback() for _ in range(500)}
    assert "127.0.0.1" not in seen
    for address in seen:
        a, b, c = (int(part) for part in address.removeprefix("127.").split("."))
        assert 0 <= a <= 255 and 0 <= b <= 255 and 1 <= c <= 254
    assert len(seen) > 490  # 2**24 possibilities: practically no repeats


def test_a_fixed_port_taken_on_one_random_address_tries_another() -> None:
    if not _random_loopback_available():
        pytest.skip("needs a second loopback address (macOS has only 127.0.0.1)")
    with socket.create_server(("127.61.7.9", 0)) as busy:
        port = busy.getsockname()[1]
        choices = iter(["127.61.7.9", "127.61.7.10"])
        sockets = bind_loopback(port, choose=lambda: next(choices))
        try:
            assert (sockets.host, sockets.port) == ("127.61.7.10", port)
        finally:
            sockets.close()


def test_without_other_loopback_addresses_127_0_0_1_is_used(monkeypatch: pytest.MonkeyPatch) -> None:
    # macOS: binding an address that is not configured fails with EADDRNOTAVAIL; 127.0.0.1 is used then.
    real_bind = bind_module._bind_v4

    def bind(host: str, port: int) -> socket.socket:
        if host != "127.0.0.1":
            raise OSError(errno.EADDRNOTAVAIL, "Can't assign requested address")
        return real_bind(host, port)

    monkeypatch.setattr(bind_module, "_bind_v4", bind)
    sockets = bind_loopback(0)
    try:
        assert sockets.host == "127.0.0.1"
    finally:
        sockets.close()
    with socket.create_server(("127.0.0.1", 0)) as busy:
        port = busy.getsockname()[1]
        with pytest.raises(PortUnavailableError, match=f"cannot listen on 127.0.0.1:{port}"):
            bind_loopback(port)


def test_fixed_port_taken_on_ipv6_is_refused() -> None:
    if not _ipv6_loopback_available():
        sockets = bind_loopback(0)
        assert sockets.v6_guard is None
        sockets.close()
        return
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as rival:
        rival.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        rival.bind(("::1", 0))
        rival.listen()
        port = rival.getsockname()[1]
        with pytest.raises(PortUnavailableError, match=r"\[::1\] is used by another program"):
            bind_loopback(port)
        # The IPv4 port is free again afterwards.
        with socket.create_server(("127.0.0.1", port)):
            pass
