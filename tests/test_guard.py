"""Attack cases against SessionGuard, ported from Tabrion Studio's tests/security/test_access.py.

Each group names the threat of docs/design.md section 3. The product of tests/app.py runs in process on port 1234.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from nodestro_session import CONTENT_SECURITY_POLICY, SECURITY_HEADERS, SessionGuard, SessionStore
from nodestro_session.guard import REFUSALS, Refusal

from .app import (
    CONTROL_AUTH,
    COOKIE,
    CSRF_HEADER,
    EXPECTED_SECURITY_HEADERS,
    HOST,
    ORIGIN,
    PORT,
    TOKEN,
    Product,
    make_product,
)

#: A test client answer (Starlette's client uses httpx2 or httpx).
Answer = Any

# Every route of the app, with a body where the route takes one (the Host allowlist applies to all of them).
ROUTES: list[tuple[str, str]] = [
    ("GET", "/"),
    ("GET", "/launch"),
    ("GET", "/assets/app.js"),
    ("GET", "/api/health"),
    ("GET", "/api/heartbeat"),
    ("GET", "/api/openapi.json"),
    ("GET", "/api/control/proof"),
    ("POST", "/api/control/launch"),
    ("POST", "/api/control/shutdown"),
    ("POST", "/api/session"),
]
FOREIGN_HOSTS = [
    "evil.example",
    f"evil.example:{PORT}",
    f"127.0.0.1.nip.io:{PORT}",  # a DNS name that resolves to 127.0.0.1 (DNS rebinding)
    f"localhost:{PORT}",  # only the origin's own address is answered
    f"[::1]:{PORT}",
    f"localhost.:{PORT}",
    "127.0.0.1",  # no port
    f"127.0.0.1:{PORT + 1}",
    f"127.0.0.2:{PORT}",
    f"0.0.0.0:{PORT}",
    f"127.0.0.1:{PORT}.evil.example",
    f"127.0.0.1:{PORT}@evil.example",
    f"2130706433:{PORT}",  # 127.0.0.1 as a single number
]


def _assert_refused(response: Answer, status: int, code: str) -> None:
    assert response.status_code == status, response.text
    assert response.json()["code"] == code
    _assert_security_headers(response)


def _assert_security_headers(response: Answer) -> None:
    for name, value in EXPECTED_SECURITY_HEADERS.items():
        assert response.headers.get_list(name) == [value], name


def _signed_in_headers(product: Product) -> dict[str, str]:
    return {**product.sign_in(), "Origin": ORIGIN}


def _request(product: Product, method: str, path: str, headers: dict[str, str]) -> Answer:
    if method == "POST":
        body: dict[str, object] = {"token": product.launch_token()} if path == "/api/session" else {}
        return product.client.request(method, path, headers=headers, json=body)
    return product.client.request(method, path, headers=headers)


async def _noop_app(scope: Any, receive: Any, send: Any) -> None:
    raise AssertionError("not used")


def _asgi_status(
    headers: list[tuple[bytes, bytes]], path: str = "/api/health", method: str = "GET", **options: Any
) -> int:
    """Run the guard on a raw ASGI scope; 0 if the request reached the app, else the refusal's status."""
    reached: list[str] = []
    sent: list[dict[str, Any]] = []

    async def app(scope: Any, receive: Any, send: Any) -> None:
        reached.append("app")

    async def send(message: Any) -> None:
        sent.append(message)

    async def receive() -> Any:
        return {"type": "http.request", "body": b""}

    settings: dict[str, Any] = {
        "origin": ORIGIN,
        "sessions": SessionStore(),
        "cookie": COOKIE,
        "open_paths": {"/api/health"},
        "control_prefix": "/api/control/",
        "control_token": TOKEN,
        "control_open_paths": {"/api/control/proof"},
        **options,
    }
    guard = SessionGuard(app, **settings)
    scope = {"type": "http", "method": method, "path": path, "headers": headers}
    asyncio.run(guard(scope, receive, send))
    return 0 if reached else int(sent[0]["status"])


# ---------------------------------------------------------------------------------------------------------------------
# T1: Host allowlist on every route, DNS rebinding
# ---------------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("host", FOREIGN_HOSTS)
@pytest.mark.parametrize(("method", "path"), ROUTES)
def test_host_allowlist_on_every_route(method: str, path: str, host: str) -> None:
    # Valid control token, valid session and the page's own Origin: only the Host is wrong.
    product = make_product()
    headers = {**CONTROL_AUTH, **_signed_in_headers(product)} if "/control/" not in path else dict(CONTROL_AUTH)
    sessions = len(product.sessions)
    response = _request(product, method, path, {**headers, "Host": host})
    _assert_refused(response, 403, "host_not_allowed")
    assert product.shutdowns == []
    assert len(product.sessions) == sessions


@pytest.mark.parametrize(("method", "path"), ROUTES)
def test_the_own_host_is_answered(method: str, path: str) -> None:
    product = make_product()
    headers = dict(CONTROL_AUTH) if "/control/" in path else _signed_in_headers(product)
    response = _request(product, method, path, headers)
    assert response.status_code in (200, 202, 204), response.text
    _assert_security_headers(response)


def test_dns_rebinding_page_cannot_read_the_api() -> None:
    # A page of evil.example that rebinds its name to 127.0.0.1 is same-origin to itself and sends its own Host.
    product = make_product()
    for path in ("/api/health", "/api/openapi.json", "/api/heartbeat", "/"):
        response = product.client.get(path, headers={"Host": f"evil.example:{PORT}", "Sec-Fetch-Site": "same-origin"})
        _assert_refused(response, 403, "host_not_allowed")
        assert "openapi" not in response.text


def test_missing_or_duplicate_host_is_refused() -> None:
    own = (b"host", HOST.encode())
    assert _asgi_status([own]) == 0  # reaches the app
    assert _asgi_status([]) == 403
    assert _asgi_status([own, (b"host", b"evil.example")]) == 403
    assert _asgi_status([own, own]) == 403


def test_a_random_loopback_address_answers_only_that_address() -> None:
    """The Host and Origin allowlist is exactly the instance's own ``127.a.b.c:<port>``, nothing else."""
    origin = f"http://127.45.6.7:{PORT}"

    def status(host: str, origin_header: str | None = None) -> int:
        headers = [(b"host", host.encode())]
        if origin_header is not None:
            headers.append((b"origin", origin_header.encode()))
        return _asgi_status(headers, origin=origin)

    assert status(f"127.45.6.7:{PORT}") == 0
    assert status(f"127.45.6.7:{PORT}", f"http://127.45.6.7:{PORT}") == 0
    for other in ("127.0.0.1", "127.45.6.8", "127.0.0.2", "localhost", "[::1]"):
        assert status(f"{other}:{PORT}") == 403, other
        assert status(f"127.45.6.7:{PORT}", f"http://{other}:{PORT}") == 403, other


@pytest.mark.parametrize(
    "origin",
    [
        "http://evil.example:80",
        "http://192.168.1.10:8080",
        "http://127.0.0.1",
        "ftp://127.0.0.1:1",
        "http://127.0.0.1:1/x",
    ],
)
def test_the_guard_only_serves_a_loopback_origin(origin: str) -> None:
    with pytest.raises(ValueError, match="origin"):
        SessionGuard(_noop_app, origin=origin, sessions=SessionStore(), cookie=COOKIE)


def test_websockets_are_refused() -> None:
    sent: list[Any] = []

    async def send(message: Any) -> None:
        sent.append(message)

    async def receive() -> Any:
        return {"type": "websocket.connect"}

    guard = SessionGuard(_noop_app, origin=ORIGIN, sessions=SessionStore(), cookie=COOKIE)
    scope = {"type": "websocket", "path": "/api/events", "headers": [(b"host", HOST.encode())]}
    asyncio.run(guard(scope, receive, send))
    assert sent == [{"type": "websocket.close", "code": 1008}]


def test_lifespan_passes_through() -> None:
    seen: list[str] = []

    async def app(scope: Any, receive: Any, send: Any) -> None:
        seen.append(scope["type"])

    async def nothing() -> Any:
        return {}

    async def ignore(message: Any) -> None:
        return None

    guard = SessionGuard(app, origin=ORIGIN, sessions=SessionStore(), cookie=COOKIE)
    asyncio.run(guard({"type": "lifespan"}, nothing, ignore))
    assert seen == ["lifespan"]


# ---------------------------------------------------------------------------------------------------------------------
# T10: forwarded requests
# ---------------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "header", ["Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP"]
)
@pytest.mark.parametrize(("method", "path"), ROUTES)
def test_forwarded_requests_are_refused(method: str, path: str, header: str) -> None:
    product = make_product()
    headers = dict(CONTROL_AUTH) if "/control/" in path else _signed_in_headers(product)
    response = _request(product, method, path, {**headers, header: "127.0.0.1"})
    _assert_refused(response, 403, "forwarded_not_allowed")
    assert product.shutdowns == []


# ---------------------------------------------------------------------------------------------------------------------
# T2, T3: Origin and fetch metadata
# ---------------------------------------------------------------------------------------------------------------------

FOREIGN_ORIGINS = [
    "http://evil.example",
    "null",  # sandboxed frames and file:// pages
    f"http://127.0.0.1:{PORT + 1}",  # another program on this computer: same site, other port
    f"http://localhost:{PORT}",
    f"https://127.0.0.1:{PORT}",
    f"http://[::1]:{PORT}",
]


@pytest.mark.parametrize("origin", FOREIGN_ORIGINS)
@pytest.mark.parametrize(("method", "path"), [r for r in ROUTES if "/control/" not in r[1]])
def test_foreign_origin_is_refused(method: str, path: str, origin: str) -> None:
    product = make_product()
    headers = {**_signed_in_headers(product), "Origin": origin}
    sessions = len(product.sessions)
    response = _request(product, method, path, headers)
    _assert_refused(response, 403, "origin_not_allowed")
    assert len(product.sessions) == sessions


def test_unsafe_requests_need_the_own_origin() -> None:
    # Browsers send Origin with every POST; a request without one did not come from the app's page.
    product = make_product()
    response = product.client.post("/api/session", json={"token": product.launch_token()})
    _assert_refused(response, 403, "origin_required")
    assert len(product.sessions) == 0
    for method in ("PUT", "PATCH", "DELETE"):
        _assert_refused(product.client.request(method, "/api/heartbeat"), 403, "origin_required")
    # The pages too: a form posted to them from elsewhere carries no Origin of the app.
    _assert_refused(product.client.post("/", content=b"x"), 403, "origin_required")


@pytest.mark.parametrize("site", ["cross-site", "same-site", "Cross-Site"])
@pytest.mark.parametrize(
    ("method", "path"), [r for r in ROUTES if r[1].startswith("/api/") and "/control/" not in r[1]]
)
def test_cross_site_api_requests_are_refused(method: str, path: str, site: str) -> None:
    # same-site matters: a page on another port of 127.0.0.1 is same-site with the app.
    product = make_product()
    headers = {**_signed_in_headers(product), "Sec-Fetch-Site": site}
    response = _request(product, method, path, headers)
    _assert_refused(response, 403, "cross_site")


def test_navigation_from_other_sites_reaches_the_pages() -> None:
    # The redirect file (file://) and links open /launch and / as a cross-site navigation: the pages hold no data.
    client = make_product().client
    for path in ("/", "/launch"):
        assert (
            client.get(path, headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"}).status_code == 200
        )


BROWSER_HEADERS = [
    {"Origin": ORIGIN},  # even the page's own origin
    {"Origin": "http://evil.example"},
    {"Sec-Fetch-Site": "same-origin"},
    {"Sec-Fetch-Site": "none"},
    {"Sec-Fetch-Mode": "cors"},
    {"Sec-Fetch-Dest": "empty"},
    {"Sec-Fetch-User": "?1"},
]


@pytest.mark.parametrize("extra", BROWSER_HEADERS, ids=lambda h: "-".join(f"{k}={v}" for k, v in h.items()))
@pytest.mark.parametrize("path", ["/api/control/launch", "/api/control/shutdown", "/api/control/proof"])
def test_control_rejects_browser_headers(path: str, extra: dict[str, str]) -> None:
    # With a valid token a browser still cannot drive the control endpoints; the command line never sends these.
    product = make_product()
    method = "GET" if "proof" in path else "POST"
    response = _request(product, method, path, {**CONTROL_AUTH, **extra})
    code = "origin_not_allowed" if extra.get("Origin", ORIGIN) != ORIGIN else "browser_not_allowed"
    _assert_refused(response, 403, code)
    assert "proof" not in response.text
    assert product.shutdowns == []
    assert product.launches.pending == 0


def test_only_get_and_head_of_open_control_paths_skip_the_token() -> None:
    own = [(b"host", HOST.encode()), (b"content-type", b"application/json")]
    proof = "/api/control/proof"
    assert _asgi_status(own, proof, "GET") == 0
    assert _asgi_status(own, proof, "HEAD") == 0
    for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
        assert _asgi_status(own, proof, method) == 401, method
    for path in ("/api/control/proof/", "/api/control/launch", "/api/control/x"):
        assert _asgi_status(own, path, "GET") == 401, path
    # An empty segment is refused before the token check (review N-02 L1).
    assert _asgi_status(own, "/api/control//proof", "GET") == 404
    token = [*own, (b"authorization", f"Bearer {TOKEN}".encode())]
    assert _asgi_status(token, proof, "POST") == 0
    assert _asgi_status([*token, (b"authorization", f"Bearer {TOKEN}".encode())], "/api/control/launch", "POST") == 401
    wrong = [*own, (b"authorization", f"Bearer {TOKEN}x".encode())]
    assert _asgi_status(wrong, "/api/control/launch", "POST") == 401
    basic = [*own, (b"authorization", f"Basic {TOKEN}".encode())]
    assert _asgi_status(basic, "/api/control/launch", "POST") == 401


def test_an_empty_control_token_opens_nothing() -> None:
    own = [(b"host", HOST.encode()), (b"content-type", b"application/json"), (b"authorization", b"Bearer ")]
    assert _asgi_status(own, "/api/control/launch", "POST", control_token="") == 401


@pytest.mark.parametrize(
    "path", ["/api/control/../heartbeat", "/api/./heartbeat", "/api/control/./launch", "/api/x/../../launch"]
)
def test_dot_segments_in_api_paths_are_refused(path: str) -> None:
    own = [(b"host", HOST.encode())]
    assert _asgi_status(own, path, "GET") == 404


# ---------------------------------------------------------------------------------------------------------------------
# T2, T3: JSON only and the CSRF header
# ---------------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content_type",
    [None, "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", "text/plain", "application/jsonx"],
)
def test_api_accepts_json_only(content_type: str | None) -> None:
    # A form or a fetch without preflight can only send these types.
    product = make_product()
    headers = {"Origin": ORIGIN} if content_type is None else {"Origin": ORIGIN, "Content-Type": content_type}
    body = f'{{"token": "{product.launch_token()}"}}'.encode()
    _assert_refused(product.client.post("/api/session", content=body, headers=headers), 415, "json_only")
    assert len(product.sessions) == 0
    control_headers = {**CONTROL_AUTH} if content_type is None else {**CONTROL_AUTH, "Content-Type": content_type}
    response = product.client.post("/api/control/shutdown", content=b"{}", headers=control_headers)
    _assert_refused(response, 415, "json_only")
    assert product.shutdowns == []


def test_json_with_a_charset_is_accepted() -> None:
    product = make_product()
    body = f'{{"token": "{product.launch_token()}"}}'.encode()
    headers = {"Origin": ORIGIN, "Content-Type": "application/json; charset=utf-8"}
    assert product.client.post("/api/session", content=body, headers=headers).status_code == 200


def test_cookie_alone_is_useless_without_csrf_header() -> None:
    # Cookies are not port-scoped. A server on another local port that the browser visits receives the cookie, but
    # not the CSRF value, which only lives in the page's sessionStorage.
    product = make_product()
    csrf = product.sign_in()[CSRF_HEADER]
    for headers in ({}, {CSRF_HEADER: ""}, {CSRF_HEADER: "wrong"}, {CSRF_HEADER: csrf[:-1]}, {"Cookie-CSRF": csrf}):
        for path in ("/api/heartbeat", "/api/openapi.json"):
            _assert_refused(product.client.get(path, headers=headers), 403, "csrf_invalid")
    assert product.activity == []  # refused requests are no activity
    assert product.client.get("/api/heartbeat", headers={CSRF_HEADER: csrf}).status_code == 204
    assert product.activity == ["request"]


def test_two_csrf_headers_are_refused() -> None:
    product = make_product()
    csrf = product.sign_in()[CSRF_HEADER]
    cookie = product.client.cookies.get(COOKIE)
    product.client.cookies.clear()
    headers = [(b"cookie", f"{COOKIE}={cookie}".encode()), (CSRF_HEADER.encode(), csrf.encode())] * 2
    response = product.client.get("/api/heartbeat", headers=headers)
    _assert_refused(response, 403, "csrf_invalid")


def test_csrf_value_is_bound_to_its_session() -> None:
    product = make_product()
    first = product.sign_in()[CSRF_HEADER]
    first_cookie = product.client.cookies.get(COOKIE)
    second = product.sign_in()[CSRF_HEADER]
    assert first != second
    # The client now holds the second cookie; the first session's CSRF value does not fit it.
    _assert_refused(product.client.get("/api/heartbeat", headers={CSRF_HEADER: first}), 403, "csrf_invalid")
    assert product.client.get("/api/heartbeat", headers={CSRF_HEADER: second}).status_code == 204
    product.client.cookies.set(COOKIE, first_cookie or "")
    assert product.client.get("/api/heartbeat", headers={CSRF_HEADER: first}).status_code == 204


def test_csrf_value_never_travels_in_a_cookie() -> None:
    product = make_product()
    response = product.client.post("/api/session", json={"token": product.launch_token()}, headers={"Origin": ORIGIN})
    csrf = response.json()["csrf"]
    assert csrf not in response.headers.get("set-cookie", "")
    assert len(response.headers.get_list("set-cookie")) == 1


def test_csrf_header_without_a_session_is_refused() -> None:
    product = make_product()
    csrf = product.sign_in()[CSRF_HEADER]
    product.client.cookies.clear()
    _assert_refused(product.client.get("/api/heartbeat", headers={CSRF_HEADER: csrf}), 401, "session_required")


def test_a_tossed_cookie_does_not_hide_the_real_session() -> None:
    # Another local server can set a second cookie with the app's name for 127.0.0.1; the real one still counts,
    # and the tossed one alone opens nothing.
    product = make_product()
    csrf = product.sign_in()[CSRF_HEADER]
    real = product.client.cookies.get(COOKIE)
    product.client.cookies.clear()
    tossed = {"Cookie": f"{COOKIE}=attacker; {COOKIE}={real}", CSRF_HEADER: csrf}
    assert product.client.get("/api/heartbeat", headers=tossed).status_code == 204
    only_tossed = {"Cookie": f"{COOKIE}=attacker", CSRF_HEADER: csrf}
    _assert_refused(product.client.get("/api/heartbeat", headers=only_tossed), 401, "session_required")


# ---------------------------------------------------------------------------------------------------------------------
# T4: a session only through a one-time launch token; without the cookie 401
# ---------------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/api/heartbeat", "/api/openapi.json", "/api/anything", "/api", "/api/heartbeat/"])
def test_api_needs_a_session(path: str) -> None:
    # Another local program reaches the port, but has no launch token and so no cookie.
    product = make_product()
    _assert_refused(product.client.get(path, headers={CSRF_HEADER: "x"}), 401, "session_required")


def test_launch_token_gives_a_session_cookie() -> None:
    product = make_product()
    response = product.client.post("/api/session", json={"token": product.launch_token()}, headers={"Origin": ORIGIN})
    assert response.status_code == 200
    assert set(response.json()) == {"csrf"}
    cookie = response.headers["set-cookie"]
    name, _, rest = cookie.partition("=")
    assert name == f"test_session_{PORT}"  # per port: two instances never overwrite each other's cookie
    attributes = {part.strip().split("=", 1)[0].lower(): part.strip() for part in rest.split(";")[1:]}
    assert "httponly" in attributes
    assert attributes["samesite"].lower() == "samesite=strict"
    assert attributes["path"] == "Path=/"
    assert "secure" not in attributes  # http on loopback
    assert "domain" not in attributes  # host-only
    assert "max-age" not in attributes and "expires" not in attributes  # ends with the browser session


def test_launch_token_works_once() -> None:
    product = make_product()
    token = product.launch_token()
    first = product.client.post("/api/session", json={"token": token}, headers={"Origin": ORIGIN})
    assert first.status_code == 200
    product.client.cookies.clear()
    second = product.client.post("/api/session", json={"token": token}, headers={"Origin": ORIGIN})
    assert second.status_code == 401 and second.json()["code"] == "launch_used"
    assert "set-cookie" not in second.headers
    assert len(product.sessions) == 1


def test_launch_token_expires() -> None:
    product = make_product()
    token = product.launch_token()
    product.clock.now += product.launches.ttl + 1
    response = product.client.post("/api/session", json={"token": token}, headers={"Origin": ORIGIN})
    assert response.status_code == 401 and response.json()["code"] == "launch_expired"
    assert len(product.sessions) == 0


@pytest.mark.parametrize("token", ["", "x" * 43, "a" * 42, "a" * 44, None, 5, ["a" * 43], "../../etc/passwd"])
def test_unknown_launch_token_is_refused(token: object) -> None:
    product = make_product()
    response = product.client.post("/api/session", json={"token": token}, headers={"Origin": ORIGIN})
    assert response.status_code == 401 and response.json()["code"] == "launch_invalid"
    assert len(product.sessions) == 0


def test_session_of_another_port_does_not_count() -> None:
    # The same session ID under the cookie name of another port opens nothing here.
    product = make_product()
    csrf = product.sign_in()[CSRF_HEADER]
    session_id = product.client.cookies.get(COOKIE)
    product.client.cookies.clear()
    other = {"Cookie": f"test_session_{PORT + 1}={session_id}", CSRF_HEADER: csrf}
    _assert_refused(product.client.get("/api/heartbeat", headers=other), 401, "session_required")


def test_routes_get_the_session_digest_never_the_cookie() -> None:
    product = make_product()
    csrf = product.sign_in()
    session_id = product.client.cookies.get(COOKIE)
    assert product.client.get("/api/heartbeat", headers=csrf).status_code == 204
    assert session_id is not None
    assert product.seen_sessions[0] != session_id and len(product.seen_sessions[0]) == 64


def test_an_idle_session_ends() -> None:
    product = make_product(idle=60)
    csrf = product.sign_in()
    product.clock.now += 59
    assert product.client.get("/api/heartbeat", headers=csrf).status_code == 204
    product.clock.now += 61
    _assert_refused(product.client.get("/api/heartbeat", headers=csrf), 401, "session_required")


# ---------------------------------------------------------------------------------------------------------------------
# T13: strict CSP and no caching on every answer
# ---------------------------------------------------------------------------------------------------------------------


def test_security_headers_are_pinned() -> None:
    """The code's header set is exactly the one written out in the tests."""
    assert dict(SECURITY_HEADERS) == EXPECTED_SECURITY_HEADERS
    assert len(SECURITY_HEADERS) == len(EXPECTED_SECURITY_HEADERS)


def test_csp_is_strict() -> None:
    directives = dict(part.strip().split(" ", 1) for part in CONTENT_SECURITY_POLICY.split(";"))
    assert directives["default-src"] == "'self'"
    assert directives["script-src"] == "'self'"
    assert directives["object-src"] == "'none'"
    assert directives["frame-ancestors"] == "'none'"
    assert directives["base-uri"] == "'none'"
    assert "unsafe" not in CONTENT_SECURITY_POLICY
    assert "data:" not in CONTENT_SECURITY_POLICY and "*" not in CONTENT_SECURITY_POLICY


def test_security_headers_on_every_answer() -> None:
    product = make_product()
    headers = _signed_in_headers(product)
    answers = [
        product.client.get("/"),
        product.client.get("/launch"),
        product.client.get("/assets/app.js"),
        product.client.get("/missing.js"),  # 404 of the app
        product.client.get("/api/health"),
        product.client.get("/api/heartbeat", headers=headers),
        product.client.get("/api/heartbeat"),  # 401
        product.client.get("/api/health", headers={"Host": "evil.example"}),  # 403
        product.client.post("/api/control/launch", json={}),  # 401
        product.client.request("PUT", "/api/health", headers={"Origin": ORIGIN}, json={}),  # 405
    ]
    for response in answers:
        _assert_security_headers(response)


def test_no_store_on_every_answer() -> None:
    product = make_product()
    headers = _signed_in_headers(product)
    for method, path in ROUTES:
        hdrs = dict(CONTROL_AUTH) if "/control/" in path else headers
        response = _request(product, method, path, hdrs)
        assert response.headers.get_list("cache-control") == ["no-store"], path
    # The app's own caching headers are replaced, not added to.
    asset = product.client.get("/assets/app.js")
    assert asset.headers.get_list("cache-control") == ["no-store"]


# ---------------------------------------------------------------------------------------------------------------------
# The product keeps its own codes and format
# ---------------------------------------------------------------------------------------------------------------------


def test_every_refusal_has_a_fixed_text_and_status() -> None:
    for code, (status, detail) in REFUSALS.items():
        assert status in (401, 403, 404, 415), code
        assert detail and "{" not in detail, code


def test_a_product_sends_its_own_refusals() -> None:
    sent: list[Any] = []
    refusals: list[Refusal] = []

    async def refuse(scope: Any, send: Any, refusal: Refusal) -> None:
        refusals.append(refusal)
        await send({"type": "http.response.start", "status": refusal.status, "headers": []})
        await send({"type": "http.response.body", "body": f"access.{refusal.code}".encode()})

    async def send(message: Any) -> None:
        sent.append(message)

    async def receive() -> Any:
        return {"type": "http.request", "body": b""}

    guard = SessionGuard(_noop_app, origin=ORIGIN, sessions=SessionStore(), cookie=COOKIE, refuse=refuse)
    scope = {"type": "http", "method": "GET", "path": "/api/x", "headers": [(b"host", b"evil.example")]}
    asyncio.run(guard(scope, receive, send))
    assert refusals == [Refusal("host_not_allowed", 403, REFUSALS["host_not_allowed"][1])]
    assert sent[1]["body"] == b"access.host_not_allowed"
    # The security headers are added to the product's refusal too.
    assert (b"x-frame-options", b"DENY") in sent[0]["headers"]


# ---------------------------------------------------------------------------------------------------------------------
# Review N-02 L1: an app that normalizes paths (merges slashes, resolves dot segments, ignores case) gets no path that
# skipped the session or control checks.
# ---------------------------------------------------------------------------------------------------------------------


def _normalizing_status(path: str, method: str = "GET") -> int:
    """The status of ``path`` through the guard, in front of an app that routes on a normalized, lower-case path."""
    import posixpath

    sent: list[dict[str, Any]] = []

    async def app(scope: Any, receive: Any, send: Any) -> None:
        normalized = posixpath.normpath("/" + scope["path"].replace("\\", "/").lstrip("/")).lower()
        found = normalized in ("/api/secret", "/api/control/shutdown")
        await send({"type": "http.response.start", "status": 200 if found else 404, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def send(message: Any) -> None:
        sent.append(message)

    async def receive() -> Any:
        return {"type": "http.request", "body": b""}

    guard = SessionGuard(
        app, origin=ORIGIN, sessions=SessionStore(), cookie=COOKIE, control_prefix="/api/control", control_token=TOKEN
    )
    scope = {
        "type": "http",
        "path": path,
        "raw_path": path.encode(),
        "method": method,
        "headers": [(b"host", HOST.encode())],
        "query_string": b"",
    }
    asyncio.run(guard(scope, receive, send))
    return int(sent[0]["status"])


@pytest.mark.parametrize(
    "path",
    [
        "//api/secret",
        "/x/../api/secret",
        "/static/../api/control/shutdown",
        "//api/control/shutdown",
        "/api//secret",
        "/./api/secret",
        "/static/..\\api/secret",
        "/static\\..\\api\\control\\shutdown",
    ],
)
def test_paths_a_later_normalization_could_change_are_refused(path: str) -> None:
    assert _normalizing_status(path) == 404


@pytest.mark.parametrize(("path", "status"), [("/API/secret", 401), ("/Api/Control/shutdown", 401)])
def test_the_prefixes_match_without_regard_to_case(path: str, status: int) -> None:
    assert _normalizing_status("/api/secret") == 401  # the control: guarded as expected
    assert _normalizing_status(path) == status


def test_a_control_path_in_another_case_needs_the_control_token() -> None:
    own = [(b"host", HOST.encode()), (b"content-type", b"application/json")]
    assert _asgi_status(own, "/API/CONTROL/launch", "POST") == 401
    auth = (b"authorization", CONTROL_AUTH["Authorization"].encode())
    assert _asgi_status([*own, auth], "/API/CONTROL/launch", "POST") == 0


def test_usual_paths_still_pass() -> None:
    own = [(b"host", HOST.encode())]
    for path in ("/", "/assets/app.js", "/api/health", "/api/control/proof", "/assets/v1.2/app.js"):
        assert _asgi_status(own, path, "GET") == 0, path
    assert _asgi_status(own, "/api/heartbeat/", "GET") == 401  # a trailing slash is a usual API path


# ---------------------------------------------------------------------------------------------------------------------
# Review N-02 (re-check of #2): routers that fold Unicode (re.IGNORECASE, casefold, NFKC) or decode a second time.
# ---------------------------------------------------------------------------------------------------------------------


def _status_behind(app: Any, path: str) -> int:
    sent: list[dict[str, Any]] = []

    async def send(message: Any) -> None:
        sent.append(message)

    async def receive() -> Any:
        return {"type": "http.request", "body": b""}

    guard = SessionGuard(
        app, origin=ORIGIN, sessions=SessionStore(), cookie=COOKIE, control_prefix="/api/control", control_token=TOKEN
    )
    scope = {
        "type": "http",
        "path": path,
        "raw_path": path.encode(),
        "method": "GET",
        "headers": [(b"host", HOST.encode())],
        "query_string": b"",
    }
    asyncio.run(guard(scope, receive, send))
    return int(sent[0]["status"])


@pytest.mark.parametrize(
    "path",
    [
        "/ap\u0131/secret",  # U+0131 dotless i
        "/ap\u0131/control/shutdown",
        "/AP\u0130/secret",  # U+0130
        "/api/contro\u017f/shutdown",  # U+017F long s: still under the API prefix
        "/\uff41\uff50\uff49/secret",  # fullwidth, NFKC
    ],
)
def test_unicode_folding_routers_get_no_unguarded_api_path(path: str) -> None:
    import re
    import unicodedata

    routes = [re.compile(r"/api/secret", re.IGNORECASE), re.compile(r"/api/control/shutdown", re.IGNORECASE)]

    async def router(scope: Any, receive: Any, send: Any) -> None:
        seen = unicodedata.normalize("NFKC", scope["path"])
        hit = any(route.fullmatch(seen) for route in routes)
        await send({"type": "http.response.start", "status": 200 if hit else 404, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    assert _status_behind(router, "/API/secret") == 401
    assert _status_behind(router, path) == 401


def test_a_folded_control_prefix_needs_the_control_token() -> None:
    import re

    async def router(scope: Any, receive: Any, send: Any) -> None:
        hit = re.fullmatch(r"/api/control/shutdown", scope["path"], re.IGNORECASE) is not None
        await send({"type": "http.response.start", "status": 200 if hit else 404, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    for path in ("/ap\u0131/control/shutdown", "/api/control/\u017fhutdown", "/API/CONTROL/shutdown"):
        assert _status_behind(router, path) == 401, path
    own = [(b"host", HOST.encode()), (b"content-type", b"application/json")]
    assert _asgi_status(own, "/ap\u0131/control/launch", "POST") == 401
    auth = (b"authorization", CONTROL_AUTH["Authorization"].encode())
    assert _asgi_status([*own, auth], "/ap\u0131/control/launch", "POST") == 0  # classified as a control path


@pytest.mark.parametrize(
    "path",
    [
        "/x/%2e%2e/api/secret",
        "/x/%2E%2E/api/secret",
        "/x%2f..%2fapi/secret",
        "/x/..%5capi/secret",
        "/x/%252e%252e/api/secret",
        "/assets/%00",
        "/x/\uff0e\uff0e/api/secret",  # fullwidth full stops, NFKC
        "/x\uff0f..\uff0fapi/secret",  # fullwidth solidus, NFKC
    ],
)
def test_paths_a_second_decoding_could_change_are_refused(path: str) -> None:
    from urllib.parse import unquote

    async def decoding_app(scope: Any, receive: Any, send: Any) -> None:
        import posixpath
        import unicodedata

        seen = posixpath.normpath(unquote(unquote(unicodedata.normalize("NFKC", scope["path"]))).replace("\\", "/"))
        await send({"type": "http.response.start", "status": 200 if seen == "/api/secret" else 404, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    assert _status_behind(decoding_app, path) == 404


def test_usual_paths_with_unicode_and_percent_signs_still_pass() -> None:
    own = [(b"host", HOST.encode())]
    for path in ("/assets/caf\u00e9.js", "/assets/100%.txt", "/assets/%41.js", "/apiary"):
        assert _asgi_status(own, path, "GET") == 0, path
