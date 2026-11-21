"""A small product on top of the library, for in-process tests: the way an app wires the pieces together.

Routes: the pages ``/``, ``/launch`` and ``/assets/app.js``; ``/api/health`` and ``POST /api/session`` (the launch
exchange) without a session; ``/api/heartbeat`` and ``/api/openapi.json`` with one; a control channel under
``/api/control/`` with the bearer token, of which ``GET /api/control/proof`` is open.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route
from starlette.testclient import TestClient

from nodestro_session import LaunchTokens, SessionGuard, SessionStore, cookie_name, loopback_origin, set_cookie

PORT = 1234
ORIGIN = loopback_origin(PORT)
HOST = f"127.0.0.1:{PORT}"
TOKEN = "control-token-for-tests"
CONTROL_AUTH = {"Authorization": f"Bearer {TOKEN}"}
CSRF_HEADER = "X-Test-CSRF"
COOKIE = cookie_name("test_session_", PORT)
#: The security headers every answer carries, written out here rather than read from the code: a header dropped or
#: weakened in the code must fail the tests.
EXPECTED_SECURITY_HEADERS: dict[str, str] = {
    "content-security-policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; "
        "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    ),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
}


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@dataclass
class Product:
    client: TestClient
    launches: LaunchTokens
    sessions: SessionStore
    clock: Clock
    shutdowns: list[str] = field(default_factory=list)
    activity: list[str] = field(default_factory=list)
    seen_sessions: list[str] = field(default_factory=list)

    def launch_token(self) -> str:
        return self.launches.issue(redirect=False).url.split("#", 1)[1]

    def sign_in(self) -> dict[str, str]:
        """Redeem a launch token like the launch page; returns the CSRF header of the signed-in page."""
        response = self.client.post("/api/session", json={"token": self.launch_token()}, headers={"Origin": ORIGIN})
        assert response.status_code == 200, response.text
        return {CSRF_HEADER: response.json()["csrf"]}


def _refused(code: str) -> Response:
    return JSONResponse({"code": code}, status_code=401, media_type="application/problem+json")


def make_product(redirect_dir: Path | None = None, idle: float | None = None, max_age: float | None = None) -> Product:
    clock = Clock()
    launches = LaunchTokens(ORIGIN, redirect_dir, "test", clock=clock)
    sessions = SessionStore(idle=idle, max_age=max_age, clock=clock)
    shutdowns: list[str] = []
    activity: list[str] = []
    seen: list[str] = []

    async def page(request: Request) -> Response:
        return HTMLResponse("<!doctype html><title>page</title>")

    async def asset(request: Request) -> Response:
        return Response("console.log(1)", media_type="text/javascript", headers={"cache-control": "max-age=3600"})

    async def health(request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def heartbeat(request: Request) -> Response:
        seen.append(request.state.session)
        return Response(status_code=204)

    async def openapi(request: Request) -> Response:
        return JSONResponse({"openapi": "3.1.0"})

    async def session(request: Request) -> Response:
        try:
            body = json.loads(await request.body())
        except ValueError:
            body = None
        token = body.get("token") if isinstance(body, dict) else None
        result = launches.redeem(token)
        if result != "ok":
            return _refused(f"launch_{result}")
        session_id, csrf = sessions.create()
        return JSONResponse({"csrf": csrf}, headers={"set-cookie": set_cookie(COOKIE, session_id)})

    async def proof(request: Request) -> Response:
        return JSONResponse({"proof": "ok"})

    async def control_launch(request: Request) -> Response:
        launches.issue(redirect=False)
        return JSONResponse({}, status_code=202)

    async def shutdown(request: Request) -> Response:
        shutdowns.append("shutdown")
        return Response(status_code=202)

    app = Starlette(
        routes=[
            Route("/", page),
            Route("/launch", page),
            Route("/assets/app.js", asset),
            Route("/api/health", health),
            Route("/api/heartbeat", heartbeat, methods=["GET", "PUT", "PATCH", "DELETE"]),
            Route("/api/openapi.json", openapi),
            Route("/api/session", session, methods=["POST"]),
            Route("/api/control/proof", proof, methods=["GET", "HEAD", "POST"]),
            Route("/api/control/launch", control_launch, methods=["POST"]),
            Route("/api/control/shutdown", shutdown, methods=["POST"]),
        ],
        middleware=[
            Middleware(
                SessionGuard,
                origin=ORIGIN,
                sessions=sessions,
                cookie=COOKIE,
                csrf_header=CSRF_HEADER,
                open_paths={"/api/health", "/api/session"},
                control_prefix="/api/control/",
                control_token=TOKEN,
                control_open_paths={"/api/control/proof"},
                on_activity=lambda: activity.append("request"),
            )
        ],
    )
    client = TestClient(app, base_url=ORIGIN)
    return Product(client, launches, sessions, clock, shutdowns, activity, seen)
