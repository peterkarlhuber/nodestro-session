# nodestro-session

Protection for a single-user app that serves HTTP on loopback and is opened in a browser or a webview. It keeps other
web pages (DNS rebinding, cross-site requests), other local programs and other OS users away from the app.

- **Loopback only:** refuses binding to the network, binds a random `127.a.b.c` with a `[::1]` guard and exclusive
  sockets (`bind`).
- **Host and Origin rules:** exact `Host`, no proxy headers, exact `Origin` (required on changes), `Sec-Fetch-Site`,
  JSON only (`guard`).
- **One-time launch tokens:** in the URL fragment, with a TTL, digests only, handed to the browser through a 0600
  redirect file (`tokens`).
- **Sessions:** a cookie per port (`HttpOnly; SameSite=Strict`) plus a CSRF value in a header, with idle time, max
  age and logout (`sessions`, `cookies`).
- **Private state:** 0700 directories and 0600 files with owner checks, and the Windows DACL check (`private`).
- **Secrets from a pipe, never from argv or the environment** (`handoff`), and **log redaction** (`redact`).

The package is pure Python with no runtime dependencies. It defines the ASGI types it uses, so any ASGI framework
works.

The design, the threat model and the migration of the products are in [docs/design.md](docs/design.md). Open work is
in [docs/TODO.md](docs/TODO.md).

## Use

```python
from nodestro_session import (
    LaunchTokens,
    SessionGuard,
    SessionStore,
    bind_loopback,
    cookie_name,
    ensure_private_dir,
    loopback_origin,
)

sockets = bind_loopback(0)
origin = loopback_origin(sockets.port, sockets.host)
launches = LaunchTokens(origin, redirect_dir=ensure_private_dir(state_dir), prefix="app", name="Example")
sessions = SessionStore(idle=8 * 3600, max_age=24 * 3600)
app = SessionGuard(
    app,
    origin=origin,
    sessions=sessions,
    cookie=cookie_name("app_session_", sockets.port),
    csrf_header="X-App-CSRF",
    open_paths={"/api/health", "/api/session"},
)
```

`tests/app.py` shows a complete app with the launch exchange.

## Install

There are no releases and nothing is published to a package index. Consumers require the package by version range
(`nodestro-session>=0.1.0.dev0,<0.2`). The studio lock (nodestro-studio `platform/internal*.txt`) pins the exact
commit:

```
nodestro-session @ git+https://github.com/peterkarlhuber/nodestro-session.git@<commit>
```

## Develop

```
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy && pytest
```

`tests/test_second_user.py` runs only with `NODESTRO_SESSION_OTHER_USER` set to a second local user that
`sudo -n -u` can switch to. CI creates one.

## License

Proprietary, see [LICENSE](LICENSE).
