# nodestro-session: design

Status: version 0.1 (N-02 of the platform plan, first step). Only internal development. Nothing is released or
published.

## 1. Purpose

A local app often runs as an HTTP server on loopback, and the user opens it in a browser or a webview. The server must
not answer anyone else who can reach that port:

- other web pages in the same browser;
- other programs of the same user;
- other users of the same computer.

Today two products each have their own code for this, with different strengths:

| | Tabrion Studio (`tabrion_studio.security`, `server.py`, `paths.py`) | nodestro-api (`launch.py`, `local_access.py`, `handoff.py`) |
|---|---|---|
| Launch token | one-time, TTL 120 s, digest only, in the URL fragment, 0600 redirect file | one-time without TTL (desktop) or reusable access key (Local Docker), in the query (`?token=`) |
| Session | cookie per port + CSRF header, digest only | cookie (`HttpOnly; SameSite=Strict`); idle and max age only in Local Docker |
| Host check | exactly `<127.a.b.c>:<port>` | any loopback name (desktop), loopback names + ports (Local Docker) |
| Origin | exact, required on unsafe methods, `Sec-Fetch-Site` checked | exact on unsafe methods and WebSockets, a missing Origin is allowed |
| JSON only | yes | no |
| Bind | random `127.a.b.c`, `[::1]` guard socket, exclusive socket | `require_loopback_only` refuses non-loopback bind addresses |
| Private files | 0700/0600, owner check, Windows DACL check | none needed so far (pipe handoff) |
| Secret handoff | — | JSON on an inherited pipe (`--secrets-fd`) |

This library holds the shared, product-neutral building blocks. It takes the strictest variant of each part (mostly
Tabrion's) and keeps every check that exists in either product. Product details stay in the products: route paths,
cookie prefixes, error codes and texts, the problem format, which paths are open, how a browser is opened, and the
Local Docker access-key mode.

## 2. What is extracted

| Module | Content | Taken from |
|---|---|---|
| `hosts` | `is_loopback`, `split_host`, `split_port`, `is_ip_address`, `listens_everywhere`, `loopback_origin`, `FORWARDING_HEADERS` | api `local_access.py`, Tabrion `access.py` |
| `bind` | `loopback_refusals` and `require_loopback` (refuse binding `0.0.0.0`, `::`, LAN addresses and non-loopback host names); `bind_loopback` (random `127.a.b.c`, `[::1]` guard socket, exclusive socket against port takeover) | api `require_loopback_only`, Tabrion `server.py` |
| `tokens` | `LaunchTokens` (one-time, TTL, SHA-256 digests only, URL fragment, optional 0600 redirect file), `redirect_page`, `secret_equals` (constant time), `check_secret_length` | Tabrion `security/launch.py`, api `launch.py` |
| `sessions` | `SessionStore`: session ID + CSRF value, digests only, bounded, optional idle time and max age, `end` and `end_all` | Tabrion `security/sessions.py`, api `launch.py` (idle, max age) |
| `cookies` | `cookie_name` (port namespace), `set_cookie` and `clear_cookie` (fixed `HttpOnly; SameSite=Strict; Path=/`), `cookie_values` (all values of a name) | Tabrion `sessions.py`/`access.py`, api `launch.py` |
| `guard` | `SessionGuard`, an ASGI middleware: exact Host, no forwarding headers, exact Origin (required on unsafe methods), `Sec-Fetch-Site`, JSON only, session cookie + CSRF header, optional control prefix with a bearer token, security headers on every answer | Tabrion `security/access.py` |
| `handoff` | `read_secrets_fd`: read secrets from an inherited pipe, close it, replace stdin with the null device | api `handoff.py` |
| `private` | `ensure_private_dir`, `check_private_dir`, `write_private_file`, `read_private_file`, `remove_file` (POSIX 0700/0600 and owner; Windows reparse points and DACL) | Tabrion `paths.py`, `_winsec.py` |
| `redact` | `SecretRedactor`, a `logging.Filter` that removes registered secrets and `?token=` values | api `launch.py`, Tabrion `logs.py` |

Not in 0.1 (see `docs/TODO.md`):

- `peer`, the check that a TCP peer belongs to the same OS user (Linux `/proc/net/tcp` or `sock_diag`, macOS
  `pcblist`, Windows `GetExtendedTcpTable`). The plan treats it as optional hardening. It needs a spike per platform.
- Logout routes. They differ per product. The store has `end` and `end_all` for them.
- A token handoff through a pipe from the launcher to the browser. Browsers cannot read a pipe. The launcher reads it
  (`handoff`) and passes the token on through a 0600 redirect file (`tokens`).

The package has no runtime dependencies. It uses the standard library only and defines the ASGI types itself. Starlette
and httpx are needed only for the tests.

## 3. Threat model

Assets: the session (what the app can do for the user), the launch token, the session ID, the CSRF value, and the
files in the state directory.

Trust boundary: the app trusts the user's own browser tab that redeemed the launch token, and the user's launcher.
It trusts nobody else who reaches the port.

| # | Attacker or attack | Defense in this library | Test (tests/) |
|---|---|---|---|
| T1 | **Web page, DNS rebinding.** `evil.example` resolves its own name to `127.0.0.1` and reads the app as a same-origin page. | `SessionGuard` accepts exactly one `Host` header equal to the app's own `host:port`. `localhost`, other loopback addresses, other ports, no port, numeric forms and suffix tricks are refused. | `test_guard.py::test_host_allowlist_on_every_route`, `test_missing_or_duplicate_host_is_refused` |
| T2 | **Web page, cross-site request (CSRF).** A form or a `fetch` without preflight. | Exact `Origin`, required on unsafe methods. `Sec-Fetch-Site: cross-site` and `same-site` are refused on API paths. JSON only (`415` for forms and `text/plain`). Session cookie with `SameSite=Strict`. CSRF value in a header that only the app's page knows. | `test_foreign_origin_is_refused`, `test_unsafe_requests_need_the_own_origin`, `test_cross_site_api_requests_are_refused`, `test_api_accepts_json_only`, `test_cookie_alone_is_useless_without_csrf_header` |
| T3 | **Program of the same user on another port** of `127.0.0.1`. The browser sends every cookie of the host to it (cookies are not port-scoped), and it can set cookies too. | The cookie name contains the port, so it never collides. With `SessionGuard`, which wants the CSRF value on every API path (reads included), a cookie alone is useless: the value lives in the page's `sessionStorage` (scoped by port). A product that checks the value on changes only (nodestro-api, 5.2 step 2) keeps changes from such a program, but its reads still answer to the cookie alone. A cookie that another program tossed in does not hide the real one, and opens nothing on its own. A session ID under another port's cookie name opens nothing. | `test_session_of_another_port_does_not_count`, `test_a_tossed_cookie_does_not_hide_the_real_session`, `test_csrf_value_is_bound_to_its_session` |
| T4 | **Other local process or user without the token** on the port. | Every API path except the configured open ones needs a session. A session exists only after a one-time launch token. | `test_api_needs_a_session` |
| T5 | **Token leakage: logs, URLs, Referer, process lists.** | The launch token is in the URL fragment, which is never sent to a server, so it is never logged or put in a `Referer`. `Referrer-Policy: no-referrer`. The browser is opened with the `file://` path of a 0600 redirect file, never with the URL, because argv is readable by other users. The token is one-time with a TTL, so a token seen later is useless. Only SHA-256 digests are kept in memory. `SecretRedactor` removes registered secrets and `?token=` values from log records; the parameter name matches in any case and percent-encoded (`?Token=`, `?%74oken=`, `token%3D`). `read_secrets_fd` takes secrets from a pipe, not from argv or the environment. | `test_tokens.py`, `test_redact.py`, `test_handoff.py` |
| T6 | **Token reuse and guessing.** | 256-bit random values. `redeem` answers `used`, `expired` or `invalid`. Spent digests are remembered (bounded) to give a precise answer. A malformed token is refused before hashing. At most `max_pending` (32) tokens wait: `issue` sweeps expired ones and drops the oldest beyond the cap, with its redirect file. | `test_tokens.py::test_launch_token_works_once`, `::test_launch_token_expires`, `::test_malformed_tokens_are_invalid`, `::test_pending_tokens_are_bounded_and_the_oldest_is_dropped_with_its_file` |
| T7 | **Timing attacks** on secret comparison. | `secret_equals` and the CSRF check use `hmac.compare_digest`. Sessions and tokens are looked up by their SHA-256 digest, so an attacker cannot learn the stored value from timing. | `test_sessions.py`, `test_tokens.py::test_secret_equals` |
| T8 | **Cookie flags.** | `HttpOnly; SameSite=Strict; Path=/`, host-only (no `Domain`), session cookie (no `Max-Age` unless asked). `Secure` is optional, because loopback is plain http. Values and names are checked against RFC 6265, so no header injection is possible. | `test_cookies.py` |
| T9 | **Session lifetime and rotation.** | Each launch gives a new random session ID and CSRF value. The store is bounded (oldest dropped), has an optional idle time and max age, and `end` / `end_all` (logout). Nothing survives a restart. Tokens rotate by design: one per launch, and a reusable key stays a product decision (Local Docker). | `test_sessions.py` |
| T10 | **Exposure to the network.** | `require_loopback` refuses `0.0.0.0`, `::`, empty, LAN addresses and non-loopback names (also as extra allowed host names, and `*`). `SessionGuard` refuses forwarded requests (`Forwarded`, `X-Forwarded-*`, `X-Real-IP`). | `test_bind.py`, `test_forwarded_requests_are_refused` |
| T11 | **Port takeover.** A second process binds the same port, or answers `localhost` over IPv6. | `bind_loopback`: exclusive socket on Windows (`SO_EXCLUSIVEADDRUSE`), no `SO_REUSEPORT`, `[::1]` held by a bound guard socket, random `127.a.b.c` per start (fresh origin, so nothing an earlier instance left in the browser applies). | `test_bind.py` |
| T12 | **Other OS user reads the state directory or redirect file.** | 0700 directories and 0600 files, owner check, refuse group- or world-writable directories and symlinks. The parents count too: one owned by another non-root user, or writable by the group or others without the sticky bit, could swap the directory, so it is refused (on the path as given and as resolved); `LaunchTokens.issue` checks the directory again before each redirect file. On Windows: reparse points refused on every parent, "inside the profile" decided on the path as given, and a DACL check outside the profile or whenever the path resolves elsewhere. | `test_private.py`, `test_tokens.py::test_issue_checks_the_redirect_directory_again`, `test_second_user.py` (Linux CI with a real second user) |
| T13 | **Framing, sniffing, caching.** | Strict CSP, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `nosniff`, `Cache-Control: no-store`, COOP and CORP `same-origin` on every answer, refusals included. | `test_security_headers_on_every_answer` |
| T14 | **Control channel driven by a page.** | Optional control prefix: needs a bearer token (constant time), and any `Origin` or `Sec-Fetch-*` header is refused there. Paths with `.`, `..` or empty segments, a backslash, or a still-encoded `%2e`, `%2f`, `%5c`, `%25` or `%00` (also in their NFKC form) are refused on every path. The API and control prefixes match case-insensitively as `re.IGNORECASE` does (including U+0131, U+017F and U+212A), and after `casefold` and NFKC, so an app that normalizes paths, folds Unicode or decodes twice gets no path that skipped these checks. | `test_control_rejects_browser_headers`, `test_only_get_and_head_of_open_control_paths_skip_the_token`, `test_paths_a_later_normalization_could_change_are_refused`, `test_the_prefixes_match_without_regard_to_case`, `test_unicode_folding_routers_get_no_unguarded_api_path`, `test_paths_a_second_decoding_could_change_are_refused` |

Out of scope:

- Malware running as the same OS user. It can read the user's files and memory, so no local scheme protects against
  it.
- A local administrator.
- TLS on loopback.
- Multi-user servers with logins (axentra, nodestro-server). They use `SameSite=Lax` for OIDC and sessions in a
  database. They could still share `hosts` and `cookies` later.

## 4. Public API (0.1)

```python
from nodestro_session import (
    # hosts and binding
    is_loopback,
    split_host,
    split_port,
    is_ip_address,
    listens_everywhere,
    loopback_origin,
    FORWARDING_HEADERS,
    loopback_refusals,
    require_loopback,
    LoopbackRequired,
    bind_loopback,
    random_loopback,
    LoopbackSockets,
    PortUnavailableError,
    # tokens, sessions, cookies
    LaunchTokens,
    Launch,
    Redemption,
    redirect_page,
    redirect_file_pattern,
    secret_equals,
    check_secret_length,
    WeakSecretError,
    SessionStore,
    session_digest,
    cookie_name,
    set_cookie,
    clear_cookie,
    cookie_values,
    # the middleware
    SessionGuard,
    Refusal,
    REFUSALS,
    SECURITY_HEADERS,
    CONTENT_SECURITY_POLICY,
    send_problem,
    # files, handoff, logs
    ensure_private_dir,
    check_private_dir,
    write_private_file,
    read_private_file,
    remove_file,
    UnsafePathError,
    read_secrets_fd,
    HandoffError,
    SecretRedactor,
)
```

A product wires it like this (Locria will look like this; `tests/app.py` is a full example):

```python
sockets = bind_loopback(0)  # random 127.a.b.c, [::1] guard
origin = loopback_origin(sockets.port, sockets.host)
state = ensure_private_dir(state_dir)  # 0700, owner checked
launches = LaunchTokens(origin, redirect_dir=state, prefix="app", on_secret=redactor.add)
sessions = SessionStore(idle=8 * 3600, max_age=24 * 3600, on_secret=redactor.add)
cookie = cookie_name("app_session_", sockets.port)
app = SessionGuard(
    app,
    origin=origin,
    sessions=sessions,
    cookie=cookie,
    csrf_header="X-App-CSRF",
    open_paths={"/api/health", "/api/session"},
)
browser_open(launches.issue(redirect=True).redirect.as_uri())  # the file:// path, never the URL
# POST /api/session {"token": ...}: launches.redeem(token) == "ok" -> sessions.create() -> set_cookie(cookie, sid)
```

`SessionGuard` sends its refusals with `refuse(scope, send, refusal)`. The default is a problem document with a
neutral code (`host_not_allowed`, `origin_required`, ...). A product passes its own sender to keep its codes and
format. Tabrion, for example, would prefix them with `access.`.

Stability: the names above are the 0.x interface. A change goes into `CHANGELOG.md` and the minor version, and the
consumers' version ranges (`>=0.1.0.dev0,<0.2`) keep them from taking an incompatible version unnoticed.

## 5. Consumers and migration

The rule for every step: no security regression. Each consumer keeps its tests unchanged, and its existing tests
must pass on top of the library.

### 5.1 nodestro-api: first step (this change)

nodestro-api depends on `nodestro-session>=0.1.0.dev0,<0.2`. The studio lock holds the exact commit. Its modules
keep their names, behavior and contract (paths, codes, texts, cookie names, the open paths) and use the library
inside:

- `local_access`: `is_loopback`, `split_host`, `split_port`, `is_ip_address` and `listens_everywhere` come from
  `nodestro_session.hosts` (re-exported). `require_loopback_only` uses `loopback_refusals` and keeps the api's own
  error code and text. `LocalAccessMiddleware` keeps its rules, because the desktop still accepts `localhost` names
  and the Local Docker ports. Its forwarded-header list stays the api's (no `X-Forwarded-Proto`), so that nothing
  is refused that was accepted before.
- `launch`: sessions live in a `SessionStore`, so only digests are kept and lookups no longer scan. Desktop: one
  session. Local Docker: 64 sessions, idle time and max age as before. The comparisons use `secret_equals`, the
  cookies are built with `set_cookie` and `clear_cookie`, and are read with `cookie_values` (every value of the
  name, so a tossed cookie no longer hides the real one). Log redaction uses `SecretRedactor`. The desktop launch
  secret stays one-time without a TTL, delivered in the query. The CSRF value of the store is not used yet.
- `handoff`: reading the descriptor uses `read_secrets_fd`. The api keeps the JSON format and the error code
  `access.handoff_invalid`.

This covers the product host (`nodestro_api.host.create_product_app`, N-01) and the local profiles: both install
their guards through `install_guards`, which uses these modules.

Proof: the api's existing tests stay green unchanged (`test_launch.py`, `test_local_access.py`, `test_handoff.py`,
`test_local_container.py`, `test_cross_origin.py`, `test_product_host.py`, `test_hardening.py` and the rest).
`tests/test_session_library.py` adds checks that the api really uses the library, and repeats the attack cases on a
product-host app.

### 5.2 nodestro-api: later, each a separate change with a migration

These hardenings come from P0-5. Each one changes the contract, or needs the desktop or the frontend to change at the
same time. Each one comes behind a switch that is off by default until its counterpart ships:

1. TTL for the desktop launch secret (`LaunchTokens`). The desktop opens the window within seconds.
2. CSRF header + JSON only + required Origin for the studio API (`SessionGuard` or its checks). The studio frontend
   must send the header first.
3. Logout in desktop mode.
4. No more terminal mode without a secret: always issue a token and print a link or write a redirect file. Today the
   `nodestro` command without a secret answers every local process.
5. Launch token in the fragment instead of the query (desktop shell and launch page change together).
6. `bind_loopback` for the desktop backend (random `127.a.b.c`, `[::1]` guard). The desktop shell chooses the port
   today.

NS-002 (wave 3) builds these steps in nodestro-api (`nodestro_api.launch.LaunchHardening`), each behind its own
switch, all off. The library is used as it is: `SessionStore.check` for the CSRF value, `set_cookie`/`clear_cookie`,
`redirect_page` with `ensure_private_dir` and `write_private_file` for the terminal start, and `bind_loopback`.

| Step | Switch | Effect |
|---|---|---|
| 1 | `NODESTRO_LAUNCH_TTL=<seconds>` | The launch secret expires that long after the backend's first answer. |
| 2 | `NODESTRO_LAUNCH_CSRF=1` | Changes need `Origin`, JSON or `multipart/form-data` (or no body) and `X-Nodestro-CSRF`; a WebSocket needs `Origin`. The launch page hands the value to the studio through `sessionStorage`. Reads are not covered: a program on another port that got the cookie (T3) can still read, but not change anything. |
| 3 | `NODESTRO_DESKTOP_LOGOUT=1` | `POST /api/logout` ends the window's session. |
| 4 | `NODESTRO_TERMINAL_LAUNCH=1` | The command line issues a secret, opens a 0600 redirect file and prints the link once. |
| 5 | `NODESTRO_LAUNCH_FRAGMENT=1` | `/api/launch#token=`, exchanged by the launch page with `POST /api/launch`. `?token=` is refused. |
| 6 | `NODESTRO_BIND_LOOPBACK=1` | The command line listens through `bind_loopback`. |

With every switch off, the answers are byte-identical to the ones before NS-002. A recorded request matrix in
nodestro-api `tests/vectors/launch-switches-off.json` checks this.

### 5.3 Tabrion Studio: later PR in tabrion-studio

Tabrion Studio keeps its own code and behavior in this change. Nothing in tabrion-studio changes now.

Switching it to the library is a later PR in tabrion-studio:

- `security/launch.py` becomes `LaunchTokens` (`redirect_page(url, name="Tabrion Studio")` gives the same bytes);
- `security/sessions.py` becomes `SessionStore`;
- `security/access.py` becomes `SessionGuard` with `control_prefix="/api/control/"`,
  `control_open_paths={"/api/control/proof"}`, `csrf_header="X-Tabrion-CSRF"`, `state_key="studio_session"` and a
  refusal sender that maps the neutral codes to `access.*` and `not_found` to `studio.not_found`;
- `server.bind_loopback` becomes `bind_loopback`;
- `paths` and `_winsec` become `private`.

Its `tests/security` suite must pass unchanged.

That PR needs two things first:

- a dependency-policy edge `tabrion-studio -> nodestro-session` (a K-33 decision by the plan owner);
- an answer to the naming question: `tabrion-studio` would depend on a package with `nodestro-` in its name. The API
  is brand-neutral, so a rename stays possible before 1.0.

The plan allows Tabrion Studio to stay on its own code if the migration is not accepted.

### 5.4 Locria

Locria uses the library directly (section 4) through the product host. It is not part of this change.

## 6. Defaults and switches

The library has no global state and reads no environment variables. Every protection of `SessionGuard` is on, and
only the product's configuration narrows it: open paths, a control prefix. Optional hardening that is not built yet
(`peer`) will be off by default, with a policy `off | warn | require`.

In nodestro-api this change adds no switch and turns nothing on: the behavior is unchanged. The NS-002 switches
(section 5.2) live in nodestro-api, not here, and are all off by default.

## 7. Platforms

Linux, macOS and Windows. CI runs lint, types and tests on Linux with Python 3.11 and 3.13, and the tests on macOS and
Windows. A job on Linux creates a second OS user and shows that it cannot read the 0600 redirect file or the 0700
state directory. `.github/ci-manifest.json` lists these jobs as mandatory and `ci-ok.yml` reports on them, as in the
other library repositories. macOS has only `127.0.0.1` by default, so `bind_loopback` falls back to it. That is a documented
residual risk: the origin is predictable there.
