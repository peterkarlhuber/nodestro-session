# Changelog

## Unreleased

- 0.1.0.dev0: first version (N-02, "shared library for the local session"). The building blocks come from Tabrion
  Studio (`security/`, `server.py`, `paths.py`, `_winsec.py`) and nodestro-api (`launch.py`, `local_access.py`,
  `handoff.py`). Each takes the strictest variant, without product names, texts or codes:
  - `hosts`: loopback names, `Host` values, origins, proxy headers;
  - `bind`: `require_loopback` and `loopback_refusals` (no binding to the network); `bind_loopback` (random
    `127.a.b.c`, `[::1]` guard, exclusive sockets);
  - `tokens`: `LaunchTokens` (one-time, TTL, URL fragment, digests only, 0600 redirect files), `secret_equals`,
    `check_secret_length`;
  - `sessions`: `SessionStore` (session ID + CSRF value, digests only, bounded, idle time and max age, `end`,
    `end_all`);
  - `cookies`: names per port, fixed `HttpOnly; SameSite=Strict; Path=/`, every value of a name, no header
    injection;
  - `guard`: `SessionGuard`, an ASGI middleware with Tabrion Studio's checks in the same order, neutral refusal codes,
    a refusal sender of the product's choice and security headers on every answer;
  - `handoff`: `read_secrets_fd` (secrets from an inherited pipe);
  - `private`: 0700/0600 files with owner checks, and the Windows reparse-point and DACL checks;
  - `redact`: `SecretRedactor` log filter.
- Tests: the attack cases of Tabrion Studio's `tests/security` and of nodestro-api's launch, local access and
  handoff tests, ported as regression tests. A Linux CI job with a second OS user shows that the 0600 redirect file
  and the 0700 state directory stay closed to that user.
