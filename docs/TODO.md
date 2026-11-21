# TODO: nodestro-session

> Open work for this repository. Design and threat model: [design.md](design.md).
>
> **Last full review:** 2026-11-21 (N-02: CI manifest and ci-ok)

## Summary

| Priority | Count |
|---|---|
| P0 Critical | 0 |
| P1 High | 3 |
| P2 Medium | 4 |
| P3 Low | 2 |

No release and no publishing is planned. Consumers pin commits in the studio lock.

## Priorities and statuses

- **P1 High**: blocks a planned step of N-02 or a promised capability.
- **P2 Medium**: a gap with a workaround; schedule soon.
- **P3 Low**: polish or small debt.

Statuses: `Open`, `In progress`, `Blocked` (names the blocker), `Needs decision`, `Needs external review`.

## Open

| ID | Priority | Status | Item |
|---|---|---|---|
| NS-001 | P1 | Needs external review | Internal security review of 0.1 (no high findings) and an independent review before phase E (SEC-7). Covers the guard order, the session store and the private-file checks. |
| NS-002 | P1 | Open | nodestro-api hardening steps of design.md 5.2, each behind a switch that is off by default: launch-secret TTL, CSRF header + JSON only + required Origin (studio frontend first), logout on the desktop, no terminal mode without a secret, token in the fragment, `bind_loopback` for the desktop backend. |
| NS-003 | P1 | Blocked | Tabrion Studio migration (design.md 5.3). Blocked by a K-33 decision on the dependency edge `tabrion-studio -> nodestro-session` and by the naming question (a `nodestro-` package under Tabrion). |
| NS-004 | P2 | Open | `peer`: optional check that a TCP peer belongs to the same OS user (Linux `sock_diag` or `/proc/net/tcp`, macOS `pcblist_n` or libproc, Windows `GetExtendedTcpTable` with the process SID). Policy `off \| warn \| require`, off by default. It must report "unknown" in containers (Local Docker) instead of a false "ok". Needs a spike per platform (P0-5 b). |
| NS-005 | P2 | Open | Branch protection on master (owner setting). The mandatory checks are listed in `.github/ci-manifest.json` and `ci-ok.yml` reports on them as in the other library repositories; `ci-ok` stays report-only until the platform enforces it. |
| NS-006 | P2 | Open | Dependency policy: the studio's `platform/dependency-policy.json` needs the component `nodestro-session` (`kind: library`) and the edge `nodestro-api -> nodestro-session`. A copy of its own edges here once it has any. |
| NS-007 | P2 | Open | Windows: the DACL and junction tests run on the Windows runner only. Check them on a Windows machine with a second user, as the Linux job does. |
| NS-008 | P3 | Open | Shared logout helper (`POST` with Origin + CSRF; ending every session with a control token), once two products use the same routes. |
| NS-009 | P3 | Open | macOS has only `127.0.0.1` by default, so the origin is predictable there (residual risk, design.md 7). Document the `ifconfig lo0 alias` option or accept the risk. |
