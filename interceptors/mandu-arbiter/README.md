# mandu-arbiter (Rust lib)

The shared **arbiter IPC client** for the Mandu OS-level interceptors. A faithful
Rust reimplementation of `arbiter/ipc/protocol.ts` + `arbiter/ipc/client.ts`:
NDJSON over a Unix-domain socket (path from `MANDU_ARBITER_SOCK`), one JSON
request line in, one JSON response line out, correlated by `id`.

## Pure vs kernel-gated

Everything here is **PURE / privilege-free** — Unix-domain sockets need no root,
so the client and the mock both run under `cargo test` on an unprivileged host.
There is no `kernel` feature in this crate.

| Module | What |
|---|---|
| `protocol` (pure) | typed request/response structs matching `arbiter/ipc/protocol.ts` (classify, symbolize, desymbolize, resolve, desymbolizationDecision, classifyExec, resolveExecArgv, emit, ping). |
| `event` (pure) | serde mirror of the dashboard `ManduEvent` (`dashboard/src/event-model.ts`) for the `emit` op. |
| `client` (pure) | the blocking `ArbiterClient` — the NDJSON Unix-socket transport. |
| `symbols` (pure) | a dependency-free `$MDU:*` token scanner (matches the JS `SYMBOL_PATTERN`). |
| `mock` (pure, `feature = "mock"` / `cfg(test)`) | an in-process mock arbiter (real `UnixListener` + canned handler) for downstream tests. |

## Ops

`classify`, `symbolize`, `desymbolize`, `resolve`, `desymbolizationDecision`,
`classifyExec`, `resolveExecArgv`, `emit`, `ping`. Every op returns `Result`; an
`Err` means the arbiter is unreachable/refused → callers **fail closed**.
`mandu_arbiter::safe_emit` is the only call that swallows errors (observability
is off the security path).

## How the mock-socket test works

`mock::MockArbiter::start(handler)` binds a real `UnixListener` on a fresh temp
socket in a background thread; for each request line it parses the JSON, runs the
user's `handler(&Value) -> Result<Value, String>`, and writes back
`{id, ok:true, result}` or `{id, ok:false, error}`. Tests then point the **real**
`ArbiterClient` at `arbiter.socket_path` and assert each op round-trips — exercising
the genuine wire framing, id-correlation, and error paths. Enable it downstream
with `mandu-arbiter = { ..., features = ["mock"] }` under `[dev-dependencies]`.

## Build / test

```
cargo build -p mandu-arbiter        # default features
cargo test  -p mandu-arbiter        # 20 unit tests (mock socket round-trips)
```
