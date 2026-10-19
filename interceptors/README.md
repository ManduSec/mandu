# interceptors/ — Mandu OS-level interceptors

> Status: **LANDED.** This directory is a mix of **TypeScript** packages (the
> Track-A model-API proxies and the cooperative Tier-2 FS/net/exec chokepoints)
> and a **Rust** Cargo workspace (the kernel/userspace interceptor crates, rooted
> at `interceptors/Cargo.toml`). They are the "OS-level attachment layer" CONTRIBUTING.md
> says Mandu must build new; the defense logic itself (symbol table, policy
> engine, view-sync) is lifted from adfi-openclaw into `arbiter/` and `fs-sync/`.

All interceptors are clients of the **arbiter** (`../arbiter/`): they speak the
NDJSON Unix-socket protocol in `../arbiter/ipc/protocol.ts` to `symbolize` /
`desymbolize` / `classify` (and the usage/exec ops). They identify the monitored
agent by **cgroup v2 scope membership** — the scope created by
`../launcher/mandu-run.sh` (`MANDU_SCOPE_ID`), which replaces OpenClaw's
`isTargetSession()`.

## The TypeScript packages (userspace, live unprivileged)

| Package | Chokepoint | What it is |
|---|---|---|
| `anthropic-proxy/` | (1) model context | **Track A** for **Claude Code**: a local reverse proxy reached via `ANTHROPIC_BASE_URL` (launcher placeholder `http://127.0.0.1:8788`), forwarding to `api.anthropic.com`. Classifies + symbolizes untrusted `tool_result` spans, injects the handling system prompt, records `tool_use` decisions so the FS/exec interceptors can correlate a later `openat`/`connect`/`execve`. This proxy is the §9 invariant oracle. |
| `openai-proxy/` | (1) model context | **Track A** for **Codex CLI**: the OpenAI **Responses API** sibling. Request-side only — symbolizes untrusted `function_call_output` spans + injects the handling prompt, then streams the response back verbatim. |
| `inspect-mcp/` | U-LLM (M4) | The cooperative `inspect_symbol` MCP stdio server: resolve → quarantined U-LLM call → re-symbolize → emit. U-LLM transport is a direct API call or a `claude -p`/`codex exec` subprocess that reuses the user's login (`MANDU_ULLM_MODE`). |
| `net-proxy/` | (2) network | **Tier-2** egress gate: a cooperative forward `HTTP_PROXY`/`HTTPS_PROXY` proxy (optional session-CA MITM for HTTPS bodies). A symbol bound for an untrusted destination is blocked by the arbiter's data-usage policy. Launcher `--net-proxy[-mitm]`. |
| `exec-wrap/` | (4) exec | **Tier-2** exec chokepoint: a `PATH`-shadowing wrapper for HIGH-RISK commands (default `curl,wget,nc`). A symbol used as a command/arg is refused (exit 77); otherwise it desymbolizes the argv and execs the real binary. Launcher `--exec-wrap`. |

All are pure-userspace, fail-closed, and lift the arbiter policy directly (no
agent cooperation beyond the cooperative env wiring).

## The Rust Cargo workspace

Rooted at `interceptors/Cargo.toml`. Its `members` list **only the Rust crate
dirs** (`mandu-arbiter`, `fs-supervisor`, `fs-preload`, `net-supervisor`,
`exec-supervisor`), so the sibling Node packages above are excluded. That is
**four interceptor crates + one shared client crate** (`mandu-arbiter`).

| Crate | Task | Pure (default, no root) | Kernel-gated (`--features kernel`) |
|---|---|---|---|
| `mandu-arbiter/` | shared client | NDJSON Unix-socket arbiter client, typed protocol structs, `ManduEvent` mirror, `$MDU:*` scanner, mock-socket harness | — (Unix sockets need no privilege) |
| `fs-supervisor/` | Track B (kernel) | `layout` (path rewrite to AgentView worktree), `decision` (tracked match + `decide_open` + first-touch classify/symbolize), `events` | `kernel` — seccomp-unotify openat loop (ADDFD redirect needs kernel ≥ 5.9) |
| `fs-preload/` | Tier-2 (userspace) | cdylib `LD_PRELOAD` `openat` interposer that redirects tracked reads to the AgentView worktree — works on **any** kernel, no root, no seccomp (launcher `--fs-preload`) | — (LD_PRELOAD needs no privilege) |
| `net-supervisor/` | M3 (kernel) | `transform` (ingress symbolize / egress desymbolize gated by data-usage policy; model-host exclusion), `events` | `kernel` — nftables/TPROXY redirect + accept loop |
| `exec-supervisor/` | M3 (kernel) | `orchestrate` (`plan_exec`: classifyExec → AgentShell/HumanShell, resolveExecArgv after the gate), `events` | `kernel` — execve seccomp/ptrace trap + namespace setup |

All crates are clients of the arbiter (`../arbiter/`) over the NDJSON Unix-socket
protocol in `../arbiter/ipc/protocol.ts`, and identify the monitored agent by
cgroup v2 scope membership (the launcher's `MANDU_SCOPE_ID`). `fs-supervisor`
pairs with `../fs-sync/` (TS), which reconciles AgentView → HumanView and
re-symbolizes human edits via `git blame` (lifted from adfi-openclaw's
`adfi-git.ts`, `adfi-filecommit-*.ts`, `adfi-human-edit.ts`, `adfi-revert.ts`).

### Build / test

```
cd interceptors
cargo build          # default features — NO root, NO kernel deps
cargo test           # 57 unit tests (pure logic + mock-socket round-trips); 3 #[ignore]d kernel tests
```

The privileged kernel paths are documented per-crate (see each crate's README)
and live behind the `kernel` cargo feature + `#[ignore]`d integration tests, so
the default build/test pass on an unprivileged host without `nft`, root, or fuse.
