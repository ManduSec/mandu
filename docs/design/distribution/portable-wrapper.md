# Mandu — Portable Wrapper (the `mandu` launcher CLI)

> **Status: IMPLEMENTED** on Linux and macOS in `launcher/`
> (`@mandusec/mandu`, bin `mandu`): the parser, the pure env composer
> (`coop-env`), the platform module (linux/darwin), the backend registry,
> arbiter attach-or-refuse, the spawner and the service manager (model
> proxies, net-proxy ± session-CA MITM, exec-wrap shims, `.mcp.json`, the
> fs-sync AgentView worktree), so every chokepoint is wired cooperatively. The
> bash `launcher/mandu-run.sh` is a thin shim over it (§7). The opt-in
> `linux-fs-preload` and `linux-userns` backends were **retired** (2026-07-14)
> along with their flags (`--fs-preload`, `--unshare`, `--unshare-net`,
> slirp); requesting one is a parse-time error, and their jobs are covered by
> shipped default-on layers (fs-sync + the kernel FS layer; the bwrap layers
> exec-box / secret-twins; landlock-net + net-guard). The backend and flag
> tables below keep those rows as retired. §10 is the macOS/Windows platform
> design (darwin has historical hardware runs, fresh integrated-branch tests pending; win32 designed,
> not built).
>
> Companion to [`privilege-model.md`](../architecture/privilege-model.md) (§2
> the enforcement layers (context / wrapper / kernel) whose terminology this
> doc uses throughout; §3.1 why a cooperative boundary is enough for the IPI
> adversary), [`os-test-matrix.md`](../testing/os-test-matrix.md) (§4 the
> `wrapper` suite this spec fills; §6 the parity-then-shim migration
> precedent), and [`mandu.md`](../architecture/mandu.md) §4 (the four
> chokepoints being wired). Terminology pairs the paper term with the repo
> term (e.g. *AgentView (repo: Agent File System)*, *T-LLM (privileged
> LLM)*).

## 1. Motivation: why a TypeScript launcher

Everything the launcher wires is portable Node/TS, but the original wiring
was a long bash script full of Linuxisms (`systemd-run --scope`, `unshare`,
`slirp4netns` re-entry via `mkfifo`, `/proc`). The portable wrapper is a
TypeScript CLI: `launcher/` is a standalone npm package like every other TS
package in the repo (own `node_modules`, own `npm test`, `npm run
typecheck`), bin name **`mandu`**.

The claim it makes concrete: **all four chokepoints (model context, network,
filesystem, exec) realized by a wrapper process with no OS-specific kernel
support required.** The boundary is **cooperative**, a settled decision per
the threat model (`privilege-model.md` §3.1): the IPI adversary is a
prompt-injected agent driving normal tools through libc/Node, not a hostile
native payload scrubbing its own env. The architecture is OS-agnostic;
**Linux + macOS are implemented; Windows is admitted by the design but not
built** (§10).

The wrapper also replaces **cgroup membership** as the portable answer to "is
this process the monitored agent?" (`mandu.md` §0): the wrapper is the
**parent of the agent's process tree and owns it** (spawn, enumeration,
signal, reap), exactly the attribution the arbiter's proc-key scheme (the
shared `${pid}-${starttime_ticks}` key) consumes. Where a cgroup scope is
available it is kept as an add-on signal (§2.2), never a requirement.

## 2. Architecture: three layers, one rule

The one structural rule: **`process.platform` appears in exactly ONE module**
(the platform module, §2.2); the core orchestrator and every backend are
written against its narrow interface, and nothing else may branch on OS.

### 2.1 Core orchestrator (portable, zero OS conditionals)

- **Service manager.** Start-or-attach the **arbiter** (attach if its socket
  answers an IPC ping; start it otherwise, health-checked, not assumed), then
  the services: the **model proxies** (start-or-reuse; skipped on an explicit
  base-URL override or `MANDU_NO_CONTEXT_PROXY=1`, since the context
  chokepoint is always on and a composed base URL must not point at a dead
  port), `net-proxy` (± session-CA MITM), the `exec-wrap` shim dir, `fs-sync`
  AgentView-worktree seeding.
- **Env composer.** A **pure function** `LaunchPlan → env delta`: no I/O, no
  platform branches, exhaustively unit-testable. It produces
  `ANTHROPIC_BASE_URL` → the anthropic-proxy (claude target), or the **Codex
  config splice** (Codex selects its base URL by config file /
  `-c model_provider`, not an env var; §9.3); `HTTP(S)_PROXY` + `NO_PROXY`
  (loopback + model hosts excluded, so the proxy channels never loop);
  `PATH` with the shim dir prepended; the **`MANDU_*` env contract** (scope
  id, and the arbiter socket path passed **EXPLICITLY** so no other package
  needs platform-aware defaults); `CWD` → the AgentView worktree.
- **Agent spawner / lifecycle.** Spawn the target as a **child** with stdio
  passthrough (TUI-safe: the agent inherits the real terminal fds), forward
  signals (SIGINT/SIGTERM/SIGWINCH), wait, propagate the exit code. Post-exit:
  `fs-sync` write-back (AgentView → HumanView), then teardown of **only what
  the wrapper started** (an attached pre-existing arbiter is never killed).
  Post-exit teardown is the GRACEFUL path only: every service the manager
  starts also carries a kernel-bound **lifeline** (stdin pipe +
  `MANDU_LIFELINE=stdin`, runtime-instances.md §8) so a launcher that dies
  WITHOUT reaching post-exit (SIGKILL, OOM) still takes its services with it,
  the shared arbiter/dashboard stack deliberately excluded. Fixed service
  ports accept `0` (kernel-assigned, published back via `MANDU_PORT_FILE`)
  for collision-free parallel/test launches.
- **Teardown signals (`launcher/src/teardown-signals.ts`).** From the agent
  chain's exit to the launcher's exit (the service stop, the fs-view sweep
  when the frozen integrity axis is on, the session-exit event) the launcher
  **ignores SIGINT**. Once the agent quits, the reply filter's `script(1)`
  puts the terminal back in cooked mode, so a ^C there is a SIGINT for the
  terminal's foreground group, which would otherwise kill the launcher
  part-way (exit 130, services left to their lifelines, the sweep cut off).
  `runAgent` arms the guard before it drops its signal forwarders, so SIGINT
  never falls back to its default action in between; the first ^C prints one
  line (`^C is ignored until that is done. To end it now: kill <pid>`). **No
  ^C count force-exits**: reflexive ^C bursts (claude's own ^C-^C quit,
  OpenCode's) spill into the teardown and must not cut the write-back short,
  and every teardown step is bounded by its own timeout (the watcher drain
  30 s, the sweep 10 min). **SIGTERM, SIGHUP and SIGQUIT keep their default
  action** (no handler, so they act at once even inside a synchronous step):
  a supervisor's stop, a closed terminal or a ^\ ends the launcher promptly
  and the services die through their lifelines. The **sweep runs in a
  session of its own** (`runOnce` `ownSession`): libuv resets every signal to
  its default in a child, so ignoring SIGINT in the launcher does not protect
  a same-group child, and the terminal's ^C would otherwise kill the sweep
  itself; the same isolation means that if the launcher is ended mid-sweep
  the sweep finishes on its own. A launch that aborts after its services
  started runs its `services.stop()` under the same guard. `mandu demo`
  applies the same policy to its own cleanup through the same guard
  (`createTeardownGuard`; `mandu-demo.md` §3 "Signals").
  **The window ends at the process's exit, not at the guard's disarm.**
  Removing the last SIGINT listener restores the default action at once, so
  a guard disarmed at the end of `main()` would leave `main()`'s return and
  `process.exit()`'s own shutdown (the `exit` handlers, stopping the module
  loader's worker, restoring the terminal) unguarded, tens of milliseconds
  on a terminal in which a ^C killed the launcher with 130 after its teardown
  had finished (`differential-interactive.md` §21). The CLI entry calls
  `holdTeardownGuardsUntilExit()`, after which a guard's `disarm()` keeps its
  handler: every guard of the process stays armed until the exit. `main()`
  imported by a test keeps the plain disarm. The e2e bar is six launches
  under a real terminal (`script(1)`), each with a ^C every 30 ms from the
  agent's cooked-mode quit to the launcher's exit, all exiting 0. Tests:
  `launcher/test/unit/teardown-signals.test.ts`,
  `launcher/test/component/teardown-sigint.test.ts`.
  **Left open: the window before teardown.** A ^C between the agent's own
  quit and the chain's exit can still make the session report 130. The
  measurement (`differential-interactive.md` §21, "The chain's exit window")
  found both causes in the reply filter, not in the launcher's SIGINT
  forwarder, and the launcher cannot see its grandchild's exit anyway, so no
  launcher rule would close it. Forwarding stays as it is, and ^C still
  reaches a running agent.

### 2.2 Platform module: one narrow interface

Implementations `linux` and `darwin`; `win32` designed (§10), not built.
Three methods:

| Method | Linux | macOS (darwin) | Windows (designed) |
|---|---|---|---|
| `scope()`: process scoping | `systemd-run --user --scope` when available (keeps the cgroup membership signal); POSIX process-group (`setsid`/detached + `kill(-pgid)`) as fallback | POSIX process-group (the default; no systemd) | Job Objects |
| `agentTree(pid)`: descendant enumeration | `/proc` walk, or `cgroup.procs` when scoped | `pgrep -g` / `sysctl` proc listing | Job Object query |
| `runtimeDir()`: socket/state dir | `$XDG_RUNTIME_DIR/mandu` | `$TMPDIR/mandu` if the instance socket fits, else the owner-checked private `0700` `/tmp/mandu-<uid>` (runtime-instances.md §3b) | `%LOCALAPPDATA%` |

The POSIX process-group path is the **portable floor** for scoping on every
OS; its weakness vs a cgroup is stated in §9.2.

### 2.3 Enforcement backend registry: the seam that keeps hardening optional

```ts
interface EnforcementBackend {
  id: 'coop-env' | /* future: macos-*, win-*, container, micro-vm */
  chokepoints: ('context'|'net'|'fs'|'exec')[]
  probe(): Availability            // available | unavailable(reason)
  prepare(plan: LaunchPlan): void  // mutate env / wrap the launch prefix
  postExit?(): void
}
```

| Backend | Layer (`privilege-model.md` §2) | Status | Mechanism |
|---|---|---|---|
| `coop-env` | wrapper layer | **REQUIRED, identical on every OS** | it IS the wrapper layer: env + PATH + CWD + proxies composed in §2.1 |
| `linux-userns` | kernel layer | **retired** (2026-07-14) | was `unshare(CLONE_NEWUSER\|NEWNS[\|NEWNET])` + slirp4netns; the bwrap layers and landlock-net + net-guard do its job |
| `linux-fs-preload` | wrapper-layer Linux-only add-on | **retired** (2026-07-14) | was the `LD_PRELOAD` interposer (`interceptors/fs-preload`, in-tree, wired to nothing) |
| `container` / VM profile | future | no commitment | a deployment profile the wrapper can *target*, never a replacement for the wrapper |
| `micro-vm` | future, **designed** in [`privilege-model.md §6`](../architecture/privilege-model.md) | the missing *portable-hard* cell of the portability × strength matrix (`privilege-model.md` §2); a wrapper-served libkrun microVM that serves the AgentView as the guest FS, robust against untrusted agents, behind this same seam |

Opt-in backends are probed at runtime and report `unavailable: <reason>` where
the facility is missing; an *explicitly requested* backend that probes
unavailable is an **error** (§5).

## 3. CLI compatibility

The flags and `MANDU_*` env spellings of the original bash launcher carry
over:

| Flag | Env twin | Semantics |
|---|---|---|
| `--net-proxy` / `--net-proxy-mitm` | `MANDU_NET_PROXY=1` / `MANDU_NET_PROXY_MITM=1` | mitm implies net-proxy; setup failure aborts (§5) |
| `--exec-wrap[=cmd1,cmd2]` | `MANDU_EXEC_WRAP=1`, `MANDU_EXEC_WRAP_CMDS` | setup failure aborts (§5) |
| `--fs-preload[=<root>]` | `MANDU_FS_PRELOAD=1`, `MANDU_PRELOAD_WORKSPACE` | **retired**: a parse-time error naming the default-on layers that cover the job |
| `--unshare` / `--unshare-net` | `MANDU_UNSHARE=1` / `MANDU_UNSHARE_NET=1` | **retired**: a parse-time error, as above |
| `--target claude\|codex\|openclaw\|opencode\|shell` | — | auto-detect from argv[0] basename otherwise, with every other unknown basename REFUSED (agent-e2e-harness.md §9, §9.1) |
| `--id`, `--no-scope`, `--no-mcp`, `--mock-sites=<path>` | `MANDU_SCOPE_ID` (minted if absent), —, —, `MANDU_NET_PROXY_MOCK_SITES` | unchanged |
| `--best-effort` | — | opts back into degrade-with-loud-warning (§5) |

The other consumed env vars (`MANDU_ARBITER_SOCK`,
`MANDU_PROXY_HOST/PORT`, `MANDU_OPENAI_*`, `MANDU_MODEL_HOSTS`,
`MANDU_ULLM_*`, `MANDU_MCP_CONFIG`, `MANDU_NO_ARBITER_AUTOSTART`) keep their
spellings and defaults. (`MANDU_EVENT_DIR` was retired: the launcher hands
its arbiter `--event-dir` instead, on-disk-layout.md §5.)

## 4. Launch data flow

1. **Parse args → `LaunchPlan`.** Detect the agent from argv[0] basename
   unless `--target` overrides; mint `MANDU_SCOPE_ID` if absent.
2. **Probe/attach arbiter.** IPC ping the socket; start the arbiter if absent
   and re-ping. No answering arbiter → refuse to launch (§5).
3. **Start services.** Model proxies, net-proxy (± MITM CA mint), exec-wrap
   shim dir, fs-sync AgentView worktree seed.
4. **Backends probe + prepare.** `coop-env` composes the env delta (§2.1);
   a kernel-layer backend may also wrap the launch prefix.
5. **Spawn.** `platform.scope()` spawn with composed env + CWD (AgentView
   worktree) + stdio passthrough.
6. **Wait** with signal forwarding; propagate the agent's exit code.
7. **Post-exit.** fs-sync AgentView → HumanView write-back; backends'
   `postExit()`; teardown of only what we started; session-end event. A ^C
   here is ignored; SIGTERM / SIGHUP still end the launcher at once (§2.1
   "Teardown signals").

## 5. Error handling: fail-closed rules

The repo invariant is fail-closed; the launcher is where a requested security
posture is either delivered or refused.

- **Arbiter unreachable at launch → REFUSE to launch the agent.** Every gate
  decides through the arbiter; launching without it means launching ungated.
- **An explicitly-requested gate that fails setup → ABORT the launch**:
  net-proxy port busy, shim dir write fails, MITM CA mint fails, a backend
  that probed available but whose `prepare()` fails. **`--best-effort`**
  opts back into degrade-with-loud-warning.
- **A layer is reported LIVE only when it can run.** The exec-wrap shims
  once printed `exec-wrap LIVE` in a checkout whose
  `interceptors/exec-wrap` dependencies were never installed; every shimmed
  call then crashed (failing closed, so nothing leaked, but every `curl`
  broke). The launcher now runs one written shim in exec-wrap's probe mode
  (`MANDU_EXECWRAP_PROBE=1`: the shim's runtime, `wrap.ts` and the arbiter
  client module load, it prints `mandu-exec-wrap: probe ok` and exits 0,
  running and connecting to nothing; `probeExecShim` in
  `launcher/src/services/exec-shims.ts`) before it puts the shim dir on the
  agent's PATH. A probe that fails is a failed start under the rules above:
  default-on, the launch goes on without exec-wrap and says so (`service
  'exec-wrap' is on by default but failed to start: the exec-wrap shim
  cannot load (…) — proceeding WITHOUT it`), and no shim that cannot load
  shadows the agent's PATH; an explicit `--exec-wrap` refuses the launch.
  The probe starts with the model and egress proxies, so its node start
  overlaps theirs. Pinned by the launcher's `exec-shims` and `manager` unit
  tests, its `services` component test (a launch against a checkout with no
  exec-wrap dependencies) and exec-wrap's `wrap.test.ts` scenario (e).
- **The probe's pass is kept for the boot (2026-10-16).** With a warm stack
  the proxies are reused at once, so the probe's node start (0.18-0.24 s on
  the development host, whose distribution node takes 0.09-0.16 s to start
  at all) was what every launch waited on in `startServices`. What it
  proves is not per-session: the probe connects to nothing, and the
  session's shim dir and arbiter socket are only exported strings it never
  reads. So a pass is kept in the launch's per-boot probe cache
  (packaging.md §5.4, entry `exec-shim`; `probeExecShimCached` in
  `exec-shims.ts`, `cachedProbeAsync` in `probe-cache.ts`) under that
  cache's rules: only a pass is kept, a failure is asked again on every
  launch (and drops a kept pass, `MANDU_PROBE_CACHE=0` included), the file
  is the user's own, `MANDU_PROBE_CACHE=0` probes afresh, and a launch that
  used a kept answer and then failed drops the file. The key is everything
  the answer depends on: the shim script as a template (this launch's shim
  dir and socket replaced; kept only when both, the command and every
  runtime token are inert in its double-quoted strings: no `"`, `$`,
  backquote, backslash or newline), the identity (real path, device, inode,
  size, mtime, ctime, mode, owner) of `/usr/bin/env`, of the bash and the
  `node` PATH finds, of the exec-shim bundle and the arbiter client module
  it loads, and of `/etc/ld.so.cache` (a shared library node links was
  replaced), the shim dir's mount and its options (`noexec`), the loader
  environment (PATH, `BASH_ENV`, `ENV`, `SHELLOPTS`, `BASHOPTS`,
  `GLIBC_TUNABLES`, `MALLOC_CONF`, every `LD_*`, `NODE_*` and `UV_*`), plus the context every kept probe has (the boot, the uid, the
  launcher's namespaces, seccomp, capabilities and AppArmor label, the
  launcher's own file). Never kept, so probed on every launch: the source
  form (tsx loads `wrap.ts` and every module it imports out of the
  checkout, which no fixed list of files keys) and a host other than
  Linux. A kept pass that is somehow wrong costs utility, not the gate:
  each shimmed call still runs exec-wrap, which fails closed (exit 77 or a
  crash) and never runs the real command raw. Overlapping the probe with
  the rest of `startServices` instead was not taken: its verdict decides
  whether the agent's PATH gets the shim dir, so the launch would wait for
  it anyway, and a refusal must come before the agent starts. Measured on
  the development host (load 45-60): the exec-wrap step of `startServices`
  from a median of 132 ms (fresh probe) to 2.6 ms (kept pass), fifteen
  interleaved runs each, real bundle and shims. The whole `mandu claude
  --version` (a checkout build, an isolated arbiter, the entry dropped
  before each "fresh" run) stayed inside the host's noise at load 50-110
  (medians 1.96 s fresh vs 2.24 s kept, thirty interleaved runs each, a
  spread of 1.5-5.4 s). Pinned by `exec-shims` unit
  tests (the key's inputs, the never-kept forms, a hit, a changed key, the
  bypass, a failure), `probe-cache` unit tests (`cachedProbeAsync`) and a
  `services` component test (the real bundle, shims, probe and cache file:
  a kept pass skips the node start, a rebuilt bundle and the bypass probe
  again, a shim that cannot load is never kept and still degrades the
  default launch and refuses `--exec-wrap`).
- **This is a deliberate tightening vs the bash launcher**, which degraded
  gracefully on nearly every path. A matrix run on a pristine guest saw that
  degrade path silently weaken the requested posture because a dependency
  was missing. Silent weakening of an explicitly requested gate is the
  launch-time analog of falling through to raw; the TS CLI makes it an error
  by default.
- **Agent crash** (non-zero exit, signal death) → write-back and teardown
  **still run**; the agent's exit code is propagated.
- **Wrapper crash mid-session** → the agent keeps running orphaned **with env
  intact**: the cooperative gates keep working because the env is baked into
  the agent's process and the services are separate processes. The missed
  write-back is detected at the **next launch** (dirty AgentView worktree).

## 6. Testing

Repo rule: unit + e2e in the same change; the e2e suite is the invariant
oracle ([CONTRIBUTING.md](../../../CONTRIBUTING.md)).

- **Unit:** the env composer (given a `LaunchPlan`, assert the **exact** env
  delta; a pure function, so table-driven); backend probes against a mocked
  platform module; arg parsing (every §3 flag/env twin); platform
  scope-fallback logic (systemd reachable / absent / `--no-scope`).
- **E2e:** launch a **fake agent** (a script that prints its env and CWD and
  attempts an egress) under `mandu`, and assert: `ANTHROPIC_BASE_URL`
  points at the proxy; the PATH shim shadows a high-risk command; CWD is the
  AgentView worktree; and **arbiter-unreachable → launch refused**, the
  fail-closed e2e every chokepoint ships.
- **Matrix integration:** this spec fills `os-test-matrix.md` §4's
  **`wrapper` suite** (deps: node): the parity e2e runs on `host` and
  `ubuntu-2604`, macOS later (§10.6), which turns "portable" from a claim
  into a tested fact (`os-test-matrix.md` §1).
- **Typecheck:** `npm run typecheck` like every package (`npm test` runs via
  tsx, which masks type errors).

## 7. Migration: parity-then-shim

Same pattern as `os-test-matrix.md` §6: (1) the TS CLI lands in `launcher/`
as an npm package alongside `mandu-run.sh`; (2) the bash script stays until a
**per-flag parity checklist** (every §3 row, exercised by the e2e suite) is
green; (3) `mandu-run.sh` becomes a thin `exec` shim over the `mandu` bin;
(4) its body is removed.

**DONE (2026-07-14): steps 3–4.** `launcher/mandu-run.sh` is a ~30-line shim
that sources the secrets env and execs the TS launcher: from SOURCE via the
launcher's local tsx in a dev checkout, or the built bundle via
`bin/mandu.mjs` when installed. Every `mandu-run.sh -- <agent>` invocation
therefore runs the ONE launcher and gains its default-on hardening. The only
non-parity: the four opt-in flags the bash launcher alone implemented
(`--fs-preload`, `--unshare`, `--unshare-net`, slirp) were **retired
outright**: requesting one is a parse-time error with an actionable message
naming the default-on layers that cover the job, rather than a silent no-op.
The bash test oracles that exercised those flags were retired in the same
change (their observable behavior is covered by the TS launcher's unit suite
and the launcher-routed live suites; see
[e2e-catalog.md](../../testing/e2e-catalog.md)).

## 8. Fences (what this is NOT)

- **No new interception mechanisms.** This reorganizes how existing gates are
  launched and wired; it adds no hooks, no syscall attachment, no parsing.
- **No monitoring / env-scrub-detection loop.** That was "Approach B",
  layerable later behind `agentTree()`, not built.
- **No Windows implementation.** The platform interface admits `win32`
  (§10); nothing is written for it.
- **No behavior changes inside arbiter / model proxies / net-proxy /
  exec-wrap / fs-sync**: only how they are launched and wired.

## 9. Honest caveats

1. **TTY fidelity for the Claude Code TUI** through stdio passthrough (raw
   mode, cursor queries, resize (SIGWINCH) propagation) needs verification
   against the real `claude` TUI on each platform; a fake-agent e2e cannot
   prove it. On Linux the differential harness (maintainers only)
   compares the wrapped and unwrapped TUI screen by screen.
2. **Process-group scoping is weaker than a systemd scope.** No cgroup
   membership signal; the wrapper's parent-of-tree tracking (`agentTree()` +
   the proc keys) replaces it, but a **double-forked daemon can escape a
   process group** where cgroup v2 would have kept it (`mandu.md` §0).
   On Linux with systemd the scope is kept to retain the stronger signal.
3. **The Codex config splice is the fiddliest part.** Codex selects its base
   URL by config file / `-c model_provider`, not env, so the composer must
   splice argv/config rather than set a variable: the one place the "pure
   env delta" abstraction leaks. Codex 0.154 keeps a separate `-c` list per
   command level (root, `exec`, `exec resume`, `review`, …), and the
   innermost level with ANY `-c` replaces the outer lists wholesale, so a
   splice placed only after argv[0] is dropped by `mandu codex exec -c
   model_reasoning_effort=low …`, and Codex would talk to api.openai.com
   directly, unmasked, while the launch looked protected (found by the
   fresh-agents VM suite, `os-test-matrix.md §10` §14). `OPENAI_BASE_URL`
   is not honored, so no env var backs the route up. The overrides are
   therefore spliced after argv[0] AND after every subcommand of the chain
   (`launcher/src/codex-argv.ts`; flag values skipped, nothing after the
   first plain positional or `--` touched), and a user override that
   re-points the provider (`-c model_provider…`, `-c model_providers.…`,
   `--oss`, `--local-provider`) is refused before anything starts, since
   within one level the last `-c` for a key wins. The provider's `env_key`
   is `CODEX_API_KEY` when only that is set, and absent for a `codex login`
   sign-in ([agent-sign-in.md](../agents/agent-sign-in.md) §2.4). Unit:
   `test/unit/codex-argv.test.ts`; e2e: `test/component/codex-routing.test.ts`.
   **Who receives the overrides (`codexOverridesReach`).** The codex binary
   gets the full splice. Any other program under `--target codex` is a
   wrapper the user vouched for, and gets them right after argv[0]: they are
   its codex's only route, so dropping them would leave a wrapper that
   passes its arguments on to codex silently unrouted. A POSIX shell (`sh`,
   `bash`, `zsh`, …) gets none, MCP entries included: it is not codex and
   cannot pass them on, and `sh -c <script>` would take the first override
   as its script. The launch prints a `WARNING` note that a codex started
   from the shell is not routed (`env-compose.ts` `codexShellNote`), as the
   `shell` target's note does. A language runtime (`node app.js`, `python3
   app.py`; `types.ts hostRuntimeOf`) gets none either (`node -c` is node's
   own `--check`): a program built on the Codex SDK is routed by the SDK
   route instead, which splices the same overrides into the argv of the
   codex the program starts ([agent-sdks.md](../agents/agent-sdks.md)). Unit: `codex-argv.test.ts`,
   `env-compose.test.ts`; e2e: `codex-routing.test.ts` (a wrapper still
   routed; a shell runs the user's script and gets the note).
   **Embedded mode by name (`CODEX_NO_DAEMON`).** Codex 0.159 runs the
   agent, tool runner included, in a shared background server, one per
   `CODEX_HOME`, that detaches (own session, parent init) and outlives the
   TUI. Any `-c` makes it run embedded instead, with a `⚠ 1 warning` footer.
   Embedded is what Mandu needs: a server started outside Mandu would run the
   tools past every chokepoint. So the launcher also passes `--no-daemon`
   when the probed Codex version is 0.159.1 or later (`codexTakesNoDaemon`;
   an older Codex refuses the flag, and an unread version gets none, costing
   only the warning). The splice places it at the root and after root-level
   `resume` / `fork` only (`exec` rejects it) and never where the user
   already gave it (clap refuses a repeat). `--remote` and `codex agents`,
   which attach to a server Mandu did not start, are refused before launch
   (`codexLaunchRefusal`). A per-session `CODEX_HOME` and an edit of the
   user's `config.toml` were weighed and dropped
   (differential-interactive.md §16). **The server subcommands** (codex-cli
   0.159.1 `--help` at every level). `codexLaunchRefusal` also refuses each
   root subcommand that starts, manages or attaches to a Codex server, found
   the way `agents` is (the root subcommand, flag values skipped, prompt text
   and anything after `--` left alone):

   | Subcommand | Decision | Why |
   |---|---|---|
   | `agents` | refused | browses sessions on the shared background server |
   | `remote-control` (bare, `start`, `stop`, `pair`) | refused | starts or manages the background server with remote control on; it detaches and takes work from outside the launch |
   | `app-server` (every form) | refused | runs the agent server for an outside client (`--listen unix://`, `ws://`), manages its detached daemon (`daemon start`, …) or attaches to it (`proxy`); the `generate-*` code generators need no Mandu |
   | `exec-server` (every form) | refused | runs the command-execution server, listening on `ws://` by default; `forward` registers it as a remote environment |
   | `debug app-server` | refused | its child `codex app-server` does not take the launcher's `-c` routing: probed, its turn went to api.openai.com, past the model proxy |
   | `exec`, `review`, `resume`, `fork` | allowed | the agent in the launched process (`--remote` on them is refused) |
   | `queue` | allowed | writes the queue database under `CODEX_HOME` and exits (probed: no server, no socket); `--remote` is refused |
   | `cloud` (alias `cloud-tasks`) | refused (2026-10-07) | sends the prompt to Codex Cloud as a task: the agent runs on OpenAI's machines, past the model proxy and every other chokepoint |
   | `sandbox`, `mcp`, `plugin`, `doctor`, `debug models` / `prompt-input`, the session bookkeeping | allowed | a plain child that exits with the launch |
   | `mcp-server` | allowed | absent from 0.154 and 0.159.1; where it exists it is a stdio child that dies with its client |

   Unit: `codex-argv.test.ts` (each refused form, the near-misses that
   launch); e2e: `codex-routing.test.ts` (the stand-in Codex never runs).
4. **The slirp4netns re-entry** was to stay bash-shaped inside the
   `linux-userns` backend; moot since that backend was retired (§2.3).

## 10. Cross-platform: macOS and Windows

> **Status: DESIGN, partly built (scope decided 2026-07-05).** Built: the
> `darwin` platform module (pgid scoping, `pgrep` tree, `$TMPDIR/mandu` if the instance socket fits, else the owner-checked private `0700` `/tmp/mandu-<uid>` (runtime-instances.md §3b)),
> historically exercised on a Mac (packaging.md §6), with fresh integrated-branch
> validation pending, plus the darwin reply-filter PTY
> backend ([packaging.md](./packaging.md) §6). Not built: the `win32`
> platform (`platform/index.ts` throws a clear "not supported yet" error),
> the four new `Platform` methods of §10.3.1, `tree-kill`, and the arbiter
> connect-probe (§10.4). Windows users run the Linux package in WSL2
> (packaging.md §6.1). Scope: the **cooperative agent model** only (trust
> the agent binary, defend against injected data), code + mocked-platform
> unit tests; the hard/untrusted-agent layer is
> [`privilege-model.md §6`](../architecture/privilege-model.md).

### 10.1 Goal

Make the `mandu` cooperative wrapper run on **macOS and Windows**, not just
Linux. The wrapper's chokepoints ride four portable seams (**env vars, `PATH`,
`CWD`, localhost proxies**) that exist on all three OSes; the work is removing
the POSIX assumptions in the launcher and adding the `win32` implementation.
macOS is most of the way there (the `darwin` platform module exists and bash
shims run); Windows is the real port.

**Invariant preserved:** `process.platform` appears in exactly one module (the
platform module). The Windows break points are *scattered* (signals in
`spawn.ts`, process-groups in `services/primitives.ts`, bash shims in
`services/exec-shims.ts`); the design **consolidates all of them behind the
`Platform` interface, then adds `win32`.**

### 10.2 What is already portable vs what breaks

| Chokepoint | Mechanism | Linux | macOS | Windows |
|---|---|---|---|---|
| Context | base-URL env → proxy | ✅ | ✅ | ✅ (env) |
| Network | `HTTP(S)_PROXY` → net-proxy | ✅ | ✅ | ⚠️ Node/curl honor env; native Win tools may use WinHTTP (§10.8) |
| Exec | PATH-shadow shims | ✅ bash | ✅ bash | ❌ → `.cmd` + PATHEXT (§10.3.2) |
| Filesystem | CWD = AgentView worktree | ⚠️ path-scoped | ⚠️ path-scoped | ⚠️ path-scoped |

Concrete Windows break points: `platform/index.ts` throws for `win32`;
`services/exec-shims.ts` writes `#!/usr/bin/env bash … exec -a`;
`services/primitives.ts` uses `process.kill(-pgid)`; `spawn.ts` forwards
`SIGWINCH`/`SIGHUP`; and the arbiter socket is a Unix path
(`arbiter/ipc/server.ts` `listen()` does `mkdirSync(dirname(sock))`, which
fails for a `\\.\pipe\…` name).

### 10.3 Architecture: consolidate, then add `win32`

#### 10.3.1 The `Platform` interface grows four methods

Alongside `runtimeDir` / `planScope` / `agentTree`:

| Method | linux / darwin | win32 |
|---|---|---|
| `arbiterEndpoint(scopeId, env)` | Unix socket path | `\\.\pipe\mandu-<scopeId>` |
| `signalsToForward()` | `["SIGINT","SIGTERM","SIGHUP","SIGWINCH"]` | `["SIGINT","SIGTERM"]` (HUP/WINCH don't exist) |
| `killTree(child)` | `process.kill(-pgid, sig)` | `tree-kill` → `taskkill /T /F /PID` (no process groups) |
| `execShim(cmd, tsx, wrap, sock)` → `{filename, content, mode}` | `cmd` file, `#!/usr/bin/env bash … exec -a` | `cmd.cmd`, `@echo off … "<tsx>" "<wrap>" %*` (found via PATHEXT) |

Three implementations (`linux`, `darwin`, `win32`); `platform/index.ts` stays
the only `process.platform` switch.

#### 10.3.2 `win32` specifics

- **Runtime dir:** `%LOCALAPPDATA%\mandu` (fallback `%TEMP%\mandu`).
- **Arbiter endpoint:** `\\.\pipe\mandu-<scopeId>`; Node's `net`
  `createServer().listen(pipe)` / `connect(pipe)` speak named pipes natively.
- **Exec shim:** a `<cmd>.cmd` batch file in the shim dir (prepended to `PATH`);
  Windows `CreateProcess` resolves a bare `curl` to `curl.cmd` via **PATHEXT**.
  The shim sets `MANDU_EXECWRAP_CMD`/`_SHIM_DIR`/`MANDU_ARBITER_SOCK` and
  `"<tsx>" "<wrap.ts>" %*`; `wrap.ts` keys off the env var, so the lack of
  a Windows `exec -a` (argv[0] spoof) does not matter.
- **Teardown:** `tree-kill` (Node, MIT): `taskkill /T /F` on Windows, `pgrep`
  walk on Unix. No process groups on Windows; a Job Object with
  `KILL_ON_JOB_CLOSE` would be stronger but needs a native addon (out of
  scope for the cooperative layer: the agent is trusted not to daemonize
  away).
- **`scopeSpawn`:** detached child; scope membership is the wrapper's
  parent-of-tree tracking (`agentTree`) as on the pgid path.

#### 10.3.3 macOS (`darwin`)

The `darwin` module exists (pgid scoping, `pgrep` tree, `$TMPDIR/mandu` if the instance socket fits, else the owner-checked private `0700` `/tmp/mandu-<uid>` (runtime-instances.md §3b)). Its
gaps are the same four methods above (bash shim + POSIX signals + pgid kill,
all reused from linux) and **verification on a real Mac**, which has not
happened (packaging.md §6 item 1).

#### 10.3.4 De-POSIX the generic modules

- `spawn.ts` → forward `platform.signalsToForward()` instead of the hardcoded set.
- `services/primitives.ts` teardown → `platform.killTree(child)` instead of
  `process.kill(-pgid)`.
- `services/exec-shims.ts` → write `platform.execShim(...)` (filename + content +
  mode) instead of the hardcoded bash shim.
- Command lookup → a **pure-Node PATH + PATHEXT lookup** (no `bash -c`);
  `systemdUserOk` stays Linux-guarded.
- The arbiter endpoint everywhere comes from `platform.arbiterEndpoint(...)`.

#### 10.3.5 `killTree` — ending what the agent leaves running (darwin, 2026-09-29)

**The gap.** On darwin the launch is scoped by a process group only, and
`runAgent` waits for the chain's first process (the reply-filter). Post-exit
stopped the per-session services and nothing else: a `sleep 300 &`, a dev
server, an MCP server that ignored its stdin EOF all lived on, still inside the
Seatbelt wrap, with `HTTP(S)_PROXY` naming ports nobody served any more. Linux
does not have this gap wherever the twin wrap is in the chain: its PID namespace
dies with its first process and takes the tree along.

**Why a kill-time walk cannot work (measured on macOS 26.5.1).**

- The moment the chain's first process exits, everything it left running is
  reparented to launchd (ppid 1). A `pgrep -P` walk from the root, which is what
  `tree-kill` does on Unix, finds nothing.
- The chain's process group is not the tree either. BSD `script(1)` (the
  reply-filter's PTY relay) runs the agent in a session of its own, and Claude
  Code starts every Bash command, hook and background task detached, in a new
  session each (the bash provider in Claude Code 2.1.284 spawns with
  `detached: true`). A `kill(-pgid)` reaches none of them.
- macOS has no session id to ask for: `ps -o sess` prints a zeroed kernel
  pointer, `pgrep` has no `-s`, and `ps -E` shows no other process's
  environment, so an env marker cannot name the tree either.

**The design (`launcher/src/platform/proc-tree.ts`).** `trackTree(rootPid)`
samples the tree while the chain runs: one `ps -x -o
pid=,ppid=,pgid=,stat=,etime=,lstart=` (this user's processes, a few ms) at
once and then once a second, from an unref'd timer. It runs under `LC_ALL=C
TZ=UTC0`: `lstart` is rendered in the local time zone, so without the pin a
zone change mid-session (automatic time zone on a travelling laptop) rewrote
every recorded start time, and the teardown found nothing. Each sample
records two sets:

- **members**: every process seen in the tree (the root, its descendants by
  ppid, every live process of a recorded group, and the live descendants of
  every earlier member), keyed by pid AND start time (`lstart`), so a recycled
  pid is a different process;
- **groups**: every process group a member was seen in. Such a group belongs
  to a session an agent process created (`setsid` only makes a NEW session;
  `setpgid` only joins a group of the caller's own session), so every process
  in it was started by the agent, including a child forked after the last
  sample whose parent has since exited. A group is trusted only while it
  lives (below).

After the chain exits, `killTree` stops the sampler and reads a fresh table.
The targets are the live members (pid and start time match), the live
processes of a recorded group, and every live descendant of either. After a
250 ms settle (what is exiting on its own, such as an MCP server on its stdin
EOF, is not counted), each target gets SIGTERM and SIGCONT. The table is read
again every 100 ms, so a child forked during the grace gets its SIGTERM too.
After 2 s the survivors get SIGKILL, in up to three rounds. Every signal goes to
a pid that the table just listed as a target. No group signal is sent, because
a group id is trusted only as far as the table that confirmed it.

**Never a target:** anything older than the launch (an age floor from `etime`,
with 2 s of slack for one-second resolution), the launcher, its ancestors (the
user's shell), the launcher's process group, pid 0/1, and zombies. Mandu's own
services are never in the tree: the launcher spawns them, not the chain, each
in a session of its own. A `mandu` started *inside* the agent is the agent's,
and ends with it, as it would in Linux's PID namespace. An unreadable table
signals nothing: the teardown never kills blind.

**The age floor is the chain's spawn (2026-10-09).** "The launch" here is the
moment the chain's first process was spawned, which `runAgent` hands to
`trackTree` (`TrackTreeOpts.sinceMs`). Since the reply filter is started with
the services and handed its agent later (`reply-filter.ts`, 2026-10-04),
`runAgent` adopts a chain that is seconds older than the call. The floor was
the time tracking began, so the root and the filter's own processes read as
older than the launch, no seed was found, and the session end stopped
nothing: the agent's background jobs outlived the session inside the Seatbelt
wrap. The first macOS CI run that reached the suites found it
(`darwin-teardown.test.ts`, the real launch path). An adopted chain now carries
its spawn time (`AdoptedChain.spawnedAtMs`), and a floor in the future is
clamped to now.

**Recorded groups expire.** Every table, before any target is chosen, drops
two kinds of recorded group. The first is a group that no process in the
table carries any more: it emptied, and the kernel frees its id with it, so
that id can only come back as the pid of a new leader, which makes it someone
else's group. This holds even after that new leader exits and leaves its
members behind, with no leader left to compare. The second is a group whose id
now names a different process: a leader whose start time is not the recorded
one, that is older than the launch, or that is the launcher or one of its
ancestors. A leader that is merely a zombie still names the same group.
Without the expiry a group recorded early in a long session stayed trusted
until teardown. After a pid wrap another session's shell (or the user's own
`sh start.sh`) could lead a new group with that id, start a server in it and
exit, and the teardown ended that server. The expiry runs on every sample, so
a group escapes it only if, within one sampling interval (1 s), it empties,
its id is reused as a new leader's pid, and that leader exits again.

**Order and output.** `runAgent` (spawn.ts) calls `trackTree` right after the
spawn. Once the chain exits it calls `killTree` BEFORE `onChainExit` and
`postExit`, so nothing the agent started outlives the services it was pointed
at. When anything was stopped, it prints one line:
`mandu: the session ended, so N processes the agent left running were stopped
(pid …)`. The teardown is best-effort. A throw never changes the exit code or
skips `postExit`. It starts only when the chain exits: a job that keeps the
chain's stdout open (`sleep 300 &` without a redirect) keeps the reply-filter's
pipe mode waiting for EOF, so the launch lasts until that job ends. That is the
reply-filter's behaviour and is not changed here.

**Linux keeps its behaviour.** `linuxPlatform.trackTree` is inert and
`killTree` ends nothing, and says so in `skipped`. The twin wrap's PID namespace
ends the tree. The Linux gap this leaves: where the twin wrap is not in the
chain (mode `off`, a posture without it), background processes outlive the
session. On the systemd path they stay inside the scope, attributed, and
`systemctl --user stop mandu-<id>.scope` ends them. On the detached no-systemd
fallback they are loose, as darwin's were. The same engine could close this over
`/proc`, but that is not built.

**The residual (documented, not closed).** A process that moves to a new
session AND loses its parent within one sampling interval is never seen, so it
outlives the session. Examples are a double-fork daemon, or `cmd &` inside one
Bash tool call that returns at once (Claude Code's own shell for that call lives
for milliseconds). `run_in_background` tasks, MCP servers, the reply-filter's
`script` session, and anything that lives past one sample are ended. Closing the
residual needs kernel help that macOS does not give an unprivileged process.
Endpoint Security and DTrace need root or an entitlement, and kqueue's
`NOTE_TRACK` is unsupported on macOS. Linux's answer is the PID namespace or cgroup.
Separately, a launcher killed with SIGKILL runs no teardown at all (the services'
lifeline covers only the services).

**Tests.** `launcher/test/unit/proc-tree.test.ts` (injected `ps` tables:
parsing, the `ps` env with `TZ` pinned, the membership rules, the exclusions,
pid and group recycling, group expiry (an emptied group whose id later leads
an orphaned group with no leader yields no target), the residual pinned as
such, and the SIGTERM → grace → SIGKILL loop on a fake host).
`launcher/test/unit/spawn.test.ts` (the hook's order, and that it is
best-effort). `launcher/test/component/darwin-teardown.test.ts` (macOS only):
`runAgent` + `darwinPlatform` on the real host with a plain `&` job, a
`nohup` job, a `setsid` process and a SIGTERM-ignoring job, and a bystander
that must survive. It also runs the real launch path: `mandu --target shell --
sh -c '… & echo started'` in mode `secrets` under a scratch HOME, with a
confined fake credential, so the jobs run inside the Seatbelt wrap. The jobs
end, the line is printed, and the autostarted arbiter and dashboard keep
running.


### 10.4 Arbiter liveness: connect-probe (+ one arbiter guard)

Named pipes are not files, so the launcher's `existsSync(sock)` attach check
(`launcher/src/arbiter.ts` `pollSocket`) cannot work on Windows. The design
replaces it with a **connect-probe**: attempt a short `net.connect(endpoint)`;
if it answers, attach. This is OS-agnostic and also stops a stale Unix
socket file from reading as "arbiter alive".

One targeted arbiter-package change: `arbiter/ipc/server.ts` `listen()` does
`mkdirSync(dirname(socketPath))` + `existsSync`/`unlinkSync`, which for a
`\\.\pipe\…` endpoint (dirname `\\.\pipe`) throws. Guard it: **when the endpoint
is a named pipe (prefix `\\.\pipe\`), skip the filesystem prep and just `listen`.**
Everything else stays launcher-side.

### 10.5 Reuse

| Concern | Decision |
|---|---|
| `killTree` (process-group vs Job Object) | adopt [`tree-kill`](https://github.com/pkrumins/node-tree-kill) (Node, MIT) behind `platform.killTree`; do not hand-roll `killpg`/`taskkill` |
| per-OS exec-shim + signal set | reference [Codex CLI sandbox](https://github.com/openai/codex) (Apache-2.0): its Windows restricted-token crate + macOS SBPL confirm the per-OS shapes |
| arbiter-over-UDS / pipe egress model | validated by [Anthropic `sandbox-runtime`](https://github.com/anthropic-experimental/sandbox-runtime) (UDS→host-proxy egress = Mandu's design) |
| the wrapper's env/PATH/CWD interception | stays ours: no OSS symbolizes model context; the cooperative wrapper is the Mandu contribution |

The Rust `process-wrap` crate is for the **Rust `*-supervisor` crates**
(kernel layer), *not* this TypeScript launcher, whose analog is `tree-kill`;
it and any FUSE/ProjFS filesystem work are out of scope here.

### 10.6 Testing: mocked platform, no real OS

Unit-test each generic module against a **fake `Platform`**: the win32 branch
emits a `.cmd` shim (not bash), the `\\.\pipe\` endpoint form, the reduced
signal set, and `tree-kill`-shaped teardown; darwin still emits bash + pgid +
Unix socket. A command-lookup unit test covers PATHEXT resolution. The
arbiter connect-probe gets a unit test with a live mock server. No real
Windows run and no `wrapper` matrix target for a new OS yet; the macOS
GitHub Actions job (packaging.md §6 item 3) is the first real-OS run.

### 10.7 Fences

- **No filesystem-chokepoint work**: the CWD worktree is already portable.
- **No hard/untrusted-agent layer**: Seatbelt/microVM/Job-Object-as-boundary
  live in [`privilege-model.md §6`](../architecture/privilege-model.md).
- **No arbiter IPC audit**: only the one named-pipe guard.
- **No new interception mechanisms**: this reorganizes launch and adds `win32`.

### 10.8 Honest caveats

1. **Windows egress via `HTTP_PROXY` is partial.** Node and `curl.exe` honor the
   env var; some native Windows tools use the WinHTTP system proxy instead. Full
   Windows egress capture would need WFP/WinDivert (admin, hard layer), out
   of the cooperative scope. The cooperative wrapper gates env-honoring
   tools, which is the injected-agent-through-normal-tools threat.
2. **`.cmd` shim quoting** is crude batch syntax; the shim only forwards `%*` to
   `tsx wrap.ts`, so exposure is minimal, but paths with spaces need the quoting
   verified on a real Windows run.
3. **PATHEXT ordering**: a real `curl.exe` earlier on PATH than the shim dir
   would win; the shim dir is *prepended*, so it shadows, but a user profile
   that re-prepends its own dir can defeat it. Assert *presence* on PATH, not
   position.
4. **`tree-kill` is enumeration-based** (racy vs a Job Object). Acceptable for a
   trusted, non-daemonizing agent; the hard layer uses a real Job Object /
   microVM.
5. **macOS is experimental and needs a fresh integrated-branch hardware run**: the macOS branch records hardware runs
   (packaging.md §6), and the current integration must rerun them.
