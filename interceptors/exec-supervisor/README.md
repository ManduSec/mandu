# exec-supervisor (Rust lib) — M3

On `execve`, select **AgentShell** vs **HumanShell** and resolve argv only after
the gated data-usage check.

- **AgentShell (default):** net off, FS = AgentView, argv stays **symbolic** (the
  output is already symbolic and safe). No desymbolization. The **world** it runs
  in is the asymmetric overlay (`sandbox`, exec-routing.md §4 Phase 1): **RW =
  the AgentView worktree** (over the workspace path), **RO = the rest of the
  filesystem** (a write outside the AgentView fails), **net = off**, plus fresh
  `/dev` `/proc` and a writable `/tmp` scratch. It is further **hardened** (all
  on by default, all unprivileged bwrap toggles): the **PID / IPC / UTS / cgroup**
  namespaces are unshared (so the fresh `/proc` shows only sandbox PIDs, no shared
  IPC/hostname/cgroup view), a **new session** blocks `TIOCSTI` terminal-injection
  (AgentShell commands are non-interactive), **all in-userns capabilities are
  dropped** (`--cap-drop ALL`), **userns nesting is disabled** — via
  `--disable-userns` where the **probed** bwrap supports it (≥ 0.8; the backend
  runs `bwrap --help` once per process, parent-side, unless the launcher baked
  the sha256 of exactly that bwrap's bytes as one that supports it,
  `MANDU_BWRAP_DISABLE_USERNS_SHA256`), and otherwise by the
  **seccomp filter itself** (`agentshell_seccomp_filter_with(deny_userns=true)`:
  `unshare`/`clone` with `CLONE_NEWUSER` → EPERM, `clone3` → ENOSYS so callers
  fall back to the filtered `clone`; plain fork/clone stay allowed) — an older
  bwrap would reject the unknown flag and kill every AgentShell exec, so the
  denial degrades to the next-best unprivileged mechanism, never silently away —
  and a **seccomp deny-filter** (`seccomp_filter`) is installed via
  `--seccomp <fd>` — a default-allow BPF deny-list of dangerous syscalls (ptrace,
  process_vm_*, kexec_*, bpf, init/finit/delete_module, mount/umount2/pivot_root/
  move_mount/fsopen, open_by_handle_at/name_to_handle_at, setns, reboot, swapon/off,
  add_key/keyctl/request_key, kcmp, userfaultfd, perf_event_open) that ordinary
  agent tools never need. The box also carries a **Landlock LSM leg** (below) that
  re-states the same RO/RW overlay plus a deny-all-TCP posture in-kernel. This is
  defense in depth against a prompt-injected
  command reaching for a kernel-escape surface.
- **HumanShell:** net on, FS = HumanView, argv desymbolized — but **only after**
  the data-usage check via `resolveExecArgv`. A symbol in command/code position
  is **left symbolic** and surfaced for approval. No sandbox (passthrough).

## Pure vs kernel-gated

| Module | Pure / gated | What |
|---|---|---|
| `orchestrate` | **pure** | `plan_exec`: pick the shell (with **escalation gating** + proxy **correlation**), then (HumanShell only) `resolveExecArgv` to desymbolize argv after the data-usage check. Correlation (`execDecisionFor`) tightens HumanShell → AgentShell when the proxy recorded a block/AgentShell/evasion; `EscalationMode::Gated` routes a `needs_*` escalation through `escalateExec` (HumanShell only on human approval). Produces an `ExecPlan` (shell, argv, approvals, `escalation_pending`). |
| `sandbox` | **pure** | the AgentShell **world** (exec-routing.md §4/§5): `plan_sandbox` → `SandboxPlan` (RW=AgentView / RO=rest / net=off / fresh dev+proc+tmpfs + hardened PID/IPC/UTS/cgroup namespaces + new-session + `--cap-drop ALL` + `--disable-userns` + a `seccomp_fd` slot + the Landlock slots: `landlock_rw_paths` — the RW set in in-box coordinates — and `landlock_apply`, the applier path the kernel backend fills in); `bwrap_argv` (Linux bubblewrap realization; interposes the applier when set) and `seatbelt_profile` (macOS SBPL deny tier). Fully unit-tested; the kernel feature only enacts the plan. |
| `seccomp_filter` | **pure** | the AgentShell **seccomp deny-filter** builder — a classic BPF, default-allow deny-list of dangerous syscalls, emitted as raw `struct sock_filter[]` bytes for `bwrap --seccomp <fd>`. Two postures: the base list (`agentshell_seccomp_filter`, for a bwrap ≥ 0.8 whose `--disable-userns` owns the userns-nesting denial) and `agentshell_seccomp_filter_with(deny_userns=true)` (for a probed bwrap < 0.8: adds `unshare`/`clone`+`CLONE_NEWUSER` → EPERM and `clone3` → ENOSYS). No `libc`; per-arch syscall tables (x86_64 + aarch64) unit-tested, including a cBPF evaluator that checks the verdicts and every jump target. |
| `events` | **pure** | the `exec_action` event builder (AgentView for AgentShell, HumanView for HumanShell). |
| `kernel` | **`--features kernel`** | the seccomp/ptrace `execve` trap + the fork-model per-shell sandbox. Two backends: **`Bubblewrap` (DEFAULT)** — execs `bwrap` from `sandbox::bwrap_argv` (the full asymmetric overlay + hardened namespaces + the seccomp deny-filter, materialized as a non-CLOEXEC fd and threaded in as `--seccomp <fd>`; **requires `bwrap` on PATH**; `--disable-userns` is probe-gated — `bwrap_help_supports` parses one parent-side `bwrap --help` per process (skipped when the launcher-baked `MANDU_BWRAP_DISABLE_USERNS_SHA256` matches the resolved bwrap's bytes), and a bwrap < 0.8 swaps the userns-nesting denial into the filter; interposes `mandu-landlock-apply` inside the box when located) — and `InProcess` (legacy opt-in: `unshare`+`mount`, net-off netns + AgentView bind, no mount-level RO / hardening / seccomp — but now with the Landlock leg: the forked child calls `restrict_self_to_plan` just before `execve`, that backend's **first RO-outside-AgentView enforcement**, fail-closed exit 71 on a supporting kernel). Both block on `plan.approvals`. Fail-closed: if the seccomp fd can't be created, the AgentShell exec is refused (exit 71) rather than run un-filtered. |

**Pure decision functions:** `orchestrate::plan_exec(client, req) -> ExecPlan`
and `sandbox::plan_sandbox(shell, view, cwd) -> SandboxPlan`.

**Behind `kernel`:** `kernel::supervise_exec` (fork model, `SandboxBackend`) +
`kernel::run_supervisor` (seccomp attach front-end).

## The Landlock LSM leg (both backends)

The AgentShell world now carries the `fs-supervisor::landlock` plan in-kernel, so
the RO/RW overlay and the net-off posture hold at the LSM even if a mount trick
or netns is escaped. The plan shape: **RO `/`**, **RW = the workspace path (the
AgentView bind destination) + `/tmp`** (in-box coordinates), a **WRITE_FILE-only
carve-out on `/dev`** (`> /dev/null` opens; no MAKE_* rights, so nothing can be
*created* under `/dev` — `/dev/shm` cannot become exfil staging), and
**deny-all-TCP** via `handled_access_net BIND|CONNECT` with no rules (ABI ≥ 4,
kernel ≥ 6.7; masked away below that, where the bwrap netns remains the net
boundary).

- **Bubblewrap backend:** a Landlock-restricted thread cannot `mount(2)`, so the
  restrict must happen *after* bwrap's mounts — a helper bin,
  **`mandu-landlock-apply`** (this crate, `kernel` feature), is interposed
  inside the box: `bwrap …mounts… --seccomp <fd> -- mandu-landlock-apply --rw
  <workspace> --rw /tmp --deny-tcp -- <argv>`. It is located via
  `SupervisorConfig.landlock_apply` → `$MANDU_LANDLOCK_APPLY` → a sibling of
  the current exe; a **missing applier degrades to mounts-only** (the LSM is
  purely additive there — the bwrap overlay still enforces RO/RW and the netns
  still kills the net). The applier itself is fail-closed: a restrict error on a
  supporting kernel exits 71, the target argv is never exec'd unrestricted.
- **InProcess backend (legacy):** the forked child calls
  `restrict_self_to_plan` just **before `execve`** (mounts are done by then) —
  this backend's **first-ever RO-outside-AgentView enforcement** (it has no
  mount-level RO). Fail-closed exit 71 on a supporting kernel; probe-gated
  self-SKIP below 5.13. **Honest residual:** its RW `/tmp` is the REAL `/tmp`
  (this backend mounts no tmpfs), so scratch staging remains there — the default
  Bubblewrap backend masks `/tmp` with a fresh tmpfs.

`ExecOutcome.landlock_engaged` reports whether the leg was actually applied
(kernel support and, for Bubblewrap, an applier found); `ro_enforced` is now also
true for InProcess-with-Landlock. Kernel integration tests prove the overlay
(write inside RW OK, outside EACCES) and the net leg (connect/bind → EACCES,
UDP unaffected) live — on this 6.8 / ABI v4 host, unprivileged.

## Security invariant (fail-closed)

- A **classifyExec arbiter miss defaults to AgentShell** (the safe view: net off,
  AgentView FS, argv symbolic) — never HumanShell.
- On a HumanShell, a **resolveExecArgv miss withholds all symbols** (argv runs
  unchanged / requires approval) — an argv is never desymbolized without a
  positive gate decision. A symbol in command/code position is never resolved.

## Running the kernel path (privileged host)

Requires root, namespace + seccomp/ptrace support, and the agent under the
launcher's cgroup v2 scope.

```
cargo build -p exec-supervisor --features kernel
sudo ./target/debug/exec-supervisor ...                       # attach to the execve trap
cargo test  -p exec-supervisor --features kernel -- --ignored # root only

# unprivileged user namespace (no host changes) — also exercises the Bubblewrap
# backend's asymmetric-overlay test (needs `bwrap` on PATH):
unshare --user --map-root-user --mount --net --pid --fork -- \
  bash -c 'cargo test -p exec-supervisor --features kernel -- --ignored --nocapture'
```

Default `cargo build` / `cargo test` need **no privileges** and skip the
`#[ignore]`d `tests/kernel_integration.rs`.
