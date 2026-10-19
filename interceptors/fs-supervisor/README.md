# fs-supervisor (Rust lib) — Track B

`openat()` redirection of **tracked workspace paths** to the **AgentView**
git worktree. A read of a tracked file serves the symbolized AgentView; a write
is captured into AgentView (the `fs-sync` TS daemon reconciles to HumanView).

## Pure vs kernel-gated

| Module | Pure / gated | What |
|---|---|---|
| `layout` | **pure** | view path math + `rewrite_to_worktree` (faithful port of `fs-sync/src/git.ts::rewriteToWorktree` + `layout.ts`; same `<basename>-<sha256(root)[:12]>` workspace-id derivation as `workspaceIdFor`). |
| `decision` | **pure** | tracked-root matching (`TrackedRoots::match_path`), open-flag → access intent (`Access::from_flags`), the `decide_open` routing decision, and `first_touch_classify` (arbiter classify + symbolize on first touch, fail-closed). |
| `events` | **pure** | the `fs_action` event builder (AgentView for a redirect, HumanView for a passthrough). |
| `landlock` | **pure** | the Landlock ruleset PLAN (`plan_landlock` / `plan_landlock_deny_tcp` / `plan_agent_view_sandbox` → `LandlockPlan`): the asymmetric overlay (whole real FS READ-ONLY; AgentView worktree + scratch `/tmp` READ-WRITE) plus the net-off posture (all TCP bind/connect DENIED; `allow_tcp_port` pokes single ports through) as pure data, with FS and net rights each masked to a target ABI. `LANDLOCK_ACCESS_FS_*` / `LANDLOCK_ACCESS_NET_*` bit constants defined locally (no libc). |
| `kernel` | **`--features kernel`** | the seccomp-unotify supervisor loop (SECCOMP_USER_NOTIF reads openat args; enacts the pure `OpenDecision` via `addfd` for a redirect / `CONTINUE` for a passthrough). Syscall plumbing only — all policy is in `decision`/`layout`. |
| `landlock` (gated section) | **`--features kernel`** | Landlock ENACTMENT: `landlock_abi_version` / `landlock_supported` (runtime probe) + `restrict_self_to_plan` (create ruleset → add path + net-port rules → `no_new_privs` → `landlock_restrict_self`). Raw syscalls `444/445/446` (arch-generic; same on x86_64 + aarch64). |

**Pure decision function:** `decision::decide_open(roots, path, flags, first_touch)
-> OpenDecision` (Redirect to the AgentView worktree, or Passthrough).

**Behind `kernel`:** `kernel::run_supervisor(listener_fd, roots)` + `kernel::step`;
`landlock::restrict_self_to_plan(plan)` (the Landlock backend, below).

## Landlock backend (unprivileged, kernel ≥ 5.13, defense-in-depth)

An **LSM-enforced** filesystem **and TCP-network** sandbox for the FS chokepoint,
complementing the seccomp redirect and the exec sandbox's bubblewrap overlay.

**Filesystem:** it enforces the SAME asymmetric overlay `exec-supervisor::sandbox`
bind-mounts — the whole real FS **READ-ONLY**, with the AgentView worktree +
scratch (`/tmp`) the only **WRITABLE** subtrees — but as an in-kernel access check
that holds even for a process that escapes or was never wrapped by bubblewrap. A
prompt-injected write to `~/.bashrc` or exfil staging in the real `/tmp` is
refused by the kernel.

**Network (ABI v4, kernel ≥ 6.7):** the AgentShell world is net-off by design —
the exec sandbox's bwrap netns already unplugs it; the deny-TCP plan makes the
same posture hold at the LSM even for a **netns escape or an unwrapped process**.
`plan_agent_view_sandbox` therefore handles `LANDLOCK_ACCESS_NET_BIND_TCP |
CONNECT_TCP` with **no allow rules** (handled-but-never-granted = denied
everywhere). `LANDLOCK_RULE_NET_PORT` allow rules (`LandlockPlan::allow_tcp_port`)
can poke single TCP ports through — for a future launcher wrap that must reach
only the model-proxy port. **Honest boundary:** Landlock net governs **TCP only**
(UDP/ICMP/unix sockets untouched) — the netns remains the full net boundary.
CAUTION: the net bits are a **separate bit-namespace** from the FS bits (they
collide numerically — `BIND_TCP == FS_EXECUTE == 1<<0`); never OR them into one
mask (`handled_access_net` vs `handled_access_fs`).

- **Unprivileged**: Landlock needs **no root and no capability** — only
  `no_new_privs` (which `restrict_self_to_plan` sets), or CAP_SYS_ADMIN in a userns.
- **The ABI ladder** (each rung probe-gated via `landlock_abi_version()`, so every
  supported right is **ON BY DEFAULT** and simply inert on older kernels):
  v1 (kernel ≥ 5.13) the base FS rights; v2 (≥ 5.19) `FS_REFER`; v3 (≥ 6.2)
  `FS_TRUNCATE`; v4 (≥ 6.7) `NET_BIND_TCP`/`NET_CONNECT_TCP`; v5 (≥ 6.10)
  `FS_IOCTL_DEV` and v6 (≥ 6.12) scoped signals/abstract-unix — **not yet
  modelled** (the documented frontier in `abi_access_mask`). FS and net rights are
  each **masked to the running kernel's ABI** on their own ladder before they
  reach the ruleset (the kernel rejects an unknown access bit, which would fail
  the whole restrict and leave the process UNrestricted; masking keeps the
  restriction enforceable and fail-closed).
- **The 8-vs-16-byte attr compat rule**: `landlock_ruleset_attr` grew
  `handled_access_net` at v4 (8 → 16 bytes). The kernel's `copy_struct_from_user`
  E2BIGs a size larger than it knows unless the trailing bytes are zero, so the
  enactment passes **size=16 only when the ABI-masked `handled_access_net` is
  nonzero** (possible only on a v4+ kernel) and otherwise the universally-safe
  FS-only **size=8** — a pre-6.7 kernel always takes the 8-byte path because the
  net mask is zero below v4.
- **Deny-all vs port-allow**: an empty `net_rules` with a nonzero handled net mask
  denies ALL TCP bind/connect (the AgentShell posture); each `NetPortRule` grants
  its access bits on exactly one port (host byte order, ≤ 65535 — the UAPI
  `landlock_net_port_attr` is two naturally aligned u64s, NOT packed, unlike
  `landlock_path_beneath_attr`). Enactment drops allow rules the live ABI cannot
  express — dropping an ALLOW only denies more, so fail-closed is preserved.
- **Irreversible**: `restrict_self_to_plan` restricts the calling thread + all
  descendants and is inherited across `execve` — so the right shape is a
  **forked child, just before `execve`**, leaving the supervisor unrestricted.
  Fail-closed: any error → `Err` (the
  caller aborts the exec rather than running unrestricted on a supporting kernel).
- **Wired into the exec sandbox (both backends).** This is no longer an intended
  shape — `exec-supervisor` enacts it: the legacy **InProcess** backend calls
  `restrict_self_to_plan` in the forked child just before `execve` (fail-closed
  exit 71 on a supporting kernel; probe-gated self-SKIP below 5.13), and the
  default **Bubblewrap** backend enacts the same plan *inside* the box via the
  interposed `mandu-landlock-apply` bin — after bwrap's mounts, because a
  Landlock-restricted thread cannot `mount(2)`. See
  `interceptors/exec-supervisor/README.md` for the applier's locate/degrade rules.

Pure plan (unit-tested unprivileged): `landlock::plan_landlock(ro_root, rw_paths,
abi)` (FS-only) / `landlock::plan_landlock_deny_tcp(...)` (FS + all TCP denied;
chain `.allow_tcp_port(port, access)`) / `landlock::plan_agent_view_sandbox
(agent_view_root, abi)` (the AgentShell posture: overlay + net-off).

The enactment self-SKIPs where the kernel lacks the rung (FS tests < 5.13, net
tests < 6.7) and runs live otherwise — this host (6.8, ABI v4) exercises all of
it, no root, no unshare:

```
# Unprivileged (no root, no unshare) — self-SKIPs per-test below the needed ABI:
cargo test -p fs-supervisor --features kernel -- --ignored --nocapture landlock
#   → FS overlay: write inside RW dir OK, write to RO control dir EACCES
#   → net-off:    TCP connect + bind EACCES, UDP unaffected (TCP-only scope)
#   → port rule:  CONNECT allow-rule admits the connect; bind stays denied
```

## Security invariant (fail-closed)

A tracked read is **always** redirected to the AgentView worktree, even if the
arbiter first-touch classify/symbolize fails (`first_touch_classify` returns
`arbiter_miss=true` with a fail-closed UNTRUSTED verdict, and the redirect still
holds). We never fall through to raw HumanView bytes.

## Running the kernel path (privileged host)

Requires root (or CAP_SYS_ADMIN), kernel ≥ 5.4 with
CONFIG_SECCOMP_USER_NOTIFICATION, and the agent under the launcher's cgroup v2
scope.

```
cargo build -p fs-supervisor --features kernel
sudo ./target/debug/fs-supervisor ...                       # attach to the notif fd
cargo test  -p fs-supervisor --features kernel -- --ignored # root only
```

The default `cargo build` / `cargo test` need **no privileges** and skip the
`#[ignore]`d `tests/kernel_integration.rs`.
