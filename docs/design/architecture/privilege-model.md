# Mandu — Privilege Model

> Companion to [`mandu.md`](./mandu.md) (architecture; see §4.0 cgroup scoping,
> §4.1–4.4 chokepoints, §6 honest hard problems) and
> [`implementation-plan.md`](./implementation-plan.md) (the `kernel` cargo-feature
> gating, and the note that Codex's Landlock+seccomp sandbox is a working
> reference). §6 holds the unbuilt microVM tier for untrusted agents. This
> doc answers a single question that the architecture doc deliberately leaves
> open: **how much OS privilege does Mandu actually require, and can we get the
> security invariant without root?** Terminology pairs the paper term with the
> adfi-openclaw repo term, per repo convention (e.g. *AgentView (repo: Agent File
> System / agent-view worktree)*, *T-LLM (privileged LLM)*).

The short answer: the **core invariant ships at zero privilege today**, and the
privileged defense-in-depth on top can be obtained **without host root and
without host pollution** by wrapping the agent in an **unprivileged user
namespace**. The expensive options (host root, a QEMU VM) address a
threat — a fully hostile native payload escaping the namespace — that is *not*
Mandu's primary adversary, and are **decided out of scope, not deferred**
(2026-07-16, §0): they will not be implemented while the non-root principle
stands.

> **Status.** The three kernel-attaching interceptor crates' (`fs-supervisor`,
> `net-supervisor`, `exec-supervisor`) kernel-attachment loops are implemented
> behind each crate's `kernel` cargo feature and run end-to-end on a 6.x kernel
> through the unprivileged-user-namespace path (the kernel layer) — exec sandbox
> (net-dead AgentShell + bind-mounted AgentView + the Landlock LSM leg in both
> backends), net-supervisor TPROXY-in-netns and the `connect(2)` guard, and
> fs-supervisor seccomp-unotify openat **interception AND the ADDFD openat
> redirect** (kernel ≥ 5.9). The harness is `scripts/kernel-tests.sh` (the
> userns runner); `scripts/kernel-vm.sh` covers older kernels. What is *not
> yet* live is called out in §1 below (net-supervisor's single-buffer read;
> exec-supervisor's `run_supervisor` attach front-end is still glue).

---

## 0. The governing principle — implement everything that is non-root

> **Mandu implements every OS security primitive it can attach *without host
> root*, and turns each *on by default* wherever the running kernel supports it**
> (probe-gated; degrade/self-SKIP where the feature or kernel version is absent).
> The privilege boundary is the *only* thing that gates a mechanism out. An
> unprivileged hardening that is available and unused is a **gap to close, not a
> design choice.**

This is why the ladder below is exhaustive on the non-root side. Everything that
an unprivileged process (or root-in-an-unprivileged-userns, §2) can turn on, we
turn on:

- **Namespaces** — user, mount, net, **PID, IPC, UTS, cgroup** (the AgentShell
  exec sandbox unshares all of them by default; the secret-confinement wrap adds
  the subset that does not break a live networked agent).
- **seccomp, three uses** — user-notification *interception* (`fs-supervisor`
  `openat`, `exec-supervisor` `execve`, and now `net-supervisor` **`connect`** — the
  IP/domain-aware egress connect-guard, §7.5 of exec-routing.md; with a secret
  policy also the open family, every open that can read or write PERFORMED by
  the guard in the tracee's view, and `landlock_restrict_self`, mirrored on guard threads
  so a sandboxed task's performed opens stay in its sandbox,
  confidentiality-plan-10 §4.1a; where the guard serves the secret twins with
  no bind, also the stat calls that name a path and follow it, `stat` /
  `newfstatat` / `statx` without `AT_SYMLINK_NOFOLLOW` or `AT_EMPTY_PATH` on
  a real descriptor,
  answered for a twinned path with the twin's metadata, confidentiality.md
  §7.2a), a syscall-denial
  *deny-filter* (the AgentShell bubblewrap child gets a default-allow BPF deny-list
  of dangerous syscalls via `bwrap --seccomp <fd>` — ptrace / process_vm_* / kexec /
  bpf / module / mount-family / handle-family / setns / io_uring / …, plus
  `socket(AF_VSOCK)` → EAFNOSUPPORT, the host channel a netns does not cut;
  exec-routing.md §4.1; and `socket`/`socketpair(AF_UNIX, SOCK_DGRAM|SOCK_RAW)`
  → EPERM, so `connect` is the box's only road to a host socket, §4.2), the
  command box's own user-notification listener on `connect`/`bind` (its Unix
  socket allow-list, exec-routing.md §4.2; the kernel allows one listener per
  filter chain, so under the whole-agent guard the guard serves it, and where
  neither can the deny-filter refuses every `connect`), and the userns-nesting
  denial. All three USER_NOTIF uses need only `no_new_privs` — NOT CAP_SYS_ADMIN, a
  userns, or root (the connect-guard is confirmed live as a plain unprivileged uid).
  Where the probed bwrap lacks `--disable-userns` (< 0.8, e.g. Ubuntu 22.04's 0.6), the
  deny-filter also owns the **userns-nesting denial**: `unshare`/`clone` with
  `CLONE_NEWUSER` → EPERM (cBPF arg inspection), `clone3` → ENOSYS so callers fall
  back to the filtered `clone`. The whole-agent connect-guard's own filter
  (`net-supervisor/src/guard_filter.rs`, the agent's whole tree) also refuses
  in the filter itself: `io_uring_setup`, x32 numbers, `ioctl(TIOCSTI |
  TIOCLINUX)` and the source-route `setsockopt`s in every posture, and under a
  secret policy `open_by_handle_at`, `pidfd_getfd`, `clone` with
  `CLONE_PARENT` (EPERM: no process makes a sibling the holder lineage would
  miss) and `clone3` (ENOSYS, the same fallback to the filtered `clone`;
  exec-routing.md §7.5 gap (d), 2026-10-03).
- **Landlock** (LSM filesystem **+ TCP-network** access control) — unprivileged,
  kernel ≥ 5.13 for the FS rights / ≥ 6.7 (ABI v4) for the net rights, probe-gated
  on by default, and now **wired into the exec sandbox in both backends**: the
  plans live in `fs-supervisor::landlock`; the Bubblewrap backend enacts them
  in-box via the interposed `mandu-landlock-apply` bin, the legacy InProcess
  backend via a pre-`execve` `restrict_self_to_plan` in the forked child. Inert
  (self-SKIP) on older kernels.
- **Capability & privilege minimization** — `--cap-drop ALL`, `--disable-userns`
  (no nested-userns cap-regain; probe-gated — the seccomp fallback above owns the
  denial below bwrap 0.8), `--new-session` (TIOCSTI protection),
  `no_new_privs`.
- **Launcher default-on wiring** — the live TS launcher turns each attachable
  hardening on by default (exec-routing.md §7): the kernel-tier `--exec-box`
  (boxed read-only command set), `--landlock-net` (whole-agent TCP CONNECT
  allow-list, kernel ≥ 6.7), and `--net-guard` (the IP/DOMAIN-aware `connect(2)`
  guard — seccomp-unotify + `pidfd_getfd` supervisor-connect, and since
  2026-10-01 the same for every send that names an address, performed on the
  guard's copy of the socket; needs only `no_new_privs`, kernel ≥ 5.6, so it
  runs on hosts landlock-net cannot; §7.5; since 2026-10-05 it also performs
  the one ephemeral loopback bind an OpenCode 2 launch's private server needs
  and admits that server's client, and only it, to the port: the
  agent-owned-server allowance, exec-routing.md §7.5, with no widening of
  the landlock-net wrap)
  AND the wrapper-tier `--net-proxy` / `--exec-wrap` gates. Each is probe-gated
  and degrades gracefully where the host lacks the bin/kernel feature;
  `--no-<flag>` (env `=0`) opts out. The wrapper pair is tri-state like fs-sync —
  default-on soft-degrades (warn + proceed), an explicit flag stays fail-closed.
- **Mandu's own git** — the launcher's and the arbiter's git runners, which
  read repositories the agent can write from outside every sandbox, run git
  in a bubblewrap with no network, a read-only root (writable only where the
  call writes: the pack cache), `--cap-drop ALL`, `--disable-userns`,
  `--new-session` and their own user/pid/ipc/uts namespaces; on macOS under
  a Seatbelt profile of their own (`/usr/bin/sandbox-exec -p`, never nested
  in the agent's) with no network, no write but the call's paths, no fork
  and no exec but git itself (so a program a repository names cannot start
  at all), no terminal, no signal or IPC outside it and no host service
  (write-protection.md §8.5.2); probe-gated (a probe that could not be judged
  is tried again later, never settled as none),
  on by default, `MANDU_GIT_SANDBOX=0` opts out (write-protection.md §8.5). It is
  defense in depth behind the git hardening, not the defense. Mandu's other
  git calls (the launcher's single reads, `gitRevOf`, the dashboard,
  fs-sync) are hardened only.

Only two classes are excluded, and **only because they cross the root boundary**,
never because they are hard or non-portable: (a) mechanisms that *require* host
root, and (b) mechanisms that mutate **global host state** (net-supervisor's
host-global nftables; a host-root VM).

> **DECIDED — WILL NOT IMPLEMENT (2026-07-16).** These two classes are a
> standing decision, **not deferred work**: they require host root / global host
> state, so under this §0 principle they are permanently out of scope. They
> address only a threat the IPI defense does not primarily target (§3.1).
> A microVM for untrusted agents (§6) is a different thing: it needs KVM/HVF
> access, not host root.
> Revisit only if the non-root principle itself is revised.

Note this is a **partial** exclusion of
`net-supervisor`: only its TPROXY *rewrite* half (ingress/egress symbolization of
non-model traffic, which needs the host-global nftables) is root-gated. Its
*egress-decision* half now has a live UNPRIVILEGED enforcement leg — the
`connect(2)` guard (`net-supervisor::guard` + `guard_kernel`, exec-routing.md §7.5)
— giving IP/domain-aware egress teeth with no root and no global-state mutation. The engineering pattern for any new
unprivileged primitive is fixed: **pure decision logic unit-tested with no
privilege → enactment behind the crate's `kernel` cargo feature → on by default
where the kernel allows, self-SKIP where it does not.**

The administrator's policy layer (`/etc/mandu/policy.d/`,
confidentiality-plan-12 D5) is not an exception: Mandu only READS those files,
which needs no privilege. Who may write them (root, configuration management)
is the organization's deployment, not a mechanism Mandu attaches.

---

## 1. Two enforcement tracks, two privilege classes

Mandu splits cleanly into two tracks, and the split is exactly the privilege
boundary.

- **Track A — the userspace defense (live today).** The model-API proxy
  (repo: AgentView @ context), the arbiter, the `inspect_symbol` U-LLM
  (repo: quarantined LLM) MCP server, the git-worktree view-sync
  (repo: View Synchronization), the dashboard, and the launcher. Every one of
  these runs **fully unprivileged**:
  - IPC over a Unix-domain socket and localhost TCP ports **above 1024** — the
    arbiter's default socket under `$XDG_RUNTIME_DIR/mandu/`, the anthropic-proxy on
    a kernel-assigned `127.0.0.1` port (the launcher default since 2026-09-26;
    8788 when pinned, `interceptors/anthropic-proxy` server-main), the dashboard
    on `127.0.0.1:4500` or a kernel-assigned port (`dashboard/src/server-main.ts`,
    runtime-instances.md §8).
  - State entirely under the invoking user's `$HOME`, in the one Mandu home
    `~/.mandu` (`MANDU_HOME`, mode `0700`; on-disk-layout.md §3): the
    arbiter SQLite (symbol table + durable policy state) at
    `~/.mandu/state/mandu.db` and the AgentView worktrees under
    `~/.mandu/state/workspaces/<workspace-id>/`, both resolved from the path
    table `scripts/paths/mandu-paths.mjs`.
  - Process scoping via `systemd-run --user --scope`, which is **unprivileged on
    a user session** and **degrades to direct exec** when systemd is absent
    (`launcher/mandu-run.sh:224`, with the no-scope fallback at
    `launcher/mandu-run.sh:231–238`).

  No CAP, no root, no kernel feature. This is the track that **proves the §1
  invariant end-to-end** today (`implementation-plan.md` §9, §11).

- **Track B — the OS interceptors (decision logic *and* kernel attachment now
  live via the kernel layer).** The three kernel-attaching Rust interceptor crates —
  `fs-supervisor`, `exec-supervisor`, `net-supervisor` (the workspace also ships the
  userspace `fs-preload` interposer — a retired rung, in-tree but wired to
  nothing — and the shared `mandu-arbiter` client, which need no privilege). Their security *decision logic* is privilege-free
  and unit-tested unprivileged; the **kernel attachment glue** needs privilege and
  lives behind each crate's `kernel` cargo feature and `#[ignore]`d integration
  tests (`implementation-plan.md` §11, "What remains kernel-gated"). **Track B is
  the only part of the whole system that needs privilege at all** — and that
  privilege is satisfied **without host root** by the unprivileged user
  namespace (the kernel layer, §2), so the attachment loops run green on a 6.x
  kernel:

  | Crate | `#[ignore]`d kernel test(s) | Live in a userns on a 6.x kernel? |
  |---|---|---|
  | `exec-supervisor` | route to AgentShell/HumanShell; AgentShell bind-mounts AgentView; Landlock leg; nested-userns denial | **PASS** — AgentShell net-dead + AgentView over the workspace + the Landlock LSM leg (both backends); `unshare --user` fails inside the box under either denial posture; HumanShell net-live; symbol-as-command refused |
  | `net-supervisor` | TPROXY redirect + ingress/egress transform (root); **connect(2) guard** (unprivileged) | **PASS** — TPROXY redirect in-netns + transform (host nft byte-identical after); the connect-guard ALLOW/DENY/AF_UNIX-passthrough/nonblocking legs pass as a plain uid (no CAP/userns), the netns-discriminator leg under `unshare` |
  | `fs-supervisor` | seccomp-unotify openat interception; ADDFD redirect; Landlock FS + net enactment | **PASS** — interception AND the ADDFD redirect (kernel ≥ 5.9) AND the Landlock FS overlay + deny-TCP net leg (ABI v4) |

  Run them with `scripts/kernel-tests.sh` (each crate's test inside the matching
  `unshare`; SKIPs cleanly where unprivileged userns is off). **Honest residue:**
  these prove the attach loops, but two seams are still glue — net-supervisor's accept
  path does a **single-buffer read** (not a streaming relay), and exec-supervisor's
  `run_supervisor` attach **front-end** (the production ptrace/seccomp dispatcher
  that drives the per-exec sandbox at scale) is still wiring around the proven
  per-exec core.

### Per-component privilege table

| Component | Privilege needed | State scope | Backing claim (file:line) |
|---|---|---|---|
| arbiter | **NONE** | user `$HOME` (`~/.mandu`); three channels: the data socket (`<runtime>/instances/<id>/arbiter.sock`, reachable from the agent world), the human-plane socket (`<runtime>/human/<id>.sock`, `0700` dir, walled off from the agent world without privilege: the guard's always-deny `unixDeny` list, a bwrap `--tmpfs`, Seatbelt; [`arbiter-human-plane.md`](./arbiter-human-plane.md)), the admin inherited fd | `arbiter/symbol-table/symbol-table.ts:140`, `arbiter/ipc/server.ts` `channelRefusal` |
| anthropic-proxy | **NONE** | none (forwarding proxy on a loopback port, kernel-assigned by default) | `launcher/src/parse.ts` |
| inspect-mcp (U-LLM) | **NONE** | none (stdio MCP server) | `launcher/mandu-run.sh:175` |
| prompt filter plugins (confidentiality-plan-15 §4.3) | **NONE**: a one-shot child of the arbiter under `mandu-net-guard` (required: every connect and send by destination address; the cleared `local: true` endpoint only, else none), `mandu-landlock-apply --clean --seccomp-deny` (reads only the system roots and the plugin's own directory, one scratch directory, all TCP denied in-kernel, the AgentShell deny filter) and bubblewrap's PID/IPC/UTS/cgroup namespaces, each probe-gated (`plugin-probe.ts`) | **per-process** (a fresh scratch directory per run) | `arbiter/prompt-filter/plugin-confine.ts`, `plugin-probe.ts`; `interceptors/exec-supervisor/src/bin/mandu-landlock-apply.rs` (`--seccomp-deny`, `--seccomp-only`) |
| fs-sync (view-sync) | **NONE** | user `$HOME` git worktrees | `fs-sync/src/layout.ts:7` |
| dashboard | **NONE** | none (reads arbiter events on `:4500` or a free port) | `dashboard/src/server-main.ts` |
| launcher | **NONE** | none (`systemd-run --user --scope`) | `launcher/mandu-run.sh:224` |
| **fs-supervisor** | seccomp user-notify (`SECCOMP_FILTER_FLAG_NEW_LISTENER` + `SECCOMP_IOCTL_NOTIF_ADDFD`) `openat()` redirect; **CAP_SYS_ADMIN** | **per-process** | `interceptors/fs-supervisor/src/kernel.rs:4–7,15,17` |
| **exec-supervisor** | ptrace/seccomp on `execve` + `CLONE_NEWNET` + bind-mount; **root** for namespace setup | **per-process** | `interceptors/exec-supervisor/src/kernel.rs:3,7,33` |
| **net-supervisor** (TPROXY rewrite) | nftables TPROXY + `IP_TRANSPARENT` + the `nft` binary; **root / CAP_NET_ADMIN** | **GLOBAL host netfilter** | `interceptors/net-supervisor/src/kernel.rs:3,26,31` |
| **net-supervisor** (connect guard) | seccomp user-notify (`NEW_LISTENER`) `connect()` and `sendto`/`sendmsg`/`sendmmsg` + `pidfd_getfd` supervisor-connect / supervisor-send; **`no_new_privs` only** (no CAP) | **per-process** | `interceptors/net-supervisor/src/guard_kernel.rs`, `guard_send.rs` |

The three privileged rows are the *attachment* of Track B. The corresponding
decision logic — `decide_open` (`interceptors/fs-supervisor/src/decision.rs:133`),
`plan_exec` (`interceptors/exec-supervisor/src/orchestrate.rs:74`),
`ingress_transform` / `egress_transform`
(`interceptors/net-supervisor/src/transform.rs:72,180`) — is pure and runs in the
default unprivileged `cargo test`. **Only the syscall plumbing is gated; the
security decisions are not.**

### Kernel-version and host-state details (verified against the crates)

- **fs-supervisor.** `SECCOMP_FILTER_FLAG_NEW_LISTENER` installs the listener
  (kernel ≥ 5.0); `SECCOMP_USER_NOTIF_FLAG_CONTINUE` passthrough is ≥ 5.5; the
  `openat()` **redirect** path — `SECCOMP_IOCTL_NOTIF_ADDFD`, opening the
  AgentView FD ourselves and injecting it into the target — requires **kernel
  ≥ 5.9** (`interceptors/fs-supervisor/src/kernel.rs:5–7,15`). Argument reads use
  `process_vm_readv` out of the target's address space
  (`interceptors/fs-supervisor/src/kernel.rs:41`). The state is **per-process**:
  a filter and a notification loop bound to one supervised process tree.
- **exec-supervisor.** Needs **root** to set up the per-shell namespaces and join
  the cgroup scope; it traps `execve`, then for AgentShell enters a fresh
  `CLONE_NEWNET` netns (egress off) and **bind-mounts** the AgentView worktree
  over the workspace, and for HumanShell keeps the network and FS=HumanView
  (`interceptors/exec-supervisor/src/kernel.rs:3,7,33`). State is **per-process**.
- **net-supervisor** has **two** kernel legs. (1) The **TPROXY rewrite** needs
  **root + the `nft` binary** to install nftables TPROXY rules and an
  `IP_TRANSPARENT` listening socket (`interceptors/net-supervisor/src/kernel.rs:3,26,31`).
  Critically, the nftables ruleset mutates **global host netfilter state** — this is
  **the only host-global, host-polluting piece in the entire system.** Every other
  privileged action above is per-process; this one is not. (2) The **connect(2)
  guard** (`interceptors/net-supervisor/src/guard_kernel.rs`, exec-routing.md §7.5)
  is UNPRIVILEGED and **per-process**: seccomp `NEW_LISTENER` on `connect` needs
  only `no_new_privs` (kernel ≥ 5.0 / ≥ 5.6 for the `pidfd_getfd` supervisor-connect
  enact), no CAP, no userns, no root — so the IP/domain-aware egress *decision* runs
  live within the non-root boundary even though the traffic-*rewrite* half stays
  root-gated. Its decision logic (`net-supervisor/src/guard.rs`) is pure and runs in
  the default unprivileged `cargo test`.

---

## 2. The enforcement layers (context → wrapper → kernel)

> **Terminology (2026-07-04).** The former "Tier 0/1/2 ladder" is renamed to
> named **layers** — the numbers carried no meaning and invited swapping (Tier 1
> was the *less* portable one). The design space is really two axes,
> portability × boundary strength, so the names describe the mechanism:
>
> - **context layer** *(formerly Tier 0)* — the model-API proxy invariant;
>   always-on, zero privilege, portable to any OS.
> - **wrapper layer** *(formerly Tier 2)* — everything the launcher/wrapper
>   process enforces through what a parent process portably controls: env
>   (`ANTHROPIC_BASE_URL`, `HTTP(S)_PROXY`), `PATH` shadowing, CWD/AgentView,
>   and endpoints it serves. Portable **cooperative** boundary (§3.1) on any
>   OS. (The one Linux-only wrapper add-on, `fs-preload`'s `LD_PRELOAD`, is
>   retired — superseded by fs-sync + the kernel-layer FS rungs; in-tree,
>   wired to nothing.)
> - **kernel layer** *(formerly Tier 1)* — per-OS **hard** backends behind the
>   crates' `kernel` cargo features (the code already used this word):
>   unprivileged userns + seccomp-unotify / TPROXY / bind-mounts. Optional,
>   probed, defense-in-depth.
>
> The layers stack: context is never optional; wrapper is the universal floor
> for the agent's *actions*; kernel is opt-in per host. The remaining cell of
> the matrix — a *portable hard* boundary — is a future micro-VM / container
> backend behind the same probed-backend seam, **designed in §6** (a
> wrapper-served libkrun microVM for untrusted agents; not built).

### The context layer (formerly Tier 0) — shipping today, zero privilege (the always-on baseline)

The **model-API proxy alone delivers the core invariant**: untrusted
`tool_result` spans reach **T-LLM (privileged LLM)** only as opaque symbols
(`$MDU:*`). No root, no kernel features, no namespaces — pure userspace, as
proven by the live §9 oracle and the `tests/stack/` cross-component test
(`implementation-plan.md` §11). This is the floor: it holds on *any* host, on
*any* kernel, in *any* container, with *no* privilege.

Everything below (the wrapper and kernel layers) is **defense-in-depth** on top
of the context layer — it hardens the filesystem, network, and shell boundaries
that the anthropic-proxy alone does not enforce (a child `curl` or `python` can
`connect()` / `openat()` / `execve()` without ever going through the Messages
API). The context layer makes the agent's *context* safe; the wrapper and
kernel layers make the agent's *actions* safe.

### The kernel layer (formerly Tier 1) — the key lever is the **unprivileged user namespace**

Wrap the agent's entire process tree in
`unshare(CLONE_NEWUSER | CLONE_NEWNS [ | CLONE_NEWNET ])`. Inside an unprivileged
user namespace the launcher becomes **root-in-namespace**, holding
`CAP_SYS_ADMIN` + `CAP_NET_ADMIN` **scoped to that namespace** (and to nothing
outside it). That single move makes all of Track B's attachment privilege-free on
the host:

- **fs-supervisor's** seccomp-unotify filter installs with **no host root** — the
  in-namespace `CAP_SYS_ADMIN` is sufficient.
- **exec-supervisor's** namespaces, bind-mounts, and ptrace-of-its-own-children
  work with **no host root** — namespace creation and mounts are permitted to the
  in-namespace root.
- **net-supervisor's** TPROXY/nftables run **inside the agent's own network
  namespace** — the netfilter state becomes **namespace-local instead of
  host-global.** The host's netfilter is **never touched**, and **no VM is
  needed** to contain the one host-polluting piece. This directly neutralizes the
  single global-state concern from §1.

Per the §0 principle, the AgentShell sandbox does not stop at net-off + a bind
overlay — it turns on **every** unprivileged kernel hardening, all by default:

- **exec-supervisor / AgentShell (Bubblewrap is now the DEFAULT backend).** The
  bubblewrap child unshares the **PID / IPC / UTS / cgroup** namespaces (so its
  fresh `/proc` shows only sandbox PIDs and it shares no IPC/hostname/cgroup view),
  runs in a **new session** (blocks TIOCSTI terminal-injection), **drops all
  in-userns capabilities** (`--cap-drop ALL`), **forbids nested userns** — via
  `--disable-userns` where the probed bwrap supports it (≥ 0.8; the backend runs
  one parent-side `bwrap --help` per process, or takes the launcher's kept
  answer for exactly that bwrap's bytes, exec-routing.md §4), otherwise (bwrap < 0.8)
  the seccomp deny-filter takes over the denial (`unshare`/`clone` +
  `CLONE_NEWUSER` → EPERM, `clone3` → ENOSYS) so the posture degrades to the
  next-best unprivileged mechanism, never silently away — and installs a
  **seccomp deny-filter** of dangerous syscalls via `--seccomp <fd>`. Fail-closed:
  if the filter fd cannot be built the AgentShell exec is refused, never run
  un-filtered. The box now also carries the **Landlock LSM leg**: the interposed
  `mandu-landlock-apply` bin restricts *after* bwrap's mounts (a
  Landlock-restricted thread cannot `mount(2)`) and before the target argv; a
  missing applier degrades to mounts-only, where the LSM is purely additive.
  (`exec-supervisor::sandbox` + `::seccomp_filter`, both pure + unit-tested
  unprivileged.) With the integrity axis off (no AgentView pair) the box
  shows the agent's own `/tmp`, its sockets masked, since the agent's
  unboxed programs use it anyway (`exec-routing.md` §7.2, "The agent's own
  `/tmp`", 2026-10-19). Otherwise the box's private `/tmp` (a fresh tmpfs) re-binds exactly one
  path back, read-only: the workspace, when it itself lives under `/tmp`
  (`exec-routing.md` §4 "A project under `/tmp`"). Every other
  `/tmp` entry stays hidden, and the clean box never renders the re-bind.
  On WSL the box also hides the Windows interop door: an empty
  tmpfs over `/run/WSL` and `/mnt/wslg`, `/dev/null` over `/init` and the
  `$WSL_INTEROP` socket, all unprivileged bwrap mounts; the connect guard
  refuses the same socket and `AF_VSOCK` for the whole agent
  (`exec-routing.md` §4.1).
  On every host the box hides the host's Unix sockets: the RO
  base does not stop `connect(2)` and the netns cuts only abstract sockets,
  so `/run` is an empty tmpfs with a short allow-list put back, and every
  socket a scan finds elsewhere (`/var/lib`, `/var/snap`, `$HOME`'s agent and
  VM socket dirs, the paths `SSH_AUTH_SOCK`, `DOCKER_HOST` and similar name)
  gets `/dev/null` bound over it; all unprivileged bwrap mounts
  (`exec-routing.md` §4.2).
- **fs-supervisor / Landlock (unprivileged, kernel ≥ 5.13; net rights ≥ 6.7).**
  An LSM-enforced filesystem **and TCP-network** sandbox for the FS chokepoint —
  the same asymmetric overlay (whole real FS read-only; AgentView worktree +
  `/tmp` writable, plus a WRITE_FILE-only carve-out on `/dev` so `> /dev/null`
  works but nothing can be *created* under `/dev`) enforced in-kernel, so it
  holds even for a process that escapes or was never wrapped by bubblewrap. The
  net leg (ABI v4) handles TCP `bind`/`connect` with no allow rules — deny-all
  TCP even for a netns escape (masked away below v4, where the netns remains the
  net boundary; honest scope: TCP only). **Wired into the exec sandbox in both
  backends** (the in-box applier
  above; the InProcess pre-`execve` restrict). Rights are masked per-ladder to
  the live ABI so an unknown bit never fails the restrict open
  (`fs-supervisor::landlock`); self-SKIPs below 5.13.

This is exactly the **rootless-podman / bubblewrap / Codex-sandbox** model
(`implementation-plan.md` §6 cites Codex's Landlock+seccomp sandbox as the
reference). It composes with the existing cgroup v2 scope (`mandu.md` §0): keep
the **cgroup on the host** (so the interceptors can still answer "is this the
monitored agent?" by membership), and **nest the user namespace inside it.**

**Requirement:** the host kernel must allow unprivileged user namespaces —
`sysctl kernel.unprivileged_userns_clone=1`. This is **ON by default on Ubuntu**;
**some Debian/RHEL hardenings turn it OFF**. Where it is on, the kernel layer
is **exercised live**: `scripts/kernel-tests.sh` runs each crate's
`#[ignore]`d kernel test inside the matching `unshare --user --map-root-user …`
namespace (exec + net add `--net`; fs takes mount/pid only), aggregates a
PASS/FAIL/SKIP summary, and **detects + SKIPs cleanly** when unprivileged userns is
unavailable (so it is safe on any host and never fails for a missing prerequisite).
On a 6.x kernel with Landlock ABI v4 nothing SKIPs (the Landlock tests need no
userns at all).

#### Host prerequisite: Ubuntu's AppArmor userns restriction (24.04)

Ubuntu 23.10+ / 24.04 ships `kernel.apparmor_restrict_unprivileged_userns = 1`
(`/usr/lib/sysctl.d/10-apparmor.conf`). Under it an unprivileged process may
create a user namespace only when the binary it execs carries an AppArmor
profile that grants `userns`. Every kernel-layer rung above then dies at the
uid map (`bwrap: setting up uid map: Permission denied`, `unshare: write failed
/proc/self/uid_map: Operation not permitted`): the secret-twins wrap cannot be
applied (the launch then runs in the `gated` secret posture with a loud
notice), the exec-box degrades, and
`scripts/kernel-tests.sh` self-SKIPs. An in-place upgrade to 24.04 turns the
knob on, so a host that confined secrets the day before stops doing so; the
refusal must therefore name the knob and the fix (below).

**Root stays optional (decided 2026-09-21,
[`rootless-confinement-ubuntu-2404.md`](../confidentiality/rootless-confinement-ubuntu-2404.md)).**
Mandu installs and runs with no root on such a host. The one privileged step
is an *upgrade*, never a prerequisite. A host without it is still
`confined`, by the whole-agent guard alone (it needs no user namespace);
the step adds the bind mount as a second layer. Without the guard a launch
is `gated`, with or without the bind (model-context masking + egress gates;
a subprocess can still read credential files, or, with the bind alone, one
the host replaces during the session). `--require-confinement` turns
`gated` into a refusal. This is consistent with §0: the step mutates host
state once, at the admin's choice, and nothing at runtime depends on root.
The current answers for 24.04 and 26.04, the copy of bwrap and its profile
are collected in rootless-confinement-ubuntu-2404.md §0.

What ships for it (this is a one-time host admin step, not a runtime
privilege, so it stays inside §0):

- **The probe asks the binary that matters.** `launcher/src/userns.ts`
  `probeUserns` runs `bwrap --unshare-user --unshare-pid --ro-bind / / -- true`
  through the distribution's bwrap (by absolute path, never one inside the
  working directory: rootless-confinement-ubuntu-2404.md §0.7) and falls back to the historical
  `unshare --user --map-root-user --mount -- true` only without it. The grant is
  per binary, so a host that covers bwrap alone must count as able; the old
  unshare-only probe would have refused it. `run.ts`, `exec-box-setup.ts` and
  the live harness all route through this one probe. A launch keeps its PASS
  (and only a pass) for the rest of the boot, keyed by every input it reads
  (`launchUsernsOk`, `launcher/src/probe-cache.ts`, packaging.md §5.4): a kept
  pass is still enacted, so a wrong one stops the wrap rather than skipping a
  confinement step, and an unavailable primitive is probed again on every
  launch, so turning it on is never hidden by a stale answer.
- **The refusal names the knob.** `usernsGapHint` reads
  `kernel.apparmor_restrict_unprivileged_userns`, `kernel.unprivileged_userns_clone`
  and `user.max_user_namespaces` (in that precedence; a missing file is skipped,
  never read as shut) and appends one cause+fix sentence to the
  `--require-confinement` refusal, the `mandu doctor` Secrets row and the
  exec-box degrade line. The posture oracles (the differential harness's
  `wrappedPostureFindings`, the launcher's `postureFindings`) match the gated
  notice's stable first line, `secrets are GATED`; the old "Proceeding
  UNCONFINED" phrase is gone.
- **Mandu's own bubblewrap ships in-tree.**
  `scripts/apparmor/mandu-bwrap` ships inside the npm package as a bundle
  asset. **`mandu setup`** is the one-command install: it runs unprivileged,
  prints the exact profile text and commands, confirms, runs only those under
  `sudo`, and re-probes (`--print`, `--uninstall`; never overwrites a file it
  did not create). It copies the system bwrap to the root-owned
  `/usr/lib/mandu/bin/bwrap` and loads a profile for that path only:
  `mandu_bwrap` may create a user namespace and hold capabilities in it, and
  everything it runs is stacked with `mandu_child`, which holds no capability
  and no user namespace except that bubblewrap runs as `mandu_bwrap` again. So
  the agent's own sandboxes nest inside Mandu's, `unshare -Ur` is refused
  inside it, and running the copy by hand gives nobody a namespace with
  capabilities (VM-verified on 24.04 and 26.04; rootless-confinement-ubuntu-2404.md
  §12.3, `launcher/src/bwrap-grant.ts`). The launch uses the copy when it is
  in force, and puts its directory first on the agent's PATH.
  `sudo scripts/apparmor/install.sh` is the same install from a checkout.
  Preferred over `sysctl kernel.apparmor_restrict_unprivileged_userns=0`,
  which also works but widens host-global state for every binary.
  **Rejected:** Ubuntu's documented per-binary shape for `/usr/bin/bwrap`
  and `/usr/bin/unshare` (`flags=(unconfined) { userns, }`), which an
  earlier Mandu shipped. Both let every program on the host create a user
  namespace with capabilities, and the `bwrap` one shares its profile name
  with Ubuntu's own `bwrap-userns-restrict`, so after a 24.04 → 26.04 upgrade
  it silently switched the restriction off host-wide. `mandu setup` removes a
  Mandu-marked one (deleting the file and reloading Ubuntu's file of the same
  name, never unloading by name) and `mandu doctor` flags a leftover. A
  developer-only `scripts/apparmor/mandu-dev-unshare` (Mandu-named) keeps
  `scripts/kernel-tests.sh` working on a development box.

Unit coverage: `launcher/test/unit/userns.test.ts` (probe order, each knob's
hint, the generic fallback), `confinement-posture.test.ts` (the posture and
refuse/degrade tables), `setup.test.ts`, plus the hint assertions in
`exec-box-shims.test.ts` and `secret-setup.test.ts`.

**Ubuntu 26.04: no nesting inside a bwrap sandbox.** 26.04's
`apparmor` package grants `/usr/bin/bwrap` its user namespace itself
(`bwrap-userns-restrict`), but it stacks
`unpriv_bwrap` on every program a bwrap sandbox runs, and `unpriv_bwrap`
denies every capability, CAP_SYS_ADMIN in a child's own user namespace
included. So a bwrap started inside a bwrap cannot set up its namespaces.
Under the whole-agent secret bind, that meant Codex's shell sandbox and the
exec box failed every command. Nothing unprivileged can lift a confinement
the wrap's children inherit, and a local override cannot either (`deny` beats
`allow`). Replacing the distro profile would undo Ubuntu's restriction for the
whole host, so Mandu does not offer it. The launch probes nesting instead, and
where it is barred it serves the secret twins with the guard alone
(rootless-confinement-ubuntu-2404.md §12). `mandu setup` installs Mandu's own
bubblewrap (above), whose profile lets a sandbox nest, so after it the bind
layer stays on there too.

### The wrapper layer (formerly Tier 2) — least intrusive; zero privilege, zero kernel features

Where unprivileged userns is disabled (hardened host) *and* you cannot grant root
(plain Docker without `--privileged`, old kernels), replace the kernel chokepoints
with **userspace** ones — each a shipped package wired into the launcher and
`scripts/test-all.sh`:

- **Filesystem two-views:** `fs-sync`'s dual-view git worktree (the always-on
  cooperative chokepoint) plus the model-proxy backstop. The former Linux-only
  fallback here, `interceptors/fs-preload/` (a cdylib `LD_PRELOAD` `openat`
  interposer), is **retired**: an env-borne interposer the confined
  process can strip is not a boundary. The crate stays in-tree (tested, unwired)
  as the reference implementation; a **FUSE** mount that symbolizes on read
  remains the documented alternative (`mandu.md` §3).
- **Network egress:** `interceptors/net-proxy/` — point `HTTPS_PROXY` /
  `HTTP_PROXY` at this cooperative forward proxy instead of TPROXY (no nftables,
  no `IP_TRANSPARENT`, no root, no host netfilter mutation); an optional
  session-CA MITM gates HTTPS request bodies. **On by default** in the TS
  launcher (`--no-net-proxy` opts out; the MITM add-on stays opt-in
  `--net-proxy-mitm`).
- **Exec classification:** `interceptors/exec-wrap/` — a `PATH`-shadowing wrapper
  that classifies a shadowed `execve` into AgentShell/HumanShell via the arbiter,
  instead of an `execve` ptrace trap. **On by default** in the TS launcher
  (`--no-exec-wrap` opts out).

The wrapper layer runs in plain Docker and on old kernels because it touches
nothing privileged. Its limitation is the subject of the next section.

---

## 3. Two honest caveats

These are stated plainly because the architecture doc's §6 ("Honest hard
problems") sets that bar; the privilege model has its own two.

### 3.1 Cooperative vs hard boundary — tied to the threat model

The wrapper layer is a **cooperative** boundary: a malicious *native binary* using raw
syscalls (bypassing libc), or one that unsets `HTTPS_PROXY` / `LD_PRELOAD`, can
**evade** it. But Mandu's real adversary is not an arbitrary native payload — it
is a **prompt-injected agent driving its normal tools** (`openat` / `connect` /
`execve` through libc and Node), and **the wrapper layer does capture that adversary**:
injected instructions cannot make the agent issue raw syscalls or scrub its own
environment, so the cooperative interposition holds against the threat we
actually defend.

The kernel layer (userns) is a **hard** boundary against the in-namespace agent: by
construction it **cannot escalate out of an unprivileged user namespace** — that
is what "unprivileged userns" means — *without* host root and *without* polluting
host state. The only adversary that defeats the kernel layer is a **fully hostile native
payload that escapes the namespace**, and only *that* threat would justify
host-root enforcement (and the QEMU VM, needed solely to contain net-supervisor's
global nftables). That adversary is out of scope for the IPI defense
(`mandu.md` §6, point 5: intra-process flow and a hostile native payload are
the same boundary the paper itself accepts).

So the layers map onto the threat model precisely: the **context layer** secures
the context, the **wrapper layer** secures the actions of a cooperative-tooling
injected agent, the **kernel layer** upgrades that to a hard kernel boundary
without host cost, and host root + VM — targeting only an adversary the defense
does not own — are decided out of scope (§0), not held in reserve as future work.

### 3.2 Kernel-version interaction

A current kernel (6.7 or later with Landlock at **ABI v4**) clears every
version gate in play: seccomp CONTINUE (≥ 5.5), the
`SECCOMP_IOCTL_NOTIF_ADDFD` `openat` **redirect** (≥ 5.9;
`interceptors/fs-supervisor/src/kernel.rs`), and Landlock FS (≥ 5.13) +
TCP-net (≥ 6.7). The interaction below governs *older hosts*: on kernels < 5.9, **the kernel layer's
filesystem interposition should use FUSE / `LD_PRELOAD` (wrapper-layer-style)
rather than seccomp-ADDFD.** Note that **userns does not change the kernel
version** — wrapping the agent in a user namespace grants in-namespace
capabilities but cannot back-port the ADDFD ioctl. The kernel layer and the FS
mechanism are chosen **independently**: use userns for the privilege story, and
pick the FS interposer (seccomp-ADDFD vs FUSE/LD_PRELOAD) by the host kernel
version.

This is exactly why `fs-supervisor`'s ADDFD-redirect integration test
(`seccomp_unotify_redirect_returns_agentview_fd`) **self-SKIPs on a < 5.9 host**
(the interception half still PASSes there — trap + `process_vm_readv` arg-read +
`decide_open` REDIRECT decision). On a ≥ 5.9 kernel it runs and passes: the
tracee's `openat` of a tracked path actually returns the AgentView (symbolized)
fd and reading it yields AgentView content, not the raw HumanView bytes.
`scripts/kernel-vm.sh` (a QEMU guest running `cargo test -p fs-supervisor
--features kernel -- --ignored` via the same `unshare --user --map-root-user`
userns *inside the guest*) is the **old-kernel / posture-matrix test vehicle**
([`os-test-matrix.md`](../testing/os-test-matrix.md)).

A second interaction: **a whole-agent network namespace is not free.** A naive
**empty netns has no route to the host-loopback anthropic-proxy** at
`127.0.0.1:8788`, so the agent's Messages-API traffic would have nowhere to go;
an in-netns network needs **`slirp4netns`** (or an in-netns forwarding proxy) to
reach the host loopback. This cost is why the shipped whole-agent net story is
landlock-net + net-guard instead of a netns: per-destination precision with no
relay. An early prototype had `--unshare` / `--unshare-net` launcher flags
(a bare user + mount namespace, and a netns with a `slirp4netns` relay); both
are retired and requesting one is a parse-time error, because the shipped
rungs create their namespaces per use via bwrap (exec box, secret twins). A
dedicated netns rung, if ever wanted, must be co-designed with this
reachability problem from the start, and would come back as its own rung,
not as those flags.

---

## 5. Recommendation

1. **The context layer is always on.** The model-API proxy ships the §1 invariant at zero
   privilege; it is the floor on every host and must never be optional.
2. **Default to the kernel layer (unprivileged user namespace) where the host allows it.**
   No flag needed: the launcher's kernel-tier rungs are on by default and create
   their namespaces per use via bwrap (exec-box, secret-twins), probe-gated with
   self-degrade where the host lacks them (the retired `--unshare` /
   `--unshare-net` levers: §3.2). The
   AgentShell sandbox's full hardening set (hardened namespaces + `--cap-drop ALL`
   + `--disable-userns` (probe-gated; the seccomp fallback owns the userns-nesting
   denial below bwrap 0.8) + `--new-session` + the seccomp deny-filter) and the
   Landlock FS + net backend are **on by default** — no flag needed — degrading
   cleanly where a given kernel or bwrap lacks the feature (§0). The live TS
   launcher applies the same posture at launch time: its whole-agent
   `--landlock-net` TCP confine and `--exec-box` boxed command set are likewise
   on by default (`--no-landlock-net` / `--no-exec-box` opt out), degrading
   where the bin or kernel is absent (exec-routing.md §7).
3. **Fall back to the wrapper layer alone where unprivileged userns is disabled** (hardened
   Debian/RHEL, plain Docker, old kernels) and root is unavailable: FUSE /
   `LD_PRELOAD` for the filesystem two-views, `HTTPS_PROXY` for egress, a
   `PATH`-wrapper shell for exec — cooperative, but sufficient against the
   prompt-injected-agent threat model (§3.1).
4. **Host-root enforcement is not built, by decision (§0)** — its
   single use case, containing net-supervisor's *host-global* nftables against a
   fully hostile native payload escaping the namespace, targets an adversary the
   IPI defense does not primarily own, so that leg is permanently out of scope
   rather than deferred.
   (Note the **QEMU VM here is a different, narrower role**: `scripts/kernel-vm.sh`
   is an *old-kernel test vehicle* for kernel-matrix coverage — not the
   host-root containment of the previous sentence.)
5. **Run the privileged tests via `scripts/kernel-tests.sh`** (kernel-layer userns, no
   root) to keep Track B honest in CI where the host supports it (the
   per-push CI guest runs it with `--include-ignored`, `continuous-integration.md`
   §3); on a current kernel that includes the ADDFD redirect and the Landlock
   FS + net assertions; `scripts/kernel-vm.sh` remains for old-kernel matrix
   coverage. `kernel-tests.sh`
   SKIPs cleanly on hosts without unprivileged userns, so it never breaks the
   no-root contract.

In one line: **zero-privilege today, hard-boundary-without-host-cost via
unprivileged userns (Track B runs live via `scripts/kernel-tests.sh`), and
host root never — the host-root/global-state legs are decided out of scope
(§0), for a threat we explicitly do not own.**

---

## 6. The hard isolation tier (untrusted agent / microVM) — design, not built

> **Status: design, not built.** The intended shape of a future `container` /
> `micro-vm` enforcement backend: the "portable-hard" cell of the
> portability × strength matrix (§2), plugging into the enforcement-backend
> registry of [`portable-wrapper.md`](../distribution/portable-wrapper.md)
> §2.3, above the cooperative tier of
> [`portable-wrapper.md §10`](../distribution/portable-wrapper.md).

### 6.1 When this tier applies

The cooperative wrapper (context/wrapper layers) trusts the **agent binary** and
defends only against injected **data** — it holds for Claude Code, Codex, and
other honest CLI agents. The hard tier is for the *other* requirement: **support
arbitrary / untrusted agents** — a third-party or future agent that might use
absolute paths, issue raw syscalls, be a static binary (bypassing `LD_PRELOAD`),
run tools in-process, or scrub its own environment. Against such an agent,
in-process / env-based interception is *fundamentally* insufficient: you cannot
enforce a boundary from inside a process you do not trust. Enforcement must move
to an **out-of-process boundary the agent cannot bypass** regardless of the
syscalls it issues.

### 6.2 The load-bearing finding: cooperative-or-microVM

**There is no cross-OS unified syscall-authorization primitive**: Linux has
seccomp-unotify, macOS has Endpoint Security (entitlement-gated, with the
deprecated Seatbelt for declarative sandboxing), Windows has *no* userspace
equivalent. So a per-OS kernel interposer is not a portable strategy. The
portable hard boundary that *does* generalize is a **container / microVM**: it
stops relying on intercepting individual syscalls and instead controls the
entire filesystem / network / process namespace the agent lives in. This is why
Mandu's ladder is **cooperative wrapper → microVM**, with per-OS kernel
interposers (seccomp and Landlock on Linux) as an optional middle rung, not the
portable answer.

### 6.3 Reference implementations (both open, both match our design)

Two agent vendors already ship this shape (Apache-2.0):

- **[Anthropic `sandbox-runtime`](https://github.com/anthropic-experimental/sandbox-runtime)**
  — containerless per-OS: bubblewrap + netns (Linux), Seatbelt (macOS), WFP+ACL
  (Windows, **alpha, explicitly "not a boundary against deliberate adversaries"**).
  Network is **default-deny allowlist enforced by an out-of-sandbox proxy reached
  over a Unix-domain socket** — *identical in shape to Mandu's arbiter-over-UDS
  egress*. Read/write allow-deny precedence over whole process trees is a
  ready-made policy shape.
- **[OpenAI Codex CLI sandbox](https://github.com/openai/codex)** — sandbox **on by
  default**, all 3 OSes as discrete Rust crates (Linux bubblewrap+Landlock+seccomp;
  macOS `sandbox-exec`/SBPL; Windows restricted-token+ACL). Network modes
  `Isolated / ProxyOnly / FullAccess` — **`ProxyOnly` = Mandu's egress model.**

**Consequence for Mandu:** the per-OS profiles these ship (SBPL on macOS,
restricted-token/WFP on Windows, bubblewrap/Landlock/seccomp on Linux) are
lift-able artifacts. But both are **containerless per-OS sandboxes** whose
macOS leg rides Apple's **deprecated Seatbelt** and whose Windows leg is **alpha /
soft**. That is the ceiling of the *containerless* hard tier — which is why the
*portable* hard tier is a microVM.

The Linux containerless leg is **implemented**, per the non-root principle
(§0): the AgentShell exec sandbox (`exec-supervisor`, Bubblewrap the default
backend) ships the hardened namespaces + `--cap-drop ALL` + `--disable-userns`
+ `--new-session` + a **seccomp deny-filter**, and `fs-supervisor::landlock`
adds the LSM filesystem backend, all unprivileged and on by default (§2). What
remains design-only is the **microVM / container** tier below.

### 6.4 The portable hard tier — a wrapper-served microVM

**Backend of choice: [microsandbox / libkrun](https://github.com/microsandbox/microsandbox)**
(Apache-2.0) — hardware-isolated microVMs via libkrun (**KVM on Linux, HVF on
macOS**), sub-200ms boot, OCI images. It is the only hard tier that gives real VM
isolation on *both* Linux and macOS (Windows uses WHP under the same libkrun
umbrella or a Linux guest via WSL2/Hyper-V).

**The design (how it enforces all four chokepoints at one boundary):**

1. The agent runs **inside a Linux guest**; the wrapper is the **host**.
2. **Filesystem chokepoint** = the guest's workspace is the **AgentView** served by
   the wrapper over **virtiofs / 9p** (or an overlay for a container). *Every* file
   the agent opens — absolute path, raw syscall, static binary — resolves to the
   AgentView, because the HumanView is simply not in the guest's namespace.
3. **Network chokepoint** = the guest's *only* route out is the host's user-mode
   NAT / proxy ([gvproxy](https://github.com/containers/gvisor-tap-vsock), or
   libkrun's own net) → the arbiter egress gate. No raw route to the host.
4. **Exec chokepoint** = everything the agent execs runs *in* the guest, which is
   net-gated + AgentView by construction.
5. **Context chokepoint** = unchanged — the guest's `ANTHROPIC_BASE_URL` points at
   the host's model proxy.

#### 6.4.1 The critical caveat: isolation ≠ symbolization

A microVM gives **isolation**, not **the two-view defense**. It stops the agent
seeing the HumanView, but it does *not* symbolize untrusted content by itself. The
**symbolization layer stays exactly the same**: `fs-sync` builds the AgentView, the
model proxy symbolizes the model context. The microVM's job is only to *force
all access through the AgentView the wrapper serves*. So the hard tier is the
symbolization layer **plus** a stronger enforcement boundary — not a replacement
for it.

#### 6.4.2 The cost

The agent runs in a **Linux guest**, not natively on the user's machine. On Linux
that is nearly free (namespaces — the same primitives the kernel layer already
uses). On macOS/Windows it is a real VM (HVF/WHP). Fine for CLI agents (which run
on Linux anyway); a real limitation only for an agent that needs the host's
*native* macOS/Windows toolchain. This is the deliberate trade for robustness
against an untrusted agent.

### 6.5 Per-OS hard options

| OS | Containerless (soft-hard) | microVM (portable hard) | Linux-only strong |
|---|---|---|---|
| **Linux** | bubblewrap + Landlock + seccomp (unprivileged, userns) | libkrun/KVM | [gVisor](https://github.com/google/gvisor) / [Kata](https://github.com/kata-containers/kata-containers) (OCI-drop-in); [Sysbox](https://github.com/nestybox/sysbox) (rootless DinD) |
| **macOS** | `sandbox-exec`/Seatbelt (**deprecated**, no replacement) | libkrun/HVF | — |
| **Windows** | restricted-token + WFP/ACL (**alpha, soft**) | WHP / WSL2 Linux guest | — |

The containerless column is a *soft-hard* tier (good against injected data, weak
against a deliberate adversary — the vendors say so), and its macOS leg is on
deprecated foundations. The **microVM column is the true hard boundary and the
only one that is portable**. gVisor/Kata are excellent where a Linux-only,
OCI-drop-in boundary is acceptable.

### 6.6 How it plugs in — the enforcement-backend registry

A future **`micro-vm`** (and/or `container`) backend behind the
`EnforcementBackend` seam (`portable-wrapper.md` §2.3): `probe()` checks for
libkrun/KVM/HVF availability; `prepare()` provisions the guest, mounts the
AgentView, wires the host proxy, and rewrites the agent launch to run in-guest;
`postExit()` tears the guest down. It composes with `coop-env` (which still sets
the in-guest `ANTHROPIC_BASE_URL`/proxy env) — the microVM changes *where* the
agent runs, not *what* the wrapper composes. Requesting it when unavailable
fails closed like every other backend.

### 6.7 Recommendation & fences

- **Keep the cooperative wrapper as the zero-dependency default** (trusted agents,
  no VM needed).
- **Reserve the microVM hard tier for untrusted agents**, built as a probed
  `micro-vm` backend on **libkrun/microsandbox** (portable Linux+macOS), with
  gVisor/Kata as a Linux-only strong alternative.
- **Not built.** Implementation is gated on a concrete untrusted-agent
  requirement. When built, it reuses the symbolization layer unchanged and
  lifts per-OS profiles from Codex / `sandbox-runtime`.
- **Out of scope here:** the cooperative cross-platform port (its own spec) and
  any remote/cloud sandbox (E2B-style) — that is a different deployment, not a
  local wrapper backend.
