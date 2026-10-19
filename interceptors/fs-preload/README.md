# fs-preload — unprivileged LD_PRELOAD filesystem interposer (Tier-1-old-kernel / Tier 2)

`fs-preload` is the **filesystem two-views mechanism that works at zero privilege**
on hosts where the seccomp-unotify `openat` REDIRECT is unavailable. It is an
`LD_PRELOAD` shared library (`cdylib`) that interposes the libc open family and,
for paths under a **tracked workspace root**, rewrites the path to the **AgentView
git worktree** before calling the real libc function. Reads then see symbolized
AgentView content; writes are captured into AgentView — never the raw HumanView
path — exactly as the kernel `fs-supervisor` redirect does, but with **no root, no
CAP, no kernel feature, and no user namespace**.

## Why it exists (kernels < 5.9, and hosts without the kernel layer)

`fs-supervisor`'s seccomp-unotify `openat` REDIRECT installs a listener
(kernel ≥ 5.0) and answers each notification by opening the AgentView FD itself and
injecting it with `SECCOMP_IOCTL_NOTIF_ADDFD` — and **ADDFD needs kernel ≥ 5.9**.
This crate was born when the dev host ran kernel 5.4 and that redirect path could
not run here; the host is now **6.8** (`6.8.0-1060-aws`) and the seccomp redirect
runs live on it, so on *this* machine fs-preload is no longer the only two-views
mechanism. It remains the **portable wrapper-layer fallback**: per
`docs/design/architecture/privilege-model.md` **§3.2**, on kernels < 5.9 the
filesystem interposition must use **FUSE or `LD_PRELOAD`** instead of seccomp-ADDFD.
This crate is the `LD_PRELOAD` answer. It is also the **Tier 2** FS mechanism
(`privilege-model.md` §2) for any host where unprivileged userns is disabled and
root is unavailable (plain Docker, hardened Debian/RHEL).

Note that wrapping the agent in an unprivileged user namespace (Tier 1) does **not**
back-port the ADDFD ioctl — the FS interposer and the privilege tier are chosen
*independently* (§3.2). On an old-kernel host: Tier 1 userns for the privilege
story (if desired) **plus** `fs-preload` for the FS two-views.

## How it reuses `fs-supervisor` (reuse, don't rewrite)

The redirect **decision** is not reimplemented here. `src/config.rs` builds the
SAME `fs_supervisor::decision::TrackedRoots` from
`fs_supervisor::layout::ViewLayout` and calls the SAME
`fs_supervisor::decision::decide_open`. So:

- tracked-root matching, the boundary-safe prefix check, and the
  `<state>/workspaces/<basename>-<sha256(root)[:12]>/agentview/<suffix>` path math are
  the proven, unit-tested fs-supervisor / fs-sync logic;
- read/write access intent comes from `decide_open`'s `Access`;
- a path already inside the worktree is idempotent (no double-rewrite).

This crate adds only the **transport**: a C-ABI interposer that `dlsym`s the real
open\* and swaps the path argument — the userspace equivalent of what
`fs-supervisor::kernel::step()` does with ADDFD/CONTINUE.

## Env contract

| Variable | Required | Meaning |
|---|---|---|
| `MANDU_PRELOAD_WORKSPACE` | **yes** | `:`-separated list of CANONICAL absolute tracked-workspace roots (HumanView). A file open under any of these is redirected. e.g. `/home/u/proj:/home/u/other`. |
| `MANDU_PRELOAD_AGENTVIEW` | **yes** | The view **state base** (mirrors fs-sync `defaultStateBase`, normally `$HOME/.mandu`). The AgentView worktree is `<state-base>/workspaces/<basename>-<sha256(root)[:12]>/agentview/`. |
| `MANDU_PRELOAD_DEBUG` | no | `1`/`true`/`yes`/`on` → print one `[fs-preload] redirect: <from> -> <to>` line per redirect to stderr. Off (silent) by default. |

If either required var is absent/empty, the library is **inert** — it passes every
open through unchanged (it never rewrites a path it was not configured for).

The roots must be **canonical absolute** paths (the seccomp supervisor relies on a
`realpath` step the OS provides; the preload matches absolute paths as given).

## Build & run

```sh
# from interceptors/
cargo build -p fs-preload            # produces target/debug/libfs_preload.so

# point an agent / shell at it:
MANDU_PRELOAD_WORKSPACE=/home/u/proj \
MANDU_PRELOAD_AGENTVIEW=$HOME/.mandu \
LD_PRELOAD=$PWD/target/debug/libfs_preload.so \
  <the agent command>
```

## The live redirect demo / test

`test/preload-redirect.test.sh` is a **runnable, self-contained end-to-end proof**
on any Linux host, unprivileged (zero privilege and no kernel feature is the
point). It builds the `.so`, creates a HumanView file and a
DIFFERENT AgentView file at the mapped path, then asserts:

1. `LD_PRELOAD=... cat <humanview-path>` returns the **AgentView** bytes (redirected);
2. the same `cat` **without** preload returns the HumanView bytes (the redirect is
   the preload's doing);
3. an **untracked** path under preload returns its **real** bytes (no redirect);
4. (if a C compiler is present) a probe calling `openat(AT_FDCWD, ...)` directly is
   redirected too — covering the `openat` symbol, not just `open`.

It prints `PASS`/`FAIL` and exits nonzero on failure:

```sh
bash interceptors/fs-preload/test/preload-redirect.test.sh
```

The pure parts (env/config parsing, the rewrite decision via the reused
`decide_open`, the recursion guard) are covered by `cargo test -p fs-preload`.

## Covered open variants

`open`, `openat`, `open64`, `openat64`. On glibc, `open64`/`openat64` are the
large-file-offset aliases the compiler emits for normal `open`/`openat` by default,
so interposing all four catches the common cases (coreutils' `cat` reaches us via
`open`; shells/editors/Node typically via `openat`). `openat2(2)` is **not**
interposed: glibc has no public `openat2` wrapper symbol, so there is nothing to
preload — a program using the raw `openat2` syscall bypasses this library (see
threat model).

**Path forms covered.** Every interposed call first absolute-izes its `(dirfd, path)`
pair before the redirect decision, so it is no longer limited to absolute paths:

- **absolute** `path` → used as-is (a `dirfd` is ignored, per POSIX `openat`);
- **relative** under `open`/`open64`, or `openat*` with `dirfd == AT_FDCWD` →
  resolved against the process CWD via `getcwd(3)`;
- **`dirfd`-relative** `openat*` (a real directory fd) → resolved against
  `readlink("/proc/self/fd/<dirfd>")` and joined with the relative `path`.

The joined path is then **lexically** normalized (collapse `//`, drop `.`, pop on
`..` — pure string math, no `realpath`, no symlink resolution) so it prefix-matches
the canonical tracked root the same way the seccomp `decide_open` path does. If a
`dirfd` cannot be resolved (readlink fails / points at an `anon_inode` / non-path),
or the path bytes are not UTF-8, the call **falls through unchanged** (fail safe — we
never redirect a path we cannot resolve, and never panic on non-UTF-8).

## Threat model — a COOPERATIVE boundary

Per `docs/design/architecture/privilege-model.md` **§3.1**, this is a cooperative interposition.
It **captures the real adversary**: a *prompt-injected agent driving its normal
libc/Node tools* (`open`/`openat` through glibc). Injected instructions cannot make
the agent issue raw syscalls or scrub `LD_PRELOAD` from its environment, so the
redirect holds against the threat Mandu actually defends.

It is **bypassable** by:

- a native binary issuing a **raw `syscall(SYS_openat, ...)`** (skips libc);
- a **statically-linked** binary (no dynamic loader → no preload at all);
- a non-libc runtime, or one that **unsets `LD_PRELOAD`** for its children;
- `openat2(2)` (no glibc wrapper to interpose);
- a **symlinked component inside the tracked tree** — paths are resolved
  *lexically*, not via `realpath`, so a symlink whose target lexically escapes the
  tracked root is not followed back in (same posture as the seccomp `decide_open`
  path; see Limitations).

Those are out of scope for the IPI defense. The **hard**-boundary answers are
Tier 1 (unprivileged userns) and host root, reserved for a fully hostile native
payload (§3.1).

A note on the alternative: where content must be **symbolized on read** rather than
served from a pre-symbolized worktree, **FUSE** (`fusermount3`, unprivileged) is the
other Tier-2 mechanism (`mandu.md` §3 lists FUSE as the seccomp-unotify
alternative). This crate deliberately does **not** depend on libfuse (fuse3 headers
are absent on this host); it redirects to the AgentView worktree the fs-sync daemon
already maintains.

## Limitations

- **Recursion guard.** Our own code path (`dlsym`, env reads, stderr) can itself
  call into libc; a thread-local guard makes any re-entrant `open*` fall straight
  through to the real function with the original path. The guard is panic-safe (Drop
  resets it). Consequence: opens issued *by the interposer's own machinery* are
  never redirected — which is correct (they target our config/state, not workspace
  files). Config is resolved once via `OnceLock` (outside the guard, since it only
  reads env).
- **Lexical resolution, no symlink following.** Absolute, relative-to-CWD
  (`AT_FDCWD` / plain `open`), and `dirfd`-relative opens are all resolved (the
  latter via one `readlink(/proc/self/fd/N)` per relative open) and **lexically**
  normalized — we deliberately do **not** call `realpath`/resolve symlink
  components, since the launcher canonicalizes the tracked root and `getcwd` is
  already canonical. Consequence: a symlinked path *inside* the tracked tree is
  matched by its lexical form, not its symlink target — the same posture as the
  seccomp `decide_open` path, which also matches the path as given. Statically
  linked / raw-syscall / non-libc / `openat2` bypass still applies (see threat
  model).
- **No symbolization-on-read** here — it redirects to the already-symbolized
  AgentView worktree (use FUSE for on-the-fly symbolizing reads).

See `docs/design/architecture/privilege-model.md` (§2 tiers, §3.1 cooperative boundary, §3.2
kernel-version caveat) and `docs/design/architecture/mandu.md` §3 for the broader design.
