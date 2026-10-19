//! kernel — execve interception + per-shell sandbox setup (PRIVILEGED, gated).
//!
//! Compiled ONLY with `--features kernel`. It needs CAP_SYS_ADMIN in the current
//! user namespace (real root, or root-in-a-userns: `unshare --user
//! --map-root-user --net --mount --pid --fork`) so it can create the per-exec
//! network namespace and bind-mount the AgentView worktree.
//!
//! ── Mechanism (chosen + documented) ─────────────────────────────────────────
//! A **fork + per-exec namespace sandbox** supervisor (NOT a passive observer).
//! The supervisor is the dispatcher for each exec: it decides the view with the
//! PURE `orchestrate::plan_exec`, then `fork(2)`s a child, applies the chosen
//! shell's sandbox *in the child*, and `execvp`s the planned argv. The child
//! cannot escape the namespace the parent placed it in — so the sandbox is a
//! real enforcement boundary, not advisory.
//!
//! Why fork+namespace AND seccomp-unotify: they serve different roles.
//!   - The FORK MODEL (`supervise_exec`, this section) *re-sandboxes* a
//!     cooperative exec: it owns the dispatch and places the child in its
//!     namespace before `execve`, so it can inject the AgentShell net/FS sandbox.
//!   - The ATTACH FRONT-END (`run_supervisor` + the seccomp-unotify section at the
//!     bottom of this file) traps `execve`/`execveat` of an UNCOOPERATIVE, already-
//!     running process and ENFORCES the *gate*: a disallowed exec (symbol-as-
//!     command / approval required / a needs-sandboxing AgentShell the front-end
//!     can't inject) → respond EPERM so the execve fails (kernel ≥ 5.0); a safe
//!     HumanShell exec → CONTINUE (kernel ≥ 5.5). A seccomp response can only
//!     {error, return, CONTINUE, ADDFD} — it CANNOT inject namespaces, so the
//!     front-end can BLOCK an unsafe exec but cannot re-sandbox an allow; that is
//!     the fork model's job. See the section banner at the bottom of this file.
//!
//! Per intercepted exec the loop does, end to end:
//!   1. Extract argv + cwd (here: from `ExecRequest`; in a seccomp attach: read
//!      them out of the `seccomp_notif` with process_vm_readv).
//!   2. `orchestrate::plan_exec` → AgentShell vs HumanShell (fail-closed to
//!      AgentShell on a arbiter miss — orchestrate already does this).
//!   3. `sandbox_for(plan)` → SandboxSpec; apply it in the forked child:
//!        - AgentShell: the DEFAULT `Bubblewrap` backend execs `bwrap` with the
//!          full asymmetric overlay (RW=AgentView / RO=rest / net=off / fresh
//!          dev+proc+tmpfs), the hardened namespaces (PID/IPC/UTS/cgroup unshared,
//!          new session, `--cap-drop ALL`, `--disable-userns` — probe-gated: a
//!          bwrap < 0.8 lacks the flag and the seccomp filter takes over the
//!          userns-nesting denial, see `bwrap_supports_disable_userns`), and the
//!          seccomp deny-filter (`seccomp_filter`) on `--seccomp <fd>`. The legacy
//!          `InProcess` backend instead enters a fresh net namespace with egress
//!          OFF (`unshare(CLONE_NEWNET)`; only `lo`, left DOWN) and, if a tracked
//!          AgentView root is configured, bind-mounts the AgentView worktree over
//!          the workspace (FS = AgentView) — no RO overlay/hardening/seccomp.
//!          Either way net is dead, files are symbolized; argv stays symbolic.
//!        - HumanShell: keep the inherited network + HumanView FS, but FIRST
//!          block on `plan.approvals` — refuse the exec if approval is withheld
//!          (fail-closed) — then exec the RESOLVED argv from the plan.
//!   4. `execvp` the planned argv; the parent reaps the child.
//!
//! All policy lives in `orchestrate`; this module is the namespace/mount/exec
//! plumbing only.
//!
//! HOW TO RUN ON A PRIVILEGED HOST (full recipe in the crate README):
//!   cargo build -p exec-supervisor --features kernel
//!   # real root, or an unprivileged user namespace (no host changes):
//!   unshare --user --map-root-user --mount --net --pid --fork -- \
//!     bash -c 'cargo test -p exec-supervisor --features kernel -- --ignored --nocapture'

#![cfg(feature = "kernel")]

use std::ffi::CString;
use std::io::{Error, ErrorKind, Result};
use std::os::unix::io::RawFd;
use std::sync::OnceLock;
use std::time::Duration;

use mandu_arbiter::protocol::{ExecApprovalItem, ExecShell};
use mandu_arbiter::ArbiterClient;

use crate::deadline::{exit_code, has_exited, kill_tree_and_reap, timed_out, wait_child, Deadline};
use crate::orchestrate::{plan_exec, record_spawn_lineage, ExecPlan, ExecRequest};
use crate::sandbox::{bwrap_argv, plan_sandbox};
use crate::socket_supervision::{BoxSocketMode, Handoff, SocketPlan, SocketServer};
// Re-export ViewConfig at the kernel path (it moved to `sandbox`, but the
// supervisor's public surface + the integration test reference it here).
pub use crate::sandbox::ViewConfig;
use mandu_arbiter::proc::proc_key_for_pid;

/// The execve(2) syscall number on the target arch — a seccomp/ptrace attach
/// path keys on this. Pinned from libc so the feature build matches the host arch.
pub const SYS_EXECVE: libc::c_long = libc::SYS_execve;

/// execveat(2) — the modern dirfd-relative exec; a seccomp filter must trap this
/// too (e.g. fexecve / `execveat` callers) or the trap is bypassable.
pub const SYS_EXECVEAT: libc::c_long = libc::SYS_execveat;

/// CLONE_NEWNET — the AgentShell child enters a fresh network namespace (egress
/// off: a brand-new netns has only `lo`, and we leave it DOWN).
pub const CLONE_NEWNET: libc::c_int = libc::CLONE_NEWNET;

/// CLONE_NEWNS — used when bind-mounting the AgentView worktree, so the mount is
/// private to the sandboxed child and never pollutes the host mount table.
pub const CLONE_NEWNS: libc::c_int = libc::CLONE_NEWNS;

/// The sandbox the kernel loop must construct for a plan, derived purely from the
/// chosen shell. Separated so a privileged test can assert the mapping without
/// actually creating namespaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxSpec {
    /// True → a network namespace with egress disabled.
    pub net_disabled: bool,
    /// True → bind the AgentView worktree over the workspace; false → HumanView.
    pub fs_agent_view: bool,
}

/// Map a plan's shell to its sandbox spec (pure; testable even under `kernel`).
pub fn sandbox_for(plan: &ExecPlan) -> SandboxSpec {
    match plan.shell {
        ExecShell::AgentShell => SandboxSpec {
            net_disabled: true,
            fs_agent_view: true,
        },
        ExecShell::HumanShell => SandboxSpec {
            net_disabled: false,
            fs_agent_view: false,
        },
    }
}

/// Which mechanism the fork model uses to enact an AgentShell sandbox.
///
/// **`Bubblewrap` is the DEFAULT** (the full hardened box). `InProcess` is a
/// legacy, coarser opt-in kept only for hosts without `bwrap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SandboxBackend {
    /// **DEFAULT.** Realize the full asymmetric overlay (exec-routing.md §4) by
    /// exec'ing `bubblewrap` from `sandbox::bwrap_argv`: RW=AgentView / RO=rest /
    /// net=off / fresh dev+proc+tmpfs, PLUS the hardened namespaces (PID/IPC/UTS/
    /// cgroup unshared, new session, `--cap-drop ALL`, `--disable-userns` where
    /// the probed bwrap ≥ 0.8 supports it — otherwise the seccomp filter carries
    /// the userns-nesting denial) and the
    /// **seccomp deny-filter** (`seccomp_filter`) installed via `--seccomp <fd>`.
    /// This is the design's Phase-1 enforcement and the safe default. REQUIRES the
    /// `bwrap` binary on PATH outside the cwd, the workspace and the AgentView
    /// worktree (`sandbox::resolve_bwrap`).
    #[default]
    Bubblewrap,
    /// LEGACY opt-in. In-process `unshare(2)` + `mount(2)`: net-off netns + a
    /// private bind-mount of the AgentView over the workspace. Does NOT enforce the
    /// RO-outside-AgentView overlay, the hardened namespaces, or the seccomp
    /// deny-filter — a coarser sandbox for hosts where `bwrap` is unavailable.
    InProcess,
}

// ── bwrap capability probe ───────────────────────────────────────────────────

/// PURE: does a `bwrap --help` text advertise `flag`? Whitespace-token-exact
/// match, so `--disable-userns` never matches a different flag that merely
/// embeds the substring (e.g. bwrap ≥ 0.8's `--assert-userns-disabled`).
pub fn bwrap_help_supports(help_text: &str, flag: &str) -> bool {
    help_text.split_whitespace().any(|tok| tok == flag)
}

/// One probe result per process (`bwrap --help` is invariant for the process
/// lifetime, and the probe must never run in a forked child — see
/// `bwrap_supports_disable_userns`).
static BWRAP_DISABLE_USERNS_SUPPORTED: OnceLock<Option<bool>> = OnceLock::new();

/// Does the installed bwrap support `--disable-userns` (added in bwrap 0.8.0)?
/// Runs `bwrap --help` ONCE per process; PARENT-side only (a forked child must
/// not spawn subprocesses between fork and exec).
///
/// The launcher's kept answer comes first (exec-routing.md §4, "The bwrap
/// probe, kept by content"): when `MANDU_BWRAP_DISABLE_USERNS_SHA256` names
/// the sha256 of exactly the bytes at `bwrap`, the answer is `true` with no
/// subprocess. Any other bubblewrap (replaced, patched, another on PATH) is
/// probed as before; only the positive answer is kept, so a wrong value can
/// only make an old bwrap reject the argv (the command fails closed).
///
/// `None` = bwrap itself could not be executed. The caller then keeps the plan
/// UNCHANGED (no degrade): the child's execvp of bwrap fails with the
/// documented 126 — bwrap is a hard requirement of the Bubblewrap backend, not
/// something the probe papers over.
fn bwrap_supports_disable_userns(bwrap: &str) -> Option<bool> {
    *BWRAP_DISABLE_USERNS_SUPPORTED.get_or_init(|| {
        let known = std::env::var(crate::sandbox::BWRAP_DISABLE_USERNS_SHA256_ENV).ok();
        if crate::sandbox::bwrap_known_disable_userns(known.as_deref(), std::path::Path::new(bwrap)) {
            return Some(true);
        }
        let out = std::process::Command::new(bwrap)
            .arg("--help")
            .output()
            .ok()?;
        // bwrap prints usage on stdout today; scan both streams so a version
        // that moves it to stderr does not read as "unsupported".
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        Some(bwrap_help_supports(&text, "--disable-userns"))
    })
}

/// Configuration for the supervisor loop: how to reach the arbiter, where the
/// views live, and which sandbox backend enacts an AgentShell.
///
/// `backend` defaults to `SandboxBackend::Bubblewrap` (the full hardened box:
/// asymmetric overlay + hardened namespaces + seccomp deny-filter), which needs
/// the `bwrap` binary on PATH. Set it to `InProcess` for the legacy path.
#[derive(Debug, Clone, Default)]
pub struct SupervisorConfig {
    pub view: ViewConfig,
    pub backend: SandboxBackend,
    /// Explicit path of the `mandu-landlock-apply` binary the Bubblewrap
    /// backend interposes inside the box (the LSM leg of the overlay). `None` →
    /// resolved at runtime: `$MANDU_LANDLOCK_APPLY`, then a sibling of the
    /// current executable (see `locate_landlock_applier`). Only consulted when
    /// the kernel's Landlock probe answers supported.
    pub landlock_apply: Option<String>,
    /// OPT-IN posture (exec-routing.md §8.4 rung 2, §5): attempt each
    /// AgentShell exec in the CLEAN box first — Landlock read-allow of system
    /// roots + hash-verified grants, AgentView write-only, stdout captured —
    /// and on a clean completion report the verdict (callId + sha256(stdout))
    /// to the arbiter so classify time can upgrade that tool_result. A failed
    /// attempt falls back to the ordinary box (discarded invisibly). Bubblewrap
    /// backend only: the construction leans on the FRESH tmpfs scratch (a real
    /// /tmp would make the RW read-back grant unsound) and the interposed
    /// applier. Default OFF — deliberately a matrix cell, not a new default.
    pub clean_box: bool,
    /// exec-routing.md §8.5.3: the socket of the session's guard, which
    /// runs the clean attempt itself and reports its verdict (the launcher
    /// bakes `MANDU_EXEC_CLEAN_SOCK`). With it, an eligible exec is ASKED of
    /// the guard and never attempted here: this process runs in the agent's
    /// tree and its report would not be honored. An unreachable guard or a
    /// void attempt falls back to the ordinary box.
    pub clean_via: Option<String>,
    /// The guard-hosted mode (`mandu-exec-box --clean-only`, run BY the guard):
    /// the clean attempt only, no verdict report (the guard reports), and no
    /// ordinary box after a void attempt (the requester runs that).
    pub clean_only: bool,
    /// Extra clean-box read grants, re-verified by CONTENT HASH at plan-build
    /// time (`clean::verify_trusted_reads` — the §3 TOCTOU closure). No
    /// production source mints these yet (the registry holds only
    /// untrusted-by-origin records); tests and future registry wiring feed it.
    pub trusted_reads: Vec<crate::clean::TrustedRead>,
    /// The WSL signals the box hiding keys on (`sandbox::wsl_box_hide`).
    /// `None` → probe the running host (`mandu_arbiter::wsl::probe_host`), the
    /// production default; tests pin a WSL host here to prove the hiding on a
    /// plain Linux kernel.
    pub wsl: Option<mandu_arbiter::wsl::WslSignals>,
    /// Where the box looks for host Unix sockets to mask
    /// (`sandbox::socket_box_hide`, exec-routing.md §4.2). `None` → the
    /// production scan (`host_sockets::scan_host`: `/run`, `/var/lib`,
    /// `/var/snap`, `$HOME`'s socket dirs, the sockets the environment names);
    /// tests pin stand-in roots here. Always on for AgentShell: there is no
    /// switch to turn it off.
    pub socket_roots: Option<Vec<crate::host_sockets::ScanRoot>>,
    /// The directory replaced by an empty tmpfs with an allow-list put back
    /// (`sandbox::run_box_hide`). `None` → `/run`, the production value;
    /// tests pin a stand-in, or `Some("")` for a control run with no hiding.
    pub run_dir: Option<String>,
    /// The environment the host hiding reads: the socket-naming variables
    /// (`sandbox::SOCKET_ENV`), `$HOME`, `$XDG_RUNTIME_DIR`, and the files
    /// variables name under `/run`. `None` → this process's own (the agent's,
    /// the production value); tests pin one so a stand-in never leaks into a
    /// concurrently running test's box. (`--unsetenv` in the box always acts
    /// on the real environment the command inherits.)
    pub host_env: Option<Vec<(String, String)>>,
    /// Test only (`None` in production): called with each resolved host
    /// hide just before the box is forked, so a kernel test can make a mount
    /// point vanish in exactly the window the mount race lives in (§4.2).
    pub after_host_hide: Option<fn(&crate::sandbox::HostHide)>,
    /// The box's Unix-socket allow-list (exec-routing.md §4.2,
    /// `socket_supervision`). `None` → on, the production value; tests set
    /// `Some(false)` for a control run that shows what the box reaches
    /// without it. There is no user switch.
    pub socket_allowlist: Option<bool>,
    /// The caller's limit on this whole `supervise_exec` (exec-routing.md
    /// §4.4): past it the box is killed (its whole tree) and the call returns
    /// `ErrorKind::TimedOut`, never an outcome. `None`, the production value:
    /// the command runs as long as it runs (a build, a test suite, a server
    /// the agent started are all legitimate), as an unsupervised exec would;
    /// the agent's own tool timeout is the bound. The supervisor's internal
    /// waits are bounded either way ([`HANDOFF_LIMIT`], [`DRAIN_GRACE`]).
    pub deadline: Option<Duration>,
    /// Test only (`None`: [`HANDOFF_LIMIT`]): the bound on the box's socket
    /// hand-over, so a kernel test can prove it without waiting it out.
    pub handoff_limit: Option<Duration>,
    /// Test only (`None` in production): called in the forked box child just
    /// before its socket hand-over, so a kernel test can stand in for a child
    /// that never reports (it blocks there for good).
    pub before_handoff: Option<fn()>,
}

/// How long the supervisor waits for its forked box child's socket
/// hand-over (exec-routing.md §4.2, §4.4): the child reports right after
/// the fork, before anything of the command runs, so a few milliseconds
/// suffice; a child still silent after this is stuck (a lock a fork in a
/// threaded process inherited, a wedged kernel call), and nothing else
/// would ever end the wait. The box is killed and the exec refused.
pub const HANDOFF_LIMIT: Duration = Duration::from_secs(30);

/// How long a clean attempt's capture pipes may stay open after the box
/// itself exited (exec-routing.md §4.4): the box's pid namespace takes its
/// processes with it, so only a descriptor something outside the box kept
/// (a fork of this process that inherited it) holds them; the attempt is
/// then void and falls back to the ordinary box, as any failed attempt does.
pub const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// The environment the host hiding reads (`SupervisorConfig::host_env`).
fn host_env(cfg: &SupervisorConfig) -> Vec<(String, String)> {
    cfg.host_env.clone().unwrap_or_else(|| std::env::vars().collect())
}

/// What the box hides of this host, resolved PARENT side (no filesystem work
/// between fork and exec): `/run` behind an allow-list (`resolve_run_hide`),
/// the host's other Unix sockets (`resolve_socket_hide`) and, on WSL, the
/// interop door (`resolve_wsl_hide`). `keep` names paths the box must still
/// see if they live under `/run` (the Landlock applier, the cwd, the
/// workspace).
fn resolve_host_hide(cfg: &SupervisorConfig, keep: &[String]) -> crate::sandbox::HostHide {
    let mut hide = resolve_run_hide(cfg, keep);
    hide.merge(resolve_socket_hide(cfg));
    hide.merge(resolve_wsl_hide(cfg));
    hide
}

/// `/run` as the box shows it (exec-routing.md §4.2): an empty tmpfs, its
/// top-level symlinks recreated, `RUN_KEEP` and `keep` bound back, plus every
/// regular file the environment names under it (the TLS-inspection CA bundle
/// the launcher writes to the scope run dir; Node warns on every start when
/// `NODE_EXTRA_CA_CERTS` is missing), and an empty `$XDG_RUNTIME_DIR`. A
/// directory bound back is scanned too, and each socket in it masked.
fn resolve_run_hide(cfg: &SupervisorConfig, keep: &[String]) -> crate::sandbox::HostHide {
    use crate::sandbox::RunEntry;
    let run_dir = cfg.run_dir.clone().unwrap_or_else(|| crate::sandbox::RUN_DIR.to_string());
    if run_dir.is_empty() {
        return crate::sandbox::HostHide::default();
    }
    let kind = |p: &str| -> RunEntry {
        match std::fs::symlink_metadata(p) {
            Err(_) => RunEntry::Missing,
            Ok(m) if m.is_dir() => RunEntry::Dir,
            Ok(m) if m.is_file() => RunEntry::File,
            Ok(m) if m.file_type().is_symlink() => std::fs::read_link(p)
                .ok()
                .and_then(|t| t.to_str().map(String::from))
                .map(RunEntry::Symlink)
                .unwrap_or(RunEntry::Other),
            Ok(_) => RunEntry::Other,
        }
    };
    let top: Vec<(String, RunEntry)> = std::fs::read_dir(&run_dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_type().map(|t| t.is_symlink()).unwrap_or(false))
                .filter_map(|e| {
                    let name = e.file_name().to_str()?.to_string();
                    let entry = kind(&format!("{run_dir}/{name}"));
                    Some((name, entry))
                })
                .collect()
        })
        .unwrap_or_default();
    let env = host_env(cfg);
    let mut keep: Vec<String> = keep.to_vec();
    for (_, v) in &env {
        if v.starts_with('/') && !v.contains(':') && std::path::Path::new(v).is_file() {
            keep.push(v.clone());
        }
    }
    let runtime_dir = env.iter().find(|(k, _)| k == "XDG_RUNTIME_DIR").map(|(_, v)| v.clone());
    let mut hide = crate::sandbox::run_box_hide(&run_dir, &top, kind, &keep, runtime_dir.as_deref());
    // A directory bound back (`/run/wrappers`, a workspace under /run/media)
    // may itself hold a socket: mask it.
    let dirs: Vec<crate::host_sockets::ScanRoot> = hide
        .rebinds
        .iter()
        .filter(|r| std::path::Path::new(r.as_str()).is_dir())
        .map(|r| crate::host_sockets::ScanRoot::new(r.clone(), 6))
        .collect();
    if !dirs.is_empty() {
        let inner = crate::host_sockets::scan(&dirs, &[], &host_mounts(), crate::host_sockets::SCAN_BUDGET);
        hide.files.extend(inner.sockets);
    }
    hide
}

fn host_mounts() -> std::collections::HashMap<String, String> {
    std::fs::read_to_string("/proc/self/mountinfo")
        .map(|t| crate::host_sockets::parse_mountinfo(&t))
        .unwrap_or_default()
}

/// Mask every host Unix socket the scan finds (exec-routing.md §4.2). The
/// environment read is the supervisor's own, which is the agent's.
fn resolve_socket_hide(cfg: &SupervisorConfig) -> crate::sandbox::HostHide {
    let env = host_env(cfg);
    let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let scan = match &cfg.socket_roots {
        // /tmp too when the box shows the agent's real one (exec-routing.md
        // §7.2, "The agent's own /tmp"): its tmux, X11 and ssh-agent sockets.
        None => crate::host_sockets::scan_host(get, crate::sandbox::shares_real_tmp(&cfg.view)),
        Some(roots) => {
            let named = crate::sandbox::socket_paths_from_env(get);
            crate::host_sockets::scan(roots, &named, &host_mounts(), crate::host_sockets::SCAN_BUDGET)
        }
    };
    crate::sandbox::socket_box_hide(&scan)
}

/// The box's WSL hiding for this host. The `$WSL_INTEROP` path is
/// canonicalized so the mask lands on the socket, not on a symlink to it.
fn resolve_wsl_hide(cfg: &SupervisorConfig) -> crate::sandbox::HostHide {
    use crate::sandbox::{wsl_box_hide, PathKind};
    let mut signals = cfg.wsl.clone().unwrap_or_else(|| {
        let mut probed = mandu_arbiter::wsl::probe_host();
        if let Some(env) = &cfg.host_env {
            probed.interop_env = env
                .iter()
                .find(|(k, v)| k == mandu_arbiter::wsl::INTEROP_ENV && !v.is_empty())
                .map(|(_, v)| v.clone());
        }
        probed
    });
    if let Some(sock) = signals.interop_env.take() {
        let canon = std::fs::canonicalize(&sock)
            .ok()
            .and_then(|p| p.to_str().map(String::from))
            .unwrap_or(sock);
        signals.interop_env = Some(canon);
    }
    wsl_box_hide(&signals, |p| match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => PathKind::Dir,
        Ok(_) => PathKind::Other,
        Err(_) => PathKind::Missing,
    })
}

/// Outcome of supervising one exec — surfaced so the integration test can assert
/// the route + result without scraping logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutcome {
    pub shell: ExecShell,
    /// True → the sandbox isolated the network (AgentShell). The child observed a
    /// netns with only `lo` (DOWN) — egress is dead.
    pub net_isolated: bool,
    /// True → the AgentView worktree was bind-mounted over the workspace.
    pub fs_bind_mounted: bool,
    /// True → the asymmetric overlay was enforced (RO outside the AgentView):
    /// by the `Bubblewrap` backend's mounts, or — on a Landlock-supporting
    /// kernel — by the InProcess child's pre-execve restrict (that legacy
    /// path's only RO enforcement; false there on a pre-5.13 kernel).
    pub ro_enforced: bool,
    /// True → a HumanShell exec was refused because approval was withheld.
    pub refused_pending_approval: bool,
    /// The approval items that were withheld (empty unless refused) — WHY the
    /// exec was refused, so `mandu-exec-box` can say what happened
    /// (`refusal::refusal_message`): a `secret_symbol` under `secrets` mode
    /// reads differently from the frozen integrity `symbol_as_command`.
    pub withheld_approvals: Vec<ExecApprovalItem>,
    /// True → the refusal is the supervisor's own fail-closed withhold because
    /// the arbiter's gate did not answer (the plan's `arbiter_miss`), not a
    /// policy decision; `withheld_approvals` then holds a synthesized item.
    pub gate_unreachable: bool,
    /// Set iff this exec COMPLETED inside the CLEAN box (exec-output-trust §4
    /// rung 2): the influence set was trusted by construction, the captured
    /// stdout was forwarded verbatim, and a verdict report was attempted.
    /// `None` = the ordinary path ran (posture off, ineligible stdin, or the
    /// clean attempt failed and fell back).
    pub clean: Option<CleanBoxOutcome>,
    /// True → the LANDLOCK leg of the overlay was engaged for this exec: the
    /// Bubblewrap backend interposed `mandu-landlock-apply` inside the box,
    /// or the InProcess child restricted itself pre-execve. False on a
    /// pre-Landlock kernel (probe-gated self-SKIP) or when the applier binary
    /// could not be located (Bubblewrap only — its mount overlay is complete on
    /// its own; the LSM leg is additive there, load-bearing for InProcess).
    pub landlock_engaged: bool,
    /// The child's exit status (None if it was refused before exec).
    pub child_status: Option<i32>,
    /// Who served the box's socket allow-list (exec-routing.md §4.2).
    pub box_sockets: BoxSocketMode,
}

/// What a completed clean-box run produced (exec-output-trust §4 rung 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanBoxOutcome {
    /// sha256 hex of the exact stdout bytes forwarded to the caller — what the
    /// verdict binds the future tool_result to.
    pub output_sha256: String,
    /// The tool_use id the recorded exec decision correlated to (None = no
    /// decision / no callId on it → nothing to report; the run still counts as
    /// clean-boxed, the upgrade just has no key).
    pub call_id: Option<String>,
    /// The arbiter ACKED the report AND resolved it CLEAN through its §5 gate
    /// chain. False = not reported (no callId), report unreachable, or a gate
    /// failed arbiter-side — all pure utility misses (no upgrade happens).
    pub verdict_clean: bool,
}

/// Locate the `mandu-landlock-apply` binary for the Bubblewrap backend:
/// config override → `$MANDU_LANDLOCK_APPLY` → a sibling of the current
/// executable (cargo places bins at `target/<profile>/` while test binaries run
/// from `target/<profile>/deps/`, so the parent dir is probed too). Only paths
/// that exist are returned — a dangling configured path degrades to `None`
/// (no interposition) rather than a child that can never exec.
fn locate_landlock_applier(cfg: &SupervisorConfig) -> Option<String> {
    let exists = |p: &str| std::path::Path::new(p).is_file();
    if let Some(p) = &cfg.landlock_apply {
        return exists(p).then(|| p.clone());
    }
    if let Ok(p) = std::env::var("MANDU_LANDLOCK_APPLY") {
        if !p.is_empty() {
            return exists(&p).then_some(p);
        }
    }
    let exe = std::env::current_exe().ok()?;
    for dir in [exe.parent(), exe.parent().and_then(|d| d.parent())]
        .into_iter()
        .flatten()
    {
        let cand = dir.join("mandu-landlock-apply");
        if cand.is_file() {
            return Some(cand.to_string_lossy().into_owned());
        }
    }
    None
}

/// Supervise a single exec request: plan it via the arbiter, fork a child, apply
/// the per-shell sandbox in the child, and exec the planned argv. Returns the
/// route + sandbox outcome once the child has been reaped.
///
/// This is the body the supervisor loop runs per intercepted exec. The loop
/// (`run_supervisor`) just feeds it requests; factoring it out lets the
/// privileged integration test drive one exec deterministically.
pub fn supervise_exec(
    client: &mut ArbiterClient,
    cfg: &SupervisorConfig,
    req: &ExecRequest,
) -> Result<ExecOutcome> {
    // 1+2) PURE decision (reused — never reimplemented here). Fail-closed to
    //      AgentShell on a arbiter miss is handled inside plan_exec.
    let deadline = Deadline::after(cfg.deadline);
    let plan = plan_exec(client, req);
    let spec = sandbox_for(&plan);

    // ── Symbol-twin hint (symbol-twin-shell-blindness.md §4.1 v2) ──────────
    // PARENT side, before any fork, AgentShell only (a HumanShell leaf reads
    // HumanView originals — no twin to speak of): the paths THIS leaf's argv
    // names, joined to its own cwd, whose AgentView twin is solely symbol
    // tokens, reported so the proxy can annotate a pipeline / post-`cd` leaf
    // its single `command` string cannot resolve. UTILITY-ONLY + best-effort:
    // nothing here can alter, delay past a few small reads, or fail the exec.
    if plan.shell == ExecShell::AgentShell && !cfg.clean_only {
        let _ = crate::twins::report_twins(
            client,
            &req.argv,
            req.cwd.as_deref(),
            cfg.view.agent_view_root.as_deref(),
        );
    }

    // HumanShell with withheld approvals: REFUSE before forking. We never run an
    // exec whose symbols are in command position without a positive gate (the
    // fail-closed egress rule). No child is spawned.
    if plan.is_human_shell() && plan.needs_approval() {
        return Ok(ExecOutcome {
            shell: plan.shell,
            net_isolated: false,
            fs_bind_mounted: false,
            ro_enforced: false,
            refused_pending_approval: true,
            withheld_approvals: plan.approvals.clone(),
            gate_unreachable: plan.arbiter_miss,
            landlock_engaged: false,
            clean: None,
            child_status: None,
            box_sockets: BoxSocketMode::NotBoxed,
        });
    }

    // bwrap capability probe — PARENT side, once per process, BEFORE the fork
    // (the child must never spawn a subprocess between fork and exec). A bwrap
    // < 0.8 rejects the whole argv over an unknown --disable-userns, which
    // would kill every AgentShell exec; the child then swaps the userns-nesting
    // denial into the seccomp filter instead. Some(true) and None (bwrap not
    // executable — execvp will report the documented 126) both leave the plan
    // unchanged.
    //
    // Which bubblewrap: the distribution's, by real path, never one inside
    // the command's cwd, the workspace, the AgentView worktree (the agent
    // writes there too) or this process's cwd
    // (sandbox::resolve_bwrap; rootless-confinement-ubuntu-2404.md §0.7).
    // None: the child refuses with 126 instead of an execvp PATH search that
    // could find a planted `./bwrap`.
    let bwrap_bin: Option<String> = if cfg.backend == SandboxBackend::Bubblewrap {
        let extra: Vec<&str> = [req.cwd.as_deref(), cfg.view.workspace.as_deref(), cfg.view.agent_view_root.as_deref()]
            .into_iter()
            .flatten()
            .collect();
        crate::sandbox::resolve_bwrap(&extra)
    } else {
        None
    };
    let bwrap_lacks_disable_userns = cfg.backend == SandboxBackend::Bubblewrap
        && bwrap_bin.as_deref().and_then(bwrap_supports_disable_userns) == Some(false);

    // Landlock probe + applier lookup — PARENT side, same rule as the bwrap
    // probe (no filesystem walking between fork and exec). The LSM leg engages
    // only for an AgentShell plan on a Landlock kernel; for Bubblewrap it also
    // needs the applier binary (interposed inside the box — a restricted thread
    // cannot mount, so the restriction must happen after bwrap's mounts). A
    // missing applier degrades Bubblewrap to mounts-only (complete on its own);
    // InProcess needs no binary (the child restricts itself in-process).
    let landlock_ok = plan.shell == ExecShell::AgentShell
        && fs_supervisor::landlock::landlock_supported();
    let landlock_apply_path: Option<String> =
        if landlock_ok && cfg.backend == SandboxBackend::Bubblewrap {
            locate_landlock_applier(cfg)
        } else {
            None
        };
    // What the box hides of the host by mount: `/run` behind an allow-list,
    // the other host Unix sockets, and on WSL the Windows interop door
    // (mandu_arbiter::wsl). PARENT side like the probes above; empty for
    // HumanShell. What the box itself needs from under /run stays: the
    // applier it execs first, the cwd, the workspace.
    let keep: Vec<String> = [landlock_apply_path.clone(), req.cwd.clone(), cfg.view.workspace.clone()]
        .into_iter()
        .flatten()
        .collect();
    let mut host_hide = if plan.shell == ExecShell::AgentShell {
        resolve_host_hide(cfg, &keep)
    } else {
        crate::sandbox::HostHide::default()
    };

    // The box's socket allow-list (exec-routing.md §4.2): who serves it is
    // settled in each forked child (its own listener, the whole-agent guard,
    // or nobody: every connect refused). The probes are PARENT side.
    let socket_plan: Option<SocketPlan> = (plan.shell == ExecShell::AgentShell
        && cfg.backend == SandboxBackend::Bubblewrap
        && cfg.socket_allowlist != Some(false))
        .then(|| SocketPlan::resolve(bwrap_bin.as_deref()));

    // ── CLEAN-BOX ATTEMPT (exec-output-trust §4 rung 2, opt-in posture) ────
    // Eligibility is ALL-of: the posture is on; the plan is AgentShell (only
    // boxed AgentShell can qualify, §5); the Bubblewrap backend (fresh tmpfs +
    // interposed applier — the construction's load-bearing pieces); Landlock
    // probed + applier located (the clean guarantee IS the LSM restriction);
    // and stdin provably influence-free (closed or /dev/null — a pipe could
    // carry bytes from an upstream process the box never saw, e.g. the tool
    // leaf of `cat evil.md | tool`, and upgrading THAT output would break the
    // T-LLM invariant, not just utility). Any failed attempt falls through to
    // the ordinary run below with its captured output discarded (§4's graceful
    // fallback; the rerun cost is the documented family-A trade).
    //
    // Who runs the attempt (§5.3): with the guard's socket configured, the
    // guard does, outside the agent's tree, and reports the verdict itself;
    // this process only relays the bytes. Without it the attempt runs here,
    // and its report is not honored (the arbiter resolves it UNCLEAN) unless
    // this IS the guard-hosted run (`clean_only`), which reports nothing.
    let clean_eligible = cfg.clean_box
        && plan.shell == ExecShell::AgentShell
        && cfg.backend == SandboxBackend::Bubblewrap
        && landlock_ok
        && landlock_apply_path.is_some()
        && stdin_is_influence_free();
    if clean_eligible {
        let hosted = match cfg.clean_via.as_deref().filter(|_| !cfg.clean_only) {
            Some(sock) => clean_via_guard(sock, cfg, req, &plan, &spec, deadline)?,
            None => clean_attempt(
                client,
                cfg,
                req,
                &plan,
                &spec,
                bwrap_lacks_disable_userns,
                bwrap_bin.as_deref(),
                landlock_apply_path.as_deref().unwrap(),
                &host_hide,
                socket_plan.as_ref(),
                !cfg.clean_only,
                deadline,
            )?,
        };
        if let Some(outcome) = hosted {
            return Ok(outcome);
        }
    }
    // The guard-hosted run never falls back: a void attempt is the answer
    // (the requester runs the ordinary box in the agent's own tree).
    if cfg.clean_only {
        return Ok(ExecOutcome {
            shell: plan.shell,
            net_isolated: spec.net_disabled,
            fs_bind_mounted: false,
            ro_enforced: false,
            refused_pending_approval: false,
            withheld_approvals: vec![],
            gate_unreachable: false,
            landlock_engaged: false,
            clean: None,
            child_status: None,
            box_sockets: BoxSocketMode::NotBoxed,
        });
    }

    // 3+4) Fork; the child applies the sandbox then execs the planned argv.
    //
    // The mount race (exec-routing.md §4.2): a host path the box mounts ON
    // (a masked socket, a hidden dir) that vanished after the scan fails
    // bwrap's setup before the command runs. The interposed applier writes
    // one byte on a "box is up" pipe once the mounts are done, so a box that
    // exits without it, while one of its mount points is now gone, never ran
    // the command: rescan and build it once more. Only with an applier (it is
    // the in-box hook) and only for that shape: a command that started is
    // never rerun.
    let mut attempt = 0;
    let mut box_sockets;
    let mut socket_server: Option<SocketServer>;
    let pid = loop {
        attempt += 1;
        let handoff = socket_plan.as_ref().and_then(|_| Handoff::new());
        let child_sockets = ChildSockets::of(socket_plan.as_ref(), handoff.as_ref());
        let ready = if attempt == 1
            && plan.shell == ExecShell::AgentShell
            && cfg.backend == SandboxBackend::Bubblewrap
            && landlock_apply_path.is_some()
            && host_hide.mount_points().next().is_some()
        {
            ready_pipe()
        } else {
            None
        };
        // SAFETY: fork in a program that does not hold locks across the
        // boundary; the child only calls async-signal-safe-enough setup
        // (unshare/mount/chdir/execvp) and exits via _exit on any failure so it
        // never runs parent destructors.
        if let Some(hook) = cfg.after_host_hide {
            hook(&host_hide);
        }
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(Error::last_os_error());
        }
        if pid == 0 {
            // ── CHILD ──────────────────────────────────────────────────────
            // Any failure here must _exit with a distinct code (never
            // panic/return), so the parent can tell setup-failure from the
            // child program's status.
            let code = child_apply_and_exec(
                cfg.backend,
                &spec,
                &plan,
                &cfg.view,
                req.cwd.as_deref(),
                bwrap_lacks_disable_userns,
                bwrap_bin.as_deref(),
                landlock_ok,
                landlock_apply_path.as_deref(),
                None, // ordinary (non-clean) posture
                &host_hide,
                ready.map(|(_, w)| w),
                child_sockets,
                cfg.before_handoff,
            );
            // execvp only returns on failure; child_apply_and_exec returns
            // the errno code to report.
            unsafe { libc::_exit(code) };
        }

        // ── PARENT ─────────────────────────────────────────────────────────
        // Take the box's listener (or learn who serves it) before anything
        // else: the box's first connect or bind waits on it.
        (box_sockets, socket_server) = adopt_sockets(pid, socket_plan.is_some(), handoff, handoff_deadline(cfg, deadline))?;
        // REAL spawn-lineage edge (design §3.2), best-effort + OFF the
        // security path, while the child is alive. The parent (us) holds the
        // ArbiterClient; record child(pid)→parent(self) with the SHARED
        // proc-key format so a later transitive-taint walk can mark the whole
        // invocation subtree. A miss (arbiter down / /proc race for the just-
        // forked child's starttime) is swallowed — it NEVER blocks or alters
        // the fork/exec (the chain's safety rests on the fail-closed gate).
        if let (Some(child_key), Some(parent_key)) = (
            proc_key_for_pid(pid),
            proc_key_for_pid(std::process::id() as i32),
        ) {
            let _ = record_spawn_lineage(client, &child_key, &parent_key);
        }

        let Some((read_end, write_end)) = ready else { break pid };
        // SAFETY: our copy of the write end; the child (and the box) hold theirs.
        unsafe { libc::close(write_end) };
        // Wait for the exit WITHOUT reaping it (the ordinary wait below reaps):
        // the command's run, so only the caller's deadline bounds it.
        let waited = match wait_child(pid, deadline, true) {
            Ok(None) => {
                // SAFETY: our read end, closed once.
                unsafe { libc::close(read_end) };
                kill_tree_and_reap(pid);
                drop(socket_server.take());
                return Err(timed_out("supervise_exec: the boxed command"));
            }
            Ok(Some(info)) => Some(info),
            Err(_) => None,
        };
        let up = read_ready(read_end);
        // SAFETY: our read end, closed once.
        unsafe { libc::close(read_end) };
        let failed = waited.is_some_and(|info| exit_code(&info) != Some(0));
        if crate::sandbox::box_setup_raced(up, failed, &host_hide, |p| std::fs::symlink_metadata(p).is_ok()) {
            let mut status: libc::c_int = 0;
            // SAFETY: reap the box that never ran the command before building the next.
            unsafe { libc::waitpid(pid, &mut status, 0) };
            // Its server stops before the next fork (no thread across a fork).
            drop(socket_server.take());
            host_hide = resolve_host_hide(cfg, &keep);
            continue;
        }
        break pid;
    };

    // The command's run: as long as it takes, unless the caller set a
    // deadline (then the box is killed past it and the exec refused).
    let waited = wait_child(pid, deadline, false);
    let info = match waited {
        Ok(Some(info)) => info,
        Ok(None) => {
            kill_tree_and_reap(pid);
            drop(socket_server);
            return Err(timed_out("supervise_exec: the boxed command"));
        }
        Err(e) => {
            drop(socket_server);
            return Err(e);
        }
    };
    drop(socket_server);
    let exit_code = exit_code(&info);

    Ok(ExecOutcome {
        shell: plan.shell,
        net_isolated: spec.net_disabled,
        fs_bind_mounted: spec.fs_agent_view
            && cfg.view.agent_view_root.is_some()
            && cfg.view.workspace.is_some(),
        // The asymmetric RO overlay is enacted by the bubblewrap backend's mounts
        // on an AgentShell exec, and by the InProcess child's Landlock restrict
        // where the kernel supports it (the legacy path's ONLY RO enforcement).
        ro_enforced: spec.fs_agent_view
            && (cfg.backend == SandboxBackend::Bubblewrap || landlock_ok),
        refused_pending_approval: false,
        withheld_approvals: vec![],
        gate_unreachable: false,
        landlock_engaged: landlock_ok
            && (cfg.backend == SandboxBackend::InProcess || landlock_apply_path.is_some()),
        clean: None,
        child_status: exit_code,
        box_sockets,
    })
}

/// What a forked box child does about its socket allow-list.
#[derive(Clone, Copy)]
enum ChildSockets<'a> {
    /// No allow-list (not a box, or a test's control run).
    Off,
    /// The handoff could not be set up: fail closed (every connect refused).
    Deny,
    /// Install the box's own listener, or learn who serves the box.
    Try(&'a SocketPlan, &'a Handoff),
}

impl<'a> ChildSockets<'a> {
    fn of(plan: Option<&'a SocketPlan>, handoff: Option<&'a Handoff>) -> Self {
        match (plan, handoff) {
            (None, _) => ChildSockets::Off,
            (Some(_), None) => ChildSockets::Deny,
            (Some(p), Some(h)) => ChildSockets::Try(p, h),
        }
    }
}

/// PARENT side of `ChildSockets`, right after the fork. A hand-over that
/// does not come before `until` kills the child and refuses the exec
/// (`ErrorKind::TimedOut`): nothing would ever end that wait.
fn adopt_sockets(child: i32, planned: bool, handoff: Option<Handoff>, until: Deadline) -> Result<(BoxSocketMode, Option<SocketServer>)> {
    match handoff {
        Some(h) => match crate::socket_supervision::parent_side(child, h, until) {
            Some(adopted) => Ok(adopted),
            None => {
                kill_tree_and_reap(child);
                Err(timed_out("supervise_exec: the box's socket hand-over (its forked child never reported)"))
            }
        },
        None if planned => Ok((BoxSocketMode::ConnectDenied, None)),
        None => Ok((BoxSocketMode::NotBoxed, None)),
    }
}

/// The hand-over's bound: [`HANDOFF_LIMIT`] (or a test's), never past the
/// caller's deadline.
fn handoff_deadline(cfg: &SupervisorConfig, deadline: Deadline) -> Deadline {
    deadline.capped(cfg.handoff_limit.unwrap_or(HANDOFF_LIMIT))
}

/// CHILD side, before bwrap is exec'd: an inherited Unix datagram socket
/// could send to any host path (the box never creates one: the deny-filter
/// refuses it), so none enters the box. On 0..=2 it becomes /dev/null (the
/// command keeps its stdio slots); any other one is closed.
fn drop_inherited_unix_datagrams() {
    let fds: Vec<RawFd> = match std::fs::read_dir("/proc/self/fd") {
        Ok(rd) => rd.flatten().filter_map(|e| e.file_name().to_str().and_then(|n| n.parse().ok())).collect(),
        Err(_) => return,
    };
    let opt = |fd: RawFd, name: libc::c_int| -> Option<libc::c_int> {
        let mut v: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: getsockopt into an int.
        let rc = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, name, &mut v as *mut _ as *mut libc::c_void, &mut len) };
        (rc == 0).then_some(v)
    };
    for fd in fds {
        if opt(fd, libc::SO_DOMAIN) != Some(libc::AF_UNIX) || opt(fd, libc::SO_TYPE) != Some(libc::SOCK_DGRAM) {
            continue;
        }
        if fd <= 2 {
            // SAFETY: open /dev/null and move it onto the slot.
            let null = unsafe { libc::open(b"/dev/null\0".as_ptr() as *const libc::c_char, libc::O_RDWR) };
            if null >= 0 {
                unsafe { libc::dup2(null, fd) };
                unsafe { libc::close(null) };
            } else {
                unsafe { libc::close(fd) };
            }
        } else {
            // SAFETY: closing an inherited descriptor in the child.
            unsafe { libc::close(fd) };
        }
    }
}

// ── the mount race (exec-routing.md §4.2) ────────────────────────────────────

/// The "box is up" pipe: `(read, write)`, both close-on-exec (the child clears
/// the flag on its write end just before exec'ing bwrap) and non-blocking, so
/// the parent's read after the exit never hangs on a writer the box leaked.
fn ready_pipe() -> Option<(RawFd, RawFd)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: pipe2 writes two fds into our owned array.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return None;
    }
    Some((fds[0], fds[1]))
}

/// Did the applier say the box was built? One byte on the pipe.
fn read_ready(fd: RawFd) -> bool {
    let mut b = [0u8; 1];
    // SAFETY: reading one byte into our owned buffer; non-blocking.
    unsafe { libc::read(fd, b.as_mut_ptr() as *mut libc::c_void, 1) == 1 }
}

// ── CLEAN-BOX ATTEMPT (exec-routing.md §8.4 rung 2) ───────────────────────

/// Is the supervisor's OWN stdin — which the boxed child inherits — provably
/// influence-free? True for CLOSED (fstat → EBADF: no channel at all) and for
/// the `/dev/null` character device (reads yield nothing). Everything else —
/// a pipe (an upstream process could feed bytes the box never vetted), a
/// regular file, a socket, a TTY — disqualifies the CLEAN attempt (the exec
/// still runs, ordinarily boxed; pure utility miss).
fn stdin_is_influence_free() -> bool {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fstat writes into our owned stat buffer.
    if unsafe { libc::fstat(0, &mut st) } != 0 {
        return std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF);
    }
    (st.st_mode & libc::S_IFMT) == libc::S_IFCHR
        && crate::clean::dev_is_dev_null(st.st_rdev as u64)
}

/// How a clean attempt's drain ended.
#[derive(Debug, PartialEq, Eq)]
enum Drained {
    /// Both pipes reached their end: the captured stdout and stderr.
    Whole(Vec<u8>, Vec<u8>),
    /// Overflow, a hard read/poll error, or pipes still open [`DRAIN_GRACE`]
    /// after the child `pid` exited: the attempt is void (the caller kills
    /// the child and falls back).
    Void,
    /// The caller's deadline passed first.
    TimedOut,
}

/// One capped drain of the clean child's stdout+stderr pipes: poll both until
/// EOF, appending into capacity-capped buffers. Blocking fds; EINTR retried.
/// Bounded (exec-routing.md §4.4): by `until` (the caller's deadline), and,
/// once the child `pid` has exited, by [`DRAIN_GRACE`] (its pipes are then
/// held only by something outside the box).
fn drain_two_capped(out_fd: RawFd, err_fd: RawFd, pid: i32, until: Deadline, grace: Duration) -> Drained {
    use crate::clean::{CLEAN_STDERR_CAP, CLEAN_STDOUT_CAP};
    let mut bufs: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
    let caps = [CLEAN_STDOUT_CAP, CLEAN_STDERR_CAP];
    let mut open = [true, true];
    let fds = [out_fd, err_fd];
    let mut chunk = [0u8; 65536];
    let mut exited: Option<Deadline> = None;
    while open[0] || open[1] {
        if until.passed() {
            return Drained::TimedOut;
        }
        match exited {
            Some(g) if g.passed() => return Drained::Void,
            None if has_exited(pid) => exited = Some(Deadline::after(Some(grace))),
            _ => {}
        }
        let mut pfds: Vec<libc::pollfd> = fds
            .iter()
            .zip(open.iter())
            .filter(|(_, o)| **o)
            .map(|(&fd, _)| libc::pollfd { fd, events: libc::POLLIN, revents: 0 })
            .collect();
        // A tick, so the child's exit and the deadlines are looked at.
        let tick = until.poll_ms(Duration::from_millis(100));
        // SAFETY: pfds is a live array of initialized pollfds.
        let rc = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, tick) };
        if rc < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Drained::Void;
        }
        for p in &pfds {
            if p.revents == 0 {
                continue;
            }
            let idx = if p.fd == fds[0] { 0 } else { 1 };
            // SAFETY: reading into our owned chunk buffer.
            let n = unsafe {
                libc::read(p.fd, chunk.as_mut_ptr() as *mut libc::c_void, chunk.len())
            };
            match n {
                0 => open[idx] = false, // EOF (all writers gone)
                n if n > 0 => {
                    bufs[idx].extend_from_slice(&chunk[..n as usize]);
                    if bufs[idx].len() > caps[idx] {
                        return Drained::Void; // overflow → abort the attempt
                    }
                }
                _ => {
                    let e = std::io::Error::last_os_error().raw_os_error();
                    if e != Some(libc::EINTR) {
                        return Drained::Void;
                    }
                }
            }
        }
    }
    let [out, err] = bufs;
    Drained::Whole(out, err)
}

/// One capture pipe of the clean attempt, `(read, write)`, both
/// close-on-exec (exec-routing.md §4.4). The box child moves its write ends
/// onto fd 1 and 2 with `dup2`, which clears the flag on the copies it execs
/// with; every OTHER process forked from this one while the pipes exist (a
/// spawn on another thread of a threaded caller) drops them at its exec. A
/// plain `pipe` left them in such a process for as long as it ran, the
/// drain saw them open `DRAIN_GRACE` past the box's exit, and the attempt
/// was voided (pipeline #11899, 2026-10-18).
fn capture_pipe() -> Option<(RawFd, RawFd)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: pipe2 writes two fds into our owned array.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return None;
    }
    Some((fds[0], fds[1]))
}

/// Write `bytes` to `fd` in full (short writes retried; EINTR retried).
/// Best-effort: an error stops the flush (the caller has already committed to
/// the clean outcome; a broken caller pipe is the caller's condition to see).
fn write_all_fd(fd: RawFd, bytes: &[u8]) {
    let mut off = 0usize;
    while off < bytes.len() {
        // SAFETY: writing from our owned slice.
        let n = unsafe {
            libc::write(fd, bytes[off..].as_ptr() as *const libc::c_void, bytes.len() - off)
        };
        if n > 0 {
            off += n as usize;
        } else if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return;
        }
    }
}

/// Correlate this invocation to its tool_use id and report the clean verdict.
/// BEST-EFFORT, off the security path: every miss (no decision, no callId on
/// it, arbiter unreachable, a §5 gate failing arbiter-side) only costs the
/// upgrade — the exec outcome is already decided. Returns (call_id,
/// verdict_clean-as-resolved-by-the-arbiter).
fn report_clean_verdict(
    client: &mut ArbiterClient,
    argv: &[String],
    proc_key: Option<String>,
    output_sha256: &str,
    read_grants: usize,
) -> (Option<String>, bool) {
    use mandu_arbiter::protocol::{ExecCleanVerdictReport, ExecDecisionForArgs};
    let call_id = client
        .exec_decision_for(&ExecDecisionForArgs { command: None, argv: Some(argv.to_vec()) })
        .ok()
        .and_then(|r| r.decision)
        .and_then(|d| d.call_id);
    let Some(call_id) = call_id else {
        return (None, false);
    };
    let verdict = client.report_exec_clean_verdict(&ExecCleanVerdictReport {
        call_id: call_id.clone(),
        clean: true,
        boxed: Some(true),
        shell: Some("AgentShell".into()),
        proc_key,
        output_sha256: Some(output_sha256.to_string()),
        reason: Some(format!(
            "clean box: Landlock read-allow ({} system roots + {read_grants} verified grants), \
             AgentView write-only, fresh scratch, net off",
            crate::sandbox::CLEAN_READ_ROOTS.len()
        )),
        session_key: None,
    });
    let clean = verdict.map(|v| v.clean).unwrap_or(false);
    (Some(call_id), clean)
}

/// Run one AgentShell exec inside the CLEAN box with stdout/stderr captured.
/// `Some(outcome)` iff the command COMPLETED (exit 0) under the clean ruleset —
/// the captured output has then been forwarded verbatim and a verdict report
/// attempted. `None` = the attempt is void (nonzero exit — often an in-box
/// EACCES on an unverified read —, capture overflow, or any plumbing failure):
/// nothing was forwarded, the caller reruns in the ordinary box (the §4
/// graceful fallback; today's behavior, output UNTRUSTED).
///
/// Exit-0 is the verdict gate ON PURPOSE: the applier fail-closes (exit 71,
/// target never exec'd) if the clean restriction cannot be applied, so a zero
/// exit implies the Landlock clean ruleset was live around the whole run.
#[allow(clippy::too_many_arguments)]
fn clean_attempt(
    client: &mut ArbiterClient,
    cfg: &SupervisorConfig,
    req: &ExecRequest,
    plan: &ExecPlan,
    spec: &SandboxSpec,
    bwrap_lacks_disable_userns: bool,
    bwrap_bin: Option<&str>,
    applier: &str,
    host_hide: &crate::sandbox::HostHide,
    socket_plan: Option<&SocketPlan>,
    report: bool,
    deadline: Deadline,
) -> Result<Option<ExecOutcome>> {
    // Resolve the read-allow set PRE-FORK (no filesystem work between fork and
    // exec): the system roots + every trusted-read grant whose CURRENT content
    // hashes to its granted value (clean::verify_trusted_reads — §3 TOCTOU
    // closure). Grants that fail verification are silently absent: the command
    // then can't read them and the attempt falls back (restrictive).
    let mut read_paths: Vec<String> =
        crate::sandbox::CLEAN_READ_ROOTS.iter().map(|s| s.to_string()).collect();
    let grants = crate::clean::verify_trusted_reads(&cfg.trusted_reads);
    let grant_count = grants.len();
    read_paths.extend(grants);

    // Capture pipes for stdout + stderr. Captured (not streamed) so a FAILED
    // attempt is invisible to the caller — its bytes (including in-box EACCES
    // noise) are discarded before the fallback rerun produces the real output.
    let Some((out_r, out_w)) = capture_pipe() else {
        return Ok(None);
    };
    let Some((err_r, err_w)) = capture_pipe() else {
        unsafe { libc::close(out_r); libc::close(out_w) };
        return Ok(None);
    };

    let handoff = socket_plan.and_then(|_| Handoff::new());
    let child_sockets = ChildSockets::of(socket_plan, handoff.as_ref());

    // SAFETY: same fork contract as the ordinary path (child only does
    // async-signal-safe-enough setup and _exits on failure).
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(out_r); libc::close(out_w);
            libc::close(err_r); libc::close(err_w);
        }
        return Ok(None);
    }

    if pid == 0 {
        // ── CHILD: stdout/stderr onto the capture pipes, then the SAME sandbox
        // setup as the ordinary path with the clean posture flipped on.
        unsafe {
            libc::dup2(out_w, 1);
            libc::dup2(err_w, 2);
            libc::close(out_r); libc::close(out_w);
            libc::close(err_r); libc::close(err_w);
        }
        let code = child_apply_and_exec(
            cfg.backend,
            spec,
            plan,
            &cfg.view,
            req.cwd.as_deref(),
            bwrap_lacks_disable_userns,
            bwrap_bin,
            true, // landlock_ok — eligibility already required it
            Some(applier),
            Some(&read_paths),
            host_hide,
            None, // a failed attempt falls through to the ordinary box, which retries a race
            child_sockets,
            cfg.before_handoff,
        );
        unsafe { libc::_exit(code) };
    }

    // ── PARENT ──────────────────────────────────────────────────────────────
    unsafe {
        libc::close(out_w);
        libc::close(err_w);
    }
    // Served until this function returns (the ordinary box forks after it).
    let (box_sockets, _socket_server) = match adopt_sockets(pid, socket_plan.is_some(), handoff, handoff_deadline(cfg, deadline)) {
        Ok(adopted) => adopted,
        Err(e) => {
            unsafe {
                libc::close(out_r);
                libc::close(err_r);
            }
            return Err(e);
        }
    };

    // The invocation's proc key + lineage edge, before the child can exit
    // (same best-effort posture as the ordinary path).
    let child_key = proc_key_for_pid(pid);
    if let (Some(ck), Some(pk)) = (child_key.clone(), proc_key_for_pid(std::process::id() as i32)) {
        let _ = record_spawn_lineage(client, &ck, &pk);
    }

    let drained = drain_two_capped(out_r, err_r, pid, deadline, DRAIN_GRACE);
    unsafe {
        libc::close(out_r);
        libc::close(err_r);
    }
    let captured = match drained {
        Drained::Whole(out, err) => Some((out, err)),
        Drained::TimedOut => {
            kill_tree_and_reap(pid);
            return Err(timed_out("supervise_exec: the clean attempt's command"));
        }
        Drained::Void => {
            // Overflow / drain failure: kill the (possibly still-writing)
            // child so the wait cannot hang, then reap it below.
            unsafe { libc::kill(pid, libc::SIGKILL) };
            None
        }
    };

    // Its pipes are closed; the command may still run (stdout closed, not
    // done): the caller's deadline bounds it.
    let status = match wait_child(pid, deadline, false) {
        Ok(Some(info)) => info,
        Ok(None) => {
            kill_tree_and_reap(pid);
            return Err(timed_out("supervise_exec: the clean attempt's command"));
        }
        Err(_) => return Ok(None),
    };
    let exit_zero = exit_code(&status) == Some(0);

    // Discarded-attempt diagnostics, OPT-IN only (MANDU_EXEC_CLEAN_DEBUG):
    // in production the supervisor's stderr IS the tool_result stderr, so the
    // default fallback stays byte-invisible.
    let debug = std::env::var("MANDU_EXEC_CLEAN_DEBUG").map(|v| v != "0" && !v.is_empty()).unwrap_or(false);
    if debug && (captured.is_none() || !exit_zero) {
        eprintln!(
            "mandu-exec-box[clean-debug]: attempt fell back — status={:?} captured={} stderr={:?}",
            exit_code(&status),
            captured.is_some(),
            captured
                .as_ref()
                .map(|(_, e)| String::from_utf8_lossy(&e[..e.len().min(512)]).into_owned())
        );
    }
    let Some((stdout, stderr)) = captured else { return Ok(None) };
    if !exit_zero {
        return Ok(None); // discard the buffers; the ordinary rerun speaks
    }

    // Clean completion: forward the exact bytes, then report the verdict the
    // hash binds those bytes to. Report BEFORE returning (and therefore before
    // this process exits): the harness classifies the tool_result the moment
    // the command completes, and the verdict must already be in the store.
    write_all_fd(1, &stdout);
    write_all_fd(2, &stderr);
    let output_sha256 = crate::clean::sha256_hex(&stdout);
    let (call_id, verdict_clean) = if report {
        report_clean_verdict(client, &req.argv, child_key, &output_sha256, grant_count)
    } else {
        (None, false)
    };

    Ok(Some(ExecOutcome {
        shell: plan.shell,
        net_isolated: spec.net_disabled,
        fs_bind_mounted: spec.fs_agent_view
            && cfg.view.agent_view_root.is_some()
            && cfg.view.workspace.is_some(),
        ro_enforced: true,
        refused_pending_approval: false,
        withheld_approvals: vec![],
        gate_unreachable: false,
        landlock_engaged: true,
        clean: Some(CleanBoxOutcome { output_sha256, call_id, verdict_clean }),
        child_status: Some(0),
        box_sockets,
    }))
}

/// Ask the session's guard to run this exec in the clean box
/// (exec-routing.md §8.5.3, `mandu_arbiter::clean_run`). The guard runs it
/// outside the agent's tree, reports the verdict with its own token, and
/// answers with the captured bytes, which are forwarded here verbatim.
/// `None` (nothing forwarded; the caller runs the ordinary box): the guard is
/// unreachable, the attempt was void, or the answer was cut short.
fn clean_via_guard(
    sock: &str,
    cfg: &SupervisorConfig,
    req: &ExecRequest,
    plan: &ExecPlan,
    spec: &SandboxSpec,
    deadline: Deadline,
) -> Result<Option<ExecOutcome>> {
    use mandu_arbiter::clean_run::{encode_request, parse_reply_header, CleanRequest, MAX_REPLY_HEADER};
    use std::io::{BufRead, Read, Write};
    let cwd = match req.cwd.clone().or_else(|| std::env::current_dir().ok()?.to_str().map(str::to_string)) {
        Some(c) => c,
        None => return Ok(None),
    };
    let Ok(mut stream) = std::os::unix::net::UnixStream::connect(sock) else { return Ok(None) };
    // The guard runs the command: its answer takes the command's run, so
    // only the caller's deadline bounds it (each read waits at most what is
    // left of it). Past it the exec is refused, not run again here.
    let ran_out = |e: &std::io::Error| matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) && deadline.0.is_some();
    let limit = |stream: &std::os::unix::net::UnixStream| -> Result<()> {
        if let Some(left) = deadline.remaining() {
            if left.is_zero() {
                return Err(timed_out("supervise_exec: the guard-hosted clean attempt"));
            }
            stream.set_read_timeout(Some(left))?;
            stream.set_write_timeout(Some(left))?;
        }
        Ok(())
    };
    if limit(&stream).is_err() {
        return Err(timed_out("supervise_exec: the guard-hosted clean attempt"));
    }
    match stream.write_all(&encode_request(&CleanRequest { argv: req.argv.clone(), cwd })) {
        Ok(()) => {}
        Err(e) if ran_out(&e) => return Err(timed_out("supervise_exec: the guard-hosted clean attempt")),
        Err(_) => return Ok(None),
    }
    let mut reader = std::io::BufReader::new(stream);
    let mut header = Vec::new();
    match (&mut reader).take(MAX_REPLY_HEADER as u64 + 1).read_until(b'\n', &mut header) {
        Ok(_) => {}
        Err(e) if ran_out(&e) => return Err(timed_out("supervise_exec: the guard-hosted clean attempt")),
        Err(_) => return Ok(None),
    }
    if header.last() != Some(&b'\n') {
        return Ok(None);
    }
    header.pop();
    let Ok(reply) = parse_reply_header(&header) else { return Ok(None) };
    // Opt-in diagnostics, as for the in-tree attempt (MANDU_EXEC_CLEAN_DEBUG):
    // the guard's reason for a void attempt or an unhonored verdict.
    if std::env::var("MANDU_EXEC_CLEAN_DEBUG").map(|v| v != "0" && !v.is_empty()).unwrap_or(false) && (!reply.completed || !reply.clean) {
        eprintln!("mandu-exec-box[clean-debug]: guard-hosted attempt: completed={} clean={} reason={:?}", reply.completed, reply.clean, reply.reason);
    }
    if !reply.completed {
        return Ok(None);
    }
    let mut stdout = vec![0u8; reply.stdout as usize];
    let mut stderr = vec![0u8; reply.stderr as usize];
    if limit(reader.get_ref()).is_err() {
        return Err(timed_out("supervise_exec: the guard-hosted clean attempt"));
    }
    for buf in [&mut stdout, &mut stderr] {
        match reader.read_exact(buf) {
            Ok(()) => {}
            Err(e) if ran_out(&e) => return Err(timed_out("supervise_exec: the guard-hosted clean attempt")),
            Err(_) => return Ok(None),
        }
    }
    write_all_fd(1, &stdout);
    write_all_fd(2, &stderr);
    Ok(Some(ExecOutcome {
        shell: plan.shell,
        net_isolated: spec.net_disabled,
        fs_bind_mounted: spec.fs_agent_view
            && cfg.view.agent_view_root.is_some()
            && cfg.view.workspace.is_some(),
        ro_enforced: true,
        refused_pending_approval: false,
        withheld_approvals: vec![],
        gate_unreachable: false,
        landlock_engaged: true,
        clean: Some(CleanBoxOutcome {
            output_sha256: crate::clean::sha256_hex(&stdout),
            call_id: reply.call_id,
            verdict_clean: reply.clean,
        }),
        child_status: Some(0),
        box_sockets: BoxSocketMode::Guard,
    }))
}

/// Child-side: apply the sandbox for `spec`/`plan`, then `execvp` the planned
/// argv. Returns an exit code to `_exit` with; it only returns on a setup or
/// exec FAILURE (a successful execvp never returns).
///
/// Two backends (SandboxBackend):
///   - `Bubblewrap` (DEFAULT) → build the asymmetric-overlay argv with the PURE
///     `sandbox::bwrap_argv` (RW=AgentView / RO=rest / net=off / fresh
///     dev+proc+tmpfs + hardened namespaces + dropped caps) and `execvp`
///     bubblewrap, which sets up the userns/netns/mounts itself. For the
///     AgentShell we ALSO install the seccomp deny-filter: build the bytes with
///     `seccomp_filter::agentshell_seccomp_filter_with` (deny_userns matching
///     the plan — see `bwrap_lacks_disable_userns`), write them to an anonymous
///     fd, and hand it to bwrap as `--seccomp <fd>` (see
///     `install_seccomp_filter_fd`). A HumanShell plan (passthrough) execs the
///     argv directly, unfiltered.
///   - `InProcess` → the legacy hand-rolled `unshare(2)`+`mount(2)` path below
///     (net-off netns + AgentView bind; no hardened namespaces, no seccomp
///     filter — its RO-outside-AgentView enforcement is the pre-execve Landlock
///     restrict, on kernels ≥ 5.13 where the parent's probe engaged it).
///
/// Exit-code convention (so the parent/test can diagnose):
///   0..=125  → the child program's own status (after a successful exec).
///   126      → execvp failed (command not found / not executable).
///   71       → sandbox setup failed (unshare/mount/chdir/seccomp-fd/landlock) — EX_OSERR-ish.
#[allow(clippy::too_many_arguments)]
fn child_apply_and_exec(
    backend: SandboxBackend,
    spec: &SandboxSpec,
    plan: &ExecPlan,
    view: &ViewConfig,
    cwd: Option<&str>,
    bwrap_lacks_disable_userns: bool,
    // The bubblewrap to exec (parent-resolved, sandbox::resolve_bwrap); None
    // refuses with 126 rather than an execvp PATH search.
    bwrap_bin: Option<&str>,
    landlock_ok: bool,
    landlock_apply_path: Option<&str>,
    // Some(read_paths) → the CLEAN posture (exec-output-trust §4 rung 2): the
    // interposed applier renders in clean mode with these as the only readable
    // roots. Bubblewrap-only; the clean_attempt caller guarantees the applier.
    clean_read_paths: Option<&[String]>,
    // The host hiding (`resolve_host_hide`, parent side: sockets + the WSL
    // interop door). Bubblewrap only: the legacy InProcess backend builds no
    // fresh mounts beyond the AgentView bind (exec-routing.md §4.1, §4.2).
    host_hide: &crate::sandbox::HostHide,
    // The write end of the "box is up" pipe (the mount race, §4.2), handed to
    // the applier; None without one.
    ready_fd: Option<RawFd>,
    // The socket allow-list's child side (§4.2, `socket_supervision`).
    sockets: ChildSockets<'_>,
    // Test only (`SupervisorConfig::before_handoff`): run just before the
    // hand-over, standing in for a child that never reports (§4.4).
    before_handoff: Option<fn()>,
) -> i32 {
    if backend == SandboxBackend::Bubblewrap {
        // Realize the asymmetric overlay via bubblewrap (the PURE plan builder).
        let mut sb = plan_sandbox(plan.shell, view, cwd);
        // Probed bwrap without --disable-userns (< 0.8): the flag would make
        // bwrap reject the whole argv, so the seccomp filter takes over the
        // userns-nesting denial (unshare/clone with CLONE_NEWUSER → EPERM,
        // clone3 → ENOSYS). The denial itself is never dropped.
        if sb.sandboxed && bwrap_lacks_disable_userns {
            sb.disable_userns = false;
            sb.seccomp_deny_userns = true;
        }
        // The LSM leg: interpose `mandu-landlock-apply` inside the box (the
        // parent probed Landlock + located the binary). bwrap_argv threads it
        // between bwrap and the target; the applier restricts itself AFTER
        // bwrap's mounts, then execs the target. None → mounts-only (complete
        // on its own; the LSM leg is additive for this backend).
        if sb.sandboxed && landlock_ok {
            sb.landlock_apply = landlock_apply_path.map(str::to_string);
        }
        // The applier's "box is up" byte: the fd must survive the exec into
        // bwrap and on into the box (bwrap passes inherited fds through).
        if let (true, Some(fd)) = (sb.landlock_apply.is_some(), ready_fd) {
            // SAFETY: clearing FD_CLOEXEC on our own inherited descriptor.
            if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } == 0 {
                sb.ready_fd = Some(fd);
            }
        }
        // Hide the host's Unix sockets and, on WSL, the interop door.
        if sb.sandboxed {
            sb.host_hide = host_hide.clone();
        }
        // The CLEAN posture: same mounts, same seccomp — the applier renders in
        // clean mode (reads ⊆ the verified roots, AgentView write-only). Never
        // without an applier: the clean guarantee IS the LSM restriction.
        if sb.sandboxed && sb.landlock_apply.is_some() {
            if let Some(reads) = clean_read_paths {
                sb.landlock_clean = true;
                sb.landlock_read_paths = reads.to_vec();
                // Never the agent's real /tmp in a clean attempt
                // (`SandboxPlan::fresh_scratch`): its RW scratch grant would
                // read what the agent wrote there.
                sb.fresh_scratch();
            }
        }
        // AgentShell (sandboxed) ONLY: install the seccomp deny-filter fd and
        // thread it into the bwrap argv. FAIL-CLOSED — if we cannot create the
        // filter fd we must NOT exec an un-filtered sandbox, so we return the
        // setup-failure code rather than a weaker box. HumanShell (passthrough)
        // is the unrestricted view and gets no filter.
        // The socket allow-list (§4.2): the box's own listener, the guard,
        // or nobody, in which case the deny-filter refuses every connect.
        let deny_connect = match (sb.sandboxed, sockets) {
            (false, _) | (_, ChildSockets::Off) => false,
            (true, ChildSockets::Deny) => true,
            (true, ChildSockets::Try(plan, handoff)) => {
                if let Some(hook) = before_handoff {
                    hook();
                }
                match crate::socket_supervision::child_side(plan, handoff) {
                    Ok(deny) => deny,
                    Err(()) => return 71,
                }
            }
        };
        if sb.sandboxed && !matches!(sockets, ChildSockets::Off) {
            drop_inherited_unix_datagrams();
        }
        if sb.sandboxed {
            match install_seccomp_filter_fd(sb.seccomp_deny_userns, deny_connect) {
                Some(fd) => sb.seccomp_fd = Some(fd),
                None => return 71,
            }
        }
        match bwrap_argv(&sb, &plan.argv) {
            // AgentShell → exec `bwrap … -- <argv>`; bwrap builds the world,
            // by the parent-resolved path (never a PATH search).
            Some(mut argv) => {
                let Some(bin) = bwrap_bin else {
                    let m = crate::sandbox::NO_BWRAP_MESSAGE;
                    unsafe { libc::write(2, m.as_ptr().cast(), m.len()) };
                    return 126;
                };
                argv[0] = bin.to_string();
                return exec_argv(&argv);
            }
            // Passthrough (HumanShell): chdir + exec the argv directly.
            None => {
                if let Some(cwd) = cwd {
                    if let Ok(c) = CString::new(cwd) {
                        if unsafe { libc::chdir(c.as_ptr()) } != 0 {
                            return 71;
                        }
                    }
                }
                return exec_argv(&plan.argv);
            }
        }
    }

    // ── Network side (legacy in-process backend) ─────────────────────────
    if spec.net_disabled {
        // Enter a fresh network namespace. A new netns starts with ONLY the
        // loopback device, and it is DOWN — so every connect() to a non-loopback
        // address fails (egress is dead). We deliberately do NOT create a veth or
        // bring lo up: AgentShell is net-OFF by design.
        if unsafe { libc::unshare(CLONE_NEWNET) } != 0 {
            return 71;
        }
    }

    // ── Filesystem side ──────────────────────────────────────────────────
    if spec.fs_agent_view {
        if let (Some(av), Some(ws)) = (&view.agent_view_root, &view.workspace) {
            // Private mount namespace so the bind-mount never escapes to the host
            // mount table, then bind the AgentView worktree over the workspace.
            if unsafe { libc::unshare(CLONE_NEWNS) } != 0 {
                return 71;
            }
            // Make the new mount ns's propagation private (so MS_BIND below does
            // not propagate back to the host peer group).
            let root = CString::new("/").unwrap();
            let none = CString::new("none").unwrap();
            let rc = unsafe {
                libc::mount(
                    std::ptr::null(),
                    root.as_ptr(),
                    none.as_ptr(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                )
            };
            if rc != 0 {
                return 71;
            }
            let src = match CString::new(av.as_str()) {
                Ok(s) => s,
                Err(_) => return 71,
            };
            let dst = match CString::new(ws.as_str()) {
                Ok(s) => s,
                Err(_) => return 71,
            };
            let rc = unsafe {
                libc::mount(
                    src.as_ptr(),
                    dst.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND | libc::MS_REC,
                    std::ptr::null(),
                )
            };
            if rc != 0 {
                return 71;
            }
        }
    }

    // ── cwd ──────────────────────────────────────────────────────────────
    // chdir into the (possibly bind-mounted) cwd if the request named one. After
    // an AgentShell bind-mount this lands inside the AgentView worktree.
    if let Some(cwd) = cwd {
        if let Ok(c) = CString::new(cwd) {
            // A hard chdir error is a setup failure: we must not silently exec in
            // a wider directory than the plan intended.
            if unsafe { libc::chdir(c.as_ptr()) } != 0 {
                return 71;
            }
        }
    }

    // ── Landlock (InProcess AgentShell) ──────────────────────────────────
    // The legacy backend's ONLY RO-outside-AgentView enforcement: restrict this
    // child to the asymmetric overlay (RO /, RW = the bound workspace + the
    // AgentView's own path + /tmp, WRITE_FILE on /dev, TCP denied on ABI ≥ 4)
    // just before execve — mounts
    // are done, so the no-mount-once-restricted rule is satisfied. MUST run
    // after the bind above (the RW rule opens the WORKSPACE path, which now IS
    // the AgentView). FAIL-CLOSED on a supporting kernel: a restrict error
    // aborts the exec — running unrestricted would silently drop the layer the
    // parent's probe promised. Residual (documented): the RW /tmp here is the
    // REAL /tmp (no tmpfs in this backend), so scratch staging remains — the
    // default Bubblewrap backend masks it with a fresh tmpfs.
    if landlock_ok && plan.shell == ExecShell::AgentShell {
        use fs_supervisor::landlock::{
            landlock_abi_version, plan_landlock_deny_tcp, restrict_self_to_plan, DEV,
            LANDLOCK_ACCESS_FS_WRITE_FILE, RO_ROOT, SCRATCH,
        };
        let mut rw: Vec<String> = Vec::new();
        if let (Some(av), Some(ws)) = (&view.agent_view_root, &view.workspace) {
            rw.push(ws.clone());
            // The AgentView at its OWN path too (parity with the bwrap
            // backend, whose applier --rw list derives from the plan's bind
            // dsts): fs-view cwd's the agent into the AgentView real path, so
            // a boxed command's own cwd must stay writable. av == ws deduped.
            if av != ws {
                rw.push(av.clone());
            }
        }
        // No AgentView: the workspace itself when the launcher asked for it
        // (parity with the bwrap backend's real-tree bind, sandbox.rs
        // `writable_workspace`).
        if let Some(ws) = crate::sandbox::writable_workspace(view, &[SCRATCH.to_string()]) {
            rw.push(ws.to_string());
        }
        rw.push(SCRATCH.to_string());
        let abi = landlock_abi_version();
        if abi < 1 {
            // The parent probed supported; a child-side disagreement is an
            // anomaly, not a degrade.
            return 71;
        }
        let ll = plan_landlock_deny_tcp(RO_ROOT, &rw, abi as u32)
            .allow_path(DEV, LANDLOCK_ACCESS_FS_WRITE_FILE);
        if restrict_self_to_plan(&ll).is_err() {
            return 71;
        }
    }

    // ── exec the planned argv ────────────────────────────────────────────
    // AgentShell: the symbolic argv unchanged. HumanShell: the resolved argv.
    // (Approvals were already cleared by the parent before fork.)
    exec_argv(&plan.argv)
}

/// The fixed fd the AgentShell seccomp filter is placed on. A FIXED, predictable
/// number the plan can name (`--seccomp <fd>`); high enough to avoid clobbering
/// std{in,out,err} and the usual low fds.
const SECCOMP_FILTER_FD: RawFd = 10;

/// Create the seccomp deny-filter fd for an AgentShell bubblewrap sandbox.
/// `deny_userns` MUST mirror the plan's `seccomp_deny_userns`: when the probed
/// bwrap lacks `--disable-userns`, the filter is the ONLY userns-nesting
/// denial, so building the base filter here would silently reopen the hole.
///
/// SECURITY REASON. bwrap installs the filter from an fd it reads the raw
/// `struct sock_filter[]` program off of; we build that program PURELY
/// (`seccomp_filter::agentshell_seccomp_filter_with`) so the deny-list is
/// reviewable with no privileges, then materialize it here as a runtime fd. The
/// fd must survive the `execvp` of bwrap, so it is placed on a FIXED,
/// **non-CLOEXEC** fd.
///
/// Returns `None` on ANY failure (or an unsupported arch, where the pure builder
/// yields no filter). The caller treats `None` as fail-closed: it declines to run
/// an un-filtered AgentShell sandbox.
fn install_seccomp_filter_fd(deny_userns: bool, deny_connect: bool) -> Option<RawFd> {
    let filter = crate::seccomp_filter::agentshell_seccomp_filter_opts(deny_userns, deny_connect);
    if filter.is_empty() {
        // No filter (unsupported arch) → fail closed rather than run unfiltered.
        return None;
    }

    // An anonymous in-memory file (kernel ≥ 3.17): no tmp path, auto-freed on
    // close. flags=0 → NOT close-on-exec, so it survives bwrap's execvp.
    let name = CString::new("mandu-seccomp").ok()?;
    let memfd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
    if memfd < 0 {
        return None;
    }

    // Write the whole program, handling short writes.
    let mut off = 0usize;
    while off < filter.len() {
        let n = unsafe {
            libc::write(
                memfd,
                filter[off..].as_ptr() as *const libc::c_void,
                filter.len() - off,
            )
        };
        if n <= 0 {
            unsafe { libc::close(memfd) };
            return None;
        }
        off += n as usize;
    }

    // Rewind so bwrap reads the program from the start.
    if unsafe { libc::lseek(memfd, 0, libc::SEEK_SET) } < 0 {
        unsafe { libc::close(memfd) };
        return None;
    }

    // Move it to the FIXED fd (dup2 both closes any prior occupant and clears
    // CLOEXEC on the new fd, so it survives execvp). If memfd already landed on
    // the target, keep it.
    if memfd != SECCOMP_FILTER_FD {
        if unsafe { libc::dup2(memfd, SECCOMP_FILTER_FD) } < 0 {
            unsafe { libc::close(memfd) };
            return None;
        }
        unsafe { libc::close(memfd) };
    }
    Some(SECCOMP_FILTER_FD)
}

/// `execvp` the argv. Only returns on failure (returns exit code 126). Public
/// so the `mandu-landlock-apply` bin shares the one exec + exit-code path.
pub fn exec_argv(argv: &[String]) -> i32 {
    if argv.is_empty() {
        return 126;
    }
    let cargs: std::result::Result<Vec<CString>, _> =
        argv.iter().map(|s| CString::new(s.as_str())).collect();
    let cargs = match cargs {
        Ok(v) => v,
        Err(_) => return 126,
    };
    // Build the NULL-terminated *char[] for execvp.
    let mut ptrs: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // execvp searches PATH for argv[0]. On success it does not return.
    unsafe {
        libc::execvp(cargs[0].as_ptr(), ptrs.as_ptr());
    }
    // Only reached if execvp failed. Say why on stderr: a bare 126 hides the
    // errno (ENOENT, EACCES, ETXTBSY), which is what made the routing test's
    // ETXTBSY flake undiagnosable from its log (exec-routing.md §6).
    let msg = exec_failure_message(&std::io::Error::last_os_error());
    unsafe { libc::write(2, msg.as_ptr().cast(), msg.len()) };
    126
}

/// The one line `exec_argv` writes to stderr when `execvp` fails. The errno
/// only, never the argv: a HumanShell plan's argv is DESYMBOLIZED, and this
/// stderr is the command's, which reaches the agent as tool output.
fn exec_failure_message(err: &std::io::Error) -> String {
    format!("mandu: exec failed: {err}\n")
}

// ════════════════════════════════════════════════════════════════════════════
// ATTACH FRONT-END — seccomp-unotify execve trap (the BLOCK side).
// ════════════════════════════════════════════════════════════════════════════
//
// `supervise_exec` above is the fork-MODEL enforcement core: it OWNS the dispatch
// of an exec (plan → fork → namespace → exec) and can therefore inject the
// AgentShell namespaces (net off + AgentView FS) into the child it spawns. That
// model requires cooperation (the exec flows THROUGH the supervisor).
//
// This front-end is the complementary ATTACH path for an UNCOOPERATIVE, already-
// running process: a seccomp user-notification listener traps each `execve`/
// `execveat` the tracee attempts, decodes the argv + cwd out of the SUSPENDED
// tracee, decides via the SAME pure `plan_exec`, and ENFORCES:
//   - disallowed (approvals required / symbol-as-command / arbiter miss /
//     unsupported) → respond EPERM → the tracee's execve fails (the unsafe binary
//     never runs). Works on kernel ≥ 5.0 (no CONTINUE needed).
//   - allowed (a safe exec) → respond CONTINUE (kernel ≥ 5.5) so the kernel runs
//     the real execve unchanged.
//
// ── What this front-end CANNOT do (the honest boundary) ─────────────────────
// A seccomp user-notif response is one of {error, return-value, CONTINUE,
// ADDFD}. NONE of those can place the tracee into a fresh net/mount namespace:
// namespaces are set up by the process ITSELF (unshare/setns) BEFORE exec, and
// the front-end is merely watching from outside. So the front-end can BLOCK an
// unsafe exec (EPERM) or ALLOW a safe one (CONTINUE) — it CANNOT turn an
// allowed-but-needs-sandboxing exec into an AgentShell run. Re-sandboxing an
// allow IS the fork model's job (`supervise_exec`): the deployment that needs to
// *re-sandbox* (not merely block) routes the exec through the fork model. This
// front-end's role is the gate: deny what plan_exec says is disallowed.
//
// ── Kernel-version reality ──────────────────────────────────────────────────
//   - LISTENER (NEW_LISTENER) + NOTIF_RECV + process_vm_readv arg reads:  5.0+
//   - SECCOMP_USER_NOTIF_FLAG_CONTINUE (let the trapped syscall proceed):  5.5+
// On a 5.4 kernel the DENY path is fully exercisable (respond EPERM). The ALLOW
// path needs CONTINUE (≥ 5.5); on < 5.5 a seccomp front-end fundamentally cannot
// cleanly allow-through an execve (no CONTINUE, and ADDFD can't substitute a
// successful exec), so the allow-through needs a ≥ 5.5 kernel and the integration
// test self-SKIPs below that (this 6.8 host runs it live). `continue_supported()`
// gates this.

// ── seccomp ioctl request numbers (same derivation as fs-supervisor) ─────────
// libc ships the seccomp_notif* STRUCTS + the SECCOMP_* flag constants but NOT the
// SECCOMP_IOCTL_NOTIF_* ioctl request numbers. Derived from `linux/seccomp.h`:
//   SECCOMP_IOC_MAGIC '!' (0x21)
//   RECV     = _IOWR('!', 0, struct seccomp_notif)      = 0xc0502100 (size 0x50=80)
//   SEND     = _IOWR('!', 1, struct seccomp_notif_resp) = 0xc0182101 (size 0x18=24)
//   ID_VALID = _IOW ('!', 2, __u64)                     = 0x40082102 (size 0x08= 8)
// (ADDFD is not needed here — the front-end never injects an fd.)
pub const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc050_2100;
pub const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc018_2101;
pub const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = 0x4008_2102;

/// AUDIT_ARCH_* for the filter's architecture check (not exported by libc 0.2).
/// EM_X86_64=62 | __AUDIT_ARCH_64BIT(0x80000000) | __AUDIT_ARCH_LE(0x40000000).
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
/// EM_AARCH64=183 | 64BIT | LE.
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64

/// `AT_FDCWD` (execveat "use the cwd" sentinel for a relative dirfd).
const AT_FDCWD: i32 = libc::AT_FDCWD;

// ── kernel-version probe (mirrors fs-supervisor) ────────────────────────────

/// Coarse kernel-version probe: `(major, minor)` from `uname.release`.
pub fn kernel_version() -> (u32, u32) {
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return (0, 0);
    }
    let rel: Vec<u8> = uts
        .release
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    let rel = String::from_utf8_lossy(&rel);
    let mut it = rel.split(|c: char| c == '.' || c == '-');
    let major = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (major, minor)
}

/// True iff the running kernel is ≥ the given (major, minor).
pub fn kernel_at_least(major: u32, minor: u32) -> bool {
    let (km, kn) = kernel_version();
    (km, kn) >= (major, minor)
}

/// Is SECCOMP_USER_NOTIF_FLAG_CONTINUE (the ALLOW-through primitive) available?
/// AUTHORITATIVE GATE = kernel version ≥ 5.5 (when CONTINUE landed). The DENY path
/// (respond EPERM) works on 5.0+ and never consults this.
pub fn continue_supported() -> bool {
    kernel_at_least(5, 5)
}

// ── seccomp filter install (the "listener fd" side) ─────────────────────────

/// Install a seccomp filter trapping `execve`/`execveat` with
/// `SECCOMP_FILTER_FLAG_NEW_LISTENER`, returning the listener fd. The CALLER must
/// have already set `PR_SET_NO_NEW_PRIVS` (see `install_execve_filter_self`).
///
/// This is normally called IN THE TRACEE (the process to supervise), which then
/// hands the returned fd to the supervisor over a unix socket / inherits it. The
/// filter mirrors fs-supervisor's openat listener but keys on execve/execveat.
pub fn install_execve_listener() -> Result<RawFd> {
    // BPF offsets into struct seccomp_data: arch @ 4, nr @ 0.
    const ARCH_OFF: u32 = 4;
    const NR_OFF: u32 = 0;
    let execve = SYS_EXECVE as u32;
    let execveat = SYS_EXECVEAT as u32;

    let mut prog: Vec<libc::sock_filter> = Vec::new();
    let stmt = |code: u16, k: u32| libc::sock_filter { code, jt: 0, jf: 0, k };
    let jump = |code: u16, k: u32, jt: u8, jf: u8| libc::sock_filter { code, jt, jf, k };

    let bpf_ld = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    let bpf_jeq = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    let bpf_ret = (libc::BPF_RET | libc::BPF_K) as u16;

    // 1) Load arch; if != AUDIT_ARCH → KILL_PROCESS (a foreign-arch syscall would
    //    misread nr/args; defensive).
    prog.push(stmt(bpf_ld, ARCH_OFF));
    prog.push(jump(bpf_jeq, AUDIT_ARCH, 1, 0)); // arch ok → skip the kill
    prog.push(stmt(bpf_ret, libc::SECCOMP_RET_KILL_PROCESS));
    // 2) Load nr.
    prog.push(stmt(bpf_ld, NR_OFF));
    // 3) nr == execve → USER_NOTIF.
    prog.push(jump(bpf_jeq, execve, 0, 1)); // match → next; miss → skip next
    prog.push(stmt(bpf_ret, libc::SECCOMP_RET_USER_NOTIF));
    // 4) nr == execveat → USER_NOTIF (or the trap is bypassable via fexecve).
    prog.push(jump(bpf_jeq, execveat, 0, 1));
    prog.push(stmt(bpf_ret, libc::SECCOMP_RET_USER_NOTIF));
    // 5) default → ALLOW (every other syscall runs normally).
    prog.push(stmt(bpf_ret, libc::SECCOMP_RET_ALLOW));

    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_mut_ptr(),
    };

    // SAFETY: SYS_seccomp(SET_MODE_FILTER, NEW_LISTENER, &fprog). The kernel copies
    // the program in; `prog`/`fprog` outlive the call. Returns the listener fd.
    // Requires no_new_privs + CAP_SYS_ADMIN-in-userns.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &fprog as *const libc::sock_fprog,
        )
    };
    if fd < 0 {
        return Err(Error::last_os_error());
    }
    Ok(fd as RawFd)
}

/// Set `PR_SET_NO_NEW_PRIVS` on the current thread (prerequisite for an
/// unprivileged-in-userns seccomp filter install). Idempotent.
pub fn set_no_new_privs() -> Result<()> {
    // SAFETY: prctl with no pointer args; sets a thread flag.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

/// Convenience for the tracee side: no_new_privs + install the execve listener.
pub fn install_execve_filter_self() -> Result<RawFd> {
    set_no_new_privs()?;
    install_execve_listener()
}

// ── notification receive / respond ──────────────────────────────────────────

/// Receive one notification off the listener fd (blocking). Returns the raw
/// `seccomp_notif` (id/pid/flags/data). EINTR is surfaced to the caller.
pub fn notif_recv(listener_fd: RawFd) -> Result<libc::seccomp_notif> {
    let mut notif: libc::seccomp_notif = unsafe { std::mem::zeroed() };
    // SAFETY: ioctl writes a full seccomp_notif into our stack buffer.
    let rc = unsafe {
        libc::ioctl(
            listener_fd,
            SECCOMP_IOCTL_NOTIF_RECV as _,
            &mut notif as *mut libc::seccomp_notif,
        )
    };
    if rc != 0 {
        return Err(Error::last_os_error());
    }
    Ok(notif)
}

/// True iff this notification id is still valid (the tracee has not died /
/// been interrupted). Checked before responding to avoid acting on a stale id.
pub fn notif_id_valid(listener_fd: RawFd, id: u64) -> bool {
    // SAFETY: ID_VALID reads an __u64 by pointer; returns 0 if still valid.
    let rc = unsafe {
        libc::ioctl(
            listener_fd,
            SECCOMP_IOCTL_NOTIF_ID_VALID as _,
            &id as *const u64,
        )
    };
    rc == 0
}

fn notif_send(listener_fd: RawFd, resp: &libc::seccomp_notif_resp) -> Result<()> {
    // SAFETY: SEND reads a seccomp_notif_resp by pointer.
    let rc = unsafe {
        libc::ioctl(
            listener_fd,
            SECCOMP_IOCTL_NOTIF_SEND as _,
            resp as *const libc::seccomp_notif_resp,
        )
    };
    if rc != 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

/// DENY: make the trapped execve return `-errno` to the tracee — the real execve
/// is NOT run. This is the fail-closed answer; it works on kernel ≥ 5.0.
pub fn respond_errno(listener_fd: RawFd, id: u64, errno: i32) -> Result<()> {
    let resp = libc::seccomp_notif_resp {
        id,
        val: 0,
        error: -errno.abs(),
        flags: 0,
    };
    notif_send(listener_fd, &resp)
}

/// ALLOW: answer with SECCOMP_USER_NOTIF_FLAG_CONTINUE — the kernel runs the real
/// execve unchanged. Kernel ≥ 5.5 (on 5.4 the kernel rejects the flag).
pub fn respond_continue(listener_fd: RawFd, id: u64) -> Result<()> {
    let resp = libc::seccomp_notif_resp {
        id,
        val: 0,
        error: 0,
        flags: libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
    };
    notif_send(listener_fd, &resp)
}

// ── argv / cwd decode from the SUSPENDED tracee ─────────────────────────────
//
// While we hold the notification the tracee is SUSPENDED, so its address space,
// `/proc/<pid>/cwd`, and `/proc/<pid>/fd/<dirfd>` are STABLE — reading them is
// race-free (the tracee cannot mutate them under us). Mirrors fs-supervisor's
// process_vm_readv reads + /proc-link resolution.

/// Read up to `max` bytes from the tracee `pid`'s address space at `addr` into a
/// fresh buffer. One process_vm_readv window.
fn read_remote(pid: i32, addr: u64, max: usize) -> Result<Vec<u8>> {
    if addr == 0 {
        return Err(Error::new(ErrorKind::InvalidInput, "null remote pointer"));
    }
    let mut buf = vec![0u8; max];
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: buf.len(),
    };
    // SAFETY: `local` points at our owned `buf` of `iov_len` bytes; `remote` names
    // the tracee's address space. process_vm_readv copies up to the min of the two
    // iov lengths and never writes past `buf`.
    let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    if n < 0 {
        return Err(Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(buf)
}

/// Read a NUL-terminated C string the syscall pointed at, from the tracee. Bounded
/// (paths/args are PATH_MAX/ARG_MAX-bounded; one window covers any legal value).
fn read_remote_cstr(pid: i32, addr: u64) -> Result<String> {
    let buf = read_remote(pid, addr, 4096)?;
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Ok(String::from_utf8_lossy(&buf[..end]).into_owned())
}

/// The host pointer width — `char *argv[]` is an array of these in the tracee.
const PTR_BYTES: usize = std::mem::size_of::<usize>();

/// Decode the NULL-terminated `char *argv[]` pointer array at `argv_addr` in the
/// tracee, then each string it points at. Bounded by `MAX_ARGV` entries so a
/// hostile/garbage pointer array can't make us loop forever. An empty/NULL argv
/// yields an empty vec (the caller treats that as a malformed exec → DENY).
fn read_remote_argv(pid: i32, argv_addr: u64) -> Result<Vec<String>> {
    /// POSIX guarantees no fixed cap, but a real argv is small; bound defensively.
    const MAX_ARGV: usize = 4096;
    if argv_addr == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for i in 0..MAX_ARGV {
        let slot = argv_addr + (i * PTR_BYTES) as u64;
        // Read one pointer-sized slot of the argv array.
        let bytes = read_remote(pid, slot, PTR_BYTES)?;
        if bytes.len() < PTR_BYTES {
            break; // short read at the array's edge → stop
        }
        let mut p = [0u8; PTR_BYTES];
        p.copy_from_slice(&bytes[..PTR_BYTES]);
        let ptr = usize::from_ne_bytes(p) as u64;
        if ptr == 0 {
            break; // the NULL terminator of the argv array
        }
        out.push(read_remote_cstr(pid, ptr)?);
    }
    Ok(out)
}

/// Read the TRACEE's cwd via `/proc/<pid>/cwd` (a realpath symlink). The tracee is
/// suspended → the link is stable. `None` if it can't be read or is non-absolute
/// (we never fabricate a cwd).
fn read_tracee_cwd(pid: i32) -> Option<String> {
    read_proc_link(pid, "cwd")
}

/// Read a `/proc/<pid>/<suffix>` symlink (cwd or fd/<n>) for the TRACEE → the
/// absolute path it points at. `None` if readlink fails, the target is non-UTF-8,
/// or it is not absolute (e.g. an `anon_inode:`/pipe/socket dirfd). Plain
/// readlink(2) — no openat. (Mirror of fs-supervisor::read_proc_link.)
fn read_proc_link(pid: i32, suffix: &str) -> Option<String> {
    let link = format!("/proc/{pid}/{suffix}\0");
    let mut buf = [0u8; 4096];
    // SAFETY: `link` is NUL-terminated; `buf` is a valid writable region of len().
    let n = unsafe {
        libc::readlink(
            link.as_ptr() as *const libc::c_char,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
        )
    };
    if n <= 0 {
        return None;
    }
    let target = std::str::from_utf8(&buf[..n as usize]).ok()?;
    if !target.starts_with('/') {
        return None;
    }
    Some(target.to_string())
}

/// Decode a trapped execve/execveat notification into an `ExecRequest`.
///
/// execve(pathname, argv, envp):        args[0]=pathname, args[1]=argv, args[2]=envp
/// execveat(dirfd,pathname,argv,envp,fl): args[0]=dirfd, args[1]=pathname,
///                                        args[2]=argv,  args[3]=envp, args[4]=flags
///
/// For execveat we factor the dirfd into the FIRST argv element so the plan sees
/// the real program identity (argv[0] from the caller is by convention the program
/// name, but the EXECUTED file is `pathname` resolved against `dirfd`). We surface
/// the resolved program as argv[0] when the caller passed an empty argv[0], so
/// `plan_exec`'s basename classification keys on the real target.
fn decode_exec_request(notif: &libc::seccomp_notif) -> Result<ExecRequest> {
    let pid = notif.pid as i32;
    let nr = notif.data.nr as libc::c_long;

    // Pick the argv pointer slot per syscall.
    let (pathname_addr, argv_addr, dirfd, flags): (u64, u64, Option<i32>, i32) = if nr == SYS_EXECVEAT
    {
        (
            notif.data.args[1],
            notif.data.args[2],
            Some(notif.data.args[0] as i32),
            notif.data.args[4] as i32,
        )
    } else {
        // SYS_EXECVE (and any other trapped nr defaults to execve layout).
        (notif.data.args[0], notif.data.args[1], None, 0)
    };

    let mut argv = read_remote_argv(pid, argv_addr)?;

    // Resolve the EXECUTED program path so plan_exec classifies on the real target,
    // not just argv[0] (which the caller controls). For execveat with AT_EMPTY_PATH
    // the file is the dirfd itself; otherwise it is `pathname` (relative → resolved
    // against dirfd / cwd lexically — symlink resolution out of scope, same posture
    // as fs-supervisor). We keep the caller's argv but ensure argv[0] names the
    // executed file when the caller left it empty.
    let pathname = if pathname_addr != 0 {
        read_remote_cstr(pid, pathname_addr).ok()
    } else {
        None
    };
    let executed = resolve_executed_path(pid, dirfd, pathname.as_deref(), flags);
    if let Some(prog) = executed {
        match argv.first() {
            Some(a0) if !a0.is_empty() => { /* keep the caller's argv[0] */ }
            _ => {
                // Empty or absent argv[0] → put the executed program in front so the
                // classifier has the real identity.
                if argv.is_empty() {
                    argv.push(prog);
                } else {
                    argv[0] = prog;
                }
            }
        }
    }

    let cwd = read_tracee_cwd(pid);

    Ok(ExecRequest {
        argv,
        cwd,
        // The front-end does not infer net/FS resource hints from the trapped
        // syscall (it sees only the execve args); leave them unset so classifyExec
        // decides purely on argv/cwd/params. A richer attach could fill these.
        needs_network: false,
        needs_original_fs: false,
        params: None,
        escalation: Default::default(),
    })
}

/// Resolve the file an execve/execveat actually executes, as an absolute (lexical)
/// path string where possible — for the classifier's basename. NO symlink
/// resolution (documented caveat, matching fs-supervisor). Returns `None` if it
/// can't be resolved (the caller then falls back to the caller-provided argv[0]).
fn resolve_executed_path(pid: i32, dirfd: Option<i32>, pathname: Option<&str>, flags: i32) -> Option<String> {
    const AT_EMPTY_PATH: i32 = 0x1000; // not always in libc 0.2; pin the value.
    match (dirfd, pathname) {
        // execveat with AT_EMPTY_PATH (or empty pathname): the file IS the dirfd.
        (Some(fd), p) if (flags & AT_EMPTY_PATH) != 0 || p.map(|s| s.is_empty()).unwrap_or(true) => {
            read_proc_link(pid, &format!("fd/{fd}"))
        }
        // Absolute pathname: dirfd irrelevant (POSIX).
        (_, Some(p)) if p.starts_with('/') => Some(p.to_string()),
        // Relative pathname + AT_FDCWD (or plain execve): resolve against cwd.
        (None, Some(p)) | (Some(AT_FDCWD), Some(p)) => {
            let base = read_tracee_cwd(pid)?;
            Some(format!("{}/{}", base.trim_end_matches('/'), p))
        }
        // Relative pathname + a real dirfd: resolve against that dir.
        (Some(fd), Some(p)) => {
            let base = read_proc_link(pid, &format!("fd/{fd}"))?;
            Some(format!("{}/{}", base.trim_end_matches('/'), p))
        }
        _ => None,
    }
}

/// TEST HELPER: decode just the `argv` array from a trapped execve/execveat
/// notification, exactly as the front-end reads it (process_vm_readv of the
/// argv-pointer array). Exposed so the privileged integration test can assert the
/// supervisor read the RIGHT program + args off the SUSPENDED tracee, BEFORE the
/// notification is answered. Returns the caller's argv as-is (no executed-path
/// fix-up — that fix-up only fills an empty argv[0]).
pub fn decode_argv_for_test(notif: &libc::seccomp_notif) -> Vec<String> {
    let pid = notif.pid as i32;
    let nr = notif.data.nr as libc::c_long;
    // execve: argv = args[1]; execveat: argv = args[2].
    let argv_addr = if nr == SYS_EXECVEAT {
        notif.data.args[2]
    } else {
        notif.data.args[1]
    };
    read_remote_argv(pid, argv_addr).unwrap_or_default()
}

/// The decision the front-end will enact for one trapped execve, surfaced so the
/// integration test can assert the route + the decoded request without scraping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrontEndAction {
    /// DENY — responded EPERM; the tracee's execve fails (the binary never runs).
    Denied { reason: String },
    /// ALLOW — responded CONTINUE; the kernel ran the real execve. (≥ 5.5 only.)
    Continued,
    /// ALLOW was the decision, but CONTINUE is unavailable (< 5.5): we cannot
    /// cleanly let the execve through, so we DENIED with EPERM as the fail-closed
    /// fallback and recorded that the allow-through is deferred to ≥ 5.5.
    ContinueUnavailableDenied,
}

/// Decide a decoded `ExecRequest` via the PURE `plan_exec` (reused — never
/// reimplemented) and map it to a front-end action. FAIL-CLOSED: an empty argv,
/// an AgentShell requirement that the front-end CANNOT sandbox, a needs-approval
/// HumanShell, or a arbiter miss all map to DENY.
///
/// The semantics the front-end can honestly enforce:
///   - HumanShell, no approvals needed → the exec is allowed to run as-is →
///     ALLOW (CONTINUE). (resolveExecArgv already desymbolized argv in the plan;
///     the front-end can't rewrite the tracee's argv, but a no-approval HumanShell
///     plan means argv had no command-position symbols, so the tracee's own argv
///     is already safe to run.)
///   - HumanShell needing approval (symbol-as-command) → DENY (EPERM).
///   - AgentShell → the safe view requires the net-off + AgentView-FS sandbox the
///     front-end CANNOT inject (only the fork model can). So a seccomp front-end
///     DENIES an AgentShell exec rather than letting an un-sandboxed, allegedly-
///     "safe" exec run with full network + HumanView FS. (Re-sandboxing routes
///     through `supervise_exec`.) This is the fail-closed default.
fn decide_front_end(client: &mut ArbiterClient, req: &ExecRequest) -> FrontEndAction {
    if req.argv.is_empty() {
        return FrontEndAction::Denied {
            reason: "empty/undecodable argv → fail-closed DENY".into(),
        };
    }
    let plan = plan_exec(client, req);

    // A arbiter miss fails closed to AgentShell inside plan_exec; either way an
    // AgentShell plan needs the sandbox we can't inject → DENY.
    if plan.shell == ExecShell::AgentShell {
        return FrontEndAction::Denied {
            reason: format!(
                "AgentShell requires net-off + AgentView sandbox a seccomp front-end \
                 cannot inject → DENY (route through the fork model to re-sandbox): {}",
                plan.reason
            ),
        };
    }

    // HumanShell with withheld approvals (symbol-as-command) → DENY.
    if plan.needs_approval() {
        return FrontEndAction::Denied {
            reason: format!("HumanShell approval withheld (symbol-as-command) → DENY: {}", plan.reason),
        };
    }

    // HumanShell, no approvals → safe to run as-is. ALLOW via CONTINUE if the
    // kernel supports it; otherwise we cannot cleanly allow-through → fail closed.
    if continue_supported() {
        FrontEndAction::Continued
    } else {
        FrontEndAction::ContinueUnavailableDenied
    }
}

/// Handle exactly ONE already-received notification: decode the execve, decide via
/// `plan_exec`, and enact the kernel answer. Factored out of `run_supervisor` so
/// the integration test can drive a single trapped execve deterministically.
///
/// FAIL-CLOSED everywhere: a decode error, a arbiter error (handled inside
/// `decide_front_end`/`plan_exec`), or an unsupported allow → DENY (EPERM).
pub fn handle_exec_notif(
    listener_fd: RawFd,
    client: &mut ArbiterClient,
    notif: &libc::seccomp_notif,
) -> Result<FrontEndAction> {
    // Decode the trapped execve. A decode FAILURE is fail-closed → DENY EPERM.
    let action = match decode_exec_request(notif) {
        Ok(req) => decide_front_end(client, &req),
        Err(e) => FrontEndAction::Denied {
            reason: format!("could not decode execve args ({e}) → fail-closed DENY"),
        },
    };

    // Enact. Guard each response on id-validity (the tracee may have died while we
    // talked to the arbiter); a dead id needs no response.
    match &action {
        FrontEndAction::Continued => {
            if notif_id_valid(listener_fd, notif.id) {
                respond_continue(listener_fd, notif.id)?;
            }
        }
        FrontEndAction::Denied { .. } | FrontEndAction::ContinueUnavailableDenied => {
            if notif_id_valid(listener_fd, notif.id) {
                respond_errno(listener_fd, notif.id, libc::EPERM)?;
            }
        }
    }
    Ok(action)
}

/// Run the seccomp-unotify supervisor loop on `listener_fd`. Owns the listener and
/// loops: NOTIF_RECV → decode execve → `plan_exec` → DENY (EPERM) / ALLOW
/// (CONTINUE). This is the ATTACH front-end for an uncooperative process; the
/// fork-model `supervise_exec` is the cooperative re-sandboxing core.
///
/// Runs until no task uses the filter any more, the normal termination: the
/// listener polls `POLLHUP` (kernel ≥ 5.8), or RECV returns ENOENT/EBADF.
/// RECV alone does not see the end on every kernel: a 7.0 kernel answers
/// ENOENT once the last user is gone, but the CI guest's (6.8) leaves the
/// receive asleep for good, also one begun after the last tracee exited
/// (exec-routing.md §4.4; kernel test
/// `the_notification_loop_ends_when_its_tracee_is_gone`). So each receive
/// waits for the listener to poll readable first. A failure handling ONE
/// notification is logged best-effort and does not kill the loop (one bad
/// exec can't wedge the supervisor).
pub fn run_supervisor(listener_fd: i32, client: &mut ArbiterClient) -> Result<()> {
    if listener_fd < 0 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "run_supervisor: invalid listener fd",
        ));
    }
    loop {
        let mut p = libc::pollfd { fd: listener_fd, events: libc::POLLIN, revents: 0 };
        // SAFETY: poll one descriptor we own.
        let rc = unsafe { libc::poll(&mut p, 1, -1) };
        if rc < 0 {
            let e = Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        if p.revents & libc::POLLIN == 0 && p.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            // No task uses the filter any more: nothing will ever arrive.
            return Ok(());
        }
        match notif_recv(listener_fd) {
            Ok(notif) => {
                let _ = handle_exec_notif(listener_fd, client, &notif);
            }
            Err(e) => match e.raw_os_error() {
                Some(libc::EINTR) => continue,
                // No more notifications / tracee gone → normal shutdown.
                Some(libc::ENOENT) | Some(libc::EBADF) => return Ok(()),
                _ => return Err(e),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioctl_numbers_match_canonical_seccomp_h() {
        // The published SECCOMP_IOCTL_NOTIF_* values + the struct sizes the _IO*
        // encoding depends on. Guards the hard-coded ioctl numbers against a libc
        // struct-layout change.
        assert_eq!(std::mem::size_of::<libc::seccomp_notif>(), 0x50);
        assert_eq!(std::mem::size_of::<libc::seccomp_notif_resp>(), 0x18);
        assert_eq!(SECCOMP_IOCTL_NOTIF_RECV, 0xc050_2100);
        assert_eq!(SECCOMP_IOCTL_NOTIF_SEND, 0xc018_2101);
        assert_eq!(SECCOMP_IOCTL_NOTIF_ID_VALID, 0x4008_2102);
    }

    #[test]
    fn kernel_version_parses() {
        let (maj, _min) = kernel_version();
        assert!(maj >= 3, "unexpected kernel major {maj}");
    }

    #[test]
    fn bwrap_help_supports_is_token_exact() {
        // bwrap 0.6-style help: no --disable-userns line at all.
        let help_06 = "usage: bwrap [OPTIONS...] [--] COMMAND [ARGS...]\n\
                       \x20   --unshare-user               Create new user namespace\n\
                       \x20   --cap-drop CAP               Drop cap CAP when running as privileged user\n\
                       \x20   --new-session                Create a new terminal session\n";
        assert!(!bwrap_help_supports(help_06, "--disable-userns"));
        assert!(bwrap_help_supports(help_06, "--new-session"));
        // bwrap 0.8-style help advertises the flag as its own token.
        let help_08 = "usage: bwrap [OPTIONS...] [--] COMMAND [ARGS...]\n\
                       \x20   --disable-userns             Disable further use of user namespaces inside sandbox\n\
                       \x20   --assert-userns-disabled     Fail unless further use of user namespace inside sandbox is disabled\n";
        assert!(bwrap_help_supports(help_08, "--disable-userns"));
        // Token-exact: a flag that merely embeds the queried name never counts.
        assert!(!bwrap_help_supports(
            "    --disable-userns-extra       something else\n",
            "--disable-userns"
        ));
        assert!(!bwrap_help_supports("", "--disable-userns"));
    }

    #[test]
    fn a_failed_exec_names_its_errno_but_never_the_argv() {
        // In a forked child with stderr on a pipe: exec a path that cannot
        // exist; the child exits 126 and its stderr names the errno.
        let argv0 = "/nonexistent/mandu-exec-argv-SECRET-ARG".to_string();
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let argv = vec![argv0.clone(), "x".into()];
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                libc::dup2(fds[1], 2);
                libc::_exit(exec_argv(&argv));
            }
        }
        unsafe { libc::close(fds[1]) };
        let mut out = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            let n = unsafe { libc::read(fds[0], buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
            out.extend_from_slice(&buf[..n as usize]);
        }
        unsafe { libc::close(fds[0]) };
        let mut st = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut st, 0) }, pid);
        assert!(libc::WIFEXITED(st));
        assert_eq!(libc::WEXITSTATUS(st), 126);
        let err = String::from_utf8_lossy(&out);
        assert!(err.contains("mandu: exec failed"), "stderr: {err}");
        assert!(err.contains("No such file or directory"), "the errno, named: {err}");
        assert!(!err.contains("SECRET-ARG"), "the (desymbolized) argv never reaches stderr: {err}");
        assert_eq!(
            exec_failure_message(&std::io::Error::from_raw_os_error(libc::ETXTBSY)),
            "mandu: exec failed: Text file busy (os error 26)\n"
        );
    }

    /// exec-routing.md §4.4: the clean attempt's capture pipes never outlive
    /// an exec, so a process another thread spawns while they exist cannot
    /// hold them open past the box's exit (pipeline #11899).
    #[test]
    fn the_clean_capture_pipes_are_close_on_exec() {
        let (r, w) = capture_pipe().expect("pipe2");
        for fd in [r, w] {
            // SAFETY: F_GETFD on a descriptor we own.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(flags >= 0, "F_GETFD on {fd}");
            assert_ne!(flags & libc::FD_CLOEXEC, 0, "fd {fd} must be close-on-exec");
        }
        unsafe {
            libc::close(r);
            libc::close(w);
        }
    }

    /// A child whose stdout/stderr are two fresh pipes; `body` runs in it
    /// (async-signal-safe calls only) and its return is the exit code.
    fn drain_child(body: fn(RawFd, RawFd) -> i32) -> (i32, RawFd, RawFd) {
        let (mut o, mut e) = ([0; 2], [0; 2]);
        assert_eq!(unsafe { libc::pipe2(o.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        assert_eq!(unsafe { libc::pipe2(e.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                libc::close(o[0]);
                libc::close(e[0]);
                libc::_exit(body(o[1], e[1]));
            }
        }
        unsafe {
            libc::close(o[1]);
            libc::close(e[1]);
        }
        (pid, o[0], e[0])
    }

    /// exec-routing.md §4.4: the clean attempt's drain ends however its pipes
    /// are held. Whole when the child writes and exits; void (the attempt
    /// falls back) when a process the child left keeps a pipe open after the
    /// child exited, instead of waiting for it for good; timed out at the
    /// caller's deadline while the child itself runs on.
    #[test]
    fn the_clean_drain_ends_when_its_pipes_outlive_the_child_or_the_deadline_passes() {
        use std::time::Instant;
        let unbounded = Deadline::after(None);
        // Whole.
        let (pid, o, e) = drain_child(|o, _| {
            unsafe { libc::write(o, b"out".as_ptr().cast(), 3) };
            0
        });
        assert_eq!(drain_two_capped(o, e, pid, unbounded, DRAIN_GRACE), Drained::Whole(b"out".to_vec(), Vec::new()));
        kill_tree_and_reap(pid);
        unsafe {
            libc::close(o);
            libc::close(e);
        }
        // A grandchild keeps stdout open past the child's exit.
        let (pid, o, e) = drain_child(|_, _| {
            if unsafe { libc::fork() } == 0 {
                // Long enough to outlast the grace, short enough to leave
                // no orphan behind for long.
                unsafe {
                    libc::sleep(4);
                    libc::_exit(0);
                }
            }
            0
        });
        let t0 = Instant::now();
        assert_eq!(drain_two_capped(o, e, pid, unbounded, Duration::from_millis(300)), Drained::Void);
        assert!(t0.elapsed() < Duration::from_secs(10), "it gave up near the grace: {:?}", t0.elapsed());
        kill_tree_and_reap(pid);
        unsafe {
            libc::close(o);
            libc::close(e);
        }
        // The child runs on: the caller's deadline.
        let (pid, o, e) = drain_child(|_, _| {
            unsafe { libc::sleep(20) };
            0
        });
        let t0 = Instant::now();
        assert_eq!(drain_two_capped(o, e, pid, Deadline::after(Some(Duration::from_millis(300))), DRAIN_GRACE), Drained::TimedOut);
        assert!(t0.elapsed() < Duration::from_secs(10));
        kill_tree_and_reap(pid);
        unsafe {
            libc::close(o);
            libc::close(e);
        }
    }

    #[test]
    fn ptr_width_is_eight_on_64bit() {
        // The argv-array stride is the host pointer width; on the 64-bit targets we
        // support this is 8. (Guards read_remote_argv's slot stride.)
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        assert_eq!(PTR_BYTES, 8);
    }
}
