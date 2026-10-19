//! mandu-exec-box — the production entry point into the fork-model exec sandbox
//! (kernel feature). A launcher shim execs `mandu-exec-box -- <argv...>`; this
//! bin classifies the command via the arbiter and runs it in the right world:
//!   - AgentShell (default, safe): inside the bubblewrap box — net off,
//!     RO-outside-AgentView, the seccomp deny-filter, and the Landlock leg.
//!   - HumanShell (a command that needs real network / the original FS, or a
//!     symbol used as a command): passthrough / gated, exactly as `supervise_exec`
//!     decides.
//! Until now `supervise_exec` had NO production caller (only #[ignore] tests); this
//! is the thin CLI that makes AgentShell routing live for a real session.
//!
//! ── Safe degrade (the launcher opts in; this bin must not wedge a live session) ──
//! The arbiter's classifyExec defaults a command to the net-off AgentShell unless
//! the caller HINTS that it needs network / the original FS. A generic shell shim
//! cannot know that per-command, so this bin infers `needs_network` from the
//! program name (`orchestrate::argv_needs_network`, a conservative utility list:
//! curl/git/npm/… route to HumanShell so they never silently run net-dead). An
//! explicit `--needs-network` / `--needs-original-fs` overrides the inference, and
//! `--no-needs-network` forces the box. Fail-closed stays fail-closed: an arbiter
//! miss defaults to AgentShell inside `plan_exec`, and a withheld approval
//! (symbol-as-command) BLOCKS with exit 77 rather than desymbolizing.
//!
//! ── Env / config (all optional except the socket) ──────────────────────────────
//!   MANDU_ARBITER_SOCK        the arbiter Unix socket (REQUIRED — no gate, no run)
//!   MANDU_AGENTVIEW_ROOT      absolute path of the AgentView worktree (RW bind)
//!   MANDU_WORKSPACE           absolute path the AgentView is bound over
//!   MANDU_EXEC_BOX_WORKSPACE_RW  "1" → with NO AgentView root, bind the
//!                               workspace WRITABLE at its own path (the
//!                               launcher bakes it when the integrity axis is
//!                               OFF; exec-routing.md §7.2, "The workspace
//!                               without an AgentView")
//!   MANDU_LANDLOCK_APPLY      path of the mandu-landlock-apply bin (LSM leg)
//!   MANDU_EXEC_BOX_BACKEND    "bubblewrap" (default) | "inprocess"
//!   MANDU_EXEC_CLEAN_BOX      truthy (non-empty, not "0") → attempt each
//!                               AgentShell exec in the CLEAN box first (the
//!                               bin's own default is OFF; the launcher's
//!                               exec-box shims bake "1" by default since
//!                               2026-09-04 — exec-routing.md §8.5.1)
//!                               (exec-routing.md §8.4 rung 2): reads only
//!                               under system roots, AgentView write-only,
//!                               stdout captured + hash-reported so the arbiter
//!                               can upgrade the tool_result; a failed attempt
//!                               falls back to the ordinary box. OFF by default
//!                               (a posture cell, not a new default).
//!   MANDU_EXEC_CLEAN_SOCK     the session guard's clean-run socket
//!                               (exec-routing.md §8.5.3): with it, the
//!                               clean attempt is ASKED of the guard, which
//!                               runs it outside the agent's process tree and
//!                               reports the verdict itself; this process only
//!                               forwards the bytes. Unreachable guard or void
//!                               attempt → the ordinary box.
//!   MANDU_BWRAP_DISABLE_USERNS_SHA256  the launcher's kept `bwrap --help`
//!                               answer: the sha256 of a bubblewrap it saw
//!                               support `--disable-userns`. The box skips its
//!                               own probe only when the bwrap it resolved has
//!                               exactly those bytes (exec-routing.md §4, "The
//!                               bwrap probe, kept by content").
//!
//! `--clean-only` is the guard-hosted mode (the guard runs this bin with a
//! cleared environment it composed at launch): the clean attempt only, no
//! verdict report, and exit 79 instead of the ordinary box when the attempt
//! is void (not eligible, a refused read, a nonzero exit).
//!
//! Without AGENTVIEW_ROOT/WORKSPACE the box still isolates net + RO-root (there is
//! just no writable AgentView bind) — see `sandbox::plan_sandbox`. WORKSPACE
//! alone (the launcher's no-view shims) names the project: under `/tmp` it is
//! re-bound READ-ONLY over the box's fresh `/tmp` (`sandbox::tmpfs_keep_binds`).
//!
//! ── Exit codes (mirror the fork model / exec-wrap) ──────────────────────────────
//!   the child's own status (0..=125) on a run; 126 exec failed; 71 sandbox setup
//!   failed; 77 BLOCKED (approval withheld — symbol-as-command); 78 usage / no
//!   arbiter socket (fail-closed: we refuse to run a command we cannot gate).

#![cfg(feature = "kernel")]

use std::process::exit;

use mandu_arbiter::ArbiterClient;
use exec_supervisor::kernel::{supervise_exec, SandboxBackend, SupervisorConfig};
use exec_supervisor::orchestrate::{argv_needs_network, path_without, EscalationMode, ExecRequest};
use exec_supervisor::refusal::refusal_message;
use exec_supervisor::socket_supervision::BoxSocketMode;
use exec_supervisor::sandbox::ViewConfig;

/// BLOCKED — a symbol sits in command position and approval was withheld. Same
/// code exec-wrap uses so a shim/test can tell a gate refusal from a program exit.
const EXIT_BLOCK: i32 = 77;
/// Usage / no arbiter socket — fail-closed (we never run an ungated command).
const EXIT_USAGE: i32 = 78;
/// Sandbox setup failed (mirrors the fork model's convention).
const EXIT_SETUP: i32 = 71;
/// `--clean-only`: the clean attempt is void (the guard answers "not
/// completed" and the requester runs the ordinary box).
const EXIT_CLEAN_VOID: i32 = 79;

fn usage(msg: &str) -> ! {
    eprintln!("mandu-exec-box: {msg}");
    eprintln!(
        "usage: mandu-exec-box [--cwd <dir>] [--needs-network|--no-needs-network] \
         [--needs-original-fs] [--clean-only] -- <argv...>"
    );
    exit(EXIT_USAGE);
}

fn main() {
    // Prevent shim recursion: a launcher `--exec-box` shim shadows commands by
    // name on the agent's PATH and execs us. We then run the command INSIDE the
    // box via a PATH search — with the shim dir still on PATH, a boxed `cat` would
    // resolve straight back to the shim. Strip the shim dir (in OUR env, so bwrap
    // and the boxed command inherit the cleaned PATH) → `cat` finds the real
    // /usr/bin/cat. No-op when the launcher didn't set the shim dir.
    if let Ok(shim) = std::env::var("MANDU_EXEC_BOX_SHIM_DIR") {
        if !shim.is_empty() {
            if let Ok(path) = std::env::var("PATH") {
                std::env::set_var("PATH", path_without(&path, &shim));
            }
        }
    }

    let mut cwd: Option<String> = std::env::var("PWD").ok();
    // None = infer from the program name; Some(bool) = an explicit override.
    let mut needs_network: Option<bool> = None;
    let mut needs_original_fs = false;
    let mut clean_only = false;
    let mut argv: Option<Vec<String>> = None;

    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--cwd" => cwd = Some(it.next().unwrap_or_else(|| usage("--cwd needs a value"))),
            "--needs-network" => needs_network = Some(true),
            "--no-needs-network" => needs_network = Some(false),
            "--needs-original-fs" => needs_original_fs = true,
            "--clean-only" => clean_only = true,
            "--" => {
                argv = Some(it.collect());
                break;
            }
            other => usage(&format!("unknown argument {other:?}")),
        }
    }

    let argv = match argv {
        Some(v) if !v.is_empty() => v,
        _ => usage("no command given (expected `-- <argv...>`)"),
    };

    // Fail-closed: without the arbiter we cannot classify, so we refuse to run.
    let mut client = match ArbiterClient::from_env() {
        Ok(c) => c,
        Err(_) => usage("MANDU_ARBITER_SOCK is required (cannot gate the exec)"),
    };

    // Infer the network hint from the program name unless overridden. This is the
    // safe-degrade: a net-needing tool routes to HumanShell instead of running in
    // the net-off box (see orchestrate::argv_needs_network).
    let needs_network = needs_network.unwrap_or_else(|| argv_needs_network(&argv));

    let backend = match std::env::var("MANDU_EXEC_BOX_BACKEND").as_deref() {
        Ok("inprocess") | Ok("InProcess") => SandboxBackend::InProcess,
        _ => SandboxBackend::Bubblewrap,
    };
    let cfg = SupervisorConfig {
        view: ViewConfig {
            agent_view_root: non_empty_env("MANDU_AGENTVIEW_ROOT"),
            workspace: non_empty_env("MANDU_WORKSPACE"),
            // Exactly "1" (the launcher's shims bake it, or unset it, HARD).
            workspace_writable: non_empty_env("MANDU_EXEC_BOX_WORKSPACE_RW").as_deref() == Some("1"),
        },
        backend,
        landlock_apply: non_empty_env("MANDU_LANDLOCK_APPLY"),
        // The rung-2 clean-box posture (exec-routing.md §8.5): opt-in env.
        clean_box: clean_only || non_empty_env("MANDU_EXEC_CLEAN_BOX").map(|v| v != "0").unwrap_or(false),
        // §5.3: the guard hosts the attempt (never asked from inside it).
        clean_via: if clean_only { None } else { non_empty_env("MANDU_EXEC_CLEAN_SOCK") },
        clean_only,
        // No production grant source yet (the registry records only
        // untrusted-by-origin); tests construct grants directly.
        trusted_reads: vec![],
        // WSL interop hiding keys on the running host's signals.
        wsl: None,
        // The host hiding uses the production roots and /run.
        socket_roots: None,
        run_dir: None,
        host_env: None,
        after_host_hide: None,
        // The box's Unix-socket allow-list is always on (exec-routing.md §4.2).
        socket_allowlist: None,
        // No wall-clock cap on the command (exec-routing.md §4.4): a build or a
        // server runs as long as it runs; the agent's tool timeout bounds it.
        // The supervisor's own internal waits are bounded regardless.
        deadline: None,
        handoff_limit: None,
        before_handoff: None,
    };

    let req = ExecRequest {
        argv,
        cwd,
        needs_network,
        needs_original_fs,
        params: None,
        // Auto: a needs_* hint routes straight to HumanShell. (Gated escalation —
        // approval-before-HumanShell — is a launcher policy choice for later.)
        escalation: EscalationMode::Auto,
    };

    match supervise_exec(&mut client, &cfg, &req) {
        Ok(outcome) if clean_only => exit(if outcome.clean.is_some() { 0 } else { EXIT_CLEAN_VOID }),
        Ok(outcome) => {
            if outcome.refused_pending_approval {
                // Plain words (release checklist d5): what, why, what to do —
                // per withheld kind (a `secrets`-mode secret_symbol is not the
                // frozen integrity symbol_as_command). No approval queue exists
                // for the exec itself, so none is promised (refusal.rs).
                eprintln!(
                    "{}",
                    refusal_message(&outcome.withheld_approvals, outcome.gate_unreachable)
                );
                exit(EXIT_BLOCK);
            }
            // A box nobody could supervise refuses every connect (§4.2); a
            // command that failed there gets the reason, once.
            if outcome.box_sockets == BoxSocketMode::ConnectDenied && outcome.child_status != Some(0) {
                eprintln!(
                    "mandu-exec-box: note: this host cannot supervise the command box's sockets \
                     (no seccomp listener, no guard), so every connect inside the box is refused"
                );
            }
            // The child's own exit status (None only when it never ran, which the
            // refusal branch above already handled → treat as setup failure).
            exit(outcome.child_status.unwrap_or(EXIT_SETUP));
        }
        Err(e) => {
            eprintln!("mandu-exec-box: sandbox setup failed (fail-closed): {e}");
            exit(EXIT_SETUP);
        }
    }
}

/// Read an env var, treating unset OR empty as absent (an empty AGENTVIEW_ROOT
/// must not become a bind of "" ).
fn non_empty_env(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}
