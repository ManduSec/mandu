//! Privileged integration test for the seccomp-unotify openat() redirect.
//!
//! `#[ignore]`d so the default `cargo test` (unprivileged) skips it. Run with the
//! kernel feature, as root OR as root-in-an-unprivileged-user-namespace (no host
//! state changed, no real root needed):
//!
//!   cargo build -p fs-supervisor --features kernel
//!   unshare --user --map-root-user --mount --pid --fork -- \
//!     bash -c 'cd interceptors && cargo test -p fs-supervisor --features kernel \
//!                -- --ignored --nocapture'
//!
//! Requirements: CAP_SYS_ADMIN in the filter's user namespace + no_new_privs
//! (both satisfied by `unshare --user --map-root-user`), and kernel ≥ 5.0 with
//! CONFIG_SECCOMP_USER_NOTIFICATION (works even on a 5.4 kernel) for the INTERCEPTION
//! assertion. The REDIRECT assertion additionally needs SECCOMP_IOCTL_NOTIF_ADDFD
//! (kernel ≥ 5.9 — the 6.8 dev host runs it live) and is SKIPPED with a clear
//! message on older kernels.
//!
//! ── What this proves, and where ─────────────────────────────────────────────
//!  • INTERCEPTION (passes on 5.4): we install the listener, a forked tracee
//!    `openat`s a TRACKED path, and the supervisor RECEIVES the notification,
//!    reads back the CORRECT path via process_vm_readv, and the pure
//!    `step`/`decide_open` decides REDIRECT (→ the AgentView worktree). This is
//!    the trap + read-args + decision core, unprivileged-in-userns on 5.4.
//!  • REDIRECT (needs ≥ 5.9): the tracee's `openat` of a tracked path actually
//!    returns an fd to the AgentView (symbolized) file via ADDFD, and reading
//!    that fd yields the AgentView content (NOT the raw HumanView bytes).
//!
//! The pure decision logic is fully covered by the `src/` unit tests on the
//! unprivileged host; this file proves the kernel glue where privileges exist.

// Everything below is kernel-feature + cfg(target_os = "linux"). The default
// build compiles an empty crate so the file never breaks `cargo test`.
#![cfg(all(feature = "kernel", target_os = "linux"))]

// The deadline helpers net-supervisor's integration tests share
// (docs/design/testing/test-organization.md §8.5): a wait for the tracee
// fails by name with its /proc state, and kills it, instead of hanging.
#[path = "../../net-supervisor/tests/support/mod.rs"]
mod support;
use support::{in_test_process, read_to_end_from, reap_within, readable_within, wait_limit};

use std::ffi::CString;
use std::os::unix::io::RawFd;

use fs_supervisor::decision::{FirstTouchSet, TrackedRoots};
use fs_supervisor::kernel::{
    self, handle_notif, install_filter_self, kernel_at_least, notif_recv, DegradedPassthrough,
    HandledNotif, LoopConfig, NotifReader, VmReader,
};
use fs_supervisor::layout::ViewLayout;

/// Build a temp view layout on disk: a tracked HumanView root with a
/// `secret.txt`, and the matching AgentView worktree with DIFFERENT (symbolized)
/// content, so a successful REDIRECT is observable (content differs).
struct Fixture {
    /// temp dir root (state base lives here too); cleaned on drop.
    _tmp: TempDir,
    roots: TrackedRoots,
    /// The tracked HumanView root dir (the tracee chdir's here for relative opens).
    human_root: String,
    human_file: String,
    agent_view_file: String,
    agent_view_content: &'static str,
}

const HUMAN_CONTENT: &str = "RAW HUMANVIEW BYTES - the agent must never see these";
const AGENT_CONTENT: &str = "AGENTVIEW: content is $MDU:Read[0001].v (symbolized)";

fn make_fixture() -> Fixture {
    let tmp = TempDir::new("fs-supervisor-kernel-it");
    let human_root = format!("{}/human/proj", tmp.path);
    let state_base = format!("{}/state", tmp.path);

    let layout = ViewLayout::new(&human_root, &state_base);
    let agent_view_dir = layout.agent_view_path().to_string_lossy().into_owned();

    // HumanView: tracked root + a secret file with the RAW bytes.
    std::fs::create_dir_all(&human_root).unwrap();
    let human_file = format!("{human_root}/secret.txt");
    std::fs::write(&human_file, HUMAN_CONTENT).unwrap();

    // AgentView worktree: same relative path, but SYMBOLIZED content.
    std::fs::create_dir_all(&agent_view_dir).unwrap();
    let agent_view_file = format!("{agent_view_dir}/secret.txt");
    std::fs::write(&agent_view_file, AGENT_CONTENT).unwrap();

    Fixture {
        _tmp: tmp,
        roots: TrackedRoots::with_layouts(vec![layout]),
        human_root,
        human_file,
        agent_view_file,
        agent_view_content: AGENT_CONTENT,
    }
}

/// How the forked tracee should issue its `openat` — lets one driver exercise the
/// absolute, relative-to-cwd, dirfd-relative, and `..`-escape cases. All but
/// `AbsoluteTracked` require canonicalization in the supervisor to be classified
/// correctly; the driver returns what the supervisor DECIDED so the test asserts it.
enum OpenRecipe {
    /// `chdir(<dir>)` then `openat(AT_FDCWD, <rel>)` — relative-to-cwd resolution.
    /// The `chdir` happens BEFORE the filter is installed so it is not itself trapped.
    /// (The absolute-tracked case is covered by `seccomp_unotify_intercepts_*`.)
    RelativeFromCwd { chdir_to: String, rel: String },
    /// `open(<dir>, O_DIRECTORY)` → dirfd (BEFORE the filter is installed, so the
    /// dirfd acquisition itself is not trapped), then `openat(dirfd, <rel>)` — dirfd
    /// resolution via `/proc/<pid>/fd/<dirfd>`.
    DirfdRelative { dir: String, rel: String },
}

/// Result of driving one trapped open through the supervisor: the path the
/// supervisor READ back (raw, pre-canon, exactly as the tracee passed it) and the
/// `HandledNotif` the supervisor decided after canonicalization.
struct DriveOutcome {
    /// The RAW path the tracee passed (pre-canonicalization), as the supervisor read
    /// it via process_vm_readv — relative for the relative recipes.
    read_back: String,
    /// What `canonicalize_for_tracee` resolved the (pid, dirfd, raw) to — the same
    /// computation `handle_notif` does internally. `None` is the fail-safe (an
    /// unresolvable dirfd). Asserted so the tests prove RESOLUTION, not coincidence.
    canonical: Option<String>,
    handled: HandledNotif,
}

/// Fork a tracee that installs the listener, hands it to us, and issues the
/// `recipe`'s open (suspended on the trap). We (the supervisor) RECV the notif,
/// read the raw path back, and run `handle_notif` (DenyEperm degraded → on 5.4 the
/// decision is made but enactment deferred). Returns `None` to SKIP when seccomp
/// NEW_LISTENER is denied (no CAP_SYS_ADMIN-in-userns).
fn drive_one_open(fx: &Fixture, recipe: OpenRecipe) -> Option<DriveOutcome> {
    let (sup_sock, child_sock) = socketpair();
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed: {}", last_err());

    if child == 0 {
        // ── TRACEE ──────────────────────────────────────────────────────────
        unsafe { libc::close(sup_sock) };

        // PRE-FILTER setup (chdir / acquire a dirfd) so these helper syscalls are
        // NOT trapped — only the single open we care about is issued post-install.
        // The acquired cwd/dirfd is what `/proc/<pid>/{cwd,fd/N}` will report to the
        // suspended supervisor; the tracee is suspended on the trap so it is stable.
        let mut dirfd: libc::c_int = libc::AT_FDCWD;
        match &recipe {
            OpenRecipe::RelativeFromCwd { chdir_to, .. } => {
                let d = CString::new(chdir_to.as_str()).unwrap();
                if unsafe { libc::chdir(d.as_ptr()) } != 0 {
                    unsafe { libc::_exit(EXIT_SETUP_FAIL) };
                }
            }
            OpenRecipe::DirfdRelative { dir, .. } => {
                let d = CString::new(dir.as_str()).unwrap();
                dirfd = unsafe { libc::open(d.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
                if dirfd < 0 {
                    unsafe { libc::_exit(EXIT_SETUP_FAIL) };
                }
            }
        }

        // Install no_new_privs + the openat listener, then hand it to the supervisor.
        let listener = match install_filter_self() {
            Ok(fd) => fd,
            Err(_) => unsafe { libc::_exit(EXIT_NO_SECCOMP) },
        };
        if send_fd(child_sock, listener).is_err() {
            unsafe { libc::_exit(EXIT_SETUP_FAIL) };
        }

        // Issue the SINGLE trapped open per the recipe. The supervisor answers EPERM
        // on 5.4, so the open result is irrelevant — the PARENT asserts the decision.
        match recipe {
            OpenRecipe::RelativeFromCwd { rel, .. } => {
                let c = CString::new(rel).unwrap();
                let _ = unsafe { libc::openat(libc::AT_FDCWD, c.as_ptr(), libc::O_RDONLY) };
            }
            OpenRecipe::DirfdRelative { rel, .. } => {
                let c = CString::new(rel).unwrap();
                let _ = unsafe { libc::openat(dirfd, c.as_ptr(), libc::O_RDONLY) };
            }
        }
        unsafe { libc::_exit(0) };
    }

    // ── SUPERVISOR (parent) ───────────────────────────────────────────────────
    unsafe { libc::close(child_sock) };
    readable_within(sup_sock, child, wait_limit(), "waiting for the tracee to hand over its seccomp listener");
    let listener = match recv_fd(sup_sock) {
        Ok(fd) => fd,
        Err(_) => {
            let code = reap(child);
            unsafe { libc::close(sup_sock) };
            if code == Some(EXIT_NO_SECCOMP) {
                eprintln!(
                    "SKIP: seccomp NEW_LISTENER install was denied (need CAP_SYS_ADMIN-in-userns + \
                     no_new_privs). Re-run under: unshare --user --map-root-user ..."
                );
                return None;
            }
            panic!("tracee failed to send listener fd (exit {code:?})");
        }
    };

    let mut cfg = LoopConfig {
        roots: fx.roots.clone(),
        reader: VmReader::default(),
        degraded_passthrough: DegradedPassthrough::DenyEperm,
        arbiter: None,
    };
    let mut seen = FirstTouchSet::new();

    // Exactly one trapped open per recipe (chdir/dirfd setup happened pre-filter).
    readable_within(listener, child, wait_limit(), "waiting for the tracee's trapped openat (its seccomp notification)");
    let notif = notif_recv(listener).expect("NOTIF_RECV failed");
    // Read back the RAW path the tracee passed (relative for the relative recipes),
    // BEFORE canonicalization — the supervisor canonicalizes inside handle_notif.
    let read_back = VmReader::default()
        .read_path(notif.pid as i32, notif.data.args[1])
        .expect("read path via process_vm_readv");
    // Recompute the supervisor's canonicalization (same inputs handle_notif uses), so
    // the test can assert WHAT the raw path resolved to — proving canonicalization
    // ran (and didn't silently fall into the None fail-safe). This must be read
    // while the tracee is still SUSPENDED on the trap (before we answer below).
    let canonical = kernel::canonicalize_for_tracee(
        notif.pid as i32,
        notif.data.args[0] as i32,
        &read_back,
    );
    let handled = handle_notif(listener, &mut cfg, &mut seen, &notif).expect("handle_notif");

    unsafe { libc::close(listener) };
    unsafe { libc::close(sup_sock) };
    reap(child);
    Some(DriveOutcome { read_back, canonical, handled })
}

/// INTERCEPTION (must PASS on 5.4): install the listener, fork a tracee that
/// `openat`s the tracked path, and assert the supervisor RECEIVES the notification,
/// reads the CORRECT path, and DECIDES redirect to the AgentView worktree.
///
/// We deliberately answer the notification with EPERM here (not a redirect), so
/// the assertion is about the TRAP + READ + DECISION — the parts that work on 5.4.
/// The full redirect is the separate, version-gated assertion below.
#[test]
#[ignore = "requires CAP_SYS_ADMIN-in-userns + SECCOMP_USER_NOTIF; --features kernel -- --ignored"]
fn seccomp_unotify_intercepts_and_decides_redirect() {
    let fx = make_fixture();
    let tracked = fx.human_file.clone();

    // The tracee installs the seccomp listener ON ITSELF, sends the fd to us over a
    // socketpair, then openat()s the tracked path (which traps). We (the parent)
    // are the supervisor: receive the listener fd, RECV the notif, handle it.
    let (sup_sock, child_sock) = socketpair();

    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed: {}", last_err());

    if child == 0 {
        // ── TRACEE ──────────────────────────────────────────────────────────
        unsafe { libc::close(sup_sock) };
        // Install no_new_privs + the openat listener on ourselves.
        let listener = match install_filter_self() {
            Ok(fd) => fd,
            // EACCES/EPERM here means the env lacks CAP_SYS_ADMIN-in-userns; use a
            // distinct exit code so the parent can SKIP rather than fail.
            Err(_) => unsafe { libc::_exit(EXIT_NO_SECCOMP) },
        };
        // Send the listener fd to the supervisor over SCM_RIGHTS.
        if send_fd(child_sock, listener).is_err() {
            unsafe { libc::_exit(EXIT_SETUP_FAIL) };
        }
        // Now trip the trap: openat the tracked path. On 5.4 the supervisor will
        // answer EPERM, so this returns -1/EACCES — that's EXPECTED for the
        // interception assertion and the child exits 0 regardless (the PARENT
        // asserts what it observed, not the child's open result).
        let c = CString::new(tracked.as_str()).unwrap();
        let _fd = unsafe { libc::openat(libc::AT_FDCWD, c.as_ptr(), libc::O_RDONLY) };
        unsafe { libc::_exit(0) };
    }

    // ── SUPERVISOR (parent) ───────────────────────────────────────────────────
    unsafe { libc::close(child_sock) };

    // If the tracee couldn't install seccomp, SKIP (don't fail) — the host/env
    // lacks the capability. We detect this by reaping and checking the exit code
    // when fd-receive fails.
    readable_within(sup_sock, child, wait_limit(), "waiting for the tracee to hand over its seccomp listener");
    let listener = match recv_fd(sup_sock) {
        Ok(fd) => fd,
        Err(_) => {
            let code = reap(child);
            unsafe { libc::close(sup_sock) };
            if code == Some(EXIT_NO_SECCOMP) {
                eprintln!(
                    "SKIP: seccomp NEW_LISTENER install was denied (need CAP_SYS_ADMIN-in-userns + \
                     no_new_privs). Re-run under: unshare --user --map-root-user ..."
                );
                return;
            }
            panic!("tracee failed to send listener fd (exit {code:?})");
        }
    };

    // Receive exactly one notification (the tracee's openat).
    readable_within(listener, child, wait_limit(), "waiting for the tracee's trapped openat (its seccomp notification)");
    let notif = notif_recv(listener).expect("NOTIF_RECV failed");

    // ASSERT 1: the supervisor can read the CORRECT path out of the tracee.
    // This MUST happen before handle_notif answers the notification: once
    // answered, the tracee's openat returns and it proceeds to exit, so a
    // later process_vm_readv races tracee death (ESRCH — deterministic on
    // ≥ 5.9 where ADDFD answers fast, flaky on cold 5.4 runs). While blocked
    // on the unanswered notification the tracee is frozen and the read is
    // race-free.
    let read_back = VmReader::default()
        .read_path(notif.pid as i32, notif.data.args[1])
        .expect("read path via process_vm_readv");
    assert_eq!(
        read_back, fx.human_file,
        "supervisor must read the exact tracked path the tracee opened"
    );

    // Drive the loop body. Use DenyEperm degraded policy: on 5.4 (no CONTINUE,
    // no ADDFD) the redirect can't be enacted, so handle_notif answers EPERM —
    // but it has ALREADY read the path and made the redirect DECISION, which is
    // exactly what we assert here.
    let mut cfg = LoopConfig {
        roots: fx.roots.clone(),
        reader: VmReader::default(),
        degraded_passthrough: DegradedPassthrough::DenyEperm,
        arbiter: None,
    };
    let mut seen = FirstTouchSet::new();
    let handled = handle_notif(listener, &mut cfg, &mut seen, &notif).expect("handle_notif");

    // ASSERT 2: the decision was REDIRECT to the AgentView worktree. On 5.4 ADDFD
    // is unavailable, so this surfaces as RedirectUnavailable carrying the intended
    // AgentView target (the redirect DECISION succeeded; only the enactment is
    // gated on ≥ 5.9). On ≥ 5.9 it would be Redirected.
    match handled {
        HandledNotif::RedirectUnavailable { agent_view_path, .. } => {
            assert_eq!(
                agent_view_path, fx.agent_view_file,
                "decided redirect must target the AgentView worktree copy"
            );
            eprintln!(
                "INTERCEPTION PASS: trapped openat({}), read path, decided REDIRECT → {} \
                 (ADDFD unavailable on this kernel → enactment deferred to ≥ 5.9)",
                fx.human_file, agent_view_path
            );
        }
        HandledNotif::Redirected { agent_view_path, new_fd } => {
            // ≥ 5.9: the redirect was actually enacted. Still a valid interception.
            assert_eq!(agent_view_path, fx.agent_view_file);
            assert!(new_fd >= 0);
            eprintln!(
                "INTERCEPTION PASS (and redirect enacted, kernel ≥ 5.9): openat → AgentView fd {new_fd}"
            );
        }
        other => panic!("expected a redirect decision for a tracked path, got {other:?}"),
    }

    unsafe { libc::close(listener) };
    unsafe { libc::close(sup_sock) };
    reap(child);
}

/// Assert the supervisor DECIDED a redirect to the AgentView worktree (5.4:
/// RedirectUnavailable carrying the target; ≥ 5.9: Redirected). Shared by the
/// canonicalization tests below.
fn assert_decided_redirect(handled: &HandledNotif, expect_agent_view: &str, ctx: &str) {
    match handled {
        HandledNotif::RedirectUnavailable { agent_view_path, .. } => {
            assert_eq!(
                agent_view_path, expect_agent_view,
                "{ctx}: canonicalized path must redirect to the AgentView worktree copy"
            );
        }
        HandledNotif::Redirected { agent_view_path, .. } => {
            assert_eq!(agent_view_path, expect_agent_view, "{ctx}");
        }
        other => panic!("{ctx}: expected a redirect decision, got {other:?}"),
    }
}

/// CANONICALIZATION — relative open from a cwd INSIDE the tracked root (PASSES on
/// 5.4). The tracee chdir's into the tracked root and `openat(AT_FDCWD, "secret.txt")`
/// with a RELATIVE path. The supervisor must resolve it against `/proc/<pid>/cwd`
/// to the absolute tracked path and DECIDE redirect to the right AgentView target —
/// proving canonicalization, since the raw string "secret.txt" alone never prefix-
/// matches the tracked root.
#[test]
#[ignore = "requires CAP_SYS_ADMIN-in-userns + SECCOMP_USER_NOTIF; --features kernel -- --ignored"]
fn canonicalizes_relative_cwd_open_to_tracked_redirect() {
    ensure_proc_matches_pidns();
    let fx = make_fixture();
    let outcome = match drive_one_open(
        &fx,
        OpenRecipe::RelativeFromCwd {
            chdir_to: fx.human_root.clone(),
            rel: "secret.txt".to_string(),
        },
    ) {
        Some(o) => o,
        None => return, // SKIP: seccomp denied (message already printed)
    };

    // The supervisor read back the RAW relative path (pre-canon) the tracee passed.
    assert_eq!(
        outcome.read_back, "secret.txt",
        "raw path the tracee passed was relative — proves canon is the supervisor's job"
    );
    // It resolved that relative name against /proc/<pid>/cwd to the ABSOLUTE tracked
    // file (proving canonicalization ran, not the None fail-safe).
    assert_eq!(
        outcome.canonical.as_deref(),
        Some(fx.human_file.as_str()),
        "relative open must canonicalize to the absolute tracked path"
    );
    // …and therefore decided REDIRECT to the AgentView copy of that file.
    assert_decided_redirect(&outcome.handled, &fx.agent_view_file, "relative-cwd open");
    eprintln!(
        "CANON PASS (relative→cwd): openat(AT_FDCWD, \"secret.txt\") from cwd={} \
         resolved → {} → REDIRECT to {}",
        fx.human_root, fx.human_file, fx.agent_view_file
    );
}

/// CANONICALIZATION — a `..`-ESCAPE out of the tracked root must NOT be redirected
/// (PASSES on 5.4). The tracee chdir's into the tracked root and opens
/// `"../../../../../../etc/passwd"` (enough `..` to climb above the temp tree to
/// the real /etc/passwd). The supervisor canonicalizes to the real absolute path
/// OUTSIDE the root, so `decide_open` says PASSTHROUGH — proving the escape is
/// classified by its RESOLVED target, not blindly prefix-matched on the raw string.
#[test]
#[ignore = "requires CAP_SYS_ADMIN-in-userns + SECCOMP_USER_NOTIF; --features kernel -- --ignored"]
fn canonicalizes_dotdot_escape_to_passthrough_not_redirect() {
    ensure_proc_matches_pidns();
    let fx = make_fixture();
    // Plenty of `..` to climb out of the (deep) temp dir to the filesystem root,
    // then down to a real file. Lexical pops stop at "/" so over-climbing is safe.
    let escape = "../../../../../../../../../../../../etc/passwd";
    let outcome = match drive_one_open(
        &fx,
        OpenRecipe::RelativeFromCwd {
            chdir_to: fx.human_root.clone(),
            rel: escape.to_string(),
        },
    ) {
        Some(o) => o,
        None => return, // SKIP
    };

    assert_eq!(outcome.read_back, escape, "raw path was the `..`-escape string");
    // Prove canonicalization actually RESOLVED the escape (not the None fail-safe):
    // the `..`-walk lands at the real /etc/passwd, which is absolute and OUTSIDE the
    // tracked root. (`/etc` cannot be under the per-test /tmp/...-tracked root.)
    let canon = outcome
        .canonical
        .as_deref()
        .expect("a `..`-escape from a real cwd must resolve, not fail-safe to None");
    assert_eq!(canon, "/etc/passwd", "`..`-walk must resolve to the real absolute target");
    assert!(
        !canon.starts_with(&fx.human_root),
        "resolved escape must be OUTSIDE the tracked root: {canon}"
    );
    // The decisive assertion: resolved OUTSIDE the root → PASSTHROUGH, NOT redirected.
    // This is what defeats the TOCTOU residue — the decision is on the RESOLVED path,
    // so an attacker can't dress a tracked-looking raw string over an escaping open.
    match outcome.handled {
        HandledNotif::PassedThrough { .. } => {
            eprintln!(
                "CANON PASS (..-escape): openat(AT_FDCWD, \"{escape}\") from inside the root \
                 resolved → {canon} (OUTSIDE the root) → PASSTHROUGH (not redirected)"
            );
        }
        other => panic!(
            "a `..`-escape out of the tracked root must PASSTHROUGH, not redirect; got {other:?}"
        ),
    }
}

/// CANONICALIZATION — a dirfd-relative open where the dirfd points INSIDE the
/// tracked root (PASSES on 5.4). The tracee opens the tracked root as a dirfd
/// (BEFORE the filter, so that open isn't trapped), then `openat(dirfd, "secret.txt")`.
/// The supervisor must resolve the relative name against `/proc/<pid>/fd/<dirfd>`
/// to the absolute tracked path and DECIDE redirect to the right AgentView target.
#[test]
#[ignore = "requires CAP_SYS_ADMIN-in-userns + SECCOMP_USER_NOTIF; --features kernel -- --ignored"]
fn canonicalizes_dirfd_relative_open_to_tracked_redirect() {
    ensure_proc_matches_pidns();
    let fx = make_fixture();
    let outcome = match drive_one_open(
        &fx,
        OpenRecipe::DirfdRelative {
            dir: fx.human_root.clone(),
            rel: "secret.txt".to_string(),
        },
    ) {
        Some(o) => o,
        None => return, // SKIP
    };

    assert_eq!(outcome.read_back, "secret.txt", "raw path was the dirfd-relative name");
    // Resolved via /proc/<pid>/fd/<dirfd> to the absolute tracked file (not None).
    assert_eq!(
        outcome.canonical.as_deref(),
        Some(fx.human_file.as_str()),
        "dirfd-relative open must canonicalize via /proc/<pid>/fd to the tracked path"
    );
    assert_decided_redirect(&outcome.handled, &fx.agent_view_file, "dirfd-relative open");
    eprintln!(
        "CANON PASS (dirfd-relative): openat(dirfd→{}, \"secret.txt\") resolved via \
         /proc/<pid>/fd → {} → REDIRECT to {}",
        fx.human_root, fx.human_file, fx.agent_view_file
    );
}

/// REDIRECT (gated on kernel ≥ 5.9; SKIPPED with a message otherwise): the
/// tracee's openat of a TRACKED path actually returns an fd whose content is the
/// AgentView (symbolized) file — proving the full ADDFD redirect end to end.
#[test]
#[ignore = "requires kernel ≥ 5.9 (ADDFD) + CAP_SYS_ADMIN-in-userns; --features kernel -- --ignored"]
fn seccomp_unotify_redirect_returns_agentview_fd() {
    if !kernel_at_least(5, 9) {
        let (maj, min) = kernel::kernel_version();
        eprintln!(
            "SKIP: full ADDFD redirect needs kernel ≥ 5.9 for SECCOMP_IOCTL_NOTIF_ADDFD; \
             this host is {maj}.{min}. The trap + decision is proven by the INTERCEPTION test; \
             this assertion runs on a ≥ 5.9 VM."
        );
        return;
    }

    let fx = make_fixture();
    let tracked = fx.human_file.clone();
    let (sup_sock, child_sock) = socketpair();
    // A pipe to ship the bytes the CHILD read from its openat fd back to us, so we
    // assert on the AgentView content the redirect delivered.
    let (rd, wr) = pipe();

    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed: {}", last_err());

    if child == 0 {
        // ── TRACEE ──────────────────────────────────────────────────────────
        unsafe {
            libc::close(sup_sock);
            libc::close(rd);
        }
        let listener = match install_filter_self() {
            Ok(fd) => fd,
            Err(_) => unsafe { libc::_exit(EXIT_NO_SECCOMP) },
        };
        if send_fd(child_sock, listener).is_err() {
            unsafe { libc::_exit(EXIT_SETUP_FAIL) };
        }
        // openat the tracked path. With ADDFD the supervisor injects the AgentView
        // fd, so THIS open returns a usable fd to the symbolized content.
        let c = CString::new(tracked.as_str()).unwrap();
        let fd = unsafe { libc::openat(libc::AT_FDCWD, c.as_ptr(), libc::O_RDONLY) };
        if fd < 0 {
            unsafe { libc::_exit(EXIT_OPEN_FAIL) };
        }
        // Read it and ship the bytes up the pipe for the parent to assert on.
        let mut buf = [0u8; 256];
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n > 0 {
            unsafe { libc::write(wr, buf.as_ptr() as *const libc::c_void, n as usize) };
        }
        unsafe {
            libc::close(wr);
            libc::_exit(0);
        }
    }

    // ── SUPERVISOR (parent) ───────────────────────────────────────────────────
    unsafe {
        libc::close(child_sock);
        libc::close(wr);
    }
    readable_within(sup_sock, child, wait_limit(), "waiting for the tracee to hand over its seccomp listener");
    let listener = match recv_fd(sup_sock) {
        Ok(fd) => fd,
        Err(_) => {
            let code = reap(child);
            unsafe {
                libc::close(sup_sock);
                libc::close(rd);
            }
            if code == Some(EXIT_NO_SECCOMP) {
                eprintln!("SKIP: seccomp NEW_LISTENER denied (need CAP_SYS_ADMIN-in-userns).");
                return;
            }
            panic!("tracee failed to send listener fd (exit {code:?})");
        }
    };

    readable_within(listener, child, wait_limit(), "waiting for the tracee's trapped openat (its seccomp notification)");
    let notif = notif_recv(listener).expect("NOTIF_RECV failed");
    let mut cfg = LoopConfig {
        roots: fx.roots.clone(),
        reader: VmReader::default(),
        degraded_passthrough: DegradedPassthrough::DenyEperm,
        arbiter: None,
    };
    let mut seen = FirstTouchSet::new();
    let handled = handle_notif(listener, &mut cfg, &mut seen, &notif).expect("handle_notif");

    // On ≥ 5.9 the redirect is enacted: assert the kernel action was Redirected.
    match handled {
        HandledNotif::Redirected { agent_view_path, new_fd } => {
            assert_eq!(agent_view_path, fx.agent_view_file);
            assert!(new_fd >= 0, "tracee should have a valid AgentView fd");
        }
        other => panic!("expected Redirected on kernel ≥ 5.9, got {other:?}"),
    }

    // The decisive assertion: the bytes the CHILD read from its openat fd are the
    // AgentView (symbolized) content, NOT the raw HumanView bytes.
    let got = String::from_utf8_lossy(&read_to_end_from(rd, child, wait_limit(), "reading what the tracee read through its redirected descriptor")).into_owned();
    unsafe { libc::close(rd) };
    assert_eq!(
        got, fx.agent_view_content,
        "REDIRECT must deliver AgentView content; got raw HumanView bytes = invariant violation"
    );
    assert_ne!(got, HUMAN_CONTENT, "must NOT be the raw HumanView bytes");

    eprintln!("REDIRECT PASS (kernel ≥ 5.9): tracee openat returned AgentView fd; content symbolized.");

    unsafe { libc::close(listener) };
    unsafe { libc::close(sup_sock) };
    reap(child);
}

/// WRITE-TAINT (kernel-gated, `#[ignore]`d): when the tracee does a WRITE-intent
/// open of a tracked path and a MockArbiter reports that writer pid as tainted, the
/// supervisor calls `record_file_taint_if_tainted` (via `maybe_taint_written_file`)
/// and the arbiter sees a `taintFile` op for the written path. The redirect still
/// happens (the taint is additive, off the redirect path).
///
/// Run:
///   unshare --user --map-root-user --mount --pid --fork -- \
///     bash -c 'cd interceptors && cargo test -p fs-supervisor --features kernel \
///                -- --ignored --nocapture write_taint'
#[test]
#[ignore = "requires CAP_SYS_ADMIN-in-userns + SECCOMP_USER_NOTIF + MockArbiter; --features kernel -- --ignored"]
fn write_by_tainted_pid_taints_file_in_arbiter() {
    use mandu_arbiter::mock::{op_handler, MockArbiter};
    use mandu_arbiter::ArbiterClient;
    use std::sync::{Arc, Mutex};

    ensure_proc_matches_pidns();

    // The write-taint hook (`maybe_taint_written_file`) runs AFTER `respond_addfd`
    // succeeds in `handle_notif`. ADDFD needs kernel ≥ 5.9; on older kernels
    // `respond_addfd` does not succeed, so the hook never fires and the arbiter
    // never receives a `taintFile` op. Skip gracefully here — the taint *logic*
    // is covered by the Plan-2 unit tests and the Plan-6 chain oracle.
    if !kernel_at_least(5, 9) {
        let (maj, min) = kernel::kernel_version();
        eprintln!(
            "SKIP: write-taint enactment needs ADDFD (kernel >= 5.9); host is {maj}.{min} \
             — taint logic is covered by the Plan-2 unit tests + the Plan-6 chain oracle"
        );
        return;
    }

    let fx = make_fixture();

    // Stand up a MockArbiter that:
    //  - responds `isProcessTainted` → tainted=true for ANY proc key (simulates a
    //    tainted writer)
    //  - records each `taintFile` op's path so we can assert it fired
    let tainted_paths: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let tainted_paths2 = tainted_paths.clone();
    let arbiter = MockArbiter::start(op_handler(move |op, req| match op {
        "isProcessTainted" => Ok(serde_json::json!({ "tainted": true, "originHost": "evil.test" })),
        "taintFile" => {
            let path = req.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
            tainted_paths2.lock().unwrap().push(path);
            Ok(serde_json::json!({ "ok": true }))
        }
        // The supervisor may also call classify/symbolize from first_touch_classify on
        // some paths — answer conservatively so we don't panic the mock.
        "classify" => Ok(serde_json::json!({ "trust": "UNTRUSTED", "category": null, "reason": "test" })),
        "symbolize" => Ok(serde_json::json!({ "symbol": "$MDU:test[0001].v" })),
        other => Err(format!("unexpected op {other}")),
    }));

    let (sup_sock, child_sock) = socketpair();
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed: {}", last_err());

    if child == 0 {
        // ── TRACEE: install the listener, then do a WRITE-intent open of the tracked path.
        unsafe { libc::close(sup_sock) };
        let listener = match install_filter_self() {
            Ok(fd) => fd,
            Err(_) => unsafe { libc::_exit(EXIT_NO_SECCOMP) },
        };
        if send_fd(child_sock, listener).is_err() {
            unsafe { libc::_exit(EXIT_SETUP_FAIL) };
        }
        // O_WRONLY | O_CREAT — a write-intent open; the supervisor must call taintFile.
        let c = std::ffi::CString::new(fx.human_file.as_str()).unwrap();
        let _ = unsafe {
            libc::openat(
                libc::AT_FDCWD,
                c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT,
                0o644i32,
            )
        };
        unsafe { libc::_exit(0) };
    }

    // ── SUPERVISOR (parent): receive the listener, drive one notification with arbiter set.
    unsafe { libc::close(child_sock) };
    readable_within(sup_sock, child, wait_limit(), "waiting for the tracee to hand over its seccomp listener");
    let listener = match recv_fd(sup_sock) {
        Ok(fd) => fd,
        Err(_) => {
            let code = reap(child);
            unsafe { libc::close(sup_sock) };
            if code == Some(EXIT_NO_SECCOMP) {
                eprintln!("SKIP: seccomp NEW_LISTENER denied (need CAP_SYS_ADMIN-in-userns).");
                return;
            }
            panic!("tracee failed to send listener fd (exit {code:?})");
        }
    };

    readable_within(listener, child, wait_limit(), "waiting for the tracee's trapped openat (its seccomp notification)");
    let notif = notif_recv(listener).expect("NOTIF_RECV failed");
    let mut cfg = LoopConfig {
        roots: fx.roots.clone(),
        reader: VmReader::default(),
        degraded_passthrough: DegradedPassthrough::DenyEperm,
        arbiter: Some(ArbiterClient::new(&arbiter.socket_path)),
    };
    let mut seen = FirstTouchSet::new();
    // Drive handle_notif — the redirect (or degraded EPERM on < 5.9) AND the write-taint
    // hook both run. We don't assert which HandledNotif variant (the redirect is already
    // proven by the other tests); we only assert the `taintFile` side-effect.
    let _ = handle_notif(listener, &mut cfg, &mut seen, &notif);

    unsafe { libc::close(listener) };
    unsafe { libc::close(sup_sock) };
    reap(child);

    // LOAD-BEARING ASSERTION: the arbiter saw at least one `taintFile` for the tracked
    // path. `record_file_taint_if_tainted` was called because:
    //   (a) the open was WRITE-intent (O_WRONLY | O_CREAT),
    //   (b) `isProcessTainted` returned true, and
    //   (c) `cfg.arbiter` was Some.
    let paths = tainted_paths.lock().unwrap();
    assert!(
        !paths.is_empty(),
        "expected at least one taintFile op for a write by a tainted pid, got none"
    );
    assert!(
        paths.iter().any(|p| p == &fx.human_file),
        "taintFile path must be the tracked human-view file; got: {paths:?}"
    );
    eprintln!(
        "WRITE-TAINT PASS: write-intent open of {} by a tainted pid triggered taintFile; \
         paths recorded: {paths:?}",
        fx.human_file
    );
}

// ── tiny libc helpers (test-local; the crate core stays clean) ──────────────


const EXIT_NO_SECCOMP: i32 = 91;
const EXIT_SETUP_FAIL: i32 = 92;
const EXIT_OPEN_FAIL: i32 = 93;

fn last_err() -> String {
    std::io::Error::last_os_error().to_string()
}

/// Make `/proc/<pid>` agree with the pid namespace `seccomp_notif.pid` is reported
/// in. The documented run recipe uses `unshare --mount --pid --fork`, which puts
/// us in a NEW pid namespace but leaves the HOST `/proc` mounted — so a
/// namespace-local `notif.pid` would index the wrong host process, and the
/// supervisor's `/proc/<pid>/{cwd,fd}` canonicalization reads would be bogus.
/// Remounting `/proc` here (we hold CAP_SYS_ADMIN in the new mount+user ns) makes
/// procfs reflect the new pid ns, so `notif.pid` ↔ `/proc/<pid>` line up — which is
/// the natural state of a REAL deployment (supervisor shares the tracee's pid ns +
/// `/proc`). Best-effort: on a kernel/env where this isn't needed (or not a new pid
/// ns), a remount failure is harmless and ignored. The CANONICALIZATION tests need
/// it because they assert on `/proc`-resolved relative/dirfd paths.
fn ensure_proc_matches_pidns() {
    // SAFETY: mount(2) of a fresh procfs over /proc; requires CAP_SYS_ADMIN in the
    // mount namespace (held in the userns). Args are constant NUL-terminated strings.
    let src = b"proc\0";
    let target = b"/proc\0";
    let fstype = b"proc\0";
    let _ = unsafe {
        libc::mount(
            src.as_ptr() as *const libc::c_char,
            target.as_ptr() as *const libc::c_char,
            fstype.as_ptr() as *const libc::c_char,
            0,
            std::ptr::null(),
        )
    };
}

fn socketpair() -> (RawFd, RawFd) {
    let mut fds = [0 as RawFd; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "socketpair: {}", last_err());
    (fds[0], fds[1])
}

fn pipe() -> (RawFd, RawFd) {
    let mut fds = [0 as RawFd; 2];
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "pipe: {}", last_err());
    (fds[0], fds[1])
}

/// Reap a child; return its exit code (None if signalled).
fn reap(pid: i32) -> Option<i32> {
    if in_test_process() {
        return reap_within(pid, wait_limit(), "waiting for the tracee").code();
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if libc::WIFEXITED(status) {
        Some(libc::WEXITSTATUS(status))
    } else {
        None
    }
}

/// Send a single fd over a unix socket via SCM_RIGHTS.
fn send_fd(sock: RawFd, fd: RawFd) -> std::io::Result<()> {
    let mut dummy: u8 = 0;
    let mut iov = libc::iovec {
        iov_base: &mut dummy as *mut u8 as *mut libc::c_void,
        iov_len: 1,
    };
    // Control buffer big enough for one fd.
    let mut cmsg_buf = [0u8; 32];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len();

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            &fd as *const RawFd as *const u8,
            libc::CMSG_DATA(cmsg),
            std::mem::size_of::<RawFd>(),
        );
        msg.msg_controllen = (*cmsg).cmsg_len as _;
        let n = libc::sendmsg(sock, &msg, 0);
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Receive a single fd over a unix socket via SCM_RIGHTS.
fn recv_fd(sock: RawFd) -> std::io::Result<RawFd> {
    let mut dummy: u8 = 0;
    let mut iov = libc::iovec {
        iov_base: &mut dummy as *mut u8 as *mut libc::c_void,
        iov_len: 1,
    };
    let mut cmsg_buf = [0u8; 32];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len();

    unsafe {
        let n = libc::recvmsg(sock, &mut msg, 0);
        if n <= 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("recvmsg returned {n}: {}", last_err()),
            ));
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null()
            || (*cmsg).cmsg_level != libc::SOL_SOCKET
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "no SCM_RIGHTS control message",
            ));
        }
        let mut fd: RawFd = -1;
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(cmsg),
            &mut fd as *mut RawFd as *mut u8,
            std::mem::size_of::<RawFd>(),
        );
        Ok(fd)
    }
}

/// Minimal self-cleaning temp dir (avoids a dev-dep on `tempfile`).
struct TempDir {
    path: String,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let base = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
        let uniq = format!(
            "{base}/{prefix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        std::fs::create_dir_all(&uniq).unwrap();
        TempDir { path: uniq }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
