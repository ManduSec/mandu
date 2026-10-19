//! mandu-net-guard — the WHOLE-AGENT connect-guard wrap (kernel feature).
//!
//! ── What it is ────────────────────────────────────────────────────────────────
//! The IP/domain-aware companion to `mandu-landlock-apply --net-only` (which is
//! PORT-only). A launcher shim prepends it as the OUTERMOST net wrap:
//!
//!   mandu-net-guard --allow tcp:127.0.0.1:8788 --allow api.anthropic.com:443 \
//!       -- mandu-landlock-apply --net-only ... -- <agent argv>
//!
//! It forks the agent tree under a seccomp `connect(2)` user-notification trap and
//! stays alive as the SUPERVISOR (parent). Every `connect` in the tree is decided
//! against the `--allow` list by DESTINATION (IP / CIDR / resolved hostname ×
//! port): a match is connected on the tracee's behalf from the supervisor
//! (TOCTOU-safe, and — because the supervisor is OUTSIDE the inner Landlock port
//! wrap — able to reach an allowed destination even under `--landlock-net-strict`);
//! everything else gets `-EACCES`. A `--deny <spec>` (same syntax, repeatable)
//! refuses its destinations before any `--allow` is consulted, so a deny beats
//! the `tcp:*:443` fallback (an agent's upload hosts, launcher upload-deny.ts).
//! Non-INET connects (the arbiter's AF_UNIX
//! socket) and connects from a nested different-netns box pass through untouched.
//!
//! ── Why it is a fork supervisor, not a seccomp attach ─────────────────────────
//! The seccomp listener must be installed on the TRACEE and its fd handed to a
//! surviving supervisor; boxing after the fact is impossible. So the bin:
//!   1. socketpair();
//!   2. fork();
//!   3. CHILD: no_new_privs + install the connect listener, name the
//!      listener fd to the parent (`hand_listener`: by number, which the
//!      parent copies with pidfd_getfd, since the filter traps sendmsg), then
//!      execvp the rest of argv (which is the landlock applier → the agent).
//!      The seccomp filter survives execve.
//!   4. PARENT (supervisor): receive the listener fd, run the guard loop, reap the
//!      child, and mirror its exit status.
//!
//! ── Privilege + degrade ───────────────────────────────────────────────────────
//! UNPRIVILEGED: seccomp NEW_LISTENER needs only `no_new_privs` (NOT
//! CAP_SYS_ADMIN / a userns / root — confirmed as a plain uid), and pidfd_getfd
//! works parent→child unprivileged. The floor is kernel version: ≥ 5.6 for the
//! supervisor-connect enactment (below that an allowed connect degrades to a
//! CONTINUE, documented). `--skip-unsupported` is the cooperative degrade for the
//! default-on launcher wrap: if seccomp NEW_LISTENER is unavailable it execs the
//! target DIRECTLY (unguarded) rather than failing a live agent — the inner
//! Landlock port wrap and the netns/proxy stay whatever boundary they were.
//! Without `--skip-unsupported` a setup failure is FAIL-CLOSED (exit 71, target
//! NOT run) — the caller promised the guard.
//!
//! Exit codes mirror the crate convention: 71 setup fail (fail-closed), 78 usage,
//! 126 exec fail; otherwise the child's exit status is propagated verbatim, and
//! a child a signal killed is 128 + the signal, as a shell reports it.
//!
//! `Mandu-new`.

#![cfg(all(feature = "kernel", target_os = "linux"))]

use std::os::unix::io::RawFd;
use std::process::exit;
use std::sync::Arc;

use net_supervisor::guard::{parse_rules, GuardPolicy};
use net_supervisor::guard_kernel::{
    hand_listener, install_guard_filter_self, receive_listener, run_guard_supervisor, CachingResolver, FilterTraps,
    GuardConfig,
};

const EXIT_SETUP: i32 = 71;
const EXIT_USAGE: i32 = 78;
const EXIT_EXEC: i32 = 126;
/// Distinct child exit used ONLY for the internal seccomp-unavailable handshake
/// (so the parent can distinguish "degrade" from a real setup failure). Never
/// leaks as a final status: the parent maps it to a direct exec or fail-closed.
const CHILD_NO_SECCOMP: i32 = 91;
const CHILD_SETUP_FAIL: i32 = 92;

fn die_usage(msg: &str) -> ! {
    eprintln!("mandu-net-guard: {msg}");
    eprintln!(
        "usage: mandu-net-guard [--allow <[proto:]host:port>]... [--deny <[proto:]host:port>]... [--skip-unsupported] -- <argv...>"
    );
    exit(EXIT_USAGE);
}

fn die_setup(msg: &str) -> ! {
    eprintln!("mandu-net-guard: {msg} (fail-closed; target NOT exec'd)");
    exit(EXIT_SETUP);
}

fn main() {
    let mut specs: Vec<String> = Vec::new();
    let mut deny_specs: Vec<String> = Vec::new();
    let mut skip_unsupported = false;
    let mut target: Option<Vec<String>> = None;
    let mut clean = net_supervisor::clean_host::CleanHostArgs::default();

    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match clean.take(&a, &mut || it.next()) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(e) => die_usage(&e),
        }
        match a.as_str() {
            "--allow" => match it.next() {
                Some(s) => specs.push(s),
                None => die_usage("--allow needs a spec"),
            },
            "--deny" => match it.next() {
                Some(s) => deny_specs.push(s),
                None => die_usage("--deny needs a spec"),
            },
            "--skip-unsupported" => skip_unsupported = true,
            "--" => {
                target = Some(it.collect());
                break;
            }
            other if other.starts_with("--allow=") => {
                specs.push(other["--allow=".len()..].to_string());
            }
            other if other.starts_with("--deny=") => {
                deny_specs.push(other["--deny=".len()..].to_string());
            }
            other => die_usage(&format!("unknown argument {other:?}")),
        }
    }

    let target = match target {
        Some(t) if !t.is_empty() => t,
        _ => die_usage("missing `-- <argv...>`"),
    };
    let clean = match clean.complete() {
        Ok(c) => c,
        Err(e) => die_usage(&e),
    };

    // Parse the allow-list up front (fail-closed on a bad spec — a launcher bug
    // must not silently run the agent unguarded).
    let rules = match parse_rules(&specs) {
        Ok(r) => r,
        Err(e) => die_setup(&format!("bad --allow spec: {e}")),
    };
    // The always-denied destinations (cloud metadata, link-local) stay denied
    // unless the operator opted out for this launch (guard.rs ALLOW_METADATA_ENV).
    let allow_metadata = std::env::var(net_supervisor::guard::ALLOW_METADATA_ENV).map(|v| v == "1").unwrap_or(false);
    // The deny rules (an agent's upload hosts, launcher upload-deny.ts) beat
    // every allow; a bad one fails closed like a bad allow.
    let deny = match parse_rules(&deny_specs) {
        Ok(r) => r,
        Err(e) => die_setup(&format!("bad --deny spec: {e}")),
    };
    let policy = Arc::new(GuardPolicy::new(rules).with_deny(deny).with_metadata_allowed(allow_metadata));

    // ── fork: child installs the trap + execs the target; parent supervises. ──
    let (sup_sock, child_sock) = socketpair();
    // SAFETY: fork in a program holding no locks across the boundary; the child
    // only does async-signal-safe-enough setup (seccomp install + sendmsg + execvp).
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        die_setup("fork failed");
    }

    if pid == 0 {
        // ── CHILD (tracee) ────────────────────────────────────────────────────
        close_fd(sup_sock);
        // SAFETY: getppid has no failure mode; the parent is the guard.
        let guard = unsafe { libc::getppid() };
        // rootless-confinement §12.2: signals aimed at the guard are checked.
        let traps = FilterTraps { guard_pid: guard as u32, ..FilterTraps::from_env() };
        let listener = match install_guard_filter_self(traps) {
            Ok(fd) => fd,
            Err(_) => unsafe { libc::_exit(CHILD_NO_SECCOMP) },
        };
        // By number (write, which the filter does not trap): the filter traps
        // sendmsg now, and its supervisor is the one waiting for this fd.
        if !hand_listener(child_sock, listener, !traps.no_sends) {
            close_fd(listener);
            unsafe { libc::_exit(CHILD_SETUP_FAIL) };
        }
        // The guard holds its copy now. Closed here, not at the exec: under
        // a secret policy `exit_group` is trapped (exec-routing.md §7.5,
        // 2026-10-02), and a child that exits below because the guard is
        // gone must not wait on a listener only it still holds (the call
        // then fails ENOSYS and glibc's `_exit` falls back to `exit`).
        close_fd(listener);
        // Wait for the guard to be ready (out of this process group, see
        // `harden_guard`) before the target runs; EOF = the guard is gone.
        let mut go = 0u8;
        // SAFETY: a one-byte read into a local.
        if unsafe { libc::read(child_sock, &mut go as *mut u8 as *mut libc::c_void, 1) } != 1 {
            unsafe { libc::_exit(CHILD_SETUP_FAIL) };
        }
        close_fd(child_sock);
        // §12.2: if the guard dies, the agent's top process dies with it
        // rather than live on with every trapped syscall failing ENOSYS.
        // SAFETY: prctl with integer arguments.
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong, 0, 0, 0) };
        if unsafe { libc::getppid() } != guard {
            unsafe { libc::_exit(CHILD_SETUP_FAIL) };
        }
        // The listener fd's job is done in the child; the seccomp FILTER persists
        // across execve regardless of this fd. Exec the rest of the argv (the
        // Landlock applier → the agent). Only returns on failure.
        let code = net_supervisor_exec(&target);
        unsafe { libc::_exit(code) };
    }

    // ── PARENT (supervisor) ─────────────────────────────────────────────────────
    // The guard creates files for the tree it serves (an O_CREAT open it
    // performs, confidentiality-plan-10 §4.1a) with the TRACEE's umask already
    // applied to the mode; its own must not narrow it again. Set only here,
    // after the fork: the agent keeps the umask it was launched with.
    // SAFETY: umask has no failure mode.
    unsafe { libc::umask(0) };
    close_fd(child_sock);
    let listener = match receive_listener(sup_sock) {
        Ok((fd, _)) => fd,
        Err(_) => {
            // The child could not install seccomp / hand off the fd. Reap it and
            // decide: degrade (re-exec the target unguarded) or fail-closed.
            let code = reap(pid);
            close_fd(sup_sock);
            if code == Some(CHILD_NO_SECCOMP) {
                if skip_unsupported {
                    eprintln!(
                        "mandu-net-guard: seccomp connect-trap unavailable — proceeding \
                         WITHOUT the IP-aware guard (the inner Landlock port wrap / netns stay \
                         the boundary). Re-run under an unprivileged userns for the guard."
                    );
                    let code = net_supervisor_exec(&target);
                    exit(code);
                }
                die_setup(
                    "seccomp connect-trap unavailable and --skip-unsupported not set \
                     (needs no_new_privs + kernel >= 5.0 with CONFIG_SECCOMP_USER_NOTIFICATION)",
                );
            }
            die_setup(&format!("child failed to hand off the listener fd (exit {code:?})"));
        }
    };
    harden_guard(pid);
    // Finding 1: the guard is its tree's subreaper, so a server the tree
    // daemonizes (double fork, setsid) keeps the guard as an ancestor and its
    // socket counts as the tree's own for the Unix socket allow-list. The
    // orphans it adopts are reaped here; the agent's own child is left for
    // `reap` (its exit status is the guard's).
    // SAFETY: prctl with integer arguments.
    let subreaper = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } == 0;
    if subreaper {
        spawn_orphan_reaper(pid);
    }
    // The status file's directory is opened now, every component checked,
    // and both records are written in that descriptor (safe_write: the scope
    // dir is the agent's to write while it runs, and a link it plants there
    // must not take the `exited` record into another file).
    let status_file = std::env::var(STATUS_ENV).ok().filter(|p| !p.is_empty()).and_then(|p| match net_supervisor::safe_write::DirFile::open(&p) {
        Ok(f) => Some(f),
        Err(e) => {
            net_supervisor::diag!("mandu-net-guard: the status file {p} is not written: {e}");
            None
        }
    });
    // SAFETY: getpid has no failure mode.
    let me = unsafe { libc::getpid() };
    if let Some(f) = status_file.as_ref() {
        write_status(f, &format!("supervising {me} {pid}\n"));
    }
    // exec-routing.md §8.5.3: the clean box's reporter. The token is
    // claimed BEFORE the agent runs (a racer that claimed first makes this
    // claim revoke the reporter: then nothing is hosted and the box falls
    // back to its ordinary run).
    let arbiter_sock = std::env::var("MANDU_ARBITER_SOCK").unwrap_or_default();
    let clean_host = clean.and_then(|c| {
        if arbiter_sock.is_empty() {
            net_supervisor::diag!("mandu-net-guard: no MANDU_ARBITER_SOCK, so the clean box is not hosted (its commands run in the ordinary box)");
            return None;
        }
        match net_supervisor::clean_host_kernel::claim_and_bind(&c, &arbiter_sock) {
            Ok((token, listener)) => Some((c, token, listener)),
            Err(e) => {
                net_supervisor::diag!("mandu-net-guard: the clean box is not hosted: {e} (its commands run in the ordinary box, output masked)");
                None
            }
        }
    });
    // SAFETY: a one-byte write: the child may run the target now.
    if unsafe { libc::write(sup_sock, b"g".as_ptr() as *const libc::c_void, 1) } != 1 {
        die_setup("the child is gone before the target ran");
    }
    close_fd(sup_sock);

    // Run the guard loop until the tracee tree exits (RECV drains), THEN reap and
    // mirror the child's status. The loop runs on this (parent) thread; it returns
    // Ok when the listener drains after the tracee tree is gone.
    let mut cfg = GuardConfig::new(policy, Arc::new(CachingResolver::default()));
    // exec-routing.md §7.5 (2026-10-01): the launch's own proxy ports, the
    // only loopback a process holding a secret reaches without a binding.
    // Read before the tree runs would be better, but a bad list is a
    // launcher bug that must not widen anything: the guard keeps serving
    // with NO exception (fail-closed) and says so.
    if let Ok(v) = std::env::var(net_supervisor::send_guard::PROXY_PORTS_ENV) {
        match net_supervisor::send_guard::parse_proxy_ports(&v) {
            Ok(ports) => cfg.proxy_ports = ports,
            Err(e) => net_supervisor::diag!("mandu-net-guard: {e}: no session-proxy exception for processes holding a secret"),
        }
    }
    // supported-agents.md §2.3.1: the agent's private server (an OpenCode 2
    // launch): its ephemeral loopback bind and its client's connect to it.
    // The filter's bind trap was set from the same variable (FilterTraps::
    // from_env). A malformed value is off: nothing more is admitted.
    cfg.own_server = net_supervisor::guard_kernel::own_server_exe_requested();
    // The child's own restrictions are the launch's wrap chain (the whole-
    // agent port wrap): the allow list supersedes them for the connects the
    // guard performs; a sandbox nested deeper is honored (landlock_mirror).
    cfg.landlock.set_launch_root(pid);
    // Plan 10 §4.1a, the cost of the mirror (2026-10-05): when the target
    // this guard exec'd is the net-only wrap (`launch_wrap`), the layer it
    // installs governs no file, and an open under it alone needs no mirror.
    // Identified by the file the argv names, as the guard knows it now.
    if let Some(wrap) = net_supervisor::launch_wrap::LaunchWrap::of(&target, |p| {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()))
    }) {
        cfg.landlock.set_launch_wrap(wrap);
    }
    cfg.tree_roots = vec![pid, me];
    // exec-routing.md §7.5 (2026-10-02): an orphan the guard adopts is
    // judged as one (`TaintedSet::holds_or_inherits`).
    if subreaper {
        if let Some(k) = mandu_arbiter::proc::proc_key_for_pid(me) {
            cfg.tainted.add_reaper(&k);
        }
    }
    // WSL: refuse the Windows interop door for the whole agent tree (the
    // interop socket, AF_VSOCK). Probed here, never passed in: a launcher that
    // forgot it cannot leave the door open. None on any other host.
    // exec-routing.md §4.2: the command box's socket allow-list, served here
    // when the launch runs the box (the kernel allows one listener per chain).
    if net_supervisor::guard_kernel::box_sockets_requested() {
        cfg.box_sockets = Some(Arc::new(fs_supervisor::box_sockets::BoxSockets::new()));
    }
    cfg.wsl = net_supervisor::guard::WslGuard::from_signals(&mandu_arbiter::wsl::probe_host(), |p| {
        std::fs::canonicalize(p).ok().and_then(|c| c.to_str().map(String::from))
    })
    .map(|w| {
        use std::os::unix::fs::MetadataExt;
        let id = w.interop_env.as_deref().and_then(|p| std::fs::metadata(p).ok()).map(|m| (m.dev(), m.ino()));
        w.with_interop_identity(id)
    });
    // Reap the child on a side thread so the loop and the wait proceed together;
    // the loop returns when RECV sees the tree gone.
    // Plan 10 §4.1: the registered secrets. A file that cannot be read is a
    // launcher bug, not a reason to run blind: say so and continue without
    // the reader half (the twin bind still masks; §11.7). Loaded before the
    // report channel is chosen: its `unixDeny` names the human-plane
    // directories the choice checks the human socket against (§5.2).
    let arbiter_sock_env = std::env::var("MANDU_ARBITER_SOCK").ok().filter(|s| !s.is_empty());
    if let Ok(p) = std::env::var(net_supervisor::guard_kernel::SECRETS_ENV) {
        if !p.is_empty() {
            match net_supervisor::secret_open::SecretIndex::load(std::path::Path::new(&p)) {
                Ok(idx) if !idx.is_empty() => {
                    if arbiter_sock_env.is_none() {
                        net_supervisor::diag!("mandu-net-guard: secret policy given but no MANDU_ARBITER_SOCK — readers cannot be decided; every open of a registered secret gets its twin");
                    }
                    // 2026-10-16 (`inode_pins`): hold each registered
                    // protected file by its inode before the first trapped
                    // call is answered (the workers start below), so a
                    // folder moved above one never takes its identity away.
                    let mut lim = libc::rlimit { rlim_cur: 1024, rlim_max: 1024 };
                    // SAFETY: getrlimit into a local.
                    unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) };
                    let cap = std::env::var(net_supervisor::inode_pins::PIN_MAX_ENV).ok().and_then(|v| v.parse::<usize>().ok());
                    let (held, unpinned) = idx.enable_pins(net_supervisor::inode_pins::budget(lim.rlim_cur as u64, cap));
                    if unpinned > 0 {
                        net_supervisor::diag!(
                            "mandu-net-guard: {unpinned} protected file(s) could not be held by their inode ({held} held): a folder above one cannot be renamed in this session"
                        );
                    }
                    cfg.secrets = Some(Arc::new(idx));
                }
                Ok(_) => {}
                Err(e) => eprintln!("mandu-net-guard: secret policy {p} unreadable ({e}) — proceeding without the reader half"),
            }
        }
    }
    // exec-routing.md §4.3 (2026-10-18): the Unix allow-list's bind record,
    // where every bind of the tree reaches this guard (the filter traps
    // `bind`; the tree has not run a trapped call yet, the loop below answers
    // the first) and the guard can copy a socket to perform it (`no_sends`
    // is the kernel without `pidfd_getfd`). Elsewhere the probe judges.
    let traps = FilterTraps::from_env();
    if cfg.secrets.as_ref().is_some_and(|i| i.unix_policy.is_some()) && traps.traps_bind() && !traps.no_sends {
        cfg.unix_binds = Some(Arc::new(net_supervisor::unix_owner::BindRecord::new(net_supervisor::unix_owner::BindRecord::DEFAULT_CAP)));
    }
    // The guard's arbiter client: every security report (plan 13 D9: secret
    // opens, protected writes, lineage, taint, flows, refusals, the session
    // holder's ask, guardAttach) and the observability events. The supervisor
    // lives OUTSIDE the seccomp filter + all sandboxes, so its own arbiter
    // AF_UNIX connect is unfiltered. `MANDU_NET_GUARD_EVENTS=0` turns off the
    // EVENTS only (the client's `emit`); before 2026-10-17 it dropped the
    // whole client, every report with it (arbiter-human-plane.md §5.3).
    let events_off = std::env::var_os("MANDU_NET_GUARD_EVENTS").map(|v| v == "0").unwrap_or(false);
    // SAFETY: geteuid has no failure mode.
    let uid = unsafe { libc::geteuid() };
    let walled = cfg.secrets.as_ref().map(|i| i.unix_deny.clone()).unwrap_or_default();
    // arbiter-human-plane.md §5.2: the data socket when the reports start
    // there (no human plane at start), for the looker below.
    let mut reporting_on_data: Option<String> = None;
    if let Some(sock) = arbiter_sock_env.clone() {
        // Plan 13 §3 D9: the reports go to the human-plane socket, the one
        // channel the arbiter believes them on (report_channel.rs). Chosen
        // before the guard loop serves its first notification (every trapped
        // call of the agent waits for it), under the same checks as a later
        // move (§5.2): named by the data socket's `hello` (or the test rig's
        // MANDU_ARBITER_HUMAN_SOCK), in a directory this guard walls off,
        // private and ours, answering `channel: human` for the same instance,
        // and served by the process that serves the data socket, outside
        // this guard's tree. A guard that is not its tree's subreaper cannot
        // tell such a process apart: it starts on the data socket.
        let env_human = std::env::var(mandu_arbiter::client::HUMAN_SOCK_ENV).ok();
        let channel = if subreaper {
            net_supervisor::report_channel::choose(
                &sock,
                env_human.as_deref(),
                &walled,
                uid,
                net_supervisor::report_channel::ask_socket,
                |p| net_supervisor::report_channel::private_socket_place(p, uid),
                |pid| net_supervisor::report_channel::in_tree_of(pid, me, net_supervisor::secret_open::parent_pid_of),
            )
        } else {
            net_supervisor::report_channel::ReportChannel::Data { sock: sock.clone(), why: "not the tree's subreaper: a socket the agent serves cannot be told apart".into() }
        };
        if let net_supervisor::report_channel::ReportChannel::Data { why, .. } = &channel {
            if cfg.secrets.is_some() {
                net_supervisor::diag!(
                    "mandu-net-guard: reporting on the data socket ({why}): the arbiter takes every report as a claim, \
                     so every open of a registered secret gets its twin (plan 13 D9, fail-closed) until the human plane is up"
                );
            }
            reporting_on_data = Some(sock.clone());
        }
        cfg.emitter = Some(std::sync::Arc::new(std::sync::Mutex::new(
            net_supervisor::report_channel::client_for(&channel, &sock).with_events(!events_off),
        )));
        cfg.session_id = net_supervisor::events::guard_session_id(|k| std::env::var(k).ok());
    }
    // confidentiality.md §4, "Without the guard": this guard holds the
    // session's processes, so a HIGH session's command card may say an
    // allowed run is held. Best-effort: unannounced, the card understates
    // the hold. (On the data socket the arbiter ignores it: the looker
    // announces again once on the human plane.)
    if let (Some(c), Some(session)) = (cfg.emitter.as_ref(), cfg.secrets.as_ref().and_then(|i| i.session.clone())) {
        if let Ok(mut client) = c.lock() {
            if let Err(e) = client.guard_attach(&mandu_arbiter::protocol::GuardAttachArgs { session_key: session }) {
                net_supervisor::diag!("mandu-net-guard: guardAttach failed ({e}): a HIGH session's command card will say an allowed run is not held");
            }
        }
    }
    // arbiter-human-plane.md §5.2: a guard that started on the data socket
    // keeps looking for the human plane and moves its reports there once it
    // is up and proven the arbiter's (report_channel::decide_upgrade), under
    // the start's checks. Once, and never back.
    if let (Some(data_sock), Some(emitter)) = (reporting_on_data, cfg.emitter.clone()) {
        if walled.is_empty() {
            if cfg.secrets.is_some() {
                net_supervisor::diag!("mandu-net-guard: no human-plane directory is walled off here (no unixDeny), so the reports stay on the data socket for the session");
            }
        } else if !subreaper {
            net_supervisor::diag!("mandu-net-guard: not the tree's subreaper, so a socket the agent serves cannot be told apart: the reports stay on the data socket for the session");
        } else {
            let ds = data_sock.clone();
            let look = move || {
                net_supervisor::report_channel::decide_upgrade(
                    &ds,
                    &walled,
                    uid,
                    net_supervisor::report_channel::ask_socket,
                    |p| net_supervisor::report_channel::private_socket_place(p, uid),
                    |pid| net_supervisor::report_channel::in_tree_of(pid, me, net_supervisor::secret_open::parent_pid_of),
                )
            };
            // At start `guardAttach` went to the data socket, which ignores
            // it: announce the guard again, first thing on the human plane.
            let session = cfg.secrets.as_ref().and_then(|i| i.session.clone());
            let announce = move |client: &mut mandu_arbiter::ArbiterClient| {
                if let Some(session_key) = session {
                    if let Err(e) = client.guard_attach(&mandu_arbiter::protocol::GuardAttachArgs { session_key }) {
                        net_supervisor::diag!("mandu-net-guard: guardAttach on the human plane failed ({e})");
                    }
                }
            };
            if let Err(e) = net_supervisor::report_channel::spawn_upgrader(emitter, data_sock, look, announce, |m| net_supervisor::diag!("mandu-net-guard: {m}")) {
                net_supervisor::diag!("mandu-net-guard: cannot look for the human plane ({e}): the reports stay on the data socket");
            }
        }
    }
    if let Some((c, token, sock)) = clean_host {
        // The hosted child's filter: the agent's traps, this guard's pid.
        let traps = FilterTraps { guard_pid: me as u32, ..FilterTraps::from_env() };
        let host = net_supervisor::clean_host_kernel::CleanHost::new(c, arbiter_sock.clone(), token, traps, cfg.tree_roots.clone());
        net_supervisor::clean_host_kernel::serve(Arc::new(host), sock, cfg.clone());
    }
    let _ = run_guard_supervisor(listener, cfg);
    if net_supervisor::guard_kernel::trap_open_requested() {
        net_supervisor::diag!(
            "mandu-net-guard: [spike §7.1] trapped {} open(s)",
            net_supervisor::guard_kernel::OPEN_TRAPS.load(std::sync::atomic::Ordering::Relaxed)
        );
    }
    let code = reap(pid).unwrap_or(EXIT_EXEC);
    // Plan 10 §4.1a: which path the tree's reading opens took (a test's
    // proof; best-effort, decides nothing).
    if let Ok(p) = std::env::var(net_supervisor::guard_kernel::OPEN_STATS_ENV) {
        if !p.is_empty() {
            use net_supervisor::guard_kernel::{EXECS_HELD_HERE, EXECS_HELD_ON_THREAD, EXEC_HELD_NS, OPENS_MIRRORED, OPENS_UNDER_WRAP};
            use net_supervisor::landlock_mirror::{MIRROR_DOMAINS_BUILT, MIRROR_THREADS_PEAK};
            let load = |c: &std::sync::atomic::AtomicU64| c.load(std::sync::atomic::Ordering::Relaxed);
            let count = |c: &std::sync::atomic::AtomicUsize| c.load(std::sync::atomic::Ordering::Relaxed);
            // Plan 10 §4.1a, the mirror's records over a session: how many
            // mirror threads were ever alive at once, of how many domains.
            let _ = net_supervisor::safe_write::replace_file(
                &p,
                format!(
                    "wrap_opens {}\nmirrored_opens {}\nmirror_domains {}\nmirror_threads_peak {}\nexecs_held_here {}\nexecs_held_on_thread {}\nexec_held_us {}\n",
                    load(&OPENS_UNDER_WRAP),
                    load(&OPENS_MIRRORED),
                    count(&MIRROR_DOMAINS_BUILT),
                    count(&MIRROR_THREADS_PEAK),
                    load(&EXECS_HELD_HERE),
                    load(&EXECS_HELD_ON_THREAD),
                    load(&EXEC_HELD_NS) / 1000
                )
                .as_bytes(),
            );
        }
    }
    if let Some(f) = status_file.as_ref() {
        write_status(f, &format!("exited {code}\n"));
    }
    exit(code);
}

/// The launcher's record of this guard (rootless-confinement §12.2): the
/// guard writes `supervising <guard pid> <child pid>` once it serves the tree
/// and `exited <code>` when the tree is done. A file left at `supervising`
/// means the guard died first; the launcher then ends the session.
const STATUS_ENV: &str = "MANDU_NET_GUARD_STATUS";

/// Best-effort: a fresh sibling renamed over, so a reader never sees half,
/// in the directory opened at the start, never through a link
/// (`safe_write::DirFile::replace`).
fn write_status(f: &net_supervisor::safe_write::DirFile, line: &str) {
    let _ = f.replace(line.as_bytes());
}

/// The child to forward termination requests to (0 = none yet).
static CHILD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

extern "C" fn forward_signal(sig: libc::c_int, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    // Sent by a process (si_code <= 0: kill, sigqueue, tkill): pass it to the
    // agent, which decides how to end; the guard serves until the tree exits.
    // Raised by the kernel (a terminal's ^C or hangup) it reached the agent's
    // foreground group already.
    // SAFETY: the kernel hands a valid siginfo to an SA_SIGINFO handler.
    let code = unsafe { (*info).si_code };
    let child = CHILD.load(std::sync::atomic::Ordering::Relaxed);
    if code <= 0 && child > 0 {
        // SAFETY: kill is async-signal-safe.
        unsafe { libc::kill(child, sig) };
    }
}

/// rootless-confinement §12.2: the agent tree runs as this guard's uid, so the
/// guard makes itself hard for it to stop. Its own process group (a group
/// signal from the agent misses it; when the guard already leads a group,
/// the filter refuses `kill(0)` from that group instead); not dumpable (no
/// ptrace, pidfd_getfd, /proc/<pid>/mem or fd/ from the agent, whatever
/// Yama's setting); termination requests forwarded to the agent; every
/// other catchable fatal or stopping signal ignored, glibc's reserved 32
/// included (a SIGIO owner set to the guard kills nothing). SIGKILL and
/// SIGSTOP are the filter's (guard_signals).
fn harden_guard(child: i32) {
    CHILD.store(child, std::sync::atomic::Ordering::Relaxed);
    // SAFETY: setpgid / prctl / sigaction with valid arguments; failures
    // leave the defaults (setpgid fails for a session leader, which leads its
    // group already).
    unsafe {
        libc::setpgid(0, 0);
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        let mut fwd: libc::sigaction = std::mem::zeroed();
        fwd.sa_sigaction = forward_signal as usize;
        fwd.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
        libc::sigemptyset(&mut fwd.sa_mask);
        for s in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGQUIT] {
            libc::sigaction(s, &fwd, std::ptr::null_mut());
        }
        let keep = [
            libc::SIGKILL, libc::SIGSTOP, libc::SIGCHLD, libc::SIGCONT, libc::SIGWINCH, libc::SIGURG,
            libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGQUIT,
        ];
        for s in (1..32).chain(libc::SIGRTMIN()..=libc::SIGRTMAX()) {
            if !keep.contains(&s) {
                libc::signal(s, libc::SIG_IGN);
            }
        }
        // Signal 32 is glibc's reserved SIGCANCEL, left at its fatal default
        // until a pthread_cancel (the guard never cancels a thread); glibc's
        // sigaction refuses it, so it is ignored through the raw syscall.
        // (33 carries glibc's own handler, which drops a foreign sender's.)
        #[repr(C)]
        struct KernelSigaction {
            handler: usize,
            flags: libc::c_ulong,
            restorer: usize,
            mask: u64,
        }
        let ign = KernelSigaction { handler: libc::SIG_IGN, flags: 0, restorer: 0, mask: 0 };
        libc::syscall(libc::SYS_rt_sigaction, 32 as libc::c_long, &ign as *const KernelSigaction, std::ptr::null_mut::<KernelSigaction>(), 8 as libc::c_long);
    }
}

/// execvp the target argv, inheriting stdio. Only returns on failure (exit 126).
fn net_supervisor_exec(argv: &[String]) -> i32 {
    use std::ffi::CString;
    let cargs: Vec<CString> = argv
        .iter()
        .map(|a| CString::new(a.as_str()).unwrap_or_else(|_| CString::new("").unwrap()))
        .collect();
    let mut ptrs: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: execvp with a NULL-terminated argv; returns only on failure.
    unsafe {
        libc::execvp(ptrs[0], ptrs.as_ptr());
    }
    eprintln!("mandu-net-guard: exec of {:?} failed", argv.first());
    EXIT_EXEC
}

// ── fd / process plumbing (mirrors fs-supervisor's kernel_integration harness) ──

fn close_fd(fd: RawFd) {
    unsafe {
        libc::close(fd);
    }
}

fn socketpair() -> (RawFd, RawFd) {
    let mut fds = [0 as RawFd; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if rc != 0 {
        die_setup("socketpair failed");
    }
    (fds[0], fds[1])
}

/// Reap the orphans the guard adopts as subreaper, never `child` (whose
/// status `reap` reads). A peek (`WNOWAIT`) names the next waitable child
/// first; once that is `child`, nothing behind it is looked at until the
/// guard itself exits (the tree is ending then anyway).
fn spawn_orphan_reaper(child: i32) {
    let _ = std::thread::Builder::new().name("guard-reaper".into()).spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        loop {
            // SAFETY: waitid into a zeroed siginfo.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let rc = unsafe { libc::waitid(libc::P_ALL, 0, &mut info, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT) };
            // SAFETY: si_pid of a siginfo waitid filled.
            let who = if rc == 0 { unsafe { info.si_pid() } } else { 0 };
            // A hosted clean box is waited for by the thread that runs it.
            if who <= 0 || who == child || net_supervisor::clean_host_kernel::owns_child(who) {
                break;
            }
            let mut status = 0;
            // SAFETY: reap exactly the adopted child the peek named.
            unsafe { libc::waitpid(who, &mut status, libc::WNOHANG) };
        }
    });
}

/// The child's exit code as a shell reports it: its own code, or 128 + the
/// signal that killed it (`child_status::shell_code`; a signal death was 126,
/// the exec-failure code, until 2026-10-07).
fn reap(pid: i32) -> Option<i32> {
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    net_supervisor::child_status::shell_code(status)
}
