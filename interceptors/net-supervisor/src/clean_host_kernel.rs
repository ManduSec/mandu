//! clean_host_kernel — the enactment of `clean_host` (exec-routing.md §8
//! §5.3): claim the reporter token, serve the clean-run socket, run each
//! request's box as a tree this guard supervises, report, answer.
//!
//! The hosted child gets the guard's filter the way the agent did: installed
//! in the child after the fork from a program built BEFORE it (nothing
//! allocates after the fork in this multithreaded process), its listener
//! handed back over a socketpair. Because `Command::spawn` returns only once
//! the child has exec'd, and a trapped exec waits for a supervisor, the
//! listener is received and served on a thread of its own that is already
//! waiting when the child starts. Every descriptor of the guard is closed on
//! exec in the child, the agent tree's listener included.
//! `Mandu-new`.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use mandu_arbiter::clean_run::{encode_reply_header, parse_request, CleanReply, CleanRequest, MAX_REQUEST, MAX_STREAM};
use mandu_arbiter::ArbiterClient;

use crate::clean_host::{box_argv, hosted_report, CleanHostConfig, EXIT_CLEAN_VOID};
use crate::guard_filter::FilterTraps;
use crate::guard_kernel::GuardConfig;

/// The hosted children this guard waits for itself: the orphan reaper (the
/// guard is its tree's subreaper) must leave them alone.
static OWN_CHILDREN: Mutex<Vec<i32>> = Mutex::new(Vec::new());

/// Is `pid` a hosted child this guard reaps itself?
pub fn owns_child(pid: i32) -> bool {
    OWN_CHILDREN.lock().map(|v| v.contains(&pid)).unwrap_or(false)
}

/// A claimed, bound clean host, ready to serve.
pub struct CleanHost {
    pub cfg: CleanHostConfig,
    pub arbiter_sock: String,
    token: String,
    /// The filter the hosted child installs: the agent's traps, the guard's
    /// own pid for the signal block.
    pub traps: FilterTraps,
    /// Who may ask: the agent tree's roots (`GuardConfig::tree_roots`).
    pub requester_roots: Vec<i32>,
}

/// Claim the session's reporter token and bind the socket. Called BEFORE
/// the agent starts (clean-reporters.ts: a racer that claimed first makes
/// this claim revoke the reporter, and then the guard hosts nothing).
pub fn claim_and_bind(cfg: &CleanHostConfig, arbiter_sock: &str) -> Result<(String, UnixListener), String> {
    let token = ArbiterClient::new(arbiter_sock)
        .claim_clean_reporter(&cfg.session)
        .map_err(|e| format!("the arbiter did not issue a reporter token ({e})"))?;
    let path = std::path::Path::new(&cfg.socket);
    if let Ok(m) = std::fs::symlink_metadata(path) {
        use std::os::unix::fs::FileTypeExt;
        if !m.file_type().is_socket() {
            return Err(format!("{} exists and is not a socket", cfg.socket));
        }
        let _ = std::fs::remove_file(path);
    }
    let listener = UnixListener::bind(path).map_err(|e| format!("cannot bind {}: {e}", cfg.socket))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    Ok((token, listener))
}

impl CleanHost {
    pub fn new(cfg: CleanHostConfig, arbiter_sock: String, token: String, traps: FilterTraps, requester_roots: Vec<i32>) -> Self {
        CleanHost { cfg, arbiter_sock, token, traps, requester_roots }
    }
}

/// Serve the socket on a thread of its own, one thread per connection.
pub fn serve(host: Arc<CleanHost>, listener: UnixListener, guard: GuardConfig) {
    let _ = std::thread::Builder::new().name("clean-host".into()).spawn(move || {
        for conn in listener.incoming() {
            let Ok(conn) = conn else { continue };
            let (host, guard) = (host.clone(), guard.clone());
            let _ = std::thread::Builder::new().name("clean-run".into()).spawn(move || handle(&host, conn, &guard));
        }
    });
}

/// The peer's pid, as this (host) pid namespace names it.
fn peer_pid(fd: RawFd) -> Option<i32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt into an owned ucred of the right size.
    let rc = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, &mut cred as *mut _ as *mut libc::c_void, &mut len) };
    (rc == 0 && cred.pid > 0).then_some(cred.pid)
}

fn void(conn: &mut UnixStream, reason: &str) {
    let _ = conn.write_all(&encode_reply_header(&CleanReply { completed: false, reason: reason.into(), ..Default::default() }));
}

fn handle(host: &CleanHost, mut conn: UnixStream, guard: &GuardConfig) {
    let Some(peer) = peer_pid(conn.as_raw_fd()) else { return };
    // Only the agent's tree asks, and never from inside a hosted run.
    let hosted: Vec<i32> = OWN_CHILDREN.lock().map(|v| v.clone()).unwrap_or_default();
    let parent = crate::secret_open::parent_pid_of;
    if !crate::secret_open::in_tree(peer, &host.requester_roots, parent) || crate::secret_open::in_tree(peer, &hosted, parent) {
        return void(&mut conn, "not a process of this guard's agent tree");
    }
    let mut line = Vec::new();
    let read = (&mut BufReader::new(&conn)).take(MAX_REQUEST as u64 + 1).read_until(b'\n', &mut line);
    if read.is_err() || line.last() != Some(&b'\n') {
        return; // a probe that connected and left, or an oversized line
    }
    line.pop();
    let req = match parse_request(&line) {
        Ok(r) => r,
        Err(e) => return void(&mut conn, &format!("request refused: {e}")),
    };
    let requester_key = mandu_arbiter::proc_key_for_pid(peer);
    let (reply, stdout, stderr) = run(host, guard, &req, requester_key);
    if conn.write_all(&encode_reply_header(&reply)).is_ok() && reply.completed {
        let _ = conn.write_all(&stdout);
        let _ = conn.write_all(&stderr);
    }
}

/// Run one request's box under this guard's supervision; on a completed
/// attempt, report and answer with the bytes.
fn run(host: &CleanHost, guard: &GuardConfig, req: &CleanRequest, requester_key: Option<String>) -> (CleanReply, Vec<u8>, Vec<u8>) {
    let voided = |reason: String| (CleanReply { completed: false, reason, ..Default::default() }, Vec::new(), Vec::new());
    let (status, stdout, stderr) = match spawn_supervised(host, guard, &box_argv(&host.cfg.box_bin, req)) {
        Ok(r) => r,
        Err(e) => return voided(format!("the hosted box did not run: {e}")),
    };
    if status != Some(0) {
        let why = if status == Some(EXIT_CLEAN_VOID) { "the clean attempt did not complete".to_string() } else { format!("the hosted box exited {status:?}") };
        return voided(why);
    }
    let sha = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&stdout).iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    let mut client = ArbiterClient::new(&host.arbiter_sock);
    let call_id = client
        .exec_decision_for(&mandu_arbiter::protocol::ExecDecisionForArgs { command: None, argv: Some(req.argv.clone()) })
        .ok()
        .and_then(|r| r.decision)
        // The store is keyed by command signature across sessions: another
        // session's decision is not this run's (its verdict would name this
        // session and could never upgrade there anyway).
        .filter(|d| d.session_key.as_deref().map_or(true, |s| s == host.cfg.session))
        .and_then(|d| d.call_id);
    let (clean, reason) = match call_id.as_deref() {
        Some(id) => match client.report_exec_clean_verdict_as_reporter(&hosted_report(id, requester_key, &sha, &host.cfg.session), &host.token) {
            Ok(v) => (v.clean, v.reason),
            Err(e) => (false, format!("report failed: {e}")),
        },
        None => (false, "no recorded decision names this command (no callId to report)".to_string()),
    };
    let reply = CleanReply { completed: true, stdout: stdout.len() as u64, stderr: stderr.len() as u64, call_id, clean, reason };
    (reply, stdout, stderr)
}

/// Read `fd` to EOF, at most `MAX_STREAM` bytes; `None` past the cap.
fn drain(mut r: impl Read) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    (&mut r).take(MAX_STREAM + 1).read_to_end(&mut out).ok()?;
    (out.len() as u64 <= MAX_STREAM).then_some(out)
}

/// Spawn `argv` with the launcher's environment, stdin `/dev/null`, under a
/// fresh instance of this guard's filter served on a thread of its own.
/// Returns the exit code (None: killed by a signal) and the captured bytes.
fn spawn_supervised(host: &CleanHost, guard: &GuardConfig, argv: &[String]) -> Result<(Option<i32>, Vec<u8>, Vec<u8>), String> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: socketpair into an owned array.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr()) } != 0 {
        return Err("socketpair failed".into());
    }
    // SAFETY: both fds are fresh and owned here.
    let (ours, theirs) = unsafe { (UnixStream::from_raw_fd(fds[0]), UnixStream::from_raw_fd(fds[1])) };
    let child_sock = theirs.as_raw_fd();

    // The supervisor thread waits for the listener before the child exists.
    let mut sub = guard.clone();
    sub.landlock = Arc::new(crate::landlock_mirror::LandlockMirror::new());
    let supervisor = std::thread::Builder::new().name("clean-supervise".into()).spawn(move || {
        let Ok((listener, pid)) = crate::guard_kernel::receive_listener(ours.as_raw_fd()) else { return };
        sub.tree_roots = vec![pid];
        let _ = crate::guard_kernel::run_guard_supervisor(listener, sub);
        // SAFETY: the listener is ours to close once the tree is gone.
        unsafe { libc::close(listener) };
    }).map_err(|e| e.to_string())?;

    // Built before the fork: the child only makes system calls.
    let mut prog = crate::guard_filter::build_program(&host.traps);
    let prog_len = prog.len() as u16;
    let no_sends = host.traps.no_sends;
    // An address, not a pointer: the hook must be Send + Sync.
    let prog_addr = prog.as_mut_ptr() as usize;
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .env_clear()
        .envs(host.cfg.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: the hook makes only system calls on memory prepared above.
    unsafe {
        cmd.pre_exec(move || {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut fprog = libc::sock_fprog { len: prog_len, filter: prog_addr as *mut libc::sock_filter };
            let listener = libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
                &mut fprog as *mut libc::sock_fprog,
            ) as RawFd;
            if listener < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // By number: the filter traps sendmsg (guard_kernel::hand_listener).
            if !crate::guard_kernel::hand_listener(child_sock, listener, !no_sends) {
                let e = std::io::Error::last_os_error();
                // A trapped exit_group must not wait on a listener only this
                // child holds (exec-routing.md §7.5, 2026-10-02).
                libc::close(listener);
                return Err(e);
            }
            libc::close(listener);
            // The hosted box dies with the thread that waits for it.
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong, 0, 0, 0);
            // Nothing of the guard's crosses the exec: its descriptors (the
            // agent tree's listener among them) close there.
            if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, libc::CLOSE_RANGE_CLOEXEC) != 0 {
                for fd in 3..4096 {
                    libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                }
            }
            Ok(())
        });
    }
    let spawned = cmd.spawn();
    drop(theirs);
    drop(prog);
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {
            let _ = supervisor.join();
            return Err(e.to_string());
        }
    };
    let pid = child.id() as i32;
    if let Ok(mut v) = OWN_CHILDREN.lock() {
        v.push(pid);
    }
    let err_pipe = child.stderr.take();
    let err_reader = std::thread::spawn(move || err_pipe.and_then(drain));
    let stdout = child.stdout.take().and_then(drain);
    if stdout.is_none() {
        let _ = child.kill();
    }
    let status = child.wait();
    if let Ok(mut v) = OWN_CHILDREN.lock() {
        v.retain(|p| *p != pid);
    }
    let stderr = err_reader.join().ok().flatten();
    // The supervisor thread ends with the hosted tree (its listener hangs up).
    drop(supervisor);
    let status = status.map_err(|e| e.to_string())?;
    match (stdout, stderr) {
        (Some(o), Some(e)) => Ok((status.code(), o, e)),
        _ => Err("the output passed the capture cap".into()),
    }
}
