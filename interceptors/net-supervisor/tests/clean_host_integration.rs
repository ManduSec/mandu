//! Kernel test for the guard-hosted clean box (exec-routing.md §8.5.3,
//! sandbox-security-review-2026-09-28 finding 4). `#[ignore]`d; run through
//! `scripts/kernel-tests.sh` (a user namespace, no host root). Needs only
//! `no_new_privs` + seccomp NEW_LISTENER; self-SKIPs where that is missing.
//!
//! A stand-in box (a shell script) replaces `mandu-exec-box`, and a mock
//! arbiter records what the guard reports, so this proves the guard's half:
//!   • the hosted box runs under this guard's seccomp filter, with only the
//!     launcher's environment, stdin `/dev/null`, and none of the guard's
//!     descriptors;
//!   • a completed run is reported with the claimed reporter token, the
//!     requester's proc key, the session and sha256(stdout), and the bytes
//!     come back to the requester verbatim;
//!   • a void attempt (exit 79) answers "not completed" and reports nothing;
//!   • a requester outside the agent tree is refused;
//!   • a recorded decision of another session is not reported on.
//! Axes: none (the guard is below the axis switches; the arbiter decides).

#![cfg(all(feature = "kernel", target_os = "linux"))]

mod support;
use support::{readable_within_tree, reap_within, run_tag, wait_limit};

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use mandu_arbiter::clean_run::{encode_request, parse_reply_header, CleanReply, CleanRequest};
use mandu_arbiter::mock::{op_handler, MockArbiter};
use net_supervisor::clean_host::CleanHostConfig;
use net_supervisor::clean_host_kernel::{claim_and_bind, serve, CleanHost};
use net_supervisor::guard::{parse_rule, GuardPolicy, NoResolver};
use net_supervisor::guard_filter::FilterTraps;
use net_supervisor::guard_kernel::GuardConfig;

// The ETXTBSY-safe script writer exec-supervisor's tests use (its header says why).
#[path = "../../exec-supervisor/tests/support/exec_script.rs"]
mod exec_script;
use exec_script::write_exec_script;

const TOKEN: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

fn seccomp_listener_available() -> bool {
    // SAFETY: a forked child that installs a filter and exits; nothing shared.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let ok = net_supervisor::guard_kernel::install_guard_filter_self(FilterTraps::default()).is_ok();
        unsafe { libc::_exit(if ok { 0 } else { 1 }) };
    }
    reap_within(pid, wait_limit(), "waiting for the seccomp listener probe child").code() == Some(0)
}

struct Rig {
    dir: std::path::PathBuf,
    arbiter: MockArbiter,
    reports: Arc<Mutex<Vec<serde_json::Value>>>,
}

fn rig(tag: &str) -> Rig {
    rig_for(tag, "S1")
}

/// `decision_session`: the session the mock's recorded decision names.
fn rig_for(tag: &str, decision_session: &'static str) -> Rig {
    let dir = std::env::temp_dir().join(format!("mandu-clean-host-{tag}-{}", run_tag()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let reports = Arc::new(Mutex::new(Vec::new()));
    let seen = reports.clone();
    let arbiter = MockArbiter::start(op_handler(move |op, req| match op {
        "claimCleanReporter" => Ok(serde_json::json!({ "token": TOKEN })),
        "execDecisionFor" => Ok(serde_json::json!({
            "decision": { "block": false, "shell": "AgentShell", "reason": "mock", "sessionKey": decision_session, "callId": "toolu_host", "seq": 1 },
            "signature": "sig",
        })),
        "reportExecCleanVerdict" => {
            seen.lock().unwrap().push(req.clone());
            let call = req["report"]["callId"].clone();
            Ok(serde_json::json!({ "verdict": { "callId": call, "clean": true, "reason": "mock", "seq": 1 } }))
        }
        other => Err(format!("unexpected op {other}")),
    }));
    Rig { dir, arbiter, reports }
}

fn stand_in_box(dir: &std::path::Path, body: &str) -> String {
    let p = dir.join("box.sh");
    // Not std::fs::write: these tests run as threads of one process and fork, and
    // an inherited write descriptor makes the guard's exec of the box ETXTBSY.
    write_exec_script(&p, format!("#!/bin/sh\n{body}\n").as_bytes()).unwrap();
    p.to_str().unwrap().to_string()
}

fn host(r: &Rig, box_bin: String, roots: Vec<i32>) -> String {
    let sock = r.dir.join("clean.sock").to_str().unwrap().to_string();
    let cfg = CleanHostConfig {
        socket: sock.clone(),
        session: "S1".into(),
        box_bin,
        env: vec![("PATH".into(), "/usr/bin:/bin".into()), ("MARK".into(), "from-the-launcher".into())],
    };
    let arbiter = r.arbiter.socket_path.to_str().unwrap().to_string();
    let (token, listener) = claim_and_bind(&cfg, &arbiter).expect("claim + bind");
    assert_eq!(token, TOKEN);
    let guard = GuardConfig::new(Arc::new(GuardPolicy::new(vec![parse_rule("tcp:127.0.0.1:9").unwrap()])), Arc::new(NoResolver));
    let me = unsafe { libc::getpid() } as u32;
    let h = CleanHost::new(cfg, arbiter, token, FilterTraps { guard_pid: me, ..FilterTraps::default() }, roots);
    serve(Arc::new(h), listener, guard);
    sock
}

fn ask(sock: &str, argv: &[&str]) -> (CleanReply, Vec<u8>, Vec<u8>) {
    let mut s = UnixStream::connect(sock).expect("connect the clean socket");
    let req = CleanRequest { argv: argv.iter().map(|a| a.to_string()).collect(), cwd: "/".into() };
    // The host refuses a requester outside the agent tree before it reads the
    // request (clean_host_kernel.rs `handle`), so the write can meet a peer
    // that already closed (EPIPE). Its refusal is in our receive buffer all
    // the same: read it (a race seen once in CI, 2026-10-01).
    match s.write_all(&encode_request(&req)) {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
        r => r.unwrap(),
    }
    // The host answers once the box it runs (a child of this process, under
    // the guard) ends: a deadline on the first byte names a stuck run with
    // the tree's state, and one on every read after it bounds the rest.
    readable_within_tree(s.as_raw_fd(), wait_limit(), "waiting for the clean host's reply (it runs the box under the guard)");
    s.set_read_timeout(Some(wait_limit())).unwrap();
    let mut r = BufReader::new(s);
    let mut line = Vec::new();
    r.read_until(b'\n', &mut line).expect("the clean host's reply header, within wait_limit()");
    line.pop();
    let reply = parse_reply_header(&line).expect("reply header");
    let mut out = vec![0; reply.stdout as usize];
    let mut err = vec![0; reply.stderr as usize];
    r.read_exact(&mut out).expect("the clean host's stdout, within wait_limit()");
    r.read_exact(&mut err).expect("the clean host's stderr, within wait_limit()");
    (reply, out, err)
}

#[test]
#[ignore]
fn the_guard_runs_the_clean_box_supervised_and_reports_with_its_token() {
    if !seccomp_listener_available() {
        println!("SKIP: seccomp NEW_LISTENER unavailable");
        return;
    }
    std::env::set_var("MANDU_CLEAN_HOST_LEAK", "the-guards-own-env");
    let r = rig("run");
    let body = r#"echo "args=$*"
echo "mark=$MARK leak=${MANDU_CLEAN_HOST_LEAK:-none}"
grep -E '^Seccomp:' /proc/self/status
echo "stdin=$(readlink /proc/self/fd/0)"
echo "fds=$(ls /proc/self/fd | sort -n | tr '\n' ' ')"
echo to-stderr >&2"#;
    let me = unsafe { libc::getpid() };
    let sock = host(&r, stand_in_box(&r.dir, body), vec![me]);
    let (reply, out, err) = ask(&sock, &["cat", "notes.md"]);
    let out_s = String::from_utf8_lossy(&out).to_string();
    println!("reply={reply:?}\n{out_s}");
    assert!(reply.completed, "{reply:?}");
    assert!(out_s.contains("args=--clean-only --cwd / -- cat notes.md"), "{out_s}");
    assert!(out_s.contains("mark=from-the-launcher leak=none"), "only the launcher's environment: {out_s}");
    assert!(out_s.contains("Seccomp:\t2"), "the hosted box runs under a seccomp filter: {out_s}");
    assert!(out_s.contains("stdin=/dev/null"), "{out_s}");
    // 0 1 2, and the one `ls` itself opens (its /proc/self/fd directory).
    let fds: Vec<&str> = out_s.lines().find(|l| l.starts_with("fds=")).unwrap()["fds=".len()..].split_whitespace().collect();
    assert!(fds.len() <= 4 && fds.starts_with(&["0", "1", "2"]), "none of the guard's descriptors cross: {fds:?}");
    assert_eq!(String::from_utf8_lossy(&err), "to-stderr\n");
    assert_eq!(reply.call_id.as_deref(), Some("toolu_host"));
    assert!(reply.clean);

    let reports = r.reports.lock().unwrap().clone();
    assert_eq!(reports.len(), 1, "{reports:?}");
    let rep = &reports[0];
    assert_eq!(rep["reporterToken"], TOKEN);
    assert_eq!(rep["report"]["sessionKey"], "S1");
    assert_eq!(rep["report"]["callId"], "toolu_host");
    assert_eq!(rep["report"]["procKey"].as_str(), mandu_arbiter::proc_key_for_pid(me).as_deref());
    let sha = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&out).iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    assert_eq!(rep["report"]["outputSha256"], sha);
    let _ = std::fs::remove_dir_all(&r.dir);
}

#[test]
#[ignore]
fn a_void_attempt_answers_not_completed_and_reports_nothing() {
    if !seccomp_listener_available() {
        println!("SKIP: seccomp NEW_LISTENER unavailable");
        return;
    }
    let r = rig("void");
    let me = unsafe { libc::getpid() };
    let sock = host(&r, stand_in_box(&r.dir, "echo partial; exit 79"), vec![me]);
    let (reply, out, _) = ask(&sock, &["cat", "secret.md"]);
    assert!(!reply.completed, "{reply:?}");
    assert!(out.is_empty(), "a void attempt's bytes never reach the requester");
    assert!(r.reports.lock().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&r.dir);
}

#[test]
#[ignore]
fn a_requester_outside_the_agent_tree_is_refused() {
    if !seccomp_listener_available() {
        println!("SKIP: seccomp NEW_LISTENER unavailable");
        return;
    }
    let r = rig("outside");
    // The tree's root is a process this test is not under.
    let sock = host(&r, stand_in_box(&r.dir, "echo ran"), vec![999_999]);
    let (reply, out, _) = ask(&sock, &["cat", "notes.md"]);
    assert!(!reply.completed);
    assert!(reply.reason.contains("not a process of this guard's agent tree"), "{reply:?}");
    assert!(out.is_empty());
    assert!(r.reports.lock().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&r.dir);
}

#[test]
#[ignore]
fn another_sessions_recorded_decision_is_not_reported_on() {
    if !seccomp_listener_available() {
        println!("SKIP: seccomp NEW_LISTENER unavailable");
        return;
    }
    let r = rig_for("other", "S2");
    let me = unsafe { libc::getpid() };
    let sock = host(&r, stand_in_box(&r.dir, "echo ran"), vec![me]);
    let (reply, out, _) = ask(&sock, &["cat", "notes.md"]);
    assert!(reply.completed && out == b"ran\n", "{reply:?}");
    assert_eq!(reply.call_id, None);
    assert!(!reply.clean);
    assert!(r.reports.lock().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&r.dir);
}
