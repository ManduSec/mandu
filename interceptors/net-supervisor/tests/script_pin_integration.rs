//! script_pin_integration — confidentiality plan 13 §9 R5 at the guard: an
//! interpreter that opens a secret is reported with the script it runs, and
//! the facts the `(interpreter, script)` reader pin rests on are the guard's
//! own reading of the real process.
//!
//! `#[ignore]`d + `--features kernel`: run through `scripts/kernel-tests.sh`
//! (an unprivileged user namespace, where the system's files are owned by
//! an unmapped uid and so out of the agent's reach). A host where the
//! seccomp listener cannot be installed, or without python3, SKIPs.
//!
//! The script: the standard library's `base64.py` run as a program
//! (`python3 -I …/base64.py <file>` opens its file operand), a file out of
//! the agent's reach. Each case opens the registered secret once; the mock
//! arbiter records what the guard sent and answers `twin`:
//!
//!   - the pinned shape: `script` = base64.py's canonical path, its sha256,
//!     out of reach, isolated (`-I`), not traced; no `scriptProblem`;
//!   - `python3 -c …`: no script facts, `scriptProblem` names inline code;
//!   - a copy of base64.py in the workspace: the facts, `system: false`;
//!   - a relative path (`cd <dir>; python3 -I base64.py`): a problem;
//!   - `PYTHONPATH` set: D8's `openerEnv` names it (the arbiter refuses);
//!   - no `-I` / `-s`: `isolated: false`;
//!   - a traced opener (`PTRACE_TRACEME` before the exec): `traced: true`.

#![cfg(all(feature = "kernel", target_os = "linux"))]

mod support;
use support::{in_test_process, join_within, readable_within, reap_within, run_tag, socketpair, wait_limit};

use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use mandu_arbiter::mock::{op_handler, MockArbiter};
use net_supervisor::guard::{parse_rules, GuardPolicy, NoResolver};
use net_supervisor::guard_kernel::{
    hand_listener, install_guard_filter_self, receive_listener, run_guard_supervisor, FilterTraps, GuardConfig,
};

const EXIT_NO_SECCOMP: i32 = 91;

fn reap(pid: i32) -> Option<i32> {
    if in_test_process() {
        return reap_within(pid, wait_limit(), "waiting for a child the test forked").code();
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if libc::WIFEXITED(status) {
        Some(libc::WEXITSTATUS(status))
    } else {
        None
    }
}

fn close_all_but(keep: RawFd) {
    unsafe {
        if keep > 3 {
            libc::syscall(libc::SYS_close_range, 3u32, keep as u32 - 1, 0u32);
        }
        libc::syscall(libc::SYS_close_range, keep as u32 + 1, u32::MAX, 0u32);
    }
}

struct Secret {
    dir: PathBuf,
    path: PathBuf,
    policy: PathBuf,
}

impl Secret {
    fn new() -> Secret {
        let dir = std::env::temp_dir().join(format!("mandu-script-pin-{}", run_tag()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dir = std::fs::canonicalize(&dir).unwrap();
        let path = dir.join(".pgpass");
        let twin = dir.join("twin");
        std::fs::write(&path, "db:5432:prod:app:SCRIPT-PIN-CANARY\n").unwrap();
        std::fs::write(&twin, "db:5432:prod:app:$MDU:twin\n").unwrap();
        let policy = dir.join("policy.json");
        std::fs::write(
            &policy,
            format!(
                r#"{{"agentExe":"","ask":"never","session":"script-pin","secrets":[{{"path":"{}","twin":"{}","level":"no-model"}}]}}"#,
                path.display(),
                twin.display()
            ),
        )
        .unwrap();
        Secret { dir, path, policy }
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

type Asked = Arc<Mutex<Vec<serde_json::Value>>>;

fn recording_arbiter() -> (&'static MockArbiter, Asked) {
    let asked: Asked = Arc::new(Mutex::new(Vec::new()));
    let a = asked.clone();
    let m = MockArbiter::start(op_handler(move |op, req| match op {
        "decideSecretOpen" => {
            a.lock().unwrap().push(req.clone());
            Ok(serde_json::json!({ "verdict": "twin", "app": "python3", "level": "no-model", "reason": "mock", "pinNeeded": false }))
        }
        _ => Ok(serde_json::Value::Null),
    })).leak();
    (m, asked)
}

fn cfg_for(secret: &Secret, arbiter: &MockArbiter) -> GuardConfig {
    let specs: Vec<String> = ["any:127.0.0.0/8:*"].iter().map(|s| s.to_string()).collect();
    let mut cfg = GuardConfig::new(Arc::new(GuardPolicy::new(parse_rules(&specs).unwrap())), Arc::new(NoResolver));
    cfg.secrets = Some(Arc::new(net_supervisor::secret_open::SecretIndex::load(&secret.policy).unwrap()));
    cfg.emitter = Some(Arc::new(Mutex::new(mandu_arbiter::ArbiterClient::new(&arbiter.socket_path))));
    cfg
}

/// Run `body` in a forked child under the guard's filter, served by the real
/// supervisor loop; None to SKIP.
fn guarded(cfg: GuardConfig, body: impl FnOnce() -> i32) -> Option<Option<i32>> {
    let (sup, child_sock) = socketpair(libc::SOCK_STREAM);
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        close_all_but(child_sock);
        let listener = match install_guard_filter_self(FilterTraps { open: true, secrets: true, ..Default::default() }) {
            Ok(fd) => fd,
            Err(_) => unsafe { libc::_exit(EXIT_NO_SECCOMP) },
        };
        if !hand_listener(child_sock, listener, true) {
            unsafe { libc::_exit(92) };
        }
        unsafe { libc::close(listener) };
        let code = body();
        unsafe { libc::_exit(code) };
    }
    unsafe { libc::close(child_sock) };
    readable_within(sup, child, wait_limit(), "waiting for the tracee to hand over its seccomp listener");
    let listener = match receive_listener(sup) {
        Ok((fd, _)) => fd,
        Err(_) => {
            assert_eq!(reap(child), Some(EXIT_NO_SECCOMP), "the tracee could not hand over its listener");
            eprintln!("SKIP: seccomp NEW_LISTENER denied here");
            return None;
        }
    };
    let server = std::thread::spawn(move || {
        let _ = run_guard_supervisor(listener, cfg);
        unsafe { libc::close(listener) };
    });
    let code = reap(child);
    let _ = join_within(server, wait_limit(), "the guard supervisor (run_guard_supervisor), after its tracee exited");
    unsafe { libc::close(sup) };
    Some(code)
}

/// Fork, exec `argv` with `env` in `cwd` (stdout/stderr to /dev/null), and
/// wait. `traced`: the child asks to be traced first, and this process
/// (its tracer) lets it run to its end.
fn run(argv: &[String], env: &[String], cwd: &Path, traced: bool) -> i32 {
    let c_argv: Vec<CString> = argv.iter().map(|a| CString::new(a.as_str()).unwrap()).collect();
    let c_env: Vec<CString> = env.iter().map(|a| CString::new(a.as_str()).unwrap()).collect();
    let c_cwd = CString::new(cwd.to_str().unwrap()).unwrap();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            let null = libc::open(b"/dev/null\0".as_ptr() as *const libc::c_char, libc::O_WRONLY);
            libc::dup2(null, 1);
            libc::dup2(null, 2);
            libc::chdir(c_cwd.as_ptr());
            if traced && libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) != 0 {
                libc::_exit(93);
            }
            let mut av: Vec<*const libc::c_char> = c_argv.iter().map(|a| a.as_ptr()).collect();
            av.push(std::ptr::null());
            let mut ev: Vec<*const libc::c_char> = c_env.iter().map(|a| a.as_ptr()).collect();
            ev.push(std::ptr::null());
            libc::execve(av[0], av.as_ptr(), ev.as_ptr());
            libc::_exit(94);
        }
    }
    loop {
        let mut status = 0;
        if unsafe { libc::waitpid(pid, &mut status, 0) } != pid {
            return -1;
        }
        if libc::WIFEXITED(status) {
            return libc::WEXITSTATUS(status);
        }
        if libc::WIFSIGNALED(status) {
            return -2;
        }
        if libc::WIFSTOPPED(status) {
            // The exec's SIGTRAP is the tracer's; any other signal is passed on.
            let sig = libc::WSTOPSIG(status);
            let pass = if sig == libc::SIGTRAP { 0 } else { sig };
            unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, pass) };
        }
    }
}

fn python3() -> Option<(String, String)> {
    let exe = ["/usr/bin/python3", "/bin/python3"].iter().find(|p| Path::new(p).exists())?.to_string();
    let out = std::process::Command::new(&exe)
        .args(["-I", "-c", "import base64, os; print(os.path.realpath(base64.__file__))"])
        .output()
        .ok()?;
    let b64 = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (out.status.success() && b64.ends_with("base64.py")).then_some((exe, b64))
}

fn s(v: &str) -> String {
    v.to_string()
}

#[test]
#[ignore]
fn an_interpreters_script_is_reported_with_the_facts_its_pin_rests_on() {
    let Some((py, b64)) = python3() else {
        eprintln!("SKIP: no python3 with a base64.py");
        return;
    };
    let secret = Secret::new();
    let (arbiter, asked) = recording_arbiter();
    let file = secret.path.to_str().unwrap().to_string();
    let copy = secret.dir.join("base64.py");
    std::fs::copy(&b64, &copy).unwrap();
    let copy = copy.to_str().unwrap().to_string();
    let b64_dir = Path::new(&b64).parent().unwrap().to_path_buf();
    let base_env = vec![s("PATH=/usr/bin:/bin"), s("LANG=C")];
    let mut env_pp = base_env.clone();
    env_pp.push(format!("PYTHONPATH={}", secret.dir.display()));
    let ws = secret.dir.clone();
    let cases: Vec<(&str, Vec<String>, Vec<String>, PathBuf, bool)> = vec![
        ("pinned", vec![py.clone(), s("-I"), b64.clone(), file.clone()], base_env.clone(), ws.clone(), false),
        ("inline", vec![py.clone(), s("-I"), s("-c"), s("import sys; open(sys.argv[1]).read()"), file.clone()], base_env.clone(), ws.clone(), false),
        ("copy", vec![py.clone(), s("-I"), copy.clone(), file.clone()], base_env.clone(), ws.clone(), false),
        ("relative", vec![py.clone(), s("-I"), s("base64.py"), file.clone()], base_env.clone(), b64_dir.clone(), false),
        ("pythonpath", vec![py.clone(), s("-I"), b64.clone(), file.clone()], env_pp, ws.clone(), false),
        ("unisolated", vec![py.clone(), b64.clone(), file.clone()], base_env.clone(), ws.clone(), false),
        ("traced", vec![py.clone(), s("-I"), b64.clone(), file.clone()], base_env.clone(), ws.clone(), true),
    ];
    let n = cases.len();
    let cfg = cfg_for(&secret, arbiter);
    let Some(code) = guarded(cfg, move || {
        for (i, (_, argv, env, cwd, traced)) in cases.iter().enumerate() {
            if run(argv, env, cwd, *traced) == 93 && *traced {
                return 60 + i as i32; // ptrace refused here
            }
        }
        0
    }) else {
        return;
    };
    if code == Some(60 + 6) {
        eprintln!("SKIP (traced case only): PTRACE_TRACEME refused here");
    }
    let got = asked.lock().unwrap().clone();
    let traced_ran = code == Some(0);
    assert_eq!(got.len(), if traced_ran { n } else { n - 1 }, "one secret open per case: {got:#?}");
    let who = net_supervisor::reader_identity::Who::current();
    let reach_meaningful = !(who.uid == 0 && who.ns_overflow.is_none());
    let sha = net_supervisor::reader_identity::sha256_file(&b64).unwrap();

    // the pinned shape
    let p = &got[0];
    assert_eq!(p["script"]["path"], b64, "{p}");
    assert_eq!(p["script"]["sha256"], sha);
    assert_eq!(p["script"]["isolated"], true);
    assert_eq!(p["script"]["traced"], false);
    if reach_meaningful {
        assert_eq!(p["script"]["system"], true, "the stdlib's base64.py is out of the agent's reach: {p}");
    }
    assert!(p.get("scriptProblem").is_none());
    assert_eq!(p["openerEnv"], serde_json::json!([]), "a clean environment");
    // inline code
    assert!(got[1].get("script").is_none(), "{}", got[1]);
    assert!(got[1]["scriptProblem"].as_str().unwrap_or("").contains("inline"), "{}", got[1]);
    // a workspace copy
    assert_eq!(got[2]["script"]["path"], copy);
    assert_eq!(got[2]["script"]["system"], false, "a copy the agent could have written is never out of reach");
    // a relative path
    assert!(got[3].get("script").is_none());
    assert!(got[3]["scriptProblem"].as_str().unwrap_or("").contains("relative"), "{}", got[3]);
    // PYTHONPATH: D8 names it; the arbiter makes such an opener no reader
    assert!(got[4]["openerEnv"].as_array().unwrap().iter().any(|v| v == "PYTHONPATH"), "{}", got[4]);
    // no isolation from the user site-packages
    assert_eq!(got[5]["script"]["isolated"], false, "{}", got[5]);
    // traced
    if traced_ran {
        assert_eq!(got[6]["script"]["traced"], true, "{}", got[6]);
    }
}
