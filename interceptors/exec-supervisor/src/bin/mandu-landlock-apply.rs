//! mandu-landlock-apply — the IN-SANDBOX Landlock applier (kernel feature).
//!
//! ── Why a separate binary ────────────────────────────────────────────────────
//! A Landlock-restricted thread cannot mount(2) (filesystem-topology changes are
//! denied to a sandboxed process), so the exec sandbox CANNOT restrict itself
//! before exec'ing bubblewrap — bwrap still has its own mounts to build. The LSM
//! leg of the AgentShell overlay therefore has to be applied INSIDE the sandbox,
//! after bwrap's mounts, just before the target program replaces this process:
//!
//!   bwrap …mounts… --seccomp <fd> -- mandu-landlock-apply \
//!       --rw <workspace> --rw /tmp --deny-tcp -- <argv…>
//!
//! The Bubblewrap backend (`kernel::supervise_exec`) interposes this binary when
//! the parent-side probe says Landlock is available (`sandbox::SandboxPlan
//! .landlock_apply`); the whole host FS is visible read-only inside the box, so
//! the binary is exec'able at its host path. It runs UNPRIVILEGED by design —
//! Landlock needs only `no_new_privs` (which bwrap has already set) — and under
//! the already-installed seccomp deny-filter (the landlock syscalls 444/445/446,
//! openat(O_PATH) and prctl are all outside the deny-list).
//!
//! ── Two modes ─────────────────────────────────────────────────────────────────
//! FS-overlay (default): builds the SAME asymmetric overlay the mounts enforce —
//! RO `/`, RW only the `--rw` subtrees, WRITE_FILE on `/dev` (`> /dev/null` must
//! still open), with `--deny-tcp` adding the in-kernel TCP denial (ABI ≥ 4) — then
//! restricts itself and execs the target. This is the exec box's LSM leg.
//!
//! NET-ONLY (`--net-only`): governs TCP and NOTHING on the filesystem — deny all
//! TCP except a CONNECT allowance to each `--allow-tcp-port` and a BIND+CONNECT
//! allowance to each `--allow-tcp-bind-port` (a local TUI server). This is the
//! WHOLE-AGENT confinement wrap: the live agent keeps its full FS (secret-twins
//! masks secrets separately) but its process tree can only reach the localhost
//! proxy port(s), so a prompt-injected raw-socket exfil fails in-kernel even when
//! it bypasses `HTTP_PROXY`. `--rw`/`--deny-tcp` are ignored in this mode.
//!
//! CLEAN (`--clean`, exec-routing.md §8.4 rung 2): the enforce-clean box.
//! Reads are allowed ONLY under the `--read` roots (system paths + files the
//! supervisor hash-verified at plan-build time), each `--write-only` path (the
//! AgentView bind dsts) takes every mutating right but no read/execute bit, and
//! each `--rw` path (the fresh tmpfs scratch) keeps full RW; TCP denial is built
//! in (no `--deny-tcp` needed). A command that COMPLETES under this ruleset has
//! a trusted influence set by construction — that completion (exit 0, observed
//! by the supervisor) is what backs a clean-verdict report. `--read` roots that
//! do not EXIST in-box are dropped (dropping an ALLOW rule only denies more —
//! the restrictive, fail-closed direction; e.g. `/lib64` on arm);
//! `--write-only`/`--rw` paths are NOT dropped — their absence is a caller bug
//! the restrict then fails loudly on. `--skip-unsupported` is REJECTED in this
//! mode: a clean box that silently skipped its restriction would complete
//! "successfully" unrestricted and let the supervisor mint a false verdict.
//!
//! SECCOMP DENY (`--seccomp-deny`, any mode; confidentiality-plan-15 §13.5):
//! also install the AgentShell syscall deny-filter
//! (`seccomp_filter::agentshell_seccomp_filter_opts(true, false)`: the base
//! deny pairs plus the userns-nesting denials) right before the target is
//! exec'd, after the Landlock restriction. `--seccomp-only` is the mode for a
//! kernel without Landlock: the deny-filter and nothing else. The prompt
//! filter's plugin wrap (arbiter prompt-filter/plugin-confine.ts) passes it;
//! a filter that cannot be installed is a setup failure (exit 71), never a
//! silent skip, since the caller's probe said it works.
//!
//! FAIL-CLOSED: any parse/plan/restrict failure exits 71 WITHOUT exec'ing the
//! target — the caller promised the LSM layer, so running unrestricted would
//! silently drop it. `--skip-unsupported` is the cooperative degrade for a caller
//! that merely PREFERS Landlock (e.g. the whole-agent net wrap on an unknown
//! kernel): an unavailable probe (FS < 5.13, or NET < 6.7 in `--net-only`) then
//! execs directly instead of failing. Exec failure exits 126.

#![cfg(feature = "kernel")]

use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};

/// `--seccomp-deny` / `--seccomp-only`: install the deny-filter before exec.
static SECCOMP_DENY: AtomicBool = AtomicBool::new(false);

use fs_supervisor::landlock::{
    landlock_abi_version, landlock_net_supported, plan_landlock, plan_landlock_clean,
    plan_landlock_deny_tcp, plan_net_confine, restrict_self_to_plan, DEV,
    LANDLOCK_ACCESS_FS_WRITE_FILE, LANDLOCK_ACCESS_NET_CONNECT_TCP, RO_ROOT,
};

/// Sandbox setup failed (mirrors kernel.rs's exit-code convention).
const EXIT_SETUP: i32 = 71;
/// exec of the target argv failed.
const EXIT_EXEC: i32 = 126;

fn die(msg: &str) -> ! {
    eprintln!("mandu-landlock-apply: {msg} (fail-closed; target NOT exec'd)");
    exit(EXIT_SETUP);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut rw_paths: Vec<String> = Vec::new();
    let mut read_paths: Vec<String> = Vec::new();
    let mut write_only_paths: Vec<String> = Vec::new();
    let mut allow_ports: Vec<u16> = Vec::new();
    let mut bind_ports: Vec<u16> = Vec::new();
    let mut deny_tcp = false;
    let mut net_only = false;
    let mut clean = false;
    let mut skip_unsupported = false;
    let mut seccomp_only = false;
    let mut ready_fd: Option<i32> = None;
    let mut target: Option<Vec<String>> = None;

    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--rw" => match it.next() {
                Some(p) if p.starts_with('/') => rw_paths.push(p),
                Some(p) => die(&format!("--rw path must be absolute: {p:?}")),
                None => die("--rw needs a path"),
            },
            "--read" => match it.next() {
                Some(p) if p.starts_with('/') => read_paths.push(p),
                Some(p) => die(&format!("--read path must be absolute: {p:?}")),
                None => die("--read needs a path"),
            },
            "--write-only" => match it.next() {
                Some(p) if p.starts_with('/') => write_only_paths.push(p),
                Some(p) => die(&format!("--write-only path must be absolute: {p:?}")),
                None => die("--write-only needs a path"),
            },
            "--clean" => clean = true,
            "--allow-tcp-port" => match it.next() {
                Some(p) => match p.parse::<u16>() {
                    Ok(port) if port != 0 => allow_ports.push(port),
                    _ => die(&format!("--allow-tcp-port needs a port 1..=65535, got {p:?}")),
                },
                None => die("--allow-tcp-port needs a value"),
            },
            "--allow-tcp-bind-port" => match it.next() {
                Some(p) => match p.parse::<u16>() {
                    Ok(port) if port != 0 => bind_ports.push(port),
                    _ => die(&format!("--allow-tcp-bind-port needs a port 1..=65535, got {p:?}")),
                },
                None => die("--allow-tcp-bind-port needs a value"),
            },
            "--deny-tcp" => deny_tcp = true,
            "--net-only" => net_only = true,
            "--skip-unsupported" => skip_unsupported = true,
            "--seccomp-deny" => SECCOMP_DENY.store(true, Ordering::SeqCst),
            "--seccomp-only" => {
                seccomp_only = true;
                SECCOMP_DENY.store(true, Ordering::SeqCst);
            }
            "--ready-fd" => match it.next().and_then(|v| v.parse::<i32>().ok()) {
                Some(fd) if fd > 2 => ready_fd = Some(fd),
                _ => die("--ready-fd needs a descriptor number above 2"),
            },
            "--" => {
                target = Some(it.collect());
                break;
            }
            other => die(&format!("unknown argument {other:?}")),
        }
    }

    let target = match target {
        Some(t) if !t.is_empty() => t,
        _ => die(
            "usage: mandu-landlock-apply ([--rw <abs>]... [--deny-tcp] | --net-only \
             [--allow-tcp-port <port>]... [--allow-tcp-bind-port <port>]... | --clean \
             [--read <abs>]... [--write-only <abs>]... \
             [--rw <abs>]... | --seccomp-only) [--seccomp-deny] [--skip-unsupported] [--ready-fd <n>] -- <argv...>",
        ),
    };

    // The box is built: bwrap only runs this binary after every mount
    // succeeded. Say so on the supervisor's pipe (one byte, then close, so the
    // target never holds it): a box whose setup failed never writes, which is
    // how the supervisor tells a mount race from the command's own failure
    // (exec-routing.md §4.2).
    if let Some(fd) = ready_fd {
        // SAFETY: fd is a descriptor number the supervisor handed us; a bad
        // number only makes write/close fail, which is ignored (the signal is
        // advisory: without it the supervisor simply does not retry).
        unsafe {
            libc::write(fd, b"1".as_ptr() as *const libc::c_void, 1);
            libc::close(fd);
        }
    }

    // SECCOMP-ONLY mode: no Landlock (a kernel without it), the deny-filter only.
    if seccomp_only {
        if clean || net_only {
            die("--seccomp-only takes no Landlock mode");
        }
        exec_target(&target);
    }

    // CLEAN mode (exec-routing.md §8.4 rung 2): the enforce-clean box.
    if clean {
        // A clean box that silently skipped its restriction would let the
        // supervisor mint a FALSE clean verdict off a successful-looking exit —
        // this combination is a caller bug, refused loudly.
        if skip_unsupported {
            die("--clean rejects --skip-unsupported (a skipped clean restriction would back a false verdict)");
        }
        if net_only {
            die("--clean and --net-only are mutually exclusive");
        }
        let abi = landlock_abi_version();
        if abi < 1 {
            // The supervisor only interposes clean mode after ITS probe said
            // Landlock is available — a disagreement here is an anomaly, not a
            // degrade (same posture as the FS-overlay mode below).
            die("Landlock unavailable inside the sandbox but the clean box requires it");
        }
        // Partition the --read allowances by what is actually in-box:
        //   - missing paths are DROPPED (e.g. /lib64 on arm): the restrict
        //     fail-closes on a rule path that won't open, and dropping an
        //     ALLOW rule only denies more. Read allowances only — a missing
        //     --write-only/--rw path is a caller bug the restrict fails on.
        //   - non-directories go into the FILE-grant list: the kernel EINVALs
        //     a rule on a file carrying directory-only rights, which would
        //     fail the whole restrict (and with it, the attempt) for every
        //     hash-verified trusted-read grant.
        let mut read_dirs: Vec<String> = Vec::new();
        let mut read_files: Vec<String> = Vec::new();
        for p in read_paths {
            let meta = std::path::Path::new(&p);
            if meta.is_dir() {
                read_dirs.push(p);
            } else if meta.exists() {
                read_files.push(p);
            }
        }
        let plan =
            plan_landlock_clean(&read_dirs, &read_files, &write_only_paths, &rw_paths, abi as u32);
        if let Err(e) = restrict_self_to_plan(&plan) {
            die(&format!("restrict_self_to_plan (clean) failed: {e}"));
        }
        exec_target(&target);
    }

    // NET-ONLY mode: the whole-agent confinement wrap. Governs TCP only; the FS is
    // untouched (the agent keeps its full view — secrets are masked separately).
    if net_only {
        // TCP-net Landlock is ABI ≥ 4 (kernel ≥ 6.7). Below that we cannot confine
        // by port; DEGRADE (the netns/proxy stay the boundary) rather than break a
        // live agent — this mode's caller always passes --skip-unsupported.
        if !landlock_net_supported() {
            if skip_unsupported {
                exec_target(&target);
            }
            die("Landlock TCP-net unavailable (needs kernel >= 6.7 / ABI >= 4)");
        }
        let abi = landlock_abi_version();
        // `--allow-tcp-bind-port` (exec-routing.md §7.1): a port the agent may
        // LISTEN on (its TUI server / gateway) — BIND|CONNECT in one rule; all
        // other bind(2) stays denied by the handled net domain.
        let plan = plan_net_confine(&allow_ports, &bind_ports, abi as u32);
        if let Err(e) = restrict_self_to_plan(&plan) {
            die(&format!("restrict_self_to_plan (net-only) failed: {e}"));
        }
        exec_target(&target);
    }

    // FS-overlay mode (the exec box's LSM leg).
    let abi = landlock_abi_version();
    if abi < 1 {
        if skip_unsupported {
            // The cooperative degrade: the caller asked for best-effort Landlock
            // on an unknown kernel. The mount overlay (or nothing, for a bare
            // launcher wrap) remains whatever boundary the caller already built.
            exec_target(&target);
        }
        // The exec sandbox only interposes this binary after ITS OWN probe said
        // Landlock is available — an unsupported answer here means the probe and
        // the sandbox disagree about the kernel. That is an anomaly, not a
        // degrade: refuse rather than run with a silently-missing layer.
        die("Landlock unavailable inside the sandbox but the caller expected it");
    }

    // The same asymmetric overlay the mounts enforce, at the LSM layer. Rights
    // are masked to the LIVE abi by the builders; /dev gets WRITE_FILE only
    // (open-for-write of existing nodes — no MAKE_* means /dev/shm cannot become
    // writable staging where /dev is the real device tree).
    let mut plan = if deny_tcp {
        plan_landlock_deny_tcp(RO_ROOT, &rw_paths, abi as u32)
    } else {
        plan_landlock(RO_ROOT, &rw_paths, abi as u32)
    }
    .allow_path(DEV, LANDLOCK_ACCESS_FS_WRITE_FILE);
    // A `--deny-tcp` overlay may still poke specific ports through (CONNECT) — e.g.
    // a boxed command that must reach one localhost service. Harmless when empty.
    for &p in &allow_ports {
        plan = plan.allow_tcp_port(p, LANDLOCK_ACCESS_NET_CONNECT_TCP);
    }

    if let Err(e) = restrict_self_to_plan(&plan) {
        die(&format!("restrict_self_to_plan failed: {e}"));
    }

    exec_target(&target);
}

/// execvp the target argv (PATH-searched, inherits stdio). Only returns on
/// failure. Uses the lib's exec helper so the exit-code convention stays single.
fn exec_target(argv: &[String]) -> ! {
    if SECCOMP_DENY.load(Ordering::SeqCst) {
        if let Err(e) = install_deny_filter() {
            die(&format!("--seccomp-deny: {e}"));
        }
    }
    // exec_argv replaces this process on success; a return IS the failure path
    // (its code is the crate-wide 126 convention).
    let code = exec_supervisor::kernel::exec_argv(argv);
    eprintln!("mandu-landlock-apply: exec of {:?} failed", argv.first());
    debug_assert_eq!(code, EXIT_EXEC);
    exit(code)
}

/// Install the AgentShell deny-filter on this thread (inherited by the exec'd
/// target): `no_new_privs`, then `seccomp(SECCOMP_SET_MODE_FILTER, TSYNC)`.
fn install_deny_filter() -> Result<(), String> {
    let prog = exec_supervisor::seccomp_filter::agentshell_seccomp_filter_opts(true, false);
    if prog.is_empty() {
        return Err("no deny-filter for this architecture".into());
    }
    // SAFETY: prctl with integer arguments.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(format!("no_new_privs: {}", std::io::Error::last_os_error()));
    }
    let fprog = libc::sock_fprog {
        len: (prog.len() / 8) as u16,
        filter: prog.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: fprog points into `prog`, alive for the call.
    let r = unsafe {
        libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER, libc::SECCOMP_FILTER_FLAG_TSYNC, &fprog as *const libc::sock_fprog)
    };
    if r != 0 {
        return Err(format!("seccomp: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}
