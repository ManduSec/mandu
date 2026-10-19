//! guard_filter — the connect guard's seccomp program, built as data.
//!
//! PURE (always compiled, unit-tested with a small cBPF evaluator): which
//! syscalls the whole-agent guard hands to its supervisor (USER_NOTIF), which
//! it refuses outright in the filter (ERRNO), and which run at full speed.
//! `guard_kernel::install_listener_traps` installs exactly this program.
//!
//! Layout: arch check (a foreign arch is KILLed), the x32 refusal (x86_64),
//! the ioctl block, the setsockopt block (`sockopt_block`), the sendto block
//! (`send_block`), the signal block (guard_signals, when the guard's pid is
//! known), the stat block (`stat_block`, guard-only twins), the clone block
//! (`clone_block`), the prctl block (`prctl_block`) and the pidfd-info block
//! (`pidfd_info_block`, all three under a secret policy), then the dispatch:
//! `[deny jumps…][notif jumps…][ALLOW][NOTIF][ERRNO]`.
//!
//! Refused outright, in every posture (sandbox-security-review-2026-09-28
//! findings 5 and 10):
//!   - x32-ABI numbers (`nr | 0x4000_0000` under the same audit arch): every
//!     number below is a plain x86_64 number, so on a kernel with x32 enabled
//!     `connect | X32` would miss every trap. ENOSYS, as on a kernel without
//!     x32.
//!   - `io_uring_setup`: an io_uring's CONNECT and OPENAT ops never reach this
//!     filter, so the connect trap (always on) and the open trap would both be
//!     bypassed. EPERM; libuv and every mainstream user fall back to plain
//!     syscalls on it.
//!
//!   - `ioctl(TIOCSTI)` and `ioctl(TIOCLINUX)` (finding 9): the first pushes
//!     bytes into a terminal's input as if typed, the second pastes a
//!     console selection. The whole-agent wrap keeps the user's terminal (no
//!     `--new-session`, it would kill the TUI), so on a kernel before 6.2 or
//!     with `dev.tty.legacy_tiocsti=1` a program in the tree could type into
//!     the agent's own terminal. EPERM, as a kernel that forbids it answers.
//!//!   - `setsockopt(IPPROTO_IP, IP_OPTIONS)` and `setsockopt(IPPROTO_IPV6,
//!     IPV6_RTHDR | IPV6_2292RTHDR | IPV6_2292PKTOPTIONS)` (2026-10-01): a
//!     source route or a routing header makes the kernel send a connected
//!     socket's packets to the route's first address, not to the destination
//!     the guard judged at the connect; a type-2 IPv6 routing header is
//!     accepted unprivileged. EPERM.
//!
//! Sends (exec-routing.md §7.5, "Sends are judged like connects",
//! 2026-10-01), in every posture: `sendmsg` and `sendmmsg` always go to the
//! supervisor (their address is in memory); `sendto` only with a non-null
//! address (`args[4]`, both words), so `send()` (glibc's `sendto(…, NULL, 0)`)
//! on a connected socket, the hot path, runs at full speed. Under a secret
//! policy `pidfd_getfd` is refused (EPERM): it copies another process's
//! descriptor, a tainted reader's real file to an untainted sibling, or an
//! untainted process's connected socket to a tainted one.
//!
//! Lineage and accepts (exec-routing.md §7.5, 2026-10-02), under a secret
//! policy: `prctl(PR_SET_CHILD_SUBREAPER)` (`prctl_block`) goes to the
//! supervisor so a reaper the tree makes is known as one (an orphan
//! re-parented to it is judged a holder — the orphan backstop in `lineage`);
//! `accept` and `accept4` go to the supervisor where the guard can copy a
//! socket (not `no_sends`), so a holder takes a connection only from this
//! machine or a bound host (`accept_guard`). Every other `prctl` runs at
//! full speed. The fork family and `exit_group` are NOT trapped: trapping
//! task creation with seccomp user-notification destabilizes the bubblewrap
//! wrap the agent runs under, so a holder's descendants are tracked by the
//! lineage walk and the orphan backstop instead.
//!
//! No siblings (exec-routing.md §7.5 gap (d), 2026-10-03), under a secret
//! policy: `clone` with `CLONE_PARENT` is refused (EPERM) and `clone3` with
//! ENOSYS (`clone_block`), so every process the tree makes is a child of its
//! creator and the lineage walk and the orphan backstop see it. Refused in
//! the filter, nothing trapped: the whole tree carries the refusal, since a
//! seccomp program cannot ask the guard whether the caller holds a secret
//! and none can be added to a process from outside once it becomes a holder.
//!
//! The exit status (plan 13 §4.9, 2026-10-03), under a secret policy:
//! `wait4` and `waitid` go to the supervisor, which makes a waiter that may
//! reap a holder a holder before it CONTINUEs (`guard_wait`; x86_64 and
//! aarch64 have no separate `waitpid`), and `ioctl(PIDFD_GET_INFO)` is
//! refused with ENOTTY (`pidfd_info_block`). Unlike task creation, a wait
//! is no call the bubblewrap wrap needs answered in a particular way: it is
//! judged and left to the kernel.
//!
//! `Mandu-new`.

/// Which syscalls the guard's filter hands to the supervisor, beyond
/// `connect`. `guard_kernel` reads the launch's (the variables the launcher
/// sets); a test that forks from a multithreaded process builds one directly,
/// since `from_env` must not run after fork.
#[derive(Debug, Clone, Copy, Default)]
pub struct FilterTraps {
    /// The open family (the §7.1 spike, and every secret policy).
    pub open: bool,
    /// A secret policy: the open family's company (exec, introspection,
    /// Landlock's restrict, and the refusal of open_by_handle_at).
    pub secrets: bool,
    /// policy.yaml `protect:` or the launcher's `writeProtect`. It no longer
    /// changes the filter: `bind` (whose socket file the list judges like
    /// any new file), the delete / rename family, the write family
    /// (`secret_open::write_nrs`: link, symlink, truncate, creat, mknod, the
    /// chmod family, and the extended-attribute family), the mkdir family
    /// and the owner and timestamp families (`owner_time`) are trapped under every secret policy with or
    /// without it (plan 13 §9 R4 (b): a derived file's mode, and a holder's
    /// names and attributes on a mount that leaves the machine; P0 5e,
    /// 2026-10-07: a holder's socket file there is such a name).
    pub protect: bool,
    /// exec-routing.md §4.2: `bind`, to serve the command box.
    pub box_sockets: bool,
    /// supported-agents.md §2.3.1 (`own_server`): `bind`, so the guard can
    /// perform the agent's private server's ephemeral loopback bind.
    pub own_server: bool,
    /// confidentiality.md §7.2a: the guard serves the twins with no bind, so
    /// a stat by PATH of a twinned file is answered with the twin's metadata
    /// (`stat_twin`): x86_64's `stat`, and `newfstatat`/`statx` unless
    /// `AT_EMPTY_PATH` (a descriptor's own stat, glibc's `fstat`) or
    /// `AT_SYMLINK_NOFOLLOW` (an lstat) is set. With a secret policy only.
    pub stat: bool,
    /// With `stat`: which `lstat`s of a path go to the guard too
    /// (`LstatTrap`; confidentiality.md §7.2a "The size a reader sees").
    pub lstat: LstatTrap,
    /// The guard's pid as the installer sees it (the installer is the guard's
    /// child): signals aimed at it are checked (guard_signals). 0 = none.
    pub guard_pid: u32,
    /// The kernel cannot copy a socket (`pidfd_getfd`, < 5.6), so the guard
    /// cannot send for the tracee: sends are NOT trapped (the documented
    /// old-kernel degrade, exec-routing.md §7.5). Off everywhere else.
    pub no_sends: bool,
}

impl FilterTraps {
    /// Does the filter hand `bind` to the guard? Every secret policy (and so
    /// every launch with the Unix socket allow-list, which only a secret
    /// policy carries), the command box and the own-server allowance. Where
    /// it does under the allow-list, the guard keeps the bind record
    /// (exec-routing.md §4.3, `unix_owner::BindRecord`).
    pub fn traps_bind(&self) -> bool {
        self.box_sockets || self.own_server || (self.open && self.secrets)
    }
}

/// Which `lstat`s (`AT_SYMLINK_NOFOLLOW`, x86_64's `lstat`) the stat block
/// hands to the guard (confidentiality.md §7.2a "The size a reader sees",
/// 2026-10-04). A reader that `lstat`s a path, opens it and reads exactly
/// `st_size` bytes (`git diff --no-index`, `git grep --no-index`, `git add`,
/// `rsync`) got the REAL file's size and the twin's bytes: the twin cut
/// short, or padded past its end.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LstatTrap {
    /// Every `lstat` runs at full speed (the bind's posture: there the path
    /// IS the twin).
    #[default]
    Off,
    /// An `lstat` of a path relative to the cwd or absolute (`AT_FDCWD`,
    /// x86_64's `lstat`) goes to the guard; one relative to a directory
    /// descriptor (the tree walkers on fts: `find`, `du`) runs free.
    Cwd,
    /// Every `lstat` of a path goes to the guard.
    All,
}

impl LstatTrap {
    /// `guard_kernel::LSTAT_TWINS_ENV`'s value: unset or anything else is
    /// `Cwd` (the default with the stat trap), `0`/`off` is `Off`, `all` is
    /// `All`. Pure.
    pub fn from_env_value(v: Option<&str>) -> Self {
        match v.map(str::trim) {
            Some("0") | Some("off") => LstatTrap::Off,
            Some("all") => LstatTrap::All,
            _ => LstatTrap::Cwd,
        }
    }
}

/// The kernel the guard needs to perform a send or an accept for a tracee
/// (`pidfd_getfd`, 5.6): below it sends and accepts are not trapped
/// (`FilterTraps::no_sends`, the old-kernel degrade of exec-routing.md
/// §7.5).
pub const SEND_TRAP_MIN_KERNEL: (u32, u32) = (5, 6);

/// The kernel the guard needs to hand a tracee any file it opened for it,
/// the raw secret included (`SECCOMP_IOCTL_NOTIF_ADDFD` with
/// `SECCOMP_ADDFD_FLAG_SEND`, 5.14; `guard_kernel::inject`). Below it every
/// open that can read fails, so no process ever reads a secret raw and
/// none is a holder: the old-kernel degrade of sends and accepts above
/// never meets a holder (plan 13 §9 R1's question, 2026-10-02: no kernel
/// both serves a raw open and leaves the accept or the pass unjudged).
pub const RAW_OPEN_MIN_KERNEL: (u32, u32) = (5, 14);

// Checked when the crate builds: a kernel that leaves sends and accepts
// untrapped can never serve a raw open.
const _: () = assert!(
    SEND_TRAP_MIN_KERNEL.0 < RAW_OPEN_MIN_KERNEL.0 || (SEND_TRAP_MIN_KERNEL.0 == RAW_OPEN_MIN_KERNEL.0 && SEND_TRAP_MIN_KERNEL.1 < RAW_OPEN_MIN_KERNEL.1)
);

/// seccomp_data offsets.
const ARCH_OFF: u32 = 4;
const NR_OFF: u32 = 0;
/// `args[1]`, low word (little-endian on both supported arches).
const ARG1_LO_OFF: u32 = 16 + 8;
/// `args[i]`, low word.
const fn arg_lo_off(i: usize) -> u32 {
    16 + 8 * i as u32
}
/// `args[i]`, high word.
const fn arg_hi_off(i: usize) -> u32 {
    16 + 8 * i as u32 + 4
}

/// The setsockopt levels and names refused in every posture (a route the
/// guard does not see; see the module docs).
pub const SOCKOPT_REFUSED: [(u32, u32); 4] = [
    (crate::send_guard::IPPROTO_IP as u32, crate::send_guard::IP_OPTIONS as u32),
    (crate::send_guard::IPPROTO_IPV6 as u32, crate::send_guard::IPV6_RTHDR as u32),
    (crate::send_guard::IPPROTO_IPV6 as u32, crate::send_guard::IPV6_2292RTHDR as u32),
    (crate::send_guard::IPPROTO_IPV6 as u32, crate::send_guard::IPV6_2292PKTOPTIONS as u32),
];

/// The sends that always reach the supervisor (their address is in memory).
pub const SYS_SEND_MSG: [libc::c_long; 2] = [libc::SYS_sendmsg, libc::SYS_sendmmsg];

/// TIOCSTI / TIOCLINUX (asm-generic ioctls, the same on x86_64 and aarch64).
pub const TIOCSTI: u32 = 0x5412;
pub const TIOCLINUX: u32 = 0x541C;

/// AUDIT_ARCH_* for the filter's architecture check (libc 0.2 does not export it).
#[cfg(target_arch = "x86_64")]
pub const AUDIT_ARCH: u32 = 0xC000_003E; // EM_X86_64 | 64BIT | LE
#[cfg(target_arch = "aarch64")]
pub const AUDIT_ARCH: u32 = 0xC000_00B7; // EM_AARCH64 | 64BIT | LE

/// x86_64 x32-ABI syscalls carry this bit in `nr` under the SAME audit arch.
#[cfg(target_arch = "x86_64")]
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// Plan 10 §4.2: with a secret policy the guard also sees every exec, to give a
/// tool call's process tree a root and its lineage.
pub const SYS_EXEC_FAMILY: [libc::c_long; 2] = [libc::SYS_execve, libc::SYS_execveat];
/// §4.1: introspection of a tainted process by another (its memory, its
/// descriptors): trapped so the guard can refuse it when the target holds a
/// secret and the caller does not.
pub const SYS_INTROSPECT: [libc::c_long; 3] = [libc::SYS_ptrace, libc::SYS_process_vm_readv, libc::SYS_process_vm_writev];

/// `landlock_restrict_self` (446 on every arch; landlock_mirror calls it).
const SYS_LANDLOCK_RESTRICT_SELF: u32 = 446;

/// The syscalls the filter refuses with EPERM for these traps.
pub fn denied_nrs(t: &FilterTraps) -> Vec<u32> {
    // io_uring: always (the connect trap is always on).
    let mut denied = vec![libc::SYS_io_uring_setup as u32];
    // open_by_handle_at: with a secret policy (it needs CAP_DAC_READ_SEARCH
    // in the caller's namespace anyway; refused so a namespace that grants it
    // cannot open a secret by handle).
    if t.open && t.secrets {
        denied.push(libc::SYS_open_by_handle_at as u32);
    }
    // pidfd_getfd: another process's descriptor (a tainted reader's real
    // file, or an untainted process's connected socket; with `own_server`,
    // the client's connection to its private server).
    if (t.open && t.secrets) || t.own_server {
        denied.push(libc::SYS_pidfd_getfd as u32);
    }
    denied
}

/// The syscalls the filter hands to the supervisor for these traps.
pub fn notif_nrs(t: &FilterTraps) -> Vec<u32> {
    let mut nrs: Vec<u32> = vec![libc::SYS_connect as u32];
    // Every posture: a send that can name an address (the connect's twin).
    // `sendto` is routed by its address argument in `send_block`.
    if !t.no_sends {
        nrs.extend(SYS_SEND_MSG.iter().map(|n| *n as u32));
    }
    // Always: the guard performs every allowed connect itself, so a task
    // that confines its own TCP with Landlock gets its connects performed
    // under a mirror of that sandbox (landlock_mirror, "CONNECTS"); with the
    // open family trapped (§4.1a) its opens are mirrored too.
    nrs.push(SYS_LANDLOCK_RESTRICT_SELF);
    // `bind` serves the command box, and (finding 3) creates a socket file
    // that the write-protect list judges like any other new file.
    // And (own_server) the agent's private server's ephemeral loopback bind.
    // Under every secret policy, with or without a write-protect list (P0
    // 5e, 2026-10-07): a holder's socket file on a mount that leaves the
    // machine is a name the server sees (`handle_bind_notif` judges it).
    // And (exec-routing.md §4.3, 2026-10-18) the Unix socket allow-list's
    // bind record: every Unix socket the tree names, recorded.
    if t.traps_bind() {
        nrs.push(libc::SYS_bind as u32);
    }
    if t.open {
        nrs.extend(crate::secret_open::open_nrs().iter().map(|n| *n as u32));
    }
    // §4.1: introspection, judged against the taint; and (own_server) no
    // process may trace or read the private server's client.
    if (t.open && t.secrets) || t.own_server {
        nrs.extend(SYS_INTROSPECT.iter().map(|n| *n as u32));
    }
    if t.open && t.secrets {
        // §4.1a: the guard performs the tree's opens; exec keeps a sandboxed
        // task's lineage (landlock_mirror `on_exec`).
        nrs.extend(SYS_EXEC_FAMILY.iter().map(|n| *n as u32));
        // Plan 13 §9 R1, the file shapes (2026-10-02): a SysV segment joins
        // two processes at `shmat`; a holder's message queue send is
        // refused (`object_flow::ipc_nrs`). Rare calls; the rest of SysV
        // and POSIX IPC runs at full speed.
        nrs.extend(crate::object_flow::ipc_nrs().iter().map(|n| *n as u32));
        // P0 triage 1b (2026-10-07): a holder's `memfd_create`, performed by
        // the guard so the new object is marked before the holder writes it
        // (`object_flow::is_memfd_nr`); anyone else's runs on at once.
        nrs.push(libc::SYS_memfd_create as u32);
        // Plan 13 §4.9 (2026-10-02): a signal that carries a payload (the
        // `sigqueue` family, `pidfd_send_signal` with `siginfo`), refused
        // from a holder to a process that holds no secret
        // (`guard_signals::payload_aim`). The signal block in front sends
        // the ones aimed at the guard here too.
        nrs.extend(crate::guard_signals::payload_nrs().iter().map(|n| *n as u32));
        // Plan 13 §4.9 (2026-10-03): a holder's exit status reaches whoever
        // reaps it: `wait4` and `waitid` go to the supervisor, which makes
        // the waiter a holder first and CONTINUEs (`guard_wait`).
        nrs.extend(crate::wait_flow::wait_nrs().iter().map(|n| *n as u32));
        // exec-routing.md §7.5 (2026-10-02): `prctl(PR_SET_CHILD_SUBREAPER)`
        // is routed by `prctl_block` (a reaper the tree makes is known as
        // one, so an orphan re-parented to it is judged a holder — the orphan
        // backstop). NOT the fork family or `exit_group`: trapping task
        // creation with seccomp user-notification destabilizes the bubblewrap
        // wrap the agent runs under (a `clone` that builds a new user / pid /
        // mount namespace), so a holder's descendants are tracked by the
        // lineage walk and the orphan backstop instead of a fork trap.
        // A holder takes a connection only from this machine or a bound
        // host: the guard performs the accept (it needs a socket copy).
        if !t.no_sends {
            nrs.extend(crate::accept_guard::accept_nrs().iter().map(|n| *n as u32));
        }
        // The delete / rename family and the write family, under every
        // secret policy (with or without a write-protect list): plan 13 §9
        // R4 (b), 2026-10-03, a mode change and a POSIX ACL may open a
        // derived file to other local users; 2026-10-04, a holder's names
        // and attributes on a mount that leaves the machine (with the mkdir
        // family, which nothing else traps; a non-holder's runs at once).
        nrs.extend(crate::secret_open::delete_nrs().iter().map(|n| *n as u32));
        nrs.extend(crate::secret_open::write_nrs().iter().map(|n| *n as u32));
        nrs.extend(crate::secret_open::mkdir_nrs().iter().map(|n| *n as u32));
        // P0 5c (2026-10-07): the owner and timestamp families, a holder's
        // on a mount that leaves the machine (`owner_time`); anyone else's
        // runs at once.
        nrs.extend(crate::owner_time::nrs().iter().map(|n| *n as u32));
        // `newfstatat`/`statx` are routed by their flags (`stat_block`).
        if t.stat {
            nrs.extend(crate::stat_twin::stat_nrs_by_number().iter().map(|n| *n as u32));
            if t.lstat != LstatTrap::Off {
                nrs.extend(crate::stat_twin::lstat_nrs_by_number().iter().map(|n| *n as u32));
            }
        }
    }
    nrs
}

/// The stat calls that name a path and follow it go to the supervisor
/// (`FilterTraps::stat`); a miss falls through to the next block with `nr`
/// reloaded. Empty without the trap. `AT_EMPTY_PATH` runs free only on a
/// real descriptor (glibc's `fstat` is `newfstatat(fd, "", AT_EMPTY_PATH)`):
/// on `AT_FDCWD` the flag names no descriptor, the call is a stat of its
/// path (`statx(AT_FDCWD, ".env", AT_EMPTY_PATH)`, P0 4b, 2026-10-07), and
/// it goes to the supervisor as the same call without the flag would. Per
/// number: with `LstatTrap::Off` (9 instructions) `nr` → flags →
/// `AT_SYMLINK_NOFOLLOW` ? ALLOW → `AT_EMPTY_PATH` ? (dirfd == `AT_FDCWD` ?
/// NOTIF : ALLOW) : NOTIF; with `LstatTrap::All` (8) `nr` → flags →
/// `AT_EMPTY_PATH` ? (dirfd == `AT_FDCWD` ? NOTIF : ALLOW) : NOTIF; with
/// `LstatTrap::Cwd` (8) the same with `AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW`
/// (an lstat on the cwd or absolute goes to the supervisor, one relative to
/// a directory descriptor runs). The residual: `AT_EMPTY_PATH` with a path
/// relative to a real directory descriptor runs free.
fn stat_block(t: &FilterTraps) -> Vec<libc::sock_filter> {
    if !(t.open && t.secrets && t.stat) {
        return Vec::new();
    }
    let stmt = |code: u16, k: u32| libc::sock_filter { code, jt: 0, jf: 0, k };
    let jump = |code: u16, k: u32, jt: u8, jf: u8| libc::sock_filter { code, jt, jf, k };
    let bpf_ld = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    let bpf_jeq = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    let bpf_jset = (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16;
    let bpf_ret = (libc::BPF_RET | libc::BPF_K) as u16;
    let empty = crate::stat_twin::AT_EMPTY_PATH;
    let nofollow = libc::AT_SYMLINK_NOFOLLOW as u32;
    // The flags that run free unless the directory is `AT_FDCWD`.
    let on_cwd = if t.lstat == LstatTrap::Cwd { empty | nofollow } else { empty };
    let mut prog = Vec::new();
    for (nr, flags_arg) in crate::stat_twin::stat_nrs_by_flags() {
        let off = t.lstat == LstatTrap::Off;
        prog.push(stmt(bpf_ld, NR_OFF));
        prog.push(jump(bpf_jeq, nr as u32, 0, if off { 7 } else { 6 }));
        prog.push(stmt(bpf_ld, arg_lo_off(flags_arg)));
        if off {
            // Every lstat runs free.
            prog.push(jump(bpf_jset, nofollow, 3, 0));
        }
        prog.push(jump(bpf_jset, on_cwd, 0, 3));
        // The directory argument is the first of both calls.
        prog.push(stmt(bpf_ld, arg_lo_off(0)));
        prog.push(jump(bpf_jeq, libc::AT_FDCWD as u32, 1, 0));
        prog.push(stmt(bpf_ret, libc::SECCOMP_RET_ALLOW));
        prog.push(stmt(bpf_ret, libc::SECCOMP_RET_USER_NOTIF));
    }
    prog
}

/// Plan 13 D4 (2026-10-04): a stat of a DESCRIPTOR at `stat_twin::
/// TWIN_FD_BASE` or above goes to the supervisor, where the guard places a
/// derived file's twin, so `fstat` of it reports the identity of the file it
/// stands for (`stat_twin::fd_stat_call`). `fstat` by its descriptor;
/// `newfstatat` and `statx` only with `AT_EMPTY_PATH` (the rest falls
/// through to `stat_block`). A descriptor below the base, or a negative one
/// (`AT_FDCWD`), runs at full speed. 6 instructions for `fstat`, 8 per flag
/// form; a miss falls through, `nr` reloaded by the next block. Under a
/// secret policy only.
fn fd_stat_block(t: &FilterTraps) -> Vec<libc::sock_filter> {
    if !(t.open && t.secrets) {
        return Vec::new();
    }
    let stmt = |code: u16, k: u32| libc::sock_filter { code, jt: 0, jf: 0, k };
    let jump = |code: u16, k: u32, jt: u8, jf: u8| libc::sock_filter { code, jt, jf, k };
    let bpf_ld = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    let bpf_jeq = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    let bpf_jge = (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16;
    let bpf_jset = (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16;
    let bpf_ret = (libc::BPF_RET | libc::BPF_K) as u16;
    let base = crate::stat_twin::TWIN_FD_BASE;
    let mut prog = Vec::new();
    for (nr, flags_arg) in crate::stat_twin::fd_stat_nrs() {
        match flags_arg {
            None => {
                // nr? → fd ≥ base? → fd negative? ALLOW : NOTIF; every miss: past the block.
                prog.push(stmt(bpf_ld, NR_OFF));
                prog.push(jump(bpf_jeq, nr as u32, 0, 4));
                prog.push(stmt(bpf_ld, arg_lo_off(0)));
                prog.push(jump(bpf_jge, base, 0, 2));
                prog.push(jump(bpf_jge, 0x8000_0000, 1, 0));
                prog.push(stmt(bpf_ret, libc::SECCOMP_RET_USER_NOTIF));
            }
            Some(flags) => {
                // nr? → AT_EMPTY_PATH? → fd ≥ base? → fd negative? past : NOTIF.
                prog.push(stmt(bpf_ld, NR_OFF));
                prog.push(jump(bpf_jeq, nr as u32, 0, 6));
                prog.push(stmt(bpf_ld, arg_lo_off(flags)));
                prog.push(jump(bpf_jset, libc::AT_EMPTY_PATH as u32, 0, 4));
                prog.push(stmt(bpf_ld, arg_lo_off(0)));
                prog.push(jump(bpf_jge, base, 0, 2));
                prog.push(jump(bpf_jge, 0x8000_0000, 1, 0));
                prog.push(stmt(bpf_ret, libc::SECCOMP_RET_USER_NOTIF));
            }
        }
    }
    prog
}

/// `sendto(fd, buf, len, flags, addr, addrlen)`: a null `addr` (both words)
/// runs at full speed, any other goes to the supervisor. 8 instructions; a
/// miss falls through to the next block, which reloads `nr`.
fn send_block() -> Vec<libc::sock_filter> {
    let stmt = |code: u16, k: u32| libc::sock_filter { code, jt: 0, jf: 0, k };
    let jump = |code: u16, k: u32, jt: u8, jf: u8| libc::sock_filter { code, jt, jf, k };
    let bpf_ld = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    let bpf_jeq = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    let bpf_ret = (libc::BPF_RET | libc::BPF_K) as u16;
    vec![
        stmt(bpf_ld, NR_OFF),
        jump(bpf_jeq, libc::SYS_sendto as u32, 0, 6),
        stmt(bpf_ld, arg_lo_off(4)),
        jump(bpf_jeq, 0, 0, 3),
        stmt(bpf_ld, arg_hi_off(4)),
        jump(bpf_jeq, 0, 0, 1),
        stmt(bpf_ret, libc::SECCOMP_RET_ALLOW),
        stmt(bpf_ret, libc::SECCOMP_RET_USER_NOTIF),
    ]
}

/// `CLONE_PARENT` (linux/sched.h): the new process's parent is the
/// creator's parent, not the creator.
pub const CLONE_PARENT: u32 = 0x0000_8000;

/// `clone3` (asm-generic: 435 on every arch; libc 0.2 does not name it on
/// every target).
pub const SYS_CLONE3: u32 = 435;

/// The `clone` argument that carries the flags. x86_64 is
/// `clone(flags, newsp, parent_tid, child_tid, tls)`; aarch64 is
/// CONFIG_CLONE_BACKWARDS, `clone(flags, newsp, parent_tid, tls, child_tid)`:
/// the flags are `args[0]` on both (only s390's CLONE_BACKWARDS2 puts the
/// stack first, and this crate builds for neither s390 nor any arch whose
/// `AUDIT_ARCH` is not defined above).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub const CLONE_FLAGS_ARG: usize = 0;

/// exec-routing.md §7.5 gap (d), closed 2026-10-03: no process in the tree
/// can make a SIBLING of itself. Under a secret policy `clone` with
/// `CLONE_PARENT` (its flags word, `CLONE_FLAGS_ARG`) is refused with EPERM,
/// and `clone3` with ENOSYS: its flags live in a struct in memory that cBPF
/// cannot read, and glibc (`__clone_internal`, 2.34+) and Rust's std treat
/// ENOSYS as "no clone3" and fall back to `clone`, whose flags the filter
/// reads (the container runtimes' technique, and the command box's own
/// userns denial). The kernel reads only the low 32 bits of `clone`'s flags
/// (`lower_32_bits(clone_flags)`, kernel/fork.c), so the low word is the
/// whole check. Every other `clone` (fork, threads, vfork-style spawns, the
/// namespace clones bubblewrap makes) runs at full speed: nothing is
/// trapped, so the wrap is not touched. 7 instructions; a miss falls
/// through, `nr` reloaded by the next block. Empty without a secret policy.
fn clone_block(t: &FilterTraps) -> Vec<libc::sock_filter> {
    if !(t.open && t.secrets) {
        return Vec::new();
    }
    let stmt = |code: u16, k: u32| libc::sock_filter { code, jt: 0, jf: 0, k };
    let jump = |code: u16, k: u32, jt: u8, jf: u8| libc::sock_filter { code, jt, jf, k };
    let bpf_ld = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    let bpf_jeq = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    let bpf_jset = (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16;
    let bpf_ret = (libc::BPF_RET | libc::BPF_K) as u16;
    vec![
        stmt(bpf_ld, NR_OFF),
        jump(bpf_jeq, SYS_CLONE3, 0, 1),
        stmt(bpf_ret, libc::SECCOMP_RET_ERRNO | (libc::ENOSYS as u32)),
        jump(bpf_jeq, libc::SYS_clone as u32, 0, 3),
        stmt(bpf_ld, arg_lo_off(CLONE_FLAGS_ARG)),
        jump(bpf_jset, CLONE_PARENT, 0, 1),
        stmt(bpf_ret, libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32)),
    ]
}

/// Plan 13 §4.9 (2026-10-03): `ioctl(fd, PIDFD_GET_INFO, …)` is refused
/// with `ENOTTY` (what a kernel before 6.13 answers on a pidfd) under a
/// secret policy: since 6.15 it hands any holder of a pidfd the exit status
/// of the process it names (`PIDFD_INFO_EXIT`), parent or not, a reaper the
/// wait trap never sees. Matched by type and number (`wait_flow::
/// is_pidfd_get_info`: the low 16 bits of the request; the size bits vary
/// with the struct's version). 6 instructions; a miss falls through, `nr`
/// reloaded by the next block.
fn pidfd_info_block(t: &FilterTraps) -> Vec<libc::sock_filter> {
    if !(t.open && t.secrets) {
        return Vec::new();
    }
    let stmt = |code: u16, k: u32| libc::sock_filter { code, jt: 0, jf: 0, k };
    let jump = |code: u16, k: u32, jt: u8, jf: u8| libc::sock_filter { code, jt, jf, k };
    let bpf_ld = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    let bpf_jeq = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    let bpf_and = (libc::BPF_ALU | libc::BPF_AND | libc::BPF_K) as u16;
    let bpf_ret = (libc::BPF_RET | libc::BPF_K) as u16;
    vec![
        stmt(bpf_ld, NR_OFF),
        jump(bpf_jeq, libc::SYS_ioctl as u32, 0, 4),
        stmt(bpf_ld, ARG1_LO_OFF),
        stmt(bpf_and, 0xFFFF),
        jump(bpf_jeq, crate::wait_flow::PIDFD_GET_INFO_LOW, 0, 1),
        stmt(bpf_ret, libc::SECCOMP_RET_ERRNO | (libc::ENOTTY as u32)),
    ]
}

/// `prctl(PR_SET_CHILD_SUBREAPER, …)` goes to the supervisor (a reaper the
/// tree makes, `lineage`); every other `prctl` runs. 6 instructions, under a
/// secret policy only.
fn prctl_block(t: &FilterTraps) -> Vec<libc::sock_filter> {
    if !(t.open && t.secrets) {
        return Vec::new();
    }
    let stmt = |code: u16, k: u32| libc::sock_filter { code, jt: 0, jf: 0, k };
    let jump = |code: u16, k: u32, jt: u8, jf: u8| libc::sock_filter { code, jt, jf, k };
    let bpf_ld = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    let bpf_jeq = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    let bpf_ret = (libc::BPF_RET | libc::BPF_K) as u16;
    vec![
        stmt(bpf_ld, NR_OFF),
        jump(bpf_jeq, libc::SYS_prctl as u32, 0, 4),
        stmt(bpf_ld, arg_lo_off(0)),
        jump(bpf_jeq, crate::lineage::PR_SET_CHILD_SUBREAPER as u32, 0, 1),
        stmt(bpf_ret, libc::SECCOMP_RET_USER_NOTIF),
        stmt(bpf_ret, libc::SECCOMP_RET_ALLOW),
    ]
}

/// `setsockopt(fd, level, optname, …)` with a `SOCKOPT_REFUSED` pair → EPERM.
/// A miss falls through, `nr` reloaded by the next block.
fn sockopt_block() -> Vec<libc::sock_filter> {
    let stmt = |code: u16, k: u32| libc::sock_filter { code, jt: 0, jf: 0, k };
    let jump = |code: u16, k: u32, jt: u8, jf: u8| libc::sock_filter { code, jt, jf, k };
    let bpf_ld = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    let bpf_jeq = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    let bpf_ret = (libc::BPF_RET | libc::BPF_K) as u16;
    // Per pair: ld level; jeq level ? 0 : next pair; ld optname; jeq name ?
    // DENY : next pair. The pairs end in a jump past the DENY return.
    let n = SOCKOPT_REFUSED.len();
    let mut prog = vec![stmt(bpf_ld, NR_OFF)];
    // nr check: on a miss skip all 4*n pair instructions, the JA and the DENY.
    prog.push(jump(bpf_jeq, libc::SYS_setsockopt as u32, 0, u8::try_from(4 * n + 2).expect("short jump")));
    for (i, (level, name)) in SOCKOPT_REFUSED.iter().enumerate() {
        let after = 4 * (n - 1 - i); // instructions of the pairs after this one
        prog.push(stmt(bpf_ld, arg_lo_off(1)));
        prog.push(jump(bpf_jeq, *level, 0, 2));
        prog.push(stmt(bpf_ld, arg_lo_off(2)));
        // match → DENY (past the remaining pairs and the JA); miss → next pair
        prog.push(jump(bpf_jeq, *name, u8::try_from(after + 1).expect("short jump"), 0));
    }
    prog.push(libc::sock_filter { code: (libc::BPF_JMP | libc::BPF_JA) as u16, jt: 0, jf: 0, k: 1 });
    prog.push(stmt(bpf_ret, libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32)));
    prog
}

/// The guard's whole program for these traps.
pub fn build_program(t: &FilterTraps) -> Vec<libc::sock_filter> {
    let stmt = |code: u16, k: u32| libc::sock_filter { code, jt: 0, jf: 0, k };
    let jump = |code: u16, k: u32, jt: u8, jf: u8| libc::sock_filter { code, jt, jf, k };
    let bpf_ld = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    let bpf_jeq = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    let bpf_ret = (libc::BPF_RET | libc::BPF_K) as u16;

    let mut prog: Vec<libc::sock_filter> = Vec::new();
    // Arch guard: a foreign-arch syscall would misread nr/args → KILL.
    prog.push(stmt(bpf_ld, ARCH_OFF));
    prog.push(jump(bpf_jeq, AUDIT_ARCH, 1, 0));
    prog.push(stmt(bpf_ret, libc::SECCOMP_RET_KILL_PROCESS));
    // x32: refused before any number is compared (finding 10).
    #[cfg(target_arch = "x86_64")]
    {
        let bpf_jset = (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16;
        prog.push(stmt(bpf_ld, NR_OFF));
        prog.push(jump(bpf_jset, X32_SYSCALL_BIT, 0, 1));
        prog.push(stmt(bpf_ret, libc::SECCOMP_RET_ERRNO | (libc::ENOSYS as u32)));
    }
    // Finding 9: ioctl(fd, TIOCSTI | TIOCLINUX) → EPERM, in every posture.
    // 6 instructions: nr match → args[1] → either request → EPERM; every miss
    // lands past the block (the signal block and the dispatch reload nr).
    {
        prog.push(stmt(bpf_ld, NR_OFF));
        prog.push(jump(bpf_jeq, libc::SYS_ioctl as u32, 0, 4));
        prog.push(stmt(bpf_ld, ARG1_LO_OFF));
        prog.push(jump(bpf_jeq, TIOCSTI, 1, 0));
        prog.push(jump(bpf_jeq, TIOCLINUX, 0, 1));
        prog.push(stmt(bpf_ret, libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32)));
    }
    // A route the guard does not judge (source route, routing header): EPERM.
    prog.extend(sockopt_block());
    // A sendto with an address: to the supervisor; without one: full speed.
    if !t.no_sends {
        prog.extend(send_block());
    }
    // rootless-confinement §12.2: a signal aimed at the guard goes to the
    // guard for a check; the block falls through to the dispatch below.
    if t.guard_pid != 0 {
        prog.extend(crate::guard_signals::filter_block(t.guard_pid));
    }
    // Plan 13 D4 (2026-10-04): a stat of a derived twin's descriptor, by
    // its number; before the stat block, which lets `AT_EMPTY_PATH` run.
    prog.extend(fd_stat_block(t));
    // confidentiality.md §7.2a: the stat family by its flags.
    prog.extend(stat_block(t));
    // exec-routing.md §7.5 gap (d), 2026-10-03: no sibling of the caller
    // (`CLONE_PARENT` → EPERM, `clone3` → ENOSYS).
    prog.extend(clone_block(t));
    // exec-routing.md §7.5 (2026-10-02): a new process and a new reaper.
    prog.extend(prctl_block(t));
    // Plan 13 §4.9 (2026-10-03): a pidfd's exit status, parent or not.
    prog.extend(pidfd_info_block(t));
    prog.push(stmt(bpf_ld, NR_OFF));
    let nrs = notif_nrs(t);
    let denied = denied_nrs(t);
    // Layout: [deny jumps…][notif jumps…][ALLOW][NOTIF][ERRNO]. A deny hit
    // skips everything up to the ERRNO return; a notif hit lands on NOTIF; the
    // last miss falls through to ALLOW.
    let n = u8::try_from(nrs.len()).expect("short jump");
    let d = u8::try_from(denied.len()).expect("short jump");
    for (i, nr) in denied.iter().enumerate() {
        let remaining_deny = d - 1 - i as u8;
        // skip: the remaining deny jumps + all notif jumps + ALLOW + NOTIF
        prog.push(jump(bpf_jeq, *nr, remaining_deny + n + 2, 0));
    }
    for (i, nr) in nrs.iter().enumerate() {
        let remaining = n - 1 - i as u8; // notif jumps still to be emitted after this one
        prog.push(jump(bpf_jeq, *nr, remaining + 1, 0));
    }
    prog.push(stmt(bpf_ret, libc::SECCOMP_RET_ALLOW));
    prog.push(stmt(bpf_ret, libc::SECCOMP_RET_USER_NOTIF));
    if d > 0 {
        prog.push(stmt(bpf_ret, libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32)));
    }
    prog
}

/// A seccomp-BPF evaluator for the instructions this crate's filters use
/// (LD abs, JEQ, JSET, JGE, JA, RET). `None` = fell off the end.
#[cfg(test)]
pub(crate) fn run_filter(prog: &[libc::sock_filter], nr: u32, arch: u32, args: [u64; 6]) -> Option<u32> {
    let mut data = [0u8; 64];
    data[0..4].copy_from_slice(&nr.to_ne_bytes());
    data[4..8].copy_from_slice(&arch.to_ne_bytes());
    for (i, a) in args.iter().enumerate() {
        data[16 + 8 * i..24 + 8 * i].copy_from_slice(&a.to_ne_bytes());
    }
    let (mut pc, mut acc) = (0usize, 0u32);
    while pc < prog.len() {
        let ins = prog[pc];
        match (ins.code & 0x07) as u32 {
            libc::BPF_LD => {
                let o = ins.k as usize;
                acc = u32::from_ne_bytes(data[o..o + 4].try_into().unwrap());
                pc += 1;
            }
            libc::BPF_JMP if ins.code & 0xf0 == libc::BPF_JA as u16 => pc += 1 + ins.k as usize,
            libc::BPF_JMP if ins.code & 0xf0 == libc::BPF_JSET as u16 => pc += 1 + if acc & ins.k != 0 { ins.jt as usize } else { ins.jf as usize },
            libc::BPF_JMP if ins.code & 0xf0 == libc::BPF_JGE as u16 => pc += 1 + if acc >= ins.k { ins.jt as usize } else { ins.jf as usize },
            libc::BPF_JMP => pc += 1 + if acc == ins.k { ins.jt as usize } else { ins.jf as usize },
            libc::BPF_RET => return Some(ins.k),
            libc::BPF_ALU if ins.code & 0xf0 == libc::BPF_AND as u16 => {
                acc &= ins.k;
                pc += 1;
            }
            _ => panic!("unexpected instruction {:?}", ins.code),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALLOW: Option<u32> = Some(libc::SECCOMP_RET_ALLOW);
    const NOTIF: Option<u32> = Some(libc::SECCOMP_RET_USER_NOTIF);
    const EPERM: Option<u32> = Some(libc::SECCOMP_RET_ERRNO | libc::EPERM as u32);

    fn postures() -> Vec<FilterTraps> {
        let mut v = Vec::new();
        for open in [false, true] {
            for secrets in [false, true] {
                for protect in [false, true] {
                    for (box_sockets, own_server) in [(false, false), (true, false), (false, true)] {
                        for guard_pid in [0, 4242] {
                            for stat in [false, true] {
                                for lstat in [LstatTrap::Off, LstatTrap::Cwd, LstatTrap::All] {
                                    v.push(FilterTraps { open, secrets, protect, box_sockets, own_server, guard_pid, stat, lstat, no_sends: false });
                                }
                            }
                        }
                    }
                }
            }
        }
        v
    }

    fn run(p: &[libc::sock_filter], nr: i64) -> Option<u32> {
        run_filter(p, nr as u32, AUDIT_ARCH, [0; 6])
    }

    #[test]
    fn connect_is_trapped_in_every_posture() {
        for t in postures() {
            assert_eq!(run(&build_program(&t), libc::SYS_connect), NOTIF, "{t:?}");
        }
    }

    #[test]
    fn io_uring_is_refused_in_every_posture() {
        // Finding 5: the connect trap is on in every posture, and io_uring's
        // CONNECT op never reaches it. Refused with or without a secret policy.
        for t in postures() {
            assert_eq!(run(&build_program(&t), libc::SYS_io_uring_setup), EPERM, "{t:?}");
        }
    }

    #[test]
    fn open_by_handle_at_is_refused_with_a_secret_policy_only() {
        for t in postures() {
            let want = if t.open && t.secrets { EPERM } else { ALLOW };
            assert_eq!(run(&build_program(&t), libc::SYS_open_by_handle_at), want, "{t:?}");
        }
    }

    #[test]
    fn opens_are_trapped_only_when_asked() {
        for t in postures() {
            let want = if t.open { NOTIF } else { ALLOW };
            assert_eq!(run(&build_program(&t), libc::SYS_openat), want, "{t:?}");
        }
    }

    #[test]
    fn the_write_family_is_trapped_with_the_delete_family() {
        // Findings 2 and 6: a link, symlink, truncate or creat under a
        // write-protected path never reaches an open the guard sees.
        // Plan 13 §9 R4 (b): the whole family is trapped under every secret
        // policy (2026-10-03 the mode and attribute calls, a derived file
        // opened to other users; 2026-10-04 the rest, a holder's names on a
        // mount that leaves the machine), with or without a protect list.
        for t in postures() {
            let p = build_program(&t);
            for nr in crate::secret_open::write_nrs().into_iter().chain(crate::secret_open::delete_nrs()) {
                let want = if t.open && t.secrets { NOTIF } else { ALLOW };
                assert_eq!(run(&p, nr), want, "{t:?} nr {nr}");
            }
        }
    }

    #[test]
    fn mkdir_is_trapped_under_every_secret_policy() {
        // Plan 13 §9 R4 (b), 2026-10-04: a directory name a holder makes on a
        // mount that leaves the machine. Listed by number, so dropping one
        // from `mkdir_nrs` fails here.
        let mut nrs: Vec<i64> = vec![libc::SYS_mkdirat as i64];
        #[cfg(target_arch = "x86_64")]
        nrs.push(libc::SYS_mkdir as i64);
        for t in postures() {
            let p = build_program(&t);
            let want = if t.open && t.secrets { NOTIF } else { ALLOW };
            for nr in &nrs {
                assert_eq!(run(&p, *nr), want, "{t:?} nr {nr}");
            }
            // Its neighbours run at full speed.
            assert_eq!(run(&p, libc::SYS_getdents64 as i64), ALLOW, "{t:?}");
            assert_eq!(run(&p, libc::SYS_fchdir as i64), ALLOW, "{t:?}");
        }
    }

    #[test]
    fn the_owner_and_time_families_are_trapped_under_every_secret_policy() {
        // P0 5c (2026-10-07): a holder's owner and timestamps on a mount
        // that leaves the machine (they ran free). Listed by number, so
        // dropping one from `owner_time::nrs` fails here.
        let mut nrs: Vec<i64> = vec![libc::SYS_fchownat as i64, libc::SYS_fchown as i64, libc::SYS_utimensat as i64];
        #[cfg(target_arch = "x86_64")]
        nrs.extend([libc::SYS_chown as i64, libc::SYS_lchown as i64, libc::SYS_utime as i64, libc::SYS_utimes as i64, libc::SYS_futimesat as i64]);
        for t in postures() {
            let p = build_program(&t);
            let want = if t.open && t.secrets { NOTIF } else { ALLOW };
            for nr in &nrs {
                assert_eq!(run(&p, *nr), want, "{t:?} nr {nr}");
            }
            // Reading them is not a change: full speed.
            assert_eq!(run(&p, libc::SYS_fstat as i64), ALLOW, "{t:?}");
            assert_eq!(run(&p, libc::SYS_getuid as i64), ALLOW, "{t:?}");
        }
    }

    #[test]
    fn mknod_and_chmod_are_trapped_with_the_write_family() {
        // write-protection.md §4 (closed 2026-09-29): a node made under a
        // protected name, and a mode change of a protected or secret file
        // (by name, `fchmodat2`, or by descriptor), reach the supervisor.
        // Listed by number, so dropping one from `write_nrs` fails here.
        let mut nrs: Vec<i64> = vec![libc::SYS_mknodat as i64, libc::SYS_fchmodat as i64, 452, libc::SYS_fchmod as i64];
        #[cfg(target_arch = "x86_64")]
        nrs.extend([libc::SYS_mknod as i64, libc::SYS_chmod as i64]);
        for t in postures() {
            let p = build_program(&t);
            for nr in &nrs {
                // Plan 13 §9 R4 (b): under every secret policy.
                let want = if t.open && t.secrets { NOTIF } else { ALLOW };
                assert_eq!(run(&p, *nr), want, "{t:?} nr {nr}");
            }
            // The neighbours of the new numbers still run at full speed.
            assert_eq!(run(&p, libc::SYS_fchdir as i64), ALLOW, "{t:?}");
            assert_eq!(run(&p, libc::SYS_fsync as i64), ALLOW, "{t:?}");
        }
    }

    #[test]
    fn the_xattr_family_is_trapped_with_the_write_family() {
        // write-protection.md §4 (closed 2026-09-29): `setfacl -m u::rwx` is
        // a chmod by another name. Listed by number (setxattrat and
        // removexattrat are 463 and 466 on every arch), so dropping one from
        // `write_nrs` fails here.
        let nrs: Vec<i64> = vec![
            libc::SYS_setxattr as i64,
            libc::SYS_lsetxattr as i64,
            libc::SYS_fsetxattr as i64,
            libc::SYS_removexattr as i64,
            libc::SYS_lremovexattr as i64,
            libc::SYS_fremovexattr as i64,
            463,
            466,
        ];
        for t in postures() {
            let p = build_program(&t);
            // Plan 13 §9 R4 (b): under every secret policy (an ACL that
            // opens a derived file to another user).
            let want = if t.open && t.secrets { NOTIF } else { ALLOW };
            for nr in &nrs {
                assert_eq!(run(&p, *nr), want, "{t:?} nr {nr}");
            }
            // Reading an attribute is not a change: full speed.
            assert_eq!(run(&p, libc::SYS_getxattr as i64), ALLOW, "{t:?}");
            assert_eq!(run(&p, libc::SYS_listxattr as i64), ALLOW, "{t:?}");
            assert_eq!(run(&p, 464), ALLOW, "{t:?} getxattrat");
        }
    }

    #[test]
    fn a_stat_by_path_is_trapped_only_for_the_guard_only_twins() {
        // confidentiality.md §7.2a: git stats the real .pack by path and
        // reads the twin by descriptor; the stat by path must reach the guard.
        let at = libc::AT_FDCWD as u32 as u64;
        let empty = libc::AT_EMPTY_PATH as u64;
        let nofollow = libc::AT_SYMLINK_NOFOLLOW as u64;
        for t in postures() {
            let p = build_program(&t);
            let on = t.open && t.secrets && t.stat;
            let want = if on { NOTIF } else { ALLOW };
            // newfstatat(dirfd, path, buf, flags): a stat by path.
            assert_eq!(run_filter(&p, libc::SYS_newfstatat as u32, AUDIT_ARCH, [at, 1, 2, 0, 0, 0]), want, "{t:?}");
            assert_eq!(run_filter(&p, libc::SYS_newfstatat as u32, AUDIT_ARCH, [at, 1, 2, libc::AT_NO_AUTOMOUNT as u64, 0, 0]), want, "{t:?}");
            // statx(dirfd, path, flags, mask, buf), any sync mode.
            assert_eq!(run_filter(&p, libc::SYS_statx as u32, AUDIT_ARCH, [at, 1, 0, 0x7ff, 2, 0]), want, "{t:?}");
            assert_eq!(run_filter(&p, libc::SYS_statx as u32, AUDIT_ARCH, [at, 1, 0x2000, 0x7ff, 2, 0]), want, "{t:?}");
            // An lstat (2026-10-04, "The size a reader sees"): relative to
            // the cwd or absolute it reaches the guard under `Cwd` and
            // `All`; relative to a directory descriptor (the fts walkers:
            // find, du) only under `All`; never without the stat trap.
            let cwd_l = if on && t.lstat != LstatTrap::Off { NOTIF } else { ALLOW };
            let dir_l = if on && t.lstat == LstatTrap::All { NOTIF } else { ALLOW };
            assert_eq!(run_filter(&p, libc::SYS_newfstatat as u32, AUDIT_ARCH, [at, 1, 2, nofollow, 0, 0]), cwd_l, "{t:?}");
            assert_eq!(run_filter(&p, libc::SYS_statx as u32, AUDIT_ARCH, [at, 1, nofollow | 0x2000, 0x7ff, 2, 0]), cwd_l, "{t:?}");
            assert_eq!(run_filter(&p, libc::SYS_newfstatat as u32, AUDIT_ARCH, [at, 1, 2, nofollow | libc::AT_NO_AUTOMOUNT as u64, 0, 0]), cwd_l, "{t:?}");
            assert_eq!(run_filter(&p, libc::SYS_newfstatat as u32, AUDIT_ARCH, [4, 1, 2, nofollow, 0, 0]), dir_l, "{t:?}");
            assert_eq!(run_filter(&p, libc::SYS_statx as u32, AUDIT_ARCH, [4, 1, nofollow, 0x7ff, 2, 0]), dir_l, "{t:?}");
            // The directory is read from its low word, as the kernel does:
            // AT_FDCWD sign-extended or not is the cwd.
            assert_eq!(run_filter(&p, libc::SYS_newfstatat as u32, AUDIT_ARCH, [libc::AT_FDCWD as i64 as u64, 1, 2, nofollow, 0, 0]), cwd_l, "{t:?}");
            // A following stat relative to a directory descriptor is trapped
            // in every lstat mode (as before).
            assert_eq!(run_filter(&p, libc::SYS_newfstatat as u32, AUDIT_ARCH, [4, 1, 2, 0, 0, 0]), want, "{t:?}");
            // P0 4b (2026-10-07): `AT_EMPTY_PATH` on the cwd names no
            // descriptor, so its path is the stat (`statx(AT_FDCWD, ".env",
            // AT_EMPTY_PATH)`): trapped as the same call without the flag;
            // with `AT_SYMLINK_NOFOLLOW` too, as that lstat. The low word.
            let empty_l = cwd_l;
            assert_eq!(run_filter(&p, libc::SYS_newfstatat as u32, AUDIT_ARCH, [at, 1, 2, empty, 0, 0]), want, "{t:?}");
            assert_eq!(run_filter(&p, libc::SYS_newfstatat as u32, AUDIT_ARCH, [libc::AT_FDCWD as i64 as u64, 1, 2, empty, 0, 0]), want, "{t:?}");
            assert_eq!(run_filter(&p, libc::SYS_statx as u32, AUDIT_ARCH, [at, 1, empty, 0x7ff, 2, 0]), want, "{t:?}");
            assert_eq!(run_filter(&p, libc::SYS_statx as u32, AUDIT_ARCH, [at, 1, empty | 0x2000, 0x7ff, 2, 0]), want, "{t:?}");
            assert_eq!(run_filter(&p, libc::SYS_newfstatat as u32, AUDIT_ARCH, [at, 1, 2, empty | nofollow, 0, 0]), empty_l, "{t:?}");
            assert_eq!(run_filter(&p, libc::SYS_statx as u32, AUDIT_ARCH, [at, 1, empty | nofollow, 0x7ff, 2, 0]), empty_l, "{t:?}");
            // A descriptor's own stat (glibc's fstat, libuv's fstat) runs at
            // full speed in every posture; so does fstat itself.
            assert_eq!(run_filter(&p, libc::SYS_newfstatat as u32, AUDIT_ARCH, [3, 1, 2, empty, 0, 0]), ALLOW, "{t:?}");
            assert_eq!(run_filter(&p, libc::SYS_newfstatat as u32, AUDIT_ARCH, [3, 1, 2, empty | nofollow, 0, 0]), ALLOW, "{t:?}");
            assert_eq!(run_filter(&p, libc::SYS_statx as u32, AUDIT_ARCH, [3, 1, empty, 0x7ff, 2, 0]), ALLOW, "{t:?}");
            assert_eq!(run(&p, libc::SYS_fstat), ALLOW, "{t:?}");
            // The flag is read from the right argument: AT_EMPTY_PATH in
            // newfstatat's buf pointer or statx's mask changes nothing.
            assert_eq!(run_filter(&p, libc::SYS_newfstatat as u32, AUDIT_ARCH, [at, 1, empty, 0, 0, 0]), want, "{t:?}");
            assert_eq!(run_filter(&p, libc::SYS_statx as u32, AUDIT_ARCH, [at, 1, 0, empty, 2, 0]), want, "{t:?}");
            #[cfg(target_arch = "x86_64")]
            {
                assert_eq!(run(&p, libc::SYS_stat), want, "{t:?}");
                // x86_64's lstat names a path relative to the cwd.
                assert_eq!(run(&p, libc::SYS_lstat), if on && t.lstat != LstatTrap::Off { NOTIF } else { ALLOW }, "{t:?}");
            }
            // The block leaves every other trap as it was.
            assert_eq!(run(&p, libc::SYS_connect), NOTIF, "{t:?}");
            assert_eq!(run(&p, libc::SYS_openat), if t.open { NOTIF } else { ALLOW }, "{t:?}");
            assert_eq!(run(&p, libc::SYS_read), ALLOW, "{t:?}");
            assert_eq!(run(&p, libc::SYS_io_uring_setup), EPERM, "{t:?}");
        }
    }

    #[test]
    fn the_lstat_trap_is_read_from_its_variable() {
        assert_eq!(LstatTrap::from_env_value(None), LstatTrap::Cwd, "the default with the stat trap");
        assert_eq!(LstatTrap::from_env_value(Some("1")), LstatTrap::Cwd);
        assert_eq!(LstatTrap::from_env_value(Some("cwd")), LstatTrap::Cwd);
        assert_eq!(LstatTrap::from_env_value(Some("0")), LstatTrap::Off);
        assert_eq!(LstatTrap::from_env_value(Some("off")), LstatTrap::Off);
        assert_eq!(LstatTrap::from_env_value(Some("all")), LstatTrap::All);
        assert_eq!(LstatTrap::default(), LstatTrap::Off, "a FilterTraps built in code traps no lstat unless it says so");
    }

    #[test]
    fn a_descriptor_stat_at_the_twin_base_reaches_the_guard_under_a_secret_policy() {
        // Plan 13 D4 (2026-10-04): a derived twin's descriptor sits at
        // TWIN_FD_BASE or above, so its fstat can report the real file's
        // identity; every lower or negative descriptor runs at full speed.
        let base = crate::stat_twin::TWIN_FD_BASE as u64;
        let at = libc::AT_FDCWD as u32 as u64;
        let empty = libc::AT_EMPTY_PATH as u64;
        let nofollow = libc::AT_SYMLINK_NOFOLLOW as u64;
        for t in postures() {
            let p = build_program(&t);
            let on = t.open && t.secrets;
            let want = if on { NOTIF } else { ALLOW };
            for fd in [base, base + 1, 1023, 0x7fff_ffff] {
                assert_eq!(run_filter(&p, libc::SYS_fstat as u32, AUDIT_ARCH, [fd, 2, 0, 0, 0, 0]), want, "{t:?} fstat({fd})");
                assert_eq!(run_filter(&p, libc::SYS_newfstatat as u32, AUDIT_ARCH, [fd, 1, 2, empty, 0, 0]), want, "{t:?} newfstatat({fd})");
                assert_eq!(run_filter(&p, libc::SYS_newfstatat as u32, AUDIT_ARCH, [fd, 1, 2, empty | nofollow, 0, 0]), want, "{t:?}");
                assert_eq!(run_filter(&p, libc::SYS_statx as u32, AUDIT_ARCH, [fd, 1, empty, 0x7ff, 2, 0]), want, "{t:?} statx({fd})");
            }
            for fd in [0, 3, base - 1, at, 0xffff_ffff, 0x8000_0000] {
                // `AT_EMPTY_PATH` on `AT_FDCWD` is a stat by path (P0 4b):
                // the stat block's, trapped only for the guard-only twins.
                let empty_at = if fd == at && t.open && t.secrets && t.stat { NOTIF } else { ALLOW };
                assert_eq!(run_filter(&p, libc::SYS_fstat as u32, AUDIT_ARCH, [fd, 2, 0, 0, 0, 0]), ALLOW, "{t:?} fstat({fd:#x})");
                assert_eq!(run_filter(&p, libc::SYS_newfstatat as u32, AUDIT_ARCH, [fd, 1, 2, empty, 0, 0]), empty_at, "{t:?} newfstatat({fd:#x})");
                assert_eq!(run_filter(&p, libc::SYS_statx as u32, AUDIT_ARCH, [fd, 1, empty, 0x7ff, 2, 0]), empty_at, "{t:?} statx({fd:#x})");
            }
            // A path stat relative to a high descriptor is the stat block's
            // (trapped only for the guard-only twins); an lstat relative to
            // a descriptor runs free unless the lstat trap is `All`.
            let by_path = if t.open && t.secrets && t.stat { NOTIF } else { ALLOW };
            let l_path = if t.open && t.secrets && t.stat && t.lstat == LstatTrap::All { NOTIF } else { ALLOW };
            assert_eq!(run_filter(&p, libc::SYS_newfstatat as u32, AUDIT_ARCH, [base, 1, 2, 0, 0, 0]), by_path, "{t:?}");
            assert_eq!(run_filter(&p, libc::SYS_newfstatat as u32, AUDIT_ARCH, [base, 1, 2, nofollow, 0, 0]), l_path, "{t:?}");
            assert_eq!(run_filter(&p, libc::SYS_statx as u32, AUDIT_ARCH, [base, 1, nofollow, 0x7ff, 2, 0]), l_path, "{t:?}");
            // The flag is read from the right argument.
            assert_eq!(run_filter(&p, libc::SYS_newfstatat as u32, AUDIT_ARCH, [base, 1, empty, 0, 0, 0]), by_path, "{t:?}");
            // The descriptor's high word is not the descriptor (the kernel reads an int).
            assert_eq!(run_filter(&p, libc::SYS_fstat as u32, AUDIT_ARCH, [3 | (base << 32), 2, 0, 0, 0, 0]), ALLOW, "{t:?}");
            // Every other trap as it was.
            assert_eq!(run(&p, libc::SYS_connect), NOTIF, "{t:?}");
            assert_eq!(run(&p, libc::SYS_openat), if t.open { NOTIF } else { ALLOW }, "{t:?}");
            assert_eq!(run(&p, libc::SYS_read), ALLOW, "{t:?}");
        }
    }

    #[test]
    fn bind_is_trapped_for_the_box_the_own_server_or_any_secret_policy() {
        // P0 5e (2026-10-07): a holder's socket file on a mount that leaves
        // the machine is a name the server sees, with or without a
        // write-protect list (`protect` no longer matters here).
        for t in postures() {
            let want = if t.box_sockets || t.own_server || (t.open && t.secrets) { NOTIF } else { ALLOW };
            assert_eq!(run(&build_program(&t), libc::SYS_bind), want, "{t:?}");
            // The guard keeps its bind record only where this holds.
            assert_eq!(t.traps_bind(), want == NOTIF, "{t:?}");
            if t.secrets && t.open {
                assert!(t.traps_bind(), "every secret policy (so every Unix allow-list) traps bind: {t:?}");
            }
        }
    }

    #[test]
    fn terminal_injection_ioctls_are_refused_in_every_posture() {
        // Finding 9: TIOCSTI and TIOCLINUX, whatever the descriptor; every
        // other ioctl (a terminal's size, a socket's FIONREAD) runs.
        for t in postures() {
            let p = build_program(&t);
            let ioctl = |req: u64| run_filter(&p, libc::SYS_ioctl as u32, AUDIT_ARCH, [0, req, 0, 0, 0, 0]);
            assert_eq!(ioctl(TIOCSTI as u64), EPERM, "{t:?}");
            assert_eq!(ioctl(TIOCLINUX as u64), EPERM, "{t:?}");
            assert_eq!(ioctl(libc::TIOCGWINSZ as u64), ALLOW, "{t:?}");
            assert_eq!(ioctl(libc::FIONREAD as u64), ALLOW, "{t:?}");
            // The kernel reads the request as 32 bits: junk in the high word
            // is still TIOCSTI, and the filter compares the low word only.
            assert_eq!(ioctl((1u64 << 32) | TIOCSTI as u64), EPERM, "{t:?}");
            assert_eq!(ioctl((1u64 << 32) | 0x1234), ALLOW, "{t:?}");
            // The block restores nr: the traps after it still see their calls.
            assert_eq!(run_filter(&p, libc::SYS_connect as u32, AUDIT_ARCH, [0, TIOCSTI as u64, 0, 0, 0, 0]), NOTIF, "{t:?}");
        }
    }

    #[test]
    fn ordinary_calls_run_at_full_speed() {
        for t in postures() {
            let p = build_program(&t);
            for nr in [libc::SYS_read, libc::SYS_write, libc::SYS_mmap, libc::SYS_getpid] {
                assert_eq!(run(&p, nr), ALLOW, "{t:?} nr {nr}");
            }
        }
    }

    #[test]
    fn sends_with_an_address_are_trapped_in_every_posture() {
        // exec-routing.md §7.5 (2026-10-01), finding path 1: a datagram with an
        // explicit address never reached the guard.
        for t in postures() {
            let p = build_program(&t);
            let sendto = |addr: u64| run_filter(&p, libc::SYS_sendto as u32, AUDIT_ARCH, [3, 0x1000, 10, 0, addr, 16]);
            // send() is sendto(..., NULL, 0): full speed, the hot path.
            assert_eq!(sendto(0), ALLOW, "{t:?}");
            assert_eq!(sendto(0x7ffd_1234), NOTIF, "{t:?}");
            // An address above 4 GiB: the high word alone is non-zero.
            assert_eq!(sendto(0x7ffd_0000_0000), NOTIF, "{t:?}");
            assert_eq!(sendto(1 << 32), NOTIF, "{t:?}");
            // The address length alone (args[5]) changes nothing.
            assert_eq!(run_filter(&p, libc::SYS_sendto as u32, AUDIT_ARCH, [3, 0x1000, 10, 0, 0, 16]), ALLOW, "{t:?}");
            for nr in SYS_SEND_MSG {
                assert_eq!(run(&p, nr), NOTIF, "{t:?} nr {nr}");
            }
            // Writes, reads and receives stay at full speed.
            for nr in [libc::SYS_write, libc::SYS_writev, libc::SYS_recvfrom, libc::SYS_recvmsg, libc::SYS_sendfile] {
                assert_eq!(run(&p, nr), ALLOW, "{t:?} nr {nr}");
            }
            // The block restores nr for the traps after it.
            assert_eq!(run_filter(&p, libc::SYS_connect as u32, AUDIT_ARCH, [3, 0x1000, 16, 0, 0x7ffd_1234, 0]), NOTIF, "{t:?}");
            assert_eq!(run_filter(&p, libc::SYS_read as u32, AUDIT_ARCH, [3, 0x1000, 16, 0, 0x7ffd_1234, 0]), ALLOW, "{t:?}");
        }
    }

    #[test]
    fn an_old_kernel_traps_no_send() {
        // < 5.6: no pidfd_getfd, so nothing could be sent for the tracee.
        let t = FilterTraps { no_sends: true, ..Default::default() };
        let p = build_program(&t);
        assert_eq!(run_filter(&p, libc::SYS_sendto as u32, AUDIT_ARCH, [3, 0x1000, 10, 0, 0x7ffd_1234, 16]), ALLOW);
        for nr in SYS_SEND_MSG {
            assert_eq!(run(&p, nr), ALLOW, "nr {nr}");
        }
        assert_eq!(run(&p, libc::SYS_connect), NOTIF);
    }

    #[test]
    fn routes_the_guard_does_not_see_are_refused_in_every_posture() {
        // A source route or an IPv6 routing header sends a connected socket's
        // packets to another address than the one judged.
        let ip = crate::send_guard::IPPROTO_IP as u64;
        let ip6 = crate::send_guard::IPPROTO_IPV6 as u64;
        for t in postures() {
            let p = build_program(&t);
            let so = |level: u64, name: u64| run_filter(&p, libc::SYS_setsockopt as u32, AUDIT_ARCH, [3, level, name, 0x1000, 8, 0]);
            assert_eq!(so(ip, crate::send_guard::IP_OPTIONS as u64), EPERM, "{t:?}");
            for name in [crate::send_guard::IPV6_RTHDR, crate::send_guard::IPV6_2292RTHDR, crate::send_guard::IPV6_2292PKTOPTIONS] {
                assert_eq!(so(ip6, name as u64), EPERM, "{t:?} {name}");
            }
            // Their neighbours run: IP_TOS (1), IP_TTL (2), IPV6_V6ONLY (26),
            // SO_REUSEADDR at SOL_SOCKET (1/2), TCP_NODELAY (6/1), and the same
            // numbers at another level.
            assert_eq!(so(ip, 1), ALLOW, "{t:?}");
            assert_eq!(so(ip, 2), ALLOW, "{t:?}");
            assert_eq!(so(ip6, 26), ALLOW, "{t:?}");
            assert_eq!(so(1, 2), ALLOW, "{t:?}");
            assert_eq!(so(6, 1), ALLOW, "{t:?}");
            assert_eq!(so(1, crate::send_guard::IP_OPTIONS as u64), ALLOW, "{t:?}");
            assert_eq!(so(ip6, crate::send_guard::IP_OPTIONS as u64), ALLOW, "{t:?}");
            assert_eq!(so(ip, crate::send_guard::IPV6_RTHDR as u64), ALLOW, "{t:?}");
            // getsockopt of the same names is not a route.
            assert_eq!(run_filter(&p, libc::SYS_getsockopt as u32, AUDIT_ARCH, [3, ip, 4, 0x1000, 0x2000, 0]), ALLOW, "{t:?}");
            // The block restores nr.
            assert_eq!(run_filter(&p, libc::SYS_connect as u32, AUDIT_ARCH, [3, ip, 4, 0, 0, 0]), NOTIF, "{t:?}");
        }
    }

    #[test]
    fn pidfd_getfd_is_refused_with_a_secret_policy_or_the_own_server() {
        for t in postures() {
            let want = if (t.open && t.secrets) || t.own_server { EPERM } else { ALLOW };
            assert_eq!(run(&build_program(&t), libc::SYS_pidfd_getfd), want, "{t:?}");
        }
    }

    #[test]
    fn introspection_reaches_the_supervisor_with_a_secret_policy_or_the_own_server() {
        for t in postures() {
            let want = if (t.open && t.secrets) || t.own_server { NOTIF } else { ALLOW };
            for nr in SYS_INTROSPECT {
                assert_eq!(run(&build_program(&t), nr), want, "{t:?} {nr}");
            }
        }
    }

    #[test]
    fn a_new_reaper_reaches_the_supervisor_but_the_fork_family_is_not_trapped() {
        // exec-routing.md §7.5 (2026-10-02): a reaper the tree makes is
        // trapped (the orphan backstop), but the fork family and exit_group
        // are NOT (trapping task creation destabilizes the bubblewrap wrap).
        for t in postures() {
            let p = build_program(&t);
            let on = t.open && t.secrets;
            // The fork family and exit_group are never trapped: a plain
            // clone (flags 0 here) and exit_group run at full speed in EVERY
            // posture; clone3 is refused outright under a secret policy
            // (`a_sibling_is_refused_under_a_secret_policy`), never trapped.
            for nr in [libc::SYS_clone, libc::SYS_exit_group, libc::SYS_exit] {
                assert_eq!(run(&p, nr), ALLOW, "{t:?} nr {nr}");
            }
            assert_ne!(run(&p, SYS_CLONE3 as i64), NOTIF, "{t:?}");
            #[cfg(target_arch = "x86_64")]
            for nr in [libc::SYS_fork, libc::SYS_vfork] {
                assert_eq!(run(&p, nr), ALLOW, "{t:?} nr {nr}");
            }
            // prctl(PR_SET_CHILD_SUBREAPER) traps under a secret policy; every
            // other prctl runs.
            let prctl = |opt: u64| run_filter(&p, libc::SYS_prctl as u32, AUDIT_ARCH, [opt, 1, 0, 0, 0, 0]);
            assert_eq!(prctl(crate::lineage::PR_SET_CHILD_SUBREAPER), if on { NOTIF } else { ALLOW }, "{t:?}");
            assert_eq!(prctl(libc::PR_SET_PDEATHSIG as u64), ALLOW, "{t:?}");
            assert_eq!(prctl(libc::PR_SET_NAME as u64), ALLOW, "{t:?}");
            assert_eq!(prctl((1u64 << 32) | 15), ALLOW, "{t:?} the option is an int");
            // The block restores nr for the traps after it.
            assert_eq!(run_filter(&p, libc::SYS_connect as u32, AUDIT_ARCH, [crate::lineage::PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0, 0]), NOTIF, "{t:?}");
            assert_eq!(run_filter(&p, libc::SYS_read as u32, AUDIT_ARCH, [crate::lineage::PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0, 0]), ALLOW, "{t:?}");
        }
    }

    #[test]
    fn a_sibling_is_refused_under_a_secret_policy() {
        // exec-routing.md §7.5 gap (d), closed 2026-10-03: a holder's
        // `CLONE_PARENT` child would be its parent's child, out of the
        // lineage walk's and the orphan backstop's reach.
        let enosys = Some(libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32);
        let sigchld = libc::SIGCHLD as u64;
        // glibc's own shapes (fork's `arch_fork`, pthread_create's fallback,
        // posix_spawn's fallback) and bubblewrap's namespace clone.
        let fork = libc::CLONE_CHILD_SETTID as u64 | libc::CLONE_CHILD_CLEARTID as u64 | sigchld;
        let thread = (libc::CLONE_VM
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_SIGHAND
            | libc::CLONE_THREAD
            | libc::CLONE_SYSVSEM
            | libc::CLONE_SETTLS
            | libc::CLONE_PARENT_SETTID
            | libc::CLONE_CHILD_CLEARTID) as u64;
        let spawn = (libc::CLONE_VM | libc::CLONE_VFORK) as u64 | sigchld;
        let bwrap = (libc::CLONE_NEWNS | libc::CLONE_NEWUSER | libc::CLONE_NEWPID | libc::CLONE_NEWNET) as u64 | sigchld;
        for t in postures() {
            let p = build_program(&t);
            let on = t.open && t.secrets;
            let clone = |flags: u64| run_filter(&p, libc::SYS_clone as u32, AUDIT_ARCH, [flags, 0, 0, 0, 0, 0]);
            let parent = CLONE_PARENT as u64;
            assert_eq!(clone(parent | sigchld), if on { EPERM } else { ALLOW }, "{t:?}");
            assert_eq!(clone(parent), if on { EPERM } else { ALLOW }, "{t:?}");
            assert_eq!(clone(parent | spawn), if on { EPERM } else { ALLOW }, "{t:?}");
            assert_eq!(clone(parent | thread), if on { EPERM } else { ALLOW }, "{t:?}");
            // The kernel reads the low word only: junk above it changes
            // nothing, and CLONE_PARENT's bit in the high word is not it.
            assert_eq!(clone((0xdead_beefu64 << 32) | parent | sigchld), if on { EPERM } else { ALLOW }, "{t:?}");
            assert_eq!(clone((parent << 32) | sigchld), ALLOW, "{t:?}");
            // The flags are args[0]: CLONE_PARENT's value in another argument
            // (a stack pointer, a tid pointer) is not the flag.
            for i in 1..6 {
                let mut a = [sigchld, 0, 0, 0, 0, 0];
                a[i] = parent;
                assert_eq!(run_filter(&p, libc::SYS_clone as u32, AUDIT_ARCH, a), ALLOW, "{t:?} arg {i}");
            }
            // Every ordinary clone runs at full speed, in every posture.
            for flags in [0, sigchld, fork, thread, spawn, bwrap, libc::CLONE_PARENT_SETTID as u64 | sigchld] {
                assert_eq!(clone(flags), ALLOW, "{t:?} flags {flags:#x}");
            }
            // clone3: refused whatever its arguments under a secret policy
            // (ENOSYS: glibc and Rust fall back to clone); untouched otherwise.
            let clone3 = |a: [u64; 6]| run_filter(&p, SYS_CLONE3, AUDIT_ARCH, a);
            for a in [[0u64; 6], [0x7ffd_1000, 88, 0, 0, 0, 0], [parent, 88, 0, 0, 0, 0]] {
                assert_eq!(clone3(a), if on { enosys } else { ALLOW }, "{t:?}");
            }
            // fork and vfork carry no flags (x86_64 only).
            #[cfg(target_arch = "x86_64")]
            for nr in [libc::SYS_fork, libc::SYS_vfork] {
                assert_eq!(run_filter(&p, nr as u32, AUDIT_ARCH, [parent, 0, 0, 0, 0, 0]), ALLOW, "{t:?} nr {nr}");
            }
            // The block restores nr: CLONE_PARENT's value in args[0] of
            // another call changes nothing, and the traps after it still see
            // their calls.
            for nr in [libc::SYS_read, libc::SYS_mmap, libc::SYS_unshare, libc::SYS_setns] {
                assert_eq!(run_filter(&p, nr as u32, AUDIT_ARCH, [parent, 0, 0, 0, 0, 0]), ALLOW, "{t:?} nr {nr}");
            }
            assert_eq!(run_filter(&p, libc::SYS_connect as u32, AUDIT_ARCH, [parent, 0, 0, 0, 0, 0]), NOTIF, "{t:?}");
            let prctl = run_filter(&p, libc::SYS_prctl as u32, AUDIT_ARCH, [crate::lineage::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0, 0]);
            assert_eq!(prctl, if on { NOTIF } else { ALLOW }, "{t:?}");
            assert_eq!(run(&p, libc::SYS_openat), if t.open { NOTIF } else { ALLOW }, "{t:?}");
        }
        // The old-kernel posture (no socket copy) refuses siblings too.
        let old = FilterTraps { open: true, secrets: true, no_sends: true, ..Default::default() };
        let p = build_program(&old);
        assert_eq!(run_filter(&p, libc::SYS_clone as u32, AUDIT_ARCH, [CLONE_PARENT as u64 | sigchld, 0, 0, 0, 0, 0]), EPERM);
        assert_eq!(run(&p, SYS_CLONE3 as i64), enosys);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn an_x32_clone_never_reaches_the_clone_block() {
        // `clone | X32` is refused (ENOSYS) before the clone block compares
        // anything; so is `clone3 | X32`.
        let t = FilterTraps { open: true, secrets: true, ..Default::default() };
        let p = build_program(&t);
        let enosys = Some(libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32);
        let a = [CLONE_PARENT as u64 | libc::SIGCHLD as u64, 0, 0, 0, 0, 0];
        assert_eq!(run_filter(&p, libc::SYS_clone as u32 | X32_SYSCALL_BIT, AUDIT_ARCH, a), enosys);
        assert_eq!(run_filter(&p, SYS_CLONE3 | X32_SYSCALL_BIT, AUDIT_ARCH, a), enosys);
    }

    #[test]
    fn every_jump_lands_inside_the_program() {
        // A jump past the end would make the kernel refuse the program at
        // install time (the guard would then fail closed, exit 71): checked
        // here for every posture, the clone block included.
        for t in postures().into_iter().chain([FilterTraps { open: true, secrets: true, no_sends: true, ..Default::default() }]) {
            let p = build_program(&t);
            assert!(p.len() <= 4096, "{t:?}: {} instructions", p.len());
            for (i, ins) in p.iter().enumerate() {
                let class = (ins.code & 0x07) as u32;
                if class != libc::BPF_JMP {
                    continue;
                }
                let targets: Vec<usize> = if ins.code & 0xf0 == libc::BPF_JA as u16 {
                    vec![i + 1 + ins.k as usize]
                } else {
                    vec![i + 1 + ins.jt as usize, i + 1 + ins.jf as usize]
                };
                for to in targets {
                    assert!(to < p.len(), "{t:?}: instruction {i} jumps to {to} of {}", p.len());
                }
            }
            assert_eq!((p.last().unwrap().code & 0x07) as u32, libc::BPF_RET, "{t:?}: the program ends in a return");
        }
    }

    #[test]
    fn an_accept_reaches_the_supervisor_where_it_can_be_performed() {
        // exec-routing.md §7.5 (2026-10-02), "A holder's accept".
        for t in postures() {
            let p = build_program(&t);
            let want = if t.open && t.secrets { NOTIF } else { ALLOW };
            assert_eq!(run(&p, libc::SYS_accept), want, "{t:?}");
            assert_eq!(run(&p, libc::SYS_accept4), want, "{t:?}");
            // listen and bind are not accepts.
            assert_eq!(run(&p, libc::SYS_listen), ALLOW, "{t:?}");
        }
        // A kernel that cannot copy a socket cannot perform an accept: not
        // trapped. prctl still traps (it needs no copy).
        let old = FilterTraps { open: true, secrets: true, no_sends: true, ..Default::default() };
        assert_eq!(run(&build_program(&old), libc::SYS_accept4), ALLOW);
        assert_eq!(run_filter(&build_program(&old), libc::SYS_prctl as u32, AUDIT_ARCH, [crate::lineage::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0, 0]), NOTIF);
    }

    #[test]
    fn a_shared_memory_attach_and_a_queue_send_reach_the_supervisor_under_a_secret_policy() {
        // Plan 13 §9 R1, the file shapes (2026-10-02).
        for t in postures() {
            let p = build_program(&t);
            let want = if t.open && t.secrets { NOTIF } else { ALLOW };
            for nr in [libc::SYS_shmat, libc::SYS_msgsnd, libc::SYS_mq_timedsend] {
                assert_eq!(run(&p, nr), want, "{nr} {t:?}");
            }
            // What carries no bytes, or receives them, runs at full speed.
            // P0 triage 1b: a memfd a holder creates is marked at its birth.
            assert_eq!(run(&p, libc::SYS_memfd_create), want, "memfd_create {t:?}");
            for nr in [libc::SYS_shmget, libc::SYS_shmdt, libc::SYS_shmctl, libc::SYS_msgget, libc::SYS_msgrcv, libc::SYS_mq_open, libc::SYS_mq_timedreceive, libc::SYS_mmap] {
                assert_eq!(run(&p, nr), ALLOW, "{nr} {t:?}");
            }
        }
    }

    #[test]
    fn a_payload_signal_reaches_the_supervisor_under_a_secret_policy() {
        // Plan 13 §4.9 (2026-10-02).
        for t in postures() {
            let p = build_program(&t);
            for nr in crate::guard_signals::payload_nrs() {
                let got = run(&p, nr);
                if t.open && t.secrets {
                    assert_eq!(got, NOTIF, "{nr} {t:?}");
                }
            }
            if t.guard_pid == 0 {
                // kill carries only a number: not trapped for it (the guard's
                // own protection traps it only when aimed at the guard).
                assert_eq!(run(&p, libc::SYS_kill), ALLOW, "{t:?}");
            }
        }
    }

    #[test]
    fn the_wait_family_reaches_the_supervisor_under_a_secret_policy() {
        // Plan 13 §4.9 (2026-10-03): the reaper of a holder becomes one.
        for t in postures().into_iter().chain([FilterTraps { open: true, secrets: true, no_sends: true, ..Default::default() }]) {
            let p = build_program(&t);
            let want = if t.open && t.secrets { NOTIF } else { ALLOW };
            assert_eq!(run(&p, libc::SYS_wait4), want, "{t:?}");
            assert_eq!(run(&p, libc::SYS_waitid), want, "{t:?}");
            // Whatever the arguments (WNOHANG, WNOWAIT, P_PIDFD, a rusage).
            assert_eq!(run_filter(&p, libc::SYS_wait4 as u32, AUDIT_ARCH, [u64::MAX, 0x1000, libc::WNOHANG as u64, 0x2000, 0, 0]), want, "{t:?}");
            assert_eq!(run_filter(&p, libc::SYS_waitid as u32, AUDIT_ARCH, [3, 5, 0x1000, (libc::WEXITED | libc::WNOWAIT) as u64, 0x2000, 0]), want, "{t:?}");
            // Task creation and exit stay untrapped (the bubblewrap wrap).
            assert_eq!(run(&p, libc::SYS_exit_group), ALLOW, "{t:?}");
            assert_eq!(run_filter(&p, libc::SYS_clone as u32, AUDIT_ARCH, [libc::SIGCHLD as u64, 0, 0, 0, 0, 0]), ALLOW, "{t:?}");
            // Signals waited for are not the wait family.
            assert_eq!(run(&p, libc::SYS_rt_sigtimedwait), ALLOW, "{t:?}");
        }
    }

    #[test]
    fn pidfd_get_info_is_refused_under_a_secret_policy() {
        // Plan 13 §4.9 (2026-10-03): PIDFD_INFO_EXIT hands any pidfd holder
        // the exit status. ENOTTY, what a kernel before 6.13 answers.
        let enotty = Some(libc::SECCOMP_RET_ERRNO | libc::ENOTTY as u32);
        let iowr = |size: u64| (3u64 << 30) | (size << 16) | (0xFF << 8) | 11;
        for t in postures() {
            let p = build_program(&t);
            let on = t.open && t.secrets;
            let ioctl = |req: u64| run_filter(&p, libc::SYS_ioctl as u32, AUDIT_ARCH, [3, req, 0x1000, 0, 0, 0]);
            for size in [64, 72, 0, 0x3fff] {
                assert_eq!(ioctl(iowr(size)), if on { enotty } else { ALLOW }, "{t:?} size {size}");
            }
            // The high word is ignored by the kernel and by the filter.
            assert_eq!(ioctl((7u64 << 32) | iowr(64)), if on { enotty } else { ALLOW }, "{t:?}");
            // The pidfd namespace ioctls and another driver's number 11 run.
            assert_eq!(ioctl(0xFF01), ALLOW, "{t:?}");
            assert_eq!(ioctl((3u64 << 30) | (64 << 16) | (0xFE << 8) | 11), ALLOW, "{t:?}");
            assert_eq!(ioctl(libc::TIOCGWINSZ as u64), ALLOW, "{t:?}");
            // The terminal block in front still refuses its two.
            assert_eq!(ioctl(TIOCSTI as u64), EPERM, "{t:?}");
            // The request's value in another call changes nothing.
            assert_eq!(run_filter(&p, libc::SYS_read as u32, AUDIT_ARCH, [3, iowr(64), 0, 0, 0, 0]), ALLOW, "{t:?}");
            assert_eq!(run_filter(&p, libc::SYS_connect as u32, AUDIT_ARCH, [3, iowr(64), 0, 0, 0, 0]), NOTIF, "{t:?}");
        }
    }

    #[test]
    fn a_foreign_arch_is_killed() {
        let p = build_program(&FilterTraps::default());
        assert_eq!(run_filter(&p, libc::SYS_read as u32, 0x4000_0003, [0; 6]), Some(libc::SECCOMP_RET_KILL_PROCESS));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x32_numbers_are_refused_in_every_posture() {
        // Finding 10: `connect | X32` (and every other x32 number) would miss
        // every plain-number trap on a kernel with x32 enabled.
        let enosys = Some(libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32);
        for t in postures() {
            let p = build_program(&t);
            for nr in [libc::SYS_connect, libc::SYS_openat, libc::SYS_io_uring_setup, libc::SYS_kill, libc::SYS_read] {
                assert_eq!(run_filter(&p, nr as u32 | X32_SYSCALL_BIT, AUDIT_ARCH, [0; 6]), enosys, "{t:?} nr {nr}");
            }
        }
    }

    #[test]
    fn a_signal_to_the_guard_is_still_checked() {
        let t = FilterTraps { guard_pid: 4242, ..Default::default() };
        let p = build_program(&t);
        assert_eq!(run_filter(&p, libc::SYS_kill as u32, AUDIT_ARCH, [4242, 9, 0, 0, 0, 0]), NOTIF);
        assert_eq!(run_filter(&p, libc::SYS_kill as u32, AUDIT_ARCH, [5000, 15, 0, 0, 0, 0]), ALLOW);
    }
}
