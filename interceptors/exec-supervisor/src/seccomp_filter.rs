//! seccomp_filter — the PURE AgentShell seccomp deny-filter builder (defense in
//! depth on top of the bwrap overlay).
//!
//! SECURITY REASON. The asymmetric overlay (net-off + RO-outside-AgentView +
//! dropped capabilities) already boxes an AgentShell command, but a
//! prompt-injected command can still *reach for* the kernel's most dangerous
//! surfaces — trace another process (`ptrace`, `process_vm_readv/writev`), reach
//! into the host through a filesystem handle (`open_by_handle_at`), reprogram the
//! machine (`kexec_*`, `init_module`, `bpf`, `reboot`), or pry at the namespace
//! walls (`mount`, `pivot_root`, `setns`, `move_mount`). Most of those already
//! need capabilities we drop, but a deny-list closes the gap *structurally*: the
//! call returns EPERM before it can probe for a kernel bug or a capability we
//! missed. This mirrors the Docker/Codex hardened seccomp defaults — the syscalls
//! below are dangerous and never legitimately needed by ordinary agent tools.
//!
//! WHY IT LIVES HERE (pure) + NO libc. This module builds the raw BPF program as
//! bytes with zero privileges and zero syscalls, so the whole deny-list is
//! reviewable and unit-tested in the DEFAULT build (the crate's non-negotiable
//! contract: `cargo test -p exec-supervisor` passes with no `kernel` feature and
//! hence no `libc`). All BPF/seccomp/syscall constants are declared locally as
//! stable Linux UAPI values. Only the kernel feature turns these bytes into an
//! installed filter — by writing them to an fd handed to `bwrap --seccomp <fd>`,
//! which the kernel installs via `SECCOMP_SET_MODE_FILTER`.
//!
//! PROGRAM SHAPE (a classic cBPF deny-list, default-ALLOW):
//!   1. load `arch`; if it is not our AUDIT_ARCH → KILL_PROCESS (defensive: a
//!      foreign-arch syscall would misread the nr, so we refuse to guess — same
//!      posture as the execve listener in `kernel.rs`).
//!   2. load `nr`; for each denied syscall a JEQ that on match returns
//!      `SECCOMP_RET_ERRNO | EPERM` (io_uring among them: its SQEs open
//!      sockets without passing step 2b).
//!   2b. `socket(AF_VSOCK, …)` → `EAFNOSUPPORT`, in every posture: vsock is not
//!      network-namespaced on the kernels we run on, so `--unshare-net` does
//!      not cut it, and on WSL2 it reaches the Windows host (the interop door,
//!      `mandu_arbiter::wsl`; on a VM guest, the hypervisor).
//!   3. (deny_userns posture only) argument-inspecting userns-nesting denials:
//!      `unshare`/`clone` with CLONE_NEWUSER in args[0] → EPERM; `clone3` →
//!      ENOSYS (see `agentshell_seccomp_filter_with`).
//!   4. fall-through → `SECCOMP_RET_ALLOW` (everything else runs normally).
//!
//! TWO POSTURES. The deny-list has two builder entry points because the
//! userns-nesting denial has two owners depending on the probed bwrap:
//!   - `agentshell_seccomp_filter()` — the BASE list. Used when bwrap ≥ 0.8
//!     supplies `--disable-userns`: the flag closes the nested-userns
//!     cap-regain hole, so the filter does not (and must not blanket-deny
//!     `unshare`/`clone`, which benign tools use without CLONE_NEWUSER).
//!   - `agentshell_seccomp_filter_with(deny_userns=true)` — the base list PLUS
//!     the userns-nesting denials. Used when the probed bwrap lacks
//!     `--disable-userns` (< 0.8): the filter itself closes the hole, denying
//!     ONLY the CLONE_NEWUSER-carrying `unshare`/`clone` (plain fork /
//!     clone-without-NEWUSER stay allowed) and blanket-ENOSYS'ing `clone3`
//!     (its flags live in user memory cBPF cannot read; ENOSYS — not EPERM —
//!     so glibc/runtimes fall back to plain `clone`, which IS filtered — the
//!     same pattern Docker/systemd use).

// ── sock_filter (raw BPF instruction) ────────────────────────────────────────
// bwrap reads a `struct sock_filter[]` array in NATIVE layout off the --seccomp
// fd and installs it verbatim. The layout is fixed Linux UAPI:
//     struct sock_filter { __u16 code; __u8 jt; __u8 jf; __u32 k; }  // 8 bytes
// We emit each instruction as 8 native-endian bytes and concatenate them.
const SOCK_FILTER_LEN: usize = 8;

// ── BPF opcode + seccomp return constants (stable UAPI; declared here so the
//    pure build needs no libc) ──────────────────────────────────────────────
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JSET: u16 = 0x40;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;
const BPF_ALU: u16 = 0x04;
const BPF_AND: u16 = 0x50;

/// SECCOMP_RET_ERRNO — return the low 16 bits as the syscall's `errno`.
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
/// SECCOMP_RET_ALLOW — let the syscall through.
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
/// SECCOMP_RET_KILL_PROCESS — kill the whole process (the arch-mismatch guard).
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

/// EPERM — the errno a denied syscall returns (matches Docker's default action).
const EPERM: u32 = 1;
/// ENOSYS — the errno `clone3` returns in the deny_userns posture: callers
/// (glibc, runtimes) treat ENOSYS as "clone3 unavailable" and fall back to
/// plain `clone`, which the filter DOES inspect; EPERM would instead break
/// ordinary process spawning.
const ENOSYS: u32 = 38;

// ── seccomp_data field offsets (the BPF program reads these absolute offsets) ─
/// `struct seccomp_data { int nr; __u32 arch; __u64 instruction_pointer;
/// __u64 args[6]; }` — `nr` at 0, `arch` at 4, `args[0]` at 16.
const NR_OFF: u32 = 0;
const ARCH_OFF: u32 = 4;
/// The LOW 32 bits of `args[0]` (both supported arches are little-endian, so
/// the low word of the __u64 at offset 16 is at byte offset 16). cBPF loads
/// are 32-bit, so a 64-bit arg is inspected one word at a time; CLONE_NEWUSER
/// is bit 28 — it lives entirely in this low word, so no high-word (offset 20)
/// check is needed for it: the high bits cannot set or clear bit 28.
const ARG0_LO_OFF: u32 = 16;

/// CLONE_NEWUSER (bit 28) — the flag whose presence in `unshare`/`clone` args
/// mints a new user namespace (the cap-regain surface the deny_userns posture
/// closes).
const CLONE_NEWUSER: u32 = 0x1000_0000;

// ── AUDIT_ARCH_* for the architecture guard (not the same as the syscall ABI;
//    it is the value the kernel puts in seccomp_data.arch) ─────────────────────
/// EM_X86_64(62) | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE.
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;
/// EM_AARCH64(183) | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE.
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;

// ── The denied syscall table, per arch ───────────────────────────────────────
// Conservative deny-list matching the Docker/Codex hardened defaults: syscalls
// that are dangerous and never legitimately needed by ordinary agent tools. We
// deliberately do NOT deny execve/execveat, openat/openat2, clone/clone3/fork,
// socket/connect (net is already dead via the netns; only the AF_VSOCK family,
// which the netns does not cover, is refused by the arg check below), read/write, or unshare —
// benign tools use all of these. Userns NESTING (the one dangerous use of
// unshare/clone) is denied by whichever mechanism the probed bwrap supports:
// `--disable-userns` (≥ 0.8), or the deny_userns posture's argument-inspecting
// checks here (`agentshell_seccomp_filter_with`) — never by a blanket entry in
// this table. Numbers verified against the kernel syscall tables:
//   x86_64  → asm/unistd_64.h
//   aarch64 → asm-generic/unistd.h (the generic ABI aarch64 uses)
//
// Each entry is (name, nr); the name is for readability + tests, the nr is what
// the BPF program compares `seccomp_data.nr` against.

/// x86_64 denied syscalls (numbers from `asm/unistd_64.h`).
#[cfg(target_arch = "x86_64")]
pub const DENIED_SYSCALLS: &[(&str, u32)] = &[
    ("ptrace", 101),
    ("process_vm_readv", 310),
    ("process_vm_writev", 311),
    ("kcmp", 312),
    ("add_key", 248),
    ("keyctl", 250),
    ("request_key", 249),
    ("bpf", 321),
    ("userfaultfd", 323),
    ("perf_event_open", 298),
    ("kexec_load", 246),
    ("kexec_file_load", 320),
    ("init_module", 175),
    ("finit_module", 313),
    ("delete_module", 176),
    ("open_by_handle_at", 304),
    ("name_to_handle_at", 303),
    ("mount", 165),
    ("umount2", 166),
    ("pivot_root", 155),
    ("move_mount", 429),
    ("fsopen", 430),
    // The rest of the new mount API (sandbox-security-review-2026-09-28
    // finding 12): each needs CAP_SYS_ADMIN, which the box drops, so this is
    // defense in depth. Same numbers on both arches.
    ("open_tree", 428),
    ("fsconfig", 431),
    ("fsmount", 432),
    ("fspick", 433),
    ("mount_setattr", 442),
    ("swapon", 167),
    ("swapoff", 168),
    ("reboot", 169),
    ("setns", 308),    // io_uring: its SQEs create and connect sockets (IORING_OP_SOCKET /
    // CONNECT) without passing the socket(2) check below, so the AF_VSOCK
    // denial would be one ring away. Same numbers on both arches.
    ("io_uring_setup", 425),
    ("io_uring_enter", 426),
    ("io_uring_register", 427),
];

/// aarch64 denied syscalls (numbers from the generic `asm-generic/unistd.h` ABI,
/// which aarch64 uses — they DIFFER from x86_64).
#[cfg(target_arch = "aarch64")]
pub const DENIED_SYSCALLS: &[(&str, u32)] = &[
    ("ptrace", 117),
    ("process_vm_readv", 270),
    ("process_vm_writev", 271),
    ("kcmp", 272),
    ("add_key", 217),
    ("keyctl", 219),
    ("request_key", 218),
    ("bpf", 280),
    ("userfaultfd", 282),
    ("perf_event_open", 241),
    ("kexec_load", 104),
    ("kexec_file_load", 294),
    ("init_module", 105),
    ("finit_module", 273),
    ("delete_module", 106),
    ("open_by_handle_at", 265),
    ("name_to_handle_at", 264),
    ("mount", 40),
    ("umount2", 39),
    ("pivot_root", 41),
    ("move_mount", 429),
    ("fsopen", 430),
    // The rest of the new mount API (sandbox-security-review-2026-09-28
    // finding 12): each needs CAP_SYS_ADMIN, which the box drops, so this is
    // defense in depth. Same numbers on both arches.
    ("open_tree", 428),
    ("fsconfig", 431),
    ("fsmount", 432),
    ("fspick", 433),
    ("mount_setattr", 442),
    ("swapon", 224),
    ("swapoff", 225),
    ("reboot", 142),
    ("setns", 268),    // io_uring: its SQEs create and connect sockets (IORING_OP_SOCKET /
    // CONNECT) without passing the socket(2) check below, so the AF_VSOCK
    // denial would be one ring away. Same numbers on both arches.
    ("io_uring_setup", 425),
    ("io_uring_enter", 426),
    ("io_uring_register", 427),
];

/// Other arches: we refuse to guess syscall numbers. The builder returns an EMPTY
/// filter and the kernel wiring installs NONE (and, for the AgentShell, fails
/// closed rather than run an un-filtered sandbox — see `kernel.rs`). Provide the
/// symbol so the rest of the crate compiles on any target.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const DENIED_SYSCALLS: &[(&str, u32)] = &[];

// ── userns-nesting syscall numbers (the deny_userns posture inspects these;
//    they must NOT join DENIED_SYSCALLS — a blanket deny would break benign
//    tools that unshare/clone without CLONE_NEWUSER) ─────────────────────────
#[cfg(target_arch = "x86_64")]
const SYS_UNSHARE: u32 = 272;
#[cfg(target_arch = "x86_64")]
const SYS_CLONE: u32 = 56;
#[cfg(target_arch = "aarch64")]
const SYS_UNSHARE: u32 = 97;
#[cfg(target_arch = "aarch64")]
const SYS_CLONE: u32 = 220;
/// socket(2): arg0 is the address family.
#[cfg(target_arch = "x86_64")]
const SYS_SOCKET: u32 = 41;
#[cfg(target_arch = "aarch64")]
const SYS_SOCKET: u32 = 198;
#[cfg(target_arch = "x86_64")]
const SYS_SOCKETPAIR: u32 = 53;
#[cfg(target_arch = "aarch64")]
const SYS_SOCKETPAIR: u32 = 199;
#[cfg(target_arch = "x86_64")]
const SYS_CONNECT: u32 = 42;
#[cfg(target_arch = "aarch64")]
const SYS_CONNECT: u32 = 203;
/// AF_UNIX, and the socket types a Unix socket can SEND TO ANY PATH with
/// (`sendto`/`sendmsg` with an address): SOCK_DGRAM, and SOCK_RAW, which the
/// kernel turns into SOCK_DGRAM for AF_UNIX (`unix_create`). A stream socket
/// refuses an address on send and a seqpacket socket ignores it.
const AF_UNIX: u32 = 1;
const SOCK_DGRAM: u32 = 2;
const SOCK_RAW: u32 = 3;
/// SOCK_TYPE_MASK: the type without SOCK_CLOEXEC / SOCK_NONBLOCK.
const SOCK_TYPE_MASK: u32 = 0xf;
/// The LOW 32 bits of `args[1]` (the socket type).
const ARG1_LO_OFF: u32 = 24;
/// EACCES: a box whose connects nobody can supervise refuses every connect.
const EACCES: u32 = 13;
/// `AF_VSOCK` (Hyper-V sockets on WSL2, virtio-vsock on VM guests): a channel
/// to the HOST that `--unshare-net` does not cut (vsock is not network-
/// namespaced on the kernels we run on). Denied in every AgentShell box.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const AF_VSOCK: u32 = 40;
/// The errno a denied family returns: "address family not supported", the
/// answer a tool already handles for a kernel without vsock.
const EAFNOSUPPORT: u32 = 97;

/// clone3 is asm-generic-only — 435 on every arch.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const SYS_CLONE3: u32 = 435;

/// Encode one `struct sock_filter` as 8 native-endian bytes.
fn insn(code: u16, jt: u8, jf: u8, k: u32) -> [u8; SOCK_FILTER_LEN] {
    let mut b = [0u8; SOCK_FILTER_LEN];
    b[0..2].copy_from_slice(&code.to_ne_bytes());
    b[2] = jt;
    b[3] = jf;
    b[4..8].copy_from_slice(&k.to_ne_bytes());
    b
}

/// Build the BASE AgentShell seccomp deny-filter as RAW BYTES suitable for
/// `bwrap --seccomp <fd>` (a `struct sock_filter[]` in native layout). The
/// posture for a bwrap ≥ 0.8 whose `--disable-userns` owns the userns-nesting
/// denial. Equivalent to `agentshell_seccomp_filter_with(false)`.
///
/// Returns an EMPTY `Vec` on an unsupported architecture (we never emit wrong
/// syscall numbers); the kernel wiring treats "no filter" as a fail-closed setup
/// failure for the AgentShell rather than running an un-filtered sandbox.
pub fn agentshell_seccomp_filter() -> Vec<u8> {
    agentshell_seccomp_filter_with(false)
}

/// Build the AgentShell seccomp deny-filter, optionally with the userns-nesting
/// denials (`deny_userns` — the posture for a probed bwrap WITHOUT
/// `--disable-userns`, < 0.8). When set, the program ADDITIONALLY emits, after
/// the base deny pairs:
///   - `unshare(flags)`  → EPERM iff `flags & CLONE_NEWUSER` (args[0] low word);
///   - `clone(flags, …)` → same JSET check (on both x86_64 and aarch64 the raw
///     clone syscall takes flags as arg0);
///   - `clone3`          → ENOSYS unconditionally (its flags live in a
///     user-memory struct cBPF cannot read; ENOSYS makes callers fall back to
///     the filtered `clone`, where EPERM would break ordinary spawning).
/// Plain fork / clone-without-NEWUSER / unshare-without-NEWUSER stay allowed.
pub fn agentshell_seccomp_filter_with(deny_userns: bool) -> Vec<u8> {
    agentshell_seccomp_filter_opts(deny_userns, false)
}

/// `agentshell_seccomp_filter_with`, plus `deny_connect`: every `connect` in
/// the box refused EACCES. The posture for a box whose connects nobody can
/// supervise (exec-routing.md §4.2: no seccomp listener could be installed
/// and no whole-agent guard serves the box), so the socket allow-list fails
/// closed instead of open.
// The BPF program is pushed one instruction at a time, a comment per step and
// cfg-gated steps among them; a `vec![]` literal cannot hold that.
#[allow(clippy::vec_init_then_push)]
pub fn agentshell_seccomp_filter_opts(deny_userns: bool, deny_connect: bool) -> Vec<u8> {
    // Unsupported arch → no correct numbers to emit → empty (fail closed upstream).
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = (deny_userns, deny_connect);
        return Vec::new();
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        let ld = BPF_LD | BPF_W | BPF_ABS;
        let jeq = BPF_JMP | BPF_JEQ | BPF_K;
        let jset = BPF_JMP | BPF_JSET | BPF_K;
        let ret = BPF_RET | BPF_K;

        let mut prog: Vec<[u8; SOCK_FILTER_LEN]> = Vec::new();

        // 1) load arch; if it matches, skip the kill (jt=1); else fall through.
        prog.push(insn(ld, 0, 0, ARCH_OFF));
        prog.push(insn(jeq, 1, 0, AUDIT_ARCH));
        prog.push(insn(ret, 0, 0, SECCOMP_RET_KILL_PROCESS));

        // 2) load nr, then one (JEQ → ERRNO) pair per denied syscall.
        prog.push(insn(ld, 0, 0, NR_OFF));
        // 2a) x32-ABI numbers → ENOSYS, in every posture (sandbox-security-
        //     review-2026-09-28 finding 10): every number below is a plain
        //     x86_64 one, so on a kernel with x32 enabled `connect | X32`
        //     would miss the `deny_connect` posture and `unshare | X32` the
        //     userns denials.
        #[cfg(target_arch = "x86_64")]
        {
            prog.push(insn(jset, 0, 1, X32_SYSCALL_BIT));
            prog.push(insn(ret, 0, 0, SECCOMP_RET_ERRNO | ENOSYS));
        }
        for (_, nr) in DENIED_SYSCALLS {
            // match → next instr (the ERRNO ret); miss → skip it (jf=1).
            prog.push(insn(jeq, 0, 1, *nr));
            prog.push(insn(ret, 0, 0, SECCOMP_RET_ERRNO | EPERM));
        }

        // 2b) socket(AF_VSOCK) → EAFNOSUPPORT, in every posture. The box's
        //     netns does not cut vsock, which on WSL2 reaches the Windows host
        //     (mandu_arbiter::wsl) and on a VM guest the hypervisor. Same
        //     5-instruction shape as the userns blocks: inspect args[0], then
        //     RELOAD nr before falling through.
        prog.push(insn(jeq, 0, 4, SYS_SOCKET));
        prog.push(insn(ld, 0, 0, ARG0_LO_OFF));
        prog.push(insn(jeq, 0, 1, AF_VSOCK));
        prog.push(insn(ret, 0, 0, SECCOMP_RET_ERRNO | EAFNOSUPPORT));
        prog.push(insn(ld, 0, 0, NR_OFF));

        // 2c) AF_UNIX datagram sockets → EPERM, from socket() and socketpair(),
        //     in every posture (exec-routing.md §4.2). An unconnected (or even
        //     a connected) Unix datagram socket sends to ANY path its sendto /
        //     sendmsg names, and those calls carry the address in memory a
        //     filter cannot read; without such a socket, `connect` is the only
        //     way a box reaches a host socket, and `connect` is supervised.
        //     9 instructions each: nr match → arg0 == AF_UNIX → (arg1 & mask)
        //     is DGRAM or RAW → EPERM; every miss lands on the nr reload.
        for nr in [SYS_SOCKET, SYS_SOCKETPAIR] {
            prog.push(insn(jeq, 0, 7, nr));
            prog.push(insn(ld, 0, 0, ARG0_LO_OFF));
            prog.push(insn(jeq, 0, 5, AF_UNIX));
            prog.push(insn(ld, 0, 0, ARG1_LO_OFF));
            prog.push(insn(BPF_ALU | BPF_AND | BPF_K, 0, 0, SOCK_TYPE_MASK));
            prog.push(insn(jeq, 1, 0, SOCK_DGRAM));
            prog.push(insn(jeq, 0, 1, SOCK_RAW));
            prog.push(insn(ret, 0, 0, SECCOMP_RET_ERRNO | EPERM));
            prog.push(insn(ld, 0, 0, NR_OFF));
        }

        // 2d) the fail-closed posture: no supervisor for the box's connects.
        if deny_connect {
            prog.push(insn(jeq, 0, 1, SYS_CONNECT));
            prog.push(insn(ret, 0, 0, SECCOMP_RET_ERRNO | EACCES));
        }

        // 3) userns-nesting denials (only when the filter owns them).
        if deny_userns {
            // unshare / clone: 5-instruction block each. The accumulator holds
            // `nr` on entry; a block that inspects args[0] must RELOAD `nr`
            // before falling through, or every later comparison would silently
            // key on the argument word instead of the syscall number.
            for nr in [SYS_UNSHARE, SYS_CLONE] {
                // nr match → inspect args; miss → skip the whole block (jf=4:
                // over the LD/JSET/RET/LD-nr quartet below).
                prog.push(insn(jeq, 0, 4, nr));
                prog.push(insn(ld, 0, 0, ARG0_LO_OFF));
                // Bit set → next instr (the EPERM ret); clear → skip it (jf=1)
                // onto the nr reload, then fall through to the later checks.
                prog.push(insn(jset, 0, 1, CLONE_NEWUSER));
                prog.push(insn(ret, 0, 0, SECCOMP_RET_ERRNO | EPERM));
                prog.push(insn(ld, 0, 0, NR_OFF));
            }
            // clone3: blanket ENOSYS (flags unreadable from cBPF; see fn doc).
            prog.push(insn(jeq, 0, 1, SYS_CLONE3));
            prog.push(insn(ret, 0, 0, SECCOMP_RET_ERRNO | ENOSYS));
        }

        // 4) fall-through → ALLOW (default-allow deny-list).
        prog.push(insn(ret, 0, 0, SECCOMP_RET_ALLOW));

        let mut out = Vec::with_capacity(prog.len() * SOCK_FILTER_LEN);
        for i in &prog {
            out.extend_from_slice(i);
        }
        out
    }
}

// ── The box's socket allow-list: a USER_NOTIF filter (exec-routing.md §4.2) ──
// A second, separate program: the deny-filter above is a fixed list bwrap
// installs from an fd; this one is installed by the box's forked child itself
// (`SECCOMP_FILTER_FLAG_NEW_LISTENER`) before it execs bwrap, so the waiting
// parent can serve it (`kernel::socket_supervision`). It hands the supervisor
// the box's `connect` (which the supervisor performs itself, never CONTINUE)
// and `bind` (CONTINUEd; the supervisor reads back which file it created).
// Sends need no trap: the deny-filter leaves the box no Unix datagram socket,
// the only kind that sends to a path it names.

/// SECCOMP_RET_USER_NOTIF — hand the syscall to the listener.
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
/// x86_64 x32-ABI syscalls carry this bit in `nr` under the SAME audit arch: a
/// filter keyed on plain numbers would miss `connect | X32` where the kernel
/// enables x32, so every x32 call is refused (ENOSYS) in the box.
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// The trapped syscall numbers: (connect, bind).
#[cfg(target_arch = "x86_64")]
pub const BOX_SOCKET_NRS: (u32, u32) = (42, 49);
#[cfg(target_arch = "aarch64")]
pub const BOX_SOCKET_NRS: (u32, u32) = (203, 200);

/// Build the box's socket USER_NOTIF filter as raw `struct sock_filter[]`
/// bytes (the caller installs it with `SECCOMP_SET_MODE_FILTER`). EMPTY on an
/// unsupported arch: the caller then fails closed (`deny_connect`).
pub fn box_socket_notify_filter() -> Vec<u8> {
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        return Vec::new();
    }
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        let ld = BPF_LD | BPF_W | BPF_ABS;
        let jeq = BPF_JMP | BPF_JEQ | BPF_K;
        let ret = BPF_RET | BPF_K;
        let (connect, bind) = BOX_SOCKET_NRS;
        let mut prog: Vec<[u8; SOCK_FILTER_LEN]> = vec![
            insn(ld, 0, 0, ARCH_OFF),
            insn(jeq, 1, 0, AUDIT_ARCH),
            insn(ret, 0, 0, SECCOMP_RET_KILL_PROCESS),
            insn(ld, 0, 0, NR_OFF),
        ];
        #[cfg(target_arch = "x86_64")]
        {
            prog.push(insn(BPF_JMP | BPF_JSET | BPF_K, 0, 1, X32_SYSCALL_BIT));
            prog.push(insn(ret, 0, 0, SECCOMP_RET_ERRNO | ENOSYS));
        }
        prog.push(insn(jeq, 2, 0, connect));
        prog.push(insn(jeq, 1, 0, bind));
        prog.push(insn(ret, 0, 0, SECCOMP_RET_ALLOW));
        prog.push(insn(ret, 0, 0, SECCOMP_RET_USER_NOTIF));
        prog.concat()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode the byte stream back into (code, jt, jf, k) tuples so we can assert
    /// the program's shape without any kernel involvement.
    fn decode(bytes: &[u8]) -> Vec<(u16, u8, u8, u32)> {
        assert_eq!(bytes.len() % SOCK_FILTER_LEN, 0, "byte stream must be whole instructions");
        bytes
            .chunks_exact(SOCK_FILTER_LEN)
            .map(|c| {
                let code = u16::from_ne_bytes([c[0], c[1]]);
                let k = u32::from_ne_bytes([c[4], c[5], c[6], c[7]]);
                (code, c[2], c[3], k)
            })
            .collect()
    }

    /// A minimal cBPF evaluator over the OPCODES THIS BUILDER EMITS (LD|W|ABS,
    /// JEQ|K, JSET|K, RET|K), so tests can assert the filter's VERDICT for a
    /// synthetic `seccomp_data` — the only proof that survives a jump
    /// off-by-one (which would silently change verdicts, not the byte shape).
    /// Panics on any opcode/branch outside the emitted set.
    fn run_filter(insns: &[(u16, u8, u8, u32)], nr: u32, arch: u32, arg0: u64) -> u32 {
        run_filter_args(insns, nr, arch, [arg0, 0, 0, 0, 0, 0])
    }

    /// `run_filter` with every argument word.
    fn run_filter_args(insns: &[(u16, u8, u8, u32)], nr: u32, arch: u32, args: [u64; 6]) -> u32 {
        // struct seccomp_data, native layout: nr(4) arch(4) ip(8) args[6]*8.
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(&nr.to_ne_bytes());
        data[4..8].copy_from_slice(&arch.to_ne_bytes());
        for (i, a) in args.iter().enumerate() {
            data[16 + 8 * i..24 + 8 * i].copy_from_slice(&a.to_ne_bytes());
        }
        let load_w = |off: u32| -> u32 {
            let off = off as usize;
            u32::from_ne_bytes(data[off..off + 4].try_into().unwrap())
        };
        let mut acc: u32 = 0;
        let mut pc = 0usize;
        loop {
            assert!(pc < insns.len(), "fell off the end of the program");
            let (code, jt, jf, k) = insns[pc];
            if code == BPF_LD | BPF_W | BPF_ABS {
                acc = load_w(k);
                pc += 1;
            } else if code == BPF_JMP | BPF_JEQ | BPF_K {
                pc += 1 + if acc == k { jt as usize } else { jf as usize };
            } else if code == BPF_JMP | BPF_JSET | BPF_K {
                pc += 1 + if acc & k != 0 { jt as usize } else { jf as usize };
            } else if code == BPF_ALU | BPF_AND | BPF_K {
                acc &= k;
                pc += 1;
            } else if code == BPF_RET | BPF_K {
                return k;
            } else {
                panic!("unexpected opcode {code:#x} at {pc}");
            }
        }
    }

    /// The x32 refusal's instruction count (x86_64 only).
    const X32_INSNS: usize = if cfg!(target_arch = "x86_64") { 2 } else { 0 };
    #[cfg(target_arch = "x86_64")]
    const X32_BIT_OR_ZERO: u32 = X32_SYSCALL_BIT;
    #[cfg(not(target_arch = "x86_64"))]
    const X32_BIT_OR_ZERO: u32 = 0;

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_deny_filter_refuses_x32_numbers_in_every_posture() {
        // Finding 10: `connect | X32` would miss `deny_connect`, and
        // `unshare | X32` the userns denials, on a kernel with x32 enabled.
        for (userns, connect) in [(false, false), (true, false), (false, true), (true, true)] {
            let p = decode(&agentshell_seccomp_filter_opts(userns, connect));
            for nr in [SYS_CONNECT, SYS_UNSHARE, SYS_SOCKET, 0] {
                assert_eq!(run_filter_args(&p, nr | X32_SYSCALL_BIT, AUDIT_ARCH, [0; 6]), SECCOMP_RET_ERRNO | ENOSYS, "userns={userns} connect={connect} nr={nr}");
            }
        }
    }

    #[test]
    fn length_is_eight_bytes_per_instruction() {
        let f = agentshell_seccomp_filter();
        assert!(!f.is_empty(), "supported arch must emit a filter");
        // 5 fixed instructions (load arch, JEQ arch, kill, load nr, allow) + a
        // (JEQ, ERRNO) pair per denied syscall + the 5-insn AF_VSOCK block +
        // the two 9-insn Unix-datagram blocks (socket, socketpair) + the
        // 2-insn x32 refusal on x86_64.
        let expected_insns = 5 + X32_INSNS + 2 * DENIED_SYSCALLS.len() + 5 + 18;
        assert_eq!(f.len(), SOCK_FILTER_LEN * expected_insns);
        assert_eq!(decode(&f).len(), expected_insns);
    }

    #[test]
    fn base_filter_equals_with_false() {
        // `agentshell_seccomp_filter()` must stay the UNCHANGED base posture:
        // byte-identical to the parameterized builder with deny_userns off.
        assert_eq!(agentshell_seccomp_filter(), agentshell_seccomp_filter_with(false));
    }

    #[test]
    fn deny_userns_instruction_count_is_exact() {
        // Base + two 5-insn arg-inspecting blocks (unshare, clone) + the
        // 2-insn clone3 pair.
        let base = 5 + X32_INSNS + 2 * DENIED_SYSCALLS.len() + 5 + 18;
        let f = agentshell_seccomp_filter_with(true);
        assert_eq!(f.len(), SOCK_FILTER_LEN * (base + 12));
    }

    #[test]
    fn deny_userns_emits_jset_checks_and_clone3_enosys() {
        let insns = decode(&agentshell_seccomp_filter_with(true));
        let jeq = BPF_JMP | BPF_JEQ | BPF_K;
        let jset = BPF_JMP | BPF_JSET | BPF_K;
        let ld = BPF_LD | BPF_W | BPF_ABS;
        let ret = BPF_RET | BPF_K;
        // One JSET(CLONE_NEWUSER) block per inspected syscall, each preceded by
        // its nr JEQ and an args[0] load, followed by the EPERM ret and the nr
        // reload.
        for nr in [SYS_UNSHARE, SYS_CLONE] {
            let i = insns
                .iter()
                .position(|&(code, _, _, k)| code == jeq && k == nr)
                .unwrap_or_else(|| panic!("no JEQ for nr {nr}"));
            assert_eq!(insns[i], (jeq, 0, 4, nr), "nr miss must skip the whole 5-insn block");
            assert_eq!(insns[i + 1], (ld, 0, 0, ARG0_LO_OFF), "args[0] low-word load");
            assert_eq!(insns[i + 2], (jset, 0, 1, CLONE_NEWUSER), "JSET on CLONE_NEWUSER");
            assert_eq!(insns[i + 3], (ret, 0, 0, SECCOMP_RET_ERRNO | EPERM));
            assert_eq!(insns[i + 4], (ld, 0, 0, NR_OFF), "nr must be reloaded after the arg load");
        }
        // clone3 → unconditional ENOSYS (never EPERM).
        let c3 = insns
            .iter()
            .position(|&(code, _, _, k)| code == jeq && k == SYS_CLONE3)
            .expect("no JEQ for clone3");
        assert_eq!(insns[c3], (jeq, 0, 1, SYS_CLONE3));
        assert_eq!(insns[c3 + 1], (ret, 0, 0, SECCOMP_RET_ERRNO | ENOSYS));
        // The base filter must contain NONE of these (bwrap --disable-userns
        // owns the denial there).
        let base = decode(&agentshell_seccomp_filter());
        assert!(
            !base.iter().any(|&(code, _, _, k)| code == jset && k != X32_BIT_OR_ZERO),
            "the base posture must not inspect syscall args (the x32 JSET reads nr)"
        );
        assert!(
            !base.iter().any(|&(code, _, _, k)| code == jeq && k == SYS_CLONE3),
            "the base posture must not touch clone3"
        );
    }

    #[test]
    fn every_jump_lands_in_range_and_on_the_intended_kind() {
        // Raw cBPF: an off-by-one in jt/jf silently changes verdicts. Walk BOTH
        // postures; every conditional's two targets must land inside the
        // program and on an instruction kind this builder emits (LD / JEQ /
        // JSET / RET) — and the deny blocks' targets on the EXACT intended
        // instruction.
        for deny_userns in [false, true] {
            let insns = decode(&agentshell_seccomp_filter_with(deny_userns));
            let ld = BPF_LD | BPF_W | BPF_ABS;
            let jeq = BPF_JMP | BPF_JEQ | BPF_K;
            let jset = BPF_JMP | BPF_JSET | BPF_K;
            let ret = BPF_RET | BPF_K;
            for (i, &(code, jt, jf, k)) in insns.iter().enumerate() {
                if code != jeq && code != jset {
                    continue;
                }
                for target in [i + 1 + jt as usize, i + 1 + jf as usize] {
                    assert!(
                        target < insns.len(),
                        "insn {i} (code {code:#x}, k {k:#x}) jumps out of range to {target}"
                    );
                    let tcode = insns[target].0;
                    assert!(
                        tcode == ld || tcode == jeq || tcode == jset || tcode == ret,
                        "insn {i} jumps to unexpected opcode {tcode:#x} at {target}"
                    );
                }
                if code == jset && k == X32_BIT_OR_ZERO && i == 4 {
                    // The x32 refusal, right after the nr load: set → ENOSYS;
                    // clear → the first denied-syscall comparison.
                    assert_eq!(insns[i + 1 + jt as usize], (ret, 0, 0, SECCOMP_RET_ERRNO | ENOSYS));
                    assert_eq!(insns[i + 1 + jf as usize].0, jeq);
                } else if code == jset {
                    // Otherwise a JSET only appears in the deny_userns blocks:
                    // set → the EPERM ret; clear → the nr reload.
                    assert_eq!(k, CLONE_NEWUSER);
                    assert_eq!(insns[i + 1 + jt as usize], (ret, 0, 0, SECCOMP_RET_ERRNO | EPERM));
                    assert_eq!(insns[i + 1 + jf as usize], (ld, 0, 0, NR_OFF));
                }
                if (k == SYS_SOCKET || k == SYS_SOCKETPAIR) && code == jeq && insns[i + 2] == (jeq, 0, 5, AF_UNIX) {
                    // A Unix-datagram block: nr match → the args[0] load; every
                    // miss (nr, family, type) → the nr reload closing the block.
                    let reload = i + 8;
                    assert_eq!(insns[reload], (ld, 0, 0, NR_OFF));
                    assert_eq!((jt, jf), (0, 7));
                    assert_eq!(i + 3 + 5, reload, "a family miss reloads nr");
                    assert_eq!(insns[i + 7], (ret, 0, 0, SECCOMP_RET_ERRNO | EPERM));
                    assert_eq!(insns[i + 5], (jeq, 1, 0, SOCK_DGRAM), "DGRAM → the EPERM ret");
                    assert_eq!(insns[i + 6], (jeq, 0, 1, SOCK_RAW), "RAW → the EPERM ret, else the reload");
                }
                if code == jeq && k == SYS_SOCKET && insns[i + 2] == (jeq, 0, 1, AF_VSOCK) {
                    // The AF_VSOCK block: nr match → the args[0] load; miss →
                    // past the block (the next nr comparison), never inside it.
                    assert_eq!((jt, jf), (0, 4));
                    assert_eq!(insns[i + 2], (jeq, 0, 1, AF_VSOCK));
                    assert_eq!(insns[i + 3], (ret, 0, 0, SECCOMP_RET_ERRNO | EAFNOSUPPORT));
                    assert_eq!(insns[i + 4], (ld, 0, 0, NR_OFF), "nr must be reloaded after the arg load");
                    let (mcode, _, _, _) = insns[i + 1 + jf as usize];
                    assert!(mcode == jeq || mcode == ret, "nr miss must land on the next check or the allow");
                }
                if code == jeq && deny_userns && (k == SYS_UNSHARE || k == SYS_CLONE) {
                    // nr match → the args[0] load; miss → the next nr check
                    // (never into the middle of this block).
                    assert_eq!(insns[i + 1 + jt as usize], (ld, 0, 0, ARG0_LO_OFF));
                    let (mcode, _, _, mk) = insns[i + 1 + jf as usize];
                    assert_eq!(mcode, jeq, "nr miss must land on the next nr comparison");
                    assert_ne!(mk, k, "nr miss must not re-test the same nr");
                }
            }
        }
    }

    #[test]
    fn filter_verdicts_via_evaluation() {
        // Execute both postures against synthetic seccomp_data. This is the
        // authoritative off-by-one guard: a wrong jump target changes one of
        // these VERDICTS even when the byte shape looks right.
        let base = decode(&agentshell_seccomp_filter());
        let hard = decode(&agentshell_seccomp_filter_with(true));
        let eperm = SECCOMP_RET_ERRNO | EPERM;
        let enosys = SECCOMP_RET_ERRNO | ENOSYS;
        let newuser = CLONE_NEWUSER as u64;
        // Foreign arch → KILL, regardless of posture.
        for p in [&base, &hard] {
            assert_eq!(run_filter(p, 0, !AUDIT_ARCH, 0), SECCOMP_RET_KILL_PROCESS);
        }
        // A base-list syscall (ptrace) → EPERM in both postures.
        let ptrace = DENIED_SYSCALLS.iter().find(|(n, _)| *n == "ptrace").unwrap().1;
        assert_eq!(run_filter(&base, ptrace, AUDIT_ARCH, 0), eperm);
        assert_eq!(run_filter(&hard, ptrace, AUDIT_ARCH, 0), eperm);
        // unshare/clone WITH CLONE_NEWUSER: allowed by base (bwrap's
        // --disable-userns owns it), denied by the hard posture.
        for nr in [SYS_UNSHARE, SYS_CLONE] {
            assert_eq!(run_filter(&base, nr, AUDIT_ARCH, newuser), SECCOMP_RET_ALLOW);
            assert_eq!(run_filter(&hard, nr, AUDIT_ARCH, newuser), eperm);
            // …and combined with other clone flags, the bit still trips it.
            assert_eq!(run_filter(&hard, nr, AUDIT_ARCH, newuser | 0x11), eperm);
            // WITHOUT the bit (plain fork/thread/netns flags): allowed.
            assert_eq!(run_filter(&hard, nr, AUDIT_ARCH, 0), SECCOMP_RET_ALLOW);
            assert_eq!(run_filter(&hard, nr, AUDIT_ARCH, 0x0001_1000), SECCOMP_RET_ALLOW);
        }
        // clone3: base allows; hard posture → ENOSYS regardless of args.
        assert_eq!(run_filter(&base, SYS_CLONE3, AUDIT_ARCH, 0), SECCOMP_RET_ALLOW);
        assert_eq!(run_filter(&hard, SYS_CLONE3, AUDIT_ARCH, 0), enosys);
        assert_eq!(run_filter(&hard, SYS_CLONE3, AUDIT_ARCH, newuser), enosys);
        // An ordinary syscall (nr 0: read/io_setup) stays allowed in both.
        assert_eq!(run_filter(&base, 0, AUDIT_ARCH, 0), SECCOMP_RET_ALLOW);
        assert_eq!(run_filter(&hard, 0, AUDIT_ARCH, 0), SECCOMP_RET_ALLOW);
        // socket(AF_VSOCK) → EAFNOSUPPORT in both postures (the channel to the
        // WSL2 / VM host the netns does not cut); every other family allowed.
        let eafnosupport = SECCOMP_RET_ERRNO | EAFNOSUPPORT;
        for p in [&base, &hard] {
            assert_eq!(run_filter(p, SYS_SOCKET, AUDIT_ARCH, AF_VSOCK as u64), eafnosupport);
            for family in [1u64 /* AF_UNIX */, 2 /* AF_INET */, 10 /* AF_INET6 */, 16 /* AF_NETLINK */] {
                assert_eq!(run_filter(p, SYS_SOCKET, AUDIT_ARCH, family), SECCOMP_RET_ALLOW, "family {family}");
            }
            // io_uring (which could open the same socket without socket(2)) → EPERM.
            for name in ["io_uring_setup", "io_uring_enter", "io_uring_register"] {
                let nr = DENIED_SYSCALLS.iter().find(|(n, _)| *n == name).unwrap().1;
                assert_eq!(run_filter(p, nr, AUDIT_ARCH, 0), eperm, "{name}");
            }
        }
        // The later checks still key on nr after the vsock block's arg load:
        // clone WITH CLONE_NEWUSER is still denied in the hard posture.
        assert_eq!(run_filter(&hard, SYS_CLONE, AUDIT_ARCH, newuser), eperm);
    }

    #[test]
    fn first_instruction_is_the_arch_load() {
        let f = agentshell_seccomp_filter();
        let insns = decode(&f);
        let (code, jt, jf, k) = insns[0];
        assert_eq!(code, BPF_LD | BPF_W | BPF_ABS, "first insn must be an absolute word load");
        assert_eq!(k, ARCH_OFF, "…of seccomp_data.arch (offset 4)");
        assert_eq!((jt, jf), (0, 0));
        // The arch guard: a JEQ that on mismatch falls into KILL_PROCESS.
        assert_eq!(insns[1].0, BPF_JMP | BPF_JEQ | BPF_K);
        assert_eq!(insns[1].3, AUDIT_ARCH);
        assert_eq!(insns[2], (BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS));
        // Then the nr load.
        assert_eq!(insns[3], (BPF_LD | BPF_W | BPF_ABS, 0, 0, NR_OFF));
    }

    #[test]
    fn last_instruction_is_ret_allow() {
        let f = agentshell_seccomp_filter();
        let insns = decode(&f);
        assert_eq!(
            *insns.last().unwrap(),
            (BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW),
            "the deny-list must default-ALLOW everything not explicitly denied"
        );
    }

    #[test]
    fn ptrace_is_denied_with_eperm() {
        // ptrace's number is our canary that a JEQ(nr) is immediately followed by
        // a RET(ERRNO|EPERM) — the deny shape for every entry.
        let ptrace_nr = DENIED_SYSCALLS
            .iter()
            .find(|(n, _)| *n == "ptrace")
            .map(|(_, nr)| *nr)
            .expect("ptrace must be in the deny-list");
        let insns = decode(&agentshell_seccomp_filter());
        let jeq = insns
            .iter()
            .position(|&(code, _, _, k)| code == (BPF_JMP | BPF_JEQ | BPF_K) && k == ptrace_nr)
            .expect("a JEQ comparing nr to ptrace's number must be present");
        // On a match it falls through (jt=0) to the very next instruction…
        assert_eq!(insns[jeq].1, 0, "match falls through to the errno return");
        assert_eq!(insns[jeq].2, 1, "miss skips the errno return");
        assert_eq!(
            insns[jeq + 1],
            (BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | EPERM),
            "…which returns EPERM"
        );
    }

    #[test]
    fn every_denied_syscall_has_a_jeq_and_errno_pair() {
        let insns = decode(&agentshell_seccomp_filter());
        for (name, nr) in DENIED_SYSCALLS {
            let jeq = insns
                .iter()
                .position(|&(code, _, _, k)| code == (BPF_JMP | BPF_JEQ | BPF_K) && k == *nr);
            let jeq = jeq.unwrap_or_else(|| panic!("no JEQ for denied syscall {name} (nr {nr})"));
            assert_eq!(
                insns[jeq + 1],
                (BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | EPERM),
                "{name} must be followed by RET(ERRNO|EPERM)"
            );
        }
    }

    #[test]
    fn deny_list_covers_the_hardened_defaults() {
        // Guard against an accidental drop from the list (each is dangerous +
        // never needed by ordinary tools).
        for want in [
            "ptrace", "process_vm_readv", "process_vm_writev", "kcmp", "add_key", "keyctl",
            "request_key", "bpf", "userfaultfd", "perf_event_open", "kexec_load",
            "kexec_file_load", "init_module", "finit_module", "delete_module",
            "open_by_handle_at", "name_to_handle_at", "mount", "umount2", "pivot_root",
            "move_mount", "fsopen", "swapon", "swapoff", "reboot", "setns",
            "io_uring_setup", "io_uring_enter", "io_uring_register",
            "open_tree", "fsconfig", "fsmount", "fspick", "mount_setattr",
        ] {
            assert!(
                DENIED_SYSCALLS.iter().any(|(n, _)| *n == want),
                "deny-list must contain {want}"
            );
        }
        // …and must NOT deny the syscalls ordinary tools legitimately need.
        for forbidden in ["execve", "execveat", "openat", "clone", "socket", "read", "write", "unshare"] {
            assert!(
                !DENIED_SYSCALLS.iter().any(|(n, _)| *n == forbidden),
                "{forbidden} must NOT be denied (would break benign tools)"
            );
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn the_box_socket_filter_traps_connect_and_bind_and_nothing_else() {
        let p = decode(&box_socket_notify_filter());
        let (connect, bind) = BOX_SOCKET_NRS;
        let on = |nr: u32, args: [u64; 6]| run_filter_args(&p, nr, AUDIT_ARCH, args);
        for nr in [connect, bind] {
            assert_eq!(on(nr, [3, 0x1000, 16, 0, 0, 0]), SECCOMP_RET_USER_NOTIF, "nr {nr} goes to the supervisor");
        }
        // Everything else runs as issued: the box's other syscalls cost nothing
        // (sends included: the box has no socket that sends to a named path).
        for nr in [0u32, 1, 2, 41, 43, 44, 45, 46, 47, 50, 51, 53, 59, 257, 307, 435] {
            if ![connect, bind].contains(&nr) {
                assert_eq!(on(nr, [3, 0x1000, 5, 0, 0x7fff_0000, 16]), SECCOMP_RET_ALLOW, "nr {nr}");
            }
        }
        assert_eq!(run_filter_args(&p, connect, !AUDIT_ARCH, [0; 6]), SECCOMP_RET_KILL_PROCESS);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_box_socket_filter_refuses_x32_numbers() {
        let p = decode(&box_socket_notify_filter());
        let (connect, bind) = BOX_SOCKET_NRS;
        for nr in [connect, bind, 0] {
            assert_eq!(run_filter_args(&p, nr | X32_SYSCALL_BIT, AUDIT_ARCH, [0; 6]), SECCOMP_RET_ERRNO | ENOSYS);
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn the_box_has_no_unix_datagram_socket() {
        let eperm = SECCOMP_RET_ERRNO | EPERM;
        for deny_userns in [false, true] {
            let p = decode(&agentshell_seccomp_filter_with(deny_userns));
            let on = |nr: u32, dom: u64, ty: u64| run_filter_args(&p, nr, AUDIT_ARCH, [dom, ty, 0, 0, 0, 0]);
            for nr in [SYS_SOCKET, SYS_SOCKETPAIR] {
                // DGRAM and RAW (which AF_UNIX turns into DGRAM), with or
                // without SOCK_CLOEXEC / SOCK_NONBLOCK.
                for ty in [2u64, 3, 2 | 0x80000, 3 | 0x800, 2 | 0x80800] {
                    assert_eq!(on(nr, 1, ty), eperm, "nr {nr} AF_UNIX type {ty:#x}");
                }
                // Stream and seqpacket Unix sockets, and other families' datagrams, stay.
                for ty in [1u64, 5, 1 | 0x80000, 5 | 0x800] {
                    assert_eq!(on(nr, 1, ty), SECCOMP_RET_ALLOW, "nr {nr} AF_UNIX type {ty:#x}");
                }
                assert_eq!(on(nr, 2, 2), SECCOMP_RET_ALLOW, "AF_INET datagram");
                assert_eq!(on(nr, 16, 3), SECCOMP_RET_ALLOW, "AF_NETLINK raw (bwrap's loopback setup)");
            }
            // The block restores nr: a later check still keys on it.
            assert_eq!(on(DENIED_SYSCALLS[0].1, 1, 2), eperm);
            assert_eq!(on(SYS_CONNECT, 1, 2), SECCOMP_RET_ALLOW, "connect stays with the supervisor");
            // AF_VSOCK still refused on socket().
            assert_eq!(on(SYS_SOCKET, AF_VSOCK as u64, 1), SECCOMP_RET_ERRNO | EAFNOSUPPORT);
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn a_box_nobody_supervises_refuses_every_connect() {
        let p = decode(&agentshell_seccomp_filter_opts(false, true));
        let on = |nr: u32| run_filter_args(&p, nr, AUDIT_ARCH, [3, 0x1000, 16, 0, 0, 0]);
        assert_eq!(on(SYS_CONNECT), SECCOMP_RET_ERRNO | EACCES);
        assert_eq!(on(SYS_SOCKET), SECCOMP_RET_ALLOW, "an AF_INET-less arg0 of 3 is no Unix socket");
        let base = decode(&agentshell_seccomp_filter_opts(false, false));
        assert_eq!(run_filter_args(&base, SYS_CONNECT, AUDIT_ARCH, [3, 0x1000, 16, 0, 0, 0]), SECCOMP_RET_ALLOW);
        assert_eq!(agentshell_seccomp_filter_opts(true, false), agentshell_seccomp_filter_with(true));
    }

}
