//! landlock — the Landlock (Linux LSM) filesystem + TCP-network access backend
//! for the FS chokepoint. UNPRIVILEGED defense-in-depth: Landlock needs NO root
//! and NO capability (only `no_new_privs`, or CAP_SYS_ADMIN inside a user
//! namespace), but requires kernel ≥ 5.13 (Landlock ABI v1) for the FS rights and
//! kernel ≥ 6.7 (ABI v4) for the TCP rights. It is probe-gated and therefore ON BY
//! DEFAULT wherever the kernel supports it; on an older kernel
//! `landlock_supported()` is false and the live enactment SELF-SKIPs, and on a
//! pre-v4 kernel the net leg masks away while the FS ruleset still applies.
//!
//! ── Why Landlock here (mandu.md §4, the FS chokepoint) ─────────────────────
//! The exec sandbox realizes the AgentShell world with a bubblewrap overlay
//! (`exec-supervisor::sandbox`): the whole real FS READ-ONLY, the AgentView
//! worktree + scratch (`/tmp`) the only WRITABLE subtrees. Landlock enforces that
//! SAME asymmetric overlay at the LSM layer — an in-kernel access check that
//! survives even a process that escapes or was never wrapped by bubblewrap. It is
//! additive: a prompt-injected write to `~/.bashrc` or exfil staging in the real
//! `/tmp` is refused by the kernel, not merely by a mount trick. Reads of untracked
//! system paths stay allowed (RO-not-hidden): file content reaches the model only
//! via the proxy's symbolization, so read-through is the right utility/opacity
//! trade — identical posture to the bubblewrap overlay's RO base.
//!
//! ── Network confinement (ABI v4, kernel ≥ 6.7) ───────────────────────────────
//! Landlock also governs TCP `bind`/`connect` via `handled_access_net` — a bit-
//! namespace SEPARATE from the FS rights (see the `LANDLOCK_ACCESS_NET_*` consts).
//! The AgentShell world is net-off by design: the exec sandbox's bwrap netns
//! already unplugs it, and the deny-TCP plan (`plan_landlock_deny_tcp`) makes the
//! same posture hold at the LSM even for a netns escape or a process that was
//! never wrapped. Handling a net right with NO allow rules denies it everywhere;
//! `LANDLOCK_RULE_NET_PORT` allow rules (`NetPortRule`) can poke specific TCP
//! ports through — for a future launcher wrap that must reach only the
//! model-proxy port. HONEST BOUNDARY: Landlock net governs TCP only (UDP, ICMP,
//! unix sockets are untouched) — the netns remains the full net boundary.
//!
//! ── PURE vs KERNEL-GATED (matches the crate's HARD environment constraint) ────
//! PURE (default build, NO libc, unit-tested unprivileged):
//!   - `LandlockPlan` / `PathRule` / `NetPortRule` — the ruleset the sandbox WANTS:
//!     the top-level "handled" FS + net access masks, a set of path rules (path +
//!     allowed-access bitmask), and TCP-port allow rules (empty = deny all handled
//!     net access).
//!   - The `LANDLOCK_ACCESS_FS_*` / `LANDLOCK_ACCESS_NET_*` bit constants +
//!     `ACCESS_FS_RO` / `ACCESS_FS_RW` / `ACCESS_NET_TCP` composites +
//!     `abi_access_mask` / `abi_net_access_mask` (rights masked DOWN to a target
//!     ABI, each namespace on its own ladder).
//!   - `plan_landlock` (FS-only) / `plan_landlock_deny_tcp` (FS + all TCP denied)
//!     / `plan_agent_view_sandbox` (the AgentShell posture: overlay + net-off) /
//!     `plan_landlock_clean` (the exec-output-trust §4 rung-2 CLEAN box: readable
//!     ⊆ an explicit trusted set, AgentView write-only, TCP denied) —
//!     build the plan; `LandlockPlan::allow_tcp_port` pokes a port through.
//! KERNEL-GATED (`--features kernel`, uses libc via raw syscalls; enacted only on a
//! ≥ 5.13 kernel, exercised by the `#[ignore]` self-SKIPping integration test):
//!   - `landlock_abi_version` / `landlock_supported` (the runtime probe).
//!   - `restrict_self_to_plan` — create the ruleset, add each path + net-port rule,
//!     set `no_new_privs`, and `landlock_restrict_self`. This IRREVERSIBLY restricts
//!     the calling thread + its descendants, so it is meant to run in a FORKED CHILD
//!     just before `execve` (documented on the fn). Fail-closed on any error.
//!
//! SECURITY INVARIANT: rights are always masked to the running kernel's ABI before
//! they reach `handled_access_fs` / `handled_access_net` — the kernel REJECTS a
//! ruleset carrying an unknown access bit (e.g. a v2/v3 bit on a v1 kernel), which
//! would fail the whole restrict and leave the process UNrestricted. Masking keeps
//! the restriction enforceable. The net mask being zero below ABI v4 is doubly
//! load-bearing: it also selects the 8-byte FS-only `landlock_ruleset_attr`
//! encoding that a pre-6.7 kernel requires (see `enact::RulesetAttr`).

/// Landlock filesystem access-right bits (stable UAPI, `LANDLOCK_ACCESS_FS_*` from
/// `linux/landlock.h`). Defined locally as plain `u64` consts so the PURE plan
/// carries no libc dependency (libc compiles only under `--features kernel`).
///
/// The ABI version each right first appeared in is noted; `abi_access_mask` masks
/// the higher-ABI bits out for older kernels (a v1 kernel rejects unknown bits).
pub const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0; // ABI v1
pub const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1; // ABI v1
pub const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2; // ABI v1
pub const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3; // ABI v1
pub const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4; // ABI v1
pub const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5; // ABI v1
pub const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6; // ABI v1
pub const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7; // ABI v1
pub const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8; // ABI v1
pub const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9; // ABI v1
pub const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10; // ABI v1
pub const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11; // ABI v1
pub const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12; // ABI v1
pub const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13; // ABI v2 (kernel ≥ 5.19)
pub const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14; // ABI v3 (kernel ≥ 6.2)

/// Landlock NETWORK access-right bits (`LANDLOCK_ACCESS_NET_*` from
/// `linux/landlock.h`, ABI v4 / kernel ≥ 6.7).
///
/// CAUTION — SEPARATE BIT-NAMESPACE: these numerically COLLIDE with the FS bits
/// (`BIND_TCP == 1 << 0 == LANDLOCK_ACCESS_FS_EXECUTE`) because the kernel keys
/// them to a DIFFERENT ruleset field (`handled_access_net`, not
/// `handled_access_fs`). Never OR a NET bit into an FS mask or vice versa — the
/// value would silently mean an unrelated right in the other namespace.
pub const LANDLOCK_ACCESS_NET_BIND_TCP: u64 = 1 << 0; // ABI v4
pub const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 1 << 1; // ABI v4

/// Both TCP rights. HANDLING these with NO allow rules denies every TCP
/// bind/connect in-kernel — the AgentShell net-off posture. (Landlock net governs
/// TCP ONLY; UDP/ICMP/unix sockets are out of its scope — the honest boundary.)
pub const ACCESS_NET_TCP: u64 = LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP;

/// READ-ONLY composite: read a file, list a dir, execute. This is what the whole
/// real FS gets under the overlay (mirror of the bubblewrap `--ro-bind / /`), so a
/// command can read interpreters/libraries but write nothing outside the AgentView.
pub const ACCESS_FS_RO: u64 =
    LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;

/// READ-WRITE composite: the RO rights PLUS every mutating right (write, remove,
/// make-*, refer, truncate). This is what the AgentView worktree + scratch get
/// (mirror of the bubblewrap writable `--bind`/`--tmpfs`). REFER/TRUNCATE are
/// higher-ABI bits — `abi_access_mask` masks them away on kernels that lack them.
pub const ACCESS_FS_RW: u64 = ACCESS_FS_RO
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM
    | LANDLOCK_ACCESS_FS_REFER
    | LANDLOCK_ACCESS_FS_TRUNCATE;

/// WRITE-ONLY composite: every MUTATING right and NOT ONE reading/executing bit
/// (`ACCESS_FS_RW` minus the `ACCESS_FS_RO` set). This is the CLEAN-box posture
/// for the AgentView (exec-routing.md §8.4 rung 2): a boxed command may still
/// LAND results in the workspace — writes add nothing to its influence set — but
/// it must not READ pre-existing workspace files (orphan/unlabeled ⇒ fail-closed
/// untrusted, §5) and must not EXECUTE workspace program text (that would smuggle
/// untrusted influence in as code). Landlock grants compose per-target by union,
/// so a write-only rule can only ever be widened by ANOTHER rule, never by
/// itself.
pub const ACCESS_FS_WRITE_ONLY: u64 = ACCESS_FS_RW & !ACCESS_FS_RO;

/// The whole-real-FS read-only root the overlay reads through (mirror of the exec
/// sandbox's `--ro-bind / /`).
pub const RO_ROOT: &str = "/";

/// Scratch that is always writable in the AgentShell world (mirror of the exec
/// sandbox's `--tmpfs /tmp`): ordinary tools/builds need a writable scratch that
/// does not escape to the real HumanView FS.
pub const SCRATCH: &str = "/tmp";

/// The device tree: gets a WRITE_FILE-only carve-out in the AgentShell plan (so
/// `> /dev/null` opens) — see `plan_agent_view_sandbox` for why not the RW set.
pub const DEV: &str = "/dev";

/// The set of filesystem access-right bits that EXIST at Landlock ABI `abi`. Rights
/// requested by the plan are masked to this before they reach `handled_access_fs`
/// or any rule — the kernel rejects a ruleset that names an access bit it does not
/// know, so an un-masked v2/v3 bit on a v1 kernel would fail the ENTIRE restrict and
/// leave the process unrestricted. Masking is therefore load-bearing for the
/// fail-closed guarantee, not a nicety.
pub fn abi_access_mask(abi: u32) -> u64 {
    let mut mask = 0u64;
    // ABI v1 (kernel ≥ 5.13): EXECUTE..MAKE_SYM, bits 0..=12.
    if abi >= 1 {
        mask |= LANDLOCK_ACCESS_FS_EXECUTE
            | LANDLOCK_ACCESS_FS_WRITE_FILE
            | LANDLOCK_ACCESS_FS_READ_FILE
            | LANDLOCK_ACCESS_FS_READ_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_FILE
            | LANDLOCK_ACCESS_FS_MAKE_CHAR
            | LANDLOCK_ACCESS_FS_MAKE_DIR
            | LANDLOCK_ACCESS_FS_MAKE_REG
            | LANDLOCK_ACCESS_FS_MAKE_SOCK
            | LANDLOCK_ACCESS_FS_MAKE_FIFO
            | LANDLOCK_ACCESS_FS_MAKE_BLOCK
            | LANDLOCK_ACCESS_FS_MAKE_SYM;
    }
    // ABI v2 (kernel ≥ 5.19) adds REFER (rename/link across dirs).
    if abi >= 2 {
        mask |= LANDLOCK_ACCESS_FS_REFER;
    }
    // ABI v3 (kernel ≥ 6.2) adds TRUNCATE.
    if abi >= 3 {
        mask |= LANDLOCK_ACCESS_FS_TRUNCATE;
    }
    // ABI v4 adds only NETWORK rights (handled_access_net — see abi_net_access_mask),
    // not FS rights. FRONTIER for the next extension: ABI v5 (kernel ≥ 6.10) adds
    // LANDLOCK_ACCESS_FS_IOCTL_DEV (1 << 15) HERE, and ABI v6 (kernel ≥ 6.12) adds a
    // third `scoped` attr field (signal / abstract-unix scoping) with its OWN
    // bit-namespace — neither is modelled yet, so this mask ends at v3.
    mask
}

/// The set of NETWORK access-right bits that EXIST at Landlock ABI `abi` — the
/// `handled_access_net` counterpart of `abi_access_mask`, on its OWN ladder (the
/// namespaces never share a mask). Same fail-closed rationale: an unknown bit fails
/// the whole restrict, leaving the process unrestricted. Zero below ABI v4: a
/// pre-6.7 kernel has no Landlock net support, so the net leg of a plan degrades
/// away while the FS ruleset still applies (probe-gated, on-by-default) — and the
/// zero mask is also what keeps enactment on the 8-byte FS-only attr encoding such
/// a kernel requires (see `enact::RulesetAttr`).
pub fn abi_net_access_mask(abi: u32) -> u64 {
    let mut mask = 0u64;
    // ABI v4 (kernel ≥ 6.7) introduces TCP bind + connect control.
    if abi >= 4 {
        mask |= LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP;
    }
    // ABI v5/v6 add no net rights (v5 is FS-side IOCTL_DEV; v6 is the separate
    // `scoped` namespace) — see the frontier note in abi_access_mask.
    mask
}

/// One Landlock path rule: grant `access` (a bitmask of `LANDLOCK_ACCESS_FS_*`) on
/// the filesystem hierarchy beneath `path`. The kernel unions the `access` of every
/// rule whose hierarchy contains a target, so a file under both the RO `/` rule and
/// a RW AgentView rule ends up writable — exactly the asymmetric overlay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRule {
    /// Absolute path whose subtree the rule governs (opened `O_PATH` at enactment).
    pub path: String,
    /// Access rights granted beneath `path` (already masked to the plan's ABI).
    pub access: u64,
}

/// One Landlock network rule (`LANDLOCK_RULE_NET_PORT`, ABI v4): grant `access`
/// (a bitmask of `LANDLOCK_ACCESS_NET_*`) on TCP `port`. Unlike path rules there is
/// no hierarchy — each rule names exactly one port. `port` is `u64` to mirror the
/// UAPI `landlock_net_port_attr.port` (`__u64`; the kernel rejects values above
/// 65535 with EINVAL).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetPortRule {
    /// The TCP port the rule governs (host byte order, 0..=65535).
    pub port: u64,
    /// Net access rights granted on `port` (already masked to the plan's ABI).
    pub access: u64,
}

/// The Landlock ruleset the sandbox wants — PURE data the kernel feature enacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandlockPlan {
    /// Top-level "handled" FS access mask: the access TYPES this ruleset governs.
    /// Any handled right not explicitly granted on a path is DENIED. It is the
    /// union of every right we enforce (i.e. the RW set), masked to `abi`.
    pub handled_access_fs: u64,
    /// Top-level "handled" NETWORK access mask (`LANDLOCK_ACCESS_NET_*` — a
    /// bit-namespace SEPARATE from `handled_access_fs`; never OR the two). Any
    /// handled net right not granted by a `net_rules` entry is DENIED; 0 means the
    /// plan governs no net access (FS-only). Masked to `abi` (0 below v4).
    pub handled_access_net: u64,
    /// The path rules, RO root first then the RW paths in the order given
    /// (deterministic).
    pub rules: Vec<PathRule>,
    /// TCP-port allow rules. EMPTY with a nonzero `handled_access_net` = every
    /// handled TCP access DENIED in-kernel (the AgentShell net-off posture).
    pub net_rules: Vec<NetPortRule>,
    /// The target Landlock ABI the plan was masked to.
    pub abi: u32,
}

impl LandlockPlan {
    /// Add a TCP-port allow rule: grant `access` (`LANDLOCK_ACCESS_NET_*` bits,
    /// masked to the plan's ABI — below v4 it masks to zero and enactment drops the
    /// rule) on `port`. Only meaningful on a plan that handles net access (the
    /// kernel requires a rule's access ⊆ `handled_access_net`, else EINVAL →
    /// fail-closed Err). Builder-style for the future launcher wrap that allows
    /// only the model-proxy port. `port: u16` keeps out-of-range ports
    /// unrepresentable (the UAPI field is wider but rejects > 65535).
    pub fn allow_tcp_port(mut self, port: u16, access: u64) -> Self {
        self.net_rules.push(NetPortRule {
            port: u64::from(port),
            access: access & abi_net_access_mask(self.abi),
        });
        self
    }

    /// Add a path rule granting `access` (`LANDLOCK_ACCESS_FS_*` bits, masked to
    /// the plan's ABI) beneath `path`. The kernel UNIONS rules per target, so this
    /// only ever widens what the base rules grant — use it for narrow carve-outs
    /// (e.g. WRITE_FILE on `/dev` so `> /dev/null` opens, without the MAKE_* bits
    /// that would let `/dev/shm` become writable exfil staging).
    pub fn allow_path(mut self, path: &str, access: u64) -> Self {
        self.rules.push(PathRule {
            path: path.to_string(),
            access: access & abi_access_mask(self.abi),
        });
        self
    }
}

/// Build a Landlock plan modelling the asymmetric overlay: the subtree under
/// `ro_root` is READ-ONLY (read-file + read-dir + execute) and each path in
/// `rw_paths` is READ-WRITE (adds write-file, remove/make-*, refer, truncate). All
/// rights — the top-level handled mask AND every rule's access — are masked DOWN to
/// what `abi` supports, so a v1 kernel never sees a v2/v3 bit (which it would reject,
/// failing the whole restrict). Deterministic: same inputs → identical plan.
///
/// Mirrors `exec-supervisor::sandbox::plan_sandbox`'s intent (RO = the rest of the
/// FS; RW = AgentView worktree + scratch), enforced by the Landlock LSM instead of a
/// bubblewrap mount overlay.
pub fn plan_landlock(ro_root: &str, rw_paths: &[String], abi: u32) -> LandlockPlan {
    let abi_mask = abi_access_mask(abi);
    let ro = ACCESS_FS_RO & abi_mask;
    let rw = ACCESS_FS_RW & abi_mask;

    let mut rules = Vec::with_capacity(1 + rw_paths.len());
    // RO base FIRST (the whole real FS): read-through, no writes.
    rules.push(PathRule {
        path: ro_root.to_string(),
        access: ro,
    });
    // The only writable subtrees: the AgentView worktree + scratch.
    for p in rw_paths {
        rules.push(PathRule {
            path: p.clone(),
            access: rw,
        });
    }

    LandlockPlan {
        // handled = the full RW set (a superset of RO), masked to the ABI: every
        // right we enforce anywhere must be declared handled, or the kernel would
        // not check it (an undeclared right stays freely allowed).
        handled_access_fs: rw,
        // FS-only: this builder's callers govern no net access (net stays freely
        // allowed for them) — TCP denial is plan_landlock_deny_tcp's job.
        handled_access_net: 0,
        rules,
        net_rules: Vec::new(),
        abi,
    }
}

/// `plan_landlock` PLUS in-kernel TCP denial: additionally handle
/// BIND_TCP|CONNECT_TCP with NO allow rules, so every TCP bind/connect is refused
/// by the LSM (ABI v4, kernel ≥ 6.7). On a pre-v4 `abi` the net mask is empty and
/// the plan degrades to FS-only — the net boundary does not exist on that kernel;
/// the exec sandbox's bwrap netns still covers it (probe-gated, on-by-default).
/// Chain `allow_tcp_port` to poke a specific port through (e.g. a launcher wrap
/// allowing only the model-proxy port).
pub fn plan_landlock_deny_tcp(ro_root: &str, rw_paths: &[String], abi: u32) -> LandlockPlan {
    let mut plan = plan_landlock(ro_root, rw_paths, abi);
    // Handling a net right with no allow rule denies it everywhere: deny-all TCP.
    plan.handled_access_net = ACCESS_NET_TCP & abi_net_access_mask(abi);
    plan
}

/// The standard AgentShell Landlock plan for the FS chokepoint: the entire real
/// filesystem READ-ONLY, with the AgentView worktree + scratch (`/tmp`) the only
/// writable subtrees — the exact asymmetric overlay `sandbox::plan_sandbox`
/// bind-mounts — AND all TCP bind/connect DENIED: the AgentShell world is net-off
/// by design (the bwrap netns already unplugs it; Landlock makes the same posture
/// hold even for a netns escape or a process that was never wrapped). All enforced
/// by the Landlock LSM (defense-in-depth). `abi` is the target Landlock ABI (FS
/// and net rights are each masked down to it on their own ladder; below v4 the
/// net leg degrades away and the netns remains the only net boundary).
pub fn plan_agent_view_sandbox(agent_view_root: &str, abi: u32) -> LandlockPlan {
    plan_landlock_deny_tcp(
        RO_ROOT,
        &[agent_view_root.to_string(), SCRATCH.to_string()],
        abi,
    )
    // WRITE_FILE (only) on /dev: Landlock checks at OPEN time, so `> /dev/null`
    // needs a write grant on the (existing) device node even though the RO root
    // allows reading it — without this every `cmd > /dev/null` in the sandbox
    // fails EACCES. Deliberately NOT the RW composite: no MAKE_* means nothing
    // can be CREATED under /dev, so the world-writable real `/dev/shm` cannot
    // become exfil staging (inside bwrap /dev is a fresh minimal tmpfs anyway;
    // this matters for the InProcess backend and unwrapped enactments).
    .allow_path(DEV, LANDLOCK_ACCESS_FS_WRITE_FILE)
}

/// The CLEAN-box Landlock plan (exec-routing.md §8.4 rung 2, family A —
/// enforce-clean): the ONLY readable subtrees are `read_paths` (system roots
/// like `/usr`, `/lib`, … plus individually hash-verified trusted files), so a
/// command that COMPLETES inside this box has a trusted influence set BY
/// CONSTRUCTION — nothing untrusted was reachable, so nothing needed recording.
/// LSM checks are at-use ⇒ no TOCTOU; a command that legitimately needs an
/// unverified file simply FAILS in here (the caller's graceful fallback is a
/// rerun in the ordinary AgentShell box, output staying UNTRUSTED — today's
/// behavior; the miss is pure utility, never a leak).
///
/// The three path classes, and why each gets exactly its bits:
///   - `read_paths` (DIRECTORY roots) → `ACCESS_FS_RO` (read-file + read-dir +
///     EXECUTE): the command binary, interpreters and libraries live here;
///     executing them is the point. Trust rationale: system paths carry no
///     attacker-writable content under the threat model.
///   - `read_file_paths` (individual FILES — the hash-verified trusted-read
///     grants, resolved at plan-build time: the §3 TOCTOU closure — the
///     verdict is bound to the BYTES, not the label) → `READ_FILE` only: the
///     kernel EINVALs a rule on a non-directory carrying directory-only
///     rights, and a read grant deliberately confers no EXECUTE (running
///     trusted program text is the §7 sibling's decision, not a rider).
///   - `write_only_paths` → `ACCESS_FS_WRITE_ONLY`: the AgentView worktree.
///     Writes add nothing to the influence set, so results may land; reads and
///     execution of pre-existing (orphan ⇒ untrusted, §5) workspace content are
///     denied — including the write-then-reread shape, which is the utility
///     cliff rung 3 exists for.
///   - `rw_paths` → `ACCESS_FS_RW`: scratch whose entire content is BOX-AUTHORED
///     (the exec sandbox mounts a FRESH tmpfs at /tmp), so read-back is
///     inductively clean. Callers MUST only list fresh-tmpfs paths here — a
///     real, pre-populated /tmp would break the construction (which is why the
///     clean box is Bubblewrap-backend-only).
///
/// Built-in carve-outs / denials (part of the posture, not caller choices):
///   - `/dev` gets READ_FILE|WRITE_FILE (no READ_DIR, no MAKE_*): `> /dev/null`
///     and `< /dev/null` must open, and the box's /dev is bwrap's fresh minimal
///     tmpfs (null/zero/random/tty — kernel-sourced bytes, no IPI channel).
///   - `/proc` is NOT granted: its contents are kernel-generated but REVEAL
///     infrastructure (mount table → AgentView real paths — the documented
///     path-in-model leak class), and a clean verdict sends output to T-LLM
///     RAW. A tool that needs /proc fails here and falls back un-upgraded.
///   - TCP is denied in-kernel (ABI ≥ 4; below that the mask degrades away and
///     the sandbox netns remains the net floor): the clean box is definitionally
///     net-off — `net = ∅` is half the verdict.
pub fn plan_landlock_clean(
    read_paths: &[String],
    read_file_paths: &[String],
    write_only_paths: &[String],
    rw_paths: &[String],
    abi: u32,
) -> LandlockPlan {
    let abi_mask = abi_access_mask(abi);
    let mut rules = Vec::with_capacity(
        read_paths.len() + read_file_paths.len() + write_only_paths.len() + rw_paths.len() + 1,
    );
    for p in read_paths {
        rules.push(PathRule { path: p.clone(), access: ACCESS_FS_RO & abi_mask });
    }
    // Individually granted FILES (the hash-verified trusted reads). Two rules
    // shape this differently from the directory roots:
    //   - the kernel EINVALs a PATH_BENEATH rule on a NON-directory whose
    //     access carries directory-only rights (READ_DIR et al.), so a file
    //     rule must be file-compatible bits only;
    //   - READ_FILE alone, deliberately no EXECUTE: a grant vouches for
    //     reading DATA — executing trusted program text is the §7 deny-side
    //     sibling's decision, never an implicit rider on a read grant.
    for p in read_file_paths {
        rules.push(PathRule { path: p.clone(), access: LANDLOCK_ACCESS_FS_READ_FILE & abi_mask });
    }
    for p in write_only_paths {
        rules.push(PathRule { path: p.clone(), access: ACCESS_FS_WRITE_ONLY & abi_mask });
    }
    for p in rw_paths {
        rules.push(PathRule { path: p.clone(), access: ACCESS_FS_RW & abi_mask });
    }
    LandlockPlan {
        // Handle EVERY right (the RW superset): a handled-but-ungranted right is
        // denied, which is what makes "not in any list" mean UNREADABLE — the
        // whole point of the clean box (vs plan_landlock's readable-by-default
        // RO root, which this builder deliberately has no counterpart of).
        handled_access_fs: ACCESS_FS_RW & abi_mask,
        handled_access_net: ACCESS_NET_TCP & abi_net_access_mask(abi),
        rules,
        net_rules: Vec::new(),
        abi,
    }
    .allow_path(DEV, LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE)
}

/// A NET-ONLY Landlock plan: it governs TCP bind/connect and NOTHING on the
/// filesystem (`handled_access_fs = 0`, no path rules), denying all TCP EXCEPT a
/// CONNECT allowance to each port in `allow_ports` and a BIND (+CONNECT)
/// allowance to each port in `bind_ports`.
///
/// This is the whole-agent confinement posture (docs/design/confidentiality +
/// privilege-model): the live agent keeps its full filesystem (secret-twins masks
/// secret bytes separately) but its process tree can only *connect* to the
/// localhost proxy port(s) — a prompt-injected raw-socket exfil to an arbitrary
/// host:port fails in-kernel even when it bypasses `HTTP_PROXY`. A TCP client's
/// ephemeral source port is not a `bind()`, so `allow_ports` need no BIND right;
/// every `bind()` outside `bind_ports` and every other-port `connect()` is denied.
///
/// `bind_ports` (the explicit BIND allowance, exec-routing.md §7.1): an agent
/// whose TUI is a local server (OpenCode's `--port`, a gateway) must LISTEN on a
/// port; a handled net domain denies bind by default, so without this the agent
/// dies at `bind(2) = EACCES`. A bind port is also connectable — the agent's own
/// client half dials it — so it gets BOTH rights in ONE rule per port (a port in
/// both lists is upgraded, never duplicated; rule order stays first-seen).
///
/// Below ABI v4 the net mask is empty, so the returned plan handles NOTHING
/// (`handled_access_fs = 0` AND `handled_access_net = 0`) — the caller must treat
/// that as "net Landlock unavailable" and DEGRADE (the netns/proxy stay the net
/// boundary), never enact it (an all-zero ruleset is rejected by the kernel).
/// `landlock_net_supported()` is the gate.
pub fn plan_net_confine(allow_ports: &[u16], bind_ports: &[u16], abi: u32) -> LandlockPlan {
    let net_mask = abi_net_access_mask(abi);
    let mut plan = LandlockPlan {
        handled_access_fs: 0,
        handled_access_net: ACCESS_NET_TCP & net_mask,
        rules: Vec::new(),
        net_rules: Vec::new(),
        abi,
    };
    // One rule per port, first-seen order: CONNECT for a plain allow, BIND|CONNECT
    // for a bind allowance (which upgrades an earlier CONNECT rule in place).
    let mut ports: Vec<(u16, u64)> = Vec::new();
    for &p in allow_ports {
        if !ports.iter().any(|(q, _)| *q == p) {
            ports.push((p, LANDLOCK_ACCESS_NET_CONNECT_TCP));
        }
    }
    for &p in bind_ports {
        match ports.iter_mut().find(|(q, _)| *q == p) {
            Some(entry) => entry.1 = ACCESS_NET_TCP,
            None => ports.push((p, ACCESS_NET_TCP)),
        }
    }
    for (p, access) in ports {
        plan = plan.allow_tcp_port(p, access & net_mask);
    }
    plan
}

// ── KERNEL-GATED enactment (uses libc via raw syscalls; ≥ 5.13 only) ─────────
//
// Scoped in a `#[cfg(feature = "kernel")]` module so the `use libc` stays behind the
// feature (libc is an optional dependency enabled ONLY by `--features kernel`; the
// pure plan above must build with no features). Re-exported below.
#[cfg(feature = "kernel")]
mod enact {
    use super::{abi_access_mask, abi_net_access_mask, LandlockPlan};
    use std::ffi::CString;
    use std::io::{Error, ErrorKind, Result};
    use std::os::unix::io::RawFd;

    // ── Landlock syscall numbers ────────────────────────────────────────────
    // libc 0.2 does not expose these. They live in the ARCH-GENERIC syscall range
    // and are therefore IDENTICAL on x86_64 AND aarch64 (verified against
    // `arch/x86/entry/syscalls/syscall_64.tbl` and the generic
    // `include/uapi/asm-generic/unistd.h` — both assign create=444, add=445,
    // restrict=446). Arches that renumber (e.g. legacy ones) are out of scope; we
    // gate compilation to the two arches this crate targets.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

    /// `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` returns
    /// the supported ABI version instead of creating a ruleset.
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_ulong = 1 << 0;
    /// `enum landlock_rule_type { LANDLOCK_RULE_PATH_BENEATH = 1,
    /// LANDLOCK_RULE_NET_PORT = 2 }` (NET_PORT since ABI v4, kernel ≥ 6.7).
    const LANDLOCK_RULE_PATH_BENEATH: libc::c_long = 1;
    const LANDLOCK_RULE_NET_PORT: libc::c_long = 2;

    /// `struct landlock_ruleset_attr` in its ABI-v4 (kernel ≥ 6.7) 16-byte form:
    /// `handled_access_fs` + `handled_access_net` (two naturally aligned u64s).
    ///
    /// SIZE COMPAT RULE (load-bearing): the kernel's `copy_struct_from_user`
    /// accepts a userspace size LARGER than the form it knows only when every
    /// trailing byte is ZERO — otherwise E2BIG — and a pre-v4 kernel knows only the
    /// 8-byte FS-only form. So `restrict_self_to_plan` passes size=16 ONLY when the
    /// ABI-masked `handled_access_net` is nonzero (which `abi_net_access_mask`
    /// guarantees can happen only on a v4+ kernel that knows the field); otherwise
    /// it passes size=8 — the universally-safe FS-only encoding EVERY Landlock
    /// kernel (v1..v4+) accepts, and the default. Passing size=8 while the struct
    /// is 16 bytes is fine: the kernel copies only the first `size` bytes.
    /// (ABI v6 appends a third field, `scoped: u64` — out of scope; extend the same
    /// size ladder when it is modelled.)
    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
        handled_access_net: u64,
    }
    /// The two on-the-wire `landlock_ruleset_attr` sizes (see `RulesetAttr` docs).
    const RULESET_ATTR_SIZE_FS_ONLY: usize = 8;
    const RULESET_ATTR_SIZE_WITH_NET: usize = 16;

    /// `struct landlock_path_beneath_attr` — `__attribute__((packed))` in the UAPI:
    /// a `u64 allowed_access` immediately followed by an `i32 parent_fd`, total 12
    /// bytes (NO tail padding). `#[repr(C, packed)]` reproduces that layout so the
    /// pointer we hand the kernel matches what it copies in.
    #[repr(C, packed)]
    struct PathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }

    /// `struct landlock_net_port_attr`: `u64 allowed_access` + `u64 port`. Unlike
    /// `landlock_path_beneath_attr` the UAPI does NOT pack this one — two naturally
    /// aligned u64s, 16 bytes, identical layout packed or not — so plain `#[repr(C)]`
    /// is the correct mirror. `port` is HOST byte order (the UAPI documents "in host
    /// endianness" — do NOT `htons` it like a `sockaddr` port) and must be ≤ 65535
    /// or the add_rule fails EINVAL.
    #[repr(C)]
    struct NetPortAttr {
        allowed_access: u64,
        port: u64,
    }

    // Layout guards: the byte counts handed to the kernel must match the structs.
    const _: () = assert!(std::mem::size_of::<RulesetAttr>() == RULESET_ATTR_SIZE_WITH_NET);
    const _: () = assert!(std::mem::size_of::<PathBeneathAttr>() == 12);
    const _: () = assert!(std::mem::size_of::<NetPortAttr>() == 16);

    // Raw syscall wrappers. `libc::syscall` is variadic; each arg is passed in the
    // width the kernel expects (fds/rule-type as c_long, flags as c_ulong, pointers
    // as-is). All are `unsafe` — the callers document the memory contracts.
    unsafe fn sys_create_ruleset(attr: *const RulesetAttr, size: usize, flags: libc::c_ulong) -> libc::c_long {
        libc::syscall(SYS_LANDLOCK_CREATE_RULESET, attr, size, flags)
    }
    unsafe fn sys_add_rule(
        ruleset_fd: RawFd,
        rule_type: libc::c_long,
        // Untyped: the attr struct is keyed by `rule_type` (PathBeneathAttr for
        // PATH_BENEATH, NetPortAttr for NET_PORT) — callers pass the matching one.
        attr: *const libc::c_void,
        flags: libc::c_ulong,
    ) -> libc::c_long {
        libc::syscall(SYS_LANDLOCK_ADD_RULE, ruleset_fd as libc::c_long, rule_type, attr, flags)
    }
    unsafe fn sys_restrict_self(ruleset_fd: RawFd, flags: libc::c_ulong) -> libc::c_long {
        libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd as libc::c_long, flags)
    }

    /// The Landlock ABI version the running kernel supports, or a value ≤ 0 meaning
    /// "unavailable" (ENOSYS on kernels < 5.13, or when Landlock is compiled out /
    /// disabled at boot). Probes via
    /// `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` which
    /// returns the version rather than an fd — no side effects, safe to call anytime.
    pub fn landlock_abi_version() -> i32 {
        // SAFETY: the VERSION probe takes a NULL attr + size 0 by contract; no memory
        // is dereferenced. Returns the ABI (≥ 1) or -1/errno.
        let rc = unsafe {
            sys_create_ruleset(std::ptr::null(), 0, LANDLOCK_CREATE_RULESET_VERSION)
        };
        if rc < 0 {
            -1
        } else {
            rc as i32
        }
    }

    /// True iff Landlock is usable on this kernel (ABI ≥ 1 ⇒ kernel ≥ 5.13 with
    /// Landlock enabled). This is the probe the launcher gates on: ON where true.
    pub fn landlock_supported() -> bool {
        landlock_abi_version() >= 1
    }

    /// True iff Landlock's TCP NETWORK rights are usable (ABI ≥ 4 ⇒ kernel ≥ 6.7).
    /// The gate for `plan_net_confine`: below this the net leg masks away, so a
    /// caller must DEGRADE (leave the netns/proxy as the boundary) rather than try
    /// to enact an all-zero ruleset. FS-only Landlock can still be live (≥ 5.13)
    /// while this is false.
    pub fn landlock_net_supported() -> bool {
        landlock_abi_version() >= 4
    }

    /// Open `path` with `O_PATH | O_CLOEXEC` to obtain the `parent_fd` a
    /// PATH_BENEATH rule references. `O_PATH` opens without read/write intent (works
    /// on dirs the caller can only traverse) and `O_CLOEXEC` keeps the fd from
    /// leaking across a later exec.
    fn open_o_path(path: &str) -> Result<RawFd> {
        let c = CString::new(path)
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "path has interior NUL"))?;
        // SAFETY: `c` is a valid NUL-terminated C string; flags are constants.
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(Error::last_os_error());
        }
        Ok(fd)
    }

    /// IRREVERSIBLY restrict the CALLING THREAD and all its future descendants to
    /// `plan`, enforced by the Landlock LSM. On success the thread can thereafter
    /// only access the filesystem as the plan's path rules allow and — when the
    /// plan handles net rights on a v4+ kernel — only bind/connect TCP as the
    /// plan's port rules allow; the restriction cannot be lifted and is inherited
    /// across `fork`/`execve`.
    ///
    /// INTENDED WIRING: call this in a FORKED CHILD, just before `execve`, so the
    /// launched (untrusted) program runs sandboxed while the supervisor stays
    /// unrestricted — exactly where the exec sandbox applies its bubblewrap overlay.
    /// Do NOT call it in the supervisor's own thread.
    ///
    /// FAIL-CLOSED: returns `Err` on ANY failure (unavailable kernel, a rule path
    /// that will not open, an add-rule/restrict rejection). The intended caller
    /// treats an error as ABORT-THE-EXEC when Landlock was requested on a supporting
    /// kernel — running the program UNrestricted would silently drop the boundary.
    pub fn restrict_self_to_plan(plan: &LandlockPlan) -> Result<()> {
        let abi = landlock_abi_version();
        if abi < 1 {
            // Kernel < 5.13 or Landlock disabled: there is nothing to enforce with.
            // Fail closed — the caller decides (skip on an unsupported host, abort on
            // a supporting one where the probe unexpectedly regressed).
            return Err(Error::new(
                ErrorKind::Unsupported,
                "Landlock unavailable (needs kernel >= 5.13 with Landlock enabled)",
            ));
        }
        // Re-mask to the LIVE kernel ABI (the plan may have been built for a higher
        // target): the kernel rejects any unknown access bit in handled_access_fs /
        // handled_access_net. FS and net are separate namespaces, each on its own
        // mask ladder.
        let abi_mask = abi_access_mask(abi as u32);
        let net_abi_mask = abi_net_access_mask(abi as u32);
        let handled_net = plan.handled_access_net & net_abi_mask;
        let attr = RulesetAttr {
            handled_access_fs: plan.handled_access_fs & abi_mask,
            handled_access_net: handled_net,
        };
        // The 8-byte FS-only encoding is the default (accepted by every Landlock
        // kernel); the 16-byte form goes out only when it carries live net bits —
        // and `handled_net` can be nonzero only on a v4+ kernel that knows the
        // field (see the RulesetAttr size-compat rule).
        let attr_size = if handled_net != 0 {
            RULESET_ATTR_SIZE_WITH_NET
        } else {
            RULESET_ATTR_SIZE_FS_ONLY
        };

        // SAFETY: `&attr` points at a live `RulesetAttr` of at least `attr_size`
        // bytes; flags = 0 for a real create. Returns the ruleset fd or -1/errno.
        let rc = unsafe { sys_create_ruleset(&attr, attr_size, 0) };
        if rc < 0 {
            return Err(Error::last_os_error());
        }
        let ruleset_fd = rc as RawFd;

        // Add every path rule, then no_new_privs + restrict_self. Any failure inside
        // returns Err; we always close the ruleset fd afterwards (it is consumed by
        // restrict_self on success but closing our copy is still correct).
        let result = (|| -> Result<()> {
            for rule in &plan.rules {
                let parent_fd = open_o_path(&rule.path)?;
                let pb = PathBeneathAttr {
                    allowed_access: rule.access & abi_mask,
                    parent_fd,
                };
                // SAFETY: `addr_of!` yields a pointer to the whole packed struct
                // (never a misaligned field ref); the kernel copies 12 bytes in.
                let add_rc = unsafe {
                    sys_add_rule(
                        ruleset_fd,
                        LANDLOCK_RULE_PATH_BENEATH,
                        std::ptr::addr_of!(pb) as *const libc::c_void,
                        0,
                    )
                };
                let add_err = Error::last_os_error();
                // The parent_fd is only needed for the duration of the add_rule call.
                // SAFETY: closing an fd we own.
                unsafe { libc::close(parent_fd) };
                if add_rc != 0 {
                    return Err(add_err);
                }
            }

            // TCP-port ALLOW rules (LANDLOCK_RULE_NET_PORT). Skipped entirely when
            // the live kernel handles no net right (pre-v4: the rule type does not
            // exist there); a rule whose access masks to zero is likewise dropped
            // (the kernel rejects an empty-access rule with EINVAL). Both skips are
            // the RESTRICTIVE direction — dropping an allow rule only denies more —
            // so fail-closed is preserved.
            if handled_net != 0 {
                for rule in &plan.net_rules {
                    // ⊆ handled_net: the kernel EINVALs a rule granting a right the
                    // ruleset does not handle.
                    let allowed = rule.access & handled_net;
                    if allowed == 0 {
                        continue;
                    }
                    let np = NetPortAttr {
                        allowed_access: allowed,
                        port: rule.port,
                    };
                    // SAFETY: `&np` points at a live 16-byte NetPortAttr the kernel
                    // copies in; nothing is retained after the call.
                    let add_rc = unsafe {
                        sys_add_rule(
                            ruleset_fd,
                            LANDLOCK_RULE_NET_PORT,
                            std::ptr::addr_of!(np) as *const libc::c_void,
                            0,
                        )
                    };
                    if add_rc != 0 {
                        return Err(Error::last_os_error());
                    }
                }
            }

            // no_new_privs is a PREREQUISITE of an unprivileged restrict_self (the
            // kernel rejects it otherwise). Reuse the crate's existing helper.
            crate::kernel::set_no_new_privs()?;

            // SAFETY: restrict_self consumes the ruleset fd; flags = 0. On success it
            // returns 0 and the thread is irreversibly restricted.
            let r_rc = unsafe { sys_restrict_self(ruleset_fd, 0) };
            if r_rc != 0 {
                return Err(Error::last_os_error());
            }
            Ok(())
        })();

        // SAFETY: closing our copy of the ruleset fd (best-effort).
        unsafe { libc::close(ruleset_fd) };
        result
    }
}

#[cfg(feature = "kernel")]
pub use enact::{
    landlock_abi_version, landlock_net_supported, landlock_supported, restrict_self_to_plan,
};

#[cfg(test)]
mod tests {
    use super::*;

    // Small helper: the numeric AgentView root used across the plan tests.
    fn av() -> String {
        "/state/workspaces/proj-9c09f8055a26/agentview".to_string()
    }

    // ── abi_access_mask: rights appear only from the ABI that introduced them ────

    #[test]
    fn abi_mask_v1_has_no_refer_or_truncate() {
        let m = abi_access_mask(1);
        // v1 covers EXECUTE..MAKE_SYM (bits 0..=12) = 0x1fff.
        assert_eq!(m, 0x1fff);
        assert_eq!(m & LANDLOCK_ACCESS_FS_REFER, 0, "REFER is ABI v2, absent at v1");
        assert_eq!(m & LANDLOCK_ACCESS_FS_TRUNCATE, 0, "TRUNCATE is ABI v3, absent at v1");
    }

    #[test]
    fn abi_mask_grows_monotonically_with_version() {
        let v1 = abi_access_mask(1);
        let v2 = abi_access_mask(2);
        let v3 = abi_access_mask(3);
        let v4 = abi_access_mask(4);
        // v2 adds exactly REFER over v1.
        assert_eq!(v2, v1 | LANDLOCK_ACCESS_FS_REFER);
        // v3 adds exactly TRUNCATE over v2.
        assert_eq!(v3, v2 | LANDLOCK_ACCESS_FS_TRUNCATE);
        // v4 adds only NETWORK rights (not FS), so the FS mask is unchanged.
        assert_eq!(v4, v3);
        // Full FS set at v3 = bits 0..=14 = 0x7fff.
        assert_eq!(v3, 0x7fff);
    }

    // ── plan_landlock: the asymmetric overlay (RO = rest, RW = AgentView+scratch) ─

    #[test]
    fn ro_root_rule_carries_only_read_execute_bits() {
        let plan = plan_landlock(RO_ROOT, &[av()], 3);
        let ro_rule = &plan.rules[0];
        assert_eq!(ro_rule.path, "/");
        // Exactly the RO composite — read-file, read-dir, execute; nothing else.
        assert_eq!(ro_rule.access, ACCESS_FS_RO);
        // The security point: the RO root grants NO mutating right.
        assert_eq!(ro_rule.access & LANDLOCK_ACCESS_FS_WRITE_FILE, 0);
        assert_eq!(ro_rule.access & LANDLOCK_ACCESS_FS_MAKE_REG, 0);
        assert_eq!(ro_rule.access & LANDLOCK_ACCESS_FS_REMOVE_FILE, 0);
        assert_eq!(ro_rule.access & LANDLOCK_ACCESS_FS_TRUNCATE, 0);
        // But it DOES grant read + execute (so reading libs/interpreters works).
        assert_ne!(ro_rule.access & LANDLOCK_ACCESS_FS_READ_FILE, 0);
        assert_ne!(ro_rule.access & LANDLOCK_ACCESS_FS_EXECUTE, 0);
    }

    #[test]
    fn each_rw_path_rule_carries_write_bits() {
        let plan = plan_landlock(RO_ROOT, &[av(), SCRATCH.to_string()], 3);
        // rules[0] is the RO root; the rest are the RW paths, in order.
        assert_eq!(plan.rules.len(), 3);
        assert_eq!(plan.rules[1].path, av());
        assert_eq!(plan.rules[2].path, "/tmp");
        for rw in &plan.rules[1..] {
            assert_eq!(rw.access, ACCESS_FS_RW, "RW path gets the full RW composite");
            // Load-bearing: each RW path can write, create, remove, truncate.
            assert_ne!(rw.access & LANDLOCK_ACCESS_FS_WRITE_FILE, 0);
            assert_ne!(rw.access & LANDLOCK_ACCESS_FS_MAKE_REG, 0);
            assert_ne!(rw.access & LANDLOCK_ACCESS_FS_REMOVE_FILE, 0);
            assert_ne!(rw.access & LANDLOCK_ACCESS_FS_TRUNCATE, 0);
        }
    }

    #[test]
    fn handled_access_fs_is_the_rw_superset() {
        let plan = plan_landlock(RO_ROOT, &[av()], 3);
        // handled must declare EVERY right we enforce anywhere = the RW set. An
        // undeclared right would not be checked by the kernel (freely allowed).
        assert_eq!(plan.handled_access_fs, ACCESS_FS_RW);
        // The RO rule's rights are a subset of handled (so writes to RO are DENIED:
        // handled-but-not-granted ⇒ denied).
        assert_eq!(plan.rules[0].access & !plan.handled_access_fs, 0);
    }

    // ── ABI masking: a v1 kernel never sees a v2/v3 bit ──────────────────────────

    #[test]
    fn abi_v1_plan_has_no_refer_or_truncate_anywhere() {
        let plan = plan_landlock(RO_ROOT, &[av(), SCRATCH.to_string()], 1);
        assert_eq!(plan.abi, 1);
        // Neither the handled mask nor any rule may carry a right the v1 kernel would
        // reject — that rejection fails the whole restrict, leaving the process
        // UNrestricted (a silent security regression). So assert the bits are gone.
        let forbidden = LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_TRUNCATE;
        assert_eq!(plan.handled_access_fs & forbidden, 0, "handled must be v1-clean");
        for r in &plan.rules {
            assert_eq!(r.access & forbidden, 0, "rule {} must be v1-clean", r.path);
        }
        // handled at v1 = full RW masked to v1 = 0x1fff; RW paths still have write.
        assert_eq!(plan.handled_access_fs, ACCESS_FS_RW & 0x1fff);
        assert_ne!(plan.rules[1].access & LANDLOCK_ACCESS_FS_WRITE_FILE, 0);
    }

    #[test]
    fn abi_v2_plan_has_refer_but_not_truncate() {
        let plan = plan_landlock(RO_ROOT, &[av()], 2);
        // REFER (v2) present, TRUNCATE (v3) masked out.
        assert_ne!(plan.handled_access_fs & LANDLOCK_ACCESS_FS_REFER, 0);
        assert_eq!(plan.handled_access_fs & LANDLOCK_ACCESS_FS_TRUNCATE, 0);
        assert_ne!(plan.rules[1].access & LANDLOCK_ACCESS_FS_REFER, 0);
        assert_eq!(plan.rules[1].access & LANDLOCK_ACCESS_FS_TRUNCATE, 0);
    }

    // ── determinism ──────────────────────────────────────────────────────────────

    #[test]
    fn plan_is_deterministic() {
        let a = plan_landlock(RO_ROOT, &[av(), SCRATCH.to_string()], 3);
        let b = plan_landlock(RO_ROOT, &[av(), SCRATCH.to_string()], 3);
        assert_eq!(a, b, "same inputs must produce byte-identical plans");
    }

    // ── plan_agent_view_sandbox: the FS-chokepoint convenience mirrors the overlay ─

    #[test]
    fn agent_view_sandbox_mirrors_the_exec_overlay_intent() {
        let plan = plan_agent_view_sandbox(&av(), 4);
        // RO = the rest of the FS ("/"), RW = AgentView worktree + scratch (/tmp),
        // plus the WRITE_FILE-only /dev carve-out — the same asymmetric overlay
        // exec-supervisor's plan_sandbox bind-mounts (with its fresh --dev).
        assert_eq!(plan.rules.len(), 4);
        assert_eq!(plan.rules[0].path, "/");
        assert_eq!(plan.rules[0].access, ACCESS_FS_RO);
        assert_eq!(plan.rules[1].path, av());
        assert_eq!(plan.rules[2].path, "/tmp");
        assert_eq!(plan.rules[1].access, ACCESS_FS_RW);
        assert_eq!(plan.rules[2].access, ACCESS_FS_RW);
        // /dev: exactly WRITE_FILE — `> /dev/null` opens, but no MAKE_* bit, so
        // nothing can be CREATED under /dev (`/dev/shm` stays non-stageable).
        assert_eq!(plan.rules[3].path, "/dev");
        assert_eq!(plan.rules[3].access, LANDLOCK_ACCESS_FS_WRITE_FILE);
        // AND the AgentShell world is net-off: both TCP rights handled, NO allow
        // rules — every bind/connect denied (mirrors the bwrap netns unplug).
        assert_eq!(plan.handled_access_net, ACCESS_NET_TCP);
        assert!(plan.net_rules.is_empty(), "deny-all: no port may be poked through");
    }

    #[test]
    fn agent_view_sandbox_net_leg_degrades_away_below_abi_v4() {
        // A pre-6.7 kernel has no Landlock net support: the net mask must be EMPTY
        // (an unmasked net bit would select the 16-byte attr, which that kernel
        // rejects — failing the whole restrict and losing the FS boundary too).
        // The FS overlay is unaffected; the bwrap netns remains the net boundary.
        let plan = plan_agent_view_sandbox(&av(), 3);
        assert_eq!(plan.handled_access_net, 0);
        assert_eq!(plan.rules.len(), 4);
        assert_eq!(plan.handled_access_fs, ACCESS_FS_RW);
    }

    #[test]
    fn allow_path_masks_to_the_plan_abi_and_only_widens() {
        // The carve-out builder: rights are masked to the plan's ABI (a v1 plan
        // must never carry TRUNCATE), and the rule is APPENDED — the base rules
        // are untouched (the kernel unions per-target, so a carve-out only widens).
        let plan = plan_landlock(RO_ROOT, &[av()], 1)
            .allow_path("/dev", LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_TRUNCATE);
        assert_eq!(plan.rules.len(), 3);
        assert_eq!(plan.rules[2].path, "/dev");
        assert_eq!(
            plan.rules[2].access,
            LANDLOCK_ACCESS_FS_WRITE_FILE,
            "TRUNCATE is ABI v3 and must be masked out of a v1 plan"
        );
        assert_eq!(plan.rules[0].access, ACCESS_FS_RO & abi_access_mask(1));
    }

    #[test]
    fn no_rw_paths_is_a_read_only_world() {
        // Degenerate but valid: no writable subtree → the whole FS is read-only. The
        // handled mask still declares the RW rights (so writes everywhere are denied).
        let plan = plan_landlock(RO_ROOT, &[], 3);
        assert_eq!(plan.rules.len(), 1);
        assert_eq!(plan.rules[0].access, ACCESS_FS_RO);
        assert_eq!(plan.handled_access_fs, ACCESS_FS_RW);
    }

    // ── plan_landlock_clean: the enforce-clean box (exec-output-trust §4 rung 2) ──

    #[test]
    fn write_only_composite_has_every_mutating_bit_and_no_reading_bit() {
        // The load-bearing property: a write-only path can be WRITTEN (results
        // land) but never READ or EXECUTED (no untrusted influence enters).
        assert_eq!(ACCESS_FS_WRITE_ONLY & ACCESS_FS_RO, 0, "no read/readdir/execute bit");
        assert_eq!(ACCESS_FS_WRITE_ONLY | ACCESS_FS_RO, ACCESS_FS_RW, "WO ∪ RO = RW exactly");
        assert_ne!(ACCESS_FS_WRITE_ONLY & LANDLOCK_ACCESS_FS_WRITE_FILE, 0);
        assert_ne!(ACCESS_FS_WRITE_ONLY & LANDLOCK_ACCESS_FS_MAKE_REG, 0);
        assert_ne!(ACCESS_FS_WRITE_ONLY & LANDLOCK_ACCESS_FS_TRUNCATE, 0);
    }

    #[test]
    fn clean_plan_reads_only_the_read_set_and_denies_everything_else_by_handling() {
        let reads = vec!["/usr".to_string(), "/lib".to_string(), "/etc".to_string()];
        let wo = vec![av()];
        let rw = vec!["/tmp".to_string()];
        let plan = plan_landlock_clean(&reads, &[], &wo, &rw, 4);
        // NO readable-root rule: unlike plan_landlock there is no "/" entry, so
        // any path outside the three lists is handled-but-ungranted = DENIED.
        assert!(plan.rules.iter().all(|r| r.path != "/"), "a clean plan must have no RO root");
        assert_eq!(plan.handled_access_fs, ACCESS_FS_RW, "every right handled ⇒ ungranted = denied");
        // Read set: RO bits (read + readdir + execute — binaries/interpreters run).
        for p in &reads {
            let r = plan.rules.iter().find(|r| &r.path == p).expect("read rule present");
            assert_eq!(r.access, ACCESS_FS_RO, "{p} carries exactly the RO composite");
        }
        // AgentView: write-only — results land, contents never influence.
        let wo_rule = plan.rules.iter().find(|r| r.path == av()).unwrap();
        assert_eq!(wo_rule.access, ACCESS_FS_WRITE_ONLY);
        assert_eq!(wo_rule.access & LANDLOCK_ACCESS_FS_READ_FILE, 0);
        assert_eq!(wo_rule.access & LANDLOCK_ACCESS_FS_EXECUTE, 0, "workspace program text must not run");
        // Scratch: full RW (fresh tmpfs ⇒ box-authored ⇒ read-back is clean).
        let rw_rule = plan.rules.iter().find(|r| r.path == "/tmp").unwrap();
        assert_eq!(rw_rule.access, ACCESS_FS_RW);
        // /dev carve-out: exactly READ_FILE|WRITE_FILE (`> /dev/null`, `< /dev/null`),
        // no MAKE_* (nothing creatable), no READ_DIR.
        let dev = plan.rules.iter().find(|r| r.path == "/dev").expect("/dev carve-out");
        assert_eq!(dev.access, LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE);
        // No /proc rule: kernel-generated but infrastructure-revealing, and the
        // output rides RAW to T-LLM on a clean verdict — denied by omission.
        assert!(plan.rules.iter().all(|r| r.path != "/proc"));
        // net = ∅ is half the verdict: both TCP rights handled, no allow rules.
        assert_eq!(plan.handled_access_net, ACCESS_NET_TCP);
        assert!(plan.net_rules.is_empty());
    }

    #[test]
    fn clean_plan_file_grants_carry_read_file_only() {
        // A PATH_BENEATH rule on a regular FILE with directory-only bits
        // (READ_DIR, MAKE_*) is EINVAL — which would fail the WHOLE restrict
        // and (fail-closed) void the attempt. File grants must therefore carry
        // exactly READ_FILE: no READ_DIR, and deliberately no EXECUTE (a read
        // grant vouches for data, not for running program text — §7's call).
        let plan = plan_landlock_clean(
            &["/usr".to_string()],
            &["/srv/grants/data.txt".to_string()],
            &[av()],
            &["/tmp".to_string()],
            4,
        );
        let g = plan.rules.iter().find(|r| r.path == "/srv/grants/data.txt").unwrap();
        assert_eq!(g.access, LANDLOCK_ACCESS_FS_READ_FILE);
        assert_eq!(g.access & LANDLOCK_ACCESS_FS_READ_DIR, 0, "no directory-only bit on a file rule");
        assert_eq!(g.access & LANDLOCK_ACCESS_FS_EXECUTE, 0, "a read grant confers no execute");
        // The directory roots keep the full RO composite.
        let d = plan.rules.iter().find(|r| r.path == "/usr").unwrap();
        assert_eq!(d.access, ACCESS_FS_RO);
    }

    #[test]
    fn clean_plan_masks_to_the_target_abi_and_degrades_net_below_v4() {
        // ABI v1: REFER/TRUNCATE masked out everywhere, net leg gone (the netns
        // stays the floor), but the read/write asymmetry is intact.
        let plan = plan_landlock_clean(&["/usr".to_string()], &[], &[av()], &["/tmp".to_string()], 1);
        let forbidden = LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_TRUNCATE;
        assert_eq!(plan.handled_access_fs & forbidden, 0);
        for r in &plan.rules {
            assert_eq!(r.access & forbidden, 0, "rule {} must be v1-clean", r.path);
        }
        assert_eq!(plan.handled_access_net, 0, "no net rights exist below ABI v4");
        let wo = plan.rules.iter().find(|r| r.path == av()).unwrap();
        assert_eq!(wo.access & ACCESS_FS_RO, 0, "write-only stays read-free at every ABI");
        assert_ne!(wo.access & LANDLOCK_ACCESS_FS_WRITE_FILE, 0);
    }

    #[test]
    fn clean_plan_is_deterministic_and_empty_lists_are_valid() {
        let a = plan_landlock_clean(&["/usr".to_string()], &[], &[av()], &["/tmp".to_string()], 4);
        let b = plan_landlock_clean(&["/usr".to_string()], &[], &[av()], &["/tmp".to_string()], 4);
        assert_eq!(a, b, "same inputs must produce byte-identical plans");
        // Degenerate but valid: no grants at all → only the /dev carve-out rule,
        // with everything else denied (maximally restrictive, still enactable).
        let bare = plan_landlock_clean(&[], &[], &[], &[], 4);
        assert_eq!(bare.rules.len(), 1);
        assert_eq!(bare.rules[0].path, "/dev");
        assert_eq!(bare.handled_access_fs, ACCESS_FS_RW);
    }

    // ── plan_net_confine: net-only, deny-all-TCP-except-allowed (whole-agent wrap) ─

    #[test]
    fn net_confine_governs_only_net_and_allows_only_named_ports() {
        let plan = plan_net_confine(&[8788, 8790], &[], 4);
        // Net-only: NO filesystem governance at all (the agent keeps its full FS).
        assert_eq!(plan.handled_access_fs, 0, "net-confine must not touch the FS");
        assert!(plan.rules.is_empty(), "no path rules");
        // Deny-all TCP handled, with a CONNECT allowance per named port.
        assert_eq!(plan.handled_access_net, ACCESS_NET_TCP);
        assert_eq!(plan.net_rules.len(), 2);
        assert_eq!(plan.net_rules[0].port, 8788);
        assert_eq!(plan.net_rules[1].port, 8790);
        for r in &plan.net_rules {
            // CONNECT only — a client needs no bind() (its source port is ephemeral),
            // so BIND stays denied everywhere (no listening sockets).
            assert_eq!(r.access, LANDLOCK_ACCESS_NET_CONNECT_TCP);
            assert_eq!(r.access & LANDLOCK_ACCESS_NET_BIND_TCP, 0, "no bind grant");
        }
    }

    #[test]
    fn net_confine_degrades_to_an_inert_plan_below_abi_v4() {
        // Pre-6.7: the net mask is empty, so the plan handles NOTHING. The caller
        // (the applier) must gate on landlock_net_supported() and DEGRADE rather
        // than enact this all-zero ruleset (which the kernel would reject).
        let plan = plan_net_confine(&[8788], &[4096], 3);
        assert_eq!(plan.handled_access_net, 0);
        assert_eq!(plan.handled_access_fs, 0);
        // The allow rules' access also masks to zero on a pre-v4 abi.
        assert_eq!(plan.net_rules[0].access, 0);
        assert_eq!(plan.net_rules[1].access, 0);
    }

    #[test]
    fn net_confine_bind_ports_get_bind_and_connect_in_one_rule() {
        // exec-routing.md §7.1: a bind allowance is BOTH rights (the agent's own
        // client half dials its server port), one rule per port, first-seen order;
        // a port named in both lists is upgraded in place, never duplicated.
        let plan = plan_net_confine(&[8788, 4096], &[4096, 5173], 4);
        assert_eq!(plan.handled_access_net, ACCESS_NET_TCP);
        assert_eq!(plan.net_rules.len(), 3, "no duplicate rule for 4096");
        assert_eq!(plan.net_rules[0].port, 8788);
        assert_eq!(plan.net_rules[0].access, LANDLOCK_ACCESS_NET_CONNECT_TCP);
        assert_eq!(plan.net_rules[1].port, 4096);
        assert_eq!(plan.net_rules[1].access, ACCESS_NET_TCP, "upgraded to BIND|CONNECT");
        assert_eq!(plan.net_rules[2].port, 5173);
        assert_eq!(plan.net_rules[2].access, ACCESS_NET_TCP);
        // Plain allows still carry NO bind right (no listening sockets by default).
        assert_eq!(plan.net_rules[0].access & LANDLOCK_ACCESS_NET_BIND_TCP, 0);
        // Bind-only input: still net-only, FS untouched.
        let only = plan_net_confine(&[], &[4096], 4);
        assert_eq!(only.handled_access_fs, 0);
        assert_eq!(only.net_rules.len(), 1);
        assert_eq!(only.net_rules[0].access, ACCESS_NET_TCP);
    }

    // ── network rights: a separate bit-namespace with its own ABI ladder ─────────

    #[test]
    fn net_bits_numerically_collide_with_fs_bits_but_are_a_separate_namespace() {
        // The NET bits reuse the low bit VALUES (BIND_TCP == FS_EXECUTE == 1<<0)
        // because the kernel keys them to a different attr field. This test pins
        // the collision so nobody "deduplicates" the consts or ORs the namespaces
        // into one mask — the same value means an unrelated right over there.
        assert_eq!(LANDLOCK_ACCESS_NET_BIND_TCP, LANDLOCK_ACCESS_FS_EXECUTE);
        assert_eq!(LANDLOCK_ACCESS_NET_CONNECT_TCP, LANDLOCK_ACCESS_FS_WRITE_FILE);
        assert_eq!(
            ACCESS_NET_TCP,
            LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP
        );
    }

    #[test]
    fn abi_net_mask_is_zero_below_v4_and_both_tcp_bits_from_v4() {
        // Below v4 the mask MUST be zero: it both keeps unknown bits away from a
        // pre-6.7 kernel and keeps enactment on the 8-byte FS-only attr encoding.
        for abi in 0..=3 {
            assert_eq!(abi_net_access_mask(abi), 0, "no net rights exist at ABI v{abi}");
        }
        assert_eq!(abi_net_access_mask(4), ACCESS_NET_TCP);
        // v5 (FS IOCTL_DEV) and v6 (scoped) add nothing on the NET ladder.
        assert_eq!(abi_net_access_mask(5), ACCESS_NET_TCP);
        assert_eq!(abi_net_access_mask(6), ACCESS_NET_TCP);
    }

    #[test]
    fn plan_landlock_stays_fs_only() {
        // The FS-only builder's contract is unchanged by the net extension: callers
        // that govern no net access keep governing none (net stays freely allowed).
        let plan = plan_landlock(RO_ROOT, &[av()], 4);
        assert_eq!(plan.handled_access_net, 0);
        assert!(plan.net_rules.is_empty());
    }

    #[test]
    fn deny_tcp_plan_handles_both_tcp_rights_with_no_allow_rules() {
        let plan = plan_landlock_deny_tcp(RO_ROOT, &[av()], 4);
        // Handled-but-never-granted = denied everywhere: the in-kernel net-off.
        assert_eq!(plan.handled_access_net, ACCESS_NET_TCP);
        assert!(plan.net_rules.is_empty(), "no allow rules = all TCP bind/connect denied");
        // The FS side is byte-identical to the FS-only plan — deny-TCP is additive.
        let fs_only = plan_landlock(RO_ROOT, &[av()], 4);
        assert_eq!(plan.handled_access_fs, fs_only.handled_access_fs);
        assert_eq!(plan.rules, fs_only.rules);
    }

    #[test]
    fn allow_tcp_port_grants_only_abi_masked_rights_on_that_port() {
        let plan = plan_landlock_deny_tcp(RO_ROOT, &[], 4)
            .allow_tcp_port(8443, LANDLOCK_ACCESS_NET_CONNECT_TCP);
        assert_eq!(
            plan.net_rules,
            vec![NetPortRule { port: 8443, access: LANDLOCK_ACCESS_NET_CONNECT_TCP }]
        );
        // BIND stays handled-but-ungranted (denied) — the allow is CONNECT-only.
        assert_eq!(plan.net_rules[0].access & LANDLOCK_ACCESS_NET_BIND_TCP, 0);
        // Below v4 the granted access masks to zero; enactment drops such a rule
        // (dropping an ALLOW rule is the restrictive, fail-closed direction).
        let old = plan_landlock_deny_tcp(RO_ROOT, &[], 3)
            .allow_tcp_port(8443, LANDLOCK_ACCESS_NET_CONNECT_TCP);
        assert_eq!(old.net_rules[0].access, 0);
    }
}
