//! sandbox — the PURE AgentShell sandbox plan (Phase 1 of exec-routing.md §4:
//! "swap the world, not the words").
//!
//! PRIVILEGE-FREE + unit-tested by default (per the crate's HARD environment
//! constraint). This module owns the *make-or-break* Phase-1 decision: what world
//! an AgentShell command runs in. The kernel feature merely ENACTS the plan; all
//! the "which paths are writable / read-only / net on-off" logic lives here so it
//! is reviewable and testable with no root.
//!
//! ── The AgentShell world (the asymmetric overlay) ────────────────────────────
//! An AgentShell command runs verbatim inside a namespace whose world is:
//!   - **RW = the AgentView worktree**, mounted writable at TWO paths. Bound
//!     over the workspace path, so `cat notes.md` naturally reads the
//!     symbolized twin at the same path and a workspace-addressed write lands
//!     in the AgentView (fs-sync propagates it to the HumanView) — the exec
//!     analogue of the P4 ViewMap, realized as a mount not string surgery. And
//!     identity-bound at its OWN real path, because the launcher's fs-view
//!     cwd's the live agent INTO the AgentView worktree: a boxed command
//!     inherits that cwd, and without the identity bind it would chdir into
//!     the RO base layer and fail EROFS on a write at its own cwd (`sed -i`,
//!     `sort -o`). Skipped when the two paths coincide.
//!   - **RO = the rest of the real filesystem**: the command can READ system
//!     paths (interpreters, libraries) but CANNOT write outside the AgentView —
//!     closing the "inject a write to ~/.bashrc / stage exfil in the real /tmp"
//!     hole the earlier bind-only sandbox left open. Read-through of untracked
//!     paths is safe: reads reach the model only via Bash-result symbolization
//!     (the E4 guarantee), so RO-not-hidden is the right trade (utility over
//!     opacity for system files, which carry no secrets the symbol layer needs).
//!   - **net = off**: a fresh network namespace with egress disabled, so exfil is
//!     structurally impossible regardless of what the command does.
//!   - **writable scratch** (`/tmp` as a fresh tmpfs) + fresh `/dev` and `/proc`,
//!     so ordinary tools/builds still work without escaping the overlay. A
//!     project that itself lives under `/tmp` is bound back over the scratch
//!     READ-ONLY at its own path (`tmpfs_keep_binds`; only that path — every
//!     other `/tmp` entry stays hidden), else every boxed command there died
//!     with `bwrap: Can't chdir` (open-source-release checklist a7). With the
//!     integrity axis OFF (no AgentView, the writable workspace asked:
//!     `shares_real_tmp`) the box binds the agent's REAL `/tmp` instead, its
//!     sockets masked: the agent's unboxed programs use it anyway, and a fresh
//!     one only hid their files from the boxed readers (exec-routing.md §7.2,
//!     "The agent's own /tmp", 2026-10-19).
//!   - **hardened namespaces + dropped privilege**: the AgentShell also unshares
//!     the PID / IPC / UTS / cgroup namespaces (so a fresh `--proc /proc` shows
//!     ONLY sandbox PIDs, not the host's; no shared SysV IPC / hostname / cgroup
//!     view to pivot through), starts a **new session** (blocks `TIOCSTI`
//!     terminal-injection — AgentShell commands are non-interactive, so this is
//!     safe), **drops all in-userns capabilities** (`--cap-drop ALL`), and
//!     **disables further userns nesting** (`--disable-userns`, so the child
//!     cannot mint a new user namespace to regain capabilities). These are all
//!     unprivileged bwrap toggles. `--disable-userns` needs bwrap ≥ 0.8: the
//!     kernel backend PROBES the installed bwrap and, where the flag is
//!     missing, swaps the userns-nesting denial into the seccomp filter
//!     (`seccomp_deny_userns` — the same denial by the next-best unprivileged
//!     mechanism) instead of emitting a flag bwrap would reject wholesale.
//!     Alongside the seccomp deny-filter (`seccomp_filter`, threaded in as
//!     `seccomp_fd`), they harden the box against a prompt-injected command
//!     reaching for a kernel-escape surface.
//!
//! HumanShell is the UNRESTRICTED view (net on, HumanView FS) — no sandbox; the
//! plan is a passthrough. The gate that decides AgentShell vs HumanShell is
//! `orchestrate::plan_exec` (the data-usage policy); this module only realizes the
//! chosen view's world.
//!
//! ── Realization ──────────────────────────────────────────────────────────────
//! `bwrap_argv` renders a `SandboxPlan` into a `bubblewrap` command line — the
//! portable, unprivileged-userns realization the design adopts (wrapping
//! Anthropic's Apache-2.0 sandbox-runtime shape, privilege-model.md §6.3).
//! bubblewrap gets the delicate RO-base + RW-overlay + fresh-{dev,proc,tmpfs} +
//! netns ordering right; keeping the builder pure means the *plan* is fully
//! unit-tested here and the kernel feature just execs the argv.

use mandu_arbiter::protocol::ExecShell;

/// Where the two views live on disk — the FS side of the sandbox. When both are
/// set, an AgentShell command gets the AgentView worktree bind-mounted (writable)
/// over the workspace and at its own path; absent, the FS side degrades to
/// net-only isolation.
/// (Mirrors fs-supervisor's tracked roots, but exec only needs *where* to bind.)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ViewConfig {
    /// Absolute path of the AgentView worktree (the symbolized copy).
    pub agent_view_root: Option<String>,
    /// Absolute path of the workspace the agent cwd's into; the AgentView
    /// worktree is bind-mounted here (writable) for AgentShell execs. Set
    /// WITHOUT an AgentView root it still names the project: when it lies
    /// under the box's fresh `/tmp` it is re-bound there READ-ONLY
    /// (`tmpfs_keep_binds`), so a project in `/tmp/…` keeps working.
    pub workspace: Option<String>,
    /// With NO AgentView root: bind the workspace WRITABLE over itself, so a
    /// boxed in-place writer (`sed -i`, `sort -o`) can work in the project
    /// (exec-routing.md §7.2, "The workspace without an AgentView"). The
    /// launcher asks for it only when the integrity axis is OFF (`secrets`,
    /// `off`): there the agent has one view, the HumanView, and already
    /// writes it unboxed. Ignored when an AgentView root is set (the pair
    /// wins) and refused for a workspace `writable_workspace` rejects.
    pub workspace_writable: bool,
}

/// The directories a writable workspace bind may not be (or contain): the
/// box's own fresh mounts and the hidden `/run` (exec-routing.md §4.2). A
/// real-tree bind at or above one would put the host's copy back over it
/// (`/tmp`'s scratch is checked against the plan's tmpfs list as well). `/tmp`
/// stays here when the box shows the real one (`shares_real_tmp`): a
/// workspace that is or holds `/tmp` would bind over that bind and over the
/// socket masks under it.
const WRITABLE_WORKSPACE_FORBIDDEN: &[&str] = &["/dev", "/proc", "/sys", "/tmp", "/run", "/var/run"];

/// Does the box show the agent's REAL `/tmp` instead of a fresh tmpfs
/// (exec-routing.md §7.2, "The agent's own /tmp", 2026-10-19)? PURE.
///
/// Exactly the integrity-OFF posture the writable workspace serves: the
/// launcher asked (`workspace_writable`), named the project, and there is NO
/// AgentView root. There
/// the agent has one view and its unboxed programs read and write the real
/// `/tmp` anyway, so a fresh scratch hid nothing from the agent and broke only
/// the boxed readers: `curl -o /tmp/out …` then a boxed `cat /tmp/out` read
/// "No such file or directory" (demo-c14, 2026-10-19). With an AgentView
/// (the integrity axis ON) the scratch stays fresh: a boxed command's
/// staging and read-back must not touch the real `/tmp`.
pub fn shares_real_tmp(view: &ViewConfig) -> bool {
    view.workspace_writable && view.agent_view_root.is_none() && view.workspace.is_some()
}

/// The box's `/tmp` path.
pub const TMP_DIR: &str = "/tmp";

/// The workspace a box with no AgentView binds WRITABLE at its own path, or
/// `None` (exec-routing.md §7.2, "The workspace without an AgentView"). PURE.
///
/// `Some(ws)` only when the launcher asked (`workspace_writable`), there is NO
/// AgentView root (with one, workspace writes land in the AgentView), and
/// `ws` is a clean absolute path that is not `/` and does not contain the
/// box's own fresh mounts (`/dev`, `/proc`, `/sys`, the scratch tmpfs) nor
/// `/tmp`: such a bind would hand the host's copy back. Every other case
/// keeps the RO root.
pub fn writable_workspace<'a>(view: &'a ViewConfig, tmpfs: &[String]) -> Option<&'a str> {
    if !view.workspace_writable || view.agent_view_root.is_some() {
        return None;
    }
    let ws = view.workspace.as_deref()?;
    if !is_clean_abs(ws) {
        return None;
    }
    let covers = |m: &str| at_or_under(m, ws);
    if WRITABLE_WORKSPACE_FORBIDDEN.iter().any(|m| covers(m)) || tmpfs.iter().any(|t| covers(t)) {
        return None;
    }
    Some(ws)
}

/// One bind mount in the overlay: `src` from the host, mounted at `dst`,
/// `writable` (RW) or not (RO).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMount {
    pub src: String,
    pub dst: String,
    pub writable: bool,
}

/// The concrete world an exec runs in — pure data the kernel feature enacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPlan {
    /// True → this plan sandboxes (AgentShell). False → passthrough (HumanShell /
    /// the unrestricted view): run the command as-is with no namespace.
    pub sandboxed: bool,
    /// True → a fresh network namespace with egress disabled.
    pub net_off: bool,
    /// True → the entire real filesystem is the READ-ONLY base layer (RO=rest).
    pub ro_root: bool,
    /// Writable binds layered on top of the RO base (the AgentView, over the
    /// workspace and at its own path). The command can only write where these say.
    pub rw_binds: Vec<BindMount>,
    /// Fresh writable tmpfs mounts (scratch that must NOT escape to the real FS).
    pub tmpfs: Vec<String>,
    /// READ-ONLY re-binds of the project paths a fresh tmpfs would otherwise
    /// hide (`tmpfs_keep_binds`): a workspace (else cwd) under `/tmp` is bound back
    /// at its own path, AFTER the tmpfs, so the command can chdir into it and
    /// read it, while every OTHER `/tmp` entry stays invisible. Always
    /// `writable: false` (the no-view box's project is RO everywhere else
    /// too). NOT rendered in the CLEAN posture: its Landlock `--rw` over the
    /// scratch would grant reads of the re-bound project (see `bwrap_argv`).
    pub ro_keep_binds: Vec<BindMount>,
    /// Host doors the box closes by mount (`HostHide`; exec-routing.md §4.1
    /// and §4.2): `/run` replaced by an empty tmpfs with a short allow-list
    /// put back (`run_box_hide`), every other host Unix socket the scan
    /// found masked (`socket_box_hide`), and on WSL the interop door
    /// (`wsl_box_hide`). Filled by the kernel backend from host probes; the
    /// pure plan leaves it empty.
    pub host_hide: HostHide,
    /// True → mount a fresh minimal `/dev` (so `/dev/null` etc. work over the RO base).
    pub dev: bool,
    /// True → mount a fresh `/proc`.
    pub proc: bool,
    /// True → unshare the PID namespace, so the fresh `/proc` shows ONLY sandbox
    /// PIDs (not host processes the command could inspect/signal).
    pub unshare_pid: bool,
    /// True → unshare the IPC namespace (no shared SysV/POSIX IPC with the host).
    pub unshare_ipc: bool,
    /// True → unshare the UTS namespace (isolated hostname/domainname).
    pub unshare_uts: bool,
    /// True → unshare the cgroup namespace (no host cgroup view to pivot through).
    pub unshare_cgroup: bool,
    /// True → start a NEW session, detaching the controlling terminal — blocks
    /// `TIOCSTI` terminal-injection. Safe because AgentShell commands are
    /// non-interactive.
    pub new_session: bool,
    /// True → drop ALL capabilities in the user namespace (`--cap-drop ALL`).
    pub cap_drop_all: bool,
    /// True → forbid the sandboxed child from nesting its OWN user namespace
    /// (`--disable-userns`), so it cannot regain capabilities we dropped.
    /// Requires bwrap ≥ 0.8 — the kernel backend probes for the flag and, when
    /// absent, clears this in favor of `seccomp_deny_userns` below.
    pub disable_userns: bool,
    /// True → the seccomp deny-filter ADDITIONALLY denies minting a user
    /// namespace (`unshare`/`clone` with CLONE_NEWUSER → EPERM, `clone3` →
    /// ENOSYS). Set by the kernel backend when the probed bwrap lacks
    /// `--disable-userns` (< 0.8), so the filter takes over the userns-nesting
    /// denial that flag would have enforced. Pure plan data: it selects which
    /// filter bytes the backend writes to `seccomp_fd`; `bwrap_argv` never
    /// emits a token for it. Default false (the flag posture).
    pub seccomp_deny_userns: bool,
    /// A seccomp filter fd (`bwrap --seccomp <fd>`) to install, if any. PURE plans
    /// leave this `None` — the fd is a RUNTIME resource the kernel backend creates
    /// (build the bytes with `seccomp_filter::agentshell_seccomp_filter`, write
    /// them to an fd, then set this). See `kernel.rs`.
    pub seccomp_fd: Option<i32>,
    /// The write end of the supervisor's "box is up" pipe, handed to the
    /// interposed applier (`--ready-fd`), which writes one byte once bwrap's
    /// mounts are done. A runtime resource like `seccomp_fd`; rendered only
    /// with an applier (exec-routing.md §4.2, the mount race).
    pub ready_fd: Option<i32>,
    /// The subtrees the LANDLOCK leg of the overlay leaves writable, as seen
    /// FROM INSIDE the sandbox (the workspace path the AgentView is bound over,
    /// plus the scratch) — everything else is read-only at the LSM layer too,
    /// so the RO/RW asymmetry holds even against a mount-table escape. Pure
    /// data; consumed by the interposed `mandu-landlock-apply`.
    pub landlock_rw_paths: Vec<String>,
    /// Host path of the `mandu-landlock-apply` binary to interpose between
    /// bwrap and the target (`bwrap … -- <applier> --rw … -- <argv>`). A RUNTIME
    /// resource like `seccomp_fd`: PURE plans leave it `None`; the kernel
    /// backend fills it in only when its probe says Landlock is available AND
    /// the binary is locatable (a Landlock-restricted thread cannot mount, so
    /// the restriction must be applied inside the box, after bwrap's mounts —
    /// see the bin's header). `None` → no interposition; the bwrap mounts
    /// remain the (complete) boundary.
    pub landlock_apply: Option<String>,
    /// True → render the interposed applier in CLEAN mode (exec-routing.md §8
    /// §4 rung 2): instead of the RO-root overlay, the LSM leg allows reads ONLY
    /// under `landlock_read_paths`, makes the bind dsts (the AgentView)
    /// WRITE-ONLY, and keeps full RW on the fresh tmpfs scratch — so a command
    /// that completes has a trusted influence set BY CONSTRUCTION. Only
    /// meaningful with `landlock_apply` set: the clean guarantee IS the Landlock
    /// restriction (the mounts still show the whole FS read-only), so the kernel
    /// backend must never run a "clean" attempt without the applier interposed.
    pub landlock_clean: bool,
    /// CLEAN mode's read-allow roots: the system paths (interpreters, libraries,
    /// the target binary) plus any individually CONTENT-HASH-VERIFIED trusted
    /// files the backend resolved at plan-build time (the §3 TOCTOU closure).
    /// Ignored unless `landlock_clean`.
    pub landlock_read_paths: Vec<String>,
    /// Directory to chdir into before exec (lands inside the overlay).
    pub chdir: Option<String>,
}

impl SandboxPlan {
    /// The unrestricted passthrough (HumanShell): no namespace, run as-is.
    fn passthrough(cwd: Option<&str>) -> Self {
        SandboxPlan {
            sandboxed: false,
            net_off: false,
            ro_root: false,
            rw_binds: vec![],
            tmpfs: vec![],
            ro_keep_binds: vec![],
            host_hide: HostHide::default(),
            dev: false,
            proc: false,
            // HumanShell is the unrestricted view: none of the hardening applies.
            unshare_pid: false,
            unshare_ipc: false,
            unshare_uts: false,
            unshare_cgroup: false,
            new_session: false,
            cap_drop_all: false,
            disable_userns: false,
            seccomp_deny_userns: false,
            seccomp_fd: None,
            ready_fd: None,
            landlock_rw_paths: vec![],
            landlock_apply: None,
            landlock_clean: false,
            landlock_read_paths: vec![],
            chdir: cwd.map(str::to_string),
        }
    }

    /// Flip an AgentShell plan into the CLEAN posture (exec-routing.md §8.4
    /// rung 2): the interposed applier renders in clean mode with `read_paths`
    /// as the only readable roots. The kernel backend calls this ONLY when the
    /// clean posture is opted in AND the Landlock probe + applier lookup
    /// succeeded — a clean plan whose applier never runs would claim a
    /// guarantee nothing enforces (the caller also gates the verdict on the
    /// child's exit, so that combination can still never mint one).
    pub fn into_clean(mut self, read_paths: Vec<String>) -> Self {
        self.landlock_clean = true;
        self.landlock_read_paths = read_paths;
        self.fresh_scratch();
        self
    }

    /// Put the fresh tmpfs scratch back in place of the agent's real `/tmp`
    /// (`shares_real_tmp`). The CLEAN posture needs it: its LSM leg grants
    /// full RW on the scratch (box-authored, so read-back is clean), which over
    /// the real `/tmp` would let bytes the agent wrote there into a "clean"
    /// output. A no-op on a plan whose scratch is already fresh.
    pub fn fresh_scratch(&mut self) {
        let before = self.rw_binds.len();
        self.rw_binds.retain(|b| !(b.src == TMP_DIR && b.dst == TMP_DIR));
        if self.rw_binds.len() != before && !self.tmpfs.iter().any(|t| t == TMP_DIR) {
            self.tmpfs.insert(0, TMP_DIR.to_string());
        }
    }
}

/// The CLEAN box's default read-allow roots (exec-routing.md §8.4 rung 2):
/// the system paths a command's binary, interpreter, loader and libraries live
/// under. Under the threat model these carry no attacker-writable content, so
/// reading them adds no untrusted influence. Non-existent entries are dropped by
/// the applier at enactment (a missing ALLOW rule only denies more —
/// restrictive, fail-closed). Deliberately NOT included: `/proc` (kernel-
/// generated but infrastructure-revealing — the path-in-model leak class),
/// `/home`, `/opt`, and the workspace (orphan/unlabeled ⇒ untrusted, §5).
pub const CLEAN_READ_ROOTS: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"];

/// Plan the world for a chosen shell. PURE. AgentShell → the asymmetric overlay
/// (RW=AgentView / RO=rest / net=off / fresh dev+proc+tmpfs); HumanShell → the
/// unrestricted passthrough. The AgentShell world holds even without a configured
/// AgentView (net-off + RO-root still bound the command); the RW binds are added
/// only when both the AgentView root and the workspace are known — TWO of them:
/// the AgentView over the workspace (workspace-path addressing lands in the
/// AgentView) and the AgentView identity-bound at its own path (the launcher's
/// fs-view cwd's the live agent INTO the AgentView real path, so a boxed
/// command's own cwd must be writable), deduped to one when the paths coincide.
/// With no AgentView root, the workspace itself is bound writable at its own
/// path when the launcher asked for it (`writable_workspace`, integrity OFF).
pub fn plan_sandbox(shell: ExecShell, view: &ViewConfig, cwd: Option<&str>) -> SandboxPlan {
    match shell {
        ExecShell::HumanShell => SandboxPlan::passthrough(cwd),
        ExecShell::AgentShell => {
            let mut rw_binds = Vec::new();
            if let (Some(av), Some(ws)) = (&view.agent_view_root, &view.workspace) {
                rw_binds.push(BindMount {
                    src: av.clone(),
                    dst: ws.clone(),
                    writable: true,
                });
                // The AgentView at its OWN path too: fs-view hands every boxed
                // command an AgentView cwd, which the overlay bind above does
                // not cover — without this it sits on the RO base (EROFS at
                // the command's own cwd). Skipped when av == ws (same bind).
                if av != ws {
                    rw_binds.push(BindMount {
                        src: av.clone(),
                        dst: av.clone(),
                        writable: true,
                    });
                }
            }
            // The scratch: a fresh tmpfs over /tmp, except in the integrity-OFF
            // box (`shares_real_tmp`), which binds the agent's REAL /tmp
            // writable at /tmp (a real-tree bind like the workspace's, so the
            // host-socket masks under it are re-applied after it; the kernel
            // backend scans /tmp for them in that posture). It goes first
            // among the binds, so a workspace under /tmp binds over it.
            let real_tmp = shares_real_tmp(view);
            let tmpfs: Vec<String> = if real_tmp { vec![] } else { vec![TMP_DIR.to_string()] };
            if real_tmp {
                rw_binds.push(BindMount {
                    src: TMP_DIR.to_string(),
                    dst: TMP_DIR.to_string(),
                    writable: true,
                });
            }
            // No AgentView (integrity OFF: the HumanView is the only view):
            // the workspace itself, writable at its own path, when the
            // launcher asked for it. A real-tree bind: what the agent's mount
            // namespace shows there (secret twins included, bwrap binds are
            // recursive and the kernel refuses to uncover a locked submount)
            // is what the box sees, now writable. bwrap_argv re-applies the
            // host-socket masks under it.
            if let Some(ws) = writable_workspace(view, &tmpfs) {
                rw_binds.push(BindMount {
                    src: ws.to_string(),
                    dst: ws.to_string(),
                    writable: true,
                });
            }
            // The LSM leg mirrors the mount overlay's writable set, in IN-BOX
            // coordinates: the bind DESTINATIONS (the workspace path the
            // AgentView appears at + the AgentView's own path) + the scratch.
            // `/dev`'s WRITE_FILE carve-out is the applier's own invariant,
            // not listed here.
            let mut landlock_rw_paths: Vec<String> =
                rw_binds.iter().map(|b| b.dst.clone()).collect();
            if !real_tmp {
                landlock_rw_paths.push(TMP_DIR.to_string());
            }
            // A project under /tmp (checklist a7), bound back RO over the
            // fresh scratch so `bwrap --chdir` finds it. The project is the
            // WORKSPACE when the launcher named one (a cwd elsewhere under
            // /tmp is NOT re-bound: the agent's `cd /tmp/<other>` must not
            // pull other /tmp entries into the box); only a bin run without
            // a workspace falls back to its cwd. An AgentView bind over the
            // workspace already covers it (no keep).
            let keep_candidates: Vec<&str> = match view.workspace.as_deref() {
                Some(ws) => vec![ws],
                None => cwd.into_iter().collect(),
            };
            let ro_keep_binds = tmpfs_keep_binds(&tmpfs, &rw_binds, &keep_candidates);
            SandboxPlan {
                sandboxed: true,
                net_off: true,
                ro_root: true,
                rw_binds,
                tmpfs,
                ro_keep_binds,
                // Host hiding is host-probed: the kernel backend fills it
                // (`run_box_hide`, `socket_box_hide`, `wsl_box_hide`; the pure
                // plan cannot look at the host).
                host_hide: HostHide::default(),
                dev: true,
                proc: true,
                // Hardened namespaces + dropped privilege, ALL ON for AgentShell
                // (all unprivileged bwrap toggles; no kernel-version dependence
                // in this set — the probe-gated pieces are flipped by the kernel
                // backend below). Defense in depth against a prompt-injected
                // command reaching for a kernel-escape surface.
                unshare_pid: true,
                unshare_ipc: true,
                unshare_uts: true,
                unshare_cgroup: true,
                new_session: true,
                cap_drop_all: true,
                disable_userns: true,
                // The flag posture above is the default; the kernel backend flips
                // this pair (disable_userns → false, seccomp_deny_userns → true)
                // only when its runtime probe finds a bwrap without
                // --disable-userns (< 0.8). The pure plan cannot probe.
                seccomp_deny_userns: false,
                // The seccomp fd is a runtime resource; the kernel backend fills it
                // in (the pure plan cannot own an fd). Left None here.
                seccomp_fd: None,
                ready_fd: None,
                landlock_rw_paths,
                // Like the seccomp fd: the applier's path is a runtime resource
                // (probe + locate); the kernel backend fills it in. The clean
                // posture is likewise the backend's call (opt-in + probed):
                // the pure plan is always the ordinary overlay.
                landlock_apply: None,
                landlock_clean: false,
                landlock_read_paths: vec![],
                // chdir is the inherited cwd, verbatim. With the identity bind
                // an AgentView cwd (the shape fs-view hands every boxed
                // command) is writable at its own path; a cwd outside any bind
                // still resolves in the RO base — safe read-through, writes
                // there fail.
                chdir: cwd.map(str::to_string),
            }
        }
    }
}

/// Is `p` an absolute, lexically clean path (no empty, `.` or `..`
/// components, no trailing slash)? Only such a path is re-bound: a `..` could
/// name a different directory than its prefix suggests.
fn is_clean_abs(p: &str) -> bool {
    p.starts_with('/')
        && p.len() > 1
        && !p.ends_with('/')
        && p[1..].split('/').all(|c| !c.is_empty() && c != "." && c != "..")
}

/// Is `p` at or under `root` (both clean absolute paths)?
fn at_or_under(p: &str, root: &str) -> bool {
    p == root || (p.starts_with(root) && p.as_bytes().get(root.len()) == Some(&b'/'))
}

/// The READ-ONLY re-binds a fresh tmpfs needs so a project under it still
/// works (open-source-release checklist a7: a project in `/tmp/x/proj` failed
/// EVERY boxed command with `bwrap: Can't chdir to /tmp/x/proj`, because the
/// box's private `/tmp` hid it). PURE.
///
/// Each candidate (`plan_sandbox` passes the workspace, else the cwd) is kept when it is
/// a clean absolute path STRICTLY under one of `tmpfs` (the tmpfs mount point
/// itself is never re-bound: that would put the real `/tmp` back and hide the
/// scratch), and not already covered by an RW bind destination (the AgentView
/// bound over a `/tmp` workspace already wins) or by an earlier keep. Only
/// the named paths come back: every other `/tmp` entry stays invisible, so
/// the private-`/tmp` intent holds. A secret twin bound inside a kept path
/// survives the re-bind (bwrap binds are recursive and read the source from
/// the caller's mount namespace, which is the confined agent's).
pub fn tmpfs_keep_binds(tmpfs: &[String], rw_binds: &[BindMount], candidates: &[&str]) -> Vec<BindMount> {
    let mut keep: Vec<BindMount> = Vec::new();
    for &c in candidates {
        if !is_clean_abs(c) {
            continue;
        }
        let under_tmpfs = tmpfs.iter().any(|t| c != t && at_or_under(c, t));
        if !under_tmpfs {
            continue;
        }
        if rw_binds.iter().any(|b| at_or_under(c, &b.dst)) {
            continue;
        }
        if keep.iter().any(|k| at_or_under(c, &k.dst)) {
            continue;
        }
        // A later candidate that CONTAINS an earlier keep replaces it (one
        // bind of the ancestor covers both).
        keep.retain(|k| !at_or_under(&k.dst, c));
        keep.push(BindMount { src: c.to_string(), dst: c.to_string(), writable: false });
    }
    keep
}

/// What a path is on the host, for `wsl_box_hide` (bwrap needs a directory to
/// put a tmpfs on and a non-directory to bind `/dev/null` over).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    Missing,
    Dir,
    Other,
}

/// What the box hides of the host by mount: the WSL interop door
/// (`wsl_box_hide`; os-test-matrix.md `wsl2` row, `mandu_arbiter::wsl` has the
/// threat) and the host's Unix sockets (`socket_box_hide`; exec-routing.md
/// §4.2). PURE: the host facts come in as arguments.
/// `bwrap_argv` renders the fields in this order, all before the scratch
/// tmpfs and the view binds: `dirs`, `symlinks`, `mkdirs`, `rebinds`, `files`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostHide {
    /// Covered by an empty tmpfs.
    pub dirs: Vec<String>,
    /// `(target, path)`: a symlink recreated inside a hidden dir (`/run`'s
    /// top-level links, e.g. NixOS `/run/current-system`). No mount.
    pub symlinks: Vec<(String, String)>,
    /// Empty directories created inside a hidden dir (`$XDG_RUNTIME_DIR`, so
    /// tools that check it exists keep working). No mount.
    pub mkdirs: Vec<String>,
    /// Host paths bound back READ-ONLY at the same path inside a hidden dir
    /// (the allow-list `run_box_hide` keeps). Never a socket.
    pub rebinds: Vec<String>,
    /// `/dev/null` bound over each.
    pub files: Vec<String>,
}

impl HostHide {
    /// Add `other`'s entries, keeping the order and dropping duplicates.
    pub fn merge(&mut self, other: HostHide) {
        fn add<T: PartialEq>(into: &mut Vec<T>, from: Vec<T>) {
            for x in from {
                if !into.contains(&x) {
                    into.push(x);
                }
            }
        }
        add(&mut self.dirs, other.dirs);
        add(&mut self.symlinks, other.symlinks);
        add(&mut self.mkdirs, other.mkdirs);
        add(&mut self.rebinds, other.rebinds);
        add(&mut self.files, other.files);
    }

    pub fn is_empty(&self) -> bool {
        self.dirs.is_empty() && self.symlinks.is_empty() && self.mkdirs.is_empty() && self.rebinds.is_empty() && self.files.is_empty()
    }

    /// The host paths a mount lands ON, which must still exist when bwrap
    /// builds the box: the read-only base cannot grow a missing mount point,
    /// so one that vanished after the scan (a ControlMaster socket timing out)
    /// fails the box's setup. The re-binds are not here: they render as
    /// `--ro-bind-try` inside a hidden tmpfs and a missing one is skipped.
    pub fn mount_points(&self) -> impl Iterator<Item = &String> {
        self.dirs.iter().chain(&self.files)
    }
}

/// Build the box again? Only when it never came up (`up`: the applier's byte
/// on the ready pipe), it `failed`, and one of the host paths it mounts on is
/// gone now (`exists`): the shape of a socket that vanished between the scan
/// and bwrap's mount (exec-routing.md §4.2). A box that came up ran the
/// command, and a command is never rerun.
pub fn box_setup_raced(up: bool, failed: bool, hide: &HostHide, exists: impl Fn(&str) -> bool) -> bool {
    !up && failed && hide.mount_points().any(|p| !exists(p))
}

/// Decide what an AgentShell box hides on this host. Off WSL: nothing. On WSL
/// (any one signal): `/run/WSL` and `/mnt/wslg` when they are directories,
/// `/init` when it exists, and the socket `$WSL_INTEROP` names when it is an
/// existing absolute non-directory outside those directories (`interop_env`
/// must already be canonical: the caller resolves symlinks, since a bind over
/// a symlink would mask the link's target only by accident). A path that does
/// not exist is skipped: bwrap cannot create a mount point on the read-only
/// base, and a missing socket is already unreachable.
pub fn wsl_box_hide(signals: &mandu_arbiter::wsl::WslSignals, kind: impl Fn(&str) -> PathKind) -> HostHide {
    use mandu_arbiter::wsl::{INIT_PATH, INTEROP_DIR, WSLG_DIR};
    let mut hide = HostHide::default();
    if !signals.is_wsl() {
        return hide;
    }
    for d in [INTEROP_DIR, WSLG_DIR] {
        if kind(d) == PathKind::Dir {
            hide.dirs.push(d.to_string());
        }
    }
    if kind(INIT_PATH) == PathKind::Other {
        hide.files.push(INIT_PATH.to_string());
    }
    if let Some(sock) = signals.interop_env.as_deref() {
        let covered = hide.dirs.iter().any(|d| at_or_under(sock, d));
        if is_clean_abs(sock) && !covered && kind(sock) == PathKind::Other && !hide.files.iter().any(|f| f == sock) {
            hide.files.push(sock.to_string());
        }
    }
    hide
}

/// What the host socket scan found (`host_sockets::scan`, kernel backend,
/// parent side). Paths are absolute and clean.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SocketScan {
    /// Every Unix socket (and FIFO: a named pipe a host process reads is a
    /// command channel too) found, plus the canonical target of every socket
    /// an environment variable names (`socket_paths_from_env`).
    pub sockets: Vec<String>,
    /// Directories the scan could search but not list: a socket inside one is
    /// still reachable by a caller who knows its name.
    pub opaque_dirs: Vec<String>,
    /// The entry budget ran out before the scan finished (a residue: sockets
    /// past it stay visible). Reported, not fatal.
    pub truncated: bool,
}

/// Decide what the box hides of the host's Unix sockets (exec-routing.md
/// §4.2). The RO base shows the whole host, and read-only does not stop a
/// `connect(2)`; the netns does not cover pathname sockets (it DOES cover the
/// abstract ones, which are per network namespace). So every socket the scan
/// found gets `/dev/null` bound over it (a connect then fails ECONNREFUSED),
/// and every directory it could not list gets an empty tmpfs. A socket inside
/// an opaque directory needs no mask of its own. Sorted, deduplicated.
pub fn socket_box_hide(scan: &SocketScan) -> HostHide {
    let mut dirs: Vec<String> = scan.opaque_dirs.iter().filter(|d| is_clean_abs(d) && d.as_str() != "/").cloned().collect();
    dirs.sort();
    dirs.dedup();
    // An opaque dir under another opaque dir is covered by the outer tmpfs.
    let outer: Vec<String> = dirs.iter().filter(|d| !dirs.iter().any(|o| o != *d && at_or_under(d, o))).cloned().collect();
    let mut files: Vec<String> = scan
        .sockets
        .iter()
        .filter(|f| is_clean_abs(f) && !outer.iter().any(|d| at_or_under(f, d)))
        .cloned()
        .collect();
    files.sort();
    files.dedup();
    HostHide { dirs: outer, files, ..Default::default() }
}

/// What one host path is, for `run_box_hide`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunEntry {
    Missing,
    Dir,
    /// A regular file.
    File,
    /// A symlink and its target, as `readlink` returns it.
    Symlink(String),
    /// A socket, FIFO, device or anything else: never put back.
    Other,
}

/// The directory the box replaces with an empty tmpfs (`run_box_hide`).
pub const RUN_DIR: &str = "/run";

/// What `/run` keeps in the box when nothing else asks for more (relative to
/// it): NixOS's setuid wrappers (on `PATH`), the login records `who` reads,
/// the container marker podman writes, the resolver config `/etc/resolv.conf`
/// links to. Each is bound back read-only when it exists; the kernel backend
/// masks any socket inside a directory it binds back.
pub const RUN_KEEP: &[&str] = &[
    "wrappers",
    "utmp",
    ".containerenv",
    "systemd/resolve/stub-resolv.conf",
    "systemd/resolve/resolv.conf",
];

/// Decide how the box shows `/run` (exec-routing.md §4.2). `/run` is where
/// host daemons put their sockets (`docker.sock`, the system bus, containerd,
/// libvirt, snapd, and under `/run/user/<uid>` the session bus, `systemd
/// --user`, gpg/ssh agents, the editor's IPC), and it churns: masking each
/// socket costs a mount apiece and races sockets that come and go. So the box
/// gets an EMPTY tmpfs over `/run` and an allow-list put back:
///   - every top-level symlink, recreated (`/run/current-system` →
///     `/nix/store/…` on NixOS; `/run/shm` → `/dev/shm`);
///   - `RUN_KEEP` entries that exist, bound back read-only;
///   - `keep`: paths the box needs that live under `/run` (the Landlock
///     applier the launcher stages in the scope run dir, the files the
///     environment names such as the TLS-inspection CA bundle, a workspace or
///     cwd under `/run/media`), bound back read-only when they exist and are
///     not sockets;
///   - `$XDG_RUNTIME_DIR`, as an empty directory, when it is under `/run`.
///
/// `run_dir` is `RUN_DIR` in production (tests pin a stand-in); `top` lists
/// its own entries; `kind` answers for any other path. When `run_dir` is not
/// a directory (or is missing) nothing is hidden. PURE.
pub fn run_box_hide(
    run_dir: &str,
    top: &[(String, RunEntry)],
    kind: impl Fn(&str) -> RunEntry,
    keep: &[String],
    runtime_dir: Option<&str>,
) -> HostHide {
    let mut h = HostHide::default();
    if !is_clean_abs(run_dir) || kind(run_dir) != RunEntry::Dir {
        return h;
    }
    h.dirs.push(run_dir.to_string());
    for (name, e) in top {
        if let RunEntry::Symlink(target) = e {
            if !name.is_empty() && !name.contains('/') && name != "." && name != ".." {
                h.symlinks.push((target.clone(), format!("{run_dir}/{name}")));
            }
        }
    }
    let mut want: Vec<String> = Vec::new();
    for rel in RUN_KEEP {
        let p = format!("{run_dir}/{rel}");
        if matches!(kind(&p), RunEntry::File | RunEntry::Dir) {
            want.push(p);
        }
    }
    for k in keep {
        let k = k.trim_end_matches('/');
        if is_clean_abs(k) && k != run_dir && at_or_under(k, run_dir) && matches!(kind(k), RunEntry::File | RunEntry::Dir) {
            want.push(k.to_string());
        }
    }
    // Under a recreated symlink a bind would land on the link's target: skip.
    want.retain(|w| !h.symlinks.iter().any(|(_, l)| at_or_under(w, l)));
    // One bind of an ancestor covers its descendants.
    want.sort();
    want.dedup();
    let outer: Vec<String> = want.iter().filter(|w| !want.iter().any(|o| o != *w && at_or_under(w, o))).cloned().collect();
    h.rebinds = outer;
    if let Some(rt) = runtime_dir.map(|r| r.trim_end_matches('/')) {
        let covered = h.rebinds.iter().any(|r| at_or_under(rt, r) || at_or_under(r, rt));
        if is_clean_abs(rt) && rt != run_dir && at_or_under(rt, run_dir) && !covered {
            h.mkdirs.push(rt.to_string());
        }
    }
    h
}

/// Environment variables that NAME a host socket (the box's parent env is the
/// agent's). The scan roots find most of these by location; a variable can put
/// one anywhere (`SSH_AUTH_SOCK=~/.ssh/agent.sock`, `TMUX_TMPDIR`), so the
/// named path is masked too, and the variable is unset in the box
/// (`BOX_UNSET_ENV`). Each is a way to act OUTSIDE the box: the ssh-agent
/// signs as you, `tmux`/`nvim`/`kitty`/`sway` run commands in the host
/// session, `docker`/`podman` start a privileged container, the session bus
/// reaches `systemd --user`.
pub const SOCKET_ENV: &[&str] = &[
    "SSH_AUTH_SOCK", "DBUS_SESSION_BUS_ADDRESS", "DOCKER_HOST", "CONTAINER_HOST",
    "PULSE_SERVER", "GPG_AGENT_INFO", "TMUX", "NVIM", "NVIM_LISTEN_ADDRESS",
    "KITTY_LISTEN_ON", "SWAYSOCK", "I3SOCK", "HYPRLAND_INSTANCE_SIGNATURE",
    "WAYLAND_DISPLAY", "VSCODE_IPC_HOOK", "VSCODE_IPC_HOOK_CLI", "VSCODE_GIT_IPC_HANDLE",
];

/// The absolute socket paths the `SOCKET_ENV` variables name, parsed per each
/// variable's syntax (`unix:path=` for D-Bus, `unix://` for Docker/Podman,
/// `path,pid,idx` for tmux, `path:pid:proto` for the old gpg-agent, a name
/// relative to `$XDG_RUNTIME_DIR` for Wayland, `unix:` for Pulse/kitty).
/// Abstract (`@…`, `unix:abstract=`) and network addresses are skipped: the
/// box's netns already cuts those. PURE: `get` reads the environment. Not
/// canonicalized (the kernel backend resolves symlinks and keeps sockets only).
pub fn socket_paths_from_env(get: impl Fn(&str) -> Option<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |p: &str| {
        let p = p.trim();
        if p.starts_with('/') && !out.iter().any(|o| o == p) {
            out.push(p.to_string());
        }
    };
    for var in SOCKET_ENV {
        let Some(v) = get(var).filter(|v| !v.is_empty()) else { continue };
        match *var {
            "DBUS_SESSION_BUS_ADDRESS" => {
                // `unix:path=/run/user/1000/bus[,guid=…][;other-address]`
                for addr in v.split(';') {
                    let Some(rest) = addr.strip_prefix("unix:") else { continue };
                    for kv in rest.split(',') {
                        if let Some(p) = kv.strip_prefix("path=") {
                            push(p);
                        }
                    }
                }
            }
            "DOCKER_HOST" | "CONTAINER_HOST" => {
                if let Some(p) = v.strip_prefix("unix://") {
                    push(p);
                }
            }
            "PULSE_SERVER" | "KITTY_LISTEN_ON" => {
                for part in v.split_whitespace() {
                    if let Some(p) = part.strip_prefix("unix:") {
                        push(p);
                    }
                }
            }
            "TMUX" => push(v.split(',').next().unwrap_or("")),
            "GPG_AGENT_INFO" => push(v.split(':').next().unwrap_or("")),
            "WAYLAND_DISPLAY" => {
                if v.starts_with('/') {
                    push(&v);
                } else if let Some(rt) = get("XDG_RUNTIME_DIR").filter(|r| r.starts_with('/')) {
                    push(&format!("{}/{}", rt.trim_end_matches('/'), v));
                }
            }
            "HYPRLAND_INSTANCE_SIGNATURE" => {
                // Hyprland's IPC lives at $XDG_RUNTIME_DIR/hypr/<sig>/.socket.sock
                if let Some(rt) = get("XDG_RUNTIME_DIR").filter(|r| r.starts_with('/')) {
                    let base = format!("{}/hypr/{}", rt.trim_end_matches('/'), v);
                    push(&format!("{base}/.socket.sock"));
                    push(&format!("{base}/.socket2.sock"));
                }
            }
            _ => push(&v),
        }
    }
    out
}

/// Variables that change how a program LOADS or STARTS (a preload library, a
/// module path, an interpreter's startup hook): the classic way an injected
/// command escapes a wrapper. Unset inside the AgentShell box only
/// (comparisons.md §3.7); the agent and HumanShell keep them, since
/// developers rely on `NODE_OPTIONS`. Boxed tools include `find -exec` and
/// `xargs`, which run arbitrary programs, so the list is not academic.
/// macOS `DYLD_*` is not here: the Seatbelt path does not go through bwrap.
pub const BOX_UNSET_ENV: &[&str] = &[
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "GCONV_PATH",
    "NODE_OPTIONS", "PYTHONSTARTUP", "PYTHONPATH", "PERL5OPT", "RUBYOPT", "BASH_ENV", "ENV",
    // WSL: the interop socket's address (`wsl_box_hide` makes the socket
    // itself unreachable; this drops the pointer to it). A no-op elsewhere.
    "WSL_INTEROP",
    // The host sockets `socket_box_hide` masks, by the variables that name
    // them (`SOCKET_ENV`): the pointer goes too, so a tool fails fast instead
    // of dialing a masked path.
    "SSH_AUTH_SOCK", "DBUS_SESSION_BUS_ADDRESS", "DOCKER_HOST", "CONTAINER_HOST",
    "PULSE_SERVER", "GPG_AGENT_INFO", "TMUX", "NVIM", "NVIM_LISTEN_ADDRESS",
    "KITTY_LISTEN_ON", "SWAYSOCK", "I3SOCK", "HYPRLAND_INSTANCE_SIGNATURE",
    "WAYLAND_DISPLAY", "VSCODE_IPC_HOOK", "VSCODE_IPC_HOOK_CLI", "VSCODE_GIT_IPC_HANDLE",
];

/// The bubblewrap program name. The pure builder names it as argv[0]; the
/// kernel side replaces it with the path `resolve_bwrap` found (never a PATH
/// search at exec time).
pub const BWRAP: &str = "bwrap";

/// `p` is `root` or below it (component-wise). A root of `/` contains nothing
/// here: excluding it would exclude every binary.
fn inside_root(p: &std::path::Path, root: &std::path::Path) -> bool {
    root != std::path::Path::new("/") && p.starts_with(root)
}

/// PURE: the bubblewrap the box runs, by real path: the first `bwrap` in
/// `path_var` (a PATH value) whose directory and real path lie outside every
/// root in `exclude`, skipping empty and relative entries (both name the
/// current directory). The roots are the box's working directory, the
/// workspace and the AgentView worktree: a `bwrap` planted there (a repository's `bin/` or
/// `node_modules/.bin` on PATH, a `.` on PATH) is never run. Codex skips the
/// same entries (codex-rs/sandboxing/src/bwrap.rs); the launcher's twin is
/// launcher/src/bwrap-path.ts `findBwrapOnPath`
/// (rootless-confinement-ubuntu-2404.md §0.7). `canon` resolves a path
/// (`fs::canonicalize`), `is_exec` says a path is an executable regular file.
pub fn find_bwrap_in(
    path_var: &std::ffi::OsStr,
    exclude: &[std::path::PathBuf],
    canon: impl Fn(&std::path::Path) -> Option<std::path::PathBuf>,
    is_exec: impl Fn(&std::path::Path) -> bool,
) -> Option<std::path::PathBuf> {
    let roots: Vec<std::path::PathBuf> = exclude
        .iter()
        .flat_map(|r| [Some(r.clone()), canon(r)])
        .flatten()
        .collect();
    let outside = |p: &std::path::Path| !roots.iter().any(|r| inside_root(p, r));
    std::env::split_paths(path_var).find_map(|dir| {
        if !dir.is_absolute() || !outside(&dir) {
            return None;
        }
        let dir_real = canon(&dir)?;
        if !outside(&dir_real) {
            return None;
        }
        let cand = dir.join(BWRAP);
        if !is_exec(&cand) {
            return None;
        }
        let real = canon(&cand)?;
        (outside(&real) && is_exec(&real)).then_some(real)
    })
}

/// [`find_bwrap_in`] over this process's PATH, excluding its current directory
/// and `extra` (the command's cwd, the workspace, the AgentView worktree).
/// PARENT side only: it walks the filesystem. The end-to-end proof through
/// the `mandu-exec-box` bin is tests/kernel_integration.rs
/// `exec_box_bin_runs_only_the_resolved_system_bwrap`.
pub fn resolve_bwrap(extra: &[&str]) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::var_os("PATH")?;
    let mut exclude: Vec<std::path::PathBuf> = extra.iter().filter(|s| !s.is_empty()).map(std::path::PathBuf::from).collect();
    if let Ok(cwd) = std::env::current_dir() {
        exclude.push(cwd);
    }
    let is_exec = |p: &std::path::Path| {
        std::fs::metadata(p).map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
    };
    find_bwrap_in(&path, &exclude, |p| std::fs::canonicalize(p).ok(), is_exec)
        .and_then(|p| p.into_os_string().into_string().ok())
}

/// The one line the box writes when no bubblewrap may be run: it never
/// falls back to a PATH search that could find one inside the workspace.
pub const NO_BWRAP_MESSAGE: &str =
    "mandu: no bubblewrap outside the working directory on PATH; the command box will not run one from the workspace (install your distribution's bubblewrap)\n";

/// The launcher's kept answer to the box's `bwrap --help` probe
/// (exec-routing.md §4, "The bwrap probe, kept by content"): the lowercase
/// sha256 of a bubblewrap the launcher saw advertise `--disable-userns`.
/// Baked into the exec-box shims; the box then skips its per-process
/// `bwrap --help` (a fork + exec, about 7 ms a command under the guard) when
/// the bubblewrap it resolved has exactly those bytes.
pub const BWRAP_DISABLE_USERNS_SHA256_ENV: &str = "MANDU_BWRAP_DISABLE_USERNS_SHA256";

/// A bubblewrap larger than this is not hashed (the probe runs instead).
pub const BWRAP_HASH_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// PURE over the file it reads: is `bwrap` (the real path `resolve_bwrap`
/// found, the program the box will exec) the very bubblewrap whose bytes
/// hash to `known` — one the launcher probed and saw support
/// `--disable-userns`?
///
/// Keyed by CONTENT, not by path or stat identity: a replaced or patched
/// binary hashes differently and is probed afresh, and no one can make a
/// different bubblewrap collide. Only the POSITIVE answer is ever kept, so
/// whoever sets the variable (the agent can run the box with its own
/// environment) can at most make the box pass `--disable-userns` to a
/// bubblewrap that lacks it, which then rejects the whole argv: the command
/// fails, never runs with less confinement. A malformed value, an unreadable
/// or oversized file, or any mismatch answers false (probe as before).
pub fn bwrap_known_disable_userns(known: Option<&str>, bwrap: &std::path::Path) -> bool {
    let Some(known) = known else { return false };
    if known.len() != 64 || !known.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return false;
    }
    use std::io::Read;
    let Ok(f) = std::fs::File::open(bwrap) else { return false };
    let mut bytes = Vec::new();
    // One byte past the cap tells an oversized file from one exactly at it.
    if f.take(BWRAP_HASH_MAX_BYTES + 1).read_to_end(&mut bytes).is_err() || bytes.len() as u64 > BWRAP_HASH_MAX_BYTES {
        return false;
    }
    crate::clean::sha256_hex(&bytes) == known
}

/// Render a `SandboxPlan` into a `bubblewrap` command line that runs `program`
/// inside the planned world. Returns `None` for a passthrough plan (HumanShell:
/// run `program` directly, no bwrap) or an empty program (nothing to run).
///
/// The hardening toggles (`--unshare-{pid,ipc,uts,cgroup}`, `--new-session`,
/// `--cap-drop ALL`, `--disable-userns`) and the seccomp deny-filter
/// (`--seccomp <fd>`, when the backend installed one) are emitted BEFORE the
/// mounts — they are order-independent namespace/flag toggles, not path ops.
///
/// Mount ORDER matters — bubblewrap applies operations left to right and a later
/// mount at the same path wins. So we layer: the RO base FIRST, then fresh `/dev`
/// `/proc` OVER it, then the scratch tmpfs, and the writable AgentView bind LAST
/// so an explicit RW bind wins over BOTH the RO base and any scratch tmpfs it
/// sits under (e.g. a workspace that happens to live under a tmpfs'd path). The
/// command therefore sees a read-only system, fresh scratch, and a writable
/// AgentView at the workspace — exactly the asymmetric overlay.
pub fn bwrap_argv(plan: &SandboxPlan, program: &[String]) -> Option<Vec<String>> {
    if !plan.sandboxed || program.is_empty() {
        return None;
    }
    let mut a: Vec<String> = vec![BWRAP.to_string()];
    // Tie the sandbox lifetime to the supervisor: if we die, the sandboxed tree
    // is killed (no orphaned, still-running command outside our control).
    a.push("--die-with-parent".to_string());
    if plan.net_off {
        a.push("--unshare-net".to_string());
    }
    // ── Hardened namespaces + dropped privilege (all unprivileged toggles) ──────
    // Emitted BEFORE the mounts (order-independent: these are namespace/flag
    // toggles, not path operations). Security reasons, one per flag:
    if plan.unshare_pid {
        // A fresh PID ns so the AgentShell's `--proc /proc` shows only sandbox
        // PIDs — the command cannot enumerate/signal host processes.
        a.push("--unshare-pid".to_string());
    }
    if plan.unshare_ipc {
        a.push("--unshare-ipc".to_string()); // no shared SysV/POSIX IPC with the host
    }
    if plan.unshare_uts {
        a.push("--unshare-uts".to_string()); // isolated hostname/domainname
    }
    if plan.unshare_cgroup {
        a.push("--unshare-cgroup".to_string()); // no host cgroup view to pivot through
    }
    if plan.new_session {
        // New session → no controlling TTY → blocks TIOCSTI terminal-injection.
        a.push("--new-session".to_string());
    }
    if plan.cap_drop_all {
        // Drop every in-userns capability (two argv tokens: flag + value).
        a.push("--cap-drop".to_string());
        a.push("ALL".to_string());
    }
    if plan.disable_userns {
        // Forbid the child nesting its own userns to regain dropped caps.
        // bwrap ≥ 0.8 REQUIRES the explicit `--unshare-user` alongside it
        // ("--disable-userns requires --unshare-user" — the whole command line
        // is rejected otherwise). Unprivileged bwrap unshares the user
        // namespace implicitly anyway, so the flag changes nothing on a host
        // where it was already implied; without it every AgentShell-boxed
        // command died on bwrap 0.8.0 (the CI image) / 0.9 (Ubuntu 24.04) —
        // invisible on a 0.6.1 host, whose probe takes the seccomp posture
        // and never reaches this branch (found 2026-09-05, E47 in CI).
        a.push("--unshare-user".to_string());
        a.push("--disable-userns".to_string());
    }
    // The seccomp deny-filter fd, if the backend installed one (an fd bwrap reads
    // the `struct sock_filter[]` program from). Placed among the early flags.
    if let Some(fd) = plan.seccomp_fd {
        a.push("--seccomp".to_string());
        a.push(fd.to_string());
    }
    // RO base: the whole real FS, read-only.
    if plan.ro_root {
        a.push("--ro-bind".to_string());
        a.push("/".to_string());
        a.push("/".to_string());
    }
    // Fresh minimal /dev and /proc OVER the RO base (device semantics + a real
    // /proc the tools expect).
    if plan.dev {
        a.push("--dev".to_string());
        a.push("/dev".to_string());
    }
    if plan.proc {
        a.push("--proc".to_string());
        a.push("/proc".to_string());
    }
    // Host doors closed by mount (`HostHide`, exec-routing.md §4.1/§4.2): an
    // EMPTY tmpfs over each hidden directory (`/run`; on WSL `/run/WSL`,
    // `/mnt/wslg`), the allow-list put back into it (symlinks, empty dirs,
    // read-only re-binds), then /dev/null over each masked file (host sockets
    // outside `/run`; on WSL `/init`). Before the scratch and the binds, so
    // nothing the plan binds later can be shadowed by them. An entry a later
    // or outer mount already covers is skipped: under the scratch tmpfs,
    // under a bind destination (the later bind replaces that tree), or (for a
    // hidden dir or a mask) under a hidden dir and not put back.
    let hh = &plan.host_hide;
    let under_bind = |p: &str| plan.rw_binds.iter().chain(&plan.ro_keep_binds).any(|b| at_or_under(p, &b.dst));
    let under_scratch = |p: &str| plan.tmpfs.iter().any(|t| at_or_under(p, t));
    render_host_hide(&mut a, hh, &|p: &str| under_scratch(p) || under_bind(p));
    // Writable scratch tmpfs (before the explicit binds so a bind can still win).
    for t in &plan.tmpfs {
        a.push("--tmpfs".to_string());
        a.push(t.clone());
    }
    // The project paths the scratch tmpfs would hide (a workspace / cwd under
    // /tmp), bound back READ-ONLY right after it (`tmpfs_keep_binds`). NOT in
    // the CLEAN posture: its Landlock leg grants `--rw` over the whole scratch
    // mount, which would reach the re-bound project too (Landlock follows the
    // path up through the bind's mount point) and let untrusted project bytes
    // into a "clean" output. Without the keep the clean attempt cannot chdir,
    // exits nonzero, and the ordinary box reruns it (the §4 fallback).
    if !plan.landlock_clean {
        for b in &plan.ro_keep_binds {
            a.push(if b.writable { "--bind" } else { "--ro-bind" }.to_string());
            a.push(b.src.clone());
            a.push(b.dst.clone());
        }
    }
    // Writable overlays (AgentView over the workspace) LAST → highest precedence.
    for b in &plan.rw_binds {
        a.push(if b.writable { "--bind" } else { "--ro-bind" }.to_string());
        a.push(b.src.clone());
        a.push(b.dst.clone());
    }
    // A bind of the REAL tree at its own path (the no-AgentView writable
    // workspace, the AgentView's own path, a rendered read-only keep) brings
    // back what the host-hide pass above left out under it: bwrap takes a
    // bind's source from the caller's namespace, where no mask exists.
    // Re-apply those entries after the binds (exec-routing.md §7.2, "The
    // workspace without an AgentView"), except under a bind of ANOTHER tree
    // (the AgentView over the workspace), which replaced the host's entries.
    let keeps_rendered = !plan.landlock_clean;
    let real_tree = |p: &str| {
        plan.rw_binds
            .iter()
            .filter(|b| b.src == b.dst)
            .chain(plan.ro_keep_binds.iter().filter(|_| keeps_rendered))
            .any(|b| at_or_under(p, &b.dst))
    };
    let other_tree = |p: &str| plan.rw_binds.iter().filter(|b| b.src != b.dst).any(|b| at_or_under(p, &b.dst));
    render_host_hide(&mut a, hh, &|p: &str| !real_tree(p) || other_tree(p));
    if let Some(cwd) = &plan.chdir {
        a.push("--chdir".to_string());
        a.push(cwd.clone());
    }
    for v in BOX_UNSET_ENV {
        a.push("--unsetenv".to_string());
        a.push((*v).to_string());
    }
    a.push("--".to_string());
    // The LSM leg: interpose the in-sandbox Landlock applier between bwrap and
    // the target, so the RO/RW asymmetry (+ TCP denial) is ALSO enforced by the
    // kernel's LSM after bwrap's mounts are in place (a Landlock-restricted
    // thread cannot mount, so this is the only spot it can run). The applier
    // path is set by the backend only when Landlock is available — absent, the
    // target runs directly under the (complete) mount overlay.
    if let Some(applier) = &plan.landlock_apply {
        a.push(applier.clone());
        if let Some(fd) = plan.ready_fd {
            a.push("--ready-fd".to_string());
            a.push(fd.to_string());
        }
        if plan.landlock_clean {
            // CLEAN mode (exec-output-trust §4 rung 2): reads only under the
            // verified read roots; the AgentView bind dsts are WRITE-ONLY
            // (results land, contents never influence); full RW only on the
            // fresh tmpfs scratch (box-authored ⇒ read-back is clean). TCP
            // denial is built into the applier's clean plan — no flag needed.
            a.push("--clean".to_string());
            for r in &plan.landlock_read_paths {
                a.push("--read".to_string());
                a.push(r.clone());
            }
            for b in &plan.rw_binds {
                a.push("--write-only".to_string());
                a.push(b.dst.clone());
            }
            for t in &plan.tmpfs {
                a.push("--rw".to_string());
                a.push(t.clone());
            }
        } else {
            for rw in &plan.landlock_rw_paths {
                a.push("--rw".to_string());
                a.push(rw.clone());
            }
            // net_off is enforced by the netns; the LSM TCP denial makes the same
            // posture hold even against a netns escape (ABI ≥ 4; masked below).
            if plan.net_off {
                a.push("--deny-tcp".to_string());
            }
        }
        a.push("--".to_string());
    }
    a.extend(program.iter().cloned());
    Some(a)
}

/// Render the host-hide entries `skip` leaves in (exec-routing.md §4.1/§4.2):
/// an empty tmpfs over each hidden directory, the allow-list put back into
/// it, then `/dev/null` over each masked file. A dir inside another rendered
/// hidden dir, and a mask inside a rendered hidden dir and not put back, are
/// left out (the outer tmpfs already covers them). Called twice by
/// `bwrap_argv`: before the scratch and the binds, and again after the binds
/// for what a real-tree bind brought back. PURE.
fn render_host_hide(a: &mut Vec<String>, hh: &HostHide, skip: &dyn Fn(&str) -> bool) {
    let rendered_dirs: Vec<&String> = hh
        .dirs
        .iter()
        .filter(|d| !skip(d) && !hh.dirs.iter().any(|o| o != *d && at_or_under(d, o) && !skip(o)))
        .collect();
    let in_hidden = |p: &str| rendered_dirs.iter().any(|d| at_or_under(p, d));
    let put_back = |p: &str| hh.rebinds.iter().any(|r| at_or_under(p, r));
    for d in &rendered_dirs {
        a.push("--tmpfs".to_string());
        a.push((*d).clone());
    }
    for (target, link) in &hh.symlinks {
        if in_hidden(link) && !skip(link) {
            a.push("--symlink".to_string());
            a.push(target.clone());
            a.push(link.clone());
        }
    }
    for d in &hh.mkdirs {
        if in_hidden(d) && !skip(d) {
            a.push("--dir".to_string());
            a.push(d.clone());
        }
    }
    for r in &hh.rebinds {
        if in_hidden(r) && !skip(r) {
            // `-try`: a kept path that vanished since the scan is simply not
            // put back (its mount point is inside the fresh tmpfs, so only the
            // source can be missing) instead of failing the whole box.
            a.push("--ro-bind-try".to_string());
            a.push(r.clone());
            a.push(r.clone());
        }
    }
    for f in &hh.files {
        if skip(f) || (in_hidden(f) && !put_back(f)) {
            continue;
        }
        a.push("--ro-bind".to_string());
        a.push("/dev/null".to_string());
        a.push(f.clone());
    }
}

// ── macOS Seatbelt deny tier (exec-routing.md §5) ─────────────────────────────

/// Render a `SandboxPlan` into a macOS **Seatbelt** (`sandbox-exec`) SBPL profile
/// — the Phase-2 macOS tier. Returns `None` for a passthrough plan.
///
/// The ACCEPTED ASYMMETRY (exec-routing.md §5): Seatbelt CANNOT remount the
/// AgentView over the canonical workspace path, so — unlike the Linux bwrap
/// overlay — it does NOT substitute the symbolized twin for reads (the command
/// sees the REAL file). That is safe: reads reach the model only via Bash-result
/// symbolization (the E4 guarantee). What Seatbelt DOES enforce is the rest of the
/// overlay's teeth: **deny all network** and **deny writes outside the AgentView /
/// scratch** (a prompt-injected write to `~/.zshrc` or exfil staging fails). A
/// command that genuinely needs more escalates-to-approval (§5), rather than
/// world-swapping.
///
/// SBPL evaluates rules top-to-bottom, LAST match wins — so: deny by default,
/// allow reads + exec, deny writes, then allow writes back INSIDE the AgentView
/// (its `dst` path) and scratch. `/dev/null` etc. stay writable via `/dev`.
pub fn seatbelt_profile(plan: &SandboxPlan) -> Option<String> {
    if !plan.sandboxed {
        return None;
    }
    let mut p = String::new();
    p.push_str("(version 1)\n");
    p.push_str(";; Mandu AgentShell deny tier (exec-routing.md §5)\n");
    p.push_str("(deny default)\n");
    // Run the command + children.
    p.push_str("(allow process-fork)\n");
    p.push_str("(allow process-exec)\n");
    p.push_str("(allow sysctl-read)\n");
    // Reads are allowed (output is symbolized at the proxy — the E4 guarantee).
    p.push_str("(allow file-read*)\n");
    // Writes: deny everything, then allow back the AgentView + scratch.
    p.push_str("(deny file-write*)\n");
    if plan.net_off {
        p.push_str("(deny network*)\n");
    }
    for b in &plan.rw_binds {
        // On macOS there is no bind: writes land in the REAL workspace path (`dst`).
        p.push_str(&format!("(allow file-write* (subpath {}))\n", sbpl_quote(&b.dst)));
    }
    for t in &plan.tmpfs {
        p.push_str(&format!("(allow file-write* (subpath {}))\n", sbpl_quote(t)));
    }
    if plan.dev {
        // Device nodes the tools need (null/zero/random/tty) — writable.
        p.push_str("(allow file-write* (subpath \"/dev\"))\n");
    }
    Some(p)
}

/// Quote a path as an SBPL string literal (escape `\` and `"`). SBPL string
/// literals are double-quoted C-style strings.
fn sbpl_quote(path: &str) -> String {
    let escaped = path.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view() -> ViewConfig {
        ViewConfig {
            agent_view_root: Some("/srv/av/agentview".to_string()),
            workspace: Some("/home/u/project".to_string()),
            workspace_writable: false,
        }
    }

    // ── plan_sandbox ─────────────────────────────────────────────────────────

    #[test]
    fn agentshell_is_the_asymmetric_overlay() {
        let p = plan_sandbox(ExecShell::AgentShell, &view(), Some("/home/u/project"));
        assert!(p.sandboxed);
        assert!(p.net_off, "AgentShell egress must be off");
        assert!(p.ro_root, "the rest of the FS must be read-only");
        assert!(p.dev && p.proc);
        // Hardened namespaces + dropped privilege — ALL on for AgentShell.
        assert!(p.unshare_pid, "PID ns unshared so /proc shows only sandbox PIDs");
        assert!(p.unshare_ipc, "IPC ns unshared");
        assert!(p.unshare_uts, "UTS ns unshared");
        assert!(p.unshare_cgroup, "cgroup ns unshared");
        assert!(p.new_session, "new session blocks TIOCSTI terminal-injection");
        assert!(p.cap_drop_all, "all in-userns capabilities dropped");
        assert!(p.disable_userns, "further userns nesting disabled");
        assert!(
            !p.seccomp_deny_userns,
            "the pure plan defaults to the flag posture; only the backend's bwrap probe flips it"
        );
        // The seccomp fd is a runtime resource — the PURE plan never owns one.
        assert_eq!(p.seccomp_fd, None, "the pure plan leaves the seccomp fd unset");
        assert_eq!(p.tmpfs, vec!["/tmp".to_string()]);
        assert_eq!(
            p.rw_binds,
            vec![
                BindMount {
                    src: "/srv/av/agentview".into(),
                    dst: "/home/u/project".into(),
                    writable: true,
                },
                BindMount {
                    src: "/srv/av/agentview".into(),
                    dst: "/srv/av/agentview".into(),
                    writable: true,
                },
            ],
            "the ONLY writable places are the AgentView, at the workspace and at its own path",
        );
        assert_eq!(p.chdir.as_deref(), Some("/home/u/project"));
    }

    #[test]
    fn agentview_identity_bind_dedupes_when_av_is_the_workspace() {
        // av == ws → the identity bind WOULD duplicate the overlay bind at the
        // same dst; the plan must carry exactly one.
        let v = ViewConfig {
            agent_view_root: Some("/srv/av/agentview".to_string()),
            workspace: Some("/srv/av/agentview".to_string()),
            workspace_writable: false,
        };
        let p = plan_sandbox(ExecShell::AgentShell, &v, None);
        assert_eq!(
            p.rw_binds,
            vec![BindMount {
                src: "/srv/av/agentview".into(),
                dst: "/srv/av/agentview".into(),
                writable: true,
            }],
            "av == ws must yield exactly ONE bind",
        );
        // The LSM leg deduped with it (derived from the bind dsts).
        assert_eq!(
            p.landlock_rw_paths,
            vec!["/srv/av/agentview".to_string(), "/tmp".to_string()]
        );
    }

    #[test]
    fn agentshell_agentview_cwd_is_inside_a_writable_bind() {
        // The property the launcher relies on: fs-view rewrites the live
        // agent's cwd INTO the AgentView real path, and a boxed command
        // inherits it — so that cwd must be kept verbatim AND sit under a
        // writable bind dst (the identity bind), or every relative write at
        // the command's own cwd fails EROFS.
        let cwd = "/srv/av/agentview/sub/dir";
        let p = plan_sandbox(ExecShell::AgentShell, &view(), Some(cwd));
        assert_eq!(p.chdir.as_deref(), Some(cwd), "chdir is the inherited cwd, verbatim");
        assert!(
            p.rw_binds
                .iter()
                .any(|b| b.writable
                    && (cwd == b.dst || cwd.starts_with(&format!("{}/", b.dst)))),
            "an AgentView cwd must sit under a writable bind dst, got: {:?}",
            p.rw_binds,
        );
    }

    #[test]
    fn humanshell_is_a_passthrough() {
        let p = plan_sandbox(ExecShell::HumanShell, &view(), Some("/home/u/project"));
        assert!(!p.sandboxed);
        assert!(!p.net_off);
        assert!(!p.ro_root);
        assert!(p.rw_binds.is_empty());
        assert!(p.tmpfs.is_empty());
        // The unrestricted view applies NONE of the AgentShell hardening.
        assert!(!p.unshare_pid && !p.unshare_ipc && !p.unshare_uts && !p.unshare_cgroup);
        assert!(!p.new_session && !p.cap_drop_all && !p.disable_userns);
        assert!(!p.seccomp_deny_userns);
        assert_eq!(p.seccomp_fd, None);
    }

    #[test]
    fn agentshell_without_view_still_isolates_net_and_ro() {
        // No AgentView configured → no RW bind, but net-off + RO-root STILL bound
        // the command (it can read but not write, and cannot egress).
        let p = plan_sandbox(ExecShell::AgentShell, &ViewConfig::default(), None);
        assert!(p.sandboxed);
        assert!(p.net_off && p.ro_root);
        assert!(p.rw_binds.is_empty(), "no AgentView → nothing writable outside tmpfs");
    }

    // ── the workspace without an AgentView (exec-routing.md §7.2) ────────────

    fn no_view(ws: &str, writable: bool) -> ViewConfig {
        ViewConfig { agent_view_root: None, workspace: Some(ws.into()), workspace_writable: writable }
    }

    #[test]
    fn the_workspace_is_writable_only_when_asked_and_only_without_an_agentview() {
        // Asked, no AgentView (integrity OFF): one RW bind of the real tree at
        // its own path, after the agent's own /tmp (`shares_real_tmp`),
        // both mirrored into the Landlock leg's writable set.
        let p = plan_sandbox(ExecShell::AgentShell, &no_view("/home/u/p", true), Some("/home/u/p/src"));
        assert_eq!(p.rw_binds, vec![
            BindMount { src: "/tmp".into(), dst: "/tmp".into(), writable: true },
            BindMount { src: "/home/u/p".into(), dst: "/home/u/p".into(), writable: true },
        ]);
        assert!(p.tmpfs.is_empty(), "the agent's own /tmp, no fresh scratch");
        assert_eq!(p.landlock_rw_paths, vec!["/tmp".to_string(), "/home/u/p".to_string()]);
        assert!(p.ro_root && p.net_off, "the rest of the box is unchanged: RO root, net off");
        assert!(p.ro_keep_binds.is_empty());
        // Not asked (the launcher's default, and every integrity launch): RO.
        let p = plan_sandbox(ExecShell::AgentShell, &no_view("/home/u/p", false), Some("/home/u/p"));
        assert!(p.rw_binds.is_empty(), "not asked → the workspace stays read-only");
        assert_eq!(p.tmpfs, vec!["/tmp".to_string()], "and the scratch stays fresh");
        assert_eq!(p.landlock_rw_paths, vec!["/tmp".to_string()]);
        // With an AgentView the pair wins: the flag adds nothing.
        let mut v = view();
        v.workspace_writable = true;
        let with_pair = plan_sandbox(ExecShell::AgentShell, &v, Some("/home/u/project"));
        assert_eq!(with_pair.rw_binds, plan_sandbox(ExecShell::AgentShell, &view(), Some("/home/u/project")).rw_binds);
        assert!(with_pair.rw_binds.iter().all(|b| b.src == "/srv/av/agentview"), "never the HumanView beside an AgentView");
        // Asked with no workspace named: nothing to bind.
        let none = ViewConfig { workspace_writable: true, ..ViewConfig::default() };
        assert!(plan_sandbox(ExecShell::AgentShell, &none, Some("/home/u/p")).rw_binds.is_empty());
        // HumanShell is a passthrough either way.
        assert!(!plan_sandbox(ExecShell::HumanShell, &no_view("/home/u/p", true), None).sandboxed);
    }

    #[test]
    fn a_writable_workspace_never_covers_the_box_own_mounts() {
        let tmpfs = vec!["/tmp".to_string()];
        for bad in ["/", "/tmp", "/dev", "/proc", "/sys", "/run", "/var", "/var/run", "rel/p", "/home/u/../etc", "/home/u/p/", "/home//p"] {
            assert_eq!(writable_workspace(&no_view(bad, true), &tmpfs), None, "{bad:?} must stay read-only");
            assert_eq!(writable_workspace(&no_view(bad, true), &[]), None, "{bad:?}: read-only beside the real /tmp too");
            // only the agent's own /tmp (`shares_real_tmp`) is writable then
            let binds = plan_sandbox(ExecShell::AgentShell, &no_view(bad, true), None).rw_binds;
            assert!(binds.iter().all(|b| b.src == "/tmp" && b.dst == "/tmp"), "{bad:?}: {binds:?}");
        }
        for good in ["/home/u/p", "/tmp/x/proj", "/run/media/u/disk/proj", "/var/www/site", "/srv/devroot"] {
            assert_eq!(writable_workspace(&no_view(good, true), &tmpfs), Some(good), "{good:?}");
        }
        // A scratch the caller names is honored too (the in-process backend's).
        assert_eq!(writable_workspace(&no_view("/scratch", true), &["/scratch/t".to_string()]), None);
    }

    #[test]
    fn a_writable_tmp_workspace_is_bound_after_the_agent_own_tmp_with_no_read_only_keep() {
        let p = plan_sandbox(ExecShell::AgentShell, &no_view("/tmp/x/proj", true), Some("/tmp/x/proj"));
        assert!(p.ro_keep_binds.is_empty(), "the real /tmp already shows the project");
        let j = bwrap_argv(&p, &["sed".into()]).unwrap().join(" ");
        let tmp = j.find("--bind /tmp /tmp").expect("the agent's own /tmp, writable");
        let bind = j.find("--bind /tmp/x/proj /tmp/x/proj").expect("the project, writable");
        assert!(tmp < bind, "{j}");
        assert!(!j.contains("--tmpfs /tmp"), "no fresh scratch over it: {j}");
    }

    // ── the agent's own /tmp (exec-routing.md §7.2, 2026-10-19) ─────────────

    #[test]
    fn the_real_tmp_only_in_the_integrity_off_box() {
        // demo-c14 (2026-10-19): `curl -o /tmp/out …` ran unboxed, then a
        // boxed `cat /tmp/out` saw the box's fresh tmpfs: "No such file".
        assert!(shares_real_tmp(&no_view("/home/u/p", true)));
        assert!(!shares_real_tmp(&ViewConfig { workspace_writable: true, ..ViewConfig::default() }), "no project named: fresh");
        assert!(!shares_real_tmp(&no_view("/home/u/p", false)), "not asked: fresh");
        let mut v = view();
        v.workspace_writable = true;
        assert!(!shares_real_tmp(&v), "an AgentView (integrity ON): fresh");
        for (cfg, real) in [(no_view("/home/u/p", true), true), (no_view("/home/u/p", false), false), (v, false), (view(), false)] {
            let p = plan_sandbox(ExecShell::AgentShell, &cfg, Some("/home/u/p"));
            let j = bwrap_argv(&p, &["cat".into()]).unwrap().join(" ");
            assert_eq!(j.contains("--bind /tmp /tmp"), real, "{j}");
            assert_eq!(j.contains("--tmpfs /tmp"), !real, "{j}");
            assert!(p.net_off && p.ro_root && j.contains("--unshare-net"), "net off and the RO root stay: {j}");
        }
        // A workspace that is or holds /tmp is never bound writable over it.
        for bad in ["/tmp", "/"] {
            let p = plan_sandbox(ExecShell::AgentShell, &no_view(bad, true), None);
            assert_eq!(p.rw_binds.iter().filter(|b| b.dst != "/tmp").count(), 0, "{bad:?}");
        }
    }

    #[test]
    fn host_sockets_under_the_real_tmp_are_masked_after_its_bind() {
        // The real-tree bind takes its source from the caller's namespace,
        // where no mask exists: the tmux, X11 and ssh-agent masks come after.
        let mut p = plan_sandbox(ExecShell::AgentShell, &no_view("/home/u/p", true), Some("/home/u/p"));
        p.host_hide = socket_box_hide(&SocketScan {
            sockets: vec!["/tmp/tmux-1000/default".into(), "/tmp/.X11-unix/X0".into(), "/run/docker.sock".into()],
            opaque_dirs: vec!["/tmp/systemd-private-x".into()],
            truncated: false,
        });
        let argv = bwrap_argv(&p, &["cat".into()]).unwrap();
        let j = argv.join(" ");
        let at = |needle: &str| j.find(needle).unwrap_or_else(|| panic!("{needle} missing: {j}"));
        let tmp = at("--bind /tmp /tmp");
        for after in ["--ro-bind /dev/null /tmp/tmux-1000/default", "--ro-bind /dev/null /tmp/.X11-unix/X0", "--tmpfs /tmp/systemd-private-x"] {
            assert!(tmp < at(after), "{after} after the bind: {j}");
        }
        assert_eq!(argv.iter().filter(|a| *a == "/tmp/tmux-1000/default").count(), 1, "rendered once: {j}");
        assert!(p.host_hide.mount_points().any(|m| m == "/tmp/.X11-unix/X0"), "the race check knows it");
    }

    #[test]
    fn the_clean_posture_never_reads_the_real_tmp() {
        // Its LSM leg grants RW on the scratch: over the real /tmp that would
        // read what the agent wrote there into a "clean" output.
        let p = plan_sandbox(ExecShell::AgentShell, &no_view("/home/u/p", true), Some("/home/u/p")).into_clean(vec!["/usr".into()]);
        assert_eq!(p.tmpfs, vec!["/tmp".to_string()]);
        assert!(!p.rw_binds.iter().any(|b| b.dst == "/tmp"), "{:?}", p.rw_binds);
        let mut q = plan_sandbox(ExecShell::AgentShell, &no_view("/home/u/p", true), Some("/home/u/p"));
        q.landlock_apply = Some("/opt/mandu/landlock-apply".into());
        q.landlock_clean = true;
        q.fresh_scratch();
        let j = bwrap_argv(&q, &["cat".into()]).unwrap().join(" ");
        assert!(j.contains("--tmpfs /tmp") && !j.contains("--bind /tmp /tmp"), "{j}");
        assert!(j.contains("--rw /tmp") && j.contains("--write-only /home/u/p"), "{j}");
        // a no-op on a fresh plan
        let mut f = plan_sandbox(ExecShell::AgentShell, &no_view("/home/u/p", false), None);
        let before = f.clone();
        f.fresh_scratch();
        assert_eq!(f, before);
    }

    #[test]
    fn host_masks_under_a_writable_workspace_are_re_applied_after_its_bind() {
        // The real-tree bind takes its source from the caller's namespace,
        // where no mask exists: a mask rendered before it would be undone.
        let mut p = plan_sandbox(ExecShell::AgentShell, &no_view("/home/u/p", true), Some("/home/u/p"));
        p.host_hide = socket_box_hide(&SocketScan {
            sockets: vec![
                "/run/docker.sock".into(),
                "/home/u/.ssh/cm.sock".into(), // outside the workspace
                "/home/u/p/.dev.sock".into(),  // inside it
                "/tmp/tmux-1000/default".into(),
            ],
            opaque_dirs: vec!["/home/u/p/locked".into(), "/home/u/.gnupg/private".into()],
            truncated: false,
        });
        let argv = bwrap_argv(&p, &["true".into()]).unwrap();
        let j = argv.join(" ");
        let at = |needle: &str| j.find(needle).unwrap_or_else(|| panic!("{needle} missing: {j}"));
        let outside = at("--ro-bind /dev/null /home/u/.ssh/cm.sock");
        let gnupg = at("--tmpfs /home/u/.gnupg/private");
        // the agent's own /tmp (integrity OFF), a real-tree bind too
        let tmp = at("--bind /tmp /tmp");
        let bind = at("--bind /home/u/p /home/u/p");
        let locked = at("--tmpfs /home/u/p/locked");
        let inside = at("--ro-bind /dev/null /home/u/p/.dev.sock");
        let tmux = at("--ro-bind /dev/null /tmp/tmux-1000/default");
        let chdir = at("--chdir /home/u/p");
        assert!(gnupg < outside && outside < tmp && tmp < bind, "{j}");
        assert!(bind < locked && bind < inside && inside < chdir && locked < chdir, "re-applied after the bind: {j}");
        assert!(bind < tmux && tmux < chdir, "the /tmp socket masked after the binds: {j}");
        assert_eq!(argv.iter().filter(|a| *a == "/home/u/p/.dev.sock").count(), 1, "rendered once, after the bind: {j}");
        assert_eq!(argv.iter().filter(|a| *a == "/home/u/.ssh/cm.sock").count(), 1, "{j}");
        assert_eq!(argv.iter().filter(|a| *a == "/tmp/tmux-1000/default").count(), 1, "{j}");
        // With the scratch fresh (not asked), the scratch covers it.
        let mut fresh = plan_sandbox(ExecShell::AgentShell, &no_view("/home/u/p", false), Some("/home/u/p"));
        fresh.host_hide = p.host_hide.clone();
        let f = bwrap_argv(&fresh, &["true".into()]).unwrap();
        assert!(!f.iter().any(|a| a == "/tmp/tmux-1000/default"), "the scratch covers it: {}", f.join(" "));
        // The masks are still mount points the race check knows.
        assert!(p.host_hide.mount_points().any(|m| m == "/home/u/p/.dev.sock"));
    }

    #[test]
    fn a_mask_inside_a_tmp_project_is_applied_after_the_bind_that_brings_it_back() {
        // A /tmp project: the scratch hid the host's entry, the project's
        // bind (writable, or the read-only keep) brings it back unmasked.
        for writable in [true, false] {
            let mut p = plan_sandbox(ExecShell::AgentShell, &no_view("/tmp/x/proj", writable), Some("/tmp/x/proj"));
            p.host_hide.files = vec!["/tmp/x/proj/.agent.sock".into(), "/tmp/other.sock".into()];
            let j = bwrap_argv(&p, &["true".into()]).unwrap().join(" ");
            let bind = j.find(if writable { "--bind /tmp/x/proj /tmp/x/proj" } else { "--ro-bind /tmp/x/proj /tmp/x/proj" }).unwrap();
            let mask = j.find("--ro-bind /dev/null /tmp/x/proj/.agent.sock").unwrap_or_else(|| panic!("mask missing: {j}"));
            assert!(bind < mask, "{j}");
            if writable {
                // integrity OFF: the agent's own /tmp, every socket in it masked
                let other = j.find("--ro-bind /dev/null /tmp/other.sock").unwrap_or_else(|| panic!("mask missing: {j}"));
                assert!(j.find("--bind /tmp /tmp").unwrap() < other, "{j}");
            } else {
                assert!(!j.contains("/tmp/other.sock"), "the scratch hides the rest of /tmp: {j}");
            }
        }
    }

    // ── bwrap_argv ───────────────────────────────────────────────────────────

    #[test]
    fn bwrap_argv_orders_ro_base_then_overlays() {
        let p = plan_sandbox(ExecShell::AgentShell, &view(), Some("/home/u/project"));
        let argv = bwrap_argv(&p, &["cat".into(), "notes.md".into()]).expect("sandboxed → Some");
        let joined = argv.join(" ");
        assert_eq!(argv[0], "bwrap");
        assert!(joined.contains("--unshare-net"));
        // Hardened namespaces + dropped privilege must all be emitted.
        assert!(joined.contains("--unshare-pid"), "PID ns");
        assert!(joined.contains("--unshare-ipc"), "IPC ns");
        assert!(joined.contains("--unshare-uts"), "UTS ns");
        assert!(joined.contains("--unshare-cgroup"), "cgroup ns");
        assert!(joined.contains("--new-session"), "new session (TIOCSTI block)");
        assert!(joined.contains("--disable-userns"), "no userns nesting");
        // bwrap ≥ 0.8 rejects --disable-userns without an explicit --unshare-user.
        let uu = argv.iter().position(|s| s == "--unshare-user").expect("--unshare-user present");
        let du = argv.iter().position(|s| s == "--disable-userns").unwrap();
        assert!(uu < du, "--unshare-user precedes --disable-userns");
        // --cap-drop ALL is two adjacent argv tokens.
        let cd = argv.iter().position(|s| s == "--cap-drop").expect("--cap-drop present");
        assert_eq!(argv[cd + 1], "ALL", "--cap-drop is followed by ALL");
        // Hardening toggles precede the mounts.
        assert!(
            joined.find("--unshare-pid").unwrap() < joined.find("--ro-bind").unwrap(),
            "flag toggles come before the mounts"
        );
        // Precedence via order: RO base, then scratch tmpfs, then the writable
        // AgentView binds LAST (so the explicit binds win over both) — BOTH of
        // them: the overlay at the workspace and the identity bind at the
        // AgentView's own path.
        let ro = joined.find("--ro-bind / /").expect("ro base present");
        let tmp = joined.find("--tmpfs /tmp").expect("tmpfs scratch present");
        let rw = joined.find("--bind /srv/av/agentview /home/u/project").expect("rw overlay present");
        let ident = joined
            .find("--bind /srv/av/agentview /srv/av/agentview")
            .expect("rw identity bind present");
        assert!(ro < tmp && tmp < rw, "order must be RO base < tmpfs < RW AgentView overlay");
        assert!(tmp < ident, "the identity bind must also come after the tmpfs");
        // fresh dev/proc + chdir + the program after `--`.
        assert!(joined.contains("--dev /dev") && joined.contains("--proc /proc"));
        assert!(joined.contains("--chdir /home/u/project"));
        let dd = argv.iter().position(|s| s == "--").expect("-- separator");
        assert_eq!(&argv[dd + 1..], &["cat".to_string(), "notes.md".to_string()]);
    }

    #[test]
    fn bwrap_argv_none_for_passthrough_and_empty_program() {
        let human = plan_sandbox(ExecShell::HumanShell, &view(), None);
        assert!(bwrap_argv(&human, &["ls".into()]).is_none(), "HumanShell runs as-is");
        let agent = plan_sandbox(ExecShell::AgentShell, &view(), None);
        assert!(bwrap_argv(&agent, &[]).is_none(), "empty program → nothing to run");
    }

    #[test]
    fn bwrap_argv_die_with_parent_always_present_when_sandboxed() {
        let p = plan_sandbox(ExecShell::AgentShell, &ViewConfig::default(), None);
        let argv = bwrap_argv(&p, &["true".into()]).unwrap();
        assert!(argv.contains(&"--die-with-parent".to_string()));
        // No AgentView → no --bind overlay, but the RO base + net-off still apply.
        assert!(argv.join(" ").contains("--ro-bind / /"));
        assert!(!argv.join(" ").contains("--bind /srv"));
    }

    #[test]
    fn bwrap_argv_deny_userns_posture_drops_the_flag_and_adds_no_token() {
        // The degraded posture (probed bwrap < 0.8): the backend clears
        // disable_userns and sets seccomp_deny_userns. The argv must lose
        // --disable-userns (bwrap would reject the whole command line) and gain
        // NOTHING — the denial moves into the filter bytes, not the argv.
        let mut p = plan_sandbox(ExecShell::AgentShell, &view(), Some("/home/u/project"));
        let flag_argv = bwrap_argv(&p, &["true".into()]).unwrap();
        p.disable_userns = false;
        p.seccomp_deny_userns = true;
        let filter_argv = bwrap_argv(&p, &["true".into()]).unwrap();
        assert!(flag_argv.contains(&"--disable-userns".to_string()));
        assert!(!filter_argv.contains(&"--disable-userns".to_string()));
        assert!(!filter_argv.contains(&"--unshare-user".to_string()), "the pairing flag goes with it");
        // Identical argv apart from the dropped flag pair.
        let without: Vec<&String> = flag_argv
            .iter()
            .filter(|s| *s != "--disable-userns" && *s != "--unshare-user")
            .collect();
        assert_eq!(
            without,
            filter_argv.iter().collect::<Vec<_>>(),
            "seccomp_deny_userns must not surface in the argv"
        );
    }

    #[test]
    fn bwrap_argv_emits_seccomp_fd_only_when_set() {
        let mut p = plan_sandbox(ExecShell::AgentShell, &ViewConfig::default(), None);
        // No fd set (the pure plan) → no --seccomp token.
        let argv = bwrap_argv(&p, &["true".into()]).unwrap();
        assert!(
            !argv.iter().any(|s| s == "--seccomp"),
            "no seccomp fd → no --seccomp flag"
        );
        // A runtime fd → `--seccomp <fd>` as two adjacent early tokens.
        p.seccomp_fd = Some(10);
        let argv = bwrap_argv(&p, &["true".into()]).unwrap();
        let i = argv.iter().position(|s| s == "--seccomp").expect("--seccomp emitted");
        assert_eq!(argv[i + 1], "10", "--seccomp is followed by the fd number");
        // It sits among the early flags, before the mounts.
        assert!(i < argv.iter().position(|s| s == "--ro-bind").unwrap());
    }

    // ── the Landlock leg (in-sandbox applier interposition) ─────────────────────

    #[test]
    fn agentshell_plan_carries_the_landlock_rw_set_in_in_box_coordinates() {
        // The LSM leg's writable set mirrors the mount overlay's, as seen from
        // INSIDE the box: the bind DESTINATIONS (the workspace the AgentView is
        // bound over + the AgentView's own path, in dst order), plus the
        // scratch. The applier path is a runtime resource the pure plan never
        // owns (same rule as seccomp_fd).
        let p = plan_sandbox(ExecShell::AgentShell, &view(), Some("/home/u/project"));
        assert_eq!(
            p.landlock_rw_paths,
            vec![
                "/home/u/project".to_string(),
                "/srv/av/agentview".to_string(),
                "/tmp".to_string()
            ],
            "RW = the workspace the AgentView is bound over + the AgentView's own path + scratch"
        );
        assert_eq!(p.landlock_apply, None, "the pure plan leaves the applier unset");
        // No configured view → only the scratch stays writable at the LSM layer.
        let bare = plan_sandbox(ExecShell::AgentShell, &ViewConfig::default(), None);
        assert_eq!(bare.landlock_rw_paths, vec!["/tmp".to_string()]);
        // The passthrough carries no LSM leg at all.
        let human = plan_sandbox(ExecShell::HumanShell, &view(), None);
        assert!(human.landlock_rw_paths.is_empty() && human.landlock_apply.is_none());
    }

    #[test]
    fn bwrap_argv_interposes_the_landlock_applier_between_bwrap_and_target() {
        let mut p = plan_sandbox(ExecShell::AgentShell, &view(), Some("/home/u/project"));
        // No applier set (Landlock unavailable / binary not locatable) → the
        // target follows the first `--` directly, and no applier token leaks in.
        let argv = bwrap_argv(&p, &["cat".into(), "x".into()]).unwrap();
        let dd = argv.iter().position(|s| s == "--").unwrap();
        assert_eq!(&argv[dd + 1..], &["cat".to_string(), "x".to_string()]);
        assert!(!argv.iter().any(|s| s == "--rw" || s == "--deny-tcp"));

        // Applier set → `<applier> --rw <ws> --rw <av> --rw /tmp --deny-tcp --
        // <target>` right after bwrap's own `--`, so bwrap execs the applier
        // and the applier execs the target AFTER restricting itself.
        p.landlock_apply = Some("/usr/lib/mandu/mandu-landlock-apply".into());
        let argv = bwrap_argv(&p, &["cat".into(), "x".into()]).unwrap();
        let dd = argv.iter().position(|s| s == "--").unwrap();
        assert_eq!(
            &argv[dd + 1..],
            &[
                "/usr/lib/mandu/mandu-landlock-apply".to_string(),
                "--rw".into(),
                "/home/u/project".into(),
                "--rw".into(),
                "/srv/av/agentview".into(),
                "--rw".into(),
                "/tmp".into(),
                "--deny-tcp".into(),
                "--".into(),
                "cat".into(),
                "x".into(),
            ],
            "the applier wraps the target inside the box"
        );
    }

    #[test]
    fn bwrap_argv_renders_the_clean_applier_mode() {
        // The CLEAN posture (exec-output-trust §4 rung 2): --clean with the
        // verified read roots, the bind dsts write-only, the tmpfs scratch rw —
        // and NO --deny-tcp token (TCP denial is built into the clean plan).
        let p = plan_sandbox(ExecShell::AgentShell, &view(), Some("/home/u/project"))
            .into_clean(vec!["/usr".into(), "/etc".into()]);
        let mut p = p;
        p.landlock_apply = Some("/usr/lib/mandu/mandu-landlock-apply".into());
        let argv = bwrap_argv(&p, &["sha256sum".into()]).unwrap();
        let dd = argv.iter().position(|s| s == "--").unwrap();
        assert_eq!(
            &argv[dd + 1..],
            &[
                "/usr/lib/mandu/mandu-landlock-apply".to_string(),
                "--clean".into(),
                "--read".into(), "/usr".into(),
                "--read".into(), "/etc".into(),
                "--write-only".into(), "/home/u/project".into(),
                "--write-only".into(), "/srv/av/agentview".into(),
                "--rw".into(), "/tmp".into(),
                "--".into(),
                "sha256sum".into(),
            ],
            "clean mode: reads ⊆ the verified roots, AgentView write-only, scratch rw"
        );
        assert!(!argv.iter().any(|s| s == "--deny-tcp"), "clean plans deny TCP intrinsically");
        // The bwrap MOUNT side is unchanged — the clean guarantee is the LSM leg.
        let joined = argv.join(" ");
        assert!(joined.contains("--ro-bind / /") && joined.contains("--tmpfs /tmp"));
        assert!(joined.contains("--unshare-net"));
    }

    #[test]
    fn clean_mode_defaults_off_and_ordinary_rendering_is_unchanged() {
        // The pure plan never opts into clean — it is the kernel backend's call.
        let p = plan_sandbox(ExecShell::AgentShell, &view(), None);
        assert!(!p.landlock_clean);
        assert!(p.landlock_read_paths.is_empty());
        // With an applier but NO clean flag, the ordinary --rw/--deny-tcp shape
        // renders exactly as before (regression pin for the branch split).
        let mut p = p;
        p.landlock_apply = Some("/x/mandu-landlock-apply".into());
        let argv = bwrap_argv(&p, &["cat".into(), "x".into()]).unwrap();
        let dd = argv.iter().position(|s| s == "--").unwrap();
        assert_eq!(argv[dd + 1], "/x/mandu-landlock-apply");
        assert!(argv.iter().any(|s| s == "--deny-tcp"));
        assert!(!argv.iter().any(|s| s == "--clean" || s == "--read" || s == "--write-only"));
    }

    #[test]
    fn clean_read_roots_are_system_paths_only() {
        // The posture pin: no /proc (path-in-model leak class), no /home, no
        // workspace — a read grant outside the system set must arrive via a
        // hash-verified TrustedRead, never this default list.
        for banned in ["/proc", "/home", "/opt", "/tmp", "/"] {
            assert!(
                !CLEAN_READ_ROOTS.contains(&banned),
                "{banned} must not be a default clean-read root"
            );
        }
        assert!(CLEAN_READ_ROOTS.contains(&"/usr") && CLEAN_READ_ROOTS.contains(&"/etc"));
    }

    // ── Seatbelt (macOS deny tier) ─────────────────────────────────────────────

    #[test]
    fn seatbelt_profile_denies_net_and_writes_outside_agentview() {
        let sb = seatbelt_profile(&plan_sandbox(ExecShell::AgentShell, &view(), Some("/home/u/project")))
            .expect("sandboxed → Some");
        assert!(sb.contains("(deny default)"));
        assert!(sb.contains("(allow file-read*)"), "reads allowed (output symbolized at the proxy)");
        assert!(sb.contains("(deny file-write*)"));
        assert!(sb.contains("(deny network*)"), "AgentShell egress off");
        // Writes are allowed back only inside the AgentView — at the real
        // workspace dst AND at its own path (both bind dsts).
        assert!(sb.contains("(allow file-write* (subpath \"/home/u/project\"))"));
        assert!(sb.contains("(allow file-write* (subpath \"/srv/av/agentview\"))"));
        // Ordering: the blanket write-deny must precede the AgentView write-allow
        // (SBPL last-match-wins → the allow re-permits the subtree).
        let deny = sb.find("(deny file-write*)").unwrap();
        let allow = sb.find("(allow file-write* (subpath \"/home/u/project\"))").unwrap();
        assert!(deny < allow, "deny-all-writes must precede the AgentView write-allow");
    }

    #[test]
    fn seatbelt_profile_none_for_passthrough() {
        let human = plan_sandbox(ExecShell::HumanShell, &view(), None);
        assert!(seatbelt_profile(&human).is_none(), "HumanShell has no Seatbelt profile");
    }

    #[test]
    fn sbpl_quote_escapes_quotes_and_backslashes() {
        assert_eq!(sbpl_quote(r#"/a/"b"/c"#), r#""/a/\"b\"/c""#);
        assert_eq!(sbpl_quote(r"/a\b"), r#""/a\\b""#);
    }

    #[test]
    fn the_box_unsets_loader_variables() {
        let plan = plan_sandbox(ExecShell::AgentShell, &ViewConfig::default(), None);
        let argv = bwrap_argv(&plan, &["true".to_string()]).unwrap();
        let dash = argv.iter().position(|t| t == "--").unwrap();
        for v in BOX_UNSET_ENV {
            let at = argv.windows(2).position(|w| w[0] == "--unsetenv" && w[1] == *v);
            assert!(at.map_or(false, |i| i < dash), "{v} is unset before the program");
        }
        assert!(BOX_UNSET_ENV.contains(&"LD_PRELOAD") && BOX_UNSET_ENV.contains(&"NODE_OPTIONS"));
        // HumanShell is not boxed at all: nothing is unset there.
        let human = plan_sandbox(ExecShell::HumanShell, &ViewConfig::default(), None);
        assert!(bwrap_argv(&human, &["true".to_string()]).is_none());
    }

    // ── a project under /tmp (open-source-release checklist a7) ──────────────

    fn ro(p: &str) -> BindMount {
        BindMount { src: p.into(), dst: p.into(), writable: false }
    }

    #[test]
    fn a_tmp_workspace_without_a_view_is_rebound_read_only_after_the_tmpfs() {
        // The fresh-user repro: `cd /tmp/x/proj && mandu claude` (no AgentView
        // pair) → every boxed command died `bwrap: Can't chdir to /tmp/x/proj`.
        let v = ViewConfig { agent_view_root: None, workspace: Some("/tmp/x/proj".into()), workspace_writable: false };
        let p = plan_sandbox(ExecShell::AgentShell, &v, Some("/tmp/x/proj/src"));
        assert_eq!(p.ro_keep_binds, vec![ro("/tmp/x/proj")]);
        assert!(p.rw_binds.is_empty(), "still nothing writable but the scratch");
        let argv = bwrap_argv(&p, &["cat".into(), "README.md".into()]).unwrap();
        let joined = argv.join(" ");
        let tmp = joined.find("--tmpfs /tmp").unwrap();
        let keep = joined.find("--ro-bind /tmp/x/proj /tmp/x/proj").expect("the project is re-bound");
        let chdir = joined.find("--chdir /tmp/x/proj/src").unwrap();
        assert!(tmp < keep, "the re-bind must come AFTER the tmpfs (a later mount wins)");
        assert!(keep < chdir);
        // The rest of the real /tmp is NOT brought back.
        assert!(!argv.windows(3).any(|w| w[0] == "--ro-bind" && w[1] == "/tmp"), "never the whole /tmp");
        assert!(!argv.windows(3).any(|w| w[0] == "--bind" && w[1].starts_with("/tmp")), "never writable");
    }

    #[test]
    fn keep_binds_only_when_the_project_is_strictly_under_the_tmpfs() {
        let plan = |ws: Option<&str>, cwd: Option<&str>| {
            let v = ViewConfig { agent_view_root: None, workspace: ws.map(str::to_string), workspace_writable: false };
            plan_sandbox(ExecShell::AgentShell, &v, cwd).ro_keep_binds
        };
        // a /home project: unchanged (the RO root already shows it)
        assert!(plan(Some("/home/u/proj"), Some("/home/u/proj")).is_empty());
        // /tmp itself is the scratch mount point: never re-bound (that would put
        // the real /tmp back over the scratch)
        assert!(plan(Some("/tmp"), Some("/tmp")).is_empty());
        // a look-alike prefix is not "under /tmp"
        assert!(plan(Some("/tmpfoo/proj"), None).is_empty());
        // lexically unclean paths are refused (a `..` could name anything)
        assert!(plan(Some("/tmp/../home/u"), None).is_empty());
        assert!(plan(Some("/tmp/x/./proj"), None).is_empty());
        assert!(plan(Some("tmp/x"), None).is_empty());
        assert!(plan(Some("/tmp/x/"), None).is_empty());
        // with a workspace named, a cwd ELSEWHERE under /tmp is not re-bound
        // (`cd /tmp/ssh-XXXX` must not pull other /tmp entries into the box)
        assert!(plan(Some("/home/u/proj"), Some("/tmp/ssh-XXXX")).is_empty());
        assert_eq!(plan(Some("/tmp/x/proj"), Some("/tmp/other")), vec![ro("/tmp/x/proj")]);
        // no workspace at all (the bin run standalone): the cwd is the project hint
        assert_eq!(plan(None, Some("/tmp/x/proj")), vec![ro("/tmp/x/proj")]);
        assert!(plan(None, None).is_empty());
    }

    #[test]
    fn an_agentview_bound_over_a_tmp_workspace_needs_no_keep() {
        // The integrity-mode shape: the AgentView RW bind over /tmp/x/proj
        // already comes after the tmpfs and wins; a RO keep would be redundant.
        let v = ViewConfig {
            agent_view_root: Some("/home/u/.mandu/workspaces/w/agentview".into()),
            workspace: Some("/tmp/x/proj".into()),
            workspace_writable: false,
        };
        let p = plan_sandbox(ExecShell::AgentShell, &v, Some("/home/u/.mandu/workspaces/w/agentview"));
        assert!(p.ro_keep_binds.is_empty());
        assert!(p.rw_binds.iter().any(|b| b.dst == "/tmp/x/proj" && b.writable));
    }

    #[test]
    fn tmpfs_keep_binds_dedupes_and_prefers_the_ancestor() {
        let t = vec!["/tmp".to_string()];
        assert_eq!(
            tmpfs_keep_binds(&t, &[], &["/tmp/a/b", "/tmp/a/b/c"]),
            vec![ro("/tmp/a/b")],
            "a path under an earlier keep is covered"
        );
        assert_eq!(
            tmpfs_keep_binds(&t, &[], &["/tmp/a/b/c", "/tmp/a"]),
            vec![ro("/tmp/a")],
            "an ancestor replaces the keep it contains"
        );
        let rw = vec![BindMount { src: "/av".into(), dst: "/tmp/a".into(), writable: true }];
        assert!(tmpfs_keep_binds(&t, &rw, &["/tmp/a/b"]).is_empty(), "an RW bind dst covers it");
        assert!(tmpfs_keep_binds(&[], &[], &["/tmp/a"]).is_empty(), "no tmpfs, nothing hidden");
    }

    #[test]
    fn the_clean_box_never_renders_the_keep_binds() {
        // Clean mode's Landlock leg grants --rw over the whole scratch mount; a
        // re-bound project under it would be READABLE there and its bytes could
        // reach a "clean" (unmasked) output. So the clean attempt omits the keep,
        // fails to chdir, and the ordinary box reruns the command.
        let v = ViewConfig { agent_view_root: None, workspace: Some("/tmp/x/proj".into()), workspace_writable: false };
        let mut p = plan_sandbox(ExecShell::AgentShell, &v, Some("/tmp/x/proj"))
            .into_clean(vec!["/usr".into()]);
        p.landlock_apply = Some("/x/mandu-landlock-apply".into());
        let argv = bwrap_argv(&p, &["date".into()]).unwrap();
        assert!(
            !argv.windows(3).any(|w| w[0] == "--ro-bind" && w[1] == "/tmp/x/proj"),
            "no keep bind in the clean posture: {argv:?}"
        );
        // ...while the ordinary rendering of the same plan carries it.
        p.landlock_clean = false;
        let ordinary = bwrap_argv(&p, &["date".into()]).unwrap();
        assert!(ordinary.windows(3).any(|w| w[0] == "--ro-bind" && w[1] == "/tmp/x/proj" && w[2] == "/tmp/x/proj"));
    }

    #[test]
    fn humanshell_has_no_keep_binds() {
        let v = ViewConfig { agent_view_root: None, workspace: Some("/tmp/x/proj".into()), workspace_writable: false };
        assert!(plan_sandbox(ExecShell::HumanShell, &v, Some("/tmp/x/proj")).ro_keep_binds.is_empty());
    }

    // ── WSL: the Windows interop door ─────────────────────────────────────────

    use mandu_arbiter::wsl::WslSignals;

    /// A WSL2 host's layout: the interop dir, WSLg, and /init.
    fn wsl_host(p: &str) -> PathKind {
        match p {
            "/run/WSL" | "/mnt/wslg" => PathKind::Dir,
            "/init" | "/run/WSL/8_interop" | "/srv/odd/1_interop" => PathKind::Other,
            _ => PathKind::Missing,
        }
    }

    fn wsl2() -> WslSignals {
        WslSignals { osrelease: Some("6.6.36.6-microsoft-standard-WSL2".into()), ..Default::default() }
    }

    #[test]
    fn off_wsl_the_box_hides_nothing() {
        let plain = WslSignals { osrelease: Some("6.8.0-139-generic".into()), ..Default::default() };
        // Even with the paths present (a container with an s6 /init): no signal, no hiding.
        assert_eq!(wsl_box_hide(&plain, wsl_host), HostHide::default());
        let p = plan_sandbox(ExecShell::AgentShell, &ViewConfig::default(), None);
        assert!(p.host_hide.is_empty(), "the pure plan never probes");
    }

    #[test]
    fn on_wsl_the_box_hides_the_interop_socket_wslg_and_init() {
        let h = wsl_box_hide(&wsl2(), wsl_host);
        assert_eq!(h.dirs, vec!["/run/WSL".to_string(), "/mnt/wslg".to_string()]);
        assert_eq!(h.files, vec!["/init".to_string()]);
        // The env signal alone is enough, and the socket inside /run/WSL is
        // covered by the tmpfs (no second mask).
        let env_only = WslSignals { interop_env: Some("/run/WSL/8_interop".into()), ..Default::default() };
        assert_eq!(wsl_box_hide(&env_only, wsl_host).files, vec!["/init".to_string()]);
    }

    #[test]
    fn a_socket_named_outside_run_wsl_is_masked_by_name() {
        let s = WslSignals { interop_env: Some("/srv/odd/1_interop".into()), ..wsl2() };
        assert_eq!(wsl_box_hide(&s, wsl_host).files, vec!["/init".to_string(), "/srv/odd/1_interop".to_string()]);
        // Relative, dotted, or missing: never bound (bwrap could not, and a
        // missing socket is already unreachable).
        for bad in ["odd/1_interop", "/srv/../srv/odd/1_interop", "/srv/gone"] {
            let s = WslSignals { interop_env: Some(bad.into()), ..wsl2() };
            assert!(!wsl_box_hide(&s, wsl_host).files.iter().any(|f| f == bad), "{bad}");
        }
    }

    #[test]
    fn missing_wsl_paths_are_skipped() {
        let h = wsl_box_hide(&wsl2(), |_| PathKind::Missing);
        assert_eq!(h, HostHide::default());
    }

    #[test]
    fn the_wsl_hiding_renders_before_the_scratch_and_the_binds() {
        let v = ViewConfig { agent_view_root: Some("/srv/av".into()), workspace: Some("/home/u/p".into()), workspace_writable: false };
        let mut p = plan_sandbox(ExecShell::AgentShell, &v, Some("/home/u/p"));
        let h = wsl_box_hide(&WslSignals { interop_env: Some("/srv/odd/1_interop".into()), ..wsl2() }, wsl_host);
        p.host_hide = h;
        p.host_hide.files.push("/tmp/gone_interop".into()); // under the scratch: skipped
        let argv = bwrap_argv(&p, &["true".into()]).unwrap();
        let j = argv.join(" ");
        let run = j.find("--tmpfs /run/WSL").expect("interop dir hidden");
        let wslg = j.find("--tmpfs /mnt/wslg").expect("WSLg hidden");
        let init = j.find("--ro-bind /dev/null /init").expect("/init masked");
        let odd = j.find("--ro-bind /dev/null /srv/odd/1_interop").expect("the named socket masked");
        let proc_ = j.find("--proc /proc").unwrap();
        let scratch = j.find("--tmpfs /tmp").unwrap();
        let bind = j.find("--bind /srv/av /home/u/p").unwrap();
        assert!(proc_ < run && run < wslg && wslg < init && init < odd && odd < scratch && scratch < bind, "{j}");
        assert!(!j.contains("/tmp/gone_interop"), "a mask under the scratch is redundant: {j}");
        assert!(argv.windows(2).any(|w| w[0] == "--unsetenv" && w[1] == "WSL_INTEROP"));
    }

    // ── host Unix sockets (exec-routing.md §4.2) ─────────────────────────────

    #[test]
    fn every_scanned_socket_is_masked_and_an_opaque_dir_hidden() {
        let scan = SocketScan {
            sockets: vec![
                "/run/docker.sock".into(),
                "/run/user/1000/bus".into(),
                "/run/containerd/containerd.sock".into(), // inside an opaque dir
                "/run/docker.sock".into(),                // duplicate
                "relative.sock".into(),                   // never bound
            ],
            opaque_dirs: vec!["/run/containerd".into(), "/run/containerd/inner".into(), "/".into()],
            truncated: false,
        };
        let h = socket_box_hide(&scan);
        assert_eq!(h.dirs, vec!["/run/containerd".to_string()], "outermost opaque dir only; never /");
        assert_eq!(h.files, vec!["/run/docker.sock".to_string(), "/run/user/1000/bus".to_string()]);
        assert_eq!(socket_box_hide(&SocketScan::default()), HostHide::default());
    }

    #[test]
    fn host_hide_merge_keeps_order_and_dedupes() {
        let mut a = HostHide { dirs: vec!["/a".into()], files: vec!["/x".into()], ..Default::default() };
        a.merge(HostHide { dirs: vec!["/a".into(), "/b".into()], files: vec!["/y".into(), "/x".into()], ..Default::default() });
        assert_eq!(a.dirs, vec!["/a".to_string(), "/b".to_string()]);
        assert_eq!(a.files, vec!["/x".to_string(), "/y".to_string()]);
    }

    #[test]
    fn env_named_sockets_parse_per_variable() {
        let env = |k: &str| -> Option<String> {
            Some(match k {
                "SSH_AUTH_SOCK" => "/home/u/.ssh/agent.sock",
                "DBUS_SESSION_BUS_ADDRESS" => "unix:abstract=/tmp/dbus-x,guid=1;unix:path=/run/user/1000/bus,guid=2",
                "DOCKER_HOST" => "unix:///home/u/.docker/run/docker.sock",
                "CONTAINER_HOST" => "tcp://10.0.0.1:2375",
                "PULSE_SERVER" => "unix:/run/user/1000/pulse/native tcp:host",
                "GPG_AGENT_INFO" => "/home/u/.gnupg/S.gpg-agent:123:1",
                "TMUX" => "/srv/tmux-1000/default,4242,0",
                "NVIM" => "/run/user/1000/nvim.1.0",
                "KITTY_LISTEN_ON" => "unix:@kitty",
                "WAYLAND_DISPLAY" => "wayland-0",
                "XDG_RUNTIME_DIR" => "/run/user/1000/",
                "HYPRLAND_INSTANCE_SIGNATURE" => "abc",
                "VSCODE_IPC_HOOK_CLI" => "",
                _ => return None,
            }.to_string())
        };
        let got = socket_paths_from_env(env);
        for want in [
            "/home/u/.ssh/agent.sock",
            "/run/user/1000/bus",
            "/home/u/.docker/run/docker.sock",
            "/run/user/1000/pulse/native",
            "/home/u/.gnupg/S.gpg-agent",
            "/srv/tmux-1000/default",
            "/run/user/1000/nvim.1.0",
            "/run/user/1000/wayland-0",
            "/run/user/1000/hypr/abc/.socket.sock",
        ] {
            assert!(got.iter().any(|g| g == want), "{want} in {got:?}");
        }
        assert!(got.iter().all(|g| g.starts_with('/')), "abstract and network addresses are skipped: {got:?}");
        assert!(!got.iter().any(|g| g.contains("dbus-x") || g.contains("kitty") || g.contains("10.0.0.1")), "{got:?}");
        assert!(socket_paths_from_env(|_| None).is_empty());
    }

    #[test]
    fn socket_pointers_are_unset_in_the_box() {
        for v in SOCKET_ENV {
            assert!(BOX_UNSET_ENV.contains(v), "{v} names a masked socket and must be unset in the box");
        }
    }

    #[test]
    fn socket_masks_render_before_the_scratch_and_skip_what_a_later_mount_covers() {
        let v = ViewConfig { agent_view_root: Some("/srv/av".into()), workspace: Some("/home/u/p".into()), workspace_writable: false };
        let mut p = plan_sandbox(ExecShell::AgentShell, &v, Some("/home/u/p"));
        let h = socket_box_hide(&SocketScan {
            sockets: vec![
                "/run/docker.sock".into(),
                "/tmp/tmux-1000/default".into(),  // under the scratch
                "/home/u/p/.dev.sock".into(),     // under the AgentView bind dst
                "/run/lvm/x.sock".into(),         // under an opaque dir
            ],
            opaque_dirs: vec!["/run/lvm".into(), "/tmp/locked".into(), "/home/u/p/locked".into()],
            truncated: false,
        });
        p.host_hide = h;
        let argv = bwrap_argv(&p, &["true".into()]).unwrap();
        let j = argv.join(" ");
        let proc_ = j.find("--proc /proc").unwrap();
        let lvm = j.find("--tmpfs /run/lvm").expect("opaque dir hidden");
        let docker = j.find("--ro-bind /dev/null /run/docker.sock").expect("docker.sock masked");
        let scratch = j.find("--tmpfs /tmp").unwrap();
        let bind = j.find("--bind /srv/av /home/u/p").unwrap();
        assert!(proc_ < lvm && lvm < docker && docker < scratch && scratch < bind, "{j}");
        for gone in ["/tmp/tmux-1000/default", "/home/u/p/.dev.sock", "/run/lvm/x.sock", "/tmp/locked", "/home/u/p/locked"] {
            assert!(!argv.iter().any(|a| a == gone), "{gone} is covered by a later/outer mount: {j}");
        }
    }

    #[test]
    fn nested_hide_dirs_render_only_the_outer_one() {
        let mut p = plan_sandbox(ExecShell::AgentShell, &ViewConfig::default(), None);
        p.host_hide.dirs = vec!["/run/WSL".into(), "/run/WSL/inner".into()];
        let argv = bwrap_argv(&p, &["true".into()]).unwrap();
        assert!(argv.windows(2).any(|w| w[0] == "--tmpfs" && w[1] == "/run/WSL"));
        assert!(!argv.iter().any(|a| a == "/run/WSL/inner"));
    }

    // ── /run behind an allow-list (exec-routing.md §4.2) ──────────────────────

    fn run_host(p: &str) -> RunEntry {
        match p {
            "/run" | "/run/wrappers" | "/run/user/1000/mandu/s1/bin" | "/run/media/u/disk/proj" => RunEntry::Dir,
            "/run/utmp" | "/run/user/1000/mandu/s1/ca.pem" | "/run/user/1000/mandu/s1/bin/mandu-landlock-apply" => RunEntry::File,
            "/run/docker.sock" => RunEntry::Other,
            "/run/current-system" => RunEntry::Symlink("/nix/store/abc-system".into()),
            _ => RunEntry::Missing,
        }
    }

    #[test]
    fn run_is_an_empty_tmpfs_with_the_allow_list_put_back() {
        let top = vec![
            ("current-system".to_string(), RunEntry::Symlink("/nix/store/abc-system".into())),
            ("shm".to_string(), RunEntry::Symlink("/dev/shm".into())),
        ];
        let keep = vec![
            "/run/user/1000/mandu/s1/bin/mandu-landlock-apply".to_string(), // the staged applier
            "/run/user/1000/mandu/s1/ca.pem".to_string(),                   // an env-named file
            "/run/docker.sock".to_string(),                                  // a socket: never
            "/run/current-system/sw/bin".to_string(),                        // under a recreated link
            "/home/u/p".to_string(),                                         // not under /run
            "/run/gone".to_string(),                                         // missing
            "/run".to_string(),                                              // the dir itself: never
        ];
        let h = run_box_hide(RUN_DIR, &top, run_host, &keep, Some("/run/user/1000/"));
        assert_eq!(h.dirs, vec!["/run".to_string()]);
        assert_eq!(
            h.symlinks,
            vec![
                ("/nix/store/abc-system".to_string(), "/run/current-system".to_string()),
                ("/dev/shm".to_string(), "/run/shm".to_string()),
            ]
        );
        assert_eq!(
            h.rebinds,
            vec![
                "/run/user/1000/mandu/s1/bin/mandu-landlock-apply".to_string(),
                "/run/user/1000/mandu/s1/ca.pem".to_string(),
                "/run/utmp".to_string(),
                "/run/wrappers".to_string(),
            ]
        );
        assert!(h.mkdirs.is_empty(), "the runtime dir is created by the re-binds under it: {h:?}");
        assert!(h.files.is_empty());
        // No keep under the runtime dir: it is created empty.
        let h = run_box_hide(RUN_DIR, &[], run_host, &[], Some("/run/user/1000"));
        assert_eq!(h.mkdirs, vec!["/run/user/1000".to_string()]);
        // Outside /run, or no /run at all: no mkdir, no hiding.
        assert!(run_box_hide(RUN_DIR, &[], run_host, &[], Some("/srv/rt")).mkdirs.is_empty());
        assert_eq!(run_box_hide(RUN_DIR, &[], |_| RunEntry::Missing, &keep, None), HostHide::default());
        assert_eq!(run_box_hide("relative", &[], run_host, &[], None), HostHide::default());
    }

    #[test]
    fn an_ancestor_keep_covers_its_descendants() {
        let keep = vec!["/run/media/u/disk/proj".to_string(), "/run/media/u/disk/proj/src".to_string()];
        let kind = |p: &str| if p == "/run/media/u/disk/proj/src" { RunEntry::Dir } else { run_host(p) };
        let h = run_box_hide(RUN_DIR, &[], kind, &keep, None);
        assert!(h.rebinds.contains(&"/run/media/u/disk/proj".to_string()));
        assert!(!h.rebinds.contains(&"/run/media/u/disk/proj/src".to_string()));
    }

    #[test]
    fn the_run_allow_list_renders_in_order_and_masks_only_what_is_put_back() {
        let v = ViewConfig { agent_view_root: Some("/run/user/1000/mandu/s1/av".into()), workspace: Some("/home/u/p".into()), workspace_writable: false };
        let mut p = plan_sandbox(ExecShell::AgentShell, &v, Some("/home/u/p"));
        let mut h = run_box_hide(
            RUN_DIR,
            &[("current-system".to_string(), RunEntry::Symlink("/nix/store/abc".into()))],
            run_host,
            &["/run/user/1000/mandu/s1/ca.pem".to_string()],
            Some("/run/user/1000"),
        );
        h.files.push("/run/wrappers/odd.sock".into()); // inside a put-back dir: masked
        h.files.push("/run/docker.sock".into()); // inside hidden /run, not put back: already gone
        h.merge(socket_box_hide(&SocketScan { sockets: vec!["/var/lib/lxd/unix.socket".into()], ..Default::default() }));
        p.host_hide = h;
        let argv = bwrap_argv(&p, &["true".into()]).unwrap();
        let j = argv.join(" ");
        let at = |needle: &str| j.find(needle).unwrap_or_else(|| panic!("{needle} missing: {j}"));
        let proc_ = at("--proc /proc");
        let run = at("--tmpfs /run ");
        let link = at("--symlink /nix/store/abc /run/current-system");
        // Put back with `-try`: a kept path gone since the scan is skipped,
        // not a failed box.
        let ca = at("--ro-bind-try /run/user/1000/mandu/s1/ca.pem /run/user/1000/mandu/s1/ca.pem");
        let wrappers = at("--ro-bind-try /run/wrappers /run/wrappers");
        let odd = at("--ro-bind /dev/null /run/wrappers/odd.sock");
        let lxd = at("--ro-bind /dev/null /var/lib/lxd/unix.socket");
        let scratch = at("--tmpfs /tmp");
        let av = at("--bind /run/user/1000/mandu/s1/av /run/user/1000/mandu/s1/av");
        assert!(proc_ < run && run < link && link < ca && ca < wrappers && wrappers < odd && odd < lxd && lxd < scratch && scratch < av, "{j}");
        assert!(!j.contains("/run/docker.sock"), "a socket under hidden /run needs no mask: {j}");
        // The AgentView under /run is bound LATER (it wins over the tmpfs).
        assert!(argv.windows(2).any(|w| w[0] == "--dir" && w[1] == "/run/user/1000") || j.contains("/run/user/1000/mandu"));
    }

    #[test]
    fn mount_points_are_the_hidden_dirs_and_the_masks_only() {
        let h = HostHide {
            dirs: vec!["/run".into()],
            symlinks: vec![("/nix/store/abc".into(), "/run/current-system".into())],
            mkdirs: vec!["/run/user/1000".into()],
            rebinds: vec!["/run/utmp".into()],
            files: vec!["/home/u/.ssh/cm-host".into()],
        };
        let got: Vec<&String> = h.mount_points().collect();
        assert_eq!(got, vec!["/run", "/home/u/.ssh/cm-host"], "a re-bind is `-try`, a symlink or dir lands in the tmpfs");
    }

    #[test]
    fn the_ready_fd_goes_to_the_applier_and_only_with_one() {
        let v = ViewConfig { agent_view_root: Some("/av".into()), workspace: Some("/ws".into()), workspace_writable: false };
        let mut p = plan_sandbox(ExecShell::AgentShell, &v, Some("/ws"));
        p.ready_fd = Some(9);
        let bare = bwrap_argv(&p, &["true".into()]).unwrap();
        assert!(!bare.iter().any(|a| a == "--ready-fd"), "no applier, nothing to signal: {bare:?}");
        p.landlock_apply = Some("/opt/mandu/mandu-landlock-apply".into());
        let argv = bwrap_argv(&p, &["true".into()]).unwrap();
        let app = argv.iter().position(|a| a == "/opt/mandu/mandu-landlock-apply").unwrap();
        assert_eq!(&argv[app + 1..app + 3], &["--ready-fd".to_string(), "9".to_string()]);
        let sep = argv.iter().position(|a| a == "--").unwrap();
        assert!(sep < app, "the applier's flag, never bwrap's: {argv:?}");
        p.landlock_clean = true;
        let clean = bwrap_argv(&p, &["true".into()]).unwrap();
        let app = clean.iter().position(|a| a == "/opt/mandu/mandu-landlock-apply").unwrap();
        assert_eq!(&clean[app + 1..app + 3], &["--ready-fd".to_string(), "9".to_string()], "the clean posture signals too");
    }

    #[test]
    fn only_a_box_that_never_came_up_over_a_vanished_mount_point_is_rebuilt() {
        let h = HostHide { files: vec!["/home/u/.ssh/cm-host".into()], rebinds: vec!["/run/utmp".into()], ..Default::default() };
        let gone = |p: &str| p != "/home/u/.ssh/cm-host";
        assert!(box_setup_raced(false, true, &h, gone), "setup failed on the vanished socket");
        assert!(!box_setup_raced(true, true, &h, gone), "the box came up: the command ran and failed on its own");
        assert!(!box_setup_raced(false, false, &h, gone), "succeeded");
        assert!(!box_setup_raced(false, true, &h, |_| true), "every mount point still there: some other failure");
        let only_rebind = HostHide { rebinds: vec!["/run/utmp".into()], ..Default::default() };
        assert!(!box_setup_raced(false, true, &only_rebind, |_| false), "a missing re-bind is `-try`, not a race");
    }

    // ── which bubblewrap the box runs (rootless-confinement-ubuntu-2404.md §0.7) ──

    #[test]
    fn find_bwrap_skips_relative_empty_and_inside_the_workspace() {
        use std::path::{Path, PathBuf};
        let exists = ["/ws/bin/bwrap", "/ws/node_modules/.bin/bwrap", "/usr/bin/bwrap", "/opt/link/bwrap"];
        let is_exec = |p: &Path| exists.iter().any(|e| Path::new(e) == p);
        // `/opt/link/bwrap` is a symlink into the workspace.
        let canon = |p: &Path| -> Option<PathBuf> {
            Some(if p == Path::new("/opt/link/bwrap") { PathBuf::from("/ws/bin/bwrap") } else { p.to_path_buf() })
        };
        let ws = vec![PathBuf::from("/ws")];
        let find = |path: &str| find_bwrap_in(std::ffi::OsStr::new(path), &ws, canon, is_exec);
        assert_eq!(find("/ws/bin:/usr/bin"), Some(PathBuf::from("/usr/bin/bwrap")), "an entry inside the workspace is skipped");
        assert_eq!(find(".:bin:node_modules/.bin::/usr/bin"), Some(PathBuf::from("/usr/bin/bwrap")), "relative and empty entries name the cwd");
        assert_eq!(find("/ws/node_modules/.bin:/usr/bin"), Some(PathBuf::from("/usr/bin/bwrap")));
        assert_eq!(find("/opt/link:/usr/bin"), Some(PathBuf::from("/usr/bin/bwrap")), "a link into the workspace is skipped by its real path");
        assert_eq!(find("/ws/bin:.:/opt/link"), None, "none outside: none, never a PATH search");
        // A root of `/` excludes nothing (it would exclude every binary).
        let root = vec![PathBuf::from("/")];
        assert_eq!(
            find_bwrap_in(std::ffi::OsStr::new("/usr/bin"), &root, canon, is_exec),
            Some(PathBuf::from("/usr/bin/bwrap"))
        );
    }

    #[test]
    fn find_bwrap_on_the_real_filesystem_never_returns_a_planted_one() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("mandu-bwrap-path-{}", std::process::id()));
        let ws = base.join("ws");
        let sys = base.join("sys");
        std::fs::create_dir_all(ws.join("bin")).unwrap();
        std::fs::create_dir_all(&sys).unwrap();
        for p in [ws.join("bwrap"), ws.join("bin").join("bwrap"), sys.join("bwrap")] {
            std::fs::write(&p, "#!/bin/sh\nexit 0\n").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let is_exec = |p: &std::path::Path| {
            std::fs::metadata(p).map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
        };
        let path = std::env::join_paths([ws.clone(), ws.join("bin"), sys.clone()]).unwrap();
        let got = find_bwrap_in(&path, &[ws.clone()], |p| std::fs::canonicalize(p).ok(), is_exec);
        assert_eq!(got, Some(std::fs::canonicalize(sys.join("bwrap")).unwrap()));
        let only_planted = std::env::join_paths([ws.clone(), ws.join("bin")]).unwrap();
        assert_eq!(find_bwrap_in(&only_planted, &[ws.clone()], |p| std::fs::canonicalize(p).ok(), is_exec), None);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn the_kept_bwrap_answer_holds_only_for_the_very_bytes_the_launcher_probed() {
        let base = std::env::temp_dir().join(format!("mandu-bwrap-known-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let bwrap = base.join("bwrap");
        std::fs::write(&bwrap, b"bubblewrap 0.11 bytes").unwrap();
        let known = crate::clean::sha256_hex(b"bubblewrap 0.11 bytes");
        assert!(bwrap_known_disable_userns(Some(&known), &bwrap), "the probed bytes: kept");
        assert!(!bwrap_known_disable_userns(None, &bwrap), "nothing baked: probe");
        assert!(!bwrap_known_disable_userns(Some(&known.to_ascii_uppercase()), &bwrap), "only the canonical lowercase hex");
        assert!(!bwrap_known_disable_userns(Some(&known[..63]), &bwrap), "a short value");
        assert!(!bwrap_known_disable_userns(Some(&format!("{}g", &known[..63])), &bwrap), "not hex");
        assert!(!bwrap_known_disable_userns(Some(""), &bwrap));
        assert!(!bwrap_known_disable_userns(Some(&known), &base.join("absent")), "unreadable: probe");
        assert!(!bwrap_known_disable_userns(Some(&known), &base), "a directory: probe");
        // The binary replaced in place, same size, same path: a changed
        // bubblewrap is probed afresh, whatever its path or stat says.
        std::fs::write(&bwrap, b"bubblewrap 0.06 bytes").unwrap();
        assert!(!bwrap_known_disable_userns(Some(&known), &bwrap), "different bytes: probe");
        // A link to the probed bytes is the same program.
        std::fs::write(base.join("real"), b"bubblewrap 0.11 bytes").unwrap();
        let link = base.join("link");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(base.join("real"), &link).unwrap();
        assert!(bwrap_known_disable_userns(Some(&known), &link));
        let _ = std::fs::remove_dir_all(&base);
    }
}
