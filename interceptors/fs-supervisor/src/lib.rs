//! fs-supervisor — Mandu Track B: openat() redirection of tracked workspace
//! paths to the AgentView worktree.
//!
//! PURE (default build, no privileges):
//!   - `layout`   — view path math + `rewrite_to_worktree` (mirrors fs-sync).
//!   - `decision` — tracked-root matching, open-flag access intent, the openat
//!                  routing decision, and the arbiter first-touch
//!                  classify/symbolize orchestration (fail-closed).
//!   - `events`   — the `fs_action` event builder.
//!   - `landlock` — the PURE Landlock (Linux LSM) ruleset PLAN: the asymmetric
//!                  overlay (whole real FS READ-ONLY; AgentView worktree + scratch
//!                  READ-WRITE) plus the net-off posture (all TCP bind/connect
//!                  DENIED, ABI v4; optional per-port allow rules) modelled as a
//!                  `LandlockPlan`, with FS and net rights each masked to a target
//!                  ABI. The plan carries no libc; it is unit-tested here.
//!
//! KERNEL-GATED (`--features kernel`):
//!   - `kernel`   — the seccomp-unotify supervisor loop (needs root/CAP_SYS_ADMIN +
//!                  SECCOMP_USER_NOTIF). It reads openat() args out of the
//!                  notification and enacts the PURE decision via ADDFD (redirect) /
//!                  CONTINUE (passthrough). All policy lives in `decision`/`layout`;
//!                  this module is syscall plumbing only.
//!   - `landlock` (gated section) — Landlock ENACTMENT: an UNPRIVILEGED
//!                  defense-in-depth backend for the FS chokepoint. Needs NO root
//!                  (only `no_new_privs`) but kernel ≥ 5.13; probe-gated so it is ON
//!                  BY DEFAULT wherever supported. `restrict_self_to_plan` applies a
//!                  `LandlockPlan` to the calling thread (meant to run in a forked
//!                  child pre-execve), complementing the bubblewrap overlay with an
//!                  LSM-enforced check.
//!
//! SECURITY INVARIANT: a tracked read is ALWAYS redirected to the AgentView
//! worktree (symbolized content), even if the arbiter first-touch fails — we never
//! fall through to raw HumanView bytes. See `decision::first_touch_classify`.

pub mod decision;
pub mod events;
pub mod landlock;
pub mod layout;
pub mod box_sockets;
pub mod tracee;

#[cfg(feature = "kernel")]
pub mod kernel;

pub use decision::{decide_open, Access, OpenDecision, TrackedRoots};
pub use landlock::{
    plan_agent_view_sandbox, plan_landlock, plan_landlock_deny_tcp, plan_net_confine, LandlockPlan,
    NetPortRule, PathRule,
};
pub use layout::{rewrite_to_worktree, ViewLayout};
