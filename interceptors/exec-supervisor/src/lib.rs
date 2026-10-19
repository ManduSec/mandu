//! exec-supervisor — Mandu M3: on execve, select AgentShell vs HumanShell and
//! resolve argv only after the gated data-usage check.
//!
//! PURE (default build, no privileges):
//!   - `orchestrate` — `plan_exec`: call classifyExec to pick the shell, then
//!                     (HumanShell only) resolveExecArgv to desymbolize argv AFTER
//!                     the data-usage check. Fail-closed: a classify miss defaults
//!                     to AgentShell; a resolve miss withholds all symbols.
//!   - `sandbox`     — the AgentShell WORLD (exec-routing.md §4 Phase 1): the
//!                     asymmetric overlay plan (RW=AgentView / RO=rest / net=off /
//!                     fresh dev+proc+tmpfs + hardened namespaces + dropped caps) +
//!                     its bubblewrap realization. Pure, unit-tested; the kernel
//!                     feature only ENACTS the plan.
//!   - `seccomp_filter` — the AgentShell seccomp DENY-filter (a default-allow BPF
//!                     deny-list of dangerous syscalls) as raw bytes for
//!                     `bwrap --seccomp`. Pure (no libc), unit-tested.
//!   - `host_sockets` — find the host's Unix sockets the box masks (std-only
//!                     filesystem scan, unit-tested on temp dirs).
//!   - `events`      — the `exec_action` event builder.
//!   - `refusal`     — the plain-words line `mandu-exec-box` prints when it
//!                     refuses an exec pending approval (per withheld kind).
//!
//! KERNEL-GATED (`--features kernel`, needs root):
//!   - `kernel`      — the seccomp/ptrace execve trap + per-shell namespace/cgroup
//!                     setup (AgentShell: net off + AgentView FS; HumanShell: net
//!                     on + HumanView FS) + blocking on approvals.
//!   - `deadline`    — the supervisor's bounded waits (a caller's deadline on
//!                     the exec; its own limits on hand-overs and drains).
//!
//! SECURITY INVARIANT: exec DEFAULTS to AgentShell (symbolic, safe). It only
//! desymbolizes argv through the gated `resolveExecArgv`, and a symbol in
//! command/code position is NEVER resolved without human approval.

pub mod clean;
pub mod events;
pub mod host_sockets;
pub mod orchestrate;
pub mod refusal;
pub mod sandbox;
pub mod seccomp_filter;
pub mod twins;

#[cfg(feature = "kernel")]
pub mod deadline;
#[cfg(feature = "kernel")]
pub mod kernel;
#[cfg(feature = "kernel")]
pub mod socket_supervision;

pub use orchestrate::{plan_exec, EscalationMode, ExecPlan, ExecRequest};
pub use sandbox::{bwrap_argv, plan_sandbox, seatbelt_profile, BindMount, SandboxPlan, ViewConfig};
