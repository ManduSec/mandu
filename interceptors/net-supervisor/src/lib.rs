//! net-supervisor — Mandu M3: ingress symbolization + egress desymbolization for the
//! agent's NON-MODEL network traffic.
//!
//! PURE (default build, no privileges):
//!   - `transform` — `ingress_transform` (classify + symbolize a response body
//!                   before the agent sees it), `egress_transform` (desymbolize
//!                   an outbound body gated per-symbol by the data-usage policy,
//!                   withholding fail-closed), and `is_model_host` (model-API
//!                   exclusion).
//!   - `events`    — the `net_action` event builders.
//!   - `xattr_change` — the extended-attribute family the guard performs:
//!                   decode, the kernel's own checks, the rule, the no-op test,
//!                   the ACL id translation (write-protection.md §2).
//!   - `stat_twin` — the stat family the guard answers with a twin's metadata
//!                   where it serves the twins alone (confidentiality.md §7.2a).
//!   - `send_guard` — judging a SEND like a connect: the destination the
//!                   kernel would use, the message layouts, the ancillary data
//!                   passed on or refused, the session-proxy exception, the
//!                   egress gate and the taint-time sweep's verdict
//!                   (exec-routing.md §7.5, 2026-10-01).
//!   - `lineage`   — keeping a holder's descendants holders after it is
//!                   gone: the fork, exit and subreaper traps' decisions,
//!                   the orphan window (exec-routing.md §7.5, 2026-10-02).
//!   - `death_watch` — a holder's death stamped when it happens (a pidfd
//!                   per holder), so the orphan window ends at the death
//!                   and never before it (2026-10-09).
//!   - `wait_flow` — a holder's exit status followed to whoever learns it:
//!                   its parent and tracer at the taint, a reaper at its
//!                   wait (plan 13 §4.9, 2026-10-03).
//!   - `accept_guard` — judging a holder's ACCEPT: whose connection a
//!                   process holding a secret may take (exec-routing.md
//!                   §7.5, 2026-10-02).
//!   - `reader_identity` — who a secret's opener really is: the inode it
//!                   runs and its hash, whether the agent could have written
//!                   it, and the loader / interpreter variables it runs with
//!                   (Plan 13 D8).
//!   - `git_lock`  — the backstop for locked objects in repositories the
//!                   launch did not prepare: the prefilter, the pack-index
//!                   lookup, the verdict cache (plan 14 §11.1 R4).
//!   - `local_exits` — the exits a holder's write reaches as a path: a
//!                   network or FUSE mount, another local user (the mode a
//!                   labelled file gets), a device node (plan 13 §9 R4 (b)).
//!   - `visible_mounts` — the mounts that would see a holder's lookups,
//!                   per mount namespace: a raw open is withheld while an
//!                   unbound, untrusted one is visible (plan 13 §4.6).
//!   - `launch_wrap` — which Landlock layer is the launch's net-only wrap,
//!                   which governs no file access, so an open under it alone
//!                   needs no mirror thread (plan 10 §4.1a).
//!   - `own_server` — the agent's private server (OpenCode 2 `--standalone`):
//!                   the one ephemeral loopback bind and the one client
//!                   connect the guard admits for it (supported-agents.md
//!                   §2.3.1).
//!   - `child_status` — the exit code the guard reports for its child: the
//!                   child's code, or 128 + the signal that killed it.
//!   - `held_ask`  — a HIGH session's held command refused at an unbound
//!                   address asks the human; the answer that admits one
//!                   connect, and the sockets so connected
//!                   (confidentiality.md §4, 2026-10-12).
//!   - `guard_trace` — the guard's diagnostic trace file
//!                   (`MANDU_NET_GUARD_TRACE`, off by default): the agent
//!                   pick, each new holder, each taint-leg refusal.
//!   - `diag`      — where the guard's own non-fatal messages go: the
//!                   launch's log under its default display, never over the
//!                   agent's terminal (packaging.md §5).
//!
//! KERNEL-GATED (`--features kernel`, needs root + `nft`):
//!   - `kernel`    — the nftables TPROXY redirection of the cgroup's non-model
//!                   traffic + the accept loop that runs the pure transforms.
//!
//! SECURITY INVARIANT: ingress NEVER lets un-symbolized untrusted bytes reach the
//! agent (a arbiter miss serves an opaque marker, not raw bytes). Egress is
//! fail-closed: a symbol is desymbolized ONLY on a positive gate decision;
//! otherwise it stays symbolic on the wire (withheld, needs approval).

pub mod conn_attr;
pub mod events;
pub mod guard;
pub mod transform;
pub mod secret_open;
pub mod reader_identity;
pub mod args_code;
pub mod script_identity;
pub mod derived_index;
pub mod label_index;
pub mod stat_twin;
pub mod git_lock;
pub mod inode_pins;
pub mod xattr_change;
pub mod owner_time;
pub mod guard_signals;
pub mod guard_filter;
pub mod send_guard;
pub mod lineage;
pub mod death_watch;
pub mod wait_flow;
pub mod pipe_flow;
pub mod object_flow;
pub mod accept_guard;
pub mod clean_host;
pub mod report_channel;
pub mod unix_owner;
pub mod local_exits;
pub mod visible_mounts;
pub mod launch_wrap;
pub mod mirror_records;
pub mod own_server;
pub mod child_status;
pub mod held_ask;
pub mod guard_trace;
pub mod safe_write;
pub mod diag;

#[cfg(feature = "kernel")]
pub mod kernel;

/// The connect-guard's kernel enactment (seccomp-unotify connect(2) trap +
/// supervisor-side connect). Feature- AND Linux-gated; the PURE decision core
/// (`guard`) is always compiled and unit-tested.
#[cfg(all(feature = "kernel", target_os = "linux"))]
pub mod guard_kernel;
/// The send trap's kernel half and the taint-time sweep (exec-routing.md
/// §7.5, 2026-10-01); the pure half is `send_guard`.
#[cfg(all(feature = "kernel", target_os = "linux"))]
pub mod guard_send;
/// The accept trap's kernel half (exec-routing.md §7.5, 2026-10-02); the
/// pure half is `accept_guard`.
#[cfg(all(feature = "kernel", target_os = "linux"))]
pub mod guard_accept;
/// A descriptor passed over `SCM_RIGHTS` to a process holding a secret,
/// judged at its sender; what a Unix socket has queued (exec-routing.md
/// §7.5, 2026-10-02).
#[cfg(all(feature = "kernel", target_os = "linux"))]
pub mod guard_rights;
#[cfg(all(feature = "kernel", target_os = "linux"))]
pub mod guard_flow;
/// A holder's exit status followed to its reaper: the wait trap and the
/// taint-time receivers (plan 13 §4.9, 2026-10-03); the pure half is
/// `wait_flow`.
#[cfg(all(feature = "kernel", target_os = "linux"))]
pub mod guard_wait;
#[cfg(all(feature = "kernel", target_os = "linux"))]
pub mod landlock_mirror;
#[cfg(all(feature = "kernel", target_os = "linux"))]
pub mod context_helper;
#[cfg(all(feature = "kernel", target_os = "linux"))]
pub mod clean_host_kernel;

pub use guard::{
    decode_sockaddr, parse_rule, parse_rules, AllowRule, ConnTarget, Decision, Endpoint,
    GuardPolicy, HostMatch, HostResolver, NoResolver, Proto,
};
pub use transform::{
    egress_transform, ingress_transform, is_model_host, EgressResult, EgressSymbol, IngressResult,
};
