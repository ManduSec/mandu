//! orchestrate — the PURE exec view-selection + argv-resolution orchestration.
//!
//! PURE / unit-tested by default. The kernel feature's seccomp/ptrace execve
//! interception reads the argv/cwd off the trapped syscall and calls
//! `plan_exec`; the loop then sets up the chosen shell's namespaces (net off +
//! AgentView FS for AgentShell; net on + HumanView FS for HumanShell) and execs
//! the RESOLVED argv. All the policy orchestration lives here.
//!
//! Contract (mandu.md §4, design plan §6):
//!   1. classifyExec(argv, cwd, needs*) → AgentShell (DEFAULT: net off,
//!      FS=AgentView, output already symbolic) vs HumanShell (net on,
//!      FS=HumanView).
//!   2. ONLY for HumanShell: resolveExecArgv(argv, shell) desymbolizes argv —
//!      AFTER the data-usage check + command rewriting. Symbols in command/code
//!      position are LEFT SYMBOLIC and surfaced for approval (fail-closed).
//!   3. AgentShell never desymbolizes — symbols stay symbolic (the AgentView is
//!      symbolic by design).
//!
//! FAIL-CLOSED: if the arbiter is unreachable for classifyExec, default to
//! AgentShell (the safe view). If it is unreachable for resolveExecArgv on a
//! HumanShell, WITHHOLD all symbols (run argv unchanged / require approval) — we
//! never desymbolize an argv without a positive gate decision.

use mandu_arbiter::protocol::{
    ClassifyExecArgs, EscalateExecArgs, ExecApprovalItem, ExecDecisionForArgs, ExecShell,
    ProcessLineageArgs, ResolveExecArgvArgs, ResolveExecArgvResult, TaintProcessArgs,
};
use mandu_arbiter::symbols::has_symbols;
use mandu_arbiter::{ArbiterClient, ArbiterError};

/// How a command's need for a restricted resource (real network / HumanView FS)
/// is handled when it would otherwise stay AgentShell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EscalationMode {
    /// Legacy: a `needs_*` hint routes straight to HumanShell (classifyExec).
    #[default]
    Auto,
    /// exec-routing.md §5: a `needs_*` hint escalates to HumanShell ONLY behind a
    /// human approval (`escalateExec`); absent approval the command stays
    /// AgentShell and a pending approval is queued (fail-safe).
    Gated,
}

/// Inputs the supervisor observed at execve.
#[derive(Debug, Clone, Default)]
pub struct ExecRequest {
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    /// Runtime resource hints the supervisor inferred (e.g. the command tried to
    /// open a socket / the original FS). Either true → HumanShell (subject to the
    /// escalation mode).
    pub needs_network: bool,
    pub needs_original_fs: bool,
    /// Exec params, e.g. `{ "env": { "RESTRICTED": "1" } }` pins AgentShell.
    pub params: Option<serde_json::Value>,
    /// How a `needs_*` escalation to HumanShell is gated (default `Auto`).
    pub escalation: EscalationMode,
}

/// Programs whose top-level invocation ordinarily needs REAL network — so a
/// generic "box this command" front-end (`mandu-exec-box`) that would otherwise
/// default it to the net-off AgentShell must hint `needs_network` and let it route
/// to HumanShell instead. This is a UTILITY safety net, not a security boundary:
/// the security default is still AgentShell (net-off); this list only keeps a
/// live `git push` / `npm install` from silently running with the network dead.
///
/// It errs toward INCLUSION (route to HumanShell) for ambiguous multi-purpose
/// tools — a false "needs network" only costs a command its box (it runs in the
/// less-isolated but still gated HumanShell), whereas a false "no network" BREAKS
/// the command. Deliberately NOT listed: interpreters/build drivers
/// (python/node/make/…) — boxing THOSE net-off is the whole point (process
/// untrusted data safely); a genuine net need there is an escalation, not a
/// silent pass-through. `git` is listed wholesale (push/fetch need net; boxing
/// `git status` net-off is harmless, so the safe call is to pass all of git).
const NETWORK_PROGRAMS: &[&str] = &[
    // fetch / transfer / remote shell
    "curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp",
    "rsync", "ftp", "tftp", "telnet",
    // version control (remote ops)
    "git", "hg", "svn",
    // language package managers / toolchains that fetch
    "npm", "npx", "pnpm", "yarn", "bun", "deno",
    "pip", "pip3", "pipx", "poetry", "uv", "conda",
    "cargo", "go", "rustup", "gem", "bundle", "mvn", "gradle", "sbt",
    // OS / container / cloud package + control planes
    "apt", "apt-get", "aptitude", "yum", "dnf", "zypper", "brew", "snap",
    "pacman", "apk", "docker", "podman", "kubectl", "helm",
    "aws", "gcloud", "az", "gh", "glab", "terraform", "ansible",
    // network diagnostics
    "ping", "ping6", "dig", "host", "nslookup", "traceroute", "mtr", "whois",
];

/// Remove every occurrence of `dir` from a colon-separated `PATH` value,
/// returning the rebuilt PATH. Used by `mandu-exec-box` to strip the launcher's
/// SHIM DIR from the environment before it runs a boxed command: the shim shadows
/// commands by name on the agent's PATH, so without this a boxed `cat` would
/// re-resolve to the shim (infinite recursion) instead of the real `/usr/bin/cat`.
/// Empty `dir` → PATH unchanged. Preserves order and any remaining duplicates.
pub fn path_without(path: &str, dir: &str) -> String {
    if dir.is_empty() {
        return path.to_string();
    }
    path.split(':')
        .filter(|entry| *entry != dir)
        .collect::<Vec<_>>()
        .join(":")
}

/// Does this command's PROGRAM (argv[0] basename) ordinarily need real network?
/// Pure heuristic used by the `mandu-exec-box` front-end to set
/// `ExecRequest::needs_network` so a net-needing command routes to HumanShell
/// rather than the net-off AgentShell. See `NETWORK_PROGRAMS` for the posture
/// (utility net, err toward inclusion). Empty argv → false (nothing to run).
pub fn argv_needs_network(argv: &[String]) -> bool {
    let Some(arg0) = argv.first() else {
        return false;
    };
    // Basename, and drop a leading path so `/usr/bin/curl` still matches.
    let base = arg0.rsplit('/').next().unwrap_or(arg0);
    NETWORK_PROGRAMS.contains(&base)
}

/// The full plan the kernel loop enacts for one execve.
#[derive(Debug, Clone)]
pub struct ExecPlan {
    pub shell: ExecShell,
    /// The command's canonical identity (basename), if known.
    pub identifier: Option<String>,
    /// The argv to actually exec. For AgentShell this is the symbolic argv
    /// unchanged; for HumanShell it is the resolved argv (with code-position
    /// symbols left symbolic — see `approvals`).
    pub argv: Vec<String>,
    /// Items requiring human approval before the run may proceed. Non-empty means
    /// the supervisor must BLOCK until approved (fail-closed).
    pub approvals: Vec<ExecApprovalItem>,
    /// True iff this plan came from a arbiter miss → fail-closed default.
    pub arbiter_miss: bool,
    /// True iff a `needs_*` escalation to HumanShell is PENDING a human approval
    /// (exec-routing.md §5): the command stays AgentShell (without the resource)
    /// until a human approves. Observability — the run still proceeds (in the safe
    /// view); the human sees the queued approval in the dashboard.
    pub escalation_pending: bool,
    /// Audit reason.
    pub reason: String,
    /// The `tool_use` id the proxy's recorded exec decision for this argv
    /// correlated to (`execDecisionFor`), when the correlation lookup ran and
    /// hit. UTILITY-ONLY: it rides onto the `exec_action` event so the
    /// dashboard can join a boxed exec to its tool call; a miss is `None` and
    /// never changes the plan (found 2026-09-18: the event always carried
    /// `null` even when the box had resolved the id).
    pub call_id: Option<String>,
}

impl ExecPlan {
    pub fn needs_approval(&self) -> bool {
        !self.approvals.is_empty()
    }
    pub fn is_human_shell(&self) -> bool {
        self.shell == ExecShell::HumanShell
    }
}

/// The shell selection + why, plus whether an escalation is pending approval.
struct ShellChoice {
    shell: ExecShell,
    identifier: Option<String>,
    reason: String,
    arbiter_miss: bool,
    escalation_pending: bool,
}

/// Plan an execve: select the shell (with escalation gating + proxy correlation),
/// then (HumanShell only) resolve the argv via the gated data-usage check. This
/// is the single pure entry point the kernel loop calls.
pub fn plan_exec(client: &mut ArbiterClient, req: &ExecRequest) -> ExecPlan {
    // 1) Select the shell view (escalation-mode aware).
    let choice = match select_shell(client, req) {
        Ok(c) => c,
        Err(e) => {
            // FAIL-CLOSED: default to AgentShell (safe: net off, AgentView FS,
            // symbols stay symbolic — nothing desymbolized).
            return ExecPlan {
                shell: ExecShell::AgentShell,
                identifier: None,
                argv: req.argv.clone(),
                approvals: vec![],
                arbiter_miss: true,
                escalation_pending: false,
                reason: format!(
                    "classifyExec unreachable ({e}) → fail-closed AgentShell (symbolic, safe)"
                ),
                call_id: None,
            };
        }
    };

    // 2) Correlation (exec-routing.md §4 step 1): consult the proxy's recorded
    //    decision and take the MORE RESTRICTIVE of it and our own classification.
    //    This can only TIGHTEN (HumanShell → AgentShell), never loosen — a miss /
    //    arbiter error is a no-op, so it is pure defense-in-depth.
    let (shell, corr_note, call_id) = apply_correlation(client, &req.argv, choice.shell);
    let identifier = choice.identifier;
    let classify_reason = format!("{}{corr_note}", choice.reason);

    // 3) AgentShell never desymbolizes — argv stays symbolic.
    if shell == ExecShell::AgentShell {
        return ExecPlan {
            shell,
            identifier,
            argv: req.argv.clone(),
            approvals: vec![],
            arbiter_miss: choice.arbiter_miss,
            escalation_pending: choice.escalation_pending,
            reason: format!("{classify_reason}; AgentShell: argv left symbolic (no desymbolization)"),
            call_id,
        };
    }

    // 4) HumanShell: resolve the argv AFTER the data-usage check. If the argv
    //    carries no symbols there is nothing to gate.
    if !req.argv.iter().any(|a| has_symbols(a)) {
        return ExecPlan {
            shell,
            identifier,
            argv: req.argv.clone(),
            approvals: vec![],
            arbiter_miss: choice.arbiter_miss,
            escalation_pending: false,
            reason: format!("{classify_reason}; HumanShell: no symbols in argv → run as-is"),
            call_id,
        };
    }

    let resolved = client.resolve_exec_argv(&ResolveExecArgvArgs {
        argv: req.argv.clone(),
        shell: Some(ExecShell::HumanShell),
        params: req.params.clone(),
    });

    let mut plan = match resolved {
        Ok(r) => human_plan_from_resolution(shell, identifier, &classify_reason, req, r),
        Err(e) => fail_closed_human_resolution(shell, identifier, &classify_reason, req, &e),
    };
    plan.call_id = call_id;
    plan
}

/// Select the shell view for `req`, honoring the escalation mode.
///
/// `Auto` (default): the `needs_*` hints go straight to classifyExec, which
/// routes to HumanShell — the legacy behavior.
///
/// `Gated` (exec-routing.md §5): classify WITHOUT the resource hints (so the base
/// view is AgentShell unless `RESTRICTED` pins it), and if the command needs a
/// restricted resource, ask `escalateExec` — HumanShell only if a human approved,
/// else stay AgentShell with `escalation_pending` set (a pending approval is
/// queued arbiter-side). An `Err` here is a classifyExec transport error the
/// caller turns into the fail-closed AgentShell default.
fn select_shell(client: &mut ArbiterClient, req: &ExecRequest) -> Result<ShellChoice, ArbiterError> {
    let needs_resource = if req.needs_network {
        Some("network")
    } else if req.needs_original_fs {
        Some("original-fs")
    } else {
        None
    };

    if req.escalation == EscalationMode::Gated {
        if let Some(resource) = needs_resource {
            // Base classification WITHOUT the resource hint → AgentShell (or a
            // RESTRICTED pin). Only escalate an otherwise-AgentShell command.
            let base = client.classify_exec(&ClassifyExecArgs {
                argv: req.argv.clone(),
                cwd: req.cwd.clone(),
                needs_network: Some(false),
                needs_original_fs: Some(false),
                params: req.params.clone(),
            })?;
            if base.shell != ExecShell::AgentShell {
                return Ok(ShellChoice {
                    shell: base.shell,
                    identifier: base.identifier,
                    reason: base.reason,
                    arbiter_miss: false,
                    escalation_pending: false,
                });
            }
            // Ask the escalation gate. A transport error here is NOT fatal — fail
            // safe by staying AgentShell (the command still runs, sandboxed).
            match client.escalate_exec(&EscalateExecArgs {
                argv: req.argv.clone(),
                cwd: req.cwd.clone(),
                resource: resource.to_string(),
                session_key: None,
            }) {
                Ok(esc) => {
                    return Ok(ShellChoice {
                        shell: esc.shell,
                        identifier: base.identifier,
                        reason: format!("escalation ({resource}): {}", esc.reason),
                        arbiter_miss: false,
                        escalation_pending: esc.requires_approval,
                    });
                }
                Err(e) => {
                    return Ok(ShellChoice {
                        shell: ExecShell::AgentShell,
                        identifier: base.identifier,
                        reason: format!(
                            "escalateExec unreachable ({e}) → stay AgentShell (fail-safe)"
                        ),
                        arbiter_miss: false,
                        escalation_pending: true,
                    });
                }
            }
        }
    }

    // Auto mode (or Gated with no resource need): classify with the hints as-is.
    let d = client.classify_exec(&ClassifyExecArgs {
        argv: req.argv.clone(),
        cwd: req.cwd.clone(),
        needs_network: Some(req.needs_network),
        needs_original_fs: Some(req.needs_original_fs),
        params: req.params.clone(),
    })?;
    Ok(ShellChoice {
        shell: d.shell,
        identifier: d.identifier,
        reason: d.reason,
        arbiter_miss: false,
        escalation_pending: false,
    })
}

/// Take the MORE RESTRICTIVE of our classification and the proxy's recorded
/// decision for this command (exec-routing.md §4 step 1). Returns the (possibly
/// tightened) shell + an audit note + the decision's `tool_use` callId when the
/// lookup hit (observability only — `ExecPlan.call_id`). BEST-EFFORT: a miss or
/// arbiter error leaves the shell unchanged (the supervisor's own decision
/// already fail-closed). It only ever tightens HumanShell → AgentShell — never
/// the reverse. An AgentShell plan skips the lookup (no roundtrip on the common
/// path; the clean box resolves its own callId when it reports a verdict).
fn apply_correlation(
    client: &mut ArbiterClient,
    argv: &[String],
    shell: ExecShell,
) -> (ExecShell, String, Option<String>) {
    if shell == ExecShell::AgentShell {
        return (shell, String::new(), None); // already the most restrictive view
    }
    match client.exec_decision_for(&ExecDecisionForArgs {
        command: None,
        argv: Some(argv.to_vec()),
    }) {
        Ok(r) => match r.decision {
            Some(d) if d.block || d.shell == ExecShell::AgentShell || !d.evasion.is_empty() => {
                let why = if d.block {
                    "proxy blocked"
                } else if d.shell == ExecShell::AgentShell {
                    "proxy said AgentShell"
                } else {
                    "proxy saw evasion"
                };
                (
                    ExecShell::AgentShell,
                    format!("; correlation → AgentShell (more restrictive: {why})"),
                    d.call_id,
                )
            }
            Some(d) => (shell, String::new(), d.call_id),
            None => (shell, String::new(), None),
        },
        Err(_) => (shell, String::new(), None), // best-effort: no override on a miss/error
    }
}

fn human_plan_from_resolution(
    shell: ExecShell,
    identifier: Option<String>,
    classify_reason: &str,
    _req: &ExecRequest,
    r: ResolveExecArgvResult,
) -> ExecPlan {
    ExecPlan {
        shell,
        identifier,
        argv: r.argv,
        approvals: r.approvals,
        arbiter_miss: false,
        escalation_pending: false,
        reason: format!("{classify_reason}; {}", r.reason),
        call_id: None,
    }
}

fn fail_closed_human_resolution(
    shell: ExecShell,
    identifier: Option<String>,
    classify_reason: &str,
    req: &ExecRequest,
    e: &ArbiterError,
) -> ExecPlan {
    // The gate is unreachable: WITHHOLD every symbol (do not resolve), keep the
    // symbolic argv, and require approval. Never desymbolize without the gate.
    let symbols: Vec<String> = req
        .argv
        .iter()
        .flat_map(|a| mandu_arbiter::symbols::extract_symbols(a))
        .collect();
    ExecPlan {
        shell,
        identifier,
        argv: req.argv.clone(),
        approvals: vec![ExecApprovalItem {
            kind: "symbol_as_command".into(),
            symbols,
            reason: format!("resolveExecArgv unreachable ({e}) → withhold all desymbolization (fail-closed)"),
        }],
        arbiter_miss: true,
        escalation_pending: false,
        reason: format!("{classify_reason}; HumanShell gate unreachable → withhold (fail-closed)"),
        call_id: None,
    }
}

/// Record a parent→child spawn lineage edge (design §3.2): a child of a tainted
/// process is tainted, so the arbiter's transitive-ancestor walk needs to know the
/// edge at spawn time. SEPARATE from `plan_exec` — lineage is a spawn-time event,
/// not part of the argv→shell decision.
///
/// BEST-EFFORT / OFF THE SECURITY PATH: returns `true` iff the arbiter ack'd the
/// `processLineage` op; a arbiter error returns `false`. It NEVER panics and NEVER
/// blocks the spawn — emission failing must not stop a real exec (the chain's
/// safety rests on the fail-closed gate + the model-proxy backstop, not on this
/// edge being recorded). `child_key`/`parent_key` are opaque proc keys; their
/// cross-layer FORMAT is a deferred co-design (see the module/plan notes).
pub fn record_spawn_lineage(
    client: &mut ArbiterClient,
    child_key: &str,
    parent_key: &str,
) -> bool {
    client
        .process_lineage(&ProcessLineageArgs {
            child_key: child_key.to_string(),
            parent_key: parent_key.to_string(),
            session: None,
        })
        .is_ok()
}

/// Taint the ROOT of an invocation subtree (design §3.1/§3.2): the "taint at the
/// invocation root" primitive a future net→exec bridge calls so that, once the
/// parent→child lineage edges are recorded, the arbiter's transitive walk marks the
/// WHOLE invocation subtree tainted. (If any process in an invocation touches an
/// untrusted host, the whole invocation is tainted — coarse-but-safe, §3.2.)
///
/// BEST-EFFORT / OFF THE SECURITY PATH: returns `true` iff the arbiter ack'd the
/// `taintProcess` op; a arbiter error returns `false`. NEVER panics, NEVER blocks.
pub fn taint_invocation(
    client: &mut ArbiterClient,
    root_proc_key: &str,
    origin_host: &str,
) -> bool {
    client
        .taint_process(&TaintProcessArgs {
            proc_key: root_proc_key.to_string(),
            origin_host: origin_host.to_string(),
            session: None,
        })
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mandu_arbiter::mock::{op_handler, MockArbiter};

    #[test]
    fn argv_needs_network_routes_net_tools_but_not_interpreters() {
        // Net tools / VCS / package managers → HumanShell (won't run net-off).
        for c in ["curl", "wget", "git", "npm", "pip3", "ssh", "cargo", "apt-get", "gh"] {
            assert!(argv_needs_network(&[c.into()]), "{c} should be net-needing");
        }
        // A leading path still resolves to the basename.
        assert!(argv_needs_network(&["/usr/bin/curl".into(), "https://x".into()]));
        // Interpreters / build drivers / read tools are BOXED (net-off) by design —
        // a genuine net need there is an escalation, not a silent pass-through.
        for c in ["python", "python3", "node", "make", "cat", "grep", "sed", "bash", "./build.sh"] {
            assert!(!argv_needs_network(&[c.into()]), "{c} must NOT auto-route to HumanShell");
        }
        // Empty argv → nothing to run.
        assert!(!argv_needs_network(&[]));
    }

    #[test]
    fn path_without_strips_the_shim_dir_only() {
        let shim = "/run/mandu/exec-shims";
        assert_eq!(
            path_without(&format!("{shim}:/usr/bin:/bin"), shim),
            "/usr/bin:/bin",
            "the shim dir (prepended) must be removed so a boxed cmd finds the real binary"
        );
        // Removes every occurrence, keeps the rest in order.
        assert_eq!(
            path_without(&format!("{shim}:/usr/bin:{shim}:/bin"), shim),
            "/usr/bin:/bin"
        );
        // A PATH without the shim dir is untouched; an empty dir is a no-op.
        assert_eq!(path_without("/usr/bin:/bin", shim), "/usr/bin:/bin");
        assert_eq!(path_without("/usr/bin:/bin", ""), "/usr/bin:/bin");
    }

    fn agentshell_arbiter() -> MockArbiter {
        MockArbiter::start(op_handler(|op, _r| match op {
            "classifyExec" => Ok(serde_json::json!({
                "shell":"AgentShell","identifier":"python","reason":"default AgentShell"
            })),
            _ => Err("should not be called for AgentShell".into()),
        }))
    }

    #[test]
    fn agentshell_default_keeps_argv_symbolic() {
        let arbiter = agentshell_arbiter();
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let plan = plan_exec(
            &mut c,
            &ExecRequest {
                argv: vec!["python".into(), "$MDU:Read[ab12].body".into()],
                ..Default::default()
            },
        );
        assert_eq!(plan.shell, ExecShell::AgentShell);
        // No resolveExecArgv call; argv unchanged (symbolic).
        assert_eq!(plan.argv[1], "$MDU:Read[ab12].body");
        assert!(!plan.needs_approval());
    }

    #[test]
    fn humanshell_data_position_resolves() {
        let arbiter = MockArbiter::start(op_handler(|op, _r| match op {
            "classifyExec" => Ok(serde_json::json!({
                "shell":"HumanShell","identifier":"cat","reason":"needs original FS"
            })),
            "resolveExecArgv" => Ok(serde_json::json!({
                "argv":["cat","/real/path.txt"],"approvals":[],"reason":"data-position resolved"
            })),
            _ => Err("nope".into()),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let plan = plan_exec(
            &mut c,
            &ExecRequest {
                argv: vec!["cat".into(), "$MDU:Read[ab12].path".into()],
                needs_original_fs: true,
                ..Default::default()
            },
        );
        assert_eq!(plan.shell, ExecShell::HumanShell);
        assert_eq!(plan.argv, vec!["cat".to_string(), "/real/path.txt".to_string()]);
        assert!(!plan.needs_approval());
    }

    #[test]
    fn humanshell_symbol_as_command_withheld() {
        let arbiter = MockArbiter::start(op_handler(|op, _r| match op {
            "classifyExec" => Ok(serde_json::json!({
                "shell":"HumanShell","identifier":"sh","reason":"needs network"
            })),
            "resolveExecArgv" => Ok(serde_json::json!({
                "argv":["sh","-c","$MDU:Read[ab12].body"],
                "approvals":[{"kind":"symbol_as_command","symbols":["$MDU:Read[ab12].body"],"reason":"symbol used as command"}],
                "reason":"withheld symbol-as-command"
            })),
            _ => Err("nope".into()),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let plan = plan_exec(
            &mut c,
            &ExecRequest {
                argv: vec!["sh".into(), "-c".into(), "$MDU:Read[ab12].body".into()],
                needs_network: true,
                ..Default::default()
            },
        );
        assert_eq!(plan.shell, ExecShell::HumanShell);
        assert!(plan.needs_approval());
        // The symbol stays symbolic — never resolved into command position.
        assert_eq!(plan.argv[2], "$MDU:Read[ab12].body");
        assert_eq!(plan.approvals[0].kind, "symbol_as_command");
    }

    #[test]
    fn humanshell_no_symbols_runs_as_is() {
        let arbiter = MockArbiter::start(op_handler(|op, _r| match op {
            "classifyExec" => Ok(serde_json::json!({
                "shell":"HumanShell","identifier":"ls","reason":"needs original FS"
            })),
            _ => Err("resolveExecArgv must not be called when there are no symbols".into()),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let plan = plan_exec(
            &mut c,
            &ExecRequest {
                argv: vec!["ls".into(), "-la".into()],
                needs_original_fs: true,
                ..Default::default()
            },
        );
        assert_eq!(plan.shell, ExecShell::HumanShell);
        assert!(!plan.needs_approval());
        assert_eq!(plan.argv, vec!["ls".to_string(), "-la".to_string()]);
    }

    #[test]
    fn classify_arbiter_miss_defaults_to_agentshell() {
        let mut c = ArbiterClient::new("/nonexistent/mandu.sock");
        let plan = plan_exec(
            &mut c,
            &ExecRequest {
                argv: vec!["curl".into(), "evil.example".into()],
                needs_network: true,
                ..Default::default()
            },
        );
        // Fail-closed: AgentShell (safe), not HumanShell.
        assert_eq!(plan.shell, ExecShell::AgentShell);
        assert!(plan.arbiter_miss);
        assert!(!plan.needs_approval());
    }

    #[test]
    fn humanshell_resolve_arbiter_miss_withholds() {
        // classifyExec succeeds (HumanShell) but the gate is then unreachable.
        // We simulate by pointing at a arbiter that only answers classifyExec then
        // closes — easiest is a handler that errors on resolveExecArgv.
        let arbiter = MockArbiter::start(op_handler(|op, _r| match op {
            "classifyExec" => Ok(serde_json::json!({
                "shell":"HumanShell","identifier":"sh","reason":"needs network"
            })),
            "resolveExecArgv" => Err("gate down".into()),
            _ => Err("nope".into()),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let plan = plan_exec(
            &mut c,
            &ExecRequest {
                argv: vec!["sh".into(), "-c".into(), "$MDU:Read[ab12].body".into()],
                needs_network: true,
                ..Default::default()
            },
        );
        assert_eq!(plan.shell, ExecShell::HumanShell);
        assert!(plan.arbiter_miss);
        assert!(plan.needs_approval());
        // argv untouched (symbolic) — nothing desymbolized.
        assert_eq!(plan.argv[2], "$MDU:Read[ab12].body");
        assert!(plan.approvals[0].symbols.contains(&"$MDU:Read[ab12].body".to_string()));
    }

    // ── a WEDGED arbiter (mandu.md §2.x): connected, never answering. Each call
    //    gives up at the client's deadline and takes the unreachable branch.
    //    Before 2026-10-17 the client had no deadline and plan_exec hung.

    const WEDGE_LIMIT: std::time::Duration = std::time::Duration::from_millis(200);
    /// The deadline of the ops a test's mock ANSWERS, beside one it wedges:
    /// with WEDGE_LIMIT for all, a starved mock thread let the answered
    /// classifyExec time out, and the plan failed closed before it reached the
    /// wedged op (CI, 2026-10-22: `asked_after("resolveExecArgv", 1)` read 0).
    const ANSWER_LIMIT: std::time::Duration = std::time::Duration::from_secs(30);

    fn wedged_client(arbiter: &mandu_arbiter::mock::StallingArbiter) -> ArbiterClient {
        ArbiterClient::new(&arbiter.socket_path).with_io_timeout(Some(WEDGE_LIMIT))
    }

    /// A client that waits ANSWER_LIMIT for every op but `wedged`, which
    /// gives up at WEDGE_LIMIT.
    fn client_wedged_at(arbiter: &mandu_arbiter::mock::StallingArbiter, wedged: &str) -> ArbiterClient {
        ArbiterClient::new(&arbiter.socket_path).with_io_timeout(Some(ANSWER_LIMIT)).with_op_deadline(wedged, WEDGE_LIMIT)
    }

    #[test]
    fn a_wedged_classify_fails_closed_to_agentshell() {
        let arbiter = mandu_arbiter::mock::StallingArbiter::wedged();
        let mut c = wedged_client(&arbiter);
        let t0 = std::time::Instant::now();
        let plan = plan_exec(
            &mut c,
            &ExecRequest { argv: vec!["curl".into(), "evil.example".into()], needs_network: true, ..Default::default() },
        );
        assert!(t0.elapsed() < WEDGE_LIMIT * 10, "plan_exec waited {:?}", t0.elapsed());
        assert_eq!(plan.shell, ExecShell::AgentShell, "a HumanShell-bound command stays boxed");
        assert!(plan.arbiter_miss);
        assert!(plan.reason.contains("timed out"), "{}", plan.reason);
        assert_eq!(arbiter.asked_after("classifyExec", 1), 1);
    }

    #[test]
    fn a_wedged_argv_gate_withholds_every_symbol() {
        let arbiter = mandu_arbiter::mock::StallingArbiter::start(mandu_arbiter::mock::op_stall(|op, _| match op {
            "classifyExec" => mandu_arbiter::mock::Stall::Answer(Ok(serde_json::json!({
                "shell":"HumanShell","identifier":"sh","reason":"needs network"
            }))),
            "execDecisionFor" => mandu_arbiter::mock::Stall::Answer(Ok(serde_json::json!({ "decision": null, "signature": "" }))),
            _ => mandu_arbiter::mock::Stall::Never,
        }));
        let mut c = client_wedged_at(&arbiter, "resolveExecArgv");
        let t0 = std::time::Instant::now();
        let plan = plan_exec(
            &mut c,
            &ExecRequest { argv: vec!["sh".into(), "-c".into(), "$MDU:Read[ab12].body".into()], needs_network: true, ..Default::default() },
        );
        assert!(t0.elapsed() < ANSWER_LIMIT, "plan_exec waited {:?}", t0.elapsed());
        assert_eq!(plan.shell, ExecShell::HumanShell, "the classify was answered: {plan:?}");
        assert!(plan.arbiter_miss && plan.needs_approval(), "{plan:?}");
        assert_eq!(plan.argv[2], "$MDU:Read[ab12].body", "nothing desymbolized");
        assert!(plan.approvals[0].reason.contains("resolveExecArgv timed out"), "the gate itself timed out: {:?}", plan.approvals);
        assert!(plan.approvals[0].symbols.contains(&"$MDU:Read[ab12].body".to_string()), "{:?}", plan.approvals);
        // Asked once, never retried (none only if the client starved past the
        // gate's whole deadline before writing it: unsent, the same Timeout).
        assert!(arbiter.asked_after("resolveExecArgv", 1) <= 1, "{:?}", arbiter.requests());
    }

    #[test]
    fn a_wedged_escalation_stays_agentshell() {
        let arbiter = mandu_arbiter::mock::StallingArbiter::start(mandu_arbiter::mock::op_stall(|op, _| match op {
            "classifyExec" => mandu_arbiter::mock::Stall::Answer(Ok(serde_json::json!({
                "shell":"AgentShell","identifier":"curl","reason":"base"
            }))),
            _ => mandu_arbiter::mock::Stall::Never,
        }));
        let mut c = client_wedged_at(&arbiter, "escalateExec");
        let t0 = std::time::Instant::now();
        let plan = plan_exec(
            &mut c,
            &ExecRequest {
                argv: vec!["curl".into(), "x".into()],
                needs_network: true,
                escalation: EscalationMode::Gated,
                ..Default::default()
            },
        );
        assert!(t0.elapsed() < ANSWER_LIMIT, "plan_exec waited {:?}", t0.elapsed());
        assert_eq!(plan.shell, ExecShell::AgentShell);
        assert!(plan.escalation_pending, "{plan:?}");
        assert!(plan.reason.contains("escalateExec timed out"), "the escalation itself timed out: {}", plan.reason);
        assert!(arbiter.asked_after("escalateExec", 1) <= 1, "asked once, never retried: {:?}", arbiter.requests());
    }

    #[test]
    fn a_wedged_lineage_or_taint_report_returns_false_at_the_deadline() {
        let arbiter = mandu_arbiter::mock::StallingArbiter::wedged();
        let mut c = wedged_client(&arbiter);
        let t0 = std::time::Instant::now();
        assert!(!record_spawn_lineage(&mut c, "curl-2", "bash-1"));
        assert!(!taint_invocation(&mut c, "bash-root", "evil.example"));
        assert!(t0.elapsed() < WEDGE_LIMIT * 10, "waited {:?}", t0.elapsed());
        // The second call dialed afresh: the first connection is wedged.
        arbiter.requests_after(2); // each connection's thread reads in its own time
        assert_eq!(arbiter.connection_count(), 2);
    }

    #[test]
    fn restricted_env_pins_agentshell() {
        // The arbiter's classifyExec honors RESTRICTED=1 → AgentShell; we just
        // assert the orchestration passes params through and respects the result.
        let arbiter = MockArbiter::start(op_handler(|op, req| match op {
            "classifyExec" => {
                let restricted = req
                    .get("params")
                    .and_then(|p| p.get("env"))
                    .and_then(|e| e.get("RESTRICTED"))
                    .map(|v| v == "1")
                    .unwrap_or(false);
                let shell = if restricted { "AgentShell" } else { "HumanShell" };
                Ok(serde_json::json!({ "shell": shell, "identifier": null, "reason": "param" }))
            }
            _ => Err("nope".into()),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let plan = plan_exec(
            &mut c,
            &ExecRequest {
                argv: vec!["python".into()],
                needs_network: true, // would be HumanShell, but RESTRICTED pins Agent
                params: Some(serde_json::json!({ "env": { "RESTRICTED": "1" } })),
                ..Default::default()
            },
        );
        assert_eq!(plan.shell, ExecShell::AgentShell);
    }

    // ── lineage + invocation-taint emitters (spec §3.1/§3.2) — privilege-free,
    //    best-effort: a arbiter error returns false; NEVER panics, NEVER blocks
    //    exec. Separate from plan_exec (a spawn-time event, not the argv decision).
    //    proc-key attribution is kernel-side + DEFERRED, so these run only in unit
    //    tests today; the kernel execve loop would call them once attribution lands.

    fn lineage_arbiter() -> MockArbiter {
        MockArbiter::start(op_handler(|op, req| match op {
            "processLineage" => {
                // Assert the edge args are sent at the envelope top level (camelCase).
                assert_eq!(req.get("childKey").and_then(|v| v.as_str()), Some("curl-2"));
                assert_eq!(req.get("parentKey").and_then(|v| v.as_str()), Some("bash-1"));
                Ok(serde_json::json!({ "ok": true }))
            }
            "taintProcess" => {
                assert_eq!(req.get("procKey").and_then(|v| v.as_str()), Some("bash-root"));
                assert_eq!(req.get("originHost").and_then(|v| v.as_str()), Some("evil.example"));
                Ok(serde_json::json!({ "ok": true }))
            }
            other => Err(format!("unexpected op {other}")),
        }))
    }

    #[test]
    fn record_spawn_lineage_success_returns_true() {
        let arbiter = lineage_arbiter();
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let ok = record_spawn_lineage(&mut c, "curl-2", "bash-1");
        assert!(ok, "a successful processLineage ack should return true");
        assert_eq!(arbiter.request_count(), 1, "the mock should have seen one processLineage call");
    }

    #[test]
    fn record_spawn_lineage_arbiter_miss_returns_false_no_panic() {
        // No arbiter at this socket → the call errors → best-effort returns false
        // (NEVER panics, NEVER blocks the spawn).
        let mut c = ArbiterClient::new("/nonexistent/mandu.sock");
        let ok = record_spawn_lineage(&mut c, "curl-2", "bash-1");
        assert!(!ok, "a arbiter miss must return false, not panic");
    }

    #[test]
    fn taint_invocation_success_returns_true() {
        let arbiter = lineage_arbiter();
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let ok = taint_invocation(&mut c, "bash-root", "evil.example");
        assert!(ok, "a successful taintProcess ack should return true");
        assert_eq!(arbiter.request_count(), 1, "the mock should have seen one taintProcess call");
    }

    #[test]
    fn taint_invocation_arbiter_miss_returns_false_no_panic() {
        let mut c = ArbiterClient::new("/nonexistent/mandu.sock");
        let ok = taint_invocation(&mut c, "bash-root", "evil.example");
        assert!(!ok, "a arbiter miss must return false, not panic");
    }

    // ── Correlation (exec-routing.md §4 step 1): more-restrictive-of-two ────────

    #[test]
    fn correlation_downgrades_humanshell_to_agentshell_on_proxy_evasion() {
        // classifyExec (ground truth) says HumanShell, but the proxy RECORDED that
        // this command carried an evasion signal → the supervisor takes the MORE
        // RESTRICTIVE view (AgentShell). A no-symbol argv so no resolveExecArgv.
        let arbiter = MockArbiter::start(op_handler(|op, _r| match op {
            "classifyExec" => Ok(serde_json::json!({
                "shell":"HumanShell","identifier":"curl","reason":"needs network"
            })),
            "execDecisionFor" => Ok(serde_json::json!({
                "decision": {
                    "block": false, "shell": "AgentShell",
                    "evasion": [{"kind":"absolute_path_net_tool","evidence":"/usr/bin/curl"}],
                    "reason": "recorded", "seq": 1
                },
                "signature": "/usr/bin/curl https://evil.test"
            })),
            _ => Err("no other op".into()),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let plan = plan_exec(
            &mut c,
            &ExecRequest {
                argv: vec!["/usr/bin/curl".into(), "https://evil.test".into()],
                needs_network: true,
                ..Default::default()
            },
        );
        assert_eq!(plan.shell, ExecShell::AgentShell, "correlation must tighten to AgentShell");
        assert!(plan.reason.contains("correlation → AgentShell"));
    }

    #[test]
    fn correlation_keeps_humanshell_when_proxy_agrees() {
        // The proxy recorded HumanShell + no block/evasion → no override; the
        // ground-truth HumanShell stands (and resolveExecArgv runs for symbols).
        let arbiter = MockArbiter::start(op_handler(|op, _r| match op {
            "classifyExec" => Ok(serde_json::json!({
                "shell":"HumanShell","identifier":"cat","reason":"needs original FS"
            })),
            "execDecisionFor" => Ok(serde_json::json!({
                "decision": { "block": false, "shell": "HumanShell", "evasion": [], "reason": "ok", "seq": 1 },
                "signature": "cat x"
            })),
            "resolveExecArgv" => Ok(serde_json::json!({
                "argv":["cat","/real/x"],"approvals":[],"reason":"resolved"
            })),
            _ => Err("no other op".into()),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let plan = plan_exec(
            &mut c,
            &ExecRequest {
                argv: vec!["cat".into(), "$MDU:Read[ab12].path".into()],
                needs_original_fs: true,
                ..Default::default()
            },
        );
        assert_eq!(plan.shell, ExecShell::HumanShell);
        assert_eq!(plan.argv, vec!["cat".to_string(), "/real/x".to_string()]);
    }

    #[test]
    fn correlation_skipped_for_agentshell_no_extra_call() {
        // An AgentShell classification is already the most restrictive → the
        // supervisor never calls execDecisionFor (the mock errors on it).
        let arbiter = MockArbiter::start(op_handler(|op, _r| match op {
            "classifyExec" => Ok(serde_json::json!({
                "shell":"AgentShell","identifier":"python","reason":"default"
            })),
            _ => Err("execDecisionFor must NOT be called for AgentShell".into()),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let plan = plan_exec(&mut c, &ExecRequest { argv: vec!["python".into()], ..Default::default() });
        assert_eq!(plan.shell, ExecShell::AgentShell);
    }

    // ── Escalation (exec-routing.md §5): needs_* gated behind approval ──────────

    #[test]
    fn gated_escalation_stays_agentshell_when_pending() {
        // Gated mode + needs_network, but escalateExec says pending (no approval)
        // → stay AgentShell with escalation_pending set (the command runs safely,
        // the human sees a queued approval).
        let arbiter = MockArbiter::start(op_handler(|op, _r| match op {
            "classifyExec" => Ok(serde_json::json!({
                "shell":"AgentShell","identifier":"curl","reason":"base (no hints)"
            })),
            "escalateExec" => Ok(serde_json::json!({
                "shell":"AgentShell","approved":false,"requiresApproval":true,
                "reason":"needs network; escalation requires approval → pending"
            })),
            _ => Err("no other op".into()),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let plan = plan_exec(
            &mut c,
            &ExecRequest {
                argv: vec!["curl".into(), "https://x.test".into()],
                needs_network: true,
                escalation: EscalationMode::Gated,
                ..Default::default()
            },
        );
        assert_eq!(plan.shell, ExecShell::AgentShell);
        assert!(plan.escalation_pending, "a pending escalation must be flagged");
    }

    #[test]
    fn gated_escalation_goes_humanshell_when_approved() {
        let arbiter = MockArbiter::start(op_handler(|op, _r| match op {
            "classifyExec" => Ok(serde_json::json!({
                "shell":"AgentShell","identifier":"curl","reason":"base"
            })),
            "escalateExec" => Ok(serde_json::json!({
                "shell":"HumanShell","approved":true,"requiresApproval":false,
                "reason":"human-approved escalation"
            })),
            // No symbols → no resolveExecArgv. Correlation lookup on the HumanShell:
            "execDecisionFor" => Ok(serde_json::json!({ "decision": null, "signature": "curl https://x.test" })),
            _ => Err("no other op".into()),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let plan = plan_exec(
            &mut c,
            &ExecRequest {
                argv: vec!["curl".into(), "https://x.test".into()],
                needs_network: true,
                escalation: EscalationMode::Gated,
                ..Default::default()
            },
        );
        assert_eq!(plan.shell, ExecShell::HumanShell, "an approved escalation reaches HumanShell");
        assert!(!plan.escalation_pending);
    }

    #[test]
    fn gated_escalation_unreachable_stays_agentshell_failsafe() {
        // classifyExec answers (AgentShell base) but escalateExec is unreachable
        // → fail-safe: stay AgentShell, escalation pending. (Simulated by a handler
        // that errors on escalateExec.)
        let arbiter = MockArbiter::start(op_handler(|op, _r| match op {
            "classifyExec" => Ok(serde_json::json!({
                "shell":"AgentShell","identifier":"curl","reason":"base"
            })),
            "escalateExec" => Err("escalation gate down".into()),
            _ => Err("no other op".into()),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let plan = plan_exec(
            &mut c,
            &ExecRequest {
                argv: vec!["curl".into(), "https://x.test".into()],
                needs_network: true,
                escalation: EscalationMode::Gated,
                ..Default::default()
            },
        );
        assert_eq!(plan.shell, ExecShell::AgentShell);
        assert!(plan.escalation_pending);
    }

    #[test]
    fn auto_mode_needs_network_still_routes_humanshell() {
        // Default Auto mode preserves the legacy behavior: needs_network → the
        // classifyExec HumanShell route directly (no escalation gate).
        let arbiter = MockArbiter::start(op_handler(|op, _r| match op {
            "classifyExec" => Ok(serde_json::json!({
                "shell":"HumanShell","identifier":"ls","reason":"needs network"
            })),
            "execDecisionFor" => Ok(serde_json::json!({ "decision": null, "signature": "ls" })),
            _ => Err("escalateExec must NOT be called in Auto mode".into()),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let plan = plan_exec(
            &mut c,
            &ExecRequest {
                argv: vec!["ls".into()],
                needs_network: true,
                ..Default::default() // escalation: Auto
            },
        );
        assert_eq!(plan.shell, ExecShell::HumanShell);
    }
}
