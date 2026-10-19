//! events — build the `exec_action` observability event for one execve plan.
//! PURE. Best-effort emission (off the security path).

use mandu_arbiter::event::*;
use mandu_arbiter::protocol::ExecShell;

use crate::orchestrate::{ExecPlan, ExecRequest};

/// Build an `exec_action` event. AgentShell renders in the AgentView lane
/// (symbolic argv); HumanShell in HumanView (desymbolized argv, or withheld).
pub fn exec_action_event(
    session_id: &str,
    turn: u64,
    req: &ExecRequest,
    plan: &ExecPlan,
) -> ManduEvent {
    let view = match plan.shell {
        ExecShell::AgentShell => View::AgentView,
        ExecShell::HumanShell => View::HumanView,
    };
    let shell_label = match plan.shell {
        ExecShell::AgentShell => "AgentShell",
        ExecShell::HumanShell => "HumanShell",
    };
    let usage = if plan.needs_approval() || plan.escalation_pending {
        // Either a withheld symbol-as-command OR a pending needs_* escalation
        // (exec-routing.md §5): the human has a queued approval to act on.
        Some("needs_approval".to_string())
    } else if plan.shell == ExecShell::HumanShell {
        Some("allow".to_string())
    } else {
        None
    };
    let policy = EventPolicy {
        shell: Some(shell_label.into()),
        usage,
        reason: Some(plan.reason.clone()),
        ..Default::default()
    };

    // input = the argv the agent decided (AgentView/symbolic) vs the argv we will
    // actually run (the resolved/withheld argv). For AgentShell they are equal.
    let agent_argv = req.argv.join(" ");
    let run_argv = plan.argv.join(" ");
    let original = if plan.shell == ExecShell::HumanShell {
        Some(run_argv)
    } else {
        None
    };

    ManduEvent {
        id: new_event_id(),
        session_id: session_id.to_string(),
        turn,
        ts: now_iso8601(),
        seq: 0,
        // The tool_use id the correlation lookup resolved for this argv (None
        // on a miss) — lets the dashboard join the boxed exec to its tool call.
        call_id: plan.call_id.clone(),
        parent_id: None,
        kind: EventKind::ExecAction,
        view,
        boundary: Boundary::Shell,
        emitter: Emitter::ExecSupervisor,
        input: Some(DualRepr::new(agent_argv, original, vec![])),
        output: None,
        policy: Some(policy),
        // Withholding/AgentShell is the SAFE outcome. The exec path never puts
        // un-symbolized untrusted data into the agent's context (it desymbolizes
        // OUTWARD for HumanShell), so the ingress invariant is not at stake here.
        invariant: EventInvariant::ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mandu_arbiter::protocol::ExecApprovalItem;

    fn agent_plan() -> (ExecRequest, ExecPlan) {
        let req = ExecRequest {
            argv: vec!["python".into(), "$MDU:Read[ab12].body".into()],
            ..Default::default()
        };
        let plan = ExecPlan {
            shell: ExecShell::AgentShell,
            identifier: Some("python".into()),
            argv: req.argv.clone(),
            approvals: vec![],
            arbiter_miss: false,
            escalation_pending: false,
            reason: "AgentShell default".into(),
            call_id: None,
        };
        (req, plan)
    }

    #[test]
    fn agentshell_event_is_agentview() {
        let (req, plan) = agent_plan();
        let ev = exec_action_event("s", 0, &req, &plan);
        assert_eq!(ev.view, View::AgentView);
        assert_eq!(ev.kind, EventKind::ExecAction);
        assert_eq!(ev.policy.as_ref().unwrap().shell.as_deref(), Some("AgentShell"));
        assert!(!ev.invariant.violated_invariant);
    }

    #[test]
    fn humanshell_withheld_event_marks_needs_approval() {
        let req = ExecRequest {
            argv: vec!["sh".into(), "-c".into(), "$MDU:Read[ab12].body".into()],
            needs_network: true,
            ..Default::default()
        };
        let plan = ExecPlan {
            shell: ExecShell::HumanShell,
            identifier: Some("sh".into()),
            argv: req.argv.clone(),
            approvals: vec![ExecApprovalItem {
                kind: "symbol_as_command".into(),
                symbols: vec!["$MDU:Read[ab12].body".into()],
                reason: "symbol used as command".into(),
            }],
            arbiter_miss: false,
            escalation_pending: false,
            reason: "withheld".into(),
            call_id: None,
        };
        let ev = exec_action_event("s", 0, &req, &plan);
        assert_eq!(ev.view, View::HumanView);
        assert_eq!(ev.policy.unwrap().usage.as_deref(), Some("needs_approval"));
    }

    #[test]
    fn event_carries_the_correlated_call_id_and_null_on_a_miss() {
        let (req, mut plan) = agent_plan();
        assert_eq!(exec_action_event("s", 0, &req, &plan).call_id, None);
        plan.call_id = Some("toolu_01abc".into());
        let ev = exec_action_event("s", 0, &req, &plan);
        assert_eq!(ev.call_id.as_deref(), Some("toolu_01abc"));
        // observability only: the id changes nothing about the decision
        assert_eq!(ev.policy.as_ref().unwrap().shell.as_deref(), Some("AgentShell"));
        assert!(!ev.invariant.violated_invariant);
    }
}
