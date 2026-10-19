//! events — build the `fs_action` observability event for one openat decision.
//!
//! PURE. Best-effort emission only — the caller uses `mandu_arbiter::safe_emit`,
//! which swallows errors so emission can never affect the enforcement decision.

use mandu_arbiter::event::*;

use crate::decision::{Access, FirstTouch, OpenDecision};

/// Build an `fs_action` event from a decision + (optional) first-touch metadata.
/// A REDIRECT renders in the AgentView lane (the agent sees symbolized content);
/// a PASSTHROUGH renders in HumanView (an untracked path the agent reads raw).
pub fn fs_action_event(
    session_id: &str,
    turn: u64,
    decision: &OpenDecision,
    first_touch: Option<&FirstTouch>,
) -> ManduEvent {
    let (view, input, policy, invariant) = match decision {
        OpenDecision::Passthrough { reason } => (
            View::HumanView,
            DualRepr::new("(untracked path)", None, vec![]),
            Some(EventPolicy {
                reason: Some(reason.clone()),
                ..Default::default()
            }),
            EventInvariant::ok(),
        ),
        OpenDecision::Redirect {
            original,
            agent_view_path,
            access,
            reason,
            ..
        } => {
            let mut symbols = vec![];
            let mut pol = EventPolicy {
                reason: Some(reason.clone()),
                ..Default::default()
            };
            // The AgentView-shown path is the "symbolized" surface; the real
            // HumanView path is the "original". For a read whose content was
            // symbolized, we attach the symbol provenance + trust.
            if let Some(ft) = first_touch {
                pol.trust = Some(match ft.trust {
                    mandu_arbiter::protocol::Trust::Trusted => "TRUSTED",
                    mandu_arbiter::protocol::Trust::Untrusted => "UNTRUSTED",
                }
                .into());
                pol.category = ft.category.clone();
                if let Some(sym) = &ft.symbol {
                    symbols.push(SymbolRef {
                        name: sym.clone(),
                        tool: "fs".into(),
                        field: None,
                        origin: Some(original.clone()),
                        value: None,
                        derived_from: None,
                        line_range: None,
                    });
                }
            }
            // The redirect itself enforces the invariant (the agent reads the
            // AgentView, never raw HumanView). A arbiter miss does NOT violate the
            // invariant — we still served the AgentView (already symbolized by the
            // sync daemon); we record the miss in the detail for the dashboard.
            let invariant = match first_touch {
                Some(ft) if ft.arbiter_miss => EventInvariant {
                    violated_invariant: false,
                    detail: Some(format!(
                        "arbiter miss on first-touch classify; redirect to AgentView held ({})",
                        ft.reason
                    )),
                },
                _ => EventInvariant::ok(),
            };
            let _ = access; // reflected in `reason` already
            (
                View::AgentView,
                DualRepr::new(agent_view_path.clone(), Some(original.clone()), symbols),
                Some(pol),
                invariant,
            )
        }
    };

    ManduEvent {
        id: new_event_id(),
        session_id: session_id.to_string(),
        turn,
        ts: now_iso8601(),
        seq: 0,
        call_id: None,
        parent_id: None,
        kind: EventKind::FsAction,
        view,
        boundary: Boundary::Filesystem,
        emitter: Emitter::FsSupervisor,
        input: Some(input),
        output: None,
        policy,
        invariant,
    }
}

/// Tiny helper so callers can label the access in human terms.
pub fn access_label(a: Access) -> &'static str {
    match a {
        Access::Read => "read",
        Access::Write => "write",
        Access::ReadWrite => "read+write",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{decide_open, TrackedRoots};
    use crate::layout::ViewLayout;

    #[test]
    fn redirect_event_is_agentview_and_invariant_ok() {
        let roots = TrackedRoots::with_layouts(vec![ViewLayout::new("/home/u/p", "/s")]);
        let d = decide_open(&roots, "/home/u/p/secret.txt", 0, true);
        let ev = fs_action_event("sess", 1, &d, None);
        assert_eq!(ev.view, View::AgentView);
        assert_eq!(ev.kind, EventKind::FsAction);
        assert!(!ev.invariant.violated_invariant);
        // The shown path is the AgentView worktree path.
        assert!(ev.input.unwrap().symbolized.contains("/agentview/"));
    }

    #[test]
    fn passthrough_event_is_humanview() {
        let roots = TrackedRoots::with_layouts(vec![ViewLayout::new("/home/u/p", "/s")]);
        let d = decide_open(&roots, "/etc/hosts", 0, true);
        let ev = fs_action_event("sess", 1, &d, None);
        assert_eq!(ev.view, View::HumanView);
    }

    #[test]
    fn arbiter_miss_does_not_violate_invariant() {
        let roots = TrackedRoots::with_layouts(vec![ViewLayout::new("/home/u/p", "/s")]);
        let d = decide_open(&roots, "/home/u/p/x.txt", 0, true);
        let ft = FirstTouch {
            trust: mandu_arbiter::protocol::Trust::Untrusted,
            category: None,
            symbol: None,
            reason: "arbiter unreachable".into(),
            arbiter_miss: true,
        };
        let ev = fs_action_event("sess", 1, &d, Some(&ft));
        // Redirect to AgentView held; invariant intact, miss noted in detail.
        assert!(!ev.invariant.violated_invariant);
        assert!(ev.invariant.detail.unwrap().contains("arbiter miss"));
    }
}
