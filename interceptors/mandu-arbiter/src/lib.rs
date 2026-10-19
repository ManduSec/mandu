//! mandu-arbiter — the shared arbiter IPC client for the Mandu OS-level
//! interceptors (fs-supervisor, net-supervisor, exec-supervisor).
//!
//! PURE / PRIVILEGE-FREE: this whole crate needs no root and no kernel features.
//! Unix-domain sockets are unprivileged, so the client and the mock both run in
//! `cargo test` on an unprivileged host.
//!
//! Modules:
//!   - `protocol` — typed request/response structs matching `arbiter/ipc/protocol.ts`.
//!   - `event`    — serde mirror of the dashboard `ManduEvent` for the `emit` op.
//!   - `client`   — the blocking NDJSON Unix-socket client (`ArbiterClient`).
//!   - `mock`     — an in-process mock arbiter for tests (cfg(test) or feature "mock").
//!   - `wsl`      — WSL detection + the Windows interop surface the boxes hide.
//!   - `clean_run` — the box ↔ guard wire of the guard-hosted clean box.
//!
//! THE HUMAN PLANE (docs/design/architecture/arbiter-human-plane.md): the arbiter serves
//! the ops that return ORIGINALS — `desymbolize`, a shallow `resolve`,
//! `events`/`subscribe`/`sessions`/`verifyEvents` — only on its human-plane
//! socket (`$MANDU_ARBITER_HUMAN_SOCK`, [`ArbiterClient::human_from_env`]),
//! never on the data socket (`$MANDU_ARBITER_SOCK`, [`ArbiterClient::from_env`])
//! that the agent world can reach; on the data socket they come back
//! `ArbiterError::Arbiter("human-plane: …")`. No wire change: the same client,
//! a different socket. A caller never falls back from the human socket to the
//! data one.
//!
//! SECURITY: every op returns `Result`. An `Err` means the arbiter is unreachable
//! or refused — callers MUST fail closed (deny / redirect to AgentView), never
//! fall through to raw. `safe_emit` is the ONLY call that swallows errors, because
//! observability emission is explicitly off the security path.

pub mod clean_run;
pub mod client;
pub mod event;
pub mod proc;
pub mod protocol;
pub mod symbols;
pub mod wsl;

#[cfg(test)]
mod rediscovery_tests;
#[cfg(test)]
mod timeout_tests;

#[cfg(any(test, feature = "mock"))]
pub mod mock;

pub use client::{ArbiterClient, ArbiterError};
pub use event::ManduEvent;
pub use proc::{proc_key_for_pid, proc_key_from, read_starttime};

/// Best-effort observability emit. NEVER propagates an error and NEVER blocks the
/// caller's enforcement decision — a arbiter/emit failure is silently dropped (the
/// dashboard simply misses one event). This is the only place a arbiter error is
/// intentionally ignored; every enforcement op uses the fallible `ArbiterClient`
/// methods so failures fail closed.
pub fn safe_emit(client: &mut ArbiterClient, event: &ManduEvent) {
    let _ = client.emit(event);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{op_handler, MockArbiter};
    use crate::protocol::*;

    /// A mock that answers each op with a canned, op-appropriate response.
    fn canned_arbiter() -> MockArbiter {
        MockArbiter::start(op_handler(|op, req| match op {
            "ping" => Ok(serde_json::json!({ "pong": true, "protocolVersion": 1 })),
            "classify" => {
                // Echo the tool back in the reason so the test can assert routing.
                let tool = req
                    .get("request")
                    .and_then(|r| r.get("tool"))
                    .and_then(|t| t.as_str())
                    .unwrap_or("?");
                Ok(serde_json::json!({
                    "trust": "UNTRUSTED",
                    "category": null,
                    "reason": format!("classified {tool}")
                }))
            }
            "symbolize" => {
                let tool = req.get("tool").and_then(|t| t.as_str()).unwrap_or("x");
                Ok(serde_json::json!({ "symbol": format!("$MDU:{tool}[a1b2].v") }))
            }
            "desymbolize" => {
                let text = req.get("text").and_then(|t| t.as_str()).unwrap_or("");
                Ok(serde_json::json!({ "text": text.replace("$MDU:x[a1b2].v", "SECRET") }))
            }
            "resolve" => Ok(serde_json::json!({ "value": "raw-value" })),
            "desymbolizationDecision" => Ok(serde_json::json!({
                "allow": false, "requiresApproval": true, "reason": "test deny"
            })),
            "classifyExec" => Ok(serde_json::json!({
                "shell": "AgentShell", "identifier": "python", "reason": "default"
            })),
            "resolveExecArgv" => Ok(serde_json::json!({
                "argv": ["echo", "hi"], "approvals": [], "reason": "ok"
            })),
            "emit" => Ok(serde_json::json!({ "seq": 42 })),
            other => Err(format!("unknown op {other}")),
        }))
    }

    #[test]
    fn ping_roundtrips() {
        let arbiter = canned_arbiter();
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let p = c.ping().unwrap();
        assert!(p.pong);
        assert_eq!(p.protocol_version, 1);
    }

    #[test]
    fn classify_roundtrips() {
        let arbiter = canned_arbiter();
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let req = ClassifyRequest {
            tool: "web_fetch".into(),
            field: Some("text".into()),
            value: "evil".into(),
            boundary: Boundary::Network,
            origin: Some("http://evil.example".into()),
            params: None,
        };
        let res = c.classify(&req).unwrap();
        assert_eq!(res.trust, Trust::Untrusted);
        assert_eq!(res.reason, "classified web_fetch");
    }

    #[test]
    fn symbolize_roundtrips() {
        let arbiter = canned_arbiter();
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let args = SymbolizeArgs {
            tool: "Read".into(),
            value: "secret".into(),
            field: Some("content".into()),
            ..Default::default()
        };
        let res = c.symbolize(&args).unwrap();
        assert_eq!(res.symbol, "$MDU:Read[a1b2].v");
    }

    #[test]
    fn desymbolize_and_resolve_roundtrip() {
        let arbiter = canned_arbiter();
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let d = c.desymbolize("here is $MDU:x[a1b2].v end").unwrap();
        assert_eq!(d.text, "here is SECRET end");
        let r = c.resolve("$MDU:x[a1b2].v").unwrap();
        assert_eq!(r.value.as_deref(), Some("raw-value"));
    }

    #[test]
    fn desymbolization_decision_roundtrips() {
        let arbiter = canned_arbiter();
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let req = DesymbolizationRequest {
            symbol: "$MDU:x[a1b2].v".into(),
            boundary: Boundary::Network,
            destination: Some("evil.example".into()),
            as_command: None,
        };
        let dec = c.desymbolization_decision(&req).unwrap();
        assert!(!dec.allow);
        assert_eq!(dec.requires_approval, Some(true));
    }

    #[test]
    fn classify_exec_and_resolve_argv_roundtrip() {
        let arbiter = canned_arbiter();
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let dec = c
            .classify_exec(&ClassifyExecArgs {
                argv: vec!["python".into(), "fix.py".into()],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(dec.shell, ExecShell::AgentShell);
        assert_eq!(dec.identifier.as_deref(), Some("python"));

        let r = c
            .resolve_exec_argv(&ResolveExecArgvArgs {
                argv: vec!["echo".into(), "hi".into()],
                shell: Some(ExecShell::AgentShell),
                params: None,
            })
            .unwrap();
        assert!(!r.needs_approval());
        assert_eq!(r.argv, vec!["echo".to_string(), "hi".to_string()]);
    }

    #[test]
    fn emit_roundtrips_and_safe_emit_swallows_errors() {
        let arbiter = canned_arbiter();
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let ev = ManduEvent {
            id: event::new_event_id(),
            session_id: "s".into(),
            turn: 0,
            ts: event::now_iso8601(),
            seq: 0,
            call_id: None,
            parent_id: None,
            kind: event::EventKind::FsAction,
            view: event::View::AgentView,
            boundary: event::Boundary::Filesystem,
            emitter: event::Emitter::FsSupervisor,
            input: None,
            output: None,
            policy: None,
            invariant: event::EventInvariant::ok(),
        };
        let r = c.emit(&ev).unwrap();
        assert_eq!(r.seq, 42);

        // safe_emit against a dead socket must NOT panic / propagate.
        let mut dead = ArbiterClient::new("/nonexistent/mandu.sock");
        safe_emit(&mut dead, &ev); // no panic

        // arbiter-human-plane.md §5.3: events off silences `emit` only; every
        // other op still reaches the arbiter.
        drop(c); // the mock serves one connection at a time
        let before = arbiter.request_count();
        let mut quiet = ArbiterClient::new(&arbiter.socket_path).with_events(false);
        assert!(!quiet.events_enabled());
        assert_eq!(quiet.emit(&ev).unwrap().seq, -1, "an event not sent reads as a suppressed one");
        assert_eq!(arbiter.request_count(), before, "nothing was sent for the event");
        assert!(quiet.ping().unwrap().pong);
        assert_eq!(arbiter.request_count(), before + 1, "a report still goes");
        assert!(ArbiterClient::new(&arbiter.socket_path).events_enabled(), "on by default");
    }

    #[test]
    fn arbiter_error_when_socket_missing() {
        // No mock running: connecting fails → Err (caller fails closed).
        let mut c = ArbiterClient::new("/nonexistent/mandu-arbiter.sock");
        let err = c.ping().unwrap_err();
        matches!(err, ArbiterError::Io(_));
    }

    #[test]
    fn arbiter_error_reply_propagates() {
        let arbiter = MockArbiter::start(op_handler(|_op, _req| Err("policy unavailable".into())));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let err = c
            .classify(&ClassifyRequest {
                tool: "x".into(),
                field: None,
                value: "v".into(),
                boundary: Boundary::Filesystem,
                origin: None,
                params: None,
            })
            .unwrap_err();
        match err {
            ArbiterError::Arbiter(msg) => assert_eq!(msg, "policy unavailable"),
            other => panic!("expected Arbiter error, got {other:?}"),
        }
    }

    #[test]
    fn multiple_requests_on_one_connection_correlate() {
        let arbiter = canned_arbiter();
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        // Three sequential calls reuse one connection; ids must correlate.
        c.ping().unwrap();
        c.ping().unwrap();
        let p = c.ping().unwrap();
        assert!(p.pong);
        assert!(arbiter.request_count() >= 3);
    }

    #[test]
    fn taint_process_acks_ok() {
        let arbiter = MockArbiter::start(op_handler(|op, _req| match op {
            "taintProcess" => Ok(serde_json::json!({ "ok": true })),
            other => Err(format!("unknown op {other}")),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        c.taint_process(&TaintProcessArgs {
            proc_key: "1234-9".into(),
            origin_host: "evil.example".into(),
            session: Some("s1".into()),
        })
        .unwrap();
        assert_eq!(arbiter.request_count(), 1);
    }

    #[test]
    fn process_lineage_acks_ok() {
        let arbiter = MockArbiter::start(op_handler(|op, _req| match op {
            "processLineage" => Ok(serde_json::json!({ "ok": true })),
            other => Err(format!("unknown op {other}")),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        c.process_lineage(&ProcessLineageArgs {
            child_key: "curl-2".into(),
            parent_key: "bash-1".into(),
            session: None,
        })
        .unwrap();
        assert_eq!(arbiter.request_count(), 1);
    }

    #[test]
    fn is_process_tainted_roundtrips() {
        let arbiter = MockArbiter::start(op_handler(|op, req| match op {
            "isProcessTainted" => {
                // Assert the arg is sent at top level (not nested under "request").
                let key = req.get("procKey").and_then(|v| v.as_str()).unwrap_or("?");
                assert_eq!(key, "grep-3");
                Ok(serde_json::json!({ "tainted": true, "originHost": "evil.example" }))
            }
            other => Err(format!("unknown op {other}")),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let r = c.is_process_tainted("grep-3").unwrap();
        assert!(r.tainted);
        assert_eq!(r.origin_host.as_deref(), Some("evil.example"));
    }

    #[test]
    fn is_process_tainted_reports_untainted() {
        let arbiter = MockArbiter::start(op_handler(|op, _req| match op {
            "isProcessTainted" => Ok(serde_json::json!({ "tainted": false })),
            other => Err(format!("unknown op {other}")),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let r = c.is_process_tainted("clean-1").unwrap();
        assert!(!r.tainted);
        assert!(r.origin_host.is_none());
    }

    #[test]
    fn taint_file_acks_ok() {
        let arbiter = MockArbiter::start(op_handler(|op, req| match op {
            "taintFile" => {
                assert_eq!(req.get("contentHash").and_then(|v| v.as_str()), Some("abc123"));
                assert_eq!(req.get("path").and_then(|v| v.as_str()), Some("/tmp/setup.md"));
                Ok(serde_json::json!({ "ok": true }))
            }
            other => Err(format!("unknown op {other}")),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        c.taint_file(&TaintFileArgs {
            content_hash: "abc123".into(),
            path: "/tmp/setup.md".into(),
            origin_host: "example.test".into(),
            writer_proc: Some("curl-2".into()),
            session: None,
        })
        .unwrap();
        assert_eq!(arbiter.request_count(), 1);
    }

    #[test]
    fn report_exec_clean_verdict_nests_the_report_and_unwraps_the_verdict() {
        let arbiter = MockArbiter::start(op_handler(|op, req| match op {
            "reportExecCleanVerdict" => {
                // The report MUST ride nested under `report` (the TS op shape),
                // with camelCase field names, absent optionals omitted.
                let r = req.get("report").expect("report is nested");
                assert_eq!(r.get("callId").and_then(|v| v.as_str()), Some("toolu_c1"));
                assert_eq!(r.get("clean").and_then(|v| v.as_bool()), Some(true));
                assert_eq!(r.get("boxed").and_then(|v| v.as_bool()), Some(true));
                assert_eq!(r.get("shell").and_then(|v| v.as_str()), Some("AgentShell"));
                assert_eq!(r.get("procKey").and_then(|v| v.as_str()), Some("777-42"));
                assert_eq!(
                    r.get("outputSha256").and_then(|v| v.as_str()).map(str::len),
                    Some(64)
                );
                assert!(r.get("sessionKey").is_none(), "absent optionals are omitted");
                // The arbiter answers with what its gate chain RESOLVED.
                Ok(serde_json::json!({ "verdict": {
                    "callId": "toolu_c1", "clean": true,
                    "reason": "clean (boxed AgentShell, lineage untainted)",
                    "outputSha256": r.get("outputSha256"), "procKey": "777-42", "seq": 1
                }}))
            }
            other => Err(format!("unknown op {other}")),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let v = c
            .report_exec_clean_verdict(&ExecCleanVerdictReport {
                call_id: "toolu_c1".into(),
                clean: true,
                boxed: Some(true),
                shell: Some("AgentShell".into()),
                proc_key: Some("777-42".into()),
                output_sha256: Some("a".repeat(64)),
                reason: None,
                session_key: None,
            })
            .unwrap();
        assert!(v.clean);
        assert_eq!(v.call_id, "toolu_c1");
        assert_eq!(v.output_sha256.as_deref(), Some("a".repeat(64).as_str()));
    }

    #[test]
    fn exec_clean_verdict_for_roundtrips_hit_and_miss() {
        let arbiter = MockArbiter::start(op_handler(|op, req| match op {
            "execCleanVerdictFor" => {
                let id = req.get("callId").and_then(|v| v.as_str()).unwrap_or("?");
                if id == "toolu_hit" {
                    Ok(serde_json::json!({ "verdict": {
                        "callId": "toolu_hit", "clean": false,
                        "reason": "invocation did not run inside the exec box (§5: boxed only)",
                        "seq": 2
                    }}))
                } else {
                    Ok(serde_json::json!({ "verdict": null }))
                }
            }
            other => Err(format!("unknown op {other}")),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let hit = c.exec_clean_verdict_for("toolu_hit").unwrap().unwrap();
        assert!(!hit.clean);
        assert!(hit.reason.contains("§5"));
        assert!(c.exec_clean_verdict_for("toolu_miss").unwrap().is_none());
    }

    #[test]
    fn recorded_exec_decision_call_id_deserializes_and_defaults() {
        // With callId (a new-proxy record) and without (an older proxy) — the
        // supervisor must read both shapes.
        let with: RecordedExecDecision = serde_json::from_value(serde_json::json!({
            "block": false, "shell": "AgentShell", "evasion": [],
            "reason": "recorded", "callId": "toolu_x", "seq": 3
        }))
        .unwrap();
        assert_eq!(with.call_id.as_deref(), Some("toolu_x"));
        let without: RecordedExecDecision = serde_json::from_value(serde_json::json!({
            "block": false, "shell": "AgentShell", "evasion": [], "reason": "old", "seq": 4
        }))
        .unwrap();
        assert!(without.call_id.is_none());
    }

    #[test]
    fn file_trust_roundtrips() {
        let arbiter = MockArbiter::start(op_handler(|op, req| match op {
            "fileTrust" => {
                // path supplied at top level, content-hash omitted.
                assert_eq!(req.get("path").and_then(|v| v.as_str()), Some("/tmp/setup.md"));
                assert!(req.get("contentHash").is_none());
                Ok(serde_json::json!({ "untrusted": true, "origin": "example.test" }))
            }
            other => Err(format!("unknown op {other}")),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let r = c
            .file_trust(&FileTrustArgs {
                content_hash: None,
                path: Some("/tmp/setup.md".into()),
            })
            .unwrap();
        assert!(r.untrusted);
        assert_eq!(r.origin.as_deref(), Some("example.test"));
    }
}
