//! event — a serde mirror of the canonical `ManduEvent` (dashboard
//! `src/event-model.ts`). The OS interceptors EMIT these (best-effort) via the
//! arbiter `emit` op so the dashboard can render the dual-view trace.
//!
//! We mirror the schema field-for-field rather than depend on the dashboard
//! package (it is a Node package). Only the fields the interceptors set are
//! constructed here; `seq` is stamped by the arbiter on emit (we leave it 0).
//!
//! IMPORTANT: emission is BEST-EFFORT and OFF THE SECURITY PATH. A failed emit
//! must never block or change an enforcement decision. The `original` field of a
//! `DualRepr` may carry raw (untrusted) bytes — those go ONLY to the arbiter's
//! privileged event log, never back upstream toward the agent.

use serde::{Deserialize, Serialize};

/// The lane each event renders in (§2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum View {
    AgentView,
    HumanView,
    Quarantine,
}

/// Event kinds (§2.4). The OS interceptors only emit the three `*_action` kinds,
/// but we model the full enum for parity / round-trip with the arbiter store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    TllmCall,
    UllmCall,
    ToolUse,
    ToolResult,
    Classify,
    Symbolize,
    Desymbolize,
    EgressRequest,
    EgressDecision,
    FsAction,
    NetAction,
    ExecAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Boundary {
    ModelContext,
    Network,
    Filesystem,
    Shell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Emitter {
    AnthropicProxy,
    Arbiter,
    FsSupervisor,
    NetSupervisor,
    ExecSupervisor,
}

/// Symbol provenance (§2.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolRef {
    pub name: String,
    pub tool: String,
    pub field: Option<String>,
    pub origin: Option<String>,
    pub value: Option<String>,
    #[serde(rename = "derivedFrom", skip_serializing_if = "Option::is_none")]
    pub derived_from: Option<String>,
    #[serde(rename = "lineRange", skip_serializing_if = "Option::is_none")]
    pub line_range: Option<String>,
}

/// The two-representation model (§2.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualRepr {
    pub symbolized: String,
    pub original: Option<String>,
    pub differs: bool,
    pub symbols: Vec<SymbolRef>,
}

impl DualRepr {
    /// Mirrors dashboard `makeDualRepr`: `differs` is derived from the values so
    /// it can never drift (§2.5).
    pub fn new(symbolized: impl Into<String>, original: Option<String>, symbols: Vec<SymbolRef>) -> Self {
        let symbolized = symbolized.into();
        let differs = matches!(&original, Some(o) if *o != symbolized);
        DualRepr { symbolized, original, differs, symbols }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EventPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// "allow" | "deny" | "needs_approval"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<String>,
    /// "AgentShell" | "HumanShell"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventInvariant {
    /// True iff this event would put UN-symbolized UNTRUSTED data into the agent's
    /// context. MUST be false for every event in a healthy session.
    #[serde(rename = "violatedInvariant")]
    pub violated_invariant: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl EventInvariant {
    pub fn ok() -> Self {
        EventInvariant { violated_invariant: false, detail: None }
    }
    pub fn violated(detail: impl Into<String>) -> Self {
        EventInvariant { violated_invariant: true, detail: Some(detail.into()) }
    }
}

/// The canonical event (§2.4). Built by the interceptors and passed to `emit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManduEvent {
    pub id: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    pub turn: u64,
    pub ts: String,
    /// Stamped by the arbiter on emit; interceptors leave it 0.
    pub seq: i64,
    #[serde(rename = "callId")]
    pub call_id: Option<String>,
    #[serde(rename = "parentId")]
    pub parent_id: Option<String>,

    pub kind: EventKind,
    pub view: View,
    pub boundary: Boundary,
    pub emitter: Emitter,

    pub input: Option<DualRepr>,
    pub output: Option<DualRepr>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<EventPolicy>,
    pub invariant: EventInvariant,
}

/// Monotonic-ish unique id without a ULID dependency: time-millis prefix + a
/// process-local counter, base-36. Sorts roughly by emit time within a process.
/// Mirrors anthropic-proxy `newEventId` intent.
pub fn new_event_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let c = COUNTER.fetch_add(1, Ordering::Relaxed) & 0xff_ffff;
    format!("ev_{}{:05}", to_base36(millis), c)
}

fn to_base36(mut n: u64) -> String {
    if n == 0 {
        return "0".into();
    }
    const ALPHA: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut buf = Vec::new();
    while n > 0 {
        buf.push(ALPHA[(n % 36) as usize]);
        n /= 36;
    }
    buf.reverse();
    String::from_utf8(buf).unwrap()
}

/// ISO-8601-ish wall clock for the `ts` field, computed without a chrono dep.
/// Produces an RFC-3339 UTC string (seconds precision is sufficient for the
/// dashboard; seq is the causal tiebreak).
pub fn now_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Civil-from-days (Howard Hinnant's algorithm), UTC.
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, h, mi, s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dual_repr_differs_is_derived() {
        let same = DualRepr::new("x", Some("x".into()), vec![]);
        assert!(!same.differs);
        let diff = DualRepr::new("$MDU:a[0000]", Some("secret".into()), vec![]);
        assert!(diff.differs);
        // original=None means collapsed, not differing.
        let none = DualRepr::new("$MDU:a[0000]", None, vec![]);
        assert!(!none.differs);
    }

    #[test]
    fn event_serializes_with_camelcase_keys() {
        let ev = ManduEvent {
            id: new_event_id(),
            session_id: "sess1".into(),
            turn: 0,
            ts: now_iso8601(),
            seq: 0,
            call_id: None,
            parent_id: None,
            kind: EventKind::FsAction,
            view: View::AgentView,
            boundary: Boundary::Filesystem,
            emitter: Emitter::FsSupervisor,
            input: Some(DualRepr::new("/path", None, vec![])),
            output: None,
            policy: None,
            invariant: EventInvariant::ok(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"sessionId\":\"sess1\""));
        assert!(json.contains("\"kind\":\"fs_action\""));
        assert!(json.contains("\"view\":\"AgentView\""));
        assert!(json.contains("\"emitter\":\"fs-supervisor\""));
        assert!(json.contains("\"violatedInvariant\":false"));
        // Round-trip.
        let back: ManduEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.session_id, "sess1");
        assert_eq!(back.kind, EventKind::FsAction);
    }

    #[test]
    fn iso8601_format_shape() {
        let ts = now_iso8601();
        // YYYY-MM-DDTHH:MM:SSZ → 20 chars.
        assert_eq!(ts.len(), 20);
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[10..11], "T");
    }

    #[test]
    fn event_id_is_unique_and_monotonic_counter() {
        let a = new_event_id();
        let b = new_event_id();
        assert_ne!(a, b);
        assert!(a.starts_with("ev_"));
    }
}

// ── tenancy (policy-surface.md §2.7) ────────────────────────────────

/// The tenant this emitter runs in: `MANDU_TENANT` = `live` | `test` (the
/// launcher exports it for every child). Anything else → `None` (unstamped;
/// the arbiter stamps its own tenant). Read at emit time, not cached, so a
/// test harness can set it per process.
pub fn tenant_from_env() -> Option<String> {
    match std::env::var("MANDU_TENANT") {
        Ok(v) if v == "live" || v == "test" => Some(v),
        _ => None,
    }
}

/// Stamp `tenant` onto a serialized event (top-level field) when the event
/// carries none. The struct itself has no `tenant` field — every interceptor
/// builds events by struct literal, and the stamp is an emitter-wide fact,
/// not a per-event decision — so the client stamps the wire form.
pub fn stamp_tenant(event: &mut serde_json::Value, tenant: Option<&str>) {
    if let (Some(t), Some(obj)) = (tenant, event.as_object_mut()) {
        if !obj.contains_key("tenant") {
            obj.insert("tenant".to_string(), serde_json::Value::String(t.to_string()));
        }
    }
}

#[cfg(test)]
mod tenant_tests {
    use super::*;

    #[test]
    fn stamp_tenant_adds_the_field_once_and_never_overwrites() {
        let mut v = serde_json::json!({ "id": "e1", "kind": "fs_action" });
        stamp_tenant(&mut v, Some("test"));
        assert_eq!(v["tenant"], "test");
        stamp_tenant(&mut v, Some("live"));
        assert_eq!(v["tenant"], "test", "an existing stamp is kept");
        let mut none = serde_json::json!({ "id": "e2" });
        stamp_tenant(&mut none, None);
        assert!(none.get("tenant").is_none(), "no tenant → unstamped (the arbiter stamps its own)");
    }
}
