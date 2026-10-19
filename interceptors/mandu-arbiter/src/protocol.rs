//! protocol — typed request/response structs for the Mandu arbiter wire protocol.
//!
//! This is a faithful Rust reimplementation of `arbiter/ipc/protocol.ts`. The
//! transport is NDJSON over a Unix-domain socket: each request is one JSON object
//! on a single line terminated by `\n`; the arbiter replies with exactly one JSON
//! object line, correlated by `id`.
//!
//! Every request carries `{ id, op, ... }`; every response is
//! `{ id, ok, result | error }`. We model the success path per-op with typed
//! result structs and the error path with `ArbiterError`.
//!
//! The structs here cover ONLY the ops the OS interceptors need (the subset named
//! in the task): classify, symbolize, desymbolize, desymbolizationDecision,
//! classifyExec, resolveExecArgv, emit, plus the resolve/ping ops the fs path
//! finds useful. Field names match the TS protocol exactly (camelCase) via serde
//! rename attributes where Rust's snake_case differs.

use serde::{Deserialize, Serialize};

/// The four boundaries at which data crosses into/out of the agent.
/// Mirrors `arbiter/policy/policy-interface.ts` `Boundary`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Boundary {
    ModelContext,
    Network,
    Filesystem,
    Shell,
}

/// Inbound trust classification. Mirrors Mandu `Trust`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Trust {
    Trusted,
    Untrusted,
}

/// Which shell view a command runs in. Mirrors `exec-classify.ts` `ExecShell`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecShell {
    AgentShell,
    HumanShell,
}

// ── classify ──────────────────────────────────────────────────────────────────

/// `classify` request payload (the `request` field of the op envelope).
/// Mirrors `policy-interface.ts` `ClassifyRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifyRequest {
    pub tool: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    pub value: String,
    pub boundary: Boundary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

/// `classify` result. Mirrors `ClassifyResult`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifyResult {
    pub trust: Trust,
    pub category: Option<String>,
    pub reason: String,
}

// ── symbolize ───────────────────────────────────────────────────────────────

/// `symbolize` request fields (flattened into the op envelope, not nested).
/// Mirrors `protocol.ts` `SymbolizeRequest` (minus id/op).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SymbolizeArgs {
    pub tool: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(rename = "sessionKey", skip_serializing_if = "Option::is_none")]
    pub session_key: Option<String>,
    #[serde(rename = "callId", skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolizeResult {
    /// The allocated symbol name, e.g. `$MDU:web_fetch[a1b2].text`.
    pub symbol: String,
}

// ── desymbolize ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesymbolizeResult {
    /// `text` with all known symbols replaced by their raw values.
    pub text: String,
}

// ── resolve (single symbol) ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveResult {
    /// Raw value, or null if unknown.
    pub value: Option<String>,
}

// ── desymbolizationDecision (the egress gate) ───────────────────────────────────

/// Mirrors `policy-interface.ts` `DesymbolizationRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesymbolizationRequest {
    pub symbol: String,
    pub boundary: Boundary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(rename = "asCommand", skip_serializing_if = "Option::is_none")]
    pub as_command: Option<bool>,
}

/// Mirrors the `DesymbolizationDecision` union. The TS shape is
/// `{ allow:true, reason }` | `{ allow:false, requiresApproval, reason }`.
/// We model it as one struct: `requires_approval` is absent on the allow arm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesymbolizationDecision {
    pub allow: bool,
    #[serde(rename = "requiresApproval", skip_serializing_if = "Option::is_none")]
    pub requires_approval: Option<bool>,
    pub reason: String,
}

impl DesymbolizationDecision {
    /// Fail-closed default used when the arbiter is unreachable: deny, require
    /// approval. NEVER allow egress without a positive arbiter decision.
    pub fn fail_closed(reason: impl Into<String>) -> Self {
        DesymbolizationDecision {
            allow: false,
            requires_approval: Some(true),
            reason: reason.into(),
        }
    }
}

// ── classifyExec ────────────────────────────────────────────────────────────────

/// `classifyExec` request fields (flattened into the op envelope).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClassifyExecArgs {
    pub argv: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(rename = "needsNetwork", skip_serializing_if = "Option::is_none")]
    pub needs_network: Option<bool>,
    #[serde(rename = "needsOriginalFs", skip_serializing_if = "Option::is_none")]
    pub needs_original_fs: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

/// Mirrors `exec-classify.ts` `ExecClassifyDecision`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecClassifyDecision {
    pub shell: ExecShell,
    pub identifier: Option<String>,
    pub reason: String,
}

// ── resolveExecArgv ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResolveExecArgvArgs {
    pub argv: Vec<String>,
    pub shell: Option<ExecShell>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

/// Mirrors `exec-classify.ts` `ExecApprovalItem`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecApprovalItem {
    pub kind: String,
    pub symbols: Vec<String>,
    pub reason: String,
}

/// Mirrors `exec-classify.ts` `ResolveExecArgvResult`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveExecArgvResult {
    pub argv: Vec<String>,
    pub approvals: Vec<ExecApprovalItem>,
    pub reason: String,
}

impl ResolveExecArgvResult {
    /// True iff at least one item was withheld pending human approval.
    pub fn needs_approval(&self) -> bool {
        !self.approvals.is_empty()
    }
}

// ── execDecisionFor (proxy↔execve correlation, exec-routing.md §4 step 1) ──────

/// A non-blocking evasion signal the proxy recorded. Mirrors `exec-gate.ts`
/// `ExecGateEvasion`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecEvasion {
    pub kind: String,
    pub evidence: String,
}

/// The proxy's recorded exec decision. Mirrors `exec-decision-store.ts`
/// `RecordedExecDecision`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedExecDecision {
    /// Did the proxy's execGate BLOCK the command?
    pub block: bool,
    /// The shell the proxy's classification pointed at.
    pub shell: ExecShell,
    /// Evasion signals the proxy recorded (informational).
    #[serde(default)]
    pub evasion: Vec<ExecEvasion>,
    pub reason: String,
    #[serde(rename = "sessionKey", default, skip_serializing_if = "Option::is_none")]
    pub session_key: Option<String>,
    /// The tool_use id the proxy attributed this command to — the callId leg of
    /// the correlation (exec-routing.md §8.5): the supervisor keys its
    /// clean-verdict report on it. Absent on records from an older proxy.
    #[serde(rename = "callId", default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    #[serde(default)]
    pub seq: i64,
}

/// Args for `execDecisionFor` — pass EITHER a command string or the observed argv.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExecDecisionForArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argv: Option<Vec<String>>,
}

/// `execDecisionFor` ⇒ the recorded proxy decision (or None), + the lookup key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecDecisionForResult {
    pub decision: Option<RecordedExecDecision>,
    #[serde(default)]
    pub signature: String,
}

// ── reportExecCleanVerdict / execCleanVerdictFor (exec-routing.md §8.5) ────

/// What the exec supervisor reports for one finished boxed invocation. Mirrors
/// `arbiter/policy/exec-clean-verdicts.ts` `ExecCleanVerdictReport`. The ARBITER
/// resolves it through the fail-closed §5 gate chain (its own taint re-check on
/// `proc_key`, `boxed`, AgentShell, 64-hex output hash) — the supervisor's claim
/// is an input to the gates, never the verdict itself.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExecCleanVerdictReport {
    /// The originating tool_use id (from the recorded exec decision's callId).
    #[serde(rename = "callId")]
    pub call_id: String,
    /// The supervisor's own claim: influence set clean (files ⊆ trusted ∧ net = ∅).
    pub clean: bool,
    /// The invocation ran inside the exec box (Landlock clean view).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boxed: Option<bool>,
    /// Which shell world ran it — only "AgentShell" qualifies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    /// The invocation's proc key, for the arbiter's OWN lineage-taint re-check.
    #[serde(rename = "procKey", skip_serializing_if = "Option::is_none")]
    pub proc_key: Option<String>,
    /// sha256 (hex) of the exact stdout bytes returned to the harness. The HASH
    /// BINDING is what makes a wrong/forged correlation harmless: an upgrade
    /// requires the classified tool_result bytes to equal these bytes.
    #[serde(rename = "outputSha256", skip_serializing_if = "Option::is_none")]
    pub output_sha256: Option<String>,
    /// Supervisor audit note (which ruleset, how many read grants, …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "sessionKey", skip_serializing_if = "Option::is_none")]
    pub session_key: Option<String>,
}

/// The RESOLVED verdict the arbiter recorded. Mirrors `ExecCleanVerdict`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecCleanVerdict {
    #[serde(rename = "callId")]
    pub call_id: String,
    /// True only when every §5 gate passed at report time.
    pub clean: bool,
    /// Why clean, or the FIRST failing gate.
    pub reason: String,
    /// Present iff clean (classify hash-matches the tool_result against it).
    #[serde(rename = "outputSha256", default, skip_serializing_if = "Option::is_none")]
    pub output_sha256: Option<String>,
    #[serde(rename = "procKey", default, skip_serializing_if = "Option::is_none")]
    pub proc_key: Option<String>,
    #[serde(rename = "sessionKey", default, skip_serializing_if = "Option::is_none")]
    pub session_key: Option<String>,
    #[serde(default)]
    pub seq: i64,
}

/// `reportExecCleanVerdict` ⇒ what the report RESOLVED to post-gates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportExecCleanVerdictResult {
    pub verdict: ExecCleanVerdict,
}

/// `claimCleanReporter` ⇒ the reporter token (64 hex), issued once per session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimCleanReporterResult {
    pub token: String,
}

/// `execCleanVerdictFor` ⇒ the resolved verdict, or None on a miss.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecCleanVerdictForResult {
    pub verdict: Option<ExecCleanVerdict>,
}

// ── reportExecTwins (symbol-twin-shell-blindness.md §4.1 v2) ─────────────────

/// One path a boxed AgentShell leaf named whose AgentView twin consists solely
/// of `$MDU:` symbol tokens. Mirrors `arbiter/policy/exec-twin-store.ts`
/// `ExecTwinCandidate`. A HINT: the proxy re-applies the predicate under its
/// own view-map roots before it builds a note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecTwinCandidate {
    /// The path as the leaf's argv spelled it (the note's spelling).
    #[serde(rename = "asTyped")]
    pub as_typed: String,
    /// The absolute AgentView twin path (cwd-joined, under the root).
    pub abs: String,
}

/// What the exec box reports BEFORE it runs one AgentShell leaf. Mirrors
/// `ExecTwinReport`. Signature-keyed arbiter-side (a pipeline / post-`cd`
/// leaf has no callId of its own).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExecTwinReport {
    pub argv: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    pub twins: Vec<ExecTwinCandidate>,
    /// Path-like words the leaf named beyond those listed: symbolic twins past
    /// the report cap plus words past the scan bound. A COUNT only — the note
    /// says "N more file(s) not listed"; zero is omitted on the wire.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub more: u32,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// `reportExecTwins` ⇒ how many candidates the store kept.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportExecTwinsResult {
    pub recorded: u32,
}

// ── escalateExec (exec escalation gate, exec-routing.md §5) ────────────────────

/// Args for `escalateExec`: may an AgentShell command needing `resource` escalate
/// to HumanShell? `resource` is "network" | "original-fs".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalateExecArgs {
    pub argv: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    pub resource: String,
    #[serde(rename = "sessionKey", skip_serializing_if = "Option::is_none")]
    pub session_key: Option<String>,
}

/// `escalateExec` ⇒ the escalation verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalateExecResult {
    pub shell: ExecShell,
    pub approved: bool,
    #[serde(rename = "requiresApproval")]
    pub requires_approval: bool,
    pub reason: String,
}

// ── emit ────────────────────────────────────────────────────────────────────────

/// `emit` ⇒ the arbiter-assigned per-session monotonic seq for the stored event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmitResult {
    pub seq: i64,
}

// ── ping ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingResult {
    pub pong: bool,
    #[serde(rename = "protocolVersion")]
    pub protocol_version: u32,
}

pub const PROTOCOL_VERSION: u32 = 1;

/// `hello` — who answers this socket. Only the fields a client here reads:
/// the human-plane socket's path (arbiter-human-plane.md §5, for discovery),
/// the channel the answer came on (confidentiality plan 13 §3 D9: the guard
/// reports where it is believed, `human`), and the instance id (§5.1: a
/// re-learned human socket must belong to the instance the data socket
/// names). All absent on an older arbiter.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HelloResult {
    #[serde(rename = "humanSock", default)]
    pub human_sock: Option<String>,
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(rename = "instanceId", default)]
    pub instance_id: Option<String>,
}

// ── provenance (taint registry) — Plan 2 consumes Plan 1's arbiter ops ──────────

/// `taintProcess` request fields (flattened into the op envelope, not nested).
/// Mirrors `arbiter/ipc/protocol.ts` `TaintProcessOpRequest` (minus id/op).
/// Plan 10 §4.1: the interposer asks the arbiter what an open of a registered
/// secret path by this process should become. The arbiter DECIDES (readers,
/// pins, consumer table, ask mode) and, on `raw`, RECORDS the taint before it
/// answers, so the guard can inject the descriptor knowing the record exists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecideSecretOpenArgs {
    /// The canonical path the tracee is opening (a registered secret).
    pub path: String,
    /// `/proc/<pid>/exe` of the opener, resolved.
    pub exe: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(rename = "isAgent")]
    pub is_agent: bool,
    #[serde(rename = "procKey")]
    pub proc_key: String,
    /// The opener's parent, so a fork-only child gets its lineage edge at the
    /// moment it matters (plan 10 §4.2).
    #[serde(rename = "parentKey", skip_serializing_if = "Option::is_none")]
    pub parent_key: Option<String>,
    /// Plan 13 D7: the opener's live ancestor proc keys, nearest first,
    /// stopped below the guard. The arbiter records every edge (first edge
    /// winning), so a reader under a subshell that never exec'd is in its
    /// call's tree.
    #[serde(rename = "ancestorKeys", skip_serializing_if = "Option::is_none")]
    pub ancestor_keys: Option<Vec<String>>,
    /// Plan 13 D7, the orphan subshell: no agent process among the actor's
    /// live ancestors, and the topmost of them was re-parented to a reaper
    /// after the agent started: its key (the ORPHAN ROOT). The arbiter folds
    /// its tree into every tool call relayed no later than it was first seen.
    #[serde(rename = "orphanRoot", skip_serializing_if = "Option::is_none")]
    pub orphan_root: Option<String>,
    /// The opener's ancestor executables, nearest first (learn-from-nono
    /// §3.5): a reader with `from:` counts only under that app.
    #[serde(rename = "ancestorExes", skip_serializing_if = "Option::is_none")]
    pub ancestor_exes: Option<Vec<String>>,
    /// Plan 13 D8: one bit per `ancestor_exes` entry, same order: that
    /// ancestor's executable is out of the agent's reach (it and every
    /// directory above it unwritable by the agent's uid) and it runs with a
    /// clean loader environment. A `from:` reader counts only under a trusted
    /// ancestor. Absent = unknown: no `from:` reader matches.
    #[serde(rename = "ancestorTrusted", skip_serializing_if = "Option::is_none")]
    pub ancestor_trusted: Option<Vec<bool>>,
    /// Plan 13 D8: the opener's executable (the inode it runs) and every
    /// directory above its path are unwritable by the agent's uid, so the
    /// agent cannot have put it there. Only such a binary is pinned on first
    /// use; absent = unknown = not.
    #[serde(rename = "exeSystem", skip_serializing_if = "Option::is_none")]
    pub exe_system: Option<bool>,
    /// Plan 13 D8: the loader and interpreter variables (LD_PRELOAD,
    /// PYTHONPATH, NODE_OPTIONS, …) the opener runs with set to a value the
    /// launch did not give, by NAME (never the value), and `code:<path>` for
    /// an executable file mapped into it that the agent can write (a
    /// preloaded library; `IdentityCtx::findings`), `args:<program> <what>`
    /// for code its command line hands it, `runs:<family>` for a binary
    /// whose content is an interpreter's under a name that does not say so,
    /// and `pkg:<package>` for one whose content is a program of a package
    /// of printers or launchers (GNU coreutils, findutils, util-linux, …)
    /// under a name neither list knows (Plan 13 D8 (13)).
    /// Empty = checked and clean; absent = not checked: the opener is then
    /// no reader.
    #[serde(rename = "openerEnv", skip_serializing_if = "Option::is_none")]
    pub opener_env: Option<Vec<String>>,
    /// Plan 13 R5: for an opener that is a script interpreter (python, node,
    /// a shell, perl), the script it runs: its absolute canonical path, hash,
    /// whether it and its directories are out of the agent's reach, whether
    /// the interpreter is isolated from per-user code, and whether another
    /// process traces it. A reader entry naming a `script:` matches only on
    /// these. Absent for any other program.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script: Option<ScriptFactsWire>,
    /// Plan 13 R5: an interpreter that runs no script an entry could pin
    /// (inline code, a module, stdin, a relative path, …): why.
    #[serde(rename = "scriptProblem", skip_serializing_if = "Option::is_none")]
    pub script_problem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// The launch's prompting mode: known | always | never.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ask: Option<String>,
    /// Plan 10 §12.2: set on the guard's LAST ask of a held open, once its
    /// ceiling has passed. The arbiter records the unanswered hold as a
    /// denial (so the tool result's note can say "held: …", §11.8) and
    /// answers `deny`; the Inbox row stays pending for a later answer.
    #[serde(rename = "heldMs", skip_serializing_if = "Option::is_none")]
    pub held_ms: Option<u64>,
}

/// Plan 13 R5: the script an interpreter that opens a secret runs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScriptFactsWire {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub system: bool,
    pub isolated: bool,
    pub traced: bool,
}

/// confidentiality.md §4, "What Allow once means for a command": the
/// guard's question at a tool call's shell exec (the call root), before it
/// lets the exec go. Mirrors `SessionExecRootOpRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionExecRootArgs {
    #[serde(rename = "procKey")]
    pub proc_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}

/// `sessionExecRoot` result: `holder` ⇔ the session is HIGH and the
/// arbiter recorded the session's taint rows on the process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionExecRootResult {
    pub holder: bool,
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub reason: String,
}

/// confidentiality.md §4, "Without the guard": the session's guard
/// announces that it holds the session's processes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardAttachArgs {
    #[serde(rename = "sessionKey")]
    pub session_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardAttachResult {
    pub attached: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Plan 10 §4.3: where a tainted process may still connect.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaintedProcessBindingsArgs {
    #[serde(rename = "procKey")]
    pub proc_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ancestors: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// Plan 13 D2 (2026-10-02): processes whose taint reached this one
    /// through a descriptor (a pipe, a FIFO, an unnamed socket pair) or as
    /// the lost holders of an orphan. The arbiter takes the union of their
    /// taint with the process's own; no lineage edge is recorded for them.
    #[serde(rename = "flowsFrom", default, skip_serializing_if = "Option::is_none")]
    pub flows_from: Option<Vec<String>>,
    /// confidentiality.md §4, "A held command's refused connection"
    /// (2026-10-12): the destination the guard is about to refuse
    /// (`ip:port`, `[v6]:port`), named so the arbiter consults (and spends)
    /// the human's answer for the HIGH session's own network question, or
    /// files it. Believed on the human plane only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    /// Ask only the HIGH session's question, never a holder's send question
    /// (an address is not a host a file rule could take).
    #[serde(rename = "sessionAskOnly", default, skip_serializing_if = "Option::is_none")]
    pub session_ask_only: Option<bool>,
}

/// The human's answer (or the question filed) for a refused destination
/// (`TaintedProcessBindingsArgs::destination`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaintAsk {
    #[serde(rename = "approvalId")]
    pub approval_id: String,
    /// `pending` | `approved` | `denied`.
    pub status: String,
    #[serde(default)]
    pub scope: Option<String>,
    /// `session` (the HIGH session's network ask) | `holder`.
    #[serde(default)]
    pub question: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintedProcessBindings {
    pub tainted: bool,
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub files: Vec<String>,
    #[serde(default)]
    pub bindings: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ask: Option<TaintAsk>,
}

/// Plan 10 §4, filesystem exit: a tainted process wrote `path`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelWrittenPathTaintedArgs {
    pub path: String,
    #[serde(rename = "procKey")]
    pub proc_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ancestors: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// Plan 13 D2 (2026-10-02): processes whose taint reached this one
    /// through a descriptor (a pipe, a FIFO, an unnamed socket pair) or as
    /// the lost holders of an orphan. The arbiter takes the union of their
    /// taint with the process's own; no lineage edge is recorded for them.
    #[serde(rename = "flowsFrom", default, skip_serializing_if = "Option::is_none")]
    pub flows_from: Option<Vec<String>>,
}

/// Confidentiality plan 13 §9 R1 (and D2): `procKey` received the bytes of
/// the processes `flowsFrom` through a descriptor (a pipe, a FIFO, a socket
/// pair end, a connection to a holder's listener), so it holds what they
/// hold. The arbiter records it (no lineage edge) and unions their taint in
/// wherever it walks the process's taint, the model exit's fold included.
/// A record only ever adds taint; from the data socket it is a claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordProcessFlowArgs {
    #[serde(rename = "procKey")]
    pub proc_key: String,
    #[serde(rename = "flowsFrom")]
    pub flows_from: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}

/// `recordAgentFlow` — confidentiality plan 13 §4.5.1 (decision 2026-10-02:
/// mask, do not refuse): the AGENT process itself holds `channel` (its
/// socket, `socket:[ino]`), the other end of a connection a holder
/// (`flowsFrom`) accepted or held at its taint. The agent is never made a
/// holder (D2); the model exit masks what it received instead. `closed`:
/// the guard saw the agent no longer hold the channel (believed on the human
/// socket only). An open from the data socket is a claim (it only adds
/// masking).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordAgentFlowArgs {
    pub channel: String,
    #[serde(rename = "flowsFrom", skip_serializing_if = "Option::is_none")]
    pub flows_from: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}

/// `labelWrittenPathTainted`'s answer: whether the file now carries a
/// derived label, at which level.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LabelWrittenPathTaintedResult {
    #[serde(default)]
    pub labeled: bool,
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub reason: String,
}

/// Confidentiality plan 13 D4: the derived labels changed after `since` in
/// `epoch` (another epoch, or none, answers every row).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DerivedLabelsSinceArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
}

/// One derived label: the path and the level it classifies at now.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DerivedLabelRow {
    pub path: String,
    pub level: String,
}

/// `derivedLabelsSince`'s answer.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DerivedLabelsSince {
    #[serde(default)]
    pub epoch: String,
    #[serde(default)]
    pub gen: u64,
    #[serde(default)]
    pub labels: Vec<DerivedLabelRow>,
}

/// 2026-10-17 (confidentiality.md §6, "Read by a program the launch did not
/// see"): where the human labels above `public` lie, for the guard's gate of
/// a labelled file the launch did not register. `key`: the answer last seen
/// (an unchanged list answers `unchanged` and no rows).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LabelRootsSinceArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The guard's session: its launch HOME's catalog places are listed too
    /// (2026-10-17).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}

/// One catalog name anchor (2026-10-17, secret-catalog.ts `NameAnchor`): a
/// necessary condition on a file name for a catalog shape to match; every
/// field given must hold (`ci`: ASCII case folded).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct NameAnchorRow {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suffix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contains: Option<String>,
    /// The name ends in none of these (2026-10-17: the `*credentials*`
    /// shape's documentation and program-source extensions). No condition by
    /// itself.
    #[serde(rename = "notSuffixes", default, skip_serializing_if = "Vec::is_empty")]
    pub not_suffixes: Vec<String>,
    #[serde(default)]
    pub ci: bool,
}

/// The catalog's name prefilter (2026-10-17, confidentiality.md §6 "Read by
/// a program the launch did not see"): a regular file whose name meets one
/// of `names`, with no directory below the deepest of `homes` holding it
/// (below `/` outside every one) named in the walk's `skipDirs` or in
/// `skip_dirs` here, is a candidate the arbiter classifies (`labelledLevel`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct GuardCatalogRow {
    #[serde(default)]
    pub names: Vec<NameAnchorRow>,
    #[serde(default)]
    pub homes: Vec<String>,
    #[serde(rename = "skipDirs", default)]
    pub skip_dirs: Vec<String>,
}

/// The last segment of a pattern label, as two literal anchors: a name that
/// the pattern's last segment matches starts with `head` and ends with
/// `tail` (`exact`: is exactly `head`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct LabelShapeRow {
    #[serde(default)]
    pub head: String,
    #[serde(default)]
    pub tail: String,
    #[serde(default)]
    pub exact: bool,
}

/// One label root: a literal label's path, or a pattern's literal directory
/// prefix (`/` when it has none) with the shape of its last segment (absent:
/// any file below the root may be labelled).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LabelRootRow {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape: Option<LabelShapeRow>,
}

/// `labelRootsSince`'s answer.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LabelRootsSince {
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub unchanged: bool,
    #[serde(default)]
    pub roots: Vec<LabelRootRow>,
    /// The directory names the discovery walk never enters: a file below a
    /// root inside one is not gated (the walk would not have registered it).
    #[serde(rename = "skipDirs", default)]
    pub skip_dirs: Vec<String>,
    /// The catalog's name prefilter (absent: an arbiter older than it, or an
    /// unchanged answer, which keeps the one in force).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog: Option<GuardCatalogRow>,
}

/// `labelledLevel`: the level `path` classifies at now (labels, then the
/// catalog; the session's launch HOME as `decideSecretOpen` reads it).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelledLevelArgs {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// 2026-10-17 (confidentiality.md §6, "The base follows the shell"): the
    /// AGENT process itself opened `path` for reading. The arbiter records a
    /// file above `public` (human plane only) for the classify of the file
    /// tool that named it by a relative path. An older arbiter ignores it.
    #[serde(rename = "agentOpen", default, skip_serializing_if = "Option::is_none")]
    pub agent_open: Option<bool>,
}

/// `labelledLevel`'s answer: the level (`public` for a file no label or
/// catalog rule covers) and the label roots' key it was decided under.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct LabelledLevel {
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub key: String,
    /// With `agentOpen`: the arbiter recorded the open (an older one never
    /// says so).
    #[serde(default)]
    pub recorded: bool,
}

/// Confidentiality plan 13 D4: the derived label of `from` follows its file
/// to `to` (`how`: rename | link | identity).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FollowDerivedLabelArgs {
    pub from: String,
    pub to: String,
    pub how: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}

/// `followDerivedLabel`'s answer.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FollowDerivedLabelResult {
    #[serde(default)]
    pub labeled: bool,
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub reason: String,
}

/// `registerSecret`: the arbiter reads the file and mints its symbol (and
/// its structured twin, when the file has a known shape). The bytes never
/// leave the arbiter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterSecretArgs {
    pub path: String,
}

/// `registerSecret`'s answer: no symbol when the file is not a secret,
/// unreadable or empty (`reason`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegisterSecretResult {
    #[serde(default)]
    pub symbol: Option<String>,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub twin: Option<String>,
    #[serde(default)]
    pub terminator: Option<String>,
}

/// Plan 10 §4.2: a process in the agent tree exec'd. The arbiter records the
/// lineage edge and the argv's exec signature, so a tool call can be matched
/// to its root process later (`callTaint` by signature).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordExecRootArgs {
    #[serde(rename = "procKey")]
    pub proc_key: String,
    #[serde(rename = "parentKey", skip_serializing_if = "Option::is_none")]
    pub parent_key: Option<String>,
    /// Plan 13 D7: the exec'ing process's live ancestor proc keys, nearest
    /// first (the parent first), read before the exec was let go and stopped
    /// below the guard: every edge is recorded, so a subshell that never
    /// execs is linked to its parent through the first exec below it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ancestors: Option<Vec<String>>,
    pub argv: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// Plan 13 D7: the exec'ing process is a direct child of the agent (the
    /// shell the agent runs one tool call in): a candidate root for the
    /// call whose command it carries (the arbiter's call-root recorder).
    #[serde(rename = "callRoot", skip_serializing_if = "Option::is_none")]
    pub call_root: Option<bool>,
    /// 2026-10-04 (confidentiality.md §6): the exec'ing process's working
    /// directory as the kernel names it (`/proc/<pid>/cwd`), read while the
    /// exec was suspended. Sent with `call_root` only: the directory a bound
    /// call's relative path tokens are read in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Plan 13 D7, the orphan subshell: no agent process among the actor's
    /// live ancestors, and the topmost of them was re-parented to a reaper
    /// after the agent started: its key (the ORPHAN ROOT). The arbiter folds
    /// its tree into every tool call relayed no later than it was first seen.
    #[serde(rename = "orphanRoot", skip_serializing_if = "Option::is_none")]
    pub orphan_root: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretOpenVerdict {
    /// raw | twin | deny | ask
    pub verdict: String,
    #[serde(default)]
    pub app: String,
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub reason: String,
    #[serde(rename = "pinNeeded", default)]
    pub pin_needed: bool,
    /// `ask`: the Inbox row; the guard re-asks until it resolves (§11.1).
    #[serde(rename = "approvalId", default)]
    pub approval_id: Option<String>,
}

/// `decideProtectedWrite` request (sandbox-security-review-2026-09-28
/// finding 6): a program in the agent's tree wants to change a file under an
/// `ask` write-protect entry (a shell startup file, a systemd user unit, a git
/// hook). The arbiter answers from a prior human verdict for (program, file),
/// or files an Inbox row and answers `ask` (the guard holds the call and asks
/// again); with `heldMs` set, the hold's ceiling passed and the answer is
/// `deny`. Mirrors `DecideProtectedWriteOpRequest`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DecideProtectedWriteArgs {
    /// The path being changed (created, written, renamed, linked, removed).
    pub path: String,
    /// `/proc/<pid>/exe` of the writer, resolved.
    pub exe: String,
    /// The writer's identity facts, as `DecideSecretOpenArgs` reports an
    /// opener's (write-protection.md §2.1, the Plan 13 D8 follow-up): the
    /// human's verdict is keyed by the binary's path and hash, and a writer
    /// whose `opener_env` is absent or not empty is refused without a prompt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(rename = "exeSystem", skip_serializing_if = "Option::is_none")]
    pub exe_system: Option<bool>,
    #[serde(rename = "openerEnv", skip_serializing_if = "Option::is_none")]
    pub opener_env: Option<Vec<String>>,
    /// Plan 13 §8 decision (c): for a writer that is a script interpreter, the
    /// script it runs (as `DecideSecretOpenArgs::script`): the verdict then
    /// names the script too. Absent for any other program.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script: Option<ScriptFactsWire>,
    /// Plan 13 §8 decision (c): an interpreter writer running no script a pin
    /// could name (inline code, stdin, …): why. Its verdict names its run.
    #[serde(rename = "scriptProblem", skip_serializing_if = "Option::is_none")]
    pub script_problem: Option<String>,
    #[serde(rename = "procKey")]
    pub proc_key: String,
    /// The protected entry's label ("a shell startup file").
    #[serde(default)]
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    #[serde(rename = "heldMs", skip_serializing_if = "Option::is_none")]
    pub held_ms: Option<u64>,
}

/// `registerRepository` (confidentiality-plan-14 §11.1 R1): an absolute path
/// in the work tree to register.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegisterRepositoryArgs {
    pub root: String,
}

/// `registerRepository` result.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegisterRepositoryResult {
    pub axis: bool,
    /// The work-tree root registered (real path); null with the axis OFF.
    #[serde(default)]
    pub root: Option<String>,
    /// False when it was already known (renewed) or the axis is OFF.
    #[serde(default)]
    pub added: bool,
    /// Repositories the registry knows.
    #[serde(default)]
    pub known: u64,
}

/// `readerProgram` request (Plan 13 D8, 2026-10-03): what the arbiter knows
/// a binary to be, by its name and path and by the hashes of the host's
/// installed programs. The guard asks it for a secret socket's reader.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReaderProgramArgs {
    /// The resolved executable.
    pub exe: String,
    /// sha256 of the inode it runs, hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// `readerProgram` result.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReaderProgramResult {
    /// A printer, by name or path or a byte-identical copy of an installed one.
    #[serde(default)]
    pub prints: bool,
    /// A program that runs code it is given, likewise.
    #[serde(rename = "runsCode", default)]
    pub runs_code: bool,
    /// The installed program a renamed copy is, byte for byte.
    #[serde(rename = "copyOf", default)]
    pub copy_of: Option<String>,
}

/// `decideProtectedWrite` result.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProtectedWriteVerdict {
    /// allow | deny | ask (anything else is refused by the guard)
    pub verdict: String,
    #[serde(default)]
    pub reason: String,
    #[serde(rename = "approvalId", default)]
    pub approval_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TaintProcessArgs {
    #[serde(rename = "procKey")]
    pub proc_key: String,
    #[serde(rename = "originHost")]
    pub origin_host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}

/// `processLineage` request fields. Mirrors `ProcessLineageOpRequest`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcessLineageArgs {
    #[serde(rename = "childKey")]
    pub child_key: String,
    #[serde(rename = "parentKey")]
    pub parent_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}

/// `isProcessTainted` request fields. Mirrors `IsProcessTaintedOpRequest`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IsProcessTaintedArgs {
    #[serde(rename = "procKey")]
    pub proc_key: String,
}

/// `isProcessTainted` result. Mirrors `IsProcessTaintedResult`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsProcessTaintedResult {
    pub tainted: bool,
    #[serde(rename = "originHost")]
    pub origin_host: Option<String>,
}

/// `taintFile` request fields. Mirrors `TaintFileOpRequest`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TaintFileArgs {
    #[serde(rename = "contentHash")]
    pub content_hash: String,
    pub path: String,
    #[serde(rename = "originHost")]
    pub origin_host: String,
    #[serde(rename = "writerProc", skip_serializing_if = "Option::is_none")]
    pub writer_proc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}

/// `fileTrust` request fields. Mirrors `FileTrustOpRequest`. Dual-keyed: either
/// content-hash OR path may be supplied; the arbiter returns untrusted if EITHER
/// matches (fail-closed).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileTrustArgs {
    #[serde(rename = "contentHash", skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// `fileTrust` result. Mirrors `FileTrustResult`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTrustResult {
    pub untrusted: bool,
    pub origin: Option<String>,
}

#[cfg(test)]
mod provenance_protocol_tests {
    use super::*;

    #[test]
    fn decide_secret_open_carries_ancestor_exes_camelcase() {
        let v = serde_json::to_value(DecideSecretOpenArgs {
            path: "/h/.ssh/id_ed25519".into(),
            exe: "/usr/bin/ssh".into(),
            sha256: None,
            is_agent: false,
            proc_key: "7-1".into(),
            parent_key: None,
            ancestor_keys: Some(vec!["6-1".into(), "5-1".into()]),
            orphan_root: Some("5-1".into()),
            ancestor_exes: Some(vec!["/usr/bin/git".into()]),
            ancestor_trusted: Some(vec![true]),
            exe_system: Some(true),
            opener_env: Some(vec!["LD_PRELOAD".into()]),
            script: None,
            script_problem: None,
            session: None,
            ask: None,
            held_ms: None,
        })
        .unwrap();
        assert!(v.get("script").is_none() && v.get("scriptProblem").is_none(), "no script facts for a program that is no interpreter");
        assert_eq!(v["ancestorKeys"], serde_json::json!(["6-1", "5-1"]));
        assert_eq!(v["orphanRoot"], "5-1");
        assert_eq!(v["ancestorExes"], serde_json::json!(["/usr/bin/git"]));
        assert_eq!(v["ancestorTrusted"], serde_json::json!([true]));
        assert_eq!(v["exeSystem"], serde_json::json!(true));
        assert_eq!(v["openerEnv"], serde_json::json!(["LD_PRELOAD"]));
    }

    #[test]
    fn decide_secret_open_carries_the_script_facts_camelcase() {
        let v = serde_json::to_value(DecideSecretOpenArgs {
            path: "/h/.pgpass".into(),
            exe: "/usr/bin/python3.12".into(),
            sha256: None,
            is_agent: false,
            proc_key: "7-1".into(),
            parent_key: None,
            ancestor_keys: None,
            orphan_root: None,
            ancestor_exes: None,
            ancestor_trusted: None,
            exe_system: Some(true),
            opener_env: Some(vec![]),
            script: Some(ScriptFactsWire { path: "/opt/t/r.py".into(), sha256: Some("cd".repeat(32)), system: true, isolated: true, traced: false }),
            script_problem: Some("inline code (python -c)".into()),
            session: None,
            ask: None,
            held_ms: None,
        })
        .unwrap();
        assert_eq!(v["script"], serde_json::json!({"path": "/opt/t/r.py", "sha256": "cd".repeat(32), "system": true, "isolated": true, "traced": false}));
        assert_eq!(v["scriptProblem"], "inline code (python -c)");
    }

    #[test]
    fn reader_program_args_and_result_use_the_arbiters_names() {
        let v = serde_json::to_value(ReaderProgramArgs { exe: "/usr/bin/perl5.40.1".into(), sha256: Some("ab".repeat(32)) }).unwrap();
        assert_eq!(v, serde_json::json!({"exe": "/usr/bin/perl5.40.1", "sha256": "ab".repeat(32)}));
        assert!(serde_json::to_value(ReaderProgramArgs { exe: "/x".into(), sha256: None }).unwrap().get("sha256").is_none());
        let r: ReaderProgramResult = serde_json::from_value(serde_json::json!({"prints": false, "runsCode": true, "copyOf": "perl"})).unwrap();
        assert!(!r.prints && r.runs_code && r.copy_of.as_deref() == Some("perl"));
        let r: ReaderProgramResult = serde_json::from_value(serde_json::json!({"prints": false, "runsCode": false, "copyOf": null})).unwrap();
        assert!(!r.prints && !r.runs_code && r.copy_of.is_none());
    }

    #[test]
    fn decide_protected_write_args_serialize_camelcase() {
        let v = serde_json::to_value(DecideProtectedWriteArgs {
            path: "/h/.bashrc".into(),
            exe: "/usr/bin/bash".into(),
            sha256: Some("ab".repeat(32)),
            exe_system: Some(true),
            opener_env: Some(vec!["LD_PRELOAD".into()]),
            script: Some(ScriptFactsWire { path: "/opt/t/fix.py".into(), sha256: Some("cd".repeat(32)), system: true, isolated: true, traced: false }),
            script_problem: None,
            proc_key: "7-1".into(),
            label: "a shell startup file".into(),
            session: None,
            held_ms: Some(60_000),
        })
        .unwrap();
        // Plan 13 §8 decision (c): the writer's script, under the arbiter's names.
        assert_eq!(v["script"], serde_json::json!({"path": "/opt/t/fix.py", "sha256": "cd".repeat(32), "system": true, "isolated": true, "traced": false}));
        assert!(v.get("scriptProblem").is_none());
        let inline = serde_json::to_value(DecideProtectedWriteArgs { path: "/h/.bashrc".into(), exe: "/usr/bin/bash".into(), script_problem: Some("inline code (sh -c)".into()), ..Default::default() }).unwrap();
        assert_eq!(inline["scriptProblem"], "inline code (sh -c)");
        assert!(inline.get("script").is_none());
        assert_eq!(v["procKey"], "7-1");
        assert_eq!(v["heldMs"], 60_000);
        assert!(v.get("session").is_none());
        // The D8 follow-up's identity facts, under the arbiter's names.
        assert_eq!(v["sha256"], "ab".repeat(32));
        assert_eq!(v["exeSystem"], true);
        assert_eq!(v["openerEnv"], serde_json::json!(["LD_PRELOAD"]));
        let bare = serde_json::to_value(DecideProtectedWriteArgs { path: "/h/.bashrc".into(), exe: "/usr/bin/bash".into(), ..Default::default() }).unwrap();
        assert!(bare.get("openerEnv").is_none(), "unchecked is absent, never an empty (clean) list");
        let back: ProtectedWriteVerdict = serde_json::from_value(serde_json::json!({"verdict": "ask", "reason": "held", "approvalId": "a1"})).unwrap();
        assert_eq!((back.verdict.as_str(), back.approval_id.as_deref()), ("ask", Some("a1")));
    }

    #[test]
    fn record_process_flow_args_serialize_camelcase() {
        // Plan 13 §9 R1: the arbiter's `recordProcessFlow` reads these names.
        let v = serde_json::to_value(RecordProcessFlowArgs {
            proc_key: "2001-77".into(),
            flows_from: vec!["1999-70".into()],
            session: None,
        })
        .unwrap();
        assert_eq!(v["procKey"], "2001-77");
        assert_eq!(v["flowsFrom"], serde_json::json!(["1999-70"]));
        assert!(v.get("session").is_none(), "no session: omitted");
    }

    #[test]
    fn record_agent_flow_args_serialize_camelcase() {
        // Plan 13 §4.5.1: the arbiter's `recordAgentFlow` reads these names;
        // a close carries no flowsFrom.
        let v = serde_json::to_value(RecordAgentFlowArgs {
            channel: "socket:[4242]".into(),
            flows_from: Some(vec!["1999-70".into()]),
            closed: None,
            session: Some("s1".into()),
        })
        .unwrap();
        assert_eq!(v["channel"], "socket:[4242]");
        assert_eq!(v["flowsFrom"], serde_json::json!(["1999-70"]));
        assert_eq!(v["session"], "s1");
        assert!(v.get("closed").is_none());
        let c = serde_json::to_value(RecordAgentFlowArgs { channel: "socket:[4242]".into(), flows_from: None, closed: Some(true), session: None }).unwrap();
        assert_eq!(c["closed"], true);
        assert!(c.get("flowsFrom").is_none() && c.get("session").is_none());
    }

    #[test]
    fn labelled_level_agent_open_serializes_camelcase_and_an_older_answer_reads_unrecorded() {
        // 2026-10-17 (confidentiality.md §6, "The base follows the shell"):
        // the arbiter's `labelledLevel` reads `agentOpen`; the guard's own
        // gate asks without it.
        let v = serde_json::to_value(LabelledLevelArgs { path: "/w/vault/plan.md".into(), session: Some("s1".into()), agent_open: Some(true) }).unwrap();
        assert_eq!(v["path"], "/w/vault/plan.md");
        assert_eq!(v["agentOpen"], true);
        let g = serde_json::to_value(LabelledLevelArgs { path: "/w/x".into(), session: None, agent_open: None }).unwrap();
        assert!(g.get("agentOpen").is_none() && g.get("session").is_none());
        let r: LabelledLevel = serde_json::from_value(serde_json::json!({ "level": "no-model", "key": "k", "recorded": true })).unwrap();
        assert!(r.recorded && r.level == "no-model");
        let old: LabelledLevel = serde_json::from_value(serde_json::json!({ "level": "no-model", "key": "k" })).unwrap();
        assert!(!old.recorded, "an older arbiter never says it recorded the open");
    }

    #[test]
    fn taint_process_args_serialize_camelcase() {
        let v = serde_json::to_value(TaintProcessArgs {
            proc_key: "1234-9".into(),
            origin_host: "evil.example".into(),
            session: Some("s1".into()),
        })
        .unwrap();
        assert_eq!(v["procKey"], "1234-9");
        assert_eq!(v["originHost"], "evil.example");
        assert_eq!(v["session"], "s1");
    }

    #[test]
    fn taint_process_args_omit_none_session() {
        let v = serde_json::to_value(TaintProcessArgs {
            proc_key: "1234-9".into(),
            origin_host: "evil.example".into(),
            session: None,
        })
        .unwrap();
        assert!(v.get("session").is_none());
    }

    #[test]
    fn process_lineage_args_serialize_camelcase() {
        let v = serde_json::to_value(ProcessLineageArgs {
            child_key: "curl-2".into(),
            parent_key: "bash-1".into(),
            session: None,
        })
        .unwrap();
        assert_eq!(v["childKey"], "curl-2");
        assert_eq!(v["parentKey"], "bash-1");
        assert!(v.get("session").is_none());
    }

    #[test]
    fn record_exec_root_args_carry_the_chain_and_call_root_camelcase() {
        let v = serde_json::to_value(RecordExecRootArgs {
            proc_key: "9-1".into(),
            parent_key: Some("8-1".into()),
            ancestors: Some(vec!["8-1".into(), "7-1".into()]),
            argv: vec!["bash".into(), "-lc".into(), "ls".into()],
            session: Some("s".into()),
            call_root: Some(true),
            cwd: Some("/w/proj".into()),
            orphan_root: Some("7-1".into()),
        })
        .unwrap();
        assert_eq!(v["ancestors"], serde_json::json!(["8-1", "7-1"]));
        assert_eq!(v["callRoot"], serde_json::json!(true));
        assert_eq!(v["cwd"], "/w/proj");
        assert_eq!(v["orphanRoot"], "7-1");
        let bare = serde_json::to_value(RecordExecRootArgs { proc_key: "9-1".into(), parent_key: None, ancestors: None, argv: vec![], session: None, call_root: None, cwd: None, orphan_root: None }).unwrap();
        assert!(bare.get("callRoot").is_none() && bare.get("ancestors").is_none() && bare.get("orphanRoot").is_none() && bare.get("cwd").is_none());
    }

    #[test]
    fn a_held_connect_names_its_address_and_reads_the_answer() {
        // confidentiality.md §4 (2026-10-12): the guard's held-connect ask.
        let v = serde_json::to_value(TaintedProcessBindingsArgs {
            proc_key: "9-1".into(),
            destination: Some("203.0.113.9:443".into()),
            session_ask_only: Some(true),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(v["destination"], "203.0.113.9:443");
        assert_eq!(v["sessionAskOnly"], serde_json::json!(true));
        let bare = serde_json::to_value(TaintedProcessBindingsArgs { proc_key: "9-1".into(), ..Default::default() }).unwrap();
        assert!(bare.get("destination").is_none() && bare.get("sessionAskOnly").is_none(), "the plain question names neither");
        let r: TaintedProcessBindings = serde_json::from_value(serde_json::json!({
            "tainted": true, "level": "any-model", "files": ["/m/q3.md"], "bindings": ["docs.corp"],
            "ask": { "approvalId": "egr-3", "status": "approved", "scope": "once", "question": "session" }
        }))
        .unwrap();
        let ask = r.ask.unwrap();
        assert_eq!((ask.approval_id.as_str(), ask.status.as_str(), ask.question.as_deref()), ("egr-3", "approved", Some("session")));
        let older: TaintedProcessBindings = serde_json::from_value(serde_json::json!({ "tainted": true, "files": [], "bindings": [] })).unwrap();
        assert!(older.ask.is_none(), "an answer with no ask reads as none");
    }

    #[test]
    fn is_process_tainted_result_deserializes() {
        let r: IsProcessTaintedResult =
            serde_json::from_value(serde_json::json!({ "tainted": true, "originHost": "evil.example" }))
                .unwrap();
        assert!(r.tainted);
        assert_eq!(r.origin_host.as_deref(), Some("evil.example"));

        let r2: IsProcessTaintedResult =
            serde_json::from_value(serde_json::json!({ "tainted": false })).unwrap();
        assert!(!r2.tainted);
        assert!(r2.origin_host.is_none());
    }

    #[test]
    fn taint_file_args_serialize_camelcase() {
        let v = serde_json::to_value(TaintFileArgs {
            content_hash: "abc123".into(),
            path: "/tmp/setup.md".into(),
            origin_host: "example.test".into(),
            writer_proc: Some("curl-2".into()),
            session: None,
        })
        .unwrap();
        assert_eq!(v["contentHash"], "abc123");
        assert_eq!(v["path"], "/tmp/setup.md");
        assert_eq!(v["originHost"], "example.test");
        assert_eq!(v["writerProc"], "curl-2");
        assert!(v.get("session").is_none());
    }

    #[test]
    fn file_trust_args_serialize_camelcase() {
        let v = serde_json::to_value(FileTrustArgs {
            content_hash: Some("abc123".into()),
            path: None,
        })
        .unwrap();
        assert_eq!(v["contentHash"], "abc123");
        assert!(v.get("path").is_none());
    }

    #[test]
    fn file_trust_result_deserializes() {
        let r: FileTrustResult =
            serde_json::from_value(serde_json::json!({ "untrusted": true, "origin": "example.test" }))
                .unwrap();
        assert!(r.untrusted);
        assert_eq!(r.origin.as_deref(), Some("example.test"));

        let r2: FileTrustResult =
            serde_json::from_value(serde_json::json!({ "untrusted": false })).unwrap();
        assert!(!r2.untrusted);
        assert!(r2.origin.is_none());
    }

    #[test]
    fn hello_reads_the_human_socket_and_the_channel_and_tolerates_an_older_arbiter() {
        // plan 13 D9: the guard finds the human plane and checks it reports there
        let r: HelloResult = serde_json::from_value(serde_json::json!({
            "pid": 7, "sockPath": "/run/a.sock", "humanSock": "/run/human/i.sock", "channel": "data", "protocolVersion": 1
        }))
        .unwrap();
        assert_eq!(r.human_sock.as_deref(), Some("/run/human/i.sock"));
        assert_eq!(r.channel.as_deref(), Some("data"));
        let old: HelloResult = serde_json::from_value(serde_json::json!({ "pid": 7, "humanSock": null })).unwrap();
        assert!(old.human_sock.is_none() && old.channel.is_none());
    }
}
