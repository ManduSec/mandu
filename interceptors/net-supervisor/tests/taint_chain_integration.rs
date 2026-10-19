//! taint_chain_integration — the ACTIVATION oracle (Plan 6 §5 / spec §7 #1 / #4).
//!
//! With proc-key attribution wired across net/exec/fs (Plan 6 Tasks 1–4), prove
//! the taint CHAIN flows through the SHARED arbiter registry + the SHARED proc-key
//! format:
//!
//!   net:  ingress_transform(proc_key="P") → taintProcess → arbiter marks P as tainted
//!   fs:   record_file_taint_if_tainted(proc_key="P") → isProcessTainted hits → taintFile
//!   fs:   fs_inbound_trust(path) → fileTrust hits → UNTRUSTED + SYMBOL
//!   net:  egress_transform(proc_key="P", dest=untrusted) → tainted→untrusted → WITHHELD
//!
//! Uses a MockArbiter whose handler carries an in-memory taint registry so that
//! taint SET by the net path (taintProcess op) is READ by the fs path
//! (isProcessTainted op) and the egress gate — proving the chain crosses two
//! chokepoints via the shared proc key + the shared (mock) arbiter registry. A mock
//! is sufficient here because the individual real-arbiter integration tests live in
//! the tests/stack/ suites; THIS test proves the WIRE FORMAT of the cross-layer
//! contract (the ops + the proc-key string shape) are correctly threaded through the
//! transform functions.
//!
//! `#[ignore]`d + `--features kernel`: the test body is pure (no kernel calls), but
//! the `#[cfg(feature = "kernel")]` guard ensures it is NEVER compiled or run in the
//! default (unprivileged) suite — matching the "kernel-gated live chain" posture of
//! Tasks 2–4. Run:
//!
//!   unshare --user --map-root-user --net --mount --pid --fork -- \
//!     bash -c 'cd interceptors && cargo test -p net-supervisor --features kernel \
//!                --test taint_chain_integration -- --ignored --nocapture'
//!
//! (The `unshare` wrapper is not required for the MockArbiter path — a plain
//! `cargo test ... --features kernel -- --ignored` also works — but the run command
//! matches the canonical "full kernel path" recipe so CI can graduate to real
//! kernel/TPROXY components without changing the run command.)

#![cfg(feature = "kernel")]

use std::sync::{Arc, Mutex};

use mandu_arbiter::mock::{op_handler, MockArbiter};
use mandu_arbiter::proc::proc_key_for_pid;
use mandu_arbiter::ArbiterClient;
use net_supervisor::transform::{egress_transform, ingress_transform};

// ── Shared in-memory arbiter state ────────────────────────────────────────────

/// The state the mock arbiter carries across calls. Two cells:
///   • `tainted_procs`: set of proc_keys the arbiter has been told are tainted
///     (written by `taintProcess`, read by `isProcessTainted`).
///   • `tainted_files`: set of paths the arbiter has been told are tainted
///     (written by `taintFile`, read by `fileTrust`).
///
/// IMPORTANT: both are mutated and read by the SAME shared arbiter so that taint
/// set by the net path is visible to the fs path — that cross-call visibility is
/// exactly what this oracle proves.
#[derive(Default)]
struct ArbiterState {
    tainted_procs: std::collections::HashSet<String>,
    tainted_files: std::collections::HashSet<String>,
    taint_file_calls: Vec<String>, // log of paths passed to `taintFile`
}

fn chain_arbiter() -> (MockArbiter, Arc<Mutex<ArbiterState>>) {
    let state: Arc<Mutex<ArbiterState>> = Arc::new(Mutex::new(ArbiterState::default()));
    let state2 = state.clone();
    let arbiter = MockArbiter::start(op_handler(move |op, req| {
        let mut st = state2.lock().unwrap();
        match op {
            // ── classify: branch on the boundary so the fs leg proves fileTrust is
            // load-bearing.  If filesystem→TRUSTED, the ONLY way fs_inbound_trust
            // can return UNTRUSTED+symbol is via the fileTrust taint leg (design §4.1:
            // "trusted path + tainted writer → symbol via taint").  An always-UNTRUSTED
            // classify would mask the taint entirely: the classify_untrusted flag alone
            // would satisfy fs_inbound_trust, so the fileTrust lookup would be redundant
            // and the chain assertion would pass even if taintFile was never called.
            //   • network   → UNTRUSTED: net ingress still triggers taintProcess (unchanged).
            //   • filesystem → TRUSTED:  taint (fileTrust) is the SOLE untrusted signal.
            //   • other     → UNTRUSTED: safe default (fail-closed).
            "classify" => {
                let boundary = req
                    .get("request")
                    .and_then(|r| r.get("boundary"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let (trust, reason) = if boundary == "filesystem" {
                    ("TRUSTED", "test: trusted path — only fileTrust taint can flip UNTRUSTED")
                } else {
                    ("UNTRUSTED", "test: untrusted origin")
                };
                Ok(serde_json::json!({
                    "trust": trust,
                    "category": "HTTP",
                    "reason": reason
                }))
            }
            // ── net ingress symbolize → returns a symbol string
            "symbolize" => {
                let origin = req.get("origin").and_then(|v| v.as_str()).unwrap_or("unknown");
                Ok(serde_json::json!({
                    "symbol": format!("$MDU:web_fetch[{:08x}].body",
                        stable_tag_u32(origin))
                }))
            }
            // ── net ingress taintProcess: mark the proc_key tainted
            "taintProcess" => {
                let pk = req.get("procKey").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if !pk.is_empty() {
                    st.tainted_procs.insert(pk);
                }
                Ok(serde_json::json!({ "ok": true }))
            }
            // ── fs / egress isProcessTainted: check against the in-memory set
            "isProcessTainted" => {
                let pk = req.get("procKey").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let tainted = st.tainted_procs.contains(&pk);
                let origin = if tainted { Some("evil.test") } else { None };
                Ok(serde_json::json!({
                    "tainted": tainted,
                    "originHost": origin
                }))
            }
            // ── fs taintFile: record the path
            "taintFile" => {
                let path = req.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if !path.is_empty() {
                    st.tainted_files.insert(path.clone());
                    st.taint_file_calls.push(path);
                }
                Ok(serde_json::json!({ "ok": true }))
            }
            // ── fs fileTrust: check against the in-memory set
            "fileTrust" => {
                let path = req.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let untrusted = st.tainted_files.contains(&path);
                let origin = if untrusted { Some("evil.test") } else { None };
                Ok(serde_json::json!({
                    "untrusted": untrusted,
                    "origin": origin
                }))
            }
            // ── egress desymbolizationDecision (symbol gate): deny if destination untrusted
            "desymbolizationDecision" => Ok(serde_json::json!({
                "allow": false,
                "requiresApproval": true,
                "reason": "untrusted destination"
            })),
            other => Err(format!("unexpected op {other} in chain_arbiter")),
        }
    }));
    (arbiter, state)
}

/// Tiny FNV-1a 32-bit hash for a stable symbol tag (mirrors transform.rs).
fn stable_tag_u32(s: &str) -> u32 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x00000100000001b3);
    }
    (h & 0xffffffff) as u32
}

// ── Test 1: net → fs (chain re-trace) ────────────────────────────────────────

/// NET → FS taint chain re-trace (the ACTIVATION oracle, spec §7 #1):
///
/// 1. A process P (this test process, proc key = current pid + starttime) connects
///    to an untrusted host. `ingress_transform` classifies the response UNTRUSTED,
///    symbolizes it, and calls `taintProcess(P_key)` on the mock arbiter (which sets
///    P as tainted in the shared state).
///
/// 2. The FS path: `record_file_taint_if_tainted` is called for a tracked file
///    written by P. The mock arbiter's `isProcessTainted(P_key)` → true (because
///    step 1 set it), so `taintFile(path)` is called and the mock registers the
///    file as tainted.
///
/// 3. A later READ: `fs_inbound_trust` calls `fileTrust(path)` → untrusted=true
///    (because step 2 registered it) and then `symbolize` → symbol. The result
///    carries Trust::Untrusted AND a Some(symbol).
///
/// LOAD-BEARING ASSERTIONS:
///   (a) ingress_transform returned a symbol (not raw), AND
///   (b) record_file_taint_if_tainted returned true (file was tainted), AND
///   (c) fs_inbound_trust returned Trust::Untrusted + Some(symbol).
///
/// The chain from net→fs crossed two chokepoints via the SHARED arbiter state
/// (taintProcess set by net, read back as isProcessTainted by fs) — this is what
/// "the chain is live" means.
#[test]
#[ignore = "live taint chain oracle (Plan 6 §5): needs --features kernel; run: cargo test -p net-supervisor --features kernel --test taint_chain_integration -- --ignored --nocapture"]
fn net_taints_process_then_fs_read_returns_symbol() {
    let (arbiter, state) = chain_arbiter();

    // ── P's proc key: THIS test process, using the shared format (${pid}-${starttime}).
    let proc_key = proc_key_for_pid(std::process::id() as i32)
        .expect("proc_key_for_pid(self) must succeed — /proc/self/stat is always readable");
    // Sanity: proc key has the right shape `${pid}-${starttime}`.
    assert!(
        is_pid_dash(proc_key.as_str()),
        "proc_key must be `${{pid}}-${{starttime}}`, got: {proc_key}"
    );
    assert!(
        proc_key.starts_with(&format!("{}-", std::process::id())),
        "proc_key must start with this pid; got: {proc_key}"
    );

    // Use ONE shared ArbiterClient throughout: the MockArbiter's listener processes one
    // persistent connection at a time (single-threaded accept loop), so all calls in
    // this test must flow over the same connection to avoid deadlock.
    let mut client = ArbiterClient::new(&arbiter.socket_path);

    // ── STEP 1: net ingress — simulate P receiving a response from an untrusted host.
    //    Plan 7: ingress_transform classifies UNTRUSTED, returns the body RAW (no
    //    symbolization), and calls taintProcess (observe-and-tag). The TAINT — not a
    //    symbol — is what drives the rest of the chain.
    let ingress = ingress_transform(
        &mut client,
        "web_fetch",
        "evil.test",           // untrusted origin host
        "raw-untrusted-bytes", // the response body
        Some(proc_key.as_str()),
    );

    // ASSERT (a): Plan 7 — ingress is classified UNTRUSTED, returns the RAW body
    //             (no symbol), and tags the process (observe-and-tag).
    assert_eq!(
        ingress.trust,
        mandu_arbiter::protocol::Trust::Untrusted,
        "ingress from untrusted host must be classified UNTRUSTED"
    );
    assert!(
        ingress.symbol.is_none(),
        "Plan 7: net ingress no longer symbolizes — symbol must be None, got: {:?}",
        ingress.symbol
    );
    assert!(
        ingress.agent_visible.contains("raw-untrusted-bytes"),
        "Plan 7: net ingress returns the RAW body; got: {:?}",
        ingress.agent_visible
    );
    eprintln!("[CHAIN] STEP 1 PASS: ingress returned RAW (symbol={:?}, Plan 7), taintProcess({proc_key}) called", ingress.symbol);

    // Verify the mock recorded the taintProcess call.
    {
        let st = state.lock().unwrap();
        assert!(
            st.tainted_procs.contains(&proc_key),
            "arbiter must have received taintProcess({proc_key}); tainted_procs={:?}",
            st.tainted_procs
        );
    }

    // ── STEP 2: fs write — P writes a tracked file.
    //    record_file_taint_if_tainted calls isProcessTainted(P_key) → true, then taintFile.
    let tracked_path = "/test/tracked/tainted_by_chain.txt";
    let was_tainted = fs_supervisor::decision::record_file_taint_if_tainted(
        &mut client,
        proc_key.as_str(),
        tracked_path, // content_hash = path (Task 4 posture: path-keyed, no file read)
        tracked_path,
        "evil.test", // origin_host
    );

    // ASSERT (b): the file was tainted (because P was tainted).
    assert!(
        was_tainted,
        "record_file_taint_if_tainted must return true for a tainted writer ({proc_key})"
    );
    // And the mock registered the file as tainted.
    {
        let st = state.lock().unwrap();
        assert!(
            st.tainted_files.contains(tracked_path),
            "arbiter must have received taintFile({tracked_path}); tainted_files={:?}",
            st.tainted_files
        );
    }
    eprintln!("[CHAIN] STEP 2 PASS: record_file_taint_if_tainted({proc_key}) → true; taintFile({tracked_path}) called");

    // ── STEP 3: fs read — a later read of the same file.
    //    fs_inbound_trust calls fileTrust → untrusted=true (taint set in step 2),
    //    then symbolizes the content → Some(symbol).
    let ft = fs_supervisor::decision::fs_inbound_trust(
        &mut client,
        "Read",        // tool
        "evil.test",   // origin (from taint, same host)
        tracked_path,  // path
        Some(tracked_path), // content_hash (path-keyed)
        Some("the-untrusted-content"), // content_for_symbol
    );

    // ASSERT (c): LOAD-BEARING — the read returned UNTRUSTED + a SYMBOL.
    assert_eq!(
        ft.trust,
        mandu_arbiter::protocol::Trust::Untrusted,
        "fs_inbound_trust on a tainted file must return UNTRUSTED"
    );
    assert!(
        ft.symbol.is_some(),
        "fs_inbound_trust on a tainted file must return Some(symbol) (agent sees symbol, not raw)"
    );
    eprintln!(
        "[CHAIN] STEP 3 PASS (LOAD-BEARING): fs_inbound_trust({tracked_path}) → UNTRUSTED + symbol={:?}",
        ft.symbol
    );

    eprintln!("[CHAIN] NET→FS TAINT CHAIN ACTIVATED: net taints P ({proc_key}) → \
               fs records taintFile({tracked_path}) → later read returns SYMBOL. Plan 6 §5 oracle PASS.");
}

// ── Test 2: taint-egress gate ─────────────────────────────────────────────────

/// Taint-egress gate (the ACTIVATION oracle, spec §7 #4):
///
/// With process P tainted (via `taintProcess` in step 1 of the chain), an outbound
/// body from P to an UNTRUSTED host MUST be WITHHELD by `egress_transform`, even
/// when the body carries NO symbols. This is the exfil backstop.
///
/// The test drives `egress_transform` with:
///   - `proc_key = P_key` (same key as the net→fs test's tainted process)
///   - `destination = "evil.test"` (an untrusted host, classified UNTRUSTED by the mock)
///   - `body = "plain text, no symbols"` (no $-references — the taint gate runs on
///     the content-agnostic path)
///
/// LOAD-BEARING ASSERTION: `result.any_withheld == true`.
///
/// Note: this test uses its OWN arbiter instance (separate from the net→fs test) so
/// tests can run in any order. It manually pre-seeds the taint by calling
/// `taintProcess` directly via the arbiter client, then drives egress_transform.
#[test]
#[ignore = "live taint-egress oracle (Plan 6 §5): needs --features kernel; run: cargo test -p net-supervisor --features kernel --test taint_chain_integration -- --ignored --nocapture"]
fn tainted_process_egress_to_untrusted_host_is_withheld() {
    let (arbiter, _state) = chain_arbiter();

    // ── P's proc key (this test process).
    let proc_key = proc_key_for_pid(std::process::id() as i32)
        .expect("proc_key_for_pid(self) must succeed");

    // Use ONE shared ArbiterClient throughout (same reason as the chain test above:
    // single-threaded MockArbiter accept loop requires a single persistent connection).
    let mut client = ArbiterClient::new(&arbiter.socket_path);

    // Pre-seed: mark P as tainted (simulates the net ingress path having done so).
    client
        .taint_process(&mandu_arbiter::protocol::TaintProcessArgs {
            proc_key: proc_key.clone(),
            origin_host: "evil.test".into(),
            session: None,
        })
        .expect("taintProcess must succeed against the mock");

    // ── Drive egress_transform with the tainted proc key + an untrusted destination.
    let result = egress_transform(
        &mut client,
        None,                     // no human plane: nothing here resolves
        "plain text, no symbols", // body carries NO $-references
        "evil.test",              // destination host (untrusted per mock classifier)
        false,                    // as_command
        Some(proc_key.as_str()),  // the tainted proc key
    );

    // LOAD-BEARING ASSERTION: the taint gate withheld the egress.
    assert!(
        result.any_withheld,
        "a TAINTED process sending to an UNTRUSTED host must be WITHHELD even with no symbols; \
         got any_withheld=false, decisions={:?}",
        result.decisions
    );
    eprintln!(
        "[CHAIN] TAINT-EGRESS PASS (LOAD-BEARING): egress from tainted proc ({proc_key}) to \
         evil.test is WITHHELD. Plan 6 §5 oracle PASS. Plan 7 (drop net ingress symbolization) is now unblocked."
    );
}

// ── Helper ────────────────────────────────────────────────────────────────────

/// Check `\d+-\d+` shape (no regex dep): both parts are non-empty decimals.
fn is_pid_dash(s: &str) -> bool {
    match s.split_once('-') {
        Some((a, b)) => {
            !a.is_empty()
                && !b.is_empty()
                && a.bytes().all(|c| c.is_ascii_digit())
                && b.bytes().all(|c| c.is_ascii_digit())
        }
        None => false,
    }
}
