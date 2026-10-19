/**
 * exec-correlation.test.ts — the proxy↔execve correlation (exec-routing.md §4
 * step 1) + the exec escalation gate (§5): the pure signature, the bounded
 * decision store, and the server-level record→lookup / escalate flows.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { execSignature, execSignatureForArgv, rootSignaturesOfArgv } from "../../policy/exec-signature.js";
import { ExecDecisionStore } from "../../policy/exec-decision-store.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

/** A dispatch-only server (no socket needed) backed by a throwaway temp DB. */
function makeServer(): { srv: ArbiterServer; cleanup: () => void } {
  const workdir = mkdtempSync(join(tmpdir(), "mandu-execcorr-"));
  const srv = new ArbiterServer({
    socketPath: join(workdir, "arbiter.sock"),
    dbPath: join(workdir, "symbols.db"),
    eventDir: join(workdir, "events"),
    log: () => {},
  });
  return { srv, cleanup: () => { srv.close().catch(() => {}); rmSync(workdir, { recursive: true, force: true }); } };
}

// ── execSignature: bridge the proxy↔execve gap ───────────────────────────────

test("execSignature unwraps a bash -c wrapper to the same core as the bare command", () => {
  const bare = execSignature("curl https://x.test/a");
  assert.equal(bare, "curl https://x.test/a");
  assert.equal(execSignature('bash -lc "curl https://x.test/a"'), bare);
  assert.equal(execSignature("bash -c 'curl https://x.test/a'"), bare);
  // Unquoted `sh -c curl https://…` means the -c ARG is just `curl` ($0 is the
  // URL) — so it correctly reduces to `curl`, NOT the full line.
  assert.equal(execSignature("sh -c curl https://x.test/a"), "curl");
});

test("execSignature unwraps nested shells and normalizes whitespace", () => {
  assert.equal(
    execSignature(`bash -lc "sh -c 'curl    https://x.test/a'"`),
    execSignature("curl https://x.test/a"),
  );
});

test("execSignature leaves a non-shell command as normalized text", () => {
  assert.equal(execSignature("grep -n foo   file.txt"), "grep -n foo file.txt");
  assert.equal(execSignature("   "), "");
});

test("execSignatureForArgv joins argv then normalizes (bash -c argv unwraps)", () => {
  assert.equal(
    execSignatureForArgv(["bash", "-lc", "curl https://x.test/a"]),
    execSignature("curl https://x.test/a"),
  );
  assert.equal(execSignatureForArgv(["curl", "https://x.test/a"]), execSignature("curl https://x.test/a"));
});

// ── ExecDecisionStore: bounded record/lookup ─────────────────────────────────

test("ExecDecisionStore records and looks up by signature", () => {
  const s = new ExecDecisionStore();
  s.record("curl https://x.test/a", {
    block: false, shell: "AgentShell", evasion: [{ kind: "absolute_path_net_tool", evidence: "/usr/bin/curl" }],
    reason: "recorded",
  });
  const got = s.lookup("curl https://x.test/a");
  assert.ok(got);
  assert.equal(got!.shell, "AgentShell");
  assert.equal(got!.evasion[0].kind, "absolute_path_net_tool");
  assert.equal(s.lookup("something else"), undefined);
  assert.equal(s.lookup(""), undefined);
});

test("ExecDecisionStore ignores empty signatures and evicts oldest past capacity", () => {
  const s = new ExecDecisionStore({ capacity: 2 });
  s.record("", { block: false, shell: "AgentShell", evasion: [], reason: "x" });
  assert.equal(s.size(), 0, "empty signature is not stored");
  s.record("a", { block: false, shell: "AgentShell", evasion: [], reason: "a" });
  s.record("b", { block: false, shell: "AgentShell", evasion: [], reason: "b" });
  s.record("c", { block: false, shell: "AgentShell", evasion: [], reason: "c" }); // evicts "a"
  assert.equal(s.size(), 2);
  assert.equal(s.lookup("a"), undefined);
  assert.ok(s.lookup("b") && s.lookup("c"));
});

test("ExecDecisionStore carries the callId leg of the correlation", () => {
  const s = new ExecDecisionStore();
  s.record("cat notes.md", {
    block: false, shell: "AgentShell", evasion: [], reason: "recorded",
    callId: "toolu_clean01",
  });
  assert.equal(s.lookup("cat notes.md")!.callId, "toolu_clean01");
  // A same-signature re-record overwrites with the freshest callId (the rerun
  // is the invocation about to execute — utility-only; the verdict store's
  // hash binding carries the security).
  s.record("cat notes.md", {
    block: false, shell: "AgentShell", evasion: [], reason: "recorded again",
    callId: "toolu_clean02",
  });
  assert.equal(s.lookup("cat notes.md")!.callId, "toolu_clean02");
});

// ── Server: execGate records → execDecisionFor looks up ──────────────────────

test("server records an execGate verdict and serves it back via execDecisionFor", () => {
  const { srv, cleanup } = makeServer();
  try {
    const sym = "$MDU:web_fetch[a1b2].text";

    // A symbol-as-command → the proxy would BLOCK; the arbiter records that.
    const gate = srv.dispatch({ id: 1, op: "execGate", command: `bash -c "${sym}"` });
    assert.ok(gate.ok);

    // The supervisor looks it up by its OBSERVED argv (bash -c wrapper) → same sig.
    const look = srv.dispatch({ id: 2, op: "execDecisionFor", argv: ["bash", "-c", sym] });
    assert.ok(look.ok);
    const res = (look as { result: { decision: { block: boolean } | null; signature: string } }).result;
    assert.ok(res.decision, "the recorded decision is found");
    assert.equal(res.decision!.block, true, "the block verdict is preserved for correlation");

    // A never-seen command → miss.
    const miss = srv.dispatch({ id: 3, op: "execDecisionFor", command: "echo unseen" });
    assert.equal((miss as { result: { decision: unknown } }).result.decision, null);
  } finally {
    cleanup();
  }
});

test("execGate's callId rides the signature record to the supervisor's argv lookup", () => {
  const { srv, cleanup } = makeServer();
  try {
    // The E47 leaf shape (exec-routing.md §8.6a): a spaceless `python3 -c`
    // one-liner. The proxy submits the command STRING the model wrote — with a
    // trailing stdin redirect the -c unwrap drops — and the supervisor looks up
    // by its OBSERVED leaf argv (no redirect: bash consumed it). Both must
    // reduce to the SAME signature, or the clean-verdict report has no callId.
    const code = 'import hashlib;print(hashlib.sha256(b"mandu-nonce").hexdigest())';
    const gate = srv.dispatch({
      id: 1, op: "execGate",
      command: `python3 -c '${code}' < /dev/null`,
      callId: "toolu_e47_first",
    });
    assert.ok(gate.ok);
    const look = srv.dispatch({ id: 2, op: "execDecisionFor", argv: ["python3", "-c", code] });
    const res = (look as { result: { decision: { callId?: string } | null } }).result;
    assert.ok(res.decision, "the leaf argv reduces to the recorded signature");
    assert.equal(res.decision!.callId, "toolu_e47_first");

    // Without a callId on the gate call the record simply has none (older
    // proxy) — the lookup still works, the report leg just has nothing to key.
    srv.dispatch({ id: 3, op: "execGate", command: "grep -n foo file.txt" });
    const look2 = srv.dispatch({ id: 4, op: "execDecisionFor", argv: ["grep", "-n", "foo", "file.txt"] });
    const res2 = (look2 as { result: { decision: { callId?: string } | null } }).result;
    assert.ok(res2.decision);
    assert.equal(res2.decision!.callId, undefined);
  } finally {
    cleanup();
  }
});

// ── Server: escalateExec via the approval queue ──────────────────────────────

test("escalateExec stays AgentShell + queues pending until approved", () => {
  const { srv, cleanup } = makeServer();
  try {
    const argv = ["curl", "https://x.test/a"];

    // First attempt: no prior decision → PENDING, stay AgentShell (fail-safe).
    const first = srv.dispatch({ id: 1, op: "escalateExec", argv, resource: "network" });
    const r1 = (first as { result: { shell: string; approved: boolean; requiresApproval: boolean } }).result;
    assert.equal(r1.shell, "AgentShell");
    assert.equal(r1.approved, false);
    assert.equal(r1.requiresApproval, true);

    // The escalation was queued as a pending egress-approval entry.
    const listed = srv.dispatch({ id: 2, op: "egressApprovals", status: "pending" });
    const approvals = (listed as { result: { approvals: { id: string; symbol: string }[] } }).result.approvals;
    const entry = approvals.find((a) => a.symbol.startsWith("exec-escalate:network"));
    assert.ok(entry, "a pending exec-escalate entry was queued");

    // Human approves it.
    srv.dispatch({ id: 3, op: "resolveEgressApproval", approvalId: entry!.id, approve: true });

    // Next attempt: APPROVED → HumanShell.
    const second = srv.dispatch({ id: 4, op: "escalateExec", argv, resource: "network" });
    const r2 = (second as { result: { shell: string; approved: boolean } }).result;
    assert.equal(r2.shell, "HumanShell");
    assert.equal(r2.approved, true);
  } finally {
    cleanup();
  }
});

test("escalateExec honors a human DENY (stay AgentShell, no re-queue growth)", () => {
  const { srv, cleanup } = makeServer();
  try {
    const argv = ["rsync", "-a", "src", "host:/dst"];
    srv.dispatch({ id: 1, op: "escalateExec", argv, resource: "original-fs" });
    const listed = srv.dispatch({ id: 2, op: "egressApprovals", status: "pending" });
    const entry = (listed as { result: { approvals: { id: string; symbol: string }[] } }).result.approvals
      .find((a) => a.symbol.startsWith("exec-escalate:original-fs"))!;
    srv.dispatch({ id: 3, op: "resolveEgressApproval", approvalId: entry.id, approve: false });

    const after = srv.dispatch({ id: 4, op: "escalateExec", argv, resource: "original-fs" });
    const r = (after as { result: { shell: string; approved: boolean; requiresApproval: boolean } }).result;
    assert.equal(r.shell, "AgentShell", "a denied escalation stays AgentShell");
    assert.equal(r.approved, false);
    assert.equal(r.requiresApproval, false, "a denied verdict does not re-queue");
  } finally {
    cleanup();
  }
});

// ── plan 13 D7: the call-root recorder's signatures ─────────────────────────
// The agent runs each shell tool call in a shell of its own. Codex-style
// `bash -lc '<command>'` carries the command as the payload; Claude Code
// wraps it in a snapshot preamble and `eval '<command, shell-quoted>'`. Each
// must yield the command's own signature, so the proxy's command text binds
// the call to that shell (before, Claude Code's shell matched no call at all:
// its signature is the whole preamble).
test("rootSignaturesOfArgv: Claude Code's eval-wrapped shell yields the command's signature", () => {
  const command = "( cat ./x.tx?; true ) | od -An -tx1 | tr -d ' \\n'";
  const quoted = `'${command.replace(/'/g, `'"'"'`)}'`;
  const argv = ["/usr/bin/zsh", "-c", `source /h/.claude/shell-snapshots/snapshot-zsh-1-x.sh 2>/dev/null || true && setopt NO_EXTENDED_GLOB 2>/dev/null || true && eval ${quoted} && pwd -P >| /tmp/claude-11df-cwd`];
  const sigs = rootSignaturesOfArgv(argv);
  assert.ok(sigs.includes(execSignature(command)), JSON.stringify(sigs));
  assert.notEqual(execSignatureForArgv(argv), execSignature(command), "the preamble alone never matched the call");
  // the older `\< /dev/null` form, and bash -c -l with options after -c
  const older = ["/bin/bash", "-c", "-l", `source /s.sh && eval ${quoted} \\< /dev/null && pwd -P >| /tmp/claude-2-cwd`];
  assert.ok(rootSignaturesOfArgv(older).includes(execSignature(command)), JSON.stringify(rootSignaturesOfArgv(older)));
});

test("rootSignaturesOfArgv: Codex's bash -lc yields the command's signature; a command with its own eval matches both ways; junk yields nothing", () => {
  assert.deepEqual(rootSignaturesOfArgv(["bash", "-lc", "cat .env | grep FOO"]), [execSignature("cat .env | grep FOO")]);
  const inner = rootSignaturesOfArgv(["bash", "-c", "eval 'ls -la'"]);
  assert.ok(inner.includes(execSignature("eval 'ls -la'")) && inner.includes(execSignature("ls -la")), JSON.stringify(inner));
  assert.deepEqual(rootSignaturesOfArgv([]), []);
  assert.deepEqual(rootSignaturesOfArgv(["/usr/bin/cat", "x.txt"]), ["/usr/bin/cat x.txt"]);
  assert.deepEqual(rootSignaturesOfArgv([1 as unknown as string]), []);
});
