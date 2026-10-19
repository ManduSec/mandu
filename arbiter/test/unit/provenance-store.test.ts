import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ProvenanceStore, STORE_STAMP_COLUMNS } from "../../provenance/provenance-store.js";
import Database from "../../db/sqlite.js";

function tmpDb(): { path: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-prov-"));
  const path = join(dir, "symbols.db");
  return { path, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test("taintProcess then isProcessTainted reports tainted with originHost", () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    store.taintProcess("1234-555", "evil.example", "sess-1");
    const r = store.isProcessTainted("1234-555");
    assert.equal(r.tainted, true);
    assert.equal(r.originHost, "evil.example");
  } finally {
    store.close();
    cleanup();
  }
});

test("unknown process is not tainted", () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    assert.equal(store.isProcessTainted("9999-1").tainted, false);
  } finally {
    store.close();
    cleanup();
  }
});

test("process taint survives a reopen of the same DB", () => {
  const { path, cleanup } = tmpDb();
  const a = new ProvenanceStore({ dbPath: path });
  a.taintProcess("1-1", "evil.example");
  a.close();
  const b = new ProvenanceStore({ dbPath: path });
  try {
    assert.equal(b.isProcessTainted("1-1").tainted, true);
  } finally {
    b.close();
    cleanup();
  }
});

test("isProcessTainted walks lineage: a child of a tainted parent is tainted", () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    store.taintProcess("bash-1", "evil.example", "sess-1");
    store.recordLineage("curl-2", "bash-1", "sess-1");      // curl spawned by bash
    store.recordLineage("grep-3", "curl-2", "sess-1");      // grep spawned by curl
    const r = store.isProcessTainted("grep-3");             // 2 hops up to the taint
    assert.equal(r.tainted, true);
    assert.equal(r.originHost, "evil.example");
  } finally {
    store.close();
    cleanup();
  }
});

test("lineage walk terminates on cycles and untainted chains", () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    store.recordLineage("a", "b");
    store.recordLineage("b", "a");                          // cycle, neither tainted
    assert.equal(store.isProcessTainted("a").tainted, false);
  } finally {
    store.close();
    cleanup();
  }
});

test("taintFile then fileTrust hits by content-hash OR by path", () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    store.taintFile({
      contentHash: "abc123",
      path: "/tmp/setup.md",
      originHost: "example.test",
      writerProc: "curl-2",
      session: "sess-1",
    });
    assert.deepEqual(store.fileTrust({ contentHash: "abc123" }),
      { untrusted: true, origin: "example.test" });
    assert.deepEqual(store.fileTrust({ path: "/tmp/setup.md" }),
      { untrusted: true, origin: "example.test" });
    // Edit changed the hash, but the path is still on record → fail-closed untrusted.
    assert.equal(store.fileTrust({ contentHash: "different", path: "/tmp/setup.md" }).untrusted, true);
  } finally {
    store.close();
    cleanup();
  }
});

test("fileTrust returns not-untrusted for an unknown file", () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    assert.equal(store.fileTrust({ contentHash: "nope", path: "/etc/hosts" }).untrusted, false);
  } finally {
    store.close();
    cleanup();
  }
});

test("fileTrust throws when neither contentHash nor path is provided", () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    assert.throws(() => store.fileTrust({}), /fileTrust/);
  } finally {
    store.close();
    cleanup();
  }
});

// ── §7a declared net writes + program-text trust ─────────────────────────────

test("declareNetWrite + programTextTrust: relative paths are session-scoped, absolute global", () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    store.declareNetWrite({ path: "setup.sh", originHost: "example.test", session: "A", callId: "toolu_1" });
    assert.deepEqual(store.programTextTrust({ path: "setup.sh", session: "A" }), { untrusted: true, origin: "example.test" });
    assert.equal(store.programTextTrust({ path: "setup.sh", session: "B" }).untrusted, false, "another session's cwd");
    assert.equal(store.programTextTrust({ path: "setup.sh" }).untrusted, false, "no session ≠ session A");
    assert.equal(store.programTextTrust({ path: "other.sh", session: "A" }).untrusted, false);

    store.declareNetWrite({ path: "/opt/x.sh", originHost: "h.test" });
    assert.deepEqual(store.programTextTrust({ path: "/opt/x.sh", session: "Z" }), { untrusted: true, origin: "h.test" });
    // First origin wins per (session, path) — monotonic taint, like taintFile.
    store.declareNetWrite({ path: "setup.sh", originHost: "other.test", session: "A" });
    assert.equal(store.programTextTrust({ path: "setup.sh", session: "A" }).origin, "example.test");
    // A different session's declaration of the same relative name is its own row.
    store.declareNetWrite({ path: "setup.sh", originHost: "third.test", session: "B" });
    assert.equal(store.programTextTrust({ path: "setup.sh", session: "B" }).origin, "third.test");
    // The generic fileTrust sees declared rows as well (one registry).
    assert.equal(store.fileTrust({ path: "/opt/x.sh" }).untrusted, true);
    assert.equal(store.programTextTrust({ path: "" }).untrusted, false);
  } finally {
    store.close();
    cleanup();
  }
});

test("programTextTrust matches a kernel-observed ABSOLUTE row by cwd-relative suffix within the session", () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    store.taintFile({ contentHash: "h1", path: "/home/u/ws/scripts/setup.sh", originHost: "evil.example", session: "K" });
    assert.equal(store.programTextTrust({ path: "scripts/setup.sh", session: "K" }).untrusted, true);
    assert.equal(store.programTextTrust({ path: "setup.sh", session: "K" }).untrusted, true);
    assert.equal(store.programTextTrust({ path: "setup.sh", session: "L" }).untrusted, false);
    assert.equal(store.programTextTrust({ path: "up.sh", session: "K" }).untrusted, false, "suffix must be segment-aligned");
    assert.equal(store.programTextTrust({ path: "/home/u/ws/scripts/setup.sh" }).untrusted, true);
  } finally {
    store.close();
    cleanup();
  }
});

// ── plan 10: the confidentiality taint (§3.1) and the call fold (§4.2) ──────
test("secret taint: a child inherits its ancestors' rows; the strictest level wins", () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    store.taintProcessSecret({ procKey: "bash-1", path: "/ws/.env", level: "no-model", app: "bash" });
    store.recordLineage("psql-2", "bash-1");
    store.taintProcessSecret({ procKey: "psql-2", path: "/h/.pgpass", level: "any-model", app: "psql" });
    store.recordLineage("sh-3", "psql-2");
    const child = store.processSecretTaint("sh-3");
    assert.equal(child.level, "no-model");
    assert.deepEqual(child.rows.map((r) => [r.procKey, r.path, r.app]).sort(), [["bash-1", "/ws/.env", "bash"], ["psql-2", "/h/.pgpass", "psql"]]);
    assert.equal(store.processSecretTaint("psql-2").rows.length, 2);
    assert.equal(store.processSecretTaint("nobody-9").level, null);
    // idempotent per (process, file)
    store.taintProcessSecret({ procKey: "bash-1", path: "/ws/.env", level: "no-model", app: "bash" });
    assert.equal(store.processSecretTaint("bash-1").rows.length, 1);
  } finally {
    cleanup();
  }
});

test("callTaint: the fold sees the root's ancestors AND its whole subtree; an unrecorded call has nothing", () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    // agent → bash(root of the call) → { psql, sh → curl }; a tainted grandparent shell above the root
    store.recordLineage("root-bash-10", "agent-1");
    store.recordLineage("psql-11", "root-bash-10");
    store.recordLineage("sh-12", "root-bash-10");
    store.recordLineage("curl-13", "sh-12");
    store.recordCallRoot("toolu_A", "root-bash-10");
    assert.deepEqual(store.callTaint("toolu_A"), { level: null, rows: [], root: "root-bash-10", denied: [] });
    store.taintProcessSecret({ procKey: "psql-11", path: "/h/.pgpass", level: "no-model", app: "psql" });
    store.taintProcessSecret({ procKey: "curl-13", path: "/h/.netrc", level: "no-model", app: "curl" });
    const t = store.callTaint("toolu_A");
    assert.equal(t.level, "no-model");
    assert.deepEqual(t.rows.map((r) => r.app).sort(), ["curl", "psql"]);
    // a taint ABOVE the root (a sourced shell) reaches the call too
    store.taintProcessSecret({ procKey: "agent-1", path: "/ws/.env", level: "any-model", app: "bash" });
    assert.equal(store.callTaint("toolu_A").rows.length, 3);
    assert.deepEqual(store.callTaint("toolu_never"), { level: null, rows: [], root: null, denied: [] });
  } finally {
    cleanup();
  }
});

// ── plan 13 D7: lineage at fork as well as exec ──────────────────────────────
// The guard reports the live ancestor chain at every exec and every secret
// open. A subshell that never execs (`( cat x; true ) | cat`,
// `echo "$(cat x; true)"`) has no event of its own; before, the exec below it
// recorded only `cat → subshell`, and the walk from the call's root never
// reached the reader.
test("D7 fork lineage: a reader under a subshell that never exec'd is in its call's tree (the exec's chain)", () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    // agent-1 → root bash (exec'd) → subshell (fork only) → cat (exec'd, reads x.txt)
    store.recordExecRoot({ procKey: "bash-10", ancestors: ["agent-1"], signature: "( cat x.txt; true ) | cat", session: "s" });
    store.recordExecRoot({ procKey: "cat-12", parentKey: "sub-11", ancestors: ["sub-11", "bash-10", "agent-1"], signature: "cat x.txt", session: "s" });
    store.taintProcessSecret({ procKey: "cat-12", path: "/ws/x.txt", level: "no-model", app: "cat", session: "s" });
    store.recordCallRoot("toolu_sub", "bash-10", "s");
    const t = store.callTaint("toolu_sub");
    assert.equal(t.level, "no-model", "the walk from the root reaches the reader through the subshell");
    assert.deepEqual(t.rows.map((r) => r.app), ["cat"]);
  } finally {
    store.close();
    cleanup();
  }
});

test("D7 fork lineage: a command substitution's reader, linked by the secret open's chain alone", () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    // `echo "$(cat x.txt; true)"`: the substitution subshell forks cat; only
    // the open's chain (no exec record below the subshell) links them
    store.recordExecRoot({ procKey: "bash-20", ancestors: ["agent-1"], signature: "echo \"$(cat x.txt; true)\"", session: "s" });
    store.recordLineageChain("cat-22", ["subst-21", "bash-20", "agent-1"], "s");
    store.taintProcessSecret({ procKey: "cat-22", path: "/ws/x.txt", level: "local-model", app: "cat", session: "s" });
    store.recordCallRoot("toolu_subst", "bash-20", "s");
    assert.equal(store.callTaint("toolu_subst").level, "local-model");
  } finally {
    store.close();
    cleanup();
  }
});

test("D7 fork lineage: the first edge wins; a later report of another parent (a reparenting) cannot cut a reader out of its tree", () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    store.recordExecRoot({ procKey: "bash-30", ancestors: ["agent-1"], signature: "x", session: "s" });
    store.recordExecRoot({ procKey: "sh-32", ancestors: ["sub-31", "bash-30", "agent-1"], signature: "sh", session: "s" });
    // the subshell exits; sh is adopted by the subreaper and execs again,
    // and its open reports the subreaper as its parent
    store.recordExecRoot({ procKey: "sh-32", ancestors: ["reaper-2"], signature: "cat x.txt", session: "s" });
    store.recordLineageChain("sh-32", ["reaper-2"], "s");
    store.recordLineage("sh-32", "reaper-2", "s");
    store.taintProcessSecret({ procKey: "sh-32", path: "/ws/x.txt", level: "no-model", app: "cat", session: "s" });
    store.recordCallRoot("toolu_reparent", "bash-30", "s");
    assert.equal(store.callTaint("toolu_reparent").level, "no-model", "the reader stays under the root it was started in");
    // and the chain stops at a child that already has its edge: nothing above
    // the existing edge is rewritten
    assert.equal(store.processSecretTaint("sub-31").level, null, "the taint never flows up to the subshell");
  } finally {
    store.close();
    cleanup();
  }
});

test("listSecretTaint: newest first, with the program and file (plan 10 §11.9)", () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    store.taintProcessSecret({ procKey: "a-1", path: "/h/.pgpass", level: "no-model", app: "psql", session: "s" });
    store.taintProcessSecret({ procKey: "b-2", path: "/h/.env", level: "no-model", app: "sh", session: "s" });
    const l = store.listSecretTaint(10);
    assert.equal(l.length, 2);
    assert.deepEqual(l.map((r) => r.app).sort(), ["psql", "sh"]);
    assert.ok(l.every((r) => r.since > 0 && r.session === "s"));
    assert.equal(store.listSecretTaint(1).length, 1);
  } finally {
    cleanup();
  }
});

// ── plan 13 D9: the guard's records are evidence, the data socket's claims ───
// A claim (a record from the socket the agent's tree reaches) only widens a
// walk: it never takes the guard's first-edge slot, its taint row folds as
// `secret` and is never a secret the process holds raw (attestedOnly).

test("D9: a claimed edge recorded before the guard's does not take the guard's slot; the reader stays in its call's tree", () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    store.recordLineage("cat-3", "elsewhere-9", "s", { claimed: true });
    store.recordLineageChain("cat-3", ["sub-2", "sh-1", "agent-0"], "s");
    store.taintProcessSecret({ procKey: "cat-3", path: "/ws/x.txt", level: "no-model", app: "cat", session: "s", exe: "/usr/bin/cat", via: "reader" });
    store.recordCallRoot("toolu_d9", "sh-1", "s");
    assert.equal(store.callTaint("toolu_d9").level, "no-model", "the guard's chain links the reader to the call's shell");
    // a claimed chain cuts nothing: every edge is a claim of its own
    store.recordLineageChain("cat-4", ["elsewhere-9"], "s", { claimed: true });
    store.recordExecRoot({ procKey: "cat-4", ancestors: ["sh-1", "agent-0"], signature: "cat", session: "s" });
    store.taintProcessSecret({ procKey: "cat-4", path: "/ws/y.txt", level: "local-model", app: "cat", session: "s" });
    assert.deepEqual(store.callTaint("toolu_d9").rows.map((r) => r.path).sort(), ["/ws/x.txt", "/ws/y.txt"]);
  } finally {
    store.close();
    cleanup();
  }
});

test("D9: a claimed edge only widens: a claimed parent's taint is inherited and a claimed child is folded, except where attestedOnly asks", () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    store.taintProcessSecret({ procKey: "holder-1", path: "/h/.env", level: "no-model", app: "bash", session: "s" });
    store.recordLineage("p-2", "sh-5", "s");
    store.recordLineage("p-2", "holder-1", "s", { claimed: true });
    assert.equal(store.processSecretTaint("p-2").level, "no-model", "a claimed parent's taint is inherited (tightening is anyone's)");
    assert.equal(store.processSecretTaint("p-2", { attestedOnly: true }).level, null, "but it is no raw holding of the parent's file");
    store.recordLineage("child-7", "sh-6", "s", { claimed: true });
    store.taintProcessSecret({ procKey: "child-7", path: "/h/.pgpass", level: "local-model", app: "psql", session: "s" });
    assert.equal(store.treeTaint("sh-6").level, "local-model", "a claimed child is in the tree it claims");
    store.taintProcess("holder-1", "evil.example", "s");
    assert.equal(store.isProcessTainted("p-2").tainted, true, "integrity taint follows a claimed parent too");
  } finally {
    store.close();
    cleanup();
  }
});

test("D9: a claimed taint row folds as `secret`, is not held raw, and the guard's row for the same file replaces it", () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    store.taintProcessSecret({ procKey: "p-1", path: "/ws/x.txt", level: "public", app: "cat", session: "s", exe: "/w/cat", via: "reader", claimed: true });
    const claimed = store.processSecretTaint("p-1").rows;
    assert.equal(claimed.length, 1);
    assert.equal(claimed[0]!.via, undefined, "a claim names no binary and no way in");
    assert.equal(claimed[0]!.exe, undefined);
    assert.deepEqual(store.processSecretTaint("p-1", { attestedOnly: true }).rows, []);
    assert.equal(store.sessionSecretTaint("s").level, "public", "a claim still counts in the session's holdings");
    store.taintProcessSecret({ procKey: "p-1", path: "/ws/x.txt", level: "no-model", app: "cat", session: "s", exe: "/usr/bin/cat", via: "reader" });
    const real = store.processSecretTaint("p-1", { attestedOnly: true }).rows;
    assert.deepEqual(real.map((r) => [r.level, r.exe, r.via]), [["no-model", "/usr/bin/cat", "reader"]]);
    // and a later claim does not replace the guard's row
    store.taintProcessSecret({ procKey: "p-1", path: "/ws/x.txt", level: "public", app: "x", session: "s", claimed: true });
    assert.equal(store.processSecretTaint("p-1").level, "no-model");
  } finally {
    store.close();
    cleanup();
  }
});

test("D9: a read-only callTree (a data-socket ask) changes nothing: no first ask, no binding, no guess", () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    store.recordCallCommand("toolu_ro", "echo hi", "gate", "s");
    store.recordExecRoot({ procKey: "sh-1", ancestors: ["agent-0"], signature: "echo hi", session: "s", callRoot: true, rootSignatures: ["echo hi"] });
    const ro = store.callTree("toolu_ro", { signature: "echo hi", session: "s", readOnly: true });
    assert.equal(ro.binding, "none");
    const bound = store.callTree("toolu_ro", { signature: "echo hi", session: "s" });
    assert.equal(bound.binding, "exact", "the first real ask binds (the read-only ask fixed no time)");
    assert.equal(store.callTree("toolu_ro", { readOnly: true }).binding, "exact", "a read-only ask reads an existing binding");
  } finally {
    store.close();
    cleanup();
  }
});


// ── Plan 13 D9 follow-up: a call binds by the command the proxy RECORDED ─────
// (execGate's `gate`, recordCallCommand's `delivered`), never by the text the
// agent echoes back in its next request.

test("D9 follow-up: callTree binds by the recorded command; an echoed text naming another call's clean shell binds nothing new", () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    store.recordCallCommand("toolu_r", "cat ./x.txt", "gate", "s");
    store.recordCallCommand("toolu_c", "echo ok", "gate", "s");
    store.recordExecRoot({ procKey: "sh-r", ancestors: ["agent-0"], signature: "cat ./x.txt", session: "s", callRoot: true, rootSignatures: ["cat ./x.txt"] });
    store.recordExecRoot({ procKey: "sh-c", ancestors: ["agent-0"], signature: "echo ok", session: "s", callRoot: true, rootSignatures: ["echo ok"] });
    store.taintProcessSecret({ procKey: "sh-r", path: "/w/x.txt", level: "no-model", app: "cat", session: "s" });
    // the reader's call asked first, with the clean call's text echoed
    const r = store.callTree("toolu_r", { signature: "echo ok", session: "s" });
    assert.equal(r.binding, "exact");
    assert.deepEqual(r.roots, ["sh-r"]);
    assert.equal(r.level, "no-model");
    const c = store.callTree("toolu_c", { signature: "echo ok", session: "s" });
    assert.deepEqual(c.roots, ["sh-c"], "the clean call keeps its own shell");
    assert.equal(c.level, null);
  } finally {
    store.close();
    cleanup();
  }
});

test("D9 follow-up: a call with no recorded command is never bound by the recorder, however well the echoed text matches (at most a guess)", () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    store.recordCallPending("toolu_n", "s"); // a gate time, no command (an older proxy)
    store.recordExecRoot({ procKey: "sh-n", ancestors: ["agent-0"], signature: "echo hi", session: "s", callRoot: true, rootSignatures: ["echo hi"] });
    const t = store.callTree("toolu_n", { signature: "echo hi", session: "s" });
    assert.equal(t.binding, "guess", "the most recent exec is folded, never evidence");
    assert.deepEqual(store.callCommandSignatures("toolu_n"), []);
    assert.equal(store.callTree("toolu_none", { session: "s" }).binding, "none");
  } finally {
    store.close();
    cleanup();
  }
});

test("D9 follow-up: the delivered command wins over the gated one (the view map's rewrite); several delivered commands of one call are all bound; recordCallCommand sets the gate time once", async () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    store.recordCallCommand("toolu_v", "cat /home/u/p/x.txt", "gate", "s");
    store.recordCallCommand("toolu_v", "cat /v/p/x.txt", "delivered", "s");
    assert.deepEqual(store.callCommandSignatures("toolu_v"), ["cat /v/p/x.txt"]);
    store.recordExecRoot({ procKey: "sh-v", ancestors: ["agent-0"], signature: "cat /v/p/x.txt", session: "s", callRoot: true, rootSignatures: ["cat /v/p/x.txt"] });
    assert.deepEqual(store.callTree("toolu_v", { session: "s" }).roots, ["sh-v"]);
    // a script cell's two exec literals, delivered under the cell's one id
    store.recordCallCommand("toolu_cell", "ls", "delivered", "s");
    store.recordCallCommand("toolu_cell", "cat ./y", "delivered", "s");
    assert.deepEqual(store.callCommandSignatures("toolu_cell").sort(), ["cat ./y", "ls"]);
    store.recordExecRoot({ procKey: "sh-l", ancestors: ["agent-0"], signature: "ls", session: "s", callRoot: true, rootSignatures: ["ls"] });
    store.recordExecRoot({ procKey: "sh-y", ancestors: ["agent-0"], signature: "cat ./y", session: "s", callRoot: true, rootSignatures: ["cat ./y"] });
    const cell = store.callTree("toolu_cell", { session: "s" });
    assert.equal(cell.binding, "shared");
    assert.deepEqual([...cell.roots].sort(), ["sh-l", "sh-y"]);
    // an exec older than the first record is no root: the gate time is the first record's
    store.recordExecRoot({ procKey: "sh-old", ancestors: ["agent-0"], signature: "echo late", session: "s", callRoot: true, rootSignatures: ["echo late"] });
    await new Promise((ok) => setTimeout(ok, 5));
    store.recordCallCommand("toolu_late", "echo late", "gate", "s");
    await new Promise((ok) => setTimeout(ok, 5));
    store.recordCallCommand("toolu_late", "echo late", "delivered", "s");
    assert.equal(store.callTree("toolu_late", { session: "s" }).binding, "none", "the older shell is not the call's");
  } finally {
    store.close();
    cleanup();
  }
});

// Plan 13 D7 residual (closed 2026-10-02): a call whose shell record was lost
// while a same-text shell of ANOTHER live call is in its window bound `exact`
// to that other shell. Its own (lost) tree read a secret; the other shell is
// clean: the result reached the model raw, and the other call lost its shell.
const pause = (ms: number) => new Promise((ok) => setTimeout(ok, ms));
const shell = (store: ProvenanceStore, procKey: string, signature: string, session = "s") =>
  store.recordExecRoot({ procKey, ancestors: ["agent-0"], signature, session, callRoot: true, rootSignatures: [signature] });

test("D7 lost record: a call whose shell was lost does not bind to a live same-text call's shell (bound to none; nor is the other call)", async () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    store.recordCallCommand("toolu_x", "./run.sh", "gate", "s");
    store.recordCallCommand("toolu_y", "./run.sh", "gate", "s");
    await pause(3);
    // X's shell read the secret; its exec record never reached the arbiter.
    store.taintProcessSecret({ procKey: "sh-x-lost", path: "/w/x.txt", level: "no-model", app: "cat", session: "s" });
    shell(store, "sh-y", "./run.sh");
    await pause(3);
    const x = store.callTree("toolu_x", { session: "s" });
    assert.notEqual(x.binding, "exact", "X is not bound to Y's clean shell");
    assert.equal(x.binding, "none");
    const y = store.callTree("toolu_y", { session: "s" });
    assert.equal(y.binding, "none", "nothing tells Y's shell from X's: neither call is bound");
    // Y asked FIRST is no different: X's window (still open) holds Y's shell.
    store.recordCallCommand("toolu_x2", "./go.sh", "gate", "s");
    store.recordCallCommand("toolu_y2", "./go.sh", "gate", "s");
    await pause(3);
    shell(store, "sh-y2", "./go.sh");
    await pause(3);
    assert.equal(store.callTree("toolu_y2", { session: "s" }).binding, "none");
    assert.equal(store.callTree("toolu_x2", { session: "s" }).binding, "none");
  } finally {
    store.close();
    cleanup();
  }
});

test("D7 lost record: what still binds: one call and its shell, sequential same-text calls, concurrent same-text calls with every shell recorded (shared), another session's call", async () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    // sequential: A runs and is asked before B is relayed
    store.recordCallCommand("toolu_a", "./run.sh", "gate", "s");
    await pause(3);
    shell(store, "sh-a", "./run.sh");
    await pause(3);
    const a = store.callTree("toolu_a", { session: "s" });
    assert.equal(a.binding, "exact");
    assert.deepEqual(a.roots, ["sh-a"]);
    await pause(3);
    store.recordCallCommand("toolu_b", "./run.sh", "gate", "s");
    await pause(3);
    shell(store, "sh-b", "./run.sh");
    await pause(3);
    const b = store.callTree("toolu_b", { session: "s" });
    assert.equal(b.binding, "exact", "A's window closed at its ask: it does not compete for B's shell");
    assert.deepEqual(b.roots, ["sh-b"]);
    // concurrent, both shells recorded: shared over both, as before
    store.recordCallCommand("toolu_c1", "./par.sh", "gate", "s");
    store.recordCallCommand("toolu_c2", "./par.sh", "gate", "s");
    await pause(3);
    shell(store, "sh-c1", "./par.sh");
    shell(store, "sh-c2", "./par.sh");
    await pause(3);
    const c1 = store.callTree("toolu_c1", { session: "s" });
    const c2 = store.callTree("toolu_c2", { session: "s" });
    assert.equal(c1.binding, "shared");
    assert.equal(c2.binding, "shared");
    assert.deepEqual([...c1.roots].sort(), ["sh-c1", "sh-c2"]);
    // another session's same-text call does not compete
    store.recordCallCommand("toolu_o", "./solo.sh", "gate", "other");
    store.recordCallCommand("toolu_s", "./solo.sh", "gate", "s");
    await pause(3);
    shell(store, "sh-s", "./solo.sh");
    await pause(3);
    assert.equal(store.callTree("toolu_s", { session: "s" }).binding, "exact");
  } finally {
    store.close();
    cleanup();
  }
});

test("D7 lost record: counted per command: a cell whose `ls` shell may be another call's binds to none", async () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    store.recordCallCommand("toolu_cell", "ls", "delivered", "s");
    store.recordCallCommand("toolu_cell", "cat ./y", "delivered", "s");
    store.recordCallCommand("toolu_z", "ls", "gate", "s");
    await pause(3);
    // one `ls` shell recorded (whose, nothing says), the cell's `cat` shell
    shell(store, "sh-l", "ls");
    shell(store, "sh-y", "cat ./y");
    await pause(3);
    assert.equal(store.callTree("toolu_cell", { session: "s" }).binding, "none", "two calls, one `ls` shell");
    assert.equal(store.callTree("toolu_z", { session: "s" }).binding, "none");
  } finally {
    store.close();
    cleanup();
  }
});

// Plan 13 D7, the store clock (CI pipeline #8378): a same-text call's shell
// reported in the SAME millisecond as the previous call's first ask fell
// inside that call's window too (inclusive bounds on a millisecond clock):
// two calls "owned" one shell, the lost-record rule left the new call
// unbound, and its result was masked whole (config-twin-fidelity's
// `.npmrc` raw read, `cat` twice). The tests above pause between steps; these
// run on a wall clock that never moves, and one that steps back.
test("D7 store clock: windows follow the order the arbiter handled each report, not the millisecond (a frozen and a backward wall clock)", () => {
  for (const [name, wallClock] of [
    ["frozen", () => 1_700_000_000_000],
    ["backward", (() => { let t = 1_700_000_000_000; return () => (t -= 7); })()],
  ] as Array<[string, () => number]>) {
    const { path, cleanup } = tmpDb();
    const store = new ProvenanceStore({ dbPath: path, wallClock });
    try {
      store.taintProcessSecret({ procKey: "git-1", path: "/w/.git-credentials", level: "no-model", app: "git", session: "s" });
      // The failure: the twin call, then the raw call, same text, in a row.
      store.recordCallCommand("toolu_twin", "cat /h/.npmrc", "delivered", "s");
      shell(store, "sh-1", "cat /h/.npmrc");
      const twin = store.callTree("toolu_twin", { session: "s" });
      assert.equal(twin.binding, "exact", name);
      assert.deepEqual(twin.roots, ["sh-1"], name);
      store.recordCallCommand("toolu_raw", "cat /h/.npmrc", "delivered", "s");
      shell(store, "sh-2", "cat /h/.npmrc");
      const raw = store.callTree("toolu_raw", { session: "s" });
      assert.equal(raw.binding, "exact", `${name}: the twin call's window closed at its first ask; the raw call keeps its own shell`);
      assert.deepEqual(raw.roots, ["sh-2"], name);
      // What must not loosen: a shell reported after a call's first ask is
      // never that call's (a later exec, stray or forged, never binds it).
      store.recordCallCommand("toolu_late", "echo late", "delivered", "s");
      assert.equal(store.callTree("toolu_late", { session: "s" }).binding, "none", name);
      shell(store, "sh-late", "echo late");
      assert.equal(store.callTree("toolu_late", { session: "s" }).binding, "none", `${name}: a shell after the first ask`);
      // nor is a shell reported before the call was relayed
      shell(store, "sh-early", "echo early");
      store.recordCallCommand("toolu_early", "echo early", "delivered", "s");
      assert.equal(store.callTree("toolu_early", { session: "s" }).binding, "none", `${name}: a shell before the relay`);
      // The lost record still binds nothing: two live same-text calls, one shell.
      store.recordCallCommand("toolu_x", "./run.sh", "gate", "s");
      store.recordCallCommand("toolu_y", "./run.sh", "gate", "s");
      shell(store, "sh-y", "./run.sh");
      assert.equal(store.callTree("toolu_x", { session: "s" }).binding, "none", name);
      assert.equal(store.callTree("toolu_y", { session: "s" }).binding, "none", name);
      // Concurrent with every shell recorded: shared, as before.
      store.recordCallCommand("toolu_c1", "./par.sh", "gate", "s");
      store.recordCallCommand("toolu_c2", "./par.sh", "gate", "s");
      shell(store, "sh-c1", "./par.sh");
      shell(store, "sh-c2", "./par.sh");
      assert.equal(store.callTree("toolu_c1", { session: "s" }).binding, "shared", name);
      // An orphan first seen before a call's relay is not folded into it;
      // one first seen after is.
      store.recordOrphanRoot("orph-before", "s");
      store.taintProcessSecret({ procKey: "orph-before", path: "/w/x.txt", level: "no-model", app: "cat", session: "s" });
      store.recordCallCommand("toolu_o", "echo o", "delivered", "s");
      shell(store, "sh-o", "echo o");
      assert.equal(store.callTree("toolu_o", { session: "s", readOnly: true }).level, null, `${name}: an orphan older than the relay`);
      store.recordOrphanRoot("orph-after", "s");
      store.taintProcessSecret({ procKey: "orph-after", path: "/w/x.txt", level: "no-model", app: "cat", session: "s" });
      assert.equal(store.callTree("toolu_o", { session: "s" }).level, "no-model", `${name}: an orphan seen after the relay`);
      // The panel's times stay whole milliseconds.
      for (const r of store.listSecretTaint()) assert.ok(Number.isInteger(r.since), name);
    } finally {
      store.close();
      cleanup();
    }
  }
});

// Plan 13 D7's last lineage residual (closed 2026-10-02): a subshell whose
// first exec or open below it comes after its parent (the call's shell)
// exited is re-parented to a reaper, and no edge links it to the call. The
// guard now names its ORPHAN ROOT; its tree folds into every call relayed no
// later than it was first seen.
test("D7 orphan root: a reader under a subshell orphaned before it acted folds into the calls relayed before it was first seen, not into later ones; its refusals are not the call's", async () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  const wait = (ms: number) => new Promise((ok) => setTimeout(ok, ms));
  try {
    store.recordCallCommand("toolu_bg", "( read -t 2 <&-; cat ./x.tx? ) &", "gate", "s");
    store.recordExecRoot({ procKey: "sh-bg", ancestors: ["agent-0"], signature: "( read -t 2 <&-; cat ./x.tx? ) &", session: "s", callRoot: true, rootSignatures: ["( read -t 2 <&-; cat ./x.tx? ) &"] });
    await wait(3);
    // the call's shell exited; its subshell (sub-9) was re-parented to the
    // guard; then it ran cat, whose chain stops at sub-9
    store.recordOrphanRoot("sub-9", "s");
    store.recordExecRoot({ procKey: "cat-10", ancestors: ["sub-9"], signature: "cat ./x.txt", session: "s" });
    store.taintProcessSecret({ procKey: "cat-10", path: "/w/x.txt", level: "no-model", app: "cat", session: "s" });
    store.recordSecretOpenDenial({ procKey: "cat-10", path: "/w/y.txt", app: "cat", reason: "not a listed reader", session: "s" });
    await wait(3);
    // a call relayed after the orphan was first seen did not start it
    store.recordCallCommand("toolu_later", "echo later", "gate", "s");
    store.recordExecRoot({ procKey: "sh-later", ancestors: ["agent-0"], signature: "echo later", session: "s", callRoot: true, rootSignatures: ["echo later"] });
    await wait(3);
    const bg = store.callTree("toolu_bg", { session: "s" });
    assert.equal(bg.binding, "exact");
    assert.deepEqual(bg.roots, ["sh-bg"], "bound to its own shell");
    assert.equal(bg.level, "no-model", "the orphan's reader is folded into the call that may have started it");
    assert.deepEqual(bg.denied, [], "an orphan's refused open is no denial of the call's");
    const later = store.callTree("toolu_later", { session: "s" });
    assert.equal(later.level, null, "utility: a call relayed after the orphan was first seen is not folded");
    // another session's orphan is not this session's
    store.recordCallCommand("toolu_o2", "echo other", "gate", "s");
    store.recordExecRoot({ procKey: "sh-o2", ancestors: ["agent-0"], signature: "echo other", session: "s", callRoot: true, rootSignatures: ["echo other"] });
    await wait(3);
    store.recordOrphanRoot("sub-x", "elsewhere");
    store.taintProcessSecret({ procKey: "sub-x", path: "/w/x.txt", level: "no-model", app: "cat", session: "elsewhere" });
    assert.equal(store.callTree("toolu_o2", { session: "s" }).level, null);
    // a read-only ask folds it too
    assert.equal(store.callTree("toolu_bg", { session: "s", readOnly: true }).level, "no-model");
  } finally {
    store.close();
    cleanup();
  }
});

// ── Plan 13 D7, the store clock ACROSS A RESTART (2026-10-17) ────────────────
// The records outlive the arbiter (mandu.db); the clock did not: a new store
// started at the wall clock, so after a restart across a backward wall-clock
// step every new stamp sorted before the stored ones. Each test: store A on a
// clock AHEAD (a clock that ran fast, later corrected), closed; store B on
// the same file with the clock an hour BEHIND what A stamped.

const AHEAD = 1_800_000_000_000;
const BEHIND = AHEAD - 3_600_000;
const clockFrom = (t0: number) => { let t = t0; return () => (t += 1); };
const stampsOf = (path: string, sql: string): number[] => {
  const db = new Database(path);
  try { return (db.prepare(sql).all() as Array<{ t: number }>).map((r) => r.t); } finally { db.close(); }
};

test("D7 store clock across a restart: a store holding stamps ahead of the wall clock starts above them; every new stamp orders after every stored one", () => {
  const { path, cleanup } = tmpDb();
  try {
    const a = new ProvenanceStore({ dbPath: path, wallClock: clockFrom(AHEAD) });
    a.recordCallPending("toolu_a", "s");
    a.recordAgentFlow("socket:[1]", ["h-1"], "s");
    a.closeAgentFlow("socket:[1]"); // the newest stamp is a closed_at
    const aMax = a.storedClockFloor();
    a.close();
    assert.ok(aMax > AHEAD, "A stamped ahead");
    const b = new ProvenanceStore({ dbPath: path, wallClock: clockFrom(BEHIND) });
    try {
      assert.equal(b.storedClockFloor(), aMax, "the floor is the newest stored stamp, a closed_at included");
      b.recordCallPending("toolu_b1", "s");
      b.recordCallPending("toolu_b2", "s");
      const [pa, pb1, pb2] = ["toolu_a", "toolu_b1", "toolu_b2"].map((id) => stampsOf(path, `SELECT created_at AS t FROM call_pending WHERE call_id = '${id}'`)[0]!);
      assert.ok(pb1! > aMax && pb2! > pb1! && pb1! > pa!, `ordered after the stored ones: ${pa} ${pb1} ${pb2}`);
      assert.ok(pb1! - aMax < 1, "one step above the floor, not a jump");
    } finally {
      b.close();
    }
    // An empty store starts at the wall clock, as before.
    const fresh = tmpDb();
    const c = new ProvenanceStore({ dbPath: fresh.path, wallClock: () => BEHIND });
    try {
      assert.equal(c.storedClockFloor(), -Infinity);
      c.recordCallPending("toolu_c", "s");
      assert.equal(stampsOf(fresh.path, "SELECT created_at AS t FROM call_pending")[0], BEHIND);
    } finally { c.close(); fresh.cleanup(); }
  } finally {
    cleanup();
  }
});

test("D7 store clock across a restart, the decisions: an agent flow opened before the restart masks a later call's receipt and a side call (before: raw)", () => {
  const { path, cleanup } = tmpDb();
  try {
    const a = new ProvenanceStore({ dbPath: path, wallClock: clockFrom(AHEAD) });
    a.taintProcessSecret({ procKey: "h-1", path: "/w/.env", level: "no-model", app: "python3", session: "s" });
    a.recordAgentFlow("socket:[9]", ["h-1"], "s"); // the agent holds a channel the holder writes into
    a.close();
    const b = new ProvenanceStore({ dbPath: path, wallClock: clockFrom(BEHIND) });
    try {
      b.recordCallPending("toolu_fetch", "s");
      // MASTER: the flow's opened_at sorted after this call's window: level null
      assert.equal(b.sideCallAgentTaint("s").level, "no-model", "CONFIDENTIALITY: a side call while the call is out");
      assert.equal(b.agentReceiptTaint("toolu_fetch", { session: "s" }).level, "no-model", "CONFIDENTIALITY: the agent's own receipt from the holder");
      b.closeAgentFlow("socket:[9]");
      b.recordCallPending("toolu_after", "s");
      assert.equal(b.agentReceiptTaint("toolu_after", { session: "s" }).level, null, "a call relayed after the close is raw (the close orders after the open)");
    } finally {
      b.close();
    }
  } finally {
    cleanup();
  }
});

test("D7 store clock across a restart, the decisions: an orphan seen after the restart folds into a call relayed before it (before: raw); one seen before does not fold into a later call (before: masked)", () => {
  const { path, cleanup } = tmpDb();
  try {
    const a = new ProvenanceStore({ dbPath: path, wallClock: clockFrom(AHEAD) });
    // A background call, bound before the restart: its result came back empty.
    a.recordCallCommand("toolu_bg", "( sleep 5; cat ./x.tx? ) &", "delivered", "s");
    shell(a, "sh-bg", "( sleep 5; cat ./x.tx? ) &");
    assert.equal(a.callTree("toolu_bg", { session: "s" }).binding, "exact");
    // An older orphan that read a secret before the restart.
    a.recordOrphanRoot("orph-old", "s");
    a.taintProcessSecret({ procKey: "orph-old", path: "/w/old.txt", level: "no-model", app: "cat", session: "s" });
    a.close();
    const b = new ProvenanceStore({ dbPath: path, wallClock: clockFrom(BEHIND) });
    try {
      // After the restart the call's subshell, orphaned, reads the secret.
      b.recordOrphanRoot("orph-bg", "s");
      b.taintProcessSecret({ procKey: "orph-bg", path: "/w/x.txt", level: "no-model", app: "cat", session: "s" });
      // MASTER: orph-bg's first_seen sorted before the call's relay: not folded, the poll's output raw
      const bg = b.callTree("toolu_bg", { session: "s" });
      assert.equal(bg.level, "no-model", `CONFIDENTIALITY: the orphan's read folds into the call relayed before it: ${JSON.stringify(bg.rows)}`);
      assert.ok(bg.rows.some((r) => r.path === "/w/x.txt"));
      // A call relayed after the restart is not masked by an orphan seen before it.
      b.recordCallCommand("toolu_new", "echo hi", "delivered", "s");
      shell(b, "sh-new", "echo hi");
      const fresh = b.callTree("toolu_new", { session: "s" });
      assert.equal(fresh.binding, "exact");
      assert.ok(!fresh.rows.some((r) => r.path === "/w/old.txt"), `utility: an orphan older than the relay is not folded (MASTER: it was): ${JSON.stringify(fresh.rows)}`);
    } finally {
      b.close();
    }
  } finally {
    cleanup();
  }
});

test("D7 store clock across a restart, the decisions: a call relayed before the restart binds the shell reported after it (before: unbound, masked whole)", () => {
  const { path, cleanup } = tmpDb();
  try {
    const a = new ProvenanceStore({ dbPath: path, wallClock: clockFrom(AHEAD) });
    a.recordCallCommand("toolu_span", "ls /w", "delivered", "s");
    a.close();
    const b = new ProvenanceStore({ dbPath: path, wallClock: clockFrom(BEHIND) });
    try {
      shell(b, "sh-span", "ls /w");
      const t = b.callTree("toolu_span", { session: "s" });
      assert.equal(t.binding, "exact", "MASTER: the window [relay, first ask] was empty, so the call was unbound");
      assert.deepEqual(t.roots, ["sh-span"]);
      // Never loosened: a shell reported after the first ask still binds nothing.
      b.recordCallCommand("toolu_late2", "ls /x", "delivered", "s");
      assert.equal(b.callTree("toolu_late2", { session: "s" }).binding, "none");
      shell(b, "sh-late2", "ls /x");
      assert.equal(b.callTree("toolu_late2", { session: "s" }).binding, "none");
    } finally {
      b.close();
    }
  } finally {
    cleanup();
  }
});

test("D7 store clock: every time column of the store's schema is a listed stamp column; the panel's `since` is the wall clock's time", () => {
  const { path, cleanup } = tmpDb();
  try {
    const s = new ProvenanceStore({ dbPath: path, wallClock: clockFrom(AHEAD) });
    s.recordCallPending("toolu_ahead", "s");
    s.close();
    const db = new Database(path);
    const timeCols: string[] = [];
    try {
      const tables = (db.prepare(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`).all() as Array<{ name: string }>).map((r) => r.name);
      for (const t of tables) {
        for (const c of db.prepare(`PRAGMA table_info(${t})`).all() as Array<{ name: string }>) {
          if ((/_at$/.test(c.name) || c.name === "first_seen") && c.name !== "wall_at") timeCols.push(`${t}.${c.name}`);
        }
      }
    } finally { db.close(); }
    const listed = STORE_STAMP_COLUMNS.map(([t, c]) => `${t}.${c}`);
    assert.deepEqual(timeCols.filter((c) => !listed.includes(c)), [], "a stamp column the clock's floor misses");
    assert.deepEqual(listed.filter((c) => !timeCols.includes(c)), [], "a listed column the schema lacks");
    // The panel shows when a secret was read, by the wall clock, though
    // the store's clock runs above it after the restart.
    const b = new ProvenanceStore({ dbPath: path, wallClock: () => BEHIND });
    try {
      b.taintProcessSecret({ procKey: "r-1", path: "/w/.env", level: "no-model", app: "cat", session: "s" });
      assert.equal(b.listSecretTaint()[0]!.since, BEHIND);
    } finally { b.close(); }
  } finally {
    cleanup();
  }
});
