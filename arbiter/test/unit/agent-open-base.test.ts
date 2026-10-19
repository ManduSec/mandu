/**
 * agent-open-base.test — the base of a relative path follows the agent's
 * REAL directory, as the kernel sees it (2026-10-17, confidentiality.md §6,
 * "The base follows the shell"; fs-sync.md §1.4.1).
 *
 * Claude Code keeps one session directory: a `cd` in a `Bash` call moves it
 * (the next call's shell is spawned there) and EnterWorktree moves it with
 * no shell at all. No request names it. Two kernel facts carry it:
 *
 *   - a `Bash` call: the directory its own shell started in
 *     (`ProvenanceStore.callStartDir`, the guard's `/proc/<pid>/cwd` at the
 *     exec), which after `cd vault` in the call before is `<ws>/vault`;
 *   - a file tool (`Read {file_path: "plan.md"}`): the file the agent itself
 *     then opened, as the guard saw the open (`recordAgentOpen`), read for
 *     the call by its relative value (`callAgentOpens`, `agentOpened`).
 *
 * Pinned here: the relative tail a value must end an opened path with; the
 * call window (an open before the call's relay is not the call's), the
 * session, the cap; the derivation's reading (raise-only: a `public` file
 * opened there lowers nothing, a value with no open keeps its other
 * readings, the token is named and never placed); and a Bash call whose
 * kernel directory is not the launch directory (masked there; with no
 * directory, the fallback of before).
 *
 * Run: npx tsx --test test/unit/agent-open-base.test.ts
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { labelForClassify, type LabelLookup } from "../../policy/secret-catalog.js";
import { resolvePathLabel, type PathLabel } from "../../policy/path-labels.js";
import { AGENT_OPENS_MAX, ProvenanceStore, relativeTail } from "../../provenance/provenance-store.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality derivation is the code under test

const HOME = "/home/u";
const WS = "/home/u/proj";

function lookupOver(...rows: Array<Partial<PathLabel> & { path: string }>): LabelLookup {
  const m = new Map<string, PathLabel>();
  for (const r of rows) {
    m.set(r.path, {
      path: r.path,
      confidentiality: r.confidentiality ?? "no-model",
      bindings: r.bindings ?? [],
      recursive: r.recursive ?? true,
      source: "user",
      updatedAt: 1,
    });
  }
  return (p) => resolvePathLabel(p, m, HOME);
}

function tmpDb(): { path: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-agent-open-"));
  return { path: join(dir, "symbols.db"), cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

const VAULT = { path: `${WS}/vault` };

// ── the relative tail ────────────────────────────────────────────────────────

test("relativeTail: the part of a relative value an opened path must end with", () => {
  assert.equal(relativeTail("plan.md"), "plan.md");
  assert.equal(relativeTail("./plan.md"), "plan.md");
  assert.equal(relativeTail("vault/plan.md"), "vault/plan.md");
  assert.equal(relativeTail("../vault/plan.md"), "vault/plan.md", "past the leading `..`: the directory above is not known");
  assert.equal(relativeTail("a/../../x/plan.md"), "x/plan.md", "lexically normalized first");
  assert.equal(relativeTail("vault//./plan.md"), "vault/plan.md");
  for (const v of ["", " ", ".", "..", "../..", "/abs/plan.md", "~/plan.md", "~u/plan.md", "a\0b"]) {
    assert.equal(relativeTail(v), null, JSON.stringify(v));
  }
});

// ── the store ────────────────────────────────────────────────────────────────

test("callAgentOpens: the files the agent opened in the call's window whose path ends with the value, in its session, newest first", () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    // an open BEFORE the call was relayed is not the call's
    store.recordAgentOpen(`${WS}/old/plan.md`, "s");
    store.recordCallPending("toolu_r", "s");
    store.recordAgentOpen(`${WS}/vault/plan.md`, "s");
    store.recordAgentOpen(`${WS}/vault/notes/plan.md`, "s");
    store.recordAgentOpen(`${WS}/vault/xplan.md`, "s"); // not a path-segment match
    store.recordAgentOpen(`${WS}/other/plan.md`, "t"); // another session
    const got = store.callAgentOpens("toolu_r", "s", ["plan.md"]).map((o) => o.path);
    assert.deepEqual(got, [`${WS}/vault/notes/plan.md`, `${WS}/vault/plan.md`]);
    assert.deepEqual(store.callAgentOpens("toolu_r", "s", ["notes/plan.md"]).map((o) => o.path), [`${WS}/vault/notes/plan.md`]);
    assert.deepEqual(store.callAgentOpens("toolu_r", "s", ["../vault/plan.md"]), [{ token: "../vault/plan.md", path: `${WS}/vault/plan.md` }]);
    assert.deepEqual(store.callAgentOpens("toolu_r", "s", ["README.md", "/abs/plan.md", "."]), [], "no open, an absolute value, nothing left");

    // a call whose relay was never recorded: the whole session (fail-closed: only adds readings)
    assert.ok(store.callAgentOpens("toolu_unrelayed", "s", ["plan.md"]).some((o) => o.path === `${WS}/old/plan.md`));
    // a request that names no session reads every session's opens (only adds readings)
    assert.ok(store.callAgentOpens("toolu_r", undefined, ["plan.md"]).some((o) => o.path === `${WS}/other/plan.md`));

    // a relative path the kernel cannot name is not kept
    store.recordAgentOpen("plan.md", "s");
    assert.ok(!store.callAgentOpens("toolu_r", "s", ["plan.md"]).some((o) => o.path === "plan.md"));

    // at most AGENT_OPENS_MAX files per value
    store.recordCallPending("toolu_many", "s");
    for (let i = 0; i < AGENT_OPENS_MAX + 5; i++) store.recordAgentOpen(`${WS}/d${i}/k.md`, "s");
    assert.equal(store.callAgentOpens("toolu_many", "s", ["k.md"]).length, AGENT_OPENS_MAX);
  } finally {
    store.close();
    cleanup();
  }
});

// ── the derivation ───────────────────────────────────────────────────────────

const read = (filePath: string, agentOpened?: Array<{ token: string; path: string }>) =>
  ({ tool: "Read", origin: filePath, params: { file_path: filePath }, ...(agentOpened !== undefined ? { agentOpened } : {}) });

test("a Read by a relative path is read at the file the agent opened: a no-model vault masks it; with no open, the reading of before", () => {
  const lk = lookupOver(VAULT);
  // THE GAP (before 2026-10-17): Claude Code resolved `plan.md` in
  // `<ws>/vault` (a `cd vault` in the Bash call before), the value named no
  // label, and the plan reached the model in clear.
  assert.equal(labelForClassify(read("plan.md"), HOME, lk).level, "public", "no kernel fact: the value as written names no label (the fallback)");
  const r = labelForClassify(read("plan.md", [{ token: "plan.md", path: `${WS}/vault/plan.md` }]), HOME, lk);
  assert.equal(r.level, "no-model");
  assert.deepEqual(r.paths, ["plan.md"], "the note names the model's own token");
  assert.equal(r.files, undefined, "never placed on a file: a path row does not narrow on it");
});

test("raise-only: a public file opened there lowers nothing; the strictest reading stands", () => {
  const lk = lookupOver(VAULT, { path: `${WS}/test/fixtures/.env`, confidentiality: "public", recursive: false });
  // a `.env`-shaped value keeps the catalog's verdict even where a public file was opened
  assert.equal(labelForClassify(read(".env", [{ token: ".env", path: `${WS}/test/fixtures/.env` }]), HOME, lk).level, "no-model");
  // two files opened that end with the value: the strictest
  const both = labelForClassify(read("plan.md", [{ token: "plan.md", path: `${WS}/plan.md` }, { token: "plan.md", path: `${WS}/vault/plan.md` }]), HOME, lk);
  assert.equal(both.level, "no-model");
  // a relative path a caller would place elsewhere is ignored
  assert.equal(labelForClassify(read("plan.md", [{ token: "plan.md", path: "vault/plan.md" }]), HOME, lk).level, "public");
});

// ── Bash: the kernel's start directory follows the shell ─────────────────────

test("a Bash call after `cd vault` in the call before: its shell started in <ws>/vault (the kernel's directory), so `cat plan.md` is masked; with no directory observed, the fallback of before", () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  const lk = lookupOver(VAULT);
  const bash = (command: string, callStartDir: string | null) =>
    ({ tool: "Bash", origin: command, params: { command }, ...(callStartDir !== null ? { callStartDir } : {}) });
  try {
    // call 1: `cd vault`, its shell started in the workspace
    store.recordCallCommand("toolu_1", "cd vault", "gate", "s");
    store.recordExecRoot({ procKey: "sh-1", ancestors: ["agent-0"], signature: "cd vault", session: "s", callRoot: true, rootSignatures: ["cd vault"], cwd: WS });
    store.callTree("toolu_1", { session: "s" });
    assert.equal(store.callStartDir("toolu_1"), WS);
    // call 2: Claude Code spawned its shell where call 1 ended
    store.recordCallCommand("toolu_2", "cat plan.md", "gate", "s");
    store.recordExecRoot({ procKey: "sh-2", ancestors: ["agent-0"], signature: "cat plan.md", session: "s", callRoot: true, rootSignatures: ["cat plan.md"], cwd: `${WS}/vault` });
    store.callTree("toolu_2", { session: "s" });
    const dir2 = store.callStartDir("toolu_2");
    assert.equal(dir2, `${WS}/vault`, "the kernel's directory for this call, not the launch directory");
    assert.equal(labelForClassify(bash("cat plan.md", dir2), HOME, lk).level, "no-model");
    // the launch directory would have read the open workspace plan
    assert.equal(labelForClassify(bash("cat plan.md", store.callStartDir("toolu_1")), HOME, lk).level, "public");
    // a root the guard reported with no directory: no base, the reading of before
    store.recordCallCommand("toolu_3", "cat  plan.md", "gate", "s");
    store.recordExecRoot({ procKey: "sh-3", ancestors: ["agent-0"], signature: "cat  plan.md", session: "s", callRoot: true, rootSignatures: ["cat  plan.md"] });
    store.callTree("toolu_3", { session: "s" });
    assert.equal(store.callStartDir("toolu_3"), null);
    assert.equal(labelForClassify(bash("cat plan.md", null), HOME, lk).level, "public", "no directory observed: the fallback (the guard's own gate of the shell's open is what masks it there)");
  } finally {
    store.close();
    cleanup();
  }
});
