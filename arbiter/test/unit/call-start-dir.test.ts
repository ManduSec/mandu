/**
 * call-start-dir.test — Claude Code's `Bash` names no working directory, so a
 * relative path token in its command was never matched to a human label (a
 * `public` fixture stayed masked: an over-block). Since 2026-10-04 the guard
 * reports the directory the kernel says each call's shell started in
 * (`recordExecRoot.cwd`, read off `/proc/<pid>/cwd` while the exec was
 * suspended), the arbiter keeps it for a call the call-root recorder bound
 * (`ProvenanceStore.callStartDir`), and the classify derivation reads the
 * call's relative tokens there (`callWorkdir`'s `startDir`,
 * confidentiality.md §6).
 *
 * Pinned here: the resolution (a human label decides the token, in either
 * direction; without one the stricter reading stands); every case that keeps
 * the mask (no start directory, a command that may change directory, a
 * glob or an expansion, a token that also names a secret); `..` read as the
 * label rules read an absolute path (lexically); and the store's
 * bookkeeping (only a recorder binding; shared roots must agree).
 *
 * Run: npx tsx --test test/unit/call-start-dir.test.ts
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { callWorkdir, changesDirectory, labelForClassify, labelForUnmappedInput, type LabelLookup } from "../../policy/secret-catalog.js";
import { resolvePathLabel, type PathLabel } from "../../policy/path-labels.js";
import { CODEX_WORKDIR_TOOLS } from "../../policy/tool-gate-surface.js";
import { ProvenanceStore, isCanonicalDir } from "../../provenance/provenance-store.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality derivation is the code under test

const HOME = "/home/u";

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

const PUBLIC_FIXTURE = { path: "/home/u/proj/test/fixtures/.env", confidentiality: "public" as const, recursive: false };
/** A Claude Code Bash call as the arbiter's classify handler hands it to the
 *  policy: `callStartDir` set from its own record, or not at all. */
const bash = (command: string, callStartDir?: string) =>
  ({ tool: "Bash", origin: command, params: { command }, ...(callStartDir !== undefined ? { callStartDir } : {}) });

// ── the resolution ───────────────────────────────────────────────────────────

test("a Bash call whose shell started in a known directory: a relative token there takes the human's public label, as a Read of the path does", () => {
  const lk = lookupOver(PUBLIC_FIXTURE);
  assert.equal(labelForClassify(bash("cat test/fixtures/.env", "/home/u/proj"), HOME, lk).level, "public");
  assert.equal(labelForClassify(bash("rg '^API_KEY=' ./test/fixtures/.env", "/home/u/proj"), HOME, lk).level, "public");
  assert.equal(labelForClassify(bash("cat fixtures/.env", "/home/u/proj/test"), HOME, lk).level, "public");
  assert.equal(labelForClassify(bash("cat test/fixtures/.env | head -3", "/home/u/proj"), HOME, lk).level, "public", "a pipeline that changes no directory");
  // the same file, the same call, no start directory known: the catalog's `.env` shape (fail-closed)
  assert.equal(labelForClassify(bash("cat test/fixtures/.env"), HOME, lk).level, "no-model");
});

test("`..` is read lexically, as the label rules read an absolute path: it lifts only where the path it names is the labelled one", () => {
  const lk = lookupOver(PUBLIC_FIXTURE);
  assert.equal(labelForClassify(bash("cat ../test/fixtures/.env", "/home/u/proj/src"), HOME, lk).level, "public");
  assert.equal(labelForClassify(bash("cat test/fixtures/../../.env", "/home/u/proj"), HOME, lk).level, "no-model", "names /home/u/proj/.env: no label there, the catalog's shape");
  assert.equal(labelForClassify(bash("cat ../../proj/test/fixtures/.env", "/home/u/proj/test"), HOME, lk).level, "public");
});

test("the human label decides in either direction: a relative token under a no-model label is masked where the catalog knew nothing", () => {
  const lk = lookupOver({ path: "/home/u/proj/vault", confidentiality: "no-model", recursive: true });
  assert.equal(labelForClassify(bash("cat vault/key.txt", "/home/u/proj"), HOME, lk).level, "no-model");
  const none = lookupOver();
  assert.equal(labelForClassify(bash("cat notes.md", "/home/u/proj"), HOME, none).level, "public");
  assert.equal(labelForClassify(bash("cat .env", "/home/u/proj"), HOME, none).level, "no-model", "no label: the stricter reading");
});

// ── what keeps the mask ──────────────────────────────────────────────────────

test("a call that also names a secret stays masked: every other token keeps its own verdict", () => {
  const lk = lookupOver(PUBLIC_FIXTURE);
  assert.equal(labelForClassify(bash("cat test/fixtures/.env .env", "/home/u/proj"), HOME, lk).level, "no-model");
  assert.equal(labelForClassify(bash("cat test/fixtures/.env ~/.aws/credentials", "/home/u/proj"), HOME, lk).level, "no-model");
  assert.equal(labelForClassify(bash("cat other/.env", "/home/u/proj"), HOME, lk).level, "no-model", "the same name elsewhere is not the labelled file");
});

test("a command that may change directory before it reads keeps the mask: cd, pushd, a subshell's cd, -C, source, `.`, eval", () => {
  const lk = lookupOver(PUBLIC_FIXTURE);
  for (const cmd of [
    "cd test && cat fixtures/.env",
    "cd /elsewhere; cat test/fixtures/.env",
    "pushd /x >/dev/null; cat test/fixtures/.env",
    "(cd /x && cat test/fixtures/.env)",
    "bash -c 'cd /x; cat test/fixtures/.env'",
    "git -C /x show HEAD:test/fixtures/.env",
    "source ./env.sh && cat test/fixtures/.env",
    ". ./env.sh; cat test/fixtures/.env",
    "true && . ./env.sh && cat test/fixtures/.env",
    "eval \"$GO\"; cat test/fixtures/.env",
  ]) {
    assert.equal(labelForClassify(bash(cmd, "/home/u/proj"), HOME, lk).level, "no-model", cmd);
  }
  // a glob or an expansion is not one path
  assert.equal(labelForClassify(bash("cat test/*/.env", "/home/u/proj"), HOME, lk).level, "no-model");
  assert.equal(labelForClassify(bash("cat $D/test/fixtures/.env", "/home/u/proj"), HOME, lk).level, "no-model");
});

test("changesDirectory: the new words, and what is not one", () => {
  for (const t of ["source x", "a && source x", ". x", "a; . x", "(. x)", "eval x", "a | eval x"]) assert.equal(changesDirectory(t), true, t);
  for (const t of ["cat ./x", "cat ../x", "ls .", "echo sourced", "rg evaluate f", "cat a.b", "git log ."]) assert.equal(changesDirectory(t), false, t);
});

test("callWorkdir: the start directory is any non-workdir tool's base, only absolute and with no `..`; Codex's tools keep theirs", () => {
  assert.equal(callWorkdir("Bash", { command: "x" }, undefined, "/w/proj"), "/w/proj");
  assert.equal(callWorkdir("Bash", { command: "x" }), undefined, "no start directory: none");
  assert.equal(callWorkdir("Bash", { command: "x" }, "/s"), undefined, "Codex's session default is not Claude's");
  assert.equal(callWorkdir("Bash", { command: "x", workdir: "/claimed" }), undefined, "a workdir param Bash does not have is a claim nothing checks");
  assert.equal(callWorkdir("Bash", { command: "x" }, undefined, "proj"), undefined);
  assert.equal(callWorkdir("Bash", { command: "x" }, undefined, "/w/../etc"), undefined);
  assert.equal(callWorkdir("exec_command", { workdir: "/w" }, undefined, "/k", CODEX_WORKDIR_TOOLS), "/w", "Codex's named workdir is unchanged");
  assert.equal(callWorkdir("exec_command", { workdir: "/w" }, undefined, "/k"), "/k", "no agent named: the kernel's directory, never the claim");
  assert.equal(callWorkdir("exec_command", { cmd: "x" }, "/s", "/k", CODEX_WORKDIR_TOOLS), "/s");
  assert.equal(callWorkdir(undefined, { command: "x" }, undefined, "/w"), undefined);
});

test("an unmapped tool's scan reads the start directory the same way", () => {
  const lk = lookupOver(PUBLIC_FIXTURE);
  const wide = labelForUnmappedInput([{ command: "cat test/fixtures/.env" }], HOME, lk, callWorkdir("acme_shell", {}, undefined, "/home/u/proj"));
  assert.equal(wide.level, "public");
  assert.match(wide.rule ?? "", /^label:/);
});

// ── the store ────────────────────────────────────────────────────────────────

function tmpDb(): { path: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-start-dir-"));
  return { path: join(dir, "symbols.db"), cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test("callStartDir: the kernel's directory of a call the recorder bound; none for an unbound, claimed or guessed call, or a root with no directory", () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    store.recordCallCommand("toolu_d", "cat a/.env", "gate", "s");
    store.recordExecRoot({ procKey: "sh-d", ancestors: ["agent-0"], signature: "cat a/.env", session: "s", callRoot: true, rootSignatures: ["cat a/.env"], cwd: "/w/proj" });
    assert.equal(store.callStartDir("toolu_d"), null, "not bound yet: callTaint's ask binds, this lookup does not");
    assert.equal(store.callTree("toolu_d", { session: "s" }).binding, "exact");
    assert.equal(store.callStartDir("toolu_d"), "/w/proj");
    assert.equal(store.callStartDir("toolu_d"), "/w/proj", "a lookup, repeatable");

    // a root the guard reported without a directory
    store.recordCallCommand("toolu_n", "cat b/.env", "gate", "s");
    store.recordExecRoot({ procKey: "sh-n", ancestors: ["agent-0"], signature: "cat b/.env", session: "s", callRoot: true, rootSignatures: ["cat b/.env"] });
    store.callTree("toolu_n", { session: "s" });
    assert.equal(store.callStartDir("toolu_n"), null);
    // a directory sent with an exec that is not a call root is not kept
    store.recordExecRoot({ procKey: "sh-n", signature: "cat b/.env", session: "s", cwd: "/elsewhere" });
    assert.equal(store.callStartDir("toolu_n"), null);

    // a caller's claim and a guess are not evidence the tree is the call's
    store.recordExecRoot({ procKey: "sh-g", ancestors: ["agent-0"], signature: "ls", session: "s", callRoot: true, rootSignatures: ["ls"], cwd: "/w/proj" });
    store.recordCallRoot("toolu_claimed", "sh-g", "s");
    assert.equal(store.callTree("toolu_claimed", { session: "s" }).binding, "claimed");
    assert.equal(store.callStartDir("toolu_claimed"), null);
    assert.equal(store.callTree("toolu_guess", { signature: "ls", session: "s" }).binding, "guess");
    assert.equal(store.callStartDir("toolu_guess"), null);
    assert.equal(store.callStartDir("toolu_unknown"), null);

    // a directory the kernel does not name plainly is not kept
    store.recordCallCommand("toolu_dd", "cat c/.env", "gate", "s");
    store.recordExecRoot({ procKey: "sh-dd", ancestors: ["agent-0"], signature: "cat c/.env", session: "s", callRoot: true, rootSignatures: ["cat c/.env"], cwd: "/w/../etc" });
    store.callTree("toolu_dd", { session: "s" });
    assert.equal(store.callStartDir("toolu_dd"), null);
  } finally {
    store.close();
    cleanup();
  }
});

test("callStartDir: a call bound to two shells (shared) has a directory only when both started in the same one", () => {
  const { path, cleanup } = tmpDb();
  const store = new ProvenanceStore({ dbPath: path });
  try {
    for (const [call, a, b, da, db] of [
      ["toolu_same", "sh-s1", "sh-s2", "/w/proj", "/w/proj"],
      ["toolu_diff", "sh-d1", "sh-d2", "/w/proj", "/w/other"],
    ] as const) {
      const cmd = `cat ${call}/.env`;
      store.recordCallCommand(call, cmd, "gate", "s");
      store.recordExecRoot({ procKey: a, ancestors: ["agent-0"], signature: cmd, session: "s", callRoot: true, rootSignatures: [cmd], cwd: da });
      store.recordExecRoot({ procKey: b, ancestors: ["agent-0"], signature: cmd, session: "s", callRoot: true, rootSignatures: [cmd], cwd: db });
      assert.equal(store.callTree(call, { session: "s" }).binding, "shared");
    }
    assert.equal(store.callStartDir("toolu_same"), "/w/proj");
    assert.equal(store.callStartDir("toolu_diff"), null, "nothing tells which shell ran the call");
  } finally {
    store.close();
    cleanup();
  }
});

test("isCanonicalDir", () => {
  for (const d of ["/", "/w", "/w/proj x"]) assert.equal(isCanonicalDir(d), true, d);
  for (const d of ["", "w", "/w/", "/w//x", "/w/./x", "/w/../x", "/w/gone (deleted)", "(unreachable)/w", 7, null]) assert.equal(isCanonicalDir(d), false, String(d));
});
