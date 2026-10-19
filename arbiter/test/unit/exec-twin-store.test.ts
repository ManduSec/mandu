/**
 * exec-twin-store.test.ts — the box→proxy symbol-twin hint store
 * (symbol-twin-shell-blindness.md §4.1 v2): signature/program correlation for
 * pipeline + post-`cd` + shell-expanded leaves, the recency and capacity
 * bounds, and the server-level reportExecTwins → execTwinsFor round trip.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import {
  ExecTwinStore,
  containsAtTokenBoundary,
  mentionsProgram,
  TWIN_HINT_MAX_PATHS,
} from "../../policy/exec-twin-store.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

const ROOT = "/views/agentview";
const twin = (asTyped: string, rel = asTyped) => ({ asTyped, abs: join(ROOT, rel) });

test("containsAtTokenBoundary: a leaf signature inside a pipeline / chain, never inside a longer word", () => {
  assert.ok(containsAtTokenBoundary("cat notes.md | grep X", "cat notes.md"));
  assert.ok(containsAtTokenBoundary("cd docs && sed -n 3p notes.md", "sed -n 3p notes.md"));
  assert.ok(containsAtTokenBoundary("cat notes.md; wc -l", "cat notes.md"));
  assert.ok(containsAtTokenBoundary("(cat notes.md)", "cat notes.md"));
  assert.ok(!containsAtTokenBoundary("cat notes.md.bak | grep X", "cat notes.md"));
  assert.ok(!containsAtTokenBoundary("concat notes.md", "cat notes.md"));
  assert.ok(!containsAtTokenBoundary("", "cat"));
  assert.ok(!containsAtTokenBoundary("cat", ""));
});

test("mentionsProgram: whole command words only, path-spelled programs included", () => {
  assert.ok(mentionsProgram("cd docs && sed -n 3p x.md", "sed"));
  assert.ok(mentionsProgram("/usr/bin/sed -n 3p x.md", "sed"));
  assert.ok(mentionsProgram("find . -name '*.md' -exec sed -n 3p {} \\;", "sed"));
  assert.ok(!mentionsProgram("used -n 3p x.md", "sed"));
  assert.ok(!mentionsProgram("echo hi", ""));
});

test("record: keeps only well-formed candidates, caps at TWIN_HINT_MAX_PATHS, ignores empty reports", () => {
  const store = new ExecTwinStore();
  assert.equal(store.record({ argv: [], twins: [twin("a.md")] }), 0);
  assert.equal(store.record({ argv: ["cat", "a.md"], twins: [] }), 0);
  assert.equal(store.record({ argv: ["cat", "a.md"], twins: [{ asTyped: "a.md", abs: "" }] }), 0);
  assert.equal(store.size(), 0);
  const many = Array.from({ length: 12 }, (_, i) => twin(`f${i}.md`));
  assert.equal(store.record({ argv: ["cat", ...many.map((t) => t.asTyped)], twins: many }), TWIN_HINT_MAX_PATHS);
  assert.equal(store.size(), 1);
});

test("twinsFor: exact, pipeline-contained and post-cd leaves all correlate; unrelated commands do not", () => {
  const store = new ExecTwinStore();
  store.record({ argv: ["cat", "notes.md"], cwd: ROOT, twins: [twin("notes.md")] });
  store.record({ argv: ["sed", "-n", "3p", "release-notes-alpha.md"], cwd: join(ROOT, "docs"), twins: [twin("release-notes-alpha.md", "docs/release-notes-alpha.md")] });

  // exact leaf == whole command
  assert.deepEqual(store.twinsFor("cat notes.md").twins, [twin("notes.md")]);
  // the pipeline the proxy's parse ALSO sees — the box hint agrees
  assert.deepEqual(store.twinsFor("cat notes.md | grep -c MDUTOKEN").twins, [twin("notes.md")]);
  // the post-cd leaf: the proxy's parse cannot resolve `release-notes-alpha.md`
  // against the root; the box saw cwd=docs and reports the real twin
  const r = store.twinsFor("cd docs && sed -n '3p' release-notes-alpha.md");
  assert.equal(r.signature, "cd docs && sed -n 3p release-notes-alpha.md");
  assert.deepEqual(r.twins, [twin("release-notes-alpha.md", "docs/release-notes-alpha.md")]);
  assert.equal(r.more, 0);
  // a bash -c wrapper unwraps to the same core
  assert.deepEqual(store.twinsFor("bash -lc 'cat notes.md | wc -l'").twins, [twin("notes.md")]);
  // an unrelated command mentioning neither leaf nor program: nothing
  assert.deepEqual(store.twinsFor("ls -la").twins, []);
  assert.deepEqual(store.twinsFor("echo hi").twins, []);
  assert.deepEqual(store.twinsFor("").twins, []);
});

test("twinsFor: shell expansion (glob / find -exec) correlates by program word; unique by abs, newest first", () => {
  const store = new ExecTwinStore();
  store.record({ argv: ["sed", "-n", "3p", "release-notes-alpha.md"], twins: [twin("release-notes-alpha.md")] });
  store.record({ argv: ["sed", "-n", "3p", "release-notes-beta.md"], twins: [twin("release-notes-beta.md")] });
  // duplicate report of the same leaf: one candidate
  store.record({ argv: ["sed", "-n", "3p", "release-notes-beta.md"], twins: [twin("release-notes-beta.md")] });
  const r = store.twinsFor("sed -n '3p' release-notes-*.md");
  assert.deepEqual(r.twins.map((t) => t.asTyped), ["release-notes-beta.md", "release-notes-alpha.md"]);
  assert.deepEqual(store.twinsFor("find . -name '*.md' -exec sed -n 3p {} \\;").twins.length, 2);
  // a different program word: nothing (grep leaves were never reported)
  assert.deepEqual(store.twinsFor("grep -r TOKEN .").twins, []);
});

test("twinsFor: the recency window and the capacity bound", () => {
  let now = 1_000_000;
  const store = new ExecTwinStore({ capacity: 2, maxAgeMs: 1000, now: () => now });
  // Distinct program words per entry, so the loose program-word rule cannot
  // cross-match and each assertion isolates ONE bound.
  store.record({ argv: ["sed", "-n", "1p", "old.md"], twins: [twin("old.md")] });
  now += 2000;
  store.record({ argv: ["cat", "new.md"], twins: [twin("new.md")] });
  assert.deepEqual(store.twinsFor("sed -n 1p old.md").twins, [], "an entry past the window never matches");
  assert.deepEqual(store.twinsFor("cat new.md").twins, [twin("new.md")]);
  store.record({ argv: ["head", "c.md"], twins: [twin("c.md")] });
  store.record({ argv: ["tail", "d.md"], twins: [twin("d.md")] });
  assert.equal(store.size(), 2, "oldest evicted on overflow");
  assert.deepEqual(store.twinsFor("cat new.md").twins, [], "evicted");
});

test("twinsFor caps the answer at TWIN_HINT_MAX_PATHS across entries and COUNTS the rest in `more`", () => {
  const store = new ExecTwinStore();
  for (let i = 0; i < 12; i++) store.record({ argv: ["cat", `f${i}.md`], twins: [twin(`f${i}.md`)] });
  const r = store.twinsFor("cat *.md");
  assert.equal(r.twins.length, TWIN_HINT_MAX_PATHS);
  assert.equal(r.more, 4, "12 matched twins − 8 listed");
  // a leaf's own `more` (the box's scan bound / report cap) carries through as the max
  const s2 = new ExecTwinStore();
  s2.record({ argv: ["tail", "-n", "+1", "a.txt"], twins: [twin("a.txt")], more: 2 });
  s2.record({ argv: ["tail", "-n", "+1", "b.txt"], twins: [twin("b.txt")], more: 1 });
  assert.deepEqual(s2.twinsFor("tail -n +1 *.txt").more, 2);
  // malformed `more` is 0
  const s3 = new ExecTwinStore();
  s3.record({ argv: ["cat", "a.md"], twins: [twin("a.md")], more: -3 });
  assert.equal(s3.twinsFor("cat a.md").more, 0);
});

// ── Server-level round trip ─────────────────────────────────────────────────

function makeServer(): { srv: ArbiterServer; cleanup: () => void } {
  const workdir = mkdtempSync(join(tmpdir(), "mandu-exectwin-"));
  const srv = new ArbiterServer({
    socketPath: join(workdir, "arbiter.sock"),
    dbPath: join(workdir, "symbols.db"),
    eventDir: join(workdir, "events"),
    log: () => {},
  });
  return { srv, cleanup: () => { srv.close().catch(() => {}); rmSync(workdir, { recursive: true, force: true }); } };
}

test("server: reportExecTwins → execTwinsFor round trip (utility op, nothing classified by it)", () => {
  const { srv, cleanup } = makeServer();
  try {
    const rep = srv.dispatch({
      id: 1, op: "reportExecTwins",
      report: { argv: ["cat", "notes.md"], cwd: ROOT, twins: [twin("notes.md")] },
    }) as { ok: boolean; result?: unknown };
    assert.equal(rep.ok, true);
    assert.deepEqual(rep.result, { recorded: 1 });
    const q = srv.dispatch({ id: 2, op: "execTwinsFor", command: "cat notes.md | grep X" }) as { ok: boolean; result?: unknown };
    assert.equal(q.ok, true);
    assert.deepEqual(q.result, { signature: "cat notes.md | grep X", twins: [twin("notes.md")], more: 0 });
    const miss = srv.dispatch({ id: 3, op: "execTwinsFor", command: "ls" }) as { result?: unknown };
    assert.deepEqual(miss.result, { signature: "ls", twins: [], more: 0 });
    // malformed report: nothing recorded, no throw
    const bad = srv.dispatch({
      id: 4, op: "reportExecTwins",
      report: { argv: "cat", twins: "x" } as unknown as { argv: string[]; twins: [] },
    }) as { ok: boolean; result?: unknown };
    assert.equal(bad.ok, true);
    assert.deepEqual(bad.result, { recorded: 0 });
  } finally {
    cleanup();
  }
});

test("server: pathLevel mirrors the mint-time derivation (catalog + labels) and reports the axis", () => {
  const { srv, cleanup } = makeServer();
  try {
    const q = (path: string) => (srv.dispatch({ id: 9, op: "pathLevel", path }) as { ok: boolean; result?: { level: string; axis: boolean; bindings: string[]; rule: string | null } });
    const env = q("/home/x/proj/.env");
    assert.equal(env.ok, true);
    if (env.result!.axis) {
      assert.equal(env.result!.level, "no-model", "the default-secret catalog marks .env strict");
      assert.equal(env.result!.rule, "shape:.env*", "the deciding rule is named, so a reader can see WHY the file is secret");
      assert.equal(q("/home/x/proj/README.md").result!.level, "public");
      assert.equal(q("/home/x/proj/README.md").result!.rule, null, "nothing matched: public by default, no rule");
    } else {
      assert.equal(env.result!.level, "public", "axis off: everything public");
      assert.equal(env.result!.rule, null);
    }
    assert.deepEqual(env.result!.bindings, []);
  } finally {
    cleanup();
  }
});
