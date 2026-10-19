// ci-live-events.test.mjs — scripts/ci/live-events.mjs, the guest side of a
// CI live drill session's event lanes (docs/design/testing/
// continuous-integration.md §6, "The live-drill records"): which event dir
// it reads (the run's own arbiter's, never another path), which logs (the
// sessions the run names, nothing else of the work dir), the layout
// (<run>/events-<session>.ndjson), the caps (one log, and all of them
// together: the largest left behind first) and the permissions (0600).
//
// Run: node --test scripts/test/ci-live-events.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  copyLiveEvents, namedSessions, ownArbiterEventDir, EVENTS_FILE_RE, SESSION_ID_RE, EVENTS_FILE_MAX_BYTES, EVENTS_MAX_BYTES,
} from "../ci/live-events.mjs";

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const CLI = path.join(REPO, "scripts/ci/live-events.mjs");

let root;
function tmp() {
  root ??= fs.mkdtempSync(path.join(os.tmpdir(), "ci-live-events-"));
  return fs.mkdtempSync(path.join(root, "t-"));
}
process.on("exit", () => { if (root) fs.rmSync(root, { recursive: true, force: true }); });

const RUN = "watch-20261003T010203";
const S1 = `${RUN}-util-reasoning`;
const S2 = `${RUN}-conf-env-catalog`;
const ev = (sid, n = 1) => Array.from({ length: n }, (_, i) => JSON.stringify({ v: 1, seq: i + 1, ts: "2026-10-03T01:02:04.000Z", sessionId: sid, kind: "tllm_call", input: { symbolized: "$MDU:a", original: "synthetic" } })).join("\n") + "\n";
const write = (f, data) => { fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, typeof data === "string" ? data : JSON.stringify(data)); };

/** A scratch store (what drill-run.ts left) and the dest collect_live made. */
function fixture({ sessions = { "util-reasoning": S1 }, chapters = [{ id: "util-reasoning", scopeId: S1 }], logs = { [S1]: ev(S1) }, meta = {}, inRun = true } = {}) {
  const d = tmp();
  const store = path.join(d, "live"), dest = path.join(d, "out", "drills", "live");
  const src = path.join(store, RUN);
  const m = { runId: RUN, startedAt: "2026-10-03T01:02:03Z", status: "done", sessions, ...meta };
  const evDir = inRun ? path.join(src, "arbiter", "events") : null;
  if (evDir) {
    for (const [sid, text] of Object.entries(logs)) write(path.join(evDir, `${sid}.ndjson`), text);
    write(path.join(src, "arbiter", "mandu.db"), "SYMBOL-DB");
    write(path.join(src, "arbiter", "arbiter.log"), "LOG");
    write(path.join(src, "arbiter", "policy.yaml"), "POLICY");
  }
  write(path.join(src, "meta.json"), m);
  // collect_live already copied the record files
  write(path.join(dest, RUN, "meta.json"), m);
  write(path.join(dest, RUN, "chapters.json"), chapters);
  write(path.join(dest, RUN, "report.json"), []);
  return { d, store, dest, src, evDir };
}

test("namedSessions: meta.sessions' values and the chapters' and report rows' scopeIds that are session ids, sorted and once", () => {
  assert.deepEqual(namedSessions({ sessions: { a: S2, b: S1, c: 7, d: "../x" } }, [{ scopeId: S1 }, { scopeId: "a/b" }, null], [{ scopeId: `${RUN}-x` }]), [S2, S1, `${RUN}-x`].sort());
  assert.deepEqual(namedSessions(null, "nope", undefined), []);
  for (const ok of [S1, "mandu-watch-1", "gl-1.watch-1-x"]) assert.ok(SESSION_ID_RE.test(ok), ok);
  for (const bad of ["", ".x", "a/b", "a b", "x".repeat(201)]) assert.ok(!SESSION_ID_RE.test(bad), bad);
});

test("ownArbiterEventDir: <run>/arbiter/events, else meta's eventDir only as <tmp>/mdu-a-XXXXXX/events; never a symlink or another path", () => {
  const f = fixture();
  assert.equal(ownArbiterEventDir(f.src, {}), f.evDir);
  const g = fixture({ inRun: false });
  assert.equal(ownArbiterEventDir(g.src, {}), null, "no own arbiter");
  const work = path.join(g.d, "mdu-a-Ab12Cd");
  fs.mkdirSync(path.join(work, "events"), { recursive: true });
  assert.equal(ownArbiterEventDir(g.src, { arbiter: { eventDir: path.join(work, "events") } }), path.join(work, "events"));
  for (const bad of [path.join(g.d, "elsewhere", "events"), path.join(work, "events", ".."), "relative/mdu-a-Ab12Cd/events", path.join(work, "events2")]) {
    fs.mkdirSync(bad.startsWith("/") ? bad : path.join(g.d, bad), { recursive: true });
    assert.equal(ownArbiterEventDir(g.src, { arbiter: { eventDir: bad } }), null, bad);
  }
  const linked = path.join(g.d, "mdu-a-Zz99Yy");
  fs.symlinkSync(work, linked);
  assert.equal(ownArbiterEventDir(g.src, { arbiter: { eventDir: path.join(linked, "events") } }), null, "a symlinked work dir");
  const h = fixture({ inRun: false });
  fs.mkdirSync(path.join(h.d, "real-events"));
  fs.mkdirSync(path.join(h.src, "arbiter"), { recursive: true });
  fs.symlinkSync(path.join(h.d, "real-events"), path.join(h.src, "arbiter", "events"));
  assert.equal(ownArbiterEventDir(h.src, {}), null, "a symlinked events dir");
});

test("copyLiveEvents: the named sessions' logs as <run>/events-<session>.ndjson, 0600; nothing else of the arbiter's work dir", () => {
  const f = fixture({ logs: { [S1]: ev(S1, 3), [`${RUN}-not-named`]: ev("x") } });
  const old = process.umask(0o022);
  try {
    const r = copyLiveEvents({ store: f.store, dest: f.dest });
    assert.deepEqual(r.copied.map((c) => [c.run, c.session]), [[RUN, S1]]);
    assert.deepEqual(fs.readdirSync(path.join(f.dest, RUN)).sort(), ["chapters.json", `events-${S1}.ndjson`, "meta.json", "report.json"]);
    const out = path.join(f.dest, RUN, `events-${S1}.ndjson`);
    assert.equal(fs.readFileSync(out, "utf8"), ev(S1, 3));
    assert.equal(fs.statSync(out).mode & 0o777, 0o600, "owner-only whatever the umask");
    assert.ok(EVENTS_FILE_RE.test(path.basename(out)));
    const all = fs.readdirSync(f.dest, { recursive: true }).join("\n");
    assert.ok(!/mandu\.db|arbiter\.log|policy\.yaml|not-named/.test(all), all);
  } finally { process.umask(old); }
});

test("copyLiveEvents: a named session without a log, a symlinked log and a fifo are left behind, each said", () => {
  const f = fixture({ sessions: { a: S1, b: S2, c: `${RUN}-fifo` }, logs: {} });
  fs.mkdirSync(f.evDir, { recursive: true });
  fs.writeFileSync(path.join(f.d, "outside.ndjson"), ev("outside"));
  fs.symlinkSync(path.join(f.d, "outside.ndjson"), path.join(f.evDir, `${S2}.ndjson`));
  spawnSync("mkfifo", [path.join(f.evDir, `${RUN}-fifo.ndjson`)]);
  const r = copyLiveEvents({ store: f.store, dest: f.dest });
  assert.deepEqual(r.copied, []);
  assert.ok(r.notes.some((n) => n.includes(`no event log for ${S1}`)));
  assert.ok(r.notes.some((n) => n.includes(`the event log of ${S2} left behind (not a regular file)`)));
  if (fs.existsSync(path.join(f.evDir, `${RUN}-fifo.ndjson`))) assert.ok(r.notes.some((n) => n.includes(`${RUN}-fifo left behind (not a regular file)`)));
  assert.ok(!fs.readdirSync(path.join(f.dest, RUN)).some((x) => x.startsWith("events-")));
});

test("copyLiveEvents: a run without an own arbiter carries no logs and says so; a run not in the store is skipped", () => {
  const f = fixture({ inRun: false });
  fs.mkdirSync(path.join(f.dest, "watch-only-in-dest"));
  const r = copyLiveEvents({ store: f.store, dest: f.dest });
  assert.deepEqual(r.copied, []);
  assert.ok(r.notes.some((n) => n.includes(`${RUN}: no event logs (no own arbiter's event dir`)));
});

test("caps: a log over --max-file-bytes is left behind; past --max-bytes the LARGEST go first, so the most sessions keep their lanes", () => {
  const S3 = `${RUN}-util-write-file`;
  const f = fixture({
    sessions: { a: S1, b: S2, c: S3 },
    logs: { [S1]: "a".repeat(100), [S2]: "b".repeat(300), [S3]: "c".repeat(50) },
  });
  const r = copyLiveEvents({ store: f.store, dest: f.dest, maxFileBytes: 250, maxBytes: 120 });
  assert.ok(r.notes.some((n) => n.includes(`the event log of ${S2} left behind (over 250 bytes)`)));
  assert.ok(r.notes.some((n) => n.includes(`the event log of ${S1} left behind (over the events cap: 100 bytes; cap 120 bytes`)));
  assert.deepEqual(r.copied.map((c) => c.session), [S3]);
  const again = copyLiveEvents({ store: f.store, dest: f.dest, maxFileBytes: 250, maxBytes: 120 });
  assert.deepEqual(again.copied, [], "a log already in dest is never overwritten");
  assert.ok(again.notes.some((n) => n.includes(`the event log of ${S3} not written (EEXIST)`)));
  assert.equal(EVENTS_FILE_MAX_BYTES, 32 * 1024 * 1024);
  assert.equal(EVENTS_MAX_BYTES, 96 * 1024 * 1024);
});

test("caps: across runs, the budget is drills/live's as a whole", () => {
  const f = fixture({ logs: { [S1]: "a".repeat(80) } });
  const RUN2 = "watch-20261003T020000", T = `${RUN2}-util-reasoning`;
  write(path.join(f.store, RUN2, "arbiter", "events", `${T}.ndjson`), "b".repeat(60));
  write(path.join(f.store, RUN2, "meta.json"), { startedAt: "x", sessions: { u: T } });
  write(path.join(f.dest, RUN2, "meta.json"), { startedAt: "x", sessions: { u: T } });
  const r = copyLiveEvents({ store: f.store, dest: f.dest, maxBytes: 100 });
  assert.deepEqual(r.copied.map((c) => [c.run, c.session]), [[RUN2, T]], "the larger of the two left behind");
});

test("the CLI: says what it copied and its cap; refuses a bad call", () => {
  const f = fixture();
  const r = spawnSync(process.execPath, [CLI, "--store", f.store, "--dest", f.dest, "--max-bytes", "1000000"], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /^live: event logs: 1 copied, \d+ bytes \(cap 1000000 bytes\)$/m);
  assert.ok(fs.existsSync(path.join(f.dest, RUN, `events-${S1}.ndjson`)));
  for (const bad of [["--dest", f.dest], ["--store", f.store, "--dest", f.dest, "--max-bytes", "x"], ["--bogus", "1"]]) {
    assert.equal(spawnSync(process.execPath, [CLI, ...bad], { encoding: "utf8" }).status, 2, bad.join(" "));
  }
});
