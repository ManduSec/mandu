/**
 * policy-suggestions e2e — confidentiality plan 14 §4, §5.1, §5.2, §5.5
 * through the REAL arbiter: an in-process ArbiterServer with a file-backed
 * law, a DATA socket (what the agent's tools and the terminal reach) and an
 * ADMIN socket (what the dashboard supervisor holds), the production
 * `ArbiterClient` on both (no test bridge: this is also the client's parity
 * test), and the real git-history scan over a REAL fixture repository:
 *
 *   - a deploy key committed and then deleted (C17): `suggestPolicy` files
 *     one lock-path suggestion; `applySuggestion` on the DATA socket applies
 *     it and the law (and policy.yaml) shows the lock;
 *   - a token once inline in `config.py`, since removed: a lock-blob
 *     suggestion, dismissed ("Not a secret") on the ADMIN socket after the
 *     data socket is refused;
 *   - a labelled file holding a key: covered, no suggestion;
 *   - a rescan files nothing: the applied one is covered by the law, the
 *     dismissed one stays dismissed;
 *   - the §5.5 budget: with `waitMs` the reply comes before the scan ends,
 *     and the arbiter files what it finds in the background;
 *   - axis OFF: `suggestPolicy` answers empty;
 *   - provenance: an apply on the DATA socket is recorded `agent-tighten`,
 *     one on the ADMIN socket `tighten` by the named person; a relaxing
 *     suggestion is refused on both and records nothing;
 *   - a label that lives only in mandu.db (set on the dashboard, on a path
 *     that no longer exists) covers the path: nothing is suggested for it,
 *     and a pending suggestion is closed `superseded` on the next read.
 *
 * The oracle (implementation-plan.md §9): the key's bytes, and every
 * 8-character run of either secret's body, appear in no op reply, the event
 * store, the arbiter's log, or the proposals table. Axes stated: secrets.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import Database from "../../db/sqlite.js";
import { ArbiterServer, adminOnlyError } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { resetCurrentPolicyForTests } from "../../policy/compiled-policy.js";
import { POLICY_EDIT_OPS } from "../../policy/policy-edit.js";
import { defaultHistoryGitRunner } from "../../policy/secret-history-scan.js";
import type { SuggestPolicyResult } from "../../ipc/protocol.js";
import { stateAxes } from "../axes.js";
import { randomSecretBody } from "../helpers/random-secret.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

const LOCK_BLOB_KNOWN = (POLICY_EDIT_OPS as readonly string[]).includes("lock-blob");
assert.equal(LOCK_BLOB_KNOWN, true, "lock-blob is in the law's grammar (plan 14 §8.2)");

// Assembled at run time from random bytes: this file holds no key-shaped
// literal, and a run of a body cannot match an id or a path by accident.
// A letter and a digit, no placeholder run: a value the detectors take
// (a plain random draw has no digit 0.19% of the time; random-secret.ts).
const alnum = randomSecretBody;
const KEY_BODY = alnum(96);
const PEM = `-----BEGIN OPENSSH ` + `PRIVATE KEY-----\n${KEY_BODY}\n-----END OPENSSH PRIVATE KEY-----\n`;
const TOKEN_BODY = alnum(36);
const TOKEN = "gh" + "p_" + TOKEN_BODY;
const RUNS = [KEY_BODY, TOKEN_BODY].flatMap((b) => Array.from({ length: b.length - 7 }, (_, i) => b.slice(i, i + 8)));

function noValue(what: string, s: string): void {
  assert.ok(!s.includes(PEM) && !s.includes(TOKEN), `${what} carries a secret`);
  const hit = RUNS.find((r) => s.includes(r));
  assert.equal(hit, undefined, `${what} carries an 8-character run of a secret's body`);
}

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

interface Fixture { dir: string; home: string; repo: string; policy: string; added: string; removed: string }

function fixture(): Fixture {
  // realpath: the history scan names a repository by git's real top level,
  // and macOS reaches the temp dir through a link (/tmp, /var → /private/…).
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-suggest-e2e-")));
  dirs.push(dir);
  const home = join(dir, "home");
  const repo = join(home, "proj");
  mkdirSync(repo, { recursive: true });
  const gitEnv = { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" };
  const git = (...a: string[]): string => execFileSync("git", a, { cwd: repo, env: gitEnv, encoding: "utf8" });
  const put = (rel: string, body: string): void => { mkdirSync(join(repo, rel, ".."), { recursive: true }); writeFileSync(join(repo, rel), body); };
  git("init", "-q", "-b", "main");
  put("README.md", "a project\n");
  put("config.py", `API_TOKEN = "${TOKEN}"\n`);
  put("protected.txt", `token ${TOKEN}\n`);
  git("add", "."); git("commit", "-qm", "init");
  put("deploy/id_ed25519", PEM);
  git("add", "."); git("commit", "-qm", "add deploy key");
  const added = git("rev-parse", "HEAD").trim();
  git("rm", "-q", "deploy/id_ed25519");
  put("config.py", "import os\nAPI_TOKEN = os.environ['API_TOKEN']\n");
  git("add", "."); git("commit", "-qm", "remove the key; read the token from the environment");
  const removed = git("rev-parse", "HEAD").trim();
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${join(repo, "protected.txt")}\n    level: no-model\n`);
  return { dir, home, repo, policy, added, removed };
}

async function rig(
  f: Fixture,
  opts: { confidentiality?: boolean; slowGitMs?: number },
  fn: (c: { data: ArbiterClient; admin: ArbiterClient; logs: string[] }) => Promise<void>,
): Promise<void> {
  const logs: string[] = [];
  const server = new ArbiterServer({
    socketPath: join(f.dir, "arbiter.sock"),
    adminSocketPath: join(f.dir, "admin.sock"),
    dbPath: join(f.dir, "mandu.db"),
    eventDir: join(f.dir, "events"),
    policyPath: f.policy,
    policyPollMs: 0,
    confidentiality: opts.confidentiality ?? true,
    integrity: false,
    log: (m) => logs.push(m),
    ...(opts.slowGitMs
      ? { historyScan: { git: async (args, o) => { await new Promise((r) => setTimeout(r, opts.slowGitMs)); return defaultHistoryGitRunner(args, o); } } }
      : {}),
  });
  await server.listen();
  const data = new ArbiterClient(join(f.dir, "arbiter.sock"));
  const admin = new ArbiterClient(join(f.dir, "admin.sock"));
  try {
    await fn({ data, admin, logs });
  } finally {
    data.close();
    admin.close();
    await server.close();
  }
}

function storeText(f: Fixture): { events: string; proposals: string } {
  const eventsDir = join(f.dir, "events");
  const events = existsSync(eventsDir)
    ? readdirSync(eventsDir, { recursive: true, withFileTypes: true })
      .filter((e) => e.isFile()).map((e) => readFileSync(join(e.parentPath, e.name), "utf8")).join("")
    : "";
  const db = new Database(join(f.dir, "mandu.db"));
  const proposals = JSON.stringify(db.prepare("SELECT * FROM policy_proposals").all()) + JSON.stringify(db.prepare("SELECT * FROM policy_changes").all());
  db.close();
  return { events, proposals };
}

test("C17 through the real arbiter: the scan files, the data socket applies, only the admin dismisses, a rescan refiles nothing, no value anywhere", async () => {
  const f = fixture();
  const replies: string[] = [];
  await rig(f, {}, async ({ data, admin, logs }) => {
    // ── the scan files: one lock-path (the deleted key), one lock-blob (the old config.py); protected.txt is covered
    const r = await data.suggestPolicy([f.repo], { home: f.home });
    replies.push(JSON.stringify(r));
    assert.equal(r.axis, true);
    assert.equal(r.running, false);
    assert.equal(r.counts.filed, 2, JSON.stringify(r.counts));
    assert.equal(r.counts.covered, 1);
    const key = r.suggestions.find((s) => s.edits[0]?.op === "lock-path")!;
    const blob = r.suggestions.find((s) => s.edits[0]?.op === "lock-blob")!;
    assert.deepEqual(key.edits, [{ op: "lock-path", path: join(f.repo, "deploy/id_ed25519"), level: "no-model" }]);
    assert.equal(key.sentence, "Make ~/proj/deploy/id_ed25519 a secret no AI may read (only in git history)");
    assert.equal(key.requestedBy, "mandu:scan");
    assert.equal(key.historyOnly, true);
    assert.equal(key.rotate, true);
    assert.equal(key.evidence.findings[0]!.firstCommit, f.added);
    assert.equal(key.evidence.findings[0]!.lastCommit, f.removed);
    assert.equal(key.evidence.findings[0]!.detectors[0]!.mask, "-----BEGIN OPENSSH " + "PRIVATE KEY-----…");
    assert.equal(blob.sentence, "Hide an old version of ~/proj/config.py from the AI");
    assert.equal(blob.historyOnly, false);
    assert.equal(blob.applicable, LOCK_BLOB_KNOWN);
    assert.deepEqual(r.covered.map((c) => c.paths), [["protected.txt"]]);
    // The Inbox's proposal list is not flooded; the suggestions have their own read.
    assert.equal((await data.policyProposals("pending")).proposals.length, 0);
    const listed = await data.policySuggestions("pending");
    replies.push(JSON.stringify(listed));
    assert.equal(listed.suggestions.length, 2);

    // ── "Not a secret" is refused on the data socket, whatever the args
    await assert.rejects(() => data.dismissSuggestion(blob.id, "human:forged"), new RegExp(adminOnlyError("dismissSuggestion").replace(/[()']/g, ".")));
    assert.equal((await data.policySuggestions("pending")).suggestions.length, 2, "the refused dismissal did nothing");

    // ── Apply on the DATA socket (the terminal's path): a pure tightening
    const before = readFileSync(f.policy, "utf8");
    const applied = await data.applySuggestion(key.id);
    replies.push(JSON.stringify(applied));
    assert.equal(applied.applied, true);
    assert.equal(applied.suggestion.status, "approved");
    assert.notEqual(readFileSync(f.policy, "utf8"), before);
    const law = await data.policyDocument();
    const lock = (law.inForce as { paths?: Array<{ path: string; level: string }> }).paths?.find((p) => p.path === join(f.repo, "deploy/id_ed25519"));
    assert.deepEqual(lock, { path: join(f.repo, "deploy/id_ed25519"), level: "no-model" });
    const change = (await data.policyChanges(1)).changes[0]!;
    assert.equal(change.via, "agent-tighten", "the data socket is the agent's channel: its apply is never recorded as a person's");
    assert.equal(change.proposalId, key.id);
    assert.equal(change.proposedBy, "mandu:scan");
    assert.equal(change.requestedBy, "data-plane", "the data plane never names a human");
    assert.equal(change.undoable, true);
    await assert.rejects(() => data.applySuggestion(key.id), /already approved/);

    // ── dismissed on the ADMIN socket
    const dismissed = await admin.dismissSuggestion(blob.id, "human:e2e");
    replies.push(JSON.stringify(dismissed));
    assert.equal(dismissed.suggestion.status, "denied");

    // ── a rescan files nothing: the key is covered by the law, the dismissed one stays dismissed
    const again = await data.suggestPolicy([f.repo], { home: f.home });
    replies.push(JSON.stringify(again));
    assert.equal(again.counts.filed, 0, JSON.stringify(again.counts));
    assert.equal(again.counts.dismissed, 1);
    assert.equal(again.counts.covered, 2, "protected.txt, and now the deploy key");
    assert.equal(again.suggestions.length, 0);

    // ── the oracle
    const all = await admin.policySuggestions();
    replies.push(JSON.stringify(all), JSON.stringify(await admin.policyProposals(undefined)));
    const { events, proposals } = storeText(f);
    assert.match(events, /"policySuggestion":\{"action":"filed"/, "the dashboard can react to a filing");
    assert.match(events, /"action":"applied"/);
    assert.match(events, /"action":"dismissed"/);
    for (const [what, s] of [["the op replies", replies.join("\n")], ["the event store", events], ["the proposals table", proposals], ["the arbiter log", logs.join("\n")], ["policy.yaml", readFileSync(f.policy, "utf8")]] as const) {
      noValue(what, s);
    }
  });
});

test("lock-blob end to end: the old version is locked by id, the current file untouched; the launcher's read carries it; a rescan finds it covered", async () => {
  const f = fixture();
  await rig(f, {}, async ({ data }) => {
    const r = await data.suggestPolicy([f.repo], { home: f.home });
    const blob = r.suggestions.find((s) => s.edits[0]?.op === "lock-blob")!;
    assert.equal(blob.applicable, true);
    const id = (blob.edits[0] as { blob: string }).blob;
    assert.match(id, /^sha1:[0-9a-f]{40}$/);
    const applied = await data.applySuggestion(blob.id);
    assert.equal(applied.applied, true, JSON.stringify(applied));
    assert.deepEqual(applied.delta.map((d) => [d.facet, d.direction, d.subject]), [["blob-lock", "tighten", id]]);
    const text = readFileSync(f.policy, "utf8");
    assert.match(text, /blobs:/);
    assert.doesNotMatch(text, /config\.py\n\s+level/, "no path lock on the current config.py");
    noValue("policy.yaml", text);
    // What the launcher's object twins read at the next launch (§8.2).
    assert.deepEqual((await data.gitHistoryLocks()).blobs, [{ id, level: "no-model" }]);
    // The scan now reports the locked version covered, so nothing refiles.
    const again = await data.suggestPolicy([f.repo], { home: f.home });
    assert.equal(again.suggestions.some((s) => s.edits.some((e) => e.op === "lock-blob")), false, JSON.stringify(again.counts));
    assert.ok(again.covered.some((c) => c.blobs.includes(id.slice("sha1:".length))), JSON.stringify(again.covered));
  });
});

test("§5.5: with a budget the reply comes first; the scan finishes and files in the background", async () => {
  const f = fixture();
  await rig(f, { slowGitMs: 150 }, async ({ data }) => {
    const r: SuggestPolicyResult = await data.suggestPolicy([f.repo], { home: f.home, waitMs: 0 });
    assert.equal(r.axis, true);
    assert.equal(r.running, true);
    assert.equal(r.filed.length, 0);
    // A second call while it runs, with a budget, is an answer too (not an error).
    const busy = await data.suggestPolicy([f.repo], { home: f.home, waitMs: 0 });
    assert.equal(busy.running, true);
    const deadline = Date.now() + 60_000;
    let pending = 0;
    while (Date.now() < deadline) {
      pending = (await data.policySuggestions("pending")).suggestions.length;
      // One filing lands every suggestion at once: stop at the first count, so a
      // wrong one fails the assert below at once, not at the deadline.
      if (pending >= 2) break;
      await new Promise((res) => setTimeout(res, 100));
    }
    assert.equal(pending, 2, "the background scan filed its suggestions");
  });
});

test("§5.5: answerFromEarlier over the real client — the first launch's scan is waited for; the next answers at once from it and scans in the background", async () => {
  const f = fixture();
  await rig(f, { slowGitMs: 150 }, async ({ data }) => {
    let t0 = Date.now();
    const first = await data.suggestPolicy([f.repo], { home: f.home, waitMs: 60_000, answerFromEarlier: true });
    const scanMs = Date.now() - t0;
    assert.equal(first.running, false);
    assert.equal(first.suggestions.length, 2);
    assert.equal(typeof first.lastScanAt, "number");
    t0 = Date.now();
    const second = await data.suggestPolicy([f.repo], { home: f.home, waitMs: 60_000, answerFromEarlier: true });
    const answerMs = Date.now() - t0;
    assert.equal(second.running, true);
    assert.equal(second.lastScanAt, first.lastScanAt);
    assert.deepEqual(second.suggestions.map((s) => s.id).sort(), first.suggestions.map((s) => s.id).sort(), "what the finished scan left");
    assert.ok(answerMs < scanMs, `answered (${answerMs} ms) before a scan could end (${scanMs} ms)`);
    // The scan goes on in the arbiter and records its own time.
    const deadline = Date.now() + 60_000;
    let third: SuggestPolicyResult | null = null;
    while (third === null && Date.now() < deadline) {
      try { third = await data.suggestPolicy([f.repo], { home: f.home }); } catch { await new Promise((res) => setTimeout(res, 100)); }
    }
    assert.ok(third !== null, "the background scan ended");
    assert.ok(third.lastScanAt! > first.lastScanAt!);
    assert.equal(third.counts.alreadyPending, 2, "the background scan refiled nothing");
  });
});

test("§5.5 across an arbiter restart: the finished scan is kept in mandu.db, so the first launch after a restart answers at once", async () => {
  const f = fixture();
  let first: SuggestPolicyResult | null = null;
  let scanMs = 0;
  await rig(f, { slowGitMs: 150 }, async ({ data }) => {
    const t0 = Date.now();
    first = await data.suggestPolicy([f.repo], { home: f.home, waitMs: 60_000, answerFromEarlier: true });
    scanMs = Date.now() - t0;
    assert.equal(first.running, false, "a new workspace: the scan is waited for");
    assert.equal(first.suggestions.length, 2);
    assert.equal(typeof first.lastScanAt, "number");
  });
  const kept = first as unknown as SuggestPolicyResult;
  // What the table holds: the root and a time, nothing of what the scan read.
  const db = new Database(join(f.dir, "mandu.db"));
  const rows = (db.prepare("SELECT root, finished_at FROM suggest_scans").all() as Array<{ root: string; finished_at: number }>).map((r) => ({ ...r }));
  db.close();
  assert.deepEqual(rows, [{ root: f.repo, finished_at: kept.lastScanAt }]);
  noValue("the suggest_scans table", JSON.stringify(rows));

  // A new arbiter process on the same mandu.db (an upgrade, `mandu stop`, a reboot).
  await rig(f, { slowGitMs: 150 }, async ({ data }) => {
    const t0 = Date.now();
    const again = await data.suggestPolicy([f.repo], { home: f.home, waitMs: 60_000, answerFromEarlier: true });
    const answerMs = Date.now() - t0;
    assert.equal(again.running, true, "answered from the kept scan, this one in the background");
    assert.equal(again.lastScanAt, kept.lastScanAt, "the time the earlier arbiter's scan finished");
    assert.deepEqual(again.suggestions.map((s) => s.id).sort(), kept.suggestions.map((s) => s.id).sort(), "what that scan filed");
    assert.ok(answerMs < scanMs, `answered (${answerMs} ms) before a scan could end (${scanMs} ms)`);
    // A cwd under the kept root counts; a sibling with a common prefix does not.
    const under = await data.suggestPolicy([join(f.repo, "sub")], { home: f.home, waitMs: 0, answerFromEarlier: true });
    assert.equal(under.lastScanAt, kept.lastScanAt);
    noValue("the answer from the kept scan", JSON.stringify(again));
    const deadline = Date.now() + 60_000;
    let done: SuggestPolicyResult | null = null;
    while (done === null && Date.now() < deadline) {
      try { done = await data.suggestPolicy([f.repo], { home: f.home }); } catch { await new Promise((res) => setTimeout(res, 100)); }
    }
    assert.ok(done !== null, "the background scan ended");
    assert.ok(done.lastScanAt! > kept.lastScanAt!, "and recorded its own time");
  });
});

test("axis OFF: suggestPolicy answers empty and files nothing", async () => {
  const f = fixture();
  await rig(f, { confidentiality: false }, async ({ data }) => {
    const r = await data.suggestPolicy([f.repo], { home: f.home });
    assert.equal(r.axis, false);
    assert.deepEqual(r.suggestions, []);
    assert.equal((await data.policySuggestions()).suggestions.length, 0);
  });
});

test("provenance: the data socket's apply is recorded agent-tighten, the admin socket's tighten by the person", async () => {
  const f = fixture();
  await rig(f, {}, async ({ data, admin }) => {
    const r = await data.suggestPolicy([f.repo], { home: f.home });
    const key = r.suggestions.find((s) => s.edits[0]?.op === "lock-path")!;
    const blob = r.suggestions.find((s) => s.edits[0]?.op === "lock-blob")!;
    // The client sends requestedBy; the data plane ignores it (it never names a person).
    const viaData = await data.applySuggestion(key.id, "human:forged");
    assert.equal(viaData.applied, true, JSON.stringify(viaData));
    const viaAdmin = await admin.applySuggestion(blob.id, "human:e2e");
    assert.equal(viaAdmin.applied, true, JSON.stringify(viaAdmin));
    const byId = new Map((await admin.policyChanges(5)).changes.map((c) => [c.proposalId, c]));
    assert.deepEqual([byId.get(key.id)?.via, byId.get(key.id)?.requestedBy, byId.get(key.id)?.sessionKey], ["agent-tighten", "data-plane", null]);
    assert.deepEqual([byId.get(blob.id)?.via, byId.get(blob.id)?.requestedBy], ["tighten", "human:e2e"]);
    assert.equal(byId.get(key.id)?.undoable, true, "undoable in History like the agent's own tightening");
  });
});

test("a label only in mandu.db covers its path: no duplicate suggestion, and a pending one is closed superseded", async () => {
  const f = fixture();
  const deployKey = join(f.repo, "deploy/id_ed25519"); // deleted from the work tree: the path no longer exists
  await rig(f, {}, async ({ data, admin }) => {
    const first = await data.suggestPolicy([f.repo], { home: f.home });
    const key = first.suggestions.find((s) => s.edits[0]?.op === "lock-path")!;
    assert.deepEqual(key.edits, [{ op: "lock-path", path: deployKey, level: "no-model" }]);
    // The person labels it on the dashboard: a row in mandu.db, not policy.yaml.
    await admin.setPathLabel({ path: deployKey, confidentiality: "no-model" });
    assert.doesNotMatch(readFileSync(f.policy, "utf8"), /id_ed25519/, "the label lives only in mandu.db");
    const listed = await data.policySuggestions();
    assert.equal(listed.suggestions.find((s) => s.id === key.id)?.status, "superseded", "the db label covers the pending lock");
  });
  // A fresh scan (a new arbiter on the same mandu.db, no pending row left to dedup against): still nothing for it.
  rmSync(join(f.dir, "arbiter.sock"), { force: true });
  rmSync(join(f.dir, "admin.sock"), { force: true });
  const db = new Database(join(f.dir, "mandu.db"));
  db.prepare("DELETE FROM policy_proposals").run();
  db.close();
  await rig(f, {}, async ({ data }) => {
    const again = await data.suggestPolicy([f.repo], { home: f.home });
    assert.equal(again.suggestions.some((s) => s.edits.some((e) => e.op === "lock-path" && (e as { path?: string }).path === deployKey)), false, JSON.stringify(again.suggestions.map((s) => s.edits)));
    assert.ok(again.covered.some((c) => c.paths.includes("deploy/id_ed25519")), JSON.stringify(again.covered));
  });
});
