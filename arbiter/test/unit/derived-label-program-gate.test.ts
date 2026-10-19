/**
 * derived-label-program-gate.test.ts — confidentiality plan 13 D4, the
 * arbiter's half: a DERIVED label (a file a process holding a secret wrote,
 * or a high session's write) reaches the program gate.
 *
 * Before the fix the label stored the level and nothing read it at the gate:
 * the guard loaded its secret index once at start, nothing told it of a
 * derived path, and the next launch's discovery did not list derived labels.
 * So a copy of `.env` made by a reader was opened raw by every program
 * (`curl --data @copy.txt`), this session and every later one, and the label
 * fell off at `mv`. Asserted here:
 *
 *   - the store numbers its changes (`gen`, `since`, an `epoch` per store),
 *     so the guard can ask for what changed since its last look;
 *   - `derivedLabelsSince` answers the derived paths that classify secret,
 *     with their level, all of them on a new epoch, only the new ones after;
 *     nothing with the confidentiality axis off;
 *   - `followDerivedLabel` labels the new name of a renamed or hard-linked
 *     derived file at the source's level (raise-only: a path with no derived
 *     row moves nothing);
 *   - the launch's discovery lists a derived file wherever it lies (outside
 *     the walked roots, below the depth cap), so the next launch registers
 *     and twins it;
 *   - at the program gate the arbiter answers a derived path like any
 *     labelled file with no reader list: the twin, and `registerSecret`
 *     mints the twin's symbol.
 *
 * The guard's half (the live index, the open lookup, rename and link) is
 * interceptors/net-supervisor tests/derived_label_integration.rs; the e2e
 * under the real guard and arbiter is launcher/test/derived-label-live.test.sh.
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { DerivedLabelStore, holderMayReadDerived } from "../../policy/derived-labels.js";
import { discoverSecretsReport } from "../../policy/secret-discovery.js";
import { directoryLineOf } from "../../secret-registry/registry.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality axis: a derived copy of a secret stays a secret at the program gate

// ── the store's change numbers ───────────────────────────────────────────────

test("DerivedLabelStore numbers its changes: since(gen) is what changed after gen; a reopened store is a new epoch", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-d4-store-"));
  const dbPath = join(dir, "a.db");
  try {
    const s = new DerivedLabelStore({ dbPath });
    assert.equal(s.generation(), 0);
    s.raise("/w/a.txt", "no-model", { sessionKey: "proc:1" });
    const g1 = s.generation();
    assert.ok(g1 > 0);
    assert.deepEqual(s.since(0).map((r) => r.path), ["/w/a.txt"]);
    s.raise("/w/b.txt", "any-model", { sessionKey: "proc:1" });
    assert.deepEqual(s.since(g1).map((r) => r.path), ["/w/b.txt"]);
    assert.deepEqual(s.since(s.generation()), []);
    const epoch = s.epoch;
    s.close();
    const t = new DerivedLabelStore({ dbPath });
    try {
      assert.notEqual(t.epoch, epoch, "a restarted arbiter is a new epoch: the guard re-reads every row");
      assert.deepEqual(t.since(0).map((r) => r.path).sort(), ["/w/a.txt", "/w/b.txt"]);
    } finally {
      t.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("DerivedLabelStore keeps the writers' sources: their union over writes; unknown once any write's are unknown; kept on reopen", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-d4-src-"));
  const dbPath = join(dir, "a.db");
  try {
    const s = new DerivedLabelStore({ dbPath });
    s.raise("/w/a.txt", "no-model", { sessionKey: "p", sources: ["/s/.env"] });
    s.raise("/w/a.txt", "no-model", { sessionKey: "p", sources: ["/s/creds", "/s/.env"] });
    assert.deepEqual(s.map().get("/w/a.txt")!.sources, ["/s/.env", "/s/creds"]);
    s.raise("/w/b.txt", "any-model", { sessionKey: "sess" });
    assert.equal(s.map().get("/w/b.txt")!.sources, null, "a high session's write (Plan 9): sources unknown");
    s.raise("/w/b.txt", "any-model", { sessionKey: "p", sources: ["/s/.env"] });
    assert.equal(s.map().get("/w/b.txt")!.sources, null, "unknown stays unknown: the file may hold what the session read");
    s.close();
    const t = new DerivedLabelStore({ dbPath });
    try {
      assert.deepEqual(t.map().get("/w/a.txt")!.sources, ["/s/.env", "/s/creds"]);
      assert.equal(t.map().get("/w/b.txt")!.sources, null);
    } finally {
      t.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("holderMayReadDerived: only a holder of every known source", () => {
  const row = { sources: ["/s/.env", "/s/creds"] };
  assert.equal(holderMayReadDerived(row, new Set(["/s/.env", "/s/creds", "/s/other"])), true);
  assert.equal(holderMayReadDerived(row, new Set(["/s/.env"])), false, "holding one of two sources is not enough");
  assert.equal(holderMayReadDerived({ sources: null }, new Set(["/s/.env"])), false, "unknown sources: never");
  assert.equal(holderMayReadDerived({ sources: [] }, new Set(["/s/.env"])), false, "no sources: never");
});

// ── discovery lists derived files wherever they lie ──────────────────────────

test("discovery lists a derived file outside the walked roots and below the depth cap; a missing one is skipped", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-d4-disc-"));
  try {
    const home = join(dir, "home");
    mkdirSync(home, { recursive: true });
    const far = join(dir, "elsewhere", "a", "b", "c", "d", "e", "f");
    mkdirSync(far, { recursive: true });
    const copy = join(far, "copy.txt");
    writeFileSync(copy, "API_KEY=D4_DISCOVERY_CANARY_000001\n");
    const gone = join(dir, "gone.txt");
    const lookup = (p: string) => (p === copy || p === gone)
      ? { level: "no-model" as const, bindings: [], via: p, origin: "derived" as const, overridesCatalog: false }
      : null;
    const report = discoverSecretsReport([home], home, lookup, { derivedPaths: [copy, gone] });
    assert.deepEqual(report.files.map((f) => f.path), [copy]);
    assert.equal(report.files[0]!.level, "no-model");
    assert.match(report.files[0]!.rule, /^derived:/);
    // without the option (the code before the fix) the file is not found
    assert.deepEqual(discoverSecretsReport([home], home, lookup).files, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── the ops, over IPC on a real ArbiterServer ────────────────────────────────

async function withArbiter(fn: (c: ArbiterClient, dir: string, env: string) => Promise<void>, confidentiality = true): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-d4-"));
  const env = join(dir, ".env");
  writeFileSync(env, "STRIPE_KEY=sk_live_D4CANARY0000000001\n");
  const sock = join(dir, "a.sock");
  const s = new ArbiterServer({
    socketPath: sock, humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {},
    confidentiality, integrity: false,
    policyDocument: { version: 1, paths: [{ path: env, level: "no-model", readers: ["ssh"] }] },
  });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's and the proxy's channel (plan 13 D9)
  await c.connect();
  try {
    await fn(c, dir, env);
  } finally {
    c.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

/** A reader copies the secret: the copy gets its derived label (the filesystem exit). */
async function readerCopies(c: ArbiterClient, env: string, copy: string): Promise<void> {
  assert.ok((await c.registerSecret({ path: env })).symbol);
  assert.equal((await c.decideSecretOpen({ path: env, exe: "/usr/bin/ssh", isAgent: false, exeSystem: true, openerEnv: [], procKey: "d4-cp-1" })).verdict, "raw");
  writeFileSync(copy, "STRIPE_KEY=sk_live_D4CANARY0000000001\n");
  assert.equal((await c.labelWrittenPathTainted({ path: copy, procKey: "d4-cp-1" })).labeled, true);
}

test("derivedLabelsSince: a reader's copy is listed with its level; only new rows after `gen`; every row on another epoch", async () => {
  await withArbiter(async (c, dir, env) => {
    const copy = join(dir, "copy.txt");
    const first = await c.derivedLabelsSince({});
    assert.deepEqual(first.labels, []);
    await readerCopies(c, env, copy);
    const r = await c.derivedLabelsSince({ epoch: first.epoch, since: first.gen });
    assert.equal(r.epoch, first.epoch);
    assert.deepEqual(r.labels, [{ path: copy, level: "no-model" }]);
    assert.deepEqual((await c.derivedLabelsSince({ epoch: r.epoch, since: r.gen })).labels, []);
    assert.deepEqual((await c.derivedLabelsSince({ epoch: "an-older-arbiter", since: r.gen })).labels, [{ path: copy, level: "no-model" }]);
  });
});

test("derivedLabelsSince lists nothing with the confidentiality axis off", async () => {
  await withArbiter(async (c) => {
    assert.deepEqual((await c.derivedLabelsSince({})).labels, []);
  }, false);
});

test("followDerivedLabel: the label follows a rename and a hard link; a path with no derived row moves nothing", async () => {
  await withArbiter(async (c, dir, env) => {
    const copy = join(dir, "copy.txt");
    await readerCopies(c, env, copy);
    const moved = join(dir, "moved.txt");
    const f = await c.followDerivedLabel({ from: copy, to: moved, how: "rename", session: "s-d4" });
    assert.equal(f.labeled, true);
    assert.equal(f.level, "no-model");
    const cls = await c.classify({ tool: "Read", value: "x", boundary: "model_context", origin: moved, params: { file_path: moved } });
    assert.equal(cls.confidentiality, "no-model", "the moved name classifies at the source's level");
    const listed = (await c.derivedLabelsSince({})).labels.map((l) => l.path).sort();
    assert.deepEqual(listed, [copy, moved].sort());
    const plain = join(dir, "plain.txt");
    const none = await c.followDerivedLabel({ from: plain, to: join(dir, "plain2.txt"), how: "link" });
    assert.equal(none.labeled, false);
  });
});

test("followDerivedLabel from a PROTECTED file (moved with its folder, 2026-10-16): its new path takes the file's own level; a public or unknown path moves nothing", async () => {
  await withArbiter(async (c, dir, env) => {
    // A labelled file (policy.yaml `paths:`), never copied: no derived row.
    const moved = join(dir, "moved-folder", ".env");
    const f = await c.followDerivedLabel({ from: env, to: moved, how: "rename", session: "s-move" });
    assert.equal(f.labeled, true, f.reason);
    assert.equal(f.level, "no-model");
    const cls = await c.classify({ tool: "Read", value: "x", boundary: "model_context", origin: moved, params: { file_path: moved } });
    assert.equal(cls.confidentiality, "no-model", "the moved path classifies at the file's level");
    assert.ok((await c.derivedLabelsSince({})).labels.some((l) => l.path === moved), "the next session's guard reads it");
    // A catalog match (no human label): ~/.ssh-shaped key names are the catalog's.
    const key = join(dir, "id_ed25519");
    writeFileSync(key, "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n");
    const k = await c.followDerivedLabel({ from: key, to: join(dir, "keys2", "id_ed25519"), how: "rename" });
    assert.equal(k.labeled, true, `a catalog file follows too: ${k.reason}`);
    // A plain file moves nothing.
    const plain = join(dir, "notes.txt");
    writeFileSync(plain, "hello\n");
    assert.equal((await c.followDerivedLabel({ from: plain, to: join(dir, "x", "notes.txt"), how: "rename" })).labeled, false);
  });
});

test("a raise never adds a destination: no sources and unknown sources absorb; known ones only grow (an intersection)", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-raise-"));
  try {
    const s = new DerivedLabelStore({ dbPath: join(dir, "d.sqlite") });
    const meta = (sources: string[] | null) => ({ sessionKey: "s", tool: "rename", sources });
    // bound nowhere (no sources) stays so after a follow names a source
    s.raise("/w/none", "no-model", meta([]));
    assert.deepEqual(s.raise("/w/none", "no-model", meta(["/h/a"]))?.sources, [], "[] → [a] would move it from nowhere to a's hosts");
    // unknown stays unknown
    s.raise("/w/unknown", "no-model", meta(null));
    assert.equal(s.raise("/w/unknown", "no-model", meta(["/h/a"]))?.sources, null);
    // known sources union (the destinations intersect: narrower)
    s.raise("/w/known", "no-model", meta(["/h/b"]));
    assert.deepEqual(s.raise("/w/known", "no-model", meta(["/h/a"]))?.sources, ["/h/a", "/h/b"]);
    // a follow that brings no sources onto a known row: nowhere
    assert.deepEqual(s.raise("/w/known", "no-model", meta([]))?.sources, []);
    // a fresh row takes what it is given
    assert.deepEqual(s.raise("/w/fresh", "no-model", meta(["/h/a"]))?.sources, ["/h/a"]);
    s.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a follow never widens a holder's destinations: a target that is a registered file is refused; a row bound nowhere stays nowhere", async () => {
  await withArbiter(async (c, dir, env) => {
    // A registered file of its own (its registry row), with no label of its own.
    const key = join(dir, "id_ed25519");
    writeFileSync(key, "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n");
    assert.ok((await c.registerSecret({ path: key })).symbol, "registered");
    const onto = await c.followDerivedLabel({ from: env, to: key, how: "rename" });
    assert.equal(onto.labeled, false, "a follow onto a registered file would give it the source's hosts");
    assert.match(onto.reason, /registered file/);
    assert.ok(!(await c.derivedLabelsSince({})).labels.some((l) => l.path === key), "no row was written");
    // A second follow onto a moved copy (another source): its destinations
    // are the intersection, never more.
    const cls = (p: string) => c.classify({ tool: "Read", value: "x", boundary: "model_context", origin: p, params: { file_path: p } });
    const moved = join(dir, "sub", "moved.env");
    const first = await c.followDerivedLabel({ from: env, to: moved, how: "rename" });
    assert.equal(first.labeled, true);
    const before = (await cls(moved)).bindings ?? [];
    const again = await c.followDerivedLabel({ from: key, to: moved, how: "rename" });
    assert.equal(again.labeled, true);
    const after = (await cls(moved)).bindings ?? [];
    assert.ok(after.every((b) => before.includes(b)), `a second follow never adds a destination: ${JSON.stringify(before)} → ${JSON.stringify(after)}`);
  });
});

test("at the program gate a derived path is a labelled file with no reader list: the twin, and registerSecret mints its symbol", async () => {
  await withArbiter(async (c, dir, env) => {
    const copy = join(dir, "copy.txt");
    await readerCopies(c, env, copy);
    const v = await c.decideSecretOpen({ path: copy, exe: "/usr/bin/curl", isAgent: false, procKey: "d4-curl-2" });
    assert.equal(v.verdict, "twin", "a program that is no opener of the copy gets the twin (openers are not inherited, plan 13 §4.6)");
    assert.equal(v.level, "no-model");
    const reg = await c.registerSecret({ path: copy });
    assert.ok(reg.symbol, `the copy is registered: ${reg.reason}`);
    assert.ok(!(reg.twin ?? "").includes("D4CANARY"), "the twin carries no byte of the secret");
  });
});

// ── a holder's working-directory file (2026-10-04) ───────────────────────────

test("directoryLineOf: one absolute path and at most one final newline, nothing else", () => {
  assert.equal(directoryLineOf("/tmp/ws/sub\n"), "/tmp/ws/sub");
  assert.equal(directoryLineOf("/tmp/ws/sub"), "/tmp/ws/sub");
  assert.equal(directoryLineOf("/\n"), "/");
  for (const bad of ["", "\n", "tmp/ws\n", "/tmp/ws\n\n", "/tmp/ws\nAPI_KEY=x\n", "/tmp/ws/\n", "/tmp//ws\n", "/tmp/./ws\n", "/tmp/../ws\n", "/tmp/w\ts\n", "/tmp/ws\r\n", `/${"a".repeat(4096)}\n`, "$MDU:nomodel_Read[1234]\n"]) {
    assert.equal(directoryLineOf(bad), null, JSON.stringify(bad.slice(0, 40)));
  }
});

test("a derived file holding only the canonical path of an existing directory (Claude Code's cwd file) twins as its own text, no symbol; anything else stays a symbol", async () => {
  await withArbiter(async (c, dir, env) => {
    const sub = join(dir, "sub");
    mkdirSync(sub);
    const cwdFile = join(dir, "claude-ab12-cwd");
    // the call's shell (a holder: it reaped the reader) writes `pwd -P`
    assert.ok((await c.registerSecret({ path: env })).symbol);
    assert.equal((await c.decideSecretOpen({ path: env, exe: "/usr/bin/ssh", isAgent: false, exeSystem: true, openerEnv: [], procKey: "d4-cwd-1" })).verdict, "raw");
    const write = async (text: string): Promise<void> => {
      writeFileSync(cwdFile, text);
      assert.equal((await c.labelWrittenPathTainted({ path: cwdFile, procKey: "d4-cwd-1" })).labeled, true);
    };
    await write(`${sub}\n`);
    assert.equal((await c.decideSecretOpen({ path: cwdFile, exe: "/usr/bin/claude", isAgent: true, procKey: "d4-agent-2" })).verdict, "twin", "the label stays: the agent is served the twin");
    const reg = await c.registerSecret({ path: cwdFile });
    assert.equal(reg.symbol, null, `no symbol is minted for a directory name: ${reg.reason}`);
    assert.equal(reg.twin, `${sub}\n`, "the twin is the path itself");
    assert.equal((reg as { shape?: string }).shape, "directory-path");
    // Fail-closed: every other content keeps the whole-file symbol twin.
    for (const text of [`${join(dir, "missing")}\n`, `${sub}\nSTRIPE_KEY=sk_live_D4CANARY0000000001\n`, "sk_live_D4CANARY0000000001\n", `${env}\n`, `${dir}/sub/../sub\n`]) {
      await write(text);
      const r = await c.registerSecret({ path: cwdFile });
      assert.ok(r.symbol, `${JSON.stringify(text.slice(-30))} stays a symbol: ${r.reason}`);
      assert.ok(!(r.twin ?? "").includes("D4CANARY"));
    }
    // A symlink on the path is no canonical name (`pwd -P` writes none).
    const link = join(dir, "link");
    symlinkSync(sub, link);
    await write(`${link}\n`);
    assert.ok((await c.registerSecret({ path: cwdFile })).symbol, "a path through a symlink stays a symbol");
  });
});

test("a HUMAN-labelled or catalog file holding a directory path stays a symbol: the rule is the derived label's only", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-d4-cwdh-"));
  const labelled = join(dir, "where.txt");
  const sub = join(dir, "sub");
  mkdirSync(sub);
  writeFileSync(labelled, `${sub}\n`);
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: labelled, level: "no-model" }] },
  });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock"));
  await c.connect();
  try {
    const r = await c.registerSecret({ path: labelled });
    assert.ok(r.symbol, `a human's label says the file itself is the secret: ${r.reason}`);
    assert.notEqual(r.twin, `${sub}\n`);
  } finally {
    c.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a process that already holds every source of a copy reads it raw (no new taint row); anyone else, the twin", async () => {
  await withArbiter(async (c, dir, env) => {
    const copy = join(dir, "copy.txt");
    await readerCopies(c, env, copy);
    // the writer itself, and its child (npm's own npx server reading the package npm wrote)
    const own = await c.decideSecretOpen({ path: copy, exe: "/usr/bin/node", isAgent: false, procKey: "d4-node-3", parentKey: "d4-cp-1" });
    assert.equal(own.verdict, "raw", own.reason);
    // no taint row for the copy: the holder's bindings stay its sources' (a copy's own row would carry none)
    const t = await c.processSecretTaint("d4-node-3");
    assert.deepEqual([...new Set(t.rows.map((r) => r.path))], [env]);
    // a process holding nothing
    assert.equal((await c.decideSecretOpen({ path: copy, exe: "/usr/bin/node", isAgent: false, procKey: "d4-stranger-4" })).verdict, "twin");
    // the agent's own process, even as a holder's child
    assert.equal((await c.decideSecretOpen({ path: copy, exe: "/usr/bin/claude", isAgent: true, procKey: "d4-agent-5", parentKey: "d4-cp-1" })).verdict, "twin");
    // the label followed a rename: the sources follow too
    const moved = join(dir, "moved.txt");
    assert.equal((await c.followDerivedLabel({ from: copy, to: moved, how: "rename" })).labeled, true);
    assert.equal((await c.decideSecretOpen({ path: moved, exe: "/usr/bin/node", isAgent: false, procKey: "d4-node-6", parentKey: "d4-cp-1" })).verdict, "raw");
  });
});

test("discoverSecrets over IPC lists a derived copy that lies outside the launch's roots", async () => {
  await withArbiter(async (c, dir, env) => {
    const copy = join(dir, "copy.txt");
    await readerCopies(c, env, copy);
    const home = join(dir, "home");
    mkdirSync(home);
    const files = await c.discoverSecrets([home], home);
    assert.ok(files.some((f) => f.path === copy), `the derived copy is discovered: ${JSON.stringify(files)}`);
  });
});
