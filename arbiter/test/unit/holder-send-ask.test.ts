/**
 * holder-send-ask.test.ts — confidentiality plan 13 §5.4, §9 R2: a holder's
 * refused send asks a question that names every file it holds, and an
 * *Always* is one per file, each its own human-plane edit of THAT file's rule.
 *
 * Two layers: the pure module (the row key, the matcher, which files block,
 * a copy named by its sources, where an *Always* writes and when it is
 * refused) and the arbiter over IPC (the ask filed and answered through
 * `taintedProcessBindings`, never from the data socket; `holderSourceBinding`
 * describing the edit; the question retired once every file may go).
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { resetCurrentPolicyForTests } from "../../policy/compiled-policy.js";
import type { DerivedLabel } from "../../policy/derived-labels.js";
import {
  bindingsAdmit, holderBindEdit, holderSendReleased, holderSendSubject, holderSources, hostIsBound,
  isHolderSendSubject, parseHolderSendSubject, type HolderSourceDeps,
} from "../../policy/holder-send-ask.js";
import type { LabelSnapshot } from "../../policy/label-lookup.js";
import type { PathLabel } from "../../policy/path-labels.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality axis: where a holder's bytes may go

// ── the pure module ─────────────────────────────────────────────────────────

test("the row key names the session and the sorted files; any other key is not one", () => {
  const k = holderSendSubject("s1", ["/w/b.csv", "/w/.env", "/w/b.csv"]);
  assert.equal(k, 'holder-send:{"session":"s1","files":["/w/.env","/w/b.csv"]}');
  assert.deepEqual(parseHolderSendSubject(k), { session: "s1", files: ["/w/.env", "/w/b.csv"] });
  assert.deepEqual(parseHolderSendSubject(holderSendSubject(undefined, ["/w/.env"])), { session: null, files: ["/w/.env"] });
  for (const other of ["$MDU:nomodel_Read[1].K", "session-net:s1", "holder-send:{", 'holder-send:{"files":[]}', 'holder-send:{"files":[1]}']) {
    assert.equal(isHolderSendSubject(other), false, other);
  }
});

test("the matcher is the proxy's; a file blocks unless one of its bindings covers the host", () => {
  assert.equal(hostIsBound("hooks.slack.com", ["slack.com"]), true, "a subdomain, as the proxy matches");
  assert.equal(hostIsBound("hooks.slack.com", ["*.slack.com"]), true);
  assert.equal(hostIsBound("slack.com", ["*.slack.com"]), false, "a *. is under the suffix, never the suffix itself");
  assert.equal(hostIsBound("evil.example", ["api.stripe.com"]), false);
  assert.equal(bindingsAdmit(["*.slack.com"], "hooks.slack.com"), true);
  // One rule (host-bindings.ts, 2026-10-11): the card's cover and the
  // proxy's match agree, so a file the proxy lets through is not listed as
  // in the way (until then the join read a bare host as that host only).
  assert.equal(bindingsAdmit(["slack.com"], "hooks.slack.com"), true, "a host covers the hosts under it, as the proxy matches");
  assert.equal(bindingsAdmit(["slack.com"], "evilslack.com"), false);
  assert.equal(bindingsAdmit([], "hooks.slack.com"), false);
});

const human = (rows: Array<Partial<PathLabel> & { path: string; confidentiality: PathLabel["confidentiality"] }>): Map<string, PathLabel> =>
  new Map(rows.map((r) => [r.path, { bindings: [], recursive: true, source: "policy-file", updatedAt: 0, ...r } as PathLabel]));
const derivedRow = (path: string, sources: string[] | null): DerivedLabel => ({ path, confidentiality: "no-model", bindings: [], sessionKey: "s", tool: "process", sources, createdAt: 0, updatedAt: 0 });
const deps = (snapshot: LabelSnapshot, registry: Record<string, string[]> = {}): HolderSourceDeps => ({
  snapshot, registryBindings: (p) => registry[p] ?? [], sessionValueBindings: () => null, home: "/home/u",
});

test("every file is named with where it may go; the blocking ones take an Always; the send is released only when none blocks", () => {
  const snapshot: LabelSnapshot = {
    human: human([
      { path: "/home/u/ws/app/.env", confidentiality: "no-model", bindings: ["api.stripe.com", "*.amazonaws.com"] },
      { path: "/home/u/data/customers.csv", confidentiality: "any-model" },
    ]),
    derived: new Map(), clientKeys: [],
  };
  const files = ["/home/u/ws/app/.env", "/home/u/data/customers.csv"];
  const s = holderSources(files, "hooks.slack.com", deps(snapshot));
  assert.deepEqual(s.map((x) => [x.path, x.bindings, x.blocks, x.always]), [
    ["/home/u/ws/app/.env", ["api.stripe.com", "*.amazonaws.com"], true, true],
    ["/home/u/data/customers.csv", [], true, true],
  ]);
  assert.equal(holderSendReleased(s, "hooks.slack.com"), false);
  // A registry row's binding counts for its file (as the gate counts it).
  const withRegistry = holderSources(files, "api.stripe.com", deps(snapshot, { "/home/u/data/customers.csv": ["api.stripe.com"] }));
  assert.deepEqual(withRegistry.map((x) => x.blocks), [false, false]);
  assert.equal(holderSendReleased(withRegistry, "api.stripe.com"), true);
  // One file bound, the other not: only that one blocks.
  const one = holderSources(files, "s3.amazonaws.com", deps(snapshot));
  assert.deepEqual(one.map((x) => x.blocks), [false, true]);
});

test("a copy is named by its sources (an Always binds at the source, never the copy); a folder rule over it takes none", () => {
  const snapshot: LabelSnapshot = {
    human: human([
      { path: "/home/u/ws/app/.env", confidentiality: "no-model", bindings: ["api.stripe.com"] },
      { path: "/home/u/out", confidentiality: "no-model", bindings: [], readers: ["cat"] },
    ]),
    derived: new Map([
      ["/home/u/out/copy.txt", derivedRow("/home/u/out/copy.txt", ["/home/u/ws/app/.env", "/home/u/notes.txt"])],
      ["/home/u/tmp/unknown.txt", derivedRow("/home/u/tmp/unknown.txt", null)],
    ]),
    clientKeys: [],
  };
  const s = holderSources(["/home/u/out/copy.txt"], "hooks.slack.com", deps(snapshot));
  const byPath = new Map(s.map((x) => [x.path, x]));
  assert.equal(byPath.has("/home/u/out/copy.txt"), false, "the copy itself is not a row: its sources are");
  assert.equal(byPath.get("/home/u/ws/app/.env")!.via, "/home/u/out/copy.txt");
  assert.equal(byPath.get("/home/u/ws/app/.env")!.always, true, "the source takes the Always");
  assert.equal(byPath.get("/home/u/out")!.rule, true);
  assert.equal(byPath.get("/home/u/out")!.noAlways, "folder-rule", "the folder rule over the copy covers other files");
  // A source that no longer classifies secret counts as bound nowhere (the
  // copy's composition): no Always could release it.
  assert.deepEqual([byPath.get("/home/u/notes.txt")!.blocks, byPath.get("/home/u/notes.txt")!.noAlways], [true, "not-secret"]);
  // A copy of unknown origin is an ordinary file bound nowhere: its Always
  // writes an exact rule on the copy (at its level, with this host).
  const u = holderSources(["/home/u/tmp/unknown.txt"], "hooks.slack.com", deps(snapshot));
  assert.deepEqual(u.map((x) => [x.path, x.blocks, x.always]), [["/home/u/tmp/unknown.txt", true, true]]);
  const e = holderBindEdit("/home/u/tmp/unknown.txt", "hooks.slack.com", { snapshot, document: { version: 1 }, home: "/home/u" });
  assert.deepEqual(e, { rule: "/home/u/tmp/unknown.txt", edits: [{ op: "lock-path", path: "/home/u/tmp/unknown.txt", level: "no-model", bindings: ["hooks.slack.com"] }] });
});

test("where an Always writes: the exact rule as written, a new exact rule under a plain folder rule, none under a folder rule with readers or a page rule", () => {
  const snapshot: LabelSnapshot = {
    human: human([
      { path: "/home/u/ws/app/.env", confidentiality: "no-model", bindings: ["api.stripe.com"], readers: ["deploy"] },
      { path: "/home/u/contracts", confidentiality: "any-model", bindings: ["smtp.gmail.com"] },
      { path: "/home/u/keys", confidentiality: "no-model", readers: ["ssh-add"] },
      { path: "/home/u/old.env", confidentiality: "no-model", source: "user" },
    ]),
    derived: new Map(), clientKeys: [],
  };
  const document = { version: 1 as const, paths: [{ path: "~/ws/app/.env", level: "no-model", bindings: ["api.stripe.com"], readers: ["deploy"], recursive: false }] };
  const at = (p: string) => holderBindEdit(p, "hooks.slack.com", { snapshot, document, home: "/home/u" });
  assert.deepEqual(at("/home/u/ws/app/.env"), {
    rule: "/home/u/ws/app/.env",
    edits: [{ op: "lock-path", path: "~/ws/app/.env", level: "no-model", bindings: ["api.stripe.com", "hooks.slack.com"], recursive: false }],
  }, "the file's own rule, its readers kept by lock-path, the host added");
  assert.deepEqual(at("/home/u/contracts/q3.pdf"), {
    rule: "/home/u/contracts/q3.pdf",
    edits: [{ op: "lock-path", path: "/home/u/contracts/q3.pdf", level: "any-model", bindings: ["smtp.gmail.com", "hooks.slack.com"] }],
  }, "a new exact rule for this file alone: the folder's other files do not change");
  assert.deepEqual(at("/home/u/keys/id_ed25519"), { refused: "folder-rule" }, "an exact rule would drop the folder's readers for this file");
  assert.deepEqual(at("/home/u/old.env"), { refused: "page-rule" }, "a mandu.db row outranks policy.yaml: the edit would change nothing");
  assert.deepEqual(at("/home/u/x[1].env"), { refused: "pattern-name" });
  // The catalog decides (no rule): a new exact rule at the catalog's level.
  assert.deepEqual(at("/home/u/proj/.env"), {
    rule: "/home/u/proj/.env",
    edits: [{ op: "lock-path", path: "/home/u/proj/.env", level: "no-model", bindings: ["hooks.slack.com"] }],
  });
  const s = holderSources(["/home/u/keys/id_ed25519", "/home/u/old.env"], "hooks.slack.com", deps(snapshot));
  assert.deepEqual(s.map((x) => [x.blocks, x.always, x.noAlways]), [[true, false, "folder-rule"], [true, false, "page-rule"]]);
});

// ── over IPC: the ask, the edit, the retirement ─────────────────────────────

test("a refused holder asks once per file set; each Always is that file's own edit; the question goes when every file may go", { timeout: 60_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-holder-ask-"));
  const env = join(dir, ".env");
  const csv = join(dir, "customers.csv");
  const other = join(dir, "other.key");
  writeFileSync(env, "STRIPE_KEY=sk_live_holderAskCanary0000001\n");
  writeFileSync(csv, "name,card\nAda,4111111111111111\n");
  writeFileSync(other, "OTHER_KEY=holderAskOther000000000001\n");
  const policyPath = join(dir, "policy.yaml");
  writeFileSync(policyPath, `version: 1
paths:
  - { path: "${env}", level: no-model, readers: [ssh-add], bindings: [api.stripe.com, "*.amazonaws.com"] }
  - { path: "${csv}", level: no-model, readers: [ssh-add] }
  - { path: "${other}", level: no-model, readers: [ssh-add] }
`);
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), adminSocketPath: join(dir, "admin.sock"), humanSocketPath: join(dir, "human", "h.sock"),
    dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {},
    policyPath, policyPollMs: 0, confidentiality: true, integrity: false,
  });
  await s.listen();
  const guard = new ArbiterClient(join(dir, "human", "h.sock")); await guard.connect(); // the proxy's channel
  const data = new ArbiterClient(join(dir, "a.sock")); await data.connect(); // the agent's
  const admin = new ArbiterClient(join(dir, "admin.sock")); await admin.connect(); // the dashboard's
  const H = "hooks.slack.com";
  try {
    for (const f of [env, csv]) {
      assert.equal((await guard.decideSecretOpen({ path: f, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "py-1", session: "s1" })).verdict, "raw");
    }
    // From the data socket the destination is ignored: no answer, no row.
    const fromAgent = await data.taintedProcessBindings({ procKey: "py-1", session: "s1", destination: H });
    assert.equal(fromAgent.ask, undefined);
    assert.equal((await admin.egressApprovals("pending")).length, 0);
    const asked = await guard.taintedProcessBindings({ procKey: "py-1", session: "s1", destination: H });
    assert.equal(asked.ask?.status, "pending");
    const id = asked.ask!.approvalId;
    const again = await guard.taintedProcessBindings({ procKey: "py-1", session: "s1", destination: H });
    assert.equal(again.ask?.approvalId, id, "one question per file set × destination");
    const row = (await admin.egressApprovals("pending")).find((a) => a.id === id)!;
    assert.deepEqual(parseHolderSendSubject(row.symbol), { session: "s1", files: [csv, env].sort() });
    const files = (row.holderSources ?? []).map((x) => [x.path, x.blocks, x.always]);
    assert.deepEqual(files.sort(), [[csv, true, true], [env, true, true]].sort());

    // Allow once: the next ask is approved (and spends it), the one after asks again.
    await admin.resolveEgressApproval(id, true, "once");
    assert.equal((await guard.taintedProcessBindings({ procKey: "py-1", session: "s1", destination: H })).ask?.status, "approved");
    assert.equal((await guard.taintedProcessBindings({ procKey: "py-1", session: "s1", destination: H })).ask?.status, "pending");

    // An Always on a file that is not one of the row's, or one that does not block: refused.
    await assert.rejects(admin.holderSourceBinding(id, other), /not one of the files/);
    // The Always on .env: the edit names .env's rule alone.
    const bindEnv = await admin.holderSourceBinding(id, env);
    assert.equal(bindEnv.rule, env);
    assert.deepEqual(bindEnv.relaxes.map((r) => r.subject), [env]);
    // It names the rule it was planned from, at its version in that read
    // (policy-surface.md §8.4.6 "An item-level version").
    const envVersion = (await admin.policyDocument()).itemVersions!["paths"]![env]!;
    assert.deepEqual(bindEnv.basedOn, [{ section: "paths", key: env, version: envVersion }]);
    const p = await admin.policyPropose({ edits: bindEnv.edits, requestedBy: "test", basedOn: bindEnv.basedOn });
    assert.equal(p.applied, false);
    await admin.resolvePolicyProposal((p as { proposalId: string }).proposalId, "approved", "human:test");
    // Still pending: customers.csv blocks; the holder still may not send.
    const left = (await admin.egressApprovals("pending")).find((a) => a.id === id)!;
    assert.ok(left, "the question stays while a file blocks");
    assert.deepEqual((left.holderSources ?? []).filter((x) => x.blocks).map((x) => x.path), [csv]);
    assert.ok(!(await guard.taintedProcessBindings({ procKey: "py-1", session: "s1" })).bindings.includes(H), "one source answered still refuses");
    await assert.rejects(admin.holderSourceBinding(id, env), /may already go/);
    // The Always on customers.csv, planned; its rule changes before the
    // proposal (another tab gives it a host): proposed with what it was planned
    // from, it is refused stale and writes nothing.
    const planned = await admin.holderSourceBinding(id, csv);
    const moved = await admin.policyPropose({ edits: [{ op: "lock-path", path: csv, level: "no-model", bindings: ["smtp.example.com"] }], requestedBy: "test" });
    assert.ok(!moved.applied && "proposalId" in moved, JSON.stringify(moved));
    await admin.resolvePolicyProposal(moved.proposalId, "approved", "human:test");
    const onDiskBefore = readFileSync(policyPath, "utf8");
    const refused = await admin.policyPropose({ edits: planned.edits, requestedBy: "test", basedOn: planned.basedOn });
    assert.ok("refused" in refused && refused.refused === "stale", JSON.stringify(refused));
    assert.deepEqual("refused" in refused ? refused.changed : null, [`paths ${csv}`]);
    assert.equal(readFileSync(policyPath, "utf8"), onDiskBefore, "nothing written: the other change stands");
    // The Always on customers.csv, planned again: the question goes, and the holder may send.
    const bindCsv = await admin.holderSourceBinding(id, csv);
    const p2 = await admin.policyPropose({ edits: bindCsv.edits, requestedBy: "test", basedOn: bindCsv.basedOn });
    await admin.resolvePolicyProposal((p2 as { proposalId: string }).proposalId, "approved", "human:test");
    assert.equal((await admin.egressApprovals("pending")).some((a) => a.id === id), false, "retired: the law answers it now");
    const after = await guard.taintedProcessBindings({ procKey: "py-1", session: "s1", destination: H });
    assert.ok(after.bindings.includes(H));
    assert.equal(after.ask, undefined, "a bound destination asks nothing");
    await assert.rejects(admin.resolveEgressApproval(id, true), /no longer applies/);
    // The file: H in exactly those two rules.
    const yaml = readFileSync(policyPath, "utf8");
    assert.equal(yaml.split(H).length - 1, 2, `the host is written twice, once per answered rule:\n${yaml}`);
    const onDisk = (await admin.policyDocument()).onDisk.parsed as { paths?: Array<{ path: string; bindings?: string[] }> };
    const bound = (onDisk.paths ?? []).filter((e) => (e.bindings ?? []).includes(H)).map((e) => e.path).sort();
    assert.deepEqual(bound, [csv, env].sort(), "H only in the two rules answered");
    assert.deepEqual((onDisk.paths ?? []).find((e) => e.path === env)!.bindings, ["api.stripe.com", "*.amazonaws.com", H], ".env keeps its bindings");
  } finally {
    guard.close(); data.close(); admin.close();
    await s.close();
    resetCurrentPolicyForTests("claude-code");
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Allow this session stands for that session's holders of those files; a row with no session keeps an Always as once", { timeout: 60_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-holder-session-"));
  const env = join(dir, ".env");
  writeFileSync(env, "STRIPE_KEY=sk_live_holderAskCanary0000002\n");
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), adminSocketPath: join(dir, "admin.sock"), humanSocketPath: join(dir, "human", "h.sock"),
    dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: env, level: "no-model", readers: ["ssh-add"] }] },
  });
  await s.listen();
  const guard = new ArbiterClient(join(dir, "human", "h.sock")); await guard.connect();
  const admin = new ArbiterClient(join(dir, "admin.sock")); await admin.connect();
  try {
    for (const [proc, session] of [["a-1", "s1"], ["b-1", undefined]] as const) {
      assert.equal((await guard.decideSecretOpen({ path: env, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: proc, ...(session ? { session } : {}) })).verdict, "raw");
    }
    const a = await guard.taintedProcessBindings({ procKey: "a-1", session: "s1", destination: "x.example" });
    const r = await admin.resolveEgressApproval(a.ask!.approvalId, true);
    assert.equal(r.scope, "always", "this session: a standing answer on a row keyed to the session");
    for (let i = 0; i < 2; i++) assert.equal((await guard.taintedProcessBindings({ procKey: "a-1", session: "s1", destination: "x.example" })).ask?.status, "approved");
    // Another session's holder of the same file is another question.
    assert.equal((await guard.taintedProcessBindings({ procKey: "a-1", session: "s2", destination: "x.example" })).ask?.status, "pending");
    const b = await guard.taintedProcessBindings({ procKey: "b-1", destination: "x.example" });
    assert.equal((await admin.resolveEgressApproval(b.ask!.approvalId, true)).scope, "once", "no session to scope it to");
  } finally {
    guard.close(); admin.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── plan 13 §5.2: a file with values: on the holder's card ─────────────────

test("a held file with values: shows the intersection over its values (never a value's host from its field rows), and takes no Always: per-value", () => {
  const values = [{ key: "STRIPE_KEY", bindings: ["api.stripe.com"] }, { key: "AWS_*", bindings: ["amazonaws.com"] }];
  const snap: LabelSnapshot = {
    human: human([
      { path: "/home/u/ws/.env", confidentiality: "no-model", recursive: false, values },
      { path: "/home/u/ws/shared.env", confidentiality: "no-model", recursive: false, bindings: ["api.stripe.com"], values: [{ key: "K", bindings: ["api.stripe.com"] }] },
    ]),
    derived: new Map(), clientKeys: [],
  };
  (snap.human as Map<string, PathLabel>).set("glob:/home/u/proj/**/.env", { path: "/home/u/proj/**/.env", confidentiality: "no-model", glob: true, bindings: [], recursive: true, source: "policy-file", updatedAt: 0, values });
  // The registry's field rows carry their own values' hosts and a wire grant.
  const reg = { "/home/u/ws/.env": ["api.stripe.com", "amazonaws.com", "registry.npmjs.org"] };
  const [env] = holderSources(["/home/u/ws/.env"], "api.stripe.com", deps(snap, reg));
  assert.deepEqual(env!.bindings, ["registry.npmjs.org"], "the whole file: api.stripe.com ∩ amazonaws.com is empty; only the host Mandu added stays");
  assert.equal(env!.blocks, true);
  assert.equal(env!.always, false);
  assert.equal(env!.noAlways, "per-value");
  assert.deepEqual(holderBindEdit("/home/u/ws/.env", "api.stripe.com", { snapshot: snap, document: { version: 1, paths: [{ path: "/home/u/ws/.env", level: "no-model", values: { STRIPE_KEY: { bindings: ["api.stripe.com"] }, "AWS_*": { bindings: ["amazonaws.com"] } } }] } }), { refused: "per-value" });
  // A pattern rule with values: the same.
  assert.deepEqual(holderBindEdit("/home/u/proj/a/.env", "api.stripe.com", { snapshot: snap, document: { version: 1 } }), { refused: "per-value" });
  // A file whose every value and itself allow the host: it lets the send through.
  const [shared] = holderSources(["/home/u/ws/shared.env"], "api.stripe.com", deps(snap));
  assert.equal(shared!.blocks, false);
});
