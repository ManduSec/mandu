/**
 * policy-item-version.test — a typed edit built from an earlier read of an
 * item names it with its version (policy-surface.md §8.4.6 "An item-level
 * version"), over a REAL ArbiterServer and its sockets:
 *
 *   - `policyDocument` answers `itemVersions` and the snapshot
 *     `document.modelVersions`, the same keyed version for the same entry;
 *     a change to one entry moves its version only;
 *   - `policyPropose` with `basedOn` naming an entry that changed since is
 *     refused `stale` (`changed` names it), nothing filed, nothing written;
 *     an unchanged entry is filed and approved; a change to ANOTHER entry
 *     does not refuse it;
 *   - a filed proposal keeps the precondition: approving it after the entry
 *     changed writes nothing, closes it `superseded` by `mandu:stale` and
 *     answers `stale`; the precondition never reaches the wire;
 *   - a malformed `basedOn` is refused `invalid`;
 *   - the store keeps a proposal's `basedOn` over a restart;
 *   - the label writers' items: a sensitivity-label mapping is its own item
 *     (by id and site), so another mapping's change neither moves its
 *     version nor refuses its save, and Undo of one keeps the other; a file
 *     rule (by path) likewise; `absentVersion` names an item a read did not
 *     find, refused once someone made it; the snapshot's `pathVersions` are
 *     the same versions.
 *
 * No privilege.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import yaml from "js-yaml";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { resetCurrentPolicyForTests } from "../../policy/compiled-policy.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { PolicyProposalStore } from "../../policy/policy-proposals.js";
import { itemVersionOf } from "../../policy/policy-document-store.js";
import { itemValue } from "../../policy/policy-edit.js";
import { STALE_RESOLVER, parseBasedOn } from "../../ipc/policy-agent-ops.js";
import { openSymbolDb } from "../../symbol-table/symbol-table.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4); the check reads none

const INITIAL = [
  "version: 1",
  "models:",
  "  - { name: gw, url: \"https://gw.example.com\" }",
  "  - { name: other, url: \"https://other.example.com\" }",
  "",
].join("\n");

async function up(initial: string = INITIAL) {
  const dir = mkdtempSync(join(tmpdir(), "mandu-item-version-"));
  const policyPath = join(dir, "policy.yaml");
  writeFileSync(policyPath, initial);
  const server = new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"),
    adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "symbols.db"),
    eventDir: join(dir, "events"),
    log: () => {},
    policyPath,
    policyPollMs: 0,
  });
  await server.listen();
  const admin = new ArbiterClient(join(dir, "admin.sock"));
  const data = new ArbiterClient(join(dir, "arbiter.sock"));
  await admin.connect();
  await data.connect();
  /** Apply edits as a person would (Settings' sequence: propose, approve). */
  const apply = async (edits: unknown[], basedOn?: Array<{ section: string; key: string; version: string }>) => {
    const r = await admin.policyPropose({ edits, requestedBy: "settings", ...(basedOn ? { basedOn } : {}) });
    if (r.applied || "refused" in r) return { propose: r };
    return { propose: r, resolve: await admin.resolvePolicyProposal(r.proposalId, "approved", "human:settings") };
  };
  return {
    policyPath, admin, data, apply,
    close: async () => {
      admin.close();
      data.close();
      await server.close();
      rmSync(dir, { recursive: true, force: true });
      resetCurrentPolicyForTests("claude-code");
    },
  };
}

const urlOf = (doc: unknown, name: string): unknown => ((doc as PolicyFileConfig | null)?.models ?? []).find((m) => m.name === name)?.url;
const gwVersion = async (c: ArbiterClient): Promise<string> => (await c.policyDocument()).itemVersions!["models"]!["gw"]!;

test("policyDocument and the snapshot answer each entry's version; a change to one entry moves its version only", async () => {
  const h = await up();
  try {
    const a = await h.admin.policyDocument();
    const v = a.itemVersions?.["models"];
    assert.match(v?.["gw"] ?? "", /^[0-9a-f]{32}$/);
    assert.notEqual(v?.["gw"], v?.["other"]);
    assert.deepEqual((await h.data.policyDocument()).itemVersions?.["models"], v, "the same versions on the data socket (keyed: they test no guess)");
    const snap = await h.data.policySnapshot() as { document?: { modelVersions?: Record<string, string> } };
    assert.deepEqual(snap.document?.modelVersions, { gw: v!["gw"], other: v!["other"] }, "the snapshot carries the same version per declared model");
    assert.equal(itemVersionOf(itemValue(a.inForce as PolicyFileConfig, "models", "gw")), v!["gw"], "the version is the keyed hash of the entry");

    await h.apply([{ op: "update-model", name: "other", url: "https://other2.example.com" }]);
    const b = (await h.admin.policyDocument()).itemVersions?.["models"];
    assert.equal(b?.["gw"], v!["gw"], "an unrelated entry's change does not move it");
    assert.notEqual(b?.["other"], v!["other"]);
  } finally {
    await h.close();
  }
});

test("an update naming an entry that changed since it was read is refused stale, nothing filed or written; unchanged or unrelated: applied", async () => {
  const h = await up();
  try {
    const read = await gwVersion(h.admin);
    // Someone else changes gw (another tab, a hand edit the poll loaded).
    await h.apply([{ op: "update-model", name: "gw", url: "https://gw-new.example.com" }]);
    const before = readFileSync(h.policyPath, "utf8");
    const pendingBefore = (await h.admin.policyProposals("pending")).proposals.length;

    const stale = await h.admin.policyPropose({
      edits: [{ op: "update-model", name: "gw", url: "https://gw.example.com", model: "m" }], requestedBy: "settings",
      basedOn: [{ section: "models", key: "gw", version: read }],
    });
    assert.equal(stale.applied, false);
    assert.ok("refused" in stale && stale.refused === "stale", JSON.stringify(stale));
    assert.deepEqual("refused" in stale ? stale.changed : null, ["models gw"]);
    assert.equal((await h.admin.policyProposals("pending")).proposals.length, pendingBefore, "nothing filed");
    assert.equal(readFileSync(h.policyPath, "utf8"), before, "nothing written");
    assert.equal(urlOf((await h.admin.policyDocument()).inForce, "gw"), "https://gw-new.example.com", "the newer change stands");

    // Read again: the update goes through.
    const fresh = await gwVersion(h.admin);
    // An unrelated entry changes meanwhile: not a reason to refuse.
    await h.apply([{ op: "update-model", name: "other", url: "https://other3.example.com" }]);
    const ok = await h.apply([{ op: "update-model", name: "gw", url: "https://gw-new.example.com", model: "m" }], [{ section: "models", key: "gw", version: fresh }]);
    assert.equal(ok.resolve?.changeId !== undefined, true, JSON.stringify(ok));
    const doc = (await h.admin.policyDocument()).inForce;
    assert.deepEqual(((doc as PolicyFileConfig).models ?? []).find((m) => m.name === "gw"), { name: "gw", url: "https://gw-new.example.com", model: "m" });
    assert.equal(urlOf(doc, "other"), "https://other3.example.com", "the other change is kept");
    assert.equal(urlOf(yaml.load(readFileSync(h.policyPath, "utf8")), "gw"), "https://gw-new.example.com");
  } finally {
    await h.close();
  }
});

test("a filed proposal keeps the precondition: approving it after the entry changed writes nothing and closes it as stale", async () => {
  const h = await up();
  try {
    const read = await gwVersion(h.admin);
    const filed = await h.admin.policyPropose({
      edits: [{ op: "update-model", name: "gw", url: "https://gw.example.com", model: "old-read" }], requestedBy: "settings",
      basedOn: [{ section: "models", key: "gw", version: read }],
    });
    assert.ok(!filed.applied && "proposalId" in filed, JSON.stringify(filed));
    const id = (filed as { proposalId: string }).proposalId;
    const wire = (await h.admin.policyProposals("pending")).proposals.find((p) => p.id === id)!;
    assert.equal("basedOn" in wire, false, "the precondition stays in the arbiter");
    assert.doesNotMatch(JSON.stringify((await h.data.policyProposals("pending")).proposals), /basedOn/);

    // The entry changes before the approval lands.
    await h.apply([{ op: "update-model", name: "gw", url: "https://gw-new.example.com" }]);
    const before = readFileSync(h.policyPath, "utf8");
    const r = await h.admin.resolvePolicyProposal(id, "approved", "human:settings");
    assert.deepEqual(r.stale, ["models gw"]);
    assert.equal(r.changeId, undefined, "no change recorded");
    assert.equal(r.proposal.status, "superseded");
    assert.equal(r.proposal.resolvedBy, STALE_RESOLVER);
    assert.equal(readFileSync(h.policyPath, "utf8"), before, "nothing written");
    assert.equal(urlOf((await h.admin.policyDocument()).inForce, "gw"), "https://gw-new.example.com");
    await assert.rejects(h.admin.resolvePolicyProposal(id, "approved", "human:settings"), /already superseded/, "it cannot be approved later");
  } finally {
    await h.close();
  }
});

test("the same edits with and without a precondition are different proposals; a malformed basedOn is refused invalid", async () => {
  const h = await up();
  try {
    const edits = [{ op: "update-model", name: "gw", url: "https://gw.example.com", model: "x" }];
    const plain = await h.admin.policyPropose({ edits, requestedBy: "settings" });
    const based = await h.admin.policyPropose({ edits, requestedBy: "settings", basedOn: [{ section: "models", key: "gw", version: await gwVersion(h.admin) }] });
    assert.ok("proposalId" in plain && "proposalId" in based);
    assert.notEqual((plain as { proposalId: string }).proposalId, (based as { proposalId: string }).proposalId, "not deduplicated onto a proposal that checks nothing");
    for (const bad of [7, [{ section: "models", key: "gw" }], [{ section: "models", key: "gw", version: "short" }], [{ section: "Models!", key: "gw", version: "a".repeat(32) }], Array.from({ length: 65 }, () => ({ section: "models", key: "gw", version: "a".repeat(32) }))]) {
      const r = await h.admin.policyPropose({ edits, requestedBy: "settings", basedOn: bad as never });
      assert.ok("refused" in r && r.refused === "invalid", JSON.stringify(bad).slice(0, 80));
    }
  } finally {
    await h.close();
  }
  assert.deepEqual(parseBasedOn(undefined), { ok: true, items: [] });
});

test("the store keeps a proposal's basedOn over a restart", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-item-version-db-"));
  const dbPath = join(dir, "mandu.db");
  try {
    openSymbolDb(dbPath).close();
    const a = new PolicyProposalStore({ dbPath, now: () => 1000 });
    const basedOn = [{ section: "models", key: "gw", hash: "h".repeat(32) }];
    const p = a.file({ edits: [], reason: null, requestedBy: "settings", sessionKey: null, relaxes: [], tightens: [], editsHash: "e1", lawHash: "l1", basedOn });
    const q = a.file({ edits: [], reason: null, requestedBy: "settings", sessionKey: null, relaxes: [], tightens: [], editsHash: "e2", lawHash: "l1" });
    a.close();
    const b = new PolicyProposalStore({ dbPath, now: () => 2000 });
    assert.deepEqual(b.getProposal(p.id)?.basedOn, basedOn);
    assert.equal(b.getProposal(q.id)?.basedOn, null, "none named reads as none");
    b.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── the label writers (policy-surface.md §8.4.6 "An item-level version") ────

const HC = "9fbde396-1a24-4c79-8edf-9254a0f35055";
const GEN = "0e4c2b8a-3b1d-4f5e-9a6b-7c8d9e0f1a2b";
const LABELS = [
  "version: 1",
  "sensitivity_labels:",
  `  - { id: "${HC}", name: Highly Confidential, level: no-model }`,
  `  - { id: "${GEN}", name: General, level: any-model }`,
  "paths:",
  "  - { path: /srv/proj/.env, level: no-model, bindings: [api.stripe.com] }",
  "  - { path: /srv/proj/docs, level: any-model }",
  "",
].join("\n");
const HC_KEY = `${HC}|`;
const GEN_KEY = `${GEN}|`;
const labelOf = (doc: unknown, id: string) => ((doc as PolicyFileConfig | null)?.sensitivity_labels ?? []).find((l) => l.id === id);
const pathOf = (doc: unknown, path: string) => ((doc as PolicyFileConfig | null)?.paths ?? []).find((l) => l.path === path);

test("a sensitivity-label mapping is its own item: another mapping's change moves neither its version nor refuses its save; a moved one is refused, nothing written", async () => {
  const h = await up(LABELS);
  try {
    const v = (await h.admin.policyDocument()).itemVersions?.["sensitivity-labels"];
    assert.match(v?.[HC_KEY] ?? "", /^[0-9a-f]{32}$/, "each mapping has a version, by id and site");
    assert.notEqual(v?.[HC_KEY], v?.[GEN_KEY]);
    assert.equal((await h.admin.policyDocument()).itemVersions?.["key"]?.["sensitivity_labels"], undefined, "no longer one whole-key item");

    // Another mapping changes: HC's version stands, and a save based on it lands.
    await h.apply([{ op: "map-sensitivity-label", id: GEN, name: "General", level: "public" }]);
    const after = (await h.admin.policyDocument()).itemVersions?.["sensitivity-labels"];
    assert.equal(after?.[HC_KEY], v?.[HC_KEY], "an unrelated mapping's change does not move it");
    const ok = await h.apply([{ op: "map-sensitivity-label", id: HC, name: "Highly Confidential", level: "local-model" }], [{ section: "sensitivity-labels", key: HC_KEY, version: v![HC_KEY]! }]);
    assert.ok(ok.resolve?.changeId, JSON.stringify(ok));
    assert.equal(labelOf((await h.admin.policyDocument()).inForce, HC)?.level, "local-model");
    assert.equal(labelOf((await h.admin.policyDocument()).inForce, GEN)?.level, "public", "the other change is kept");

    // HC changes somewhere else (raised again): a save built from the read before is refused.
    const read = (await h.admin.policyDocument()).itemVersions!["sensitivity-labels"]![HC_KEY]!;
    await h.apply([{ op: "map-sensitivity-label", id: HC, name: "Highly Confidential", level: "no-model" }]);
    const before = readFileSync(h.policyPath, "utf8");
    for (const edit of [
      { op: "map-sensitivity-label", id: HC, name: "Highly Confidential", level: "public" },
      { op: "unmap-sensitivity-label", id: HC },
    ]) {
      const r = await h.admin.policyPropose({ edits: [edit], requestedBy: "settings", basedOn: [{ section: "sensitivity-labels", key: HC_KEY, version: read }] });
      assert.ok("refused" in r && r.refused === "stale", JSON.stringify(r));
      assert.deepEqual("refused" in r ? r.changed : null, [`sensitivity-labels ${HC_KEY}`]);
    }
    assert.equal(readFileSync(h.policyPath, "utf8"), before, "nothing written");
    assert.equal(labelOf((await h.admin.policyDocument()).inForce, HC)?.level, "no-model", "the stricter, newer mapping stays in force");
    assert.equal((await h.admin.policyProposals("pending")).proposals.length, 0, "nothing filed");
  } finally {
    await h.close();
  }
});

test("a new mapping or a first rule on a path names the absent version: refused once someone made that item, accepted while it is still absent", async () => {
  const h = await up(LABELS);
  try {
    const pd = await h.admin.policyDocument();
    const absent = pd.absentVersion!;
    assert.match(absent, /^[0-9a-f]{32}$/);
    assert.equal(absent, itemVersionOf(null), "the keyed version of null");
    assert.equal((await h.data.policyDocument()).absentVersion, absent, "the same on the data socket (a constant: it says nothing about the law)");
    const NEW = "11111111-2222-4333-8444-555555555555";
    // Still absent: accepted.
    const ok = await h.apply([{ op: "map-sensitivity-label", id: NEW, name: "Internal", level: "no-model" }], [{ section: "sensitivity-labels", key: `${NEW}|`, version: absent }]);
    assert.equal(ok.propose.applied, true, JSON.stringify(ok)); // a tightening: applied at once

    // A rule on a path the read found none on: someone else makes one first.
    await h.apply([{ op: "lock-path", path: "/srv/proj/secrets.json", level: "no-model" }]);
    const before = readFileSync(h.policyPath, "utf8");
    const r = await h.admin.policyPropose({
      edits: [{ op: "lock-path", path: "/srv/proj/secrets.json", level: "public" }], requestedBy: "rules-page",
      basedOn: [{ section: "paths", key: "/srv/proj/secrets.json", version: absent }],
    });
    assert.ok("refused" in r && r.refused === "stale", JSON.stringify(r));
    assert.deepEqual("refused" in r ? r.changed : null, ["paths /srv/proj/secrets.json"]);
    assert.equal(readFileSync(h.policyPath, "utf8"), before, "nothing written");
    assert.equal(pathOf((await h.admin.policyDocument()).inForce, "/srv/proj/secrets.json")?.level, "no-model", "the other rule stands");
  } finally {
    await h.close();
  }
});

test("a file rule is its own item: the snapshot's pathVersions are its version; another rule's change does not refuse it; a moved one is refused; Undo of one mapping keeps another's later change", async () => {
  const h = await up(LABELS);
  try {
    const pd = await h.admin.policyDocument();
    const env = pd.itemVersions!["paths"]!["/srv/proj/.env"]!;
    const snap = await h.data.policySnapshot() as { document?: { pathVersions?: Record<string, string> } };
    assert.equal(snap.document?.pathVersions?.["/srv/proj/.env"], env, "the snapshot names the same version by the path it lists");
    assert.equal(snap.document?.pathVersions?.["/srv/proj/docs"], pd.itemVersions!["paths"]!["/srv/proj/docs"]);

    await h.apply([{ op: "lock-path", path: "/srv/proj/docs", level: "no-model" }]);
    const ok = await h.apply([{ op: "lock-path", path: "/srv/proj/.env", level: "no-model", bindings: ["api.stripe.com", "hooks.slack.com"] }], [{ section: "paths", key: "/srv/proj/.env", version: env }]);
    assert.ok(ok.resolve?.changeId, JSON.stringify(ok));

    const read = (await h.admin.policyDocument()).itemVersions!["paths"]!["/srv/proj/.env"]!;
    await h.apply([{ op: "lock-path", path: "/srv/proj/.env", level: "no-model" }]); // the hosts taken away elsewhere
    const before = readFileSync(h.policyPath, "utf8");
    const r = await h.admin.policyPropose({
      edits: [{ op: "lock-path", path: "/srv/proj/.env", level: "no-model", bindings: ["api.stripe.com", "hooks.slack.com", "x.example"] }], requestedBy: "rules-page",
      basedOn: [{ section: "paths", key: "/srv/proj/.env", version: read }],
    });
    assert.ok("refused" in r && r.refused === "stale", JSON.stringify(r));
    assert.equal(readFileSync(h.policyPath, "utf8"), before, "nothing written");
    assert.equal(pathOf((await h.admin.policyDocument()).inForce, "/srv/proj/.env")?.bindings, undefined, "the narrower rule stays in force");

    // Undo, item by item: undoing HC's change keeps GEN's later change.
    const hc = await h.apply([{ op: "map-sensitivity-label", id: HC, name: "Highly Confidential", level: "local-model" }]);
    await h.apply([{ op: "map-sensitivity-label", id: GEN, name: "General", level: "no-model" }]);
    await h.admin.undoPolicyChange(hc.resolve!.changeId!, "human:test");
    const doc = (await h.admin.policyDocument()).inForce;
    assert.equal(labelOf(doc, HC)?.level, "no-model", "HC back to what it was");
    assert.equal(labelOf(doc, GEN)?.level, "no-model", "GEN's later change survives the undo");
  } finally {
    await h.close();
  }
});
