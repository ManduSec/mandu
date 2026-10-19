/**
 * policy-suggestions-labels e2e — confidentiality plan 14 §14.1 (S4, 4a:
 * sensitivity labels) through the REAL arbiter: an in-process ArbiterServer
 * with a file-backed law, a DATA socket and an ADMIN socket, the production
 * `ArbiterClient` on both (no test bridge: the client's parity test for
 * `countLabels`, the `sensitivity-label` source, `workspaceScan.labels` and
 * `humanOnly`), the real walk and the real safe open over Office files built
 * at run time (test/helpers/office-zip.ts):
 *
 *   - no mapping, no count (the launch's call): no Office file is opened;
 *   - no mapping, `countLabels` (an explicit scan): labelled files counted,
 *     the unmapped ids listed with their file counts, nothing filed;
 *   - a mapping proposed on the DATA socket (a new mapping above public is a
 *     tightening, applied at once), then a scan: the `no-model` label files
 *     one `lock-path` (applied on the data socket), the `any-model` one is
 *     `humanOnly` (refused on the data socket, applied by a person on the
 *     admin socket), `public` and unmapped suggest nothing, a file the law
 *     labels is never opened; a rescan files nothing;
 *   - the administrator's layer maps a label with no user mapping;
 *   - `sources: ["sensitivity-label"]` reads no text file; bad `sources` /
 *     `countLabels` are refused; axis OFF opens nothing.
 *
 * The oracle (implementation-plan.md §9): no byte of any fixture's text (the
 * documents' bodies, the display name Office wrote into custom.xml) in any
 * op reply, the event store, the proposals and changes tables, the arbiter's
 * log, or policy.yaml. Axes stated: secrets.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import Database from "../../db/sqlite.js";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { resetCurrentPolicyForTests } from "../../policy/compiled-policy.js";
import { defaultWorkspaceFs, type WorkspaceScanFs } from "../../policy/secret-workspace-scan.js";
import { bombLabelInfo, buildEncryptedContainer, buildOfficeFile } from "../helpers/office-zip.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

const HC = "9fbde396-1a24-4c79-8edf-9254a0f35055";
const CONF = "7c7c7c7c-1111-4222-8333-444455556666";
const GEN = "1e4f7c2a-3b5d-4e6f-8a9b-0c1d2e3f4a5b";
const UNMAPPED = "2b2b2b2b-1111-4222-8333-444455556666";
const TENANT = "5b3c2d4e-1111-4222-8333-444455556666";
// Canaries assembled at run time: each document's text and the display name
// Office wrote. None may appear anywhere Mandu writes or answers.
const canary = (tag: string): string => `${tag}${randomBytes(12).toString("hex")}`;
const BODIES = { hc: canary("BOARD"), conf: canary("BUDGET"), gen: canary("NOTES"), unmapped: canary("PLAN"), covered: canary("LEDGER") };
const DISPLAY_NAME = canary("DISPLAYNAME");
const CANARIES = [...Object.values(BODIES), DISPLAY_NAME];

function noText(what: string, s: string): void {
  for (const c of CANARIES) {
    assert.ok(!s.includes(c), `${what} carries a document's text`);
    assert.ok(!s.includes(c.slice(-16)), `${what} carries a run of a document's text`);
  }
}

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

interface Fixture { dir: string; home: string; proj: string; policy: string; files: Record<string, string> }

function fixture(policyText = "version: 1\n"): Fixture {
  const dir = mkdtempSync(join(tmpdir(), "mdu-suggest-labels-e2e-"));
  dirs.push(dir);
  const home = join(dir, "home");
  const proj = join(home, "proj");
  mkdirSync(join(proj, "board"), { recursive: true });
  const files = {
    hc: join(proj, "board", "q3-board.docx"),
    conf: join(proj, "budget.xlsx"),
    gen: join(proj, "notes.pptx"),
    unmapped: join(proj, "plan.docx"),
    covered: join(proj, "ledger.docx"),
    enc: join(proj, "sealed.docx"),
    bomb: join(proj, "bomb.docx"),
    zip64: join(proj, "big.xlsx"),
    text: join(proj, "README.md"),
  };
  writeFileSync(files.hc, buildOfficeFile({ labelInfo: [{ id: HC, site: TENANT }], custom: [{ id: HC, site: TENANT, name: DISPLAY_NAME }], body: BODIES.hc }));
  writeFileSync(files.conf, buildOfficeFile({ custom: [{ id: CONF, site: TENANT, name: DISPLAY_NAME }], body: BODIES.conf }));
  writeFileSync(files.gen, buildOfficeFile({ labelInfo: [{ id: GEN, site: TENANT }], body: BODIES.gen }));
  writeFileSync(files.unmapped, buildOfficeFile({ labelInfo: [{ id: UNMAPPED, site: TENANT }], body: BODIES.unmapped }));
  writeFileSync(files.covered, buildOfficeFile({ labelInfo: [{ id: HC, site: TENANT }], body: BODIES.covered }));
  writeFileSync(files.enc, buildEncryptedContainer());
  writeFileSync(files.bomb, buildOfficeFile({ labelInfoRaw: bombLabelInfo(8) }));
  writeFileSync(files.zip64, buildOfficeFile({ labelInfo: [{ id: HC }], zip: { zip64Markers: true } }));
  writeFileSync(files.text, "# a project\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `${policyText}paths:\n  - path: ${files.covered}\n    level: no-model\n`);
  return { dir, home, proj, policy, files };
}

async function rig(
  f: Fixture,
  opts: { confidentiality?: boolean; adminPolicyDir?: string | null },
  fn: (c: { data: ArbiterClient; admin: ArbiterClient; logs: string[]; opened: string[]; textRead: string[] }) => Promise<void>,
): Promise<void> {
  const logs: string[] = [];
  const opened: string[] = [];
  const textRead: string[] = [];
  const fs: WorkspaceScanFs = {
    ...defaultWorkspaceFs,
    readRegular: async (p, caps) => { textRead.push(p); return defaultWorkspaceFs.readRegular(p, caps); },
    readLabels: async (p, caps) => { opened.push(p); return defaultWorkspaceFs.readLabels!(p, caps); },
  };
  const server = new ArbiterServer({
    socketPath: join(f.dir, "arbiter.sock"),
    adminSocketPath: join(f.dir, "admin.sock"),
    dbPath: join(f.dir, "mandu.db"),
    eventDir: join(f.dir, "events"),
    policyPath: f.policy,
    policyPollMs: 0,
    adminPolicyDir: opts.adminPolicyDir ?? null,
    historyScanCacheDir: null,
    confidentiality: opts.confidentiality ?? true,
    integrity: false,
    log: (m) => logs.push(m),
    workspaceScan: { fs, env: {}, discovery: { installEnv: {}, selfDir: null } },
  });
  await server.listen();
  const data = new ArbiterClient(join(f.dir, "arbiter.sock"));
  const admin = new ArbiterClient(join(f.dir, "admin.sock"));
  try {
    await fn({ data, admin, logs, opened, textRead });
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

test("S4 through the real arbiter: off without a mapping, counted on an explicit scan, mapped and filed, applied on both channels, never a byte of text", async () => {
  const f = fixture();
  const replies: string[] = [];
  await rig(f, {}, async ({ data, admin, logs, opened }) => {
    // 1. The launch's call: no mapping, no count: no Office file opened.
    const launch = await data.suggestPolicy([f.proj], { home: f.home });
    replies.push(JSON.stringify(launch));
    assert.equal(launch.workspaceScan!.labels!.mode, "off");
    assert.equal(opened.length, 0, "no Office file is opened while no mapping is in force");
    assert.equal(launch.suggestions.filter((s) => s.source === "sensitivity-label").length, 0);

    // 2. An explicit scan counts them.
    const counted = await data.suggestPolicy([f.proj], { home: f.home, countLabels: true });
    replies.push(JSON.stringify(counted));
    const L = counted.workspaceScan!.labels!;
    assert.equal(L.mode, "count");
    assert.ok(!opened.includes(f.files.covered), "a file the law labels is never opened");
    assert.equal(L.covered, 1);
    assert.equal(L.files, 4, "q3-board, budget, notes, plan");
    assert.equal(L.mapped, 0);
    assert.equal(L.unmappedFiles, 4);
    assert.deepEqual(L.unmapped.map((u) => u.id).sort(), [CONF, GEN, HC, UNMAPPED].sort());
    assert.ok(L.unmapped.every((u) => u.site === TENANT && u.files === 1));
    assert.equal(L.encrypted, 1);
    assert.equal(L.unreadable, 2, "the bomb and the Zip64 archive");
    assert.equal(counted.counts.filed, 0, "counted, not suggested");

    // 3. The person maps three of them. A new mapping above public is a
    //    tightening (the data socket applies it); the public one relaxes and
    //    waits for a person (the admin socket approves it).
    const mapUp = await data.policyPropose({ edits: [
      { op: "map-sensitivity-label", id: HC, site: TENANT, name: "Highly Confidential", level: "no-model" },
      { op: "map-sensitivity-label", id: CONF, name: "Confidential", level: "any-model" },
    ], reason: "the tenant's labels" });
    assert.equal(mapUp.applied, true, JSON.stringify(mapUp));
    const mapPub = await data.policyPropose({ edits: [{ op: "map-sensitivity-label", id: GEN, name: "General", level: "public" }], reason: "general is public" });
    assert.equal(mapPub.applied, false);
    assert.ok("proposalId" in mapPub);
    await admin.resolvePolicyProposal((mapPub as { proposalId: string }).proposalId, "approved", "human:e2e");

    opened.length = 0;
    const mapped = await data.suggestPolicy([f.proj], { home: f.home });
    replies.push(JSON.stringify(mapped));
    assert.equal(mapped.workspaceScan!.labels!.mode, "mapped");
    assert.equal(mapped.workspaceScan!.labels!.cached, 7, "unchanged since the count: from the cache");
    assert.deepEqual(mapped.workspaceScan!.labels!.unmapped.map((u) => u.id), [UNMAPPED]);
    const labelled = mapped.suggestions.filter((s) => s.source === "sensitivity-label");
    assert.equal(mapped.counts.filed, 2, JSON.stringify(mapped.counts));
    const hc = labelled.find((s) => s.evidence.paths[0] === "board/q3-board.docx")!;
    const conf = labelled.find((s) => s.evidence.paths[0] === "budget.xlsx")!;
    assert.ok(hc && conf, JSON.stringify(labelled.map((s) => s.evidence.paths)));
    assert.deepEqual(hc.edits, [{ op: "lock-path", path: f.files.hc, level: "no-model" }]);
    assert.equal(hc.findingKey, `sensitivity-label:${f.files.hc}`);
    assert.equal(hc.sentence, "Make ~/proj/board/q3-board.docx a secret no AI may read: its sensitivity label is Highly Confidential");
    assert.deepEqual(hc.evidence.label, { id: HC, site: TENANT, name: "Highly Confidential", level: "no-model" });
    assert.equal(hc.humanOnly, false);
    assert.equal(hc.rotate, false);
    assert.equal(hc.repoRoot, f.proj);
    assert.deepEqual(conf.edits, [{ op: "lock-path", path: f.files.conf, level: "any-model" }]);
    assert.equal(conf.humanOnly, true);

    // 4. Apply: the no-model lock on the DATA socket; the any-model one is
    //    refused there and applied by a person on the ADMIN socket.
    const a = await data.applySuggestion(hc.id);
    replies.push(JSON.stringify(a));
    assert.equal(a.applied, true, JSON.stringify(a));
    const refused = await data.applySuggestion(conf.id);
    replies.push(JSON.stringify(refused));
    assert.equal(refused.applied, false);
    assert.equal(!refused.applied && refused.refused, "relaxes");
    assert.equal(((await data.policyDocument()).inForce as { paths?: Array<{ path: string }> }).paths?.some((p) => p.path === f.files.conf) ?? false, false, "the data plane never loosens");
    const approved = await admin.resolvePolicyProposal(conf.id, "approved", "human:e2e");
    replies.push(JSON.stringify(approved));
    assert.ok(approved.changeId);
    const law = (await data.policyDocument()).inForce as { paths?: Array<{ path: string; level: string }> };
    assert.deepEqual(law.paths?.find((p) => p.path === f.files.hc), { path: f.files.hc, level: "no-model" });
    assert.deepEqual(law.paths?.find((p) => p.path === f.files.conf), { path: f.files.conf, level: "any-model" });
    const changes = (await data.policyChanges(3)).changes;
    assert.deepEqual(changes.slice(0, 2).map((c) => [c.via, c.proposedBy]), [["proposal", "mandu:scan"], ["agent-tighten", "mandu:scan"]]);

    // 5. A rescan files nothing; the locked files are now covered, never opened.
    opened.length = 0;
    const again = await data.suggestPolicy([f.proj], { home: f.home, countLabels: true });
    replies.push(JSON.stringify(again));
    assert.equal(again.counts.filed, 0, JSON.stringify(again.counts));
    assert.ok(!opened.includes(f.files.hc) && !opened.includes(f.files.conf), "the files the person locked are not opened again");
    assert.equal(again.workspaceScan!.labels!.covered, 3);

    // The oracle.
    replies.push(JSON.stringify(await admin.policySuggestions()), JSON.stringify(await data.policyDocument()));
    const { events, proposals } = storeText(f);
    for (const [what, s] of [["the op replies", replies.join("\n")], ["the event store", events], ["the proposals and changes tables", proposals], ["the arbiter log", logs.join("\n")], ["policy.yaml", readFileSync(f.policy, "utf8")]] as const) {
      noText(what, s);
    }
    assert.match(logs.join("\n"), /sensitivity labels \(mapped\): 0 Office file\(s\) read, 7 from the cache/);
  });
});

test("the administrator's layer maps a label the user did not; sources and countLabels are validated; the label source alone reads no text file", async () => {
  const f = fixture();
  const layer = join(f.dir, "policy.d");
  mkdirSync(layer);
  writeFileSync(join(layer, "10-org.yaml"), `sensitivity_labels:\n  - id: ${HC}\n    name: Highly Confidential (org)\n    level: no-model\n`);
  await rig(f, { adminPolicyDir: layer }, async ({ data, textRead }) => {
    const r = await data.suggestPolicy([f.proj], { home: f.home, sources: ["sensitivity-label"] });
    assert.equal(r.scan, null, "no history scan");
    assert.equal(r.workspaceScan!.labels!.mode, "mapped");
    assert.deepEqual(textRead, [], "the label source alone reads no text file");
    const s = r.suggestions.find((x) => x.source === "sensitivity-label")!;
    assert.equal(s.sentence, "Make ~/proj/board/q3-board.docx a secret no AI may read: its sensitivity label is Highly Confidential (org)");
    assert.equal(s.evidence.label?.adminFile, join(layer, "10-org.yaml"));
    const doc = await data.policyDocument();
    assert.equal((doc as { admin?: { sensitivityLabels: unknown[] } }).admin?.sensitivityLabels.length, 1);
    await assert.rejects(() => data.suggestPolicy([f.proj], { sources: ["labels" as never] }), /sources must list "git-history", "workspace" and\/or "sensitivity-label"/);
    await assert.rejects(() => data.suggestPolicy([f.proj], { countLabels: "yes" as never }), /countLabels must be a boolean/);
  });
});

test("axis OFF: no Office file opened, even with countLabels", async () => {
  const f = fixture();
  await rig(f, { confidentiality: false }, async ({ data, opened }) => {
    const r = await data.suggestPolicy([f.proj], { home: f.home, countLabels: true });
    assert.equal(r.axis, false);
    assert.equal(r.workspaceScan, null);
    assert.deepEqual(opened, []);
  });
});
