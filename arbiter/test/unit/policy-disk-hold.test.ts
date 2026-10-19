/**
 * policy-disk-hold.test — a policy.yaml change seen on DISK that relaxes the
 * law is held out of force until a human approves it
 * (policy-surface.md §8.4.6; sandbox security review 2026-09-28,
 * finding 2: the file is writable from the agent's process tree wherever the
 * agent is not confined, so a write to it is not a human's word).
 *
 * Over a REAL policy file, PolicyDocumentStore and PolicyAgentOps (the
 * dashboard's approve/deny op), with an in-memory proposal store. Pins:
 *   - a relaxing disk edit is HELD: the law in force is unchanged, one
 *     pending proposal (`requestedBy: "file"`, a `diskHash`, no edits) lists
 *     the relaxations, and the file is left as written;
 *   - a tightening, and a neutral edit (comments only), apply at once and
 *     file nothing;
 *   - approve loads exactly the held bytes and records the change;
 *   - approve after a further change judges the file afresh (a new
 *     relaxation is re-filed; content back at the law closes the card), and
 *     never loads bytes the human was not shown;
 *   - deny keeps the law, RESTORES the file to it (policy-restore.ts; the
 *     row keeps the declined text), and does not re-hold the same bytes on a
 *     later poll or a rewrite of the same content (restored again);
 *   - the arbiter's OWN writes (a tightening through the surface, a dashboard
 *     apply) are never judged as a foreign edit;
 *   - the writes from outside the surface (the developer view's whole-file
 *     apply, a minted rule, the label migrations; tour 17 after !1095) keep
 *     the person's comments, and, while a change is held, are made to it as
 *     well item by item (never written over it); one that changes an item
 *     the held change changes too is refused, naming it, nothing written;
 *   - a second relaxing edit supersedes the first card;
 *   - at start a card pending from before a restart stays pending and held
 *     (policy-restore.test.ts covers the restart paths in full);
 *   - a judge that throws counts as a relaxation (fail closed).
 *
 * No privilege. The hold is axis-independent: the store never reads the
 * protection axes, and this suite pins one mode only because every suite
 * states its axes.
 */
import { test, beforeEach, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import yaml from "js-yaml";

import { compilePolicy, getCurrentPolicy, resetCurrentPolicyForTests, swapCurrentPolicy } from "../../policy/compiled-policy.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { contentHash, lawHashOf, PolicyDocumentStore, StalePolicyError } from "../../policy/policy-document-store.js";
import { PolicyProposalStore } from "../../policy/policy-proposals.js";
import { loadPolicyFileStrict } from "../../policy/policy-file-validate.js";
import { PolicyAgentOps } from "../../ipc/policy-agent-ops.js";
import { reconcilePolicyFileAtStart } from "../../policy/policy-restore.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4); none is read

const INITIAL: PolicyFileConfig = {
  version: 1,
  paths: [{ path: "/home/u/repo/.env", level: "no-model" }],
};
const INITIAL_TEXT = yaml.dump(INITIAL);
/** A standing allow rule: a relaxation (user-rules). */
const RELAX_TEXT = INITIAL_TEXT + "user_rules:\n  - { id: hand, kind: release, to: { host: attacker.example }, mode: allow }\n";
/** A different relaxation (a second allow rule). */
const RELAX2_TEXT = INITIAL_TEXT + "user_rules:\n  - { id: other, kind: release, to: { host: paste.example }, mode: allow }\n";
/** A plain strict lock: a tightening. */
const TIGHT_TEXT = "version: 1\npaths:\n  - { path: /home/u/repo/.env, level: no-model }\n  - { path: /home/u/repo/id_rsa, level: no-model }\n";

let dir: string;
let file: string;
let docs: PolicyDocumentStore;
let proposals: PolicyProposalStore;
let ops: PolicyAgentOps;
let logs: string[];
let bump = 0;
const clock = Date.parse("2026-09-28T00:00:00Z");

function rebuild(doc: PolicyFileConfig | null): void {
  swapCurrentPolicy(compilePolicy({ specId: "claude-code", document: doc }));
}

function newOps(): PolicyAgentOps {
  return new PolicyAgentOps({
    docs, proposals,
    pendingAsks: () => [],
    dbLabels: () => [],
    ruleHits: () => ({}),
    hostOf: (d) => d,
    now: () => clock,
  });
}

/** Write the file as a foreign process would, with a fresh mtime. */
function writeDisk(text: string): void {
  writeFileSync(file, text);
  const t = new Date(Date.now() + 5_000 + ++bump * 1_000);
  utimesSync(file, t, t);
}

function touch(): void {
  const t = new Date(Date.now() + 5_000 + ++bump * 1_000);
  utimesSync(file, t, t);
}

const ruleIds = (): string[] => getCurrentPolicy().userRules.map((r) => r.id);
const pending = () => ops.proposalsList("pending").proposals;

beforeEach(() => {
  docs?.close();
  if (dir) rmSync(dir, { recursive: true, force: true });
  dir = mkdtempSync(join(tmpdir(), "mandu-disk-hold-"));
  file = join(dir, "policy.yaml");
  writeFileSync(file, INITIAL_TEXT);
  const loaded = loadPolicyFileStrict(file);
  rebuild(loaded.config);
  logs = [];
  proposals = new PolicyProposalStore({ now: () => clock });
  docs = new PolicyDocumentStore(
    { path: file, rebuild, pollMs: 0, log: (m) => logs.push(m), persistEnforced: (e) => proposals.recordEnforced(file, e) },
    { document: loaded.config, found: true },
  );
  ops = newOps();
});

after(() => {
  docs?.close();
  if (dir) rmSync(dir, { recursive: true, force: true });
  resetCurrentPolicyForTests("claude-code");
});

test("a relaxing disk edit is held: the law is unchanged, one Inbox proposal lists the relaxation, the file is left as written", () => {
  writeDisk(RELAX_TEXT);
  assert.equal(docs.pollDisk(), true, "the change was seen");
  assert.deepEqual(ruleIds(), [], "the allow rule is NOT the law");
  assert.deepEqual(docs.document, INITIAL, "the document in force is the old one");
  const [p, ...rest] = pending();
  assert.equal(rest.length, 0);
  assert.equal(p!.requestedBy, "file");
  assert.equal(p!.diskHash, contentHash(RELAX_TEXT));
  assert.deepEqual(p!.edits, [], "a held disk change carries no edits");
  assert.equal(p!.reason, null, "no untrusted text rides on it");
  assert.ok(p!.relaxes.some((r) => r.facet === "user-rules" && r.subject === "hand"), "the relaxation is named");
  assert.equal(readFileSync(file, "utf8"), RELAX_TEXT, "the file is left as written");
  assert.equal(docs.heldChange?.hash, contentHash(RELAX_TEXT));
  assert.ok(logs.some((l) => /would RELAX the law/.test(l) && /NOT applied/.test(l)), "the hold is logged");
  // Further polls see nothing new and file nothing more.
  touch();
  assert.equal(docs.pollDisk(), false, "same bytes: no change");
  assert.equal(pending().length, 1);
});

test("a tightening disk edit applies at once and files nothing", () => {
  writeDisk(TIGHT_TEXT);
  assert.equal(docs.pollDisk(), true);
  assert.ok(getCurrentPolicy().pathLabels.has("/home/u/repo/id_rsa"), "the new lock is the law");
  assert.equal(pending().length, 0);
  assert.equal(docs.heldChange, null);
});

test("a neutral disk edit (a comment, layout) applies at once and files nothing", () => {
  writeDisk("# my note\n" + INITIAL_TEXT + "\n\n");
  assert.equal(docs.pollDisk(), true);
  assert.deepEqual(docs.document, INITIAL);
  assert.equal(pending().length, 0);
  assert.equal(docs.heldChange, null);
});

test("approve loads exactly the held bytes and records the change as an approved proposal", () => {
  writeDisk(RELAX_TEXT);
  docs.pollDisk();
  const [p] = pending();
  const r = ops.resolve(p!.id, "approved", "dashboard");
  assert.equal(r.proposal.status, "approved");
  assert.ok(r.changeId, "the approval became a recorded change");
  assert.deepEqual(ruleIds(), ["hand"], "the held content is the law now");
  assert.equal(readFileSync(file, "utf8"), RELAX_TEXT, "approving does not rewrite the person's file");
  assert.equal(docs.heldChange, null);
  const c = proposals.getChange(r.changeId!)!;
  assert.equal(c.via, "proposal");
  assert.equal(c.proposalId, p!.id);
  assert.equal(c.requestedBy, "dashboard");
  assert.ok(c.delta.some((d) => d.direction === "relax" && d.subject === "hand"));
  assert.equal(docs.pollDisk(), false, "the loaded bytes are not re-judged");
});

test("approve after a further relaxing change re-judges: the new content is re-filed, the approval never loads it", () => {
  writeDisk(RELAX_TEXT);
  docs.pollDisk();
  const [p] = pending();
  writeDisk(RELAX2_TEXT); // not polled yet: the approval must notice by hash
  const r = ops.resolve(p!.id, "approved", "dashboard");
  assert.equal(r.proposal.status, "superseded");
  assert.equal(r.changeId, undefined);
  assert.ok(r.refiled, "the newer content waits as its own card");
  assert.equal(r.refiled!.diskHash, contentHash(RELAX2_TEXT));
  assert.ok(r.refiled!.relaxes.some((x) => x.subject === "other"));
  assert.deepEqual(ruleIds(), [], "nothing the human was not shown became the law");
  assert.deepEqual(pending().map((x) => x.id), [r.refiled!.id]);
});

test("approve after the file went back to the law closes the card and changes nothing", () => {
  writeDisk(RELAX_TEXT);
  docs.pollDisk();
  const [p] = pending();
  writeDisk(INITIAL_TEXT);
  const r = ops.resolve(p!.id, "approved", "dashboard");
  assert.equal(r.proposal.status, "superseded");
  assert.equal(r.refiled, undefined);
  assert.deepEqual(ruleIds(), []);
  assert.equal(pending().length, 0);
});

test("a further relaxing edit supersedes the first card; an edit back to the law closes it", () => {
  writeDisk(RELAX_TEXT);
  docs.pollDisk();
  const [first] = pending();
  writeDisk(RELAX2_TEXT);
  docs.pollDisk();
  const [second, ...rest] = pending();
  assert.equal(rest.length, 0, "one card at a time");
  assert.notEqual(second!.id, first!.id);
  assert.equal(proposals.getProposal(first!.id)!.status, "superseded");
  assert.equal(proposals.getProposal(first!.id)!.supersededBy, second!.id);
  writeDisk(INITIAL_TEXT);
  docs.pollDisk();
  assert.equal(pending().length, 0, "the file is back at the law: nothing waits");
  assert.equal(proposals.getProposal(second!.id)!.status, "superseded");
  assert.deepEqual(ruleIds(), []);
});

test("deny keeps the law, restores the file, and does not re-hold the same bytes", () => {
  writeDisk(RELAX_TEXT);
  docs.pollDisk();
  const [p] = pending();
  const r = ops.resolve(p!.id, "denied", "dashboard");
  assert.equal(r.proposal.status, "denied");
  assert.equal(r.restored, true);
  assert.equal(r.proposal.diskText, RELAX_TEXT, "the row keeps the declined hand edit");
  assert.deepEqual(ruleIds(), []);
  assert.equal(readFileSync(file, "utf8"), INITIAL_TEXT, "the file is back at the law in force");
  touch();
  assert.equal(docs.pollDisk(), false, "the restore is the arbiter's own write: not judged");
  assert.equal(pending().length, 0, "a touch does not re-file it");
  writeDisk(RELAX_TEXT);
  docs.pollDisk();
  assert.equal(pending().length, 0, "rewriting the same declined content does not re-file it");
  assert.equal(readFileSync(file, "utf8"), INITIAL_TEXT, "it is restored again");
  assert.deepEqual(ruleIds(), [], "and it never becomes the law");
  // The human fixes the file: a tightening applies as usual.
  writeDisk(TIGHT_TEXT);
  docs.pollDisk();
  assert.ok(getCurrentPolicy().pathLabels.has("/home/u/repo/id_rsa"));
  assert.equal(pending().length, 0);
});

test("the arbiter's own writes are never judged as a foreign edit", () => {
  // A tightening through the surface writes the file.
  const t = ops.propose({ id: "1", op: "policyPropose", edits: [{ op: "lock-path", path: "/home/u/repo/**/*.pem", level: "no-model" }], sessionKey: "s1" }, "data");
  assert.equal(t.applied, true);
  touch();
  assert.equal(docs.pollDisk(), false, "our own bytes, even with a new mtime");
  // A dashboard apply that RELAXES (a human on the admin channel) writes too.
  const relaxed = { ...(docs.document as PolicyFileConfig), user_rules: [{ id: "r-0001", kind: "release" as const, to: { host: "api.example.com" }, mode: "allow" as const }] };
  docs.apply(relaxed, { via: "apply", requestedBy: "dashboard" });
  assert.deepEqual(ruleIds(), ["r-0001"]);
  assert.equal(docs.pollDisk(), false);
  touch();
  assert.equal(docs.pollDisk(), false);
  assert.equal(pending().length, 0, "nothing was held");
});

const PEM_LOCK = [{ op: "lock-path", path: "/home/u/repo/**/*.pem", level: "no-model" }];
const lockedPaths = (): string[] => (getCurrentPolicy().document?.paths ?? []).map((x) => x.path).sort();

/** The person's own file, a comment on every level: each must survive. */
const COMMENTED =
  "# Our team's policy. Ask Dana before you loosen anything.\n" +
  "version: 1\n\n" +
  "paths:\n" +
  "  # the deploy secrets\n" +
  "  - path: /home/u/repo/.env   # prod\n" +
  "    level: no-model\n";
const COMMENT_LINES = ["# Our team's policy. Ask Dana before you loosen anything.", "  # the deploy secrets", "# prod"];
/** COMMENTED with a relaxing hand edit (an allow rule) and its own comments. */
const COMMENTED_HELD = COMMENTED + "\n# temporary, for the conference demo\nuser_rules:\n  - { id: hand, kind: release, to: { host: attacker.example }, mode: allow }   # remove after Oct 20\n";
const HELD_LINES = ["# temporary, for the conference demo", "# remove after Oct 20"];
const K_LOCK = { path: "/home/u/k", level: "no-model" as const };

function keepsEvery(text: string, lines: readonly string[]): void {
  for (const l of lines) assert.ok(text.includes(l), `the file keeps "${l}":\n${text}`);
}

/** Held: the hand edit is still in the file, still not the law, one card
 *  filed again for the new bytes giving up what the first one showed. */
function stillHeld(first: { id: string; relaxes: Array<{ subject: string }> }, heldRule = "hand"): void {
  const onDisk = yaml.load(readFileSync(file, "utf8")) as PolicyFileConfig;
  assert.ok(onDisk.user_rules?.some((r) => r.id === heldRule), "the file keeps the hand edit");
  assert.ok(!ruleIds().includes(heldRule), "which is still not the law");
  assert.equal(proposals.getProposal(first.id)!.status, "superseded");
  const now = pending();
  assert.equal(now.length, 1, "one card");
  assert.ok(now[0]!.id !== first.id && now[0]!.diskHash === docs.heldChange!.hash, "filed again for the file's new bytes");
  assert.deepEqual(now[0]!.relaxes.map((r) => r.subject), first.relaxes.map((r) => r.subject), "giving up what the first card showed, no more");
}

test("tour 17 after !1095: the developer view's whole-file apply keeps the person's comments", () => {
  writeDisk(COMMENTED);
  docs.pollDisk();
  docs.apply({ ...INITIAL, paths: [...INITIAL.paths!, K_LOCK] }, { via: "apply", requestedBy: "dashboard" });
  const text = readFileSync(file, "utf8");
  assert.ok(text.startsWith(COMMENTED), `every line as written, the lock added after them:\n${text}`);
  assert.ok(lockedPaths().includes("/home/u/k"));
  assert.equal(docs.pollDisk(), false, "the arbiter's own write is not judged as a hand edit");
});

test("tour 17 after !1095: a whole-file apply while a change is held is made to it as well, not written over it", () => {
  writeDisk(COMMENTED); // the person's commented file is the law
  docs.pollDisk();
  writeDisk(COMMENTED_HELD);
  docs.pollDisk();
  const [p] = pending();
  assert.ok(p && docs.heldChange);
  docs.apply({ ...INITIAL, paths: [...INITIAL.paths!, K_LOCK] }, { via: "apply", requestedBy: "dashboard" });
  assert.ok(lockedPaths().includes("/home/u/k"), "the apply is the law");
  const text = readFileSync(file, "utf8");
  assert.ok(text.includes("/home/u/k"), "the file has it");
  keepsEvery(text, [...COMMENT_LINES, ...HELD_LINES]);
  stillHeld(p!);
  // Declining restores the law in force: the apply, never the hand rule.
  const [q] = pending();
  assert.equal(ops.resolve(q!.id, "denied", "dashboard").restored, true);
  const restored = readFileSync(file, "utf8");
  assert.equal((yaml.load(restored) as PolicyFileConfig).user_rules, undefined);
  assert.ok(restored.includes("/home/u/k"));
  keepsEvery(restored, COMMENT_LINES);
});

test("tour 17 after !1095: a whole-file apply that changes a rule the held change changes too is refused, naming it; nothing is written", () => {
  // The hand edit lowers the .env lock: a relaxation, held.
  writeDisk(COMMENTED.replace("    level: no-model\n", "    level: any-model\n"));
  docs.pollDisk();
  const [p] = pending();
  assert.ok(p);
  const before = readFileSync(file, "utf8");
  const lawBefore = structuredClone(docs.document);
  assert.throws(
    () => docs.apply({ ...INITIAL, paths: [{ ...INITIAL.paths![0]!, bindings: ["api.example.com"] }] }, { via: "apply", requestedBy: "dashboard" }),
    (e: unknown) => e instanceof StalePolicyError && e.held && e.message.includes("waits for a human in Approvals") && e.message.includes("paths /home/u/repo/.env"),
  );
  assert.equal(readFileSync(file, "utf8"), before, "the held edit is untouched");
  assert.deepEqual(docs.document, lawBefore, "the law is unchanged");
  assert.deepEqual(pending().map((x) => x.id), [p!.id], "the same card waits");
});

test("tour 17 after !1095: a minted rule and the label migrations keep the comments, and are made to a held change as well", () => {
  writeDisk(COMMENTED);
  docs.pollDisk();
  docs.exportDbLabels([{ path: "/home/u/exported", level: "no-model" }], "dashboard");
  docs.moveDbLabels([{ path: "/home/u/moved", level: "no-model", bindings: ["api.example.com"] }], "dashboard");
  docs.mintUserRule({ kind: "release", to: { host: "paste.example" }, mode: "block" }, "dashboard");
  let text = readFileSync(file, "utf8");
  assert.ok(text.startsWith(COMMENTED), `every line as written:\n${text}`);
  for (const x of ["/home/u/exported", "/home/u/moved"]) assert.ok(lockedPaths().includes(x), x);
  assert.deepEqual(ruleIds(), ["r-0001"]);

  // Now a relaxing hand edit (an allow rule, with its comments) waits.
  writeDisk(text.trimEnd() + "\n  # temporary, for the conference demo\n  - { id: r-0002, kind: release, to: { host: attacker.example }, mode: allow }   # remove after Oct 20\n");
  docs.pollDisk();
  const [p] = pending();
  assert.ok(p && docs.heldChange, "held");
  docs.exportDbLabels([{ path: "/home/u/exported2", level: "no-model" }], "dashboard");
  docs.moveDbLabels([{ path: "/home/u/moved2", level: "no-model" }], "dashboard");
  const minted = docs.mintUserRule({ kind: "release", to: { host: "*.pastebin.com" }, mode: "block" }, "dashboard");
  assert.equal(minted.id, "r-0003", "a fresh id, free in the held change too");
  for (const x of ["/home/u/exported2", "/home/u/moved2"]) assert.ok(lockedPaths().includes(x), `${x} is the law`);
  assert.deepEqual(ruleIds(), ["r-0001", "r-0003"], "the held allow rule is still not the law");
  text = readFileSync(file, "utf8");
  const onDisk = yaml.load(text) as PolicyFileConfig;
  assert.deepEqual(onDisk.user_rules!.map((r) => r.id), ["r-0001", "r-0002", "r-0003"], "the file keeps the hand edit, with the minted rule");
  for (const x of ["/home/u/exported2", "/home/u/moved2"]) assert.ok(onDisk.paths!.some((e) => e.path === x), `the file has ${x}`);
  keepsEvery(text, [...COMMENT_LINES, ...HELD_LINES]);
  stillHeld(p!, "r-0002");
});

test("tour 17 after !1095: a write from outside the surface is refused when a hand edit landed inside the poll window", () => {
  writeDisk(TIGHT_TEXT);
  assert.throws(() => docs.apply({ ...INITIAL, paths: [...INITIAL.paths!, K_LOCK] }, { via: "apply", requestedBy: "dashboard" }), (e: unknown) => e instanceof StalePolicyError && !e.held);
  assert.equal(readFileSync(file, "utf8"), TIGHT_TEXT, "the hand edit is not written over");
  assert.ok(lockedPaths().includes("/home/u/repo/id_rsa"), "it was loaded");
  assert.ok(!lockedPaths().includes("/home/u/k"));
});

test("tour 17 after !1095: `mayLayer` refuses the layering for a held change the write was not computed for", () => {
  writeDisk(RELAX_TEXT);
  docs.pollDisk();
  const [p] = pending();
  const before = readFileSync(file, "utf8");
  assert.throws(
    () => docs.apply({ ...INITIAL, paths: [...INITIAL.paths!, K_LOCK] }, { via: "pin-reader", requestedBy: "arbiter" }, { mayLayer: () => false }),
    (e: unknown) => e instanceof StalePolicyError && e.held,
  );
  assert.equal(readFileSync(file, "utf8"), before);
  assert.ok(!lockedPaths().includes("/home/u/k"));
  assert.deepEqual(pending().map((x) => x.id), [p!.id]);
});

// ── A whole-file apply names the law it was built from (§8.4.6, after !1973) ──
// The developer view builds its whole document from a law it read earlier;
// `applyDocument` refuses it as stale once the law moved, so a change that
// landed in between is never undone without a word.

/** The developer view's read-then-apply: the document built from the law as
 *  read, with `/home/u/k` locked, and the version it was built from. */
function readForApply(): { doc: PolicyFileConfig; basedOn: string } {
  const law = structuredClone(docs.document ?? {});
  return { doc: { ...law, paths: [...(law.paths ?? []), K_LOCK] }, basedOn: docs.lawHash };
}

test("after !1973: a whole-file apply built from the law in force is written (comments kept)", () => {
  writeDisk(COMMENTED);
  docs.pollDisk();
  const { doc, basedOn } = readForApply();
  docs.applyDocument(doc, basedOn, { via: "apply", requestedBy: "dashboard" });
  assert.ok(lockedPaths().includes("/home/u/k"), "the apply is the law");
  assert.ok(readFileSync(file, "utf8").startsWith(COMMENTED), "the person's lines kept");
  assert.notEqual(docs.lawHash, basedOn, "the law moved with it");
});

test("after !1973: an agent's tightening that lands between the read and the apply is not undone: refused as stale, naming it", () => {
  const { doc, basedOn } = readForApply();
  assert.equal(ops.propose({ id: "1", op: "policyPropose", edits: PEM_LOCK, sessionKey: "s1" }, "data").applied, true);
  const bytes = readFileSync(file, "utf8");
  assert.throws(
    () => docs.applyDocument(doc, basedOn, { via: "apply", requestedBy: "dashboard" }),
    (e: unknown) => e instanceof StalePolicyError && e.lawMoved && !e.held
      && e.changed.includes("paths glob:/home/u/repo/**/*.pem")
      && /changed since this document was read/.test(e.message) && e.message.includes("paths glob:/home/u/repo/**/*.pem"),
  );
  assert.ok(lockedPaths().includes("/home/u/repo/**/*.pem"), "the agent's lock is still the law");
  assert.ok(!lockedPaths().includes("/home/u/k"), "nothing of the stale document was applied");
  assert.equal(readFileSync(file, "utf8"), bytes, "nothing was written");
  // Built again from the law as it is now, the same change applies.
  const again = readForApply();
  docs.applyDocument(again.doc, again.basedOn, { via: "apply", requestedBy: "dashboard" });
  assert.ok(lockedPaths().includes("/home/u/k") && lockedPaths().includes("/home/u/repo/**/*.pem"), "both in force");
});

test("after !1973: a hand edit the poll already loaded is not undone by a document read before it", () => {
  const { doc, basedOn } = readForApply();
  writeDisk(TIGHT_TEXT);
  assert.equal(docs.pollDisk(), true, "the poll loaded the tightening");
  assert.throws(
    () => docs.applyDocument(doc, basedOn, { via: "apply", requestedBy: "dashboard" }),
    (e: unknown) => e instanceof StalePolicyError && e.lawMoved && e.changed.includes("paths /home/u/repo/id_rsa"),
  );
  assert.equal(readFileSync(file, "utf8"), TIGHT_TEXT, "the hand edit is not written over");
  assert.ok(lockedPaths().includes("/home/u/repo/id_rsa"));
});

test("after !1973: a hand edit inside the poll window is read first, and names what it changed", () => {
  const { doc, basedOn } = readForApply();
  writeDisk(TIGHT_TEXT); // not polled yet
  assert.throws(
    () => docs.applyDocument(doc, basedOn, { via: "apply", requestedBy: "dashboard" }),
    (e: unknown) => e instanceof StalePolicyError && e.lawMoved && e.changed.includes("paths /home/u/repo/id_rsa"),
  );
  assert.equal(readFileSync(file, "utf8"), TIGHT_TEXT);
  assert.ok(lockedPaths().includes("/home/u/repo/id_rsa"), "it was loaded");
  assert.ok(!lockedPaths().includes("/home/u/k"));
});

test("after !1973: a relaxing hand edit inside the poll window leaves the law as read, and the apply is still refused as stale (as before)", () => {
  const { doc, basedOn } = readForApply();
  writeDisk(RELAX_TEXT);
  assert.throws(
    () => docs.applyDocument(doc, basedOn, { via: "apply", requestedBy: "dashboard" }),
    (e: unknown) => e instanceof StalePolicyError && !e.lawMoved && !e.held,
  );
  assert.equal(readFileSync(file, "utf8"), RELAX_TEXT, "the held edit is not written over");
  assert.ok(docs.heldChange, "held");
  assert.ok(!lockedPaths().includes("/home/u/k"));
});

test("after !1973: with a change held, a document built from the law in force is layered onto it, as !1973 made it", () => {
  writeDisk(COMMENTED);
  docs.pollDisk();
  writeDisk(COMMENTED_HELD);
  docs.pollDisk();
  const [p] = pending();
  assert.ok(p && docs.heldChange);
  const { doc, basedOn } = readForApply(); // the law in force, never the held file
  docs.applyDocument(doc, basedOn, { via: "apply", requestedBy: "dashboard" });
  assert.ok(lockedPaths().includes("/home/u/k"), "the apply is the law");
  keepsEvery(readFileSync(file, "utf8"), [...COMMENT_LINES, ...HELD_LINES]);
  stillHeld(p!);
});

test("after !1973: a version the store does not know (another arbiter's, or a guess) is refused as stale", () => {
  const { doc } = readForApply();
  const bytes = readFileSync(file, "utf8");
  assert.throws(
    () => docs.applyDocument(doc, "0".repeat(32), { via: "apply", requestedBy: "dashboard" }),
    (e: unknown) => e instanceof StalePolicyError && e.lawMoved && e.changed.length === 0 && /not known any more/.test(e.message),
  );
  assert.equal(readFileSync(file, "utf8"), bytes);
  assert.ok(!lockedPaths().includes("/home/u/k"));
});

test("after !1973: the law's version does not move on key order or a comment-only hand edit", () => {
  const v = docs.lawHash;
  assert.equal(lawHashOf({ paths: INITIAL.paths, version: 1 }), v, "key order");
  writeDisk(COMMENTED); // the same document, with comments
  docs.pollDisk();
  assert.equal(docs.lawHash, v, "comments are not the law");
  assert.notEqual(lawHashOf({ ...INITIAL, paths: [...INITIAL.paths!, K_LOCK] }), v);
});

test("tour 17: the agent's lock does not wait on an unrelated held edit; the edit stays held, in the file, with the lock", () => {
  writeDisk(RELAX_TEXT);
  docs.pollDisk();
  const [p] = pending();
  const t = ops.propose({ id: "1", op: "policyPropose", edits: PEM_LOCK, sessionKey: "s1" }, "data");
  assert.equal(t.applied, true, "a tightening applies at once, held edit or not");
  assert.ok(lockedPaths().includes("/home/u/repo/**/*.pem"), "the lock is the law");
  assert.deepEqual(ruleIds(), [], "the held relaxation is still not the law");
  const onDisk = yaml.load(readFileSync(file, "utf8")) as PolicyFileConfig;
  assert.ok(onDisk.paths!.some((x) => x.path === "/home/u/repo/**/*.pem"), "the file has the lock");
  assert.deepEqual(onDisk.user_rules!.map((r) => r.id), ["hand"], "and keeps the hand edit");
  // The card is filed again for the file's new bytes, with the same delta.
  assert.equal(proposals.getProposal(p!.id)!.status, "superseded");
  const [q] = pending();
  assert.ok(q && q.id !== p!.id && q.diskHash === docs.heldChange!.hash);
  assert.equal(proposals.getProposal(p!.id)!.supersededBy, q!.id);
  assert.deepEqual(q!.relaxes.map((r) => r.subject), p!.relaxes.map((r) => r.subject), "it gives up what the first card showed, no more");
  // The content in force (what a decline writes back, and a restart loads)
  // has the lock and not the relaxation.
  const inForce = yaml.load(proposals.enforcedPolicy(file)!.text!) as PolicyFileConfig;
  assert.ok(inForce.paths!.some((x) => x.path === "/home/u/repo/**/*.pem"));
  assert.equal(inForce.user_rules, undefined);
  // Declining it restores the law in force, lock included.
  const d = ops.resolve(q!.id, "denied", "dashboard");
  assert.equal(d.restored, true);
  assert.deepEqual(ruleIds(), []);
  const restored = yaml.load(readFileSync(file, "utf8")) as PolicyFileConfig;
  assert.ok(restored.paths!.some((x) => x.path === "/home/u/repo/**/*.pem"));
  assert.equal(restored.user_rules, undefined);
});

test("tour 17: approving the held edit after the lock loads both; nothing the human was not shown", () => {
  writeDisk(RELAX_TEXT);
  docs.pollDisk();
  ops.propose({ id: "1", op: "policyPropose", edits: PEM_LOCK, sessionKey: "s1" }, "data");
  const [q] = pending();
  const r = ops.resolve(q!.id, "approved", "dashboard");
  assert.equal(r.proposal.status, "approved");
  assert.deepEqual(ruleIds(), ["hand"]);
  assert.ok(lockedPaths().includes("/home/u/repo/**/*.pem"), "the lock stays");
  assert.equal(docs.heldChange, null);
});

test("tour 17: a lock that covers what the held edit relaxed ends the hold; the file is the law", () => {
  // The held edit labels id_rsa at any-model (a lock that lets a model read
  // a file is a relaxation, §8.3.3); the agent then locks id_rsa at
  // no-model: the held content with the lock gives up nothing.
  writeDisk(INITIAL_TEXT + "  - { path: /home/u/repo/id_rsa, level: any-model }\n");
  docs.pollDisk();
  const [p] = pending();
  assert.ok(p, "a model-readable label is held");
  const t = ops.propose({ id: "1", op: "policyPropose", edits: [{ op: "lock-path", path: "/home/u/repo/id_rsa", level: "no-model" }], sessionKey: "s1" }, "data");
  assert.equal(t.applied, true);
  assert.equal(docs.heldChange, null, "nothing waits any more");
  assert.equal(proposals.getProposal(p!.id)!.status, "superseded");
  assert.deepEqual(pending(), []);
  assert.equal(getCurrentPolicy().document?.paths?.find((x) => x.path === "/home/u/repo/id_rsa")?.level, "no-model");
});

test("tour 17: an Undo does not wait on an unrelated held edit; the same revert is made to it, and it stays held", () => {
  const t = ops.propose({ id: "1", op: "policyPropose", edits: PEM_LOCK, sessionKey: "s1" }, "data");
  assert.ok("changeId" in t && t.changeId);
  writeDisk(readFileSync(file, "utf8") + "# my hand rule\nuser_rules:\n  - { id: hand, kind: release, to: { host: attacker.example }, mode: allow }  # for the demo\n");
  docs.pollDisk();
  const [p] = pending();
  assert.ok(docs.heldChange && p);
  const u = ops.undo(t.changeId!, "dashboard");
  assert.equal(u.undone, t.changeId);
  assert.ok(!lockedPaths().includes("/home/u/repo/**/*.pem"), "the Undo is the law");
  assert.deepEqual(ruleIds(), [], "the held relaxation is still not the law");
  const text = readFileSync(file, "utf8");
  const onDisk = yaml.load(text) as PolicyFileConfig;
  assert.ok(!onDisk.paths!.some((x) => x.path === "/home/u/repo/**/*.pem"), "the file has the Undo");
  assert.deepEqual(onDisk.user_rules!.map((r) => r.id), ["hand"], "and keeps the hand edit");
  assert.match(text, /# my hand rule\n/, "with its comments");
  assert.match(text, /# for the demo/);
  const [q] = pending();
  assert.ok(q && q.id !== p!.id && q.diskHash === docs.heldChange!.hash, "the card is filed again for the new bytes");
  assert.deepEqual(q!.relaxes.map((r) => r.subject), p!.relaxes.map((r) => r.subject), "giving up what the first card showed, no more");
  // Declining restores the law in force: the Undo, never the hand rule.
  assert.equal(ops.resolve(q!.id, "denied", "dashboard").restored, true);
  const restored = yaml.load(readFileSync(file, "utf8")) as PolicyFileConfig;
  assert.equal(restored.user_rules, undefined);
  assert.ok(!restored.paths!.some((x) => x.path === "/home/u/repo/**/*.pem"));
});

test("tour 17: an Undo of a rule the held edit changes too is refused, naming it; nothing changes", () => {
  const t = ops.propose({ id: "1", op: "policyPropose", edits: PEM_LOCK, sessionKey: "s1" }, "data");
  assert.ok("changeId" in t && t.changeId);
  // The hand edit lowers the same lock to any-model: a relaxation, held.
  writeDisk(readFileSync(file, "utf8").replace(/(\*\*\/\*\.pem\n\s+level: )no-model/, "$1any-model"));
  docs.pollDisk();
  assert.ok(docs.heldChange, "held");
  const before = readFileSync(file, "utf8");
  assert.throws(() => ops.undo(t.changeId!, "dashboard"), /cannot undo pc-\d+ yet: the change to policy\.yaml waiting in Approvals changes the same rule \(.*pem.*\)/);
  assert.ok(lockedPaths().includes("/home/u/repo/**/*.pem"), "the lock stays in force");
  assert.equal(readFileSync(file, "utf8"), before, "the file is untouched");
  assert.equal(proposals.getChange(t.changeId!)!.undoneAt, null);
});

test("tour 17: a held hand edit re-saved with the agent's lock keeps its comments and layout", () => {
  const HAND =
    "# Our team's policy. Ask Dana before you loosen anything.\n" +
    "version: 1\n\n" +
    "paths:\n" +
    "  # the deploy secrets\n" +
    "  - path: /home/u/repo/.env   # prod\n" +
    "    level: no-model\n\n" +
    "# temporary, for the conference demo\n" +
    "user_rules:\n" +
    "  - { id: hand, kind: release, to: { host: attacker.example }, mode: allow }   # remove after Oct 20\n";
  writeDisk(HAND);
  docs.pollDisk();
  assert.ok(docs.heldChange);
  const t = ops.propose({ id: "1", op: "policyPropose", edits: PEM_LOCK, sessionKey: "s1" }, "data");
  assert.equal(t.applied, true);
  const text = readFileSync(file, "utf8");
  const pem = getCurrentPolicy().document!.paths!.find((x) => x.path === "/home/u/repo/**/*.pem")!;
  const pemItem = yaml.dump([pem], { lineWidth: 100, noRefs: true }).replace(/^/gm, "  ").trimEnd();
  assert.equal(
    text,
    HAND.replace("    level: no-model\n\n", `    level: no-model\n${pemItem}\n\n`),
    "every line of the hand edit as written, the lock added under paths:",
  );
  assert.deepEqual(ruleIds(), [], "still held");
  assert.ok(docs.heldChange && docs.heldChange.text === text);
});

test("a tightening with nothing held is written into the file as it is: comments stay", () => {
  const HAND = "# mine\nversion: 1\npaths:\n  - path: /home/u/repo/.env  # prod key\n    level: no-model\n";
  writeDisk(HAND);
  docs.pollDisk();
  assert.equal(docs.heldChange, null);
  const t = ops.propose({ id: "1", op: "policyPropose", edits: [{ op: "lock-path", path: "/home/u/repo/.env", level: "no-model", bindings: [] }, ...PEM_LOCK], sessionKey: "s1" }, "data");
  assert.equal(t.applied, true);
  const text = readFileSync(file, "utf8");
  assert.ok(text.startsWith("# mine\nversion: 1\npaths:\n  - path: /home/u/repo/.env  # prod key\n"), text);
  assert.ok(lockedPaths().includes("/home/u/repo/**/*.pem"));
  assert.equal(docs.pollDisk(), false, "the arbiter's own write is not judged as a hand edit");
});

test("tour 17: a held edit the law has come to say is closed when the pending list is read", () => {
  writeDisk(RELAX_TEXT);
  docs.pollDisk();
  const [p] = pending();
  // The law comes to say the same by another way, without the store seeing a
  // new file (the content the hold names stays on disk).
  const law = yaml.load(RELAX_TEXT) as PolicyFileConfig;
  rebuild(law);
  (docs as unknown as { current: PolicyFileConfig }).current = law;
  assert.deepEqual(pending(), [], "read: the card is closed");
  assert.equal(proposals.getProposal(p!.id)!.status, "superseded");
  assert.equal(docs.heldChange, null);
  assert.deepEqual(ruleIds(), ["hand"]);
});

test("at start a card pending from before the restart stays pending and its change stays held", () => {
  writeDisk(RELAX_TEXT);
  docs.pollDisk();
  const [p] = pending();
  docs.close();
  // Restart as the server does it (policy-restore.ts): the content in force
  // was recorded, and a pending row names the file's bytes.
  const at = reconcilePolicyFileAtStart({ path: file, enforced: proposals.enforcedPolicy(file), diskRows: proposals.listProposals() });
  assert.equal(at.decision.law, "enforced");
  assert.deepEqual(at.inForce, { hash: contentHash(INITIAL_TEXT), text: INITIAL_TEXT });
  rebuild(INITIAL);
  docs = new PolicyDocumentStore(
    { path: file, rebuild, pollMs: 0, log: (m) => logs.push(m), persistEnforced: (e) => proposals.recordEnforced(file, e) },
    { document: INITIAL, found: true, inForce: at.inForce, declined: at.declined },
  );
  assert.equal(docs.heldChange?.hash, contentHash(RELAX_TEXT), "held again at load time");
  assert.deepEqual(ruleIds(), [], "the waiting change is not the law");
  ops = newOps(); // same proposal store (mandu.db survives a restart)
  assert.equal(proposals.getProposal(p!.id)!.status, "pending", "the same card");
  assert.deepEqual(pending().map((x) => x.id), [p!.id], "no second card");
  assert.equal(docs.pollDisk(), false);
  ops.resolve(p!.id, "approved", "dashboard");
  assert.deepEqual(ruleIds(), ["hand"], "approving after the restart loads it");
});

test("a judge that throws counts as a relaxation (fail closed)", () => {
  docs.close();
  docs = new PolicyDocumentStore(
    { path: file, rebuild, pollMs: 0, judge: () => { throw new Error("boom"); } },
    { document: INITIAL, found: true },
  );
  writeDisk(TIGHT_TEXT);
  assert.equal(docs.pollDisk(), true);
  assert.equal(docs.heldChange?.delta.relaxations[0]?.facet, "law");
  assert.ok(!getCurrentPolicy().pathLabels.has("/home/u/repo/id_rsa"), "not applied");
});

test("removing the file is judged too: dropping a lock relaxes, so it is held", () => {
  rmSync(file);
  assert.equal(docs.pollDisk(), true);
  assert.equal(docs.heldChange?.found, false);
  assert.ok(getCurrentPolicy().pathLabels.has("/home/u/repo/.env"), "the lock stays in force");
  const [p] = pending();
  assert.equal(p!.diskHash, "absent");
  ops.resolve(p!.id, "approved", "dashboard");
  assert.ok(!getCurrentPolicy().pathLabels.has("/home/u/repo/.env"), "approved: the built-ins are the law");
  assert.equal(docs.status.found, false);
});
