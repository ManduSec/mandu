/**
 * policy-pattern-channel e2e — the policy reads with the prompt exceptions'
 * patterns kept off the DATA socket, through the real arbiter sockets
 * (confidentiality-plan-15-prompt-filter.md §13.7 item 4; arbiter-human-plane.md
 * §3; policy/prompt-pattern-redact.ts).
 *
 * One in-process ArbiterServer with a file-backed law holding two exceptions
 * (one written beside a comment that repeats it), a data, a human and an
 * admin socket. Proves:
 *   - `policyDocument`, `policyProposals` and `policyChanges` on the data
 *     socket hold no exception's pattern anywhere (document, parse, text,
 *     edits, delta lines), the placeholder and `patternHidden` in their
 *     place, and the rest of the answer as the human socket gives it (the
 *     file's other lines byte for byte);
 *   - on the human socket and the admin channel the same ops answer in full;
 *   - the placeholder never overwrites a stored pattern: a whole document
 *     built from the data read is refused on the admin channel (with the flag
 *     and without it), an edit built from a data-read change row is refused
 *     on the data socket, the file is byte-identical, and the exception
 *     still lets its span through.
 *
 * Axes: secrets (stated; the server's confidentiality option pinned ON).
 */
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { NO_ADMIN_LAYER, setAdminLayer } from "../../policy/admin-layer.js";
import { PROMPT_PATTERN_PLACEHOLDER as PH } from "../../policy/prompt-pattern-redact.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const WORDS = "*@my-own-private-words.example";
const CODE = "falconridgeproject";
const ADDED = "ACME-2*";

const LAW = [
  "version: 1",
  "# my rules",
  "prompt_filters:",
  "  filters:",
  "    acme-dlp: on",
  "  actions:",
  "    acme.codename: redact",
  "  exceptions:",
  `    - { category: pii.email, match: '${WORDS}' }   # mail to ${WORDS} is fine`,
  "    - category: acme.codename",
  `      match: ${CODE}`,
  "",
].join("\n");

const dirs: string[] = [];
after(() => {
  setAdminLayer(NO_ADMIN_LAYER);
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

async function rig() {
  const dir = mkdtempSync(join(tmpdir(), "mdu-pattern-channel-"));
  dirs.push(dir);
  const packs = join(dir, "prompt-filters");
  mkdirSync(packs);
  writeFileSync(join(packs, "acme.yaml"), `pack: acme-dlp\nversion: 1\nkeywords:\n  - category: acme.codename\n    words: [${CODE}]\n  - category: acme.ticket\n    match: substring\n    words: [ACME-2]\n`);
  const file = join(dir, "policy.yaml");
  writeFileSync(file, LAW);
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false,
    policyPath: file, policyPollMs: 0, packDir: null, promptPackDir: packs, adminPromptPackDir: null, adminPolicyDir: null, packKeysDir: join(dir, "keys"),
  });
  await server.listen();
  const data = new ArbiterClient(join(dir, "a.sock"));
  const human = new ArbiterClient(join(dir, "human", "h.sock"));
  const admin = new ArbiterClient(join(dir, "admin.sock"));
  return { file, data, human, admin, close: async () => { data.close(); human.close(); admin.close(); await server.close(); } };
}

const hidden = (what: string, v: unknown): void => {
  const json = JSON.stringify(v);
  for (const p of [WORDS, CODE, ADDED, "my-own-private-words"]) assert.ok(!json.includes(p), `${what}: '${p}' is in the data answer: ${json.slice(0, 400)}`);
};

test("the three policy reads: no pattern on the data socket, the placeholder and the flag instead; in full on human and admin", async () => {
  const r = await rig();
  try {
    // A human adds an exception on the admin channel (Settings' path): a
    // relaxation, filed then approved, so a proposal and a change hold it.
    const filed = await r.admin.policyPropose({ edits: [{ op: "add-prompt-exception", category: "acme.ticket", match: ADDED }], requestedBy: "human:settings" });
    assert.ok(filed.applied === false && "proposalId" in filed, JSON.stringify(filed));
    const approved = await r.admin.resolvePolicyProposal(filed.proposalId, "approved", "human:settings");
    assert.ok(approved.changeId);

    const doc = await r.data.policyDocument();
    hidden("policyDocument", doc);
    assert.equal(doc.patternsHidden, true);
    const exc = (doc.inForce as { prompt_filters: { exceptions: Array<Record<string, unknown>> } }).prompt_filters.exceptions;
    assert.deepEqual(exc.map((e) => [e.category, e.match, e.patternHidden]), [["pii.email", PH, true], ["acme.codename", PH, true], ["acme.ticket", PH, true]]);
    const full = await r.human.policyDocument();
    assert.ok(JSON.stringify(full).includes(WORDS) && JSON.stringify(full).includes(ADDED), "the human socket answers in full");
    assert.equal(full.patternsHidden, undefined);
    assert.ok(JSON.stringify(await r.admin.policyDocument()).includes(CODE), "so does the admin channel");
    // The text: only the match values and the comment repeating one change.
    const want = full.onDisk.text!.split("\n");
    const got = doc.onDisk.text!.split("\n");
    assert.equal(got.length, want.length);
    for (let i = 0; i < want.length; i++) {
      if (/match:|#.*@/.test(want[i]!)) continue;
      assert.equal(got[i], want[i], `line ${i} is as on disk`);
    }
    assert.deepEqual(doc.status, full.status, "the status is the same");

    const proposals = await r.data.policyProposals("approved");
    hidden("policyProposals", proposals);
    const card = proposals.proposals.find((p) => p.id === filed.proposalId)!;
    assert.deepEqual(card.edits, [{ op: "add-prompt-exception", category: "acme.ticket", match: PH, patternHidden: true }]);
    assert.equal(card.relaxes[0]!.patternHidden, true);
    assert.ok(JSON.stringify(await r.human.policyProposals("approved")).includes(ADDED), "the human queue shows it");

    const changes = await r.data.policyChanges(10);
    hidden("policyChanges", changes);
    const ch = changes.changes.find((c) => c.id === approved.changeId)!;
    assert.deepEqual(ch.edits, [{ op: "add-prompt-exception", category: "acme.ticket", match: PH, patternHidden: true }]);
    assert.ok(ch.delta.every((d) => d.subject.startsWith("prompt exception ") ? d.patternHidden === true : true));
    const humanCh = (await r.human.policyChanges(10)).changes.find((c) => c.id === approved.changeId)!;
    assert.deepEqual(humanCh.edits, [{ op: "add-prompt-exception", category: "acme.ticket", match: ADDED }]);
    assert.deepEqual({ ...ch, edits: [], delta: [] }, { ...humanCh, edits: [], delta: [] }, "the rest of the row is the same");
  } finally {
    await r.close();
  }
});

test("a placeholder never overwrites a stored pattern: a document or an edit built from a data read is refused, the file unchanged, the exception still in force", async () => {
  const r = await rig();
  try {
    const bytes = readFileSync(r.file, "utf8");
    const dataRead = await r.data.policyDocument();
    const fromData = dataRead.inForce as Record<string, unknown>;
    await assert.rejects(() => r.admin.applyPolicyDocument(fromData, "test", dataRead.lawHash!), /patternHidden|placeholder/, "with the flag");
    const unflagged = JSON.parse(JSON.stringify(fromData).replace(/,"patternHidden":true/g, "")) as Record<string, unknown>;
    assert.ok(!JSON.stringify(unflagged).includes("patternHidden"));
    await assert.rejects(() => r.admin.applyPolicyDocument(unflagged, "test", dataRead.lawHash!), /placeholder a data-socket read shows/, "without it");
    // An edit lifted from a data-read row (the agent proposes it back).
    for (const edit of [
      { op: "add-prompt-exception", category: "acme.codename", match: PH },
      { op: "remove-prompt-exception", category: "acme.codename", match: PH },
      { op: "add-prompt-exception", category: "acme.codename", match: PH, patternHidden: true },
    ]) {
      const out = await r.data.policyPropose({ edits: [edit], sessionKey: "s1" });
      assert.equal((out as { applied?: boolean }).applied, false, JSON.stringify(out));
      assert.equal((out as { refused?: string }).refused, "invalid", `refused as invalid, never filed: ${JSON.stringify(out)}`);
    }
    assert.equal(readFileSync(r.file, "utf8"), bytes, "policy.yaml is byte-identical");
    const pending = (await r.human.policyProposals("pending")).proposals;
    assert.equal(pending.length, 0, `nothing was filed: ${JSON.stringify(pending)}`);
    // The stored pattern still lets its span through (the engine matches it).
    const f = await r.data.filterPrompt({ session: "s1", agent: "claude-code", segments: [{ id: "h", origin: "human", text: `ship ${CODE} today` }] });
    assert.equal(f.segments[0]!.action, "pass", JSON.stringify(f.segments[0]));
  } finally {
    await r.close();
  }
});
