/**
 * prompt-filter-policy-op.test — phase 2 of the prompt filter over the
 * arbiter's real sockets (confidentiality-plan-15-prompt-filter.md §4.2, §6,
 * §7, §8.1). Mandu-new.
 *
 * A listening ArbiterServer with a policy FILE (`prompt_filters:` turning on
 * `key-shapes` and a pack, `pii.payment-card: block`) and the person's pack
 * directory. Proves, through ArbiterClient on the data, human and admin
 * channels:
 *   - `filterPrompt` (data, the proxies' op) redacts an unregistered GitHub
 *     token and answers `block` for a payment card, with a reason that never
 *     holds the value and a safe text;
 *   - `promptFilters` (data) carries switches, actions and pack COUNTS, never
 *     a regex or a keyword; `promptFilterPacks` is refused on the data socket
 *     and served on the human one;
 *   - an exception is enforced by the arbiter itself (`filterPrompt` lets the
 *     matching card through), yet `promptFilters` lists it with no pattern
 *     and `promptExceptions`, the pattern's one reader, is refused on the
 *     data socket and served on the human one (plan 15 §13.7 item 4);
 *   - `promptPackEdit` is refused on the data and human sockets and applies
 *     on the admin channel: a dry run counts matches and writes nothing; a
 *     live edit writes the person's pack file and the NEXT request runs it;
 *     an edit that does not validate (RE2) writes nothing;
 *   - the monotonic split over the data plane's `policyPropose`: raising an
 *     action applies to policy.yaml at once and the next request enforces it;
 *     lowering one is filed as a proposal and enforces nothing.
 *
 * Axes: secrets (stated; the server's confidentiality option pinned ON).
 */
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer, adminOnlyError, humanPlaneOnlyError } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { NO_ADMIN_LAYER, setAdminLayer } from "../../policy/admin-layer.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const GH = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
const CARD = "4111 1111 1111 1111";
/** A test card the person excepted (its pattern stands for their own words). */
const EXC_CARD = "5555 5555 5555 4444";

const dirs: string[] = [];
after(() => {
  setAdminLayer(NO_ADMIN_LAYER);
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

async function rig() {
  const dir = mkdtempSync(join(tmpdir(), "mdu-prompt-policy-"));
  dirs.push(dir);
  const packs = join(dir, "prompt-filters");
  mkdirSync(packs);
  writeFileSync(join(packs, "acme.yaml"), "pack: acme-dlp\nversion: 1\npatterns:\n  - id: card\n    category: pii.payment-card\n    regex: '\\b(?:\\d[ -]?){13,19}\\b'\n    check: luhn\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, "version: 1\nprompt_filters:\n  filters:\n    key-shapes: on\n    acme-dlp: on\n  actions:\n    pii.payment-card: block\n  exceptions:\n    - { category: pii.payment-card, match: '" + EXC_CARD + "' }\n");
  const sock = join(dir, "a.sock");
  const humanSock = join(dir, "human", "h.sock");
  const adminSock = join(dir, "admin.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, adminSocketPath: adminSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0, packDir: null,
    promptPackDir: packs, adminPromptPackDir: join(dir, "admin-packs"), adminPolicyDir: null, packKeysDir: join(dir, "keys"),
  });
  await server.listen();
  const data = new ArbiterClient(sock);
  const human = new ArbiterClient(humanSock);
  const admin = new ArbiterClient(adminSock);
  return { dir, packs, policy, server, data, human, admin, close: async () => { data.close(); human.close(); admin.close(); await server.close(); } };
}

test("filterPrompt under the policy file: an unregistered token is redacted, a card blocks with a safe text", async () => {
  const r = await rig();
  try {
    const out = await r.data.filterPrompt({ session: "s1", agent: "claude-code", segments: [{ id: "h", origin: "human", text: `push ${GH} and pay ${CARD}, thanks` }] });
    const [h] = out.segments;
    assert.equal(h!.action, "block");
    assert.match(h!.reason!, /pii\.payment-card \(acme-dlp\)/);
    assert.equal(h!.text, "push [redacted: secret.shape.github-token] and pay [blocked: pii.payment-card], thanks");
    assert.ok(!JSON.stringify(out).includes(GH) && !JSON.stringify(out).includes(CARD), "no value in the answer outside the text it replaced");
    // Harness text: the policy's filters run too, and a block there is a redaction (never a refusal).
    const hr = await r.data.filterPrompt({ agent: "claude-code", segments: [{ id: "r", origin: "harness", text: `<system-reminder>${GH} ${CARD}</system-reminder>` }] });
    assert.equal(hr.segments[0]!.action, "rewrite");
    assert.equal(hr.segments[0]!.text, "<system-reminder>[redacted: secret.shape.github-token] [redacted: pii.payment-card]</system-reminder>");
  } finally {
    await r.close();
  }
});

test("promptFilters carries counts only; promptFilterPacks is human-plane", async () => {
  const r = await rig();
  try {
    writeFileSync(join(r.packs, "broken.yaml"), "pack: broken\nversion: 1\npatterns:\n  - id: x\n    category: a.b\n    regex: '(secretword)\\1'\n");
    const pf = await r.data.promptFilters();
    const broken = JSON.stringify(pf.packProblems);
    assert.match(broken, /broken\.yaml/);
    assert.ok(!broken.includes("secretword") && !broken.includes("\\\\1"), `the data plane never quotes a pack's regex: ${broken}`);
    assert.deepEqual(pf.filters.map((f) => [f.id, f.on, f.setBy]), [["registered-value", true, "default"], ["key-shapes", true, "you"], ["acme-dlp", true, "you"]]);
    assert.deepEqual(pf.packs!.map((p) => [p.id, p.source, p.patterns]), [["acme-dlp", "user", 1]]);
    assert.ok(pf.actions!.some((a) => a.category === "pii.payment-card" && a.action === "block" && a.setBy === "you"));
    assert.ok(!JSON.stringify(pf).includes("\\\\d"), "no regex on the data plane");
    await assert.rejects(() => r.data.promptFilterPacks(), (e: Error) => e.message.includes(humanPlaneOnlyError("promptFilterPacks")));
    const det = await r.human.promptFilterPacks();
    assert.match(JSON.stringify(det.packProblems), /RE2 engine rejects/);
    assert.equal(det.packs[0]!.patterns[0]!.check, "luhn");
    assert.equal(det.packs[0]!.editable, true);
  } finally {
    await r.close();
  }
});

test("an exception is enforced in the arbiter; promptFilters lists it without its pattern; promptExceptions is human-plane (plan 15 §13.7 item 4)", async () => {
  const r = await rig();
  try {
    const out = await r.data.filterPrompt({ session: "s1", agent: "claude-code", segments: [{ id: "h", origin: "human", text: `pay ${EXC_CARD}, thanks` }] });
    assert.equal(out.segments[0]!.action, "pass", `the excepted card goes as written: the proxies need no pattern ${JSON.stringify(out.segments[0])}`);
    const pf = await r.data.promptFilters();
    assert.deepEqual(pf.exceptions, [{ category: "pii.payment-card", setBy: "you", inForce: true }]);
    assert.ok(!JSON.stringify(pf).includes("5555"), "no exception's pattern on the data plane");
    await assert.rejects(() => r.data.promptExceptions(), (e: Error) => e.message.includes(humanPlaneOnlyError("promptExceptions")));
    assert.deepEqual((await r.human.promptExceptions()).exceptions, [{ category: "pii.payment-card", match: EXC_CARD, setBy: "you", inForce: true }]);
    assert.deepEqual((await r.admin.promptExceptions()).exceptions.map((e) => e.match), [EXC_CARD]);
  } finally {
    await r.close();
  }
});

test("promptPackEdit: admin channel only; a dry run counts and writes nothing; a live edit runs on the next request", async () => {
  const r = await rig();
  try {
    const edits = [{ op: "set-prompt-pattern", pack: "acme-dlp", pattern: { id: "ticket", category: "acme.ticket", regex: "ACME-\\d{4,}" } }];
    await assert.rejects(() => r.data.promptPackEdit({ edits }), (e: Error) => e.message.includes(adminOnlyError("promptPackEdit")));
    await assert.rejects(() => r.human.promptPackEdit({ edits }), /admin-only/);
    const before = readFileSync(join(r.packs, "acme.yaml"), "utf8");
    const dry = await r.admin.promptPackEdit({ edits, dryRun: true, sample: "see ACME-1234" });
    assert.equal(dry.ok, true);
    assert.deepEqual(dry.counts, [{ id: "ticket", corpus: 0, sample: 1 }]);
    assert.equal(readFileSync(join(r.packs, "acme.yaml"), "utf8"), before, "a dry run writes nothing");
    const bad = await r.admin.promptPackEdit({ edits: [{ op: "set-prompt-pattern", pack: "acme-dlp", pattern: { id: "x", category: "a.b", regex: "(a)\\1" } }] });
    assert.equal(bad.ok, false);
    assert.match(bad.problems!.join("\n"), /RE2 engine rejects/);
    assert.equal(readFileSync(join(r.packs, "acme.yaml"), "utf8"), before);
    const live = await r.admin.promptPackEdit({ edits, requestedBy: "test" });
    assert.equal(live.ok, true, JSON.stringify(live));
    assert.deepEqual(live.changes!.map((c) => c.direction), ["tighten"]);
    assert.match(readFileSync(join(r.packs, "acme.yaml"), "utf8"), /ACME-/);
    const out = await r.data.filterPrompt({ agent: "codex", segments: [{ id: "h", origin: "human", text: "about ACME-20417 today" }] });
    assert.equal(out.segments[0]!.text, "about [redacted: acme.ticket] today", "the next request runs the new pattern (default action redact)");
    // A new pack of the person's.
    const created = await r.admin.promptPackEdit({ edits: [{ op: "add-prompt-keyword", pack: "mine", category: "me.project", word: "moonshot" }] });
    assert.equal(created.created, true);
    assert.equal(created.file, join(r.packs, "mine.yaml"));
  } finally {
    await r.close();
  }
});

test("the monotonic split on the data plane: a stronger action applies and enforces; a weaker one is only proposed", async () => {
  const r = await rig();
  try {
    const up = await r.data.policyPropose({ edits: [{ op: "set-prompt-action", category: "secret.shape", action: "block" }], sessionKey: "s1" });
    assert.equal(up.applied, true, JSON.stringify(up));
    assert.match(readFileSync(r.policy, "utf8"), /secret\.shape: block/);
    const out = await r.data.filterPrompt({ agent: "claude-code", segments: [{ id: "h", origin: "human", text: `push ${GH}` }] });
    assert.equal(out.segments[0]!.action, "block", "the tightened law is enforced on the next request");
    const down = await r.data.policyPropose({ edits: [{ op: "set-prompt-action", category: "pii.payment-card", action: "log" }], sessionKey: "s1" });
    assert.equal(down.applied, false);
    assert.ok("proposalId" in down && down.proposalId, JSON.stringify(down));
    assert.match(readFileSync(r.policy, "utf8"), /pii\.payment-card: block/, "a relaxation waits for the human");
    const still = await r.data.filterPrompt({ agent: "claude-code", segments: [{ id: "h", origin: "human", text: `pay ${CARD}` }] });
    assert.equal(still.segments[0]!.action, "block");
  } finally {
    await r.close();
  }
});
