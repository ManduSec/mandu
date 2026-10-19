/**
 * prompt-filter-hold-op.test — `ask` and the Inbox hold over the arbiter's
 * real sockets (confidentiality-plan-15-prompt-filter.md §7, phase 3; §13.6).
 * Mandu-new.
 *
 * A listening ArbiterServer with a policy FILE (`acme.codename: ask`, a pack
 * that finds the code name) and three ArbiterClients (data, human, admin).
 * Proves:
 *   - from the DATA socket an `ask` goes with its default (masked): no hold,
 *     no Inbox row, whatever the caller asks for (plan 13 D9);
 *   - from the HUMAN socket (where the proxies dial) the request is held:
 *     `hold`, no text, a pending row whose reason never names the span;
 *   - `promptHolds` (the span for the Inbox card) is human-plane only;
 *   - the answer is ADMIN-ONLY: `resolvePromptHold`, `resolveEgressApproval`
 *     and `letPromptFindingThrough` are refused on the data and the human
 *     sockets, so an answer from the agent's world is never taken;
 *   - after "send as written" the next request carries the span raw; an
 *     Always through the generic Inbox route covers the session;
 *   - under a LOCKED administrator's `ask` row (a file in the administrator's
 *     layer) the hold takes an answer for this message only (§12,
 *     2026-10-04): `promptHolds` and the queue say `onceOnly`; a session
 *     answer, an Always on the generic route and a session let-through are
 *     refused on the admin channel; the next message is held again;
 *   - across an arbiter restart the references are stable (the verdict
 *     still applies) and a hold's deadline runs from its first sighting, so
 *     a resend after it goes masked at once.
 *
 * Axes: secrets (stated; the server's confidentiality option pinned ON).
 */
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer, adminOnlyError, humanPlaneOnlyError } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

function files() {
  const dir = mkdtempSync(join(tmpdir(), "mdu-prompt-hold-"));
  dirs.push(dir);
  const packs = join(dir, "prompt-filters");
  mkdirSync(packs);
  writeFileSync(join(packs, "acme.yaml"), "pack: acme-dlp\nversion: 1\nkeywords:\n  - category: acme.codename\n    words: [falcon]\n    level: local-model\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, "version: 1\nprompt_filters:\n  filters:\n    acme-dlp: on\n  actions:\n    acme.codename: ask\n");
  return { dir, packs, policy };
}

async function rig(f: ReturnType<typeof files>, holdMs = 30_000, adminPolicyDir: string | null = null) {
  const sock = join(f.dir, "a.sock");
  const humanSock = join(f.dir, "human", "h.sock");
  const adminSock = join(f.dir, "admin.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, adminSocketPath: adminSock, dbPath: join(f.dir, "mandu.db"), eventDir: join(f.dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPath: f.policy, policyPollMs: 0, packDir: null,
    promptPackDir: f.packs, adminPromptPackDir: join(f.dir, "admin-packs"), adminPolicyDir, packKeysDir: join(f.dir, "keys"),
    promptHoldMs: holdMs,
  });
  await server.listen();
  const data = new ArbiterClient(sock);
  const human = new ArbiterClient(humanSock);
  const admin = new ArbiterClient(adminSock);
  return { server, data, human, admin, close: async () => { data.close(); human.close(); admin.close(); await server.close(); } };
}

const ask = (session: string, text: string) => ({ session, agent: "claude-code", segments: [{ id: "h", origin: "human" as const, text }], holds: true });

test("data socket: the default, no hold, no row; human socket: held; only the admin channel answers", async () => {
  const r = await rig(files());
  try {
    const d = (await r.data.filterPrompt(ask("s1", "ship falcon today"))).segments[0]!;
    assert.equal(d.action, "rewrite");
    assert.ok(!d.text!.includes("falcon"), "masked by default from the data socket");
    assert.equal(d.findings[0]!.hold?.state, "default");
    assert.deepEqual(await r.admin.egressApprovals(), [], "no Inbox row from the data socket");

    const h = (await r.human.filterPrompt(ask("s1", "ship falcon today"))).segments[0]!;
    assert.equal(h.action, "hold");
    assert.equal(h.text, undefined);
    const id = h.hold!.approvalId;
    const rows = await r.data.egressApprovals("pending");
    assert.equal(rows.length, 1);
    assert.ok(!JSON.stringify(rows).includes("falcon"), "the queue (data plane) never names the span");

    await assert.rejects(() => r.data.promptHolds(), new RegExp(humanPlaneOnlyError("promptHolds").slice(0, 40).replace(/[()]/g, ".")));
    const view = await r.human.promptHolds();
    assert.equal(view.holds[0]!.span, "falcon");
    assert.equal(view.holds[0]!.approvalId, id);

    for (const c of [r.data, r.human]) {
      await assert.rejects(() => c.resolvePromptHold({ approvalId: id, answer: "send" }), (e: Error) => e.message === adminOnlyError("resolvePromptHold"));
      await assert.rejects(() => c.resolveEgressApproval(id, true), (e: Error) => e.message === adminOnlyError("resolveEgressApproval"));
      await assert.rejects(() => c.letPromptFindingThrough({ session: "s1", category: "acme.codename", ref: h.findings[0]!.ref!, scope: "session" }), (e: Error) => e.message === adminOnlyError("letPromptFindingThrough"));
    }
    assert.equal((await r.human.filterPrompt(ask("s1", "ship falcon today"))).segments[0]!.action, "hold", "still held: no claimed answer was taken");

    const res = await r.admin.resolvePromptHold({ approvalId: id, answer: "send", scope: "once" });
    assert.equal(res.approval.status, "approved");
    const sent = (await r.human.filterPrompt(ask("s1", "ship falcon today"))).segments[0]!;
    assert.equal(sent.action, "pass", "as written after the human's answer");
    assert.equal(sent.findings[0]!.let, "once");
    // From the data socket the same message is still masked: no verdict is consulted there.
    assert.ok(!(await r.data.filterPrompt(ask("s1", "ship falcon today"))).segments[0]!.text!.includes("falcon"));

    // The generic Inbox route: Always = this session.
    const h2 = (await r.human.filterPrompt(ask("s1", "falcon again"))).segments[0]!;
    assert.equal(h2.action, "hold");
    await r.admin.resolveEgressApproval(h2.hold!.approvalId, true, "always");
    assert.equal((await r.human.filterPrompt(ask("s1", "a third falcon"))).segments[0]!.action, "pass");
    assert.equal((await r.human.filterPrompt(ask("s2", "a third falcon"))).segments[0]!.action, "hold", "another session asks");
  } finally {
    await r.close();
  }
});

test("a locked administrator's ask row: this message only, a session answer refused on every route, the next message held again", async () => {
  const f = files();
  writeFileSync(f.policy, "version: 1\nprompt_filters:\n  filters:\n    acme-dlp: on\n");
  const layer = join(f.dir, "policy.d");
  mkdirSync(layer);
  writeFileSync(join(layer, "10-org.yaml"), "prompt_filters:\n  actions:\n    acme.codename: { action: ask, locked: true }\n");
  const r = await rig(f, 30_000, layer);
  try {
    const h = (await r.human.filterPrompt(ask("s1", "ship falcon today"))).segments[0]!;
    assert.equal(h.action, "hold", "the administrator's ask holds");
    const id = h.hold!.approvalId;
    assert.equal((await r.human.promptHolds()).holds[0]!.onceOnly, true, "the Inbox card: this message only");
    assert.equal((await r.data.egressApprovals("pending"))[0]!.onceOnly, true, "the queue row says so too");

    const once = /answer it for this message only/;
    await assert.rejects(() => r.admin.resolvePromptHold({ approvalId: id, answer: "send", scope: "session" }), once);
    await assert.rejects(() => r.admin.resolvePromptHold({ approvalId: id, answer: "mask", scope: "session" }), once);
    await assert.rejects(() => r.admin.resolveEgressApproval(id, true, "always"), once);
    await assert.rejects(() => r.admin.resolveEgressApproval(id, false), once, "an absent scope is the standing Always: refused, never downgraded");
    await assert.rejects(() => r.admin.letPromptFindingThrough({ session: "s1", category: "acme.codename", ref: h.findings[0]!.ref!, scope: "session" }), once);
    assert.equal((await r.data.egressApprovals("pending")).length, 1, "every refusal left the row waiting");
    assert.equal((await r.human.filterPrompt(ask("s1", "ship falcon today"))).segments[0]!.action, "hold", "still held");

    await r.admin.resolvePromptHold({ approvalId: id, answer: "send", scope: "once" });
    assert.equal((await r.human.filterPrompt(ask("s1", "ship falcon today"))).segments[0]!.action, "pass", "this message, as written");
    const next = (await r.human.filterPrompt(ask("s1", "falcon again"))).segments[0]!;
    assert.equal(next.action, "hold", "the next message is held again");
    await r.admin.resolveEgressApproval(next.hold!.approvalId, true, "once");
    assert.equal((await r.human.filterPrompt(ask("s1", "falcon again"))).segments[0]!.action, "pass", "the generic route's Allow once is taken");
    assert.equal((await r.human.filterPrompt(ask("s1", "a third falcon"))).segments[0]!.action, "hold");
  } finally {
    await r.close();
  }
});

test("letPromptFindingThrough on the admin channel; a dry run never holds", async () => {
  const f = files();
  writeFileSync(f.policy, "version: 1\nprompt_filters:\n  filters:\n    acme-dlp: on\n  actions:\n    acme.codename: redact\n");
  const r = await rig(f);
  try {
    const s = (await r.human.filterPrompt(ask("s1", "ship falcon today"))).segments[0]!;
    assert.equal(s.text, "ship [redacted: acme.codename] today");
    await r.admin.letPromptFindingThrough({ session: "s1", category: "acme.codename", ref: s.findings[0]!.ref!, turn: s.turn!, scope: "once" });
    assert.equal((await r.human.filterPrompt(ask("s1", "ship falcon today"))).segments[0]!.action, "pass");
    await assert.rejects(() => r.admin.letPromptFindingThrough({ session: "s1", category: "secret.registered", ref: "0".repeat(32), scope: "session" }), /registered secret/);
    const dry = await r.human.filterPrompt({ ...ask("s9", "ship falcon today"), dryRun: true });
    assert.notEqual(dry.segments[0]!.action, "hold");
  } finally {
    await r.close();
  }
});

test("restart: references and verdicts survive; a hold's deadline runs from its first sighting", async () => {
  const f = files();
  let r = await rig(f, 400);
  try {
    const h = (await r.human.filterPrompt(ask("s1", "ship falcon today"))).segments[0]!;
    assert.equal(h.action, "hold");
    const ref = h.findings[0]!.ref;
    const other = (await r.human.filterPrompt(ask("s1", "falcon two"))).segments[0]!;
    await r.admin.resolvePromptHold({ approvalId: other.hold!.approvalId, answer: "send", scope: "once" });
    await r.close();
    await new Promise((res) => setTimeout(res, 450));
    r = await rig(f, 400);
    const again = (await r.human.filterPrompt(ask("s1", "ship falcon today"))).segments[0]!;
    assert.equal(again.action, "rewrite", "past the deadline: the default at once, no second hold");
    assert.ok(!again.text!.includes("falcon"));
    assert.equal(again.findings[0]!.ref, ref, "the same reference after a restart");
    assert.equal(again.findings[0]!.hold?.state, "timed-out");
    assert.equal((await r.human.filterPrompt(ask("s1", "falcon two"))).segments[0]!.action, "pass", "the verdict survived");
    // The pending row is still answerable; the answer applies to the next resend.
    await r.admin.resolvePromptHold({ approvalId: h.hold!.approvalId, answer: "send", scope: "once" });
    assert.equal((await r.human.filterPrompt(ask("s1", "ship falcon today"))).segments[0]!.action, "pass");
  } finally {
    await r.close();
  }
});

test("every answer lands one approval_resolved audit event with promptAnswer and promptScope, never the span (plan 15 §13.9)", async () => {
  const r = await rig(files());
  try {
    const held = async (session: string, text: string) => (await r.human.filterPrompt(ask(session, text))).segments[0]!;
    const a = await held("s1", "ship falcon today");
    await r.admin.resolvePromptHold({ approvalId: a.hold!.approvalId, answer: "send", scope: "once" });
    const b = await held("s1", "falcon at noon");
    await r.admin.resolvePromptHold({ approvalId: b.hold!.approvalId, answer: "mask", scope: "session" });
    const c = await held("s2", "cancel falcon");
    await r.admin.resolvePromptHold({ approvalId: c.hold!.approvalId, answer: "cancel" });
    const d = await held("s3", "generic falcon");
    await r.admin.resolveEgressApproval(d.hold!.approvalId, true, "always");
    const e = await held("s4", "deny falcon");
    await r.admin.resolveEgressApproval(e.hold!.approvalId, false, "once");
    await r.admin.letPromptFindingThrough({ session: "s5", category: "acme.codename", ref: a.findings[0]!.ref!, scope: "session" });

    const audit = (await r.human.events("arbiter-admin", 0)).filter((ev) => ev["kind"] === "approval_resolved");
    assert.deepEqual(audit.map((ev) => [ev["promptAnswer"], ev["promptScope"]]), [
      ["send", "once"], ["mask", "session"], ["cancel", "once"], ["send", "session"], ["mask", "once"], ["let-through", "session"],
    ]);
    assert.ok(!JSON.stringify(audit).includes("falcon"), "the audit stream never carries the span");
    for (const ev of audit) {
      assert.match(String((ev["input"] as { symbolized: string }).symbolized), /^prompt:acme\.codename#[0-9a-f]{32} × model:s\d/);
    }
  } finally {
    await r.close();
  }
});
