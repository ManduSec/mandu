/**
 * test-flow-remembered-answer — `testFlow` for a FILE sees the human's
 * remembered answers about that file's placeholders (policy-surface.md §4
 * "Test a flow", §5 "Tester ≡ gates"; tour 1, 2026-10-05).
 *
 * The bug: a human answered Always allow for a send of `.env` to a host, so
 * the live egress gate released every later send there, while `mandu why
 * .env --to <host>` (testFlow) said "held for your approval": the tester
 * asked the standing-answer layer for a placeholder probe symbol that no
 * answer is ever keyed on. Now, for a registered file read (`tool: Read`,
 * a path origin), the tester asks that layer for each placeholder a real
 * send of the file carries (every active registration's field symbols, or
 * the whole-file symbol), reading only (never spending a once, never
 * queueing), and answers the most restrictive of them.
 *
 * Fail-closed negatives: an answer for another host, another file, a forced
 * different level, an Allow once, a removed answer, an answer covering only
 * one of the file's values, and an answer on an older registration of the
 * file never make the tester say released.
 *
 * A real ArbiterServer in `secrets`, data / human / admin sockets.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { loadPolicyFileStrict } from "../../policy/policy-file-validate.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const HOST = "collector.example";
const OTHER_HOST = "pastebin.example";

interface Rig {
  dir: string;
  envA: string;
  envB: string;
  envTwo: string;
  data: ArbiterClient;
  human: ArbiterClient;
  admin: ArbiterClient;
  close(): Promise<void>;
}

async function rig(prefix: string): Promise<Rig> {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  const proj = join(dir, "proj");
  mkdirSync(proj, { recursive: true });
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const envA = join(proj, "a.env");
  const envB = join(proj, "b.env");
  const envTwo = join(proj, "two.env");
  writeFileSync(envA, "STRIPE_KEY=sk_live_TFRA_aaaaaaaaaaaa\n");
  writeFileSync(envB, "STRIPE_KEY=sk_live_TFRA_bbbbbbbbbbbb\n");
  writeFileSync(envTwo, "STRIPE_KEY=sk_live_TFRA_cccccccccccc\nGITHUB_TOKEN=ghp_TFRAdddddddddddddddddddddddddddddddd\n");
  const policy = join(dir, "policy.yaml");
  // Labelled no-model, bound nowhere: every send is the human's to answer.
  writeFileSync(policy, `version: 1
paths:
  - path: ${envA}
    level: no-model
  - path: ${envB}
    level: no-model
  - path: ${envTwo}
    level: no-model
`);
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"),
    humanSocketPath: join(dir, "human", "h.sock"),
    adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "db.sqlite"),
    eventDir: join(dir, "events"),
    log: () => {},
    confidentiality: true,
    integrity: false,
    policyPollMs: 0,
    policyDocument: loadPolicyFileStrict(policy).config,
  });
  await s.listen();
  const data = new ArbiterClient(join(dir, "a.sock")); await data.connect();
  const human = new ArbiterClient(join(dir, "human", "h.sock")); await human.connect();
  const admin = new ArbiterClient(join(dir, "admin.sock")); await admin.connect();
  return {
    dir, envA, envB, envTwo, data, human, admin,
    async close() {
      data.close(); human.close(); admin.close();
      await s.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

/** Register `path` as a launch does and return its field placeholders (the
 *  symbols its twin carries). */
async function register(r: Rig, path: string): Promise<string[]> {
  const reg = await r.data.registerSecret({ path });
  assert.ok(reg.symbol, `registered: ${reg.reason}`);
  assert.ok(reg.twin, "a dotenv file has a structured twin");
  const fields = reg.twin.match(/\$MDU:[A-Za-z_]+\[[0-9a-f]+\]\.[A-Z_]+/g) ?? [];
  assert.ok(fields.length > 0, "the twin carries field placeholders");
  return fields;
}

/** The live gate's ask for a real send (the net-proxy asks on the human
 *  socket), queued, then the human's answer on the admin channel. */
async function answer(r: Rig, symbol: string, host: string, approve: boolean, scope: "always" | "once"): Promise<string> {
  const ask = await r.human.desymbolizationDecision({ symbol, boundary: "network", destination: host, sessionKey: "s-tfra" });
  assert.equal(ask.allow, false, "unbound: the live gate asks first");
  const id = (ask as { approvalId?: string }).approvalId;
  assert.ok(id, "the ask queued a row");
  await r.admin.resolveEgressApproval(id, approve, scope);
  return id;
}

const sendFile = (r: Rig, path: string, host: string, level?: string) =>
  r.data.testFlow({ source: { tool: "Read", origin: path }, destination: host, ...(level ? { level } : {}) });

test("an Always allow for the file's placeholder at the host: the tester says released by that answer, as the live gate does", async () => {
  const r = await rig("mdu-tfra-pos-");
  try {
    const [field] = await register(r, r.envA);
    // Before any answer: held, from the law.
    const before = await sendFile(r, r.envA, HOST);
    assert.equal(before.egress?.decision.allow, false);
    assert.equal(before.egress?.decision.requiresApproval, true);

    const id = await answer(r, field!, HOST, true, "always");
    const live = await r.human.desymbolizationDecision({ symbol: field!, boundary: "network", destination: HOST });
    assert.equal(live.allow, true, "the live gate releases the send");

    const rowsBefore = await r.admin.egressApprovals();
    const t = await sendFile(r, r.envA, HOST);
    assert.equal(t.egress?.decision.allow, true, "the tester agrees with the live gate");
    assert.equal(t.egress?.stage, "verdict");
    assert.deepEqual(t.egress?.decision.ruleRef, { source: "verdict", id: `verdict:${id}` });
    assert.equal(t.placeholders, 1, "one placeholder in the file's twin, and it was checked");
    // A read: nothing queued, counted or changed.
    assert.deepEqual(await r.admin.egressApprovals(), rowsBefore, "the tester changed no answer and queued nothing");

    // The same file read for its whole-file datum under another tool is a
    // synthetic probe, as before (no file placeholder is named).
    const web = await r.data.testFlow({ source: { tool: "WebFetch", origin: r.envA }, destination: HOST });
    assert.notEqual(web.egress?.stage, "verdict");
    assert.equal(web.placeholders, undefined);
  } finally {
    await r.close();
  }
});

test("negatives: another host, another file, a forced other level, an Allow once, a removed answer: never released by an answer", async () => {
  const r = await rig("mdu-tfra-neg-");
  try {
    const [fieldA] = await register(r, r.envA);
    await register(r, r.envB);
    const id = await answer(r, fieldA!, HOST, true, "always");

    const otherHost = await sendFile(r, r.envA, OTHER_HOST);
    assert.equal(otherHost.egress?.decision.allow, false, "an answer for another host does not cover this one");
    assert.equal(otherHost.egress?.decision.requiresApproval, true);

    const otherFile = await sendFile(r, r.envB, HOST);
    assert.equal(otherFile.egress?.decision.allow, false, "an answer about another file does not cover this one");
    assert.notEqual(otherFile.egress?.stage, "verdict");

    const forced = await sendFile(r, r.envA, HOST, "local-model");
    assert.equal(forced.egress?.decision.allow, false, "a forced level is a hypothetical datum, not this file's placeholder");
    assert.notEqual(forced.egress?.stage, "verdict");
    assert.equal(forced.placeholders, undefined);
    // The file's own level, forced explicitly, is still the file.
    assert.equal((await sendFile(r, r.envA, HOST, "no-model")).egress?.decision.allow, true);

    // Removed (the Rules page's Remove): asked again.
    await r.admin.forgetEgressApproval(id);
    const removed = await sendFile(r, r.envA, HOST);
    assert.equal(removed.egress?.decision.allow, false, "a removed answer covers nothing");
    assert.equal(removed.egress?.decision.requiresApproval, true);

    // An Allow once: the tester neither credits it nor spends it.
    const once = await answer(r, fieldA!, HOST, true, "once");
    const t = await sendFile(r, r.envA, HOST);
    assert.equal(t.egress?.decision.allow, false, "an Allow once is the next send's, not a standing release");
    const row = (await r.admin.egressApprovals()).find((a) => a.id === once)!;
    assert.equal(row.status, "approved");
    assert.equal(row.consumedAt, null, "the tester did not spend the once");
    const use = await r.human.desymbolizationDecision({ symbol: fieldA!, boundary: "network", destination: HOST });
    assert.equal(use.allow, true, "the real send still gets its one use");
  } finally {
    await r.close();
  }
});

test("a denial is reported as blocked by the answer; a file of two values needs an answer for each", async () => {
  const r = await rig("mdu-tfra-two-");
  try {
    const [fieldA] = await register(r, r.envA);
    const denied = await answer(r, fieldA!, HOST, false, "always");
    const d = await sendFile(r, r.envA, HOST);
    assert.equal(d.egress?.decision.allow, false);
    assert.equal(d.egress?.decision.requiresApproval, false);
    assert.deepEqual(d.egress?.decision.ruleRef, { source: "verdict", id: `verdict:${denied}` });

    const fields = await register(r, r.envTwo);
    assert.equal(fields.length, 2);
    await answer(r, fields[0]!, HOST, true, "always");
    const half = await sendFile(r, r.envTwo, HOST);
    assert.equal(half.egress?.decision.allow, false, "one value answered, the other still asks");
    assert.equal(half.egress?.decision.requiresApproval, true);
    assert.equal(half.placeholders, 2);
    await answer(r, fields[1]!, HOST, true, "always");
    const both = await sendFile(r, r.envTwo, HOST);
    assert.equal(both.egress?.decision.allow, true, "every value answered");
    assert.equal(both.egress?.stage, "verdict");

    // egress-hold.md "One card per file" (2026-10-19): a request carrying
    // both values asks on the FILE's one card, and its answer covers both,
    // in the tester as at the gate.
    const ask = await r.human.desymbolizationDecision({ symbol: fields[0]!, boundary: "network", destination: OTHER_HOST, sessionKey: "s-tfra", requestSymbols: fields });
    const fileCard = (ask as { approvalId?: string }).approvalId!;
    assert.equal((await r.admin.egressApprovals()).find((a) => a.id === fileCard)?.symbol, fields[0]!.slice(0, fields[0]!.indexOf("].") + 1), "the file's card");
    assert.equal((await sendFile(r, r.envTwo, OTHER_HOST)).egress?.decision.allow, false, "held before the answer");
    await r.admin.resolveEgressApproval(fileCard, true, "always");
    const whole = await sendFile(r, r.envTwo, OTHER_HOST);
    assert.equal(whole.egress?.decision.allow, true, "the file's one answer covers both values");
    assert.deepEqual(whole.egress?.decision.ruleRef, { source: "verdict", id: `verdict:${fileCard}` });
  } finally {
    await r.close();
  }
});

test("an answer on an older registration of the file does not cover the file as it is now", async () => {
  const r = await rig("mdu-tfra-old-");
  try {
    const [old] = await register(r, r.envA);
    await answer(r, old!, HOST, true, "always");
    assert.equal((await sendFile(r, r.envA, HOST)).egress?.decision.allow, true);
    // The file changes; the next launch registers its new value.
    writeFileSync(r.envA, "STRIPE_KEY=sk_live_TFRA_changed_eeeeeee\n");
    const [fresh] = await register(r, r.envA);
    assert.notEqual(fresh, old);
    const t = await sendFile(r, r.envA, HOST);
    assert.equal(t.egress?.decision.allow, false, "the new value has no answer: held");
    assert.equal(t.egress?.decision.requiresApproval, true);
  } finally {
    await r.close();
  }
});
