/**
 * policy-pending-in-force e2e — first-session tour item 17, across the real
 * arbiter (file-backed law, the hand-edit poll running, mandu.db surviving a
 * restart), the dashboard's production wiring (`makeApprovalsArbiter`, the
 * Rules projection `toPolicyPanelViewModel`) and `mandu why` over its
 * production call path (launcher/src/why.ts):
 *
 *   - a relaxing hand edit of policy.yaml waits in Approvals and the agent's
 *     own lock (`policyPropose` on the data socket, what `mandu_policy_propose`
 *     calls) still applies at once; the file keeps the hand edit with the
 *     lock, the card is filed again for the new bytes, and a restart keeps
 *     it waiting;
 *   - Rules lists the rules in force all along, and `mandu why` names the
 *     waiting change and what it would make the file;
 *   - an agent's relaxing request the human made by hand while Mandu was
 *     stopped is closed at the next start, not left on Approvals;
 *   - THE INVARIANT (fail-closed): the secret is never released to the host
 *     the waiting change would bind it to, before, after the lock, or after
 *     a restart; only the human's own edit (loaded at start) releases it.
 *
 * Secrets axes (confidentiality ON, integrity OFF), stated below.
 * policy-surface.md §8.4.5, §8.4.6; dashboard.md §4.25 "A change waits";
 * comparisons.md §3.2.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { loadPolicyFileStrict } from "../../arbiter/policy/policy-file-validate.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { toPolicyPanelViewModel } from "../../dashboard/src/view-model/policy-panel.js";
import { toProposalCard } from "../../dashboard/src/view-model/policy-proposals.js";
import type { PolicySnapshot } from "../../dashboard/src/policy-model.js";
import { runWhy, realWhyDeps } from "../../launcher/src/why.js";
import type { Layout } from "../../launcher/src/services/layout.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: each server pins them below

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

async function waitFor<T>(what: string, probe: () => Promise<T | undefined>): Promise<T> {
  for (let i = 0; i < 200; i++) {
    const v = await probe();
    if (v !== undefined) return v;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error(`timed out waiting for ${what}`);
}

interface Stack {
  data: ArbiterClient;
  wired: NonNullable<Awaited<ReturnType<typeof makeApprovalsArbiter>>>;
  close: () => Promise<void>;
}

/** One arbiter start over the same file and mandu.db, with the dashboard's
 *  production wiring of its Approvals surface. */
async function start(dir: string, file: string): Promise<Stack> {
  const dataSock = join(dir, "a.sock");
  const adminSock = join(dir, "admin.sock");
  const server = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath: file, policyPollMs: 30, confidentiality: true, integrity: false, log: () => {},
  });
  await server.listen();
  const data = new ArbiterClient(dataSock);
  await data.connect();
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc?.policyProposals, "the dashboard's wiring exposes the proposals");
  return {
    data, wired: wired!,
    close: async () => {
      data.close();
      wired?.close();
      await server.close();
    },
  };
}

/** What the Approvals page lists (the product's cards). */
async function approvals(s: Stack) {
  return (await s.wired.policyDoc!.policyProposals!("pending")).proposals.map((p) => toProposalCard(p));
}

/** What the Rules page lists: the server projection of /api/policy/panel. */
async function rules(s: Stack) {
  const panel = toPolicyPanelViewModel((await s.data.policySnapshot()) as unknown as PolicySnapshot);
  return (panel.yourRules ?? []).filter((r) => r.kind === "lock").map((r) => ({ path: r.subject, bindings: r.bindings ?? [] }));
}

/** The egress gate's answer for the file's value sent to `host` (a probe). */
async function released(s: Stack, file: string, host: string): Promise<boolean> {
  const r = await s.data.testFlow({ source: { tool: "Read", origin: file }, destination: host });
  return r.egress?.decision.allow === true;
}

async function why(sock: string, args: string[], home: string, cwd: string): Promise<string> {
  const chunks: string[] = [];
  const deps = { ...realWhyDeps(), arbiter: async () => ({ sock, kind: "resident" as const, axisOn: true, stop: async () => {} }), cwd: () => cwd, out: (x: string) => { chunks.push(x); } };
  const code = await runWhy(args, { HOME: home }, {} as Layout, deps);
  assert.equal(code, 0, chunks.join(""));
  return chunks.join("");
}

/** The law: .env a secret, bound to Stripe or nowhere. */
function law(env: string, bound: boolean): string {
  return `version: 1\npaths:\n  - path: ${env}\n    level: no-model\n${bound ? "    bindings: [api.stripe.com]\n" : ""}`;
}

function setup(): { dir: string; home: string; proj: string; env: string; conf: string; file: string } {
  const dir = mkdtempSync(join(tmpdir(), "mdu-t17-"));
  dirs.push(dir);
  const home = join(dir, "home");
  const proj = join(home, "mandu-try");
  mkdirSync(join(proj, "deploy"), { recursive: true });
  const env = join(proj, ".env");
  writeFileSync(env, "STRIPE_KEY=sk_live_TOUR17VALUE\n");
  const conf = join(proj, "deploy", "staging.conf");
  writeFileSync(conf, "token=ghp_tour17\n");
  const file = join(dir, "policy.yaml");
  writeFileSync(file, law(env, false));
  return { dir, home, proj, env, conf, file };
}

test("tour 17 [secrets]: a held relaxing edit does not block the agent's lock; Rules and mandu why tell the truth; nothing is released", async () => {
  const { dir, home, proj, env, conf, file } = setup();
  let s = await start(dir, file);
  try {
    assert.equal(await released(s, env, "api.stripe.com"), false, "bound nowhere: a send is not released");
    // The human (or anything that can write the file) binds .env to Stripe by hand.
    writeFileSync(file, law(env, true));
    const [card] = await waitFor("the held card", async () => {
      const c = await approvals(s);
      return c.length ? c : undefined;
    });
    assert.equal(card!.onDisk, true);
    assert.equal(await released(s, env, "api.stripe.com"), false, "held: the binding is not the law");

    // (b) Rules lists the rule in force (no binding), not the held one.
    assert.deepEqual(await rules(s), [{ path: env, bindings: [] }]);

    // (c) mandu why says a change waits and what it would make the file.
    const w = await why(join(dir, "a.sock"), [".env"], home, proj);
    assert.match(w, /may go to +no host/, "the law in force");
    assert.match(w, new RegExp(`waiting +a change to this file's rule waits for your OK in Approvals \\(${card!.id}: policy\\.yaml was changed on disk\\); approved, the file is a secret no AI may read \\(no-model\\) and may go to api\\.stripe\\.com`));
    assert.match(w, /the lines above are what Mandu enforces/);
    assert.doesNotMatch(w, /sk_live_TOUR17VALUE/, "never a value");
    assert.match(await why(join(dir, "a.sock"), ["api.stripe.com"], home, proj), /waiting +a change to what may go to this host waits for your OK in Approvals/);

    // (a) The agent's own lock applies at once (mandu_policy_propose's op).
    const lock = await s.data.policyPropose({ edits: [{ op: "lock-path", path: conf, level: "no-model" }], sessionKey: "agent-1" });
    assert.equal(lock.applied, true, JSON.stringify(lock));
    assert.deepEqual((await rules(s)).map((r) => r.path).sort(), [env, conf].sort(), "the lock is in force");
    assert.equal(await released(s, env, "api.stripe.com"), false, "the lock released nothing");
    const onDisk = loadPolicyFileStrict(file).config as { paths: Array<{ path: string; bindings?: string[] }> };
    assert.deepEqual(onDisk.paths.find((p) => p.path === env)!.bindings, ["api.stripe.com"], "the hand edit stays in the file");
    assert.ok(onDisk.paths.some((p) => p.path === conf), "with the lock");
    const after = await approvals(s);
    assert.equal(after.length, 1, "one card: filed again for the file's new bytes");
    assert.notEqual(after[0]!.id, card!.id);
    assert.equal(after[0]!.onDisk, true);

    // A restart keeps the change waiting and the lock in force.
    await s.close();
    s = await start(dir, file);
    assert.deepEqual((await approvals(s)).map((c) => c.id), [after[0]!.id], "the same card after a restart");
    assert.deepEqual((await rules(s)).map((r) => [r.path, r.bindings]).sort(), [[conf, []], [env, []]].sort());
    assert.equal(await released(s, env, "api.stripe.com"), false, "a restart releases nothing");
    const again = await s.data.policyPropose({ edits: [{ op: "lock-path", path: join(proj, "id_rsa"), level: "no-model" }], sessionKey: "agent-1" });
    assert.equal(again.applied, true, JSON.stringify(again));
  } finally {
    await s.close();
  }
});

test("tour 17 [secrets]: an agent's relaxing request the human made by hand while Mandu was stopped is closed at the next start", async () => {
  const { dir, home, proj, env, conf, file } = setup();
  let s = await start(dir, file);
  const BIND = [{ op: "lock-path", path: env, level: "no-model", bindings: ["api.stripe.com"] }];
  try {
    const asked = await s.data.policyPropose({ edits: BIND, sessionKey: "agent-1" });
    assert.ok("proposalId" in asked, "a binding waits for the human");
    assert.equal((await approvals(s)).length, 1);
    assert.equal(await released(s, env, "api.stripe.com"), false);
    await s.close();
    // The human writes the same binding into policy.yaml while Mandu is stopped.
    writeFileSync(file, law(env, true));
    s = await start(dir, file);
    assert.deepEqual(await approvals(s), [], "closed at start: the law already says it");
    assert.deepEqual(await rules(s), [{ path: env, bindings: ["api.stripe.com"] }], "Rules lists it, in force");
    assert.equal(await released(s, env, "api.stripe.com"), true, "the human's own edit releases it");
    assert.equal(await released(s, env, "paste.example"), false, "and only there");
    const w = await why(join(dir, "a.sock"), [".env"], home, proj);
    assert.doesNotMatch(w, /waiting/);
    // The agent's same request no longer waits, and its lock applies.
    const again = await s.data.policyPropose({ edits: BIND, sessionKey: "agent-1" });
    assert.equal(again.applied, true, JSON.stringify(again));
    assert.ok(!("duplicate" in again));
    const lock = await s.data.policyPropose({ edits: [{ op: "lock-path", path: conf, level: "no-model" }], sessionKey: "agent-1" });
    assert.equal(lock.applied, true, JSON.stringify(lock));
  } finally {
    await s.close();
  }
});
