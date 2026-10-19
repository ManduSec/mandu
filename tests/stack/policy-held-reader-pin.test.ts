/**
 * policy-held-reader-pin e2e — first-session tour item 17, what !1095 and
 * !1174 left: the writes of policy.yaml from outside the policy surface
 * (the arbiter's reader pin, the Rules page's move of its older rules into
 * the file) dropped the person's comments, and a reader pin made while a
 * relaxing hand edit waited in Approvals wrote the law over the file: the
 * hand edit was gone from it and its card superseded.
 *
 * Across the real components: a REAL ArbiterServer (file-backed law, the
 * hand-edit poll running), the guard's own channel (the human socket, plan
 * 13 D9) for the open that pins a reader, and the dashboard's HTTP routes
 * over the production wiring (`makeApprovalsArbiter`, a real
 * DashboardServer: Approvals, the Rules page's move):
 *
 *   1. a hand edit that binds the billing key to a host is held; the card
 *      is on Approvals;
 *   2. the backup job (a listed reader) opens the database password: raw,
 *      and its pin is the law at once; the file keeps the hand edit, with
 *      the pin and EVERY comment of the person's file; one card, filed again
 *      for the new bytes;
 *   3. the Rules page moves its older rule into policy.yaml (200): in force;
 *      the file keeps the hand edit and every comment; one card;
 *   4. approving the card makes the hand edit the law, the pin and the
 *      moved rule with it, the file untouched;
 *   5. THE INVARIANT (fail-closed): the billing key is never released to the
 *      host the held edit binds it to until the human approves it, after the
 *      pin, after the move; then only there. No secret value in the
 *      dashboard's answers or policy.yaml.
 *
 * Secrets axes (confidentiality ON, integrity OFF), stated below.
 * policy-surface.md §2.1, §8.4.6.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import type { PolicyFileConfig } from "../../arbiter/policy/load-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import type { EventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { randomSecretBody } from "../../arbiter/test/helpers/random-secret.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the server pins them below

// Assembled at run time: no key-shaped literal in this file.
const BILLING_BODY = randomSecretBody(32);
const DB_BODY = randomSecretBody(24);
const RUNS = [BILLING_BODY, DB_BODY].flatMap((b) => Array.from({ length: b.length - 7 }, (_, i) => b.slice(i, i + 8)));

function noValue(what: string, s: string): void {
  const hit = RUNS.find((r) => s.includes(r));
  assert.equal(hit, undefined, `${what} carries an 8-character run of a secret's body`);
}

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

async function waitFor<T>(what: string, probe: () => Promise<T | undefined>): Promise<T> {
  for (let i = 0; i < 250; i++) {
    const v = await probe();
    if (v !== undefined) return v;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error(`timed out waiting for ${what}`);
}

/** No recorded sessions: the routes this test calls read none. */
const noSessions: EventSource = {
  async listSessions() { return []; },
  async readEvents() { return []; },
  subscribe() { return () => {}; },
  close() {},
};

/** The person's own file: every comment here must survive the arbiter's writes. */
const COMMENTS = [
  "# Team policy. Ask Dana before you loosen anything.",
  "  # the database password",
  "# the backup job",
  "  # the billing key",
  "# prod",
];
function law(pgpass: string, billing: string): string {
  return [
    COMMENTS[0],
    "version: 1",
    "",
    "paths:",
    COMMENTS[1],
    `  - path: ${pgpass}`,
    "    level: no-model",
    `    readers: [ssh-add]   ${COMMENTS[2]}`,
    COMMENTS[3],
    `  - path: ${billing}   ${COMMENTS[4]}`,
    "    level: no-model",
    "",
  ].join("\n");
}
const SHA = "c".repeat(64);

test("tour 17 after !1095 [secrets]: a reader pin and the Rules page's move while a hand edit waits: layered, every comment kept, nothing released before the human says so", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-t17c-"));
  dirs.push(dir);
  const home = join(dir, "home");
  mkdirSync(join(home, "billing"), { recursive: true });
  mkdirSync(join(home, "notes"), { recursive: true });
  const pgpass = join(home, ".pgpass");
  const billing = join(home, "billing", ".env");
  const notes = join(home, "notes", "id_rsa");
  writeFileSync(pgpass, `db:5432:prod:app:${DB_BODY}\n`);
  writeFileSync(billing, `STRIPE_KEY=sk_live_${BILLING_BODY}\n`);
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, law(pgpass, billing));

  const dataSock = join(dir, "a.sock");
  const adminSock = join(dir, "admin.sock");
  const humanSock = join(dir, "human", "h.sock");
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath: policy, policyPollMs: 30, confidentiality: true, integrity: false, log: () => {},
  });
  await arbiter.listen();
  const clients: ArbiterClient[] = [];
  const connect = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const data = await connect(dataSock);
  const guard = await connect(humanSock);
  const admin = await connect(adminSock);
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc?.resolvePolicyProposal && wired.policyDoc.movePageLabels, "the dashboard's wiring forwards the verdict and the move");
  const dash = new DashboardServer({ source: noSessions, policyDocArbiter: wired.policyDoc, fileBrowserHome: home, log: () => {}, ...ADMIN_OPTS });
  const base = `http://127.0.0.1:${await dash.listen(0)}`;
  const bodies: string[] = [];
  const call = async (method: "GET" | "POST", path: string, body?: unknown) => {
    const r = await fetch(base + path, { method, headers: { ...CSRF_ADMIN, ...(body !== undefined ? { "Content-Type": "application/json" } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    const text = await r.text();
    bodies.push(text);
    return { status: r.status, body: JSON.parse(text) as any };
  };
  const cards = async () => (await call("GET", "/api/policy/proposals?status=pending")).body.proposals as Array<{ id: string; onDisk?: boolean }>;
  const released = async (host: string): Promise<boolean> =>
    (await data.testFlow({ source: { tool: "Read", origin: billing }, destination: host })).egress?.decision.allow === true;
  const inForce = async (): Promise<PolicyFileConfig> => (await data.policyDocument()).inForce as PolicyFileConfig;
  const pinned = (doc: PolicyFileConfig): boolean =>
    ((doc.paths ?? []).find((p) => p.path === pgpass)?.readers ?? []).some((x) => typeof x === "object" && (x as { path?: string }).path === "/usr/bin/ssh-add" && (x as { sha256?: string }).sha256 === SHA);
  const keepsAll = (text: string): void => {
    for (const c of [...COMMENTS, "# billing goes to Stripe"]) assert.ok(text.includes(c), `the file keeps "${c}":\n${text}`);
  };

  try {
    // 0. A rule made on the Rules page before rules lived in policy.yaml (a mandu.db row).
    await admin.setPathLabel({ path: notes, confidentiality: "no-model", recursive: false });

    // 1. The hand edit binds the billing key to Stripe: a relaxation, held.
    const hand = readFileSync(policy, "utf8").replace(
      `  - path: ${billing}   # prod\n    level: no-model\n`,
      `  - path: ${billing}   # prod\n    level: no-model\n    bindings: [api.stripe.com]   # billing goes to Stripe\n`,
    );
    assert.notEqual(hand, readFileSync(policy, "utf8"));
    writeFileSync(policy, hand);
    const [card] = await waitFor("the held card", async () => {
      const c = await cards();
      return c.length ? c : undefined;
    });
    assert.equal(card!.onDisk, true);
    assert.equal(await released("api.stripe.com"), false, "held: the binding is not the law");

    // 2. The backup job opens the database password: raw, and its reader pinned.
    const open = await guard.decideSecretOpen({ path: pgpass, exe: "/usr/bin/ssh-add", sha256: SHA, isAgent: false, exeSystem: true, openerEnv: [], procKey: "backup-1" });
    assert.equal(open.verdict, "raw", JSON.stringify(open));
    assert.equal(open.pinNeeded, true);
    assert.ok(pinned(await inForce()), "the pin is the law at once");
    assert.equal(await released("api.stripe.com"), false, "the pin released nothing the hand edit asks for");
    let text = readFileSync(policy, "utf8");
    keepsAll(text);
    assert.match(text, new RegExp(`path: /usr/bin/ssh-add\\n\\s+sha256: ${SHA}`), "the file has the pin");
    assert.match(text, /bindings: \[api\.stripe\.com\]   # billing goes to Stripe/, "and the hand edit, as written");
    let now = await cards();
    assert.equal(now.length, 1, "one card");
    assert.notEqual(now[0]!.id, card!.id, "filed again for the file's new bytes");

    // 3. The Rules page moves its older rule into policy.yaml.
    const moved = await call("POST", "/api/files/move-page-rules");
    assert.equal(moved.status, 200, JSON.stringify(moved.body));
    assert.equal(moved.body.moved, 1);
    assert.ok((await inForce()).paths!.some((p) => p.path === notes), "the moved rule is the law");
    assert.equal(await released("api.stripe.com"), false, "the move released nothing");
    text = readFileSync(policy, "utf8");
    keepsAll(text);
    assert.match(text, /notes\/id_rsa/, "the file has the moved rule");
    assert.match(text, /bindings: \[api\.stripe\.com\]/, "and the hand edit");
    now = await cards();
    assert.equal(now.length, 1, "one card");

    // 4. The human approves the hand edit: the law, the file untouched.
    const before = readFileSync(policy, "utf8");
    const ok = await call("POST", `/api/policy/proposals/${encodeURIComponent(now[0]!.id)}`, { verdict: "approved" });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    assert.equal(await released("api.stripe.com"), true, "approved: released to Stripe");
    assert.equal(await released("paste.example"), false, "and only there");
    const doc = await inForce();
    assert.ok(pinned(doc), "the pin stays");
    assert.ok(doc.paths!.some((p) => p.path === notes), "the moved rule stays");
    assert.equal(readFileSync(policy, "utf8"), before, "the approval wrote nothing over the person's file");
    assert.deepEqual(await cards(), []);

    // 5. The oracle.
    noValue("the dashboard's answers", bodies.join("\n"));
    noValue("policy.yaml", readFileSync(policy, "utf8"));
  } finally {
    await dash.close();
    for (const c of clients) c.close();
    await arbiter.close();
  }
});
