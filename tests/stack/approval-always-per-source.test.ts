/**
 * approval-always-per-source.test — a program holding two secret files with
 * different bindings sends to a host neither is bound to; the Approvals card
 * names both, and an *Always* is one per file, each its own human-plane edit
 * of THAT file's rule (confidentiality plan 13 §5.4, §9 R2; dashboard.md
 * §4.34 "A send names every file"). Mandu-new.
 *
 * Production wiring throughout: a real ArbiterServer (`secrets` axes) with a
 * policy.yaml on disk; the net-proxy's own secret-taint verdict over its
 * production adapter (`new ArbiterClientAdapter(data, human)`, the human
 * socket the proxy asks on); a real DashboardServer over the dashboard's
 * production adapter (`makeApprovalsArbiter`: queue and edit reads on the
 * data socket, the rule change on the admin channel).
 *
 *   S1  the refused send files ONE question that names both files, where
 *       each may go, and an Always for each (none "Always allow" for all);
 *   S2  Allow once over the real route lets the next send go, once;
 *   S3  Always on .env alone: the send is still refused, the question still
 *       waits and names customers.csv as left; the same Always again is 409;
 *       a file that is not the question's is refused;
 *   S4  Always on customers.csv: the question is gone and the send goes;
 *   S5  policy.yaml has the host in exactly those two rules, each keeping
 *       its own bindings and readers, and in no other;
 *   S6  no route carries a secret's value.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { ArbiterClientAdapter } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { secretTaintVerdict } from "../../interceptors/net-proxy/src/egress.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON: where a holder's bytes may go

const SESSION = "1791400000-555";
const H = "hooks.slack.com";
const ENV_VALUE = "sk_live_alwaysPerSourceCanary000001";
const CARD_VALUE = "4111111111111111";
/** The programs a reader list names (a bare name, or a pin the arbiter wrote on first use). */
const appsOf = (readers: unknown[] | undefined): string[] => (readers ?? []).map((r) => (typeof r === "string" ? r : String((r as { app?: unknown }).app)));

test("a holder of two secrets: one Always per file, the send goes only when both are answered", { timeout: 90_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-always-per-source-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "ws", "app"), { recursive: true });
  mkdirSync(join(home, "data"), { recursive: true });
  const env = join(home, "ws", "app", ".env");
  const csv = join(home, "data", "customers.csv");
  const other = join(home, "data", "other.key");
  writeFileSync(env, `STRIPE_KEY=${ENV_VALUE}\n`);
  writeFileSync(csv, `name,card\nAda,${CARD_VALUE}\n`);
  writeFileSync(other, "OTHER=alwaysPerSourceOther0000001\n");
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1
paths:
  - { path: "${env}", level: no-model, readers: [ssh-add], bindings: [api.stripe.com, "*.amazonaws.com"] }
  - { path: "${csv}", level: any-model, readers: [ssh-add] }
  - { path: "${other}", level: no-model, bindings: [api.example.com] }
`);
  const dataSock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {},
    policyPath, policyPollMs: 0, confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const guard = await open(humanSock);
  const admin = await open(adminSock);
  // The net-proxy's production adapter: data socket + the human socket it asks on.
  const proxyArbiter = new ArbiterClientAdapter(await open(dataSock), await open(humanSock));
  const send = () => secretTaintVerdict({ arbiter: proxyArbiter, holders: [{ procKey: "py-1", ancestors: [] }], destinationHost: H, sessionKey: SESSION });
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc);
  assert.ok(wired.arbiter.holderSourceBinding, "the production adapter forwards holderSourceBinding");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: dataSock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter,
    policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home") },
    log: () => {},
    ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const homeVm = async (): Promise<HomeVM> => (await (await fetch(`${base}/api/home`)).json()) as HomeVM;
  const post = async (path: string, body?: unknown) => {
    const r = await fetch(base + path, { method: "POST", headers: { ...CSRF_ADMIN, "Content-Type": "application/json" }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: r.status, body: (await r.json()) as Record<string, unknown> };
  };
  try {
    // The program (`ssh-add` is a reader of both) reads both files raw.
    for (const path of [env, csv]) {
      const d = await guard.decideSecretOpen({ path, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "py-1", session: SESSION });
      assert.equal(d.verdict, "raw", `${path}: ${JSON.stringify(d)}`);
    }

    // S1: refused; one question naming both files.
    const first = await send();
    assert.equal(first.action, "block");
    const askId = first.action === "block" ? first.withheld[0]!.approvalId : undefined;
    assert.ok(askId, `the question's id rides on the block: ${JSON.stringify(first)}`);
    assert.equal(((await send()) as { withheld: Array<{ approvalId?: string }> }).withheld[0]!.approvalId, askId, "one question, asked again");
    const card = (await homeVm()).waiting.find((a) => a.id === askId)!;
    assert.ok(card, "the card is served");
    assert.equal(card.family, "send");
    const sentence = card.sentence.map((p) => p.text).join("");
    assert.match(sentence, /program wants to send data from ~\/data\/customers\.csv and ~\/ws\/app\/\.env to hooks\.slack\.com$/);
    assert.deepEqual(card.actions.map((a) => a.label), ["Allow once", "Allow this session", "Block"], "no Always allow for every file at once");
    assert.deepEqual(card.sources!.map((s) => [s.name, s.mayGo, s.blocks, s.always ?? null]).sort(), [
      ["~/data/customers.csv", "may go nowhere", true, `Always: add ${H} to customers.csv`],
      ["~/ws/app/.env", "may go to: api.stripe.com, *.amazonaws.com", true, `Always: add ${H} to .env`],
    ]);

    // S2: Allow once over the real route: the next send goes, the one after asks.
    const once = await post(`/api/egress/approvals/${askId}/approve-once`);
    assert.equal(once.status, 200, JSON.stringify(once.body));
    assert.equal((await send()).action, "allow", "the next send goes");
    assert.equal((await send()).action, "block", "Allow once covered one send");

    // S3: Always on .env alone does not release.
    const one = await post(`/api/egress/approvals/${askId}/always-source`, { path: env });
    assert.equal(one.status, 200, JSON.stringify(one.body));
    assert.equal(one.body.released, false);
    assert.deepEqual(one.body.left, [csv]);
    assert.equal((await send()).action, "block", "one file answered: the send is still refused");
    const after = (await homeVm()).waiting.find((a) => a.id === askId)!;
    assert.ok(after, "the question still waits");
    assert.deepEqual(after.sources!.filter((s) => s.blocks).map((s) => s.name), ["~/data/customers.csv"]);
    assert.equal(after.sourcesLeft, `The send goes once every file may go to ${H}. Still in the way: ~/data/customers.csv.`);
    assert.equal((await post(`/api/egress/approvals/${askId}/always-source`, { path: env })).status, 409, ".env may already go there");
    const notOurs = await post(`/api/egress/approvals/${askId}/always-source`, { path: other });
    assert.equal(notOurs.status, 422, JSON.stringify(notOurs.body));

    // S4: Always on customers.csv: released.
    const two = await post(`/api/egress/approvals/${askId}/always-source`, { path: csv });
    assert.equal(two.status, 200, JSON.stringify(two.body));
    assert.equal(two.body.released, true);
    assert.equal((await homeVm()).waiting.some((a) => a.id === askId), false, "the question is gone");
    assert.equal((await send()).action, "allow", "every file may go there: the send goes by the rules");

    // S5: the rules file: H in exactly those two rules, nothing else changed.
    const yaml = readFileSync(policyPath, "utf8");
    assert.equal(yaml.split(H).length - 1, 2, yaml);
    const parsed = (await admin.policyDocument()).onDisk.parsed as { paths: Array<{ path: string; level: string; bindings?: string[]; readers?: unknown[] }> };
    const byPath = new Map(parsed.paths.map((p) => [p.path, p]));
    assert.deepEqual(byPath.get(env)!.bindings, ["api.stripe.com", "*.amazonaws.com", H]);
    assert.deepEqual(appsOf(byPath.get(env)!.readers), ["ssh-add"], "its reader kept (pinned on first use)");
    assert.equal(byPath.get(env)!.level, "no-model");
    assert.deepEqual(byPath.get(csv)!.bindings, [H]);
    assert.deepEqual(appsOf(byPath.get(csv)!.readers), ["ssh-add"]);
    assert.equal(byPath.get(csv)!.level, "any-model");
    assert.deepEqual(byPath.get(other)!.bindings, ["api.example.com"]);
    // Two changes on record, each the person's, each one rule.
    const changes = (await admin.policyChanges()).changes.slice(0, 2);
    assert.ok(changes.every((c) => c.edits.length === 1), JSON.stringify(changes));

    // S6: no route carries a value.
    const bodies = [await (await fetch(`${base}/api/home`)).text(), await (await fetch(`${base}/api/policy/panel`)).text()];
    for (const b of bodies) {
      assert.ok(!b.includes(ENV_VALUE) && !b.includes(CARD_VALUE), "no secret value is served");
    }
  } finally {
    await dashboard.close();
    for (const c of clients) c.close();
    wired?.close();
    await arbiter.close();
    resetCurrentPolicyForTests("claude-code");
    rmSync(tmp, { recursive: true, force: true });
  }
});
