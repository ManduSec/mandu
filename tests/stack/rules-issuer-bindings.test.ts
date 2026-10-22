/**
 * rules-issuer-bindings — Rules › Built-in protections says which companies'
 * keys go to their own API without asking, as the REAL arbiter has it in
 * force (dashboard.md §4.25z, confidentiality.md §2.3). Mandu-new.
 *
 * A real ArbiterServer reading a policy FILE (`secrets` axes) and a real
 * DashboardServer over the production adapter (`makeApprovalsArbiter`,
 * whose `policyDocument` the home route reads):
 *
 *   I1  `issuer_bindings: { issuers_off: [stripe] }`: /api/home's built-in
 *       item is on but "Off for: Stripe", lists every company with its
 *       hosts, and the served Rules page draws it, folded;
 *   I2  the oracle: neither /api/home nor the drawn page carries the
 *       registered key's value, only names;
 *   I3  `issuer_bindings: false`: the item says every key asks, with no list;
 *   I4  no `issuer_bindings`: on for every company.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { ISSUER_TABLE } from "../../dashboard/src/view-model/issuer-words.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const KEY_VALUE = `sk_live_rulesIssuerCanary${process.pid}0000000000`;
const SENT = "A key whose format names the company that issued it goes to that company's own API without asking.";

/** The stack over a policy.yaml whose `issuer_bindings` is `bindings` (a
 *  YAML line, or none), and `fn` over its served base. */
async function withStack(bindings: string | null, fn: (base: string, homeVm: () => Promise<{ vm: HomeVM; body: string }>) => Promise<void>): Promise<void> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rules-issuer-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const env = join(home, "proj", ".env");
  writeFileSync(env, `STRIPE_SECRET_KEY=${KEY_VALUE}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - { path: "${env}", level: no-model }\n${bindings ? `${bindings}\n` : ""}`);
  const dataSock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {},
    policyPath, policyPollMs: 0, adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production wiring connects");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: dataSock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter,
    policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home"), MANDU_POLICY_FILE: policyPath },
    log: () => {},
    ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const homeVm = async (): Promise<{ vm: HomeVM; body: string }> => {
    const r = await pageFetch(`${base}/api/home`, { headers: { Cookie: ADMIN_COOKIE } });
    const body = await r.text();
    assert.equal(r.status, 200, body);
    return { vm: JSON.parse(body) as HomeVM, body };
  };
  try {
    await fn(base, homeVm);
  } finally {
    await dashboard.close();
    wired?.close();
    await arbiter.close();
    resetCurrentPolicyForTests();
    rmSync(tmp, { recursive: true, force: true });
  }
}

test("Built-in protections names the companies whose keys go without asking, as the arbiter has issuer_bindings in force, and carries no value (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  // I1, I2: Stripe turned off.
  await withStack("issuer_bindings: { issuers_off: [stripe] }", async (base, homeVm) => {
    const { vm, body } = await homeVm();
    assert.equal(vm.protection.level, "secrets");
    const it = vm.builtIn.issuers;
    assert.ok(it, "the item is there in the Secrets mode");
    assert.equal(it.state, "partly");
    assert.equal(it.text, `${SENT} Off for: Stripe.`);
    assert.deepEqual(it.companies.map((c) => c.name), ISSUER_TABLE.map((i) => i.name));
    assert.deepEqual(it.companies.filter((c) => c.off).map((c) => c.name), ["Stripe"]);
    assert.ok(vm.builtIn.items.includes("Keys and secret files leave this computer only where a rule or your OK allows."), "the sentence beside it stays");
    assert.ok(!body.includes(KEY_VALUE), "CONFIDENTIALITY VIOLATION: /api/home carries the key's value");
    assert.doesNotMatch(body, /\$MDU/, "the product's home carries no token");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    type Doc = any;
    await servedProductPage(base, "/rules", (doc: Doc) => doc.querySelector("#builtin-list > li.builtin-issuers") !== null, (doc: Doc) => {
      const li = doc.querySelector("#builtin-list > li.builtin-issuers");
      assert.ok(li, "the Rules page draws the item");
      assert.equal(li.dataset.state, "partly");
      assert.match(li.textContent, /Off for: Stripe\./);
      const fold = li.querySelector("details.more");
      assert.equal(fold.querySelector("summary").textContent, "Which companies");
      const codes = [...fold.querySelectorAll("code")].map((c: Doc) => c.textContent);
      assert.deepEqual(codes, ISSUER_TABLE.flatMap((i) => [...i.hosts]), "every host, as code");
      assert.ok(!doc.body.textContent.includes(KEY_VALUE), "CONFIDENTIALITY VIOLATION: the rendered page carries the key's value");
    }, { headers: { Cookie: ADMIN_COOKIE } });
  });
  // I3: off.
  await withStack("issuer_bindings: false", async (_base, homeVm) => {
    const it = (await homeVm()).vm.builtIn.issuers;
    assert.equal(it?.state, "off");
    assert.equal(it?.text, "Every key asks before it goes to its company's API (issuer_bindings is off in policy.yaml).");
    assert.deepEqual(it?.companies, []);
  });
  // I4: the default.
  await withStack(null, async (_base, homeVm) => {
    const it = (await homeVm()).vm.builtIn.issuers;
    assert.equal(it?.state, "on");
    assert.equal(it?.text, SENT);
    assert.ok(it?.companies.every((c) => !c.off));
  });
});
