/**
 * rules-send-rule-mode.test — on the Rules page, in the Secrets mode, a
 * host's send rule says it decides nothing, across the REAL components
 * (dashboard.md §4.25e *A send rule says when the mode leaves it nothing to
 * decide*). Mandu-new.
 *
 * Until 2026-10-30 a `user_rules` entry of kind `release` read
 * "`paste.example` · sending any masked data · Always blocked" with a red
 * dot in every mode, while the egress gate asks a rule for a host only
 * about data that is not a secret (`arbiter/ipc/server.ts`, the user-rule
 * branch; `user-rules-gate.test.ts`), and the Secrets mode masks only
 * secrets. A person read "Always blocked" as Mandu stopping data going
 * there.
 *
 * Here a real ArbiterServer (secrets: confidentiality ON, integrity OFF)
 * holds a policy.yaml with `user_rules: [{ kind: release, to: { host:
 * paste.example }, mode: block }]` and a registered `.env`. A real
 * DashboardServer over the production adapter (`makeApprovalsArbiter`)
 * serves the Rules page:
 *
 *   M1  the oracle that makes the line true: the key's symbol bound for
 *       `paste.example` is decided by the secret path (`egress:secret-*`),
 *       never `egress:user-rule-block`;
 *   M2  the served Rules page (its own index.html and home.js in jsdom):
 *       the `paste.example` row carries the line under its reach and a grey
 *       dot; its opened row has the line too; the menu still reads Always
 *       blocked;
 *   M3  no raw secret in the panel, `/api/home`, the page or the decision.
 *
 * The other modes (the integrity axis on, the axes unread, off) are the
 * unit test's (`home-js-rules.test.ts`): integrity is frozen, so no new
 * integrity stack run is added here.
 *
 * Axes: secrets (stated).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

const KEY_VALUE = "sk_" + "live_rulesSendRuleModeStackCanary000001";
const SESSION = "1791210000-224";
const HOST = "paste.example";
const IDLE_WORDS = "Decides nothing in the Secrets mode: a rule for a host never covers your secrets, and this mode masks only secrets.";

test("Rules over the real arbiter: in the Secrets mode a host's block rule says it decides nothing, and the gate decides a secret to that host by the secret path (secrets axes, explicit)", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rules-send-rule-mode-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "app"), { recursive: true });
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, [
    "version: 1",
    "user_rules:",
    `  - { id: r-0224, kind: release, to: { host: ${HOST} }, mode: block }`,
    "",
  ].join("\n"));
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {},
    policyPath, policyPollMs: 0, adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const gate = new ArbiterClient(socketPath);
  await gate.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  // No config.toml under MANDU_HOME: the saved axes are the built-in
  // default, the Secrets mode, as the arbiter above runs.
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home, configEnv: { MANDU_HOME: join(tmp, "mandu-home"), MANDU_POLICY_FILE: policyPath, HOME: home },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const noValue = (body: string, where: string) =>
    assert.ok(!body.includes(KEY_VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the registered value`);
  try {
    // ── M1: the gate never asks the host rule about a secret ──
    const env = join(home, "app", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    const d = await gate.desymbolizationDecision({ symbol: keySym!, boundary: "network", destination: HOST, sessionKey: SESSION, scheme: "https" });
    const id = d.ruleRef?.id ?? "";
    assert.match(id, /^egress:secret-/, `a secret to ${HOST} is decided by the secret path: ${JSON.stringify(d)}`);
    assert.notEqual(id, "egress:user-rule-block", "the block rule is not consulted for a secret");
    noValue(JSON.stringify(d), "the decision");

    // The arbiter's panel holds the rule as a block rule, as before.
    const r = await pageFetch(`${base}/api/policy/panel`, { headers: CSRF_ADMIN });
    const body = await r.text();
    assert.equal(r.status, 200, body);
    noValue(body, "the panel");
    const rule = (JSON.parse(body) as { panel: { yourRules: Array<{ id: string; kind: string }> } }).panel.yourRules.find((x) => x.id === "r-0224");
    assert.equal(rule?.kind, "release-block", "the rule is kept as it was written");

    // ── M2: the served Rules page ──
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    type Doc = any;
    const ruleRow = (doc: Doc): Doc => [...doc.querySelectorAll("#rules-list .row.rule")].find((x: Doc) => x.querySelector(".rule-text")?.title === HOST);
    await servedProductPage(base, "/rules", (doc: Doc) => !!ruleRow(doc) && !!ruleRow(doc).querySelector(".rule-mode-note"), async (doc: Doc) => {
      const row = ruleRow(doc);
      const line = row.querySelector(".rule-mode-note");
      assert.equal(line.textContent, IDLE_WORDS, "the row says it decides nothing in this mode");
      assert.equal(line.previousElementSibling.textContent, "sending any masked data", "under its reach");
      assert.equal(row.querySelector("select").options[0].textContent, "Always blocked", "the menu's words are unchanged");
      assert.equal(row.querySelector(".label-pick").getAttribute("data-effect"), "none", "a grey dot: it decides nothing now");
      row.querySelector(".file-more").click();
      const detail = ruleRow(doc).nextElementSibling;
      assert.ok(detail.classList.contains("rule-detail"), "the row opens");
      assert.equal(detail.querySelector(".rule-mode-note")?.textContent, IDLE_WORDS, "the opened row says it too");
      noValue(doc.body.textContent ?? "", "the Rules page");
    }, { headers: { Cookie: ADMIN_COOKIE, "X-Mandu-Control": "1" } });

    // ── M3: the routes the page reads, signed out ──
    for (const route of ["/api/policy/panel", "/api/home", "/rules"]) {
      const res = await pageFetch(base + route);
      const text = await res.text();
      assert.equal(res.status, 200, `${route}: ${text}`);
      noValue(text, `${route} signed out`);
    }
  } finally {
    await dashboard.close();
    wired?.close();
    gate.close();
    await arbiter.close();
    resetCurrentPolicyForTests();
    rmSync(tmp, { recursive: true, force: true });
  }
});
