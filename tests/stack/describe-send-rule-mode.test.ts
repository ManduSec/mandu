/**
 * describe-send-rule-mode.test — Rules › Describe what you want, in the
 * Secrets mode, says before Apply that a suggested rule for a host decides
 * nothing, across the REAL components (dashboard.md *Describe what you
 * want*, *A suggested send rule says when the mode leaves it nothing to
 * decide*). Mandu-new.
 *
 * Since 2026-10-30 a saved send rule says so under Your rules (§4.25e, #224,
 * `rules-send-rule-mode.test.ts`). Describe's box invites one ("Never send
 * anything to paste sites."), and its card offered the rule without a word:
 * the line was read only after Apply. Here a real ArbiterServer runs at the
 * `secrets` axes (confidentiality ON, integrity OFF) with a file-backed
 * policy.yaml; the dashboard reaches it through the PRODUCTION adapter
 * (`makeApprovalsArbiter`) and serves the Rules page (its own index.html and
 * home.js in jsdom, signed in). Only the helper model is faked; its answer
 * goes through the real preview and apply:
 *
 *   B1  the fake helper answers a `release` block edit for `paste.example`:
 *       the served card's row carries the line, word for word Your rules',
 *       and Try it is still there;
 *   B2  Apply: policy.yaml has the rule, and Your rules shows #224's line
 *       on its new row, so the line before Apply is the line after it;
 *   B3  the oracle that makes the words true: a registered secret's symbol
 *       bound for `paste.example` is decided by the secret path
 *       (`egress:secret-*`), never `egress:user-rule-block`;
 *   B4  no raw secret in the helper's input, a drawn page or an answer.
 *
 * The other modes (the integrity axis on, the axes unread, off) are the
 * unit test's (`home-js-describe.test.ts`): integrity is frozen, so no new
 * integrity stack run is added here.
 *
 * Axes: secrets (stated).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { AssistantChannel, AssistantModel } from "../../dashboard/src/policy-assistant.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const KEY_VALUE = "sk_" + "live_describeSendRuleModeStackCanary01";
const SESSION = "1791210000-264";
const HOST = "paste.example";
const IDLE_WORDS = "Decides nothing in the Secrets mode: a rule for a host never covers your secrets, and this mode masks only secrets.";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

test("Describe over the real arbiter: in the Secrets mode a suggested block rule for a host says it decides nothing before Apply, Your rules says the same after, and the gate decides a secret to that host by the secret path (secrets axes, explicit)", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-describe-send-rule-mode-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "app"), { recursive: true });
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, "version: 1\n");
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

  // The helper model: records what it was shown, answers one block rule.
  const seen: string[] = [];
  const model = async (): Promise<AssistantModel> => ({
    async complete(call) {
      seen.push(call.system + "\n" + call.user);
      return { text: JSON.stringify({ edits: [{ op: "release", to: { host: HOST }, mode: "block" }] }), model: "fake-assistant" };
    },
  });
  const assistantChannel = async (): Promise<AssistantChannel> => ({ ready: true, via: "claude" });
  // No config.toml under MANDU_HOME: the saved axes are the built-in
  // default, the Secrets mode, as the arbiter above runs.
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    assistantModel: model, assistantChannel, fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home"), MANDU_POLICY_FILE: policyPath, HOME: home },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const noValue = (body: string, where: string) =>
    assert.ok(!body.includes(KEY_VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the registered value`);
  try {
    // A registered secret exists before the helper is asked: the helper's
    // summary of the rules must not carry its value (B4).
    const env = join(home, "app", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);

    const ruleRow = (doc: Doc): Doc => [...doc.querySelectorAll("#rules-list .row.rule")].find((x: Doc) => x.querySelector(".rule-text")?.title === HOST);
    await servedProductPage(base, "/rules", (doc: Doc) => !!doc.querySelector("#describe-form") && !doc.getElementById("page-rules").hidden, async (doc: Doc) => {
      const host = doc.getElementById("describe-result");
      // ── B1: the suggestion, before Apply ──
      await waitWhile(() => !doc.getElementById("rules-list"));
      doc.getElementById("describe-text").value = "Never send anything to paste sites.";
      doc.getElementById("describe-form").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
      await waitWhile(() => !host.querySelector(".suggestion"));
      const rows = [...host.querySelectorAll(".suggestion-rows li")];
      assert.equal(rows.length, 1, `one suggested row: ${host.textContent}`);
      assert.ok(rows[0].textContent.includes(HOST), `the row names the host: ${rows[0].textContent}`);
      const line = rows[0].querySelector(".rule-mode-note");
      assert.equal(line?.textContent, IDLE_WORDS, "the suggested row says it decides nothing in this mode");
      assert.ok(line.classList.contains("dim"), "a muted line");
      assert.ok(rows[0].querySelector(".try-row"), "Try it is still drawn");
      assert.equal(host.querySelectorAll(".rule-mode-note").length, 1, "the line is on the row only");
      noValue(doc.body.textContent ?? "", "the Rules page with the suggestion");

      // ── B2: Apply, then Your rules says the same ──
      const typed = host.querySelector(".proposal-confirm");
      if (typed) {
        typed.value = "ALLOW";
        typed.dispatchEvent(new doc.defaultView.Event("input"));
      }
      const apply = [...host.querySelectorAll("button")].find((b: Doc) => b.textContent === "Apply");
      assert.ok(apply && !apply.disabled, "Apply can be pressed");
      apply.click();
      await waitWhile(() => !host.querySelector(".describe-done, .ask-error"));
      assert.ok(host.querySelector(".describe-done"), `applied: ${host.textContent}`);
      await waitWhile(() => !ruleRow(doc) || !ruleRow(doc).querySelector(".rule-mode-note"));
      assert.equal(ruleRow(doc).querySelector(".rule-mode-note").textContent, line.textContent, "the line before Apply is the line after it");
      noValue(doc.body.textContent ?? "", "the Rules page after Apply");
    }, { headers: { Cookie: ADMIN_COOKIE, "X-Mandu-Control": "1" } });
    const onDisk = readFileSync(policyPath, "utf8");
    assert.match(onDisk, /kind: release/, `the rule is written:\n${onDisk}`);
    assert.ok(onDisk.includes(HOST), `for the host:\n${onDisk}`);

    // ── B3: the gate never asks the host rule about a secret ──
    const d = await gate.desymbolizationDecision({ symbol: keySym!, boundary: "network", destination: HOST, sessionKey: SESSION, scheme: "https" });
    const id = d.ruleRef?.id ?? "";
    assert.match(id, /^egress:secret-/, `a secret to ${HOST} is decided by the secret path: ${JSON.stringify(d)}`);
    assert.notEqual(id, "egress:user-rule-block", "the block rule is not consulted for a secret");
    noValue(JSON.stringify(d), "the decision");

    // ── B4: the helper, and the routes the page reads ──
    assert.ok(seen.length >= 1, "the helper was asked");
    for (const s of seen) noValue(s, "the helper's input");
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
