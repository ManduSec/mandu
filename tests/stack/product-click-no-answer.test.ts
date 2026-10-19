/**
 * product-click-no-answer.test — a click on the product page that gets no
 * answer says so where it was made, across the REAL components (dashboard.md
 * §4.25 *A click with no answer says so*). Mandu-new.
 *
 * Until 2026-10-10 the page's POST helper threw when no answer came. A
 * rule's effect menu and Remove, and Settings › Protection's switch, had no
 * catch: with the dashboard server gone the row stayed disabled over an
 * unhandled rejection and nothing was said. A Home card's answer caught it
 * and said "could not reach the server". Here a real ArbiterServer runs at
 * the `secrets` axes with a policy.yaml send rule, a registered key and a
 * send of it waiting for an answer; a real DashboardServer reaches it over
 * the production adapter (`makeApprovalsArbiter`). Three tabs of the served
 * product page (its own index.html and home.js in jsdom, signed in) are open
 * on Rules, Settings and Home when the dashboard server stops:
 *
 *   N1  running: Rules lists the send rule, Settings' switch is on, Home
 *       shows the waiting question;
 *   N2  the dashboard stops: on Rules the rule's effect menu and its Remove
 *       each say "The dashboard could not reach its own server. Refresh in a
 *       moment." on the row and leave no control disabled; on Settings the
 *       switch says it in its note and stays on; on Home the card's Block
 *       says it on the card and gives its buttons back;
 *   N3  no unhandled rejection in any tab, never the old words nor the
 *       browser's; the oracle: no rendered tab carries the registered key
 *       or a token.
 */
import { test, after } from "node:test";
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
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const KEY = "ghp_productClickNoAnswerStackCanary000001";
const GONE = "The dashboard could not reach its own server. Refresh in a moment.";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const text = (doc: any, sel: string): string => doc.querySelector(sel)?.textContent ?? "";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const button = (node: any, label: string) => ([...node.querySelectorAll("button")] as any[]).find((b) => b.textContent === label);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const disabled = (node: any): string[] => ([...node.querySelectorAll("button, select")] as any[]).filter((b) => b.disabled).map((b) => b.textContent || b.className);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const ruleRow = (doc: any) => ([...doc.querySelectorAll("#rules-list .row.rule")] as any[]).find((r) => /api\.example\.com/.test(r.textContent));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const errors = (node: any): string[] => [...node.querySelectorAll(".ask-error")].map((e: any) => e.textContent);

test("a click with no answer says so where it was made: Rules, Settings and Home with the dashboard gone (real arbiter, production adapter, dashboard, served tabs)", { timeout: 240_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-click-no-answer-"));
  const home = join(tmp, "home");
  mkdirSync(home, { recursive: true });
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, [
    "version: 1",
    "user_rules:",
    "  - { id: r-0001, kind: release, to: { host: api.example.com }, mode: allow }",
    "",
  ].join("\n"));
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    confidentiality: true, integrity: false, log: () => {}, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const data = new ArbiterClient(socketPath);
  await data.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home"), MANDU_POLICY_FILE: policyPath },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  let dashboardOpen = true;
  const unhandled: string[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", onUnhandled);
  const rendered: string[] = [];
  const signedIn = { headers: { Cookie: ADMIN_COOKIE } };
  try {
    // A registered key and a send of it waiting for an answer: Home has a
    // card to answer, and the oracle a value no tab may show.
    const reg = await data.registerEnvSecrets({ vars: [{ name: "GITHUB_TOKEN", value: KEY }] });
    const sym = reg.vars[0]?.symbol;
    assert.match(String(sym), /^\$MDU:nomodel_Env\[/, "the key has its placeholder");
    const ask = await data.desymbolizationDecision({ symbol: sym!, boundary: "network", destination: "gist.github.com", scheme: "https" });
    assert.equal((ask as { requiresApproval?: boolean }).requiresApproval, true, `the send waits for an answer: ${JSON.stringify(ask)}`);

    // N1: three tabs, each drawn while the dashboard answers.
    await servedProductPage(base, "/rules", (doc) => !!ruleRow(doc), async (rules) => {
      await servedProductPage(base, "/settings", (doc) => text(doc, "#settings-protect-row .name") === "On", async (settings) => {
        await servedProductPage(base, "/", (doc) => !!doc.querySelector("#home-waiting .ask"), async (homeTab) => {
          assert.ok(ruleRow(rules), "Rules lists the send rule");
          assert.equal(settings.getElementById("switch-protection").getAttribute("aria-checked"), "true");
          const card = homeTab.querySelector("#home-waiting .ask");
          assert.ok(button(card, "Block"), `the card offers Block: ${card.textContent}`);

          // N2: the dashboard server stops under the three tabs.
          await dashboard.close();
          dashboardOpen = false;

          // Rules: the rule's effect menu, then its Remove.
          const menu = ruleRow(rules).querySelector("select.effect-select");
          menu.value = "flip";
          menu.dispatchEvent(new rules.defaultView.Event("change", { bubbles: true }));
          await waitWhile(() => !errors(ruleRow(rules)).length);
          assert.deepEqual(errors(ruleRow(rules)), [GONE]);
          assert.equal(menu.disabled, false, "the menu works again");
          ruleRow(rules).querySelector(".file-more").click();
          const more = ruleRow(rules).nextElementSibling;
          assert.deepEqual(errors(more), []);
          button(more, "Remove").click();
          await waitWhile(() => !errors(more).length);
          assert.deepEqual(errors(more), [GONE], "Remove says it under the rule");
          assert.deepEqual(disabled(rules.getElementById("rules-list")), [], "no control is left disabled");
          assert.equal(rules.getElementById("rules-notice").hidden, true, "nothing claims it changed");
          rendered.push(rules.body.textContent ?? "");

          // Settings: the switch.
          settings.defaultView.prompt = () => "OFF";
          settings.getElementById("switch-protection").click();
          await waitWhile(() => text(settings, "#settings-protect-note") !== GONE);
          assert.equal(text(settings, "#settings-protect-note"), GONE);
          assert.equal(settings.getElementById("switch-protection").getAttribute("aria-checked"), "true", "nothing changed");
          rendered.push(settings.body.textContent ?? "");

          // Home: the card's Block.
          button(card, "Block").click();
          await waitWhile(() => !errors(card).length);
          assert.deepEqual(errors(card), [GONE]);
          assert.deepEqual(disabled(card), [], "the card's buttons work again");
          rendered.push(homeTab.body.textContent ?? "");
        }, signedIn);
      }, signedIn);
    }, signedIn);
    await new Promise((r) => setTimeout(r, 50));

    // N3: no unhandled rejection, never the old or the browser's words, and
    // the oracle on every tab drawn above.
    assert.deepEqual(unhandled, [], "no unhandled rejection in any tab");
    assert.equal(rendered.length, 3);
    for (const page of rendered) {
      assert.doesNotMatch(page, /could not reach the server|fetch failed|Failed to fetch/);
      assert.ok(!page.includes(KEY), "no rendered tab carries the registered key");
      assert.doesNotMatch(page, /\$MDU/, "nor a token");
    }
  } finally {
    process.off("unhandledRejection", onUnhandled);
    data.close();
    if (dashboardOpen) await dashboard.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
