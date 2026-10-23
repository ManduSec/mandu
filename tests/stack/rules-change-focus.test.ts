/**
 * rules-change-focus.test — on the product page's Rules, a change made in
 * Your rules keeps the keyboard focus, across the REAL components
 * (dashboard.md §4.25 *A change in Your rules keeps the focus*). Mandu-new.
 *
 * Until 2026-10-11 a change in a sending rule's menu, in an answer's menu,
 * Remove under an opened rule and the notice's Undo each left the focus on
 * <body>: the row's menu or button goes off while the change is on its way,
 * and the list is drawn again after it.
 *
 * Here a real ArbiterServer (secrets) holds a policy.yaml with two sending
 * rules (api.example.com allowed, b.example blocked) and a registered key
 * whose send to paste.example the person answered "always block". A real
 * DashboardServer over the production adapter (`makeApprovalsArbiter`)
 * serves the Rules page (its own index.html and home.js in jsdom):
 *
 *   F1  signed in, Always blocked in api.example.com's menu gives the focus
 *       back to that row's menu, drawn again with the new effect, and the
 *       arbiter's panel has the rule blocking;
 *   F2  the notice's Undo gives the focus to the Your rules heading, and the
 *       rule allows again;
 *   F3  Remove under b.example's opened row gives the focus to the heading,
 *       never another row's control, and the rule is gone;
 *   F4  Always allowed in the answer's menu gives the focus back to that
 *       answer's menu, and the arbiter now lets that send go;
 *   F5  signed out, a refused change gives the focus back to the menu,
 *       described by "Sign in first…", and nothing changed;
 *   F6  the oracle: neither the rendered pages nor the answers read here
 *       carry the registered key.
 *
 * jsdom keeps the focus of a control turned off, so `pick` and `press` drop
 * it to <body> after the change, as Chromium does. Axes: secrets (stated).
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
import type { PolicyPanelVM } from "../../dashboard/src/view-model/policy-panel.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { controlName } from "../../dashboard/test/unit/ui/control-names.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const KEY = "sk_" + "live_rulesChangeFocusStackCanary000000001";
const SESSION = "1791400000-153";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
/** The browser drops the focus of a control the change turned off to
 *  <body>; jsdom does not, so it is blurred while on for a moment. */
function drop(x: Doc): void {
  assert.equal(x.disabled, true, "the change turns its control off while it is on its way");
  x.disabled = false;
  x.blur();
  x.disabled = true;
  assert.equal(x.ownerDocument.activeElement, x.ownerDocument.body);
}
/** Enter on a button. */
function press(btn: Doc): void {
  btn.focus();
  btn.click();
  drop(btn);
}
/** A pick in a row's menu with the keyboard: the effect it can turn into. */
function pick(sel: Doc): void {
  sel.focus();
  sel.value = "flip";
  sel.dispatchEvent(new sel.ownerDocument.defaultView.Event("change", { bubbles: true }));
  drop(sel);
}
const rowOf = (doc: Doc, key: string) => [...doc.querySelectorAll("#rules-list .row.rule")].find((r: Doc) => r.dataset.rule === key);
const menuOf = (doc: Doc, key: string) => rowOf(doc, key)?.querySelector("select.effect-select");
const effects = (sel: Doc) => [...sel.options].map((o: Doc) => o.textContent);

test("Rules over the real arbiter: a rule's menu, an answer's menu, Remove and Undo keep the focus; a refusal gives it back described; no key on the page", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rules-change-focus-"));
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, [
    "version: 1",
    "user_rules:",
    "  - { id: r-0001, kind: release, to: { host: api.example.com }, mode: allow }",
    "  - { id: r-0002, kind: release, to: { host: b.example }, mode: block }",
    "",
  ].join("\n"));
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {},
  });
  await arbiter.listen();
  const data = new ArbiterClient(socketPath);
  await data.connect();
  const admin = new ArbiterClient(adminSock);
  await admin.connect();
  const guard = new ArbiterClient(humanPath);
  await guard.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc,
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const bodies: string[] = [];
  const read = async (path: string) => {
    const text = await (await pageFetch(base + path, { headers: CSRF_ADMIN })).text();
    bodies.push(text);
    return JSON.parse(text);
  };
  const rule = async (id: string) => {
    const panel = (await read("/api/policy/panel")).panel as PolicyPanelVM;
    assert.ok(panel.yourRules, "the panel lists your rules");
    return panel.yourRules.find((r) => r.id === id);
  };
  const pages: string[] = [];
  try {
    // A registered key, and the person's standing answer about sending it
    // to paste.example: always block.
    mkdirSync(join(tmp, "proj"));
    const env = join(tmp, "proj", ".env");
    writeFileSync(env, `PASTE_KEY=${KEY}\n`);
    const reg = await data.registerSecret({ path: env, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.PASTE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    const send = () => guard.desymbolizationDecision({ symbol: keySym!, boundary: "network", destination: "paste.example", sessionKey: SESSION, scheme: "https" });
    const asked = await send();
    assert.equal(asked.allow, false);
    const answerId = String((asked as { approvalId?: string }).approvalId);
    await admin.resolveEgressApproval(answerId, false);
    assert.equal((await send()).allow, false, "the answer blocks the send");
    const ANSWER = `answer:${answerId}`;

    const ready = (doc: Doc) => !!menuOf(doc, "r-0001") && !!menuOf(doc, "r-0002") && !!menuOf(doc, ANSWER);
    await servedProductPage(base, "/rules", ready, async (doc) => {
      doc.defaultView.confirm = () => true;
      assert.equal(controlName(menuOf(doc, "r-0001")), "What happens for api.example.com");

      // F1: a rule's menu.
      const old = menuOf(doc, "r-0001");
      const before = effects(old);
      pick(old);
      await waitWhile(() => menuOf(doc, "r-0001") === old);
      const now = menuOf(doc, "r-0001");
      assert.notDeepEqual(effects(now), before, "the row says the new effect");
      assert.equal(doc.activeElement, now, "the same row's menu, drawn again");
      assert.equal(doc.getElementById("rules-notice").firstChild.textContent, "Now always blocked.");
      assert.equal((await rule("r-0001"))?.kind, "release-block", "the arbiter's panel has the rule blocking");

      // F2: the notice's Undo.
      const undo = [...doc.querySelectorAll("#rules-notice button")].find((b: Doc) => b.textContent === "Undo");
      press(undo);
      await waitWhile(() => menuOf(doc, "r-0001") === now);
      assert.equal(doc.getElementById("rules-notice").textContent, "Undone.");
      assert.equal(doc.activeElement, doc.getElementById("rules-title"), "the Your rules heading");
      assert.deepEqual(effects(menuOf(doc, "r-0001")), before, "the rule as it was");
      assert.equal((await rule("r-0001"))?.kind, "release-allow");

      // F3: Remove under an opened rule.
      rowOf(doc, "r-0002").querySelector(".file-more").click();
      const remove = [...rowOf(doc, "r-0002").nextElementSibling.querySelectorAll("button")].find((b: Doc) => b.textContent === "Remove");
      press(remove);
      await waitWhile(() => rowOf(doc, "r-0002") !== undefined);
      assert.equal(doc.activeElement, doc.getElementById("rules-title"), "the heading, never another row's control");
      assert.equal(doc.getElementById("rules-notice").firstChild.textContent, "Rule removed.");
      assert.equal(await rule("r-0002"), undefined, "the rule is gone");

      // F4: an answer's menu.
      const answerMenu = menuOf(doc, ANSWER);
      pick(answerMenu);
      await waitWhile(() => menuOf(doc, ANSWER) === answerMenu);
      assert.equal(doc.activeElement, menuOf(doc, ANSWER), "the same answer's menu, drawn again");
      assert.equal(doc.getElementById("rules-notice").firstChild.textContent, "Now always allowed.");
      assert.equal((await send()).allow, true, "the arbiter now lets that send go");
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // F5: signed out, a refusal.
    const before = readFileSync(policyPath, "utf8");
    await servedProductPage(base, "/rules", (doc) => !!menuOf(doc, "r-0001"), async (doc) => {
      const sel = menuOf(doc, "r-0001");
      pick(sel);
      await waitWhile(() => !rowOf(doc, "r-0001").querySelector(".ask-error"));
      const words = rowOf(doc, "r-0001").querySelector(".ask-error");
      assert.match(words.textContent, /^Sign in first/);
      assert.equal(doc.activeElement, sel, "the menu, on again");
      assert.equal(sel.disabled, false);
      assert.equal(sel.getAttribute("aria-describedby"), words.id, "described by the refusal's words");
      pages.push(doc.body.textContent ?? "");
    });
    assert.equal(readFileSync(policyPath, "utf8"), before, "nothing changed signed out");

    // F6: the oracle.
    for (const path of ["/api/policy/panel", "/api/home"]) await read(path);
    for (const text of [...pages, ...bodies]) assert.ok(!text.includes(KEY), "no page or answer carries the registered key");
  } finally {
    await dashboard.close();
    wired.close();
    guard.close();
    admin.close();
    data.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
