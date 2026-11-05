/**
 * always-source-answer-line.test — the last *Always: add <host> to <file>*
 * of a program's send leaves an answer line with Undo, and every earlier
 * file's Always leaves Undo in its card's words, across the REAL
 * components (dashboard.md §4.34 *A send names every file*, §4.25 *An
 * answer says what it did*). Mandu-new.
 *
 * Until 2026-10-25 the last file's Always wrote its words inside the card,
 * the arbiter retired the question, and the next draw of Approvals dropped
 * the card and its words: nothing said the rule changed, nor to tell the
 * agent to try again, and the change id the route returns was thrown away.
 * Here a real ArbiterServer (`secrets` axes) reads a policy.yaml on disk;
 * the net-proxy's own secret-taint verdict runs over its production adapter;
 * a real DashboardServer over the production approvals adapter
 * (`makeApprovalsArbiter`) serves the product page (its own index.html and
 * home.js in jsdom, signed in):
 *
 *   A1  a program that read `.env` and `customers.csv` sends to a host
 *       neither may go to: refused, one question on Approvals with one
 *       Always per file;
 *   A2  Always on the first file: the card stays, says which is left, keeps
 *       the next file's Always, and links the change the arbiter recorded
 *       ("Undo it in Approvals", `/approvals/<pc-…>`); the link opens that
 *       change with its Undo, and Undo takes the host off `.env`'s rule in
 *       policy.yaml; Always on `.env` again (until 2026-10-26 only the
 *       last file's Always had a way back);
 *   A3  Always on the last: the card is gone, one answer line where it
 *       was ("Always allowed: … Tell … to try again. Undo it in
 *       Approvals"), a status with the focus, its link `/approvals/<pc-…>`,
 *       the change the arbiter recorded; the send goes;
 *   A4  the link opens Approvals with that Rule changes row marked and its
 *       Undo; Undo puts the file's rule back, and the next send is refused
 *       again;
 *   A5  the oracle: no page drawn nor route read carries a file's value.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { ArbiterClientAdapter } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { secretTaintVerdict } from "../../interceptors/net-proxy/src/egress.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON: where a holder's bytes may go

const SESSION = "1791400000-556";
const H = "hooks.slack.com";
const ENV_VALUE = "sk_" + "live_alwaysSourceLineCanary0000001";
const CARD_VALUE = "4111111111111111";

/** Poll `read()` until it gives `want`, for at most 20 s; the caller asserts
 *  afterwards, so a write that never lands still fails there. policy.yaml
 *  is read only once the answer that writes it has landed: on a loaded
 *  host a press can go out on a card drawn from an older poll, and a poll
 *  asked before the Undo then draws the card without its Always before the
 *  press's answer is back (pipelines 13921, 13927, 13929). */
async function settled<T>(read: () => Promise<T>, want: T): Promise<void> {
  for (const end = Date.now() + 20_000; !isDeepStrictEqual(await read(), want) && Date.now() < end;) await new Promise((r) => setTimeout(r, 50));
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const words = (x: Doc): string => String(x.textContent).replace(/\s+/g, " ").trim();
/** Enter on a button: it has the focus, the click answers, and the browser
 *  drops the focus of the button the answer turned off to <body>. */
function press(btn: Doc): void {
  assert.ok(btn, "the button is there");
  btn.focus();
  btn.click();
  btn.disabled = false;
  btn.blur();
  btn.disabled = true;
}

test("the last Always of a program's send leaves a line with Undo it in Approvals; that Undo puts the rule back (real arbiter, net-proxy verdict, dashboard, served page); no secret anywhere", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-always-source-line-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "ws", "app"), { recursive: true });
  mkdirSync(join(home, "data"), { recursive: true });
  const env = join(home, "ws", "app", ".env");
  const csv = join(home, "data", "customers.csv");
  writeFileSync(env, `STRIPE_KEY=${ENV_VALUE}\n`);
  writeFileSync(csv, `name,card\nAda,${CARD_VALUE}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1
paths:
  - { path: "${env}", level: no-model, readers: [ssh-add], bindings: [api.stripe.com] }
  - { path: "${csv}", level: any-model, readers: [ssh-add] }
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
  const signedIn = { Cookie: ADMIN_COOKIE };
  const rendered: [string, string][] = [];
  const unhandled: string[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", onUnhandled);
  try {
    // ── A1: the program reads both files raw; its send is refused ───────────
    for (const path of [env, csv]) {
      const d = await guard.decideSecretOpen({ path, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "py-1", session: SESSION });
      assert.equal(d.verdict, "raw", `${path}: ${JSON.stringify(d)}`);
    }
    const first = await send();
    assert.equal(first.action, "block");
    const askId = first.action === "block" ? first.withheld[0]!.approvalId : undefined;
    assert.ok(askId, `the question's id rides on the block: ${JSON.stringify(first)}`);
    const served = ((await (await pageFetch(`${base}/api/home`, { headers: signedIn })).json()) as HomeVM).waiting.find((a) => a.id === askId);
    assert.ok(served, "the card is served");
    const what = (served.whatParts ?? served.sentence).map((p) => p.text).join("");
    assert.ok(served.afterAllow, "the ask says what is left to do once allowed");

    const cardIn = (doc: Doc) => [...doc.querySelectorAll("#approvals-waiting > .ask")].find((c: Doc) => c.dataset.id === askId) ?? null;
    const always = (doc: Doc, file: string) => [...(cardIn(doc)?.querySelectorAll(".ask-source-always") ?? [])].find((b: Doc) => b.textContent === `Always: add ${H} to ${file}`);
    let changeId = "";
    const bindingsOf = async (path: string) => ((await admin.policyDocument()).onDisk.parsed as { paths: Array<{ path: string; bindings?: string[] }> }).paths.find((p) => p.path === path)!.bindings ?? [];
    await servedProductPage(base, "/approvals", (doc) => !!always(doc, ".env") && !!always(doc, "customers.csv"), async (doc) => {
      // ── A2: the first file; the card stays and names the one left ─────────
      press(always(doc, ".env"));
      await waitWhile(() => !/Still in the way/.test(cardIn(doc)?.textContent ?? ""), 20_000);
      assert.match(words(cardIn(doc)), /Done: ~\/ws\/app\/\.env may go there now\. Still in the way: ~\/data\/customers\.csv\. Undo it in Approvals/);
      assert.equal(doc.querySelector("#approvals-waiting > .answer-line"), null, "no line while a file is left");
      assert.ok(always(doc, "customers.csv"), "the next file's Always stays");
      const envChange = (await admin.policyChanges()).changes[0]!;
      assert.match(envChange.id, /^pc-\d{6}$/);
      const envLink = cardIn(doc).querySelector(".prompt-let-done a");
      assert.equal(envLink.textContent, "Undo it in Approvals");
      assert.equal(envLink.getAttribute("href"), `/approvals/${envChange.id}`, "the change the arbiter recorded for .env");
      const envRules = () => bindingsOf(env);
      await settled(envRules, ["api.stripe.com", H]);
      assert.deepEqual(await envRules(), ["api.stripe.com", H], "policy.yaml: .env may go there");
      rendered.push(["Approvals after the first Always", doc.documentElement.outerHTML]);
      envLink.click();
      const envRow = () => [...doc.querySelectorAll("#approvals-rule-history .row")].find((r: Doc) => r.dataset.id === envChange.id) ?? null;
      await waitWhile(() => !envRow()?.classList.contains("focus"), 20_000);
      assert.equal(doc.defaultView.location.pathname, `/approvals/${envChange.id}`);
      assert.deepEqual([...doc.querySelectorAll("#page-approvals .focus")].map((x: Doc) => x.dataset.id), [envChange.id], "exactly that change is marked");
      const envUndo = [...envRow().querySelectorAll("button")].find((b: Doc) => b.textContent === "Undo");
      assert.ok(envUndo, "Undo on it");
      envUndo.click();
      await settled(envRules, ["api.stripe.com"]);
      assert.deepEqual(await envRules(), ["api.stripe.com"], "policy.yaml: .env's rule loses the host again");
      // .env is in the way again: the next poll (here a return to the tab;
      // the page's timer does not run in jsdom) brings its Always back.
      Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
      doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
      await waitWhile(() => !always(doc, ".env") || always(doc, ".env").disabled, 20_000);
      press(always(doc, ".env"));
      await waitWhile(() => !!always(doc, ".env"), 20_000);
      await settled(envRules, ["api.stripe.com", H]);
      assert.deepEqual(await envRules(), ["api.stripe.com", H]);
      // The page has that press's answer, its words linking the change it
      // made (not the first, undone), before the next press: until it does,
      // the card is busy, and a press on it is dropped.
      await waitWhile(() => !/^\/approvals\/pc-\d{6}$/.test(cardIn(doc)?.querySelector(".prompt-let-done a")?.getAttribute("href") ?? "")
        || cardIn(doc).querySelector(".prompt-let-done a").getAttribute("href") === `/approvals/${envChange.id}`, 20_000);

      // ── A3: the last; the card's place holds the line ─────────────────────
      await waitWhile(() => !always(doc, "customers.csv") || always(doc, "customers.csv").disabled, 20_000);
      press(always(doc, "customers.csv"));
      const line = () => doc.querySelector("#approvals-waiting > .answer-line");
      await waitWhile(() => line() === null || cardIn(doc) !== null, 20_000);
      assert.equal(cardIn(doc), null, "the arbiter retired the question: its card is gone");
      assert.equal(doc.querySelectorAll("#approvals-waiting > .answer-line").length, 1);
      assert.equal(words(line()), `Always allowed: ${what}. ${served.afterAllow} Undo it in Approvals`);
      assert.match(what, /program wants to send data from ~\/data\/customers\.csv and ~\/ws\/app\/\.env to hooks\.slack\.com$/);
      assert.doesNotMatch(doc.body.textContent, /After you answer/);
      assert.equal(line().getAttribute("role"), "status");
      assert.equal(doc.activeElement, line(), "the line has the focus");
      const link = line().querySelector("a");
      assert.equal(link.textContent, "Undo it in Approvals");
      const newest = (await admin.policyChanges()).changes[0]!;
      changeId = newest.id;
      assert.match(changeId, /^pc-\d{6}$/);
      assert.equal(link.getAttribute("href"), `/approvals/${changeId}`, "the change the arbiter recorded for the last file");
      rendered.push(["Approvals after the last Always", doc.documentElement.outerHTML]);
      assert.equal((await send()).action, "allow", "every file may go there: the send goes");

      // ── A4: the link opens that change, marked, with its Undo ─────────────
      link.click();
      const row = () => [...doc.querySelectorAll("#approvals-rule-history .row")].find((r: Doc) => r.dataset.id === changeId) ?? null;
      await waitWhile(() => !row()?.classList.contains("focus"), 20_000);
      assert.equal(doc.defaultView.location.pathname, `/approvals/${changeId}`);
      assert.deepEqual([...doc.querySelectorAll("#page-approvals .focus")].map((x: Doc) => x.dataset.id), [changeId], "exactly that change is marked");
      assert.equal(doc.getElementById("approvals-focus-note").hidden, true, "no note");
      // It sits under the day it was made, History's heading as an h3
      // (dashboard.md §4.25 *Changes sit under their day*): "Today", or
      // "Yesterday" for a run that crossed midnight since.
      let head = row().previousElementSibling;
      while (head && !head.matches(".history-day")) head = head.previousElementSibling;
      const pad = (k: number) => String(k).padStart(2, "0");
      const day = (ms: number) => { const d = new Date(ms); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`; };
      assert.ok(head, "a day heading above the change");
      assert.equal(head.tagName, "H3");
      assert.equal(head.querySelector("time").getAttribute("datetime"), day(newest.createdAt));
      assert.equal(words(head), day(newest.createdAt) === day(Date.now()) ? "Today" : "Yesterday");
      assert.equal(line(), null, "the line went with the visit");
      const undo = [...row().querySelectorAll("button")].find((b: Doc) => b.textContent === "Undo");
      assert.ok(undo, "Undo on it");
      rendered.push(["Approvals at the change", doc.documentElement.outerHTML]);
      undo.click();
      const undone = async () => (await admin.policyChanges()).changes.find((c) => c.id === changeId)?.undoneAt;
      for (const end = Date.now() + 20_000; !(await undone()) && Date.now() < end;) await new Promise((r) => setTimeout(r, 50));
      assert.ok(await undone(), "the arbiter has the change undone");
      rendered.push(["Approvals after Undo", doc.documentElement.outerHTML]);
    }, { headers: signedIn });

    // The file's rule is back: customers.csv may go nowhere, so the next send is refused.
    await settled(() => bindingsOf(csv), []);
    const parsed = (await admin.policyDocument()).onDisk.parsed as { paths: Array<{ path: string; bindings?: string[] }> };
    const byPath = new Map(parsed.paths.map((p) => [p.path, p]));
    assert.deepEqual(byPath.get(csv)!.bindings ?? [], [], "customers.csv's rule as it was");
    assert.deepEqual(byPath.get(env)!.bindings, ["api.stripe.com", H], ".env keeps its own Always");
    assert.equal((await send()).action, "block", "the next send is refused again");

    // ── A5: the oracle ───────────────────────────────────────────────────────
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");
    const bodies: [string, string][] = [
      ["/api/home", await (await pageFetch(`${base}/api/home`, { headers: signedIn })).text()],
      ["/api/policy/changes", await (await pageFetch(`${base}/api/policy/changes?limit=21`, { headers: { ...signedIn, "X-Mandu-Control": "1" } })).text()],
      ...rendered,
    ];
    assert.equal(rendered.length, 4);
    for (const [where, body] of bodies) {
      assert.ok(!body.includes(ENV_VALUE) && !body.includes(CARD_VALUE), `CONFIDENTIALITY VIOLATION: a file's value is in ${where}`);
      assert.doesNotMatch(body, /\$MDU/, `${where} carries no token`);
    }
  } finally {
    process.off("unhandledRejection", onUnhandled);
    await dashboard.close();
    for (const c of clients) c.close();
    wired?.close();
    await arbiter.close();
    resetCurrentPolicyForTests("claude-code");
    rmSync(tmp, { recursive: true, force: true });
  }
});
