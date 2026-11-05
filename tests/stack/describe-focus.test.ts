/**
 * describe-focus.test — Rules › Describe what you want keeps the keyboard
 * focus through its requests, across the REAL components (dashboard.md
 * §4.25 *Describe what you want keeps the focus*). Mandu-new.
 *
 * Suggest rules, Try it and Apply go off while they ask, and Describe it
 * again goes with its card: a browser drops the focus of each to the page
 * (<body>). Until 2026-10-14 nothing gave it back. Here a real ArbiterServer
 * runs at the `secrets` axes with a file-backed policy.yaml (a `.env` at
 * `no-model`, a `svc` list); the dashboard reaches it through the
 * PRODUCTION adapter (`makeApprovalsArbiter`) and serves the Rules page
 * (its own index.html and home.js in jsdom, signed in). Only the helper
 * model is faked (it would spend budget); its answers go through the real
 * preview, probe and propose ops. jsdom keeps the focus of a button turned
 * off, so `press` drops it, as Chromium does, while the button still has it:
 *
 *   D0  Ctrl+Enter in the box presses Suggest rules: the page posts the box's
 *       text unchanged to POST /api/policy/assistant, the helper reads it
 *       whole, and the focus stays in the box;
 *   D1  Enter on Suggest rules: the focus waits on the card's heading, then
 *       the suggestion opens on its first line, "Suggested rules"; the line
 *       above the box, which said no helper was found (and no "again":
 *       nothing was pressed), follows the press's answer and names Claude
 *       Code (dashboard.md *Describe says which AI reads your words*);
 *   D2  Try it on the pypi.org row: the button has the focus back, described
 *       by the arbiter's own Now / After;
 *   D3  ALLOW typed, Apply: the line "Applied. …" takes the focus;
 *       policy.yaml carries both rules; the line has Undo and See it in
 *       Approvals at the change made, and its Undo puts policy.yaml and
 *       Your rules back as before (§4.25 *Every change made on Rules ends
 *       with an Undo or a link*);
 *   D4  the law moves under a second suggestion: Apply is refused (409) and
 *       has the focus back, described by the refusal, and policy.yaml is
 *       unchanged; Describe it again waits on the heading, then the new
 *       suggestion opens on its first line;
 *   D7  Discard leaves "Suggestion discarded." with Undo, which has the
 *       focus; Undo draws the suggestion again, on its first line, and
 *       posts nothing; Apply then writes the rule (§4.25n *Describe can undo
 *       its Discard*);
 *   D8  a suggestion discarded, the law moved meanwhile, then Undo and
 *       Apply: refused (409) and policy.yaml unchanged, so Undo is no way
 *       around the rules-changed check;
 *   D6  that suggestion applied, See it in Approvals opens Approvals with
 *       the change's Rule changes row marked, with its Undo;
 *   D5  the oracle: the `.env` value reaches neither the helper model nor a
 *       drawn page nor an answer.
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
import { HELPER_WORDS, type AssistantChannel, type AssistantModel } from "../../dashboard/src/policy-assistant.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const ENV_VALUE = "describeFocusStackEnvValue000001";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

/** Enter on a button that goes off (or goes) while it acts. Chromium drops
 *  its focus to the page, but only while the button still has it. */
function press(btn: Doc): void {
  btn.focus();
  btn.click();
  if (btn.ownerDocument.activeElement !== btn) return;
  assert.equal(btn.disabled, true, "the button goes off while it acts");
  btn.disabled = false;
  btn.blur();
  btn.disabled = true;
}
const describedBy = (doc: Doc, b: Doc): string => {
  const id = b.getAttribute("aria-describedby");
  return id ? doc.getElementById(id)?.textContent ?? `(no #${id})` : "";
};

test("Describe what you want over the real arbiter: Ctrl+Enter, Suggest rules, Try it, Apply, Discard and its Undo, and Describe it again keep the focus; the helper never sees a secret", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-describe-focus-"));
  const home = join(tmp, "home");
  const proj = join(home, "proj");
  mkdirSync(proj, { recursive: true });
  const env = join(proj, ".env");
  writeFileSync(env, `API_TOKEN=${ENV_VALUE}\n`);
  const token = join(proj, "deploy.token");
  writeFileSync(token, "not read by this test\n");
  const notes = join(proj, "notes.txt");
  writeFileSync(notes, "not read by this test either\n");
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\nlists:\n  svc: [api.example.com]\n  mirrors: [a.example.org]\npaths:\n  - path: "${env}"\n    level: no-model\n`);
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
  const admin = new ArbiterClient(adminSock);
  await admin.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets && wired.policyDoc, "the production adapter has the secrets and policy surfaces");

  // The helper model: records what it was shown, answers from a queue.
  const seen: string[] = [];
  const answers: string[] = [];
  const model = async (): Promise<AssistantModel> => ({
    async complete(call) { seen.push(call.system + "\n" + call.user); return { text: answers.shift() ?? "{}", model: "fake-assistant" }; },
  });
  // Which helper the channel line finds: none until the person signs in
  // to Claude Code (set by D1 once the line before the press is checked).
  let signedIn = false;
  const assistantChannel = async (): Promise<AssistantChannel> => (signedIn ? { ready: true, via: "claude" } : { ready: false, reason: "no-channel" });
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    assistantModel: model, assistantChannel, fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policyPath },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const pages: string[] = [];
  const bodies: string[] = [];
  const unhandled: string[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", onUnhandled);
  try {
    await servedProductPage(base, "/rules", (doc: Doc) => !!doc.querySelector("#describe-form") && !doc.getElementById("page-rules").hidden, async (doc: Doc) => {
      const head = doc.querySelector("#describe-block h2");
      const submit = doc.getElementById("describe-submit");
      const host = doc.getElementById("describe-result");
      const firstLine = () => host.querySelector(".suggestion .proposal-k");
      const button = (words: string) => [...host.querySelectorAll("button")].find((b: Doc) => b.textContent === words);

      // D0: Ctrl+Enter in the box, the page's fetch watched.
      const win = doc.defaultView;
      const pageFetchFn = win.fetch;
      const posted: unknown[] = [];
      win.fetch = (url: string, init: RequestInit = {}) => {
        if (String(url).endsWith("/api/policy/assistant") && init.method === "POST") posted.push(JSON.parse(String(init.body)));
        return pageFetchFn(url, init);
      };
      answers.push(JSON.stringify({ edits: [{ op: "lock-path", path: token, level: "no-model" }] }));
      const box = doc.getElementById("describe-text");
      const said = "Keep deploy.token secret.\nOur written policy: nothing leaves for paste sites.";
      box.value = said;
      box.focus();
      const ctrlEnter = new win.KeyboardEvent("keydown", { key: "Enter", ctrlKey: true, bubbles: true, cancelable: true });
      box.dispatchEvent(ctrlEnter);
      assert.equal(ctrlEnter.defaultPrevented, true, "no new line");
      assert.equal(submit.disabled, true, "Suggest rules is pressed: off while the helper works");
      await waitWhile(() => !firstLine());
      assert.deepEqual(posted, [{ sentence: said }], "the box's text, unchanged, once");
      assert.equal(seen.length, 1, "the helper was asked once");
      assert.ok(seen[0].includes(`<<<\n${said}\n>>>`), "the helper reads the text whole");
      assert.equal(doc.activeElement, box, "the focus stays in the box");
      win.fetch = pageFetchFn;

      // D1: Suggest rules.
      answers.push(JSON.stringify({
        edits: [
          { op: "lock-path", path: token, level: "no-model" },
          { op: "release", to: { host: "pypi.org" }, mode: "allow" },
        ],
        note: "I did not add GitHub: you did not say what to allow there.",
      }));
      const where = doc.getElementById("describe-where");
      await waitWhile(() => where.hidden);
      assert.equal(where.textContent, HELPER_WORDS["no-channel"].replace(", then press Suggest rules again.", ", then press Suggest rules."), "no helper found, in the 503's words");
      assert.doesNotMatch(where.textContent, /\bagain\b/, "no \"again\" before this press");
      signedIn = true;
      doc.getElementById("describe-text").value = "Keep deploy.token secret. My data may go to PyPI.";
      press(submit);
      assert.equal(doc.activeElement, head, "the focus waits on the card's heading, never <body>");
      assert.equal(head.textContent, "Describe what you want");
      await waitWhile(() => !firstLine());
      assert.equal(doc.activeElement, firstLine(), "the suggestion opens on its first line");
      assert.equal(firstLine().textContent, "Suggested rules");
      assert.equal(submit.disabled, false);
      assert.equal(submit.getAttribute("aria-describedby"), null);
      assert.equal(seen.length, 2, "the helper was asked once more");
      const ready = /^What you write here goes through Claude Code on this computer/;
      await waitWhile(() => !ready.test(where.textContent));
      assert.match(where.textContent, ready, "the line follows what the press found");
      assert.equal(where.hidden, false);
      assert.equal(firstLine().textContent, "Suggested rules", "the suggestion is unchanged");
      assert.equal(host.querySelectorAll(".suggestion-rows li").length, 2);
      pages.push(doc.body.textContent ?? "");

      // D2: Try it on the pypi.org row, through the arbiter's own probe.
      const rows = [...host.querySelectorAll(".suggestion-rows li")];
      const tryIt = rows[1].querySelector(".try-row");
      assert.ok(tryIt, "the release row can be tried");
      press(tryIt);
      assert.equal(doc.activeElement, doc.body, "off while it asks: the focus fell");
      await waitWhile(() => tryIt.disabled || !rows[1].querySelector(".try-result"));
      assert.equal(doc.activeElement, tryIt, "Try it has the focus back");
      assert.match(describedBy(doc, tryIt), /^Now: .*pypi\.org.*After: .*pypi\.org/, "described by its answer");
      pages.push(doc.body.textContent ?? "");

      // D3: Apply, once ALLOW is typed (the release row has no limit on
      // where the data comes from).
      const typed = host.querySelector(".proposal-confirm");
      assert.ok(typed, "a wide change asks for ALLOW");
      typed.value = "ALLOW";
      typed.dispatchEvent(new doc.defaultView.Event("input"));
      const yamlBefore = readFileSync(policyPath, "utf8");
      const yourRules = () => (doc.getElementById("rules-list").textContent ?? "") + "\n" + (doc.getElementById("files-tree")?.textContent ?? "");
      const rulesBefore = yourRules();
      press(button("Apply"));
      await waitWhile(() => !host.querySelector(".describe-done, .ask-error"));
      const done = host.querySelector(".describe-done");
      assert.ok(done, `applied: ${host.textContent}`);
      assert.match(done.textContent, /^Applied\./);
      assert.equal(doc.activeElement, done, "the line that says so has the focus");
      const onDisk = readFileSync(policyPath, "utf8");
      assert.match(onDisk, /pypi\.org/);
      assert.match(onDisk, /deploy\.token/);
      pages.push(doc.body.textContent ?? "");

      // D3a: the line has Undo and See it in Approvals at the change made.
      assert.equal(done.querySelector("span").textContent, "Applied. Your rules are updated.");
      const seeIt = done.querySelector("a.change-link");
      assert.equal(seeIt?.textContent, "See it in Approvals");
      const changeId = seeIt.dataset.ask;
      assert.match(changeId, /^pc-\d+$/, "a change made");
      assert.equal(seeIt.getAttribute("href"), `/approvals/${changeId}`);
      const undo = [...done.querySelectorAll("button")].find((b: Doc) => b.textContent === "Undo");
      assert.ok(undo, "Undo on the line");
      await waitWhile(() => undo.disabled || !/pypi\.org/.test(yourRules()));
      assert.notEqual(yourRules(), rulesBefore, "Your rules lists the applied rules");

      // D3b: Undo: policy.yaml and Your rules are back as before.
      press(undo);
      await waitWhile(() => done.textContent !== "Undone." || /pypi\.org/.test(yourRules()));
      assert.equal(doc.activeElement, done, "the line says Undone. and has the focus");
      const undone = readFileSync(policyPath, "utf8");
      assert.doesNotMatch(undone, /pypi\.org/, "policy.yaml lost the release rule");
      assert.doesNotMatch(undone, /deploy\.token/, "and the lock");
      assert.match(yamlBefore, /\.env/);
      assert.match(undone, /\.env/, "the rules of before are kept");
      assert.equal(yourRules(), rulesBefore, "Your rules is back as before");
      pages.push(doc.body.textContent ?? "");

      // D7: Discard, Undo, then Apply writes the rule.
      const posts: string[] = [];
      const statuses: number[] = [];
      win.fetch = (url: string, init: RequestInit = {}) => {
        if (init.method === "POST") posts.push(String(url));
        const r = pageFetchFn(url, init);
        if (String(url).endsWith("/api/policy/assistant/apply")) r.then((res: Response) => statuses.push(res.status));
        return r;
      };
      answers.push(JSON.stringify({ edits: [{ op: "lock-path", path: notes, level: "no-model" }] }));
      doc.getElementById("describe-text").value = "Keep notes.txt secret.";
      press(submit);
      await waitWhile(() => !firstLine());
      const discard = button("Discard");
      discard.focus();
      discard.click();
      const line = host.querySelector(".describe-done");
      assert.equal(line?.querySelector("span").textContent, "Suggestion discarded.");
      const undoDiscard = button("Undo");
      assert.equal(undoDiscard.getAttribute("aria-label"), "Undo the discard in Describe what you want");
      assert.equal(doc.activeElement, undoDiscard, "the line's Undo has the focus");
      const postsBefore = posts.length;
      undoDiscard.focus();
      undoDiscard.click();
      assert.equal(doc.activeElement, firstLine(), "Undo: the suggestion opens on its first line");
      assert.equal(posts.length, postsBefore, "Undo posts nothing");
      assert.doesNotMatch(readFileSync(policyPath, "utf8"), /notes\.txt/, "nothing written yet");
      press(button("Apply"));
      await waitWhile(() => !host.querySelector(".describe-done a.change-link, .ask-error"));
      assert.ok(host.querySelector(".describe-done a.change-link"), `applied: ${host.textContent}`);
      assert.deepEqual(statuses, [200]);
      assert.match(readFileSync(policyPath, "utf8"), /notes\.txt/, "the rule kept through Discard and Undo is written");
      pages.push(doc.body.textContent ?? "");

      // D8: Discard, the law moves (mirrors released), Undo, Apply: the
      // server refuses what is now a wider change than the one shown.
      answers.push(JSON.stringify({ edits: [{ op: "list", name: "mirrors", add: ["b.example.org"] }] }));
      doc.getElementById("describe-text").value = "Add b.example.org to my mirrors.";
      press(submit);
      await waitWhile(() => !firstLine());
      button("Discard").click();
      const moved = await admin.policyDocument();
      const law = moved.inForce as Record<string, unknown>;
      const lawRules = Array.isArray(law.user_rules) ? law.user_rules : [];
      await admin.applyPolicyDocument({ ...law, user_rules: [...lawRules, { id: "r-0099", kind: "release", to: { host: "@mirrors" }, mode: "allow" }] }, "human", moved.lawHash!);
      const yamlMoved = readFileSync(policyPath, "utf8");
      button("Undo").click();
      assert.ok(firstLine(), "the suggestion is back");
      press(button("Apply"));
      await waitWhile(() => !host.querySelector(".describe-done, .ask-error"));
      assert.ok(host.querySelector(".ask-error"), `refused: ${host.textContent}`);
      assert.deepEqual(statuses, [200, 409], "the rules-changed answer");
      assert.ok(button("Describe it again"), "a 409 offers Describe it again");
      assert.equal(readFileSync(policyPath, "utf8"), yamlMoved, "nothing written");
      assert.doesNotMatch(yamlMoved, /b\.example\.org/);
      win.fetch = pageFetchFn;
      pages.push(doc.body.textContent ?? "");

      // D4: a second suggestion; the law moves before Apply.
      answers.push(JSON.stringify({ edits: [{ op: "list", name: "svc", add: ["pastebin.com"] }] }));
      doc.getElementById("describe-text").value = "Add pastebin to my services list.";
      press(submit);
      await waitWhile(() => !firstLine());
      assert.equal(doc.activeElement, firstLine());
      const lawRead = await admin.policyDocument();
      const cur = lawRead.inForce as Record<string, unknown>;
      const rules = Array.isArray(cur.user_rules) ? cur.user_rules : [];
      await admin.applyPolicyDocument({ ...cur, user_rules: [...rules, { id: "r-0100", kind: "release", to: { host: "@svc" }, mode: "allow" }] }, "human", lawRead.lawHash!);
      const before = readFileSync(policyPath, "utf8");
      const apply = button("Apply");
      press(apply);
      await waitWhile(() => apply.disabled || !host.querySelector(".ask-error"));
      assert.equal(doc.activeElement, apply, "refused: Apply has the focus back");
      assert.ok(describedBy(doc, apply).trim(), "described by the refusal's words");
      assert.equal(doc.getElementById(apply.getAttribute("aria-describedby")), host.querySelector(".ask-error"));
      assert.equal(readFileSync(policyPath, "utf8"), before, "nothing applied");
      pages.push(doc.body.textContent ?? "");

      answers.push(JSON.stringify({ edits: [{ op: "lock-path", path: token, level: "no-model" }] }));
      const again = button("Describe it again");
      assert.ok(again, "a 409 offers Describe it again");
      press(again);
      assert.equal(doc.activeElement, head, "Describe it again: the heading, never <body>");
      await waitWhile(() => !firstLine());
      assert.equal(doc.activeElement, firstLine(), "the new suggestion opens on its first line");
      assert.equal(seen.length, 6);
      pages.push(doc.body.textContent ?? "");

      // D6: Apply it, then See it in Approvals: Approvals opens with that
      // change's Rule changes row marked, with its Undo.
      press(button("Apply"));
      await waitWhile(() => !host.querySelector(".describe-done a.change-link"));
      const link = host.querySelector(".describe-done a.change-link");
      const applied = link.dataset.ask;
      assert.match(readFileSync(policyPath, "utf8"), /deploy\.token/);
      link.click();
      const marked = () => [...doc.querySelectorAll("#page-approvals .focus")].map((x: Doc) => x.dataset.id);
      await waitWhile(() => !marked().includes(applied));
      assert.equal(doc.getElementById("page-approvals").hidden, false, "Approvals is open");
      assert.equal(doc.defaultView.location.pathname, `/approvals/${applied}`);
      assert.deepEqual(marked(), [applied]);
      const row = doc.querySelector("#approvals-rule-history .row.focus");
      assert.ok([...row.querySelectorAll("button")].some((b: Doc) => b.textContent === "Undo"), "its Undo on the row");
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // D5: the oracle.
    for (const path of ["/api/policy/panel", "/api/secrets", "/api/home"]) {
      bodies.push(await (await pageFetch(base + path, { headers: CSRF_ADMIN })).text());
    }
    for (const t of [...seen, ...pages, ...bodies]) {
      assert.ok(!t.includes(ENV_VALUE), "CONFIDENTIALITY VIOLATION: the .env value reached the helper, a page or an answer");
    }
  } finally {
    process.off("unhandledRejection", onUnhandled);
    await dashboard.close();
    wired.close();
    admin.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
