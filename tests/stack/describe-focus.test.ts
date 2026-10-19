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
 *   D1  Enter on Suggest rules: the focus waits on the card's heading, then
 *       the suggestion opens on its first line, "Suggested rules";
 *   D2  Try it on the pypi.org row: the button has the focus back, described
 *       by the arbiter's own Now / After;
 *   D3  ALLOW typed, Apply: the line "Applied. …" takes the focus;
 *       policy.yaml carries both rules;
 *   D4  the law moves under a second suggestion: Apply is refused (409) and
 *       has the focus back, described by the refusal, and policy.yaml is
 *       unchanged; Describe it again waits on the heading, then the new
 *       suggestion opens on its first line;
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
import type { AssistantModel } from "../../dashboard/src/policy-assistant.js";
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

test("Describe what you want over the real arbiter: Suggest rules, Try it, Apply and Describe it again keep the focus; the helper never sees a secret", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-describe-focus-"));
  const home = join(tmp, "home");
  const proj = join(home, "proj");
  mkdirSync(proj, { recursive: true });
  const env = join(proj, ".env");
  writeFileSync(env, `API_TOKEN=${ENV_VALUE}\n`);
  const token = join(proj, "deploy.token");
  writeFileSync(token, "not read by this test\n");
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\nlists:\n  svc: [api.example.com]\npaths:\n  - path: "${env}"\n    level: no-model\n`);
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
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    assistantModel: model, fileBrowserHome: home,
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

      // D1: Suggest rules.
      answers.push(JSON.stringify({
        edits: [
          { op: "lock-path", path: token, level: "no-model" },
          { op: "release", to: { host: "pypi.org" }, mode: "allow" },
        ],
        note: "I did not add GitHub: you did not say what to allow there.",
      }));
      doc.getElementById("describe-text").value = "Keep deploy.token secret. My data may go to PyPI.";
      press(submit);
      assert.equal(doc.activeElement, head, "the focus waits on the card's heading, never <body>");
      assert.equal(head.textContent, "Describe what you want");
      await waitWhile(() => !firstLine());
      assert.equal(doc.activeElement, firstLine(), "the suggestion opens on its first line");
      assert.equal(firstLine().textContent, "Suggested rules");
      assert.equal(submit.disabled, false);
      assert.equal(submit.getAttribute("aria-describedby"), null);
      assert.equal(seen.length, 1, "the helper was asked once");
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
      assert.equal(seen.length, 3);
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
