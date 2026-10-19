/**
 * describe-home-paths — Rules › Describe what you want names a file under
 * the dashboard's home folder as `~/…`, as the Rules page and Approvals do
 * (dashboard.md §4.34 "`~` is the dashboard's home"), across the REAL
 * components. Mandu-new.
 *
 * Until 2026-10-15 the suggestion's rows and its *This would let* lines
 * (policy-assistant.ts `suggestRules`) wrote every file as recorded: "Make
 * `/home/alice/proj/.env` a secret no AI may read". Here a real
 * ArbiterServer runs at the `secrets` axes with a file-backed policy.yaml
 * (`notes.md` under the home and `other.env` outside it at `no-model`); the
 * dashboard, its home folder the temp home, reaches it through the
 * PRODUCTION adapter (`makeApprovalsArbiter`). Only the helper model is
 * faked (it would spend budget); its answers go through the real preview
 * and propose ops. It suggests locking `.env`, removing both rules and
 * blocking pastebin.com.
 *
 *   P1  the POST's rows and lines say `~/proj/…` for the files under the
 *       home, the other file and the host as written; `edits` and
 *       `expected` are the arbiter's own (absolute paths);
 *   P2  the served Rules page (index.html and home.js in jsdom, signed in):
 *       Suggest rules draws those words, and the card never spells the home
 *       folder out;
 *   P3  Apply from that card is taken (the binding to what was shown still
 *       holds): policy.yaml carries `.env`'s lock by its full path and
 *       neither removed rule;
 *   P4  no unhandled rejection; the oracle: no file's value reached the
 *       helper model, a drawn page or an answer, and no token did.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
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

const ENV_VALUE = "describeHomePathsEnvValue0000001";
const NOTES_VALUE = "describeHomePathsNotesValue00002";
const OTHER_VALUE = "describeHomePathsOtherValue00003";
const VALUES = [ENV_VALUE, NOTES_VALUE, OTHER_VALUE];

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
type Parts = Array<{ kind: string; text: string }>;
const said = (parts: Parts): string => parts.map((p) => p.text).join("");
const words = (el: Doc): string => String(el?.textContent ?? "").replace(/\s+/g, " ").trim();
/** A suggested row's sentence: its text and code, not its tag or Try it. */
const sentence = (li: Doc): string => [...li.childNodes].filter((n: Doc) => n.nodeType === 3 || n.nodeName === "CODE").map((n: Doc) => n.textContent).join("");

test("Describe what you want names a file under the dashboard's home as ~/…, and Apply still writes what the arbiter named (real arbiter, production adapter, served Rules page); no secret anywhere", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-describe-home-"));
  const home = join(tmp, "home");
  const proj = join(home, "proj");
  mkdirSync(proj, { recursive: true });
  const env = join(proj, ".env");
  writeFileSync(env, `API_TOKEN=${ENV_VALUE}\n`);
  const notes = join(proj, "notes.md");
  writeFileSync(notes, `${NOTES_VALUE}\n`);
  // Outside the home: always named in full.
  mkdirSync(join(tmp, "elsewhere"));
  const other = join(tmp, "elsewhere", "other.env");
  writeFileSync(other, `K=${OTHER_VALUE}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: "${notes}"\n    level: no-model\n  - path: "${other}"\n    level: no-model\n`);
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
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets && wired.policyDoc, "the production adapter has the secrets and policy surfaces");

  // The helper model: records what it was shown, gives the same answer each time.
  const seen: string[] = [];
  const answer = JSON.stringify({
    edits: [
      { op: "lock-path", path: env, level: "no-model" },
      { op: "unlock-path", path: notes },
      { op: "unlock-path", path: other },
      { op: "release", to: { host: "pastebin.com" }, mode: "block" },
    ],
    note: "I left out GitHub: you did not say what to allow there.",
  });
  const model = async (): Promise<AssistantModel> => ({
    async complete(call) { seen.push(call.system + "\n" + call.user); return { text: answer, model: "fake-assistant" }; },
  });
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    assistantModel: model, fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policyPath },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const ROWS = [
    "Make ~/proj/.env a secret no AI may read",
    "Remove the rule for ~/proj/notes.md",
    `Remove the rule for ${other}`,
    "Always block sending masked data from anywhere to pastebin.com",
  ];
  const LETS = ["~/proj/notes.md would be protected less", `${other} would be protected less`].sort();
  const bodies: string[] = [];
  const pages: string[] = [];
  const unhandled: string[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", onUnhandled);
  try {
    // P1: the POST.
    const r = await pageFetch(`${base}/api/policy/assistant`, { method: "POST", headers: { ...CSRF_ADMIN, "Content-Type": "application/json" }, body: JSON.stringify({ sentence: "Keep .env secret, stop hiding notes.md and other.env, never paste." }) });
    const text = await r.text();
    bodies.push(text);
    assert.equal(r.status, 200, text);
    const s = JSON.parse(text) as { rows: Array<{ parts: Parts; loosens: boolean }>; loosens: Array<{ line: Parts }>; edits: unknown[]; expected: string[] };
    assert.deepEqual(s.rows.map((row) => said(row.parts)), ROWS);
    assert.deepEqual(s.rows.map((row) => row.loosens), [false, true, true, false], "the arbiter's own preview marks the rows");
    assert.deepEqual(s.loosens.map((l) => said(l.line)).sort(), LETS);
    assert.deepEqual(s.edits, (JSON.parse(answer) as { edits: unknown[] }).edits, "the edits Apply sends are the assistant's, untouched");
    assert.deepEqual([...s.expected].sort(), [`paths\u0000${notes}`, `paths\u0000${other}`].sort(), "Apply's binding: the arbiter's own subjects");

    // P2 + P3: the served Rules page.
    await servedProductPage(base, "/rules", (doc: Doc) => !!doc.querySelector("#describe-form") && !doc.getElementById("page-rules").hidden, async (doc: Doc) => {
      assert.equal(doc.querySelector('meta[name="home-dir"]')?.getAttribute("content"), home, "the page is served with its home folder");
      const host = doc.getElementById("describe-result");
      doc.getElementById("describe-text").value = "Keep .env secret, stop hiding notes.md and other.env, never paste.";
      doc.getElementById("describe-form").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
      await waitWhile(() => !host.querySelector(".suggestion"));
      const card = host.querySelector(".suggestion");
      assert.ok(card, `a suggestion: ${words(host)}`);
      const rows = [...card.querySelectorAll(".suggestion-rows li")];
      assert.deepEqual(rows.map(sentence), ROWS);
      assert.deepEqual(rows.map((li: Doc) => !!li.querySelector(".tag-loosens")), [false, true, true, false]);
      assert.deepEqual([...card.querySelectorAll(".proposal-let li")].map(words).sort(), LETS);
      assert.deepEqual([...card.querySelectorAll(".suggestion-rows li code")].map(words), ["~/proj/.env", "~/proj/notes.md", other, "pastebin.com"]);
      assert.ok(!card.textContent.includes(`${home}/`), `the card does not spell the home folder out: ${words(card)}`);
      pages.push(doc.documentElement.outerHTML);

      const apply = [...card.querySelectorAll("button")].find((b: Doc) => b.textContent === "Apply");
      assert.ok(apply && !apply.disabled, "Apply needs no typed ALLOW here");
      apply.click();
      await waitWhile(() => !host.querySelector(".describe-done, .ask-error"));
      assert.ok(host.querySelector(".describe-done"), `applied: ${words(host)}`);
      pages.push(doc.documentElement.outerHTML);
    }, { headers: { Cookie: ADMIN_COOKIE } });
    assert.equal(seen.length, 2, "the helper was asked twice (the POST, then the page)");
    const onDisk = readFileSync(policyPath, "utf8");
    assert.ok(onDisk.includes(env), `the lock is written by its full path:\n${onDisk}`);
    assert.ok(!onDisk.includes(notes) && !onDisk.includes(other), `both rules are gone:\n${onDisk}`);
    assert.match(onDisk, /pastebin\.com/);
    assert.ok(!onDisk.includes("~/"), "nothing the page shortened reached policy.yaml");

    await new Promise((res) => setTimeout(res, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // P4: the oracle.
    assert.equal(pages.length, 2);
    for (const t of [...pages, ...bodies]) {
      for (const v of VALUES) assert.ok(!t.includes(v), "CONFIDENTIALITY VIOLATION: a file's value in a page or an answer");
      assert.doesNotMatch(t, /\$MDU/, "nor a token");
    }
    for (const t of seen) for (const v of VALUES) assert.ok(!t.includes(v), "CONFIDENTIALITY VIOLATION: the helper model got a file's value");
  } finally {
    process.off("unhandledRejection", onUnhandled);
    await dashboard.close();
    wired?.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
