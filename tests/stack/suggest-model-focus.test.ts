/**
 * suggest-model-focus.test — on the product page's Rules, the model preview
 * of *Keys Mandu found* keeps the keyboard focus and Escape closes it,
 * across the REAL components (dashboard.md §4.25t *The preview keeps the
 * focus*). Mandu-new.
 *
 * Until 2026-10-12 the preview opened with the focus on <body>, Escape did
 * nothing in it, Cancel and Send left the focus on <body>, and Cancel
 * stayed on while a send was on its way, saying "Nothing was sent." of names
 * the model already had.
 *
 * Here a real ArbiterServer (secrets) walks a work tree whose
 * `deploy/app.conf` holds a registered key, and starts the arbiter's fake
 * classifier (the classify-main.ts contract, no model) for a names-only run,
 * through a wrapper that holds each run until the test lets it go. A real
 * DashboardServer over the production adapter (`makeApprovalsArbiter`), with
 * the model picker offered, serves Rules (its own index.html and home.js in
 * jsdom), signed in:
 *
 *   M1  Names only, Enter on *See what it would send*: the preview opens
 *       with the focus on its headline (the server's sentence), never Send;
 *   M2  Escape in it: the preview closes, "Nothing was sent.", the focus is
 *       back on *See what it would send*, and the classifier got no run;
 *   M3  again, then Enter on Send: Send and Cancel are off, the focus waits
 *       on the headline, Escape and Cancel close nothing while the run is
 *       held; let go, the run's line shows, the preview closes and the
 *       focus is back on *See what it would send*; the classifier got
 *       exactly one run;
 *   M4  the oracle: the classifier's request (names only), the rendered
 *       page and the answers read here carry no key.
 *
 * Axes: secrets (stated).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const HERE = dirname(fileURLToPath(import.meta.url));
const FAKE = join(HERE, "..", "..", "arbiter", "test", "helpers", "fake-classifier.mjs");
const KEY = "sk_" + "live_suggestModelFocusStackCanary00000001";

/** The classifier the arbiter starts: describe answers at once; a run waits
 *  until the `go` file exists, then the fake classifier answers it. A run
 *  never let go gives up after 2 minutes, so no process outlives the test. */
const HOLDING = `
import { existsSync } from "node:fs";
import { spawn } from "node:child_process";
const [go, fake, ...rest] = process.argv.slice(2);
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => { input += c; });
process.stdin.on("end", () => {
  const start = () => {
    const ch = spawn(process.execPath, [fake, ...rest], { stdio: ["pipe", "inherit", "inherit"] });
    ch.stdin.end(input);
    ch.on("exit", (code) => process.exit(code ?? 1));
  };
  if (input.includes('"describe"')) return start();
  const end = Date.now() + 120_000;
  const wait = () => (existsSync(go) ? start() : Date.now() > end ? process.exit(1) : setTimeout(wait, 20));
  wait();
});
`;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const byId = (doc: Doc, id: string) => doc.getElementById(id);
/** Enter on a button: the focus is on it, then it acts. */
function enter(btn: Doc): void {
  btn.focus();
  btn.click();
}
/** Escape where the focus is, as a browser sends it. */
function escape(doc: Doc): Doc {
  const ev = new doc.defaultView.KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true });
  doc.activeElement.dispatchEvent(ev);
  return ev;
}

test("Rules over the real arbiter: the model preview opens with the focus on its headline, never Send; Escape closes it and sends nothing; a held send keeps Cancel off and gives the focus back when it ends; no key anywhere", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-suggest-model-focus-"));
  const home = join(tmp, "home");
  const repo = join(home, "proj");
  const put = (rel: string, body = "ordinary text\n") => {
    mkdirSync(dirname(join(repo, rel)), { recursive: true });
    writeFileSync(join(repo, rel), body);
  };
  mkdirSync(join(repo, ".git"), { recursive: true });
  put("README.md", "a project\n");
  put("docs/guide.md");
  put("clients/acme/contract.docx");
  put("deploy/app.conf", `STRIPE_API_KEY=${KEY}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, "version: 1\n");
  const holding = join(tmp, "holding-classifier.mjs");
  writeFileSync(holding, HOLDING);
  const go = join(tmp, "go");
  const record = join(tmp, "record.jsonl");
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {},
    policyClassifier: { argv: [process.execPath, holding, go, FAKE, "ok", record] },
    policyModel: { env: { PATH: process.env["PATH"], HOME: home }, userName: "nobody-here" },
  });
  await arbiter.listen();
  const data = new ArbiterClient(socketPath);
  await data.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  for (const op of ["modelSuggestPreview", "modelSuggest"] as const) assert.equal(typeof wired.policyDoc[op], "function", `the adapter forwards ${op}`);
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home, policyModelOffered: true,
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const bodies: string[] = [];
  const read = async (path: string) => {
    const text = await (await pageFetch(base + path, { headers: CSRF_ADMIN })).text();
    bodies.push(text);
    return JSON.parse(text);
  };
  const pages: string[] = [];
  const runs = () => (existsSync(record) ? readFileSync(record, "utf8").split("\n").filter(Boolean).length : 0);
  try {
    await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
    const ready = (doc: Doc) => !!byId(doc, "suggest-open");
    await servedProductPage(base, "/rules", ready, async (doc) => {
      const run = byId(doc, "suggest-model-run");
      const head = byId(doc, "suggest-model-head");
      const dialog = byId(doc, "suggest-model-preview");
      const cancel = byId(doc, "suggest-model-cancel");
      const send = byId(doc, "suggest-model-send");
      const status = () => byId(doc, "suggest-model-status").textContent;
      const sel = byId(doc, "suggest-model-tier");
      enter(byId(doc, "suggest-open"));
      await waitWhile(() => sel.options[1].disabled);
      assert.equal(sel.options[1].disabled, false, "the server offers Names only");
      byId(doc, "suggest-root").value = repo;
      sel.value = "names";
      sel.dispatchEvent(new doc.defaultView.Event("change"));
      assert.equal(run.disabled, false);

      // M1: the preview opens with the focus on its headline.
      enter(run);
      await waitWhile(() => dialog.hidden && !byId(doc, "suggest-error").textContent);
      assert.equal(byId(doc, "suggest-error").textContent, "", "the preview was built");
      assert.equal(dialog.hidden, false);
      assert.equal(doc.activeElement, head, "the headline, never <body>");
      assert.notEqual(doc.activeElement, send, "never Send");
      assert.match(head.textContent, /^This sends \d+ file and folder names from 1 folder to Claude \(fake\) .*No file's content is sent\.$/);
      assert.match(byId(doc, "suggest-model-list").textContent, /app\.conf/, "the names as sent");

      // M2: Escape closes it and sends nothing.
      assert.equal(escape(doc).defaultPrevented, true, "the preview takes the Escape");
      assert.equal(dialog.hidden, true);
      assert.equal(status(), "Nothing was sent.");
      assert.equal(doc.activeElement, run, "back on See what it would send");
      await new Promise((r) => setTimeout(r, 200));
      assert.equal(runs(), 0, "the classifier got no run");

      // M3: again, then Send, held.
      enter(run);
      await waitWhile(() => dialog.hidden);
      assert.equal(doc.activeElement, head);
      enter(send);
      assert.equal(send.disabled, true);
      assert.equal(cancel.disabled, true, "Cancel is off: the send cannot be called back");
      assert.equal(doc.activeElement, head, "the focus waits on the headline");
      assert.equal(escape(doc).defaultPrevented, false, "not taken");
      cancel.click();
      assert.equal(dialog.hidden, false, "neither Escape nor Cancel closes it while it is on its way");
      assert.equal(status(), "Sending…", "never \"Nothing was sent.\"");
      writeFileSync(go, "");
      await waitWhile(() => !dialog.hidden);
      assert.equal(dialog.hidden, true, "the run ended");
      assert.match(status(), /^Claude \(fake\) suggested 1 rule: 1 waits here for you\.$/);
      assert.equal(cancel.disabled, false);
      assert.equal(doc.activeElement, run, "back on See what it would send");
      assert.equal(runs(), 1, "exactly one run");
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // M4: the oracle.
    const sentToModel = readFileSync(record, "utf8");
    assert.match(sentToModel, /app\.conf/, "the classifier got the names");
    assert.ok(!sentToModel.includes(KEY), "the classifier's request carries no key: names only");
    for (const path of ["/api/suggestions", "/api/home"]) await read(path);
    for (const text of [...pages, ...bodies]) assert.ok(!text.includes(KEY), "no page or answer carries the registered key");
  } finally {
    writeFileSync(go, ""); // a run still held ends
    await dashboard.close();
    data.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
