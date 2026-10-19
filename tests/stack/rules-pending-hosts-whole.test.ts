/**
 * rules-pending-hosts-whole — the Rules page names each host of a change
 * waiting to be saved, and of what Save asks about, as its own code, so a
 * short one is never broken, across the REAL components and the served page
 * (dashboard.md §4.25u *A waiting change names each host*). Mandu-new.
 *
 * Until 2026-10-16 *Will be: … (not saved)*, *Changes to save*, its *Show
 * the files* rows and Save's two lists named the hosts as plain text:
 * headless Chromium broke "alerts-" / "eu.example.com" at 1280 px and
 * "deploy-" / "hooks.example.com" at 720 px. Here a real ArbiterServer runs
 * at the `secrets` axes with a policy.yaml binding `~/mandu-try/.env` to
 * two hosts, and a real DashboardServer over the production adapter
 * (`makeApprovalsArbiter`) serves:
 *
 *   P1  the answers: `POST /api/files/impact` and the first `POST
 *       /api/files/labels` (a host added is a loosening, so it asks) send
 *       each file's label before and after, and the loosening's detail, as
 *       parts reading exactly as their words, each host a code; the keys to
 *       confirm are the plain strings they were;
 *   P2  the served Rules page in jsdom under its served styles at 320 px:
 *       the person adds two hosts in the opened row, Update, then Save;
 *       *Will be* (row and opened row), *Changes to save*, *Show the files*
 *       and Save's two lists draw each host as its own code, one of at most
 *       24 characters in a `.name-fit` box (inline-block, no wider than its
 *       line) with the comma after it, a longer one a plain code, and none
 *       a nowrap `.code-whole`; the words read as the answers';
 *   P3  Save anyway sends the keys back and the change is applied: the
 *       confirmation works as it did;
 *   P4  the oracle: no page or answer read here carries the file's value,
 *       and none a minted token (`$MDU:NAME[hex]`).
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON). What is
 * under test is the words the served page draws; the stack supplies the
 * real labels, as the arbiter decides them, and the real confirmation.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { resolveCssVars, stylesAt } from "../../dashboard/test/unit/ui/css-flatten.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const VALUE = `sk_live_pendingHostsCanary_${process.pid}_000000`;
/** 24 and 21 characters (kept whole), and 27 (past the bound, wraps). */
const HOOKS = "deploy-hooks.example.com";
const ALERTS = "alerts-eu.example.com";
const UPLOADS = "uploads.example-storage.net";
const BEFORE = ["api.stripe.com", HOOKS];
const AFTER = [...BEFORE, ALERTS, UPLOADS];
const words = (hosts: readonly string[]) => `No AI; may be sent to ${hosts.join(", ")}`;

/** A minted token (the panel's own help text names the `$MDU:` form). */
const TOKEN = /\$MDU:[A-Za-z_][A-Za-z0-9_-]*\[[0-9a-f]{4,8}\]/;

type Part = { kind: string; text: string };
const text = (parts: Part[]): string => parts.map((p) => p.text).join("");
const codes = (parts: Part[]): string[] => parts.filter((p) => p.kind === "code").map((p) => p.text);

test("a change waiting on the Rules page and Save's question name each host as its own code and keep each short one whole, on the real stack with its served page; the confirmation still applies it; no value is shown (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-pending-hosts-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "mandu-try"), { recursive: true });
  const env = join(home, "mandu-try", ".env");
  writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, ["version: 1", "paths:", `  - { path: "${env}", level: no-model, bindings: [api.stripe.com, ${HOOKS}] }`, ""].join("\n"));
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
    secretsArbiter: wired.secrets,
    policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home"), MANDU_POLICY_FILE: policyPath, HOME: home },
    log: () => {},
    ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const noValue = (body: string, where: string) => {
    assert.ok(!body.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the file's value`);
    assert.doesNotMatch(body, TOKEN, `${where} carries no token`);
  };
  const ask = async (path: string, body: unknown) => {
    const r = await pageFetch(base + path, { method: "POST", headers: { ...CSRF_ADMIN, "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const raw = await r.text();
    assert.equal(r.status, 200, `${path}: ${raw}`);
    noValue(raw, path);
    return JSON.parse(raw);
  };
  const read = async (path: string): Promise<string> => {
    const r = await pageFetch(base + path, { headers: { Cookie: ADMIN_COOKIE } });
    const body = await r.text();
    assert.equal(r.status, 200, `${path}: ${body}`);
    noValue(body, path);
    return body;
  };
  try {
    // ── P1: the answers ──
    const change = { changes: [{ path: env, level: "no-model", bindings: AFTER, recursive: false }], folder: "~" };
    type Row = { display: string; before: string; after: string; beforeParts: Part[]; afterParts: Part[] };
    const fileRow = (impact: { files: Row[] }) => {
      const row = impact.files.find((f) => f.display === "~/mandu-try/.env");
      assert.ok(row, `the file is listed: ${JSON.stringify(impact.files)}`);
      assert.equal(row!.before, words(BEFORE));
      assert.equal(row!.after, words(AFTER));
      assert.equal(text(row!.beforeParts), row!.before, "the parts read as the label before");
      assert.equal(text(row!.afterParts), row!.after, "the parts read as the label after");
      assert.deepEqual(codes(row!.beforeParts), BEFORE, "each host before its own code");
      assert.deepEqual(codes(row!.afterParts), AFTER, "each host after its own code");
    };
    fileRow((await ask("/api/files/impact", change)).impact);
    const q = await ask("/api/files/labels", change);
    assert.equal(q.confirm, true, `a host added asks first: ${JSON.stringify(q)}`);
    assert.ok(Array.isArray(q.expected) && q.expected.length > 0 && q.expected.every((k: unknown) => typeof k === "string"), "the keys to confirm are plain strings, as before");
    const [loosen] = q.loosens as Array<{ subject: string; detail: string; detailParts?: Part[] }>;
    assert.equal(loosen!.subject, "~/mandu-try/.env");
    assert.equal(loosen!.detail, `Becomes ${words(AFTER)}, which lets more reach an AI or leave this computer than now.`);
    assert.ok(loosen!.detailParts, "the detail as parts too");
    assert.equal(text(loosen!.detailParts!), loosen!.detail);
    assert.deepEqual(codes(loosen!.detailParts!), AFTER);
    fileRow(q.impact);

    // ── P2 + P3: the served Rules page under its served styles, a 320 px phone ──
    const sheets = `${await read("/mandu.css")}\n${await read("/app.css")}`;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    type Doc = any;
    const ruleRow = (doc: Doc) => doc.querySelector(`#files-tree .row.file-rule[data-path="${env}"]`);
    const until = async (ok: () => boolean, what: string): Promise<void> => {
      for (let i = 0; i < 400 && !ok(); i++) await new Promise((r) => setTimeout(r, 25));
      assert.ok(ok(), `the page drew ${what}`);
    };
    await servedProductPage(base, "/rules", (doc: Doc) => !!ruleRow(doc), async (doc: Doc) => {
      const win = doc.defaultView;
      const drawnNames = (node: Doc, where: string): string[] => [...node.querySelectorAll("code")].map((c: Doc) => {
        const short = c.textContent.length <= 24;
        const fit = c.parentElement.classList.contains("name-fit");
        assert.equal(fit, short, `${where}, ${c.textContent}: ${short ? "kept whole in its box" : "past the bound, a plain code"}`);
        assert.equal(c.classList.contains("code-whole"), false, `${where}, ${c.textContent}: never a nowrap .code-whole, which would run past a narrow column`);
        assert.notEqual(win.getComputedStyle(c).whiteSpace, "nowrap", `${where}, ${c.textContent}: may wrap where its column is narrower than it`);
        if (fit) {
          const box = win.getComputedStyle(c.parentElement);
          assert.equal(box.display, "inline-block", `${where}, ${c.textContent}: one box`);
          assert.equal(box.maxWidth, "100%", `${where}, ${c.textContent}: no wider than its line`);
        }
        return c.textContent;
      });
      ruleRow(doc).querySelector(".file-more").click();
      await until(() => !!doc.getElementById("lock-to"), "the opened row");
      doc.getElementById("lock-to").value = AFTER.join(", ");
      doc.getElementById("files-to-update").click();
      await until(() => !!doc.querySelector("#files-pending-list li") && !!doc.querySelector("#files-impact .impact-files li"), "the change waiting and what it changes");
      const will = `Will be: ${words(AFTER)} (not saved)`;
      for (const [where, line] of [["the row", ruleRow(doc).querySelector(".file-pending")], ["the opened row", doc.querySelector("#files-tree .file-detail .file-pending")]] as const) {
        assert.equal(line?.textContent, will, `${where}: the words as before`);
        assert.deepEqual(drawnNames(line, where), AFTER, `${where}: each host its own code`);
        const fit = [...line.querySelectorAll(".name-fit")].find((f: Doc) => f.textContent.startsWith(HOOKS));
        assert.equal(fit?.textContent, `${HOOKS},`, `${where}: the comma after a host is in its box`);
      }
      const li = doc.querySelector("#files-pending-list li");
      assert.equal(li.textContent, `~/mandu-try/.env ${words(BEFORE)} → ${words(AFTER)} Drop`, "Changes to save: the words as before");
      assert.deepEqual(drawnNames(li, "Changes to save"), ["~/mandu-try/.env", ...BEFORE, ...AFTER]);
      const shown = doc.querySelector("#files-impact .impact-files li");
      assert.equal(shown.textContent, `~/mandu-try/.env ${words(BEFORE)} → ${words(AFTER)}`, "Show the files reads as the answer");
      assert.deepEqual(drawnNames(shown, "Show the files"), ["~/mandu-try/.env", ...BEFORE, ...AFTER]);
      noValue(doc.body.textContent, "the Rules page with a change waiting");

      doc.getElementById("files-save").click();
      await until(() => doc.getElementById("files-confirm").hidden === false, "Save's question");
      const becomes = doc.querySelector("#files-confirm-list li");
      assert.equal(becomes.textContent, `~/mandu-try/.env ${loosen!.detail}`, "what it becomes reads as the answer");
      assert.deepEqual(drawnNames(becomes, "Save's question"), ["~/mandu-try/.env", ...AFTER]);
      const less = doc.querySelector("#files-confirm-files li");
      assert.equal(less.textContent, `~/mandu-try/.env ${words(BEFORE)} → ${words(AFTER)}`);
      assert.deepEqual(drawnNames(less, "Files that become less protected"), ["~/mandu-try/.env", ...BEFORE, ...AFTER]);
      noValue(doc.body.textContent, "the Rules page asking before it saves");

      // P3: Save anyway sends the keys back; the change is made.
      doc.getElementById("files-save").click();
      await until(() => doc.getElementById("files-pending").hidden === true, "the change saved");
      assert.match(readFileSync(policyPath, "utf8"), new RegExp(ALERTS.replace(/\./g, "\\.")), "the confirmed change is in policy.yaml");
    }, { headers: { Cookie: ADMIN_COOKIE, "X-Mandu-Control": "1" }, css: resolveCssVars(stylesAt(sheets, 320)) });

    // ── P4: the oracle ──
    for (const route of ["/api/home", "/api/policy/panel", "/rules", "/"]) await read(route);
  } finally {
    await dashboard.close();
    wired?.close();
    await arbiter.close();
    resetCurrentPolicyForTests();
    rmSync(tmp, { recursive: true, force: true });
  }
});
