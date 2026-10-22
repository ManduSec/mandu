/**
 * rules-hosts-whole — the Rules page names each host a file may be sent to
 * as its own code, so a short one is never broken, and a file whose values
 * are bound one by one says where each may go, across the REAL components
 * and the served page (dashboard.md §4.25u *Rules names each host*).
 * Mandu-new.
 *
 * Until 2026-10-16 an opened row's *What the rules say › May be sent to*
 * and the *Per value* sentence named the hosts as plain text: headless
 * Chromium broke "deploy-" / "hooks.example.com" in the first at 390 px
 * and "payments-" / "eu.example.com" in the second at 320 px. And for a
 * file with `values:` (plan 13 §5.2) the line read "Nowhere without your
 * OK." (the whole file's hosts) under a sentence saying STRIPE_KEY may go
 * to two hosts. Here a real ArbiterServer runs at the `secrets` axes with
 * a policy.yaml holding `~/mandu-try/.env` (four hosts) and
 * `~/mandu-try/app.env` (per-value hosts). A real DashboardServer over the
 * production adapter (`makeApprovalsArbiter`) serves:
 *
 *   R1  the answers: `/api/files/why` for each file (signed in) names each
 *       host, and each value's key, as its own code, the words exactly the
 *       line's text; app.env's line is the per-value sentence; the panel's
 *       row and the All files browser's label carry `sendParts` reading as
 *       their `send`;
 *   R2  the served Rules page in jsdom under its served styles at 320 px:
 *       app.env's *Per value* sentence and each opened row's *May be sent
 *       to* draw each name as its own code, one of at most 24 characters
 *       kept on one line (`.code-whole`, `white-space: nowrap`), a longer
 *       one a plain code; the words read as the answer's;
 *       and app.env's row says on the page how to change where its values
 *       go: a line under the sentence naming `values:` and the policy file
 *       as the panel reports it, which describes the disabled menu
 *       (`aria-describedby`); .env's row (whole-file hosts) has none;
 *   R3  the oracle: no page or answer read here carries a file's value,
 *       and none a minted token (`$MDU:NAME[hex]`).
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON). What is
 * under test is the words the served page draws; the stack supplies the
 * real labels, as the arbiter decides them, that the words are about.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
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

const ENV_VALUE = `sk_live_rulesHostsCanary_${process.pid}_000000`;
const APP_STRIPE = `sk_live_rulesHostsCanary_${process.pid}_000001`;
const APP_AWS = `AKIARULESHOSTS${process.pid}`;
/** 24 characters (kept whole), 23, and 27 and 29 (past the bound, wrap). */
const HOOKS = "deploy-hooks.example.com";
const PAYMENTS = "payments-eu.example.com";
const UPLOADS = "uploads.example-storage.net";
const S3 = "s3.eu-central-1.amazonaws.com";
const ENV_HOSTS = ["api.stripe.com", "db.internal:5432", HOOKS, UPLOADS];
const APP_CODES = ["STRIPE_KEY", "api.stripe.com", PAYMENTS, "AWS_*", S3, HOOKS];
const APP_SEND = `STRIPE_KEY may be sent only to api.stripe.com, ${PAYMENTS}; AWS_* only to ${S3}; any other value only to ${HOOKS}; a program holding the whole file may send it nowhere without asking.`;

/** A minted token (the panel's own help text names the `$MDU:` form). */
const TOKEN = /\$MDU:[A-Za-z_][A-Za-z0-9_-]*\[[0-9a-f]{4,8}\]/;

type Part = { kind: string; text: string };
const text = (parts: Part[]): string => parts.map((p) => p.text).join("");
const codes = (parts: Part[]): string[] => parts.filter((p) => p.kind === "code").map((p) => p.text);

test("the Rules page names each host as its own code and keeps each short one whole, and a per-value file says where each value may go, on the real stack with its served page; no value is shown (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rules-hosts-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "mandu-try"), { recursive: true });
  const env = join(home, "mandu-try", ".env");
  const app = join(home, "mandu-try", "app.env");
  writeFileSync(env, `STRIPE_KEY=${ENV_VALUE}\n`);
  writeFileSync(app, `STRIPE_KEY=${APP_STRIPE}\nAWS_ACCESS_KEY_ID=${APP_AWS}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, [
    "version: 1",
    "paths:",
    `  - { path: "${env}", level: no-model, bindings: [api.stripe.com, "db.internal:5432", ${HOOKS}, ${UPLOADS}] }`,
    `  - path: "${app}"`,
    "    level: no-model",
    `    bindings: [${HOOKS}]`,
    "    values:",
    `      STRIPE_KEY: { bindings: [api.stripe.com, ${PAYMENTS}] }`,
    `      "AWS_*": { bindings: [${S3}] }`,
    "",
  ].join("\n"));
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
    for (const v of [ENV_VALUE, APP_STRIPE, APP_AWS]) assert.ok(!body.includes(v), `CONFIDENTIALITY VIOLATION: ${where} carries a file's value`);
    assert.doesNotMatch(body, TOKEN, `${where} carries no token`);
  };
  const read = async (path: string, headers: Record<string, string>): Promise<string> => {
    const r = await pageFetch(base + path, { headers });
    const body = await r.text();
    assert.equal(r.status, 200, `${path}: ${body}`);
    noValue(body, path);
    return body;
  };
  try {
    // ── R1: the answers ──
    type Line = { term: string; text: string; parts?: Part[] };
    const why = async (path: string): Promise<Line> => {
      const w = JSON.parse(await read(`/api/files/why?path=${encodeURIComponent(path)}`, CSRF_ADMIN)) as { why: { lines: Line[] } };
      const line = w.why.lines.find((l) => l.term === "May be sent to");
      assert.ok(line?.parts, `${path}: May be sent to, with parts: ${JSON.stringify(w.why.lines)}`);
      assert.equal(text(line!.parts!), line!.text, `${path}: the parts read as the line`);
      return line!;
    };
    const envLine = await why(env);
    assert.equal(envLine.text, ENV_HOSTS.join(", "));
    assert.deepEqual(codes(envLine.parts!), ENV_HOSTS, ".env: each host its own code");
    const appLine = await why(app);
    assert.equal(appLine.text, APP_SEND, "app.env: where each value may go, not the whole file's nowhere");
    assert.deepEqual(codes(appLine.parts!), APP_CODES, "app.env: each key and host its own code");
    const panel = JSON.parse(await read("/api/policy/panel", { Cookie: ADMIN_COOKIE })) as { panel: { policyFile: { path: string | null } | null; yourRules: Array<{ id: string; plain: { send?: string; sendParts?: Part[] } }> } };
    assert.equal(panel.panel.policyFile?.path, policyPath, "the panel names the policy file the page will point at");
    const row = panel.panel.yourRules.find((r) => r.id === `lock:${app}`);
    assert.ok(row?.plain.sendParts, `the panel's row for app.env: ${JSON.stringify(panel.panel.yourRules.map((r) => r.id))}`);
    assert.equal(row!.plain.send, APP_SEND);
    assert.equal(text(row!.plain.sendParts!), APP_SEND);
    assert.deepEqual(codes(row!.plain.sendParts!), APP_CODES);
    // The All files browser's label for the same file, from the arbiter's pathLevels.
    const listed = JSON.parse(await read(`/api/files/list?path=${encodeURIComponent(join(home, "mandu-try"))}`, CSRF_ADMIN)) as { entries: Array<{ name: string; label: { send?: string; sendParts?: Part[] } | null }> };
    const label = listed.entries.find((x) => x.name === "app.env")?.label;
    assert.ok(label?.sendParts, `the browser's label for app.env: ${JSON.stringify(listed.entries.map((x) => x.name))}`);
    assert.equal(label!.send, APP_SEND);
    assert.equal(text(label!.sendParts!), APP_SEND);
    assert.deepEqual(codes(label!.sendParts!), APP_CODES);

    // ── R2: the served Rules page under its served styles, a 320 px phone ──
    const sheets = `${await read("/mandu.css", { Cookie: ADMIN_COOKIE })}\n${await read("/app.css", { Cookie: ADMIN_COOKIE })}`;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    type Doc = any;
    const ruleRow = (doc: Doc, path: string) => doc.querySelector(`#files-tree .row.file-rule[data-path="${path}"]`);
    const until = async (ok: () => boolean, what: string): Promise<void> => {
      for (let i = 0; i < 200 && !ok(); i++) await new Promise((r) => setTimeout(r, 25));
      assert.ok(ok(), `the page drew ${what}`);
    };
    await servedProductPage(base, "/rules", (doc: Doc) => !!(ruleRow(doc, env) && ruleRow(doc, app)), async (doc: Doc) => {
      const win = doc.defaultView;
      const drawnCodes = (node: Doc): string[] => [...node.querySelectorAll("code")].map((c: Doc) => {
        const short = c.textContent.length <= 24;
        assert.equal(c.className, short ? "code-whole" : "", `${c.textContent}: ${short ? "kept whole" : "past the bound, a plain code"}`);
        assert.equal(win.getComputedStyle(c).whiteSpace === "nowrap", short, `${c.textContent}: ${short ? "on one line" : "may wrap"}`);
        return c.textContent;
      });
      const values = ruleRow(doc, app).querySelector(".file-values");
      assert.equal(values.textContent, APP_SEND, "the Per value sentence reads as the answer");
      assert.deepEqual(drawnCodes(values), APP_CODES, "the Per value sentence: each key and host its own code");
      // Where to change the per-value hosts, said on the page (§4.25p *Per value*).
      const how = ruleRow(doc, app).querySelector(".file-values-how");
      assert.ok(how, "app.env's row says how to change where its values go");
      assert.equal(how.previousElementSibling, values, "right under the Per value sentence");
      assert.equal(how.textContent, `Each value has its own hosts, so this menu cannot change them. Edit values: for this file in ${policyPath}.`);
      assert.deepEqual([...how.querySelectorAll("code")].map((c: Doc) => c.textContent), ["values:", policyPath], "it names values: and the policy file");
      const perValueMenu = ruleRow(doc, app).querySelector("select.send-select");
      assert.equal(perValueMenu.disabled, true, "the menu stays read only");
      assert.equal(perValueMenu.getAttribute("aria-describedby"), how.id, "the line describes the menu");
      assert.equal(ruleRow(doc, env).querySelector(".file-values-how"), null, ".env's row (whole-file hosts) has no such line");
      for (const [path, words, want] of [[env, ENV_HOSTS.join(", "), ENV_HOSTS], [app, APP_SEND, APP_CODES]] as const) {
        ruleRow(doc, path).querySelector(".file-more").click();
        await until(() => !!doc.querySelector(`#files-tree .file-why[data-path="${path}"] dl`), `What the rules say for ${path}`);
        const box = doc.querySelector(`#files-tree .file-why[data-path="${path}"]`);
        const dd = [...box.querySelectorAll("dt")].find((dt: Doc) => dt.textContent === "May be sent to")?.nextElementSibling;
        assert.ok(dd, `${path}: May be sent to`);
        assert.equal(dd.textContent, words, `${path}: the line reads as the answer`);
        assert.deepEqual(drawnCodes(dd), [...want], `${path}: each name its own code`);
        noValue(doc.body.textContent, "the rendered Rules page");
      }
    }, { headers: { Cookie: ADMIN_COOKIE }, css: resolveCssVars(stylesAt(sheets, 320)) });

    // ── R3: the oracle ──
    for (const route of ["/api/home", "/api/policy/panel", "/rules", "/"]) {
      await read(route, { Cookie: ADMIN_COOKIE });
    }
  } finally {
    await dashboard.close();
    wired?.close();
    await arbiter.close();
    resetCurrentPolicyForTests();
    rmSync(tmp, { recursive: true, force: true });
  }
});
