/**
 * rules-why-width — on the product page's Rules, an opened row's *What the
 * rules say* gives its answers the box's width, across the REAL components
 * (dashboard.md §4.25p *The rules' answers keep their width*). Mandu-new.
 *
 * Wider than 1000 px the opened row is two equal columns and the box takes
 * the right one, 368 to 396 px wide in a headless Chromium. Until
 * 2026-10-16 its terms sat beside their answers there, as across a whole
 * row: the longest term took 175 px and each answer had 179 px at 1280 px,
 * narrower than on a 390 px phone, where the box puts each term over its
 * answer. Now it does so wherever the opened row is two columns. jsdom lays
 * out nothing, so the served page runs with its served stylesheets as a
 * window that wide applies them (css-flatten.ts stylesAt).
 *
 * A real ArbiterServer (secrets) holds a policy.yaml with a file rule that
 * names readers and hosts, a folder rule and a file rule inside the folder,
 * over real files holding a value; a real DashboardServer over the
 * production adapter serves Rules, signed in. Each rule's row is opened and
 * its What the rules say read from the real why route:
 *
 *   B1  1280 and 1001 px: the opened row is two columns, and the box puts
 *       each term over its answer;
 *   B2  1000 and 980 px: the opened row is one column, and the box's
 *       terms sit beside their answers, as before;
 *   B3  390 px: both one column, as before;
 *   B4  the box draws the arbiter's answer (its terms in order, the
 *       readers, the hosts), unchanged by the layout; since 2026-10-16 it
 *       leaves out a Warning line its row says in full beside it (§4.25p
 *       *A warning is said once*), so the row says that warning once;
 *   B5  the oracle: no page or answer read here carries a file's value or
 *       a minted token, and policy.yaml is as it was.
 *
 * Axes: secrets (stated).
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
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { resolveCssVars, stylesAt } from "../../dashboard/test/unit/ui/css-flatten.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const VALUES = [`sk_live_rulesWhyWidthCanary_${process.pid}_0`, `rulesWhyWidthCanary${process.pid}x1`, `rulesWhyWidthCanary${process.pid}x2`];
/** A minted token (the panel's own help text names the `$MDU:` form). */
const TOKEN = /\$MDU:[A-Za-z_][A-Za-z0-9_-]*\[[0-9a-f]{4,8}\]/;

const TWO = "minmax(0, 1fr) minmax(0, 1fr)";
const ONE = "minmax(0, 1fr)";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

test("Rules over the real arbiter: an opened row's What the rules say puts each term over its answer wherever the row is two columns, beside it where the box spans the row, over it on a phone; no value on the page", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rules-why-width-"));
  const home = join(tmp, "home");
  const deploy = join(home, "mandu-try", "deploy");
  mkdirSync(deploy, { recursive: true });
  const env = join(home, "mandu-try", ".env");
  const prod = join(deploy, "prod.env");
  writeFileSync(env, `STRIPE_KEY=${VALUES[0]}\n`);
  writeFileSync(prod, `DB_PASSWORD=${VALUES[1]}\n`);
  writeFileSync(join(deploy, "staging.conf"), `token = ${VALUES[2]}\n`);
  const policyPath = join(tmp, "policy.yaml");
  const policy = [
    "version: 1",
    "paths:",
    `  - { path: "${env}", level: no-model, bindings: [api.stripe.com, "db.internal:5432"], readers: [psql, { app: ssh, from: git }] }`,
    `  - { path: "${deploy}", level: no-model }`,
    `  - { path: "${prod}", level: no-model }`,
    "",
  ].join("\n");
  writeFileSync(policyPath, policy);
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
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policyPath, HOME: home },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const signedIn = { Cookie: ADMIN_COOKIE };
  const noValue = (body: string, where: string) => {
    for (const v of VALUES) assert.ok(!body.includes(v), `CONFIDENTIALITY VIOLATION: ${where} carries a file's value`);
    assert.doesNotMatch(body, TOKEN, `${where} carries no token`);
  };
  const read = async (path: string, headers: Record<string, string>): Promise<string> => {
    const r = await pageFetch(base + path, { headers });
    const body = await r.text();
    assert.equal(r.status, 200, `${path}: ${body.slice(0, 200)}`);
    noValue(body, path);
    return body;
  };
  try {
    const sheets = `${await read("/mandu.css", signedIn)}\n${await read("/app.css", signedIn)}`;
    const rows = [env, deploy, prod];
    const ruleRow = (doc: Doc, path: string) => doc.querySelector(`#files-tree .row.file-rule[data-path="${path}"]`);
    const seen: Record<string, string[]> = {};
    const said: Record<string, string[]> = {};
    await servedProductPage(base, "/rules", (doc: Doc) => rows.every((p) => ruleRow(doc, p)), async (doc: Doc) => {
      const win = doc.defaultView;
      const sheet = [...doc.head.querySelectorAll("style")].at(-1);
      assert.ok(sheet, "the served styles are applied");
      for (const path of rows) {
        ruleRow(doc, path).querySelector(".file-more").click();
        const boxOf = () => doc.querySelector(`#files-tree .file-detail .file-why[data-path="${path}"]`);
        await waitWhile(() => !boxOf()?.querySelector("dl"));
        const box = boxOf();
        assert.ok(box?.querySelector("dl"), `${path}: What the rules say is read and drawn`);
        seen[path] = ([...box.querySelectorAll("dt")] as Doc[]).map((dt) => `${dt.textContent}: ${dt.nextElementSibling.textContent}`);
        said[path] = ([...box.closest(".file-detail").querySelectorAll(".file-detail-main .rule-warn")] as Doc[]).map((w) => w.textContent);
        const layout = (width: number) => {
          sheet.textContent = resolveCssVars(stylesAt(sheets, width));
          return { row: win.getComputedStyle(box.closest(".file-detail")).gridTemplateColumns, box: win.getComputedStyle(box.querySelector("dl")).gridTemplateColumns };
        };
        // ── B1 ──
        for (const w of [1280, 1001]) assert.deepEqual(layout(w), { row: TWO, box: ONE }, `${path}, ${w}px: the box is the opened row's right column, so each term goes over its answer`);
        // ── B2 ──
        for (const w of [1000, 980]) assert.deepEqual(layout(w), { row: ONE, box: "max-content minmax(0, 1fr)" }, `${path}, ${w}px: the box spans the opened row, its terms beside their answers`);
        // ── B3 ──
        assert.deepEqual(layout(390), { row: ONE, box: "1fr" }, `${path}, 390px: a phone stacks them`);
        noValue(doc.body.textContent, "the rendered Rules page");
        ruleRow(doc, path).querySelector(".file-more").click();
        await waitWhile(() => !!boxOf());
      }
    }, { headers: signedIn, css: resolveCssVars(stylesAt(sheets, 1280)) });

    // ── B4: the arbiter's answer, as the route gives it ──
    for (const path of rows) {
      const why = JSON.parse(await read(`/api/files/why?path=${encodeURIComponent(path)}`, CSRF_ADMIN)) as { why: { lines: Array<{ term: string; text: string }> } };
      // A Warning the opened row says in full beside the box is not said
      // again in it (§4.25p, *A warning is said once*).
      const inRow = (l: { term: string; text: string }) => l.term === "Warning" && said[path]!.some((w) => w.includes(l.text));
      assert.deepEqual(seen[path], why.why.lines.filter((l) => !inRow(l)).map((l) => `${l.term}: ${l.text}`), `${path}: the box draws the route's lines, in order`);
      const warning = why.why.lines.find((l) => l.term === "Warning");
      if (warning) assert.deepEqual(said[path], [warning.text], `${path}: the row says the route's warning, beside the box`);
    }
    assert.match(said[env]![0] ?? "", /^psql prints or copies what it reads/, ".env: psql's warning, said once");
    assert.ok(seen[env]!.some((l) => /^Programs that get the real file: .*ssh \(only when git starts it\)/.test(l)), `.env: its readers: ${JSON.stringify(seen[env])}`);
    assert.ok(seen[env]!.includes("May be sent to: api.stripe.com, db.internal:5432"), ".env: its hosts");
    assert.ok(seen[deploy]!.some((l) => l.startsWith("Programs that get the real files: Decided for each file inside")), "the folder: decided file by file");

    // ── B5: the oracle ──
    for (const route of ["/api/home", "/api/policy/panel", "/api/secrets", "/rules", "/"]) await read(route, signedIn);
    assert.equal(readFileSync(policyPath, "utf8"), policy, "nothing was saved");
  } finally {
    await dashboard.close();
    wired.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
