/**
 * rules-tree-whole.test — on the product page's Rules, Your rules' files and
 * folders are as long as the rules: every rule lies in the page's flow,
 * never in a box of its own, across the REAL components (dashboard.md
 * §4.25f *The tree is as long as its rules*). Mandu-new.
 *
 * Until 2026-10-14 the tree wore the file browser's class, a box 60vh /
 * 560px high that scrolls by itself: in a headless Chromium over six file
 * rules, one showed whole at 390×844 (four hidden, no scrollbar drawn) and
 * one was hidden at 1280×800, with nothing but a row cut at the box's edge
 * to say so. The served page here runs in jsdom with the served mandu.css
 * and app.css applied, so "a box of its own" is the page's own computed
 * height and overflow.
 *
 * A real ArbiterServer (secrets) holds a policy.yaml of twelve file rules (a
 * pattern, a folder with three rules inside it, eight files) and a sending
 * rule; a real DashboardServer over the production adapter serves Rules:
 *
 *   T1  signed out: every rule of policy.yaml is a row of the tree, and the
 *       tree and Sending data have no height of their own and do not scroll;
 *   T2  signed in: the same, and Add a rule's file browser, listing the
 *       project folder, keeps its own box (a folder can hold thousands);
 *   T3  the oracle: no page or answer read here carries a key.
 *
 * Axes: secrets (stated).
 */
import { test, after } from "node:test";
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
import { resolveCssVars } from "../../dashboard/test/unit/ui/css-flatten.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const KEY = "sk_" + "live_rulesTreeWholeStackCanary0000000";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

/** The served product styles, tokens resolved, to apply in jsdom. */
async function servedStyles(base: string): Promise<string> {
  const css = async (f: string) => {
    const r = await pageFetch(`${base}/${f}`);
    assert.equal(r.status, 200, `${f} is served`);
    return r.text();
  };
  return resolveCssVars((await css("mandu.css")) + "\n" + (await css("app.css")));
}

const scrolls = (v: string) => /\b(auto|scroll)\b/.test(v);
const treePaths = (doc: Doc): string[] => [...doc.querySelectorAll("#files-tree .row.file-rule")].map((r: Doc) => r.getAttribute("data-path"));

/** T1/T2: every rule is a row of the tree; the tree and Sending data are no box of their own. */
function inTheFlow(doc: Doc, rules: string[], when: string): void {
  const drawn = treePaths(doc);
  for (const r of rules) assert.ok(drawn.includes(r), `${when}: ${r} is a row of the tree`);
  for (const id of ["files-tree", "rules-list"]) {
    const s = doc.defaultView.getComputedStyle(doc.getElementById(id));
    assert.deepEqual([s.overflow, s.overflowX, s.overflowY].filter(scrolls), [], `${when}: #${id} does not scroll by itself`);
    assert.equal(s.maxHeight, "none", `${when}: #${id} has no height of its own`);
  }
}

test("Rules over the real arbiter: every file rule lies in the page's flow, signed out and in; the file browser keeps its box; no key on the page", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rules-tree-whole-"));
  const home = join(tmp, "home");
  const proj = join(home, "proj");
  const keys = join(proj, "keys");
  mkdirSync(keys, { recursive: true });
  const files = [
    ...Array.from({ length: 8 }, (_, i) => join(proj, `service-${String(i + 1).padStart(2, "0")}.env`)),
    ...["a.token", "b.token", "c.token"].map((f) => join(keys, f)),
  ];
  for (const f of files) writeFileSync(f, `API_KEY=${KEY}\n`);
  writeFileSync(join(proj, "README.md"), "nothing secret\n");
  const rules = ["**/*.pem", keys, ...files];
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, [
    "version: 1",
    "paths:",
    ...rules.flatMap((p, i) => [
      `  - path: "${p}"`,
      `    level: ${i % 2 ? "no-model" : "any-model"}`,
      ...(p === keys || p.startsWith("**") ? [] : ["    recursive: false"]),
    ]),
    "user_rules:",
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
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets && wired.policyDoc, "the production adapter has the secrets and policy surfaces");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policyPath },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const pages: string[] = [];
  const bodies: string[] = [];
  const ready = (doc: Doc) => treePaths(doc).length >= rules.length && !!doc.querySelector("#rules-list .row.rule");
  try {
    const css = await servedStyles(base);

    // T1: signed out.
    await servedProductPage(base, "/rules", ready, (doc) => {
      inTheFlow(doc, rules, "signed out");
      pages.push(doc.body.textContent ?? "");
    }, { css });

    // T2: signed in, and Add a rule's browser over the project folder.
    await servedProductPage(base, "/rules", ready, async (doc) => {
      inTheFlow(doc, rules, "signed in");
      doc.getElementById("rules-add").click();
      await waitWhile(() => !doc.querySelector("#files-list .row.file"));
      doc.getElementById("lock-path").value = "~/proj/";
      doc.getElementById("files-go").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
      await waitWhile(() => !doc.querySelector(`#files-list .row.file[data-path="${files[0]}"]`));
      assert.ok(doc.querySelector(`#files-list .row.file[data-path="${files[0]}"]`), "the browser lists the project folder");
      const browser = doc.defaultView.getComputedStyle(doc.getElementById("files-list"));
      assert.equal(browser.overflowY, "auto", "a folder's entries scroll in their own box");
      assert.notEqual(browser.maxHeight, "none", "with a height of its own");
      inTheFlow(doc, rules, "with Add a rule open");
      pages.push(doc.body.textContent ?? "");
    }, { css, headers: { Cookie: ADMIN_COOKIE } });

    // T3: the oracle.
    for (const path of ["/api/policy/panel", "/api/secrets", "/api/home", `/api/files/list?path=${encodeURIComponent(proj)}`]) {
      bodies.push(await (await pageFetch(base + path, { headers: CSRF_ADMIN })).text());
    }
    assert.ok(bodies[0].includes("service-08.env"), "the panel answer names the rules");
    for (const t of [...pages, ...bodies]) assert.ok(!t.includes(KEY), "no page or answer carries the key");
  } finally {
    await dashboard.close();
    wired.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
