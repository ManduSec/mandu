/**
 * rules-tree-anchor.test — on the product page's Rules, a label chosen in
 * Your rules keeps its menu on screen, across the REAL components
 * (dashboard.md §4.25n *A label chosen keeps its menu on screen*).
 * Mandu-new.
 *
 * Every choice in the tree draws it again from nothing (home.js
 * renderLabeled). On a phone the tree is longer than the window, and
 * Chrome's scroll anchoring kept its anchor on a node inside it, which each
 * redraw removes: in a headless Chromium at 390×844 a label chosen in the
 * fourth of six rules moved the page up 360px at once, and the menu, which
 * keeps the focus, ended below the window. The served stylesheet now takes
 * the tree, and nothing else, out of anchoring (`overflow-anchor: none`,
 * which leaves out its whole subtree). jsdom lays out nothing and does not
 * anchor, so this proves the served rule and the reason for it.
 *
 * A real ArbiterServer (secrets) holds a policy.yaml of four file rules; a
 * real DashboardServer over the production adapter serves Rules, signed in:
 *
 *   A1  the served app.css has one overflow-anchor rule: `none`, on the tree;
 *       on the served page it names `#files-tree` alone, never the window;
 *   A2  a label chosen in the tree for a rule of policy.yaml waits in
 *       Changes to save, and its menu is drawn again from nothing inside the
 *       box that rule names, keeping the focus; Discard leaves policy.yaml
 *       as it was;
 *   A3  the oracle: no page or answer read here carries a key.
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
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const KEY = "sk_live_rulesTreeAnchorStackCanary0000000";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

/** The served stylesheet, comments dropped, as `selector { body }` rules. */
function rulesOf(css: string): Array<{ sel: string; body: string }> {
  return [...css.replace(/\/\*[\s\S]*?\*\//g, "").matchAll(/([^{}]+)\{([^{}]*)\}/g)].map((m) => ({ sel: m[1]!.trim(), body: m[2]!.trim() }));
}

test("Rules over the real arbiter: the served stylesheet takes Your rules' tree out of scroll anchoring, and a label chosen there is drawn again inside it with the focus; no key on the page", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rules-tree-anchor-"));
  const home = join(tmp, "home");
  const proj = join(home, "proj");
  mkdirSync(proj, { recursive: true });
  const files = ["a.env", "b.env", "deploy.token", "notes.md"].map((f) => join(proj, f));
  for (const f of files) writeFileSync(f, `API_KEY=${KEY}\n`);
  const policyPath = join(tmp, "policy.yaml");
  const policy = [
    "version: 1",
    "paths:",
    ...files.flatMap((p) => [`  - path: "${p}"`, "    level: no-model", "    recursive: false"]),
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
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policyPath },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const pages: string[] = [];
  const bodies: string[] = [];
  const menuOf = (doc: Doc, path: string) => doc.querySelector(`#files-tree .row.file-rule[data-path="${path}"] select.label-select:not(.send-select)`);
  const ready = (doc: Doc) => files.every((f) => !!menuOf(doc, f));
  try {
    // A1: the served stylesheet.
    const css = rulesOf(await (await pageFetch(`${base}/app.css`)).text());
    const anchor = css.filter((r) => /overflow-anchor/.test(r.body));
    assert.deepEqual(anchor.map((r) => `${r.sel} { ${r.body} }`), [".files-tree { overflow-anchor: none; }"],
      "one rule takes a box out of scroll anchoring: Your rules' tree");
    const sel = anchor[0]!.sel;

    await servedProductPage(base, "/rules", ready, async (doc) => {
      assert.deepEqual([...doc.querySelectorAll(sel)].map((x: Doc) => x.id), ["files-tree"], "on the served page the rule names the tree alone");
      assert.equal(doc.documentElement.matches(sel) || doc.body.matches(sel), false, "the rest of the page keeps anchoring");
      const tree = doc.getElementById("files-tree");
      const bar = doc.getElementById("files-pending");

      // A2: a label chosen for a rule of policy.yaml, on its way to the bar.
      const path = files[2]!;
      const old = menuOf(doc, path);
      const above: Doc[] = [];
      for (let p = old.parentElement; p; p = p.parentElement) above.push(p);
      old.focus();
      old.value = "any-model";
      old.dispatchEvent(new doc.defaultView.Event("change", { bubbles: true }));
      await waitWhile(() => bar.hidden);
      assert.equal(bar.hidden, false, "the choice waits in Changes to save");
      assert.match(doc.getElementById("files-pending-list").textContent, /deploy\.token/);
      assert.equal(old.isConnected, false, "the tree was drawn again from nothing");
      const kept = above.find((p) => p.isConnected);
      assert.equal(kept, tree, "the box the menu was drawn again in is the tree");
      assert.equal(kept.matches(sel), true, "which the served stylesheet takes out of anchoring");
      const menu = menuOf(doc, path);
      assert.equal(menu.value, "any-model", "the menu shows the choice waiting");
      assert.equal(doc.activeElement, menu, "the menu, drawn again, keeps the focus");
      pages.push(doc.body.textContent ?? "");

      doc.getElementById("files-discard").click();
      await waitWhile(() => !bar.hidden);
      assert.equal(bar.hidden, true);
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });
    assert.equal(readFileSync(policyPath, "utf8"), policy, "nothing was saved");

    // A3: the oracle.
    for (const path of ["/api/policy/panel", "/api/secrets", "/api/home"]) {
      bodies.push(await (await pageFetch(base + path, { headers: CSRF_ADMIN })).text());
    }
    assert.ok(bodies[0]!.includes("deploy.token"), "the panel answer names the rules");
    for (const t of [...pages, ...bodies]) assert.ok(!t.includes(KEY), "no page or answer carries the key");
  } finally {
    await dashboard.close();
    wired.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
