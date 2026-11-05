/**
 * rules-missing-path.test — across the REAL components, a rule whose path
 * has nothing on this computer says so on the product page's Rules, and only
 * that rule (dashboard.md §4.25f *A rule on nothing says so*). Mandu-new.
 *
 * A rule on `~/shop/.evn` (a typo for `.env`) was drawn exactly like the
 * rule on the real file: the person read "No AI" beside the name and took
 * the file for protected. Here a real ArbiterServer (secrets) holds a
 * policy.yaml with one rule on a real file and one on its misspelt sibling;
 * a real DashboardServer over the production adapter (`makeApprovalsArbiter`)
 * serves the Rules page (its own index.html and home.js in jsdom):
 *
 *   M1  /api/policy/panel marks the misspelt rule `missing`, not the real
 *       one, and keeps its reach and level;
 *   M2  the served page, signed out: the line under the misspelt rule only,
 *       with a file's icon, and its opened row says it;
 *   M3  once a file is created at that path, the next read of Rules (signed
 *       in) drops the line;
 *   M4  the oracle: neither the rendered pages nor the answers read here
 *       carry the key in the real file, or an 8-character run of it;
 *   M5  a rule made on the page (a label, through the real admin socket) on
 *       a moved project's `.env`: /api/secrets marks it `missing`, the
 *       served page draws the line under that row only, and once the file
 *       is back the next read drops it (M4's oracle covers these reads);
 *   M6  in M2's page: the folder holding the misspelt rule, folded, says
 *       "…, 1 on a path where nothing is"; the line under the Files and
 *       folders heading counts that rule only (not the real `.env`), and
 *       its button unfolds the folder and opens the row with the line;
 *       in M3's page the heading line is gone;
 *   M7  in M2's page, Who may get your secrets marks the misspelt rule's
 *       file "(nothing at this path)" on each tab (Programs, Hosts, AI),
 *       and its button's name says it too; never the real `.env`; in M3's
 *       page the mark is gone (queue item #225).
 *
 * Axes: secrets (stated).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { randomSecretBody } from "../../arbiter/test/helpers/random-secret.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

// Assembled at run time: this file holds no key-shaped literal.
const BODY = randomSecretBody(36);
const TOKEN = "gh" + "p_" + BODY;
const RUNS = Array.from({ length: BODY.length - 7 }, (_, i) => BODY.slice(i, i + 8));
const LINE = "Nothing at this path on this computer. The rule applies if something appears here; if you meant another file, check the spelling.";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const treeRow = (doc: Doc, path: string) => [...doc.querySelectorAll("#files-tree .row.file-rule")].find((r: Doc) => r.getAttribute("data-path") === path);
const menuIn = (row: Doc) => row?.querySelector("select.label-select:not(.send-select)");
const missingLine = (row: Doc) => row.querySelector(".file-missing")?.textContent as string | undefined;
const icon = (row: Doc) => row.querySelector(".row-icon").innerHTML as string;
const shopHead = (doc: Doc) => [...doc.querySelectorAll("#files-tree .rules-folder")].find((f: Doc) => f.title === "~/shop");
const WHO_TABS = ["Programs", "Hosts", "AI"];
/** M7: on each tab of Who may get your secrets, every item naming `name`
 *  (its text, its button's name), in the order drawn. */
const byWhoItems = (doc: Doc, name: string) => WHO_TABS.map((tab, i) => {
  doc.getElementById("by-who-block").querySelectorAll("[role=tab]")[i].click();
  const items = [...doc.querySelectorAll("#by-who-list li")].filter((li: Doc) => li.querySelector("code")?.textContent === name);
  return { tab, items: items.map((li: Doc) => ({ text: li.textContent as string, label: li.querySelector("button")?.getAttribute("aria-label") as string | undefined })) };
});

test("Rules over the real arbiter: only the rule on a misspelt path says nothing is there, and the line goes once something is", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rules-missing-"));
  const home = join(tmp, "home");
  const shop = join(home, "shop");
  mkdirSync(join(shop, "config"), { recursive: true });
  const env = join(shop, ".env");
  writeFileSync(env, `API_TOKEN=${TOKEN}\n`);
  const typo = join(shop, ".evn");
  const folder = join(shop, "config");
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, [
    "version: 1",
    "paths:",
    `  - path: ${env}`,
    "    level: no-model",
    "    bindings: [api.stripe.com]",
    `  - path: ${typo}`,
    "    level: no-model",
    "    bindings: [api.stripe.com]",
    `  - path: ${folder}`,
    "    level: no-model",
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
  const bodies: string[] = [];
  const pages: string[] = [];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const panelRow = async (path: string): Promise<any> => {
    const r = await pageFetch(base + "/api/policy/panel", { headers: CSRF_ADMIN });
    const text = await r.text();
    bodies.push(text);
    return (JSON.parse(text).panel.yourRules as Array<{ id: string }>).find((x) => x.id === `lock:${path}`);
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const labelRow = async (path: string): Promise<any> => {
    const r = await pageFetch(base + "/api/secrets", { headers: CSRF_ADMIN });
    const text = await r.text();
    bodies.push(text);
    return (JSON.parse(text).panel.labels as Array<{ path: string }>).find((x) => x.path === path);
  };
  const ready = (doc: Doc) => [env, typo, folder].every((p) => !!menuIn(treeRow(doc, p)))
    && !!doc.querySelector("#by-who-list .by-who-row");
  const admin = new ArbiterClient(adminSock);
  try {
    // M1: the answer.
    const typoRow = await panelRow(typo);
    assert.equal(typoRow.missing, true, "nothing at the misspelt path");
    assert.deepEqual([typoRow.covers, typoRow.level, typoRow.plain.reach], ["subtree", "no-model", "and everything inside"], "the rule as written");
    assert.equal((await panelRow(env)).missing, undefined, "the real file");
    assert.equal((await panelRow(folder)).missing, undefined, "the real folder");

    // M2: the served page, signed out.
    await servedProductPage(base, "/rules", ready, async (doc) => {
      assert.equal(missingLine(treeRow(doc, typo)), LINE);
      assert.equal(missingLine(treeRow(doc, env)), undefined);
      assert.equal(missingLine(treeRow(doc, folder)), undefined);
      assert.equal(icon(treeRow(doc, typo)), icon(treeRow(doc, env)), "a file's icon");
      assert.notEqual(icon(treeRow(doc, typo)), icon(treeRow(doc, folder)), "never the folder's");
      treeRow(doc, typo).querySelector(".file-more").click();
      const box = doc.querySelector("#files-tree .file-detail").textContent as string;
      assert.ok(box.includes(LINE), "the opened row says it");
      assert.doesNotMatch(box, /A folder's rule covers everything inside it/);
      pages.push(doc.body.textContent ?? "");

      // M6: a fold no longer hides it, and the heading line takes you there.
      treeRow(doc, typo).querySelector(".file-more").click();
      shopHead(doc).click();
      assert.equal(shopHead(doc).getAttribute("aria-expanded"), "false", "folded");
      assert.equal(shopHead(doc).querySelector(".dim").textContent, "3 rules, 1 on a path where nothing is");
      const note = doc.getElementById("files-missing");
      assert.equal(note.hidden, false);
      assert.equal(note.textContent, "1 rule names a path where nothing is on this computer: ~/shop/.evn.", "the real .env is not counted");
      note.querySelector("button").click();
      assert.equal(shopHead(doc).getAttribute("aria-expanded"), "true", "unfolded");
      const row = treeRow(doc, typo);
      assert.ok(row.classList.contains("open"), "the row is opened");
      assert.ok((doc.querySelector("#files-tree .file-detail").textContent as string).includes(LINE), "with the line");
      assert.equal(doc.activeElement, row.querySelector(".file-more"), "the focus is on its ⋯");
      pages.push(doc.body.textContent ?? "");

      // M7: Who may get your secrets marks the misspelt rule only, on each tab.
      for (const { tab, items } of byWhoItems(doc, "~/shop/.evn")) {
        assert.ok(items.length > 0, `${tab}: ~/shop/.evn is listed`);
        for (const it of items) {
          assert.match(it.text, /^~\/shop\/\.evn .*\(nothing at this path\)$/, `${tab}: ${it.text}`);
          assert.equal(it.label, "Show the rule for ~/shop/.evn in Your rules (nothing at this path)", tab);
        }
      }
      for (const { tab, items } of byWhoItems(doc, "~/shop/.env")) {
        assert.ok(items.length > 0, `${tab}: ~/shop/.env is listed`);
        for (const it of items) {
          assert.doesNotMatch(it.text, /nothing at this path/, `${tab}: the real file`);
          assert.equal(it.label, "Show the rule for ~/shop/.env in Your rules", tab);
        }
      }
      pages.push(doc.body.textContent ?? "");
    });

    // M3: something appears at the path; the next read drops the line.
    writeFileSync(typo, "nothing secret here\n");
    assert.equal((await panelRow(typo)).missing, undefined);
    await servedProductPage(base, "/rules", ready, async (doc) => {
      for (const p of [env, typo, folder]) assert.equal(missingLine(treeRow(doc, p)), undefined, p);
      assert.ok(!(doc.body.textContent as string).includes(LINE));
      assert.equal(doc.getElementById("files-missing").hidden, true, "M6: no heading line");
      assert.doesNotMatch(shopHead(doc).querySelector(".dim").textContent, /nothing/);
      // M7: the file is there now: no mark, on any tab.
      for (const { tab, items } of byWhoItems(doc, "~/shop/.evn")) {
        assert.ok(items.length > 0, `${tab}: ~/shop/.evn is listed`);
        for (const it of items) {
          assert.doesNotMatch(it.text, /nothing at this path/, tab);
          assert.equal(it.label, "Show the rule for ~/shop/.evn in Your rules", tab);
        }
      }
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // M5: a rule made on the page, on a project that was then moved away.
    const moved = join(home, "old-shop", ".env");
    mkdirSync(join(home, "old-shop"));
    writeFileSync(moved, "nothing secret here\n");
    await admin.connect();
    await admin.setPathLabel({ path: moved, confidentiality: "no-model" });
    rmSync(join(home, "old-shop"), { recursive: true });
    const movedRow = await labelRow(moved);
    assert.equal(movedRow?.missing, true, "/api/secrets marks the page-made rule on nothing");
    assert.deepEqual([movedRow.scope, movedRow.level, movedRow.source], ["subtree", "no-model", "user"], "the rule as made");
    const withMoved = (doc: Doc) => ready(doc) && !!menuIn(treeRow(doc, moved));
    await servedProductPage(base, "/rules", withMoved, async (doc) => {
      assert.equal(missingLine(treeRow(doc, moved)), LINE);
      for (const p of [env, typo, folder]) assert.equal(missingLine(treeRow(doc, p)), undefined, p);
      assert.equal(icon(treeRow(doc, moved)), icon(treeRow(doc, env)), "a file's icon");
      treeRow(doc, moved).querySelector(".file-more").click();
      assert.ok((doc.querySelector("#files-tree .file-detail").textContent as string).includes(LINE), "the opened row says it");
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });
    mkdirSync(join(home, "old-shop"));
    writeFileSync(moved, "nothing secret here\n");
    assert.equal((await labelRow(moved))?.missing, undefined, "something is there again");
    await servedProductPage(base, "/rules", withMoved, async (doc) => {
      assert.ok(!(doc.body.textContent as string).includes(LINE));
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // M4: the oracle.
    for (const text of [...pages, ...bodies]) {
      assert.ok(!text.includes(TOKEN), "no page or answer carries the key");
      assert.equal(RUNS.find((r) => text.includes(r)), undefined, "no page or answer carries an 8-character run of the key");
    }
  } finally {
    admin.close();
    await dashboard.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
