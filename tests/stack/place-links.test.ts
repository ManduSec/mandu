/**
 * place-links.test — a sentence on the product page that sends you
 * somewhere links that place, across the REAL components (dashboard.md
 * §4.25 *The hero links where it points*, §4.25p, §4.34). Mandu-new.
 *
 * A real ArbiterServer (`secrets` axes) holds a policy.yaml with no model
 * and two folder rules: `~/notes` at `local-model` (Your own AI only, so no
 * AI reads it) and `~/vault` at `no-model` with `ssh-add` as its reader. The
 * net-proxy's own secret-taint verdict over its production adapter files a
 * program's send question for `~/vault/key[1].txt`, a file under the folder
 * rule whose name reads as a pattern, so it takes no Always. A real DashboardServer over the production adapter
 * (`makeApprovalsArbiter`) serves the page (its own index.html and home.js
 * in jsdom), signed in:
 *
 *   P1  `/api/policy/panel`: the notes rule's warning keeps its words and
 *       comes as parts, "Settings › Models" a link part;
 *   P2  Rules: the notes row opened, its "Settings › Models" link opens
 *       Settings at the Models card with the focus on Add a model;
 *   P3  Approvals: the vault file's "Change it under Rules" links the file
 *       (`/rules?file=<path>`) and opens Rules with the rule that decides
 *       it open (its own, which the reader's first use wrote, else the
 *       folder's), the focus on its ⋯;
 *   P4  the oracle: no link's address and no page or answer read here
 *       carries the file's secret value.
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
import { ArbiterClientAdapter } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { secretTaintVerdict } from "../../interceptors/net-proxy/src/egress.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { NO_OWN_MODEL_WARNING } from "../../dashboard/src/view-model/model-endpoints.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const SESSION = "1791400000-558";
const H = "hooks.slack.com";
const VALUE = "sk_" + "live_placeLinksStackCanary0000000001";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const treeRow = (doc: Doc, path: string) => [...doc.querySelectorAll("#files-tree .row.file-rule")].find((r: Doc) => r.getAttribute("data-path") === path);
const hrefs = (doc: Doc): string[] => [...doc.querySelectorAll("a[href]")].map((a: Doc) => a.getAttribute("href"));

test("over the real arbiter: Settings › Models opens Settings at Add a model; Change it under Rules opens the rule of that file; no address carries a value", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-place-links-"));
  const home = join(tmp, "home");
  const notes = join(home, "notes");
  const vault = join(home, "vault");
  mkdirSync(notes, { recursive: true });
  mkdirSync(vault, { recursive: true });
  writeFileSync(join(notes, "plan.md"), "the plan\n");
  // Its name reads as a pattern, so Mandu writes no rule for it from the
  // card: it takes no Always, and the card says to change it under Rules.
  const key = join(vault, "key[1].txt");
  writeFileSync(key, `KEY=${VALUE}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1
paths:
  - { path: "${notes}", level: local-model, recursive: true }
  - { path: "${vault}", level: no-model, recursive: true, readers: [ssh-add] }
`);
  const dataSock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {},
    policyPath, policyPollMs: 0, confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const guard = await open(humanSock);
  const proxyArbiter = new ArbiterClientAdapter(await open(dataSock), await open(humanSock));
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: dataSock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter,
    policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home") },
    log: () => {},
    ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const signedIn = { headers: { Cookie: ADMIN_COOKIE } };
  const bodies: string[] = [];
  const read = async (path: string) => {
    const text = await (await pageFetch(base + path, { headers: { ...CSRF_ADMIN } })).text();
    bodies.push(text);
    return JSON.parse(text);
  };
  const links: string[] = [];
  try {
    // P1: the warning's words, and its parts.
    const panel = (await read("/api/policy/panel")).panel;
    const rule = panel.yourRules.find((r: { subject: string }) => r.subject === notes);
    assert.ok(rule, JSON.stringify(panel.yourRules.map((r: { subject: string }) => r.subject)));
    assert.equal(rule.warning, NO_OWN_MODEL_WARNING, "the words are unchanged");
    assert.equal(rule.warningParts.map((p: { text: string }) => p.text).join(""), rule.warning);
    assert.deepEqual(rule.warningParts.filter((p: { kind: string }) => p.kind === "link"), [{ kind: "link", text: "Settings › Models", to: "models" }]);

    // P2: Rules, the notes row opened: its link lands on Add a model.
    await servedProductPage(base, "/rules", (doc) => !!treeRow(doc, notes), async (doc) => {
      const mark = treeRow(doc, notes).querySelector(".file-warn-mark");
      assert.equal(mark.tagName, "BUTTON", "the ⚠ mark opens the row");
      mark.click();
      const warn = doc.querySelector("#files-tree .file-detail .rule-warn");
      assert.ok(warn, "the row opened, its warning said in full");
      assert.ok(warn.textContent.startsWith(NO_OWN_MODEL_WARNING), warn.textContent);
      const a = warn.querySelector("a");
      assert.deepEqual([a.textContent, a.getAttribute("href")], ["Settings › Models", "/settings#models"]);
      links.push(...hrefs(doc));
      a.click();
      await waitWhile(() => doc.activeElement !== doc.getElementById("model-open"));
      assert.equal(doc.defaultView.location.pathname, "/settings");
      assert.equal(doc.defaultView.location.hash, "#models");
      assert.equal(doc.activeElement, doc.getElementById("model-open"), "the focus is on Add a model");
      assert.equal(doc.activeElement.textContent, "Add a model");
      bodies.push(doc.documentElement.outerHTML);
    }, signedIn);

    // P3: a program that read the vault file sends it to a host its rule does not name.
    const d = await guard.decideSecretOpen({ path: key, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "py-1", session: SESSION });
    assert.equal(d.verdict, "raw", JSON.stringify(d));
    const sent = await secretTaintVerdict({ arbiter: proxyArbiter, holders: [{ procKey: "py-1", ancestors: [] }], destinationHost: H, sessionKey: SESSION });
    assert.equal(sent.action, "block");
    const askId = sent.action === "block" ? sent.withheld[0]!.approvalId : undefined;
    assert.ok(askId, JSON.stringify(sent));
    const card = ((await read("/api/home")) as HomeVM).waiting.find((a) => a.id === askId)!;
    assert.ok(card?.sources, "the card lists its file");
    const src = card.sources.find((s) => s.path === key)!;
    assert.ok(src, JSON.stringify(card.sources));
    assert.equal(src.always, undefined, "no Always for it");
    assert.match(src.noAlways ?? "", /reads as a pattern.*Change it under Rules\.$/);
    assert.deepEqual(src.noAlwaysParts!.filter((p) => p.kind === "link"), [{ kind: "link", text: "Change it under Rules", to: "rule", path: key }]);

    // The rule that decides the file: its own, when the reader's first use
    // wrote one (the arbiter pins the reader on the file), else the folder's.
    const subjects = (await read("/api/policy/panel")).panel.yourRules.map((r: { subject: string }) => r.subject);
    const decider = subjects.includes(key) ? key : vault;

    await servedProductPage(base, `/approvals/${encodeURIComponent(askId!)}`, (doc) => !!doc.querySelector(`#approvals-waiting .ask[data-id="${askId}"] .ask-source-why a`), async (doc) => {
      const a = doc.querySelector(`#approvals-waiting .ask[data-id="${askId}"] .ask-source-why a`);
      assert.equal(a.textContent, "Change it under Rules");
      assert.equal(a.getAttribute("href"), `/rules?file=${encodeURIComponent(key).replace(/%2F/g, "/")}`, "the address names the file only");
      links.push(...hrefs(doc));
      a.click();
      await waitWhile(() => !treeRow(doc, decider)?.classList.contains("open"));
      assert.equal(doc.defaultView.location.pathname, "/rules");
      const row = treeRow(doc, decider);
      assert.ok(row.classList.contains("open"), `the rule that decides the file is open (${decider})`);
      assert.equal(doc.querySelectorAll("#files-tree .row.file-rule.open").length, 1, "and only it");
      assert.equal(doc.activeElement, row.querySelector(".file-more"), "the focus on its ⋯");
      bodies.push(doc.documentElement.outerHTML);
    }, signedIn);

    // P4: the oracle.
    assert.ok(links.length > 0);
    for (const h of links) assert.ok(!h.includes(VALUE) && !h.includes(encodeURIComponent(VALUE)), h);
    for (const b of bodies) assert.ok(!b.includes(VALUE), "no page or answer carries the secret value");
  } finally {
    await dashboard.close();
    for (const c of clients) c.close();
    wired?.close();
    await arbiter.close();
    resetCurrentPolicyForTests("claude-code");
    rmSync(tmp, { recursive: true, force: true });
  }
});
