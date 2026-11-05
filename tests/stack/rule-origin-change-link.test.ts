/**
 * rule-origin-change-link.test — an opened rule's origin line on Rules
 * ("You added this on the Rules page, …") links that change in Approvals,
 * where its Rule changes row is marked with its Undo, across the REAL
 * components (dashboard.md §4.25i). Mandu-new.
 *
 * Until 2026-10-23 the line named a recorded change you could undo, but
 * linked it nowhere: you opened Approvals and looked for the row by its
 * words. Here a real ArbiterServer runs at the `secrets` axes with `.env`
 * at `no-model` in policy.yaml. A real DashboardServer reaches it over the
 * production adapter (`makeApprovalsArbiter`), and the served product page
 * (its own index.html and home.js in jsdom, signed in):
 *
 *   O1  a file locked on the Rules page (`POST /api/files/labels`, a
 *       tightening, made at once): its opened row's origin line ends with
 *       "See this change in Approvals", named by the file, linking
 *       `/approvals/<changeId>`, the id the arbiter returned;
 *   O2  following it opens Approvals with that change's row marked under
 *       Rule changes, Undo on it, and no note;
 *   O3  Undo pressed there: the arbiter's panel loses the rule;
 *   O5  the file locked again (a second change to it): its origin line now
 *       also has "Find its changes" (`/approvals?changes=~/proj/deploy.key`),
 *       which opens Approvals with Rule changes searched for that path: both
 *       changes listed, the Undo between them too (a change of its own),
 *       and the count line ("3 of 3 changes match");
 *       Back returns to Rules (§4.25 *Finding a rule change*);
 *   O6  an agent's send rule (`release` to `pastebin.example`) and its
 *       connection made with no port (`allow-connect` `pypi.example`, shown
 *       on Rules as `pypi.example:443`), each held and then approved over
 *       the dashboard's route: each opened row's origin line has "Find its
 *       changes", searched for its host (`?changes=pastebin.example`,
 *       `?changes=pypi.example`), and the Approvals it opens lists that
 *       change;
 *   O4  the oracle: `.env`'s value is on no page, nor in any answer read
 *       here; no page draws a token.
 *
 * Axes: secrets (stated).
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
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const ENV_VALUE = "ruleOriginChangeLinkEnvValue00000001";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const treeRow = (doc: Doc, path: string) => [...doc.querySelectorAll("#files-tree .row.file-rule")].find((r: Doc) => r.getAttribute("data-path") === path);
const marked = (doc: Doc) => [...doc.querySelectorAll("#page-approvals .focus")].map((x: Doc) => x.dataset.id);

test("a rule's origin line links its change in Approvals, marked with its Undo, and that Undo takes the rule away (real arbiter, dashboard); no secret on either page", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rule-origin-link-"));
  const home = join(tmp, "home");
  const proj = join(home, "proj");
  mkdirSync(proj, { recursive: true });
  const env = join(proj, ".env");
  writeFileSync(env, `DB_PASSWORD=${ENV_VALUE}\n`);
  const key = join(proj, "deploy.key");
  writeFileSync(key, "FAKE KEY FOR THE TEST\n");
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${env}\n    level: no-model\n`);
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
  const call = async (method: "GET" | "POST", path: string, body?: unknown) => {
    const r = await pageFetch(base + path, { method, headers: { ...CSRF_ADMIN, ...(body !== undefined ? { "Content-Type": "application/json" } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    const text = await r.text();
    bodies.push(text);
    assert.equal(r.status, 200, `${path}: ${text}`);
    return JSON.parse(text);
  };
  const lockRow = async () => ((await call("GET", "/api/policy/panel")).panel.yourRules as Array<{ id: string }>).find((r) => r.id === `lock:${key}`);
  const unhandled: string[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", onUnhandled);
  try {
    // O1: the file is locked on the Rules page (a tightening: made at once).
    const saved = await call("POST", "/api/files/labels", { changes: [{ path: key, level: "no-model", recursive: false }] });
    assert.equal(saved.applied, true, JSON.stringify(saved));
    const changeId = String(saved.changeId);
    assert.match(changeId, /^pc-\d{6}$/);
    assert.ok(await lockRow(), "the arbiter's panel has the rule");
    const origins = await call("GET", "/api/policy/rules/origins");
    assert.equal(origins.origins[`lock:${key}`]?.changeId, changeId, "the origin names the change that wrote it");

    await servedProductPage(base, "/rules", (doc: Doc) => !!treeRow(doc, key), async (doc: Doc) => {
      treeRow(doc, key).querySelector(".file-more").click();
      const line = doc.querySelector("#files-tree .file-detail .rule-origin");
      assert.ok(line, "the opened row has its origin line");
      assert.match(line.textContent, /^You added this on the Rules page, .+\. See this change in Approvals · Find its changes$/);
      const a = line.querySelector("a.change-link");
      assert.equal(a.getAttribute("href"), `/approvals/${changeId}`);
      assert.equal(a.getAttribute("aria-label"), "See this change in Approvals: ~/proj/deploy.key");
      pages.push(doc.documentElement.outerHTML);

      // O2: Approvals, at that change, marked, with its Undo.
      a.click();
      await waitWhile(() => !marked(doc).includes(changeId));
      assert.equal(doc.getElementById("page-approvals").hidden, false, "Approvals is open");
      assert.equal(doc.defaultView.location.pathname, `/approvals/${changeId}`);
      assert.deepEqual(marked(doc), [changeId]);
      const row = doc.querySelector("#approvals-rule-history .row.focus");
      assert.ok(row, "its Rule changes row");
      assert.equal(doc.getElementById("approvals-focus-note").hidden, true, "no note");
      const undo = [...row.querySelectorAll("button")].find((b: Doc) => b.textContent === "Undo");
      assert.ok(undo, "Undo on it");
      pages.push(doc.documentElement.outerHTML);

      // O3: Undo, pressed there.
      undo.click();
      await waitWhile(() => !/Undone/.test(doc.querySelector(`#approvals-rule-history .row[data-id="${changeId}"]`)?.textContent ?? ""));
      pages.push(doc.documentElement.outerHTML);
    }, { headers: { Cookie: ADMIN_COOKIE } });
    assert.equal(await lockRow(), undefined, "the arbiter's panel lost the rule");
    assert.doesNotMatch(readFileSync(policyPath, "utf8"), /deploy\.key/, "policy.yaml no longer has it");

    // O5: the same file locked again; its rule's Find its changes lists both.
    const again = await call("POST", "/api/files/labels", { changes: [{ path: key, level: "no-model", recursive: false }] });
    assert.equal(again.applied, true, JSON.stringify(again));
    const second = String(again.changeId);
    assert.notEqual(second, changeId);
    await servedProductPage(base, "/rules", (doc: Doc) => !!treeRow(doc, key), async (doc: Doc) => {
      treeRow(doc, key).querySelector(".file-more").click();
      await waitWhile(() => !doc.querySelector("#files-tree .file-detail .rule-origin a.change-find-link"));
      const line = doc.querySelector("#files-tree .file-detail .rule-origin");
      assert.equal(line.querySelector("a.change-link").getAttribute("href"), `/approvals/${second}`, "the newest change");
      const find = line.querySelector("a.change-find-link");
      assert.equal(find.textContent, "Find its changes");
      assert.equal(find.getAttribute("href"), "/approvals?changes=~%2Fproj%2Fdeploy.key#rule-changes");
      pages.push(doc.documentElement.outerHTML);
      find.click();
      const found = () => [...doc.querySelectorAll("#approvals-rule-history .row.answered")].map((r: Doc) => r.dataset.id);
      await waitWhile(() => found().length < 3 || doc.getElementById("changes-count").hidden);
      assert.equal(doc.getElementById("page-approvals").hidden, false, "Approvals is open");
      assert.equal(doc.getElementById("changes-q").value, "~/proj/deploy.key", "the box holds the path");
      assert.equal(found().length, 3, "the two locks and the Undo between them");
      assert.ok(found().includes(changeId) && found().includes(second), "both changes to the file");
      assert.equal(doc.getElementById("changes-count").textContent, "3 of 3 changes match");
      pages.push(doc.documentElement.outerHTML);
      doc.defaultView.history.back();
      await waitWhile(() => doc.defaultView.location.pathname !== "/rules");
      await waitWhile(() => doc.getElementById("page-rules").hidden);
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // O6: an agent's send rule and its portless connection, each approved
    // over the dashboard's route, find their changes by their host.
    const agent = new ArbiterClient(socketPath);
    await agent.connect();
    const approved: Record<string, string> = {};
    try {
      for (const [host, edit] of [
        ["pastebin.example", { op: "release", to: { host: "pastebin.example" }, mode: "allow" }],
        ["pypi.example", { op: "allow-connect", host: "pypi.example" }],
      ] as const) {
        const asked = await agent.policyPropose({ edits: [edit], reason: "o6", sessionKey: "s-o6" });
        assert.ok(!asked.applied && "proposalId" in asked, `a loosening waits for you: ${JSON.stringify(asked)}`);
        const ok = await call("POST", `/api/policy/proposals/${asked.proposalId}`, { verdict: "approved" });
        approved[host] = String(ok.changeId);
        assert.match(approved[host]!, /^pc-\d{6}$/, JSON.stringify(ok));
      }
    } finally {
      agent.close();
    }
    const listRow = (doc: Doc, text: string) => [...doc.querySelectorAll("#rules-list .row")].find((r: Doc) => r.textContent.includes(text));
    for (const [shown, host] of [["pastebin.example", "pastebin.example"], ["pypi.example:443", "pypi.example"]] as const) {
      await servedProductPage(base, "/rules", (doc: Doc) => !!listRow(doc, shown), async (doc: Doc) => {
        listRow(doc, shown).querySelector(".file-more").click();
        await waitWhile(() => !listRow(doc, shown).nextElementSibling?.querySelector(".rule-origin a.change-find-link"));
        const line = listRow(doc, shown).nextElementSibling.querySelector(".rule-origin");
        assert.equal(line.querySelector("a.change-link").getAttribute("href"), `/approvals/${approved[host]}`, `${shown}: its change`);
        const find = line.querySelector("a.change-find-link");
        assert.equal(find.getAttribute("href"), `/approvals?changes=${host}#rule-changes`, `${shown}: searched for its host`);
        assert.equal(find.getAttribute("aria-label"), `Find its changes: ${shown}`);
        pages.push(doc.documentElement.outerHTML);
        find.click();
        const found = () => [...doc.querySelectorAll("#approvals-rule-history .row.answered")].map((r: Doc) => r.dataset.id);
        await waitWhile(() => doc.getElementById("changes-q")?.value !== host || !found().includes(approved[host]!));
        assert.equal(doc.getElementById("page-approvals").hidden, false, "Approvals is open");
        assert.deepEqual(found(), [approved[host]], `${shown}: the change that made it, and nothing else`);
        pages.push(doc.documentElement.outerHTML);
      }, { headers: { Cookie: ADMIN_COOKIE } });
    }

    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // O4: the oracle.
    assert.equal(pages.length, 9);
    for (const text of [...pages, ...bodies]) assert.ok(!text.includes(ENV_VALUE), "CONFIDENTIALITY VIOLATION: .env's value in a page or an answer");
    // The panel's answer explains the token format in words; a page never draws one.
    for (const text of pages) assert.doesNotMatch(text, /\$MDU:/, "nor a token on a page");
  } finally {
    process.off("unhandledRejection", onUnhandled);
    await dashboard.close();
    wired?.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
