/**
 * home-js-rules-follow.test — Rules shows a rule change made elsewhere while
 * it is open (public/js/home.js `followRules`; dashboard.md §4.25 *Rules
 * follows a change made elsewhere*).
 *
 * Until 2026-10-28 Rules read your rules when it opened and after its own
 * changes, never on a poll: a file your agent made "No AI", or an Always
 * allow given in another tab, stayed missing until a reload. Now `/api/home`
 * carries `rulesVersion` and an open Rules page reads its rules again when
 * it moves:
 *
 *   F1  the same version: nothing is read again;
 *   F2  a new version: one read, the new row drawn, the line said, and its
 *       link opens Rule changes at the newest change;
 *   F3  a choice waiting to save keeps the rule version it was made
 *       against (its Save is still refused if that rule changed) and the
 *       bar still counts it;
 *   F4  an opened row stays open;
 *   F5  with the focus in Find a rule nothing is read until it leaves;
 *   F6  a server with no `rulesVersion`: nothing is read again;
 *   F7  a read the page asks itself (after its own save) never says the
 *       rules changed elsewhere, and takes the line away;
 *   F8  a newest change older than the drawn read gets no link.
 *
 * Drives the PRODUCT page script in jsdom over the shared fetch stub
 * (home-js-fixtures.ts). Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, tick, rowOf, openRule, RULES_PANEL, type Call } from "./home-js-fixtures.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const PENDING = "mandu.files.pending";
const STAGING = {
  id: "lock:/home/u/ws/deploy/staging.tfvars", kind: "lock", subject: "/home/u/ws/deploy/staging.tfvars", effect: "x", reach: null, hits: null,
  level: "no-model", bindings: [], version: "rv-new", actions: { remove: true, flip: null },
  plain: { subject: "/home/u/ws/deploy/staging.tfvars", reach: null, effect: "No AI may read it" },
};
const MEMO = RULES_PANEL.panel.yourRules[0]!;
const before = { panel: { ...RULES_PANEL.panel, yourRules: [{ ...MEMO, version: "rv-memo-1" }, ...RULES_PANEL.panel.yourRules.slice(1)] } };
const after = { panel: { ...before.panel, yourRules: [STAGING, { ...MEMO, version: "rv-memo-2", level: "no-model" }, ...before.panel.yourRules.slice(1)] } };

/** Rules open over a panel the test switches (`panel.now`), the newest rule
 *  change `newest`. */
async function rules(opts: { storage?: Record<string, string>; newest?: unknown } = {}) {
  const panel = { now: before as unknown };
  const page = load({
    url: "http://127.0.0.1:4500/mandu/rules",
    storage: opts.storage,
    homeVm: home({ rulesVersion: "v1" }),
    routes: {
      "GET policy/panel": () => panel.now,
      // Made after the drawn read (an hour ahead: a slow boot is still before it).
      "GET policy/changes?limit=1": { changes: opts.newest === undefined ? [{ id: "pc-000042", createdAt: Date.now() + 3_600_000 }] : [opts.newest] },
    },
  });
  assert.equal(page.err, null);
  await tick();
  // The first poll asked after the read the page opened with gives the
  // version the drawn rules are at.
  await poll(page.doc);
  return { ...page, panel };
}
async function poll(doc: Doc): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(30);
}
const panelReads = (calls: Call[]) => calls.filter((c) => c.url.endsWith("/api/policy/panel")).length;
const line = (doc: Doc) => doc.getElementById("rules-changed");

test("F1: the same rulesVersion on each poll reads nothing again and says nothing", async () => {
  const { doc, calls } = await rules();
  const n = panelReads(calls);
  assert.equal(n, 1, "Rules read once, when it opened");
  await poll(doc);
  await poll(doc);
  assert.equal(panelReads(calls), n, "no read while the version holds");
  assert.equal(line(doc).hidden, true);
  assert.equal(calls.some((c) => c.url.includes("policy/changes?limit=1")), false, "the newest change is read only on a follow");
});

test("F2: a new rulesVersion reads the rules once, draws the new rule and says so, with a link to Rule changes", async () => {
  const { window, doc, calls, setHome, panel } = await rules();
  assert.equal(rowOf(doc, /staging\.tfvars/), undefined);
  panel.now = after;
  setHome(home({ rulesVersion: "v2" }));
  const n = panelReads(calls);
  await poll(doc);
  assert.equal(panelReads(calls), n + 1, "one read");
  assert.match(doc.getElementById("rules-list").textContent + doc.getElementById("files-tree")?.textContent, /staging\.tfvars/, "the agent's new rule is drawn");
  assert.equal(line(doc).hidden, false);
  assert.match(line(doc).textContent, /^Your rules changed since this page was read\. It shows them now\./);
  assert.equal(line(doc).getAttribute("role"), "status");
  await poll(doc);
  assert.equal(panelReads(calls), n + 1, "the next poll at v2 reads nothing");
  const link = line(doc).querySelector("a");
  assert.equal(link.textContent, "See the change in Approvals");
  link.dispatchEvent(new window.MouseEvent("click", { bubbles: true, cancelable: true }));
  await tick();
  assert.match(window.location.pathname, /\/approvals\/pc-000042$/, "the link opens Rule changes at the change");
});

test("F3: a choice waiting to save keeps the rule version it was made against, and the bar still counts it", async () => {
  const wait = [{ path: "**/ws-*/memo/**", display: "**/ws-*/memo/**", level: "local-model", bindings: [], recursive: null, before: "Any AI, when it asks", target: null, version: "rv-memo-1" }];
  const { doc, setHome, panel, window } = await rules({ storage: { [PENDING]: JSON.stringify(wait) } });
  assert.equal(doc.getElementById("files-pending-count").textContent, "1");
  panel.now = after;
  setHome(home({ rulesVersion: "v2" }));
  await poll(doc);
  assert.equal(line(doc).hidden, false, "followed");
  assert.equal(doc.getElementById("files-pending-count").textContent, "1", "the choice still waits");
  const stored = JSON.parse(window.localStorage.getItem(PENDING));
  assert.equal(stored.length, 1);
  assert.equal(stored[0].version, "rv-memo-1", "not moved onto the new version: its Save is still refused as stale");
});

test("F4: an opened row stays open across the read", async () => {
  const { doc, setHome, panel } = await rules();
  openRule(doc, /paste\.example/);
  assert.equal(rowOf(doc, /paste\.example/).querySelector(".file-more").getAttribute("aria-expanded"), "true");
  panel.now = after;
  setHome(home({ rulesVersion: "v2" }));
  await poll(doc);
  assert.equal(line(doc).hidden, false, "followed");
  assert.equal(rowOf(doc, /paste\.example/).querySelector(".file-more").getAttribute("aria-expanded"), "true", "still open");
});

test("F5: with the focus in Find a rule nothing is read; the first poll after it leaves reads", async () => {
  const { doc, calls, setHome, panel } = await rules();
  const find = doc.getElementById("rules-find");
  find.focus();
  assert.equal(doc.activeElement, find);
  panel.now = after;
  setHome(home({ rulesVersion: "v2" }));
  const n = panelReads(calls);
  await poll(doc);
  await poll(doc);
  assert.equal(panelReads(calls), n, "not while typing");
  assert.equal(line(doc).hidden, true);
  assert.equal(doc.activeElement, find, "the focus stays where it was");
  find.blur();
  await poll(doc);
  assert.equal(panelReads(calls), n + 1, "read once the focus left");
  assert.equal(line(doc).hidden, false);
});

test("F6: a server with no rulesVersion keeps today's behaviour: nothing is read again", async () => {
  const page = load({ url: "http://127.0.0.1:4500/mandu/rules", routes: { "GET policy/panel": before } });
  await tick();
  const n = panelReads(page.calls);
  await poll(page.doc);
  page.setHome(home({}));
  await poll(page.doc);
  assert.equal(panelReads(page.calls), n);
  assert.equal(line(page.doc).hidden, true);
});

test("F7: a read the page asks itself (after its own save) takes the next version without the line, and takes the line away", async () => {
  const { window, doc, calls, setHome, panel } = await rules();
  panel.now = after;
  setHome(home({ rulesVersion: "v2" }));
  await poll(doc);
  assert.equal(line(doc).hidden, false);
  // The page's own change: its read again, then the version moves with it.
  await window.loadRules();
  await tick();
  assert.equal(line(doc).hidden, true, "a read of the page's own takes the line away");
  setHome(home({ rulesVersion: "v3" }));
  const n = panelReads(calls);
  await poll(doc);
  assert.equal(panelReads(calls), n, "the first poll after it gives the version, no read");
  assert.equal(line(doc).hidden, true, "never says a change of its own was made elsewhere");
  await poll(doc);
  assert.equal(panelReads(calls), n);
});

test("F8: the newest rule change older than the drawn read (an answer moved the version): the line has no link", async () => {
  const { doc, setHome, panel } = await rules({ newest: { id: "pc-000007", createdAt: Date.now() - 3_600_000 } });
  panel.now = after;
  setHome(home({ rulesVersion: "v2" }));
  await poll(doc);
  assert.equal(line(doc).hidden, false);
  assert.equal(line(doc).querySelector("a"), null);
});
