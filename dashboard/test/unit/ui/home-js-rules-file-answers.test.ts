/**
 * home-js-rules-file-answers.test — dashboard.md §4.25n *A file's row names
 * your answers about it* (2026-10-30). Until then a file's row under Rules ›
 * Your rules answered *Where it may be sent* from the label's hosts alone:
 * a `.env` with no hosts read *Needs your OK* while an Always allow answer
 * about that same file let it go to a host without asking, said only under
 * *Sending data*, in another group, ordered by host. Now:
 *
 *   A1  under the second menu, a line names the standing send answers about
 *       that exact file, in the panel order (newest first, as Sending data
 *       lists them): each host as code, then the mark
 *       and words its Sending data row has (✓ Always allowed, ✗ Always
 *       blocked); the menu itself is unchanged (*Needs your OK*);
 *   A2  each host links `/rules#answer-<id>`; a plain click opens that
 *       answer's row under Sending data (openAnswerRule), a modifier click
 *       is the browser's;
 *   A3  left out: a once answer, a waiting one, one that no longer applies,
 *       one about another file or an environment variable, a program's
 *       (`holder-send:`) and a session's (`session-net:`);
 *   A4  a folder rule with an answer about a file inside shows nothing;
 *   A5  four answers: the first three, then "and 1 more";
 *   A6  the send menu is described by the line (aria-describedby);
 *   A7  a Not secret row shows no line;
 *   A8  the browse list row of the same path shows it too, under an
 *       inherited menu; a Per value row adds it after its own line, both
 *       describing the menu.
 *
 * And the sends of that file that wait for your answer (the same section,
 * *And the sends of it that wait*), a second line under the first:
 *
 *   W1  two waiting sends of the row's file: "Waiting for your answer:"
 *       and both hosts, newest first, each a link to its question in
 *       Approvals (`/approvals/<id>`, `data-ask`); a plain click opens
 *       Approvals there, a modifier click is the browser's; an answered
 *       send stays in "Your answers:" only, and the menu is described by
 *       both lines;
 *   W2  left out: a waiting send of another file, a program's
 *       (`holder-send:`) or a session's (`session-net:`, `session-exec:`)
 *       question, an `env:` origin, one that no longer applies, a waiting
 *       question that is not a send;
 *   W3  four waiting: the first three, then "and 1 more", a link to
 *       Approvals itself;
 *   W4  a host asked twice is named once, by its newest question;
 *   W5  a folder row, and a Not secret row, have no line;
 *   W6  under Listed hosts and under Per value too, after the answers line.
 *
 * And it follows a send that starts or stops waiting while Rules stays open
 * (queue item #284): `rulesVersion` leaves the questions waiting out, so the
 * Home poll's waiting ids read your rules again (followFileWaiting):
 *
 *   W7  a poll whose waiting gains an id, the panel now listing a pending
 *       send of the file: the line appears under the row of Your rules (no
 *       folder open) and of the open folder, with its link and the menu's
 *       description; the focus back on its menu (pollRefocus), and
 *       no "Your rules changed" line;
 *   W8  a poll whose waiting loses it, the panel showing it answered once:
 *       the line goes; a "Your rules changed" line already shown stays;
 *   W9  a poll with the same ids, in any order, reads no panel;
 *   W10 the focus in Find a rule: no read on that poll, the first poll after
 *       it leaves reads; a hidden tab reads nothing, the first poll after
 *       its return reads;
 *   W11 a Home answer that does not know the questions waiting yet takes
 *       nothing: the first poll that knows them, with one waiting, reads.
 *
 * Drives the PRODUCT page script in jsdom over the shared fetch stub
 * (home-js-fixtures.ts); across the real arbiter and dashboard,
 * tests/stack/rules-file-answers.test.ts. Axes: none (display only).
 * Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { ASK, FILES_ROUTES, home, load, rowFor, tick, treeRow } from "./home-js-fixtures.js";

const RULES = "http://127.0.0.1:4500/mandu/rules";
const ENV = "/home/u/ws/.env";

/** A file or folder rule of yours as `/api/policy/panel` sends it. */
function lock(path: string, more: Record<string, unknown> = {}) {
  return {
    id: `lock:${path}`, kind: "lock", subject: path, reach: null, hits: null, covers: "exact", level: "no-model", bindings: [],
    effect: "x", actions: { remove: true, flip: null },
    plain: { subject: path, reach: "this file only", effect: "No AI" }, ...more,
  };
}
/** A standing send answer as the panel's queue sends it (policy-panel.ts). */
function answer(id: string, host: string, approved: boolean, more: Record<string, unknown> = {}) {
  const origin = (more.origin as string | undefined) ?? ENV;
  return {
    id, status: approved ? "approved" : "denied", scope: "always", where: "network", subject: `$MDU:ENV_${id}`, target: host, origin,
    count: 1, sessions: [], resolvedAt: null, actions: [{ approve: !approved, label: approved ? "Block instead" : "Allow instead" }],
    plain: { subject: host, reach: `sending only the file ${origin}`, effect: approved ? "Always allowed" : "Always blocked" }, ...more,
  };
}
function page(yourRules: unknown[], queue: unknown[], routes: Record<string, unknown> = {}) {
  return load({ url: RULES, routes: { ...routes, "GET policy/panel": { panel: { available: true, verdictsKnown: true, queue, yourRules } } } });
}
const lineOf = (row: any) => row.querySelector(".file-answers");
/** The line with each host as `[host]`, its marks as ✓ / ✗. */
function drawn(node: any): string {
  let out = "";
  const walk = (n: any) => {
    for (const k of n.childNodes) {
      if (k.nodeType === 3) out += k.textContent;
      else if (k.tagName === "CODE") out += `[${k.textContent}]`;
      else if (k.tagName?.toLowerCase() === "svg") out += k.parentElement.classList.contains("ok") ? "✓ " : "✗ ";
      else walk(k);
    }
  };
  walk(node);
  return out;
}

test("A1: a file's row names its allowed and blocked answers in order, in Sending data's words and colours, under an unchanged menu", async () => {
  const { doc } = page([lock(ENV)], [answer("egr-1", "api.stripe.com", true), answer("egr-2", "hooks.zapier.com", false)]);
  await tick();
  const row = treeRow(doc, /\.env$/);
  const sel = row.querySelector("select.send-select");
  assert.equal(sel.value, "ask", "the menu still reads Needs your OK");
  assert.equal(sel.selectedOptions[0].textContent, "Needs your OK");
  const line = lineOf(row);
  assert.ok(line, "the row has the line");
  assert.ok(line.classList.contains("dim"), "in the row's secondary ink");
  assert.equal(drawn(line), "Your answers: [api.stripe.com] ✓ Always allowed · [hooks.zapier.com] ✗ Always blocked");
  const effects = [...line.querySelectorAll(".outcome")] as any[];
  assert.deepEqual(effects.map((e) => e.className), ["outcome ok", "outcome bad"], "the colours of their Sending data rows");
  // The same words as the rows under Sending data.
  const sendRows = [...doc.querySelectorAll("#rules-list .row[data-rule]")] as any[];
  for (const [id, words] of [["egr-1", "Always allowed"], ["egr-2", "Always blocked"]]) {
    const r = sendRows.find((x) => x.getAttribute("data-rule") === `answer:${id}`);
    assert.ok(r, `${id} is listed under Sending data`);
    assert.match(r.textContent, new RegExp(words!));
  }
  assert.equal(line.parentElement, row.querySelector(".file-hosts"), "under the second menu, in its cell");
});

test("A2: each host links /rules#answer-<id>; a plain click opens that answer's row, a modifier click is the browser's", async () => {
  const { doc, window } = page([lock(ENV)], [answer("egr-1", "api.stripe.com", true), answer("egr-2", "hooks.zapier.com", false)]);
  await tick();
  window.HTMLElement.prototype.scrollIntoView = function () { /* jsdom has no layout */ };
  const links = [...lineOf(treeRow(doc, /\.env$/)).querySelectorAll("a")] as any[];
  assert.deepEqual(links.map((a) => a.getAttribute("href")), ["/mandu/rules#answer-egr-1", "/mandu/rules#answer-egr-2"]);
  assert.deepEqual(links.map((a) => a.textContent), ["api.stripe.com", "hooks.zapier.com"]);
  // A modifier click is left to the browser (a new tab at the same place).
  const ctrl = new window.MouseEvent("click", { bubbles: true, cancelable: true, ctrlKey: true });
  links[1].dispatchEvent(ctrl);
  assert.equal(ctrl.defaultPrevented, false);
  links[1].click();
  await tick(30);
  const row = ([...doc.querySelectorAll("#rules-list .row[data-rule]")] as any[]).find((r) => r.getAttribute("data-rule") === "answer:egr-2");
  assert.ok(row && row.classList.contains("open"), "the answer's row is open");
  assert.equal(doc.querySelectorAll("#rules-list .rule-detail").length, 1, "only that row");
  assert.equal(doc.activeElement, row.querySelector(".file-more"), "the focus on its ⋯");
});

test("A3: once, waiting, no-longer-applies, another file, env:, holder-send: and session-net: answers are left out", async () => {
  const queue = [
    answer("keep", "api.stripe.com", true),
    answer("once", "once.example", true, { scope: "once" }),
    answer("wait", "wait.example", true, { status: "pending" }),
    answer("stale", "stale.example", true, { noLongerApplies: "name-only", staleNote: "This answer no longer applies." }),
    answer("other", "other.example", false, { origin: "/home/u/ws/other.env" }),
    answer("envvar", "env.example", false, { origin: "env:STRIPE_KEY" }),
    answer("holder", "holder.example", true, { subject: "holder-send:s1#abc" }),
    answer("session", "session.example", true, { subject: "session-net:s1" }),
  ];
  const { doc } = page([lock(ENV)], queue);
  await tick();
  assert.equal(drawn(lineOf(treeRow(doc, /\.env$/))), "Your answers: [api.stripe.com] ✓ Always allowed");
});

test("A4: a folder rule with an answer about a file inside shows nothing", async () => {
  const { doc } = page([lock("/home/u/ws/config", { covers: "subtree", plain: { subject: "/home/u/ws/config", reach: "this folder", effect: "No AI" } })],
    [answer("egr-1", "api.stripe.com", true, { origin: "/home/u/ws/config/db.yaml" }), answer("egr-2", "b.example", true, { origin: "/home/u/ws/config" })]);
  await tick();
  const row = treeRow(doc, /config/);
  assert.ok(row, "the folder row is drawn");
  assert.equal(lineOf(row), null);
  assert.equal(row.querySelector("select.send-select").getAttribute("aria-describedby"), null);
});

test("A5: four answers show the first three, then and 1 more", async () => {
  const { doc } = page([lock(ENV)], [
    answer("a1", "a.example", true), answer("a2", "b.example", false), answer("a3", "c.example", true), answer("a4", "d.example", false),
  ]);
  await tick();
  const line = lineOf(treeRow(doc, /\.env$/));
  assert.equal(drawn(line), "Your answers: [a.example] ✓ Always allowed · [b.example] ✗ Always blocked · [c.example] ✓ Always allowed · and 1 more");
  assert.equal(line.querySelectorAll("a").length, 3);
});

test("A6: the send menu is described by the line; a row with no answers has no description", async () => {
  const { doc } = page([lock(ENV), lock("/home/u/ws/b.env")], [answer("egr-1", "api.stripe.com", true)]);
  await tick();
  const row = treeRow(doc, /ws\/\.env$|^\.env$/);
  const line = lineOf(row);
  const sel = row.querySelector("select.send-select");
  assert.ok(line.id);
  assert.equal(sel.getAttribute("aria-describedby"), line.id);
  assert.equal(doc.querySelectorAll(`[id="${line.id}"]`).length, 1, "the id is the page's only one");
  const other = treeRow(doc, /b\.env$/);
  assert.equal(lineOf(other), null);
  assert.equal(other.querySelector("select.send-select").getAttribute("aria-describedby"), null);
});

test("A7: a Not secret row shows no line", async () => {
  const { doc } = page([lock(ENV, { level: "public", plain: { subject: ENV, reach: "this file only", effect: "Not secret" } })], [answer("egr-1", "api.stripe.com", true)]);
  await tick();
  const row = treeRow(doc, /\.env$/);
  assert.equal(row.querySelector("select.send-select").value, "public");
  assert.equal(lineOf(row), null);
});

test("A8: the browse list row of the same path shows the line under its inherited menu; a Per value row adds it after its own line", async () => {
  const { doc } = page([], [answer("egr-1", "api.stripe.com", true)], FILES_ROUTES);
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  (doc.getElementById("lock-path") as any).value = "/home/u/ws";
  doc.getElementById("files-go").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
  await tick();
  const row = rowFor(doc, /^\.env/);
  assert.ok(row, "the browse row is drawn");
  assert.equal(row.querySelector(".send-pick").getAttribute("data-from"), "ask", "inherited from the built-in rule");
  const line = lineOf(row);
  assert.equal(drawn(line), "Your answers: [api.stripe.com] ✓ Always allowed");
  assert.equal(row.querySelector("select.send-select").getAttribute("aria-describedby"), line.id);
  // README.md has no label: nothing is withheld, no line.
  assert.equal(lineOf(rowFor(doc, /^README\.md/)), null);
  // The folder row: none, though an answer names a file inside it.
  assert.equal(lineOf(rowFor(doc, /^config/)), null);

  const values = [{ key: "STRIPE_KEY", bindings: ["api.stripe.com"] }];
  const perValue = page([lock(ENV, { values, plain: { subject: ENV, reach: "this file only", effect: "No AI", send: "STRIPE_KEY may be sent only to api.stripe.com." } })], [answer("egr-1", "api.stripe.com", true)]);
  await tick();
  const pv = treeRow(perValue.doc, /\.env$/);
  const how = pv.querySelector(".file-values-how");
  const pvLine = lineOf(pv);
  assert.equal(pvLine.previousElementSibling, how, "after the Per value line");
  assert.equal(pv.querySelector("select.send-select").getAttribute("aria-describedby"), `${how.id} ${pvLine.id}`);
});

/** A send of the row's file that waits for your answer, as the panel's queue sends it. */
function waiting(id: string, host: string, more: Record<string, unknown> = {}) {
  return { ...answer(id, host, false), status: "pending", resolvedAt: null, actions: [], ...more };
}
const waitOf = (row: any) => row.querySelector(".file-waiting");

test("W1: two waiting sends of the file are named, each a link to its question in Approvals; an answered one stays under Your answers", async () => {
  const { doc, window } = page([lock(ENV)], [waiting("egr-3", "hooks.slack.com"), waiting("egr-2", "evil.example"), answer("egr-1", "api.stripe.com", false)]);
  await tick();
  const row = treeRow(doc, /\.env$/);
  const sel = row.querySelector("select.send-select");
  assert.equal(sel.value, "ask", "the menu still reads Needs your OK");
  const line = waitOf(row);
  assert.ok(line, "the row names the sends that wait");
  assert.ok(line.classList.contains("dim"));
  assert.equal(drawn(line), "Waiting for your answer: [hooks.slack.com] · [evil.example]");
  assert.equal(drawn(lineOf(row)), "Your answers: [api.stripe.com] ✗ Always blocked", "the answered one, not waiting");
  assert.equal(lineOf(row).nextElementSibling, line, "under the answers line");
  assert.equal(sel.getAttribute("aria-describedby"), `${lineOf(row).id} ${line.id}`, "the menu is described by both");
  const links = [...line.querySelectorAll("a")] as any[];
  assert.deepEqual(links.map((a) => a.getAttribute("href")), ["/mandu/approvals/egr-3", "/mandu/approvals/egr-2"]);
  assert.deepEqual(links.map((a) => a.getAttribute("data-ask")), ["egr-3", "egr-2"]);
  assert.deepEqual(links.map((a) => a.textContent), ["hooks.slack.com", "evil.example"]);
  const ctrl = new window.MouseEvent("click", { bubbles: true, cancelable: true, ctrlKey: true });
  links[1].dispatchEvent(ctrl);
  assert.equal(ctrl.defaultPrevented, false, "a modifier click is the browser's");
  links[1].click();
  await tick(30);
  assert.equal(window.location.pathname, "/mandu/approvals/egr-2", "Approvals opens at that question");
});

test("W2: another file, holder-send:, session-net:, session-exec:, env:, no-longer-applies and a waiting question that is not a send are left out", async () => {
  const queue = [
    waiting("keep", "hooks.slack.com"),
    waiting("other", "other.example", { origin: "/home/u/ws/other.env" }),
    waiting("holder", "holder.example", { subject: "holder-send:s1#abc" }),
    waiting("session", "session.example", { subject: "session-net:s1" }),
    waiting("sexec", "sexec.example", { subject: "session-exec:s1" }),
    waiting("envvar", "env.example", { origin: "env:STRIPE_KEY" }),
    waiting("stale", "stale.example", { noLongerApplies: "name-only" }),
    waiting("exec", "exec.example", { where: "exec" }),
  ];
  const { doc } = page([lock(ENV)], queue);
  await tick();
  const row = treeRow(doc, /\.env$/);
  assert.equal(drawn(waitOf(row)), "Waiting for your answer: [hooks.slack.com]");
  assert.equal(lineOf(row), null, "no answer given, no answers line");
});

test("W3: four waiting show the first three, then and 1 more, a link to Approvals", async () => {
  const { doc } = page([lock(ENV)], [waiting("w1", "a.example"), waiting("w2", "b.example"), waiting("w3", "c.example"), waiting("w4", "d.example")]);
  await tick();
  const line = waitOf(treeRow(doc, /\.env$/));
  assert.equal(drawn(line), "Waiting for your answer: [a.example] · [b.example] · [c.example] · and 1 more");
  const links = [...line.querySelectorAll("a")] as any[];
  assert.equal(links.length, 4);
  assert.equal(links[3].textContent, "and 1 more");
  assert.equal(links[3].getAttribute("href"), "/mandu/approvals");
  assert.equal(links[3].getAttribute("data-ask"), null);
});

test("W4: a host asked twice is named once, by its newest question", async () => {
  const { doc } = page([lock(ENV)], [waiting("new", "hooks.slack.com"), waiting("mid", "evil.example"), waiting("old", "hooks.slack.com")]);
  await tick();
  const line = waitOf(treeRow(doc, /\.env$/));
  assert.equal(drawn(line), "Waiting for your answer: [hooks.slack.com] · [evil.example]");
  assert.deepEqual(([...line.querySelectorAll("a")] as any[]).map((a) => a.getAttribute("data-ask")), ["new", "mid"]);
});

test("W5: a folder row and a Not secret row have no waiting line", async () => {
  const folder = page([lock("/home/u/ws/config", { covers: "subtree", plain: { subject: "/home/u/ws/config", reach: "this folder", effect: "No AI" } })],
    [waiting("w1", "a.example", { origin: "/home/u/ws/config/db.yaml" }), waiting("w2", "b.example", { origin: "/home/u/ws/config" })]);
  await tick();
  const row = treeRow(folder.doc, /config/);
  assert.ok(row, "the folder row is drawn");
  assert.equal(waitOf(row), null);
  assert.equal(row.querySelector("select.send-select").getAttribute("aria-describedby"), null);

  const open = page([lock(ENV, { level: "public", plain: { subject: ENV, reach: "this file only", effect: "Not secret" } })], [waiting("w1", "a.example")]);
  await tick();
  assert.equal(waitOf(treeRow(open.doc, /\.env$/)), null);
});

test("W6: under Listed hosts and under Per value too, after the answers line, both describing the menu", async () => {
  const hosts = page([lock(ENV, { bindings: ["api.stripe.com"] })], [waiting("w1", "hooks.slack.com")]);
  await tick();
  const hr = treeRow(hosts.doc, /\.env$/);
  assert.equal(hr.querySelector("select.send-select").value, "hosts");
  const hl = waitOf(hr);
  assert.equal(drawn(hl), "Waiting for your answer: [hooks.slack.com]");
  assert.equal(hr.querySelector("select.send-select").getAttribute("aria-describedby"), hl.id);

  const values = [{ key: "STRIPE_KEY", bindings: ["api.stripe.com"] }];
  const pv = page([lock(ENV, { values, plain: { subject: ENV, reach: "this file only", effect: "No AI", send: "STRIPE_KEY may be sent only to api.stripe.com." } })],
    [waiting("w1", "hooks.slack.com"), answer("a1", "evil.example", false)]);
  await tick();
  const row = treeRow(pv.doc, /\.env$/);
  const how = row.querySelector(".file-values-how");
  const answers = lineOf(row);
  const wait = waitOf(row);
  assert.equal(answers.previousElementSibling, how);
  assert.equal(wait.previousElementSibling, answers);
  assert.equal(row.querySelector("select.send-select").getAttribute("aria-describedby"), `${how.id} ${answers.id} ${wait.id}`);
});

// ── Follows a send that starts or stops waiting (queue item #284) ───────────

const EVIL = "evil.example";
/** Rules whose panel is swappable (`set`), the Home answer at `waiting`,
 *  and one poll already compared, as a page left open is. */
async function following(waitingIds: unknown[], queue: unknown[], over: Record<string, unknown> = {}, routes: Record<string, unknown> = {}, before?: (w: any) => void) {
  let now = queue;
  const r = load({ url: RULES, before, homeVm: home({ waiting: waitingIds, rulesVersion: "v1", ...over }), routes: {
    ...routes,
    "GET policy/panel": () => ({ panel: { available: true, verdictsKnown: true, queue: now, yourRules: [lock(ENV)] } }),
    "GET policy/changes?limit=1": { changes: [] },
  } });
  await tick();
  await poll(r.doc);
  return { ...r, set: (q: unknown[]) => { now = q; } };
}
async function poll(doc: any) {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(30);
}
const reads = (calls: any[]) => calls.filter((c) => c.url.endsWith("/api/policy/panel")).length;
const changed = (doc: any) => doc.getElementById("rules-changed");
const WAITS = { ...ASK, id: "egr-9" };

test("W7: a send of the file that starts waiting shows on its row at the next poll, the place and the focus kept, no changed line", async () => {
  const { doc, calls, setHome, set } = await following([], []);
  let row = treeRow(doc, /\.env$/);
  assert.equal(waitOf(row), null, "nothing waits yet");
  row.querySelector("select.send-select").focus();
  const before = reads(calls);
  set([waiting("egr-9", EVIL)]);
  setHome(home({ waiting: [WAITS], rulesVersion: "v1" }));
  await poll(doc);
  assert.equal(reads(calls), before + 1, "one read of the panel");
  row = treeRow(doc, /\.env$/);
  const line = waitOf(row);
  assert.ok(line, "the line appears without a reload");
  assert.equal(drawn(line), `Waiting for your answer: [${EVIL}]`);
  assert.equal(line.querySelector("a").getAttribute("href"), "/mandu/approvals/egr-9");
  const sel = row.querySelector("select.send-select");
  assert.equal(sel.getAttribute("aria-describedby"), line.id);
  assert.equal(doc.activeElement, sel, "the focus is back on the row's menu");
  assert.equal(changed(doc).hidden, true, "your rules did not change: no line says so");
});

test("W7: under an open folder too, its row of the same file gains the line", async () => {
  const { doc, calls, setHome, set } = await following([], [], {}, FILES_ROUTES);
  doc.getElementById("rules-add").click();
  await tick();
  (doc.getElementById("lock-path") as any).value = "/home/u/ws";
  doc.getElementById("files-go").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
  await tick();
  assert.equal(waitOf(rowFor(doc, /^\.env/)), null);
  doc.getElementById("files-go").focus();
  const lists = calls.filter((c) => c.url.includes("/api/files/list")).length;
  set([waiting("egr-9", EVIL)]);
  setHome(home({ waiting: [WAITS], rulesVersion: "v1" }));
  await poll(doc);
  const line = waitOf(rowFor(doc, /^\.env/));
  assert.ok(line, "the browse row gains the line");
  assert.equal(drawn(line), `Waiting for your answer: [${EVIL}]`);
  assert.equal(calls.filter((c) => c.url.includes("/api/files/list")).length, lists, "the folder's rows redraw from its listing, not read again");
  assert.equal(changed(doc).hidden, true);
});

test("W8: that send answered once elsewhere: the next poll drops the line; a changed line already shown stays", async () => {
  const { doc, calls, setHome, set } = await following([WAITS], [waiting("egr-9", EVIL)]);
  assert.equal(drawn(waitOf(treeRow(doc, /\.env$/))), `Waiting for your answer: [${EVIL}]`);
  // Your rules changed elsewhere meanwhile: the follow says so.
  setHome(home({ waiting: [WAITS], rulesVersion: "v2" }));
  await poll(doc);
  assert.equal(changed(doc).hidden, false, "the follow of your rules says they changed");
  const before = reads(calls);
  set([{ ...answer("egr-9", EVIL, true), scope: "once" }]);
  setHome(home({ waiting: [], rulesVersion: "v2" }));
  await poll(doc);
  assert.equal(reads(calls), before + 1);
  const row = treeRow(doc, /\.env$/);
  assert.equal(waitOf(row), null, "the line is gone");
  assert.equal(lineOf(row), null, "a once answer is not a standing one");
  assert.equal(row.querySelector("select.send-select").getAttribute("aria-describedby"), null);
  assert.equal(changed(doc).hidden, false, "the line already shown stays");
});

test("W9: a poll with the same ids waiting, in any order, reads no panel", async () => {
  const W2 = { ...ASK, id: "egr-8" };
  const { doc, calls, setHome } = await following([WAITS, W2], [waiting("egr-9", EVIL), waiting("egr-8", "hooks.slack.com")]);
  const before = reads(calls);
  await poll(doc);
  setHome(home({ waiting: [W2, WAITS], rulesVersion: "v1" }));
  await poll(doc);
  assert.equal(reads(calls), before, "no read on a quiet poll");
  assert.equal(changed(doc).hidden, true);
});

test("W10: the focus in Find a rule reads nothing until it leaves; a hidden tab reads nothing until its return", async () => {
  let tickPoll: () => void = () => {};
  const { doc, calls, setHome, set } = await following([], [], {}, {}, (w) => { w.setInterval = (f: () => void) => { tickPoll = f; return 0; }; });
  const find = doc.getElementById("rules-find") as any;
  find.focus();
  const before = reads(calls);
  set([waiting("egr-9", EVIL)]);
  setHome(home({ waiting: [WAITS], rulesVersion: "v1" }));
  await poll(doc);
  assert.equal(reads(calls), before, "no read under the keys of the person");
  assert.equal(waitOf(treeRow(doc, /\.env$/)), null);
  find.blur();
  await poll(doc);
  assert.equal(reads(calls), before + 1, "the first poll after the focus leaves reads");
  assert.equal(drawn(waitOf(treeRow(doc, /\.env$/))), `Waiting for your answer: [${EVIL}]`);
  assert.equal(changed(doc).hidden, true);

  // Hidden: the tab still polls Home, but reads no panel.
  set([]);
  setHome(home({ waiting: [], rulesVersion: "v1" }));
  Object.defineProperty(doc, "visibilityState", { value: "hidden", configurable: true });
  const hidden = reads(calls);
  tickPoll();
  await tick(30);
  assert.equal(reads(calls), hidden, "a hidden tab reads nothing");
  assert.ok(waitOf(treeRow(doc, /\.env$/)), "the row as it was");
  await poll(doc);
  assert.equal(reads(calls), hidden + 1, "its return reads");
  assert.equal(waitOf(treeRow(doc, /\.env$/)), null);
  assert.equal(changed(doc).hidden, true);
});

test("W11: Home not knowing the questions waiting yet takes nothing; the first poll that knows one waiting reads the panel", async () => {
  const { doc, calls, setHome, set } = await following([], [], { waitingKnown: false });
  const before = reads(calls);
  set([waiting("egr-9", EVIL)]);
  setHome(home({ waiting: [WAITS], rulesVersion: "v1" }));
  await poll(doc);
  assert.equal(reads(calls), before + 1, "nothing was taken as compared: it reads");
  assert.equal(drawn(waitOf(treeRow(doc, /\.env$/))), `Waiting for your answer: [${EVIL}]`);
  assert.equal(changed(doc).hidden, true);
});
