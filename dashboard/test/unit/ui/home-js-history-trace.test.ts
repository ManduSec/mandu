/**
 * home-js-history-trace.test — dashboard.md §4.25ae: the product page is a
 * whole trace, in a build without the developer view (`extensions: ""`).
 *
 *   - History (`/history`): Home's *History* link opens it in both builds;
 *     every session, newest first, each row opening its agent page; "Show
 *     more" reads the next page after the last row and gives the first new
 *     row the focus; a page that could not be read says why;
 *   - the agent page's *What the leak check found*: each place, its time a
 *     button that opens the step; no word names the trace; then *What to do
 *     now*, its Report a problem link the issue tracker in a new tab;
 *   - a turn's background: *List them* asks for its steps
 *     (`&background=<turn id>`), and the first line takes the focus;
 *   - an original cut at the page's cap: signed in, *Show the whole original*
 *     reads `home/original` and puts it in the box, which takes the focus;
 *     signed out, no such button.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, T, home, load, tick } from "./home-js-fixtures.js";
import { ISSUES_URL } from "../../../src/agent-versions.js";

const row = (id: string, over: Record<string, unknown> = {}) => ({
  id, agent: "Claude Code", title: `Task ${id}`, cwd: "/home/u/ws", startedAt: "2026-09-01T10:00:00.000Z", lastAt: "2026-09-01T10:05:00.000Z", state: "idle",
  stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 }, secrets: { masked: 1, early: 0 }, untrusted: 0, blocked: 0, sent: 0, holds: true, waiting: 0, notice: null, preview: null, ...over,
});
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const historyRows = (doc: any) => [...doc.querySelectorAll("#history-list .row.agent")] as any[];
/** The words a reader can reach: no hidden element's. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function shownText(x: any): string {
  const copy = x.cloneNode(true);
  for (const h of copy.querySelectorAll("[hidden]")) h.remove();
  return copy.textContent;
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function reachableDevLinks(doc: any): string[] {
  return ([...doc.querySelectorAll("a")] as any[]).filter((a) => /\/dev\//.test(a.href) && !a.closest("[hidden]")).map((a) => a.id || a.textContent);
}

test("History: Home's link opens it in a product-only build; rows newest first, each to its agent page; Show more reads the next page and focuses its first row", async () => {
  const routes = {
    "GET home/history": { total: 3, rows: [row("s1", { state: "running" }), row("s2", { holds: false, blocked: 2 })], next: "s2" },
    "GET home/history?after=s2": { total: 3, rows: [row("s2"), row("s3", { title: null })], next: null },
  };
  const { doc, calls } = load({ extensions: "", homeVm: home(), routes });
  await tick();
  const link = doc.getElementById("home-history");
  assert.equal(link.hidden, false);
  assert.equal(link.textContent, "History: 9 sessions");
  link.click();
  await tick();
  assert.equal(doc.getElementById("page-history").hidden, false);
  assert.equal(doc.defaultView.location.pathname, "/mandu/history");
  assert.equal(doc.activeElement, doc.querySelector("#page-history h1"), "a page change gives the page's heading the focus");
  assert.ok(calls.some((c) => c.url === "/mandu/api/home/history"));
  let rows = historyRows(doc);
  assert.deepEqual(rows.map((r) => r.dataset.session), ["s1", "s2"]);
  assert.match(rows[0].textContent, /Task s1 in ~\/ws/);
  assert.match(rows[0].textContent, /running now, started/);
  assert.match(rows[1].textContent, /protection failed, 1 secret masked, 2 actions blocked/);
  assert.match(rows[1].textContent, /ended/);
  assert.equal(rows[0].querySelector("a").getAttribute("href"), "/mandu/agents/s1");
  const more = doc.querySelector("#history-list .history-more");
  assert.equal(more.textContent, "1 more session. Show more");
  const btn = more.querySelector("button");
  assert.equal(doc.getElementById(btn.getAttribute("aria-describedby")).textContent, "1 more session.");
  btn.click();
  await tick();
  rows = historyRows(doc);
  assert.deepEqual(rows.map((r) => r.dataset.session), ["s1", "s2", "s3"], "a row already drawn is not drawn twice");
  assert.equal(doc.activeElement, rows[2], "the first new row takes the focus");
  assert.match(rows[2].textContent, /No prompt reached the AI/);
  assert.equal(doc.querySelector("#history-list .history-more"), null, "nothing more");
  assert.deepEqual(reachableDevLinks(doc), []);
  // A row opens its agent page.
  rows[0].querySelector("a").click();
  await tick();
  assert.equal(doc.defaultView.location.pathname, "/mandu/agents/s1");
});

test("History: opened by its address; an empty record and a failed read say so", async () => {
  const empty = load({ extensions: "", url: "http://127.0.0.1:4500/mandu/history", routes: { "GET home/history": { total: 0, rows: [], next: null } } });
  await tick();
  assert.equal(empty.doc.getElementById("page-history").hidden, false);
  assert.match(empty.doc.getElementById("history-list").textContent, /No session has been recorded yet/);
  const failed = load({ extensions: "", url: "http://127.0.0.1:4500/mandu/history", routes: { "GET home/history": { status: 500, body: { error: "boom" } } } });
  await tick();
  assert.match(failed.doc.getElementById("history-list").textContent, /^Could not read the history\. /);
});

const flaggedAgent = {
  ...AGENT, waiting: [], holds: false, violations: 2,
  finding: {
    count: 2, more: 1,
    items: [
      { ts: "2026-09-25T10:00:01.000Z", step: "t1", parts: [T("At "), { kind: "time", text: "2026-09-25T10:00:01.000Z", step: "t1" }, T(", the result of this step reached the AI without a mask: Read "), { kind: "code", text: "notes.md" }, T(". It held your secret "), { kind: "code", text: "API_KEY" }, T(".")] },
      { ts: "2026-09-25T10:00:05.000Z", parts: [T("At "), { kind: "time", text: "2026-09-25T10:00:05.000Z" }, T(", a request to the AI carried an item as it was, though Mandu had masked it.")] },
    ],
    todo: [
      [T("Change "), { kind: "code", text: "API_KEY" }, T(" where it was issued, and turn the old one off: the AI's provider received it as it was.")],
      [T("If what reached the AI held a key or a password, change it the same way. Open the step to see what it was.")],
      [T("This is a fault in Mandu, not in your rules. "), { kind: "text", text: "Report a problem", href: ISSUES_URL }, T(", with this session's time. Never paste the key itself.")],
    ],
  },
};

test("the agent page says what the leak check found: each place, its time opening the step; the rest counted; no word points at the trace", async () => {
  const { doc } = load({ extensions: "", url: "http://127.0.0.1:4500/mandu/agents/s1", routes: { "GET home/agent?session=s1": flaggedAgent } });
  await tick();
  const block = doc.getElementById("agent-finding-block");
  assert.equal(block.hidden, false);
  assert.equal(doc.getElementById("agent-finding-intro").textContent, "Mandu's leak check found 3 places where something reached the AI without its mask. Each line says where and when, never the text itself.");
  const items = [...doc.querySelectorAll("#agent-finding li")] as any[];
  assert.equal(items.length, 3);
  assert.match(items[0].textContent, /the result of this step reached the AI without a mask: Read notes\.md\. It held your secret API_KEY\./);
  assert.equal(items[2].textContent, "1 more place is past what this page lists.");
  // The time opens the step.
  const opens = items[0].querySelector("button.step-link");
  assert.equal(opens.dataset.opens, "t1");
  opens.click();
  await tick();
  assert.equal(doc.activeElement, doc.querySelector('#agent-story [data-step-id="t1"]'));
  assert.equal(items[1].querySelector("button.step-link"), null, "a request is no step");
  assert.doesNotMatch(shownText(doc.getElementById("page-agent")), /detailed trace|developer view/i);
  assert.deepEqual(reachableDevLinks(doc), []);
  // What to do now, after the lines: each line, the report linked.
  const title = doc.getElementById("agent-finding-todo-title");
  const todo = doc.getElementById("agent-finding-todo");
  assert.equal(title.hidden, false);
  assert.equal(title.textContent, "What to do now");
  assert.equal(todo.hidden, false);
  assert.ok(doc.getElementById("agent-finding").compareDocumentPosition(todo) & 4, "the list follows the lines");
  const todos = [...todo.querySelectorAll("li")] as any[];
  assert.deepEqual(todos.map((li) => li.textContent), [
    "Change API_KEY where it was issued, and turn the old one off: the AI's provider received it as it was.",
    "If what reached the AI held a key or a password, change it the same way. Open the step to see what it was.",
    "This is a fault in Mandu, not in your rules. Report a problem, with this session's time. Never paste the key itself.",
  ]);
  assert.equal(todos[0].querySelector("code").textContent, "API_KEY");
  const links = [...todo.querySelectorAll("a")] as any[];
  assert.equal(links.length, 1);
  assert.equal(links[0].textContent, "Report a problem");
  assert.equal(links[0].getAttribute("href"), ISSUES_URL);
  assert.equal(links[0].getAttribute("target"), "_blank");
  assert.match(links[0].getAttribute("rel"), /\bnoopener\b/);
  // An address that is not https is drawn as plain words, never a link.
  const odd = load({ extensions: "", url: "http://127.0.0.1:4500/mandu/agents/s1", routes: { "GET home/agent?session=s1": { ...flaggedAgent, finding: { ...flaggedAgent.finding, todo: [[{ kind: "text", text: "Report a problem", href: "javascript:alert(1)" }]] } } } });
  await tick();
  assert.equal(odd.doc.querySelector("#agent-finding-todo a"), null);
  assert.equal(odd.doc.getElementById("agent-finding-todo").textContent, "Report a problem");
  // A session the check did not flag: no block.
  const clean = load({ extensions: "", url: "http://127.0.0.1:4500/mandu/agents/s1", routes: { "GET home/agent?session=s1": { ...AGENT, finding: null } } });
  await tick();
  assert.equal(clean.doc.getElementById("agent-finding-block").hidden, true);
  assert.equal(clean.doc.querySelector("#agent-finding-todo li"), null);
});

test("a turn's background: List them asks for its steps and the first line takes the focus; once listed, each step with its time", async () => {
  const listed = {
    ...AGENT,
    story: [{ ...AGENT.story[0], routine: { ...AGENT.story[0]!.routine, items: [
      { ts: "2026-09-25T10:00:02.000Z", parts: [T("Connected to "), { kind: "code", text: "api.anthropic.com" }, T(" (4 times)")] },
      { ts: "2026-09-25T10:00:03.000Z", parts: [T("Mandu checked a command: "), { kind: "code", text: "git status" }] },
    ], moreItems: 0 } }, AGENT.story[1]],
  };
  const { doc, calls } = load({ extensions: "", url: "http://127.0.0.1:4500/mandu/agents/s1", routes: { "GET home/agent?session=s1": AGENT, "GET home/agent?session=s1&background=turn%3Ai1": listed } });
  await tick();
  const turn = doc.querySelector('#agent-story article.turn[data-turn-id="turn:i1"]');
  const btn = turn.querySelector("button.routine-show");
  assert.equal(btn.textContent, "List them");
  assert.match(btn.getAttribute("aria-label"), /^List them: In the background: 4 connections/);
  assert.equal(turn.querySelector(".routine").textContent, "In the background: 4 connections to api.anthropic.com; 1 command Mandu checked.", "the line keeps its words");
  btn.click();
  await tick();
  assert.ok(calls.some((c) => c.url === "/mandu/api/home/agent?session=s1&background=turn%3Ai1"));
  const after = doc.querySelector('#agent-story article.turn[data-turn-id="turn:i1"]');
  const lis = [...after.querySelectorAll(".routine-list li")] as any[];
  assert.deepEqual(lis.map((l) => l.textContent.replace(/^\d{2}:\d{2} /, "")), ["Connected to api.anthropic.com (4 times)", "Mandu checked a command: git status"]);
  assert.equal(doc.activeElement, lis[0], "the first line takes the focus");
  assert.equal(after.querySelector("button.routine-show"), null);
});

test("an original cut at the page's cap: signed in, Show the whole original reads it and the box takes the focus; signed out, no such button", async () => {
  const cut = "y".repeat(4000);
  const agent = {
    ...AGENT, waiting: [], valuesShown: true,
    story: [{ ...AGENT.story[0], steps: [{ ...AGENT.story[0]!.steps[0], split: { ...AGENT.story[0]!.steps[0]!.split, hidden: { text: cut, secret: false, truncated: true } } }] }],
  };
  const { doc, calls } = load({ extensions: "", url: "http://127.0.0.1:4500/mandu/agents/s1", routes: { "GET home/agent?session=s1": agent, "GET home/original?session=s1&step=t1": { text: cut + "THE-END", truncated: false } } });
  await tick();
  const box = doc.querySelector('#agent-story [data-step-id="t1"] .hidden-box');
  const whole = box.querySelector("button.whole-original");
  assert.ok(whole);
  assert.equal(whole.hidden, true, "hidden while the box is closed");
  box.querySelector("button.reveal").click();
  assert.equal(whole.hidden, false);
  assert.match(box.querySelector("pre").textContent, /\n…$/);
  whole.click();
  await tick();
  assert.ok(calls.some((c) => c.url === "/mandu/api/home/original?session=s1&step=t1" && c.headers["X-Mandu-Control"] === "1"));
  const pre = box.querySelector("pre");
  assert.equal(pre.textContent, cut + "THE-END");
  assert.equal(whole.hidden, true, "shown: the button goes");
  assert.equal(doc.activeElement, pre);
  // Closed and opened again: the whole stays, no button comes back.
  box.querySelector("button.reveal").click();
  box.querySelector("button.reveal").click();
  assert.equal(whole.hidden, true);

  // A refusal says why, beside the button.
  const refused = load({ extensions: "", url: "http://127.0.0.1:4500/mandu/agents/s1", routes: { "GET home/agent?session=s1": agent, "GET home/original?session=s1&step=t1": { status: 403, body: { error: "admin session required" } } } });
  await tick();
  const rbox = refused.doc.querySelector('#agent-story [data-step-id="t1"] .hidden-box');
  rbox.querySelector("button.reveal").click();
  rbox.querySelector("button.whole-original").click();
  await tick();
  assert.match(rbox.querySelector(".ask-error").textContent, /^Sign in first/, "a 403 says how to sign in");

  // Signed out: no button (the page has no original to begin with).
  const out = load({ extensions: "", url: "http://127.0.0.1:4500/mandu/agents/s1", routes: { "GET home/agent?session=s1": { ...agent, valuesShown: false } } });
  await tick();
  assert.equal(out.doc.querySelector("button.whole-original"), null);
});
