/**
 * home-js-last-step-link.test — dashboard.md §4.25 *A live row names its
 * last step as well as its start*. A Running now row says "started 5 hours
 * ago · last step 2 minutes ago"; to see what that step was, the row or its
 * Details opened the session page at its top, and a long story's newest
 * turn was many screens down. Now the "last step" phrase is a link to the
 * session at its newest turn (`?go=latest`, as Latest turn goes):
 *
 *   K1  a row whose last step is more than a minute after its start has the
 *       link (`/agents/<id>?go=latest`), in the phrase's own box, named by
 *       its words, where it goes and its row; a row within a minute of its
 *       start has none;
 *   K2  a poll that moves the last step keeps the same link and rewrites
 *       its time and its name only (moveLastSteps);
 *   K3  pressed, the session page opens with its newest turn focused and
 *       `go` dropped from the address; Back returns to Home;
 *   K4  a plain or modified click on the row's blank space still opens the
 *       session at its top, at Details' address (rowClick follows Details).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, CLOCK, T, home, load, tick } from "./home-js-fixtures.js";
import { waitWhile } from "../page-wait.js";

const minutesAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString();
/** The fixture's first agent, running: started `startedMin` and last acted `lastMin` minutes ago. */
const live = (startedMin: number, lastMin: number, over: Record<string, unknown> = {}) =>
  ({ ...(home().agents as Record<string, unknown>[])[0], state: "running", waiting: 0, startedAt: minutesAgo(startedMin), lastAt: minutesAgo(lastMin), ...over });
const vmOf = (...agents: unknown[]) => home({ waiting: [], agents });

const step = (id: string) => ({ kind: "action", id, ts: "2026-09-25T10:00:01.000Z", icon: "run", sentence: [T(`Ran ${id}`)], outcome: "plain", note: null, split: null });
const turn = (id: string, min: number) => ({
  ...AGENT.story[1], id, ts: `2026-09-25T10:${String(min).padStart(2, "0")}:00.000Z`, prompt: `Question ${id}`, routine: null, reply: null, moreSteps: 0, promptNote: null,
  summary: "Nothing here needed guarding.", summaryParts: null, tone: "plain", steps: [step(`${id}-a`)],
});
const PAGE = { ...AGENT, waiting: [], earlier: 0, story: [1, 2, 3, 4, 5].map((m) => turn(`t:${m}`, m)) };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
const rowOf = (doc: El, id = "s1") => doc.querySelector(`#home-agents .row.agent[data-session="${id}"]`);
const linkOf = (doc: El, id = "s1") => rowOf(doc, id)?.querySelector("a.agent-last-link") ?? null;
const turns = (doc: El) => [...doc.querySelectorAll("#agent-story article.turn[data-turn-id]")] as El[];
const clickOn = (target: El, init: Record<string, unknown> = {}, type = "click") =>
  target.dispatchEvent(new target.ownerDocument.defaultView.MouseEvent(type, { bubbles: true, cancelable: true, ...init }));
async function poll(doc: El): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}

test("K1: a row whose last step is past its first minute links it to the newest turn, named by its words and its row; a row within a minute has none", async () => {
  const a = live(5 * 60, 2);
  const { doc, err } = load({ homeVm: vmOf(a, { ...live(30, 30), id: "s3" }) });
  assert.equal(err, null);
  await tick();
  const link = linkOf(doc);
  assert.ok(link, "the phrase is a link");
  assert.equal(link.getAttribute("href"), "/mandu/agents/s1?go=latest");
  assert.equal(link.dataset.pageLink, "agent");
  assert.equal(link.dataset.session, "s1");
  assert.equal(link.dataset.land, "latest");
  assert.equal(link.textContent, "last step 2 minutes ago");
  assert.ok(link.classList.contains("when-phrase"), "the phrase's own box: a narrow column still breaks only between the two phrases");
  assert.deepEqual([...rowOf(doc).querySelectorAll(".when-phrase")].map((x: El) => x.textContent), ["started 5 hours ago ·", "last step 2 minutes ago"]);
  assert.equal(link.getAttribute("aria-label"), "Last step 2 minutes ago: go to the latest turn of Claude Code, Fix the test in ~/ws", "its own words first, then where it goes and its row");
  const t = link.querySelector("time.agent-last");
  assert.equal(t.getAttribute("datetime"), a.lastAt);
  assert.match(t.getAttribute("title"), new RegExp(`^${CLOCK}$`), "the clock time on hover, as before");
  // Details is unchanged, and stays the row's name.
  const details = rowOf(doc).querySelector("a.right");
  assert.equal(details.getAttribute("href"), "/mandu/agents/s1");
  assert.equal(details.getAttribute("aria-label"), "Details: Claude Code, Fix the test in ~/ws");
  assert.equal(link.compareDocumentPosition(details) & doc.defaultView.Node.DOCUMENT_POSITION_FOLLOWING, doc.defaultView.Node.DOCUMENT_POSITION_FOLLOWING, "the link comes before Details");
  // Within a minute of its start: "started …" alone, no link.
  assert.equal(rowOf(doc, "s3").querySelector(".agent-when").textContent, "started 30 minutes ago");
  assert.equal(linkOf(doc, "s3"), null);
});

test("K2: a poll that moves the last step keeps the same link and rewrites only its time and its name", async () => {
  const a = live(5 * 60, 20);
  const p = load({ homeVm: vmOf(a) });
  await tick();
  const row = rowOf(p.doc);
  const link = linkOf(p.doc);
  link.focus();
  const later = { ...a, lastAt: minutesAgo(1) };
  p.setHome(vmOf(later));
  await poll(p.doc);
  assert.equal(rowOf(p.doc), row, "the row is the node already there");
  assert.equal(linkOf(p.doc), link, "and so is its link");
  assert.equal(p.doc.activeElement, link, "which keeps the focus");
  assert.equal(link.querySelector("time.agent-last").getAttribute("datetime"), later.lastAt);
  assert.equal(link.textContent, "last step 1 minute ago");
  assert.equal(link.getAttribute("aria-label"), "Last step 1 minute ago: go to the latest turn of Claude Code, Fix the test in ~/ws");
  assert.equal(link.getAttribute("href"), "/mandu/agents/s1?go=latest");
});

test("K3: pressed, the session page opens with its newest turn focused, `go` dropped from the address; Back returns to Home", async () => {
  const { doc, window, calls } = load({ homeVm: vmOf(live(5 * 60, 2)), routes: { "GET home/agent?session=s1": PAGE } });
  await tick();
  const scrolled: string[] = [];
  window.HTMLElement.prototype.scrollIntoView = function (this: El) { scrolled.push(this.dataset.turnId ?? this.className); };
  linkOf(doc).click();
  await tick(40);
  assert.ok(calls.some((c) => c.url === "/mandu/api/home/agent?session=s1"));
  assert.equal(doc.getElementById("page-agent").hidden, false);
  assert.equal(window.location.pathname + window.location.search, "/mandu/agents/s1", "used once: a reload or Back to it does not jump again");
  const last = turns(doc).at(-1);
  assert.equal(last.dataset.turnId, "t:5");
  assert.equal(doc.activeElement, last, "the newest turn has the focus, as Latest turn's press gives it");
  assert.deepEqual(scrolled, ["t:5"], "and is scrolled to");
  window.history.back();
  await waitWhile(() => window.location.pathname !== "/mandu/");
  assert.equal(window.location.pathname, "/mandu/");
  assert.equal(doc.getElementById("page-home").hidden, false, "Back returns to Home");
});

test("K4: a plain click on the row's blank space opens the session at its top, a modified one at Details' address, never the newest turn", async () => {
  const opened: unknown[][] = [];
  const { doc, window } = load({ homeVm: vmOf(live(5 * 60, 2)), routes: { "GET home/agent?session=s1": PAGE }, before: (w) => { w.open = (...a: unknown[]) => { opened.push(a); return null; }; } });
  await tick();
  const scrolled: string[] = [];
  window.HTMLElement.prototype.scrollIntoView = function (this: El) { scrolled.push(this.dataset.turnId ?? this.className); };
  const prompt = rowOf(doc).querySelector(".agent-what .sub");
  clickOn(prompt, { ctrlKey: true });
  clickOn(prompt, { button: 1 }, "auxclick");
  assert.deepEqual(opened, [["http://127.0.0.1:4500/mandu/agents/s1", "_blank", "noopener"], ["http://127.0.0.1:4500/mandu/agents/s1", "_blank", "noopener"]], "Details' address, not the link's");
  clickOn(prompt);
  await tick(40);
  assert.equal(window.location.pathname + window.location.search, "/mandu/agents/s1");
  assert.equal(doc.getElementById("page-agent").hidden, false);
  assert.ok(turns(doc).length === 5, "the story is drawn");
  assert.notEqual(doc.activeElement.closest?.("article.turn"), turns(doc).at(-1), "no turn has the focus");
  assert.deepEqual(scrolled, [], "nothing scrolled to: the page opens at its top");
  assert.equal(window.scrollY, 0);
});
