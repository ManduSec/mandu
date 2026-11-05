/**
 * home-js-rule-origin-agent.test — the line under a rule on Rules that your
 * agent put there names that agent and its folder when Home lists its
 * session: "Claude Code added this. It only makes your rules stricter, so
 * it did not need your OK, Oct 21, 16:31 · 2 hours ago · from Claude Code in
 * ~/ws." (public/js/home.js `originLine`, `sessionAsker`; dashboard.md
 * §4.25 *A rule change and the agent that asked*).
 *
 * Until 2026-10-23 the line said "Your agent added this…" whichever agent
 * did it, so with two agents running only *See what the agent was doing*
 * told them apart. The server keeps its sentence and adds `who` and
 * `named` (the words around the agent); the page names the agent only for
 * those two kinds, never by matching the English:
 *
 *   - Home's row of the session: the agent and its folder, both links kept;
 *   - a row with no folder names the agent alone; another agent its own;
 *   - a session Home does not list, or a line of yours: today's words;
 *   - Home answering after Rules drew the line: the poll names it, a focus
 *     on its link kept.
 *
 * Drives the PRODUCT page script in jsdom over the shared fetch stub
 * (home-js-fixtures.ts); across the real arbiter and dashboard,
 * tests/stack/change-history-agent-link.test.ts. Axes: none (display only).
 * Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { CLOCK, RULES_PANEL, home, load, openRule, tick, treeRow, opened } from "./home-js-fixtures.js";

const RULES = "http://127.0.0.1:4500/mandu/rules";
const LINK = "See what the agent was doing";
const CHANGE = "See this change in Approvals";
/** A send rule to one host searches its changes too (§4.25 *Finding a rule change*). */
const FIND = "Find its changes";
const ASKED = { before: "", after: " asked for this and you approved it" };
const ADDED = { before: "", after: " added this. It only makes your rules stricter, so it did not need your OK" };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const origin = (sentence: string, session: string | null, over: Record<string, unknown> = {}) => ({
  recorded: true, sentence, at: Date.now() - 2 * 3_600_000, session, changedSince: false, changeId: "pc-000007", ...over,
});
const originsOf = (send: unknown, memo: unknown = origin("You added this on the Rules page", null, { changeId: "pc-000003" })) => ({
  origins: { "r-0001": send, "lock:**/ws-*/memo/**": memo },
  complete: true,
  unrecorded: { recorded: false, sentence: "No record of who added this", at: null, session: null, changedSince: false, changeId: null },
});
const rules = (origins: unknown, homeVm: unknown = home({ waiting: [], verdict: "protected" })) =>
  load({ url: RULES, homeVm, routes: { "GET policy/panel": RULES_PANEL, "GET policy/rules/origins": origins } });
const lineOf = (doc: Doc) => openRule(doc, /api\.example\.com/).querySelector(".rule-origin");
async function poll(doc: Doc): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}

test("a rule your agent asked for names that agent and its folder, as Home knows its session; both links stay", async () => {
  const { doc } = rules(originsOf(origin("Your agent asked for this and you approved it", "s1", { who: "agent-approved", named: ASKED })));
  await tick();
  const line = lineOf(doc);
  assert.match(line.textContent, new RegExp(`^Claude Code asked for this and you approved it, ${CLOCK} · 2 hours ago · from Claude Code in ~/ws\\. ${LINK} · ${CHANGE} · ${FIND}$`));
  assert.equal(line.querySelector(".ask-from code").textContent, "~/ws", "the folder as a name, as on the request's card");
  const [agent, change] = [...line.querySelectorAll("a")] as Doc[];
  assert.equal(agent.getAttribute("href"), "/mandu/agents/s1");
  assert.equal(change.getAttribute("href"), "/mandu/approvals/pc-000007");
  assert.equal(change.getAttribute("aria-label"), `${CHANGE}: api.example.com`, "still named by its rule");
  // A rule of yours keeps its words.
  treeRow(doc, /ws-\*\/memo/).click();
  assert.match(opened(doc).querySelector(".rule-origin").textContent, new RegExp(`^You added this on the Rules page, ${CLOCK} · 2 hours ago\\. ${CHANGE} · Find its changes$`));
});

test("another agent's rule names that agent; a row with no folder names the agent alone", async () => {
  const { doc } = rules(originsOf(origin("Your agent added this. It only makes your rules stricter, so it did not need your OK", "s2", { who: "agent", named: ADDED })));
  await tick();
  assert.match(lineOf(doc).textContent, new RegExp(`^Codex CLI added this\\. It only makes your rules stricter, so it did not need your OK, ${CLOCK} · 2 hours ago\\. ${LINK} · ${CHANGE} · ${FIND}$`));
  assert.equal(lineOf(doc).querySelector(".ask-from"), null, "no folder known: none drawn");
});

test("a session Home does not list, or a line without `who`: today's words, no folder", async () => {
  for (const send of [
    origin("Your agent asked for this and you approved it", "sess-9", { who: "agent-approved", named: ASKED }),
    origin("Your agent asked for this and you approved it", "s1"),
  ]) {
    const { doc } = rules(originsOf(send));
    await tick();
    assert.match(lineOf(doc).textContent, new RegExp(`^Your agent asked for this and you approved it, ${CLOCK} · 2 hours ago\\. ${LINK} · ${CHANGE} · ${FIND}$`), JSON.stringify(send));
    assert.equal(lineOf(doc).querySelector(".ask-from"), null);
  }
});

test("Home lists the session after Rules drew the line: the next poll names the agent, a focus on its link kept", async () => {
  const quiet = home({ waiting: [], verdict: "protected" }) as { agents: Array<Record<string, unknown>> };
  const without = { ...quiet, agents: quiet.agents.filter((a) => a.id !== "s1") };
  const { doc, setHome } = rules(originsOf(origin("Your agent asked for this and you approved it", "s1", { who: "agent-approved", named: ASKED })), without);
  await tick();
  assert.match(lineOf(doc).textContent, /^Your agent asked for this/);
  const link = lineOf(doc).querySelector("a.ask-link");
  link.focus();
  setHome(quiet);
  await poll(doc);
  const line = lineOf(doc);
  assert.match(line.textContent, new RegExp(`^Claude Code asked for this and you approved it, ${CLOCK} · 2 hours ago · from Claude Code in ~/ws\\. ${LINK} · ${CHANGE} · ${FIND}$`));
  assert.equal(doc.activeElement, line.querySelector("a.ask-link"), "the focus stays on the agent link, never <body>");
  // A poll with the same agent leaves the line as it is.
  const same = line;
  await poll(doc);
  assert.equal(lineOf(doc), same, "not drawn again");
});
