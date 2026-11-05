/**
 * home-js-off-session.test — dashboard.md §4.25 *A session that ran with
 * protection off says so*, §4.25b. A session that ran with protection off
 * (its recorded mode `off`) looked like a protected one everywhere a person
 * looks for it afterwards: a running one had the green dot, an ended one the
 * grey one, and its counts line was empty, which reads as "nothing happened",
 * not "nothing was guarded"; its page said so only in the grey line at the
 * end of Your secrets.
 *
 *   O1  Home: Running now and Earlier give an Off row the amber dot and
 *       "protection was off" first in its counts; a protected row is drawn
 *       as before; a failed Off row keeps its red dot, "protection failed"
 *       first;
 *   O2  History: the same, running or ended;
 *   O3  the session page of an Off session says it in one line at its top,
 *       with a link to Settings › Protection while protection is off now;
 *       once it is back on, the line stays and the link goes;
 *   O4  a protected session's page has no such line;
 *   O5  Home's hero counts them once protection is back on: "1 session ran
 *       with protection off", amber, first among the window's counts (after
 *       a waiting fact), linking that session (several: History), and the
 *       window is then not "Nothing to count" nor "Mandu last stepped in";
 *       not drawn while protection is off now, nor from an older server
 *       that sends no `off`;
 *   O6  a session where a protection did not start (`lessProtection`,
 *       dashboard.md §4.21): Running now, Earlier and History give it the
 *       amber dot and "less protection than usual" in its counts, after
 *       "protection failed" and "protection was off" (a failed one stays
 *       red); a row without the field is drawn as before.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, home, load, tick } from "./home-js-fixtures.js";

const STATS = { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 };
const row = (id: string, over: Record<string, unknown> = {}) => ({
  id, agent: "Claude Code", title: `Task ${id}`, cwd: null, startedAt: new Date(Date.now() - 600_000).toISOString(), lastAt: new Date().toISOString(), state: "idle",
  stats: STATS, secrets: { masked: 0, early: 0 }, untrusted: 0, blocked: 0, sent: 0, holds: true, protectionOff: false, waiting: 0, notice: null, preview: null, ...over,
});
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const rowIn = (doc: any, host: string, id: string) => doc.querySelector(`#${host} .row.agent[data-session="${id}"]`) as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const counts = (r: any) => r.querySelector(".agent-counts")?.textContent ?? null;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const dot = (r: any) => r.querySelector(".dot").className;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const poll = async (doc: any) => { doc.dispatchEvent(new doc.defaultView.Event("visibilitychange")); await tick(); };

const OFF_WORDS = "Protection was off in this session: Mandu only watched. Your secrets were not guarded and nothing was masked.";

test("O1: Home's Running now and Earlier mark an Off session with the amber dot and \"protection was off\" first; a failed one stays red", async () => {
  const agents = [
    row("run-off", { state: "running", protectionOff: true }),
    row("run-on", { state: "running", secrets: { masked: 1, early: 0 } }),
    row("end-off", { protectionOff: true }),
    row("end-on", { blocked: 1 }),
    row("end-bad", { protectionOff: true, holds: false }),
  ];
  const { doc } = load({ extensions: "", homeVm: home({ agents, waiting: [], verdict: "protected" }) });
  await tick();
  assert.equal(dot(rowIn(doc, "home-agents", "run-off")), "dot warn", "a running Off session is not green");
  assert.equal(counts(rowIn(doc, "home-agents", "run-off")), "protection was off");
  assert.equal(dot(rowIn(doc, "home-agents", "run-on")), "dot ok", "a protected one is drawn as before");
  assert.equal(counts(rowIn(doc, "home-agents", "run-on")), "1 secret masked");
  assert.equal(dot(rowIn(doc, "home-earlier", "end-off")), "dot warn");
  assert.equal(counts(rowIn(doc, "home-earlier", "end-off")), "protection was off");
  assert.equal(dot(rowIn(doc, "home-earlier", "end-on")), "dot");
  assert.equal(counts(rowIn(doc, "home-earlier", "end-on")), "1 action blocked");
  assert.equal(dot(rowIn(doc, "home-earlier", "end-bad")), "dot bad", "protection failed outranks the amber dot");
  assert.equal(counts(rowIn(doc, "home-earlier", "end-bad")), "protection failed, protection was off");
});

test("O2: History marks an Off session the same way, running or ended", async () => {
  const rows = [
    row("h-run-off", { state: "running", protectionOff: true }),
    row("h-run-on", { state: "running" }),
    row("h-off", { protectionOff: true, untrusted: 2 }),
    row("h-on", { secrets: { masked: 1, early: 0 } }),
    row("h-bad", { protectionOff: true, holds: false }),
  ];
  const { doc } = load({ extensions: "", url: "http://127.0.0.1:4500/mandu/history", homeVm: home(), routes: { "GET home/history": { total: rows.length, rows, next: null } } });
  await tick();
  const r = (id: string) => rowIn(doc, "history-list", id);
  assert.equal(dot(r("h-run-off")), "dot warn");
  assert.equal(counts(r("h-run-off")), "protection was off");
  assert.equal(dot(r("h-run-on")), "dot ok");
  assert.equal(counts(r("h-run-on")), null);
  assert.equal(dot(r("h-off")), "dot warn");
  assert.equal(counts(r("h-off")), "protection was off, 2 untrusted items masked", "first, before the counts");
  assert.equal(dot(r("h-on")), "dot");
  assert.equal(counts(r("h-on")), "1 secret masked");
  assert.equal(dot(r("h-bad")), "dot bad");
  assert.equal(counts(r("h-bad")), "protection failed, protection was off");
});

test("O3: an Off session's page says so at its top, linking Settings › Protection only while protection is off now", async () => {
  const offNow = home({ protection: { level: "off", configured: "off", connected: true } });
  const { doc, window, setHome } = load({
    extensions: "", url: "http://127.0.0.1:4500/mandu/agents/s1", homeVm: offNow,
    routes: { "GET home/agent?session=s1": { ...AGENT, protectionOff: true } },
  });
  await tick();
  const line = doc.getElementById("agent-off");
  assert.equal(doc.getElementById("page-agent").hidden, false);
  assert.equal(line.hidden, false);
  assert.ok(line.classList.contains("posture-line"), "the amber line of the posture note");
  assert.equal(line.nextElementSibling.id, "agent-posture", "just above the posture line");
  assert.equal(line.textContent, `${OFF_WORDS} Protection is in Settings.`);
  const link = line.querySelector("a");
  assert.equal(link.textContent, "Protection is in Settings");
  assert.equal(link.getAttribute("href"), "/mandu/settings#protection");
  // A poll that changes nothing leaves the line, and a focused link, as they are.
  link.focus();
  await poll(doc);
  assert.equal(line.querySelector("a"), link, "not drawn again");
  assert.equal(doc.activeElement, link);
  // Protection back on: the session still ran without it; there is nothing to turn on.
  setHome(home({ protection: { level: "secrets", configured: "secrets", connected: true } }));
  await poll(doc);
  assert.equal(line.hidden, false, "the session's own record, never today's setting");
  assert.equal(line.textContent, OFF_WORDS);
  assert.equal(line.querySelector("a"), null);
  // Off again: the link comes back, and opens Settings at Protection.
  setHome(offNow);
  await poll(doc);
  const again = line.querySelector("a");
  assert.equal(again.textContent, "Protection is in Settings");
  again.click();
  await tick();
  assert.equal(window.location.pathname, "/mandu/settings");
  assert.equal(doc.getElementById("page-settings").hidden, false);
  assert.ok(doc.getElementById("settings-protection-block"), "Settings › Protection");
});

test("O4: a protected session's page has no such line", async () => {
  const { doc } = load({ extensions: "", url: "http://127.0.0.1:4500/mandu/agents/s1", homeVm: home({ protection: { level: "off", configured: "off", connected: true } }) });
  await tick();
  assert.equal(doc.getElementById("page-agent").hidden, false);
  assert.equal(doc.getElementById("agent-off").hidden, true, "a session that recorded no Off mode is drawn as before");
  assert.equal(doc.getElementById("agent-off").textContent, "");
});

test("O5: Home's counts say \"1 session ran with protection off\", amber and first, linking that session (several: History); never \"Nothing to count\" beside it; not while protection is off now, nor from an older server", async () => {
  const zero = { hours: 24, sessions: 1, counted: 1, masked: 0, secretsMasked: 0, secretsEarly: 0, untrusted: 0, blocked: 0, sent: 0, waiting: 0 };
  const owners = (o: Record<string, string | null> = {}) => ({ secretsMasked: null, secretsEarly: null, blocked: null, sent: null, off: null, ...o });
  const LAST = { id: "sess-friday", agent: "Claude Code", cwd: null, at: "2026-10-23T08:40:00.000Z" };
  const on = { verdict: "secrets-only", headline: "Your secrets are guarded.", sentence: "No agent is running right now.", protection: { level: "secrets", configured: "secrets", connected: true }, waiting: [], lastSteppedIn: LAST };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const facts = async (over: Record<string, unknown>): Promise<any> => {
    const { doc, err } = load({ extensions: "", homeVm: home({ ...on, ...over }) });
    assert.equal(err, null);
    await tick();
    return doc.getElementById("hero-facts");
  };
  const TITLE = "nothing was masked or blocked.";

  // One session: its page.
  const one = await facts({ window: { ...zero, off: 1, only: owners({ off: "s-off" }) } });
  // Its words, then its "?" with what it means (§4.25 *What the counts mean*).
  assert.equal(one.textContent, `In the last 24 hours: 1 session ran with protection off ?Mandu only watched in it: ${TITLE}`);
  assert.equal(one.querySelector(".help-btn").getAttribute("aria-label"), "What protection off means");
  const link = one.querySelector("a");
  assert.equal(link.textContent, "1 session ran with protection off");
  assert.equal(link.getAttribute("href"), "/mandu/agents/s-off");
  assert.deepEqual([link.dataset.pageLink, link.dataset.session], ["agent", "s-off"]);
  assert.equal(link.title, `Mandu only watched in it: ${TITLE} Opens the session where it happened.`);
  assert.ok(link.querySelector("strong.warn"), "amber, as the rows' dot");
  assert.doesNotMatch(one.textContent, /Nothing to count|Mandu last stepped in/, "not a quiet day");

  // Several: History, whose rows mark each (not its stepped-in switch).
  const two = await facts({ window: { ...zero, sessions: 2, counted: 2, off: 2, only: owners() } });
  assert.equal(two.textContent, `In the last 24 hours: 2 sessions ran with protection off ?Mandu only watched in them: ${TITLE}`);
  const many = two.querySelector("a");
  assert.equal(many.getAttribute("href"), "/mandu/history");
  assert.equal(many.dataset.pageLink, "history");
  assert.equal(many.title, `Mandu only watched in them: ${TITLE} Opens History.`);
  assert.ok(many.querySelector("strong.warn"));

  // First among the window's counts, after a waiting fact.
  const mixed = await facts({ verdict: "failed", headline: "Protection failed.", window: { ...zero, sessions: 2, counted: 2, off: 1, blocked: 1, waiting: 1, only: owners({ off: "s-off", blocked: "s-on" }) } });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  assert.deepEqual([...mixed.children].map((c: any) => c.textContent.replace(/\?.*$/s, "?")), ["1 waiting for you", "In the last 24 hours: 1 session ran with protection off ?", "1 action blocked ?"]);

  // Partly counted: History, never one session.
  const partly = await facts({ window: { ...zero, sessions: 3, counted: 2, off: 1, only: owners({ off: "s-off" }) } });
  assert.equal(partly.querySelector("a").getAttribute("href"), "/mandu/history");

  // Protection off now: the headline says so; no fact.
  const offNow = await facts({ verdict: "off", headline: "Protection is off.", protection: { level: "off", configured: "off", connected: true }, window: { ...zero, off: 1, only: owners({ off: "s-off" }) } });
  assert.doesNotMatch(offNow.textContent, /ran with protection off/);

  // An older server sends no `off`: the empty window's line, as before.
  const older = await facts({ window: { ...zero, only: { secretsMasked: null, secretsEarly: null, blocked: null, sent: null } } });
  assert.match(older.textContent, /^Nothing to count in the last 24 hours\. Mandu last stepped in /);
  assert.doesNotMatch(older.textContent, /protection off/);
  // Zero: the same.
  assert.match((await facts({ window: { ...zero, off: 0, only: owners() } })).textContent, /^Nothing to count in the last 24 hours\. Mandu last stepped in /);
});

test("O6: Running now, Earlier and History mark a session where a protection did not start: amber, \"less protection than usual\" after the other marks; a failed one stays red", async () => {
  const LESS = "less protection than usual";
  const set = (p: string) => [
    row(`${p}-run`, { state: "running", lessProtection: true, secrets: { masked: 1, early: 0 } }),
    row(`${p}-end`, { lessProtection: true }),
    row(`${p}-bad`, { lessProtection: true, holds: false }),
    row(`${p}-all`, { lessProtection: true, protectionOff: true, holds: false, blocked: 1 }),
    row(`${p}-offless`, { lessProtection: true, protectionOff: true }),
    // No field (no protection lost, or an older server): as before.
    row(`${p}-old`, { state: "running" }),
  ];
  const { doc } = load({ extensions: "", homeVm: home({ agents: set("h"), waiting: [], verdict: "protected" }) });
  await tick();
  const run = rowIn(doc, "home-agents", "h-run");
  assert.equal(dot(run), "dot warn", "a running agent that lost a protection is not green");
  assert.equal(counts(run), `${LESS}, 1 secret masked`, "first, before the counts");
  assert.equal(dot(rowIn(doc, "home-agents", "h-old")), "dot ok");
  assert.equal(counts(rowIn(doc, "home-agents", "h-old")), null);
  assert.equal(dot(rowIn(doc, "home-earlier", "h-end")), "dot warn");
  assert.equal(counts(rowIn(doc, "home-earlier", "h-end")), LESS);
  assert.equal(dot(rowIn(doc, "home-earlier", "h-bad")), "dot bad", "protection failed outranks the amber dot");
  assert.equal(counts(rowIn(doc, "home-earlier", "h-bad")), `protection failed, ${LESS}`);
  assert.equal(counts(rowIn(doc, "home-earlier", "h-all")), `protection failed, protection was off, ${LESS}, 1 action blocked`);
  assert.equal(dot(rowIn(doc, "home-earlier", "h-all")), "dot bad");
  assert.equal(dot(rowIn(doc, "home-earlier", "h-offless")), "dot warn");
  assert.equal(counts(rowIn(doc, "home-earlier", "h-offless")), `protection was off, ${LESS}`);

  const rows = set("x");
  const hist = load({ extensions: "", url: "http://127.0.0.1:4500/mandu/history", homeVm: home(), routes: { "GET home/history": { total: rows.length, rows, next: null } } });
  await tick();
  const r = (id: string) => rowIn(hist.doc, "history-list", id);
  assert.equal(dot(r("x-run")), "dot warn");
  assert.equal(counts(r("x-run")), `${LESS}, 1 secret masked`);
  assert.equal(dot(r("x-end")), "dot warn");
  assert.equal(counts(r("x-end")), LESS);
  assert.equal(dot(r("x-bad")), "dot bad");
  assert.equal(counts(r("x-bad")), `protection failed, ${LESS}`);
  assert.equal(counts(r("x-all")), `protection failed, protection was off, ${LESS}, 1 action blocked`);
  assert.equal(dot(r("x-offless")), "dot warn");
  assert.equal(dot(r("x-old")), "dot ok");
  assert.equal(counts(r("x-old")), null);
});
