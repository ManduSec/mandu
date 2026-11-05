/**
 * home-js-history-found.test — dashboard.md §4.25ae *By a secret or a host*
 * (#249). History's search also finds a session by the secrets that came up
 * in it and the hosts its sends went to; the page says why such a row is
 * listed, and a read that could not look at every session says how far it
 * looked:
 *
 *   G1  a row with `found` draws "Found here: …" under its line, at most
 *       three names, then "and N more"; a row without it draws nothing new;
 *   G2  a search that stopped short of the oldest session (`query.through`)
 *       with matches: the status line reads "1 in the newest 200 of 514
 *       sessions" and the more line "Looked through 200 of 514 sessions."
 *       with Show more, which reads on with the same search;
 *   G3  with none yet: never "No session matches": the list says "None of
 *       the newest 200 of 514 sessions matches “…”." with Show more, and
 *       the status line claims nothing;
 *   G4  the hint names what the box finds;
 *   G5  each name is a link into its session where it came up (#301): a
 *       secret at Your secrets (`?go=secrets`), "a send to …" at the sent
 *       steps (`?go=sent`), "a blocked send to …" at the blocked steps
 *       (`?go=blocked`); "and N more" stays words; an older server's plain
 *       strings, or an unknown `go`, draw words as before;
 *   G6  pressed, a name lands on Your secrets' heading or the blocked step,
 *       while a press elsewhere on the row still opens the session at its
 *       top.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, home, load, tick } from "./home-js-fixtures.js";

const URL = "http://127.0.0.1:4500/mandu/history";
const row = (id: string, over: Record<string, unknown> = {}) => ({
  id, agent: "Claude Code", title: `Task ${id}`, cwd: "/home/u/ws", startedAt: "2026-09-01T10:00:00.000Z", lastAt: "2026-09-01T10:05:00.000Z", state: "idle",
  stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 }, secrets: { masked: 0, early: 0 }, untrusted: 0, blocked: 0, sent: 0, holds: true, waiting: 0, notice: null, preview: null, ...over,
});
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const ids = (doc: any) => ([...doc.querySelectorAll("#history-list .row.agent")] as any[]).map((r) => r.dataset.session);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const historyCalls = (calls: any[]) => calls.filter((c) => c.url.startsWith("/mandu/api/home/history")).map((c) => c.url.slice("/mandu/api/".length));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const found = (doc: any, id: string) => doc.querySelector(`#history-list .row.agent[data-session="${id}"] .history-found`);
/** A found name as the server sends it (#301). */
const F = (name: string, go: string) => ({ name, go });
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const links = (doc: any, id: string) => ([...(found(doc, id)?.querySelectorAll("a") ?? [])] as any[]).map((a) => [a.textContent, a.getAttribute("href"), a.dataset.land]);

test("G1: a row found by its secrets or hosts says why under its line, three names then 'and N more'; others draw nothing new", async () => {
  const r = {
    total: 3, next: null, query: { text: "stripe", all: 9 },
    rows: [
      row("s1", { title: "Why does the stripe webhook fail?" }),
      row("s2", { found: [F("STRIPE_KEY in ~/proj/.env", "secrets"), F("a send to api.stripe.com", "sent")] }),
      row("s3", { found: [F("STRIPE_KEY in ~/proj/.env", "secrets"), F("STRIPE_OLD in ~/proj/.env.bak", "secrets"), F("a send to api.stripe.com", "sent"), F("a send to files.stripe.com", "sent"), F("a send to m.stripe.network", "sent")] }),
    ],
  };
  const { doc } = load({ extensions: "", url: `${URL}?q=stripe`, homeVm: home(), routes: { "GET home/history?q=stripe": r } });
  await tick();
  assert.deepEqual(ids(doc), ["s1", "s2", "s3"]);
  assert.equal(found(doc, "s1"), null, "found by its own words: nothing new");
  assert.equal(found(doc, "s2").textContent, "Found here: STRIPE_KEY in ~/proj/.env and a send to api.stripe.com");
  assert.equal(found(doc, "s3").textContent, "Found here: STRIPE_KEY in ~/proj/.env, STRIPE_OLD in ~/proj/.env.bak, a send to api.stripe.com and 2 more");
  assert.ok(found(doc, "s2").closest(".agent-what"), "under the row's line, beside its counts");
  assert.equal(doc.getElementById("history-count").textContent, "3 of 9 sessions", "it looked through every session: the count is exact");
  // Without a search, no row carries found, and none draws it.
  const plain = load({ extensions: "", url: URL, homeVm: home(), routes: { "GET home/history": { total: 2, rows: [row("a"), row("b")], next: "b" } } });
  await tick();
  assert.equal(plain.doc.querySelectorAll("#history-list .history-found").length, 0);
});

test("G2: a search that stopped short says how far it looked, and Show more reads on with the same search", async () => {
  const first = { total: 1, rows: [row("s7", { found: [F("a blocked send to pastebin.com", "blocked")] })], next: "s200", query: { text: "pastebin", all: 514, through: 200, of: 514 } };
  const more = { total: 2, rows: [row("s300", { found: [F("a blocked send to pastebin.com", "blocked")] })], next: null, query: { text: "pastebin", all: 514 } };
  const { doc, calls } = load({ extensions: "", url: `${URL}?q=pastebin`, homeVm: home(), routes: { "GET home/history?q=pastebin": first, "GET home/history?after=s200&q=pastebin": more } });
  await tick();
  assert.deepEqual(ids(doc), ["s7"]);
  assert.equal(doc.getElementById("history-count").textContent, "1 in the newest 200 of 514 sessions");
  assert.equal(doc.querySelector("#history-list .history-more span").textContent, "Looked through 200 of 514 sessions.");
  doc.querySelector("#history-list .history-more button").click();
  await tick();
  assert.deepEqual(ids(doc), ["s7", "s300"]);
  assert.equal(doc.getElementById("history-count").textContent, "2 of 514 sessions", "it reached the oldest: exact");
  assert.equal(doc.querySelector("#history-list .history-more"), null, "nothing left");
  assert.deepEqual(historyCalls(calls), ["home/history?q=pastebin", "home/history?after=s200&q=pastebin"]);
});

test("G3: none in the sessions looked through is never 'No session matches'", async () => {
  const none = { total: 0, rows: [], next: "s200", query: { text: "pastebin", all: 514, through: 200, of: 514 } };
  const { doc } = load({ extensions: "", url: `${URL}?q=pastebin`, homeVm: home(), routes: { "GET home/history?q=pastebin": none } });
  await tick();
  const list = doc.getElementById("history-list");
  assert.doesNotMatch(list.textContent, /No session matches/);
  assert.equal(list.querySelector(".history-more span").textContent, "None of the newest 200 of 514 sessions matches “pastebin”.");
  assert.ok(list.querySelector(".history-more button.show-rest"), "Show more goes on");
  assert.doesNotMatch(doc.getElementById("history-count").textContent, /No session matches/);
});

test("G4: the hint names what the box finds", async () => {
  const { doc } = load({ extensions: "", url: URL, homeVm: home(), routes: { "GET home/history": { total: 0, rows: [], next: null } } });
  await tick();
  assert.equal(doc.getElementById("history-q").getAttribute("placeholder"), "What you asked, a folder, secret or host");
});

test("G5: each found name links into its session where it came up; 'and N more' and an older server's strings stay words (#301)", async () => {
  const r = {
    total: 3, next: null, query: { text: "stripe", all: 9 },
    rows: [
      row("s2", { found: [F("STRIPE_KEY in ~/proj/.env", "secrets"), F("a send to api.stripe.com", "sent"), F("a blocked send to pastebin.com", "blocked")] }),
      row("s3", { found: [F("STRIPE_KEY in ~/proj/.env", "secrets"), F("a send to api.stripe.com", "sent"), F("a blocked send to pastebin.com", "blocked"), F("a send to files.stripe.com", "sent")] }),
      // An older server's strings; a `go` the page does not know; junk.
      row("s4", { found: ["STRIPE_KEY in ~/proj/.env", F("a send to api.stripe.com", "nonsense"), { go: "sent" }, null, 7] }),
    ],
  };
  const { doc } = load({ extensions: "", url: `${URL}?q=stripe`, homeVm: home(), routes: { "GET home/history?q=stripe": r } });
  await tick();
  assert.equal(found(doc, "s2").textContent, "Found here: STRIPE_KEY in ~/proj/.env, a send to api.stripe.com and a blocked send to pastebin.com");
  assert.deepEqual(links(doc, "s2"), [
    ["STRIPE_KEY in ~/proj/.env", "/mandu/agents/s2?go=secrets", "secrets"],
    ["a send to api.stripe.com", "/mandu/agents/s2?go=sent", "sent"],
    ["a blocked send to pastebin.com", "/mandu/agents/s2?go=blocked", "blocked"],
  ]);
  for (const a of found(doc, "s2").querySelectorAll("a")) {
    assert.equal(a.dataset.pageLink, "agent");
    assert.equal(a.dataset.session, "s2");
    assert.equal(a.getAttribute("tabindex"), null, "a tab stop of its own, as any link");
  }
  assert.equal(found(doc, "s3").textContent, "Found here: STRIPE_KEY in ~/proj/.env, a send to api.stripe.com, a blocked send to pastebin.com and 1 more");
  assert.equal(links(doc, "s3").length, 3, "'and 1 more' is words, not a link");
  assert.equal(found(doc, "s3").lastChild.nodeType, 3);
  assert.equal(found(doc, "s4").textContent, "Found here: STRIPE_KEY in ~/proj/.env and a send to api.stripe.com", "an older server's strings, as before");
  assert.deepEqual(links(doc, "s4"), [], "no go the page knows: words");
});

test("G6: a name pressed lands on Your secrets or the blocked step; a press elsewhere on the row opens the session at its top (#301)", async () => {
  const secrets = { mode: "secrets", flagged: false, more: 0, counts: { masked: 1, early: 0 }, secrets: [] };
  const page = { ...AGENT, id: "s2", waiting: [], earlier: 0, secrets };
  const r = { total: 1, next: null, query: { text: "stripe", all: 9 }, rows: [row("s2", { found: [F("STRIPE_KEY in ~/proj/.env", "secrets"), F("a blocked send to evil.example", "blocked")] })] };
  const routes = { "GET home/history?q=stripe": r, "GET home/agent?session=s2": page };
  const open = async () => {
    const at = load({ extensions: "", url: `${URL}?q=stripe`, homeVm: home(), routes });
    await tick();
    return at;
  };
  // Your secrets.
  const one = await open();
  found(one.doc, "s2").querySelector('a[data-land="secrets"]').click();
  await tick();
  assert.equal(one.doc.defaultView.location.pathname, "/mandu/agents/s2");
  assert.equal(one.doc.getElementById("page-agent").hidden, false);
  assert.equal(one.doc.activeElement, one.doc.getElementById("agent-secrets-block").querySelector("h2"), "Your secrets' heading has the focus");
  // The blocked step.
  const two = await open();
  found(two.doc, "s2").querySelector('a[data-land="blocked"]').click();
  await tick();
  assert.equal(two.doc.defaultView.location.pathname, "/mandu/agents/s2");
  assert.equal(two.doc.activeElement.dataset.stepId, "os1", "the blocked step has the focus");
  assert.equal(two.doc.activeElement.dataset.outcome, "blocked");
  // The row elsewhere: the session's top, nothing landed on.
  const three = await open();
  three.doc.querySelector('#history-list .row.agent[data-session="s2"] .agent-what .sub').dispatchEvent(new three.doc.defaultView.MouseEvent("click", { bubbles: true, cancelable: true }));
  await tick();
  assert.equal(three.doc.defaultView.location.pathname, "/mandu/agents/s2");
  assert.equal(three.doc.getElementById("page-agent").hidden, false);
  assert.equal(three.doc.activeElement.dataset?.stepId, undefined, "no step has the focus");
  assert.notEqual(three.doc.activeElement, three.doc.getElementById("agent-secrets-block").querySelector("h2"));
});
