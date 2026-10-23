/**
 * home-js-section-links.test — Rules and Settings on the PRODUCT page each
 * carry a row of links under the title, one per card, and each card has an
 * address (`/rules#keys-found`): public/js/home.js `SECTIONS`,
 * `drawSectionLinks`, `goToSection` and the hash in `parseRoute` /
 * `stateHref` (dashboard.md §4.25 *Section links*), driven in jsdom over the
 * shared fetch stub (home-js-fixtures.ts).
 *
 * Until 2026-10-18 neither page had any in-page navigation and no card an
 * address: Rules is the longest page (Keys Mandu found two screens down),
 * the links that open a card scrolled by script, and the same link opened in
 * a new tab landed at the top.
 *
 * Pins: each link names an existing card, in the page's order, under the
 * title; a click scrolls its card to the top, focuses the card's heading and
 * writes the hash without a new history entry; a modifier click is left to
 * the browser, the hash in its href; an address with a hash lands on that
 * card once the page and Home's first read have drawn, the focus on its
 * heading; an unknown hash
 * opens the top and goes from the address; a link that opens a card from
 * another page (openAtCard) writes that card's address; a nav link to the
 * page opens it without one; Back to an address with a card returns to
 * where you left the page, not to the card (since 2026-10-22, §4.25 *Back
 * and Forward keep your place*).
 *
 * Approvals since 2026-10-23: its five lists (Keys Mandu found, the rule
 * changes asked for, Waiting, Answered earlier, Rule changes) had no link
 * and no address, and Rule changes, the only Undo of a rule change, came
 * after every answer. Pins: each link names its list; a list hidden while
 * empty has no link and gets one when it shows, the row changed in place
 * (the focus stays on a link); a click writes the key; `/approvals#answered`
 * lands there; a hidden list's address, or an address naming one item
 * (`/approvals/<id>`), opens the top. Axes: none (display only).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick, home, FILES_ROUTES, ASK } from "./home-js-fixtures.js";
import { toProposalCard } from "../../../src/view-model/policy-proposals.js";
import { labelSettingsVM } from "../../../src/view-model/sensitivity-labels.js";

const BASE = "http://127.0.0.1:4500/mandu";
const ROUTES = {
  ...FILES_ROUTES,
  "GET suggestions": { suggestions: [], count: 0, scan: null },
  "GET policy/sensitivity-labels": { labels: labelSettingsVM(null, undefined, null) },
};
const RULES_LINKS = [
  ["Describe", "describe", "describe-block"],
  ["Your rules", "your-rules", "rules-block"],
  ["Who may get your secrets", "who", "by-who-block"],
  ["Keys Mandu found", "keys-found", "suggested-block"],
  ["Built-in protections", "built-in", "builtin-block"],
];
const SETTINGS_LINKS = [
  ["Protection", "protection", "settings-protection-block"],
  ["Models", "models", "settings-models-block"],
  ["Sensitivity labels", "sensitivity-labels", "settings-labels-block"],
  ["Prompt filters", "prompt-filters", "settings-prompt-block"],
  ["Notifications", "notifications", "settings-notify-block"],
  ["Appearance", "appearance", "settings-appearance-block"],
  ["About", "about", "settings-about-block"],
];

const row = (doc: any, page: string) => doc.querySelector(`#page-${page} .page-head nav.section-links`);
const links = (doc: any, page: string) => [...row(doc, page).querySelectorAll("a")] as any[];
const link = (doc: any, page: string, key: string) => links(doc, page).find((a) => a.dataset.section === key);
/** Each scroll the page makes to an element, by its id. */
const recordScrolls = (window: any) => {
  const scrolled: string[] = [];
  window.HTMLElement.prototype.scrollIntoView = function (this: any) { scrolled.push(this.id); };
  return scrolled;
};

test("under each title, a link per card, in the page's order: each names an existing card by its heading's words", async () => {
  for (const [page, want] of [["rules", RULES_LINKS], ["settings", SETTINGS_LINKS]] as const) {
    const { doc } = load({ url: `${BASE}/${page}`, routes: ROUTES });
    await tick();
    const nav = row(doc, page);
    assert.ok(nav, `${page}: the row is under the title`);
    assert.equal(nav.getAttribute("aria-label"), `Sections of ${page === "rules" ? "Rules" : "Settings"}`);
    const got = links(doc, page).map((a) => [a.textContent, a.dataset.section, a.getAttribute("href")]);
    assert.deepEqual(got, want.map(([words, key]) => [words, key, `/mandu/${page}#${key}`]));
    for (const [words, , id] of want) {
      const card = doc.getElementById(id);
      assert.ok(card, `${words}: card #${id} exists`);
      assert.equal(card.closest("section[data-page]").dataset.page, page, `${words}: on its page`);
      assert.ok(card.querySelector("h2").textContent.startsWith(words), `${words}: the card's heading starts with the link's words`);
    }
  }
});

test("Settings' row reads Protection · Models · Sensitivity labels · Prompt filters · Notifications · Appearance · About", async () => {
  const { doc } = load({ url: `${BASE}/settings`, routes: ROUTES });
  await tick();
  // The "·" between them is the stylesheet's.
  assert.equal(links(doc, "settings").map((a) => a.textContent).join(" · "), "Protection · Models · Sensitivity labels · Prompt filters · Notifications · Appearance · About");
});

test("a click scrolls its card to the top, gives the card's heading the focus and puts its key in the address, replaced", async () => {
  const { doc, window } = load({ url: `${BASE}/rules`, routes: ROUTES });
  await tick();
  const scrolled = recordScrolls(window);
  const entries = window.history.length;
  link(doc, "rules", "keys-found").click();
  assert.deepEqual(scrolled, ["suggested-block"]);
  assert.equal(doc.activeElement, doc.getElementById("suggested-title"), "the card's heading has the focus");
  assert.equal(window.location.pathname + window.location.hash, "/mandu/rules#keys-found");
  assert.equal(window.history.length, entries, "no new history entry: Back still leaves the page");
  assert.equal(doc.getElementById("page-rules").hidden, false, "the page stays");
  // Another: the address follows.
  link(doc, "rules", "built-in").click();
  assert.deepEqual(scrolled, ["suggested-block", "builtin-block"]);
  assert.equal(window.location.hash, "#built-in");
  assert.equal(doc.activeElement, doc.querySelector("#builtin-block h2"));
});

test("a modifier click is the browser's: not handled, the card's address in its href", async () => {
  const { doc, window } = load({ url: `${BASE}/settings`, routes: ROUTES });
  await tick();
  const scrolled = recordScrolls(window);
  let prevented: boolean | null = null;
  doc.addEventListener("click", (e: any) => { prevented = e.defaultPrevented; e.preventDefault(); });
  const a = link(doc, "settings", "prompt-filters");
  for (const mod of ["ctrlKey", "metaKey", "shiftKey"]) {
    prevented = null;
    a.dispatchEvent(new window.MouseEvent("click", { bubbles: true, cancelable: true, [mod]: true }));
    assert.equal(prevented, false, `${mod}: left to the browser`);
  }
  assert.equal(a.getAttribute("href"), "/mandu/settings#prompt-filters", "a new tab opens at the card");
  assert.deepEqual(scrolled, [], "this page does not move");
  assert.equal(window.location.hash, "");
});

test("an address with a card's key lands on that card once the page has drawn, the focus on its heading", async () => {
  for (const [url, id, head] of [
    [`${BASE}/rules#keys-found`, "suggested-block", "suggested-title"],
    [`${BASE}/settings#prompt-filters`, "settings-prompt-block", "settings-prompt-title"],
    [`${BASE}/settings#notifications`, "settings-notify-block", "settings-notify-title"],
    [`${BASE}/settings#about`, "settings-about-block", "settings-about-title"],
  ]) {
    const scrolled: string[] = [];
    const { doc, window } = load({ url, routes: ROUTES, before: (w) => { w.HTMLElement.prototype.scrollIntoView = function (this: any) { scrolled.push(this.id); }; } });
    await tick();
    assert.deepEqual(scrolled, [id], `${url}: one scroll, to its card`);
    assert.equal(doc.activeElement, doc.getElementById(head), `${url}: the card's heading has the focus`);
    assert.equal(window.location.href, url, `${url}: the address keeps its hash`);
  }
});

test("an address with a card's key waits for Home's first read too: it draws Built-in protections, and the page would grow under the card", async () => {
  let release!: () => void;
  const gate = new Promise<void>((r) => { release = r; });
  const scrolled: string[] = [];
  const { doc } = load({
    url: `${BASE}/rules#built-in`, routes: { ...ROUTES, "GET home": () => gate.then(() => home()) },
    before: (w) => { w.HTMLElement.prototype.scrollIntoView = function (this: any) { scrolled.push(this.id); }; },
  });
  await tick();
  assert.equal(doc.querySelectorAll("#builtin-list li").length, 0, "Built-in protections is not drawn yet");
  assert.deepEqual(scrolled, [], "no scroll before it is");
  release();
  await tick();
  assert.ok(doc.querySelectorAll("#builtin-list li").length > 0, "drawn");
  assert.deepEqual(scrolled, ["builtin-block"]);
  assert.equal(doc.activeElement, doc.querySelector("#builtin-block h2"));
});

test("an unknown hash, or another page's card, opens the page at its top and goes from the address", async () => {
  for (const url of [`${BASE}/rules#nowhere`, `${BASE}/rules#prompt-filters`, `${BASE}/settings#`]) {
    const scrolled: string[] = [];
    const { doc, window } = load({ url, routes: ROUTES, before: (w) => { w.HTMLElement.prototype.scrollIntoView = function (this: any) { scrolled.push(this.id); }; } });
    await tick();
    assert.deepEqual(scrolled, [], `${url}: no scroll`);
    assert.equal(window.location.hash, "", `${url}: the hash goes`);
    assert.notEqual(doc.activeElement?.tagName, "H2", `${url}: no card's heading took the focus`);
  }
});

test("a link that opens a card from another page writes that card's address; a nav link opens the page without one", async () => {
  const { doc, window } = load({ url: `${BASE}/settings`, routes: ROUTES });
  await tick();
  const scrolled = recordScrolls(window);
  // Settings › Sensitivity labels' note: Keys Mandu found on Rules (openSuggested).
  const note = doc.querySelector("#settings-labels .labels-note a");
  assert.equal(note.getAttribute("href"), "/mandu/rules#keys-found");
  note.click();
  await tick();
  assert.equal(window.location.pathname + window.location.hash, "/mandu/rules#keys-found");
  assert.deepEqual(scrolled, ["suggested-block"]);
  assert.equal(doc.activeElement, doc.getElementById("suggested-title"));
  // Where the card's landing left the page (jsdom has no layout); then a
  // scroll down from it.
  const to: number[] = [];
  Object.defineProperty(window, "scrollY", { value: 2100, writable: true, configurable: true });
  window.scrollTo = (_x: number, y: number) => { to.push(y); window.scrollY = y; };
  // The top bar's Settings link, then Rules: each page at its top, no hash.
  doc.querySelector('#nav a[data-page-link="settings"]').click();
  await tick();
  assert.equal(window.location.pathname + window.location.hash, "/mandu/settings");
  doc.querySelector('#nav a[data-page-link="rules"]').click();
  await tick();
  assert.equal(window.location.pathname + window.location.hash, "/mandu/rules");
  assert.deepEqual(scrolled, ["suggested-block"], "no scroll to a card");
  // Back to the address with the card: where you left the page, not the
  // card (§4.25 *Back and Forward keep your place*: the place wins).
  const mark = to.length;
  window.history.go(-2);
  await new Promise((r) => setTimeout(r, 50));
  await tick();
  assert.equal(window.location.pathname + window.location.hash, "/mandu/rules#keys-found", "the address still names the card");
  assert.deepEqual(scrolled, ["suggested-block"], "Back scrolls to no card");
  assert.deepEqual(to.slice(mark), [2100], "the place you left");
  assert.equal(doc.activeElement, doc.querySelector("#page-rules h1"), "the focus on the page's heading");
});

// ── Approvals (2026-10-23) ──────────────────────────────────────────────────
const APPROVALS_LINKS = [
  ["Keys Mandu found", "keys-found", "approvals-suggestions-block"],
  ["Rule changes asked for", "asked-for", "approvals-proposals-block"],
  ["Waiting", "waiting", "approvals-waiting-block"],
  ["Answered earlier", "answered", "approvals-answered-block"],
  ["Rule changes", "rule-changes", "approvals-rule-history-block"],
];
const PENDING = "GET policy/proposals?status=pending";
const CHANGES = "GET policy/changes?limit=21";
const PROPOSAL = toProposalCard({
  id: "pp-000001", edits: [{ op: "trust-origin", kind: "url", pattern: "https://pypi.org/" }], reason: "I need the package index",
  requestedBy: "agent:s1", sessionKey: "s1",
  relaxes: [{ facet: "origins", direction: "relax", subject: "URL:https://pypi.org/", detail: "" }], tightens: [],
  status: "pending", createdAt: Date.now() - 60_000, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
});
const CHANGE = {
  id: "pc-000001", sentence: "You changed a rule on the Rules page", rows: [[{ kind: "text", text: "Hide " }, { kind: "code", text: "~/proj/x.pem" }]],
  createdAt: Date.now() - 60_000, undone: false, undoable: true, session: null,
};
const ANSWERED = { ...ASK, id: "egr-old", state: "blocked", answeredAt: new Date(Date.now() - 3_600_000).toISOString() };
async function poll(doc: any): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}
/** The links shown, by key. */
const shown = (doc: any) => links(doc, "approvals").filter((a) => !a.closest("li").hidden).map((a) => a.dataset.section);

test("Approvals: a link per list under the title, in the page's order, each naming its list's id", async () => {
  const { doc } = load({
    url: `${BASE}/approvals`,
    routes: { ...ROUTES, [PENDING]: { proposals: [PROPOSAL] }, [CHANGES]: { changes: [CHANGE] }, "GET suggestions": { suggestions: [{ id: "g1", rule: "stripe", path: "/home/u/ws/.env", repo: "ws", source: "workspace", line: 1 }], count: 1, scan: null } },
  });
  await tick(40);
  const nav = row(doc, "approvals");
  assert.ok(nav, "the row is under the title");
  assert.equal(nav.getAttribute("aria-label"), "Sections of Approvals");
  const got = links(doc, "approvals").map((a) => [a.textContent, a.dataset.section, a.getAttribute("href")]);
  assert.deepEqual(got, APPROVALS_LINKS.map(([words, key]) => [words, key, `/mandu/approvals#${key}`]));
  for (const [words, , id] of APPROVALS_LINKS) {
    const card = doc.getElementById(id);
    assert.ok(card, `${words}: list #${id} exists`);
    assert.equal(card.closest("section[data-page]").dataset.page, "approvals", `${words}: on Approvals`);
    assert.equal(card.hidden, false, `${words}: shown here`);
  }
  assert.deepEqual(shown(doc), ["keys-found", "asked-for", "waiting", "answered", "rule-changes"], "every list shows: every link does");
  assert.equal(doc.querySelectorAll("#page-approvals nav.section-links li.end").length, 1, "one link ends the row");
  assert.equal(doc.querySelector("#page-approvals nav.section-links li.end a").dataset.section, "rule-changes");
});

test("Approvals: a list hidden while empty has no link; it gets one when it shows, the row changed in place", async () => {
  let proposals: unknown[] = [];
  const { doc } = load({ url: `${BASE}/approvals`, routes: { ...ROUTES, [PENDING]: () => ({ proposals }), [CHANGES]: { changes: [] } } });
  await tick(40);
  assert.equal(doc.getElementById("approvals-proposals-block").hidden, true);
  assert.deepEqual(shown(doc), ["waiting", "answered"], "only the lists shown have a link");
  assert.equal(doc.querySelector("#page-approvals nav.section-links li.end a").dataset.section, "answered", "no '·' after the last link shown");
  // The focus on a link, then a poll brings a rule change your agent asked for.
  const answered = link(doc, "approvals", "answered");
  answered.focus();
  proposals = [PROPOSAL];
  await poll(doc);
  assert.equal(doc.getElementById("approvals-proposals-block").hidden, false, "the list shows");
  assert.deepEqual(shown(doc), ["asked-for", "waiting", "answered"], "and its link");
  assert.equal(link(doc, "approvals", "answered"), answered, "the row was not drawn again");
  assert.equal(doc.activeElement, answered, "the focus stays on the link");
  // It goes again: so does its link.
  proposals = [];
  await poll(doc);
  assert.deepEqual(shown(doc), ["waiting", "answered"]);
  // Rules and Settings keep every link (their cards do not hide while empty).
  assert.equal(links(doc, "rules").filter((a) => a.closest("li").hidden).length, 0);
});

test("Approvals: a click scrolls its list to the top, focuses its heading and puts its key in the address, replaced", async () => {
  const { doc, window } = load({ url: `${BASE}/approvals`, routes: { ...ROUTES, [CHANGES]: { changes: [CHANGE] } } });
  await tick(40);
  const scrolled = recordScrolls(window);
  const entries = window.history.length;
  link(doc, "approvals", "answered").click();
  assert.deepEqual(scrolled, ["approvals-answered-block"]);
  assert.equal(doc.activeElement, doc.querySelector("#approvals-answered-block h2"));
  assert.equal(window.location.pathname + window.location.hash, "/mandu/approvals#answered");
  assert.equal(window.history.length, entries, "no new history entry");
  link(doc, "approvals", "rule-changes").click();
  assert.deepEqual(scrolled, ["approvals-answered-block", "approvals-rule-history-block"]);
  assert.equal(window.location.hash, "#rule-changes");
  assert.equal(doc.activeElement, doc.querySelector("#approvals-rule-history-block h2"));
});

test("Approvals: an address with a list's key lands there once Rule changes and Home have read; a hidden list's opens the top", async () => {
  let release!: () => void;
  const gate = new Promise<void>((r) => { release = r; });
  const scrolled: string[] = [];
  const before = (w: any) => { w.HTMLElement.prototype.scrollIntoView = function (this: any) { scrolled.push(this.id); }; };
  const { doc, window } = load({
    url: `${BASE}/approvals#rule-changes`, homeVm: home({ answered: [ANSWERED] }),
    routes: { ...ROUTES, [CHANGES]: () => gate.then(() => ({ changes: [CHANGE] })) }, before,
  });
  await tick(40);
  assert.deepEqual(scrolled, [], "no scroll before Rule changes has read");
  release();
  await tick(40);
  assert.deepEqual(scrolled, ["approvals-rule-history-block"]);
  assert.equal(doc.activeElement, doc.querySelector("#approvals-rule-history-block h2"));
  assert.equal(window.location.pathname + window.location.hash, "/mandu/approvals#rule-changes", "the address keeps its hash");

  for (const url of [`${BASE}/approvals#answered`, `${BASE}/approvals?q=stripe#answered`]) {
    scrolled.length = 0;
    const p = load({ url, homeVm: home({ answered: [ANSWERED] }), routes: { ...ROUTES, [CHANGES]: { changes: [] } }, before });
    await tick(40);
    assert.deepEqual(scrolled, ["approvals-answered-block"], url);
    assert.equal(p.doc.activeElement, p.doc.querySelector("#approvals-answered-block h2"), url);
    assert.equal(p.window.location.href, url, `${url}: the address keeps its hash`);
  }

  // No rule change: Rule changes is hidden, so its address opens the top.
  scrolled.length = 0;
  const empty = load({ url: `${BASE}/approvals#rule-changes`, routes: { ...ROUTES, [CHANGES]: { changes: [] } }, before });
  await tick(40);
  assert.equal(empty.doc.getElementById("approvals-rule-history-block").hidden, true);
  assert.deepEqual(scrolled, [], "no scroll");
  assert.notEqual(empty.doc.activeElement?.tagName, "H2", "no list's heading took the focus");
});

test("Approvals: an address that opens one question wins over a hash, and an unknown hash goes", async () => {
  for (const [url, want] of [
    [`${BASE}/approvals/egr-1#answered`, "/mandu/approvals/egr-1"],
    [`${BASE}/approvals#nowhere`, "/mandu/approvals"],
    [`${BASE}/approvals#who`, "/mandu/approvals"],
  ]) {
    const scrolled: string[] = [];
    const { window } = load({ url, routes: { ...ROUTES, [CHANGES]: { changes: [] } }, before: (w) => { w.HTMLElement.prototype.scrollIntoView = function (this: any) { scrolled.push(this.id); }; } });
    await tick(40);
    assert.equal(window.location.pathname + window.location.hash, want, url);
    assert.ok(!scrolled.includes("approvals-answered-block"), `${url}: not at Answered earlier`);
  }
});
