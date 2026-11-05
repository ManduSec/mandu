/**
 * home-js-hidden-poll.test — a Mandu tab in the background keeps reading
 * Home, so its notifications, its title's count and its icon keep working
 * (dashboard.md §4.25 *A background tab keeps reading*).
 *
 * Until 2026-10-25 the 10 s poll read only while the tab was `visible`.
 * Every notification is raised from that read, so a tab behind another tab
 * or in a minimised window notified on its first poll after you came back,
 * when you were already looking at it, while the program that asked waited
 * 60 s for your answer; its "(1) Mandu" and its icon stayed as you left
 * them. Now:
 *
 *   - while `hidden`, the tick reads `/api/home`: a new waiting ask raises
 *     one notification and the title counts it;
 *   - the reads only a person looking at the page needs wait: no services
 *     row (`control/summary`), no session page (`home/agent`);
 *   - the screen-reader line `#top-announce` says nothing while hidden and,
 *     on the return, says what arrived meanwhile, once;
 *   - with notifications turned off a hidden tab shows none but still
 *     counts in its title;
 *   - a page the browser prerenders reads nothing, as before.
 *
 * Drives the PRODUCT page script (public/js/home.js) in jsdom over the
 * shared fetch stub and Notification stub (home-js-fixtures.ts), with the
 * page's setInterval captured so a test fires the tick itself; across a real
 * arbiter and dashboard, tests/stack/hidden-tab-notifies.test.ts. Axes: none
 * (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { ASK, home, load, tick } from "./home-js-fixtures.js";

const SETTINGS_URL = "http://127.0.0.1:4500/mandu/settings";
const AGENT_URL = "http://127.0.0.1:4500/mandu/agents/s1";
/** A browser that already primed and saw egr-1. */
const PRIMED = { "mandu.home.notifyPrimed": "1", "mandu.home.seenAsks": JSON.stringify(["egr-1"]) };
const ASK2 = { ...ASK, id: "egr-2", agents: ["Codex CLI"] };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Any = any;

/** A page whose visibility a test sets, and whose 10 s tick it fires. */
function page(opts: { url?: string; storage?: Record<string, string>; visibility?: string } = {}) {
  let visibility = opts.visibility ?? "visible";
  const ticks: (() => void)[] = [];
  const p = load({
    url: opts.url, storage: opts.storage ?? PRIMED,
    before: (w: Any) => {
      w.setInterval = (fn: () => void) => { ticks.push(fn); return ticks.length; };
      Object.defineProperty(w.document, "visibilityState", { configurable: true, get: () => visibility });
    },
  });
  assert.equal(p.err, null);
  assert.equal(ticks.length, 1, "one poll");
  const reads = (path: string) => p.calls.filter((c) => c.method === "GET" && c.url.split("?")[0] === "/mandu/api/" + path).length;
  return {
    ...p, reads,
    /** The 10 s tick, then its reads' answers. */
    tick10: async () => { ticks[0]!(); await tick(40); },
    /** Another tab, or back to this one. */
    turn: async (state: "hidden" | "visible") => {
      visibility = state;
      p.doc.dispatchEvent(new p.window.Event("visibilitychange"));
      await tick(40);
    },
  };
}
const said = (doc: Any): string => doc.getElementById("top-announce").textContent;

test("hidden: the tick reads Home, a new ask notifies once and the title counts it", async () => {
  const p = page();
  await tick(40);
  assert.equal(p.notes.length, 0, "egr-1 was seen before");
  await p.turn("hidden");
  const before = p.reads("home");
  assert.equal(p.reads("home"), before, "going to the background reads nothing by itself");
  p.setHome(home({ waiting: [ASK, ASK2] }));
  await p.tick10();
  assert.equal(p.reads("home"), before + 1, "the hidden tab read Home");
  assert.equal(p.notes.length, 1, "one notification, from the background");
  assert.equal(p.notes[0]!.title, "Mandu: Codex CLI needs your OK");
  assert.equal(p.notes[0]!.tag, "mandu-ask-egr-2");
  assert.match(p.doc.title, /^\(2\) /, "the title counts what waits");
  assert.equal(p.doc.getElementById("nav-approvals-count").textContent, "2");
  const icon = p.doc.getElementById("favicon").getAttribute("href");
  assert.match(icon, /^data:image\/svg\+xml,/, "the icon carries the count");
  assert.match(decodeURIComponent(icon.replace(/%3C/g, "<").replace(/%3E/g, ">")), />2<\/text>/);
  await p.tick10();
  assert.equal(p.notes.length, 1, "the next hidden tick does not notify it again");
});

test("hidden on Settings: the tick does not read the services row; the return does", async () => {
  const p = page({ url: SETTINGS_URL });
  await tick(40);
  await p.tick10();
  const services = p.reads("control/summary");
  assert.ok(services >= 1, "a shown Settings follows the service");
  await p.turn("hidden");
  await p.tick10();
  await p.tick10();
  assert.equal(p.reads("control/summary"), services, "hidden: the services row waits");
  const homes = p.reads("home");
  await p.turn("visible");
  assert.equal(p.reads("home"), homes + 1, "the return reads Home at once");
  assert.equal(p.reads("control/summary"), services + 1, "and the services row");
});

test("hidden on a session page: the tick reads Home but not the session", async () => {
  const p = page({ url: AGENT_URL });
  await tick(40);
  await p.tick10();
  const agent = p.reads("home/agent");
  assert.ok(agent >= 2, "a shown session page reads its session with each poll");
  await p.turn("hidden");
  const homes = p.reads("home");
  await p.tick10();
  assert.equal(p.reads("home"), homes + 1, "Home was read");
  assert.equal(p.reads("home/agent"), agent, "the session page waits");
  await p.turn("visible");
  assert.equal(p.reads("home/agent"), agent + 1, "the return reads the session at once");
});

test("the screen-reader line says nothing while hidden and, on the return, says what arrived meanwhile, once", async () => {
  const p = page();
  await tick(40);
  await p.turn("hidden");
  p.setHome(home({ waiting: [ASK, ASK2] }));
  await p.tick10();
  assert.equal(p.notes.length, 1, "the notification came");
  assert.equal(said(p.doc), "", "nothing said to a page no one looks at");
  await p.turn("visible");
  assert.equal(said(p.doc), "Codex CLI needs your OK. 2 waiting in Approvals.", "said on the return");
  p.doc.getElementById("top-announce").textContent = "";
  await p.tick10();
  assert.equal(said(p.doc), "", "said once");
});

test("notifications turned off: a hidden tab shows none but its title still counts", async () => {
  const p = page({ storage: { ...PRIMED, "mandu.home.notifyOff": "1" } });
  await tick(40);
  await p.turn("hidden");
  p.setHome(home({ waiting: [ASK, ASK2] }));
  await p.tick10();
  assert.equal(p.notes.length, 0, "off: no notification");
  assert.match(p.doc.title, /^\(2\) /, "the title counts what waits");
});

test("a page the browser prerenders reads nothing on the tick, as before", async () => {
  const p = page({ visibility: "prerender" });
  await tick(40);
  const homes = p.reads("home");
  await p.tick10();
  assert.equal(p.reads("home"), homes);
});

test("Settings › Notifications' On line says it works while a tab is open, also in the background", async () => {
  const p = page({ url: SETTINGS_URL });
  await tick(40);
  assert.match(p.doc.getElementById("notify-state").textContent,
    /, while a Mandu tab is open in this browser, also in the background\.$/);
});
