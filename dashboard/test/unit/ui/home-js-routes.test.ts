/**
 * home-js-routes.test — the product page's path URLs (dashboard.md §4.25v):
 * `routeHref` builds every route from the base path, `parseRoute` reads it
 * back (segments encoded and decoded), a retired `?page=` URL reads as its
 * page and the address bar is made canonical, an unknown or garbled path is
 * Home, and back/forward (popstate) re-reads the route. Under the `/mandu`
 * base path and unprefixed.
 *
 * Drives the PRODUCT page script (public/js/home.js) in jsdom over the shared
 * fetch stub (home-js-fixtures.ts). Axes: none (display only). Mandu-new test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick } from "./home-js-fixtures.js";

const ORIGIN = "http://127.0.0.1:4500";
const where = (w: any) => w.location.pathname + w.location.search;
/** A jsdom-realm object, as plain data (deepEqual compares prototypes). */
const plain = (o: unknown) => JSON.parse(JSON.stringify(o));
const shown = (doc: any) => [...doc.querySelectorAll("#main > section[data-page]")].filter((s: any) => !s.hidden).map((s: any) => s.dataset.page);

for (const bp of ["/mandu", ""]) {
  const at = (path: string) => load({ basePath: bp, url: ORIGIN + bp + path });

  test(`routeHref builds every route from the base path ("${bp}")`, () => {
    const { window } = at("/");
    const r = window.routeHref;
    assert.equal(r("home"), `${bp}/`);
    assert.equal(r("approvals"), `${bp}/approvals`);
    assert.equal(r("approvals", "egr-1"), `${bp}/approvals/egr-1`);
    assert.equal(r("rules"), `${bp}/rules`);
    assert.equal(r("settings"), `${bp}/settings`);
    assert.equal(r("agent", "s1"), `${bp}/agents/s1`);
    assert.equal(r("agent", "s1", "egr-7"), `${bp}/agents/s1?ask=egr-7`);
    assert.equal(r("agent"), `${bp}/`, "an agent page with no session is Home");
    assert.equal(r("nowhere"), `${bp}/`);
    assert.equal(r("agent", "sess b/2?#", "a&b=c"), `${bp}/agents/sess%20b%2F2%3F%23?ask=a%26b%3Dc`, "segments and query are encoded");
    assert.equal(r("approvals", "\"],*,[x=\""), `${bp}/approvals/%22%5D%2C*%2C%5Bx%3D%22`);
  });

  test(`parseRoute reads every route back, decoding segments ("${bp}")`, () => {
    const { window } = at("/");
    const p = (path: string, search = "") => plain(window.parseRoute(bp + path, search));
    const R = (page: string, session: string | null = null, ask: string | null = null) => ({ page, session, ask });
    assert.deepEqual(p("/"), R("home"));
    assert.deepEqual(p("/index.html"), R("home"));
    assert.deepEqual(p("/approvals"), R("approvals"));
    assert.deepEqual(p("/approvals/egr-1"), R("approvals", null, "egr-1"));
    assert.deepEqual(p("/rules"), R("rules"));
    assert.deepEqual(p("/settings"), R("settings"));
    assert.deepEqual(p("/agents/s1"), R("agent", "s1"));
    assert.deepEqual(p("/agents/s1", "?ask=egr-7"), R("agent", "s1", "egr-7"));
    assert.deepEqual(p("/agents/sess%20b%2F2%3F%23", "?ask=a%26b%3Dc"), R("agent", "sess b/2?#", "a&b=c"));
    // The switch of §4.25ae *Only where Mandu stepped in*; any other value is off.
    assert.deepEqual(p("/agents/s1", "?ask=egr-7&only=stepped-in"), { ...R("agent", "s1", "egr-7"), only: true });
    assert.deepEqual(p("/agents/s1", "?only=yes"), R("agent", "s1"));
    // A card of Rules or Settings (§4.25 *Section links*); a hash that names
    // no card of that page, or any hash on another page, is not read.
    const h = (path: string, hash: string) => plain(window.parseRoute(bp + path, "", hash));
    assert.deepEqual(h("/rules", "#keys-found"), { ...R("rules"), section: "keys-found" });
    assert.deepEqual(h("/settings", "#prompt-filters"), { ...R("settings"), section: "prompt-filters" });
    assert.deepEqual(h("/rules", "#prompt-filters"), R("rules"), "a Settings card is not on Rules");
    assert.deepEqual(h("/rules", "#nowhere"), R("rules"));
    assert.deepEqual(h("/approvals", "#who"), R("approvals"));
    if (bp) assert.deepEqual(plain(window.parseRoute(bp, "")), R("home"), "the bare base path is Home");
    // Every built URL round-trips.
    for (const [page, id, ask] of [["approvals", "q/1 %"], ["agent", "s 1/é", "a?b"], ["rules"], ["settings"], ["home"]] as [string, string?, string?][]) {
      const u = new URL(ORIGIN + window.routeHref(page, id, ask));
      const back = window.parseRoute(u.pathname, u.search);
      assert.equal(back.page, page);
      assert.equal(page === "agent" ? back.session : page === "approvals" ? back.ask : null, id ?? null);
    }
  });

  test(`parseRoute: an unknown or garbled path, or a missing / extra segment, is Home ("${bp}")`, () => {
    const { window } = at("/");
    for (const path of ["/nope", "/inbox", "/agents", "/agents/", "/agents/s1/x", "/approvals/a/b", "/rules/x", "/agents/%E0%A4%A", "/approvals/%zz"]) {
      assert.equal(window.parseRoute(bp + path, "").page, "home", path);
    }
  });

  test(`parseRoute reads a retired ?page= URL as its page ("${bp}")`, () => {
    const { window } = at("/");
    const p = (search: string) => plain(window.parseRoute(bp + "/", search));
    assert.deepEqual(p("?page=inbox&ask=egr-1"), { page: "approvals", session: null, ask: "egr-1" });
    assert.deepEqual(p("?page=inbox"), { page: "approvals", session: null, ask: null });
    assert.deepEqual(p("?page=agent&session=s1&ask=a"), { page: "agent", session: "s1", ask: "a" });
    assert.deepEqual(p("?page=agent"), { page: "home", session: null, ask: null });
    assert.deepEqual(p("?page=rules"), { page: "rules", session: null, ask: null });
    assert.deepEqual(p("?page=settings"), { page: "settings", session: null, ask: null });
    assert.deepEqual(p("?page=bogus"), { page: "home", session: null, ask: null });
  });

  test(`boot shows the page the path names and keeps a canonical address bar ("${bp}")`, async () => {
    const cases: [string, string, string][] = [
      ["/", "home", `${bp}/`],
      ["/approvals", "approvals", `${bp}/approvals`],
      ["/approvals/egr-1", "approvals", `${bp}/approvals/egr-1`],
      ["/rules", "rules", `${bp}/rules`],
      ["/settings", "settings", `${bp}/settings`],
      ["/history", "history", `${bp}/history`],
      ["/history?only=stepped-in", "history", `${bp}/history?only=stepped-in`],
      ["/history?only=stepped-in&q=deploy", "history", `${bp}/history?q=deploy&only=stepped-in`],
      ["/history?only=all", "history", `${bp}/history`],
      ["/agents/s1", "agent", `${bp}/agents/s1`],
      ["/agents/s1?ask=egr-7", "agent", `${bp}/agents/s1?ask=egr-7`],
      ["/agents/s1?only=stepped-in&ask=egr-7", "agent", `${bp}/agents/s1?ask=egr-7&only=stepped-in`],
      ["/agents/s1?only=all", "agent", `${bp}/agents/s1`],
      // A retired query URL is replaced by its path (no history entry).
      ["/?page=inbox&ask=egr-1", "approvals", `${bp}/approvals/egr-1`],
      ["/?page=agent&session=s1&ask=egr-7", "agent", `${bp}/agents/s1?ask=egr-7`],
      ["/?page=rules", "rules", `${bp}/rules`],
      ["/?page=agent", "home", `${bp}/`],
    ];
    for (const [path, page, canonical] of cases) {
      const { window, doc } = at(path);
      await tick();
      assert.deepEqual(shown(doc), [page], path);
      assert.equal(where(window), canonical, path);
      assert.equal(window.history.length, 1, `${path}: replaced, not pushed`);
    }
  });

  test(`the page's own links are absolute under the base path; a click pushes the path, Back pops it ("${bp}")`, async () => {
    const { window, doc } = at("/");
    await tick();
    const nav = (k: string) => doc.querySelector(`#nav a[data-page-link="${k}"]`) as any;
    assert.equal(nav("home").getAttribute("href"), `${bp}/`);
    assert.equal(nav("approvals").getAttribute("href"), `${bp}/approvals`);
    assert.equal(nav("rules").getAttribute("href"), `${bp}/rules`);
    assert.equal(nav("settings").getAttribute("href"), `${bp}/settings`);
    assert.equal(nav("history").getAttribute("href"), `${bp}/history`);
    assert.equal(doc.querySelector("a.brand").getAttribute("href"), `${bp}/`);
    nav("rules").click();
    await tick();
    assert.equal(where(window), `${bp}/rules`);
    assert.equal(window.history.length, 2);
    nav("approvals").click();
    await tick();
    assert.equal(where(window), `${bp}/approvals`);
    // Back: jsdom does not navigate history itself, so stand in for it.
    window.history.replaceState(null, "", `${bp}/rules`);
    window.dispatchEvent(new window.PopStateEvent("popstate"));
    assert.deepEqual(shown(doc), ["rules"]);
    window.history.replaceState(null, "", `${bp}/agents/s1?ask=egr-1`);
    window.dispatchEvent(new window.PopStateEvent("popstate"));
    await tick();
    assert.deepEqual(shown(doc), ["agent"]);
    assert.equal(where(window), `${bp}/agents/s1?ask=egr-1`, "popstate leaves a canonical URL alone");
  });

  // History is a page link of the top bar (§4.25ae): marked on its own
  // page as the other four are on theirs, and one click from every page.
  test(`the top bar marks the current page, History on /history and none on a session page; its History link opens History ("${bp}")`, async () => {
    const marked = (doc: any) => [...doc.querySelectorAll("#nav a")].filter((a: any) => a.getAttribute("aria-current") === "page").map((a: any) => a.dataset.pageLink);
    for (const [path, page] of [["/", "home"], ["/approvals", "approvals"], ["/rules", "rules"], ["/settings", "settings"], ["/history", "history"]]) {
      const { doc } = at(path);
      await tick();
      assert.deepEqual(marked(doc), [page], `${path}: only ${page} is the current page`);
    }
    const { window, doc } = at("/agents/s1");
    await tick();
    assert.deepEqual(shown(doc), ["agent"]);
    assert.deepEqual(marked(doc), [], "a session page marks no page link");
    (doc.querySelector('#nav a[data-page-link="history"]') as any).click();
    await tick();
    assert.deepEqual(shown(doc), ["history"]);
    assert.equal(where(window), `${bp}/history`);
    assert.equal(window.history.length, 2, "one history entry");
    assert.deepEqual(marked(doc), ["history"]);
    assert.match(doc.title, /Mandu · History$/);
  });

  test(`the inspector links are paths under the base path ("${bp}")`, async () => {
    const { doc } = at("/agents/s1");
    await tick();
    assert.equal(doc.getElementById("agent-trace").getAttribute("href"), `${bp}/dev/sessions/s1`);
    assert.equal(doc.getElementById("settings-dev-link").getAttribute("href"), `${bp}/dev/`);
  });
}
