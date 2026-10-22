/**
 * top-status-opens-protection — the top bar's words open Settings ›
 * Protection from any page while protection is not plainly on, across the
 * REAL components and the served styles (dashboard.md §4.25 *The top bar
 * says on or off*). Mandu-new.
 *
 * Until 2026-10-18 the top bar said "Protection off" on every page and led
 * nowhere: on Rules, Approvals or History a person had to know the switch is
 * the first card of Settings. Here a real ArbiterServer and a real
 * DashboardServer serve the product page (its own index.html, home.js and
 * stylesheets, in jsdom as a browser of each width applies them):
 *
 *   P1  the `off` axes running, `mode = "off"` saved: on Rules at 1280 and
 *       390 px the top bar's "Protection off" is one link to Settings,
 *       named "Protection off: open Settings", in the status's own ink,
 *       size and nowrap beside its dot; a click opens Settings, scrolls the
 *       Protection card to the top and puts the focus on its switch;
 *   P2  at 720 to 1280 px the brand, the links and "Protection off" still
 *       fit the bar (the measured model, nav-row.ts);
 *   P3  the `secrets` axes running with a request waiting and `mode = "off"`
 *       saved: at 375 px the top bar reads "Protection on · off from the
 *       next start" as a link, and the page links with the count still fit
 *       their row (dashboard.md §4.25 *The page links fit a small phone*);
 *   P4  the oracle: no page or answer read here carries the key's value,
 *       and the product side no token (`$MDU`).
 *
 * Axes: each test states its own, `off` then `secrets`, on its arbiter
 * explicitly; the module pins `off`. What is under test is the served page;
 * the stack supplies the level running, the saved setting and the request
 * the count counts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { resolveCssVars, stylesAt } from "../../dashboard/test/unit/ui/css-flatten.js";
import { MARGIN, drawnNav, navRow } from "../../dashboard/test/unit/ui/nav-row.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("off"); // P1/P2; P3's arbiter states `secrets` explicitly

const SESSION = `1791840000-${process.pid}`;
const VALUE = `sk_live_topStatusCanary_${process.pid}_00000000`;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

/** A real arbiter at `axes`, a dashboard over it whose saved setting is
 *  `mode = "off"`, and its served stylesheets. */
async function stack(axes: { confidentiality: boolean; integrity: boolean }) {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-top-status-"));
  const home = join(tmp, "home");
  const manduHome = join(tmp, "mandu-home");
  mkdirSync(join(home, "proj"), { recursive: true });
  mkdirSync(manduHome, { recursive: true });
  writeFileSync(join(manduHome, "config.toml"), 'mode = "off"\n');
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    ...axes,
  });
  await arbiter.listen();
  const gate = new ArbiterClient(sock); await gate.connect();
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired, "the production wiring connects");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: manduHome, HOME: home },
    log: () => {},
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const served = async (f: string): Promise<string> => {
    const r = await pageFetch(base + f);
    assert.equal(r.status, 200, `${f} is served`);
    return r.text();
  };
  const sheets = `${await served("/mandu.css")}\n${await served("/app.css")}`;
  const close = async () => {
    await dashboard.close();
    wired.close();
    gate.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  };
  return { home, base, gate, served, sheets, close };
}

const noValue = (text: string, where: string) => {
  assert.ok(!text.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the .env value`);
};
const statusLinks = (doc: El): El[] => [...doc.getElementById("top-status").querySelectorAll("a")];

test("from Rules, the top bar's \"Protection off\" opens Settings at the Protection switch, at 1280 and 390 px (off axes, explicit)", { timeout: 120_000 }, async () => {
  const s = await stack({ confidentiality: false, integrity: false }); // the `off` axes, stated
  try {
    // ── P1: the link, its look, and where a click lands ──
    for (const width of [1280, 390]) {
      const where = `Rules at ${width}px`;
      await servedProductPage(s.base, "/rules", (doc) => statusLinks(doc).length > 0, async (doc) => {
        const w = doc.defaultView;
        const host = doc.getElementById("top-status");
        assert.equal(host.textContent, "Protection off", `${where}: the words the switch says`);
        const links = statusLinks(doc);
        assert.equal(links.length, 1, `${where}: one link`);
        const a = links[0];
        assert.equal(new URL(a.href).pathname, "/settings", `${where}: it opens Settings`);
        assert.equal(a.getAttribute("aria-label"), "Protection off: open Settings", `${where}: its name says where it goes`);
        assert.ok(host.querySelector(":scope > .dot.warn"), `${where}: the amber dot stays beside it`);
        const hs = w.getComputedStyle(host);
        const ls = w.getComputedStyle(a);
        assert.equal(ls.color, hs.color, `${where}: the status's ink, not a link's`);
        assert.deepEqual([ls.fontSize, ls.textDecorationLine], [hs.fontSize, "none"], `${where}: its size, no underline until hovered`);
        // Kept on one line: the status's nowrap, which the link inherits
        // (jsdom computes no inherited white-space), not set back.
        assert.equal(hs.whiteSpace, "nowrap", `${where}: the status keeps one line`);
        assert.ok(["", "nowrap"].includes(ls.whiteSpace), `${where}: the link does not wrap it (${ls.whiteSpace})`);
        assert.equal(a.getAttribute("style"), null, "no inline style: the stylesheet decides");

        const scrolled: string[] = [];
        w.HTMLElement.prototype.scrollIntoView = function (this: El, o: El) { scrolled.push(`${this.id} ${o && o.block}`); };
        const click = new w.MouseEvent("click", { bubbles: true, cancelable: true });
        a.dispatchEvent(click);
        assert.equal(click.defaultPrevented, true, "the page opens Settings itself");
        const sw = doc.getElementById("switch-protection");
        await waitWhile(() => doc.activeElement !== sw);
        assert.equal(w.location.pathname, "/settings", `${where}: Settings opens`);
        assert.deepEqual([...doc.querySelectorAll("#main > section[data-page]")].filter((x: El) => !x.hidden).map((x: El) => x.dataset.page), ["settings"]);
        assert.deepEqual(scrolled, ["settings-protection-block start"], `${where}: the Protection card is scrolled to the top`);
        assert.equal(doc.activeElement, sw, `${where}: the Protection switch has the focus`);
        assert.equal(sw.disabled, false);
        assert.equal(sw.getAttribute("aria-checked"), "false", "the switch says the saved setting, off");
        assert.equal(sw.hasAttribute("tabindex"), false, "the switch keeps its place in the tab order");
        assert.doesNotMatch(doc.body.textContent, /\$MDU/, "the rendered page carries no token");
      }, { css: resolveCssVars(stylesAt(s.sheets, width)) });
    }

    // ── P2: the bar, 720 to 1280 px, with "Protection off" ──
    const model = navRow(s.sheets);
    await servedProductPage(s.base, "/rules", (doc) => statusLinks(doc).length > 0, (doc) => {
      const links = drawnNav(doc);
      for (let w = 720; w <= 1280; w++) {
        const spare = model.bar(w, { ...links, count: "99" }, "Protection off");
        assert.ok(spare >= MARGIN, `${w}px: the bar has ${spare}px to spare with "Protection off" and 99 waiting`);
      }
    });
  } finally {
    await s.close();
  }
});

test("at 375 px with a request waiting, \"Protection on · off from the next start\" is a link and the page links still fit their row (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const s = await stack({ confidentiality: true, integrity: false }); // the `secrets` axes, stated
  try {
    // A registered `.env` whose key the real gate refuses to an unbound host, asking for an OK.
    const env = join(s.home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
    const reg = await s.gate.registerSecret({ path: env, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    const d = await s.gate.desymbolizationDecision({ symbol: keySym!, boundary: "network", destination: "paste.top-status.example", sessionKey: SESSION, scheme: "https" });
    assert.equal(d.allow, false, "the real gate refuses the send");
    assert.equal((d as { requiresApproval?: boolean }).requiresApproval, true, "and asks for an OK");

    // ── P3: the phone's top bar ──
    const counted = (doc: El) => doc.getElementById("nav-approvals-count")?.hidden === false && statusLinks(doc).length > 0;
    await servedProductPage(s.base, "/approvals", counted, (doc) => {
      const words = "Protection on · off from the next start";
      assert.equal(doc.getElementById("top-status").textContent, words);
      const links = statusLinks(doc);
      assert.equal(links.length, 1, "a change saved for the next start: one link");
      assert.equal(links[0].textContent, words, "its words, the tail too");
      assert.equal(links[0].getAttribute("aria-label"), `${words}: open Settings`);
      assert.equal(new URL(links[0].href).pathname, "/settings");
      const nav = drawnNav(doc);
      assert.equal(nav.count, "1", "one request waits");
      const spare = navRow(s.sheets).spare(375, nav);
      assert.ok(spare >= MARGIN, `375px: the page links and the count have ${spare}px to spare`);
      // The intro names Rules, and links it.
      const rules = doc.querySelector("#page-approvals .page-head p a");
      assert.equal(rules?.textContent, "Rules");
      assert.equal(rules?.getAttribute("data-page-link"), "rules");
      noValue(doc.body.textContent, "the rendered Approvals page at 375px");
      assert.doesNotMatch(doc.body.textContent, /\$MDU/, "the rendered page carries no token");
    }, { css: resolveCssVars(stylesAt(s.sheets, 375)) });

    // ── P4: the oracle ──
    for (const route of ["/api/home", "/approvals", "/settings", "/rules"]) {
      const text = await (await pageFetch(s.base + route)).text();
      noValue(text, route);
      assert.doesNotMatch(text, /\$MDU/, `${route} carries no token`);
    }
  } finally {
    await s.close();
  }
});
