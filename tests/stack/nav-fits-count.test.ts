/**
 * nav-fits-count — on a small phone the page links fit their row when
 * requests wait for you, across the REAL components and the served styles
 * (dashboard.md §4.25 *The page links fit a small phone*). Mandu-new.
 *
 * Until 2026-10-15 a headless Chromium over the served page with one
 * request waiting drew "Home · Approvals 1 · Rules · Settir" at 320 px:
 * the count's pill beside Approvals took the links past their 288 px row
 * at 320 to 355 px, on every page. Here a real ArbiterServer runs at the
 * `secrets` axes and registers a `.env` whose key gets its own symbol; its
 * real egress gate refuses the key's send to two hosts no rule binds it to
 * and asks for an OK each time. A real DashboardServer over the production
 * adapter (`makeApprovalsArbiter`) serves the page:
 *
 *   C1  the served Approvals page in jsdom, its served styles as a 320 px
 *       and a 375 px phone apply them: the six links (History since
 *       2026-10-18, Scan since 2026-10-21), Approvals current, the count
 *       "2" in its link, two rows of three columns, 10 px a side;
 *   C2  the model (nav-row.ts) over the served stylesheet: the links as
 *       drawn, and with 99 waiting, fit with room to spare at every window
 *       from 320 to 719 px (two rows below 500 px, one from there), every
 *       word shown; the row still scrolls where it must; and from 720 to
 *       1280 px the brand, the links and "Protection on" fit the bar;
 *   C4  at 499 and 719 px the Scan link opens the Scan page, marked as the
 *       current page, the History link History, and the brand Home;
 *   C3  the oracle: no page or answer read here carries the key's value,
 *       and the product side no token (`$MDU`).
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON). What is
 * under test is the served page and styles; the stack supplies the real
 * requests the count counts.
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
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { resolveCssVars, stylesAt } from "../../dashboard/test/unit/ui/css-flatten.js";
import { MARGIN, drawnNav, navRow, type DrawnNav } from "../../dashboard/test/unit/ui/nav-row.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const SESSION = `1791840000-${process.pid}`;
const VALUE = `sk_live_navFitsCanary_${process.pid}_00000000`;
const WORDS = ["Home", "Approvals", "Rules", "Settings", "History", "Scan"];
const PAGES = ["home", "approvals", "rules", "settings", "history", "scan"];

test("with two requests waiting the six page links fit a 320 px phone's row, on the real stack with its served styles, and no value is shown (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-nav-fits-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const gate = new ArbiterClient(sock); await gate.connect();
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired, "the production wiring connects");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home") },
    log: () => {},
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const noValue = (text: string, where: string) => {
    assert.ok(!text.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the .env value`);
  };
  const served = async (f: string): Promise<string> => {
    const r = await pageFetch(base + f);
    assert.equal(r.status, 200, `${f} is served`);
    return r.text();
  };
  try {
    // A registered `.env`: its key gets its own symbol (the structured twin).
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    // The real gate refuses its send to two hosts no rule binds it to, and asks each time.
    for (const dest of ["paste.nav.example", "uploads.nav.example"]) {
      const d = await gate.desymbolizationDecision({ symbol: keySym!, boundary: "network", destination: dest, sessionKey: SESSION, scheme: "https" });
      assert.equal(d.allow, false, `the real gate refuses ${dest}`);
      assert.equal((d as { requiresApproval?: boolean }).requiresApproval, true, `and asks for an OK about ${dest}`);
    }
    const homeText = await served("/api/home");
    noValue(homeText, "/api/home");
    assert.equal((JSON.parse(homeText) as HomeVM).waiting.length, 2, "two requests wait for an OK");
    const sheets = `${await served("/mandu.css")}\n${await served("/app.css")}`;

    // ── C1: the served page, as a 320 px and a 375 px phone apply its styles ──
    const counted = (doc: { getElementById: (id: string) => { hidden: boolean } | null }) => doc.getElementById("nav-approvals-count")?.hidden === false;
    let drawn: DrawnNav | null = null;
    for (const width of [320, 375] as const) {
      await servedProductPage(base, "/approvals", counted, (doc) => {
        const where = `the Approvals page at ${width}px`;
        drawn = drawnNav(doc);
        assert.deepEqual(drawn, { words: WORDS, pages: PAGES, current: 1, count: "2" }, `${where}: the six links, Approvals current, two waiting`);
        assert.equal(doc.defaultView.getComputedStyle(doc.getElementById("nav")).display, "grid", `${where}: two rows of three`);
        assert.equal(doc.getElementById("nav-approvals-count").parentElement.getAttribute("data-page-link"), "approvals", "the count sits in the Approvals link");
        for (const a of doc.querySelectorAll("#nav a")) {
          assert.equal(doc.defaultView.getComputedStyle(a).paddingLeft, "10px", `${where}: ${a.textContent.trim()} has 10px a side`);
          assert.equal(a.getAttribute("style"), null, "no inline style: the stylesheet decides");
          assert.notEqual(doc.defaultView.getComputedStyle(a).display, "none", `${where}: ${a.textContent.trim()} is shown`);
        }
        noValue(doc.body.textContent, `the rendered Approvals page at ${width}px`);
        assert.doesNotMatch(doc.body.textContent, /\$MDU/, "the rendered page carries no token");
      }, { css: resolveCssVars(stylesAt(sheets, width)) });
    }

    // ── C2: the served stylesheet, every phone window ──
    assert.ok(drawn, "the page drew its links");
    const links: DrawnNav = drawn;
    const model = navRow(sheets);
    assert.equal(model.need(320, links), 255, "the drawn links need 255 px at 320 px (Chromium: 255.67)");
    for (let w = 320; w <= 719; w++) {
      for (const count of [links.count, "99"]) {
        const spare = model.spare(w, { ...links, count });
        assert.ok(spare >= MARGIN, `${w}px with ${count} waiting: ${spare}px to spare`);
      }
      assert.equal(model.at(w, "#nav", "overflow-x"), "auto", `${w}px: the row still scrolls where it must`);
      assert.equal(model.hidden(w, "home"), false, `${w}px: the Home word is shown`);
      assert.equal(model.rows(w, links), w < 500 ? 2 : 1, `${w}px: the rows`);
    }
    for (let w = 720; w <= 1280; w++) {
      for (const count of [links.count, "99"]) {
        const spare = model.bar(w, { ...links, count }, "Protection on");
        assert.ok(spare >= MARGIN, `${w}px with ${count} waiting: the bar has ${spare}px to spare`);
      }
      assert.equal(model.hidden(w, "home"), false, `${w}px: the Home word is shown`);
    }

    // ── C4: the Scan, History and brand links open their pages, at 499 and 719 px ──
    for (const width of [499, 719]) {
      await servedProductPage(base, "/approvals", counted, async (doc) => {
        const shown = () => [...doc.querySelectorAll("#main > section[data-page]")].filter((x: any) => !x.hidden).map((x: any) => x.dataset.page);
        const marked = () => [...doc.querySelectorAll("#nav a")].filter((a: any) => a.getAttribute("aria-current") === "page").map((a: any) => a.dataset.pageLink);
        doc.querySelector('#nav a[data-page-link="scan"]').click();
        assert.deepEqual(shown(), ["scan"], `${width}px: the Scan link opens the Scan page`);
        assert.deepEqual(marked(), ["scan"], "and marks it the current page");
        assert.equal(doc.defaultView.location.pathname, "/scan");
        doc.querySelector('#nav a[data-page-link="history"]').click();
        assert.deepEqual(shown(), ["history"], "the History link opens History");
        assert.deepEqual(marked(), ["history"]);
        doc.querySelector("a.brand").click();
        assert.deepEqual(shown(), ["home"], "the brand opens Home");
        assert.deepEqual(marked(), ["home"], "Home is the current page");
        noValue(doc.body.textContent, `the rendered page at ${width}px`);
        assert.doesNotMatch(doc.body.textContent, /\$MDU/, "the rendered page carries no token");
      }, { css: resolveCssVars(stylesAt(sheets, width)) });
    }

    // ── C3: the oracle ──
    for (const route of ["/api/home", "/api/home/history", `/api/home/agent?session=${SESSION}`, "/approvals", "/history", "/scan", "/api/scan"]) {
      const text = await (await pageFetch(base + route)).text();
      noValue(text, route);
      assert.doesNotMatch(text, /\$MDU/, `${route} carries no token`);
    }
  } finally {
    await dashboard.close();
    wired?.close();
    gate.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
