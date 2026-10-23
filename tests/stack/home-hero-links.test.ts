/**
 * home-hero-links.test — Home's hero links the place its sentence names,
 * across the REAL components (dashboard.md §4.25, *The hero links where it
 * points*). Mandu-new.
 *
 * Until 2026-10-08 the `off` verdict said "Turn it back on under Rules.",
 * three days after the on/off switch moved to Settings › Protection; Rules
 * has no switch. No next step in the hero was a link. Here a real
 * ArbiterServer runs at the `off` axes, the saved config says `off` (the
 * person turned it off), and a real DashboardServer reads it over a real
 * ArbiterEventSource:
 *
 *   L1  /api/home: the `off` verdict's sentence names Settings, never Rules,
 *       and its one link part names the place (`settings`), not an address;
 *   L2  the served product page (its own index.html and home.js in jsdom,
 *       fetching from that server): the hero's "Turn it back on in Settings"
 *       is a link; clicking it opens Settings, whose Protection card holds
 *       the switch, saved as Off;
 *   L3  with the protection service gone (the server's 503 `unreachable`),
 *       the page's own sentence links Settings, where its Start is;
 *   L4  the oracle: neither answer nor rendered page carries the labelled
 *       file's value or a token;
 *   L5  on a phone (dashboard.md §4.25, Home): the stylesheet the server
 *       serves stacks the hero's icon above its headline at 640 px and
 *       narrower, and under it at 390 px the served page (L2's `off` hero
 *       and L3's "Not connected.") draws a column with the 40 px icon, its
 *       glyph, the 28 px headline, the sentence and its link. jsdom has no
 *       layout: the widths were measured in headless Chromium.
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
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { resolveCssVars, stylesAt } from "../../dashboard/test/unit/ui/css-flatten.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";

stateAxes("off");

const KEY_VALUE = "sk_" + "live_homeHeroLinksStackCanary00000000001";

/** L5: the hero as a 390 px window draws it under the served styles. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function assertPhoneHero(doc: any, verdict: string): void {
  const cs = (e: Element) => doc.defaultView.getComputedStyle(e);
  const hero = doc.getElementById("hero");
  const icon = hero.querySelector(".hero-icon");
  assert.equal(hero.dataset.verdict, verdict);
  assert.equal(cs(hero).flexDirection, "column", `${verdict}: the icon sits above the words`);
  assert.deepEqual([cs(icon).width, cs(icon).height], ["40px", "40px"]);
  const glyph = icon.querySelector("svg");
  assert.ok(glyph, `${verdict}: the icon keeps its glyph`);
  assert.equal(cs(glyph).width, "22px");
  assert.equal(cs(doc.getElementById("hero-headline")).fontSize, "28px");
  assert.ok(doc.getElementById("hero-sentence").textContent, `${verdict}: a sentence`);
  assert.ok(doc.getElementById("hero-facts"), "the counts' place");
}

test("protection off: Home's hero says Settings and links there, where the switch is; without the service it still links Settings", { timeout: 60_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-home-hero-links-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const manduHome = join(tmp, "mandu-home");
  mkdirSync(manduHome, { recursive: true });
  // The person turned protection off: the saved mode is `off`.
  writeFileSync(join(manduHome, "config.toml"), `mode = "off"\n`);
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: false, integrity: false, // the `off` axes, stated
  });
  await arbiter.listen();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: manduHome },
    log: () => {},
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  let arbiterOpen = true;
  try {
    // A labelled secret file, for the oracle: nothing below may carry it.
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    await admin.setPathLabel({ path: env, confidentiality: "no-model", bindings: [], recursive: false });

    // L1: the payload names the place, never Rules, never an address.
    const body = await (await pageFetch(`${base}/api/home`)).text();
    const vm = JSON.parse(body) as HomeVM;
    assert.equal(vm.protection.level, "off");
    assert.equal(vm.protection.configured, "off");
    assert.equal(vm.verdict, "off");
    assert.equal(vm.headline, "Protection is off.");
    assert.equal(vm.sentence, "The AI can read untrusted content as-is, and your secrets are not guarded. Turn it back on in Settings.");
    assert.doesNotMatch(vm.sentence, /Rules/);
    assert.deepEqual(vm.sentenceParts.filter((p) => p.kind === "link"), [{ kind: "link", text: "Turn it back on in Settings", to: "settings" }]);
    // L4 on the answer.
    assert.ok(!body.includes(KEY_VALUE), "/api/home carries no secret value");
    assert.doesNotMatch(body, /\$MDU/, "nor a token");

    // L5: the served stylesheet carries the phone rule; under it the `off`
    // hero is a column with the smaller icon and headline.
    const served = `${await (await pageFetch(`${base}/mandu.css`)).text()}\n${await (await pageFetch(`${base}/app.css`)).text()}`;
    assert.match(served, /@media \(max-width: 640px\) \{\s*\.hero \{ flex-direction: column;/, "the served app.css stacks the hero on a phone");
    const phoneCss = resolveCssVars(stylesAt(served, 390));
    await servedProductPage(base, "/", (doc) => doc.getElementById("hero").dataset.verdict === "off", (doc) => {
      assertPhoneHero(doc, "off");
      assert.equal(doc.getElementById("hero-headline").textContent, "Protection is off.");
      assert.deepEqual([...doc.querySelectorAll("#hero-sentence a")].map((a: Element) => a.textContent), ["Turn it back on in Settings"]);
      const page = doc.body.textContent;
      assert.ok(!page.includes(KEY_VALUE), "the phone page carries no secret value");
      assert.doesNotMatch(page, /\$MDU/, "nor a token");
    }, { css: phoneCss });

    // L2: the served page's link opens Settings, where the switch is.
    await servedProductPage(base, "/", (doc) => doc.getElementById("hero").dataset.verdict === "off", async (doc) => {
      assert.equal(doc.getElementById("hero-headline").textContent, "Protection is off.");
      const links = [...doc.querySelectorAll("#hero-sentence a")];
      assert.equal(links.length, 1, "one place to go");
      assert.equal(links[0].textContent, "Turn it back on in Settings");
      assert.equal(links[0].getAttribute("href"), "/settings");
      links[0].click();
      const t0 = Date.now();
      while (doc.getElementById("settings-protect-text").textContent === "Checking…" && Date.now() - t0 < 10_000) await new Promise((r) => setTimeout(r, 20));
      assert.equal(doc.defaultView.location.pathname, "/settings");
      assert.equal(doc.getElementById("page-settings").hidden, false, "Settings is shown");
      assert.equal(doc.getElementById("page-home").hidden, true);
      const sw = doc.getElementById("switch-protection");
      assert.ok(sw && sw.closest("#settings-protection-block"), "the switch is in the Protection card");
      assert.equal(sw.getAttribute("aria-checked"), "false", "saved as off");
      assert.match(doc.getElementById("settings-protect-text").textContent, /Mandu only watches/);
      // L4 on the rendered pages.
      const page = doc.body.textContent;
      assert.ok(!page.includes(KEY_VALUE), "the rendered page carries no secret value");
      assert.doesNotMatch(page, /\$MDU/, "nor a token");
    });

    // L3: the protection service is gone; the hero still sends the person
    // to Settings, where its Start is.
    admin.close();
    await arbiter.close();
    arbiterOpen = false;
    await servedProductPage(base, "/", (doc) => doc.getElementById("hero-headline").textContent === "Not connected.", (doc) => {
      // The server answers 503 `unreachable`; the page says it in its own words.
      assert.equal(doc.getElementById("hero-sentence").textContent,
        "The protection service is not running, so nothing can be checked. Start it under Settings, or refresh in a moment.");
      const links = [...doc.querySelectorAll("#hero-sentence a")];
      assert.deepEqual(links.map((a) => [a.textContent, a.getAttribute("href"), a.getAttribute("data-page-link")]), [["Start it under Settings", "/settings", "settings"]]);
    });
    // L5: "Not connected." on a phone keeps its icon above the words.
    await servedProductPage(base, "/", (doc) => doc.getElementById("hero-headline").textContent === "Not connected.", (doc) => {
      assertPhoneHero(doc, "unknown");
      assert.equal(doc.getElementById("hero-sentence").querySelector("a").textContent, "Start it under Settings");
    }, { css: phoneCss });
  } finally {
    await dashboard.close();
    if (arbiterOpen) { admin.close(); await arbiter.close(); }
    rmSync(tmp, { recursive: true, force: true });
  }
});
