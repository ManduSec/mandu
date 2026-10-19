/**
 * settings-appearance.test — Settings › Appearance across the REAL
 * components: one stored choice (`mandu.theme`) for the product page and
 * the developer view, applied before the first paint (dashboard.md §4.25
 * Settings › *Appearance*, §4.25k). Mandu-new.
 *
 * Until 2026-10-18 the product page always followed the system: a person who
 * picked Dark in the developer view was back in light on `/`, and one with
 * only the product page could not pick at all.
 *
 * Here a real ArbiterServer runs at the `secrets` axes with a registered key,
 * and a real DashboardServer over the production adapter
 * (`makeApprovalsArbiter`) serves the page. In jsdom, with the served
 * mandu.css and app.css applied and Dark stored:
 *
 *   A1  `/settings` and `/` load the served head script as a browser's
 *       parser does, before the stylesheets and before home.js (a module,
 *       run after the first paint): once it ran, and before home.js, `--bg`
 *       computes to the served stylesheet's dark token;
 *   A2  home.js then shows Dark in Settings' menu; picking Light turns the
 *       page light at once and stores "light";
 *   A3  where this tree has the developer view, its own Appearance code
 *       (its page and script, read where the server finds them) over that
 *       storage draws Light; its pick of Dark is the product page's at its
 *       next first paint. The public tree skips this half;
 *   A4  the oracle: no page or answer read here carries the registered
 *       key's value, and the product page no token (`$MDU`).
 *
 * And in a real headless Chromium driven over the DevTools protocol
 * (scripts/tour-screenshots.mjs, as section-links.test does), signed in:
 *
 *   B1  with Dark stored and home.js blocked (`Network.setBlockedURLs`), so
 *       the page is what the head script and the stylesheets paint before
 *       any module runs, `/settings` and `/` draw the dark `--bg` behind
 *       their body;
 *   B2  with home.js back, Settings' menu shows Dark; picking Light turns
 *       the page light at once and stores "light";
 *   B3  where this tree has the developer view (loaded as server-main loads
 *       it, `loadExtensions`), the served `/dev/` then draws Light with its
 *       menu on Light; its pick of Dark is `/settings`' first paint (home.js
 *       blocked again). The public tree skips this half;
 *   B4  the oracle again, on every page read.
 *
 * The Chromium test self-SKIPs without a Chromium (probeBrowser:
 * MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell, or one on
 * PATH). Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 * What is under test is the served page; the stack supplies it.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { loadExtensions } from "../../dashboard/src/extension-loader.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { pageFromHtml, servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { devPagesDir, NO_DEV_PAGES } from "../../dashboard/test/unit/ui/dev-pages.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

const VALUE = `sk_live_appearanceCanary_${process.pid}_000000`;
const KEY = "mandu.theme";
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
interface Cdp { send(method: string, params?: object, sessionId?: string): Promise<any>; close(): void }
const tour = (await import(pathToFileURL(join(REPO, "scripts", "tour-screenshots.mjs")).href)) as {
  probeBrowser: (o?: object) => string | null;
  startBrowser: (path: string, dataDir: string, env: NodeJS.ProcessEnv) => Promise<{ proc: unknown; wsUrl: string }>;
  stopProc: (proc: unknown) => Promise<void>;
  Cdp: { connect(url: string): Promise<Cdp> };
};
const browser = tour.probeBrowser({});

/** The served stack, once for both tests. */
let stack: { base: string; mandu: string; sheets: string; early: string; dark: string; light: string; close: () => Promise<void> } | null = null;
/** What the product page stored when Light was picked (A2), for A3. */
let storedByProduct: string | null = null;

const bgOf = (doc: any): string => doc.defaultView.getComputedStyle(doc.documentElement).getPropertyValue("--bg").trim();
/** A token's value in the block of `selector` in the served mandu.css. */
function token(css: string, selector: string, name: string): string {
  const at = css.indexOf(selector + " {");
  assert.ok(at >= 0, `the served mandu.css has ${selector}`);
  const block = css.slice(at, css.indexOf("}", at));
  const m = new RegExp(`${name}:\\s*([^;]+);`).exec(block);
  assert.ok(m, `${selector} sets ${name}`);
  return m![1].trim();
}

async function start() {
  if (stack) return stack;
  const tmp = mkdtempSync(join(tmpdir(), "mandu-settings-appearance-"));
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
  const data = new ArbiterClient(sock);
  await data.connect();
  await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: VALUE }] });
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
  const served = async (f: string): Promise<string> => {
    const r = await pageFetch(base + f);
    assert.equal(r.status, 200, `${f} is served`);
    const text = await r.text();
    assert.ok(!text.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${f} carries the key's value`);
    return text;
  };
  // The head script as the served page names it (stamped `?v=`).
  const html = await served("/settings");
  const head = html.slice(0, html.indexOf("</head>"));
  const tag = /<script src="(js\/theme-early\.js\?v=[^"]+)"><\/script>/.exec(head);
  assert.ok(tag, `the served head loads the classic head script: ${head}`);
  assert.ok(tag!.index < head.indexOf('rel="stylesheet"'), "before the stylesheets");
  const mandu = await served("/mandu.css");
  stack = {
    base,
    mandu,
    sheets: `${mandu}\n${await served("/app.css")}`,
    early: await served("/" + tag![1]),
    dark: token(mandu, ':root[data-theme="dark"]', "--bg"),
    light: token(mandu, ":root", "--bg"),
    close: async () => {
      await dashboard.close();
      wired.close();
      data.close();
      await arbiter.close();
      rmSync(tmp, { recursive: true, force: true });
    },
  };
  assert.notEqual(stack.dark, stack.light, "the two tokens differ");
  return stack;
}
after(async () => { await stack?.close(); });

/** The served page at `path`, `stored` in its storage; `atFirstPaint` reads
 *  the page once the head script ran, before home.js. */
async function open(path: string, stored: string, ready: (doc: any) => boolean, atFirstPaint: (doc: any) => void, fn: (doc: any) => void | Promise<void>) {
  const s = await start();
  await servedProductPage(s.base, path, ready, async (doc) => {
    assert.ok(!doc.body.textContent.includes(VALUE), `CONFIDENTIALITY VIOLATION: the rendered ${path} carries the key's value`);
    assert.doesNotMatch(doc.body.textContent, /\$MDU/, `the rendered ${path} carries no token`);
    await fn(doc);
  }, {
    css: s.sheets,
    beforeScripts: (w) => {
      w.localStorage.setItem(KEY, stored);
      w.eval(s.early);
      atFirstPaint(w.document);
    },
  });
}

test("with Dark stored, /settings and / are dark at the first paint; picking Light on Settings turns the page light and stores it (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const s = await start();
  // A1, A2: Settings.
  const drawn = (doc: any) => doc.querySelector('#page-settings nav.section-links a[data-section="appearance"]') !== null;
  await open("/settings", "dark", drawn, (doc) => {
    assert.equal(doc.documentElement.getAttribute("data-theme"), "dark", "/settings: the head script pinned Dark");
    assert.equal(bgOf(doc), s.dark, "/settings: --bg is the dark token before home.js runs");
  }, (doc) => {
    const w = doc.defaultView;
    const menu = doc.getElementById("settings-theme");
    assert.equal(menu.value, "dark", "the menu shows the stored Dark");
    assert.equal(doc.querySelector('label[for="settings-theme"]').textContent, "Colours");
    menu.value = "light";
    menu.dispatchEvent(new w.Event("change", { bubbles: true }));
    assert.equal(doc.documentElement.getAttribute("data-theme"), "light", "Light, at once");
    assert.equal(bgOf(doc), s.light, "--bg is the light token");
    storedByProduct = w.localStorage.getItem(KEY);
    assert.equal(storedByProduct, "light", "stored under the developer view's key");
  });
  // A1: Home.
  await open("/", "dark", (doc) => doc.getElementById("settings-theme").value === "dark", (doc) => {
    assert.equal(bgOf(doc), s.dark, "/: --bg is the dark token before home.js runs");
  }, (doc) => {
    assert.equal(doc.documentElement.getAttribute("data-theme"), "dark", "/: still Dark once home.js ran");
  });
});

test("the developer view follows the product page's pick, and the product page the developer view's (one stored choice)", { skip: NO_DEV_PAGES, timeout: 120_000 }, async () => {
  const s = await start();
  assert.equal(storedByProduct, "light", "the first test stored Light");
  // A3: the developer view's own page and Appearance code, over that storage.
  const dev = devPagesDir()!;
  const devHtml = readFileSync(join(dev, "index.html"), "utf8").replace(/<script\b[^>]*>[\s\S]*?<\/script>/g, "");
  const app = readFileSync(join(dev, "js", "app.js"), "utf8");
  const from = app.indexOf("const THEME_KEY = ");
  const wire = app.indexOf("function wireTheme()", from);
  const end = app.indexOf("\n}\n", wire);
  assert.ok(from >= 0 && wire > from && end > wire, "the developer view keeps its Appearance code (THEME_KEY, applyTheme, wireTheme)");
  const code = app.slice(from, end + 2);
  assert.match(code, /THEME_KEY = 'mandu\.theme'/, "under the same key");
  // The developer view builds on mandu.css.
  const w = pageFromHtml(devHtml, `${s.base}/dev/`, s.mandu);
  try {
    w.localStorage.setItem(KEY, storedByProduct);
    w.eval(`${code}\nwireTheme();`);
    const doc = w.document;
    assert.equal(doc.documentElement.getAttribute("data-theme"), "light", "the developer view draws Light");
    assert.equal(doc.getElementById("theme-select").value, "light", "its menu shows Light");
    assert.equal(bgOf(doc), s.light);
    // And the reverse: its pick of Dark is the product page's next first paint.
    const sel = doc.getElementById("theme-select");
    sel.value = "dark";
    sel.dispatchEvent(new w.Event("change", { bubbles: true }));
    const pickedByDev = w.localStorage.getItem(KEY);
    assert.equal(pickedByDev, "dark");
    await open("/settings", pickedByDev!, (d) => d.getElementById("settings-theme").value === "dark", (d) => {
      assert.equal(bgOf(d), s.dark, "the product page is dark at its first paint");
    }, (d) => {
      assert.equal(d.documentElement.getAttribute("data-theme"), "dark");
    });
  } finally {
    w.close();
  }
});

test("in a real Chromium: Dark stored is the first paint of /settings and / before home.js runs; Light picked on Settings is the developer view's, and its Dark the product page's (secrets axes, explicit)", {
  skip: browser ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const s = await start(); // the tokens, from the served mandu.css
  const tmp = mkdtempSync(join(tmpdir(), "mandu-settings-appearance-cdp-"));
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
  const data = new ArbiterClient(sock);
  await data.connect();
  await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: VALUE }] });
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired, "the production wiring connects");
  // The developer view as server-main loads it, where this tree has one.
  const extensions = NO_DEV_PAGES ? [] : await loadExtensions(join(REPO, "dashboard", "src"), {
    repoRoot: REPO, arbiterSock: sock, testArbiterSock: join(tmp, "test-arbiter.sock"), testEventDir: join(tmp, "test-events"),
    publicDir: join(REPO, "dashboard", "public"), env: {}, log: () => {},
  });
  const withDev = extensions.some((x) => x.name === "inspector");
  assert.equal(withDev, !NO_DEV_PAGES, "the developer view loads where the tree has it");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter, fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home") }, log: () => {}, extensions, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const { proc, wsUrl } = await tour.startBrowser(browser as string, join(tmp, "chrome"), process.env);
  const cdp = await tour.Cdp.connect(wsUrl);
  const texts: string[] = [];
  try {
    const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    const send = (method: string, params: object = {}) => cdp.send(method, params, sessionId);
    const evaluate = async (expression: string) => {
      const r = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) throw new Error(`page script failed: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
      return r.result.value;
    };
    const until = async (what: string, expression: string) => {
      let ok = false;
      for (const end = Date.now() + 30_000; Date.now() < end && !ok; await new Promise((r) => setTimeout(r, 100))) {
        try { ok = await evaluate(expression); } catch { /* navigating */ }
      }
      assert.ok(ok, what);
    };
    /** What the page paints: its theme, the token, the body's ground. */
    const look = () => evaluate(`(() => {
      const html = document.documentElement;
      return { theme: html.getAttribute("data-theme"), bg: getComputedStyle(html).getPropertyValue("--bg").trim(),
        ground: getComputedStyle(document.body).backgroundColor, stored: localStorage.getItem(${JSON.stringify(KEY)}),
        sheets: document.styleSheets.length, links: document.querySelectorAll("nav.section-links a").length, text: document.body.innerText };
    })()`);
    const rgb = (hex: string) => `rgb(${[1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16)).join(", ")})`;
    /** `path` as the head script and the stylesheets paint it, no module run. */
    const firstPaint = async (path: string) => {
      await send("Network.setBlockedURLs", { urls: ["*js/home.js*"] });
      await send("Page.navigate", { url: base + path });
      await until(`${path}: loaded without home.js`, `document.readyState === "complete" && document.styleSheets.length >= 2`);
      const m = await look();
      await send("Network.setBlockedURLs", { urls: [] });
      texts.push(m.text);
      assert.equal(m.links, 0, `${path}: home.js did not run (no section links drawn)`);
      return m;
    };
    await send("Page.enable");
    await send("Runtime.enable");
    await send("Network.enable");
    const eq = ADMIN_COOKIE.indexOf("=");
    await send("Network.setCookie", { name: ADMIN_COOKIE.slice(0, eq), value: ADMIN_COOKIE.slice(eq + 1), url: base, httpOnly: true, sameSite: "Strict" });
    await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "light" }] });

    // B1: Dark stored on a light system; the first paint, no module run.
    await send("Page.navigate", { url: base + "/settings" });
    await until("/settings: loaded", `document.readyState === "complete"`);
    await evaluate(`localStorage.setItem(${JSON.stringify(KEY)}, "dark"), true`);
    for (const path of ["/settings", "/"]) {
      const m = await firstPaint(path);
      assert.equal(m.theme, "dark", `${path}: the head script pinned Dark`);
      assert.equal(m.bg, s.dark, `${path}: --bg is the dark token`);
      assert.equal(m.ground, rgb(s.dark), `${path}: the body is drawn on it`);
    }

    // B2: home.js back; the menu, then a pick of Light.
    await send("Page.navigate", { url: base + "/settings" });
    await until("/settings: home.js drew the page", `document.querySelector('#page-settings nav.section-links a[data-section="appearance"]') !== null`);
    assert.equal(await evaluate(`document.getElementById("settings-theme").value`), "dark", "the menu shows Dark");
    await evaluate(`(() => { const m = document.getElementById("settings-theme"); m.value = "light"; m.dispatchEvent(new Event("change", { bubbles: true })); return true; })()`);
    const picked = await look();
    texts.push(picked.text);
    assert.equal(picked.theme, "light", "Light, at once");
    assert.equal(picked.bg, s.light, "--bg is the light token");
    assert.equal(picked.ground, rgb(s.light));
    assert.equal(picked.stored, "light", "stored under the developer view's key");

    // B3: the developer view, one stored choice.
    if (withDev) {
      await send("Page.navigate", { url: base + "/dev/" });
      await until("/dev/: its Appearance menu", `document.readyState === "complete" && document.getElementById("theme-select")?.value === "light"`);
      const dev = await look();
      assert.equal(dev.theme, "light", "the developer view draws Light");
      assert.equal(dev.bg, s.light);
      await evaluate(`(() => { const m = document.getElementById("theme-select"); m.value = "dark"; m.dispatchEvent(new Event("change", { bubbles: true })); return true; })()`);
      assert.equal((await look()).stored, "dark", "its pick is stored under the same key");
      const back = await firstPaint("/settings");
      assert.equal(back.theme, "dark", "the product page's first paint is the developer view's Dark");
      assert.equal(back.ground, rgb(s.dark));
    }

    // B4: the oracle.
    for (const t of texts) {
      assert.ok(!t.includes(VALUE), "CONFIDENTIALITY VIOLATION: a page carries the key's value");
      assert.doesNotMatch(t, /\$MDU/, "no page carries a token");
    }
  } finally {
    cdp.close();
    await tour.stopProc(proc);
    await dashboard.close();
    wired.close();
    data.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
