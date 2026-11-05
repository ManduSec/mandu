/**
 * count-meanings.test — what each count means opens with a tap or a key,
 * not only in a mouse-hover tooltip, in a real headless Chromium over the
 * REAL components (dashboard.md §4.25 *What the counts mean*). Mandu-new.
 *
 * Home's counts and a session page's tiles said what they count only in a
 * `title`, which a phone never shows, nor the keyboard. Here a real
 * ArbiterServer (`secrets`) whose event store holds the recorded
 * first-session tour (dashboard/test/fixtures/tour-1791164083-1418381.ndjson,
 * fake secrets, its times moved so it ended a minute ago: secrets masked,
 * a send blocked and a send with a real value filled in), a real
 * DashboardServer over the production adapter (`makeApprovalsArbiter`), and
 * a headless Chromium driven over the DevTools protocol
 * (scripts/tour-screenshots.mjs), signed in, at 390 px:
 *
 *   M1  Home: Tab from the "1 send with a real value filled in" link lands
 *       on its "?", Enter opens its note, which says what the count means
 *       and stays inside the window (`keepInWindow`); Escape closes it;
 *   M2  the session page: *What the counts mean* is drawn closed under the
 *       tiles; Enter on its summary opens it, and it lists the masked,
 *       blocked and sent counts with their meanings, never "Press";
 *   M3  History: *What the counts mean* is drawn closed under the search;
 *       Enter on its summary opens it, and it lists exactly the counts the
 *       tour's row shows (masked, read before it was marked, blocked,
 *       sent), in the row's order;
 *   M5  Home: *What the counts mean* is drawn closed under Earlier (where
 *       the tour's session ended a minute ago), at 1280 px and at 390 px;
 *       Enter on its summary opens it, and it lists exactly the counts the
 *       tour's Earlier row shows, in the row's order, with no sideways
 *       scroll;
 *   M4  the oracle: no page drawn here carries the tour's fake values or a
 *       token.
 *
 * Self-SKIPs without a Chromium (scripts/tour-screenshots.mjs probeBrowser:
 * MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell, or one on
 * PATH). Axes: secrets (stated).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS, ADMIN_TOKEN, SESSION_SECRET } from "../../dashboard/test/unit/admin-session.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
interface Cdp { send(method: string, params?: object, sessionId?: string): Promise<any>; close(): void }
const tour = (await import(pathToFileURL(join(REPO, "scripts", "tour-screenshots.mjs")).href)) as {
  probeBrowser: (o?: object) => string | null;
  startBrowser: (path: string, dataDir: string, env: NodeJS.ProcessEnv) => Promise<{ proc: unknown; wsUrl: string }>;
  stopProc: (proc: unknown) => Promise<void>;
  Cdp: { connect(url: string): Promise<Cdp> };
  FAKE_VALUES: string[];
};
const browser = tour.probeBrowser({});

const ID = "1791164083-1418381";
const FIXTURE = join(REPO, "dashboard", "test", "fixtures", `tour-${ID}.ndjson`);
const SENT_HELP = '#hero-facts .help-btn[aria-label="What a send with a real value means"]';

test("each count's meaning opens with a key at 390 px: Home's sent \"?\" from Tab and Enter, inside the window; the session page's, History's and Home's What the counts mean list them; no value on a page (real Chromium, arbiter and dashboard; secrets axes)", {
  skip: browser ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 240_000,
}, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-count-meanings-"));
  const home = join(tmp, "home");
  mkdirSync(home, { recursive: true });
  const eventDir = join(tmp, "events");
  mkdirSync(eventDir, { recursive: true });
  const events = readFileSync(FIXTURE, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as { ts: string });
  const shift = Date.now() - 60_000 - Date.parse(events.at(-1)!.ts);
  writeFileSync(join(eventDir, `${ID}.ndjson`), events.map((e) => JSON.stringify({ ...e, ts: new Date(Date.parse(e.ts) + shift).toISOString() })).join("\n") + "\n");
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir, policyPath: join(tmp, "policy.yaml"), policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {}, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired, "the production adapter is wired");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc, secretsArbiter: wired.secrets,
    postureArbiter: wired.posture, auditArbiter: wired.audit,
    fileBrowserHome: home, configEnv: { MANDU_HOME: join(tmp, "mandu-home"), HOME: home },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  let proc: unknown = null;
  let cdp: Cdp | null = null;
  const pages: string[] = [];
  try {
    // The session holds what is under test: masked secrets, a blocked step
    // and a send with a real value filled in.
    const vm = await (await pageFetch(`${base}/api/home/agent?session=${ID}`, { headers: { cookie: ADMIN_COOKIE } })).json() as { secrets?: { counts: { masked: number } }; blocked: number; sent: number };
    assert.ok((vm.secrets?.counts.masked ?? 0) > 0 && vm.blocked > 0 && vm.sent === 1, `the tour masks, blocks and sends: ${JSON.stringify({ secrets: vm.secrets?.counts, blocked: vm.blocked, sent: vm.sent })}`);

    const started = await tour.startBrowser(browser as string, join(tmp, "chrome"), process.env);
    proc = started.proc;
    cdp = await tour.Cdp.connect(started.wsUrl);
    const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    const s = (method: string, params: object = {}) => cdp!.send(method, params, sessionId);
    const evaluate = async (expression: string) => {
      const r = await s("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) throw new Error(`page script failed: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
      return r.result.value;
    };
    await s("Page.enable");
    await s("Runtime.enable");
    await s("Network.enable");
    const eq = ADMIN_COOKIE.indexOf("=");
    await s("Network.setCookie", { name: ADMIN_COOKIE.slice(0, eq), value: ADMIN_COOKIE.slice(eq + 1), url: base, httpOnly: true, sameSite: "Strict" });
    await s("Emulation.setDeviceMetricsOverride", { width: 390, height: 900, deviceScaleFactor: 1, mobile: true });
    const settle = () => evaluate("new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(() => setTimeout(() => r(true), 150))))");
    const open = async (path: string, ready: string, at: string) => {
      await s("Page.navigate", { url: base + path });
      let ok = false;
      for (const end = Date.now() + 30_000; Date.now() < end && !ok; await new Promise((r) => setTimeout(r, 100))) {
        try { ok = await evaluate(`document.readyState === "complete" && document.fonts.status === "loaded" && (${ready})`); } catch { /* navigating */ }
      }
      assert.ok(ok, `${at}: the page drew`);
      await settle();
    };
    // A real key press, as a keyboard sends it.
    const press = async (key: string, code: string, keyCode: number) => {
      await s("Input.dispatchKeyEvent", { type: "keyDown", key, code, windowsVirtualKeyCode: keyCode, text: key === "Enter" ? "\r" : undefined });
      await s("Input.dispatchKeyEvent", { type: "keyUp", key, code, windowsVirtualKeyCode: keyCode });
      await settle();
    };

    // ── M1: Home's sent count, from the keyboard ──
    await open("/", `!!document.querySelector(${JSON.stringify(SENT_HELP)})`, "Home at 390px");
    const link = await evaluate(`(() => {
      const btn = document.querySelector(${JSON.stringify(SENT_HELP)});
      const a = btn.closest(".help").parentElement.querySelector("a");
      a.scrollIntoView({ block: "center" });
      a.focus();
      return { focused: document.activeElement === a, text: a.textContent.trim(), inside: !!a.querySelector("button") };
    })()`) as { focused: boolean; text: string; inside: boolean };
    assert.equal(link.focused, true, "the count's link takes the focus");
    assert.equal(link.text, "1 send with a real value filled in");
    assert.equal(link.inside, false, "the \"?\" is not inside the link");
    await press("Tab", "Tab", 9);
    assert.equal(await evaluate(`document.activeElement === document.querySelector(${JSON.stringify(SENT_HELP)})`), true, "Tab from the count lands on its \"?\"");
    await press("Enter", "Enter", 13);
    const note = await evaluate(`(() => {
      const btn = document.querySelector(${JSON.stringify(SENT_HELP)});
      const pop = document.getElementById(btn.getAttribute("aria-controls"));
      const r = pop.getBoundingClientRect();
      return { expanded: btn.getAttribute("aria-expanded"), hidden: pop.hidden, text: pop.textContent, left: r.left, right: r.right, width: document.documentElement.clientWidth, scrollX: document.documentElement.scrollWidth, path: location.pathname };
    })()`) as { expanded: string; hidden: boolean; text: string; left: number; right: number; width: number; scrollX: number; path: string };
    assert.equal(note.expanded, "true", "Enter opens the note");
    assert.equal(note.hidden, false);
    assert.equal(note.text, "It went to a destination allowed to receive it.", "it says what the count means");
    assert.equal(note.path, "/", "and the page stays Home");
    assert.ok(note.left >= 0 && note.right <= note.width, `the note stays inside the window: ${note.left}..${note.right} of ${note.width}`);
    assert.ok(note.scrollX <= note.width, `the page does not scroll sideways: ${note.scrollX} > ${note.width}`);
    pages.push(await evaluate("document.documentElement.outerHTML + document.body.innerText"));
    await press("Escape", "Escape", 27);
    assert.equal(await evaluate(`document.querySelector(${JSON.stringify(SENT_HELP)}).getAttribute("aria-expanded")`), "false", "Escape closes it");

    // ── M2: the session page's What the counts mean ──
    await open(`/agents/${ID}`, `!!document.querySelector("#agent-facts .tile") && document.getElementById("agent-count-meanings").hidden === false`, "the session page at 390px");
    const closed = await evaluate(`(() => {
      const f = document.getElementById("agent-count-meanings");
      const sum = f.querySelector("summary");
      sum.scrollIntoView({ block: "center" });
      sum.focus();
      return { open: f.open, under: document.getElementById("agent-facts").nextElementSibling === f, focused: document.activeElement === sum, height: f.getBoundingClientRect().height };
    })()`) as { open: boolean; under: boolean; focused: boolean; height: number };
    assert.equal(closed.open, false, "closed by default");
    assert.equal(closed.under, true, "right under the tiles");
    assert.equal(closed.focused, true, "its summary takes the focus");
    assert.ok(closed.height < 40, `closed, it is one line: ${closed.height}px`);
    await press("Enter", "Enter", 13);
    const listed = await evaluate(`(() => {
      const f = document.getElementById("agent-count-meanings");
      return { open: f.open, entries: [...f.querySelectorAll("dt")].map((dt) => [dt.textContent, dt.nextElementSibling.textContent]), text: f.innerText };
    })()`) as { open: boolean; entries: [string, string][]; text: string };
    assert.equal(listed.open, true, "Enter opens it");
    const terms = listed.entries.map(([t]) => t);
    for (const t of ["Secrets masked before the AI saw them", "Actions blocked", "Sends with a real value filled in"]) assert.ok(terms.includes(t), `it lists ${t}: ${JSON.stringify(terms)}`);
    const sent = listed.entries.find(([t]) => t === "Sends with a real value filled in")!;
    assert.match(sent[1], /^It went to a destination allowed to receive it\./);
    assert.doesNotMatch(listed.text, /Press/, "never the press");
    pages.push(await evaluate("document.documentElement.outerHTML + document.body.innerText"));

    // ── M3: History's What the counts mean ──
    await open("/history", `!!document.querySelector('#history-list .row.agent[data-session="${ID}"]') && document.getElementById("history-count-meanings").hidden === false`, "History at 390px");
    const hClosed = await evaluate(`(() => {
      const f = document.getElementById("history-count-meanings");
      const sum = f.querySelector("summary");
      sum.scrollIntoView({ block: "center" });
      sum.focus();
      const form = document.getElementById("history-search").getBoundingClientRect();
      const list = document.getElementById("history-list").getBoundingClientRect();
      const r = f.getBoundingClientRect();
      return { open: f.open, under: document.getElementById("history-search").nextElementSibling === f, focused: document.activeElement === sum, height: r.height,
        between: form.bottom <= r.top && r.bottom <= list.top, row: document.querySelector('#history-list .row.agent[data-session="${ID}"] .agent-counts').textContent };
    })()`) as { open: boolean; under: boolean; focused: boolean; height: number; between: boolean; row: string };
    assert.equal(hClosed.open, false, "closed by default");
    assert.equal(hClosed.under, true, "right under the search");
    assert.equal(hClosed.between, true, "drawn between the search and the list");
    assert.equal(hClosed.focused, true, "its summary takes the focus");
    assert.ok(hClosed.height < 40, `closed, it is one line: ${hClosed.height}px`);
    assert.match(hClosed.row, /secrets? masked.*actions? blocked.*1 send with a real value filled in/, `the tour's row shows the counts: ${hClosed.row}`);
    await press("Enter", "Enter", 13);
    const hListed = await evaluate(`(() => {
      const f = document.getElementById("history-count-meanings");
      return { open: f.open, entries: [...f.querySelectorAll("dt")].map((dt) => [dt.textContent, dt.nextElementSibling.textContent]), width: document.documentElement.clientWidth, scrollX: document.documentElement.scrollWidth };
    })()`) as { open: boolean; entries: [string, string][]; width: number; scrollX: number };
    assert.equal(hListed.open, true, "Enter opens it");
    // Exactly the kinds the row shows (the tour reads a secret before it
    // is marked too), in the row's order.
    const shown = ([[/secrets? masked/, "Secrets masked before the AI saw them"], [/read before/, "Secrets the AI read before they were marked secrets"],
      [/actions? blocked/, "Actions blocked"], [/sends? with a real value/, "Sends with a real value filled in"]] as [RegExp, string][]).filter(([re]) => re.test(hClosed.row)).map(([, t]) => t);
    assert.deepEqual(hListed.entries.map(([t]) => t), shown, "the row's counts, in its order");
    for (const t of ["Secrets masked before the AI saw them", "Actions blocked", "Sends with a real value filled in"]) assert.ok(shown.includes(t), `it lists ${t}`);
    assert.equal(hListed.entries.find(([t]) => t === "Sends with a real value filled in")![1], "Each went to a destination allowed to receive it.");
    assert.ok(hListed.scrollX <= hListed.width, `the page does not scroll sideways: ${hListed.scrollX} > ${hListed.width}`);
    pages.push(await evaluate("document.documentElement.outerHTML + document.body.innerText"));

    // ── M5: Home's What the counts mean, under Earlier, wide and at 390 px ──
    const rowTerms = (row: string) => ([[/secrets? masked/, "Secrets masked before the AI saw them"], [/read before/, "Secrets the AI read before they were marked secrets"],
      [/actions? blocked/, "Actions blocked"], [/sends? with a real value/, "Sends with a real value filled in"]] as [RegExp, string][]).filter(([re]) => re.test(row)).map(([, t]) => t);
    for (const width of [1280, 390]) {
      await s("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 600 });
      await open("/", `!!document.querySelector('#home-earlier .row.agent[data-session="${ID}"]') && document.getElementById("home-count-meanings").hidden === false`, `Home at ${width}px`);
      const wClosed = await evaluate(`(() => {
        const f = document.getElementById("home-count-meanings");
        const sum = f.querySelector("summary");
        sum.scrollIntoView({ block: "center" });
        sum.focus();
        const above = document.getElementById("home-earlier-block").getBoundingClientRect();
        const r = f.getBoundingClientRect();
        return { open: f.open, under: document.getElementById("home-earlier-block").nextElementSibling === f, focused: document.activeElement === sum, height: r.height,
          below: above.bottom <= r.top, row: document.querySelector('#home-earlier .row.agent[data-session="${ID}"] .agent-counts').textContent };
      })()`) as { open: boolean; under: boolean; focused: boolean; height: number; below: boolean; row: string };
      assert.equal(wClosed.open, false, `${width}px: closed by default`);
      assert.equal(wClosed.under, true, `${width}px: right under Earlier`);
      assert.equal(wClosed.below, true, `${width}px: drawn below Earlier's rows`);
      assert.equal(wClosed.focused, true, `${width}px: its summary takes the focus`);
      assert.ok(wClosed.height < 40, `${width}px: closed, it is one line: ${wClosed.height}px`);
      assert.match(wClosed.row, /secrets? masked.*actions? blocked.*1 send with a real value filled in/, `the tour's Earlier row shows the counts: ${wClosed.row}`);
      await press("Enter", "Enter", 13);
      const wListed = await evaluate(`(() => {
        const f = document.getElementById("home-count-meanings");
        return { open: f.open, entries: [...f.querySelectorAll("dt")].map((dt) => [dt.textContent, dt.nextElementSibling.textContent]), width: document.documentElement.clientWidth, scrollX: document.documentElement.scrollWidth };
      })()`) as { open: boolean; entries: [string, string][]; width: number; scrollX: number };
      assert.equal(wListed.open, true, `${width}px: Enter opens it`);
      // The tour is the only session on Home: exactly its row's kinds.
      assert.deepEqual(wListed.entries.map(([t]) => t), rowTerms(wClosed.row), `${width}px: the row's counts, in its order`);
      assert.equal(wListed.entries.find(([t]) => t === "Sends with a real value filled in")![1], "Each went to a destination allowed to receive it.");
      assert.ok(wListed.scrollX <= wListed.width, `${width}px: the page does not scroll sideways: ${wListed.scrollX} > ${wListed.width}`);
      pages.push(await evaluate("document.documentElement.outerHTML + document.body.innerText"));
    }

    // ── M4: the oracle ──
    assert.equal(pages.length, 5, "every page was read");
    for (const page of pages) {
      for (const v of tour.FAKE_VALUES) assert.ok(!page.includes(v), `CONFIDENTIALITY VIOLATION: the tour's ${v} on a page`);
      assert.doesNotMatch(page, /\$MDU/, "nor a token");
      assert.ok(!page.includes(ADMIN_TOKEN) && !page.includes(SESSION_SECRET), "no credential on a page");
    }
  } finally {
    cdp?.close();
    if (proc) await tour.stopProc(proc);
    await dashboard.close();
    wired?.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
