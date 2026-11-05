/**
 * agent-page-headings.test — dashboard.md §4.25, the per-agent page,
 * *Each turn and each secret card is a heading*, end to end: the REAL
 * DashboardServer over a FileEventSource holding the first-session tour of
 * 2026-10-05 (test/fixtures/tour-1791164083-1418381.ndjson, fake
 * secrets), its times moved so its last event was 30 seconds ago; the
 * served index.html and home.js run in jsdom with fetch bridged to it.
 *
 * Pins: the served session page lists one h3 per turn, in the order
 * /api/home/agent tells them, each naming its card and saying its line and
 * its time ("You asked at 10:34"), and one h3 per Your secrets card, its
 * name, the level tag beside it; the page's heading levels never skip.
 * The unit contracts: test/unit/ui/home-js-agent-headings.test.ts.
 *
 * Axes: none (display only; the mode is the session's recorded one, and no
 * arbiter runs).
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { JSDOM } from "jsdom";

import { DashboardServer } from "../../src/server.js";
import { FileEventSource } from "../../src/event-source.js";
import { tmpDir } from "../unit/tmp-dir.js";
import { waitWhile } from "../unit/page-wait.js";
import { pageFetch } from "../unit/page-fetch.js";

const ID = "1791164083-1418381";
const FIXTURE = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", `tour-${ID}.ndjson`);

let server: DashboardServer;
let base: string;
let dir: string;

before(async () => {
  dir = tmpDir("mandu-agent-headings-");
  const events = readFileSync(FIXTURE, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as { ts: string });
  const shift = Date.now() - 30_000 - Date.parse(events[events.length - 1]!.ts);
  writeFileSync(join(dir, `${ID}.ndjson`), events.map((e) => JSON.stringify({ ...e, ts: new Date(Date.parse(e.ts) + shift).toISOString() })).join("\n") + "\n");
  server = new DashboardServer({ source: new FileEventSource(dir), configEnv: { MANDU_HOME: tmpDir("mandu-agent-headings-home-") }, fileBrowserHome: "/home/user", log: () => {} });
  base = `http://127.0.0.1:${await server.listen(0)}`;
});

after(async () => {
  await server.close();
  rmSync(dir, { recursive: true, force: true });
});

interface Part { kind: string; text: string }
interface Served {
  story: { id: string; ts: string | null; prompt: string | null; shell: unknown }[];
  secrets: { secrets: { what: Part[] }[] };
}
/** A moment as the page draws it: this process's local clock, as jsdom's. */
const hhmm = (iso: string) => { const d = new Date(iso); return String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0"); };
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const said = (e: any) => String(e.textContent).replace(/\s+/g, " ").trim();

/** The served product page at `path` in jsdom, fetch bridged to the server;
 *  `fn` runs once `ready` holds, then the window closes. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function servedPage(path: string, ready: (doc: any) => boolean, fn: (doc: any) => void): Promise<void> {
  const html = await (await pageFetch(`${base}${path}`)).text();
  const js = await (await pageFetch(`${base}/js/home.js`)).text();
  const dom = new JSDOM(html.replace(/<script type="module"[^>]*><\/script>/, ""), { url: `${base}${path}`, runScripts: "outside-only", pretendToBeVisual: true });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const w = dom.window as any;
  let closed = false;
  const gate = <T>(p: Promise<T>): Promise<T> =>
    p.then((v) => (closed ? new Promise<T>(() => {}) : v), (e) => (closed ? new Promise<T>(() => {}) : Promise.reject(e)));
  w.fetch = (url: string, { signal: _signal, ...init }: RequestInit = {}) =>
    gate(pageFetch(new URL(url, base).href, init).then(async (res) => {
      const body = await res.text();
      return { ok: res.ok, status: res.status, json: () => gate(Promise.resolve().then(() => JSON.parse(body))) };
    }));
  w.setInterval = () => 0;
  w.scrollTo = () => {};
  w.eval(js);
  try {
    const doc = w.document;
    await waitWhile(() => !ready(doc));
    fn(doc);
  } finally {
    closed = true;
    w.close();
  }
}

test("the served session page: one h3 per turn in order with its time, one per secret card, and no level skipped", async () => {
  const page = (await (await pageFetch(`${base}/api/home/agent?session=${ID}`)).json()) as Served;
  assert.ok(page.story.length >= 5, "the tour's turns");
  assert.ok(page.secrets.secrets.length >= 2, "and its two secrets");
  // Several turns at one minute; over midnight the heading names the day too.
  const expected = page.story.map((t) => {
    const line = t.shell ? "You ran" : t.prompt !== null ? "You asked" : "Before your first question";
    return t.ts ? new RegExp(`^${line} at ${hhmm(t.ts)}( on [A-Z][a-z]+day, [A-Z][a-z]{2} \\d{1,2}(, \\d{4})?)?$`) : new RegExp(`^${line}$`);
  });
  await servedPage(`/agents/${ID}`, (doc) => doc.querySelectorAll("#agent-story article.turn").length >= page.story.length && !!doc.querySelector("#agent-secrets .secret-card"), (doc) => {
    const turns = [...doc.querySelectorAll("#agent-story article.turn[data-turn-id]")] as HTMLElement[];
    assert.deepEqual(turns.map((t) => t.dataset.turnId), page.story.map((t) => t.id), "the turns the server tells, in its order");
    turns.forEach((t, i) => {
      const h3s = t.querySelectorAll("h3");
      assert.equal(h3s.length, 1, `turn ${i}: one heading`);
      assert.equal(doc.getElementById(t.getAttribute("aria-labelledby")), h3s[0], `turn ${i}: named by it`);
      assert.match(said(h3s[0]), expected[i]!, `turn ${i}: its line and its time`);
    });
    const cards = [...doc.querySelectorAll("#agent-secrets .secret-card")] as HTMLElement[];
    assert.deepEqual(cards.map((c) => {
      const h3s = c.querySelectorAll("h3");
      assert.equal(h3s.length, 1, "one heading a card");
      assert.equal(h3s[0]!.querySelector(".tag"), null, "the level tag is beside the heading, not in it");
      assert.ok(c.querySelector(".secret-head > .tag"), "the tag is still on the card");
      return said(h3s[0]);
    }), page.secrets.secrets.map((s) => s.what.map((p) => p.text).join("").replace(/\s+/g, " ").trim()), "each card's name, as the server words it");
    assert.ok(cards.some((c) => /STRIPE_KEY/.test(said(c.querySelector("h3")))), "STRIPE_KEY's card among them");
    const levels = ([...doc.querySelectorAll("#page-agent h1, #page-agent h2, #page-agent h3, #page-agent h4, #page-agent h5, #page-agent h6")] as HTMLElement[])
      .filter((h) => !h.closest("[hidden]")).map((h) => Number(h.tagName[1]));
    assert.equal(levels[0], 1);
    levels.forEach((l, i) => { if (i) assert.ok(l <= levels[i - 1]! + 1, `h${l} after h${levels[i - 1]}: no level skipped`); });
  });
});
