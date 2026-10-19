/**
 * home-earlier.test — Home's earlier sessions, end to end (dashboard.md §4.25,
 * Home: *Earlier in the last 24 hours*).
 *
 * The REAL DashboardServer over recorded Secrets-mode sessions
 * (test/unit/view-model/walkthrough-fixture.ts) placed against the real
 * clock: one that ended about 3 hours ago, one about 22 hours ago (yesterday,
 * for most of the day), one 30 hours ago (outside the window). The served
 * product page (index.html, home.js) runs in jsdom with its fetch bridged to
 * that server.
 *
 * Pins:
 * - the list is headed by the window /api/home counts (`window.hours`), never
 *   "today": the window is rolling, so after midnight it still holds
 *   yesterday evening's sessions;
 * - every row says when its session ended, also a row with counts, with the
 *   clock time on hover;
 * - a row's counts read under its prompt, in the row's widest column, and
 *   the time sits alone in the next one (they once wrapped to four lines in
 *   a narrow third column);
 * - a session outside the window is not listed;
 * - a row names the folder its session ran in when one was recorded, as
 *   Running now and History do (it lost it on its way to Earlier).
 *
 * Axes: none (display only; the mode is the sessions' recorded one, and no
 * arbiter runs).
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { rmSync, writeFileSync } from "node:fs";
import { JSDOM } from "jsdom";

import { DashboardServer } from "../../src/server.js";
import { FileEventSource } from "../../src/event-source.js";
import { tmpDir } from "../unit/tmp-dir.js";
import { walkthroughEvents } from "../unit/view-model/walkthrough-fixture.js";
import { waitWhile } from "../unit/page-wait.js";
import { pageFetch } from "../unit/page-fetch.js";

const HOUR = 3_600_000;
const SHOP = "/srv/work/projects/shop";

let server: DashboardServer;
let base: string;
let dir: string;

before(async () => {
  dir = tmpDir("mandu-home-earlier-");
  const write = (id: string, hoursAgo: number) =>
    writeFileSync(join(dir, `${id}.ndjson`), sessionAt(id, hoursAgo).map((e) => JSON.stringify(e)).join("\n") + "\n");
  write("recent", 3);
  write("last-night", 22);
  write("too-old", 30);
  // A session whose agent's own prompt recorded where it ran (session-paths.ts
  // sessionCwd, the cwd /api/home serves for every row, ended ones too).
  const shop = sessionAt("in-shop", 5);
  const call = shop.find((e) => e.kind === "tllm_call")!;
  Object.assign(call, { fullInput: { blocks: [{ role: "system", source: "agent", text: ` - Primary working directory: ${SHOP}` }] } });
  writeFileSync(join(dir, "in-shop.ndjson"), shop.map((e) => JSON.stringify(e)).join("\n") + "\n");
  server = new DashboardServer({ source: new FileEventSource(dir), configEnv: { MANDU_HOME: tmpDir("mandu-home-earlier-home-") }, log: () => {} });
  base = `http://127.0.0.1:${await server.listen(0)}`;
});

after(async () => {
  await server.close();
  rmSync(dir, { recursive: true, force: true });
});

/** The walkthrough session, started `hoursAgo` hours before now (it lasts
 *  under a minute, so it ended about then too). */
function sessionAt(session: string, hoursAgo: number) {
  return walkthroughEvents({ session, startMs: Date.now() - hoursAgo * HOUR });
}

/** The served product page at `path` in jsdom, its fetch bridged to the
 *  server; `fn` runs once `ready` holds, then the window closes. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function servedPage(path: string, ready: (doc: any) => boolean, fn: (doc: any) => void): Promise<void> {
  const html = await (await pageFetch(`${base}${path}`)).text();
  const js = await (await pageFetch(`${base}/js/home.js`)).text();
  const dom = new JSDOM(html.replace(/<script type="module"[^>]*><\/script>/, ""), { url: `${base}${path}`, runScripts: "outside-only", pretendToBeVisual: true });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const w = dom.window as any;
  let closed = false;
  // Once closed, nothing the page awaits resolves, so no late answer reaches
  // a closed window.
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

test("/api/home: the window the counts cover, with the two sessions inside it ended", async () => {
  const res = await pageFetch(`${base}/api/home`);
  assert.equal(res.status, 200);
  const home = (await res.json()) as { window: { hours: number }; agents: { id: string; state: string }[] };
  assert.equal(home.window.hours, 24);
  assert.deepEqual(home.agents.map((a) => [a.id, a.state]).sort(), [["in-shop", "idle"], ["last-night", "idle"], ["recent", "idle"]]);
});

test("the served Home heads its earlier sessions by that window, never 'today', and each row says when it ended", async () => {
  await servedPage("/", (doc) => doc.querySelectorAll("#home-earlier .row.agent").length > 0, (doc) => {
    assert.equal(doc.getElementById("home-earlier-block").hidden, false);
    assert.equal(doc.getElementById("home-earlier-title").textContent, "Earlier in the last 24 hours");
    assert.doesNotMatch(doc.getElementById("home-earlier-block").textContent, /today/i);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const row = (id: string): any => doc.querySelector(`#home-earlier [data-session="${id}"]`)?.closest(".row.agent") ?? null;
    const recent = row("recent");
    assert.ok(recent, "the session from 3 hours ago is listed");
    // The walkthrough's two secrets, its blocked send and its two sends
    // with a secret filled in, as its page's tiles count them.
    assert.equal(recent.querySelector(".agent-counts").textContent, "2 secrets masked, 1 action blocked, 2 sends with a real value filled in");
    assert.equal(recent.querySelector(".agent-ended").textContent, "ended 3 hours ago", "counts do not hide when it ended");
    // The counts under the prompt, the time alone in its own column.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    assert.deepEqual([...recent.children].map((c: any) => c.className), ["name", "agent-what", "dim agent-when", "right"]);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    assert.deepEqual([...recent.querySelector(".agent-what").children].map((c: any) => c.className), ["sub ellipsis", "dim agent-counts"]);
    assert.equal(recent.querySelector(".agent-when").textContent, "ended 3 hours ago");
    assert.match(recent.querySelector(".agent-ended time").getAttribute("title"), /^[A-Z][a-z]{2} \d{1,2}(?:, \d{4})?, \d{2}:\d{2}$/);
    assert.equal(row("last-night").querySelector(".agent-ended").textContent, "ended 22 hours ago");
    assert.equal(row("too-old"), null, "a session outside the window is not listed");
    assert.doesNotMatch(doc.getElementById("page-home").textContent, /\$MDU:/);
  });
});

test("an ended session with a recorded folder names it under Earlier, as Running now and History do; one without names none", async () => {
  await servedPage("/", (doc) => doc.querySelector('#home-earlier .row.agent[data-session="in-shop"]') !== null, (doc) => {
    const first = (id: string) => doc.querySelector(`#home-earlier .row.agent[data-session="${id}"] .agent-what .sub`);
    const shop = first("in-shop");
    assert.match(shop.textContent, / in \/srv\/work\/projects\/shop$/, "its folder, outside the home folder kept as recorded");
    assert.equal(shop.querySelector("code").textContent, SHOP);
    assert.match(shop.getAttribute("title"), new RegExp(` — ${SHOP}$`), "the full path on hover");
    assert.equal(first("recent").querySelector("code"), null, "no folder recorded: none named");
    assert.doesNotMatch(first("recent").textContent, / in \//);
  });
});
