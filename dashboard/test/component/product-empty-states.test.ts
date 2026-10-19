/**
 * product-empty-states.test — dashboard.md §4.25 "Empty states", end to end.
 *
 * The REAL DashboardServer over the fixtures with no protection service
 * behind it, which is what a fresh install shows before its first agent runs.
 * The served product page (index.html, home.js, and the served mandu.css and
 * app.css as the page's styles) runs in jsdom with its fetch bridged to that
 * server.
 *
 * Pins:
 * - each empty or fallback state the page writes names its commands as
 *   code (Home › Running now, Settings › Protection service);
 * - Approvals › Answered earlier is not a bare heading;
 * - Rules says your rules could not be read, never "no rules", since no
 *   protection service gave them (the panel route answers `available:
 *   false`); the list under the explorer is not drawn. Its "browse all
 *   files" is drawn as a link, not as the browser's grey button: the served
 *   styles give it a link's color and no border or background, and it
 *   opens All files.
 * - Settings › Models offers no Add while its list cannot be read, and
 *   Settings › Prompt filters, refused, shows no Exceptions heading or note,
 *   and no "What the choices mean" fold opening on nothing.
 * - An empty state has one frame: Home › Running now and Approvals ›
 *   Answered earlier draw no list frame around their dashed box, the
 *   Protection row's service line without controls is a plain line, and
 *   Settings › Prompt filters' Exceptions list, with nothing it could read,
 *   draws nothing (the served styles with the theme's tokens resolved).
 *
 * Axes: none (display only; no arbiter runs).
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";

import { DashboardServer } from "../../src/server.js";
import { FileEventSource } from "../../src/event-source.js";
import { tmpDir } from "../unit/tmp-dir.js";
import { resolveCssVars } from "../unit/ui/css-flatten.js";
import { waitWhile } from "../unit/page-wait.js";
import { pageFetch } from "../unit/page-fetch.js";

const FIXTURES_DIR = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..", "fixtures");

let server: DashboardServer;
let base: string;
let styles: string;

before(async () => {
  server = new DashboardServer({
    source: new FileEventSource(FIXTURES_DIR),
    configEnv: { MANDU_HOME: tmpDir("mandu-empty-states-home-") },
    log: () => {},
  });
  base = `http://127.0.0.1:${await server.listen(0)}`;
  // The page's two stylesheets, in its own order (shared first).
  const css = async (f: string) => {
    const r = await pageFetch(`${base}/${f}`);
    assert.equal(r.status, 200, `${f} is served`);
    return r.text();
  };
  styles = (await css("mandu.css")) + "\n" + (await css("app.css"));
});

after(async () => {
  await server.close();
});

/** The served page at `path` running against the server, with the served
 *  styles applied (jsdom does not fetch the page's stylesheet links), or
 *  the `css` given. */
async function openPage(path: string, css = styles) {
  const html = await (await pageFetch(`${base}${path}`)).text();
  const js = await (await pageFetch(`${base}/js/home.js`)).text();
  const dom = new JSDOM(html.replace(/<script type="module"[^>]*><\/script>/, ""), {
    url: `${base}${path}`, runScripts: "outside-only", pretendToBeVisual: true,
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const w = dom.window as any;
  const style = w.document.createElement("style");
  style.textContent = css;
  w.document.head.append(style);
  // Once closed, nothing the page awaits resolves, so no late answer reaches
  // a closed window (Settings and Rules keep loading after a test is done).
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
  return { w, doc: w.document as Document, close: () => { closed = true; w.close(); } };
}

/** Wait until `check` holds (the page renders after its fetches answer). */
async function until(check: () => boolean, what: string): Promise<void> {
  await waitWhile(() => !check());
  assert.ok(check(), what);
}

const codes = (node: Element | null): string[] => [...(node?.querySelectorAll("code") ?? [])].map((c) => c.textContent ?? "");

test("Home: no agent is running, and the sentence names mandu claude and mandu codex as code", async () => {
  const { doc, close } = await openPage("/");
  try {
    await until(() => doc.querySelector("#home-agents .empty") !== null, "Running now rendered");
    const empty = doc.querySelector("#home-agents .empty");
    assert.equal(empty?.textContent, "No agent is running right now. Start one with mandu claude or mandu codex.");
    assert.deepEqual(codes(empty), ["mandu claude", "mandu codex"]);
  } finally {
    close();
  }
});

test("Approvals: with no protection service, Answered earlier says it could not check", async () => {
  const { doc, close } = await openPage("/approvals");
  try {
    await until(() => (doc.getElementById("approvals-answered")?.textContent ?? "") !== "", "Answered earlier rendered");
    assert.equal(doc.getElementById("approvals-answered")?.textContent, "Could not check your earlier answers. The protection service may be unreachable.");
  } finally {
    close();
  }
});

test("Settings: a dashboard without the service controls names mandu dashboard as code", async () => {
  const { doc, close } = await openPage("/settings");
  try {
    await until(() => doc.querySelector("#settings-services .service-none") !== null, "Protection service rendered");
    const empty = doc.querySelector("#settings-services .service-none");
    assert.match(empty?.textContent ?? "", /^This dashboard was started without the service controls\. Start it with mandu dashboard /);
    assert.deepEqual(codes(empty), ["mandu dashboard"]);
  } finally {
    close();
  }
});

test("Rules: your rules could not be read, never \"no rules\"; add a rule is drawn as a link, not as the browser's grey button, and opens the file browser", async () => {
  const { w, doc, close } = await openPage("/rules");
  try {
    await until(() => doc.querySelector("#files-tree .empty-row button") !== null, "Your rules' empty row rendered");
    const row = doc.querySelector("#files-tree .empty-row") as HTMLElement;
    assert.equal(row.textContent, "Your rules could not be read. The protection service may be unreachable. You can still add a rule.");
    assert.equal((doc.getElementById("rules-list") as HTMLElement).hidden, true, "the list below is not drawn");
    assert.doesNotMatch(doc.getElementById("page-rules")?.textContent ?? "", /No rules yet|No file or folder has a rule of yours yet/);
    const btn = row.querySelector("button") as HTMLButtonElement;
    const css = (e: Element) => w.getComputedStyle(e);
    // The color links get (mandu.css `a`). jsdom leaves custom properties
    // unresolved, and its own `a:link` default outranks the page's `a` rule,
    // so the yardstick is the token itself, not a live link.
    assert.match(styles, /(^|\n)a \{ color: var\(--accent\);/, "links are var(--accent)");
    assert.equal(css(btn).color, "var(--accent)", "a link's color");
    assert.notEqual(css(btn).color, css(row).color, "not the sentence's own (inherited) color");
    assert.equal(css(btn).borderTopStyle, "none", "no button border");
    assert.equal(css(btn).backgroundColor, "rgba(0, 0, 0, 0)", "no button fill");
    btn.click();
    await until(() => !(doc.getElementById("lock-form") as HTMLElement).hidden, "the file browser opened");
    assert.equal(doc.getElementById("rules-add")?.getAttribute("aria-expanded"), "true");
  } finally {
    close();
  }
});

/** The list around an empty state draws no frame or fill of its own; the
 *  dashed box is the one frame (jsdom reads a border holding a `var()` as
 *  none, so the tokens are resolved first). */
function oneFrame(w: Window, list: Element, what: string): void {
  const css = (e: Element) => w.getComputedStyle(e);
  const empty = list.querySelector(":scope > .empty");
  assert.ok(empty && list.children.length === 1, `${what}: the empty state alone`);
  assert.equal(css(list).borderTopStyle, "none", `${what}: no list frame around it`);
  assert.equal(css(list).backgroundColor, "rgba(0, 0, 0, 0)", `${what}: no list fill`);
  assert.equal(css(empty).borderTopStyle, "dashed", `${what}: its own dashed frame`);
}

test("Home and Approvals: an empty state has one frame, as in the card list above it", async () => {
  const resolved = resolveCssVars(styles);
  const home = await openPage("/", resolved);
  try {
    await until(() => home.doc.querySelector("#home-agents .empty") !== null, "Running now rendered");
    await until(() => home.doc.querySelector("#home-waiting .empty") !== null, "Approvals waiting rendered");
    oneFrame(home.w, home.doc.getElementById("home-agents")!, "Running now");
    assert.equal(home.w.getComputedStyle(home.doc.querySelector("#home-waiting .empty")!).borderTopStyle, "dashed", "Approvals waiting, a card list, looks the same");
  } finally {
    home.close();
  }
  const approvals = await openPage("/approvals", resolved);
  try {
    await until(() => approvals.doc.querySelector("#approvals-answered .empty") !== null, "Answered earlier rendered");
    oneFrame(approvals.w, approvals.doc.getElementById("approvals-answered")!, "Answered earlier");
  } finally {
    approvals.close();
  }
});

test("Settings: each refusal has one frame, and the Exceptions list with nothing to show draws nothing", async () => {
  const { w, doc, close } = await openPage("/settings", resolveCssVars(styles));
  try {
    await until(() => doc.querySelector("#settings-prompt-kinds .empty") !== null, "Prompt filters rendered");
    await until(() => doc.querySelector("#settings-labels .empty") !== null, "Sensitivity labels rendered");
    await until(() => doc.querySelector("#settings-services .service-none") !== null, "Protection service rendered");
    await until(() => doc.querySelector("#settings-models .empty") !== null, "Models rendered");
    for (const id of ["settings-models", "settings-labels", "settings-prompt-kinds"]) oneFrame(w, doc.getElementById(id)!, id);
    // The service is a line of the Protection row (dashboard.md §4.25 *One
    // Protection row*): its refusal is a plain line there, in no frame.
    const none = doc.querySelector("#settings-services .service-none")!;
    assert.equal(w.getComputedStyle(none).borderTopStyle, "none", "the service line: no frame inside the row");
    assert.ok(doc.getElementById("settings-protect-row")!.contains(none), "inside the Protection row");
    const ex = doc.getElementById("settings-prompt-exceptions")!;
    assert.equal(ex.childNodes.length, 0, "the filters could not be read, so no exception is listed");
    assert.equal(w.getComputedStyle(ex).display, "none", "no stray line under the Exceptions heading");
  } finally {
    close();
  }
});

test("Settings: a block that could not be read is its sentence alone: no Add a model, no Exceptions heading, no \"What the choices mean\"", async () => {
  const { w, doc, close } = await openPage("/settings");
  try {
    await until(() => doc.querySelector("#settings-models .empty") !== null, "Models rendered");
    await until(() => doc.querySelector("#settings-prompt-kinds .empty") !== null, "Prompt filters rendered");
    assert.equal(doc.getElementById("settings-models")?.textContent, "The model list could not be read. The protection service may be unreachable.");
    const shown = (id: string) => w.getComputedStyle(doc.getElementById(id)!).display !== "none";
    assert.equal(shown("model-open"), false, "no Add a model");
    assert.equal(shown("model-form"), false);
    for (const id of ["settings-prompt-exceptions-head", "settings-prompt-exceptions-about", "settings-prompt-meanings-fold", "settings-prompt-meanings", "prompt-exception-form"]) {
      assert.equal(shown(id), false, `${id} is not drawn`);
    }
    assert.equal(shown("settings-prompt-about"), true, "the block still says what it is");
  } finally {
    close();
  }
});
