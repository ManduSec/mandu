/**
 * product-refusal-words.test — dashboard.md §4.25 "Refusals", end to end.
 *
 * The REAL DashboardServer with no protection service behind it (fixtures
 * only), and the served product page (index.html + home.js) in jsdom with its
 * fetch bridged to that server, with and without the admin session cookie.
 * So the refusals are the ones the server's own gates write: the admin
 * session gate on a read (Settings › Prompt filters, the file explorer's
 * folder) and on a POST (Describe what you want), and "no protection service"
 * on a read (Settings › Sensitivity labels, the Suggested view).
 *
 * Pins: the page says each in its own words, and no developer term from
 * those refusals (the gate's environment variable and login link, the
 * inspector's "arbiter") reaches it. The sign-in sentence names its command
 * as code everywhere it shows, never quoted or back-ticked (§4.25
 * "Refusals"). With the admin session, Settings no longer asks to sign in.
 * Axes: none (display only; no arbiter runs).
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";

import { DashboardServer } from "../../src/server.js";
import { FileEventSource } from "../../src/event-source.js";
import { ADMIN_OPTS, ADMIN_COOKIE } from "../unit/admin-session.js";
import { tmpDir } from "../unit/tmp-dir.js";
import { waitWhile } from "../unit/page-wait.js";
import { pageFetch } from "../unit/page-fetch.js";

const FIXTURES_DIR = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..", "fixtures");

const SIGN_IN = "Sign in first: in your own terminal, run mandu dashboard and open the sign-in link it prints (each link works once), or sign in with the dashboard's password if it has one.";
/** The command spelled as a string mark, which the page must not show. */
const MARKED_COMMAND = /"mandu dashboard"|`mandu dashboard`/;
const NOT_CONNECTED = "The protection service is not connected.";
/** What the server's gates say that the product page must not. */
const DEVELOPER = /arbiter|admin session|DASHBOARD_|login\?token|X-Mandu|under Services/i;

let server: DashboardServer;
let base: string;

before(async () => {
  server = new DashboardServer({
    source: new FileEventSource(FIXTURES_DIR),
    configEnv: { MANDU_HOME: tmpDir("mandu-refusal-home-") },
    log: () => {},
    ...ADMIN_OPTS,
  });
  base = `http://127.0.0.1:${await server.listen(0)}`;
});

after(async () => {
  await server.close();
});

/** The served page at `path`, running against the server; `admin` sends the
 *  admin session cookie with every request, as a signed-in browser does. */
async function openPage(path: string, admin: boolean) {
  const html = await (await pageFetch(`${base}${path}`)).text();
  const js = await (await pageFetch(`${base}/js/home.js`)).text();
  const dom = new JSDOM(html.replace(/<script type="module"[^>]*><\/script>/, ""), {
    url: `${base}${path}`, runScripts: "outside-only", pretendToBeVisual: true,
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const w = dom.window as any;
  // The page keeps loading after a test has what it needs (Settings reads
  // several blocks): once closed, nothing it awaits resolves, so no late answer
  // reaches a closed window.
  let closed = false;
  const gate = <T>(p: Promise<T>): Promise<T> =>
    p.then((v) => (closed ? new Promise<T>(() => {}) : v), (e) => (closed ? new Promise<T>(() => {}) : Promise.reject(e)));
  // A jsdom AbortSignal is not one node's fetch accepts (Describe sends one):
  // the bridge drops it, as nothing here cancels.
  w.fetch = (url: string, { signal: _signal, ...init }: RequestInit = {}) => {
    const headers = { ...(init.headers as Record<string, string> | undefined), ...(admin ? { Cookie: ADMIN_COOKIE } : {}) };
    // The body is read at once, so no answer is left half read when closed.
    return gate(pageFetch(new URL(url, base).href, { ...init, headers })
      .then(async (res) => {
        const body = await res.text();
        return { ok: res.ok, status: res.status, json: () => gate(Promise.resolve().then(() => JSON.parse(body))) };
      }));
  };
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

const text = (doc: Document, id: string): string => doc.getElementById(id)?.textContent ?? "";
/** The code elements in the element `id`, by their text. */
const codes = (doc: Document, id: string): string[] => [...(doc.getElementById(id)?.querySelectorAll("code") ?? [])].map((c) => c.textContent ?? "");

test("without the admin session, Settings says to sign in, or that no protection service is connected, in the page's words", async () => {
  const { doc, close } = await openPage("/settings", false);
  try {
    await until(() => text(doc, "settings-labels") !== "" && text(doc, "settings-prompt-kinds") !== "", "both blocks rendered");
    // The read gate (read-gate.ts, dashboard.md §6) runs before the route: a
    // signed-out read is asked to sign in first, whatever is behind it.
    assert.equal(text(doc, "settings-labels"), SIGN_IN, "the labels read is behind the read gate");
    assert.equal(text(doc, "settings-prompt-kinds"), SIGN_IN, "the prompt filters read is behind the admin session gate");
    for (const id of ["settings-labels", "settings-prompt-kinds"]) assert.deepEqual(codes(doc, id), ["mandu dashboard"], `${id}: the command is code`);
    assert.equal((doc.getElementById("prompt-exception-form") as HTMLElement).hidden, true);
    assert.doesNotMatch(text(doc, "page-settings"), DEVELOPER);
    assert.doesNotMatch(text(doc, "page-settings"), MARKED_COMMAND);
  } finally {
    close();
  }
});

test("without the admin session, the Rules page's file explorer, Suggested view and Describe say it in the page's words", async () => {
  const { w, doc, close } = await openPage("/rules", false);
  try {
    // A folder: a read behind the admin session gate.
    (doc.getElementById("rules-add") as HTMLElement).click();
    await until(() => !(doc.getElementById("files-note") as HTMLElement).hidden, "the folder note shows");
    assert.equal(text(doc, "files-note"), SIGN_IN);
    // The suggestions: a read behind the read gate (no protection service is
    // behind it either; signing in comes first).
    (doc.getElementById("suggest-open") as HTMLElement).click();
    await until(() => text(doc, "suggest-error") !== "", "the suggestions error shows");
    assert.equal(text(doc, "suggest-error"), SIGN_IN);
    // Describe what you want: a POST, refused by the global gate.
    (doc.getElementById("describe-text") as HTMLTextAreaElement).value = "Keep .env secret.";
    (doc.getElementById("describe-form") as HTMLFormElement).dispatchEvent(new w.Event("submit", { cancelable: true }));
    await until(() => text(doc, "describe-result") !== "", "the refusal shows under the box");
    assert.equal(text(doc, "describe-result"), SIGN_IN);
    for (const id of ["files-note", "suggest-error", "describe-result"]) assert.deepEqual(codes(doc, id), ["mandu dashboard"], `${id}: the command is code`);
    assert.doesNotMatch(text(doc, "page-rules"), DEVELOPER);
    assert.doesNotMatch(text(doc, "page-rules"), MARKED_COMMAND);
  } finally {
    close();
  }
});

test("with the admin session, Settings no longer asks to sign in and still names no developer term", async () => {
  const { doc, close } = await openPage("/settings", true);
  try {
    await until(() => text(doc, "settings-labels") !== "" && text(doc, "settings-prompt-kinds") !== "", "both blocks rendered");
    assert.equal(text(doc, "settings-labels"), NOT_CONNECTED);
    assert.equal(text(doc, "settings-prompt-kinds"), NOT_CONNECTED, "past the gate, the route says it in its own words");
    assert.doesNotMatch(text(doc, "page-settings"), /Sign in first/);
    assert.doesNotMatch(text(doc, "page-settings"), DEVELOPER);
  } finally {
    close();
  }
});
