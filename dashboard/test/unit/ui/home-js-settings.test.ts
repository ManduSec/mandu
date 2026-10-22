/**
 * home-js-settings.test — Settings › Protection on the PRODUCT page
 * (public/js/home.js loadSettings, dashboard.md §4.25 Settings): the one
 * on/off (the confidentiality axis; the frozen integrity axis has no switch,
 * protection-modes.md §10), the cards and folds, and the service line from
 * GET /api/control/summary under it, in the SAME row (§4.25 *One Protection
 * row*): its button POSTs the path the server named, the helper note only
 * when the server sends one, and the fallbacks. The per-service rows live
 * only in the developer view. The line follows the service on the page's
 * poll while Settings is open, drawn again only when the summary changed
 * (§4.25 *The service row follows the service*).
 *
 * The on/off's dot and sentence say what RUNS (Home's `protection`), its name
 * what is SAVED (config/axes), for every pair of the two, and follow Home's
 * poll (§4.25 "The on/off says what runs").
 *
 * Drives home.js in jsdom over the shared fetch stub (home-js-fixtures.ts).
 * Axes: the on/off tests post `secrets` / `off` (and the frozen modes only
 * under the opt-in) to a stubbed route; nothing is enforced here. Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { load, tick, home, PUB, CLOCK } from "./home-js-fixtures.js";
import { ADMIN_SESSION_REQUIRED } from "../../../src/server.js";
import { ADOPTED_SENTENCE } from "../../../src/view-model/service-summary.js";

const URL = "http://127.0.0.1:4500/mandu/settings";
const RESTART_Q = "Restart Mandu? Agents you are running with mandu right now are blocked until it is back, usually a few seconds.";
const summary = (over: Record<string, unknown> = {}) => ({
  summary: {
    available: true, state: "running", name: "Running",
    sentence: "",
    since: Date.now() - 5 * 60_000, action: { label: "Restart", path: "control/arbiter/restart", confirm: RESTART_Q }, helperNote: null,
    ...over,
  },
});
const host = (doc: any) => doc.getElementById("settings-services");
const STOPPED = { state: "stopped", name: "Stopped", since: null, sentence: "It starts again by itself when you next start an agent with mandu.", action: { label: "Start", path: "control/arbiter/start", confirm: null } };
/** The admin gate's own 403 (server.ts), as every control POST answers it signed out. */
const SIGNED_OUT = { status: 403, body: { error: ADMIN_SESSION_REQUIRED } };
const SIGN_IN = "Sign in first: reload this page and sign in with your dashboard account (if there isn't one yet, run mandu dashboard --set-password in your own terminal).";
/** The row's answer line, or null. */
const answer = (doc: any) => doc.querySelector("#settings-service-main .ask-error");

test("running: the on/off and the service share one row, one dot; its words and Restart; no per-service rows", async () => {
  const { doc } = load({ url: URL, routes: { "GET control/summary": summary() } });
  await tick();
  const rows = doc.querySelectorAll("#settings-protection-block .row");
  assert.equal(rows.length, 1, "one row: the on/off and the service (they used to read On, then Running, as two)");
  const row = doc.getElementById("settings-protect-row");
  assert.ok(row.contains(doc.getElementById("settings-service-main")), "the service line is inside the on/off's row");
  assert.equal(row.querySelector(".name").textContent, "On");
  assert.equal(row.querySelectorAll(".dot").length, 1, "one dot");
  assert.ok(row.querySelector(".name .dot.ok"), "green: on, saved and running");
  const line = doc.getElementById("settings-service-main");
  assert.equal(line.querySelector(".service-state").textContent, "Running");
  assert.match(line.textContent, new RegExp(`^Running\\. Started ${CLOCK} · 5 minutes ago\\. Restart$`));
  assert.doesNotMatch(row.textContent, /protecting/, "the line never says protecting: the on/off says what is on");
  assert.equal(line.querySelector("button").textContent, "Restart");
  assert.equal(doc.getElementById("settings-service-helper"), null);
  assert.doesNotMatch(host(doc).textContent, /proxy|arbiter|127\.0\.0\.1/i, "no service ids or addresses");
});

test("off and running: the dot is amber, the line still says Running", async () => {
  const { doc } = load({ url: URL, routes: {
    "GET control/summary": summary(),
    "GET config/axes": { ok: true, effective: { integrity: false, confidentiality: false }, effectiveMode: "off" },
    "GET home": home({ protection: { level: "off", configured: "off", connected: true } }),
  } });
  await tick();
  assert.equal(doc.querySelector("#settings-protect-row .name").textContent, "Off");
  assert.ok(doc.querySelector("#settings-protect-row .name .dot.warn"), "amber");
  assert.equal(doc.querySelector("#settings-service-main .service-state").textContent, "Running");
});

test("the button POSTs the server's path with the control header, then repaints", async () => {
  let n = 0;
  const { doc, calls } = load({ url: URL, routes: {
    "GET control/summary": () => (n++ === 0
      ? summary({ state: "stopped", name: "Stopped", since: null, sentence: "It starts again by itself when you next start an agent with mandu.", action: { label: "Start", path: "control/arbiter/start", confirm: null } })
      : summary()),
    "POST control/arbiter/start": { service: { state: "running" } },
  } });
  await tick();
  const btn = doc.querySelector("#settings-service-main button");
  assert.equal(btn.textContent, "Start");
  assert.ok(!doc.querySelector("#settings-protect-row .name .dot.ok"), "no green dot while stopped");
  btn.click();
  await tick();
  assert.equal(doc.getElementById("settings-service-confirm"), null, "Start asks nothing");
  const post = calls.find((c) => c.method === "POST");
  assert.ok(post, "a POST was sent");
  assert.match(post!.url, /\/api\/control\/arbiter\/start$/);
  assert.equal(post!.headers["X-Mandu-Control"], "1");
  assert.equal(doc.querySelector("#settings-service-main .service-state").textContent, "Running", "repainted from a fresh summary");
});

test("Restart asks first: nothing is sent until 'Restart now'; Cancel sends nothing and gives the button back", async () => {
  const { doc, calls } = load({ url: URL, routes: {
    "GET control/summary": summary(),
    "POST control/arbiter/restart": { service: { state: "running" } },
  } });
  await tick();
  const posts = () => calls.filter((c) => c.method === "POST");
  const btn = doc.querySelector("#settings-service-main button");

  btn.click();
  await tick();
  const ask = doc.getElementById("settings-service-confirm");
  assert.ok(ask, "the question appears");
  assert.equal(ask.getAttribute("role"), "alert");
  assert.equal(ask.querySelector("p").textContent, RESTART_Q);
  assert.equal(btn.disabled, true, "the row's button waits for the answer");
  assert.equal(posts().length, 0, "nothing sent on the first press");
  assert.equal(ask.previousElementSibling, doc.getElementById("settings-protect-row"), "right under the row");

  const [cancel, go] = [...ask.querySelectorAll("button")];
  assert.equal(cancel.textContent, "Cancel");
  assert.equal(go.textContent, "Restart now");
  cancel.click();
  await tick();
  assert.equal(doc.getElementById("settings-service-confirm"), null);
  assert.equal(btn.disabled, false);
  assert.equal(posts().length, 0, "Cancel sends nothing");

  btn.click();
  await tick();
  doc.querySelector("#settings-service-confirm button.primary").click();
  await tick();
  assert.equal(posts().length, 1, "one restart");
  assert.match(posts()[0]!.url, /\/api\/control\/arbiter\/restart$/);
  assert.equal(posts()[0]!.headers["X-Mandu-Control"], "1");
  assert.equal(doc.getElementById("settings-service-confirm"), null, "repainted: the question is gone");
});

test("signed out, Start says how to sign in on its row, the command as code; the row still reads Stopped", async () => {
  const { doc, calls } = load({ url: URL, routes: { "GET control/summary": summary(STOPPED), "POST control/arbiter/start": SIGNED_OUT } });
  await tick();
  assert.equal(answer(doc), null, "no line before a click");
  doc.querySelector("#settings-service-main button").click();
  await tick();
  const line = answer(doc);
  assert.ok(line, "the click is answered on the row (it used to repaint the row and say nothing)");
  assert.equal(line.textContent, SIGN_IN);
  assert.equal(line.querySelector("code")?.textContent, "mandu dashboard --set-password", "the command reads as code");
  assert.doesNotMatch(host(doc).textContent, /admin session|DASHBOARD_PASSWORD|`/, "never the server's developer text");
  assert.equal(doc.querySelector("#settings-service-main .service-state").textContent, "Stopped");
  assert.equal(doc.querySelector("#settings-service-main button").disabled, false, "the button is back");
  assert.equal(calls.filter((c) => c.method === "POST").length, 1);
});

test("signed out, Restart now: the question goes, and the row says how to sign in instead of reading as restarted", async () => {
  const { doc } = load({ url: URL, routes: { "GET control/summary": summary(), "POST control/arbiter/restart": SIGNED_OUT } });
  await tick();
  doc.querySelector("#settings-service-main button").click();
  await tick();
  doc.querySelector("#settings-service-confirm button.primary").click();
  await tick();
  assert.equal(doc.getElementById("settings-service-confirm"), null, "the question is gone");
  assert.equal(answer(doc)?.textContent, SIGN_IN);
  const btn = doc.querySelector("#settings-service-main button");
  assert.equal(btn.textContent, "Restart");
  assert.equal(btn.disabled, false);
});

test("a start that fails: the row is drawn again from a fresh summary, then says the server's words; no body: the page's own", async () => {
  let n = 0;
  const failed = "exited with code 1 before it was ready";
  const { doc } = load({ url: URL, routes: {
    "GET control/summary": () => (n++ === 0 ? summary(STOPPED) : summary({ ...STOPPED, state: "crashed", name: "Stopped unexpectedly", sentence: "Press Start, or start an agent with mandu." })),
    "POST control/arbiter/start": { status: 503, body: { error: failed, service: "arbiter" } },
  } });
  await tick();
  doc.querySelector("#settings-service-main button").click();
  await tick();
  assert.equal(doc.querySelector("#settings-service-main .service-state").textContent, "Stopped unexpectedly", "repainted first");
  assert.equal(answer(doc)?.textContent, failed, "then the answer, on the row drawn now");
  assert.equal(host(doc).querySelectorAll(".ask-error").length, 1);

  const bare = load({ url: URL, routes: { "GET control/summary": summary(STOPPED), "POST control/arbiter/start": { status: 500, body: null } } });
  await tick();
  bare.doc.querySelector("#settings-service-main button").click();
  await tick();
  assert.equal(answer(bare.doc)?.textContent, "could not start the protection service (500)");
});

test("no answer at all: the hero's words on the row (§4.25 *A click with no answer says so*)", async () => {
  const { doc } = load({ url: URL, routes: { "GET control/summary": summary(STOPPED), "POST control/arbiter/start": () => { throw new TypeError("fetch failed"); } } });
  await tick();
  doc.querySelector("#settings-service-main button").click();
  await tick();
  assert.equal(answer(doc)?.textContent, "The dashboard could not reach its own server. Refresh in a moment.");
  assert.equal(doc.querySelector("#settings-service-main button").disabled, false, "the button works again");
});

test("while its request is out the button waits (one Start, not two); the answer repaints the row", async () => {
  let release: (v: unknown) => void = () => {};
  let n = 0;
  const { doc, calls } = load({ url: URL, routes: {
    "GET control/summary": () => (n++ === 0 ? summary(STOPPED) : summary()),
    "POST control/arbiter/start": () => new Promise((r) => { release = r; }),
  } });
  await tick();
  const btn = doc.querySelector("#settings-service-main button");
  btn.click();
  await tick();
  assert.equal(btn.disabled, true, "disabled while the start is out");
  btn.click();
  await tick();
  assert.equal(calls.filter((c) => c.method === "POST").length, 1, "a second press sends nothing");
  release({ service: { state: "running" } });
  await tick();
  assert.equal(doc.querySelector("#settings-service-main .service-state").textContent, "Running");
  assert.equal(answer(doc), null, "a start that worked says nothing more");
});

test("adopted (already running when the dashboard started): the row says why and offers no Restart", async () => {
  const { doc } = load({ url: URL, routes: { "GET control/summary": summary({ sentence: ADOPTED_SENTENCE, since: null, action: null }) } });
  await tick();
  const row = doc.getElementById("settings-service-main");
  assert.equal(row.querySelector(".service-state").textContent, "Running");
  assert.equal(row.textContent, `Running. ${ADOPTED_SENTENCE}`, "no \"Started …\": the time it was found is not when it started");
  assert.equal(row.querySelector("button"), null, "no button");
});

// ── the row follows the service (§4.25 *The service row follows the service*) ──
const CRASHED = { ...STOPPED, state: "crashed", name: "Stopped unexpectedly", sentence: "Press Start, or start an agent with mandu." };
const STARTING = { state: "starting", name: "Starting", sentence: "", since: null, action: null };
/** The page's poll, as a return to the tab runs it (setInterval is stubbed). */
const pollOf = (doc: any, window: any) => async () => { doc.dispatchEvent(new window.Event("visibilitychange")); await tick(); };
const nameOf = (doc: any) => doc.querySelector("#settings-service-main .service-state")?.textContent ?? null;
const buttonOf = (doc: any) => doc.querySelector("#settings-service-main button")?.textContent ?? null;
const summaryReads = (calls: any[]) => calls.filter((c) => c.method === "GET" && c.url.endsWith("/api/control/summary")).length;

test("the poll: the row follows the service while Settings is open (a crash, a start under way, a start made elsewhere), with no click", async () => {
  let current: unknown = summary();
  const { doc, window, calls } = load({ url: URL, routes: { "GET control/summary": () => current } });
  await tick();
  const poll = pollOf(doc, window);
  assert.deepEqual([nameOf(doc), buttonOf(doc)], ["Running", "Restart"]);
  current = summary(CRASHED);
  await poll();
  assert.deepEqual([nameOf(doc), buttonOf(doc)], ["Stopped unexpectedly", "Start"], "a crash reads as one (it used to say Running until you left Settings)");
  assert.ok(doc.querySelector("#settings-protect-row .name .dot.bad"), "red dot");
  current = summary(STARTING);
  await poll();
  assert.deepEqual([nameOf(doc), buttonOf(doc)], ["Starting", null], "a start made elsewhere: no Start on a start under way");
  assert.equal(doc.getElementById("settings-service-main").textContent, "Starting.");
  assert.ok(doc.querySelector("#settings-protect-row .name .dot.warn"), "amber dot");
  current = summary();
  await poll();
  assert.deepEqual([nameOf(doc), buttonOf(doc)], ["Running", "Restart"], "running once it is up");
  assert.match(doc.getElementById("settings-service-main").textContent, new RegExp(`^Running\\. Started ${CLOCK}`));
  assert.ok(doc.querySelector("#settings-protect-row .name .dot.ok"), "green again");
  assert.equal(doc.querySelectorAll("#settings-protection-block .row").length, 1, "still one row");
  assert.equal(calls.filter((c) => c.method === "POST").length, 0, "nothing was sent");
});

test("the poll: a summary that did not change draws nothing, so the answer to the button stays; a change draws the row again", async () => {
  let current: unknown = summary(STOPPED);
  const { doc, window } = load({ url: URL, routes: { "GET control/summary": () => current, "POST control/arbiter/start": SIGNED_OUT } });
  await tick();
  const poll = pollOf(doc, window);
  doc.querySelector("#settings-service-main button").click();
  await tick();
  assert.equal(answer(doc)?.textContent, SIGN_IN);
  const drawn = doc.getElementById("settings-service-main");
  await poll();
  await poll();
  assert.equal(doc.getElementById("settings-service-main"), drawn, "the same row, not drawn again");
  assert.equal(answer(doc)?.textContent, SIGN_IN, "the answer stays");
  current = summary();
  await poll();
  assert.equal(nameOf(doc), "Running", "an agent started it: the row says so");
  assert.equal(answer(doc), null, "the answer to a Start of a stopped service goes with that row");
});

test("the poll: never under the Restart question, nor while the row's own request is out (its answer draws the row)", async () => {
  let current: unknown = summary();
  let release: (v: unknown) => void = () => {};
  const { doc, window, calls } = load({ url: URL, routes: {
    "GET control/summary": () => current,
    "POST control/arbiter/start": () => new Promise((r) => { release = r; }),
  } });
  await tick();
  const poll = pollOf(doc, window);
  doc.querySelector("#settings-service-main button").click();
  await tick();
  assert.ok(doc.getElementById("settings-service-confirm"), "the Restart question is open");
  const reads = summaryReads(calls);
  current = summary(CRASHED);
  await poll();
  assert.ok(doc.getElementById("settings-service-confirm"), "the question stays");
  assert.equal(nameOf(doc), "Running", "the row under it is not drawn again");
  assert.equal(summaryReads(calls), reads, "not even read while the question is open");
  doc.querySelector("#settings-service-confirm button").click(); // Cancel
  await poll();
  assert.deepEqual([nameOf(doc), buttonOf(doc)], ["Stopped unexpectedly", "Start"], "once answered, the next poll follows");

  const btn = doc.querySelector("#settings-service-main button");
  btn.click();
  await tick();
  assert.equal(btn.disabled, true, "the Start is out");
  current = summary(STARTING);
  await poll();
  assert.equal(doc.querySelector("#settings-service-main button"), btn, "not drawn again while its request is out");
  assert.equal(btn.disabled, true);
  current = summary();
  release({ service: { state: "running" } });
  await tick();
  assert.deepEqual([nameOf(doc), buttonOf(doc)], ["Running", "Restart"], "the answer draws the row");
  assert.equal(doc.querySelectorAll("#settings-protection-block .row").length, 1);
});

test("the poll: no answer keeps the row as drawn; Home failing does not stop the row following", async () => {
  let current: unknown = summary();
  let homeAnswer: unknown = home();
  let gone = false;
  const { doc, window } = load({ url: URL, routes: {
    "GET control/summary": () => { if (gone) throw new TypeError("fetch failed"); return current; },
    "GET home": () => homeAnswer,
  } });
  await tick();
  const poll = pollOf(doc, window);
  const drawn = doc.getElementById("settings-service-main");
  gone = true;
  await poll();
  gone = false;
  for (const refused of [{ status: 502, body: { error: "bad gateway" } }, { status: 404, body: { error: "control plane disabled" } }, { summary: null }]) {
    current = refused;
    await poll();
  }
  assert.equal(doc.getElementById("settings-service-main"), drawn, "no answer: the row stays as drawn, never the no-controls fallback");
  assert.deepEqual([nameOf(doc), buttonOf(doc)], ["Running", "Restart"]);
  homeAnswer = { status: 503, body: { error: "arbiter unreachable", unreachable: true } };
  current = summary(CRASHED);
  await poll();
  assert.equal(nameOf(doc), "Stopped unexpectedly", "the service stopped: Home cannot check, and the row says why");
});

test("the poll reads the service row only on Settings", async () => {
  const { doc, window, calls } = load({ url: "http://127.0.0.1:4500/mandu/", routes: { "GET control/summary": summary() } });
  await tick();
  await pollOf(doc, window)();
  await pollOf(doc, window)();
  assert.equal(summaryReads(calls), 0, "Home's poll does not read it");
});

test("a row's right-column button keeps its own width (a stretched one, label pushed right, read as a field)", () => {
  const css = readFileSync(join(PUB, "app.css"), "utf8");
  assert.match(css, /\.row > \.btn\.right \{ justify-self: end; text-align: center; \}/);
  assert.match(css, /@media \(max-width: 760px\) \{[^@]*\.row > \.btn\.right \{ justify-self: start; \}/, "phone width: under the text, at the start");
});

test("a crashed helper: the note under the row; crashed main: red dot", async () => {
  const note = "A helper the dashboard runs for the developer view stopped unexpectedly. Your agents are not affected. The developer view has the details.";
  const { doc } = load({ url: URL, routes: { "GET control/summary": summary({ state: "crashed", name: "Stopped unexpectedly", since: null, helperNote: note, action: { label: "Start", path: "control/arbiter/start" } }) } });
  await tick();
  assert.equal(doc.getElementById("settings-service-helper").textContent, note);
  assert.ok(doc.querySelector("#settings-protect-row .name .dot.bad"));
});

test("fallbacks: no service controls (404 / null) and a supervisor without the main service", async () => {
  for (const r of [{ status: 404, body: { error: "control plane disabled" } }, { summary: null }]) {
    const { doc } = load({ url: URL, routes: { "GET control/summary": r } });
    await tick();
    assert.match(host(doc).textContent, /started without the service controls/);
    assert.equal(doc.getElementById("settings-service-main"), null);
  }
  const { doc } = load({ url: URL, routes: { "GET control/summary": summary({ available: false, state: null, name: "", action: null, sentence: "This dashboard does not run the protection service. The developer view lists what it does run." }) } });
  await tick();
  assert.match(host(doc).textContent, /does not run the protection service/);
  assert.equal(doc.getElementById("settings-service-main"), null);
});

// ── the one on/off (the confidentiality axis) ────────────────────────────────
const axes = (integrity: boolean, confidentiality: boolean, over: Record<string, unknown> = {}) => ({
  ok: true, effective: { integrity, confidentiality },
  effectiveMode: confidentiality ? (integrity ? "full" : "secrets") : (integrity ? "injection" : "off"), ...over,
});
const sw = (doc: any) => doc.getElementById("switch-protection");
const posted = (calls: any[]) => calls.filter((c) => c.method === "POST" && c.url.endsWith("/config/axes")).map((c) => c.body);

test("protection: one switch, its state in words; off asks for a typed OFF and posts off", async () => {
  const { doc, calls, window } = load({ url: URL, routes: {
    "GET control/summary": summary(), "GET config/axes": axes(false, true), "POST config/axes": axes(false, false),
  } });
  await tick();
  assert.equal(doc.querySelectorAll("#page-settings [role=switch]").length, 1, "one switch, no masking switch");
  assert.equal(sw(doc).getAttribute("aria-checked"), "true");
  assert.equal(sw(doc).getAttribute("aria-label"), "Protection");
  assert.equal(doc.querySelector("#settings-protect-row .name").textContent, "On");
  assert.equal(doc.getElementById("settings-protect-text").textContent, "Keys and secret files leave this computer only where a rule or your OK allows.");
  window.prompt = () => "no";
  sw(doc).click();
  await tick();
  assert.deepEqual(posted(calls), [], "anything but OFF keeps it on");
  window.prompt = () => "OFF";
  sw(doc).click();
  await tick();
  assert.deepEqual(posted(calls), [{ mode: "off" }]);
  assert.equal(sw(doc).getAttribute("aria-checked"), "false");
  assert.equal(doc.querySelector("#settings-protect-row .name").textContent, "Off");
  // The flip is saved for the next start; the protection service (the
  // fixture's, running Full) still guards secrets until it restarts.
  assert.equal(doc.getElementById("settings-protect-text").textContent,
    "Still on until the protection service restarts: keys and secret files leave this computer only where a rule or your OK allows.");
  assert.equal(doc.getElementById("settings-protect-note").textContent, "Saved. It applies when the protection service next starts.");
});

test("protection: turning it on asks nothing and posts secrets; a stale masking axis is turned off with it", async () => {
  for (const integrity of [false, true]) {
    const { doc, calls } = load({ url: URL, routes: {
      "GET control/summary": summary(), "GET config/axes": axes(integrity, false, { integrityAllowed: false }), "POST config/axes": axes(false, true),
    } });
    await tick();
    sw(doc).click();
    await tick();
    assert.deepEqual(posted(calls), [{ mode: "secrets" }], `integrity was ${integrity}: never kept without the opt-in`);
    assert.equal(sw(doc).getAttribute("aria-checked"), "true");
  }
});

test("protection: under the opt-in a flip keeps masking as it is (never silently downgraded)", async () => {
  const { doc, calls, window } = load({ url: URL, routes: {
    "GET control/summary": summary(), "GET config/axes": axes(true, true, { integrityAllowed: true }), "POST config/axes": axes(true, false, { integrityAllowed: true }),
  } });
  await tick();
  window.prompt = () => "OFF";
  sw(doc).click();
  await tick();
  assert.deepEqual(posted(calls), [{ mode: "injection" }]);
});

test("protection: unreadable settings disable the switch; a refusal is said in the note", async () => {
  const down = load({ url: URL, routes: { "GET control/summary": summary(), "GET config/axes": { status: 503, body: { error: "down" } } } });
  await tick();
  assert.equal(sw(down.doc).disabled, true);
  assert.equal(down.doc.getElementById("settings-protect-text").textContent, "The protection settings could not be read. The dashboard server answered with an error (503). Refresh in a moment.");
  const refused = load({ url: URL, routes: {
    "GET control/summary": summary(), "GET config/axes": axes(false, false), "POST config/axes": { status: 403, body: { error: "sign in first" } },
  } });
  await tick();
  sw(refused.doc).click();
  await tick();
  assert.match(refused.doc.getElementById("settings-protect-note").textContent, /sign in/i);
  assert.equal(sw(refused.doc).getAttribute("aria-checked"), "false", "nothing changed");
});

// ── what runs, beside what is saved (§4.25 "The on/off says what runs") ─────
/** Home's answer with the protection service running `level` (or none). */
const runs = (level: string, connected = true) => home({ protection: { level, configured: "secrets", connected } });
const row = (doc: any) => ({
  name: doc.querySelector("#settings-protect-row .name").textContent,
  dot: doc.querySelector("#settings-protect-row .name .dot").className,
  text: doc.getElementById("settings-protect-text").textContent,
  checked: sw(doc).getAttribute("aria-checked"),
});
const ON_WORDS = "Keys and secret files leave this computer only where a rule or your OK allows.";
const OFF_WORDS = "Mandu only watches. Your secrets are not masked, and nothing is stopped.";
const UNREACHABLE = "The protection service is not reachable, so Mandu cannot say what is on now.";

test("protection: before the setting is read the row claims nothing (no On, no promise), then says what runs", async () => {
  let answer: (v: unknown) => void = () => {};
  const late = new Promise((r) => { answer = r; });
  const { doc } = load({ url: URL, routes: { "GET control/summary": summary(), "GET config/axes": () => late, "GET home": runs("secrets") } });
  await tick();
  assert.equal(doc.getElementById("settings-protect-text").textContent, "Checking…", "the served first paint, unchanged until the setting is read");
  assert.equal(doc.querySelector("#settings-protect-row .name").textContent, "Protection");
  assert.equal(sw(doc).disabled, true);
  assert.equal(sw(doc).getAttribute("aria-checked"), "false");
  answer(axes(false, true));
  await tick();
  assert.equal(doc.getElementById("settings-protect-text").textContent, ON_WORDS);
});

test("protection: on and running, the row promises no OK that a rule skips (Home's words, §4.25d)", async () => {
  const { doc } = load({ url: URL, routes: { "GET control/summary": summary(), "GET config/axes": axes(false, true), "GET home": runs("secrets") } });
  await tick();
  assert.equal(doc.getElementById("settings-protect-text").textContent,
    "Keys and secret files leave this computer only where a rule or your OK allows.");
  assert.doesNotMatch(doc.getElementById("page-settings").textContent, /not sent anywhere without your OK|cannot leave/);
});

test("protection: the name is what is saved, the dot and the sentence what runs now, for every pair", async () => {
  const cases: [string, boolean, unknown, { name: string; dot: string; text: string }][] = [
    ["on, running", true, runs("secrets"), { name: "On", dot: "dot ok", text: ON_WORDS }],
    ["on, running Full", true, runs("full"), { name: "On", dot: "dot ok", text: ON_WORDS }],
    ["off, off running", false, runs("off"), { name: "Off", dot: "dot warn", text: OFF_WORDS }],
    ["on, off still running", true, runs("off"),
      { name: "On", dot: "dot warn", text: "Still off until the protection service restarts: Mandu only watches, and your secrets are not masked." }],
    ["off, on still running", false, runs("secrets"),
      { name: "Off", dot: "dot warn", text: "Still on until the protection service restarts: keys and secret files leave this computer only where a rule or your OK allows." }],
    ["on, no protection service", true, runs("unknown", false), { name: "On", dot: "dot ", text: `Saved as on. ${UNREACHABLE}` }],
    ["off, no protection service", false, runs("unknown", false), { name: "Off", dot: "dot warn", text: `Saved as off. ${UNREACHABLE}` }],
    ["on, a service that reports no posture", true, runs("unknown"),
      { name: "On", dot: "dot ", text: "Saved as on. Mandu cannot say what the protection service runs now." }],
    ["on, Home unreadable", true, { status: 503, body: { error: "down" } }, { name: "On", dot: "dot ", text: `Saved as on. ${UNREACHABLE}` }],
  ];
  for (const [what, savedOn, homeAnswer, want] of cases) {
    const { doc } = load({ url: URL, routes: { "GET control/summary": summary(), "GET config/axes": axes(false, savedOn), "GET home": homeAnswer } });
    await tick();
    const got = row(doc);
    assert.deepEqual({ name: got.name, dot: got.dot, text: got.text }, want, what);
    assert.equal(got.checked, savedOn ? "true" : "false", `${what}: the switch is the saved setting`);
    assert.equal(sw(doc).disabled, false, `${what}: the switch still works`);
  }
});

test("protection: a direct visit whose Home answers after the setting is repainted then (the first paint never keeps the saved state as fact)", async () => {
  let answer: (v: unknown) => void = () => {};
  const late = new Promise((r) => { answer = r; });
  const { doc } = load({ url: URL, routes: {
    "GET control/summary": summary(), "GET config/axes": axes(false, false), "GET home": () => late,
  } });
  await tick();
  assert.equal(row(doc).text, `Saved as off. ${UNREACHABLE}`, "before Home answers, nothing is known of what runs");
  answer(runs("secrets"));
  await tick();
  assert.equal(row(doc).text, "Still on until the protection service restarts: keys and secret files leave this computer only where a rule or your OK allows.");
  assert.equal(doc.getElementById("settings-protect-note").textContent, "Saved. It applies when the protection service next starts.");
});

test("protection: Home's poll repaints the row when what runs changes, and leaves a refusal alone when it does not", async () => {
  let current: unknown = runs("secrets");
  const { doc, window } = load({ url: URL, routes: {
    "GET control/summary": summary(), "GET config/axes": axes(false, false), "GET home": () => current,
    "POST config/axes": { status: 403, body: { error: "sign in first" } },
  } });
  await tick();
  assert.match(row(doc).text, /^Still on until/);
  const poll = async () => { doc.dispatchEvent(new window.Event("visibilitychange")); await tick(); };
  // The switch is refused: the note says so, and a poll that finds the same
  // service running keeps it.
  sw(doc).click();
  await tick();
  assert.match(doc.getElementById("settings-protect-note").textContent, /sign in/i);
  await poll();
  assert.match(doc.getElementById("settings-protect-note").textContent, /sign in/i, "an unchanged poll repaints nothing");
  // The service restarted with the saved setting: the row says so by itself.
  current = runs("off");
  await poll();
  assert.deepEqual({ dot: row(doc).dot, text: row(doc).text }, { dot: "dot warn", text: OFF_WORDS });
  assert.equal(doc.getElementById("settings-protect-note").textContent, "A change applies when the protection service next starts.");
});

// ── the switch holds while its change is on its way (§4.25) ──────────────────
/** An answer the test sends when it likes: the POST stays out until then. */
function heldAnswer() {
  let send!: (v: unknown) => void;
  const answer = new Promise((r) => { send = r; });
  return { answer, send };
}
const held = (doc: any) => ({
  hold: sw(doc).getAttribute("aria-disabled"),
  disabled: sw(doc).disabled,
  focused: doc.activeElement === sw(doc),
  checked: sw(doc).getAttribute("aria-checked"),
});

test("protection: turning it off holds the switch until the answer: a second press asks nothing and posts nothing, the focus stays", async () => {
  const flip = heldAnswer();
  let current: unknown = runs("secrets");
  let posts = 0;
  const { doc, calls, window } = load({ url: URL, routes: {
    "GET control/summary": summary(), "GET config/axes": axes(false, true), "GET home": () => current,
    // The first change is held; any later one is answered at once.
    "POST config/axes": () => (++posts === 1 ? flip.answer : axes(false, true)),
  } });
  await tick();
  let asked = 0;
  window.prompt = () => { asked++; return "OFF"; };
  sw(doc).focus();
  sw(doc).click();
  await tick();
  assert.deepEqual(posted(calls), [{ mode: "off" }]);
  assert.equal(asked, 1);
  assert.deepEqual(held(doc), { hold: "true", disabled: false, focused: true, checked: "true" },
    "held, off-limits to a screen reader, the focus kept (disabled would drop it), still showing what is saved");
  // A second press while it is on its way: no second question, no second POST.
  sw(doc).click();
  sw(doc).click();
  await tick();
  assert.equal(asked, 1, "the typed OFF is not asked again");
  assert.deepEqual(posted(calls), [{ mode: "off" }], "nothing posted again");
  // Home's poll finds what runs changed and redraws the row: still held.
  current = runs("off");
  doc.dispatchEvent(new window.Event("visibilitychange"));
  await tick();
  assert.equal(row(doc).text, "Still off until the protection service restarts: Mandu only watches, and your secrets are not masked.", "the row was drawn again");
  assert.equal(held(doc).hold, "true", "a redraw keeps the hold");
  sw(doc).click();
  await tick();
  assert.deepEqual(posted(calls), [{ mode: "off" }], "nothing posted after the redraw either");
  // The answer: drawn, and the switch is live again with the focus on it.
  flip.send(axes(false, false));
  await tick();
  assert.deepEqual(held(doc), { hold: null, disabled: false, focused: true, checked: "false" });
  assert.equal(row(doc).name, "Off");
  sw(doc).click();
  await tick();
  assert.deepEqual(posted(calls), [{ mode: "off" }, { mode: "secrets" }], "the next press is a change of its own");
  assert.equal(asked, 1, "turning it on asks nothing");
  assert.equal(held(doc).checked, "true");
});

test("protection: turning it on, a double press posts once", async () => {
  const flip = heldAnswer();
  const { doc, calls } = load({ url: URL, routes: {
    "GET control/summary": summary(), "GET config/axes": axes(false, false), "POST config/axes": () => flip.answer,
  } });
  await tick();
  sw(doc).focus();
  sw(doc).click();
  sw(doc).click();
  await tick();
  assert.deepEqual(posted(calls), [{ mode: "secrets" }]);
  assert.deepEqual(held(doc), { hold: "true", disabled: false, focused: true, checked: "false" });
  flip.send(axes(false, true));
  await tick();
  assert.deepEqual(held(doc), { hold: null, disabled: false, focused: true, checked: "true" });
  assert.deepEqual(posted(calls), [{ mode: "secrets" }]);
});

test("protection: a refusal, or no answer, ends the hold: the refusal is said and the next press posts again", async () => {
  const noAnswer = () => { throw new TypeError("Failed to fetch"); };
  for (const [what, answer, said] of [
    ["refused", { status: 403, body: { error: "sign in first" } }, /sign in/i],
    ["no answer", noAnswer, /could not reach its own server/],
  ] as const) {
    const { doc, calls, window } = load({ url: URL, routes: {
      "GET control/summary": summary(), "GET config/axes": axes(false, true), "POST config/axes": answer,
    } });
    await tick();
    let asked = 0;
    window.prompt = () => { asked++; return "OFF"; };
    sw(doc).focus();
    sw(doc).click();
    await tick();
    assert.match(doc.getElementById("settings-protect-note").textContent, said, what);
    assert.deepEqual(held(doc), { hold: null, disabled: false, focused: true, checked: "true" }, `${what}: live again, nothing changed`);
    sw(doc).click();
    await tick();
    assert.equal(asked, 2, `${what}: a new press asks again`);
    assert.deepEqual(posted(calls), [{ mode: "off" }, { mode: "off" }], `${what}: and posts again`);
  }
});

test("protection: a press not confirmed with OFF holds nothing", async () => {
  const { doc, calls, window } = load({ url: URL, routes: {
    "GET control/summary": summary(), "GET config/axes": axes(false, true), "POST config/axes": axes(false, false),
  } });
  await tick();
  window.prompt = () => null;
  sw(doc).click();
  await tick();
  assert.deepEqual(posted(calls), []);
  assert.equal(held(doc).hold, null);
  window.prompt = () => "OFF";
  sw(doc).click();
  await tick();
  assert.deepEqual(posted(calls), [{ mode: "off" }]);
});

test("app.css: a held switch is drawn as the disabled one", () => {
  const css = readFileSync(join(PUB, "app.css"), "utf8");
  assert.match(css, /\.switch\[disabled\], \.switch\[aria-disabled="true"\] \{ opacity: 0\.5; cursor: default; \}/);
});

test("cards and folds: every Settings section is a card that says one line, the rest folded or behind a help", async () => {
  const { doc } = load({ url: URL, routes: { "GET control/summary": summary() } });
  await tick();
  const cards = [...doc.querySelectorAll("#page-settings > section.card")];
  assert.deepEqual(cards.map((c: any) => c.querySelector("h2").textContent),
    ["Protection", "Models", "Sensitivity labels", "Prompt filters", "Notifications", "Appearance", "Dashboard account", "About Mandu", "Developer view"]);
  for (const id of ["settings-prompt-about"]) assert.ok(doc.getElementById(id).closest("details.more"), `${id} is folded`);
  assert.equal(doc.querySelectorAll("#page-settings [data-help]").length, 0, "every data-help became a help button");
  const helps = [...doc.querySelectorAll("#model-form .help-btn")] as any[];
  assert.equal(helps.length, 3, "the model form's three long explanations are behind a ?");
  helps[0].click();
  assert.match(doc.getElementById(helps[0].getAttribute("aria-controls")).textContent, /^It runs on this computer/);
});

// ── Dashboard account (dashboard.md §6.z) ─────────────────────────────────────

test("dashboard account: Sign out shows only to a browser with a sign-in session; a changed account file is said on Home", async () => {
  const signedOut = load({ url: URL, routes: { "GET control/summary": summary(), "GET home": home({ signIn: { signOut: false, accountChangedAt: null } }) } });
  await tick();
  assert.equal(signedOut.doc.getElementById("settings-account-block").hidden, true, "no Sign out without a sign-in session");
  assert.equal(signedOut.doc.getElementById("home-account-changed").hidden, true);
  const none = load({ url: URL, routes: { "GET control/summary": summary(), "GET home": home({}) } });
  await tick();
  assert.equal(none.doc.getElementById("settings-account-block").hidden, true, "a home without signIn shows none");

  const at = "2026-10-22T09:30:00.000Z";
  const { doc } = load({ url: URL, routes: { "GET control/summary": summary(), "GET home": home({ signIn: { signOut: true, accountChangedAt: at } }) } });
  await tick();
  const card = doc.getElementById("settings-account-block");
  assert.equal(card.hidden, false);
  const form = doc.getElementById("settings-sign-out-form");
  assert.equal(form.getAttribute("method"), "POST");
  assert.equal(form.getAttribute("action"), "logout", "relative to the page's <base>, so it works under a base path");
  assert.equal(doc.getElementById("settings-sign-out").textContent, "Sign out");
  assert.match(card.querySelector("p.note").textContent, /mandu dashboard --set-password/);
  const notice = doc.getElementById("home-account-changed");
  assert.equal(notice.hidden, false);
  assert.match(doc.getElementById("account-changed-sentence").textContent, /^The dashboard account file changed at .+, so every browser was signed out then\.$/);
  assert.match(notice.textContent, /If you did not change it, something on this computer did/);
});

// ── About Mandu (dashboard.md §4.25 *About Mandu*) ──────────────────────────

const ABOUT = {
  version: "0.2.0-beta.7",
  guideUrl: "https://github.com/mandusec/mandu/blob/main/docs/usage.md",
  troubleshootingUrl: "https://github.com/mandusec/mandu/blob/main/docs/usage.md#troubleshooting",
  issuesUrl: "https://github.com/mandusec/mandu/issues",
};
const aboutRow = (doc: any) => doc.getElementById("settings-about-version");
const aboutLinks = (doc: any) => [...doc.querySelectorAll("#settings-about-links a")] as any[];

test("about: the card shows Mandu <version>, the doctor note and three links, each in a new tab with noopener noreferrer", async () => {
  const { doc } = load({ url: URL, routes: { "GET control/summary": summary(), "GET home": home({ about: ABOUT }) } });
  await tick();
  const card = doc.getElementById("settings-about-block");
  assert.equal(card.querySelector("h2").textContent, "About Mandu");
  assert.equal(card.querySelector(".row .name").textContent, "Version");
  assert.equal(aboutRow(doc).textContent, "Mandu 0.2.0-beta.7");
  assert.equal(card.querySelector("p.note").textContent, "To check this computer's setup, run mandu doctor in a terminal.");
  assert.equal(card.querySelector("p.note code").textContent, "mandu doctor");
  assert.equal(card.querySelector("p.note code").className, "code-whole", "a command is kept whole (§4.25u)");
  const links = aboutLinks(doc);
  assert.deepEqual(links.map((a) => [a.textContent, a.getAttribute("href")]), [
    ["Guide", ABOUT.guideUrl], ["Troubleshooting", ABOUT.troubleshootingUrl], ["Report a problem", ABOUT.issuesUrl],
  ]);
  for (const a of links) {
    assert.equal(a.getAttribute("target"), "_blank", a.textContent);
    assert.equal(a.getAttribute("rel"), "noopener noreferrer", a.textContent);
  }
  assert.equal(doc.getElementById("settings-about-links").textContent, "Guide · Troubleshooting · Report a problem");
  assert.equal(links[2].getAttribute("title"), "Say which version you run: Mandu 0.2.0-beta.7.");
  const report = doc.getElementById("settings-about-report");
  assert.equal(report.hidden, false);
  assert.equal(report.textContent, "When you report a problem, say which version you run: Mandu 0.2.0-beta.7.");
  // The card is the last product card, before the developer-only one (the
  // dashboard account's, shown only to a signed-in browser, comes before it).
  const cards = [...doc.querySelectorAll("#page-settings > section.card")] as any[];
  assert.equal(cards[cards.indexOf(card) - 1].id, "settings-account-block");
  assert.ok(cards[cards.indexOf(card) + 1].hasAttribute("data-dev-only"));
});

test("about: an unknown version says to run mandu --version, never an empty row or a bare unknown; the links stay", async () => {
  const { doc } = load({ url: URL, routes: { "GET control/summary": summary(), "GET home": home({ about: { ...ABOUT, version: "unknown" } }) } });
  await tick();
  assert.equal(aboutRow(doc).textContent, "Not known. Run mandu --version in a terminal.");
  assert.equal(aboutRow(doc).querySelector("code").textContent, "mandu --version");
  assert.equal(aboutRow(doc).querySelector("code").className, "code-whole", "kept whole (ownCode)");
  assert.equal(aboutLinks(doc).length, 3);
  assert.equal(aboutLinks(doc)[2].getAttribute("title"), null, "no version to name");
  assert.equal(doc.getElementById("settings-about-report").hidden, true);
});

test("about: before an answer it reads Checking…; a poll that fails first says how to find the version, and a later failure keeps what an answer drew", async () => {
  let release: (() => void) | null = null;
  const { doc, window } = load({ url: URL, routes: { "GET control/summary": summary() }, homeVm: home({ about: ABOUT }), before: (w) => {
    const real = w.fetch;
    w.fetch = (url: string, init?: unknown) => /\/api\/home$/.test(url)
      ? new Promise((r) => { release = () => r(real(url, init)); })
      : real(url, init);
  } });
  await tick();
  assert.equal(aboutRow(doc).textContent, "Checking…");
  assert.equal(doc.getElementById("settings-about-links").hidden, true, "no links before an answer");
  release!();
  await tick();
  assert.equal(aboutRow(doc).textContent, "Mandu 0.2.0-beta.7");
  // A later poll that fails keeps the card as drawn: the hero says it
  // could not check, the release stays.
  window.fetch = (url: string) => Promise.reject(new TypeError(`fetch failed: ${url}`));
  await pollOf(doc, window)();
  assert.equal(doc.getElementById("hero-headline").textContent, "Not connected.", "the poll failed");
  assert.equal(aboutRow(doc).textContent, "Mandu 0.2.0-beta.7");
  assert.equal(aboutLinks(doc).length, 3);
});

test("about: with no answer at all, the row never stays at Checking…", async () => {
  const { doc } = load({ url: URL, routes: { "GET control/summary": summary(), "GET home": { status: 500, body: {} } } });
  await tick();
  assert.equal(aboutRow(doc).textContent, "Not known. Run mandu --version in a terminal.");
  assert.equal(doc.getElementById("settings-about-links").hidden, true);
});

test("about: only an https address is drawn as a link", async () => {
  const { doc } = load({ url: URL, routes: { "GET control/summary": summary(), "GET home": home({ about: { ...ABOUT, guideUrl: "javascript:alert(1)", troubleshootingUrl: "http://x.example/" } }) } });
  await tick();
  assert.deepEqual(aboutLinks(doc).map((a) => a.textContent), ["Report a problem"]);
});

// ── About Mandu: a newer release (dashboard.md §4.25 *A newer release*) ──────

const UPDATE_AT = Date.now() - 3 * 3_600_000;
const NPM_LINE = "npm install -g @mandusec/mandu@0.2.0-beta.9";
const aboutWith = (update: unknown) => home({ about: { ...ABOUT, update } });
const checkLine = (doc: any) => doc.getElementById("settings-about-check");

test("about update: a newer release names itself and the command to install it, as code, and when Mandu checked", async () => {
  const { doc } = load({ url: URL, routes: { "GET control/summary": summary(), "GET home": aboutWith({ state: "newer", at: UPDATE_AT, newest: "0.2.0-beta.9", security: false, install: NPM_LINE }) } });
  await tick();
  assert.match(aboutRow(doc).textContent, new RegExp(`^Mandu 0\\.2\\.0-beta\\.7\\. Mandu 0\\.2\\.0-beta\\.9 is out\\. To update: ${NPM_LINE.replace(/[.@]/g, "\\$&")}, then start your agent again \\(checked ${CLOCK} · 3 hours ago\\)\\.$`));
  assert.equal(aboutRow(doc).querySelector("code").textContent, NPM_LINE);
  const up = aboutRow(doc).querySelector(".about-update");
  assert.equal(up.classList.contains("security"), false, "a plain update is not in the warn tint");
  assert.equal(up.querySelector("time.when").getAttribute("datetime"), new Date(UPDATE_AT).toISOString());
  assert.equal(checkLine(doc).hidden, true);
});

test("about update: with security fixes the row says update now, in the warn tint", async () => {
  const { doc } = load({ url: URL, routes: { "GET control/summary": summary(), "GET home": aboutWith({ state: "newer", at: UPDATE_AT, newest: "0.2.0-beta.9", security: true, install: NPM_LINE }) } });
  await tick();
  assert.match(aboutRow(doc).textContent, /^Mandu 0\.2\.0-beta\.7\. Mandu 0\.2\.0-beta\.9 is out with security fixes\. Update now: npm install/);
  const up = aboutRow(doc).querySelector(".about-update");
  assert.equal(up.classList.contains("security"), true);
  assert.equal(up.dataset.update, "security");
});

test("about update: the newest release says so; without a time it says no 'checked'", async () => {
  const { doc } = load({ url: URL, routes: { "GET control/summary": summary(), "GET home": aboutWith({ state: "current", at: UPDATE_AT }) } });
  await tick();
  assert.match(aboutRow(doc).textContent, new RegExp(`^Mandu 0\\.2\\.0-beta\\.7\\. This is the newest release \\(checked ${CLOCK} · 3 hours ago\\)\\.$`));
  assert.equal(checkLine(doc).hidden, true);
  const { doc: d2 } = load({ url: URL, routes: { "GET control/summary": summary(), "GET home": aboutWith({ state: "current", at: null }) } });
  await tick();
  assert.equal(aboutRow(d2).textContent, "Mandu 0.2.0-beta.7. This is the newest release.");
});

test("about update: no answer leaves the row as it was and adds when Mandu checks; nothing to compare adds nothing", async () => {
  const { doc } = load({ url: URL, routes: { "GET control/summary": summary(), "GET home": aboutWith({ state: "unknown" }) } });
  await tick();
  assert.equal(aboutRow(doc).textContent, "Mandu 0.2.0-beta.7");
  assert.equal(checkLine(doc).hidden, false);
  assert.equal(checkLine(doc).textContent, "Mandu checks for a newer release when you start an agent from a terminal.");
  for (const about of [{ ...ABOUT, update: null }, { ...ABOUT, version: "unknown", update: { state: "unknown" } }, ABOUT]) {
    const { doc: d } = load({ url: URL, routes: { "GET control/summary": summary(), "GET home": home({ about }) } });
    await tick();
    assert.equal(checkLine(d).hidden, true, JSON.stringify(about));
    assert.equal(aboutRow(d).querySelector(".about-update"), null);
  }
});
