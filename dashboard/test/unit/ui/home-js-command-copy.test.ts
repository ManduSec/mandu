/**
 * home-js-command-copy.test — a command Mandu itself asks you to run has a
 * Copy button beside it (public/js/home.js `runCode`, `copyButton`;
 * dashboard.md §4.25b *A command Mandu asks you to run has one too*).
 *
 * Until 2026-10-26 only a fenced block in an agent's reply could be copied
 * (home-js-code-copy.test.ts); every command the page asked for was a bare
 * <code>, the longest the security update's `curl -fsSL … | sh`. Pins:
 *   - the update line (Home's security notice, Settings › About), each
 *     first-run command, `mandu scan` on Home's scan card and the Scan page,
 *     a session notice's `mandu log <id>`, and index.html's `mandu dashboard
 *     --set-password` (the account-changed card, Settings › Dashboard
 *     account) each draw one Copy after the code; pressed, it writes exactly
 *     the command, reads Copied, says so in a polite status, keeps the focus;
 *   - its accessible name says what it copies ("Copy mandu scan", "Copy the
 *     update command");
 *   - no clipboard (not a secure context): the bare code, as before;
 *   - a poll that draws the card again gives the focus to the Copy drawn
 *     at its place;
 *   - a host, a file, a key name, `mandu claude` in a sentence and the
 *     notice's `mandu doctor` get none, and the reply's Copy is unchanged;
 *   - an attached OpenClaw (#147, 2026-10-28): Home's exposure card and its
 *     lost-route card (`role="alert"`) draw a Copy per command of their fix,
 *     each copying exactly it; the session id and its config file, and an
 *     unwalled launch's flags, stay plain code (the Plugins page's own are
 *     in home-js-plugins.test.ts);
 *   - the rest of the commands the page asks you to run (#193, 2026-10-29):
 *     Settings › About's `mandu doctor` (index.html) and, with no version
 *     known, `mandu --version`; Settings › Protection's `mandu dashboard`
 *     with no service controls; Where your data lives' `mandu paths` (its
 *     line, the open-places note, the list that could not load) and its
 *     broken-link note's `mandu doctor` (#263, 2026-11-02); and the
 *     page's own sentences that mark their command 'run' (the answer this
 *     dashboard cannot pass on, `mandu stop`; the session record it could
 *     not check, and Describe's helper not installed, `mandu doctor`; the
 *     sign-in sentence's `mandu dashboard --set-password`): each copies
 *     exactly it, is named for it, and the sentence reads as before with
 *     "Copy" after the command; no clipboard, the bare code; About's
 *     `update-check = true` has none;
 *   - the callers are pinned: only these places draw a runCode, and only
 *     the scan card's again line, the notice's log command, the Plugins
 *     page's stopped service line and the two OpenClaw fixes are marked
 *     `run` by the server.
 *
 * Drives the PRODUCT page script in jsdom over the shared fetch stub
 * (home-js-fixtures.ts), with a stubbed clipboard; the server parts come
 * from the real view-model builders. Axes: none (display only). Mandu-new.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

import { AGENT, JS, PUB, home, load, tick } from "./home-js-fixtures.js";
import { HELPER_WORDS } from "../../../src/policy-assistant.js";
import { ADMIN_SESSION_REQUIRED } from "../../../src/server.js";
import { homeScanCard } from "../../../src/view-model/last-scan.js";
import { buildFirstRun } from "../../../src/view-model/home.js";
import { installLine } from "../../../src/update-notice.js";
import { ROUTE_FIX_PARTS, homeRouteLost } from "../../../src/view-model/attachment-route.js";
import { PLUGIN_EXPOSURE_FIX, homeExposure, toHumanPlaneVM } from "../../../src/view-model/human-plane.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const VERSION = "0.2.0-beta.8";
const NEWER = "0.2.0-beta.9";
const CURL = installLine(NEWER, "release");
const NPM = installLine(NEWER, "npm");
const SESSION = "c0ffee00-1234-4abc-9def-000000000001";
const LOG = `mandu log ${SESSION}`;
const SET_PASSWORD = "mandu dashboard --set-password";

/** Home's answer with no session yet: the first-run card, the scan card
 *  before any scan, a security release out, the account file changed. */
function firstHome(over: Record<string, unknown> = {}): Record<string, unknown> {
  return home({
    verdict: "off", headline: "Protection is off.", waiting: [], agents: [], history: { total: 0 },
    firstRun: buildFirstRun("secrets", "secrets"),
    scan: homeScanCard(null),
    about: { version: VERSION, update: { state: "newer", at: Date.now() - 3_600_000, newest: NEWER, security: true, install: CURL } },
    signIn: { signOut: true, accountChangedAt: new Date(Date.now() - 60_000).toISOString() },
    ...over,
  });
}

/** The page at `url` over `homeVm` (and `routes`), its clipboard `mode`:
 *  writes kept in `wrote`; the two-second timers held in `later`. */
function open(mode: "ok" | "none", url = "http://127.0.0.1:4500/mandu/", homeVm: unknown = firstHome(), routes: Record<string, unknown> = {}) {
  const wrote: string[] = [];
  const later: Array<() => void> = [];
  const page = load({ url, homeVm, routes, before: (w: Doc) => {
    if (mode === "ok") {
      Object.defineProperty(w.navigator, "clipboard", { configurable: true, value: { writeText: (t: string) => (wrote.push(t), w.Promise.resolve()) } });
    }
    const st = w.setTimeout;
    w.setTimeout = (fn: () => void, ms?: number, ...a: unknown[]) => (ms === 2000 ? (later.push(fn), 0) : st(fn, ms, ...a));
  } });
  assert.equal(page.err, null);
  return { ...page, wrote, later };
}

async function poll(doc: Doc): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}

/** Each run-code's command and its Copy under `root`. */
function runCodes(root: Doc): Array<{ cmd: string; btn: Doc; name: string }> {
  return ([...root.querySelectorAll(".run-code")] as Doc[]).map((r) => {
    const btn = r.querySelector(":scope > button.code-copy.run-copy");
    assert.ok(btn, "a run-code has its Copy");
    return { cmd: r.querySelector(":scope > code").textContent, btn, name: btn.getAttribute("aria-label") };
  });
}

test("Home: the update line, each first-run command and mandu scan each have a Copy that writes exactly the command, named for it", async () => {
  const { doc, wrote, later } = open("ok");
  await tick(40);
  // The security notice: the full curl … | sh, named as the update command.
  const fix = runCodes(doc.getElementById("update-fix"));
  assert.deepEqual(fix.map((r) => [r.cmd, r.name]), [[CURL, "Copy the update command"]]);
  assert.match(CURL, /^curl -fsSL https:\/\/github\.com\/.+\/releases\/download\/v0\.2\.0-beta\.9\/install\.sh \| sh$/);
  const btn = fix[0]!.btn;
  assert.equal(btn.getAttribute("type"), "button");
  assert.equal(btn.textContent, "Copy");
  const status = btn.parentElement.querySelector(":scope > .code-copy-said");
  assert.equal(status.getAttribute("role"), "status");
  btn.focus();
  btn.click();
  await tick();
  assert.deepEqual(wrote, [CURL], "the whole command, first c to last sh");
  assert.equal(btn.textContent, "Copied");
  assert.equal(status.textContent, "Copied");
  assert.equal(doc.activeElement, btn, "the focus stays on the button");
  later.shift()!();
  assert.equal(btn.textContent, "Copy");

  // The first-run card: each step's commands, named by the command.
  const steps = runCodes(doc.getElementById("first-run-steps"));
  const fr = buildFirstRun("secrets", "secrets");
  const commands = fr.steps.flatMap((s) => s.commands.map((c) => c.command));
  assert.deepEqual(steps.map((r) => r.cmd), commands);
  assert.deepEqual(steps.map((r) => r.name), commands.map((c) => `Copy ${c}`));
  for (const r of steps) r.btn.click();
  await tick();
  assert.deepEqual(wrote.slice(1), commands);
  // A code in a step's sentence (a file, a key) has none.
  for (const c of doc.querySelectorAll("#first-run-steps .note code")) assert.equal(c.closest(".run-code"), null, c.textContent);

  // The scan card: only the again line's mandu scan, not the sentence's.
  assert.deepEqual(runCodes(doc.getElementById("home-scan-again")).map((r) => [r.cmd, r.name]), [["mandu scan", "Copy mandu scan"]]);
  assert.equal(doc.querySelector("#home-scan-sentence .run-code"), null, "the sentence names it; it does not ask to run it");
  runCodes(doc.getElementById("home-scan-again"))[0]!.btn.click();
  await tick();
  assert.equal(wrote.at(-1), "mandu scan");

  // The account-changed card's command.
  assert.equal(doc.getElementById("home-account-changed").hidden, false);
  assert.deepEqual(runCodes(doc.getElementById("home-account-changed")).map((r) => [r.cmd, r.name]), [[SET_PASSWORD, `Copy ${SET_PASSWORD}`]]);
  runCodes(doc.getElementById("home-account-changed"))[0]!.btn.click();
  await tick();
  assert.equal(wrote.at(-1), SET_PASSWORD);

  // Every Copy on Home is one of these, or a reply's code block's.
  const expected = new Set([CURL, ...commands, "mandu scan", SET_PASSWORD, "mandu paths"]);
  for (const r of runCodes(doc)) assert.ok(expected.has(r.cmd), `a Copy on ${r.cmd}`);
});

test("Settings: About's update line (npm too) and the Dashboard account's command have their Copy", async () => {
  const vm = firstHome({ about: { version: VERSION, update: { state: "newer", at: Date.now(), newest: NEWER, security: false, install: NPM } } });
  const { doc, wrote } = open("ok", "http://127.0.0.1:4500/mandu/settings", vm);
  await tick(40);
  const about = runCodes(doc.getElementById("settings-about-version"));
  assert.deepEqual(about.map((r) => [r.cmd, r.name]), [[NPM, "Copy the update command"]]);
  about[0]!.btn.click();
  await tick();
  assert.deepEqual(wrote, [NPM]);
  const account = runCodes(doc.getElementById("settings-account-block"));
  assert.deepEqual(account.map((r) => r.cmd), [SET_PASSWORD]);
  // One code on the row, the update line; Copy is no code.
  assert.equal(doc.getElementById("settings-about-version").querySelectorAll("code").length, 1);
});

test("a session that could not do its job: its page's mandu log <id> has a Copy; the notice's mandu doctor and the reply's code keep theirs as before", async () => {
  const noticeParts = [
    { kind: "text", text: "Your terminal showed masked values. If it happens again, run " },
    { kind: "code", text: "mandu doctor" },
    { kind: "text", text: ". None of the 2 commands the agent ran could start. Run " },
    { kind: "code", text: LOG, run: true },
    { kind: "text", text: " for this launch's notices." },
  ];
  const notice = noticeParts.map((p) => p.text).join("");
  const agent = { ...AGENT, id: SESSION, notice, noticeParts, noticeShown: true };
  const url = `http://127.0.0.1:4500/mandu/agents/${SESSION}`;
  const { doc, wrote, later } = open("ok", url, firstHome(), { [`GET home/agent?session=${SESSION}`]: agent });
  await tick(40);
  const line = doc.getElementById("agent-notice");
  assert.equal(line.hidden, false);
  const runs = runCodes(line);
  assert.deepEqual(runs.map((r) => [r.cmd, r.name]), [[LOG, `Copy ${LOG}`]]);
  assert.equal(line.querySelectorAll("code").length, 2, "mandu doctor stays a code");
  assert.equal([...line.querySelectorAll("code")].find((c: Doc) => c.textContent === "mandu doctor").closest(".run-code"), null);
  // The words read as before, with "Copy" after the command.
  assert.equal(line.querySelectorAll("p")[1].textContent, notice.replace(LOG, `${LOG}Copy`));
  runs[0]!.btn.focus();
  runs[0]!.btn.click();
  await tick();
  assert.deepEqual(wrote, [LOG], "the id in full");
  assert.equal(doc.activeElement, runs[0]!.btn);
  later.length = 0;
  // A reply's code block Copy has no name of its own: it reads "Copy".
  for (const b of doc.querySelectorAll("#agent-story button.code-copy")) assert.equal(b.getAttribute("aria-label"), null);
  // Print hides it, as the reply's Copy (app.css @media print).
  const css = readFileSync(join(PUB, "app.css"), "utf8");
  const print = css.slice(css.indexOf("@media print"));
  assert.match(print.slice(0, print.indexOf("}")), /\.run-copy\b/);
});

test("no clipboard (not a secure context): every command is the bare code, as before", async () => {
  const { doc } = open("none");
  await tick(40);
  assert.equal(doc.querySelector(".run-code, button.code-copy"), null);
  assert.equal(doc.querySelector("#update-fix code").textContent, CURL);
  assert.equal(doc.querySelector("#home-scan-again code").textContent, "mandu scan");
  assert.equal(doc.querySelector("#home-account-changed code").textContent, SET_PASSWORD);
  assert.ok(doc.querySelector("#home-account-changed code").classList.contains("code-whole"));
  assert.equal(doc.querySelectorAll("#first-run-steps .first-run-commands code").length, buildFirstRun("secrets", "secrets").steps.flatMap((x) => x.commands).length);
});

test("a poll that draws the scan card again gives the focus to its Copy drawn at its place", async () => {
  const page = open("ok");
  const { doc } = page;
  await tick(40);
  const before = runCodes(doc.getElementById("home-scan-again"))[0]!.btn;
  before.focus();
  before.click();
  await tick();
  page.setHome(firstHome({ scan: { ...homeScanCard(null), headline: "Did an agent already send a secret?" } }));
  await poll(doc);
  assert.equal(doc.getElementById("home-scan-headline").textContent, "Did an agent already send a secret?", "the card was drawn again");
  const now = runCodes(doc.getElementById("home-scan-again"))[0]!.btn;
  assert.notEqual(now, before);
  assert.equal(doc.activeElement, now, "the focus is on the Copy drawn now");
});

test("the callers are pinned: runCode only at the update line, the first-run commands, the Plugins set-up and a part marked run; only these server parts carry the mark", () => {
  const calls = [...JS.matchAll(/^.*\brunCode\(.*$/gm)].map((m) => m[0].trim());
  assert.equal(calls.length, 14, calls.join("\n"));
  assert.ok(calls.some((l) => l.startsWith("function runCode(text, name)")));
  assert.equal(calls.filter((l) => l.includes("runCode(up.install, 'the update command')")).length, 1, "Settings › About");
  assert.equal(calls.filter((l) => l.includes("runCode(shown.install, 'the update command')")).length, 1, "Home's security notice");
  assert.equal(calls.filter((l) => l.includes("runCode(c.command)")).length, 1, "the first-run commands");
  assert.equal(calls.filter((l) => l.includes("for (const cmd of h.setup.commands) steps.append(el('li', null, runCode(cmd)))")).length, 1, "the Plugins page's set-up steps");
  assert.equal(calls.filter((l) => l.includes("p.run === true ? runCode(p.text)")).length, 1, "textParts, for a part the server marks");
  // #193: words(), for an own-words part marked 'run'; About's unknown
  // version; Where your data lives (mandu paths twice; #263, mandu doctor
  // in its broken-link note); Settings › Protection.
  assert.equal(calls.filter((l) => l.includes("p[1] === 'run' ? runCode(p[0])")).length, 1, "words, for an own-words part marked run");
  assert.equal(calls.filter((l) => l.includes("runCode('mandu --version')")).length, 1, "Settings › About with no version");
  assert.equal(calls.filter((l) => l.includes("runCode('mandu paths')")).length, 3, "Where your data lives (its note and a failed load), and Home's card on open places");
  assert.equal(calls.filter((l) => l.includes("runCode('mandu doctor')")).length, 1, "Where your data lives' broken-link note");
  assert.equal(calls.filter((l) => l.includes("runCode('mandu dashboard')")).length, 1, "Settings › Protection with no service controls");
  // #234: the commands that start Mandu, in Settings › Protection's sentence while it is not running.
  assert.equal(calls.filter((l) => l.includes("[' or ', runCode(c)] : [runCode(c)]")).length, 1, "startRunCodes, Settings › Protection while Mandu is not running");
  // The own-words parts marked run: these four commands, and no other.
  const marked = [...JS.matchAll(/\['([^']+)', 'run'\]/g)].map((m) => m[1]);
  assert.deepEqual(marked.sort(), ["mandu dashboard --set-password", "mandu doctor", "mandu doctor", "mandu doctor", "mandu stop", "mandu stop"].sort());
  // The static commands: the account's set-password, Where your data
  // lives' mandu paths and About's mandu doctor, in index.html.
  const html = readFileSync(join(PUB, "index.html"), "utf8");
  assert.deepEqual([...html.matchAll(/<code[^>]*\bdata-run\b[^>]*>([^<]*)<\/code>/g)].map((m) => m[1]), [SET_PASSWORD, "mandu paths", SET_PASSWORD, "mandu doctor"]);
  // The server marks only the scan card's again line, the notice's log
  // command, the Plugins page's stopped service line (plugins.ts `run`) and
  // the two OpenClaw fixes (one line per command).
  const src = join(PUB, "..", "src", "view-model");
  // (A part is `kind: "code"` with `run: true`; ask-words.ts's exec
  // classification has a `run: true` of its own, no part.)
  const marks = readdirSync(src).filter((f) => f.endsWith(".ts")).flatMap((f) => [...readFileSync(join(src, f), "utf8").matchAll(/^.*\brun: true\b.*$/gm)].filter((m) => /kind|ScanPart|HomeTextPart|p\.kind/.test(m[0])).map(() => f));
  assert.deepEqual(marks.sort(), ["attachment-route.ts", "attachment-route.ts", "attachment-route.ts", "home.ts", "human-plane.ts", "human-plane.ts", "human-plane.ts", "last-scan.ts", "plugins.ts"]);
  assert.deepEqual(homeScanCard(null).againParts.filter((p) => "run" in p && p.run).map((p) => p.text), ["mandu scan"]);
  const plugins = readFileSync(join(src, "plugins.ts"), "utf8");
  assert.deepEqual([...plugins.matchAll(/\brun\((\w+)\)/g)].map((m) => m[1]), ["SERVICE_START", "SERVICE_INSTALL"], "plugins.ts marks only the stopped service line's two");
  assert.deepEqual(PLUGIN_EXPOSURE_FIX.filter((p) => p.run).map((p) => p.text), ["mandu openclaw gateway", "mandu serve stop", "mandu openclaw uninstall"]);
  assert.deepEqual(ROUTE_FIX_PARTS.filter((p) => p.run).map((p) => p.text), ["mandu openclaw install", "openclaw gateway restart", "mandu openclaw uninstall"]);
});

test("an attached OpenClaw: Home's exposure card and its lost-route card draw a Copy per command of the fix; the session, its config and a launch's flags stay plain", async () => {
  const SESSION_OC = "openclaw:main";
  // The plugin beside an unwalled launch: both fixes, the flags first.
  const plane = toHumanPlaneVM({ exposed: true, since: Date.now() - 60_000, launches: [
    { pid: 4242, mode: "off", posture: "off" },
    { pid: 0, mode: "secrets", posture: "gated", session: SESSION_OC, begunAt: 1, attachment: "openclaw-plugin" },
  ] });
  const exposure = homeExposure(plane)!;
  const routeLost = homeRouteLost([{ id: SESSION_OC, health: { attachmentRoute: {
    state: "lost", since: Date.now() - 60_000, config: "/home/u/.openclaw/openclaw.json",
    problems: [{ code: "plugin-disabled", detail: "the Mandu plugin is disabled (its entry)" }],
  } } } as never], plane)!;
  assert.ok(exposure && routeLost);
  const vm = firstHome({ firstRun: null, about: { version: VERSION, update: { state: "current", at: Date.now(), newest: VERSION } }, signIn: { signOut: true }, exposure, routeLost });
  const { doc, wrote, later } = open("ok", undefined, vm);
  await tick(40);

  const exp = doc.getElementById("home-exposure");
  assert.equal(exp.hidden, false);
  const fix = ["mandu openclaw gateway", "mandu serve stop", "mandu openclaw uninstall"];
  assert.deepEqual(runCodes(doc.getElementById("exposure-fix")).map((r) => [r.cmd, r.name]), fix.map((c) => [c, `Copy ${c}`]));
  for (const c of ["--mode off", "--no-net-guard"]) {
    const code = [...doc.querySelectorAll("#exposure-fix code")].find((x: Doc) => x.textContent === c);
    assert.ok(code, c);
    assert.equal(code.closest(".run-code"), null, `${c} is a flag, not a command`);
  }
  for (const r of runCodes(doc.getElementById("exposure-fix"))) r.btn.click();
  await tick();
  assert.deepEqual(wrote, fix);

  const card = doc.getElementById("home-route-lost");
  assert.equal(card.hidden, false);
  assert.equal(card.getAttribute("role"), "alert");
  const reattach = ["mandu openclaw install", "openclaw gateway restart", "mandu openclaw uninstall"];
  const runs = runCodes(doc.getElementById("route-lost-fix"));
  assert.deepEqual(runs.map((r) => [r.cmd, r.name]), reattach.map((c) => [c, `Copy ${c}`]));
  runs[0]!.btn.focus();
  runs[0]!.btn.click();
  await tick();
  assert.equal(wrote.at(-1), "mandu openclaw install", "exactly the command");
  assert.equal(runs[0]!.btn.textContent, "Copied");
  assert.equal(doc.activeElement, runs[0]!.btn);
  later.at(-1)!();
  assert.equal(runs[0]!.btn.textContent, "Copy", "two seconds on, it reads Copy again");
  // The session and its config file name things; they are not commands.
  assert.deepEqual([...doc.querySelectorAll("#route-lost-items code")].map((c: Doc) => c.textContent), [SESSION_OC, "/home/u/.openclaw/openclaw.json"]);
  assert.equal(doc.querySelector("#route-lost-items .run-code, #exposure-causes .run-code"), null);
  // The words read as the server's, with "Copy" after each command.
  assert.equal(doc.getElementById("route-lost-fix").textContent, routeLost.fixParts.map((p) => p.text + (p.run ? "Copy" : "")).join(""));
});

// ── #193: the rest of the commands the page asks you to run ────────────────

const SETTINGS_URL = "http://127.0.0.1:4500/mandu/settings";
const ADMIN_CHANNEL = "This dashboard cannot pass on your answers: the protection service was already running when the dashboard started. Nothing was changed. To fix it, run mandu stop when no agent is running with mandu, then start your agent again.";
const SIGN_IN = "Sign in first: reload this page and sign in with your dashboard account (if there isn't one yet, run mandu dashboard --set-password in your own terminal).";
const LOCATIONS = {
  home: "~/.mandu",
  locations: [{ name: "events", path: "~/.mandu/events", where: "home", holds: "session history", exists: true, mode: "0755", ownerOnly: false }],
};
const BROKEN = { ...LOCATIONS, locations: [...LOCATIONS.locations, { name: "cache-root", path: "~/.mandu/cache", where: "home", holds: "files Mandu can rebuild", exists: true, brokenLink: true, mode: null, ownerOnly: null }] };

/** The one Copy under `node`: it copies exactly `cmd`, is named for it,
 *  and the words read as `text` with "Copy" after the command. */
async function copiesOne(node: Doc, cmd: string, text: string, wrote: string[], name = `Copy ${cmd}`): Promise<void> {
  const runs = runCodes(node);
  assert.deepEqual(runs.map((r) => [r.cmd, r.name]), [[cmd, name]], text);
  assert.ok(runs[0]!.btn.closest(".run-code").querySelector("code").classList.contains("code-whole") || cmd.length > 24, `${cmd} kept whole`);
  assert.equal(node.textContent, text.replace(cmd, `${cmd}Copy`), "the words as before, Copy after the command");
  runs[0]!.btn.click();
  await tick();
  assert.equal(wrote.at(-1), cmd, "exactly the command");
}

function openDataWhere(doc: Doc, window: Doc): void {
  const d = doc.getElementById("home-data");
  d.open = true;
  d.dispatchEvent(new window.Event("toggle"));
}

test("#193 Settings: About's mandu doctor and, with no version known, mandu --version; Protection's mandu dashboard without service controls; update-check = true has none", async () => {
  const vm = firstHome({ about: { version: "unknown", update: { state: "source" } } });
  const { doc, wrote } = open("ok", SETTINGS_URL, vm, { "GET control/summary": { summary: null } });
  await tick(40);
  const about = doc.getElementById("settings-about-block");
  const doctor = [...about.querySelectorAll("p.note")].find((p: Doc) => p.textContent.startsWith("To check this computer's setup"));
  await copiesOne(doctor, "mandu doctor", "To check this computer's setup, run mandu doctor in a terminal.", wrote);
  await copiesOne(doc.getElementById("settings-about-version"), "mandu --version", "Not known. Run mandu --version in a terminal.", wrote);
  await copiesOne(doc.querySelector("#settings-services .service-none"), "mandu dashboard",
    "This dashboard was started without the service controls. Start it with mandu dashboard to manage the protection service here.", wrote);
  assert.deepEqual(wrote, ["mandu doctor", "mandu --version", "mandu dashboard"]);
  // A source checkout: About names a config line, not a command, so no Copy.
  const src = open("ok", SETTINGS_URL, firstHome({ about: { version: VERSION, update: { state: "unknown", check: "source" } } }));
  await tick(40);
  const check = [...src.doc.querySelectorAll("#settings-about-check code")].find((c: Doc) => c.textContent === "update-check = true");
  assert.ok(check, "About names the config line");
  assert.equal(check.closest(".run-code"), null, "update-check = true is a config line");
  assert.equal(src.doc.querySelector("#settings-about-check .run-code"), null);
});

test("#193 Home › Where your data lives: its line, the open-places note and a list that could not load each copy mandu paths; #263 its broken-link note copies mandu doctor", async () => {
  const { doc, window, wrote } = open("ok", undefined, firstHome(), { "GET data-locations": LOCATIONS });
  await tick(40);
  const about = doc.getElementById("home-data-about");
  assert.deepEqual(runCodes(about).map((r) => [r.cmd, r.name]), [["mandu paths", "Copy mandu paths"]]);
  assert.equal(about.querySelector("#home-data-folder").closest(".run-code"), null, "the folder names a place");
  openDataWhere(doc, window);
  await tick();
  await copiesOne(doc.getElementById("home-data-open"), "mandu paths",
    "Other people on this computer can open 1 place in Mandu's folder. Run mandu paths in a terminal for the command that makes them yours only.", wrote);
  const bad = open("ok", undefined, firstHome(), { "GET data-locations": { status: 500, body: {} } });
  await tick(40);
  openDataWhere(bad.doc, bad.window);
  await tick();
  await copiesOne(bad.doc.querySelector("#home-data-list .empty"), "mandu paths", "The list could not be loaded. Run mandu paths in a terminal to see it.", bad.wrote);
  // #263: the broken-link note's mandu doctor.
  const broken = open("ok", undefined, firstHome(), { "GET data-locations": BROKEN });
  await tick(40);
  openDataWhere(broken.doc, broken.window);
  await tick();
  await copiesOne(broken.doc.getElementById("home-data-broken"), "mandu doctor",
    "1 place here is a link to something that is not there, so Mandu cannot use it until the link's target is back (a disk not mounted?) or the link is removed. Run mandu doctor in a terminal: it names each one.", broken.wrote);
});

test("#193 the page's own sentences: the answer it cannot pass on (mandu stop), the sign-in sentence, a record it could not check and Describe's missing helper (mandu doctor), each the same words with a Copy", async () => {
  // Settings: a label card refused for the missing admin channel, a prompt
  // card refused by the gate.
  const s = open("ok", SETTINGS_URL, firstHome(), {
    "GET policy/sensitivity-labels": { status: 503, body: { error: "admin channel unavailable: the dashboard adopted a running service" } },
    "GET policy/prompt-filters": { status: 403, body: { error: ADMIN_SESSION_REQUIRED } },
  });
  await tick(40);
  await copiesOne(s.doc.getElementById("settings-labels"), "mandu stop", ADMIN_CHANNEL, s.wrote);
  await copiesOne(s.doc.getElementById("settings-prompt-kinds"), SET_PASSWORD, SIGN_IN, s.wrote);

  // A session page whose record could not be checked: with no secret, and
  // with some.
  const SESSION_URL = "http://127.0.0.1:4500/mandu/agents/s1";
  const story = (secrets: unknown[]) => ({ ...AGENT, secrets: { mode: "secrets", flagged: false, more: 0, counts: { masked: 0, early: 0 }, secrets, unchecked: true, recorded: [] } });
  const a = open("ok", SESSION_URL, firstHome(), { "GET home/agent?session=s1": story([]) });
  await tick(40);
  await copiesOne(a.doc.getElementById("agent-secrets-intro"), "mandu doctor",
    "Mandu could not check this session's record: on this computer the agent could reach Mandu's own controls, so this page counts no secret from it. Run mandu doctor to see why.", a.wrote);

  // Rules › Describe, its helper not installed: the server's own words.
  const r = open("ok", "http://127.0.0.1:4500/mandu/rules", firstHome(), {
    "POST policy/assistant": { status: 503, body: { error: HELPER_WORDS["not-installed"], unconfigured: true, reason: "not-installed" } },
  });
  await tick(40);
  const ta = r.doc.getElementById("describe-text");
  ta.value = "Keep .env secret.";
  ta.dispatchEvent(new r.window.Event("input"));
  r.doc.getElementById("describe-form").dispatchEvent(new r.window.Event("submit", { cancelable: true }));
  await tick(40);
  await copiesOne(r.doc.querySelector("#describe-result .ask-error"), "mandu doctor", HELPER_WORDS["not-installed"], r.wrote);

  // No clipboard: each the bare code, the words exactly as before.
  const bare = open("none", SETTINGS_URL, firstHome({ about: { version: "unknown", update: { state: "source" } } }), {
    "GET policy/sensitivity-labels": { status: 503, body: { error: "admin channel unavailable: the dashboard adopted a running service" } },
    "GET control/summary": { summary: null },
  });
  await tick(40);
  assert.equal(bare.doc.querySelector(".run-code, button.code-copy"), null);
  assert.equal(bare.doc.getElementById("settings-labels").textContent, ADMIN_CHANNEL);
  assert.equal(bare.doc.querySelector("#settings-labels code").textContent, "mandu stop");
  assert.equal(bare.doc.getElementById("settings-about-version").textContent, "Not known. Run mandu --version in a terminal.");
  assert.equal(bare.doc.querySelector("#settings-services .service-none code").textContent, "mandu dashboard");
});
