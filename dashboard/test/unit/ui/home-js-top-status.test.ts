/**
 * home-js-top-status.test — the product page's top bar says on or off
 * (dashboard.md §4.25 *The top bar says on or off*): the words of the
 * Settings switch, never a level name. Any level that protects is "on"; a
 * change saved for the next start says which way it goes; no protection
 * service is "Not connected" with a grey dot, as the hero and the tab say
 * (2026-10-28), and no answer from the server is "Not connected" with a red
 * one; a service that answers without its level is "Protection unknown".
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, tick } from "./home-js-fixtures.js";

async function status(protection: { level: string; configured: string; connected: boolean }) {
  const { doc } = load({ homeVm: home({ protection }) });
  await tick();
  const host = doc.getElementById("top-status");
  const link = host.querySelector("a");
  return { text: host.textContent as string, dot: host.querySelector(".dot").className as string, name: link ? link.getAttribute("aria-label") as string : "" };
}

test("a level that protects reads 'Protection on' with a green dot, whatever its name", async () => {
  for (const level of ["secrets", "full", "injection"]) {
    const s = await status({ level, configured: level, connected: true });
    assert.equal(s.text, "Protection on", level);
    assert.equal(s.dot, "dot ok", level);
  }
});

test("off reads 'Protection off' with a warning dot; no protection service reads 'Not connected' with a grey dot", async () => {
  const off = await status({ level: "off", configured: "off", connected: true });
  assert.equal(off.text, "Protection off");
  assert.equal(off.dot, "dot warn");
  const none = await status({ level: "unknown", configured: "secrets", connected: false });
  assert.equal(none.text, "Not connected");
  assert.equal(none.dot, "dot ", "grey, not the red of a failed read");
  assert.equal(none.name, "Not connected: open Settings");
  // A service that answers but does not report its level (one older than
  // posture reporting) is connected: the bar does not say it is not.
  const older = await status({ level: "unknown", configured: "secrets", connected: true });
  assert.equal(older.text, "Protection unknown");
  assert.equal(older.dot, "dot ");
});

test("no protection service: the hero, the tab and the top bar all say 'Not connected' for the one home", async () => {
  const { doc } = load({ homeVm: home({
    verdict: "unknown", headline: "Not connected.",
    sentence: "The protection service is not reachable, so nothing can be checked. Start an agent with Mandu, or open Settings.",
    sentenceParts: [
      { kind: "text", text: "The protection service is not reachable, so nothing can be checked. Start an agent with Mandu, or " },
      { kind: "link", text: "open Settings", to: "settings" },
      { kind: "text", text: "." },
    ],
    protection: { level: "unknown", configured: "secrets", connected: false },
    waitingKnown: false, waiting: [],
  }) });
  await tick();
  assert.equal(doc.getElementById("hero-headline").textContent, "Not connected.");
  assert.match(doc.title, /^Not connected · /, `the tab: ${doc.title}`);
  assert.equal(doc.getElementById("top-status").textContent, "Not connected");
  assert.equal(doc.querySelector("#top-status .dot").className, "dot ", "grey: the server answered");
});

test("Mandu not running at all (§4.25, *Protection is off when nothing runs*): the top bar and the hero say off, never unknown or connected", async () => {
  const notRunning = { level: "unknown", configured: "secrets", connected: false, notRunning: true };
  const s = await status(notRunning);
  assert.equal(s.text, "Protection off");
  assert.equal(s.dot, "dot warn");
  assert.match(s.name, /^Protection off: open Settings$/);
  // The hero as the server words it: its commands drawn as code, no count.
  const { doc } = load({ homeVm: home({
    verdict: "off", headline: "Protection is off: no agent runs with Mandu.",
    sentence: "Your agents send what they read to the AI as it is, secrets included. To protect one, start it with mandu claude (or mandu codex).",
    sentenceParts: [
      { kind: "text", text: "Your agents send what they read to the AI as it is, secrets included. To protect one, start it with " },
      { kind: "code", text: "mandu claude" }, { kind: "text", text: " (or " }, { kind: "code", text: "mandu codex" }, { kind: "text", text: ")." },
    ],
    protection: notRunning, waitingKnown: false, waiting: [], agents: [], history: { total: 0 },
  }) });
  await tick();
  assert.equal(doc.getElementById("hero").dataset.verdict, "off");
  assert.equal(doc.getElementById("hero-headline").textContent, "Protection is off: no agent runs with Mandu.");
  assert.deepEqual([...doc.querySelectorAll("#hero-sentence code")].map((c: { textContent: string }) => c.textContent), ["mandu claude", "mandu codex"]);
  assert.equal(doc.getElementById("hero-facts").textContent, "", "no count is claimed");
  assert.doesNotMatch(doc.getElementById("top-status").textContent, /Not connected|unknown|Protection on/);
});

test("a change saved for the next start says which way it goes; a change between two levels that protect says nothing", async () => {
  assert.equal((await status({ level: "secrets", configured: "off", connected: true })).text, "Protection on · off from the next start");
  assert.equal((await status({ level: "off", configured: "secrets", connected: true })).text, "Protection off · on from the next start");
  assert.equal((await status({ level: "secrets", configured: "full", connected: true })).text, "Protection on");
});

test("no level name reaches the top bar", async () => {
  for (const level of ["secrets", "full", "injection", "off", "unknown"]) {
    for (const configured of ["secrets", "full", "off"]) {
      const s = await status({ level, configured, connected: true });
      assert.doesNotMatch(s.text, /secrets|full|injection|saved|Secrets|Full|Injection/, `${level}/${configured}: ${s.text}`);
      assert.doesNotMatch(s.name, /secrets|full|injection|saved|Secrets|Full|Injection/, `${level}/${configured}: the link's name ${s.name}`);
    }
  }
});

// ── While not plainly on, the words open Settings › Protection ───────────────
// (dashboard.md §4.25 *The top bar says on or off*): from any page, a click
// lands on the Protection card with the focus on its switch, or on its
// heading while the switch cannot be pressed. A modifier click is the
// browser's; Protection on, with nothing to do, is words.

const AXES_ON = { ok: true, effective: { integrity: false, confidentiality: true }, effectiveMode: "secrets" };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const linksOf = (doc: any) => [...doc.getElementById("top-status").querySelectorAll("a")] as any[];

test("each row of the table: on has no link; off, unknown, not connected and a change for the next start link Settings", async () => {
  const rows: [{ level: string; configured: string; connected: boolean } | null, string][] = [
    [{ level: "secrets", configured: "secrets", connected: true }, ""],
    [{ level: "off", configured: "off", connected: true }, "Protection off"],
    [{ level: "unknown", configured: "secrets", connected: false }, "Not connected"],
    [{ level: "unknown", configured: "secrets", connected: true }, "Protection unknown"],
    [null, "Not connected"],
    [{ level: "secrets", configured: "off", connected: true }, "Protection on · off from the next start"],
    [{ level: "off", configured: "secrets", connected: true }, "Protection off · on from the next start"],
  ];
  for (const [protection, words] of rows) {
    const { doc } = load(protection ? { homeVm: home({ protection }) } : { routes: { "GET home": { status: 503, body: { error: "down" } } } });
    await tick();
    const links = linksOf(doc);
    const host = doc.getElementById("top-status");
    if (!words) {
      assert.equal(links.length, 0, "Protection on: nothing to do, no link");
      assert.equal(host.textContent, "Protection on");
      continue;
    }
    assert.equal(links.length, 1, words);
    const a = links[0];
    assert.equal(host.textContent, words, "the same words as before: the bar is no wider");
    assert.equal(a.textContent, words, "the words are the link; the dot is not");
    assert.equal(new URL(a.href).pathname, "/mandu/settings", words);
    assert.equal(a.getAttribute("aria-label"), words + ": open Settings", "its name says where it goes");
    assert.ok(host.querySelector(":scope > .dot"), "the dot stays beside it");
  }
});

test("a click from Rules opens Settings at Protection, the focus on the switch", async () => {
  const page = load({ url: "http://127.0.0.1:4500/mandu/rules", homeVm: home({ protection: { level: "off", configured: "off", connected: true } }),
    routes: { "GET config/axes": AXES_ON } });
  await tick();
  const scrolled: string[] = [];
  page.window.HTMLElement.prototype.scrollIntoView = function (this: { id: string }) { scrolled.push(this.id); };
  const a = linksOf(page.doc)[0];
  const click = new page.window.MouseEvent("click", { bubbles: true, cancelable: true });
  a.dispatchEvent(click);
  assert.equal(click.defaultPrevented, true);
  await tick(40);
  assert.equal(page.window.location.pathname, "/mandu/settings");
  assert.equal(page.doc.getElementById("page-settings").hidden, false);
  assert.deepEqual(scrolled, ["settings-protection-block"], "scrolled to the Protection card");
  const sw = page.doc.getElementById("switch-protection");
  assert.equal(sw.disabled, false);
  assert.equal(page.doc.activeElement, sw, "the focus is on the Protection switch");
  assert.equal(sw.hasAttribute("tabindex"), false, "the switch keeps its place in the tab order");
});

test("while the switch cannot be pressed, the focus goes to the Protection card's heading; on Settings itself too", async () => {
  const page = load({ url: "http://127.0.0.1:4500/mandu/settings", routes: { "GET home": { status: 503, body: { error: "down" } }, "GET config/axes": { status: 503, body: { error: "down" } } } });
  await tick(40);
  const scrolled: string[] = [];
  page.window.HTMLElement.prototype.scrollIntoView = function (this: { id: string }) { scrolled.push(this.id); };
  assert.equal(page.doc.getElementById("switch-protection").disabled, true);
  linksOf(page.doc)[0].click();
  await tick(40);
  assert.equal(page.window.location.pathname, "/mandu/settings");
  assert.deepEqual(scrolled, ["settings-protection-block"], "on Settings itself the link still scrolls");
  assert.equal(page.doc.activeElement, page.doc.getElementById("settings-protection-title"), "the card's heading has the focus");
});

test("a modifier click is left to the browser", async () => {
  const page = load({ url: "http://127.0.0.1:4500/mandu/rules", homeVm: home({ protection: { level: "off", configured: "off", connected: true } }) });
  await tick();
  for (const mod of ["metaKey", "ctrlKey", "shiftKey"]) {
    const click = new page.window.MouseEvent("click", { bubbles: true, cancelable: true, [mod]: true });
    linksOf(page.doc)[0].dispatchEvent(click);
    assert.equal(click.defaultPrevented, false, mod);
    assert.equal(page.window.location.pathname, "/mandu/rules", mod);
  }
});

test("Approvals' intro links the Rules page it names", async () => {
  const page = load({ url: "http://127.0.0.1:4500/mandu/approvals" });
  await tick();
  const a = page.doc.querySelector("#page-approvals .page-head p a");
  assert.ok(a, "a link in the intro");
  assert.equal(a.textContent, "Rules");
  assert.equal(a.getAttribute("data-page-link"), "rules");
  a.click();
  await tick();
  assert.equal(page.window.location.pathname, "/mandu/rules");
});

// ── Protection failed, on every page (dashboard.md §4.25 *The top bar says on
// or off*, 2026-10-23) ─────────────────────────────────────────────────────
// While the hero's verdict is `failed`, the top bar says so with a red dot,
// as a link to where it happened: that session's page when one failed, Home
// when several did. It wins over a change for the next start and over off,
// as the hero's ladder ranks it; not running and no answer keep their words.

const ON = { level: "secrets", configured: "secrets", connected: true };
const lead = { kind: "text", text: "One item reached the AI unmasked in the last 24 hours. " };
const failedHome = (parts: unknown[], protection: Record<string, unknown> = ON) => home({
  verdict: "failed", headline: "Protection failed.", sentence: (parts as { text: string }[]).map((p) => p.text).join(""), sentenceParts: parts, protection,
});
const ONE = [lead, { kind: "link", text: "Open that agent's page", to: "agent", session: "s1" }, { kind: "text", text: " to see which." }];
const ONE_DEV = [lead, { kind: "link", text: "Open the detailed trace", to: "trace", session: "s1" }, { kind: "text", text: " to see which." }];
// Several, as the product build's hero words them since 2026-10-25
// (home.ts failedSessionParts): each failed session a link to its page,
// newest first, three at most, then "and N more".
const place = (session: string, folder: string) => ({ kind: "link", text: `Claude Code in ~/${folder}`, to: "agent", session, parts: [{ kind: "text", text: "Claude Code in " }, { kind: "code", text: `~/${folder}` }] });
const SEVERAL = [
  { kind: "text", text: "2 items reached the AI unmasked in the last 24 hours, in " },
  place("s1", "shop"), { kind: "text", text: " and " }, place("s2", "api"),
  { kind: "text", text: ". Open each to see which." },
];
const SEVERAL_MORE = [
  { kind: "text", text: "5 items reached the AI unmasked in the last 24 hours, in " },
  place("s1", "shop"), { kind: "text", text: ", " }, place("s2", "api"), { kind: "text", text: ", " }, place("s3", "web"),
  { kind: "text", text: " and 2 more, each marked \"protection failed\" in the lists below. Open each to see which." },
];
const SEVERAL_DEV = [{ kind: "text", text: "2 items reached the AI unmasked in the last 24 hours. " }, { kind: "link", text: "Open the detailed trace", to: "trace", session: null }, { kind: "text", text: " to see which." }];

test("one failed session: a red dot and 'Protection failed', a link to that session's page; a plain click opens it", async () => {
  for (const [parts, extensions, to] of [[ONE, "", "agent"], [ONE_DEV, "inspector", "trace"]] as const) {
    const page = load({ url: "http://127.0.0.1:4500/mandu/rules", homeVm: failedHome([...parts]), extensions });
    await tick();
    const host = page.doc.getElementById("top-status");
    assert.equal(host.textContent, "Protection failed", to);
    assert.equal(host.querySelector(":scope > .dot").className, "dot bad");
    const links = linksOf(page.doc);
    assert.equal(links.length, 1);
    const a = links[0];
    assert.equal(a.textContent, "Protection failed");
    assert.equal(a.className, "top-status-link", "the status's own ink and size");
    assert.equal(new URL(a.href).pathname, "/mandu/agents/s1", `${to}: the product's session page in both builds`);
    assert.equal(a.getAttribute("aria-label"), "Protection failed: open the session where it happened");
    const click = new page.window.MouseEvent("click", { bubbles: true, cancelable: true });
    a.dispatchEvent(click);
    assert.equal(click.defaultPrevented, true);
    await tick(40);
    assert.equal(page.window.location.pathname, "/mandu/agents/s1");
    assert.equal(page.doc.getElementById("page-agent").hidden, false, "the session's page is open");
  }
});

test("several failed sessions: the link opens Home, whose hero and rows say which, never the newest one named", async () => {
  for (const [parts, name] of [[SEVERAL, "two named"], [SEVERAL_MORE, "three named and 2 more"], [SEVERAL_DEV, "the developer build's list"]] as const) {
    const page = load({ url: "http://127.0.0.1:4500/mandu/approvals", homeVm: failedHome([...parts]) });
    await tick();
    const links = linksOf(page.doc);
    assert.equal(links.length, 1, name);
    const a = links[0];
    assert.equal(page.doc.getElementById("top-status").textContent, "Protection failed", name);
    assert.equal(new URL(a.href).pathname, "/mandu/", name);
    assert.equal(a.getAttribute("aria-label"), "Protection failed: open Home", name);
    assert.equal(a.dataset.session, undefined, name);
    const click = new page.window.MouseEvent("click", { bubbles: true, cancelable: true });
    a.dispatchEvent(click);
    assert.equal(click.defaultPrevented, true, `${name}: opened in place`);
    await tick(40);
    assert.equal(page.window.location.pathname, "/mandu/", name);
    assert.equal(page.doc.getElementById("page-home").hidden, false, name);
  }
});

test("failed wins over a change for the next start and over off: no tail; not running and no answer keep their words", async () => {
  const tail = await status({ level: "secrets", configured: "off", connected: true });
  assert.equal(tail.text, "Protection on · off from the next start", "the tail as before");
  for (const protection of [{ level: "secrets", configured: "off", connected: true }, { level: "off", configured: "secrets", connected: true }, { level: "off", configured: "off", connected: true }]) {
    const { doc } = load({ homeVm: failedHome(ONE, protection) });
    await tick();
    assert.equal(doc.getElementById("top-status").textContent, "Protection failed", JSON.stringify(protection));
    assert.equal(doc.querySelector("#top-status .dim"), null, "no tail");
  }
  // The hero ranks these first, so the server never sends `failed` with
  // them; an answer that did still keeps their words.
  const notRunning = load({ homeVm: failedHome(ONE, { level: "unknown", configured: "secrets", connected: false, notRunning: true }) });
  await tick();
  assert.equal(notRunning.doc.getElementById("top-status").textContent, "Protection off");
  const down = load({ routes: { "GET home": { status: 503, body: { error: "down" } } } });
  await tick();
  assert.equal(down.doc.getElementById("top-status").textContent, "Not connected");
});

test("an identical poll leaves the live region as it is; a protecting verdict again says 'Protection on'", async () => {
  const page = load({ homeVm: failedHome(ONE) });
  await tick();
  const host = page.doc.getElementById("top-status");
  const drawn = host.querySelector("a");
  assert.equal(host.textContent, "Protection failed");
  page.doc.dispatchEvent(new page.window.Event("visibilitychange"));
  await tick(40);
  assert.equal(host.querySelector("a"), drawn, "not written again");
  // Another session failed instead: the link follows it.
  page.setHome(failedHome([lead, { kind: "link", text: "Open that agent's page", to: "agent", session: "s2" }]));
  page.doc.dispatchEvent(new page.window.Event("visibilitychange"));
  await tick(40);
  assert.equal(new URL(host.querySelector("a").href).pathname, "/mandu/agents/s2");
  // A second session fails: the link opens Home; back to one, its page again.
  page.setHome(failedHome(SEVERAL));
  page.doc.dispatchEvent(new page.window.Event("visibilitychange"));
  await tick(40);
  assert.equal(new URL(host.querySelector("a").href).pathname, "/mandu/");
  assert.equal(host.querySelector("a").getAttribute("aria-label"), "Protection failed: open Home");
  page.setHome(failedHome(ONE));
  page.doc.dispatchEvent(new page.window.Event("visibilitychange"));
  await tick(40);
  assert.equal(new URL(host.querySelector("a").href).pathname, "/mandu/agents/s1");
  assert.equal(host.querySelector("a").getAttribute("aria-label"), "Protection failed: open the session where it happened");
  page.setHome(home({ verdict: "protected", protection: ON }));
  page.doc.dispatchEvent(new page.window.Event("visibilitychange"));
  await tick(40);
  assert.equal(host.textContent, "Protection on");
  assert.equal(host.querySelector(".dot").className, "dot ok");
  assert.equal(linksOf(page.doc).length, 0);
});
