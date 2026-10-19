/**
 * home-js-top-status.test — the product page's top bar says on or off
 * (dashboard.md §4.25 *The top bar says on or off*): the words of the
 * Settings switch, never a level name. Any level that protects is "on"; a
 * change saved for the next start says which way it goes; no protection
 * service is "unknown"; no answer from the server is "Not connected".
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

test("off reads 'Protection off' with a warning dot; no protection service reads 'Protection unknown'", async () => {
  const off = await status({ level: "off", configured: "off", connected: true });
  assert.equal(off.text, "Protection off");
  assert.equal(off.dot, "dot warn");
  const unknown = await status({ level: "unknown", configured: "secrets", connected: false });
  assert.equal(unknown.text, "Protection unknown");
  assert.equal(unknown.dot, "dot ");
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
    [{ level: "unknown", configured: "secrets", connected: false }, "Protection unknown"],
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
