/**
 * home-js-appearance.test — Settings › Appearance on the PRODUCT page: one
 * row, "Colours", whose menu picks Same as this computer, Light or Dark,
 * stored under the developer view's key (`mandu.theme`), and the classic head
 * script that applies the stored choice before the first paint
 * (public/js/theme-early.js, home.js `wireAppearance`; dashboard.md §4.25
 * Settings › *Appearance*, §4.25k), in jsdom over the shared fetch stub
 * (home-js-fixtures.ts).
 *
 * Until 2026-10-18 the product page always followed the system: a person who
 * picked Dark in the developer view was back in light on `/`, and one with
 * only the product page could not pick at all.
 *
 * Pins: the head script pins `light` and `dark` and leaves `<html>` bare for
 * `system`, an unknown stored value and a storage that throws; it is a
 * classic script before the stylesheets (a module, defer or async would
 * paint first); the menu shows the stored choice, an unknown one as Same as
 * this computer; a change writes the key and the attribute at once, and
 * Same as this computer removes the attribute; a private window still
 * switches and says it is not remembered; the head script and the page agree
 * on every stored value. Axes: none (display only).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { JSDOM } from "jsdom";

import { load, tick } from "./home-js-fixtures.js";

const PUBLIC = new URL("../../../public/", import.meta.url);
const EARLY = readFileSync(new URL("js/theme-early.js", PUBLIC), "utf-8");
const HTML = readFileSync(new URL("index.html", PUBLIC), "utf-8");
const URL_SETTINGS = "http://127.0.0.1:4500/mandu/settings";
/** What the menu and the head script answer for each stored value. */
const STORED: [string | null, string, string | null][] = [
  // [stored, the menu, data-theme]
  ["light", "light", "light"],
  ["dark", "dark", "dark"],
  ["system", "system", null],
  ["theme-dracula", "system", null], // a retired palette
  ["", "system", null],
  [null, "system", null],
];

/** A window where localStorage throws on every use, as a private window or
 *  a browser with storage off does. */
const throwingStorage = (window: any) => {
  Object.defineProperty(window, "localStorage", { configurable: true, get() { throw new window.DOMException("denied", "SecurityError"); } });
};
/** The head script alone, in a bare page with `stored` in its storage. */
function early(stored: string | null, opts: { throws?: boolean } = {}) {
  const dom = new JSDOM("<!DOCTYPE html><html><head></head><body></body></html>", { url: URL_SETTINGS, runScripts: "outside-only" });
  const w = dom.window as any;
  if (stored !== null) w.localStorage.setItem("mandu.theme", stored);
  if (opts.throws) throwingStorage(w);
  w.eval(EARLY);
  return w.document.documentElement.getAttribute("data-theme");
}
const menu = (doc: any) => doc.getElementById("settings-theme");
const pick = (doc: any, window: any, value: string) => {
  menu(doc).value = value;
  menu(doc).dispatchEvent(new window.Event("change", { bubbles: true }));
};

test("the head script pins light and dark, and leaves <html> bare for system, an unknown value, nothing stored and a storage that throws", () => {
  for (const [stored, , attr] of STORED) assert.equal(early(stored), attr, `stored ${JSON.stringify(stored)}`);
  assert.equal(early("dark", { throws: true }), null, "a throwing storage: no attribute, and no error");
});

test("the head script is a classic script in <head>, before the stylesheets, so the first paint has the theme", () => {
  const head = HTML.slice(0, HTML.indexOf("</head>"));
  const tag = /<script\b[^>]*\bsrc="js\/theme-early\.js"[^>]*><\/script>/.exec(head);
  assert.ok(tag, "theme-early.js is loaded in <head>");
  assert.doesNotMatch(tag![0], /\b(type|defer|async)\b/, "classic: no type=module, no defer, no async");
  const firstSheet = head.indexOf('rel="stylesheet"');
  assert.ok(firstSheet > 0 && tag!.index < firstSheet, "before the first stylesheet");
  assert.ok(EARLY.replace(/\/\*[\s\S]*?\*\//g, "").split("\n").filter((l) => l.trim()).length <= 6, "tiny: a few lines of code");
});

test("Settings ends with Appearance: one row, Colours, and a menu of the three choices, Same as this computer first", async () => {
  const { doc, err } = load({ url: URL_SETTINGS });
  assert.equal(err, null);
  await tick();
  const card = doc.getElementById("settings-appearance-block");
  assert.ok(card, "the card");
  assert.equal(card.closest("section[data-page]").dataset.page, "settings");
  assert.equal(card.querySelector("h2").textContent, "Appearance");
  assert.equal(card.previousElementSibling.id, "settings-notify-block", "after Notifications");
  const rows = card.querySelectorAll(".row");
  assert.equal(rows.length, 1, "one row");
  const label = rows[0].querySelector("label.name");
  assert.equal(label.textContent, "Colours");
  assert.equal(label.htmlFor, "settings-theme", "the label names the menu");
  assert.deepEqual([...menu(doc).options].map((o: any) => [o.value, o.textContent]), [
    ["system", "Same as this computer"], ["light", "Light"], ["dark", "Dark"],
  ]);
});

test("the menu shows the stored choice (an unknown one as Same as this computer), and the page wears it", async () => {
  for (const [stored, shown, attr] of STORED) {
    const { doc } = load({ url: URL_SETTINGS, storage: stored === null ? {} : { "mandu.theme": stored } });
    await tick();
    assert.equal(menu(doc).value, shown, `stored ${JSON.stringify(stored)}: the menu`);
    assert.equal(doc.documentElement.getAttribute("data-theme"), attr, `stored ${JSON.stringify(stored)}: the page`);
    // The head script, run first in a browser, agrees with the page.
    assert.equal(early(stored), attr, `stored ${JSON.stringify(stored)}: the head script agrees`);
  }
});

test("a change applies at once and is stored under the developer view's key; Same as this computer removes the attribute", async () => {
  const { doc, window } = load({ url: URL_SETTINGS });
  await tick();
  assert.equal(doc.documentElement.hasAttribute("data-theme"), false, "nothing stored: the system's");
  pick(doc, window, "dark");
  assert.equal(doc.documentElement.getAttribute("data-theme"), "dark");
  assert.equal(window.localStorage.getItem("mandu.theme"), "dark");
  pick(doc, window, "light");
  assert.equal(doc.documentElement.getAttribute("data-theme"), "light");
  assert.equal(window.localStorage.getItem("mandu.theme"), "light");
  pick(doc, window, "system");
  assert.equal(doc.documentElement.hasAttribute("data-theme"), false, "Same as this computer: <html> bare");
  assert.equal(window.localStorage.getItem("mandu.theme"), "system", "the developer view's value for it");
  assert.equal(doc.getElementById("settings-theme-note").textContent, "", "remembered: no note");
});

test("a private window, where storage throws, still switches the page and says the choice is not remembered", async () => {
  const { doc, window, err } = load({ url: URL_SETTINGS, before: throwingStorage });
  assert.equal(err, null, "the page boots");
  await tick();
  assert.equal(menu(doc).value, "system");
  pick(doc, window, "dark");
  assert.equal(doc.documentElement.getAttribute("data-theme"), "dark", "switched");
  assert.equal(doc.getElementById("settings-theme-note").textContent, "Not remembered in this window.");
});
