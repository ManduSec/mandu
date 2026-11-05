/**
 * home-js-protection-changed — Settings › Protection says when protection
 * was last turned off or on in the dashboard (dashboard.md §4.25 *The
 * Protection row says when it was last turned off or on in the dashboard*;
 * queue item #306).
 *
 * Until 2026-11-04 the row said only the saved state ("Off", "Mandu only
 * watches. …"), so a person who turned protection off for a quick test and
 * forgot could not tell ten minutes from ten days. config/axes already
 * answered the latest `config_change` record per axis as `audit`; the
 * product page never read it. Now the note under the switch leads with it:
 *
 *   C1  saved off + a turn-off record: "Turned off in the dashboard <time>.
 *       A change applies …", the moment a <time datetime=ts>;
 *   C2  saved on + a turn-on record: "Turned on in the dashboard <time>. …";
 *       saved while another state runs: "… It applies when …" (no "Saved.");
 *   C3  a record whose `to` is not the saved state (`mandu mode` changed it
 *       since): no lead, the note is today's text;
 *   C4  no `audit`, only an integrity record, a `ts` that does not parse:
 *       no lead;
 *   C5  `requestedBy` is never drawn, whatever it holds;
 *   C6  a flip's POST answer with a fresh record draws the lead at once,
 *       and a read asked before the flip, answered after it, draws nothing
 *       over it (AXES_READS).
 *
 * Drives the PRODUCT page script (public/js/home.js) in jsdom over the
 * shared fetch stub (home-js-fixtures.ts). Axes: none (display only; the
 * stubs answer the `secrets` / `off` modes). Mandu-new.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, tick } from "./home-js-fixtures.js";
import { offBox, typeInOffBox, enterInOffBox } from "./protect-off.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const URL = "http://127.0.0.1:4500/mandu/settings";
const APPLIES = "A change applies when the protection service next starts.";
const SAVED = "Saved. It applies when the protection service next starts.";
const TS = new Date(Date.now() - 3 * 86_400_000).toISOString();
const savedAs = (on: boolean, audit?: unknown) => ({
  ok: true, effective: { integrity: false, confidentiality: on }, effectiveMode: on ? "secrets" : "off",
  ...(audit === undefined ? {} : { audit }),
});
const record = (to: boolean, over: Record<string, unknown> = {}) => ({ ts: TS, from: !to, to, requestedBy: "dashboard", ...over });
/** Home's answer: the protection service runs `level`. */
const runs = (level: string) => home({ protection: { level, configured: level, connected: true } });

function open(axes: unknown, level: string, routes: Record<string, unknown> = {}) {
  const page = load({ url: URL, homeVm: runs(level), routes: { "GET config/axes": axes, ...routes } });
  assert.equal(page.err, null);
  return page;
}
const note = (doc: Doc) => doc.getElementById("settings-protect-note");
const name = (doc: Doc) => doc.querySelector("#settings-protect-row .name").textContent;

test("C1: saved off with a turn-off record — the note starts 'Turned off in the dashboard', its moment a <time>", async () => {
  const { doc } = open(savedAs(false, { confidentiality: record(false) }), "off");
  await tick(30);
  assert.equal(name(doc), "Off");
  const n = note(doc);
  const t = n.querySelector("time");
  assert.ok(t, "the moment is a <time>");
  assert.equal(t.getAttribute("datetime"), TS);
  assert.ok(t.classList.contains("when"), "the page's one form of a moment (whenNode), kept current by refreshWhen");
  assert.match(t.textContent, / · 3 days ago$/);
  assert.equal(n.textContent, `Turned off in the dashboard ${t.textContent}. ${APPLIES}`);
  assert.equal(n.firstChild.nodeType, 3, "the lead is text, then the moment");
});

test("C2: saved on with a turn-on record — 'Turned on in the dashboard'; while another state runs, 'It applies …' without 'Saved.'", async () => {
  {
    const { doc } = open(savedAs(true, { confidentiality: record(true) }), "secrets");
    await tick(30);
    const t = note(doc).querySelector("time");
    assert.ok(t);
    assert.equal(note(doc).textContent, `Turned on in the dashboard ${t.textContent}. ${APPLIES}`);
  }
  {
    // Saved on, the service still runs off: the saved form of the note.
    const { doc } = open(savedAs(true, { confidentiality: record(true) }), "off");
    await tick(30);
    const t = note(doc).querySelector("time");
    assert.ok(t);
    assert.equal(note(doc).textContent, `Turned on in the dashboard ${t.textContent}. It applies when the protection service next starts.`);
  }
});

test("C3: a record whose `to` is not the saved state (changed by mandu mode since) draws no lead", async () => {
  for (const [on, rec, level, text] of [
    [false, record(true), "off", APPLIES],
    [true, record(false), "secrets", APPLIES],
    [true, record(false), "off", SAVED],
  ] as const) {
    const { doc } = open(savedAs(on, { confidentiality: rec }), level);
    await tick(30);
    assert.equal(note(doc).textContent, text);
    assert.equal(note(doc).querySelector("time"), null);
  }
});

test("C4: no audit, only an integrity record, or a ts that does not parse draws no lead", async () => {
  for (const audit of [
    undefined,
    {},
    { integrity: record(false) },
    { confidentiality: record(false, { ts: "garbage" }) },
    { confidentiality: record(false, { ts: null }) },
    { confidentiality: null },
    null,
  ]) {
    const { doc } = open(savedAs(false, audit), "off");
    await tick(30);
    assert.equal(name(doc), "Off");
    assert.equal(note(doc).textContent, APPLIES, `audit ${JSON.stringify(audit)}`);
    assert.equal(note(doc).querySelector("time"), null);
  }
});

test("C5: requestedBy is never drawn", async () => {
  const evil = '"><img src=x onerror=alert(1)>requested-by-marker';
  const { doc } = open(savedAs(false, { confidentiality: record(false, { requestedBy: evil }) }), "off");
  await tick(30);
  assert.match(note(doc).textContent, /^Turned off in the dashboard /);
  const dom = doc.documentElement.outerHTML as string;
  assert.ok(!dom.includes("requested-by-marker"), "nothing of requestedBy is in the page");
  assert.equal(doc.querySelector("img[src=x]"), null);
});

test("C6: a flip's answer draws the lead at once, and a read asked before it, answered after, draws nothing over it", async () => {
  // config.toml says on, with an older turn-on record; a flip off answers
  // a fresh turn-off record. The page's own read is held.
  const fresh = new Date().toISOString();
  let release!: () => void;
  const gate = new Promise<void>((r) => { release = r; });
  let reads = 0;
  const { doc, calls } = open(null, "secrets", {
    "GET config/axes": () => (++reads === 2 ? gate.then(() => savedAs(true, { confidentiality: record(true) })) : savedAs(true, { confidentiality: record(true) })),
    "POST config/axes": (b: { mode: string }) => savedAs(b.mode === "secrets", { confidentiality: { ts: fresh, from: true, to: b.mode === "secrets", requestedBy: "dashboard" } }),
  });
  await tick(30);
  assert.match(note(doc).textContent, /^Turned on in the dashboard .* · 3 days ago\. /);
  // Settings opened again: its read (the second) is held.
  doc.querySelector('#nav [data-page-link="home"]').click();
  await tick(30);
  doc.querySelector('#nav [data-page-link="settings"]').click();
  await tick(30);
  assert.equal(reads, 2);
  const sw = doc.getElementById("switch-protection");
  sw.focus();
  sw.click();
  assert.ok(offBox(doc), "turning off asks for OFF");
  typeInOffBox(doc, "OFF");
  enterInOffBox(doc);
  await tick(30);
  assert.deepEqual(calls.filter((c: Doc) => c.method === "POST" && c.url.endsWith("/config/axes")).map((c: Doc) => c.body), [{ mode: "off" }]);
  assert.equal(name(doc), "Off");
  const t = note(doc).querySelector("time");
  assert.ok(t);
  assert.equal(t.getAttribute("datetime"), fresh);
  assert.match(note(doc).textContent, /^Turned off in the dashboard .* · just now\. It applies when the protection service next starts\.$/);
  const drawn = note(doc).textContent;
  release();
  await tick(30);
  assert.equal(name(doc), "Off", "the older read drew nothing");
  assert.equal(note(doc).textContent, drawn, "nor over the lead");
});
