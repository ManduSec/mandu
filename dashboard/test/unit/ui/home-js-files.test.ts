/**
 * home-js-files.test — All files, the file browser (dashboard.md §4.25m):
 * the listing and its labels, filters, pending changes and the weaker-change
 * question, Remove my rule, typed paths and Tab completion, symlinks, impact,
 * keyboard moves, suggestions, and moving page rules into policy.yaml; and
 * how Changes to save keeps its buttons in view (§4.25n).
 *
 * Split out of home-js.test.ts, which drove the PRODUCT page script
 * (public/js/home.js) in jsdom over a fetch stub (dashboard.md §4.25); the
 * shared harness and fixtures are in home-js-fixtures.ts.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
  load, tick, FILES_URL, chip, NONE, WS_LIST, CONFIG_LIST, list, FILES_ROUTES,
  fileRows, rowFor, tickRow, menuOf, pressed, dot, choose, waiting, inherits, openRow, opened, bulkBtn,
  chooseTicked, PUB,
} from "./home-js-fixtures.js";
import { resolveCssVars } from "./css-flatten.js";

// ── Add a file or folder: the file browser (dashboard.md §4.25m) ─────────────

test("file browser: opens on the folder the agent worked in, each entry with its label and where it came from; names are text", async () => {
  const { doc, calls } = load({ url: FILES_URL, routes: FILES_ROUTES });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  assert.equal(doc.getElementById("lock-form").hidden, false, "Add a rule opens the browser");
  const get = calls.find((c) => c.url.includes("/api/files/list"));
  assert.equal(get!.url, "/mandu/api/files/list?path=%2Fhome%2Fu%2Fws", "starts where the agent worked");
  assert.equal(get!.headers["X-Mandu-Control"], "1", "the listing carries the page's control header");
  assert.equal(doc.getElementById("files-crumbs").textContent, "~/ws");
  assert.equal(doc.getElementById("lock-path").value, "~/ws/");
  assert.equal(fileRows(doc).length, 4);
  // ONE menu per entry (§4.25p): the labels strictest first.
  assert.deepEqual(([...menuOf(rowFor(doc, /README/)).options] as any[]).slice(1).map((o) => o.value), ["no-model", "local-model", "any-model", "public"]);
  // A rule of yours is the menu's choice; a label from elsewhere shows as inherited; an ordinary file has no rule.
  assert.deepEqual(pressed(rowFor(doc, /^config\//)), ["no-model"]);
  assert.match(rowFor(doc, /^config\//).textContent, /Your rule/);
  assert.match(rowFor(doc, /^config\//).textContent, /1 rule inside/);
  assert.deepEqual(pressed(rowFor(doc, /^\.env/)), [], "a built-in secret is not a rule of yours");
  assert.equal(inherits(rowFor(doc, /^\.env/)), "no-model");
  assert.equal(menuOf(rowFor(doc, /^\.env/)).selectedOptions[0].textContent, "No AI (inherited)");
  assert.match(rowFor(doc, /^\.env/).textContent, /Built in: environment files/);
  assert.deepEqual(pressed(rowFor(doc, /README/)), []);
  assert.equal(inherits(rowFor(doc, /README/)), null);
  assert.equal(menuOf(rowFor(doc, /README/)).selectedOptions[0].textContent, "No rule");
  assert.equal(doc.querySelector("#files-list img"), null, "a file name carrying markup is not parsed");
  assert.equal(doc.getElementById("files-note").hidden, true);
  // Into a folder: an inherited label says where it comes from.
  rowFor(doc, /^config\//).querySelector(".file-open").click();
  await tick();
  assert.match(doc.getElementById("files-self").textContent, /This folder: No AI/);
  assert.match(fileRows(doc)[0].textContent, /From your rule on ~\/ws\/config/);
  // Up again, by breadcrumb.
  [...doc.querySelectorAll("#files-crumbs .crumb")].find((b: any) => b.textContent === "ws").click();
  await tick();
  assert.equal(fileRows(doc).length, 4);
});

test("file browser: hidden files, the filter and 'Hide ordinary files' narrow the list", async () => {
  const { doc } = load({ url: FILES_URL, routes: FILES_ROUTES });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  const hidden = doc.getElementById("files-hidden") as any;
  assert.equal(hidden.checked, true, "hidden files are shown by default: .env and ~/.ssh are what people label");
  hidden.checked = false; hidden.dispatchEvent(new doc.defaultView.Event("change"));
  assert.equal(rowFor(doc, /^\.env/), undefined);
  hidden.checked = true; hidden.dispatchEvent(new doc.defaultView.Event("change"));
  const labeled = doc.getElementById("files-labeled") as any;
  labeled.checked = true; labeled.dispatchEvent(new doc.defaultView.Event("change"));
  assert.deepEqual(fileRows(doc).map((r) => r.querySelector(".file-name").textContent.split(" ")[0]), ["config/", ".env"]);
  labeled.checked = false; labeled.dispatchEvent(new doc.defaultView.Event("change"));
  const filter = doc.getElementById("files-filter") as any;
  filter.value = "READ"; filter.dispatchEvent(new doc.defaultView.Event("input"));
  assert.equal(fileRows(doc).length, 1);
});

test("file browser: ticked entries become pending changes (a folder covers what is inside, a file itself); a weaker change asks, then saves with what was shown", async () => {
  const saves: unknown[] = [];
  const { doc, calls } = load({ url: FILES_URL, routes: { ...FILES_ROUTES,
    "POST files/labels": (b: any) => {
      saves.push(b);
      return b.expected
        ? { applied: true, changeId: "pc-000007", page: 0 }
        : { applied: false, confirm: true, expected: ["paths\u0000/home/u/ws/.env"], loosens: [{ subject: "~/ws/.env", detail: "Becomes Not secret, even where Mandu treats a file as secret by default." }] };
    },
  } });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  assert.equal(bulkBtn(doc, "no-model"), null, "nothing ticked, no bar");
  assert.equal(doc.getElementById("files-selected").hidden, true);
  tickRow(doc, /^config\//);
  tickRow(doc, /^\.env/);
  assert.match(doc.getElementById("files-selected").textContent, /2 items ticked/);
  chooseTicked(doc, "any-model", "api.example.com, ");
  assert.equal(doc.getElementById("files-pending").hidden, false);
  assert.match(doc.getElementById("files-pending-list").textContent, /~\/ws\/config.*No AI → Any AI, when it asks; may be sent to api\.example\.com, and everything inside/);
  assert.match(rowFor(doc, /^\.env/).textContent, /Will be: Any AI, when it asks.*\(not saved\)/);
  assert.deepEqual(pressed(rowFor(doc, /^\.env/)), ["any-model"]);
  assert.equal(waiting(rowFor(doc, /^\.env/)), true, "the menu shows the choice waiting");
  assert.equal(rowFor(doc, /^\.env/).querySelector(".file-tick").checked, true, "ticked rows stay ticked");
  // Change one of them again, in its own menu: the last choice for a path wins.
  dot(doc, /^\.env/, "public");
  assert.equal(doc.querySelectorAll("#files-pending-list li").length, 2);

  doc.getElementById("files-save").click();
  await tick();
  assert.deepEqual(saves[0], { changes: [
    { path: "/home/u/ws/config", level: "any-model", bindings: ["api.example.com"], recursive: true },
    { path: "/home/u/ws/.env", level: "public", recursive: false },
  ], folder: "/home/u/ws" });
  assert.equal(calls.find((c) => c.url.endsWith("/api/files/labels"))!.headers["X-Mandu-Control"], "1");
  assert.equal(doc.getElementById("files-confirm").hidden, false, "a weaker change asks first");
  assert.match(doc.getElementById("files-confirm-list").textContent, /~\/ws\/\.env Becomes Not secret/);
  assert.equal(doc.getElementById("files-save").textContent, "Save anyway");
  (doc.getElementById("files-reason") as any).value = "  test fixture  ";
  doc.getElementById("files-save").click();
  await tick();
  assert.deepEqual((saves[1] as any).expected, ["paths\u0000/home/u/ws/.env"], "sends back exactly what was shown");
  assert.equal((saves[1] as any).reason, "test fixture");
  assert.equal(doc.getElementById("files-pending").hidden, true, "saved: nothing pending");
  assert.match(doc.getElementById("rules-notice").textContent, /2 changes saved\.Undo/);
});

test("file browser: dropping a change after the question asks again; a 409 forgets what was shown", async () => {
  let n = 0;
  const { doc } = load({ url: FILES_URL, routes: { ...FILES_ROUTES,
    "POST files/labels": (b: any) => (++n, b.expected ? { status: 409, body: { error: "Your rules changed while you were deciding. Nothing was changed. Try again." } } : { applied: false, confirm: true, expected: ["k"], loosens: [] }),
  } });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  dot(doc, /^\.env/, "public");
  doc.getElementById("files-save").click();
  await tick();
  assert.equal(doc.getElementById("files-confirm").hidden, false);
  doc.getElementById("files-save").click();
  await tick();
  assert.match(doc.getElementById("lock-error").textContent, /changed while you were deciding/);
  assert.equal(doc.getElementById("files-confirm").hidden, true);
  assert.equal(doc.getElementById("files-save").textContent, "Save changes");
  assert.equal(doc.getElementById("files-pending").hidden, false, "the changes stay pending");
});

// ── Changes to save keeps its buttons in view (dashboard.md §4.25n) ──────────

/** The product page's own styles, applied (jsdom cascades them, `:has()`
 *  included), with the theme's tokens resolved. */
const STYLES = resolveCssVars(readFileSync(join(PUB, "mandu.css"), "utf8") + "\n" + readFileSync(join(PUB, "app.css"), "utf8"));

test("Changes to save: with 32 changes waiting, only its lists scroll; its heading, the question with its Why? and Discard / Save never sit in a scrolling part (§4.25n)", async () => {
  const many = Array.from({ length: 32 }, (_, i) => ({
    path: `/home/u/ws/p${i}/config.yaml`, display: `~/ws/p${i}/config.yaml`, level: i % 2 ? "public" : "no-model",
    bindings: [], recursive: false, before: "Any AI, when it asks", target: null,
  }));
  const weaker = many.filter((_, i) => i % 2).map((p) => ({ path: p.path, display: p.display, before: p.before, after: "Not secret", weaker: true }));
  const impact = { scanned: 32, truncated: false, changed: 32, weaker: weaker.length, files: weaker, decidedBy: {} };
  const { doc } = load({ url: FILES_URL, storage: { "mandu.files.pending": JSON.stringify(many) }, routes: { ...FILES_ROUTES,
    "POST files/impact": { impact, page: 0 },
    "POST files/labels": { applied: false, confirm: true, expected: ["k"], impact, loosens: weaker.map((f) => ({ subject: f.display, detail: "Becomes Not secret." })) },
  } });
  const sheet = doc.createElement("style");
  sheet.textContent = STYLES;
  doc.head.append(sheet);
  await tick();
  const css = (e: any) => doc.defaultView.getComputedStyle(e);
  const box = doc.getElementById("files-pending");
  const list = doc.getElementById("files-pending-list");
  assert.equal(box.hidden, false);
  assert.equal(list.querySelectorAll("li").length, 32);
  assert.ok(box.querySelector("#files-impact details[open]"), "weaker changes open the impact's file list");

  /** The parts of the bar between `e` and the bar that scroll. The bar's own
   *  scroll is only the fallback for a window too short for its fixed parts. */
  const scrollingAbove = (e: any) => {
    const out: string[] = [];
    for (let p = e.parentElement; p && p !== box; p = p.parentElement) {
      if (/^(auto|scroll)$/.test(css(p).overflowY)) out.push(p.id || p.tagName);
    }
    return out;
  };
  const check = (when: string) => {
    assert.equal(css(box).display, "flex", when);
    assert.equal(css(box).flexDirection, "column", when);
    assert.equal(css(box).position, "sticky", `${when}: kept at the window's foot`);
    // The list of changes is the part that scrolls, and it gives way.
    assert.equal(css(list).overflowY, "auto", `${when}: the list scrolls in place`);
    assert.ok(Number(css(list).flexShrink) >= 1, `${when}: the list shrinks to fit the bar`);
    assert.notEqual(css(list).minHeight, "auto", `${when}: the list may shrink below its content`);
    // Everything else the bar holds keeps its size; the impact note may give way too.
    for (const part of [...box.children].filter((c: any) => !c.hidden && c !== list && c.id !== "files-impact")) {
      assert.equal(css(part).flexShrink, "0", `${when}: ${part.id || part.className || part.tagName} keeps its size`);
    }
    const keep = [box.querySelector("h3"), box.querySelector(".form-actions"), doc.getElementById("files-discard"), doc.getElementById("files-save")];
    if (!doc.getElementById("files-confirm").hidden) {
      keep.push(doc.querySelector("#files-confirm > p"), doc.getElementById("files-reason"), doc.getElementById("files-reason").closest("label"));
    }
    for (const e of keep) {
      assert.ok(e, when);
      assert.equal(list.contains(e), false, `${when}: ${e.id || e.tagName} is outside the list`);
      assert.deepEqual(scrollingAbove(e), [], `${when}: ${e.id || e.tagName} never scrolls away`);
      assert.equal(/^(auto|scroll)$/.test(css(e).overflowY), false, `${when}: ${e.id || e.tagName} does not scroll itself`);
    }
    // Keyboard: the bar's controls in reading order, the buttons last.
    const stops = [...box.querySelectorAll("button, input, summary")].filter((e: any) => !e.closest("[hidden]"));
    assert.deepEqual(stops.slice(-2).map((e: any) => e.id), ["files-discard", "files-save"], `${when}: Discard and Save are the last stops`);
    assert.ok(stops.indexOf(list.querySelector("button")) < stops.indexOf(doc.getElementById("files-discard")), when);
  };
  check("waiting");
  assert.match(css(box).maxHeight, /^max\(50vh, /, "waiting, the bar takes at most half the window (or 20rem)");

  // Save asks about the weaker changes: the question stays in view with the buttons.
  doc.getElementById("files-save").click();
  await tick();
  assert.equal(doc.getElementById("files-confirm").hidden, false, "a weaker change asks first");
  assert.equal(doc.getElementById("files-save").textContent, "Save anyway");
  assert.equal(doc.querySelectorAll("#files-confirm-list li").length, 16);
  check("asking");
  assert.equal(css(box).maxHeight, "calc(100dvh - 24px)", "while asking, the bar may take the window's height");
  for (const l of [doc.getElementById("files-confirm-list"), doc.querySelector("#files-confirm-files ul")]) {
    assert.equal(css(l).overflowY, "auto", "the question's own lists scroll in place");
    assert.notEqual(css(l).maxHeight, "none", "within a height");
  }
  const stops = [...box.querySelectorAll("button, input, summary")].filter((e: any) => !e.closest("[hidden]")).map((e: any) => e.id);
  assert.deepEqual(stops.slice(-3), ["files-reason", "files-discard", "files-save"], "Why? comes before the buttons");
});

test("file browser: Remove my rule is offered only for the person's own rule on that path, and sends level null", async () => {
  const saves: any[] = [];
  const { doc } = load({ url: FILES_URL, routes: { ...FILES_ROUTES, "POST files/labels": (b: any) => (saves.push(b), { applied: true, changeId: null, page: 1 }) } });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  openRow(doc, /^\.env/);
  assert.equal(doc.getElementById("files-unset"), null, "a built-in secret has no rule of the person's to remove");
  tickRow(doc, /^\.env/);
  assert.equal(doc.getElementById("files-bulk-unset"), null, "nor from the bar");
  const env = rowFor(doc, /^\.env/).querySelector("input[type=checkbox]");
  env.checked = false; env.dispatchEvent(new doc.defaultView.Event("change"));
  tickRow(doc, /^config\//);
  assert.ok(doc.getElementById("files-bulk-unset"));
  openRow(doc, /^config\//);
  assert.ok(doc.getElementById("files-unset"));
  doc.getElementById("files-unset").click();
  assert.match(doc.getElementById("files-pending-list").textContent, /No rule of its own/);
  doc.getElementById("files-save").click();
  await tick();
  assert.deepEqual(saves[0], { changes: [{ path: "/home/u/ws/config", level: null, recursive: true }], folder: "/home/u/ws" });
  assert.match(doc.getElementById("rules-notice").textContent, /1 change saved\./);
});

test("file browser: a typed folder opens, a file opens its folder with it opened, a missing path or a pattern can be chosen; a relative path is refused", async () => {
  const saves: any[] = [];
  const { doc } = load({ url: FILES_URL, routes: { ...FILES_ROUTES,
    [list("~/ws/config")]: CONFIG_LIST,
    [list("~/ws/.env")]: { status: 400, body: { error: "That is a file, not a folder.", path: "/home/u/ws/.env", file: true } },
    [list("~/new/plans")]: { status: 404, body: { error: "That folder does not exist. Use ~ to go to your home folder.", path: "/home/u/new/plans" } },
    "POST files/labels": (b: any) => (saves.push(b), { applied: true, changeId: null, page: 0 }),
  } });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  const go = (v: string) => { (doc.getElementById("lock-path") as any).value = v; doc.getElementById("files-go").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true })); };
  go("relative/path");
  await tick();
  assert.match(doc.getElementById("files-note").textContent, /full path/);
  go("~/ws/config");
  await tick();
  assert.equal(doc.getElementById("files-crumbs").textContent, "~/ws/config");
  go("~/ws/.env");
  await tick(20);
  assert.equal(doc.getElementById("files-crumbs").textContent, "~/ws");
  assert.equal(rowFor(doc, /^\.env/).classList.contains("open"), true, "the typed file is opened in its folder");
  assert.equal(rowFor(doc, /^\.env/).nextElementSibling.classList.contains("file-detail"), true);
  go("~/new/plans");
  await tick();
  assert.match(fileRows(doc)[0].textContent, /~\/new\/plans.*Not there yet/);
  assert.match(opened(doc).textContent, /A folder's rule covers everything inside it/, "a typed path opens, its notes in view");
  choose(fileRows(doc)[0], "no-model");
  go("**/*.pem");
  await tick();
  assert.match(fileRows(doc)[0].textContent, /\*\*\/\*\.pem.*Every file that matches/);
  choose(fileRows(doc)[0], "no-model");
  doc.getElementById("files-save").click();
  await tick();
  assert.deepEqual(saves[0].changes, [
    { path: "/home/u/new/plans", level: "no-model", recursive: true },
    { path: "**/*.pem", level: "no-model" },
  ]);
});

test("file browser: Tab finishes the name being typed from the folder's entries", async () => {
  const { doc } = load({ url: FILES_URL, routes: FILES_ROUTES });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  const input = doc.getElementById("lock-path") as any;
  input.value = "/home/u/ws/co";
  input.setSelectionRange(input.value.length, input.value.length);
  input.dispatchEvent(new doc.defaultView.KeyboardEvent("keydown", { key: "Tab", cancelable: true }));
  await tick();
  assert.equal(input.value, "/home/u/ws/config/", "one match, a folder: finished with a slash");
  input.value = "~/ws/.e";
  input.setSelectionRange(input.value.length, input.value.length);
  input.dispatchEvent(new doc.defaultView.KeyboardEvent("keydown", { key: "Tab", cancelable: true }));
  await tick();
  assert.equal(input.value, "~/ws/.env");
});

test("file browser: labels that could not be read show as unknown, never as ordinary; the axis being off is said", async () => {
  const unknown = { ...WS_LIST, labels: "unknown", labelError: "the protection service did not answer (down)", axis: null, self: null, entries: WS_LIST.entries.map((e) => ({ ...e, label: null })) };
  const { doc } = load({ url: FILES_URL, routes: { [list("/home/u/ws")]: unknown } });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  assert.match(doc.getElementById("files-note").textContent, /Labels could not be read: the protection service did not answer \(down\)/);
  for (const r of fileRows(doc)) assert.match(r.textContent, /Label unknown/);
  assert.doesNotMatch(doc.getElementById("files-list").textContent, /Like any other file/);
  const off = load({ url: FILES_URL, routes: { [list("/home/u/ws")]: { ...WS_LIST, axis: false } } });
  await tick();
  off.doc.getElementById("rules-add").click();
  await tick();
  assert.match(off.doc.getElementById("files-note").textContent, /^Protection is off\. These rules take effect when you turn it on in Settings\.$/);
});

const LINKED = { ...WS_LIST, entries: [...WS_LIST.entries, {
  name: "key-link", path: "/home/u/ws/key-link", display: "~/ws/key-link", kind: "file", link: "~/secrets/key", target: "/home/u/secrets/key",
  label: NONE, targetLabel: chip("no-model", "No AI", "yours", "Your rule", true), inside: 0,
}] };
const IMPACT = { impact: { scanned: 7, truncated: false, changed: 2, weaker: 1,
  files: [{ path: "/home/u/ws/.env", display: "~/ws/.env", before: "No AI", after: "Not secret", weaker: true },
          { path: "/home/u/ws/README.md", display: "~/ws/README.md", before: "Not secret", after: "No AI", weaker: false }],
  decidedBy: { "**/*.pem": { count: 2, sample: ["~/ws/a.pem", "~/ws/b.pem"] } } }, page: 0 };

test("file browser: a symlink says how the file it points to is treated, and a rule chosen for it covers that file too", async () => {
  const { doc } = load({ url: FILES_URL, routes: { [list("/home/u/ws")]: LINKED, "POST files/impact": IMPACT } });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  const row = rowFor(doc, /^key-link/);
  assert.match(row.textContent, /→ ~\/secrets\/key/);
  assert.match(row.textContent, /The file it points to: No AI/);
  openRow(doc, /^key-link/);
  assert.match(opened(doc).textContent, /A link gets the rule, and so does the file it points to\./);
  tickRow(doc, /^key-link/);
  assert.match(doc.getElementById("files-selected").textContent, /A link gets the rule, and so does the file it points to\./);
  chooseTicked(doc, "no-model");
  assert.match(doc.getElementById("files-pending-list").textContent, /and the file it points to \(~\/secrets\/key\)/);
});

test("file browser: pending changes say what they would do to the files under them, and the question names the weaker files", async () => {
  const { doc, calls } = load({ url: FILES_URL, routes: { ...FILES_ROUTES, "POST files/impact": IMPACT,
    "POST files/labels": { applied: false, confirm: true, expected: ["k"], loosens: [{ subject: "~/ws", detail: "Becomes Not secret." }], impact: IMPACT.impact } } });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  dot(doc, /^config\//, "public");
  await tick();
  const ask = calls.find((c) => c.url.endsWith("/api/files/impact"))!;
  assert.deepEqual(ask.body, { changes: [{ path: "/home/u/ws/config", level: "public", recursive: true }], folder: "/home/u/ws" });
  const box = doc.getElementById("files-impact");
  assert.equal(box.hidden, false);
  assert.match(box.textContent, /Changes the label of 2 files, 1 of them less protected\./);
  assert.match(box.textContent, /~\/ws\/\.env No AI → Not secret/);
  assert.equal(box.querySelector("details").open, true, "weaker files are shown open");
  doc.getElementById("files-save").click();
  await tick();
  const reach = doc.getElementById("files-confirm-files");
  assert.equal(reach.hidden, false);
  assert.match(reach.textContent, /Files that become less protected:~\/ws\/\.env No AI → Not secret/);
  assert.doesNotMatch(reach.textContent, /README/, "only the weaker ones are in the question");
});

test("file browser: a typed pattern shows which files it would decide under the folder shown", async () => {
  const { doc, calls } = load({ url: FILES_URL, routes: { ...FILES_ROUTES, "POST files/impact": IMPACT } });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  (doc.getElementById("lock-path") as any).value = "**/*.pem";
  doc.getElementById("files-go").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
  await tick();
  assert.deepEqual(calls.find((c) => c.url.endsWith("/api/files/impact"))!.body, { changes: [{ path: "**/*.pem", level: "no-model" }], folder: "/home/u/ws" });
  assert.match(fileRows(doc)[0].textContent, /Matches 2 files under ~\/ws: ~\/ws\/a\.pem, ~\/ws\/b\.pem/);
});

test("file browser: opening a labeled file shows what the rules say about it under its row, as text; an ordinary file asks nothing", async () => {
  const WHY = { why: { path: "/home/u/ws/.env", display: "~/ws/.env", label: WS_LIST.entries[1]!.label, off: false, lines: [
    { term: "Where the label comes from", text: "Built in: environment files" },
    { term: "Programs that get the real file", text: "<b>node</b>" },
    { term: "May be sent to", text: "Nowhere without your OK." },
  ] } };
  const { doc, calls } = load({ url: FILES_URL, routes: { ...FILES_ROUTES, [`GET files/why?path=${encodeURIComponent("/home/u/ws/.env")}`]: WHY } });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  openRow(doc, /README/);
  await tick();
  assert.equal(rowFor(doc, /README/).nextElementSibling, opened(doc), "the opened row sits under it");
  assert.match(opened(doc).textContent, /README\.md.*Like any other file/);
  assert.equal(opened(doc).querySelector(".file-why"), null, "an ordinary file has nothing to explain");
  assert.equal(calls.filter((c) => c.url.includes("/api/files/why")).length, 0);
  openRow(doc, /^\.env/);
  await tick();
  assert.equal(rowFor(doc, /^\.env/).classList.contains("open"), true);
  assert.equal(rowFor(doc, /README/).classList.contains("open"), false, "one row is open at a time");
  assert.equal(doc.querySelectorAll("#files-list .file-detail").length, 1);
  const get = calls.find((c) => c.url.includes("/api/files/why"))!;
  assert.equal(get.headers["X-Mandu-Control"], "1");
  const panel = opened(doc).querySelector(".file-why");
  assert.match(panel.textContent, /Programs that get the real file<b>node<\/b>/, "server text lands as text");
  assert.equal(panel.querySelector("b"), null);
  // Asked once per path; a second click closes the row.
  openRow(doc, /README/);
  openRow(doc, /^\.env/);
  await tick();
  openRow(doc, /^\.env/);
  assert.equal(opened(doc), null, "closed again");
  assert.equal(calls.filter((c) => c.url.includes("/api/files/why")).length, 1);
});

test("file browser: pending changes are kept across a reload in this browser, and cleared by Discard", async () => {
  const a = load({ url: FILES_URL, routes: FILES_ROUTES });
  await tick();
  a.doc.getElementById("rules-add").click();
  await tick();
  dot(a.doc, /^\.env/, "any-model");
  const kept = a.window.localStorage.getItem("mandu.files.pending");
  assert.ok(kept);
  const b = load({ url: FILES_URL, routes: FILES_ROUTES, storage: { "mandu.files.pending": kept } });
  await tick();
  b.doc.getElementById("rules-add").click();
  await tick();
  assert.match(b.doc.getElementById("files-pending-list").textContent, /~\/ws\/\.env.*Any AI, when it asks/);
  b.doc.getElementById("files-discard").click();
  assert.equal(b.window.localStorage.getItem("mandu.files.pending"), null);
  assert.equal(b.doc.getElementById("files-pending").hidden, true);
});

test("file browser: the arrow keys move between rows, Right opens a folder, Left goes up", async () => {
  const { doc } = load({ url: FILES_URL, routes: { ...FILES_ROUTES, [list("/home/u")]: { ...WS_LIST, path: "/home/u", display: "~", parent: "/home", crumbs: [{ name: "~", path: "/home/u" }] } } });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  const key = (target: any, k: string) => target.dispatchEvent(new doc.defaultView.KeyboardEvent("keydown", { key: k, bubbles: true, cancelable: true }));
  const up = doc.querySelector("#files-list .row.file.up");
  up.focus();
  key(up, "ArrowDown");
  assert.equal(doc.activeElement, rowFor(doc, /^config\//).querySelector(".file-tick"));
  key(doc.activeElement, "ArrowDown");
  assert.equal(doc.activeElement, rowFor(doc, /^\.env/).querySelector(".file-tick"));
  key(doc.activeElement, "ArrowUp");
  key(doc.activeElement, "ArrowRight");
  await tick();
  assert.equal(doc.getElementById("files-crumbs").textContent, "~/ws/config");
  assert.equal(doc.activeElement.classList.contains("row"), true, "focus lands in the opened folder");
  key(doc.activeElement, "ArrowLeft");
  await tick();
  assert.equal(doc.getElementById("files-crumbs").textContent, "~/ws");
});

test("file browser: typing fills the suggestions list with the folder's matching names", async () => {
  const { doc } = load({ url: FILES_URL, routes: FILES_ROUTES });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  const input = doc.getElementById("lock-path") as any;
  input.value = "/home/u/ws/";
  input.dispatchEvent(new doc.defaultView.InputEvent("input", { inputType: "insertText", data: "/" }));
  await tick();
  const opts = [...doc.querySelectorAll("#files-suggest option")].map((o: any) => o.value);
  assert.deepEqual(opts, ["/home/u/ws/config/", "/home/u/ws/.env", "/home/u/ws/<img src=x onerror=alert(1)>.md", "/home/u/ws/README.md"]);
});

test("file browser: rules made on this page earlier can be moved into policy.yaml in one step, after a confirmation", async () => {
  const { doc, calls, window } = load({ url: FILES_URL, routes: { ...FILES_ROUTES, "POST files/move-page-rules": { moved: 1, changeId: "pc-000009" } } });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  const box = doc.getElementById("files-move");
  assert.equal(box.hidden, false);
  assert.match(box.textContent, /1 rule was made on this page before rules were kept in policy\.yaml/);
  let asked = "";
  window.confirm = (q: string) => { asked = q; return false; };
  box.querySelector("button").click();
  await tick();
  assert.match(asked, /Protection does not change/);
  assert.equal(calls.filter((c) => c.url.endsWith("/api/files/move-page-rules")).length, 0, "declined: nothing moved");
  window.confirm = () => true;
  box.querySelector("button").click();
  await tick();
  const post = calls.find((c) => c.url.endsWith("/api/files/move-page-rules"))!;
  assert.equal(post.headers["X-Mandu-Control"], "1");
  assert.match(doc.getElementById("rules-notice").textContent, /Moved 1 rule into policy\.yaml\./);
});

test("file browser: a listing refused for want of the admin session says so", async () => {
  const { doc } = load({ url: FILES_URL, routes: { [list("/home/u/ws")]: { status: 403, body: { error: "open the admin link first" } }, [list("~")]: { status: 403, body: { error: "open the admin link first" } } } });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  assert.match(doc.getElementById("files-note").textContent, /open the admin link first/);
});

// ── A save names the rules as they were read (dashboard.md §4.25m) ─────────

test("file browser: a change names the version of its path's rule as listed; refused because that rule changed meanwhile, it says so, keeps the choice, reads again and saves against the rule as it is now", async () => {
  const V1 = "1".repeat(32);
  const V2 = "2".repeat(32);
  const ABSENT = "0".repeat(32);
  const words = "~/ws/config was changed somewhere else while you were choosing, so nothing was saved. Your choice still waits in Changes to save: look at the label as it is now, then save again.";
  const versioned = (v: string) => ({ ...WS_LIST, entries: WS_LIST.entries.map((e) => ({ ...e, version: e.name === "config" ? v : ABSENT })) });
  let lists = 0;
  const saves: any[] = [];
  const { doc } = load({ url: FILES_URL, routes: { ...FILES_ROUTES,
    // The second listing finds config's rule changed by someone else.
    [list("/home/u/ws")]: () => (++lists === 1 ? versioned(V1) : { ...versioned(V2), entries: versioned(V2).entries.map((e) => (e.name === "config" ? { ...e, label: chip("local-model", "Your own AI only", "yours", "Your rule", true) } : e)) }),
    "POST files/labels": (b: any) => {
      saves.push(b);
      return saves.length === 1
        ? { status: 409, body: { error: words, stale: true, changed: ["paths /home/u/ws/config"] } }
        : { applied: true, changeId: "pc-000008", page: 0 };
    },
  } });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  dot(doc, /^config\//, "any-model");
  dot(doc, /README/, "no-model");
  doc.getElementById("files-save").click();
  await tick();
  assert.deepEqual(saves[0].changes.map((c: any) => [c.path, c.version]), [["/home/u/ws/config", V1], ["/home/u/ws/README.md", ABSENT]],
    "each change names its path's rule as listed (none of its own: the absent version)");
  assert.equal(doc.getElementById("lock-error").textContent, words, "said in the page's words");
  assert.equal(lists, 2, "the folder is read again");
  assert.deepEqual(pressed(rowFor(doc, /^config\//)), ["any-model"], "the choice still waits");
  assert.equal(waiting(rowFor(doc, /^config\//)), true);
  assert.match(rowFor(doc, /^config\//).textContent, /Your rule/);
  assert.equal(doc.querySelectorAll("#files-pending-list li").length, 2, "both changes still wait");
  assert.equal(doc.getElementById("files-pending").hidden, false);

  doc.getElementById("files-save").click();
  await tick();
  assert.deepEqual(saves[1].changes.map((c: any) => [c.path, c.version]), [["/home/u/ws/config", V2], ["/home/u/ws/README.md", ABSENT]],
    "the next Save names the rule as it is now");
  assert.equal(doc.getElementById("files-pending").hidden, true, "saved");
});

test("§4.25p a menu says its words whole: an inherited label's second menu shows its choice with no suffix, greyed with a ring, and its tooltip and name say which rule it follows; a rule of your own is unchanged; Per value likewise", async () => {
  const inherited = (name: string, extra: object) => ({
    name, path: `/home/u/ws/notes/${name}`, display: `~/ws/notes/${name}`, kind: "file", link: null, inside: 0,
    label: { ...chip("no-model", "No AI", "inherited", "From your rule on ~/ws/notes"), ...extra },
  });
  const notes = {
    ...WS_LIST, path: "/home/u/ws/notes", display: "~/ws/notes", parent: "/home/u/ws",
    crumbs: [...WS_LIST.crumbs, { name: "notes", path: "/home/u/ws/notes" }],
    self: { ...chip("no-model", "No AI", "yours", "Your rule", true), bindings: ["api.example.com"] },
    entries: [
      inherited("contract.md", { bindings: ["api.example.com"] }),
      inherited("draft.md", {}),
      inherited("app.env", { values: [{ key: "STRIPE_KEY", bindings: ["api.stripe.com"] }], send: "STRIPE_KEY may be sent only to api.stripe.com.", sendParts: [] }),
      { name: "mine.md", path: "/home/u/ws/notes/mine.md", display: "~/ws/notes/mine.md", kind: "file", link: null, inside: 0, label: { ...chip("no-model", "No AI", "yours", "Your rule", true), bindings: ["api.example.com"] } },
      { name: "key.pem", path: "/home/u/ws/notes/key.pem", display: "~/ws/notes/key.pem", kind: "file", link: null, inside: 0, label: chip("no-model", "No AI", "builtin", "Built in: private keys") },
    ],
    total: 5,
  };
  const { doc } = load({ url: FILES_URL, routes: { ...FILES_ROUTES, [list("~/ws/notes")]: notes } });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  (doc.getElementById("lock-path") as any).value = "~/ws/notes";
  doc.getElementById("files-go").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
  await tick();
  assert.equal(doc.getElementById("files-crumbs").textContent, "~/ws/notes", "the browser shows the folder");
  const sendOf = (r: any) => r.querySelector("select.send-select") as any;
  const shown = (r: any) => sendOf(r).selectedOptions[0].textContent;

  // Listed hosts, inherited: the whole choice, greyed, a ring, and the rule.
  const contract = rowFor(doc, /^contract\.md/);
  assert.equal(shown(contract), "Listed hosts without asking", "no \"(inherited)\": it cut the menu");
  assert.ok(![...sendOf(contract).options].some((o: any) => /inherited/.test(o.textContent)), "no choice carries the word");
  assert.equal(sendOf(contract).disabled, true, "greyed: it is changed on the folder's rule");
  assert.equal(contract.querySelector(".send-pick").getAttribute("data-from"), "hosts", "the dot is a ring");
  const words = "Where ~/ws/notes/contract.md may be sent: listed hosts without asking. From your rule on ~/ws/notes. Change it there.";
  assert.equal(sendOf(contract).getAttribute("aria-label"), words, "its accessible name names the rule it follows");
  assert.equal(sendOf(contract).title, words, "and so does its tooltip");
  assert.equal(menuOf(contract).selectedOptions[0].textContent, "No AI (inherited)", "the first menu keeps the word");
  assert.match(contract.textContent, /From your rule on ~\/ws\/notes/, "the row's line under the name says it too");
  assert.deepEqual([...contract.querySelectorAll(".host-chip.from")].map((c: any) => c.textContent), ["api.example.com"]);

  // Needs your OK, inherited.
  const draft = rowFor(doc, /^draft\.md/);
  assert.equal(shown(draft), "Needs your OK");
  assert.equal(sendOf(draft).getAttribute("aria-label"), "Where ~/ws/notes/draft.md may be sent: needs your OK. From your rule on ~/ws/notes. Change it there.");

  // A built-in secret: where it comes from, with no rule of yours to change.
  const key = rowFor(doc, /^key\.pem/);
  assert.equal(shown(key), "Needs your OK");
  assert.equal(sendOf(key).getAttribute("aria-label"), "Where ~/ws/notes/key.pem may be sent: needs your OK. Built in: private keys.");

  // Per value, inherited: the same, with where the values change.
  const env = rowFor(doc, /^app\.env/);
  assert.deepEqual([...sendOf(env).options].map((o: any) => o.textContent), ["Per value"]);
  assert.equal(sendOf(env).disabled, true);
  assert.equal(env.querySelector(".send-pick").getAttribute("data-from"), "values");
  const each = "Where ~/ws/notes/app.env may be sent: per value. From your rule on ~/ws/notes. Each value has its own hosts. Change them in policy.yaml.";
  assert.equal(sendOf(env).getAttribute("aria-label"), each);
  assert.equal(sendOf(env).title, each);

  // A rule of your own: the menu as it was.
  const mine = rowFor(doc, /^mine\.md/);
  assert.equal(shown(mine), "Listed hosts without asking");
  assert.equal(sendOf(mine).disabled, false);
  assert.equal(mine.querySelector(".send-pick").hasAttribute("data-from"), false, "a solid dot");
  assert.equal(sendOf(mine).getAttribute("aria-label"), "Where ~/ws/notes/mine.md may be sent");
  assert.equal(sendOf(mine).title, "");
});
