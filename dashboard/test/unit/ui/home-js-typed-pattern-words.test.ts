/**
 * home-js-typed-pattern-words.test — on the PRODUCT page's Rules › Add a
 * rule, a typed pattern the protection service cannot use says why on its
 * own row (dashboard.md §4.25 "Refusals", *A typed pattern says why on its
 * row*).
 *
 * A typed pattern's row is worked out as it is drawn (`previewPattern`, POST
 * files/impact). The service refuses a pattern it cannot use with 422
 * "withEdits: paths[N].path: pattern "<path>": <why>" (arbiter
 * `pathLevels`). Until 2026-10-15 the row said only "Which files it matches
 * could not be worked out.", and the reason came only after a label was
 * chosen (Changes to save) or Save pressed. Pins, in jsdom over the shared
 * fetch stub (home-js-fixtures.ts):
 *
 *   - the reason alone, after "Mandu cannot use this pattern:", on the row
 *     and in the opened row; never the file's place or "withEdits";
 *   - several problems one after the other, a "; " inside one kept;
 *   - a problem about another path, or a page that shows the pattern
 *     otherwise (no home folder), keeps the path as the page shows paths; a
 *     problem of another shape without its place;
 *   - any other refusal names its cause as the line under Changes to save
 *     does: the server's error after a colon (one full stop), the page's own
 *     words as their own sentence (the Settings link, the command as code),
 *     the hedge with no cause;
 *   - a pattern it can use: what it matches, as before.
 *
 * tests/stack/product-typed-pattern-words.test.ts pins the match to the
 * real arbiter's lines. Axes: none (display only).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick, FILES_URL, FILES_ROUTES, fileRows, openRow, opened } from "./home-js-fixtures.js";
import { ADMIN_SESSION_REQUIRED } from "../../../src/server.js";

const UNCLOSED = `'[' in '[draft' is never closed (a literal '[' is '\\[')`;
const EVERY = "the pattern matches every path on the machine; label a directory instead";

/** files/impact refused as the arbiter refuses a change it cannot make. */
const withEdits = (...problems: string[]) => ({ status: 422, body: { error: "withEdits: " + problems.join("; ") } });

/** Rules › Add a rule: type `typed` in the path box and go; the typed row. */
async function typePattern(impact: unknown, typed: string, opts: { homeDir?: string | null } = {}) {
  const page = load({ url: FILES_URL, routes: { ...FILES_ROUTES, "POST files/impact": impact }, ...opts });
  const { doc } = page;
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  (doc.getElementById("lock-path") as any).value = typed;
  doc.getElementById("files-go").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
  await tick();
  const row = fileRows(doc)[0];
  assert.equal(row.querySelector(".file-name").textContent, typed, "the typed row is first");
  return { ...page, row };
}
/** The row's lines under its name. */
const lines = (row: any) => [...row.querySelectorAll(".file-from")].map((e: any) => e.textContent);

test("a typed pattern the service cannot use says why on its row, the reason alone; the opened row says the same", async () => {
  const { doc, row, calls } = await typePattern(withEdits(`paths[1].path: pattern "/home/u/notes/[draft": ${UNCLOSED}`), "~/notes/[draft");
  const sent = calls.filter((c) => c.method === "POST" && c.url === "/mandu/api/files/impact");
  assert.equal(sent.length, 1);
  assert.deepEqual((sent[0]!.body as { changes: unknown }).changes, [{ path: "~/notes/[draft", level: "no-model" }], "the request is as before");
  assert.deepEqual(lines(row), ["Every file that matches", `Mandu cannot use this pattern: ${UNCLOSED}.`]);
  assert.doesNotMatch(row.textContent, /paths\[|withEdits|could not be worked out/, "never the file's place, the service's terms or the hedge");
  assert.equal(opened(doc).querySelector(".detail-note").textContent, `Mandu cannot use this pattern: ${UNCLOSED}.`, "the row opens as it is typed, and says the same");
  openRow(doc, /\[draft/);
  await tick();
  assert.equal(opened(doc), null, "closed");
  openRow(doc, /\[draft/);
  await tick();
  assert.equal(opened(doc).querySelector(".detail-note").textContent, `Mandu cannot use this pattern: ${UNCLOSED}.`, "opened again, the same");
});

test("several problems one after the other, each problem's own '; ' kept", async () => {
  const { row } = await typePattern(withEdits(
    `paths[1].path: pattern "/**": ${EVERY}`,
    `paths[1].path: pattern "/**": '**' must be a whole path segment (got 'x**'); inside a segment use a single '*'`,
  ), "/**");
  assert.equal(lines(row)[1], `Mandu cannot use this pattern: ${EVERY}; '**' must be a whole path segment (got 'x**'); inside a segment use a single '*'.`);
});

test("a problem about another path keeps its path as the page shows it; one of another shape loses its place; a page with no home folder shows the path as written", async () => {
  const other = await typePattern(withEdits(
    `paths[1].path: pattern "/home/u/other/[x": '[' in '[x' is never closed (a literal '[' is '\\[')`,
    "edits[0] (lock-path): cannot lock /home/u/ws/gone",
  ), "~/ws/*.md");
  assert.equal(lines(other.row)[1], "Mandu cannot use this pattern: ~/other/[x: '[' in '[x' is never closed (a literal '[' is '\\['); cannot lock ~/ws/gone.");
  const noHome = await typePattern(withEdits(`paths[1].path: pattern "/home/u/notes/[draft": ${UNCLOSED}`), "~/notes/[draft", { homeDir: null });
  assert.equal(lines(noHome.row)[1], `Mandu cannot use this pattern: /home/u/notes/[draft: ${UNCLOSED}.`, "the page cannot tell it is the typed one, so it names the path");
});

test("any other refusal names its cause as the line under Changes to save does; with none, the hedge", async () => {
  const said = async (impact: unknown) => {
    const { row, doc } = await typePattern(impact, "~/notes/[draft");
    return { text: lines(row)[1], row, doc };
  };
  assert.equal((await said({ status: 502, body: { error: "the protection service did not answer" } })).text,
    "Which files it matches could not be worked out: the protection service did not answer.");
  assert.equal((await said({ status: 500, body: { error: "the folder is too large to check." } })).text,
    "Which files it matches could not be worked out: the folder is too large to check.", "one full stop");
  assert.equal((await said({ status: 422, body: { error: "not a list of changes" } })).text,
    "Which files it matches could not be worked out: not a list of changes.", "a 422 that is not the service's problems keeps its words");
  assert.equal((await said({ status: 502, body: { error: `withEdits: paths[1].path: pattern "/x": y` } })).text,
    `Which files it matches could not be worked out: withEdits: paths[1].path: pattern "/x": y.`, "only a 422 is read as the service's problems");
  const down = await said({ status: 503, body: { error: "arbiter unreachable; start it under Services", unreachable: true } });
  assert.equal(down.text, "Which files it matches could not be worked out. The protection service is not running. Start it under Settings, or try again in a moment.");
  assert.equal(down.row.querySelector(".file-from a")?.textContent, "Start it under Settings", "the page's own words keep their link");
  const note = opened(down.doc).querySelector(".detail-note");
  assert.equal(note.textContent, down.text, "the opened row says the same");
  assert.equal(note.querySelector("a")?.textContent, "Start it under Settings", "with the link");
  const out = await said({ status: 403, body: { error: ADMIN_SESSION_REQUIRED } });
  assert.match(out.text, /^Which files it matches could not be worked out\. Sign in first: reload this page and sign in with your dashboard account/);
  assert.equal(out.row.querySelector(".file-from code")?.textContent, "mandu dashboard --set-password", "the command as code");
  assert.equal((await said({ status: 500, body: null })).text, "Which files it matches could not be worked out.", "no cause: the hedge");
  assert.equal((await said(() => { throw new Error("offline"); })).text,
    "Which files it matches could not be worked out. The dashboard could not reach its own server. Refresh in a moment.", "no answer at all");
});

test("a pattern the service can use says what it matches, as before", async () => {
  const { row } = await typePattern({ impact: { scanned: 4, truncated: false, changed: 0, weaker: 0, files: [],
    decidedBy: { "/home/u/ws/*.md": { count: 2, sample: ["~/ws/a.md", "~/ws/b.md"] }, "/home/u/ws/.env": { count: 1, sample: ["~/ws/.env"] } } } }, "~/ws/*.md");
  assert.match(lines(row)[1]!, /^Matches 2 files under .*: ~\/ws\/a\.md, ~\/ws\/b\.md$/);
  const none = await typePattern({ impact: { scanned: 4, truncated: false, changed: 0, weaker: 0, files: [], decidedBy: {} } }, "~/ws/*.md");
  assert.match(lines(none.row)[1]!, /^Matches no file under .* yet\.$/);
});
