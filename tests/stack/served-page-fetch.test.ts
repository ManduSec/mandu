/**
 * served-page-fetch — a stack test that runs a served page in jsdom in its
 * own process fetches from the servers only through the dashboard's
 * `pageFetch` (dashboard/test/unit/page-fetch.ts), never the global fetch.
 *
 * jsdom runs a page's script synchronously in the test's process, the
 * dashboard's too, so on a loaded guest the event loop stays blocked for
 * seconds. A fetch made right after it (the page's own, or the test's next
 * read of the server) is put by the global fetch's pool on an idle
 * keep-alive socket, and the server's keep-alive timer, run first after
 * the block, closes it under the request: "fetch failed" in
 * inspector-agent-version (pipelines 10295, 10308) and in the served-page
 * harness (10380). `pageFetch` opens a socket of its own per request
 * (test-organization.md §8.4). Axes: none (a scan of the test sources).
 * Mandu-new test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const STACK = fileURLToPath(new URL(".", import.meta.url));
/** A file that runs a served page in jsdom: its own JSDOM, or a harness. */
const RUNS_A_PAGE = /new JSDOM\(|app-js-harness|served-page|served-inspector|home-js-fixtures/;

test("a stack test that runs a served page in jsdom calls no global fetch", () => {
  const files = readdirSync(STACK).filter((f) => f.endsWith(".ts") && f !== "served-page-fetch.test.ts")
    .map((f) => ({ f, src: readFileSync(join(STACK, f), "utf8") }))
    .filter(({ src }) => RUNS_A_PAGE.test(src));
  assert.ok(files.length >= 50, `the scan finds the files (${files.length})`);
  const offenders = files.filter(({ src }) => /(?<![\w.])fetch\(/.test(src)).map(({ f }) => f);
  assert.deepEqual(offenders, [], "each fetches through pageFetch (dashboard/test/unit/page-fetch.ts)");
});
