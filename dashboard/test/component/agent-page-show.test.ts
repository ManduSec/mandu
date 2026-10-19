/**
 * agent-page-show.test — dashboard.md §4.25ad over the real server and the
 * fixture sessions: `/api/home/agent` lifts the caps the page asks it to
 * (`turns=all`, `secrets=all`, `steps=<turn id>`) and says so, under the same
 * read gate as the page itself (originals only with the admin session); and
 * a build without the developer view (`extensions: []`) serves an agent page
 * and a Settings service line whose words point to no detailed trace, while
 * the full build's still do.
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { DashboardServer } from "../../src/server.js";
import { FileEventSource } from "../../src/event-source.js";
import { ADMIN_OPTS, CSRF_ADMIN } from "../unit/admin-session.js";

const FIXTURES_DIR = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..", "fixtures");
/** The fixture session where something reached the AI unmasked. */
const BAD = "sess-bad9";

const servers: DashboardServer[] = [];
let full: string;
let bare: string;

async function start(opts: Partial<ConstructorParameters<typeof DashboardServer>[0]>): Promise<string> {
  const s = new DashboardServer({ ...ADMIN_OPTS, source: new FileEventSource(FIXTURES_DIR), log: () => {}, ...opts });
  servers.push(s);
  return `http://127.0.0.1:${await s.listen(0)}`;
}

before(async () => {
  // The full build: an extension named `inspector` is what the server reads
  // as the developer view (its pages are another test's).
  full = await start({ extensions: [{ name: "inspector", mount: "/dev", handle: () => {} }] });
  bare = await start({ extensions: [] });
});

after(async () => {
  for (const s of servers) await s.close();
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function page(base: string, query: string, admin = true): Promise<any> {
  const r = await fetch(`${base}/api/home/agent?session=${BAD}${query}`, admin ? { headers: CSRF_ADMIN } : {});
  assert.equal(r.status, 200, query);
  return r.json();
}

test("the caps the page asks to lift are lifted and said; anything else is the caps", async () => {
  const capped = await page(full, "");
  assert.equal(capped.found, true);
  for (const k of ["allTurns", "allSecrets"]) assert.equal(k in capped, false, k);
  const all = await page(full, `&turns=all&secrets=all&steps=${encodeURIComponent(capped.story[0]?.id ?? "turn:start")}`);
  assert.equal(all.allTurns, true);
  assert.equal(all.allSecrets, true);
  assert.equal(all.earlier, 0);
  assert.equal(all.secrets.more, 0);
  // A short turn shows every step already: nothing was lifted, nothing said.
  assert.ok(all.story.every((t: { allSteps?: true }) => t.allSteps === undefined));
  // The same story either way: the fixture is under every cap.
  assert.deepEqual(all.story, capped.story);
  assert.deepEqual({ blocked: all.blocked, sent: all.sent, counts: all.secrets.counts }, { blocked: capped.blocked, sent: capped.sent, counts: capped.secrets.counts });
  const odd = await page(full, "&turns=1&secrets=true&all=1");
  for (const k of ["allTurns", "allSecrets"]) assert.equal(k in odd, false, k);
});

test("the read gate holds with the caps lifted: signed out, what the AI saw and no original", async () => {
  const out = await page(full, "&turns=all&secrets=all", false);
  assert.equal(out.valuesShown, false);
  assert.equal(out.allTurns, true);
  const signedIn = await page(full, "&turns=all&secrets=all");
  assert.equal(signedIn.valuesShown, true);
});

test("without the developer view, the agent page names no detailed trace; with it, a step that reached the AI unmasked does", async () => {
  const withDev = JSON.stringify(await page(full, "&turns=all"));
  assert.match(withDev, /detailed trace/);
  assert.match(withDev, /"trace":"trace"/);
  const without = JSON.stringify(await page(bare, "&turns=all"));
  assert.doesNotMatch(without, /detailed trace|developer view/i);
  assert.doesNotMatch(without, /"trace":/);
  assert.match(without, /"outcome":"unmasked"/, "the step is still there, marked");
});
