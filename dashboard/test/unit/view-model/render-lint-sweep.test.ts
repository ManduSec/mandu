/**
 * render-lint-sweep.test.ts — the §4.2c render self-check swept over the
 * CAPTURED-LIVE fixture corpus (fixtures/live/*.ndjson — snapshots of real
 * arbiter session logs, including the three delivered-reply incidents
 * render-lint.ts exists for; structure as recorded, personal and lab details
 * in the text rewritten to neutral values, dashboard.md §4.2). Every fixture
 * must lint free of error-severity findings; warn-severity findings are
 * advisory (logged, not failed). The corpus is auto-discovered, so dropping a new snapshot into
 * fixtures/live/ extends the sweep without touching this file.
 *
 * Plus one GOLDEN render pin on the 1783733223 session (the 429-quota-probe +
 * reply-filter-frames incident): the delivered-reply card and the collapsed
 * reply-filter OS step must render exactly as the human's terminal showed —
 * the two live-found regressions, pinned.
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

import { lintRender, toDualLanes } from "../../../src/view-model.js";
import { coerceEvent, type ManduEvent } from "../../../src/event-model.js";

const LIVE_DIR = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..", "..", "fixtures", "live");

/** Parse one captured session log the way the server does: coerce line by
 *  line (skipping unparseable/foreign lines) and drop the META kinds that
 *  toSessionViewModel keeps out of every trace projection. */
function loadFixture(name: string): ManduEvent[] {
  const events: ManduEvent[] = [];
  for (const line of readFileSync(join(LIVE_DIR, name), "utf8").split("\n")) {
    if (line.trim() === "") continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      continue;
    }
    const e = coerceEvent(parsed);
    if (e === null) continue;
    if (e.kind === "assertion" || e.kind === "workspace_seed" || e.kind === "workspace_final") continue;
    events.push(e);
  }
  return events;
}

const FIXTURES = readdirSync(LIVE_DIR).filter((n) => n.endsWith(".ndjson")).sort();

test("the captured-live corpus is non-empty (the sweep is running over something)", () => {
  assert.ok(FIXTURES.length > 0, `no *.ndjson fixtures found in ${LIVE_DIR}`);
  assert.ok(
    FIXTURES.some((n) => n.startsWith("1783733223")),
    "the 429-quota-probe incident snapshot (1783733223-*) must be in the corpus",
  );
});

for (const name of FIXTURES) {
  test(`captured-live ${name} lints free of error-severity findings`, () => {
    const events = loadFixture(name);
    assert.ok(events.length > 0, `fixture ${name} coerced to zero events`);
    const findings = lintRender(events, toDualLanes(events));
    for (const f of findings.filter((x) => x.severity === "warn")) {
      // Advisory only — surfaced for visibility, never a sweep failure.
      console.log(`[render-lint-sweep] ${name} WARN ${f.invariant}: ${f.detail}`);
    }
    const errors = findings.filter((f) => f.severity === "error");
    assert.deepEqual(errors, [], `${name}: error-severity render-lint findings`);
  });
}

// ── GOLDEN pin: the 1783733223 incident renders what the human received ───────

test("golden 1783733223: delivered reply + collapsed reply-filter step render exactly", () => {
  const name = FIXTURES.find((n) => n.startsWith("1783733223"));
  assert.ok(name, "1783733223 fixture present (asserted above)");
  const dual = toDualLanes(loadFixture(name!));

  // Regression 1: the delivery zone shows the reply the human ACTUALLY
  // received (the symbolic WebFetch count), not the 429 probe's explainer or
  // any side call's prose.
  const final = dual.steps.find((s) => s.step === "response" && s.final);
  assert.ok(final && final.step === "response", "a final response card exists");
  assert.equal(final.text, "$MDU:WebFetch[cd10]");

  // Regression 2: the reply-filter's six PTY egress frames collapse into ONE
  // user-reply OS step with repeats 6 — not six stacked rows, not zero.
  const replySteps = dual.steps.filter(
    (s) => s.step === "os" && s.title === "user reply · reply-filter",
  );
  assert.equal(replySteps.length, 1, "exactly one collapsed user-reply step");
  assert.equal(replySteps[0]!.step === "os" && replySteps[0]!.repeats, 6);
});
