/**
 * safe-log parity (runtime-instances.md §2, "planted paths"): the copies of
 * safe-log.ts, which open every log Mandu appends to with each component on
 * the way checked, are byte-identical: one helper, each package standalone.
 * The launcher's opens its daemons' logs, the dashboard supervisor's its
 * services' logs, the arbiter's its event store's per-session files. The
 * behaviour itself is pinned by launcher/test/unit/safe-log.test.ts,
 * launcher/test/component/log-dir-planted.test.ts, the dashboard's
 * supervisor-logs test and the arbiter's event-store-planted and
 * event-file-planted tests.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { stateAxes } from "../lib/axes.js";

stateAxes("off"); // a source comparison: no arbiter decides anything here

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const COPIES = ["dashboard/src/supervisor/safe-log.ts", "arbiter/events/safe-log.ts"];

test("the copies of safe-log.ts are byte-identical to the launcher's", () => {
  const want = readFileSync(join(ROOT, "launcher/src/safe-log.ts"), "utf8");
  for (const c of COPIES) assert.equal(readFileSync(join(ROOT, c), "utf8"), want, `${c} drifted from launcher/src/safe-log.ts; copy the launcher's file out again`);
});
