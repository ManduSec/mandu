/**
 * start-timeout-env.test — the supervisor's readiness deadline from
 * MANDU_SERVICE_READY_TIMEOUT_MS, which the launcher's stack autostart sets to
 * its own load-aware deadline (runtime-instances.md §10 "Autostart deadlines
 * under load").
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULTS, startTimeoutFromEnv } from "../../../src/supervisor/supervisor-defs.js";

test("startTimeoutFromEnv: a positive integer (ms) is the deadline; absent or garbled keeps the default", () => {
  assert.equal(startTimeoutFromEnv({ MANDU_SERVICE_READY_TIMEOUT_MS: "45000" }), 45_000);
  assert.equal(startTimeoutFromEnv({ MANDU_SERVICE_READY_TIMEOUT_MS: " 120000 " }), 120_000);
  assert.equal(startTimeoutFromEnv({}), undefined);
  for (const bad of ["", "0", "-1", "abc", "1.5", "30s"]) {
    assert.equal(startTimeoutFromEnv({ MANDU_SERVICE_READY_TIMEOUT_MS: bad }), undefined, `'${bad}'`);
  }
  // What undefined means: the fixed default the launcher now overrides.
  assert.equal(DEFAULTS.startTimeoutMs, 10_000);
});
