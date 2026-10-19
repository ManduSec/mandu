/**
 * launcher-stack-tenant.test.ts — the launcher-live stack (withStack) pins ONE
 * tenant on both halves, whatever MANDU_TENANT its caller exports
 * (differential-interactive.md §24).
 *
 * 2026-09-30: the nightly stack (scripts/ci/pipeline.sh, --network) exports
 * MANDU_TENANT=test for the suites that attach to its shared arbiter. The
 * in-process arbiter of withStack read it (ArbiterServer's tenantFromEnv
 * fallback) while the launch it hands out is an explicit env without it, so
 * the private arbiter was `test`, the launch `live`, and the launcher's tenant
 * preflight refused every launch: all 60 ci.claude-latest differential tests
 * red in the CI guest. The real halves are exercised here: the launcher's own
 * parse() of launcherEnv decides the launch tenant, its own preflight asks the
 * private arbiter's `hello`.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { parse } from "../../launcher/src/parse.js";
import { assertArbiterTenant, readArbiterTenant } from "../../launcher/src/tenant-preflight.js";
import { STACK_TENANT, withStack } from "../lib/launcher-live.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // withStack({ mode: "secrets" }) below; the tenant is axis-independent

for (const ambient of [undefined, "live", "test"] as const) {
  test(`withStack: arbiter and launch agree on the tenant with the caller's MANDU_TENANT=${ambient ?? "(unset)"}`, async () => {
    const saved = process.env["MANDU_TENANT"];
    if (ambient === undefined) delete process.env["MANDU_TENANT"];
    else process.env["MANDU_TENANT"] = ambient;
    try {
      await withStack(async ({ workspace, launcherEnv }) => {
        const env = launcherEnv("https://127.0.0.1:1", 0);
        const sock = env["MANDU_ARBITER_SOCK"]!;
        assert.equal(env["MANDU_TENANT"], STACK_TENANT, "the launch carries the stack's tenant");
        assert.equal(await readArbiterTenant(sock), STACK_TENANT, "the private arbiter declares the stack's tenant");
        const plan = parse(["--", "claude"], { ...env, PWD: workspace });
        assert.equal(plan.tenant, STACK_TENANT, "the launcher parses the stack's tenant from launcherEnv");
        // The launcher's own preflight (run.ts) passes: no TenantMismatchError.
        const r = await assertArbiterTenant(sock, plan.tenant);
        assert.equal(r.arbiterTenant, STACK_TENANT);
      }, { mode: "secrets" });
    } finally {
      if (saved === undefined) delete process.env["MANDU_TENANT"];
      else process.env["MANDU_TENANT"] = saved;
    }
  });
}
