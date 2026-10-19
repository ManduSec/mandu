/**
 * registry.test — prepare ordering + fail-closed on requested-unavailable.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { runBackends } from "../../src/backend/registry.js";
import { coopEnv } from "../../src/backend/coop-env.js";
import { emptyMutation, type EnforcementBackend } from "../../src/backend/types.js";
import type { LaunchPlan } from "../../src/types.js";

function plan(over: Partial<LaunchPlan> = {}): LaunchPlan {
  return {
    target: "claude", argv: ["claude"], scopeId: "sid", tenant: "live", arbiterSock: "/s", arbiterSockMode: "pinned" as const, arbiterRuntimeBase: "/tmp/mandu", eventDir: "/e",
    cwd: "/w", humanCwd: "/w", noContextProxy: true, fsSync: false, basePath: "/usr/bin:/bin", proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 8789 },
    openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: false, netProxyMitm: false, execWrap: false },
    execWrapCmds: [], ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" }, noScope: false, writeMcp: true, bestEffort: false, replyFilter: true, ...over,
  };
}

test("coop-env alone composes the env into the mutation", () => {
  const mut = emptyMutation();
  runBackends([coopEnv], plan(), mut);
  assert.equal(mut.env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8788");
});

test("requested-but-unavailable backend throws (fail-closed)", () => {
  const stub: EnforcementBackend = {
    id: "stub-net", chokepoints: ["net"],
    probe: () => ({ available: false, reason: "trap unavailable" }),
    requestedBy: (p) => p.requested.netProxyMitm === true,
    prepare: () => { throw new Error("should not prepare"); },
  };
  assert.throws(
    () => runBackends([coopEnv, stub], plan({ requested: { ...plan().requested, netProxyMitm: true } }), emptyMutation()),
    /stub-net.*trap unavailable/,
  );
});

test("unavailable but NOT requested → silently skipped", () => {
  const stub: EnforcementBackend = {
    id: "stub-fs", chokepoints: ["fs"],
    probe: () => ({ available: false, reason: "no cargo" }),
    requestedBy: (p) => p.requested.netProxyMitm === true,
    prepare: () => { throw new Error("should not prepare"); },
  };
  const mut = emptyMutation();
  runBackends([coopEnv, stub], plan(), mut); // netProxyMitm not requested
  assert.equal(mut.env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8788");
});

test("--best-effort downgrades a requested-unavailable to a skip", () => {
  const warnings: string[] = [];
  const stub: EnforcementBackend = {
    id: "stub-net", chokepoints: ["net"],
    probe: () => ({ available: false, reason: "trap unavailable" }),
    requestedBy: (p) => p.requested.netProxyMitm === true,
    prepare: () => { throw new Error("should not prepare"); },
  };
  const mut = emptyMutation();
  runBackends([coopEnv, stub], plan({ bestEffort: true, requested: { ...plan().requested, netProxyMitm: true } }), mut, (m) => warnings.push(m));
  assert.ok(warnings.some((w) => /stub-net/.test(w)));
  assert.equal(mut.env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8788");
});
