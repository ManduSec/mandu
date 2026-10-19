/**
 * darwin-rungs.test — the Linux-only rungs on macOS (portable-wrapper-
 * cross-platform.md; exec-routing.md §7): exec-box, landlock-net's native
 * applier, net-guard and the inspect-mcp confine print no "not built …
 * proceeding WITHOUT it" and no cargo hint there, at most ONE informational
 * line; landlock-net's port set becomes the Seatbelt profile's network
 * component instead (planSeatbeltNet), the SAME set as Linux's.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { computeLandlockNetPorts } from "../../src/landlock-net.js";
import { applyLandlockNet, planSeatbeltNet } from "../../src/landlock-net-setup.js";
import { applyNetGuard, NET_GUARD_LINUX_ONLY_NOTE } from "../../src/net-guard-setup.js";
import { applyExecBox, EXEC_BOX_LINUX_ONLY_NOTE } from "../../src/exec-box-setup.js";
import { planInspectNetConfine, INSPECT_CONFINE_LINUX_ONLY_NOTE } from "../../src/inspect-net-confine.js";
import { isAttentionNote } from "../../src/launch-banner.js";
import { liveRungNames, postureFindings } from "../../src/services/observe.js";
import { helperEndpointPorts, type ModelEndpoint } from "../../src/model-endpoints.js";
import { emptyMutation } from "../../src/backend/types.js";
import type { LaunchPlan } from "../../src/types.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // no arbiter; the rungs read no axis

function plan(over: Partial<LaunchPlan> = {}): LaunchPlan {
  return {
    target: "claude", argv: ["claude"], scopeId: "sid", tenant: "live", arbiterSock: "/b.sock", arbiterSockMode: "pinned" as const, arbiterRuntimeBase: "/tmp/mandu", eventDir: "/e",
    cwd: "/w", humanCwd: "/w", noContextProxy: true, fsSync: false, basePath: "/usr/bin",
    proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 8789 },
    openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: false, netProxyMitm: false, execWrap: false },
    execWrapCmds: [], ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" },
    noScope: false, writeMcp: true, bestEffort: false, replyFilter: true, execBoxCmds: ["cat"], ...over,
  };
}

const NO_BIN = (): string | null => { throw new Error("a Linux native bin must not be looked for on macOS"); };
const LINUX_NOISE = /not built|proceeding WITHOUT|cargo|build-native|WARNING/;

test("landlock-net on macOS: no applier, no wrap; the Seatbelt rules; ONE LIVE line and the honest residual, no Linux noise", () => {
  const mut = emptyMutation();
  const logs: string[] = [];
  const r = applyLandlockNet(plan({ netProxy: { host: "127.0.0.1", port: 40010 }, ullmForwarder: { host: "127.0.0.1", port: 40020 } }), mut, {
    platform: "darwin", resolveBin: NO_BIN, log: (m) => logs.push(m),
  })!;
  assert.deepEqual(mut.launchPrefix, [], "the Seatbelt profile (seatbelt-setup.ts) is the wrap");
  assert.deepEqual(r.wrapArgv, []);
  assert.deepEqual(r.ports, [22, 443, 8788, 40010, 40020]);
  assert.deepEqual(r.seatbelt, {
    connect: [
      { host: "localhost", port: 8788 }, { host: "localhost", port: 40010 }, { host: "localhost", port: 40020 },
      { host: "*", port: 443 }, { host: "*", port: 22 },
    ],
    bind: [],
  });
  assert.match(logs[0]!, /^mandu: network-confine LIVE \(Seatbelt, the macOS landlock-net\) — whole-agent TCP confined to CONNECT ports \[22, 443, 8788, 40010, 40020\] \(Mandu's own services \[8788, 40010, 40020\] on loopback only\)/);
  assert.ok(logs.some((l) => /network-confine — the workflow ports 443 \+ 22 stay allowed/.test(l)));
  assert.ok(logs.every((l) => !LINUX_NOISE.test(l) && !isAttentionNote(l)), logs.join("\n"));
  assert.deepEqual(liveRungNames(postureFindings(logs).live), ["network-confine"]);
  assert.deepEqual(postureFindings(logs).dropped, []);
});

test("landlock-net on macOS: strict, an explicit set, bind ports; off stays silent; no sandbox-exec is a named degrade", () => {
  const strict = planSeatbeltNet(plan({ landlockNetStrict: true, ullmForwarder: { host: "127.0.0.1", port: 40020 } }));
  assert.deepEqual(strict.connect, [{ host: "localhost", port: 8788 }, { host: "localhost", port: 40020 }], "strict drops 443 and 22");
  const explicit = planSeatbeltNet(plan({ landlockNetPorts: [8788, 5432], landlockNetBind: [3000, 3000] }));
  assert.deepEqual(explicit, { connect: [{ host: "*", port: 8788 }, { host: "*", port: 5432 }], bind: [3000] }, "an explicit set replaces the computed one verbatim (Linux: any host)");
  const logs: string[] = [];
  assert.equal(applyLandlockNet(plan({ landlockNet: false }), emptyMutation(), { platform: "darwin", resolveBin: NO_BIN, log: (m) => logs.push(m) }), null);
  assert.equal(logs.length, 0, "--no-landlock-net stays silent");
  const r = applyLandlockNet(plan(), emptyMutation(), { platform: "darwin", seatbeltAvailable: false, resolveBin: NO_BIN, log: (m) => logs.push(m) });
  assert.equal(r, null);
  assert.equal(logs.length, 1);
  assert.match(logs[0]!, /`sandbox-exec` is missing on this Mac; proceeding WITHOUT it/);
  assert.ok(!/cargo|not built/.test(logs[0]!));
});

test("landlock-net on macOS carries the SAME ports as Linux (parity over the plan shapes)", () => {
  const LOCAL: ModelEndpoint = { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "m", local: true };
  const shapes: Array<Partial<LaunchPlan>> = [
    {},
    { landlockNetStrict: true },
    { netProxy: { host: "127.0.0.1", port: 40010 } },
    { ullmForwarder: { host: "127.0.0.1", port: 40020 }, landlockNetStrict: true },
    { modelEndpoints: [LOCAL] },
    { modelEndpoints: [LOCAL], landlockNetStrict: true },
    { landlockNetPorts: [8788, 5432] },
    { target: "codex" },
    { proxy: { host: "127.0.0.1", port: 0 } },
  ];
  for (const over of shapes) {
    const p = plan(over);
    const linux = computeLandlockNetPorts({
      targetProxyPort: p.target === "codex" ? p.openaiProxy.port : p.proxy.port,
      netProxyPort: p.netProxy?.port ?? null,
      ullmForwarderPort: p.ullmForwarder?.port ?? null,
      modelEndpointPorts: helperEndpointPorts(p.modelEndpoints ?? []),
      explicitPorts: p.landlockNetPorts,
      strict: p.landlockNetStrict === true,
    });
    const mac = planSeatbeltNet(p).connect.map((c) => c.port);
    assert.deepEqual([...new Set(mac)].sort((a, b) => a - b), [...new Set(linux)].sort((a, b) => a - b), JSON.stringify(over));
  }
});

test("net-guard on macOS: no bin lookup, ONE informational line (not attention, not a dropped rung); off stays silent", () => {
  const logs: string[] = [];
  const mut = emptyMutation();
  assert.equal(applyNetGuard(plan(), mut, { platform: "darwin", resolveBin: NO_BIN, log: (m) => logs.push(m) }), null);
  assert.deepEqual(logs, [NET_GUARD_LINUX_ONLY_NOTE]);
  assert.deepEqual(mut.launchPrefix, []);
  assert.equal(mut.env["MANDU_NET_GUARD_BOX_SOCKETS"], undefined);
  assert.ok(!isAttentionNote(NET_GUARD_LINUX_ONLY_NOTE) && !LINUX_NOISE.test(NET_GUARD_LINUX_ONLY_NOTE));
  assert.deepEqual(postureFindings(logs).dropped, []);
  const quiet: string[] = [];
  assert.equal(applyNetGuard(plan({ netGuard: false }), emptyMutation(), { platform: "darwin", resolveBin: NO_BIN, log: (m) => quiet.push(m) }), null);
  assert.equal(applyNetGuard(plan(), emptyMutation(), { platform: "win32", resolveBin: NO_BIN, log: (m) => quiet.push(m) }), null);
  assert.deepEqual(quiet, []);
});

test("exec-box on macOS: no bin lookup, ONE informational line; --no-exec-box stays silent", () => {
  const logs: string[] = [];
  const p = plan();
  assert.equal(applyExecBox(p, "/run/sid", { platform: "darwin", resolveBin: NO_BIN, log: (m) => logs.push(m) }), null);
  assert.deepEqual(logs, [EXEC_BOX_LINUX_ONLY_NOTE]);
  assert.equal(p.execBoxShimDir, undefined);
  assert.ok(!isAttentionNote(EXEC_BOX_LINUX_ONLY_NOTE) && !LINUX_NOISE.test(EXEC_BOX_LINUX_ONLY_NOTE));
  const quiet: string[] = [];
  assert.equal(applyExecBox(plan({ execBox: false }), "/run/sid", { platform: "darwin", resolveBin: NO_BIN, log: (m) => quiet.push(m) }), null);
  assert.deepEqual(quiet, []);
});

test("the inspect_symbol confine on macOS: no applier lookup, ONE informational line", () => {
  const logs: string[] = [];
  assert.equal(planInspectNetConfine({}, { platform: "darwin", resolveBin: NO_BIN, probeNet: () => { throw new Error("no probe"); }, log: (m) => logs.push(m) }), null);
  assert.deepEqual(logs, [INSPECT_CONFINE_LINUX_ONLY_NOTE]);
  assert.ok(!isAttentionNote(INSPECT_CONFINE_LINUX_ONLY_NOTE) && !LINUX_NOISE.test(INSPECT_CONFINE_LINUX_ONLY_NOTE));
  assert.equal(planInspectNetConfine({ landlockNet: false }, { platform: "darwin", resolveBin: NO_BIN, log: (m) => logs.push(m) }), null);
  assert.equal(logs.length, 1, "--no-landlock-net stays silent");
});
