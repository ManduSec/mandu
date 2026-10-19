/**
 * landlock-net.test — the PURE port-set + wrap-argv plan, and applyLandlockNet's
 * prepend / degrade / warning behavior (docs/design/integrity/exec-routing.md §7).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { computeLandlockNetPorts, planLandlockNet } from "../../src/landlock-net.js";
import { applyLandlockNet } from "../../src/landlock-net-setup.js";
import { emptyMutation } from "../../src/backend/types.js";
import type { LaunchPlan } from "../../src/types.js";

// ── planLandlockNet: argv shape ──────────────────────────────────────────────

test("planLandlockNet: --net-only, one pair per port, --skip-unsupported + trailing -- always present", () => {
  const { wrapArgv } = planLandlockNet({ applierPath: "/bin/apply", ports: [8788, 443] });
  assert.equal(wrapArgv[0], "/bin/apply");
  assert.equal(wrapArgv[1], "--net-only");
  // deduped + SORTED ascending (443 before 8788), each its own two tokens.
  assert.deepEqual(wrapArgv, [
    "/bin/apply", "--net-only",
    "--allow-tcp-port", "443",
    "--allow-tcp-port", "8788",
    "--skip-unsupported", "--",
  ]);
  assert.equal(wrapArgv.at(-1), "--", "the agent argv follows the separator");
  assert.equal(wrapArgv.at(-2), "--skip-unsupported", "always degrade-capable");
});

test("planLandlockNet: dedupes duplicate ports", () => {
  const { wrapArgv } = planLandlockNet({ applierPath: "a", ports: [443, 8788, 443, 8788] });
  const ports = wrapArgv.filter((_, i) => wrapArgv[i - 1] === "--allow-tcp-port");
  assert.deepEqual(ports, ["443", "8788"]);
});

test("planLandlockNet: empty ports is valid (whole-agent TCP deny-all)", () => {
  const { wrapArgv } = planLandlockNet({ applierPath: "a", ports: [] });
  assert.deepEqual(wrapArgv, ["a", "--net-only", "--skip-unsupported", "--"]);
});

// ── computeLandlockNetPorts: the workflow-port policy ────────────────────────

test("planLandlockNet: bind ports render as --allow-tcp-bind-port pairs after the connect pairs (no double-listing)", () => {
  const { wrapArgv } = planLandlockNet({ applierPath: "/bin/ll", ports: [8788, 4096, 443], bindPorts: [4096, 5173, 4096] });
  assert.deepEqual(wrapArgv, [
    "/bin/ll", "--net-only",
    "--allow-tcp-port", "443", "--allow-tcp-port", "8788",
    "--allow-tcp-bind-port", "4096", "--allow-tcp-bind-port", "5173",
    "--skip-unsupported", "--",
  ]);
  // No bind ports → byte-identical to before (the default posture is unchanged).
  assert.deepEqual(planLandlockNet({ applierPath: "/bin/ll", ports: [8788] }).wrapArgv,
    planLandlockNet({ applierPath: "/bin/ll", ports: [8788], bindPorts: [] }).wrapArgv);
});

test("computeLandlockNetPorts: default = target proxy port + the workflow ports 443/22 (non-strict, no services)", () => {
  assert.deepEqual(
    computeLandlockNetPorts({ targetProxyPort: 8788, netProxyPort: null, ullmForwarderPort: null, strict: false }),
    [8788, 443, 22],
  );
});

test("computeLandlockNetPorts: net-proxy + ullm-forwarder ports included IFF live", () => {
  assert.deepEqual(
    computeLandlockNetPorts({ targetProxyPort: 8788, netProxyPort: 8790, ullmForwarderPort: null, strict: false }),
    [8788, 8790, 443, 22],
  );
  assert.deepEqual(
    computeLandlockNetPorts({ targetProxyPort: 8788, netProxyPort: 8790, ullmForwarderPort: 8791, strict: false }),
    [8788, 8790, 8791, 443, 22],
  );
});

test("computeLandlockNetPorts: strict DENIES the workflow ports (443 + 22) but keeps the forwarder", () => {
  assert.deepEqual(
    computeLandlockNetPorts({ targetProxyPort: 8788, netProxyPort: null, ullmForwarderPort: 8791, strict: true }),
    [8788, 8791],
  );
});

test("computeLandlockNetPorts: an explicit override replaces the set verbatim (no auto 443/22)", () => {
  assert.deepEqual(
    computeLandlockNetPorts({ targetProxyPort: 8788, netProxyPort: 8790, ullmForwarderPort: 8791, explicitPorts: [9000], strict: false }),
    [9000],
  );
});

// ── applyLandlockNet: prepend / degrade / warnings ───────────────────────────

function plan(over: Partial<LaunchPlan> = {}): LaunchPlan {
  return {
    target: "claude", argv: ["claude"], scopeId: "sid", tenant: "live", arbiterSock: "/b.sock", arbiterSockMode: "pinned" as const, arbiterRuntimeBase: "/tmp/mandu", eventDir: "/e",
    cwd: "/w", humanCwd: "/w", noContextProxy: true, fsSync: false, basePath: "/usr/bin",
    proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 8789 },
    openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: false, netProxyMitm: false, execWrap: false },
    execWrapCmds: [], ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" },
    noScope: false, writeMcp: true, bestEffort: false, replyFilter: true, landlockNet: true, ...over,
  };
}

test("applyLandlockNet: off → no-op (no wrap, no log)", () => {
  const mut = emptyMutation();
  const logs: string[] = [];
  const r = applyLandlockNet(plan({ landlockNet: false }), mut, { resolveBin: () => "/bin/apply", log: (m) => logs.push(m) });
  assert.equal(r, null);
  assert.deepEqual(mut.launchPrefix, []);
  assert.equal(logs.length, 0);
});

test("applyLandlockNet: bin missing → WARN + proceed WITHOUT (degrade, never throws)", () => {
  const mut = emptyMutation();
  const logs: string[] = [];
  const r = applyLandlockNet(plan(), mut, { resolveBin: () => null, log: (m) => logs.push(m) });
  assert.equal(r, null);
  assert.deepEqual(mut.launchPrefix, [], "no wrap prepended when the bin is absent");
  assert.ok(logs.some((l) => /not built/.test(l) && /WITHOUT/.test(l)));
});

test("applyLandlockNet: PREPENDS the wrap outermost, ahead of an existing launchPrefix", () => {
  const mut = emptyMutation();
  mut.launchPrefix = ["bwrap", "--", ]; // stand-in for an already-appended secret-twins wrap
  const r = applyLandlockNet(plan(), mut, { resolveBin: () => "/bin/apply", log: () => {} });
  assert.ok(r);
  assert.equal(mut.launchPrefix[0], "/bin/apply", "landlock-net is now outermost");
  // the pre-existing wrap stays AFTER (inner).
  assert.deepEqual(mut.launchPrefix.slice(-2), ["bwrap", "--"]);
  // default (non-strict, no net-proxy/forwarder): workflow ports + the proxy port.
  assert.deepEqual(r!.ports, [22, 443, 8788]);
});

test("applyLandlockNet: default-on (landlockNet undefined) applies the wrap too", () => {
  const mut = emptyMutation();
  const r = applyLandlockNet(plan({ landlockNet: undefined }), mut, { resolveBin: () => "/bin/apply", log: () => {} });
  assert.ok(r, "undefined = default-on, not off");
  assert.equal(mut.launchPrefix[0], "/bin/apply");
});

test("applyLandlockNet: net-proxy + ullm-forwarder ports added when the plan has them", () => {
  const mut = emptyMutation();
  const r = applyLandlockNet(
    plan({ netProxy: { host: "127.0.0.1", port: 8790 }, ullmForwarder: { host: "127.0.0.1", port: 8791 } }),
    mut, { resolveBin: () => "/a", log: () => {} });
  assert.deepEqual(r!.ports, [22, 443, 8788, 8790, 8791]);
});

test("applyLandlockNet: codex target allows the OPENAI proxy port, not the anthropic one", () => {
  const mut = emptyMutation();
  const r = applyLandlockNet(plan({ target: "codex" }), mut, { resolveBin: () => "/a", log: () => {} });
  assert.deepEqual(r!.ports, [22, 443, 8789]);
});

test("applyLandlockNet: strict → 443/22 denied; U-LLM survives via the forwarder (else a loud warning)", () => {
  // With the forwarder live: strict keeps it reachable and says so.
  const mut = emptyMutation();
  const logs: string[] = [];
  const r = applyLandlockNet(
    plan({ landlockNetStrict: true, ullmForwarder: { host: "127.0.0.1", port: 8791 } }),
    mut, { resolveBin: () => "/a", log: (m) => logs.push(m) });
  assert.deepEqual(r!.ports, [8788, 8791], "no 443/22 in strict mode; forwarder stays");
  assert.ok(logs.some((l) => /STRICT/.test(l) && /443 \+ 22 are DENIED/.test(l) && /forwarder/.test(l)));

  // Without the forwarder: strict must warn the U-LLM's direct dial breaks.
  const logs2: string[] = [];
  const r2 = applyLandlockNet(plan({ landlockNetStrict: true }), emptyMutation(), { resolveBin: () => "/a", log: (m) => logs2.push(m) });
  assert.deepEqual(r2!.ports, [8788]);
  assert.ok(logs2.some((l) => /STRICT/.test(l) && /U-LLM/.test(l) && /WILL fail/.test(l)));
});

test("applyLandlockNet: landlockNetBind renders bind pairs, joins the reported set, and satisfies the proxy-port check", () => {
  const mut = emptyMutation();
  const logs: string[] = [];
  const r = applyLandlockNet(plan({ landlockNetBind: [4096, 4096] }), mut, { resolveBin: () => "/bin/apply", log: (m) => logs.push(m) });
  assert.ok(r);
  assert.deepEqual(r!.bindPorts, [4096]);
  assert.ok(r!.ports.includes(4096), "a bind port is also in the reported CONNECT set");
  const i = r!.wrapArgv.indexOf("--allow-tcp-bind-port");
  assert.ok(i > 0 && r!.wrapArgv[i + 1] === "4096");
  assert.ok(!r!.wrapArgv.includes("--allow-tcp-port") || r!.wrapArgv.indexOf("--allow-tcp-port") < i, "connect pairs precede bind pairs");
  assert.ok(logs.some((l) => /BIND \(listen\) ports \[4096\]/.test(l)), "the banner names the bind ports");
  // A bind allowance on the proxy port itself counts as allowed (no false warning).
  const logs2: string[] = [];
  applyLandlockNet(plan({ landlockNetPorts: [443], landlockNetBind: [8788] }), emptyMutation(), { resolveBin: () => "/bin/apply", log: (m) => logs2.push(m) });
  assert.ok(!logs2.some((l) => /model calls will fail/.test(l)));
  // No bind list → no bind pairs, no BIND banner (the default posture is unchanged).
  const logs3: string[] = [];
  const r3 = applyLandlockNet(plan(), emptyMutation(), { resolveBin: () => "/bin/apply", log: (m) => logs3.push(m) });
  assert.deepEqual(r3!.bindPorts, []);
  assert.ok(!r3!.wrapArgv.includes("--allow-tcp-bind-port"));
  assert.ok(!logs3.some((l) => /BIND/.test(l)));
});

test("applyLandlockNet: an explicit override without the proxy port warns that model calls break", () => {
  const mut = emptyMutation();
  const logs: string[] = [];
  const r = applyLandlockNet(plan({ landlockNetPorts: [9000] }), mut, { resolveBin: () => "/a", log: (m) => logs.push(m) });
  assert.deepEqual(r!.ports, [9000]);
  assert.ok(logs.some((l) => /WARNING/.test(l) && /8788/.test(l) && /model calls will fail/.test(l)));
});

test("applyLandlockNet: a STALE applier bin is WARNED about (attention line) and the wrap still applies", () => {
  const mut = emptyMutation();
  const logs: string[] = [];
  const r = applyLandlockNet(plan(), mut, {
    resolveBin: () => "/bin/apply",
    staleNote: (name, path) => `mandu: WARNING — ${name} at ${path} is STALE`,
    log: (m) => logs.push(m),
  });
  assert.ok(r, "stale is a warning, not a degrade");
  assert.equal(mut.launchPrefix[0], "/bin/apply");
  assert.ok(logs.some((l) => /WARNING/.test(l) && /mandu-landlock-apply at \/bin\/apply is STALE/.test(l)), JSON.stringify(logs));
});

// ── policy.yaml models: (confidentiality-plan-11 D5) ─────────────────────────
import { stateAxes } from "../axes.js";
stateAxes("secrets"); // the plan-11 cases below run under the mode with local-model in play; the port logic reads no axis

test("computeLandlockNetPorts: declared local model endpoint ports join the set, strict included; an explicit override still replaces", () => {
  const base = { targetProxyPort: 8788, netProxyPort: null, ullmForwarderPort: 40001, modelEndpointPorts: [11434] };
  assert.deepEqual([...computeLandlockNetPorts({ ...base, strict: true })].sort((a, b) => a - b), [8788, 11434, 40001]);
  assert.ok(computeLandlockNetPorts({ ...base, strict: false }).includes(11434));
  assert.deepEqual(computeLandlockNetPorts({ ...base, strict: false, explicitPorts: [8788] }), [8788]);
});

test("applyLandlockNet: plan.modelEndpoints → the local endpoint's port is an --allow-tcp-port; an external one adds nothing; banner names it", () => {
  const mut = emptyMutation();
  const logs: string[] = [];
  const r = applyLandlockNet(plan({
    landlockNetStrict: true,
    modelEndpoints: [
      { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true },
      { name: "cloud", url: "https://llm.example.com:8443", wire: "anthropic", local: false },
    ],
  }), mut, { resolveBin: () => "/bin/apply", staleNote: () => null, log: (m) => logs.push(m) });
  assert.ok(r);
  const ports = r.wrapArgv.filter((_, i) => r.wrapArgv[i - 1] === "--allow-tcp-port").map(Number);
  assert.ok(ports.includes(11434), JSON.stringify(ports));
  assert.ok(!ports.includes(8443), "an external declared endpoint gets no port");
  assert.ok(logs.some((l) => /your own model endpoint port\(s\) \[11434\] are allowed/.test(l)), logs.join("\n"));
});

test("applyLandlockNet: an explicit --landlock-net set that omits a local endpoint's port WARNS", () => {
  const logs: string[] = [];
  applyLandlockNet(plan({
    landlockNetPorts: [8788],
    modelEndpoints: [{ name: "ollama", url: "http://localhost:11434", wire: "openai-chat", local: true }],
  }), emptyMutation(), { resolveBin: () => "/bin/apply", staleNote: () => null, log: (m) => logs.push(m) });
  assert.ok(logs.some((l) => /WARNING: your own model endpoint port\(s\) \[11434\].*NOT in the allowed set/.test(l)), logs.join("\n"));
});
