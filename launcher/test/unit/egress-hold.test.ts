/**
 * egress-hold — the launcher's default for the net-proxy's held request
 * (src/egress-hold.ts; docs/design/confidentiality/egress-hold.md "The
 * default"): an explicit MANDU_EGRESS_HOLD_MS (0 included) wins; otherwise
 * 60 s for an interactive session on a terminal and 0 for CI, a run whose
 * output is not a terminal, and a one-shot (`claude -p`, `codex exec`, …).
 * The one-shot list is the reply filter's (print-mode.ts), pinned here; the
 * net-proxy gets the decision in its env, always set.
 *
 * No axis: the hold's default is the same in every mode (the proxy holds
 * only a card the gate filed).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  EGRESS_HOLD_ENV, EGRESS_HOLD_MAX_MS, INTERACTIVE_EGRESS_HOLD_MS,
  egressHoldClause, launcherEgressHold, oneShotRun,
} from "../../src/egress-hold.js";
import { egressHoldOf, startNetProxy } from "../../src/services/net-proxy.js";
import { Layout } from "../../src/services/layout.js";
import type { ServiceDeps } from "../../src/services/primitives.js";
import { DEFAULT_CONFIG_TOML, loadConfigEnv, parseToml } from "../../src/config.js";
import { updateCheckGate } from "../../src/update-check.js";
import type { LaunchPlan } from "../../src/types.js";

const tty = (argv: string[], env: Record<string, string | undefined> = {}) => launcherEgressHold({ env, argv, stdoutIsTTY: true });

test("an interactive session on a terminal holds 60 s: claude, codex, goose session, opencode, openclaw chat, a shell", () => {
  assert.equal(INTERACTIVE_EGRESS_HOLD_MS, 60_000);
  for (const argv of [["claude"], ["claude", "--model", "haiku"], ["/usr/local/bin/claude", "-r"], ["codex"], ["codex", "resume"], ["goose", "session"], ["opencode"], ["openclaw", "chat"], ["bash"]]) {
    const c = tty(argv);
    assert.equal(c.ms, "60000", JSON.stringify(argv));
    assert.equal(c.source, "interactive", JSON.stringify(argv));
  }
});

test("unattended runs never hold: output not a terminal, CI, a one-shot", () => {
  const piped = launcherEgressHold({ env: {}, argv: ["claude"], stdoutIsTTY: false });
  assert.deepEqual([piped.ms, piped.source], ["0", "unattended"]);
  assert.match(piped.why, /not a terminal/);
  for (const ci of ["true", "1", "yes", "gitlab"]) {
    const c = tty(["claude"], { CI: ci });
    assert.deepEqual([c.ms, c.source, c.why], ["0", "unattended", "CI"], ci);
  }
  for (const ci of ["", "0", "false", "off", "no"]) assert.equal(tty(["claude"], { CI: ci }).ms, "60000", `CI=${ci} is not CI`);
  for (const argv of [["claude", "-p", "hi"], ["claude", "--print", "hi"], ["claude", "--model", "haiku", "-p", "x"], ["codex", "exec", "x"], ["codex", "exec", "--model", "o3", "x"], ["openclaw", "agent", "--local", "-m", "x"], ["opencode", "run", "x"]]) {
    const c = tty(argv);
    assert.deepEqual([c.ms, c.source], ["0", "unattended"], JSON.stringify(argv));
    assert.match(c.why, /one-shot/);
  }
});

test("an explicit MANDU_EGRESS_HOLD_MS always wins, 0 included; empty or blank is unset", () => {
  assert.deepEqual(tty(["claude"], { [EGRESS_HOLD_ENV]: "0" }), { ms: "0", source: "explicit", why: "MANDU_EGRESS_HOLD_MS=0" });
  assert.equal(tty(["claude"], { [EGRESS_HOLD_ENV]: " 5000 " }).ms, "5000");
  // Over every unattended rule: the user asked for it.
  assert.equal(launcherEgressHold({ env: { [EGRESS_HOLD_ENV]: "30000", CI: "true" }, argv: ["claude", "-p", "x"], stdoutIsTTY: false }).ms, "30000");
  // A value the proxy cannot read is passed as is: the proxy reads it as 0 (egress.ts egressHoldMs).
  assert.deepEqual([tty(["claude"], { [EGRESS_HOLD_ENV]: "soon" }).ms, tty(["claude"], { [EGRESS_HOLD_ENV]: "soon" }).source], ["soon", "explicit"]);
  for (const blank of ["", "  "]) assert.equal(tty(["claude"], { [EGRESS_HOLD_ENV]: blank }).source, "interactive");
});

test("the one-shot list is the reply filter's print-mode list (print-mode.ts decideMode, step 4)", async () => {
  const path = "../../../interceptors/reply-filter/src/print-mode.ts";
  const { decideMode } = await import(path) as { decideMode: (cmd: string[], tty: boolean, o?: object) => { mode: string } };
  const cases: string[][] = [
    ["claude"], ["claude", "-p"], ["claude", "--print", "x"], ["claude", "-r", "abc"], ["/opt/bin/claude", "-p", "x"], ["notclaude", "-p"],
    ["codex"], ["codex", "exec", "x"], ["codex", "-m", "o3", "exec"], ["codex", "resume"], ["codex", "--exec"],
    ["openclaw", "chat"], ["openclaw", "agent", "-m", "x"], ["openclaw", "tui"],
    ["opencode"], ["opencode", "run", "x"], ["opencode", "--model", "m"],
    ["goose", "session"], ["goose", "run", "-t", "x"], ["bash"], [],
  ];
  for (const argv of cases) {
    assert.equal(oneShotRun(argv) !== null, decideMode(argv, true).mode === "pipe", JSON.stringify(argv));
  }
});

test("the names and the cap are the net-proxy's (egress.ts, server-main.ts)", async () => {
  const path = "../../../interceptors/net-proxy/src/egress.ts";
  const { EGRESS_HOLD_MAX_MS: proxyMax } = await import(path) as { EGRESS_HOLD_MAX_MS: number };
  assert.equal(EGRESS_HOLD_MAX_MS, proxyMax);
  const main = readFileSync(new URL("../../../interceptors/net-proxy/src/server-main.ts", import.meta.url), "utf8");
  assert.ok(main.includes(`process.env["${EGRESS_HOLD_ENV}"]`), "server-main reads the variable the launcher sets");
});

test("the LIVE line's clause: said only for a hold, in seconds, capped", () => {
  const c = (ms: string) => egressHoldClause({ ms, source: "explicit", why: "x" });
  assert.equal(c("0"), "");
  assert.equal(c("soon"), "");
  assert.equal(c("-5"), "");
  assert.match(c("60000"), /held up to 60 s/);
  assert.match(c("999999"), /held up to 300 s/);
  assert.match(egressHoldClause(tty(["claude"])), /an interactive session on a terminal/);
});

test("CI is one test: the update check's and the hold's agree", () => {
  for (const ci of ["true", "0", "", "off", "1"]) {
    const updateOff = updateCheckGate({ CI: ci }, { installed: true, interactive: true }).on === false;
    assert.equal(updateOff, tty(["claude"], { CI: ci }).ms === "0", `CI=${ci}`);
  }
});

test("config egress-hold-ms seeds MANDU_EGRESS_HOLD_MS; the template documents it commented out", () => {
  assert.equal(loadConfigEnv({ HOME: "/home/u" }, () => "egress-hold-ms = 0\n")[EGRESS_HOLD_ENV], "0");
  assert.equal(loadConfigEnv({ HOME: "/home/u" }, () => "egress-hold-ms = 90000\n")[EGRESS_HOLD_ENV], "90000");
  assert.match(DEFAULT_CONFIG_TOML, /^# egress-hold-ms = 0$/m);
  assert.deepEqual(parseToml(DEFAULT_CONFIG_TOML), {});
});

function plan(over: Partial<LaunchPlan> = {}): LaunchPlan {
  return {
    target: "claude", argv: ["claude"], scopeId: "sid", tenant: "live", arbiterSock: "/b.sock", arbiterSockMode: "pinned" as const, arbiterRuntimeBase: "/tmp/mandu", eventDir: "/e",
    cwd: "/w", humanCwd: "/w", noContextProxy: true, fsSync: false, basePath: "/usr/bin",
    proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 8789 },
    openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: true, netProxyMitm: false, execWrap: false },
    execWrapCmds: [], ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" },
    noScope: false, writeMcp: true, bestEffort: false, replyFilter: true, netGuard: true, ...over,
  };
}

function deps(capture: (env: Record<string, string | undefined>) => void): ServiceDeps {
  return {
    probePort: async () => false, probeIdentity: async () => null,
    waitFor: async () => true, waitForFile: async () => true,
    startDetachedCmd: (_c, _a, { env }) => { capture(env); return { pid: 7, stop: () => {} }; },
    runOnce: () => ({ status: 0, stdout: "", stderr: "" }),
  };
}

test("startNetProxy hands the proxy the launch's decision, always set: an ambient value never reaches it, a plan without one is decided unattended", async () => {
  const saved = { port: process.env["MANDU_NET_PROXY_PORT"], hold: process.env[EGRESS_HOLD_ENV] };
  process.env["MANDU_NET_PROXY_PORT"] = "8790"; // pinned: no port file to wait on
  try {
    let env: Record<string, string | undefined> = {};
    const run = async (p: LaunchPlan) => { await startNetProxy(p, Layout.dev("/repo"), "/run/sid", deps((e) => { env = e; })); return env[EGRESS_HOLD_ENV]; };
    delete process.env[EGRESS_HOLD_ENV];
    assert.equal(await run(plan({ egressHold: tty(["claude"]) })), "60000", "interactive");
    assert.equal(await run(plan({ egressHold: launcherEgressHold({ env: {}, argv: ["claude"], stdoutIsTTY: false }) })), "0", "headless");
    assert.equal(await run(plan()), "0", "no decision on the plan and nothing set: off");
    process.env[EGRESS_HOLD_ENV] = "45000";
    assert.equal(await run(plan()), "45000", "no decision on the plan: the user's value");
    assert.equal(await run(plan({ egressHold: { ms: "0", source: "explicit", why: "MANDU_EGRESS_HOLD_MS=0" } })), "0", "the plan's decision over the ambient value");
    assert.deepEqual(egressHoldOf(plan()), { ms: "45000", source: "explicit", why: "MANDU_EGRESS_HOLD_MS=45000" });
  } finally {
    for (const [k, v] of [["MANDU_NET_PROXY_PORT", saved.port], [EGRESS_HOLD_ENV, saved.hold]] as const) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
  }
});
