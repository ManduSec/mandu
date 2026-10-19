/**
 * context-proxy.test — start-or-reuse of the model-API proxy with injected
 * ServiceDeps (no real port bound, no real npm spawned). Skip logic (base-URL
 * override / MANDU_NO_CONTEXT_PROXY) lives in the MANAGER, not here.
 */
import { test } from "node:test";
import { Layout } from "../../src/services/layout.js";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startContextProxy, ContextProxyConflictError, inboundSpecFor, agentStartDir, proxyIdentityMatches } from "../../src/services/context-proxy.js";
import { waitFor, SERVICE_READY_BASE_MS, type ServiceDeps, type WaitOpts } from "../../src/services/primitives.js";
import type { LaunchPlan } from "../../src/types.js";
import { stateAxes } from "../axes.js";
import { SANDBOX_EXEC } from "../../src/seatbelt-profile.js";

// No arbiter is built here and no decision reads an axis; stated anyway
// (protection-modes.md §4). The phase 3 cases matter under `secrets`, where
// local-model is in play.
stateAxes("secrets");

function plan(over: Partial<LaunchPlan> = {}): LaunchPlan {
  return {
    target: "claude", argv: ["claude"], scopeId: "sid-7", tenant: "live", arbiterSock: "/run/b.sock", arbiterSockMode: "pinned" as const, arbiterRuntimeBase: "/tmp/mandu",
    eventDir: "/run/sid/events", cwd: "/w", humanCwd: "/w", basePath: "/usr/bin",
    proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 8789 },
    openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: false, netProxyMitm: false, execWrap: false },
    execWrapCmds: [], ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" },
    noContextProxy: false, fsSync: false,
    noScope: false, writeMcp: true, bestEffort: false, replyFilter: true, ...over,
  };
}

function deps(over: Partial<ServiceDeps> = {}): ServiceDeps {
  return {
    probePort: async () => false,
    probeIdentity: async () => null,
    waitFor: async () => true,
    waitForFile: async () => true,
    startDetachedCmd: () => ({ pid: 12, stop: () => {} }),
    runOnce: () => ({ status: 0, stdout: "", stderr: "" }),
    ...over,
  };
}

/** A matching identity for the default `plan()` (claude, arbiterSock /run/b.sock,
 *  no view map) — what a reusable proxy for this launch would publish. */
function matchingIdentity(over: Record<string, unknown> = {}) {
  return { mandu: true, service: "anthropic-proxy", sessionKey: "sid-7", arbiterSock: "/run/b.sock", viewMap: [], agentCwd: "/w", ...over };
}

test("claude: starts anthropic-proxy with arbiter sock, port and SESSION_KEY = scopeId", async () => {
  let dir = ""; let capturedEnv: Record<string, string | undefined> = {};
  const r = await startContextProxy(plan(), Layout.dev("/repo"), "/run/sid",
    deps({ startDetachedCmd: (_c, _a, { cwd: d, env }) => { dir = d; capturedEnv = env; return { pid: 1, stop: () => {} }; } }));
  assert.equal(dir, "/repo/interceptors/anthropic-proxy");
  assert.equal(capturedEnv["MANDU_ARBITER_SOCK"], "/run/b.sock");
  assert.equal(capturedEnv["MANDU_PROXY_PORT"], "8788");
  assert.equal(capturedEnv["MANDU_PROXY_HOST"], "127.0.0.1");
  assert.equal(capturedEnv["MANDU_SESSION_KEY"], "sid-7");
  assert.deepEqual({ host: r.host, port: r.port }, { host: "127.0.0.1", port: 8788 });
});

test("config-routed targets bind their own reviewed inbound spec (MANDU_INBOUND_SPEC); claude/codex keep the ambient value", async () => {
  assert.equal(inboundSpecFor("opencode"), "opencode");
  assert.equal(inboundSpecFor("openclaw"), "openclaw-agent", "never the lifted `openclaw` spec (trusts read wholesale)");
  assert.equal(inboundSpecFor("claude"), undefined);
  assert.equal(inboundSpecFor("codex"), undefined);
  const saved = process.env["MANDU_INBOUND_SPEC"];
  try {
    process.env["MANDU_INBOUND_SPEC"] = "agentdojo";
    const envFor = async (target: LaunchPlan["target"]) => {
      let captured: Record<string, string | undefined> = {};
      await startContextProxy(plan({ target, argv: [target] }), Layout.dev("/repo"), "/run/sid",
        deps({ startDetachedCmd: (_c, _a, { env }) => { captured = env; return { pid: 1, stop: () => {} }; } }));
      return captured;
    };
    const oc = await envFor("opencode");
    assert.equal(oc["MANDU_INBOUND_SPEC"], "opencode", "the plan-derived spec wins over an ambient one");
    assert.equal(oc["MANDU_SESSION_KEY"], "sid-7", "the spec binds to this session");
    assert.equal((await envFor("openclaw"))["MANDU_INBOUND_SPEC"], "openclaw-agent");
    assert.equal((await envFor("claude"))["MANDU_INBOUND_SPEC"], "agentdojo", "claude keeps the ambient knob (eval harnesses)");
  } finally {
    if (saved === undefined) delete process.env["MANDU_INBOUND_SPEC"]; else process.env["MANDU_INBOUND_SPEC"] = saved;
  }
});

test("plan.viewMap exports as MANDU_VIEW_MAP; absent → the key is not set", async () => {
  let capturedEnv: Record<string, string | undefined> = {};
  const capture = deps({ startDetachedCmd: (_c, _a, { env }) => { capturedEnv = env; return { pid: 1, stop: () => {} }; } });
  await startContextProxy(
    plan({ viewMap: [{ human: "/w", agent: "/dv/agentview" }] }), Layout.dev("/repo"), "/run/sid", capture);
  assert.equal(capturedEnv["MANDU_VIEW_MAP"], JSON.stringify([{ human: "/w", agent: "/dv/agentview" }]));

  capturedEnv = {};
  await startContextProxy(plan(), Layout.dev("/repo"), "/run/sid", capture);
  assert.equal(capturedEnv["MANDU_VIEW_MAP"], undefined);
});

test("agentStartDir: the HumanView launch directory, unless an opencode argv moves (or may move) it", () => {
  const p = (target: LaunchPlan["target"], argv: string[], humanCwd = "/home/u/proj") => agentStartDir({ target, argv, humanCwd });
  assert.equal(p("claude", ["claude", "--add-dir", "/x"]), "/home/u/proj", "claude's relative base is not claimed by its surface; the start dir is still exact");
  assert.equal(p("opencode", ["opencode"]), "/home/u/proj");
  assert.equal(p("opencode", ["opencode", "--print-logs"]), "/home/u/proj");
  assert.equal(p("opencode", ["opencode", "run", "fix the tests"]), "/home/u/proj", "run's positionals are the message");
  assert.equal(p("opencode", ["opencode", "/other/project"]), undefined, "the [project] positional moves it");
  assert.equal(p("opencode", ["opencode", "--log-level", "DEBUG", "/other"]), undefined, "a positional after flags");
  assert.equal(p("opencode", ["opencode", "run", "--dir", "/other", "go"]), undefined);
  assert.equal(p("opencode", ["opencode", "run", "--dir=/other", "go"]), undefined);
  assert.equal(p("opencode", ["opencode", "serve"]), undefined, "a subcommand it cannot place");
  assert.equal(p("opencode", ["opencode"], "relative/dir"), undefined, "never a relative base");
  // openclaw: only the shapes whose workspace the launcher pins here
  assert.equal(p("openclaw", ["openclaw", "chat"]), "/home/u/proj");
  assert.equal(p("openclaw", ["openclaw", "agent", "--local", "-m", "hi"]), "/home/u/proj");
  assert.equal(p("openclaw", ["openclaw", "tui", "--local"]), "/home/u/proj");
  assert.equal(p("openclaw", ["openclaw", "agent", "-m", "hi"]), undefined, "a Gateway client keeps the user's workspace");
  assert.equal(p("openclaw", ["openclaw", "gateway"]), undefined);
  assert.equal(p("openclaw", ["openclaw", "agent", "--local", "--agent", "main", "-m", "hi"]), undefined, "--agent may name a non-default agent");
  assert.equal(p("openclaw", ["node", "wrapper.mjs"]), undefined, "a wrapper the launcher cannot read");
});

test("MANDU_AGENT_CWD: the anthropic-proxy gets the agent start directory, explicitly UNSET when unknown (an ambient value never survives); the reuse key includes it", async () => {
  const saved = process.env["MANDU_AGENT_CWD"];
  process.env["MANDU_AGENT_CWD"] = "/ambient/elsewhere";
  try {
    let capturedEnv: Record<string, string | undefined> = {};
    const capture = deps({ startDetachedCmd: (_c, _a, { env }) => { capturedEnv = env; return { pid: 1, stop: () => {} }; } });
    await startContextProxy(plan({ target: "opencode", argv: ["opencode"], humanCwd: "/home/u/proj" }), Layout.dev("/repo"), "/run/sid", capture);
    assert.equal(capturedEnv["MANDU_AGENT_CWD"], "/home/u/proj");
    capturedEnv = {};
    await startContextProxy(plan({ target: "opencode", argv: ["opencode", "/other"], humanCwd: "/home/u/proj" }), Layout.dev("/repo"), "/run/sid", capture);
    assert.ok("MANDU_AGENT_CWD" in capturedEnv && capturedEnv["MANDU_AGENT_CWD"] === undefined, "explicitly unset");
  } finally {
    if (saved === undefined) delete process.env["MANDU_AGENT_CWD"]; else process.env["MANDU_AGENT_CWD"] = saved;
  }
  // a listening proxy placing relative paths against ANOTHER directory is not adopted
  const id = { mandu: true, service: "anthropic-proxy", arbiterSock: "/run/b.sock", viewMap: [], agentCwd: "/w" };
  assert.equal(proxyIdentityMatches(id, plan(), "anthropic-proxy"), true);
  assert.equal(proxyIdentityMatches({ ...id, agentCwd: "/elsewhere" }, plan(), "anthropic-proxy"), false);
  assert.equal(proxyIdentityMatches({ ...id, agentCwd: undefined }, plan(), "anthropic-proxy"), true, "a proxy naming no base places nothing: safe to adopt");
  assert.equal(proxyIdentityMatches(id, plan({ target: "opencode", argv: ["opencode", "/other"] }), "anthropic-proxy"), false, "a base where this launch has none");
});

test("MANDU_NET_TLS_INSPECTED: set only when THIS launch asked for an inspecting net-proxy; an ambient value never survives", async () => {
  // The model proxy's net gate lets an ALLOWED symbol inside a WebFetch URL
  // through only when the net-proxy will release it on the decrypted request.
  let capturedEnv: Record<string, string | undefined> = {};
  const capture = deps({ startDetachedCmd: (_c, _a, { env }) => { capturedEnv = env; return { pid: 1, stop: () => {} }; } });
  const ask = async (requested: LaunchPlan["requested"]) => {
    capturedEnv = {};
    await startContextProxy(plan({ requested }), Layout.dev("/repo"), "/run/sid", capture);
    return capturedEnv["MANDU_NET_TLS_INSPECTED"];
  };
  const prev = process.env["MANDU_NET_TLS_INSPECTED"];
  process.env["MANDU_NET_TLS_INSPECTED"] = "1"; // stale ambient claim
  try {
    assert.equal(await ask({ netProxy: undefined, netProxyMitm: true, execWrap: false }), "1", "auto net-proxy + mitm");
    assert.equal(await ask({ netProxy: true, netProxyMitm: true, execWrap: false }), "1");
    assert.equal(await ask({ netProxy: false, netProxyMitm: true, execWrap: false }), undefined, "mitm without a net-proxy inspects nothing");
    assert.equal(await ask({ netProxy: true, netProxyMitm: false, execWrap: false }), undefined, "a blind tunnel is the default");
  } finally {
    if (prev === undefined) delete process.env["MANDU_NET_TLS_INSPECTED"]; else process.env["MANDU_NET_TLS_INSPECTED"] = prev;
  }
});

test("MANDU_SECRET_POSTURE: read-blocked only on darwin with the confidentiality axis on and sandbox-exec present; an ambient value never survives", async () => {
  // handling-prompt.md §2: the read-blocked section tells the model that
  // credential-file reads fail by design on macOS.
  let capturedEnv: Record<string, string | undefined> = {};
  const ask = async (platform: NodeJS.Platform, confidentiality: boolean, hasSandboxExec = true) => {
    capturedEnv = {};
    await startContextProxy(
      plan({ effectiveAxes: { confidentiality, integrity: false } }), Layout.dev("/repo"), "/run/sid",
      deps({
        platform,
        commandExists: (c) => c === SANDBOX_EXEC && hasSandboxExec,
        startDetachedCmd: (_c, _a, { env }) => { capturedEnv = env; return { pid: 1, stop: () => {} }; },
      }),
    );
    return capturedEnv["MANDU_SECRET_POSTURE"];
  };
  const prev = process.env["MANDU_SECRET_POSTURE"];
  process.env["MANDU_SECRET_POSTURE"] = "read-blocked"; // stale ambient claim
  try {
    assert.equal(await ask("darwin", true), "read-blocked");
    assert.equal(await ask("darwin", true, false), undefined, "no sandbox-exec: the launch is gated, not read-blocked");
    assert.equal(await ask("darwin", false), undefined, "confidentiality off (mode off): no posture");
    assert.equal(await ask("linux", true), undefined, "Linux twins explain themselves; no prediction");
  } finally {
    if (prev === undefined) delete process.env["MANDU_SECRET_POSTURE"]; else process.env["MANDU_SECRET_POSTURE"] = prev;
  }
});

test("codex: starts openai-proxy on the openaiProxy endpoint", async () => {
  let dir = ""; let capturedEnv: Record<string, string | undefined> = {};
  const r = await startContextProxy(plan({ target: "codex" }), Layout.dev("/repo"), "/run/sid",
    deps({ startDetachedCmd: (_c, _a, { cwd: d, env }) => { dir = d; capturedEnv = env; return { pid: 1, stop: () => {} }; } }));
  assert.equal(dir, "/repo/interceptors/openai-proxy");
  assert.equal(capturedEnv["MANDU_PROXY_PORT"], "8789");
  assert.equal(capturedEnv["MANDU_PROXY_HOST"], "127.0.0.1");
  assert.deepEqual({ host: r.host, port: r.port }, { host: "127.0.0.1", port: 8789 });
});

test("the human-plane socket reaches both context proxies (symbolShape / sessionRelay, reply-row-reservation.md §3.3, §11.7); an inherited value never leaks through", async () => {
  const prev = process.env["MANDU_ARBITER_HUMAN_SOCK"];
  process.env["MANDU_ARBITER_HUMAN_SOCK"] = "/stale/human.sock";
  try {
    let claudeEnv: Record<string, string | undefined> = {};
    await startContextProxy(plan({ arbiterHumanSock: "/run/human/i.sock" }), Layout.dev("/repo"), "/run/sid",
      deps({ startDetachedCmd: (_c, _a, { env }) => { claudeEnv = env; return { pid: 1, stop: () => {} }; } }));
    assert.equal(claudeEnv["MANDU_ARBITER_HUMAN_SOCK"], "/run/human/i.sock");

    let noHumanEnv: Record<string, string | undefined> = { MANDU_ARBITER_HUMAN_SOCK: "x" };
    await startContextProxy(plan({ arbiterHumanSock: null }), Layout.dev("/repo"), "/run/sid",
      deps({ startDetachedCmd: (_c, _a, { env }) => { noHumanEnv = env; return { pid: 1, stop: () => {} }; } }));
    assert.equal(noHumanEnv["MANDU_ARBITER_HUMAN_SOCK"], undefined, "absent → unset, not the inherited one");

    let codexEnv: Record<string, string | undefined> = { MANDU_ARBITER_HUMAN_SOCK: "x" };
    await startContextProxy(plan({ target: "codex", arbiterHumanSock: "/run/human/i.sock" }), Layout.dev("/repo"), "/run/sid",
      deps({ startDetachedCmd: (_c, _a, { env }) => { codexEnv = env; return { pid: 1, stop: () => {} }; } }));
    assert.equal(codexEnv["MANDU_ARBITER_HUMAN_SOCK"], "/run/human/i.sock", "the Codex proxy reserves rows too (§11.7)");

    let codexNoHumanEnv: Record<string, string | undefined> = { MANDU_ARBITER_HUMAN_SOCK: "x" };
    await startContextProxy(plan({ target: "codex", arbiterHumanSock: null }), Layout.dev("/repo"), "/run/sid",
      deps({ startDetachedCmd: (_c, _a, { env }) => { codexNoHumanEnv = env; return { pid: 1, stop: () => {} }; } }));
    assert.equal(codexNoHumanEnv["MANDU_ARBITER_HUMAN_SOCK"], undefined, "codex, absent → unset, not the inherited one");
  } finally {
    if (prev === undefined) delete process.env["MANDU_ARBITER_HUMAN_SOCK"]; else process.env["MANDU_ARBITER_HUMAN_SOCK"] = prev;
  }
});

test("codex: fail-closed error names openai-proxy when the port never comes up", async () => {
  await assert.rejects(
    startContextProxy(plan({ target: "codex" }), Layout.dev("/repo"), "/run/sid",
      deps({ waitFor: async () => false })),
    /openai-proxy.*did not come up/i,
  );
});

test("plan-derived env keys override stale process.env; MANDU_UPSTREAM and the reply-reserve knobs ride through", async () => {
  const saved: Record<string, string | undefined> = {
    MANDU_PROXY_PORT: process.env["MANDU_PROXY_PORT"],
    MANDU_PROXY_HOST: process.env["MANDU_PROXY_HOST"],
    MANDU_ARBITER_SOCK: process.env["MANDU_ARBITER_SOCK"],
    MANDU_UPSTREAM: process.env["MANDU_UPSTREAM"],
    MANDU_REPLY_RESERVE: process.env["MANDU_REPLY_RESERVE"],
    MANDU_REPLY_RESERVE_MAX: process.env["MANDU_REPLY_RESERVE_MAX"],
  };
  try {
    process.env["MANDU_PROXY_PORT"] = "9999";
    process.env["MANDU_PROXY_HOST"] = "10.0.0.1";
    process.env["MANDU_ARBITER_SOCK"] = "/stale.sock";
    process.env["MANDU_UPSTREAM"] = "http://mock.example:1";
    process.env["MANDU_REPLY_RESERVE"] = "0";
    process.env["MANDU_REPLY_RESERVE_MAX"] = "24";
    let capturedEnv: Record<string, string | undefined> = {};
    await startContextProxy(plan(), Layout.dev("/repo"), "/run/sid",
      deps({ startDetachedCmd: (_c, _a, { env }) => { capturedEnv = env; return { pid: 1, stop: () => {} }; } }));
    // Explicit plan-derived keys WIN over stale ambient values…
    assert.equal(capturedEnv["MANDU_PROXY_PORT"], "8788");
    assert.equal(capturedEnv["MANDU_PROXY_HOST"], "127.0.0.1");
    assert.equal(capturedEnv["MANDU_ARBITER_SOCK"], "/run/b.sock");
    // …while unrelated knobs ride through unchanged (mock-upstream e2e contract).
    assert.equal(capturedEnv["MANDU_UPSTREAM"], "http://mock.example:1");
    // Reply row reservation's kill switch and cap reach the proxy (reply-row-reservation.md §3.2).
    assert.equal(capturedEnv["MANDU_REPLY_RESERVE"], "0");
    assert.equal(capturedEnv["MANDU_REPLY_RESERVE_MAX"], "24");
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
  }
});

test("reuses a listening proxy ONLY when its identity matches (same service/arbiter/view-map)", async () => {
  let started = 0;
  const r = await startContextProxy(plan(), Layout.dev("/repo"), "/run/sid",
    deps({
      probePort: async () => true,
      probeIdentity: async () => matchingIdentity(),
      startDetachedCmd: () => { started++; return { pid: 1, stop: () => {} }; },
    }));
  r.stop(); // a reused proxy must never be torn down by us
  assert.equal(started, 0, "no new proxy spawned");
});

test("a matching-arbiter proxy with a DIFFERENT sessionKey is still reused (sessionKey not part of the key)", async () => {
  let started = 0;
  await startContextProxy(plan(), Layout.dev("/repo"), "/run/sid",
    deps({
      probePort: async () => true,
      probeIdentity: async () => matchingIdentity({ sessionKey: "some-other-session" }),
      startDetachedCmd: () => { started++; return { pid: 1, stop: () => {} }; },
    }));
  assert.equal(started, 0);
});

test("FAILS CLOSED when the listening proxy has a DIFFERENT arbiter socket (wrong symbol table)", async () => {
  let started = 0;
  await assert.rejects(
    startContextProxy(plan(), Layout.dev("/repo"), "/run/sid",
      deps({
        probePort: async () => true,
        probeIdentity: async () => matchingIdentity({ arbiterSock: "/run/OTHER.sock" }),
        startDetachedCmd: () => { started++; return { pid: 1, stop: () => {} }; },
      })),
    /occupied by another Mandu.*arbiter=\/run\/OTHER\.sock/i,
  );
  assert.equal(started, 0, "never spawns over an occupied port");
});

test("FAILS CLOSED when the listening proxy has a DIFFERENT view map (wrong worktree routing)", async () => {
  await assert.rejects(
    startContextProxy(plan({ viewMap: [{ human: "/w", agent: "/dv/agentview" }] }), Layout.dev("/repo"), "/run/sid",
      deps({
        probePort: async () => true,
        // Same arbiter, but a proxy with NO view map — routing would be wrong.
        probeIdentity: async () => matchingIdentity({ viewMap: [] }),
      })),
    /occupied by another Mandu/i,
  );
});

test("FAILS CLOSED when the port is held by a foreign (non-Mandu) server", async () => {
  await assert.rejects(
    startContextProxy(plan(), Layout.dev("/repo"), "/run/sid",
      deps({ probePort: async () => true, probeIdentity: async () => ({ mandu: false }) })),
    /occupied by a non-Mandu server/i,
  );
  // …and when nothing answers the identity probe at all (bare TCP listener).
  await assert.rejects(
    startContextProxy(plan(), Layout.dev("/repo"), "/run/sid",
      deps({ probePort: async () => true, probeIdentity: async () => null })),
    /no \/_mandu\/identity/i,
  );
});

test("codex target: reuse requires an openai-proxy identity (service must match)", async () => {
  // A listening anthropic-proxy must NOT be adopted by a codex launch.
  await assert.rejects(
    startContextProxy(plan({ target: "codex" }), Layout.dev("/repo"), "/run/sid",
      deps({ probePort: async () => true, probeIdentity: async () => matchingIdentity() })),
    /occupied by another Mandu anthropic-proxy/i,
  );
  // The matching openai-proxy identity IS reused.
  let started = 0;
  await startContextProxy(plan({ target: "codex" }), Layout.dev("/repo"), "/run/sid",
    deps({
      probePort: async () => true,
      probeIdentity: async () => matchingIdentity({ service: "openai-proxy" }),
      startDetachedCmd: () => { started++; return { pid: 1, stop: () => {} }; },
    }));
  assert.equal(started, 0);
});

test("throws when the port never comes up (fail-closed; manager applies --best-effort)", async () => {
  let stopped = 0;
  await assert.rejects(
    startContextProxy(plan(), Layout.dev("/repo"), "/run/sid",
      deps({ waitFor: async () => false, startDetachedCmd: () => ({ pid: 1, stop: () => { stopped++; } }) })),
    /anthropic-proxy.*did not come up/i,
  );
  assert.equal(stopped, 1); // the failed start was torn down
});

test("readiness deadline: load-aware and env-overridable (runtime-instances.md §14.6), not the old fixed ~10 s; expiry stays fail-closed", async () => {
  await withRunDir(async (dir) => {
    const seen: WaitOpts[] = [];
    const saved = process.env["MANDU_SERVICE_READY_TIMEOUT_MS"];
    delete process.env["MANDU_SERVICE_READY_TIMEOUT_MS"];
    try {
      // Default: at least the idle base (30 s) of probes 100 ms apart, split
      // over the port-file wait and the listen wait from ONE budget.
      await startContextProxy(plan({ proxy: { host: "127.0.0.1", port: 0 } }), Layout.dev("/repo"), dir,
        deps({
          startDetachedCmd: () => { writeFileSync(join(dir, "anthropic-proxy.port"), "41000"); return { pid: 1, stop: () => {} }; },
          waitForFile: async (_p, o) => { seen.push(o); return true; },
          waitFor: async (check, o) => { seen.push(o); return Boolean(await check()); },
          probePort: async () => true,
          probeIdentity: async () => matchingIdentity(),
        }));
      assert.ok(seen[0]!.tries * seen[0]!.delayMs >= SERVICE_READY_BASE_MS - 1000, `port-file wait covers the base deadline: ${JSON.stringify(seen[0])}`);
      assert.ok(seen[1]!.tries * seen[1]!.delayMs >= SERVICE_READY_BASE_MS - 1000, "the listen wait gets what is left of it");
      // The override, in ms: a launch that fails closed after it, naming it.
      process.env["MANDU_SERVICE_READY_TIMEOUT_MS"] = "300";
      seen.length = 0;
      let stopped = 0;
      await assert.rejects(
        startContextProxy(plan(), Layout.dev("/repo"), dir,
          deps({ waitFor: async (_c, o) => { seen.push(o); return false; }, startDetachedCmd: () => ({ pid: 1, stop: () => { stopped++; } }) })),
        /anthropic-proxy \(context proxy\) did not come up on 127\.0\.0\.1:8788 \(not ready within 300 ms; MANDU_SERVICE_READY_TIMEOUT_MS/,
      );
      assert.equal(seen[0]!.tries, 3);
      assert.equal(stopped, 1, "torn down");
    } finally {
      if (saved === undefined) delete process.env["MANDU_SERVICE_READY_TIMEOUT_MS"]; else process.env["MANDU_SERVICE_READY_TIMEOUT_MS"] = saved;
    }
  });
});

test("a proxy that EXITS before it is ready ends the wait at once (no full deadline) and fails closed naming the exit", async () => {
  let stopped = 0;
  let checks = 0;
  const t0 = Date.now();
  await assert.rejects(
    startContextProxy(plan(), Layout.dev("/repo"), "/run/sid",
      deps({
        // The real waitFor, so giveUp is honored; the port never answers.
        waitFor,
        probePort: async () => { checks++; return false; },
        startDetachedCmd: () => ({ pid: 1, stop: () => { stopped++; }, exited: () => (checks >= 2 ? { code: 1, signal: null } : null) }),
      })),
    /anthropic-proxy \(context proxy\) did not come up on 127\.0\.0\.1:8788 \(it exited with code 1 before becoming ready; its log: /,
  );
  assert.ok(Date.now() - t0 < 5000, "did not wait out the deadline");
  assert.equal(stopped, 1);
});

test("start path re-verifies identity: a CONCURRENT foreign proxy winning the port fails CLOSED", async () => {
  // Race: nothing on the port when we check, so we start; our child dies with
  // EADDRINUSE while a DIFFERENT-arbiter proxy (a concurrent launch) wins the
  // bind. The port is UP but foreign — we must NOT adopt it.
  let probeCount = 0;
  let stopped = 0;
  const err = await startContextProxy(plan(), Layout.dev("/repo"), "/run/sid",
    deps({
      probePort: async () => probeCount++ > 0, // false on the top reuse-check, then up
      probeIdentity: async () => ({ mandu: true, service: "anthropic-proxy", arbiterSock: "/run/OTHER.sock", viewMap: [] }),
      waitFor: async (check) => check(), // actually evaluate the predicate
      startDetachedCmd: () => ({ pid: 1, stop: () => { stopped++; } }),
    }),
  ).then(() => null, (e) => e as Error);
  assert.ok(err instanceof ContextProxyConflictError, "a wrong-session proxy after start is a conflict");
  assert.equal((err as ContextProxyConflictError).failClosedFatal, true);
  assert.match(err!.message, /foreign or wrong-session proxy/i);
  assert.equal(stopped, 1, "our dead child was torn down");
});

test("start path adopts our OWN child when its identity matches", async () => {
  let probeCount = 0;
  const r = await startContextProxy(plan({ viewMap: [{ human: "/w", agent: "/dv/agentview" }] }), Layout.dev("/repo"), "/run/sid",
    deps({
      probePort: async () => probeCount++ > 0, // free at first, up after start
      // Our child publishes an identity matching THIS plan (same arbiter + view map).
      probeIdentity: async () => ({ mandu: true, service: "anthropic-proxy", arbiterSock: "/run/b.sock", viewMap: [{ human: "/w", agent: "/dv/agentview" }], agentCwd: "/w" }),
      waitFor: async (check) => check(),
    }),
  );
  assert.deepEqual({ host: r.host, port: r.port }, { host: "127.0.0.1", port: 8788 });
});

test("an occupied-port CONFLICT is flagged failClosedFatal (so --best-effort cannot override it)", async () => {
  const err = await startContextProxy(plan(), Layout.dev("/repo"), "/run/sid",
    deps({ probePort: async () => true, probeIdentity: async () => ({ mandu: true, service: "anthropic-proxy", arbiterSock: "/run/OTHER.sock", viewMap: [] }) }),
  ).then(() => null, (e) => e as Error);
  assert.ok(err instanceof ContextProxyConflictError);
  assert.equal((err as ContextProxyConflictError).failClosedFatal, true);
});

// ── ephemeral port (MANDU_PROXY_PORT=0): kernel-assigned, published via the
// port file, adopted by the launcher. The point: no stale daemon can ever
// squat this launch's rendezvous, so the conflict class above cannot occur.

/** Run `fn` with a REAL tmp scope-run dir (the port-file path must exist). */
async function withRunDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-ctx-"));
  try { await fn(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

test("port 0: skips the reuse probe, spawns with port 0 + port file, adopts the bound port", async () => {
  await withRunDir(async (dir) => {
    let capturedEnv: Record<string, string | undefined> = {};
    const probed: number[] = [];
    const r = await startContextProxy(plan({ proxy: { host: "127.0.0.1", port: 0 } }), Layout.dev("/repo"), dir,
      deps({
        probePort: async (_h, p) => { probed.push(p); return true; },
        probeIdentity: async () => matchingIdentity(),
        waitForFile: async (p) => existsSync(p),
        waitFor: async (check) => Boolean(await check()),
        startDetachedCmd: (_c, _a, { env }) => {
          capturedEnv = env;
          // The fake proxy publishes its kernel-assigned port, as server-main does.
          writeFileSync(env["MANDU_PORT_FILE"]!, "45678");
          return { pid: 1, stop: () => {} };
        },
      }));
    assert.equal(capturedEnv["MANDU_PROXY_PORT"], "0");
    assert.equal(capturedEnv["MANDU_PORT_FILE"], join(dir, "anthropic-proxy.port"));
    assert.equal(r.port, 45678, "the launcher adopted the published port");
    assert.ok(!probed.includes(0), "never probed port 0 (no reuse rendezvous exists)");
  });
});

test("port 0: no port file within the wait is fail-closed (torn down)", async () => {
  await withRunDir(async (dir) => {
    let stopped = 0;
    await assert.rejects(
      startContextProxy(plan({ proxy: { host: "127.0.0.1", port: 0 } }), Layout.dev("/repo"), dir,
        deps({
          waitForFile: async () => false,
          startDetachedCmd: () => ({ pid: 1, stop: () => { stopped++; } }),
        })),
      /anthropic-proxy.*did not come up.*no port file.*its log: .*anthropic-proxy\.log/i,
    );
    assert.equal(stopped, 1);
  });
});

test("port 0: a garbled port file is fail-closed (never compose a base URL from it)", async () => {
  await withRunDir(async (dir) => {
    let stopped = 0;
    await assert.rejects(
      startContextProxy(plan({ proxy: { host: "127.0.0.1", port: 0 } }), Layout.dev("/repo"), dir,
        deps({
          waitForFile: async (p) => existsSync(p),
          startDetachedCmd: (_c, _a, { env }) => {
            writeFileSync(env["MANDU_PORT_FILE"]!, "EADDRINUSE oops");
            return { pid: 1, stop: () => { stopped++; } };
          },
        })),
      /unusable port/i,
    );
    assert.equal(stopped, 1);
  });
});

test("port 0: a STALE port file from a previous run is cleared before the spawn", async () => {
  await withRunDir(async (dir) => {
    // A leftover file with a plausible port. If it survived, waitForFile would
    // see it instantly and the launcher would adopt a port nobody owns.
    writeFileSync(join(dir, "anthropic-proxy.port"), "59999");
    await assert.rejects(
      startContextProxy(plan({ proxy: { host: "127.0.0.1", port: 0 } }), Layout.dev("/repo"), dir,
        deps({
          // The fake proxy never writes; a real existence check must time out
          // BECAUSE the stale file was removed.
          waitForFile: async (p) => existsSync(p),
        })),
      /no port file/i,
    );
  });
});

test("port 0: fixed-port launches do NOT get a port file (env key unset)", async () => {
  let capturedEnv: Record<string, string | undefined> = {};
  await startContextProxy(plan(), Layout.dev("/repo"), "/run/sid",
    deps({ startDetachedCmd: (_c, _a, { env }) => { capturedEnv = env; return { pid: 1, stop: () => {} }; } }));
  assert.equal(capturedEnv["MANDU_PORT_FILE"], undefined);
});

// ── A declared main model (plan 11 §5, phase 3; plan.tllmEndpoint) ──────────

const tllm = { name: "gpu", url: "http://localhost:8080/", local: true, upstream: "http://127.0.0.1:8080" };

test("plan.tllmEndpoint: its upstream is the proxy's MANDU_UPSTREAM, over any ambient value; without it the ambient value rides through", async () => {
  const saved = process.env["MANDU_UPSTREAM"];
  try {
    process.env["MANDU_UPSTREAM"] = "http://mock.example:1";
    const envFor = async (over: Partial<LaunchPlan>) => {
      let captured: Record<string, string | undefined> = {};
      await startContextProxy(plan(over), Layout.dev("/repo"), "/run/sid",
        deps({ startDetachedCmd: (_c, _a, { env }) => { captured = env; return { pid: 1, stop: () => {} }; } }));
      return captured;
    };
    assert.equal((await envFor({ tllmEndpoint: tllm }))["MANDU_UPSTREAM"], "http://127.0.0.1:8080");
    assert.equal((await envFor({}))["MANDU_UPSTREAM"], "http://mock.example:1");
    delete process.env["MANDU_UPSTREAM"];
    assert.equal("MANDU_UPSTREAM" in (await envFor({})), false, "no key invented without a declared main model");
  } finally {
    if (saved === undefined) delete process.env["MANDU_UPSTREAM"]; else process.env["MANDU_UPSTREAM"] = saved;
  }
});

test("plan.tllmEndpoint: a proxy already listening on a pinned port is NEVER adopted, even with a matching identity (its upstream is unknown); fatal under --best-effort", async () => {
  let started = 0;
  let identityAsked = 0;
  await assert.rejects(
    startContextProxy(plan({ tllmEndpoint: tllm, bestEffort: true }), Layout.dev("/repo"), "/run/sid",
      deps({
        probePort: async () => true,
        probeIdentity: async () => { identityAsked++; return matchingIdentity(); },
        startDetachedCmd: () => { started++; return { pid: 1, stop: () => {} }; },
      })),
    (e: Error) => {
      assert.ok(e instanceof ContextProxyConflictError);
      assert.equal((e as ContextProxyConflictError).failClosedFatal, true);
      assert.match(e.message, /127\.0\.0\.1:8788 already has a model proxy listening/);
      assert.match(e.message, /your main model "gpu" \(http:\/\/localhost:8080\/\)/);
      assert.match(e.message, /unset MANDU_PROXY_PORT/);
      return true;
    },
  );
  assert.equal(started, 0, "nothing spawned");
  assert.equal(identityAsked, 0, "refused before trusting any identity");
});

test("plan.tllmEndpoint on port 0 (the default): a fresh proxy starts with the declared upstream, no reuse probe", async () => {
  await withRunDir(async (dir) => {
    let capturedEnv: Record<string, string | undefined> = {};
    const probed: number[] = [];
    const r = await startContextProxy(plan({ proxy: { host: "127.0.0.1", port: 0 }, tllmEndpoint: tllm }), Layout.dev("/repo"), dir,
      deps({
        probePort: async (_h, p) => { probed.push(p); return true; },
        probeIdentity: async () => matchingIdentity(),
        waitForFile: async (p) => existsSync(p),
        waitFor: async (check) => Boolean(await check()),
        startDetachedCmd: (_c, _a, { env }) => {
          capturedEnv = env;
          writeFileSync(env["MANDU_PORT_FILE"]!, "45679");
          return { pid: 1, stop: () => {} };
        },
      }));
    assert.equal(r.port, 45679);
    assert.equal(capturedEnv["MANDU_UPSTREAM"], "http://127.0.0.1:8080");
    assert.ok(!probed.includes(0));
  });
});

// ── Routed OpenAI-family providers (agent-model-route.ts; plan.openaiRoutes) ──

const routes = [
  { id: "openai", api: "openai-responses" as const, upstream: "https://api.openai.com/v1" },
  { id: "deepseek", api: "openai-completions" as const, upstream: "https://api.deepseek.com/v1" },
];

test("plan.openaiRoutes: the proxy gets each routed provider's real base URL; without routes the key is explicitly unset", async () => {
  const saved = process.env["MANDU_OPENAI_UPSTREAMS"];
  try {
    process.env["MANDU_OPENAI_UPSTREAMS"] = '{"evil":"https://evil.example/v1"}';
    const envFor = async (over: Partial<LaunchPlan>) => {
      let captured: Record<string, string | undefined> = {};
      await startContextProxy(plan(over), Layout.dev("/repo"), "/run/sid",
        deps({ startDetachedCmd: (_c, _a, { env }) => { captured = env; return { pid: 1, stop: () => {} }; } }));
      return captured;
    };
    const withRoutes = await envFor({ target: "openclaw", openaiRoutes: routes });
    assert.deepEqual(JSON.parse(withRoutes["MANDU_OPENAI_UPSTREAMS"]!), { openai: "https://api.openai.com/v1", deepseek: "https://api.deepseek.com/v1" });
    const without = await envFor({ target: "openclaw" });
    assert.ok("MANDU_OPENAI_UPSTREAMS" in without && without["MANDU_OPENAI_UPSTREAMS"] === undefined, "an ambient value cannot add a route");
  } finally {
    if (saved === undefined) delete process.env["MANDU_OPENAI_UPSTREAMS"]; else process.env["MANDU_OPENAI_UPSTREAMS"] = saved;
  }
});

test("plan.openaiRoutes: a route whose agent runs tool calls written as text (Goose's ollama) reaches the proxy as MANDU_OPENAI_TEXT_CALLS; none ⇒ explicitly unset", async () => {
  const saved = process.env["MANDU_OPENAI_TEXT_CALLS"];
  try {
    process.env["MANDU_OPENAI_TEXT_CALLS"] = "[]"; // an ambient value cannot turn the check off
    const envFor = async (over: Partial<LaunchPlan>) => {
      let captured: Record<string, string | undefined> = {};
      await startContextProxy(plan(over), Layout.dev("/repo"), "/run/sid",
        deps({ startDetachedCmd: (_c, _a, { env }) => { captured = env; return { pid: 1, stop: () => {} }; } }));
      return captured;
    };
    const ollama = { id: "ollama", api: "openai-completions" as const, upstream: "http://127.0.0.1:11434", textCalls: true };
    const withText = await envFor({ target: "goose", openaiRoutes: [...routes, ollama] });
    assert.deepEqual(JSON.parse(withText["MANDU_OPENAI_TEXT_CALLS"]!), ["ollama"]);
    assert.equal(JSON.parse(withText["MANDU_OPENAI_UPSTREAMS"]!)["ollama"], "http://127.0.0.1:11434");
    const without = await envFor({ target: "goose", openaiRoutes: routes });
    assert.ok("MANDU_OPENAI_TEXT_CALLS" in without && without["MANDU_OPENAI_TEXT_CALLS"] === undefined);
  } finally {
    if (saved === undefined) delete process.env["MANDU_OPENAI_TEXT_CALLS"]; else process.env["MANDU_OPENAI_TEXT_CALLS"] = saved;
  }
});

test("plan.openaiRoutes: a proxy already listening on a pinned port is NEVER adopted (its routes are unknown); fatal", async () => {
  let started = 0;
  await assert.rejects(
    startContextProxy(plan({ target: "openclaw", openaiRoutes: routes, bestEffort: true }), Layout.dev("/repo"), "/run/sid",
      deps({
        probePort: async () => true,
        probeIdentity: async () => matchingIdentity(),
        startDetachedCmd: () => { started++; return { pid: 1, stop: () => {} }; },
      })),
    (e: Error) => {
      assert.ok(e instanceof ContextProxyConflictError);
      assert.match(e.message, /routes openai, deepseek through its own/);
      return true;
    },
  );
  assert.equal(started, 0);
});
