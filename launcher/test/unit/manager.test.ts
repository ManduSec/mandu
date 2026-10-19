/**
 * manager.test — orchestration + fail-closed + teardown, with injected service
 * fns so nothing real is spawned.
 */
import { test } from "node:test";
import { Layout } from "../../src/services/layout.js";
import assert from "node:assert/strict";
import { startServices } from "../../src/services/manager.js";
import type { LaunchPlan } from "../../src/types.js";

function plan(over: Partial<LaunchPlan> = {}): LaunchPlan {
  return {
    target: "claude", argv: ["claude"], scopeId: "sid", tenant: "live", arbiterSock: "/b.sock", arbiterSockMode: "pinned" as const, arbiterRuntimeBase: "/tmp/mandu", eventDir: "/e",
    cwd: "/w", humanCwd: "/w", noContextProxy: true, fsSync: false, basePath: "/usr/bin", proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 8789 },
    openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: false, netProxyMitm: false, execWrap: false },
    execWrapCmds: ["curl"], ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" },
    noScope: false, writeMcp: true, bestEffort: false, replyFilter: true, ...over,
  };
}

const okDeps = {
  writeAgentConfig: () => ({ envVar: "OPENCLAW_CONFIG_PATH", path: "/run/sid/openclaw.json" }),
  startNetProxy: async () => ({ netProxy: { host: "127.0.0.1", port: 8790 }, mitmCaCert: undefined, stop: () => {} }),
  writeExecShims: () => "/run/sid/exec-shims",
  writeMcpConfig: () => "/w/.mcp.json",
  startContextProxy: async () => ({ host: "127.0.0.1", port: 8788, stop: () => {} }),
  startFsView: async () => null,
  startUllmForwarder: async () => ({ host: "127.0.0.1", port: 8791, url: "http://127.0.0.1:8791", stop: async () => {} }),
  inheritWorkspaceTrust: () => ({ action: "no-config" as const, file: "/nonexistent/.claude.json" }),
  inheritCodexTrust: () => ({ action: "no-config" as const, file: "/nonexistent/config.toml" }),
};

function mockDeps() {
  return {
    writeAgentConfig: () => ({ envVar: "OPENCLAW_CONFIG_PATH", path: "/run/sid/openclaw.json" }),
    startNetProxy: async () => ({ netProxy: { host: "h", port: 1 }, stop: () => {} }),
    writeExecShims: () => "/shim",
    writeMcpConfig: () => "/w/.mcp.json",
    startContextProxy: async () => ({ host: "127.0.0.1", port: 8788, stop: () => {} }),
    startFsView: async () => null,
    startUllmForwarder: async () => ({ host: "127.0.0.1", port: 8791, url: "http://127.0.0.1:8791", stop: async () => {} }),
    inheritWorkspaceTrust: () => ({ action: "no-config" as const, file: "/nonexistent/.claude.json" }),
    inheritCodexTrust: () => ({ action: "no-config" as const, file: "/nonexistent/config.toml" }),
  };
}

test("no services requested but mcp on → only mcp populated", async () => {
  const p = plan();
  const h = await startServices(p, Layout.dev("/repo"), "/run/sid", okDeps);
  assert.equal(p.netProxy, undefined);
  assert.equal(p.shimDir, undefined);
  assert.equal(p.mcpConfig, "/w/.mcp.json");
  await h.stop();
});

test("codex: the MCP step also records the server entries (env-compose splices them as -c overrides); --no-policy-mcp keeps inspect only; --no-mcp none", async () => {
  const p = plan({ target: "codex", argv: ["codex", "exec"] });
  await (await startServices(p, Layout.dev("/repo"), "/run/sid", okDeps)).stop();
  assert.deepEqual(Object.keys(p.mcpServers ?? {}).sort(), ["mandu-inspect", "mandu-policy"]);
  assert.equal(p.mcpServers!["mandu-policy"]!.env["MANDU_SCOPE_ID"], "sid");
  const q = plan({ target: "codex", argv: ["codex", "exec"], writePolicyMcp: false });
  await (await startServices(q, Layout.dev("/repo"), "/run/sid", okDeps)).stop();
  assert.deepEqual(Object.keys(q.mcpServers ?? {}), ["mandu-inspect"]);
  const r = plan({ target: "codex", argv: ["codex", "exec"], writeMcp: false });
  await (await startServices(r, Layout.dev("/repo"), "/run/sid", okDeps)).stop();
  assert.equal(r.mcpServers, undefined);
});

test("net-proxy / exec-wrap DEFAULT-ON (tri-state undefined) → started; exec-wrap degrades with a warning, the egress gate REFUSES the launch (a1)", async () => {
  // undefined = the default-on posture: both services start.
  const p = plan({ requested: { netProxy: undefined, netProxyMitm: false, execWrap: undefined } });
  await startServices(p, Layout.dev("/repo"), "/run/sid", okDeps);
  assert.deepEqual(p.netProxy, { host: "127.0.0.1", port: 8790 });
  assert.equal(p.shimDir, "/run/sid/exec-shims");

  // Default-on + a host where the egress gate cannot start: the launch is
  // REFUSED (release checklist a1) — it used to continue with no egress gate
  // after one easy-to-miss warning. The refusal names the deliberate opt-out.
  let stopped = 0;
  const p2 = plan({ requested: { netProxy: undefined, netProxyMitm: false, execWrap: undefined } });
  await assert.rejects(
    startServices(p2, Layout.dev("/repo"), "/run/sid", {
      ...okDeps,
      startContextProxy: async () => ({ host: "127.0.0.1", port: 8788, stop: () => { stopped++; } }),
      startNetProxy: async () => { throw new Error("no npm here"); },
    }),
    (e: Error) => {
      assert.match(e.message, /the egress gate \(net-proxy\) could not start: no npm here/);
      assert.match(e.message, /refusing to launch without it/);
      assert.match(e.message, /--no-net-proxy/);
      assert.match(e.message, /--best-effort/);
      return true;
    },
  );
  assert.equal(p2.netProxy, undefined);
  // (noContextProxy is true in this plan fixture, so nothing was started to tear down.)
  assert.equal(stopped, 0);

  // A foreign/wrong-session proxy on a PINNED port (failClosedFatal): even
  // --best-effort cannot bless it.
  const conflict = Object.assign(new Error("127.0.0.1:8790 is occupied by another Mandu net-proxy"), { failClosedFatal: true });
  await assert.rejects(
    startServices(plan({ bestEffort: true, requested: { netProxy: undefined, netProxyMitm: false, execWrap: false } }), Layout.dev("/repo"), "/run/sid",
      { ...okDeps, startNetProxy: async () => { throw conflict; } }),
    (e: Error) => /refusing to launch without it/.test(e.message) && !/--best-effort\)/.test(e.message),
  );

  // exec-wrap keeps the soft degrade (a PATH shim, not the egress gate).
  const warnings: string[] = [];
  const p3 = plan({ requested: { netProxy: false, netProxyMitm: false, execWrap: undefined } });
  await startServices(p3, Layout.dev("/repo"), "/run/sid",
    { ...okDeps, writeExecShims: () => { throw new Error("read-only fs"); } }, (m) => warnings.push(m));
  assert.equal(p3.shimDir, undefined);
  assert.ok(warnings.some((w) => /exec-wrap.*on by default but failed to start/.test(w)), JSON.stringify(warnings));
});

test("exec-wrap is LIVE only when its shim loads: a failed probe degrades the default, refuses an explicit request, and never shadows PATH", async () => {
  const cannotLoad = async () => { throw new Error("the exec-wrap shim cannot load (Error [ERR_MODULE_NOT_FOUND]: Cannot find module tsx)"); };
  const probed: Array<[string, string]> = [];

  // The shim loads: probed once, on the first command, then LIVE.
  // It is handed what keys its kept pass (exec-shims.ts probeExecShimCached):
  // this launch's layout and arbiter socket.
  const okWarn: string[] = [];
  const ctxs: Array<{ layout: Layout; arbiterSock: string }> = [];
  const layout = Layout.installed("/opt/mandu");
  const ok = plan({ execWrapCmds: [" ", "curl", "wget"], requested: { netProxy: false, netProxyMitm: false, execWrap: undefined } });
  await startServices(ok, layout, "/run/sid",
    { ...okDeps, probeExecShim: async (dir: string, cmd: string, ctx: { layout: Layout; arbiterSock: string }) => { probed.push([dir, cmd]); ctxs.push(ctx); } }, (m) => okWarn.push(m));
  assert.deepEqual(probed, [["/run/sid/exec-shims", "curl"]]);
  assert.equal(ctxs[0]!.layout, layout);
  assert.equal(ctxs[0]!.arbiterSock, "/b.sock");
  assert.equal(ok.shimDir, "/run/sid/exec-shims");
  assert.ok(okWarn.some((w) => /^exec-wrap LIVE/.test(w)), JSON.stringify(okWarn));

  // Default-on, the shim cannot load: reported down, the launch goes on
  // without it, and the agent's PATH keeps no shim that would crash.
  const warnings: string[] = [];
  const dflt = plan({ requested: { netProxy: false, netProxyMitm: false, execWrap: undefined } });
  await startServices(dflt, Layout.dev("/repo"), "/run/sid", { ...okDeps, probeExecShim: cannotLoad }, (m) => warnings.push(m));
  assert.equal(dflt.shimDir, undefined);
  assert.ok(!warnings.some((w) => /exec-wrap LIVE/.test(w)), `never LIVE: ${JSON.stringify(warnings)}`);
  assert.ok(warnings.some((w) => /service 'exec-wrap' is on by default but failed to start: the exec-wrap shim cannot load .*proceeding WITHOUT it/.test(w)), JSON.stringify(warnings));

  // Asked for explicitly (--exec-wrap): the launch is refused.
  const explicit = plan({ requested: { netProxy: false, netProxyMitm: false, execWrap: true } });
  await assert.rejects(
    startServices(explicit, Layout.dev("/repo"), "/run/sid", { ...okDeps, probeExecShim: cannotLoad }, () => {}),
    /service 'exec-wrap' was requested but failed to start: the exec-wrap shim cannot load .*--best-effort/,
  );
  assert.equal(explicit.shimDir, undefined);
});

test("--no-net-proxy is the deliberate opt-out: no egress gate, no refusal, no warning (a1)", async () => {
  const warnings: string[] = [];
  const p = plan({ requested: { netProxy: false, netProxyMitm: false, execWrap: false } });
  await startServices(p, Layout.dev("/repo"), "/run/sid",
    { ...okDeps, startNetProxy: async () => { throw new Error("must not be called"); } }, (m) => warnings.push(m));
  assert.equal(p.netProxy, undefined);
  assert.ok(!warnings.some((w) => /net-proxy/.test(w)), JSON.stringify(warnings));
});

test("--best-effort still lets a (non-conflict) egress-gate failure through, loudly", async () => {
  const warnings: string[] = [];
  const p = plan({ bestEffort: true, requested: { netProxy: undefined, netProxyMitm: false, execWrap: false } });
  await startServices(p, Layout.dev("/repo"), "/run/sid",
    { ...okDeps, startNetProxy: async () => { throw new Error("boom"); } }, (m) => warnings.push(m));
  assert.equal(p.netProxy, undefined);
  assert.ok(warnings.some((w) => /egress gate \(net-proxy\) could not start: boom — proceeding WITHOUT it \(--best-effort\)/.test(w)), JSON.stringify(warnings));
});

test("explicit --net-proxy is FAIL-CLOSED too: a throwing service aborts, same refusal as the default", async () => {
  const p = plan({ requested: { netProxy: true, netProxyMitm: false, execWrap: false } });
  await assert.rejects(
    startServices(p, Layout.dev("/repo"), "/run/sid",
      { ...okDeps, startNetProxy: async () => { throw new Error("no npm here"); } }),
    /the egress gate \(net-proxy\) could not start: no npm here — refusing to launch without it/,
  );
});

test("ullm-forwarder: starts when landlock-net is not opted out and the U-LLM is Anthropic-bound", async () => {
  let stopped = 0;
  const p = plan(); // landlockNet undefined = default-on; ullm cli/claude
  const h = await startServices(p, Layout.dev("/repo"), "/run/sid", {
    ...okDeps,
    startUllmForwarder: async (o) => {
      assert.ok("upstream" in o && o.upstream === "https://api.anthropic.com", JSON.stringify(o));
      return { host: "127.0.0.1", port: 43210, url: "http://127.0.0.1:43210", stop: async () => { stopped++; } };
    },
  });
  assert.deepEqual(p.ullmForwarder, { host: "127.0.0.1", port: 43210 });
  assert.equal(p.ullm.forwarderUrl, "http://127.0.0.1:43210");
  await h.stop();
  assert.equal(stopped, 1, "forwarder teardown is registered");
});

test("ullm-forwarder: runs BEFORE the mcp config is written (the config carries the pin)", async () => {
  const order: string[] = [];
  const p = plan();
  await startServices(p, Layout.dev("/repo"), "/run/sid", {
    ...okDeps,
    startUllmForwarder: async () => { order.push("forwarder"); return { host: "127.0.0.1", port: 1, url: "http://127.0.0.1:1", stop: async () => {} }; },
    writeMcpConfig: (pl) => { order.push("mcp"); assert.equal(pl.ullm.forwarderUrl, "http://127.0.0.1:1"); return "/w/.mcp.json"; },
  });
  assert.deepEqual(order, ["forwarder", "mcp"]);
});

test("ullm-forwarder: skipped on --no-landlock-net", async () => {
  let started = 0;
  const deps = { ...okDeps, startUllmForwarder: async () => { started++; return { host: "h", port: 1, url: "u", stop: async () => {} }; } };
  const off = plan({ landlockNet: false });
  await startServices(off, Layout.dev("/repo"), "/run/sid", deps);
  assert.equal(off.ullmForwarder, undefined);
  const codexOff = plan({ landlockNet: false, ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "codex" } });
  await startServices(codexOff, Layout.dev("/repo"), "/run/sid", deps);
  assert.equal(codexOff.ullmForwarder, undefined);
  assert.equal(started, 0);
});

test("ullm-forwarder: a Codex U-LLM gets the relay of a model call to the fixed OpenAI pair (never the Anthropic base), or the stand-ins the plan names", async () => {
  const seen: unknown[] = [];
  const deps = { ...okDeps, startUllmForwarder: async (o: unknown) => { seen.push(o); return { host: "127.0.0.1", port: 4321, url: "http://127.0.0.1:4321", stop: async () => {} }; } };
  const codex = plan({ ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "codex" } });
  const warnings: string[] = [];
  await startServices(codex, Layout.dev("/repo"), "/run/sid", deps, (m) => warnings.push(m));
  assert.deepEqual(seen[0], { codex: { api: "https://api.openai.com", chatgpt: "https://chatgpt.com/backend-api/codex" }, host: "127.0.0.1", port: 0 });
  assert.deepEqual(codex.ullmForwarder, { host: "127.0.0.1", port: 4321 });
  assert.equal(codex.ullm.forwarderUrl, "http://127.0.0.1:4321");
  assert.ok(warnings.some((w) => /ullm-forwarder LIVE .*api\.openai\.com.*a model call only/.test(w)), JSON.stringify(warnings));
  const standIn = plan({ ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "codex", codexUpstreams: { api: "http://127.0.0.1:9", chatgpt: "http://127.0.0.1:9/backend-api/codex" } } });
  await startServices(standIn, Layout.dev("/repo"), "/run/sid", deps);
  assert.deepEqual((seen[1] as { codex: unknown }).codex, { api: "http://127.0.0.1:9", chatgpt: "http://127.0.0.1:9/backend-api/codex" });
});

test("ullm-forwarder failure degrades (warn; U-LLM keeps the direct dial), never aborts", async () => {
  const warnings: string[] = [];
  const p = plan();
  await startServices(p, Layout.dev("/repo"), "/run/sid",
    { ...okDeps, startUllmForwarder: async () => { throw new Error("bind failed"); } }, (m) => warnings.push(m));
  assert.equal(p.ullmForwarder, undefined);
  assert.equal(p.ullm.forwarderUrl, undefined);
  assert.ok(warnings.some((w) => /ullm-forwarder failed to start/.test(w)), JSON.stringify(warnings));
});

test("net-proxy + exec-wrap requested → both populated, plan mutated", async () => {
  const p = plan({ requested: { netProxy: true, netProxyMitm: false, execWrap: true } });
  await startServices(p, Layout.dev("/repo"), "/run/sid", okDeps);
  assert.deepEqual(p.netProxy, { host: "127.0.0.1", port: 8790 });
  assert.equal(p.shimDir, "/run/sid/exec-shims");
});

test("truth-in-labeling: a started net-proxy + exec-wrap each announce LIVE", async () => {
  const p = plan({ requested: { netProxy: true, netProxyMitm: false, execWrap: true } });
  const warnings: string[] = [];
  await startServices(p, Layout.dev("/repo"), "/run/sid", okDeps, (m) => warnings.push(m));
  assert.ok(warnings.some((w) => /net-proxy LIVE/.test(w)), `expected net-proxy LIVE, got ${JSON.stringify(warnings)}`);
  assert.ok(warnings.some((w) => /exec-wrap LIVE/.test(w)), `expected exec-wrap LIVE, got ${JSON.stringify(warnings)}`);
});

test("fail-closed: a requested service that throws aborts startServices", async () => {
  const p = plan({ requested: { netProxy: true, netProxyMitm: false, execWrap: false } });
  await assert.rejects(
    startServices(p, Layout.dev("/repo"), "/run/sid", { ...okDeps, startNetProxy: async () => { throw new Error("net-proxy did not come up"); } }),
    /net-proxy/,
  );
});

test("--best-effort: a failing requested service warns and is skipped", async () => {
  const warnings: string[] = [];
  const p = plan({ bestEffort: true, requested: { netProxy: true, netProxyMitm: false, execWrap: false } });
  await startServices(p, Layout.dev("/repo"), "/run/sid",
    { ...okDeps, startNetProxy: async () => { throw new Error("boom"); } }, (m) => warnings.push(m));
  assert.ok(warnings.some((w) => /net-proxy/.test(w)));
  assert.equal(p.netProxy, undefined);
});

test("stop() tears down only what started (net-proxy stop called)", async () => {
  let stopped = 0;
  const p = plan({ requested: { netProxy: true, netProxyMitm: false, execWrap: false } });
  const h = await startServices(p, Layout.dev("/repo"), "/run/sid",
    { ...okDeps, startNetProxy: async () => ({ netProxy: { host: "127.0.0.1", port: 8790 }, mitmCaCert: undefined, stop: () => { stopped++; } }) });
  await h.stop();
  assert.equal(stopped, 1);
});

test("context-proxy runs by default and its stop is registered", async () => {
  let started = 0; let stopped = 0;
  const h = await startServices(plan({ noContextProxy: false }), Layout.dev("/repo"), "/run/sid", {
    ...mockDeps(),
    startContextProxy: async () => { started++; return { host: "127.0.0.1", port: 8788, stop: () => { stopped++; } }; },
  });
  assert.equal(started, 1);
  await h.stop();
  assert.equal(stopped, 1);
});

test("context-proxy's BOUND port is written back to the plan (ephemeral-port adoption)", async () => {
  // A MANDU_PROXY_PORT=0 launch: the service resolves the kernel-assigned
  // port; the env composer reads plan.proxy, so the manager must adopt it.
  const p = plan({ noContextProxy: false, proxy: { host: "127.0.0.1", port: 0 } });
  await startServices(p, Layout.dev("/repo"), "/run/sid", {
    ...mockDeps(),
    startContextProxy: async () => ({ host: "127.0.0.1", port: 45678, stop: () => {} }),
  });
  assert.deepEqual(p.proxy, { host: "127.0.0.1", port: 45678 });

  // codex target: the adoption lands on openaiProxy instead.
  const pc = plan({ noContextProxy: false, target: "codex", openaiProxy: { host: "127.0.0.1", port: 0 } });
  await startServices(pc, Layout.dev("/repo"), "/run/sid", {
    ...mockDeps(),
    startContextProxy: async () => ({ host: "127.0.0.1", port: 45679, stop: () => {} }),
  });
  assert.deepEqual(pc.openaiProxy, { host: "127.0.0.1", port: 45679 });
});

test("context-proxy is skipped on explicit base-URL override and on MANDU_NO_CONTEXT_PROXY", async () => {
  for (const over of [{ anthropicBaseUrl: "http://elsewhere:9" }, { noContextProxy: true }]) {
    let started = 0;
    await startServices(plan({ noContextProxy: false, ...over }), Layout.dev("/repo"), "/run/sid", {
      ...mockDeps(),
      startContextProxy: async () => { started++; return { host: "h", port: 1, stop: () => {} }; },
    });
    assert.equal(started, 0, JSON.stringify(over));
  }
});

test("codex target: the OPENAI override (not the anthropic one) suppresses the context proxy", async () => {
  let started = 0;
  const p = plan({ target: "codex", noContextProxy: false, anthropicBaseUrl: "http://x:1" });
  await startServices(p, Layout.dev("/repo"), "/run/sid", {
    ...mockDeps(),
    startContextProxy: async () => { started++; return { host: "h", port: 1, stop: () => {} }; },
  });
  assert.equal(started, 1); // anthropic override is irrelevant for codex

  // Positive branch: the OPENAI override IS the relevant one for codex.
  let started2 = 0;
  await startServices(plan({ target: "codex", noContextProxy: false, openaiBaseUrl: "http://own:1" }), Layout.dev("/repo"), "/run/sid", {
    ...mockDeps(),
    startContextProxy: async () => { started2++; return { host: "h", port: 1, stop: () => {} }; },
  });
  assert.equal(started2, 0);
});

test("context-proxy failure fails the launch closed (and --best-effort proceeds)", async () => {
  let stopped = 0;
  // boom throws BEFORE a stop exists (context-proxy cleans up its own child on
  // a failed start) — the manager must register NO teardown for it.
  const boom = async (): Promise<{ host: string; port: number; stop: () => void }> => {
    throw new Error("port never came up");
    return { host: "h", port: 1, stop: () => { stopped++; } }; // never reached
  };
  await assert.rejects(
    startServices(plan({ noContextProxy: false }), Layout.dev("/repo"), "/run/sid", { ...mockDeps(), startContextProxy: boom }),
    /context-proxy.*failed to start/,
  );
  const h = await startServices(plan({ noContextProxy: false, bestEffort: true }), Layout.dev("/repo"), "/run/sid",
    { ...mockDeps(), startContextProxy: boom }, () => {});
  // best-effort: launch proceeds (base URL stays on the dead port); teardown
  // resolves and the never-registered context-proxy stop is never called.
  await h.stop();
  assert.equal(stopped, 0);
});

test("--best-effort does NOT swallow a failClosedFatal context-proxy conflict (port held by a stranger)", async () => {
  // A DEAD port is a safe soft-fail under --best-effort, but a LIVE foreign
  // proxy is not: proceeding would route traffic through it. The conflict error
  // carries failClosedFatal, so the launch must abort even with --best-effort.
  const conflict = Object.assign(new Error("port occupied by another Mandu proxy"), { failClosedFatal: true });
  const p = plan({ noContextProxy: false, bestEffort: true });
  await assert.rejects(
    startServices(p, Layout.dev("/repo"), "/run/sid",
      { ...mockDeps(), startContextProxy: async () => { throw conflict; } }, () => {}),
    /hard fail-closed condition.*best-effort cannot override/i,
  );
});

test("fs-view rewrites plan.cwd BEFORE the mcp config is written", async () => {
  const order: string[] = [];
  const p = plan({ fsSync: undefined, writeMcp: true });
  await startServices(p, Layout.dev("/repo"), "/run/sid", {
    ...mockDeps(),
    startFsView: async () => { order.push("fs-view"); return { agentCwd: "/dv/agentview", gitRoot: "/w", agentView: "/dv/agentview", stop: () => {} }; },
    writeMcpConfig: (pl) => { order.push("mcp"); assert.equal(pl.cwd, "/dv/agentview"); return "/dv/agentview/.mcp.json"; },
  });
  assert.equal(p.cwd, "/dv/agentview");
  assert.deepEqual(order, ["fs-view", "mcp"]);
});

test("fs-view runs BEFORE the context proxy and its root pair lands in plan.viewMap (P2)", async () => {
  const order: string[] = [];
  const p = plan({ fsSync: undefined, noContextProxy: false });
  await startServices(p, Layout.dev("/repo"), "/run/sid", {
    ...mockDeps(),
    startFsView: async () => {
      order.push("fs-view");
      return { agentCwd: "/dv/agentview/pkg", gitRoot: "/w", agentView: "/dv/agentview", stop: () => {} };
    },
    startContextProxy: async (pl) => {
      order.push("context-proxy");
      // The pair must already be on the plan when the proxy starts (it exports
      // MANDU_VIEW_MAP from this).
      assert.deepEqual(pl.viewMap, [{ human: "/w", agent: "/dv/agentview" }]);
      return { host: "127.0.0.1", port: 8788, stop: () => {} };
    },
  });
  assert.deepEqual(order, ["fs-view", "context-proxy"]);
  assert.deepEqual(p.viewMap, [{ human: "/w", agent: "/dv/agentview" }]);
});

test("fs-view skip (non-git) leaves plan.viewMap unset — the proxy runs without a map", async () => {
  const p = plan({ fsSync: undefined, noContextProxy: false });
  await startServices(p, Layout.dev("/repo"), "/run/sid", { ...mockDeps(), startFsView: async () => null });
  assert.equal(p.viewMap, undefined);
});

test("fs rung reporting (P5): ACTIVE line when fs-view lands; DEGRADED line on explicit opt-out", async () => {
  // Active: the cooperative-rung line names all three protections.
  const active: string[] = [];
  await startServices(plan({ fsSync: undefined }), Layout.dev("/repo"), "/run/sid", {
    ...mockDeps(),
    startFsView: async () => ({ agentCwd: "/dv/agentview", gitRoot: "/w", agentView: "/dv/agentview", stop: () => {} }),
  }, (m) => active.push(m));
  const rung = active.find((m) => /fs rung ACTIVE/.test(m));
  assert.ok(rung, `expected an ACTIVE rung line, got: ${JSON.stringify(active)}`);
  assert.match(rung!, /prefix map/);
  assert.match(rung!, /sensitive-path gate/);

  // Default (no --fs-sync-eager): the ACTIVE line does not claim eager sync.
  assert.doesNotMatch(rung!, /eager sync/);

  // Eager watcher live (fs-view reported eager:true): the line claims it.
  const eager: string[] = [];
  await startServices(plan({ fsSync: undefined, fsSyncEager: true }), Layout.dev("/repo"), "/run/sid", {
    ...mockDeps(),
    startFsView: async () => ({ agentCwd: "/dv/agentview", gitRoot: "/w", agentView: "/dv/agentview", eager: true, stop: () => {} }),
  }, (m) => eager.push(m));
  const eagerRung = eager.find((m) => /fs rung ACTIVE/.test(m));
  assert.ok(eagerRung, `expected an ACTIVE rung line, got: ${JSON.stringify(eager)}`);
  assert.match(eagerRung!, /eager sync \(tool-call cadence\)/);

  // Explicit opt-out: a loud DEGRADED line (truth-in-labeling).
  const off: string[] = [];
  await startServices(plan({ fsSync: false }), Layout.dev("/repo"), "/run/sid", mockDeps(), (m) => off.push(m));
  const degraded = off.find((m) => /fs rung DEGRADED/.test(m));
  assert.ok(degraded, `expected a DEGRADED rung line, got: ${JSON.stringify(off)}`);
  assert.match(degraded!, /no sensitive-path gate/);

  // Off BY MODE (integrity off — the default `secrets` mode): an informational
  // note, never the "opted out (--no-fs-sync)" warning the user did not ask
  // for (release checklist a4).
  const byMode: string[] = [];
  await startServices(plan({ fsSync: false, fsSyncOffReason: "mode" }), Layout.dev("/repo"), "/run/sid", mockDeps(), (m) => byMode.push(m));
  assert.ok(!byMode.some((m) => /DEGRADED|opted out|--no-fs-sync/.test(m)), JSON.stringify(byMode));
  assert.ok(byMode.some((m) => /^fs rung off by mode: integrity is off/.test(m)), JSON.stringify(byMode));
});

test("nested $HOME-rooted pair DEGRADES (does not abort) — no viewMap, worktree torn down", async () => {
  // A workspace rooted at $HOME with its AgentView state nested under it: the
  // pair the proxy's ViewMap would filter. The launch must NOT abort — it
  // degrades to raw CWD, leaves plan.viewMap unset, and tears the worktree down.
  const warnings: string[] = [];
  let stopped = 0;
  const p = plan({ fsSync: undefined, noContextProxy: false });
  const h = await startServices(p, Layout.dev("/repo"), "/run/sid", {
    ...mockDeps(),
    startFsView: async () => ({
      agentCwd: "/home/u/.mandu/ws/agentview",
      gitRoot: "/home/u",
      agentView: "/home/u/.mandu/ws/agentview", // nested under gitRoot
      stop: () => { stopped++; },
    }),
    startContextProxy: async (pl) => {
      // The doomed nested pair must NOT have been handed to the proxy.
      assert.equal(pl.viewMap, undefined);
      return { host: "127.0.0.1", port: 8788, stop: () => {} };
    },
  }, (m) => warnings.push(m));
  assert.equal(p.viewMap, undefined, "no view map shipped for a nested pair");
  assert.equal(p.cwd, "/w", "cwd stays raw (worktree not adopted)");
  assert.equal(stopped, 1, "the worktree was torn down");
  const degraded = warnings.find((w) => /fs rung DEGRADED/.test(w));
  assert.ok(degraded, `expected a DEGRADED line, got ${JSON.stringify(warnings)}`);
  assert.match(degraded!, /nest/);
  assert.match(degraded!, /MANDU_HOME/);
  assert.doesNotMatch(degraded!, /MANDU_VIEW_STATE/, "the retired variable is not advised");
  await h.stop();
});

test("fs rung ACTIVE label is target-accurate: Codex reports NO sensitive-path gate", async () => {
  const fsView = async () => ({ agentCwd: "/dv/agentview", gitRoot: "/w", agentView: "/dv/agentview", stop: () => {} });
  // Claude: the gate IS active.
  const claude: string[] = [];
  await startServices(plan({ fsSync: undefined, target: "claude" }), Layout.dev("/repo"), "/run/sid",
    { ...mockDeps(), startFsView: fsView }, (m) => claude.push(m));
  const claudeRung = claude.find((m) => /fs rung ACTIVE/.test(m))!;
  assert.match(claudeRung, /\+ sensitive-path gate/);

  // Codex: the openai-proxy has NO gate — the label must say so, not claim one.
  const codex: string[] = [];
  await startServices(plan({ fsSync: undefined, target: "codex", noContextProxy: false, openaiProviderName: "mandu" }), Layout.dev("/repo"), "/run/sid",
    { ...mockDeps(), startFsView: fsView }, (m) => codex.push(m));
  const codexRung = codex.find((m) => /fs rung ACTIVE/.test(m))!;
  assert.ok(codexRung, `expected an ACTIVE rung line for codex, got ${JSON.stringify(codex)}`);
  assert.match(codexRung, /no sensitive-path gate for Codex/);
  assert.doesNotMatch(codexRung, /\+ sensitive-path gate/);
});

test("fs-view skip (null) leaves plan.cwd untouched; fsSync:false never calls it", async () => {
  const p1 = plan({ fsSync: undefined });
  await startServices(p1, Layout.dev("/repo"), "/run/sid", { ...mockDeps(), startFsView: async () => null });
  assert.equal(p1.cwd, "/w");
  let called = 0;
  await startServices(plan({ fsSync: false }), Layout.dev("/repo"), "/run/sid",
    { ...mockDeps(), startFsView: async () => { called++; return null; } });
  assert.equal(called, 0);
});

// ── Config-routed targets: the agent-config step ─────────────────────────────

test("openclaw: agent-config runs, plan.agentConfig set, and NO .mcp.json is written", async () => {
  const p = plan({ target: "openclaw", argv: ["openclaw"] });
  let mcpWrites = 0;
  const h = await startServices(p, Layout.dev("/repo"), "/run/sid", {
    ...okDeps,
    writeMcpConfig: () => { mcpWrites++; return "/w/.mcp.json"; },
  }, () => {});
  assert.deepEqual(p.agentConfig, { envVar: "OPENCLAW_CONFIG_PATH", path: "/run/sid/openclaw.json" });
  // The inspect channel rides the agent config (plugin/mcp section), not a
  // workspace .mcp.json no agent reads.
  assert.equal(mcpWrites, 0);
  assert.equal(p.mcpConfig, undefined);
  await h.stop();
});

test("agent-config write failure is failClosedFatal — --best-effort CANNOT bless a silent-unprotected launch", async () => {
  const p = plan({ target: "opencode", argv: ["opencode"], bestEffort: true });
  await assert.rejects(
    startServices(p, Layout.dev("/repo"), "/run/sid", {
      ...okDeps,
      writeAgentConfig: () => { throw new Error("EACCES: cannot write"); },
    }, () => {}),
    /agent-config.*cannot write.*--best-effort cannot override/s,
  );
});

test("claude keeps its .mcp.json and never runs agent-config", async () => {
  const p = plan();
  let agentConfigCalls = 0;
  const h = await startServices(p, Layout.dev("/repo"), "/run/sid", {
    ...okDeps,
    writeAgentConfig: () => { agentConfigCalls++; return { envVar: "X", path: "/x" }; },
  }, () => {});
  assert.equal(p.mcpConfig, "/w/.mcp.json");
  assert.equal(agentConfigCalls, 0);
  assert.equal(p.agentConfig, undefined);
  await h.stop();
});

// ── Startup overlap (launch time, 2026-09-28) ───────────────────────────────

const tick = (ms: number) => new Promise((r) => setTimeout(r, ms));

test("the context proxy and the net-proxy start together", async () => {
  const events: string[] = [];
  const deps = {
    ...okDeps,
    startContextProxy: async () => { events.push("ctx:start"); await tick(20); events.push("ctx:up"); return { host: "127.0.0.1", port: 8788, stop: () => {} }; },
    startNetProxy: async () => { events.push("net:start"); await tick(20); events.push("net:up"); return { netProxy: { host: "127.0.0.1", port: 8790 }, mitmCaCert: undefined, stop: () => {} }; },
  };
  const p = plan({ noContextProxy: false, requested: { netProxy: true, netProxyMitm: false, execWrap: false } });
  await (await startServices(p, Layout.dev("/repo"), "/run/sid", deps, () => {})).stop();
  assert.deepEqual(events.slice(0, 2).sort(), ["ctx:start", "net:start"], "both start before either is up");
  assert.equal(p.netProxy?.port, 8790);
  assert.equal(p.proxy.port, 8788);
});

test("a proxy that fails refuses the launch only after its sibling settled, and the teardown stops the sibling too", async () => {
  const stopped: string[] = [];
  const deps = {
    ...okDeps,
    // The context proxy fails at once; the net-proxy comes up LATER.
    startContextProxy: async () => { throw new Error("port held by a stranger"); },
    startNetProxy: async () => { await tick(30); return { netProxy: { host: "127.0.0.1", port: 8790 }, mitmCaCert: undefined, stop: () => { stopped.push("net-proxy"); } }; },
  };
  const p = plan({ noContextProxy: false, requested: { netProxy: true, netProxyMitm: false, execWrap: false } });
  await assert.rejects(startServices(p, Layout.dev("/repo"), "/run/sid", deps, () => {}), /context-proxy/);
  assert.deepEqual(stopped, ["net-proxy"], "the proxy that came up after the failure is not left running");
});

test("both proxies failing: the first in list order names the refusal (context proxy), as one at a time did", async () => {
  const deps = {
    ...okDeps,
    startContextProxy: async () => { await tick(20); throw new Error("ctx down"); },
    startNetProxy: async () => { throw new Error("net down"); },
  };
  const p = plan({ noContextProxy: false, requested: { netProxy: true, netProxyMitm: false, execWrap: false } });
  await assert.rejects(startServices(p, Layout.dev("/repo"), "/run/sid", deps, () => {}), /context-proxy.*ctx down/);
});

test("onFsViewReady fires after the filesystem step and before the proxies; the watcher's readiness is awaited before startServices returns", async () => {
  const events: string[] = [];
  let release!: () => void;
  const ready = new Promise<void>((r) => { release = r; });
  const deps = {
    ...okDeps,
    startFsView: async () => {
      events.push("fs");
      return { agentCwd: "/av", gitRoot: "/w", agentView: "/state/av", eager: true, stop: () => {}, ready: ready.then(() => { events.push("watcher-ready"); }) };
    },
    startNetProxy: async () => { events.push("net"); return { netProxy: { host: "127.0.0.1", port: 8790 }, mitmCaCert: undefined, stop: () => {} }; },
  };
  const p = plan({ fsSync: true, requested: { netProxy: true, netProxyMitm: false, execWrap: false } });
  const started = startServices(p, Layout.dev("/repo"), "/run/sid", deps, () => {}, { onFsViewReady: () => events.push("hook") });
  await tick(20);
  assert.deepEqual(events, ["fs", "hook", "net"], "the proxies do not wait for the watcher");
  let done = false;
  void started.then(() => { done = true; });
  await tick(10);
  assert.equal(done, false, "startServices waits for the watcher's readiness");
  release();
  await (await started).stop();
  assert.equal(events.at(-1), "watcher-ready");
});

test("ullm-forwarder (agent-sign-in.md §3.8): an API-mode U-LLM is handed a stand-in, the relay holds the key, and the inspect server's entry never carries the key", async () => {
  const KEY = "sk-ant-api03-MANDUFAKEmanagerULLM";
  const seen: Array<{ apiKey?: { standIn: string; key: string } }> = [];
  let mcpKey: string | undefined;
  const p = plan({ ullm: { mode: "api", baseUrl: "https://api.anthropic.com", apiKey: KEY } });
  await startServices(p, Layout.dev("/repo"), "/run/sid", {
    ...okDeps,
    startUllmForwarder: async (o) => { seen.push(o as { apiKey?: { standIn: string; key: string } }); return { host: "127.0.0.1", port: 5, url: "http://127.0.0.1:5", stop: async () => {} }; },
    writeMcpConfig: (pl) => { mcpKey = pl.ullm.apiKey; return "/w/.mcp.json"; },
  });
  assert.equal(seen[0]!.apiKey?.key, KEY, "the relay holds the key");
  assert.match(seen[0]!.apiKey!.standIn, /^mandu-ullm-key-[0-9a-f]+$/);
  assert.equal(p.ullm.apiKey, seen[0]!.apiKey!.standIn);
  assert.equal(mcpKey, seen[0]!.apiKey!.standIn, "the entry the agent's world reads: the stand-in");
  assert.ok(!JSON.stringify(p).includes(KEY), "nothing in the plan keeps the key");
  // No relay (it failed, or --no-landlock-net): the U-LLM dials directly and keeps the key itself.
  const failed = plan({ ullm: { mode: "api", baseUrl: "https://api.anthropic.com", apiKey: KEY } });
  await startServices(failed, Layout.dev("/repo"), "/run/sid", { ...okDeps, startUllmForwarder: async () => { throw new Error("bind failed"); } }, () => {});
  assert.equal(failed.ullm.apiKey, KEY);
  // A CLI-mode U-LLM has no key: nothing handed.
  const cli = plan();
  seen.length = 0;
  await startServices(cli, Layout.dev("/repo"), "/run/sid", { ...okDeps, startUllmForwarder: async (o) => { seen.push(o as { apiKey?: { standIn: string; key: string } }); return { host: "127.0.0.1", port: 6, url: "http://127.0.0.1:6", stop: async () => {} }; } });
  assert.equal(seen[0]!.apiKey, undefined);
});

test("ullm-forwarder (agent-sign-in.md §3.9): the handle exposes the forwarder's key setter; none without a forwarder", async () => {
  const set: unknown[] = [];
  const codex = plan({ ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "codex" } });
  const h = await startServices(codex, Layout.dev("/repo"), "/run/sid", {
    ...okDeps,
    startUllmForwarder: async () => ({ host: "127.0.0.1", port: 7, url: "http://127.0.0.1:7", stop: async () => {}, setApiKey: (k) => { set.push(k); } }),
  });
  assert.ok(h.setUllmKey, "the setter is handed back");
  h.setUllmKey!({ standIn: "$MDU:nomodel_Read[e0c7].OPENAI_API_KEY", key: "sk-x" });
  assert.equal(set.length, 1);
  const off = await startServices(plan({ landlockNet: false }), Layout.dev("/repo"), "/run/sid", okDeps);
  assert.equal(off.setUllmKey, undefined);
});
