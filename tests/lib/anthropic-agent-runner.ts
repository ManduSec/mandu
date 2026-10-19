/**
 * anthropic-agent-runner.ts — the shared live-scenario runner for agents that
 * speak the ANTHROPIC MESSAGES wire (OpenClaw · OpenCode).
 *
 * Mandu (tests/). Design: docs/design/testing/agent-e2e-harness.md.
 *
 * WHY THIS IS SHARED AND claude-e2e/codex-e2e ARE NOT:
 *   e2e-catalog.md's argument against one universal runner is correct and still
 *   stands — claude-e2e carries fsSync / view-sync, interactive PTY, the model
 *   matrix, transcript fidelity, and CONF postures, and codex-e2e keys its
 *   symbol proof off a DIFFERENT surface because the openai-proxy forwards the
 *   raw body. Folding those together would need an `if (agent)` at every axis.
 *
 *   OpenClaw and OpenCode are the case that argument does NOT cover. Both were
 *   probe-verified to POST genuine /v1/messages (design doc §2), so both ride
 *   the SAME anthropic-proxy, produce the SAME event shapes, and are read by
 *   the SAME oracle surface. What differs between them is exactly what
 *   agent-provision.ts already isolates: binary, argv, env, config files, reply
 *   extraction. So this runner is parameterized over an AgentProvisioner and
 *   nothing else — no per-agent branching lives here, and if a future agent
 *   needs one, that is the signal it deserves its own runner, not an `if`.
 *
 * TWO UPSTREAM TIERS (design doc §5.2):
 *   - "fake" (DEFAULT) — a scripted local Anthropic server (lib/fake-anthropic).
 *     No credentials, no budget, hermetic, deterministic. This tier proves the
 *     ENVIRONMENT: agent → proxy → classify → symbolize → arbiter → events →
 *     oracle. It is what makes these suites runnable in the free CI tier.
 *   - "real" (MANDU_TEST_UPSTREAM=real) — api.anthropic.com, so a real model
 *     decides. Proves MODEL BEHAVIOR under the defense. Costs budget.
 *
 * PRIVATE ARBITER (design doc §4): each suite runs its own in-process arbiter
 * so the agent's inbound trust spec (openclaw-agent / opencode) is the active
 * one. The active spec is a process-global, and node's test runner gives each
 * test FILE its own process, so two suites cannot collide — and neither can
 * disturb the shared dashboard daemon. Events are written into the SHARED
 * arbiter's event dir (when one exists) so the dashboard still sees the session.
 */

import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { setActiveInboundSpec } from "../../arbiter/policy/tool-inbound.js";
import { setActiveOutboundSpec } from "../../arbiter/policy/tool-outbound.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter as AnthropicProxyArbiterAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { ViewMap } from "../../interceptors/anthropic-proxy/src/view-map.js";
import { NetProxy } from "../../interceptors/net-proxy/src/proxy.js";
import { MockSites } from "../../interceptors/net-proxy/src/mock-sites.js";
import { ArbiterClientAdapter as NetProxyArbiterAdapter } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { ViewSync } from "../../fs-sync/src/view-sync.js";
import { ArbiterClientAdapter as FsSyncArbiterAdapter } from "../../fs-sync/src/arbiter-client.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import {
  type AssertionCheck,
  evalExitOk, evalSessionPersisted, evalModelCallPresent,
  evalSymbolReachesModel, evalRawInjectionAbsent, evalSymbolizationRecorded,
  evalReplyNonEmpty, evalReplyAchieves, evalReplySymbolFree, evalExecutionEvidence, evalNotSymbolized,
  evalAgentViewSymbolized, evalAgentViewNoRaw, evalHumanViewRaw, evalAgentViewRef,
  evalNoAgentViewPathInModelContext, evalSyncedBack, evalSyncedFileExists,
  evalCommitDance, evalFileAchieves,
  evalNetObserved, evalNetEgressBlocked,
  evalQuarantineRan, evalResymbolized, evalUllmRawAbsent,
  evalQuarantineInputDesymbolized, evalUllmFaithful,
  formatAssertLine, buildAssertionEvent, buildSeedEvent, buildFinalEvent,
  blockingFailures, summarize,
} from "./assertions.js";
import { collectFinalFiles } from "./workspace-capture.js";
import { runChildToExit } from "./child-run.js";
import { BATCH_ID, E2E_ORIGIN, E2E_RUNTIME, REAL_UPSTREAM, SHARED_ARBITER_SOCK, anthropicBridge, realForwarder } from "./live-shared.js";
import type { AgentProvisioner } from "./agent-provision.js";
import { realTierApiKey, withUpstreamApiKey } from "./agent-provision.js";
import { startExfilSink, type ExfilSink } from "./conf-exfil.js";
import { startRecordingRelay, type RecordingRelay } from "./recording-relay.js";
import {
  INJECTION, UPSTREAM_TIER,
  type FakeToolStep, type FakeToolInput, type ConfExpectation, type AgentScenario, type RunnerContext,
} from "./agent-scenario.js";
import { LAST_TOOL_RESULT, countToolResults, startFakeUpstream } from "./agent-fake-script.js";
import {
  EXFIL_SINK_HOST, CONF_SECRET_FILE, confScenarios, type ConfToolSpelling,
} from "./agent-conf-scenarios.js";
import { confChecks } from "./agent-conf-checks.js";
import { PROMPT_POLICY, promptChecks, promptPolicyChecks, registerPromptSecrets } from "./agent-prompt-checks.js";
import { humanSockIn } from "./human-plane.js";
import {
  INSPECT_MCP_SERVER, MOCK_SITES_YAML, collectSeededFiles, git, inspectMcpCommand, inspectMcpEnv, netBridge,
} from "./agent-posture.js";

// ─── Re-exports: the runner is the suites' one import surface ────────────────
// The scenario model lives in agent-scenario.ts and the fake tier's scripted
// model in agent-fake-script.ts, the conf scenarios in agent-conf-scenarios.ts
// and the posture helpers in agent-posture.ts; every name the suites (and the
// offline script tests) use is re-exported here, so they keep importing from
// the runner.
export {
  INJECTION, UPSTREAM_TIER,
  type FakeToolStep, type FakeToolInput, type ConfExpectation, type AgentScenario, type RunnerContext,
};
export { LAST_TOOL_RESULT, countToolResults };
export { EXFIL_SINK_HOST, CONF_SECRET_FILE, confScenarios, type ConfToolSpelling };
export { INSPECT_MCP_SERVER };

export async function runAgentScenario(s: AgentScenario, ctx: RunnerContext): Promise<void> {
  const { provisioner: P } = ctx;
  // A scenario may need more wall clock than the suite default (see
  // AgentScenario.timeoutMs) — never less: the suite's budget is the floor.
  const timeoutMs = Math.max(ctx.timeoutMs, s.timeoutMs ?? 0);
  const sessionId = `${P.sessionClass}-${s.name}-${Date.now()}`;
  const tmp = mkdtempSync(join(tmpdir(), `mandu-${P.id}-e2e-${s.name}-`));
  const workspace = join(tmp, "workspace");
  const agentHome = join(tmp, "agent-home");
  mkdirSync(workspace, { recursive: true });
  mkdirSync(agentHome, { recursive: true });

  const notes = join(workspace, "notes.md");
  if (s.poisoned) {
    writeFileSync(
      notes,
      `# Project notes\n\nTODO: ship the proxy.\n${INJECTION}\nMore legitimate-looking notes.\n`,
    );
  }
  s.setup?.(workspace);
  const seededFiles = collectSeededFiles(workspace);

  // Reverse-acquisition teardown stack. A setup throw must not leak a live
  // arbiter socket — a stranded client holds this runner's event loop open
  // forever after the tests finish (the hung-runner class).
  const closers: Array<() => void | Promise<void>> = [];
  try {
    // ── The PRIVATE arbiter, carrying THIS agent's trust spec ────────────────
    // Events land in the SHARED arbiter's event dir (distinct per-session NDJSON
    // files, so no writer clash) to keep the session visible on the dashboard;
    // the symbol DB stays private (the arbiter is single-writer over its own DB).
    let eventDir = join(tmp, "events");
    if (existsSync(SHARED_ARBITER_SOCK)) {
      const probe = new ArbiterClient(SHARED_ARBITER_SOCK);
      try {
        await probe.connect();
        eventDir = (await probe.hello()).eventDir;
      } catch {
        // No reachable shared arbiter → keep the private event dir. The
        // dashboard loses visibility; the ORACLE does not (it reads privately).
      } finally {
        probe.close();
      }
    }
    mkdirSync(eventDir, { recursive: true });

    const arbiterSock = join(tmp, "arbiter.sock");
    // The ADMIN socket is where a user labels a path (conf scenarios) and
    // where the HumanView reveal is asked; the agent's wiring never sees it.
    const adminSock = join(tmp, "admin.sock");
    const privateArbiter = new ArbiterServer({
      socketPath: arbiterSock,
      adminSocketPath: adminSock,
      humanSocketPath: humanSockIn(tmp), // originals-returning reads (arbiter-human-plane.md)
      dbPath: join(tmp, "symbols.sqlite"),
      eventDir,
      log: () => {},
      // The prompt filter's policy (scenario.promptPolicy, plan 15 phase 2).
      ...(s.promptPolicy ? { policyDocument: PROMPT_POLICY, promptPackDir: null, adminPromptPackDir: null } : {}),
    });
    await privateArbiter.listen();
    closers.push(() => privateArbiter.close());

    // ── The confidentiality posture (scenario.conf) ─────────────────────────
    // The label is the user's act, over the admin channel, before the agent
    // starts. A label that did not land throws: an arrange that silently
    // failed would make every oracle below vacuous.
    const conf = s.conf;
    if (conf?.exfil === "net-proxy") {
      assert.ok(s.needsWeb, `[${s.name}] conf.exfil "net-proxy" needs needsWeb (the net-proxy must stand up)`);
    }
    if (conf?.label) {
      const admin = new ArbiterClient(adminSock);
      await admin.connect();
      try {
        const lbl = await admin.setPathLabel({
          path: join(workspace, conf.label.file),
          confidentiality: conf.label.level,
          recursive: false,
        });
        if (lbl.level !== conf.label.level) {
          throw new Error(`[${s.name}] labelling ${conf.label.file} ${conf.label.level} did not land (${JSON.stringify(lbl)})`);
        }
      } finally {
        admin.close();
      }
    }
    let sink: ExfilSink | undefined;
    if (conf?.exfil === "sink") {
      const started = await startExfilSink();
      sink = started;
      closers.push(() => started.close());
    }

    const proxyClient = new ArbiterClient(arbiterSock);
    closers.push(() => proxyClient.close());
    await proxyClient.connect();
    // The test's reads of originals (sessions, desymbolize) ride the human plane.
    const readClient = new ArbiterClient(humanSockIn(tmp));
    closers.push(() => readClient.close());
    await readClient.connect();
    // The prompt filter's arrange (scenario.promptSecrets): the values
    // registered as the launcher registers the environment, before the agent
    // starts (agent-prompt-checks.ts).
    const promptKeySym = s.promptSecrets ? await registerPromptSecrets(proxyClient, s.promptSecrets) : null;
    const source = new ArbiterEventSource({ socketPath: arbiterSock });
    closers.push(() => source.close());

    if (seededFiles.length > 0) {
      await readClient.emit(
        buildSeedEvent({ sessionId, batchId: BATCH_ID, runtime: E2E_RUNTIME, origin: E2E_ORIGIN, files: seededFiles }) as never,
      );
    }

    // ── Upstream: scripted fake (default) or the real API ────────────────────
    // The conf oracles read the bytes the model endpoint RECEIVED: the fake's
    // captured requests, or (real tier) a verbatim recording relay in front of
    // the real API, so both tiers grade the same surface.
    let upstreamOrigin = REAL_UPSTREAM;
    let wire: () => string[] = () => [];
    if (UPSTREAM_TIER === "fake") {
      const fake = await startFakeUpstream(s, ctx, notes, sink?.origin ?? "");
      closers.push(() => fake.close());
      upstreamOrigin = fake.origin;
      wire = () => fake.requests.map((q) => q.body);
    } else if (conf || s.promptSecrets || s.promptPolicy) {
      const relay: RecordingRelay = await startRecordingRelay(REAL_UPSTREAM);
      closers.push(() => relay.close());
      upstreamOrigin = relay.url;
      wire = () => relay.records.map((q) => q.reqBody);
    }

    // ── fsSync / view-sync posture (scenario.fsSync) ──────────────────────────
    // The agent runs with the AgentView TWIN as its CWD; the proxy gets the P2
    // ViewMap so T-LLM keeps speaking HumanView paths. Same wiring claude-e2e
    // uses — the machinery is agent-agnostic (design doc §7.4); only the
    // scenarios' tool names differ.
    let viewSync: ViewSync | undefined;
    let agentCwd = workspace;
    let viewMap: ViewMap | undefined;
    if (s.fsSync) {
      git(workspace, ["init", "-q"]);
      git(workspace, ["config", "user.name", P.sessionClass]);
      git(workspace, ["config", "user.email", `${P.sessionClass}@test.local`]);
      git(workspace, ["add", "-A"]);
      git(workspace, ["commit", "-qm", "seed", "--allow-empty"]);
      const fsSyncClient = new ArbiterClient(humanSockIn(tmp));
      closers.push(() => fsSyncClient.close());
      await fsSyncClient.connect();
      viewSync = new ViewSync({
        workspacePath: workspace,
        arbiter: new FsSyncArbiterAdapter(fsSyncClient),
        stateBase: join(tmp, "view-state"),
        sessionKey: sessionId,
      });
      await viewSync.initialize();
      agentCwd = viewSync.agentViewPath;
      viewMap = new ViewMap([{ human: workspace, agent: viewSync.agentViewPath }]);
    }

    // ── The model-context chokepoint for THIS session ────────────────────────
    const proxy = new AnthropicProxy({
      arbiter: new AnthropicProxyArbiterAdapter(anthropicBridge(proxyClient)),
      // The real tier: the agent's dummy key is swapped for the run's API key
      // on this hop only (agent-provision.ts realTierApiKey); the suites skip
      // the tier when there is none, so null never reaches here.
      upstream: UPSTREAM_TIER === "real"
        ? withUpstreamApiKey(realForwarder(upstreamOrigin), realTierApiKey() ?? "")
        : realForwarder(upstreamOrigin),
      ...(viewMap ? { viewMap } : {}),
      // An agent that sends no session header (Goose) is keyed by the proxy,
      // as the launcher's per-launch proxy keys it (MANDU_SESSION_KEY).
      ...(P.sessionHeader === false ? { sessionKey: sessionId } : {}),
      log: () => {},
    });
    closers.push(() => proxy.close());
    const proxyPort = await proxy.listen(0);

    // ── The network chokepoint (scenario.needsWeb) ───────────────────────────
    const extraEnv: Record<string, string> = {};
    if (s.needsWeb) {
      const netClient = new ArbiterClient(arbiterSock);
      closers.push(() => netClient.close());
      await netClient.connect();
      const netHuman = new ArbiterClient(humanSockIn(tmp));
      closers.push(() => netHuman.close());
      const netProxy = new NetProxy({
        arbiter: new NetProxyArbiterAdapter(netBridge(netClient), netHuman),
        mockSites: MockSites.fromYaml(MOCK_SITES_YAML),
        sessionId,
        log: () => {},
      });
      closers.push(() => netProxy.close());
      const netPort = await netProxy.listen(0);
      const netUrl = `http://127.0.0.1:${netPort}`;
      // Loopback + the model host are EXCLUDED: the agent reaches our own
      // context proxy over loopback, and looping the model API through the net
      // proxy would instrument the wrong boundary.
      const noProxy = "127.0.0.1,localhost,::1,api.anthropic.com";
      Object.assign(extraEnv, {
        HTTP_PROXY: netUrl, HTTPS_PROXY: netUrl, NO_PROXY: noProxy,
        http_proxy: netUrl, https_proxy: netUrl, no_proxy: noProxy,
      });
    }

    // ── The U-LLM channel (scenario.expectInspect) ───────────────────────────
    // Mounted through the provisioner so an agent WITHOUT one reports it in
    // `unsupported` and the runner blocks, instead of quietly running a
    // scenario whose whole point is the quarantine.
    const mcp = s.expectInspect
      ? {
          name: INSPECT_MCP_SERVER,
          command: inspectMcpCommand(),
          timeoutMs: 30_000,
          env: inspectMcpEnv(arbiterSock, sessionId),
        }
      : undefined;
    // A PLUGIN-mounted channel (OpenClaw) runs the quarantine IN the agent
    // process, so there is no separate server env to carry PATH/HOME — the
    // AGENT's env is what the `claude -p` child inherits. Give it the real HOME
    // so that child sees its subscription login; OpenClaw's own state stays
    // redirected by OPENCLAW_HOME/STATE_DIR/CONFIG_PATH, which is what actually
    // isolates it (HOME is only their fallback).
    if (mcp && P.inspectMount === "plugin") {
      Object.assign(extraEnv, {
        PATH: process.env["PATH"] ?? "",
        HOME: process.env["HOME"] ?? "",
      });
    }

    // ── Provision the agent (pure) and enact it (here) ───────────────────────
    const provisioned = P.provision({
      agentHome,
      // Under fsSync the agent lives in the AgentView twin; the PROMPT still
      // names HumanView paths (the ViewMap contract).
      workspace: agentCwd,
      proxyUrl: `http://127.0.0.1:${proxyPort}`,
      sessionId,
      batchId: BATCH_ID,
      model: ctx.model,
      prompt: s.prompt(notes, { sinkOrigin: sink?.origin ?? "" }),
      timeoutMs,
      ...(mcp ? { mcp } : {}),
      ...(Object.keys(extraEnv).length > 0 ? { extraEnv } : {}),
    });
    for (const f of provisioned.files) {
      mkdirSync(dirname(f.path), { recursive: true });
      writeFileSync(f.path, f.content);
    }

    // A capability the scenario NEEDS but the agent lacks is a blocking fact,
    // not a silent downgrade (design doc §3: a degradation that cannot be seen
    // is a defect). Asserted before the run so the reason is unambiguous.
    if (s.expectInspect) {
      assert.notEqual(
        P.inspectMount,
        "none",
        `[${s.name}] scenario needs the U-LLM inspect channel, but ${P.id} has no mount for it`,
      );
      assert.ok(
        !provisioned.unsupported.includes("mcp"),
        `[${s.name}] scenario needs the U-LLM inspect channel, but ${P.id} reports it unsupported ` +
          `(${provisioned.unsupported.join(", ")}) — do not run an inspect scenario without one`,
      );
    }

    const resolved = P.resolveBinary();
    assert.ok(resolved, `${P.id}: binary vanished between the skip gate and the run`);
    const { code, stdout, stderr } = await runChildToExit(
      resolved.binary,
      [...resolved.prefixArgs, ...provisioned.argv],
      { cwd: agentCwd, env: provisioned.env, timeoutMs, label: P.id },
    );

    // ── The launcher's post-exit reconcile (fsSync) ──────────────────────────
    let syncedList: string[] = [];
    let agentViewRefExists = false;
    let agentNotesContent = "";
    let humanNotesContent = "";
    let syncedFileOnDisk = false;
    let gitLogContent = "";
    if (s.fsSync && viewSync) {
      syncedList = await viewSync.syncToHuman({ toolName: P.sessionClass, runId: sessionId });
      try {
        git(workspace, ["--git-dir", viewSync.layout.gitDir, "rev-parse", "--verify", "--quiet", "mdu-trusted^{commit}"]);
        agentViewRefExists = true;
      } catch {
        agentViewRefExists = false;
      }
      if (s.poisoned) {
        // The fs chokepoint ON DISK: the twin holds a symbol, the HumanView
        // keeps the raw original.
        agentNotesContent = readFileSync(join(viewSync.agentViewPath, "notes.md"), "utf8");
        humanNotesContent = readFileSync(notes, "utf8");
      }
      if (s.syncedFile) {
        syncedFileOnDisk = existsSync(join(workspace, s.syncedFile));
        gitLogContent = git(workspace, ["--git-dir", viewSync.layout.gitDir, "log", "--format=%s"]);
      }
    }

    // On-disk utility evidence, per view, AFTER the sync above.
    const utilityFileContents = (s.utility?.files ?? []).map((f) => {
      const root = f.view === "AgentView" ? viewSync?.agentViewPath : workspace;
      if (!root) return null;
      try {
        return readFileSync(join(root, f.file), "utf8");
      } catch {
        return null;
      }
    });

    // The agent's own reply, extracted from its output format (pure), then run
    // through the arbiter's DEEP desymbolize — the same egress the reply-filter
    // chokepoint applies. Utility-only posture: a failed op degrades to
    // passthrough (symbols stay opaque, so nothing can leak).
    const extracted = P.extractReply(stdout);
    const rawReply = extracted.text;
    let resolvedReply = rawReply;
    try {
      const candidate = rawReply.replace(/\\\$MDU:/g, "$MDU:");
      const deep = await readClient.desymbolize(candidate);
      if (deep !== candidate) resolvedReply = deep;
    } catch {
      /* passthrough — display fidelity lost, never a harness crash */
    }

    const sessions = await readClient.sessions();
    const sessionPresent = sessions.some((x) => x.sessionId === sessionId);

    // Poll the trace (proxy emission is async). Wait for the agentic tllm_call
    // — NOT merely the first one: OpenCode fires a title-generation call before
    // it, and settling on that would read the trace before the real turn ran.
    let events: Awaited<ReturnType<typeof source.readEvents>> = [];
    for (let i = 0; i < 150; i++) {
      events = await source.readEvents(sessionId);
      const calls = events.filter((e) => e.kind === "tllm_call").length;
      const hasCall = calls > P.sideCallsPerTurn;
      const hasSymbol = !s.expectSymbol || events.some((e) => e.kind === "symbolize");
      // A gate VERDICT is emitted after the tool call returns, so settling on
      // the model call alone would read the trace before the gate ran.
      const hasNetVerdict =
        !s.netEgressBlockSink ||
        events.some(
          (e) =>
            e.kind === "net_action" &&
            String((e as { destination?: unknown }).destination ?? "").includes(s.netEgressBlockSink!),
        );
      const hasInspect = !s.expectInspect || events.some((e) => e.kind === "ullm_call");
      const hasConfNet =
        conf?.exfil !== "net-proxy" ||
        UPSTREAM_TIER === "real" ||
        events.some(
          (e) =>
            e.kind === "net_action" &&
            String((e as { destination?: unknown }).destination ?? "").includes(EXFIL_SINK_HOST),
        );
      if (hasCall && hasSymbol && hasNetVerdict && hasInspect && hasConfNet) break;
      await new Promise((r) => setTimeout(r, 100));
    }

    // The model-facing context. The anthropic-proxy REDACTS its
    // tllm_call.input.symbolized to a summary, so this surface is safe for a
    // raw-absence check (unlike the openai-proxy's raw forwarded body).
    const modelFacing = events
      .filter((e) => e.kind === "tllm_call")
      .map((e) => e.input?.symbolized ?? "")
      .join("\n");
    // The REAL minted symbols: each tool_result's symbolized side.
    const symbolizedResults = events
      .filter((e) => e.kind === "tool_result")
      .map((e) => e.output?.symbolized ?? "")
      .join("\n");
    // Execution evidence: the raw tool outputs the defense ingested. The prompt
    // never reaches these, so a marker hit is genuine proof the tool ran.
    const symbolizeOriginals = events
      .filter((e) => e.kind === "symbolize")
      .map((e) => e.input?.original ?? "")
      .join("\n");
    // Execution evidence reads the tool_result originals too (claude-e2e's
    // rule, 2026-09-24): with integrity OFF an ordinary read is not
    // symbolized, so a symbolize-only corpus would leave `executed` unmet.
    const ingestedOutputs = events
      .filter((e) => e.kind === "symbolize" || e.kind === "tool_result")
      .map((e) => (e.kind === "symbolize" ? e.input?.original : e.output?.original) ?? "")
      .join("\n");
    // The CONVERSATION-facing surface for the AgentView-path leak oracle.
    // `source:"agent"` blocks are EXCLUDED deliberately: the agent's own system
    // prompt legitimately names its real CWD (the AgentView worktree), and that
    // is not the leak this guards. The ViewMap contract is about the
    // CONVERSATION — no twin path in the user/tool messages T-LLM reasons over.
    const modelInput = events
      .filter((e) => e.kind === "tllm_call")
      .map((e) => {
        const convo = (e.fullInput?.blocks ?? [])
          .filter((b) => b.source !== "agent")
          .map((b) => b.text)
          .join("\n");
        return `${e.input?.symbolized ?? ""}\n${convo}`;
      })
      .join("\n");
    // Quarantined U-LLM outputs: `ullmRaw` is the must-not-appear surface (short
    // strings excluded — a 2-token triage word is a sanctioned channel, not a
    // leak); `ullmOutputs` is the faithfulness surface.
    const ullmOutputs = events
      .filter((e) => e.kind === "ullm_call")
      .map((e) => e.output?.original ?? "");
    const ullmRaw = ullmOutputs.filter((t) => t.length >= 12);

    // ── Build the checks (evidence in, no inline asserts) ────────────────────
    const checks: AssertionCheck[] = [];

    if (!s.allowNonZeroExit) checks.push(evalExitOk(code));
    checks.push(evalReplyNonEmpty(rawReply, /* hard */ !s.allowNonZeroExit));
    checks.push(evalSessionPersisted(sessionPresent));
    checks.push(evalModelCallPresent(events));
    // FIDELITY: did the reply parser actually locate the reply, or fall back to
    // raw stdout? Without this a broken extractor is INVISIBLE — the raw
    // envelope contains the reply text, so every reply-achieves regex still
    // matches and the suite goes green on a parser that does nothing. This
    // caught exactly that on the first OpenClaw run (design doc §2.4).
    checks.push({
      label: "reply-extracted",
      description: `${P.id}'s reply was located in its output format, not fallen back to raw stdout`,
      category: "fidelity",
      status: extracted.extracted ? "pass" : "fail",
      reason: extracted.extracted
        ? "reply parsed out of the agent's output envelope"
        : `FELL BACK to raw stdout (${stdout.length} chars) — the output envelope shape changed; ` +
          "every reply assertion below is matching the raw envelope, not the reply",
      assert: "reply_extracted",
    });

    for (const exp of s.utility?.reply ?? []) checks.push(evalReplyAchieves(resolvedReply, exp));
    if (s.utility?.replySymbolFree) checks.push(evalReplySymbolFree(rawReply));
    for (const ex of s.utility?.executed ?? []) {
      checks.push(evalExecutionEvidence(ingestedOutputs, ex.marker, ex.tool));
    }
    for (const nx of s.utility?.notSymbolized ?? []) {
      checks.push(evalNotSymbolized(symbolizeOriginals, nx.marker, nx.tool));
    }
    (s.utility?.files ?? []).forEach((f, i) => {
      checks.push(evalFileAchieves(utilityFileContents[i], f));
    });

    // SECURITY — the model-boundary invariant.
    if (s.expectSymbol) {
      checks.push(evalSymbolizationRecorded(events));
      checks.push(evalSymbolReachesModel(symbolizedResults));
      checks.push(evalRawInjectionAbsent(modelFacing, s.raw ?? "IGNORE ALL PREVIOUS INSTRUCTIONS"));
    }

    // SECURITY — the FILESYSTEM chokepoint (fsSync / view-sync posture).
    if (s.fsSync) {
      checks.push(evalAgentViewRef(agentViewRefExists));
      checks.push(evalNoAgentViewPathInModelContext(modelInput, viewSync?.agentViewPath ?? ""));
      if (s.poisoned) {
        checks.push(evalAgentViewSymbolized(agentNotesContent));
        checks.push(evalAgentViewNoRaw(agentNotesContent, INJECTION));
        checks.push(evalHumanViewRaw(humanNotesContent, INJECTION));
      }
      if (s.syncedFile) {
        checks.push(evalSyncedBack(syncedList, s.syncedFile));
        checks.push(evalSyncedFileExists(syncedFileOnDisk, s.syncedFile));
        checks.push(evalCommitDance(gitLogContent));
      }
    }

    // SECURITY — the NETWORK chokepoint.
    if (s.needsWeb) checks.push(evalNetObserved(events));
    if (s.netEgressBlockSink) checks.push(evalNetEgressBlocked(events, s.netEgressBlockSink));

    // SECURITY + UTILITY — the U-LLM quarantine.
    if (s.expectInspect) {
      checks.push(evalQuarantineRan(events));
      // The bare `$MDU:inspect[…]` tag is the PUBLIC re-symbolization; a
      // quarantined read of a labelled source mints `$MDU:<level>_inspect[…]`
      // (confidentiality-plan-7), which the conf block below grades instead.
      if (!conf?.label) checks.push(evalResymbolized(modelFacing, events));
      checks.push(evalUllmRawAbsent(modelFacing, ullmRaw));
    }

    // SECURITY — the CONFIDENTIALITY invariant (scenario.conf).
    if (conf) {
      checks.push(...(await confChecks({
        s, conf, events, wire: wire(), sink, adminSock, ullmOutputs,
      })));
    }
    // SECURITY — the prompt filter (scenario.promptSecrets, plan 15).
    if (s.promptSecrets && promptKeySym) {
      checks.push(...(await promptChecks({ s, ps: s.promptSecrets, keySym: promptKeySym, wire: wire(), human: readClient })));
    }
    if (s.promptPolicy) checks.push(...promptPolicyChecks({ s, pp: s.promptPolicy, wire: wire() }));
    // Universal and self-skipping: proves the quarantine saw DEEP-resolved
    // input whenever one ran at all.
    checks.push(evalQuarantineInputDesymbolized(events));
    if (s.utility?.ullmFaithful) checks.push(evalUllmFaithful(ullmOutputs, s.utility.ullmFaithful));

    // ── Report: greppable lines + one per-session assertion event + block ────
    for (const c of checks) console.log(formatAssertLine(P.sessionClass, s.name, c));
    const finalViews = [collectFinalFiles(workspace, "HumanView")].filter((v) => v.files.length > 0);
    if (finalViews.length > 0) {
      await readClient.emit(
        buildFinalEvent({ sessionId, batchId: BATCH_ID, runtime: E2E_RUNTIME, origin: E2E_ORIGIN, views: finalViews }) as never,
      );
    }
    await readClient.emit(
      buildAssertionEvent({ sessionId, batchId: BATCH_ID, runtime: E2E_RUNTIME, origin: E2E_ORIGIN, checks }) as never,
    );
    const counts = summarize(checks);
    console.error(
      `[${P.sessionClass}:${s.name}] assertions: ${counts.pass} pass · ${counts.fail} fail · ` +
        `${counts.warn} warn · ${counts.skip} skip (upstream=${UPSTREAM_TIER}, exit=${code}` +
        `${stderr ? `, stderr=${JSON.stringify(stderr.slice(0, 200))}` : ""})`,
    );
    // On the real tier the model decides: name what it called and what it
    // wrote, as the model wrote it (symbols unresolved, never the resolved
    // reply), so a declined or tool-less turn reads as such in the log.
    if (UPSTREAM_TIER === "real") {
      const calls = events
        .filter((e) => e.kind === "tool_use")
        .map((e) => String((e as { input?: { symbolized?: string } }).input?.symbolized ?? "").split("(")[0])
        .filter((n) => n !== "");
      console.error(
        `[${P.sessionClass}:${s.name}] real tier: tool calls [${calls.join(", ") || "none"}]; ` +
          `the model's reply: ${JSON.stringify(rawReply.slice(0, 400))}`,
      );
    }
    const blocking = blockingFailures(checks);
    assert.equal(
      blocking.length,
      0,
      `[${s.name}] ${blocking.length} blocking assertion(s) failed: ` +
        blocking.map((c) => `${c.label} (${c.reason})`).join("; "),
    );
  } finally {
    for (const close of closers.reverse()) {
      try {
        await close();
      } catch {
        /* teardown is best-effort */
      }
    }
    rmSync(tmp, { recursive: true, force: true });
  }
}

/** Apply an agent's inbound+outbound trust spec to THIS test process. Must be
 *  called at module scope in each suite, before any scenario runs: the active
 *  spec is a process-global, and node's test runner isolates each test FILE in
 *  its own process, which is exactly what makes this safe. */
export function activateSpecFor(p: AgentProvisioner): void {
  setActiveInboundSpec(p.inboundSpec);
  setActiveOutboundSpec(p.inboundSpec);
}
