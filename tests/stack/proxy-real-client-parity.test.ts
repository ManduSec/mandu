/**
 * proxy-real-client-parity — the PRODUCTION wiring of the model proxy's
 * arbiter: `new ArbiterClientAdapter(new ArbiterClient(sock))`, exactly as
 * anthropic-proxy/src/server-main.ts builds it, over a real ArbiterServer,
 * with NO test bridge in between.
 *
 * Why: the e2e stacks wrap the real client in a hand-written bridge
 * (`modelProxyRealClient`) that re-shapes each call. On 2026-09-24 that
 * bridge forwarded `callTaint` correctly while the adapter itself sent
 * `{callId: {…}}`; every e2e stayed green and every live Bash result masked
 * fail-closed ("the process taint could not be read"). This suite calls each
 * optional op the adapter forwards through the real client and asserts the
 * arbiter ANSWERED (no protocol refusal), so a shape drift between
 * arbiter/ipc/client.ts and the adapter's `RealArbiterClient` fails here
 * first. Type level: the real class must satisfy the adapter's interface.
 * The Codex proxy (openai-proxy) got the same plan 10 exit on 2026-09-24 and
 * builds its adapter the same way (src/server-main.ts): the second test pins
 * that wiring identically.
 *
 * Reply row reservation (docs/design/ui/reply-row-reservation.md §3.3, §3.6):
 * the third test pins the ops the two ends of that feature forward, each
 * through its OWN production adapter over one real server — the reply
 * filter's `setSessionRelay` (interceptors/reply-filter/src/run.ts builds
 * `new ArbiterClientAdapter(new ArbiterClient(sock))`) and the proxy's
 * `sessionRelay` / `symbolShape`. Both adapters treat a missing op as "no
 * expansion", so a shape drift would fail silently everywhere else.
 *
 * The prompt filter (confidentiality-plan-15 §3.2): both proxies' adapters
 * forward `filterPrompt` as one object; the first two tests call it over the
 * real client with a registered value and read its symbol back.
 *
 * The after-the-fact note across a resume (confidentiality.md §7.1): both
 * proxies' adapters forward `recordForwardedClear` / `forwardedClear` on the
 * human client as positional arrays; the last test records through one and
 * reads through the other, and through the ledger each proxy builds.
 *
 * OpenClaw's history redaction across a relaunch (confidentiality.md §6):
 * the anthropic-proxy's adapter forwards `recordForwardedPlaceholders` /
 * `forwardedPlaceholders` on the human client (one array each); the
 * memory the proxy builds over it records in one launch and restores in
 * the next.
 *
 * The DevTools relay's refusals told to the browser agent's model
 * (devtools-relay.md §3.4): the relay's adapter forwards `relayNotice` and
 * the egress proxy's adapter `takeRelayNotices`, each as one object on its
 * data client; the last test reports through one and takes through the
 * other. The relay's adapter also forwards `placeholderKnown` (§3.3) on its
 * human client as one object; the same test asks it over the real client.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { parseGateSurface } from "../../interceptors/anthropic-proxy/src/gate-surface.js";
import {
  ArbiterClientAdapter as ReplyFilterArbiterAdapter,
  type RealArbiterClient as ReplyFilterRealArbiterClient,
} from "../../interceptors/reply-filter/src/arbiter-client.js";
import {
  ArbiterClientAdapter as OpenAiProxyArbiterAdapter,
  type RealArbiterClient as OpenAiProxyRealArbiterClient,
} from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { ClearResultLedger as ClaudeLedger, arbiterClearResultStore as claudeStore } from "../../interceptors/anthropic-proxy/src/after-the-fact.js";
import { ClearResultLedger as CodexLedger, arbiterClearResultStore as codexStore } from "../../interceptors/openai-proxy/src/after-the-fact.js";
import { ForwardedResultMemory, arbiterPlaceholderStore } from "../../interceptors/anthropic-proxy/src/openclaw-redaction.js";
import {
  ArbiterClientAdapter as CdpRelayArbiterAdapter,
  type RealArbiterClient as CdpRelayRealArbiterClient,
} from "../../interceptors/cdp-relay/src/arbiter-client.js";
import {
  ArbiterClientAdapter as NetProxyArbiterAdapter,
  type RealArbiterClient as NetProxyRealArbiterClient,
} from "../../interceptors/net-proxy/src/arbiter-client.js";

test("the adapter over the REAL client: every plan 10 op is answered by the arbiter (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-parity-"));
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath,
    dbPath: join(tmp, "symbols.sqlite"),
    adminSocketPath: join(tmp, "admin.sock"),
    eventDir: join(tmp, "events"),
    log: () => {},
    confidentiality: true,
    integrity: false,
  });
  await server.listen();
  // The type-level pin: the real class IS a RealArbiterClient (no cast).
  const real: RealArbiterClient = new ArbiterClient(socketPath);
  await real.connect();
  const adapter = new ArbiterClientAdapter(real);
  try {
    // callTaint: an unknown call in an empty session is the neutral verdict —
    // the point is that the arbiter parsed the request (no "Unknown named
    // parameter", no throw ⇒ no fail-closed mask of a benign Bash result).
    const t = await adapter.callTaint!({ callId: "toolu_parity_1", command: "ls -la", sessionKey: "parity" });
    assert.deepEqual(t, { level: null, files: [], apps: [], rule: "secret", mask: [], root: null, denied: [] });
    const t2 = await adapter.callTaint!({ callId: "toolu_parity_2" });
    assert.equal(t2.level, null);
    // plan 10 §11.13: the per-server MCP taint, positional (tool, sessionKey)
    assert.deepEqual(await adapter.mcpServerTaint!({ tool: "mcp__store__get", sessionKey: "parity" }), { verdict: "unmapped", candidates: 0, level: null, files: [], apps: [] });
    assert.equal((await adapter.mcpServerTaint!({ tool: "mcp__mandu-policy__mandu_policy_read" })).verdict, "own");
    // the value backstop
    const scan = await adapter.scanSecretValues!("nothing registered here");
    assert.deepEqual(scan, { hits: [] });
    // a PDF document block's text (secret-discovery.md §2.8): one object; an
    // unreadable block answers null (the proxy masks it whole)
    assert.deepEqual(await adapter.documentText!({ data: Buffer.from("not a pdf").toString("base64"), mediaType: "application/pdf", origin: "/nowhere/x.pdf", sessionKey: "parity" }),
      { text: null, reason: "unreadable: not a PDF" });
    assert.equal((await adapter.documentText!({ data: "AAAA", mediaType: "image/png" })).text, null);
    // the prompt filter (confidentiality-plan-15 §3.2): one object, answered
    // per segment; a registered value in a harness segment comes back as its
    // own symbol (a shape drift would refuse every request fail-closed)
    const reg = await (real as unknown as ArbiterClient).registerEnvSecrets({ vars: [{ name: "PARITY_API_KEY", value: "parity-Zq81Hc0vNw3PpL6t" }], sessionKey: "parity" });
    const regSym = reg.vars[0]!.symbol!;
    const pf = await adapter.filterPrompt!({ session: "parity", agent: "claude-code", segments: [
      { id: "h", origin: "human", text: "nothing registered here" },
      { id: "r", origin: "harness", text: "key parity-Zq81Hc0vNw3PpL6t" },
    ] });
    assert.deepEqual(pf.segments.map((s) => s.action), ["pass", "rewrite"]);
    assert.equal(pf.segments[1]!.text, `key ${regSym}`);
    assert.equal(pf.enforcing, true);
    // the twin hints
    const tw = await adapter.execTwinsFor!("cat ~/.pgpass");
    assert.ok(Array.isArray(tw.twins));
    // the older optional ops the adapter forwards
    assert.equal(typeof (await adapter.handlingPrompt({ mode: "full" })).prompt, "string");
    // emit's bare-number → {seq} normalization is pinned in the proxy's adapter unit test
    const surface = await adapter.toolSurface(["Bash", "NoSuchTool"], "parity");
    assert.deepEqual(surface.unknown, ["NoSuchTool"]);
    // the per-agent gate surface (2026-09-27): the adapter forwards the ONE
    // optional argument positionally, the arbiter answers the session's bound
    // spec, and the proxy's validator accepts the shape (a rejected shape would
    // silently leave the Claude Code table on an OpenCode session)
    const unbound = parseGateSurface(await adapter.gateSurface!({ sessionKey: "parity" }));
    assert.equal(unbound?.spec, "claude-code");
    assert.deepEqual(unbound?.exec, { Bash: "command", Monitor: "command" });
    await real.setSessionSpec!({ sessionKey: "parity-opencode", spec: "opencode" });
    const oc = parseGateSurface(await adapter.gateSurface!({ sessionKey: "parity-opencode" }));
    assert.equal(oc?.spec, "opencode");
    // one table for OpenCode 1 and 2 (2.0.23: shell, read{path}, code mode
    // refused, background / a subagent's own model refused forms;
    // supported-agents.md §2.3); the validator keeps every part of it
    assert.deepEqual(oc?.exec, { bash: "command", shell: "command" });
    assert.deepEqual(oc?.paths["read"], { fields: ["filePath", "path"], mode: "read" });
    assert.deepEqual(oc?.dispatch, { execute: "refuse" });
    assert.deepEqual(oc?.refuseArgs["subagent"]?.map((r) => r.field), ["model", "background"]);
    assert.deepEqual(oc?.refuseArgs["shell"]?.map((r) => [r.field, [...r.allow]]), [["background", ["", "false"]]]);
    assert.ok(parseGateSurface(await adapter.gateSurface!({})), "no session key: the global spec answers");
  } finally {
    real.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("the openai-proxy (Codex) adapter over the REAL client: every plan 10 op is answered by the arbiter (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-parity-codex-"));
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath,
    dbPath: join(tmp, "symbols.sqlite"),
    adminSocketPath: join(tmp, "admin.sock"),
    eventDir: join(tmp, "events"),
    log: () => {},
    confidentiality: true,
    integrity: false,
  });
  await server.listen();
  // The type-level pin: the real class IS the openai-proxy's RealArbiterClient (no cast).
  const real: OpenAiProxyRealArbiterClient = new ArbiterClient(socketPath);
  await real.connect();
  const adapter = new OpenAiProxyArbiterAdapter(real);
  try {
    // callTaint in the real client's (callId, opts) shape: the arbiter parsed
    // it (no "Unknown named parameter", no throw ⇒ no fail-closed mask of a
    // benign exec_command result).
    const t = await adapter.callTaint!({ callId: "call_parity_1", command: "ls -la", sessionKey: "parity-codex" });
    assert.deepEqual(t, { level: null, files: [], apps: [], rule: "secret", mask: [], root: null, denied: [] });
    const t2 = await adapter.callTaint!({ callId: "call_parity_2" });
    assert.equal(t2.level, null);
    // plan 10 §11.8 (review of !1604): the output and `codexHead` ride in the
    // opts object the arbiter parses (the release they drive is proven over
    // this wiring with the guard's records in tests/stack/exec-output-key-listing).
    const t3 = await adapter.callTaint!({ callId: "call_parity_3", command: "cut -d= -f1 .env", sessionKey: "parity-codex", output: "Chunk ID: 3f2a\nProcess exited with code 0\nOutput:\nKEY\n", codexHead: true });
    assert.deepEqual(t3, { level: null, files: [], apps: [], rule: "secret", mask: [], root: null, denied: [] });
    // plan 10 §11.13: the per-server MCP taint, positional (tool, sessionKey)
    assert.deepEqual(await adapter.mcpServerTaint!({ tool: "mcp__store__get", sessionKey: "parity-codex" }), { verdict: "unmapped", candidates: 0, level: null, files: [], apps: [] });
    assert.equal((await adapter.mcpServerTaint!({ tool: "mcp__mandu_inspect__inspect_symbol" })).verdict, "own");
    // the value backstop
    const scan = await adapter.scanSecretValues!("nothing registered here");
    assert.deepEqual(scan, { hits: [] });
    // the prompt filter (confidentiality-plan-15 §3.2), one object
    const reg = await (real as unknown as ArbiterClient).registerEnvSecrets({ vars: [{ name: "PARITY_API_KEY", value: "parity-codex-Zq81Hc0vNw3P" }], sessionKey: "parity-codex" });
    const pf = await adapter.filterPrompt!({ session: "parity-codex", agent: "codex", segments: [{ id: "h", origin: "human", text: "use parity-codex-Zq81Hc0vNw3P" }] });
    assert.equal(pf.segments[0]!.action, "rewrite");
    assert.equal(pf.segments[0]!.text, `use ${reg.vars[0]!.symbol}`);
    // the older ops the adapter forwards
    assert.equal(typeof (await adapter.handlingPrompt({ mode: "full" })).prompt, "string");
    const gate = await adapter.execGate({ command: "ls -la", sessionKey: "parity-codex" });
    assert.equal(gate.decision, "allow");
    // the real client's emit resolves the BARE seq; the adapter normalizes it to {seq}
    const emitted = await adapter.emit({ id: "ev_parity_codex_1", kind: "tool_result", sessionId: "parity-codex", ts: Date.now(), callId: "call_parity_1" });
    assert.equal(typeof emitted.seq, "number");
  } finally {
    real.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("plan 13 D9 over the REAL clients: both proxies' production wiring (a data and a human client) gates and asks on the human socket, so the call binds to the agent's shell; a data-only wiring binds nothing and masks at the session's level (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-parity-d9-"));
  const socketPath = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();
  // server-main's wiring: the data client, and the human-plane one (no cast:
  // the real class satisfies both adapters' parameter types)
  const clients: ArbiterClient[] = [];
  const open = async (sock: string): Promise<ArbiterClient> => { const c = new ArbiterClient(sock); await c.connect(); clients.push(c); return c; };
  const claude = new ArbiterClientAdapter(await open(socketPath), await open(humanSock));
  const codex = new OpenAiProxyArbiterAdapter(await open(socketPath), await open(humanSock));
  const claudeDataOnly = new ArbiterClientAdapter(await open(socketPath));
  const guard = await open(humanSock); // the guard reports on the human socket too
  try {
    const session = "parity-d9";
    // a reader read a secret raw in this session (the guard's record)
    await guard.taintProcessSecret({ procKey: "d9-cat-0", path: "/w/x.txt", level: "no-model", app: "cat", session });
    const ask = {
      claude: (r: { callId: string; command: string; sessionKey: string }) => claude.callTaint!(r),
      codex: (r: { callId: string; command: string; sessionKey: string }) => codex.callTaint(r),
      "claude, data only": (r: { callId: string; command: string; sessionKey: string }) => claudeDataOnly.callTaint!(r),
    };
    const gate = {
      claude: (r: { command: string; sessionKey: string; callId: string }) => claude.execGate(r),
      codex: (r: { command: string; sessionKey: string; callId: string }) => codex.execGate(r),
      "claude, data only": (r: { command: string; sessionKey: string; callId: string }) => claudeDataOnly.execGate(r),
    };
    // Plan 13 D9 follow-up: the command the proxy DELIVERED (here, the view
    // map's AgentView spelling of the gated one), one object over the real client
    const deliver = {
      claude: (r: { callId: string; command: string; sessionKey: string }) => claude.recordCallCommand!(r),
      codex: (r: { callId: string; command: string; sessionKey: string }) => codex.recordCallCommand(r),
      "claude, data only": (r: { callId: string; command: string; sessionKey: string }) => claudeDataOnly.recordCallCommand!(r),
    };
    let n = 0;
    for (const who of ["claude", "codex", "claude, data only"] as const) {
      n += 1;
      const cmd = `cat /home/u/proj/d9-${n}.txt`;
      const delivered = `cat /v/proj/d9-${n}.txt`;
      const callId = `toolu_d9_${n}`;
      await gate[who]({ command: cmd, sessionKey: session, callId });
      const rec = await deliver[who]({ callId, command: delivered, sessionKey: session });
      assert.equal(rec.recorded, who !== "claude, data only", `${who}: recorded only on the human socket`);
      await guard.recordExecRoot({ procKey: `d9-sh-${n}`, ancestors: ["d9-agent-0"], argv: ["/bin/bash", "-c", delivered], session, callRoot: true });
      // the agent echoes a different command: never what the call binds by
      const t = await ask[who]({ callId, command: `echo innocent-${n}`, sessionKey: session });
      if (who === "claude, data only") {
        assert.equal(t.evidence, "session", `${who}: no binding from the data socket: ${JSON.stringify(t)}`);
        assert.equal(t.level, "no-model", `${who}: the session's raw read masks it (fail-closed)`);
      } else {
        assert.equal(t.evidence, "tree", `${who}: ${JSON.stringify(t)}`);
        assert.equal(t.root, `d9-sh-${n}`, `${who}: bound to the agent's shell for the delivered command`);
        assert.equal(t.level, null, `${who}: a clean call stays raw (utility)`);
      }
    }
  } finally {
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("arbiter-human-plane.md §10.2 over the REAL clients: both proxies' production wiring sends its events (and the Claude proxy its tool-call records) on the human socket, where they are believed; a data-only wiring's are claims (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-parity-obs-"));
  const socketPath = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (sock: string): Promise<ArbiterClient> => { const c = new ArbiterClient(sock); await c.connect(); clients.push(c); return c; };
  const claude = new ArbiterClientAdapter(await open(socketPath), await open(humanSock));
  const codex = new OpenAiProxyArbiterAdapter(await open(socketPath), await open(humanSock));
  const claudeDataOnly = new ArbiterClientAdapter(await open(socketPath));
  const reader = await open(humanSock);
  try {
    const session = "parity-obs";
    const ev = (id: string, emitter: string) => ({ id, sessionId: session, ts: new Date().toISOString(), kind: "tllm_call", view: "AgentView", boundary: "model_context", emitter }) as never;
    await claude.emit(ev("claude-1", "anthropic-proxy"));
    await codex.emit(ev("codex-1", "openai-proxy"));
    await claudeDataOnly.emit(ev("data-1", "anthropic-proxy"));
    const got = new Map((await reader.events(session)).map((e) => [(e as { id: string }).id, (e as { claimed?: unknown }).claimed]));
    // MASTER: both production wirings sent on the data socket (no mark could tell them from a forger's)
    assert.equal(got.get("claude-1"), undefined, "the Claude proxy's event is believed");
    assert.equal(got.get("codex-1"), undefined, "the Codex proxy's event is believed");
    assert.equal(got.get("data-1"), true, "a data-only wiring's event is a claim");

    const sym = await reader.symbolize({ tool: "WebFetch", field: "text", value: "body", callId: "toolu_obs", sessionKey: session });
    await claude.recordToolCall({ toolUseId: "toolu_obs", name: "WebFetch", input: { url: "https://docs.example" }, sessionKey: session });
    // MASTER: null (the record came from the data socket, a claim)
    assert.equal((await reader.symbolProvenance(sym)).toolName, "WebFetch", "the production wiring's record is believed");
    const sym2 = await reader.symbolize({ tool: "WebFetch", field: "text", value: "body2", callId: "toolu_obs2", sessionKey: session });
    await claudeDataOnly.recordToolCall({ toolUseId: "toolu_obs2", name: "WebFetch", input: { url: "https://docs.example" }, sessionKey: session });
    assert.equal((await reader.symbolProvenance(sym2)).toolName, null, "a data-only wiring's record is a claim");
  } finally {
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("plan 13 §4.5.1 over the REAL clients: the Claude proxy's production wiring records a command-less relay and asks agentReceiptTaint on the human socket; a data-only wiring still masks, unattributed (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-parity-af-"));
  const socketPath = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (sock: string): Promise<ArbiterClient> => { const c = new ArbiterClient(sock); await c.connect(); clients.push(c); return c; };
  const claude = new ArbiterClientAdapter(await open(socketPath), await open(humanSock));
  const claudeDataOnly = new ArbiterClientAdapter(await open(socketPath));
  const guard = await open(humanSock);
  try {
    const session = "parity-af";
    await guard.taintProcessSecret({ procKey: "af-srv-0", path: "/w/.env", level: "no-model", app: "python3", session });
    // The relay, one object with no command (a WebFetch call).
    assert.equal((await claude.recordCallCommand!({ callId: "toolu_af_1", sessionKey: session })).recorded, true, "recorded on the human socket");
    assert.equal((await claudeDataOnly.recordCallCommand!({ callId: "toolu_af_2", sessionKey: session })).recorded, false, "the data socket records no relay");
    await new Promise((ok) => setTimeout(ok, 5));
    // The guard's record: the agent itself holds a channel the server writes into.
    assert.equal((await guard.recordAgentFlow({ channel: "socket:[9001]", flowsFrom: ["af-srv-0"], session })).recorded, true);
    await new Promise((ok) => setTimeout(ok, 5));
    const calls = (id: string) => [{ callId: id, tool: "WebFetch" }, { callId: `${id}_read`, tool: "Read" }];
    const r = await claude.agentReceiptTaint!({ calls: calls("toolu_af_1"), sessionKey: session });
    assert.equal(r.calls[0]!.level, "no-model", JSON.stringify(r));
    assert.equal(r.calls[0]!.unattributed, undefined, "the relay was recorded: the window is known");
    assert.equal(r.calls[1]!.level, null, "a file tool is not the agent's receipt");
    const d = await claudeDataOnly.agentReceiptTaint!({ calls: calls("toolu_af_2"), sessionKey: session });
    assert.equal(d.calls[0]!.level, "no-model", "data-only: masked anyway (fail-closed)");
    assert.equal(d.calls[0]!.unattributed, true, "its relay was never recorded");
  } finally {
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("arbiter-human-plane.md §10.3 over the REAL clients: the Claude proxy's production wiring asks its network and path gates on the human socket, so its ask is the one that spends a human's Allow once (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-parity-once-"));
  const socketPath = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (sock: string): Promise<ArbiterClient> => { const c = new ArbiterClient(sock); await c.connect(); clients.push(c); return c; };
  const data = await open(socketPath);
  const claude = new ArbiterClientAdapter(data, await open(humanSock));
  try {
    const session = "parity-once";
    const symbol = await data.symbolize({ tool: "WebFetch", field: "text", value: "parity-once-secret", confidentiality: "secret" });
    const net = () => claude.desymbolizationDecision({ symbol, boundary: "network", destination: "evil.example", sessionKey: session });
    const fsReq = { tool: "Read", path: "/opt/parity-once/notes.txt", mode: "read" as const, workspaceRoots: [], sessionKey: session };
    const fs = () => claude.fsPathDecision(fsReq);
    const n1 = await net();
    const f1 = await fs();
    assert.equal(n1.allow, false);
    assert.equal(f1.allow, false);
    const netId = (n1 as { approvalId?: string }).approvalId;
    const fsId = (f1 as { approvalId?: string }).approvalId;
    assert.ok(netId && fsId, "both gates queue a row");
    // The human answers Allow once on each (an in-process dispatch is the admin channel).
    for (const approvalId of [netId, fsId]) {
      const v = server.dispatch({ id: `once-${approvalId}`, op: "resolveEgressApproval", approvalId, approve: true, scope: "once" } as never);
      assert.ok(v.ok, (v as { error?: string }).error);
    }
    // A data-only wiring (what a program of the agent reaches) is neither
    // granted the human's once nor spends it.
    const claudeDataOnly = new ArbiterClientAdapter(data);
    assert.equal((await claudeDataOnly.desymbolizationDecision({ symbol, boundary: "network", destination: "evil.example", sessionKey: session })).allow, false);
    assert.equal((await claudeDataOnly.fsPathDecision(fsReq)).allow, false);
    // With the data client gone, only the human socket can answer the gates.
    data.close();
    assert.equal((await net()).allow, true, "the net gate's ask, on the human socket: the one use");
    assert.equal((await fs()).allow, true, "the path gate's ask, on the human socket: the one use");
    assert.equal((await net()).allow, false, "spent: it asks again");
    assert.equal((await fs()).allow, false, "spent: it asks again");
  } finally {
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("confidentiality.md §4 (the human half) over the REAL clients: the Claude proxy's production wiring asks the HIGH-session gate on the human socket, so its ask files the row, carries its id and spends the Allow once; a data-only wiring is never granted it (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-parity-session-"));
  const socketPath = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const adminSock = join(tmp, "admin.sock");
  const server = new ArbiterServer({
    socketPath, humanSocketPath: humanSock, adminSocketPath: adminSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (sock: string): Promise<ArbiterClient> => { const c = new ArbiterClient(sock); await c.connect(); clients.push(c); return c; };
  const data = await open(socketPath);
  const admin = await open(adminSock);
  const claude = new ArbiterClientAdapter(data, await open(humanSock)); // PRODUCTION wiring
  try {
    const session = "parity-session-high";
    const memos = join(tmp, "memos");
    await admin.setPathLabel({ path: memos, confidentiality: "any-model", bindings: ["docs.corp"] });
    const s = await admin.symbolizeFull({ tool: "Read", value: "parity memo", field: "content", origin: join(memos, "m.md"), integrity: "trusted", sessionKey: session });
    assert.equal((await admin.declassifySymbol({ symbol: s.symbol, sessionKey: session })).allowed, true);
    const ask = () => claude.sessionEgressDecision({ sessionKey: session, boundary: "network", destination: "evil.example" });
    const first = await ask();
    assert.equal(first.allow, false);
    assert.ok(first.approvalId, "the forwarded op returns the row's id");
    assert.equal(first.ruleRef?.id, "session:high-unbound");
    await admin.resolveEgressApproval(first.approvalId!, true, "once");
    const claudeDataOnly = new ArbiterClientAdapter(data);
    assert.equal((await claudeDataOnly.sessionEgressDecision({ sessionKey: session, boundary: "network", destination: "evil.example" })).allow, false, "a data-only wiring is never granted the human's once");
    const second = await ask();
    assert.equal(second.allow, true, "the production wiring's ask, on the human socket: the one use");
    assert.equal(second.ruleRef?.id, `verdict:${first.approvalId}`);
    assert.equal((await ask()).allow, false, "spent: it asks again");
  } finally {
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("reply row reservation over the REAL client: the filter's setSessionRelay reaches the proxy's sessionRelay; symbolShape counts lines (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-parity-reserve-"));
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath,
    dbPath: join(tmp, "symbols.sqlite"),
    adminSocketPath: join(tmp, "admin.sock"),
    humanSocketPath: join(tmp, "human", "arbiter.sock"),
    eventDir: join(tmp, "events"),
    log: () => {},
    confidentiality: true,
    integrity: false,
  });
  await server.listen();
  // The type-level pins: the real class IS each package's RealArbiterClient (no cast).
  // Each as its production process wires it (arbiter-human-plane.md): the
  // proxy's data client plus its human-plane client for symbolShape; the
  // filter on the human-plane socket (desymbolize answers only there).
  const humanPath = join(tmp, "human", "arbiter.sock");
  const proxyReal: RealArbiterClient = new ArbiterClient(socketPath);
  const proxyHuman: RealArbiterClient = new ArbiterClient(humanPath);
  const filterReal: ReplyFilterRealArbiterClient = new ArbiterClient(humanPath);
  await proxyReal.connect();
  await proxyHuman.connect();
  await filterReal.connect();
  const proxyAdapter = new ArbiterClientAdapter(proxyReal, proxyHuman);
  const filterAdapter = new ReplyFilterArbiterAdapter(filterReal);
  // A third production client, only to seed a symbol (the proxy mints through classify).
  const seed = new ArbiterClient(socketPath);
  await seed.connect();
  try {
    // ── the relay: written by the filter's adapter, read by the proxy's ──
    const key = "parity-reserve-scope";
    assert.equal(await proxyAdapter.sessionRelay!(key), null, "never reported: null (no expansion)");
    await filterAdapter.setSessionRelay({ sessionKey: key, mode: "pty", reserve: true, wrap: true, cols: 80, rows: 24 });
    const r = await proxyAdapter.sessionRelay!(key);
    assert.ok(r, "the proxy reads what the filter reported");
    assert.deepEqual({ ...r, updatedAt: 0 }, { mode: "pty", reserve: true, wrap: true, cols: 80, rows: 24, updatedAt: 0 });
    // Both relay ops are human plane since v2 (reply-row-reservation.md §11.5):
    // a proxy with only the data socket reads no relay, and the raw data
    // client is refused.
    assert.equal(await new ArbiterClientAdapter(proxyReal).sessionRelay!(key), null);
    await assert.rejects((proxyReal as { sessionRelay(k: string): Promise<unknown> }).sessionRelay(key), /human-plane/);
    assert.equal(typeof r.updatedAt, "number");
    // A re-report (resize, or the kill switch) overwrites; another session is untouched.
    await filterAdapter.setSessionRelay({ sessionKey: key, mode: "pty", reserve: false });
    assert.equal((await proxyAdapter.sessionRelay!(key))?.reserve, false);
    await filterAdapter.setSessionRelay({ sessionKey: `${key}-pipe`, mode: "pipe", reserve: false });
    assert.equal((await proxyAdapter.sessionRelay!(`${key}-pipe`))?.mode, "pipe");
    assert.equal(await proxyAdapter.sessionRelay!("parity-other-scope"), null);
    // A malformed report is refused by the arbiter, not swallowed by the wiring.
    await assert.rejects(filterAdapter.setSessionRelay({ sessionKey: key, mode: "tty" as never, reserve: true }), /mode must be one of/);

    // ── symbolShape: a multi-line no-model value's line count, never the value ──
    const value = "Host bastion\n  HostName 10.9.8.7\n\n\tUser PARITYCANARY\n";
    const token = await seed.symbolize({ tool: "Read", value, confidentiality: "no-model" });
    assert.match(token, /^\$MDU:nomodel_/, "precondition: a no-model symbol");
    const shape = await proxyAdapter.symbolShape!(token);
    assert.deepEqual(shape, { lines: 4 }, "four lines (the blank one counts; one trailing newline dropped)");
    assert.ok(!JSON.stringify(shape).includes("PARITYCANARY"));
    // The Markdown-escaped spelling a model writes answers the same.
    assert.deepEqual(await proxyAdapter.symbolShape!(token.replace(/\$/g, "\\$").replace(/_/g, "\\_")), { lines: 4 });
    // v2: with a width the rows at that width come back too (§11.5), and the
    // first row's width counts; a layout the arbiter refuses rejects.
    const wide = await seed.symbolize({ tool: "Read", value: "PARITYWIDE " + "word ".repeat(30), confidentiality: "no-model" });
    assert.deepEqual(await proxyAdapter.symbolShape!(wide, { width: 78, first: 78 }), { lines: 1, rows: 3, last: 10 }); // 161 columns
    assert.deepEqual(await proxyAdapter.symbolShape!(token, { width: 78, first: 0 }), { lines: 4, rows: 5, last: 25 });
    await assert.rejects(proxyAdapter.symbolShape!(token, { width: 78, first: 10 }), /first must be 0 or an integer/);
    // §11.2: `indent` rides through the wiring. The last line's TAB counts its
    // stop from the content area's column 2, as the terminal does: 6
    // columns, not 8, then "User PARITYCANARY".
    assert.deepEqual(await proxyAdapter.symbolShape!(token, { width: 78, first: 0, indent: 2 }), { lines: 4, rows: 5, last: 23 });
    await assert.rejects(proxyAdapter.symbolShape!(token, { width: 78, first: 0, indent: -1 }), /indent must be an integer/);
    // §17: the wrap rule rides through both production wirings. The filter
    // reports `terminal` (Goose), the proxy reads it back and counts by it:
    // the same 161 columns at the full width break by character, 3 rows of
    // 80, 80 and 1, where Ink's word wrap at 80 gives 3 rows too, ending at 1.
    await filterAdapter.setSessionRelay({ sessionKey: `${key}-goose`, mode: "pty", reserve: true, wrap: true, cols: 80, rows: 24, rule: "terminal" });
    assert.equal((await proxyAdapter.sessionRelay!(`${key}-goose`))?.rule, "terminal");
    assert.deepEqual(await proxyAdapter.symbolShape!(wide, { width: 80, first: 80, rule: "terminal" }), { lines: 1, rows: 3, last: 1 });
    assert.deepEqual(await proxyAdapter.symbolShape!(wide, { width: 80, first: 67, rule: "terminal" }), { lines: 1, rows: 3, last: 14 });
    await assert.rejects(proxyAdapter.symbolShape!(wide, { width: 80, first: 80, rule: "char" as never }), /rule must be one of/);
    // Unknown token, and text around a token: null (the proxy does not expand).
    assert.equal(await proxyAdapter.symbolShape!("$MDU:nomodel_Read[0badc0de]"), null);
    assert.equal(await proxyAdapter.symbolShape!(`see ${token}`), null);
    // The data socket alone (a proxy without the human plane) gets no shape.
    assert.equal(await new ArbiterClientAdapter(proxyReal).symbolShape!(token), null);
    await assert.rejects((proxyReal as { symbolShape(t: string): Promise<unknown> }).symbolShape(token), /human-plane/);
    // The filter's resolver (desymbolize) answers the value on the same wiring.
    assert.equal(await filterAdapter.desymbolize(token), value);

    // ── the block registry (§3.8): written by the proxy's adapter, read by the filter's ──
    const hash = /\[([0-9a-f]{4,8})\]/.exec(token)![1]!;
    assert.equal(await filterAdapter.reserveBlock(key, hash), null, "nothing recorded yet");
    await proxyAdapter.noteReserveBlock!({ sessionKey: key, token, n: 4 });
    assert.deepEqual(await filterAdapter.reserveBlock(key, hash), { token, n: 4 });
    await proxyAdapter.noteReserveBlock!({ sessionKey: key, token: token.replace(/\$/g, "\\$").replace(/_/g, "\\_"), n: 5, width: 78, first: 0 });
    assert.deepEqual(await filterAdapter.reserveBlock(key, hash), { token, n: 5, width: 78, first: 0 }, "an escaped token is stored canonical");
    assert.equal(await filterAdapter.reserveBlock("parity-other-scope", hash), null);
    // A proxy without the human plane records nothing; the data client is refused.
    await new ArbiterClientAdapter(proxyReal).noteReserveBlock!({ sessionKey: `${key}-data`, token, n: 4 });
    assert.equal(await filterAdapter.reserveBlock(`${key}-data`, hash), null);
    await assert.rejects(
      (proxyReal as { noteReserveBlock(a: unknown): Promise<unknown> }).noteReserveBlock({ sessionKey: key, token, n: 4 }),
      /human-plane/,
    );

    // ── the Codex proxy (§11.7): the same two ops, on its own human client ──
    const codexReal: OpenAiProxyRealArbiterClient = new ArbiterClient(socketPath);
    const codexHuman: OpenAiProxyRealArbiterClient = new ArbiterClient(humanPath);
    await codexReal.connect();
    await codexHuman.connect();
    try {
      const codexAdapter = new OpenAiProxyArbiterAdapter(codexReal, codexHuman);
      assert.deepEqual({ ...(await codexAdapter.sessionRelay!(key))!, updatedAt: 0 },
        { mode: "pty", reserve: false, updatedAt: 0 }, "the Codex proxy reads the relay the filter last reported");
      assert.deepEqual(await codexAdapter.symbolShape!(token), { lines: 4 });
      assert.deepEqual(await codexAdapter.symbolShape!(wide, { width: 78, first: 78 }), { lines: 1, rows: 3, last: 10 });
      assert.deepEqual(await codexAdapter.symbolShape!(token, { width: 78, first: 0, indent: 2 }), { lines: 4, rows: 5, last: 23 },
        "§11.2: the Codex wiring forwards `indent` too");
      await codexAdapter.noteReserveBlock!({ sessionKey: `${key}-codex`, token: wide, n: 3, width: 78, first: 78 });
      assert.deepEqual(await filterAdapter.reserveBlock(`${key}-codex`, /\[([0-9a-f]{4,8})\]/.exec(wide)![1]!),
        { token: wide, n: 3, width: 78, first: 78 }, "the Codex proxy's record reaches the filter");
      // Without the human plane it gets neither (no expansion).
      const dataOnly = new OpenAiProxyArbiterAdapter(codexReal);
      assert.equal(await dataOnly.sessionRelay!(key), null);
      assert.equal(await dataOnly.symbolShape!(token), null);
    } finally {
      codexReal.close();
      codexHuman.close();
    }
  } finally {
    seed.close();
    proxyReal.close();
    proxyHuman.close();
    filterReal.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("supported-agents.md §2.3 item 7 over the REAL client: the Claude proxy's production wiring forwards sessionPathLabel as one object; the arbiter labels the path for the session (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-parity-spl-"));
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({ socketPath, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const real = new ArbiterClient(socketPath);
  await real.connect();
  try {
    const adapter = new ArbiterClientAdapter(real); // PRODUCTION wiring
    const out = "/home/u/.local/share/opencode/shell/0123456789abcdef0123456789abcdef01234567/sh_parity.out";
    assert.deepEqual(await adapter.sessionPathLabel!({ path: out, sessionKey: "parity-spl", reason: "parity" }), { labeled: true, path: out });
    assert.equal((await real.pathLevel(out)).level, "no-model");
    await assert.rejects(() => adapter.sessionPathLabel!({ path: "relative.out", sessionKey: "parity-spl" }));
  } finally {
    real.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("agent-sign-in.md §3 over the REAL clients: the Claude proxy's production wiring answers authCredential from the human socket (the gate, then the shallow resolve); a data-only wiring answers null (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-parity-authkey-"));
  const socketPath = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (sock: string): Promise<ArbiterClient> => { const c = new ArbiterClient(sock); await c.connect(); clients.push(c); return c; };
  const dir = join(tmp, "home", ".config", "goose");
  mkdirSync(dir, { recursive: true });
  const file = join(dir, "secrets.yaml");
  const key = "sk-ant-api03-MANDUFAKEparityAUTHkey0123456789abcdef";
  writeFileSync(file, `ANTHROPIC_API_KEY: ${key}\n`);
  try {
    const human = await open(humanSock);
    assert.deepEqual(await human.registerAuthGrant(file, [{ field: "ANTHROPIC_API_KEY", host: "api.anthropic.com", https: true }]), { granted: 1 });
    const reg = await human.registerSecret({ path: file });
    const symbol = /ANTHROPIC_API_KEY: (\$MDU:\S+)/.exec(reg.twin ?? "")?.[1];
    assert.ok(symbol, JSON.stringify(reg));
    const data: RealArbiterClient = await open(socketPath);
    const claude = new ArbiterClientAdapter(data, await open(humanSock)); // PRODUCTION wiring
    assert.equal((await claude.authCredential({ symbol: symbol!, destination: "api.anthropic.com", scheme: "https", sessionKey: "parity-authkey" })).value, key);
    assert.equal((await claude.authCredential({ symbol: symbol!, destination: "evil.example", scheme: "https" })).value, null, "an ungranted host");
    assert.equal((await claude.authCredential({ symbol: symbol!, destination: "api.anthropic.com", scheme: "http" })).value, null, "plain HTTP");
    assert.equal((await new ArbiterClientAdapter(data).authCredential({ symbol: symbol!, destination: "api.anthropic.com", scheme: "https" })).value, null, "data-only: never resolved");
    // §3.9: the Codex proxy's production wiring answers the same way.
    const codexData: OpenAiProxyRealArbiterClient = await open(socketPath);
    const codexHuman: OpenAiProxyRealArbiterClient = await open(humanSock);
    const codex = new OpenAiProxyArbiterAdapter(codexData, codexHuman); // PRODUCTION wiring
    assert.equal((await codex.authCredential({ symbol: symbol!, destination: "api.anthropic.com", scheme: "https", sessionKey: "parity-authkey" })).value, key);
    assert.equal((await codex.authCredential({ symbol: symbol!, destination: "evil.example", scheme: "https" })).value, null, "an ungranted host");
    assert.equal((await new OpenAiProxyArbiterAdapter(codexData).authCredential({ symbol: symbol!, destination: "api.anthropic.com", scheme: "https" })).value, null, "data-only: never resolved");
  } finally {
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("confidentiality.md §7.1 across a resume over the REAL clients: both proxies' production wiring records and reads the forwarded-in-clear ids on the human socket, positional arrays; a data-only wiring records nothing and knows nothing; the ledger over each adapter is the one the proxy builds (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-parity-fc-"));
  const socketPath = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (sock: string): Promise<ArbiterClient> => { const c = new ArbiterClient(sock); await c.connect(); clients.push(c); return c; };
  try {
    const claude = new ArbiterClientAdapter(await open(socketPath), await open(humanSock));
    const codex = new OpenAiProxyArbiterAdapter(await open(socketPath), await open(humanSock));
    const claudeDataOnly = new ArbiterClientAdapter(await open(socketPath));
    const codexDataOnly = new OpenAiProxyArbiterAdapter(await open(socketPath));

    await claude.recordForwardedClear(["toolu_fc_1", "toolu_fc_2"]);
    await codex.recordForwardedClear(["call_fc_1"]);
    await claudeDataOnly.recordForwardedClear(["toolu_fc_data"]);
    await codexDataOnly.recordForwardedClear(["call_fc_data"]);
    const all = ["toolu_fc_2", "call_fc_1", "toolu_fc_data", "call_fc_data", "toolu_fc_1", "toolu_none"];
    assert.deepEqual(await claude.forwardedClear(all), ["toolu_fc_2", "call_fc_1", "toolu_fc_1"], "the human wiring's records, in the order asked; the data-only ones never landed");
    assert.deepEqual(await codex.forwardedClear(all), ["toolu_fc_2", "call_fc_1", "toolu_fc_1"]);
    assert.deepEqual(await claudeDataOnly.forwardedClear(all), [], "no human client: nothing known (memory only)");
    assert.deepEqual(await codexDataOnly.forwardedClear(all), []);
    // the data socket itself refuses both ops (the human plane, arbiter-human-plane.md §3)
    const raw = await open(socketPath);
    await assert.rejects(raw.forwardedClear(["toolu_fc_1"]), /human-plane: 'forwardedClear'/);
    await assert.rejects(raw.recordForwardedClear(["toolu_x"]), /human-plane: 'recordForwardedClear'/);

    // the proxies' own ledger over each production adapter (proxy.ts builds it so)
    const l1 = new ClaudeLedger(undefined, { store: claudeStore(claude) });
    await l1.remember(["toolu_fc_ledger"]);
    const l2 = new CodexLedger(undefined, { store: codexStore(codex) });
    await l2.prime(["toolu_fc_ledger", "toolu_none"]);
    assert.ok(l2.wasClear("toolu_fc_ledger") && !l2.wasClear("toolu_none"), "one proxy's record, another's read: through the arbiter");

    // "Two launches at once" (2026-10-17): forwardedClear with `since` over
    // each production adapter (the generation, then the ids recorded after it).
    for (const [who, a] of [["claude", claude], ["codex", codex]] as const) {
      const g = await a.forwardedClearSince(["toolu_none"]);
      assert.equal(typeof g.generation, "number", `${who}: the generation`);
      assert.deepEqual(g.ids, []);
      await a.recordForwardedClear([`toolu_fc_since_${who}`]);
      const later = await a.forwardedClearSince([], g.generation);
      assert.deepEqual(later.recent, [`toolu_fc_since_${who}`], `${who}: the ids recorded since`);
    }
    assert.deepEqual(await claudeDataOnly.forwardedClearSince(["toolu_fc_1"], 0), { ids: [] }, "no human client: the plain ask, which knows nothing");
    await assert.rejects(raw.forwardedClearSince([], 0), /human-plane: 'forwardedClear'/);
    // the ledger over the adapter reaches for knownSince (proxy.ts builds it so)
    assert.equal(typeof claudeStore(claude)!.knownSince, "function");
    assert.equal(typeof codexStore(codex)!.knownSince, "function");
  } finally {
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("confidentiality.md §6 across a relaunch over the REAL clients: the anthropic-proxy's production wiring records and reads the placeholder records on the human socket; a data-only wiring records nothing; the memory over the adapter records in one launch and restores in the next (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-parity-fp-"));
  const socketPath = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({
    socketPath, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (sock: string): Promise<ArbiterClient> => { const c = new ArbiterClient(sock); await c.connect(); clients.push(c); return c; };
  try {
    const claude = new ArbiterClientAdapter(await open(socketPath), await open(humanSock));
    const dataOnly = new ArbiterClientAdapter(await open(socketPath));
    const tok = "$MDU:nomodel_Read[e7f3].STRIPE_KEY";
    const map = { callId: "toolu_fp_1", digest: "c".repeat(64), placeholders: [[12, tok]] as Array<[number, string]> };
    await claude.recordForwardedPlaceholders([map]);
    await dataOnly.recordForwardedPlaceholders([{ ...map, callId: "toolu_fp_data" }]);
    assert.deepEqual(await claude.forwardedPlaceholders(["toolu_fp_data", "toolu_fp_1"]), [map], "the human wiring's record; the data-only one never landed");
    assert.deepEqual(await dataOnly.forwardedPlaceholders(["toolu_fp_1"]), [], "no human client: nothing known (memory only)");
    const raw = await open(socketPath);
    await assert.rejects(raw.forwardedPlaceholders(["toolu_fp_1"]), /human-plane: 'forwardedPlaceholders'/);
    await assert.rejects(raw.recordForwardedPlaceholders([map]), /human-plane: 'recordForwardedPlaceholders'/);

    // the proxy's own memory over the production adapter (proxy.ts builds it so)
    const twin = `STRIPE_KEY='${tok}'\nDEBUG=1\n`;
    const m1 = new ForwardedResultMemory(undefined, undefined, { store: arbiterPlaceholderStore(claude) });
    m1.remember("toolu_fp_mem", twin);
    await m1.flush();
    const m2 = new ForwardedResultMemory(undefined, undefined, { store: arbiterPlaceholderStore(new ArbiterClientAdapter(await open(socketPath), await open(humanSock))) });
    await m2.prime([["toolu_fp_mem", "STRIPE_KEY='$MDU:n…_KEY'\nDEBUG=1\n"]]);
    assert.equal(m2.restore("toolu_fp_mem", "STRIPE_KEY='$MDU:n…_KEY'\nDEBUG=1\n"), twin, "one launch's record, the next launch's restore: through the arbiter");
  } finally {
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("devtools-relay.md §3.4 over the REAL clients: the relay's production wiring reports a refusal (relayNotice), the egress proxy's takes it once (takeRelayNotices), per session (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-parity-relay-notice-"));
  const socketPath = join(tmp, "arbiter.sock");
  const humanSocketPath = join(tmp, "h", "h.sock");
  const server = new ArbiterServer({ socketPath, humanSocketPath, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const data = new ArbiterClient(socketPath);
  const human = new ArbiterClient(humanSocketPath);
  await data.connect();
  await human.connect();
  try {
    // Type-level pins: the real class IS each adapter's RealArbiterClient.
    const relayReal: CdpRelayRealArbiterClient = data;
    const proxyReal: NetProxyRealArbiterClient = data;
    const relay = new CdpRelayArbiterAdapter(relayReal, human); // cdp-relay server-main.ts
    const proxy = new NetProxyArbiterAdapter(proxyReal, human); // net-proxy server-main.ts
    const notice = { kind: "unknown" as const, page: "ledgerly.localhost", symbols: ["$MDU:web_fetch[8c4f].text"], shown: ["$MDU:nomodel_Read[8c4e].CARD_NUMBER"] };
    await relay.relayNotice(notice, "parity-relay");
    await relay.relayNotice({ kind: "not-allowed", page: "chat.localhost", symbols: notice.shown }, "parity-other");
    assert.deepEqual(await proxy.takeRelayNotices({ sessionKey: "parity-relay" }), [notice]);
    assert.deepEqual(await proxy.takeRelayNotices({ sessionKey: "parity-relay" }), [], "told once");
    assert.equal((await proxy.takeRelayNotices({ sessionKey: "parity-other" })).length, 1, "per session");
    // A malformed notice is the arbiter's refusal, not a silent drop of the op.
    await assert.rejects(relay.relayNotice({ kind: "unknown", symbols: ["4242 4242 4242 4242"] }, "parity-relay"), /placeholder names only/);

    // devtools-relay.md §3.3: the relay's placeholderKnown, on its HUMAN
    // client as one object, answered by the arbiter (a known base through
    // its field row, a made-up code), never a protocol refusal; the data
    // client is refused it (a human-plane op).
    const env = join(tmp, ".env");
    writeFileSync(env, "CARD_NUMBER=4242424242424242\n");
    const reg = await human.registerSecret({ path: env, sessionKey: "parity-relay" });
    const base = String(reg.symbol);
    assert.equal(await relay.placeholderKnown(base), true, "a registered secret's base");
    assert.equal(await relay.placeholderKnown("$MDU:web_fetch[8c4f]"), false, "a made-up code");
    await assert.rejects(new CdpRelayArbiterAdapter(relayReal, data).placeholderKnown(base), /human-plane: 'placeholderKnown'/, "the data socket refuses it");
  } finally {
    data.close();
    human.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
