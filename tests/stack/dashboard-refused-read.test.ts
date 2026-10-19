/**
 * dashboard-refused-read — a program refused a labeled secret file, told on
 * the product's session page and the inspector over the PRODUCTION wiring
 * (dashboard.md §4.25b *A refusal is not a mask*; plan 10 §11.8; the work
 * ledger's tour item 15): a real ArbiterServer in `secrets`, the REAL
 * anthropic-proxy over HTTP on its production clients (`new
 * ArbiterClientAdapter(new ArbiterClient(sock), new
 * ArbiterClient(humanSock))`), a scripted model behind it, the guard's
 * records written over a second production client on the human socket, and
 * the real DashboardServer over `ArbiterEventSource`, read signed out.
 *
 * One turn: the model runs two Bash calls on the labeled `.env` and a
 * `curl` that carries a registered key's placeholder. The guard refuses
 * `cat` (no reader rule names it: `denied`) and holds `mytool` for the
 * person's OK until its ceiling passes (`held`); the REAL net-proxy
 * (`new ArbiterClientAdapter(new ArbiterClient(sock), human)`, as
 * production wires it) refuses the `curl` at a host no rule lets the key go
 * to. The next request carries each program's own output.
 *
 * Proves, end to end:
 *   - the model gets each failure text released, with the `[mandu:secret]`
 *     note's `denied:` and `held:` forms, and never the file's value;
 *   - the product's agent page (`/api/home/agent`) tells each step as
 *     blocked, with what Mandu did ("Mandu stopped a program from reading a
 *     secret file, …", "Mandu held a program's read of a secret file and
 *     asked for your OK. …"), never "A secret was masked before the AI saw
 *     it."; its turn's line names the refused send's secret beside the
 *     refused reads (dashboard.md §4.25b *The summary names the secrets*):
 *     "Mandu blocked 1 request that carried your secret `STRIPE_KEY` and
 *     stopped 2 reads of secret files.", never "blocked 3 actions", never
 *     "hid 2 secrets";
 *   - Home's row (`/api/home`) counts the three blocks the page counts;
 *   - the inspector's routes count them too: `/api/events` (the header's
 *     counts, each tool step's `readRefused`, each card's sentence, the
 *     page's own) and the sidebar's row (`/api/sessions`): 3 blocked (the
 *     two reads and the send), 2 asks (the held read, and the Approvals row
 *     the refused send queued), 1 masked (the registered key);
 *   - no route carries either value, nor does api.stripe.com get the
 *     request; the product's routes carry no token and none of the proxy's
 *     words to the AI.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { Readable } from "node:stream";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { buildTextSse, sseEvent } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { NetProxy, type HttpForwarder } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter as NetArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const dirs: string[] = [];
after(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const CANARY = `sk_live_RefusedReadCanary${process.pid}`;
const STRIPE = `sk_live_RefusedSendCanary${process.pid}`;

/** A plain-HTTP GET through the forward proxy carrying `auth`, as curl sends it. */
function viaNetProxy(port: number, url: string, auth: string): Promise<{ status: number; body: string }> {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, method: "GET", path: url, headers: { host: u.host, authorization: `Bearer ${auth}` } },
      (res) => { let b = ""; res.on("data", (c) => (b += String(c))); res.on("end", () => resolve({ status: res.statusCode ?? 0, body: b })); });
    r.on("error", reject);
    r.end();
  });
}

/** Claude Code's shell for one Bash call, as the guard reads its argv. */
const ccShell = (command: string, n: number): string[] =>
  ["/bin/bash", "-c", `source /h/.claude/shell-snapshots/snapshot-bash-1.sh 2>/dev/null || true && eval '${command.replace(/'/g, `'"'"'`)}' && pwd -P >| /tmp/claude-rr${n}-cwd`];

function toolUseTurn(calls: ReadonlyArray<{ id: string; command: string }>): string {
  let out = sseEvent("message_start", { type: "message_start", message: { id: "msg_rr_1", role: "assistant", content: [] } });
  calls.forEach((c, index) => {
    out += sseEvent("content_block_start", { type: "content_block_start", index, content_block: { type: "tool_use", id: c.id, name: "Bash", input: {} } });
    out += sseEvent("content_block_delta", { type: "content_block_delta", index, delta: { type: "input_json_delta", partial_json: JSON.stringify({ command: c.command }) } });
    out += sseEvent("content_block_stop", { type: "content_block_stop", index });
  });
  out += sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } });
  out += sseEvent("message_stop", { type: "message_stop" });
  return out;
}

function post(port: number, session: string, messages: unknown[]): Promise<{ status: number; body: string }> {
  const body = JSON.stringify({ model: "claude-opus-4", stream: true, max_tokens: 512, tools: [{ name: "Bash", input_schema: { type: "object" } }], messages });
  return new Promise((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": session } },
      (res) => { let b = ""; res.on("data", (c) => (b += String(c))); res.on("end", () => resolve({ status: res.statusCode ?? 0, body: b })); });
    r.on("error", reject);
    r.end(body);
  });
}

/** What the model received for one tool_result in one upstream request. */
function resultIn(body: string, id: string): string {
  const msgs = (JSON.parse(body) as { messages: Array<{ content?: unknown }> }).messages;
  for (const m of msgs) {
    if (!Array.isArray(m.content)) continue;
    for (const b of m.content as Array<Record<string, unknown>>) {
      if (b.type !== "tool_result" || b.tool_use_id !== id) continue;
      return typeof b.content === "string" ? b.content : JSON.stringify(b.content);
    }
  }
  throw new Error(`no tool_result ${id} forwarded`);
}

async function waitFor<T>(what: string, f: () => Promise<T | undefined>, ms = 10_000): Promise<T> {
  const until = Date.now() + ms;
  for (;;) {
    const v = await f();
    if (v !== undefined) return v;
    if (Date.now() > until) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

interface StepWire { kind: string; outcome?: string; note?: string | null; split?: unknown; sentence?: Array<{ text: string }> }
interface TurnWire { summary: string | null; steps: StepWire[] }

test("a program refused a labeled secret file (denied, and held past its ceiling) is a blocked step on the product's agent page, Home and the inspector, never 'a secret was masked'; the turn's line names a refused send's secret beside the reads; no value reaches the model, the network or the page (secrets axes)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-refused-read-"));
  dirs.push(tmp);
  const env = join(tmp, ".env");
  writeFileSync(env, `API_KEY=${CANARY}\n`);
  const policy = join(tmp, "policy.yaml");
  // A reader list exists (sh), and neither cat nor mytool is on it.
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${env}\n    level: no-model\n    readers: [sh]\n`);
  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath: policy, policyPollMs: 0, log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const guard = new ArbiterClient(human); await guard.connect(); // what the guard writes, on the human socket (plan 13 D9)
  const real = new ArbiterClient(sock); await real.connect();
  const realHuman = new ArbiterClient(human); await realHuman.connect(); // server-main's second client
  const session = `refused-read-${process.pid}`;
  // A second key, registered as the human registers one; the AI holds only its placeholder.
  const stripeEnv = join(tmp, "stripe.env");
  writeFileSync(stripeEnv, `STRIPE_KEY=${STRIPE}\n`);
  const reg = await realHuman.registerSecret({ path: stripeEnv, sessionKey: session });
  assert.match(String(reg.symbol), /^\$MDU:nomodel_Read\[/, JSON.stringify(reg));
  const stripeKey = `${reg.symbol}.STRIPE_KEY`;
  const sendUrl = "http://api.stripe.com/v1/customers";
  const calls = [
    { id: "toolu_rr_cat", command: `cat ${env}` },
    { id: "toolu_rr_held", command: `mytool ${env}` },
    { id: "toolu_rr_curl", command: `curl -s -H "Authorization: Bearer ${stripeKey}" ${sendUrl}` },
  ];
  const output: Record<string, string> = {
    toolu_rr_cat: `cat: ${env}: Permission denied\n`,
    toolu_rr_held: `mytool: ${env}: Permission denied\n`,
  };
  const seen: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const sse = seen.length === 1 ? toolUseTurn(calls) : buildTextSse("I could not read the file.", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(real, realHuman), upstream, sessionKey: session, log: () => {} });
  const proxyPort = await proxy.listen(0);
  const netData = new ArbiterClient(sock); await netData.connect();
  const netHuman = new ArbiterClient(human); await netHuman.connect();
  const forwarded: string[] = [];
  const forwarder: HttpForwarder = async (req) => {
    forwarded.push(req.url);
    return { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("ok") };
  };
  const net = new NetProxy({
    arbiter: new NetArbiterClientAdapter(netData as unknown as RealArbiterClient, netHuman as never),
    forwarder, log: () => {}, sessionId: session, attributeHolders: () => [],
  });
  const netPort = await net.listen(0);
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: human }), log: () => {} });
  const port = await dashboard.listen(0);
  const get = async (path: string) => {
    const r = await fetch(`http://127.0.0.1:${port}/api/${path}`);
    const text = await r.text();
    return { status: r.status, text, body: (() => { try { return JSON.parse(text) as Record<string, unknown>; } catch { return {}; } })() };
  };
  try {
    // 1. The model's turn: two Bash calls on the labeled file.
    const turn = await post(proxyPort, session, [{ role: "user", content: "show me the env file" }]);
    assert.equal(turn.status, 200);
    for (const c of calls) assert.ok(turn.body.includes(c.id), `the agent received ${c.id}`);
    await new Promise((ok) => setTimeout(ok, 5));

    // 2. The agent runs them; the guard reports what it saw.
    await guard.recordExecRoot({ procKey: "rr-sh-1", ancestors: ["rr-agent-0"], argv: ccShell(calls[0]!.command, 1), session, callRoot: true });
    await guard.recordExecRoot({ procKey: "rr-cat-2", ancestors: ["rr-sh-1", "rr-agent-0"], argv: ["cat", env], session });
    const open = { path: env, isAgent: false, exeSystem: true, openerEnv: [], session };
    const denied = await guard.decideSecretOpen({ ...open, exe: "/usr/bin/cat", procKey: "rr-cat-2", parentKey: "rr-sh-1", ancestorKeys: ["rr-sh-1", "rr-agent-0"] });
    assert.equal(denied.verdict, "deny", denied.reason);
    await guard.recordExecRoot({ procKey: "rr-sh-3", ancestors: ["rr-agent-0"], argv: ccShell(calls[1]!.command, 2), session, callRoot: true });
    await guard.recordExecRoot({ procKey: "rr-mytool-4", ancestors: ["rr-sh-3", "rr-agent-0"], argv: ["mytool", env], session });
    const ask = { ...open, exe: "/usr/bin/mytool", procKey: "rr-mytool-4", parentKey: "rr-sh-3", ancestorKeys: ["rr-sh-3", "rr-agent-0"], ask: "always" };
    const held = await guard.decideSecretOpen(ask);
    assert.equal(held.verdict, "ask", held.reason);
    const expired = await guard.decideSecretOpen({ ...ask, heldMs: 60_000 });
    assert.equal(expired.verdict, "deny");
    assert.match(expired.reason, /^held for 60 s, nobody answered/);
    // curl sends the key's placeholder; the net-proxy refuses it.
    const send = await viaNetProxy(netPort, sendUrl, stripeKey);
    assert.equal(send.status, 403, send.body);
    assert.deepEqual(forwarded, [], "nothing reached api.stripe.com");
    assert.ok(!send.body.includes(STRIPE), "the refusal carries no secret");
    output["toolu_rr_curl"] = send.body;

    // 3. The results go back to the model: each failure text released, with
    //    the note's form for what Mandu did.
    const history = [
      { role: "user", content: "show me the env file" },
      { role: "assistant", content: calls.map((c) => ({ type: "tool_use", id: c.id, name: "Bash", input: { command: c.command } })) },
      { role: "user", content: calls.map((c) => ({ type: "tool_result", tool_use_id: c.id, content: output[c.id] })) },
    ];
    assert.equal((await post(proxyPort, session, history)).status, 200);
    const sent = seen[1]!;
    const catResult = resultIn(sent, "toolu_rr_cat");
    const heldResult = resultIn(sent, "toolu_rr_held");
    assert.ok(catResult.startsWith(output["toolu_rr_cat"]!), `the refused program's own text is released: ${catResult}`);
    assert.match(catResult, /\[mandu:secret\] denied: cat is not a reader of /);
    assert.ok(heldResult.startsWith(output["toolu_rr_held"]!), `the held program's own text is released: ${heldResult}`);
    assert.match(heldResult, /\[mandu:secret\] held: mytool waited for the user to allow it to read /);
    assert.doesNotMatch(catResult + heldResult, /\[mandu:secret\] masked/, "nothing was masked");
    // THE ORACLE: no request to the model carried either value.
    assert.ok(!seen.join("\n").includes(CANARY), "CONFIDENTIALITY VIOLATION: the file's value reached the model");
    assert.ok(!seen.join("\n").includes(STRIPE), "CONFIDENTIALITY VIOLATION: the key's value reached the model");

    // 4. The product's agent page, signed out: each a blocked step.
    const words = (s: StepWire) => (s.sentence ?? []).map((p) => p.text).join("");
    const page = await waitFor("the reads and the refused send on the agent page", async () => {
      const r = await get(`home/agent?session=${encodeURIComponent(session)}`);
      if (r.status !== 200) return undefined;
      const turns = (r.body["story"] ?? []) as TurnWire[];
      const steps = turns.flatMap((t) => t.steps).filter((s) => s.kind === "action");
      const sendBlocked = steps.some((s) => s.outcome === "blocked" && /api\.stripe\.com/.test(words(s)));
      return steps.length >= 3 && sendBlocked && steps.every((s) => s.outcome !== undefined) ? { r, turns, steps } : undefined;
    });
    const cat = page.steps.find((s) => /cat \S*\.env/.test(words(s)));
    const mytool = page.steps.find((s) => /mytool \S*\.env/.test(words(s)));
    assert.ok(cat && mytool, `both commands are steps: ${JSON.stringify(page.steps.map(words))}`);
    assert.deepEqual([cat!.outcome, cat!.note, cat!.split], ["blocked", "Mandu stopped a program from reading a secret file, so the AI got the command's output without it.", null]);
    assert.deepEqual([mytool!.outcome, mytool!.note, mytool!.split], ["blocked", "Mandu held a program's read of a secret file and asked for your OK. Nobody answered in time, so the AI got the command's output without it.", null]);
    const refusedSend = page.steps.find((s) => s.outcome === "blocked" && /api\.stripe\.com/.test(words(s)))!;
    assert.equal(words(refusedSend), "Mandu blocked a request to api.stripe.com that carried your secret STRIPE_KEY");
    // The turn's line: the send's secret by name beside the two reads, as
    // the steps under it tell them; never "blocked 3 actions".
    const t = page.turns.find((x) => x.steps.includes(cat!))!;
    assert.ok(t.steps.includes(mytool!) && t.steps.includes(refusedSend), "one turn holds the reads and the send");
    assert.equal(t.summary, "Mandu blocked 1 request that carried your secret STRIPE_KEY and stopped 2 reads of secret files.");
    assert.doesNotMatch(page.r.text, /masked before the AI saw it|hid \d+ secrets?/, "nothing claims a mask");

    // 5. Home's row counts what the page counts: the two reads and the send.
    const home = await get("home");
    assert.equal(home.status, 200, home.text);
    const row = ((home.body["agents"] ?? []) as Array<{ id: string; blocked: number }>).find((a) => a.id === session);
    assert.ok(row, `Home lists the session: ${home.text.slice(0, 400)}`);
    assert.equal(row!.blocked, 3);

    // Neither route carries a value, a token, or the proxy's words to the AI.
    for (const text of [page.r.text, home.text]) {
      assert.ok(!text.includes(CANARY), "CONFIDENTIALITY VIOLATION: the value reached the dashboard signed out");
      assert.ok(!text.includes(STRIPE), "CONFIDENTIALITY VIOLATION: the key's value reached the dashboard signed out");
      assert.doesNotMatch(text, /\$MDU:/);
      assert.doesNotMatch(text, /is not a reader of|waited for the user to allow/);
    }

    // 6. The inspector's routes, signed out, count the same: the header's
    //    counts (/api/events) and the sidebar's row (/api/sessions) say 3
    //    blocked, 2 asks (the held read, and the row the refused send
    //    queued), 1 masked (the registered key); each read's card line is
    //    the page's note.
    const ev = await get(`events?session=${encodeURIComponent(session)}`);
    assert.equal(ev.status, 200, ev.text);
    // (`masked` 1: the registered key, which the AI holds only as its placeholder.)
    assert.deepEqual(ev.body["counts"], { masked: 1, asks: 2, blocked: 3 });
    const vm = ev.body["viewModel"] as {
      dualLanes: { steps: Array<{ step: string; callId?: string; readRefused?: unknown }> };
      paired: { turns: Array<{ rows: Array<{ row: string; stepId: string; refusedRead?: string }> }> };
    };
    const refused = Object.fromEntries(vm.dualLanes.steps.filter((x) => x.step === "tool").map((x) => [x.callId, x.readRefused ?? null]));
    assert.deepEqual(refused, { toolu_rr_cat: { denied: 1, held: 0 }, toolu_rr_held: { denied: 0, held: 1 }, toolu_rr_curl: null });
    const lines = Object.fromEntries(vm.paired.turns.flatMap((x) => x.rows).filter((r) => r.row === "tool").map((r) => [r.stepId, r.refusedRead]));
    assert.deepEqual(lines, { "tool:toolu_rr_cat": cat!.note, "tool:toolu_rr_held": mytool!.note, "tool:toolu_rr_curl": undefined });
    const list = await get("sessions");
    const sidebar = Object.values((list.body["sections"] ?? {}) as Record<string, Array<{ sessions: Array<{ id: string; counts?: unknown }> }>>)
      .flat().flatMap((g) => g.sessions).find((x) => x.id === session);
    assert.ok(sidebar, `the sidebar lists the session: ${list.text.slice(0, 400)}`);
    assert.deepEqual(sidebar!.counts, { masked: 1, asks: 2, blocked: 3 });
    for (const text of [ev.text, list.text]) {
      assert.ok(!text.includes(CANARY), "CONFIDENTIALITY VIOLATION: the value reached the inspector signed out");
      assert.ok(!text.includes(STRIPE), "CONFIDENTIALITY VIOLATION: the key's value reached the inspector signed out");
    }
  } finally {
    await dashboard.close?.();
    await proxy.close();
    await net.close();
    guard.close(); real.close(); realHuman.close(); netData.close(); netHuman.close();
    await server.close();
  }
});
