/**
 * dashboard-command-output-name — a command's masked output is never named
 * by a piece of the command on the product's session page (dashboard.md
 * §4.25b *The summary names the secrets*; the work ledger's tour item 7),
 * over the PRODUCTION wiring: a real ArbiterServer in `secrets`, the REAL
 * anthropic-proxy and openai-proxy over HTTP on their production clients
 * (`new ArbiterClientAdapter(new ArbiterClient(sock), new
 * ArbiterClient(humanSock))`), a scripted model behind each, and the real
 * DashboardServer over `ArbiterEventSource`, read signed out.
 *
 * The beta-tester tour's command names `./.env`, so the arbiter's classify
 * verdict masks its whole output (`no-model`, path-derived;
 * confidentiality.md §7.1 "the path-derived note"). The symbol's recorded
 * origin is the COMMAND (the proxies' `originFor`: Claude Code's Bash
 * `command`, Codex's `cmd`), and the page once named the item by the text
 * after the command's last `/`: "Mandu hid your secret `customers -u
 * "$STRIPE_KEY:"` from the AI."
 *
 * Proves, end to end, for Claude Code (`Bash`) and Codex (`exec_command`):
 *   - the step says the AI got one placeholder for the whole output ("Got
 *     secret in place of the result."): the `[mandu:secret]` note the proxy
 *     appends after it is Mandu's, not part of the result;
 *   - the page's turn line and its reveal box name no piece of the
 *     command: "Mandu hid 1 secret from the AI.";
 *   - the step's real side says why, from the proxy's note (§4.25b *A
 *     command's masked output says why*): "The command names your secret
 *     file `./.env`, so Mandu hid its whole output from the AI, even whether
 *     it worked.", and Your secrets names the same item by the same reason
 *     ("Output of a `Bash` step whose command named your secret file
 *     `./.env`"), never by a piece of the command;
 *   - tour item 7, the count: the proxy's path-derived `secretTaint`
 *     (`level: "public"`) is read by nothing; the symbol's `no-model` level
 *     counts as 1 masked secret on Home, on the page's tile and in the
 *     inspector (`/api/events`);
 *   - THE ORACLE: no byte of the output and no value of the .env reaches
 *     the model or any dashboard route.
 *
 * And for a command that does not name the file but whose program read it
 * (the guard's taint record, plan 10 rule (i)): the proxy's `masked: node
 * read <file>` note, and the step's "`node` read your secret file `<file>`,
 * so Mandu hid the whole result from the AI.", its Your secrets card
 * "Output of a `Bash` step in which `node` read your secret file
 * `<file>`"; the same oracle. A last case pins the two
 * proxies' note builders to the dashboard's reader (`maskCause`), so a
 * change of the note's words fails here, not silently on the page.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { Readable } from "node:stream";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { buildTextSse, sseEvent } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter as OpenAiProxyArbiterAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { MockUpstream as OpenAiMockUpstream } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { buildSecretNote, type SecretTaintInfo } from "../../interceptors/anthropic-proxy/src/rewrite-request.js";
import { buildSecretNote as buildOpenAiSecretNote } from "../../interceptors/openai-proxy/src/rewrite-request.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { maskCause } from "../../dashboard/src/view-model/secret-note.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const dirs: string[] = [];
after(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const KEY = `sk_live_fake_CmdName${process.pid}_3456`;
const TOUR = 'set -a && . ./.env && set +a && curl -sS https://api.stripe.com/v1/customers -u "$STRIPE_KEY:"';
/** What the run printed: Stripe's answer for a fake key, quoting its tail. */
const OUTPUT = '{"error":{"message":"Invalid API Key provided: sk_live_****3456","type":"invalid_request_error"}}';
const OUTPUT_PIECES = ["Invalid API Key", "sk_live_****3456", "invalid_request_error", KEY];
/** Pieces of the command a name could be cut from (the text after its last
 *  `/`, or the whole command). */
const COMMAND_PIECES = ["customers -u", "$STRIPE_KEY:", "set -a"];

interface Part { kind: string; text: string; name?: string }
interface StepWire { kind: string; outcome?: string; sentence?: Part[]; split?: { ai: Part[]; real: Part[]; hidden?: { secrets?: Array<{ name: string | null }> } } | null }
interface TurnWire { summary: string | null; parts: Part[] | null; steps: StepWire[] }
const words = (parts: readonly Part[] | undefined): string => (parts ?? []).map((p) => p.text).join("");

async function stack() {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-cmd-name-"));
  dirs.push(tmp);
  const ws = join(tmp, "ws");
  mkdirSync(ws, { recursive: true });
  writeFileSync(join(ws, ".env"), `STRIPE_KEY=${KEY}\n`);
  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: human }), log: () => {} });
  const port = await dashboard.listen(0);
  const get = async (path: string) => {
    const r = await fetch(`http://127.0.0.1:${port}/api/${path}`);
    const text = await r.text();
    return { status: r.status, text, body: (() => { try { return JSON.parse(text) as Record<string, unknown>; } catch { return {}; } })() };
  };
  return {
    ws, sock, human, open, get,
    async close() {
      await dashboard.close?.();
      for (const c of clients) c.close();
      await server.close();
    },
  };
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

/** What the dashboard tells of the session, signed out, and what every
 *  route checked here returned (for the oracle). */
async function readDashboard(s: Awaited<ReturnType<typeof stack>>, session: string, tool: string) {
  const page = await waitFor("the masked command on the agent page", async () => {
    const r = await s.get(`home/agent?session=${encodeURIComponent(session)}`);
    if (r.status !== 200) return undefined;
    const turns = (r.body["story"] ?? []) as TurnWire[];
    const step = turns.flatMap((t) => t.steps).find((x) => x.kind === "action" && x.outcome === "secret");
    return step ? { r, turns, step } : undefined;
  });
  const turn = page.turns.find((x) => x.steps.includes(page.step))!;
  const secrets = (page.r.body["secrets"] ?? {}) as { secrets?: Array<{ what: Part[] }>; counts?: unknown };
  const home = await s.get("home");
  const ev = await s.get(`events?session=${encodeURIComponent(session)}`);
  // The symbol is the command's: its origin is the command as the model wrote it.
  const symbols = ((ev.body["viewModel"] as { symbols?: Array<{ name: string; tool: string; origin: string | null }> } | undefined)?.symbols ?? []);
  const sym = symbols.find((x) => x.tool === tool);
  assert.ok(sym, `the result's symbol is recorded: ${JSON.stringify(symbols)}`);
  assert.equal(sym!.origin, TOUR, "the origin the page once cut a name from");
  return { page, turn, secrets, home, ev };
}

function assertNamedNothing(d: Awaited<ReturnType<typeof readDashboard>>, session: string, tool: string): void {
  // The step: the whole output kept from the AI (the proxy's note after the
  // placeholder is Mandu's, not part of the result), held by a secret the
  // page cannot name.
  assert.equal(words(d.page.step.split!.ai), "Got secret in place of the result.");
  // Its real side says why, from the proxy's note: the file the command
  // names, as the model wrote it (the command above shows it too).
  assert.equal(words(d.page.step.split!.real), "The command names your secret file ./.env, so Mandu hid its whole output from the AI, even whether it worked.");
  assert.deepEqual(d.page.step.split!.real.filter((p) => p.kind === "code").map((p) => p.text), ["./.env"]);
  assert.deepEqual((d.page.step.split!.hidden?.secrets ?? []).map((x) => x.name), [null], "the reveal box names no piece of the command");
  // The turn's line counts it.
  assert.equal(d.turn.summary, "Mandu hid 1 secret from the AI.");
  // Your secrets names the same item by the same reason, from the note of
  // the step that minted it: the file as the model wrote it, as code.
  assert.deepEqual((d.secrets.secrets ?? []).map((x) => words(x.what)), [`Output of a ${tool} step whose command named your secret file ./.env`]);
  assert.deepEqual(d.secrets.secrets![0]!.what.filter((p) => p.kind === "code").map((p) => p.text), [tool, "./.env"]);
  for (const piece of COMMAND_PIECES) assert.ok(!words(d.secrets.secrets![0]!.what).includes(piece), `the card names a piece of the command: ${piece}`);
  // No name anywhere on the page is a piece of the command.
  const named = JSON.stringify(d.page.r.body["story"]).match(/"name":"[^"]*"/g) ?? [];
  for (const piece of COMMAND_PIECES) assert.ok(!named.some((n) => n.includes(piece)), `a name is a piece of the command: ${named.join(", ")}`);
  assert.doesNotMatch(d.turn.summary!, /your secret/);

  // Tour item 7: the count. One masked secret on the page's tile, Home and the inspector.
  assert.deepEqual(d.secrets.counts, { masked: 1, early: 0 });
  const row = ((d.home.body["agents"] ?? []) as Array<{ id: string; secrets?: unknown }>).find((a) => a.id === session);
  assert.ok(row, `Home lists the session: ${d.home.text.slice(0, 400)}`);
  assert.deepEqual(row!.secrets, { masked: 1, early: 0 });
  assert.deepEqual(d.ev.body["counts"], { masked: 1 });

  // THE ORACLE: no route carries a byte of the output or the key.
  for (const text of [d.page.r.text, d.home.text, d.ev.text]) {
    for (const piece of OUTPUT_PIECES) assert.ok(!text.includes(piece), `CONFIDENTIALITY VIOLATION: the dashboard served output byte(s) signed out: ${piece}`);
  }
}

function toolUseTurn(id: string, command: string): string {
  let out = sseEvent("message_start", { type: "message_start", message: { id: "msg_cn_1", role: "assistant", content: [] } });
  out += sseEvent("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id, name: "Bash", input: {} } });
  out += sseEvent("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify({ command }) } });
  out += sseEvent("content_block_stop", { type: "content_block_stop", index: 0 });
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

test("Claude Code: the tour's Bash output, masked whole because the command names ./.env, is counted as 1 secret and never named by a piece of the command on the session page; no output byte reaches the model or the dashboard (secrets axes, explicit)", async () => {
  const s = await stack();
  const session = `cmd-name-claude-${process.pid}`;
  const seen: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const sse = seen.length === 1 ? toolUseTurn("toolu_cn_tour", TOUR) : buildTextSse("I cannot see the result.", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await s.open(s.sock), await s.open(s.human)), upstream, sessionKey: session, log: () => {} });
  const proxyPort = await proxy.listen(0);
  try {
    const ask = "Use the Stripe key in .env to list my Stripe customers with curl.";
    assert.equal((await post(proxyPort, session, [{ role: "user", content: ask }])).status, 200);
    const history = [
      { role: "user", content: ask },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_cn_tour", name: "Bash", input: { command: TOUR } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_cn_tour", content: OUTPUT, is_error: true }] },
    ];
    assert.equal((await post(proxyPort, session, history)).status, 200);
    // The model got a symbol and the path-derived note, never the output.
    assert.match(seen[1]!, /\$MDU:nomodel_Bash\[[0-9a-f]{4,8}\]/);
    assert.match(seen[1]!, /\[mandu:secret\] masked: the command names a secret file \(\.\/\.env\)/);
    for (const piece of OUTPUT_PIECES) assert.ok(!seen.join("\n").includes(piece), `CONFIDENTIALITY VIOLATION: the model got output byte(s): ${piece}`);

    const d = await readDashboard(s, session, "Bash");
    assert.match(words(d.page.step.sentence), /^Ran set -a && \. \.\/\.env/, "the step still shows the command itself");
    assertNamedNothing(d, session, "Bash");
  } finally {
    await proxy.close();
    await s.close();
  }
});

test("Codex: the tour's exec_command output, masked whole the same way, is counted as 1 secret and never named by a piece of the command on the session page; no output byte reaches the model or the dashboard (secrets axes, explicit)", async () => {
  const s = await stack();
  const session = `cmd-name-codex-${process.pid}`;
  const upstream = new OpenAiMockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
  const proxy = new OpenAiProxy({ arbiter: new OpenAiProxyArbiterAdapter(await s.open(s.sock), await s.open(s.human)), upstream: (a) => upstream.fetcher(a), sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const head = "Chunk ID: 5e1f\nWall time: 0.4123 seconds\nProcess exited with code 0\nOriginal token count: 30\nOutput:\n";
  try {
    const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session },
      body: JSON.stringify({
        model: "gpt-5.5", stream: true, instructions: "You are Codex.",
        input: [
          { type: "message", role: "user", content: [{ type: "input_text", text: "Use the Stripe key in .env to list my Stripe customers with curl." }] },
          { type: "function_call", call_id: "c_tour", name: "exec_command", arguments: JSON.stringify({ cmd: TOUR, workdir: s.ws }) },
          { type: "function_call_output", call_id: "c_tour", output: `${head}${OUTPUT}\n` },
        ],
      }),
    });
    assert.equal(res.status, 200, await res.text());
    const toModel = upstream.requests.map((r) => r.bodyText).join("\n");
    assert.match(toModel, /\$MDU:nomodel_exec_command\[[0-9a-f]{4,8}\]/);
    for (const piece of OUTPUT_PIECES) assert.ok(!toModel.includes(piece), `CONFIDENTIALITY VIOLATION: the model got output byte(s): ${piece}`);

    const d = await readDashboard(s, session, "exec_command");
    assertNamedNothing(d, session, "exec_command");
  } finally {
    await proxy.close();
    await s.close();
  }
});

/** Claude Code's shell for one Bash call, as the guard reads its argv. */
const ccShell = (command: string): string[] =>
  ["/bin/bash", "-c", `source /h/.claude/shell-snapshots/snapshot-bash-1.sh 2>/dev/null || true && eval '${command.replace(/'/g, `'"'"'`)}' && pwd -P >| /tmp/claude-cn-cwd`];

test("Claude Code: a command whose program read the labelled .env (the guard's taint) says so on the session page, from the proxy's `masked: node read …` note; no output byte reaches the model or the dashboard (secrets axes, explicit)", async () => {
  const s = await stack();
  const session = `cmd-read-claude-${process.pid}`;
  const env = join(s.ws, ".env");
  const command = "node app.js";
  const printed = `connected with ${KEY}\n`;
  const seen: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const sse = seen.length === 1 ? toolUseTurn("toolu_cn_read", command) : buildTextSse("I cannot see what it printed.", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await s.open(s.sock), await s.open(s.human)), upstream, sessionKey: session, log: () => {} });
  const proxyPort = await proxy.listen(0);
  try {
    const ask = "Start the app.";
    assert.equal((await post(proxyPort, session, [{ role: "user", content: ask }])).status, 200);
    // The agent runs it; the guard reports the call's shell and that node,
    // under it, opened the labelled file (an open the guard let through).
    const guard = await s.open(s.human);
    await guard.recordExecRoot({ procKey: "cn-sh-1", ancestors: ["cn-agent-0"], argv: ccShell(command), session, callRoot: true });
    await guard.processLineage({ childKey: "cn-node-2", parentKey: "cn-sh-1", session });
    await guard.taintProcessSecret({ procKey: "cn-node-2", path: env, level: "no-model", app: "node", session });
    const history = [
      { role: "user", content: ask },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_cn_read", name: "Bash", input: { command } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_cn_read", content: printed }] },
    ];
    assert.equal((await post(proxyPort, session, history)).status, 200);
    // The model got a symbol and the taint note, never the output.
    assert.match(seen[1]!, /\$MDU:nomodel_Bash\[[0-9a-f]{4,8}\]/);
    assert.ok(seen[1]!.includes(`[mandu:secret] masked: node read ${env}; you see a symbol`), `the proxy's taint note: ${seen[1]!.slice(-800)}`);
    assert.ok(!seen.join("\n").includes(KEY), "CONFIDENTIALITY VIOLATION: the model got the program's output");

    const page = await waitFor("the masked command on the agent page", async () => {
      const r = await s.get(`home/agent?session=${encodeURIComponent(session)}`);
      if (r.status !== 200) return undefined;
      const step = ((r.body["story"] ?? []) as TurnWire[]).flatMap((t) => t.steps).find((x) => x.kind === "action" && x.outcome === "secret");
      return step ? { r, step } : undefined;
    });
    assert.equal(words(page.step.split!.ai), "Got secret in place of the result.");
    assert.equal(words(page.step.split!.real), `node read your secret file ${env}, so Mandu hid the whole result from the AI.`);
    assert.deepEqual(page.step.split!.real.filter((p) => p.kind === "code").map((p) => p.text), ["node", env]);
    // Your secrets names the item by the same reason; one masked secret.
    const secrets = (page.r.body["secrets"] ?? {}) as { secrets?: Array<{ what: Part[] }>; counts?: unknown };
    assert.deepEqual((secrets.secrets ?? []).map((x) => words(x.what)), [`Output of a Bash step in which node read your secret file ${env}`]);
    assert.deepEqual(secrets.secrets![0]!.what.filter((p) => p.kind === "code").map((p) => p.text), ["Bash", "node", env]);
    assert.deepEqual(secrets.counts, { masked: 1, early: 0 });
    // THE ORACLE: no route carries the output.
    const ev = await s.get(`events?session=${encodeURIComponent(session)}`);
    for (const text of [page.r.text, ev.text, (await s.get("home")).text]) {
      assert.ok(!text.includes(KEY), "CONFIDENTIALITY VIOLATION: the dashboard served the program's output signed out");
    }
  } finally {
    await proxy.close();
    await s.close();
  }
});

test("the two proxies' `[mandu:secret]` notes read back as the dashboard reads them: the files a command names, the programs that read one (secrets axes, explicit)", () => {
  const base: SecretTaintInfo = { level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied: [], deniedOnly: false, why: "the command names a secret path" };
  const cases: Array<[SecretTaintInfo, ReturnType<typeof maskCause>]> = [
    [{ ...base, pathDerived: { paths: ["./.env"] } }, { kind: "names", paths: ["./.env"] }],
    [{ ...base, pathDerived: { paths: ["./.env", "~/.aws/credentials", "/srv/app/key.pem"] } }, { kind: "names", paths: ["./.env", "~/.aws/credentials", "/srv/app/key.pem"] }],
    [{ ...base, pathDerived: { paths: [] } }, { kind: "names", paths: [] }],
    [{ ...base, level: "no-model", maskWhole: true, files: ["/home/dev/.pgpass"], apps: ["psql"], why: "plan 10 rule (i)" }, { kind: "read", apps: ["psql"], files: ["/home/dev/.pgpass"] }],
    [{ ...base, level: "no-model", maskWhole: true, files: ["/srv/a.env", "/srv/b.env"], apps: ["sh", "node"], why: "plan 10 rule (i)", denied: [{ path: "/srv/c.env", app: "cat", reason: "no reader rule names cat" }] }, { kind: "read", apps: ["sh", "node"], files: ["/srv/a.env", "/srv/b.env"] }],
    // Forms that give no reason: the page keeps its own words.
    [{ ...base, level: "no-model", maskWhole: true, why: "the process taint could not be read: masked (fail-closed)" }, null],
    [{ ...base, denied: [{ path: "/srv/a.env", app: "cat", reason: "no reader rule names cat" }], deniedOnly: true }, null],
    [{ ...base, level: "no-model", files: ["/home/dev/.pgpass"], apps: ["psql"], rule: "clear" }, null],
  ];
  for (const [info, want] of cases) {
    const notes = [buildSecretNote(info), buildOpenAiSecretNote(info)];
    assert.equal(notes[0], notes[1], "the two proxies write the same note");
    assert.deepEqual(maskCause(notes[0]), want, String(notes[0]));
  }
});
