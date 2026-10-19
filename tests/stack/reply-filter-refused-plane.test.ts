/**
 * reply-filter-refused-plane.test.ts — the S8 reply-filter miss across the
 * REAL components (docs/design/ui/reply-row-reservation.md §18).
 *
 * The miss (2026-09-30, live drill S8, `cat .env` allowed once): the human's
 * terminal showed `$MDU:nomodel_Bash[66b7]` where the value belonged. The
 * run's own arbiter (started from a worktree that had the human plane)
 * logged nine `refused on data channel: desymbolize`, and the session had no
 * `desymbolize` event. The `mandu` the run launched came from a main checkout
 * one merge behind: its reply filter still resolved over the DATA socket,
 * which the newer arbiter refuses. Nothing recorded why the token stayed.
 *
 * The stack, real except the model and the agent:
 *   - a real ArbiterServer on the `secrets` axes, with its data, admin and
 *     human sockets; the S8 symbol minted the way the proxy mints a tainted
 *     Bash result (`symbolize`, tool `Bash`, level `no-model`), so it is a
 *     `$MDU:nomodel_Bash[…]` the model only ever sees as the token;
 *   - the real anthropic-proxy over the PRODUCTION adapter, in front of a fake
 *     upstream whose reply repeats the token, as S8's model did;
 *   - the real reply-filter CLI (src/run.ts) in PTY mode, wrapping the fake
 *     agent (tests/fixtures/reply-reserve-fake-agent.mjs), which prints the
 *     reply and, on turn 2, sends it back as history.
 *
 * Two runs:
 *   1. the filter on the human socket (today's wiring): the human's screen
 *      reads the value, never the token; the model's turn-2 request carries
 *      the token byte-exact and never the value; a `desymbolize` event.
 *   2. the S8 skew: the filter handed the DATA socket as its human plane (what
 *      the old filter used): the arbiter refuses every lookup, the screen
 *      reads the token (no original anywhere, the invariant holds), and the
 *      miss is now on the record: a `relay_mode` with `resolveFailure`, the
 *      wrapper's exit note, and the arbiter's own refusal line.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import * as xtermHeadlessNs from "@xterm/headless";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { sseEvent } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the built-in default mode: the confidentiality axis keeps the digest no-model

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..");
const RF_ROOT = join(REPO, "interceptors", "reply-filter");
const RUN_TS = join(RF_ROOT, "src", "run.ts");
const TSX_BIN = join(RF_ROOT, "node_modules", ".bin", "tsx");
const AGENT = join(HERE, "..", "fixtures", "reply-reserve-fake-agent.mjs");

const SCRIPT_AVAILABLE = (() => {
  if (process.platform !== "linux") return false;
  try {
    const r = spawnSync("script", ["--version"], { stdio: ["ignore", "pipe", "ignore"] });
    return r.status === 0 && String(r.stdout).includes("util-linux");
  } catch {
    return false;
  }
})();
const NO_PTY = !SCRIPT_AVAILABLE && "util-linux script not available (the PTY relay needs it)";

/** What `mdu-digest .env` printed: derived from the raw secret, so tainted.
 *  Short enough to sit on one 80-column row. */
const DIGEST_LINE = "mdu-digest sha256=S8CANARY3f1c9a7e .env";

function textSse(text: string): string {
  const pieces = text.match(/[\s\S]{1,9}/g) ?? [];
  return sseEvent("message_start", { type: "message_start", message: { id: "msg_s8", type: "message", role: "assistant", model: "claude-opus-4", content: [], usage: { input_tokens: 1, output_tokens: 0 } } })
    + sseEvent("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } })
    + pieces.map((p) => sseEvent("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: p } })).join("")
    + sseEvent("content_block_stop", { type: "content_block_stop", index: 0 })
    + sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "end_turn" }, usage: { output_tokens: 9 } })
    + sseEvent("message_stop", { type: "message_stop" });
}

async function renderScreen(bytes: string): Promise<string[]> {
  const { Terminal } = ((xtermHeadlessNs as { default?: unknown }).default ??
    xtermHeadlessNs) as typeof import("@xterm/headless");
  const term = new Terminal({ cols: 80, rows: 24, allowProposedApi: true, scrollback: 1000 });
  await new Promise<void>((r) => term.write(bytes, r));
  const buf = term.buffer.active;
  const rows: string[] = [];
  for (let y = 0; y < buf.length; y++) rows.push((buf.getLine(y)?.translateToString(true) ?? "").trimEnd());
  term.dispose();
  return rows;
}

interface S8Run {
  token: string;
  modelText: string;
  /** Raw SSE bytes the fake agent received on turn 1 (the agent's world). */
  agentRaw: string;
  /** Every body the proxy sent upstream (what the model receives). */
  upstream: string[];
  human: string;
  stderr: string;
  code: number | null;
  events: Array<Record<string, unknown>>;
  arbiterLog: string[];
}

async function runS8(filterPlane: "human" | "data"): Promise<S8Run> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-s8-e2e-"));
  const session = `s8-e2e-${Math.random().toString(36).slice(2, 10)}`;
  const out = join(dir, "agent-out");
  mkdirSync(out);
  const sock = join(dir, "arbiter.sock");
  const humanSock = join(dir, "human", "arbiter.sock");
  const arbiterLog: string[] = [];
  const arbiter = new ArbiterServer({
    socketPath: sock,
    dbPath: join(dir, "symbols.db"),
    adminSocketPath: join(dir, "admin.sock"),
    humanSocketPath: humanSock,
    eventDir: join(dir, "events"),
    log: (l: string) => arbiterLog.push(l),
    confidentiality: true,
    integrity: false,
  });
  await arbiter.listen();
  const data = new ArbiterClient(sock);
  await data.connect();
  const human = new ArbiterClient(humanSock);
  await human.connect();
  // The S8 mint: the tainted Bash result as ONE no-model symbol (rule i).
  const token = await data.symbolize({ tool: "Bash", value: DIGEST_LINE, sessionKey: session, confidentiality: "no-model" });
  if (!/^\$MDU:nomodel_Bash\[[0-9a-f]{4,8}\]$/.test(token)) {
    data.close();
    human.close();
    await arbiter.close();
    rmSync(dir, { recursive: true, force: true });
    assert.fail(`the S8 token family: ${token}`);
  }

  const modelText = `It printed the following (Mandu masked it from me):\n\n  ${token}\n\nDONE`;
  const upstream: string[] = [];
  const fetcher: UpstreamFetcher = async ({ body }) => {
    upstream.push(body.toString("utf8"));
    const sse = textSse(modelText);
    return {
      status: 200,
      headers: { "content-type": "text/event-stream" },
      body: Readable.from((sse.match(/[\s\S]{1,23}/g) ?? []).map((p) => Buffer.from(p))),
    };
  };
  const proxyClient = new ArbiterClient(sock);
  await proxyClient.connect();
  const proxyHuman = new ArbiterClient(humanSock);
  await proxyHuman.connect();
  const proxy = new AnthropicProxy({
    arbiter: new ArbiterClientAdapter(proxyClient, proxyHuman),
    upstream: fetcher,
    sessionKey: session,
    log: () => {},
  });
  const port = await proxy.listen(0);

  const goFile = join(dir, "go");
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    MANDU_ARBITER_SOCK: sock,
    // Run 2 hands the filter the DATA socket as its human plane: the old
    // filter's channel, which the arbiter refuses for desymbolize.
    MANDU_ARBITER_HUMAN_SOCK: filterPlane === "human" ? humanSock : sock,
    MANDU_SCOPE_ID: session,
    MANDU_REPLY_FILTER_PTY: "1",
    RR_PROXY_URL: `http://127.0.0.1:${port}`,
    RR_SESSION: session,
    RR_GO_FILE: goFile,
    RR_OUT_DIR: out,
    RR_TURNS: "2",
  };
  delete env["MANDU_ARBITER_CLIENT_MODULE"];
  delete env["MANDU_LAUNCH_DISPLAY"];
  const child = spawn(TSX_BIN, [RUN_TS, "--", process.execPath, AGENT], { env, stdio: ["ignore", "pipe", "pipe"] });
  let humanBytes = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (c: string) => (humanBytes += c));
  child.stderr.on("data", (c: string) => (stderr += c));
  const closed = once(child, "close") as Promise<[number | null]>;
  try {
    // The go signal: the filter's mode record reached the arbiter (over
    // whichever socket it was handed; `emit` is data plane).
    const deadline = Date.now() + 60000;
    for (;;) {
      const evs = (await human.events(session)) as unknown as Array<Record<string, unknown>>;
      if (evs.some((e) => e["kind"] === "relay_mode")) break;
      assert.ok(Date.now() < deadline, `the reply filter never recorded its mode; stderr: ${stderr}`);
      await new Promise((r) => setTimeout(r, 25));
    }
    writeFileSync(goFile, "");
    const timer = setTimeout(() => child.kill("SIGKILL"), 90000);
    const [code] = await closed;
    clearTimeout(timer);
    await proxy.close();
    const events = (await human.events(session)) as unknown as Array<Record<string, unknown>>;
    const read = (f: string): string => (existsSync(join(out, f)) ? readFileSync(join(out, f), "utf8") : "");
    return { token, modelText, agentRaw: read("raw1.sse"), upstream, human: humanBytes, stderr, code, events, arbiterLog };
  } finally {
    child.kill("SIGKILL");
    await proxy.close().catch(() => {});
    proxyClient.close();
    proxyHuman.close();
    data.close();
    human.close();
    await arbiter.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

/** The model side: the token, never the value, in every request and in the
 *  agent's world; turn 2 carries the model's own text back byte-exact. */
function assertModelSeesOnlyTheSymbol(r: S8Run): void {
  assert.equal(r.upstream.length, 2, "two model calls");
  for (const [i, body] of r.upstream.entries()) {
    assert.ok(!body.includes("S8CANARY"), `turn-${i + 1} request: no original`);
  }
  assert.ok(!r.agentRaw.includes("S8CANARY"), "the agent's world: no original");
  assert.ok(r.agentRaw.includes(JSON.stringify(r.token).slice(1, -1)) || r.agentRaw.includes(r.token.slice(0, 9)),
    "the agent received the token");
  const msgs = (JSON.parse(r.upstream[1]!) as { messages: Array<{ role: string; content: unknown }> }).messages;
  const asst = msgs.filter((m) => m.role === "assistant").at(-1)!;
  assert.deepEqual(asst.content, [{ type: "text", text: r.modelText }], "the model gets its own text back, token byte-exact");
}

test(
  "S8 on the human plane: the human sees the program's line, never the token; the model sees only the token",
  { skip: NO_PTY },
  async () => {
    const r = await runS8("human");
    assert.equal(r.code, 0, `the wrapper exits with the agent's code; stderr: ${r.stderr}`);
    assertModelSeesOnlyTheSymbol(r);
    const rows = await renderScreen(r.human);
    assert.ok(rows.includes(`  ${DIGEST_LINE}`), `the value on the token's row:\n${rows.join("\n")}`);
    assert.doesNotMatch(r.human, /\$MDU/, "no token byte on the human's terminal stream");
    assert.ok(r.events.some((e) => e["kind"] === "desymbolize" && e["emitter"] === "reply-filter"), "the resolution is on the record");
    assert.ok(!r.events.some((e) => e["kind"] === "relay_mode" && "resolveFailure" in e), "no degraded record");
    assert.ok(!r.arbiterLog.some((l) => /refused on data channel: desymbolize/.test(l)), "nothing asked the data socket");
    assert.doesNotMatch(r.stderr, /placeholder lookup/);
  },
);

test(
  "S8 skew (the filter on the data socket): the token stays opaque, nothing leaks, and the miss is on the record",
  { skip: NO_PTY },
  async () => {
    const r = await runS8("data");
    assert.equal(r.code, 0, `the wrapper exits with the agent's code; stderr: ${r.stderr}`);
    assertModelSeesOnlyTheSymbol(r);
    // The human's terminal: the token, whole; no original anywhere.
    const rows = await renderScreen(r.human);
    assert.ok(rows.includes(`  ${r.token}`), `the token, whole, on its row:\n${rows.join("\n")}`);
    assert.ok(!r.human.includes("S8CANARY"), "no original reached the terminal through a refused plane");
    // The arbiter refused on the data channel (the line S8's log showed) ...
    assert.ok(r.arbiterLog.some((l) => /refused on data channel: desymbolize/.test(l)), r.arbiterLog.join("\n"));
    // ... and the filter now says so: a degraded record, the exit note.
    const degraded = r.events.filter((e) => e["kind"] === "relay_mode" && typeof e["resolveFailure"] === "string");
    assert.equal(degraded.length, 1, JSON.stringify(r.events.map((e) => e["kind"])));
    assert.match(String(degraded[0]!["resolveFailure"]), /^human-plane: 'desymbolize'/);
    assert.ok(!JSON.stringify(degraded).includes("S8CANARY"), "the record names no original");
    assert.ok(!r.events.some((e) => e["kind"] === "desymbolize"), "nothing resolved");
    assert.match(r.stderr, /placeholder lookups? failed \(first: human-plane: 'desymbolize'.*nothing leaked/);
  },
);
