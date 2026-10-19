/**
 * reply-row-reservation.test.ts — reply row reservation across the REAL
 * components (docs/design/ui/reply-row-reservation.md §3, §5, §6 "Integration
 * e2e").
 *
 * The stack, all real except the model and the agent:
 *   - a real ArbiterServer on the `secrets` axes; the multi-line secret is a
 *     fake `~/.ssh/config` (indented lines, a blank line, a TAB) registered
 *     the way the launcher registers it (`registerSecret`), so its token is a
 *     `no-model` symbol the agent and the model only ever see as `$MDU:…`;
 *   - the real anthropic-proxy (in process, as the neighbouring e2e suites
 *     start it) over the PRODUCTION adapter `new ArbiterClientAdapter(new
 *     ArbiterClient(sock))`, its session key set, in front of a fake upstream
 *     that answers "Here is the file:\n\n<TOKEN>\n\nDONE";
 *   - the real reply-filter CLI (src/run.ts) in PTY mode (real util-linux
 *     `script`), MANDU_SCOPE_ID = the session key, wrapping a FAKE AGENT
 *     (tests/fixtures/reply-reserve-fake-agent.mjs) that POSTs through the
 *     proxy, reads the SSE and prints the assistant text line by line. It
 *     sends its first request only once the filter's relay report reached the
 *     arbiter (the test polls `sessionRelay`), so the proxy reads a set relay.
 *
 * The invariant (CONTRIBUTING.md): no un-symbolized secret reaches the agent's
 * world or the model. The agent receives a reserve block (the token, a count,
 * inert markers) and no original; the human's screen shows the value line by
 * line; the next request carries the token byte-exact and no marker. With
 * the kill switch, in pipe mode, or with the arbiter gone before the reply,
 * there is no expansion, and nothing leaks.
 *
 * v2 (§11): with the filter on an 80x24 outer terminal (so it reports its
 * width), a one-line key wider than the row wraps into a `T/1:N:78:78`
 * block, and a token inside a sentence gets a mid-line block whose first
 * row starts after the prefix. The screen shows the wrap, and the model
 * gets its own text back byte-exact.
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
import { reserveEnabled } from "../../interceptors/anthropic-proxy/src/reserve-block.js";
import { sseEvent } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { wrapLine } from "../../interceptors/reply-filter/src/reserve-layout.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the built-in default mode: the confidentiality axis labels the ssh config no-model

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

/** The fake `~/.ssh/config`: indented lines, a blank line, a TAB-indented line. */
const SSH_CONFIG = [
  "Host bastion",
  "  HostName 10.9.8.7",
  "  User RRCANARYUSER",
  "",
  "Host *.internal",
  "\tProxyJump bastion",
  "  IdentityFile ~/.ssh/RRCANARYKEY",
].join("\n") + "\n";
const VALUE_LINES = SSH_CONFIG.replace(/\n$/, "").split("\n");
const N = VALUE_LINES.length;
const MARKER_RE = /\$MDU\/[0-9a-f]{4,8}\/\d+|\/1:\d/;

/** What a terminal shows for a line printed at column 1 (8-column tab stops). */
function expandTabs(line: string): string {
  let out = "";
  for (const ch of line) out += ch === "\t" ? " ".repeat(8 - (out.length % 8)) : ch;
  return out;
}

/** No original — the whole value, any line of it, or a canary — in `bytes`. */
function assertNoOriginal(bytes: string, where: string): void {
  assert.ok(!bytes.includes(SSH_CONFIG) && !bytes.includes(SSH_CONFIG.replace(/\n/g, "\\n")), `${where}: the whole original leaked`);
  for (const l of VALUE_LINES) {
    const t = l.trim();
    if (t !== "") assert.ok(!bytes.includes(t), `${where}: an original line leaked: ${JSON.stringify(t)}`);
  }
  assert.ok(!bytes.includes("RRCANARY"), `${where}: a canary leaked`);
}

/** The model's reply, streamed in a few text deltas. */
function textSse(text: string): string {
  const pieces = text.match(/[\s\S]{1,9}/g) ?? [];
  return sseEvent("message_start", { type: "message_start", message: { id: "msg_rr", type: "message", role: "assistant", model: "claude-opus-4", content: [], usage: { input_tokens: 1, output_tokens: 0 } } })
    + sseEvent("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } })
    + pieces.map((p) => sseEvent("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: p } })).join("")
    + sseEvent("content_block_stop", { type: "content_block_stop", index: 0 })
    + sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "end_turn" }, usage: { output_tokens: 9 } })
    + sseEvent("message_stop", { type: "message_stop" });
}

interface StackOpts {
  /** The proxy's MANDU_REPLY_RESERVE (the kill switch), as server-main reads it. */
  proxyReserveEnv?: string;
  /** The reply filter's MANDU_REPLY_FILTER_PTY. */
  pty: boolean;
  /** Close the arbiter when the upstream receives the request (before the reply). */
  stopArbiterBeforeReply?: boolean;
  turns: 1 | 2;
  /** The registered file's content (default: the fake ssh config). */
  secret?: string;
  /** The model's reply around the token (default: the file on its own lines). */
  reply?: (token: string) => string;
  /** Run the filter on an outer terminal of this size (util-linux `script`),
   *  so it reports `cols` and the proxy may send v2 blocks (§11). Without it
   *  the filter's stdout is a pipe, it reports no width, and blocks are v1. */
  outerTty?: { cols: number; rows: number };
  /** The fake agent's rendering (fixture RR_RENDER; default line by line). */
  render?: "tail-alt" | "md-spans" | "indent2";
}

interface StackRun {
  token: string;
  /** Raw response bytes / assistant text the fake agent received, per turn. */
  raw: string[];
  text: string[];
  /** Every body the proxy sent upstream (what the model receives). */
  upstream: string[];
  /** The model's own reply text. */
  modelText: string;
  /** The reply filter's stdout: the human's terminal. */
  human: string;
  stderr: string;
  code: number | null;
  /** The arbiter's stored events for the session (null when it was stopped). */
  events: Array<Record<string, unknown>> | null;
}

async function runStack(o: StackOpts): Promise<StackRun> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-rr-e2e-"));
  const session = `rr-e2e-${Math.random().toString(36).slice(2, 10)}`;
  const home = join(dir, "home");
  mkdirSync(join(home, ".ssh"), { recursive: true });
  const cfg = join(home, ".ssh", "config");
  writeFileSync(cfg, o.secret ?? SSH_CONFIG);
  const out = join(dir, "agent-out");
  mkdirSync(out);
  const sock = join(dir, "arbiter.sock");
  const humanSock = join(dir, "human", "arbiter.sock");
  const arbiter = new ArbiterServer({
    socketPath: sock,
    dbPath: join(dir, "symbols.db"),
    adminSocketPath: join(dir, "admin.sock"),
    humanSocketPath: humanSock,
    eventDir: join(dir, "events"),
    log: () => {},
    confidentiality: true,
    integrity: false,
  });
  await arbiter.listen();
  let arbiterUp = true;
  const stopArbiter = async (): Promise<void> => {
    if (!arbiterUp) return;
    arbiterUp = false;
    await arbiter.close();
  };
  const seed = new ArbiterClient(sock);
  await seed.connect();
  // The relay state is human plane (reply-row-reservation.md §11.5).
  const relayReader = new ArbiterClient(humanSock);
  await relayReader.connect();
  // The launcher's registration call (secret-setup.ts): the arbiter reads the file.
  const reg = await seed.registerSecret({ path: cfg, home });
  assert.ok(reg.symbol, `~/.ssh/config registers: ${reg.reason}`);
  const token = reg.symbol!;
  assert.match(token, /^\$MDU:nomodel_[A-Za-z_]+\[[0-9a-f]{4,8}\]$/, "a whole-file no-model token");

  const modelText = o.reply ? o.reply(token) : `Here is the file:\n\n${token}\n\nDONE`;
  const upstream: string[] = [];
  const fetcher: UpstreamFetcher = async ({ body }) => {
    upstream.push(body.toString("utf8"));
    if (o.stopArbiterBeforeReply) await stopArbiter();
    const sse = textSse(modelText);
    return {
      status: 200,
      headers: { "content-type": "text/event-stream" },
      body: Readable.from((sse.match(/[\s\S]{1,23}/g) ?? []).map((p) => Buffer.from(p))),
    };
  };
  // The production wiring (server-main.ts): the adapter over the real client,
  // the session key, and the kill switch read the way server-main reads it.
  // Its data client, plus the human-plane client symbolShape needs
  // (arbiter-human-plane.md; the data socket refuses the op).
  const proxyClient = new ArbiterClient(sock);
  await proxyClient.connect();
  const proxyHuman = new ArbiterClient(humanSock);
  await proxyHuman.connect();
  const proxy = new AnthropicProxy({
    arbiter: new ArbiterClientAdapter(proxyClient, proxyHuman),
    upstream: fetcher,
    sessionKey: session,
    log: () => {},
    // The deadline of each eligibility call (sessionRelay, symbolShape) is
    // the test's, not the product's 150 ms (RESERVE_TIMEOUT_MS): the arbiter
    // and the proxy share this process's event loop, and on a loaded CI
    // guest a stall past 150 ms let the timer win, so the reply went out
    // with no block (the §12 and §14 cases at 80 columns, 2026-10-10/11).
    // That degradation (no expansion, nothing leaks) is the product's
    // answer to a slow arbiter and is pinned in the proxy's unit tests;
    // here the subject is the expansion itself.
    replyReserve: { enabled: reserveEnabled(o.proxyReserveEnv), timeoutMs: 10_000 },
  });
  const port = await proxy.listen(0);

  const goFile = join(dir, "go");
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    MANDU_ARBITER_SOCK: sock,
    // The filter resolves over the human plane only (arbiter-human-plane.md).
    MANDU_ARBITER_HUMAN_SOCK: humanSock,
    MANDU_SCOPE_ID: session,
    MANDU_REPLY_FILTER_PTY: o.pty ? "1" : "0",
    RR_PROXY_URL: `http://127.0.0.1:${port}`,
    RR_SESSION: session,
    RR_GO_FILE: goFile,
    RR_OUT_DIR: out,
    RR_TURNS: String(o.turns),
    ...(o.render ? { RR_RENDER: o.render } : {}),
  };
  delete env["MANDU_ARBITER_CLIENT_MODULE"];
  delete env["MANDU_REPLY_RESERVE"];
  delete env["MANDU_REPLY_RESERVE_MAX"];
  delete env["MANDU_LAUNCH_DISPLAY"]; // the banner prints (assertBlockAlone looks for it above the block)
  const argv = [TSX_BIN, RUN_TS, "--", process.execPath, AGENT];
  // Under an outer terminal the filter's stderr (its banner) stays on that
  // terminal, as for a user: the block then sits BELOW other rows, and the
  // mid-line tests assert that no repaint lands on them. (A 2026-09-30 fix
  // sent the banner to a file, blaming it for a vanished prefix; the cause
  // was the screen reconciler's TUI model running a row ahead of the
  // terminal while the stream filter held a reserve head, and it is fixed in
  // the reply filter: screen-reconcile.ts feedTui, reply-row-reservation.md §3.7.)
  const child = o.outerTty
    ? spawn("script", ["-qfec", `stty cols ${o.outerTty.cols} rows ${o.outerTty.rows} -echo; exec ${argv.map(shq).join(" ")}`, "/dev/null"],
      { env, stdio: ["ignore", "pipe", "pipe"] })
    : spawn(argv[0]!, argv.slice(1), { env, stdio: ["ignore", "pipe", "pipe"] });
  let human = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (c: string) => (human += c));
  child.stderr.on("data", (c: string) => (stderr += c));
  const closed = once(child, "close") as Promise<[number | null]>;
  let events: Array<Record<string, unknown>> | null = null;
  try {
    // The go signal: the filter's relay report reached the arbiter.
    const deadline = Date.now() + 15000;
    for (;;) {
      const r = await relayReader.sessionRelay(session); // human plane (§11.5)
      if (r) {
        assert.equal(r.mode, o.pty ? "pty" : "pipe", `the filter reported its mode: ${JSON.stringify(r)}`);
        assert.equal(r.reserve, o.pty, "reserve only for the PTY relay");
        break;
      }
      assert.ok(Date.now() < deadline, `the reply filter never reported its relay; stderr: ${stderr}`);
      await new Promise((r) => setTimeout(r, 25));
    }
    writeFileSync(goFile, "");
    const timer = setTimeout(() => child.kill("SIGKILL"), 30000);
    const [code] = await closed;
    clearTimeout(timer);
    await proxy.close(); // flushes the proxy's best-effort emits
    if (arbiterUp) {
      // The event log carries originals, so it is read over the human plane.
      const reader = new ArbiterClient(humanSock);
      await reader.connect();
      try { events = (await reader.events(session)) as unknown as Array<Record<string, unknown>>; } finally { reader.close(); }
    }
    const read = (f: string): string => (existsSync(join(out, f)) ? readFileSync(join(out, f), "utf8") : "");
    return {
      token,
      raw: [read("raw1.sse"), read("raw2.sse")],
      text: [read("text1.txt"), read("text2.txt")],
      upstream,
      modelText,
      human,
      stderr,
      code,
      events,
    };
  } finally {
    child.kill("SIGKILL");
    await proxy.close().catch(() => {});
    proxyClient.close();
    proxyHuman.close();
    seed.close();
    relayReader.close();
    await stopArbiter();
    rmSync(dir, { recursive: true, force: true });
  }
}

/** The human's terminal at 80x24 (scrollback kept, so the whole session reads back). */
async function renderScreen(bytes: string): Promise<string[]> {
  const { Terminal } = ((xtermHeadlessNs as { default?: unknown }).default ??
    xtermHeadlessNs) as typeof import("@xterm/headless");
  const term = new Terminal({ cols: 80, rows: 24, allowProposedApi: true, scrollback: 1000 });
  await new Promise<void>((r) => term.write(bytes, r));
  const buf = term.buffer.active;
  const rows: string[] = [];
  for (let y = 0; y < buf.length; y++) rows.push((buf.getLine(y)?.translateToString(true) ?? "").trimEnd());
  term.dispose();
  while (rows.length > 0 && rows[rows.length - 1] === "") rows.pop();
  return rows;
}

/** Single-quote for sh. */
function shq(s: string): string {
  return `'${s.replace(/'/g, "'\\''")}'`;
}

function hashOf(token: string): string {
  return /\[([0-9a-f]{4,8})\]/.exec(token)![1]!;
}

test(
  "PTY relay: the agent gets the reserve block and no original; the human sees the file line by line; the next request carries the token byte-exact",
  { skip: NO_PTY },
  async () => {
    const r = await runStack({ pty: true, turns: 2 });
    assert.equal(r.code, 0, `the wrapper exits with the agent's code; stderr: ${r.stderr}`);
    const T = r.token;
    const block = [`${T}/1:${N}`, ...Array.from({ length: N - 1 }, (_, i) => `$MDU/${hashOf(T)}/${i + 2}`)].join("\n");

    // ── the agent's world: the block, never an original ──
    assert.equal(r.text[0], r.modelText.replace(T, block), "the agent received the model's text with the block in place of T");
    assert.ok(r.raw[0]!.includes(JSON.stringify(block).slice(1, -1)), "the block went out whole in one text_delta");
    assertNoOriginal(r.raw[0]!, "agent-bound stream (turn 1)");
    assertNoOriginal(r.text[0]!, "agent text (turn 1)");
    assertNoOriginal(r.raw[1]!, "agent-bound stream (turn 2)");

    // ── the model: turn 1 holds no original; turn 2 holds T byte-exact, no marker ──
    assert.equal(r.upstream.length, 2, "two model calls");
    assertNoOriginal(r.upstream[0]!, "turn-1 request");
    const up2 = r.upstream[1]!;
    assertNoOriginal(up2, "turn-2 request");
    assert.doesNotMatch(up2, MARKER_RE, "no `$MDU/` row and no `/1:N` reaches the model");
    assert.ok(!up2.includes("$MDU/"), "no continuation marker");
    assert.ok(!up2.includes(`/1:${N}`), "no head suffix");
    const msgs = (JSON.parse(up2) as { messages: Array<{ role: string; content: unknown }> }).messages;
    const asst = msgs.filter((m) => m.role === "assistant").at(-1)!;
    assert.deepEqual(asst.content, [{ type: "text", text: r.modelText }], "the model gets its own text back, token byte-exact");

    // ── the human's terminal: each value line on its own row, in order ──
    const rows = await renderScreen(r.human);
    const at = rows.indexOf("Here is the file:");
    assert.ok(at >= 0, `the reply reached the screen:\n${rows.join("\n")}`);
    assert.deepEqual(
      rows.slice(at, at + N + 5),
      ["Here is the file:", "", ...VALUE_LINES.map(expandTabs), "", "DONE", "TURN2-200"],
      `screen was:\n${rows.join("\n")}`,
    );
    assert.ok(!rows.join("\n").includes("$MDU"), `no token or marker text remains on the screen:\n${rows.join("\n")}`);
    assert.ok(!r.human.includes("\t"), "the value's TAB never reaches the wire raw (expanded to its tab stop)");

    // ── observability: the proxy's reserve_expand event, token-only ──
    const ex = (r.events ?? []).filter((e) => e["kind"] === "reserve_expand");
    assert.ok(ex.length >= 1, `a reserve_expand event is stored for the session: ${JSON.stringify((r.events ?? []).map((e) => e["kind"]))}`);
    assert.equal(ex[0]!["rows"], N);
    assert.equal(ex[0]!["hash"], hashOf(T));
    assertNoOriginal(JSON.stringify(ex), "reserve_expand events");
    assert.equal((r.events ?? []).filter((e) => e["kind"] === "reserve_residual").length, 0, "an exact collapse is not a residual");
  },
);

test(
  "the proxy's kill switch (MANDU_REPLY_RESERVE=0): the agent receives the plain token, no block",
  { skip: NO_PTY },
  async () => {
    const r = await runStack({ pty: true, turns: 1, proxyReserveEnv: "0" });
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.text[0], r.modelText, "the model's text, byte-identical");
    assert.doesNotMatch(r.raw[0]!, MARKER_RE);
    assertNoOriginal(r.raw[0]!, "agent-bound stream");
    assertNoOriginal(r.upstream[0]!, "model-bound request");
    // Today's rendering: the value on the token's one row, never the token.
    const rows = await renderScreen(r.human);
    assert.ok(!rows.join("\n").includes("$MDU"), `the human sees the value, not the token:\n${rows.join("\n")}`);
    assert.ok(rows.some((l) => l.startsWith("Host bastion ⏎   HostName 10.9.8.7 ⏎")), `one frame-safe row, lines joined by ⏎:\n${rows.join("\n")}`);
    assert.equal((r.events ?? []).filter((e) => e["kind"] === "reserve_expand").length, 0);
  },
);

test("the reply filter in pipe mode: the relay reports pipe, the agent receives the plain token, the human gets the full file", async () => {
  const r = await runStack({ pty: false, turns: 1 });
  assert.equal(r.code, 0, r.stderr);
  assert.equal(r.text[0], r.modelText, "no expansion: the relay is pipe");
  assert.doesNotMatch(r.raw[0]!, MARKER_RE);
  assertNoOriginal(r.raw[0]!, "agent-bound stream");
  assertNoOriginal(r.upstream[0]!, "model-bound request");
  // Pipe mode prints the value with its real line breaks (the token's full value).
  assert.ok(r.human.includes(`Here is the file:\n\n${SSH_CONFIG}`), `the human's pipe shows the whole file: ${JSON.stringify(r.human)}`);
  assert.ok(!r.human.includes("$MDU"));
  assert.equal((r.events ?? []).filter((e) => e["kind"] === "reserve_expand").length, 0);
});

test(
  "the arbiter stopped before the reply: no expansion; the human sees the opaque token; nothing leaks",
  { skip: NO_PTY },
  async () => {
    const r = await runStack({ pty: true, turns: 1, stopArbiterBeforeReply: true });
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.upstream.length, 1, "the request reached the model while the arbiter was up");
    assert.equal(r.text[0], r.modelText, "no expansion without the arbiter");
    assert.doesNotMatch(r.raw[0]!, MARKER_RE);
    assertNoOriginal(r.raw[0]!, "agent-bound stream");
    assertNoOriginal(r.human, "the human's terminal");
    const rows = await renderScreen(r.human);
    assert.ok(rows.includes(r.token), `the token stays opaque on its own row:\n${rows.join("\n")}`);
    assert.ok(rows.includes("DONE"));
  },
);

// ── v2 (reply-row-reservation.md §11): wrapped lines and a token in a sentence ──

/** A one-line key of words, 161 columns: it wraps at 80. */
const WIDE_KEY = "RRWIDECANARY " + Array.from({ length: 21 }, (_, i) => `seg${String(i).padStart(3, "0")}`).join(" ")
  + " " + "tail".repeat(10);
/** A one-line value of words, 94 columns: after "The value is " it wraps at 80. */
const INLINE_VALUE = "RRINLINECANARY " + Array.from({ length: 12 }, (_, i) => `wd${String(i).padStart(4, "0")}`).join(" ")
  + " " + "end".repeat(3);

/** The screen of an outerTty run. The outer terminal carries the filter's
 *  stderr note too, and its line discipline echoes one NUL as a literal `^@`
 *  ahead of the agent's first row; neither is the filter's output. */
function ttyRows(rows: string[]): string[] {
  return rows.map((row) => row.replace(/^\^@/, ""));
}

/** The rows around a mid-line block of INLINE_VALUE (reply-row-reservation.md
 *  §3.7): the filter's banner sits above it (the relay does not start at the
 *  terminal's top), no row above the block holds any of the value, and its
 *  first row is on the screen once — a repaint aimed at the head row never
 *  lands on another row (the 2026-09-30 flake: one row up, or clamped at the
 *  top and every later row shifted down). */
function assertBlockAlone(rows: string[], at: number): void {
  const screen = `screen:\n${rows.join("\n")}`;
  assert.ok(rows.slice(0, at).join("\n").includes("mandu-reply-filter:"), `the banner is above the block: ${screen}`);
  assert.ok(!rows.slice(0, at).some((row) => /RRINLINECANARY|wd00\d\d/.test(row)), `nothing of the value above its row: ${screen}`);
  assert.equal(rows.filter((row) => row.includes("RRINLINECANARY")).length, 1, `the value's first row, once: ${screen}`);
}

function assertNoValue(bytes: string, value: string, where: string): void {
  for (const w of value.split(" ")) {
    if (w.length >= 6) assert.ok(!bytes.includes(w), `${where}: a word of the original leaked: ${w}`);
  }
}

test(
  "v2, PTY relay at 80 columns: a one-line key wider than the row wraps into reserved rows; the model gets its token back",
  { skip: NO_PTY },
  async () => {
    const r = await runStack({ pty: true, turns: 2, secret: WIDE_KEY + "\n", outerTty: { cols: 80, rows: 24 },
      reply: (t) => `Here is the key:\n\n${t}\n\nDONE` });
    assert.equal(r.code, 0, `stderr: ${r.stderr}`);
    const T = r.token;
    const segs = wrapLine(WIDE_KEY, 78);
    assert.ok(segs.length >= 2, "precondition: the key wraps at W = 78");
    const block = [`${T}/1:${segs.length}:78:78`, ...segs.slice(1).map((_, i) => `$MDU/${hashOf(T)}/${i + 2}`)].join("\n");
    assert.equal(r.text[0], r.modelText.replace(T, block), "the agent received a v2 block (W = cols − 2)");
    assertNoValue(r.raw[0]! + r.text[0]!, WIDE_KEY, "agent world");
    const up2 = r.upstream[1]!;
    assertNoValue(r.upstream.join(""), WIDE_KEY, "model-bound requests");
    assert.doesNotMatch(up2, MARKER_RE, "no row and no head suffix reach the model");
    const msgs = (JSON.parse(up2) as { messages: Array<{ role: string; content: unknown }> }).messages;
    assert.deepEqual(msgs.filter((m) => m.role === "assistant").at(-1)!.content, [{ type: "text", text: r.modelText }]);
    const rows = ttyRows(await renderScreen(r.human));
    const at = rows.indexOf("Here is the key:");
    assert.ok(at >= 0, `screen:\n${rows.join("\n")}`);
    assert.deepEqual(rows.slice(at + 2, at + 2 + segs.length), segs.map((x) => x.trimEnd()), `screen:\n${rows.join("\n")}`);
    assert.equal(rows[at + 2 + segs.length + 1], "DONE");
    const ex = (r.events ?? []).filter((e) => e["kind"] === "reserve_expand");
    assert.ok(ex.length >= 1 && ex[0]!["rows"] === segs.length, JSON.stringify(ex));
  },
);

test(
  "v2, PTY relay at 80 columns: a token inside a sentence — the value starts after the prefix, the suffix follows its last row",
  { skip: NO_PTY },
  async () => {
    const prefix = "The value is ";
    const suffix = " and that is all.";
    const r = await runStack({ pty: true, turns: 2, secret: INLINE_VALUE, outerTty: { cols: 80, rows: 24 },
      reply: (t) => `${prefix}${t}${suffix}\n\nDONE` });
    assert.equal(r.code, 0, `stderr: ${r.stderr}`);
    const T = r.token;
    const F = 78 - prefix.length;
    const segs = wrapLine(INLINE_VALUE, 78, F);
    assert.equal(segs.length, 2, "precondition: the value takes two rows after the prefix");
    assert.equal(r.text[0], r.modelText.replace(T, `${T}/1:2:78:${F}\n$MDU/${hashOf(T)}/2`), "a mid-line v2 block, F = W − prefix");
    assertNoValue(r.raw[0]! + r.text[0]!, INLINE_VALUE, "agent world");
    assertNoValue(r.upstream.join(""), INLINE_VALUE, "model-bound requests");
    const up2 = r.upstream[1]!;
    assert.doesNotMatch(up2, MARKER_RE);
    const msgs = (JSON.parse(up2) as { messages: Array<{ role: string; content: unknown }> }).messages;
    assert.deepEqual(msgs.filter((m) => m.role === "assistant").at(-1)!.content, [{ type: "text", text: r.modelText }],
      "the sentence comes back byte-exact");
    const rows = ttyRows(await renderScreen(r.human));
    const at = rows.findIndex((row) => row.startsWith(prefix));
    assert.ok(at >= 0, `screen:\n${rows.join("\n")}`);
    assert.equal(rows[at], (prefix + segs[0]!).trimEnd());
    assert.equal(rows[at + 1], segs[1]!.trimEnd() + suffix);
    assertBlockAlone(rows, at);
  },
);

test(
  "§14, PTY relay at 80 columns: text after a mid-line value that would clip breaks where vanilla wraps; the model gets its sentence back",
  { skip: NO_PTY },
  async () => {
    const prefix = "The value is ";
    const suffix = " and that is all, and the rest of it goes on.";
    const r = await runStack({ pty: true, turns: 2, secret: INLINE_VALUE, outerTty: { cols: 80, rows: 24 },
      reply: (t) => `${prefix}${t}${suffix}\n\nDONE` });
    assert.equal(r.code, 0, `stderr: ${r.stderr}`);
    const T = r.token;
    const F = 78 - prefix.length;
    const segs = wrapLine(INLINE_VALUE, 78, F);
    const last = segs[segs.length - 1]!.length;
    assert.ok(last + suffix.length > 78, "precondition: without a break the text would clip");
    // Where the break falls: after the words that still fit after the value's last row.
    let k = 0;
    for (let cur = last, at = 0; ;) {
      const next = suffix.indexOf(" ", at + 1);
      const word = suffix.slice(at + 1, next < 0 ? suffix.length : next);
      if (cur + 1 + word.length > 78) { k = at + 1; break; }
      cur += 1 + word.length;
      at = next;
    }
    const hash = hashOf(T);
    const rows = segs.slice(1).map((_, i) => `\n$MDU/${hash}/${i + 2}`).join("");
    assert.equal(r.text[0], `${prefix}${T}/1:${segs.length}:78:${F}:${k}${rows}${suffix.slice(0, k)}\n${suffix.slice(k)}\n\nDONE`,
      "a v2 head with the break field, and the break in the text");
    assertNoValue(r.raw[0]! + r.text[0]!, INLINE_VALUE, "agent world");
    assertNoValue(r.upstream.join(""), INLINE_VALUE, "model-bound requests");
    const up2 = r.upstream[1]!;
    assert.doesNotMatch(up2, MARKER_RE);
    const msgs = (JSON.parse(up2) as { messages: Array<{ role: string; content: unknown }> }).messages;
    assert.deepEqual(msgs.filter((m) => m.role === "assistant").at(-1)!.content, [{ type: "text", text: r.modelText }],
      "the sentence comes back byte-exact: the break went with the block");
    const screen = ttyRows(await renderScreen(r.human));
    const at = screen.findIndex((row) => row.startsWith(prefix));
    assert.ok(at >= 0, `screen:\n${screen.join("\n")}`);
    assert.equal(screen[at], (prefix + segs[0]!).trimEnd());
    assert.equal(screen[at + segs.length - 1], (segs[segs.length - 1]! + suffix.slice(0, k)).trimEnd(), "no clip: the row ends inside the width");
    assert.equal(screen[at + segs.length], suffix.slice(k), "the rest of the sentence on the next row");
    assertBlockAlone(screen, at);
  },
);

test(
  "§14, PTY relay at 80 columns: a value that fits its row but pushes the sentence past the edge gets a head-only block and the break",
  { skip: NO_PTY },
  async () => {
    const value = "RRONEROW " + "q".repeat(40); // 49 columns: fits after the prefix
    const prefix = "The value is ";
    const suffix = " and that is all, so this sentence has to wrap.";
    const r = await runStack({ pty: true, turns: 2, secret: value, outerTty: { cols: 80, rows: 24 },
      reply: (t) => `${prefix}${t}${suffix}\n\nDONE` });
    assert.equal(r.code, 0, `stderr: ${r.stderr}`);
    const T = r.token;
    const m = new RegExp(`/1:1:78:${78 - prefix.length}:(\\d+)`).exec(r.text[0]!);
    assert.ok(m, `a head-only block went to the agent: ${r.text[0]}`);
    const k = Number(m![1]);
    assert.equal(r.text[0], `${prefix}${T}/1:1:78:${78 - prefix.length}:${k}${suffix.slice(0, k)}\n${suffix.slice(k)}\n\nDONE`);
    assertNoValue(r.raw[0]! + r.text[0]!, value, "agent world");
    const msgs = (JSON.parse(r.upstream[1]!) as { messages: Array<{ role: string; content: unknown }> }).messages;
    assert.deepEqual(msgs.filter((x) => x.role === "assistant").at(-1)!.content, [{ type: "text", text: r.modelText }]);
    const screen = ttyRows(await renderScreen(r.human));
    const at = screen.findIndex((row) => row.startsWith(prefix));
    assert.equal(screen[at], (prefix + value + suffix.slice(0, k)).trimEnd());
    assert.ok(screen[at]!.length <= 78, "no clip");
    assert.equal(screen[at + 1], suffix.slice(k));
  },
);

test(
  "§14, PTY relay at 80 columns: a token in a table's first cell is not expanded (the table stays a table)",
  { skip: NO_PTY },
  async () => {
    const r = await runStack({ pty: true, turns: 1, secret: INLINE_VALUE, outerTty: { cols: 80, rows: 24 },
      reply: (t) => `${t} | the value |\n--- | --- |\n\nDONE` });
    assert.equal(r.code, 0, `stderr: ${r.stderr}`);
    assert.equal(r.text[0], r.modelText, "no block: the agent gets the model's text");
    assertNoValue(r.raw[0]! + r.text[0]!, INLINE_VALUE, "agent world");
  },
);

test(
  "§12, PTY relay at 80 columns: a token that is a whole code span — each row its own span; the model gets its backticks back",
  { skip: NO_PTY },
  async () => {
    const prefix = "The value is ";
    const suffix = ", and that is all.";
    const r = await runStack({ pty: true, turns: 2, secret: INLINE_VALUE, outerTty: { cols: 80, rows: 24 }, render: "md-spans",
      reply: (t) => `${prefix}\`${t}\`${suffix}\n\nDONE` });
    assert.equal(r.code, 0, `stderr: ${r.stderr}`);
    const T = r.token;
    const F = 78 - prefix.length; // the opening backtick never renders: no glue
    const segs = wrapLine(INLINE_VALUE, 78, F);
    assert.equal(segs.length, 2, "precondition: the value takes two rows after the prefix");
    assert.equal(r.text[0], r.modelText.replace(T, `${T}/1:2:78:${F}\`\n\`$MDU/${hashOf(T)}/2`), "the span form, F = W − prefix");
    assertNoValue(r.raw[0]! + r.text[0]!, INLINE_VALUE, "agent world");
    assertNoValue(r.upstream.join(""), INLINE_VALUE, "model-bound requests");
    const up2 = r.upstream[1]!;
    assert.doesNotMatch(up2, MARKER_RE);
    const msgs = (JSON.parse(up2) as { messages: Array<{ role: string; content: unknown }> }).messages;
    assert.deepEqual(msgs.filter((m) => m.role === "assistant").at(-1)!.content, [{ type: "text", text: r.modelText }],
      "the sentence comes back byte-exact, backticks and all");
    const rows = ttyRows(await renderScreen(r.human));
    const at = rows.findIndex((row) => row.startsWith(prefix));
    assert.ok(at >= 0, `screen:\n${rows.join("\n")}`);
    assert.equal(rows[at], (prefix + segs[0]!).trimEnd());
    assert.equal(rows[at + 1], segs[1]!.trimEnd() + suffix);
    assertBlockAlone(rows, at);
  },
);

test(
  "§3.8, a headless block on the alternate screen: the proxy's record lets the filter paint rows whose head never reached the screen",
  { skip: NO_PTY },
  async () => {
    // A fullscreen renderer showing only the tail of a block taller than its
    // viewport: the fake agent paints rows 3..N and never the head. Before
    // §3.8 every such row painted blank.
    const r = await runStack({ pty: true, turns: 1, outerTty: { cols: 80, rows: 24 }, render: "tail-alt" });
    assert.equal(r.code, 0, `stderr: ${r.stderr}`);
    const T = r.token;
    assert.ok(r.text[0]!.includes(`${T}/1:${N}:78:78`), `a v2 block went to the agent: ${r.text[0]}`);
    assertNoOriginal(r.raw[0]!, "agent-bound stream");
    assertNoOriginal(r.text[0]!, "agent text");
    assertNoOriginal(r.upstream.join(""), "model-bound requests");
    const rows = ttyRows(await renderScreen(r.human));
    // Painted from column 2, where Claude Code's text starts: the TAB line
    // reaches the terminal's stop 8, as vanilla's does (§11.2).
    const atCol2 = (l: string): string => expandTabs(`  ${l}`).trimEnd();
    assert.deepEqual(rows.slice(0, N - 2), VALUE_LINES.slice(2).map(atCol2), `alternate screen:\n${rows.join("\n")}`);
    assert.deepEqual(rows.slice(N - 2, N + 1), ["", "  DONE", "AGENT-END"], "the reply's tail follows the block");
    assert.ok(!rows.join("\n").includes("$MDU"), `no marker on the screen:\n${rows.join("\n")}`);
    assert.ok(!rows.join("\n").includes(T), "the head never reached the screen");
  },
);

/** A tab-separated file (differential-interactive.md §19's capture): the
 *  canary is a cell, so no line of it may reach the agent or the model. */
const TSV = "name\tport\towner\nweb\t8080\tRRTABCANARY\ndb\t5432\tbob\n";

test(
  "§11.2, PTY relay at 80 columns: a TAB in a reserved row reaches the terminal's own stop, as vanilla's at the reply's column 2",
  { skip: NO_PTY },
  async () => {
    // The fake agent lays its reply out two columns in, as Claude Code does.
    // Vanilla leaves each TAB to the terminal: `port` lands at column 8 and
    // the third cell at 16. Before 2026-10-18 the rows counted the stops
    // from the value's own column 0, two columns right of that.
    const r = await runStack({ pty: true, turns: 2, secret: TSV, outerTty: { cols: 80, rows: 24 }, render: "indent2",
      reply: (t) => `Here is the table:\n\n${t}\n\nDONE` });
    assert.equal(r.code, 0, `stderr: ${r.stderr}`);
    const T = r.token;
    assert.ok(r.text[0]!.includes(`${T}/1:3:78:78`), `a v2 block went to the agent: ${r.text[0]}`);
    for (const [where, bytes] of [["agent world", r.raw[0]! + r.text[0]!], ["model-bound requests", r.upstream.join("")]] as const) {
      assert.ok(!bytes.includes("RRTABCANARY") && !bytes.includes("8080"), `${where}: a cell of the original leaked`);
    }
    assert.doesNotMatch(r.upstream[1]!, MARKER_RE, "no row and no head suffix reach the model");
    const rows = ttyRows(await renderScreen(r.human));
    const at = rows.indexOf("  Here is the table:");
    assert.ok(at >= 0, `screen:\n${rows.join("\n")}`);
    // The reference is the terminal itself: vanilla's bytes, each line
    // printed two columns in with its raw TAB, through the same emulator.
    const vanilla = (await renderScreen(TSV.replace(/\n$/, "").split("\n").map((l) => `  ${l}`).join("\r\n"))).map((x) => x.trimEnd());
    assert.deepEqual(vanilla, ["  name  port    owner", "  web   8080    RRTABCANARY", "  db    5432    bob"], "precondition: the terminal's stops");
    assert.deepEqual(rows.slice(at + 2, at + 5), vanilla, `screen:\n${rows.join("\n")}`);
    assert.equal(rows[at + 2]!.indexOf("port"), 8);
    assert.equal(rows[at + 2]!.indexOf("owner"), 16);
    assert.equal(rows[at + 6], "  DONE");
  },
);
