/**
 * reply-filter-arbiter-restart.test.ts — the arbiter restarts under a live
 * session on a NEW human socket, and the human-facing consumers follow it
 * (docs/design/architecture/arbiter-human-plane.md §5.1;
 * docs/design/ui/reply-row-reservation.md §18.6, the residual this closes).
 *
 * The human socket's path carries the arbiter's instance id, so a restarted
 * arbiter listens somewhere else while the data socket keeps its spelling.
 * Before the fix the reply filter (and the proxies, net-proxy and fs-sync)
 * dialled the dead path for the rest of the session: raw placeholders on the
 * human's terminal, and the proxies' human-plane gates failing closed.
 *
 * The stack, real except the model and the agent:
 *   - ArbiterServer A on the data socket `arbiter.sock` and the human socket
 *     `human/a.sock`; the S8 symbol (`symbolize`, tool `Bash`, `no-model`);
 *   - the real anthropic-proxy over the PRODUCTION wiring
 *     (`new ArbiterClientAdapter(new ArbiterClient(data),
 *     ArbiterClient.humanPlane(human, data))`, server-main.ts);
 *   - the real reply-filter CLI in PTY mode around the fake agent, given
 *     MANDU_ARBITER_SOCK and MANDU_ARBITER_HUMAN_SOCK=human/a.sock.
 * Once the filter is up, A stops and B starts on the same data socket and
 * symbol DB with its human socket at `human/b.sock`. Then the agent runs
 * two turns. The human's screen reads the value (the filter re-learned the
 * human socket from the data socket's `hello`), the filter recorded the
 * recovery (`relay_mode`) and re-reported its relay to B, and the model and
 * the agent's stream hold only the token. B never sees a desymbolize on its
 * data socket.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
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

const DIGEST_LINE = "mdu-digest sha256=RESTARTCANARY9e2b .env";

function textSse(text: string): string {
  const pieces = text.match(/[\s\S]{1,9}/g) ?? [];
  return sseEvent("message_start", { type: "message_start", message: { id: "msg_rs", type: "message", role: "assistant", model: "claude-opus-4", content: [], usage: { input_tokens: 1, output_tokens: 0 } } })
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

function server(dir: string, human: string, log: string[]): ArbiterServer {
  return new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"),
    humanSocketPath: join(dir, "human", human),
    dbPath: join(dir, "symbols.db"),
    adminSocketPath: join(dir, `admin-${human}`),
    eventDir: join(dir, "events"),
    log: (l: string) => log.push(l),
    confidentiality: true,
    integrity: false,
  });
}

test(
  "an arbiter restarted on a new human socket mid-session: the filter re-learns it, the human sees the value, the model only the token",
  { skip: NO_PTY },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-restart-e2e-"));
    const session = `rs-e2e-${Math.random().toString(36).slice(2, 10)}`;
    const out = join(dir, "agent-out");
    mkdirSync(out);
    const dataSock = join(dir, "arbiter.sock");
    const humanA = join(dir, "human", "a.sock");
    const humanB = join(dir, "human", "b.sock");
    const logA: string[] = [];
    const logB: string[] = [];
    let a: ArbiterServer | null = server(dir, "a.sock", logA);
    let b: ArbiterServer | null = null;
    const clients: ArbiterClient[] = [];
    let proxy: AnthropicProxy | null = null;
    let child: ChildProcess | null = null;
    try {
      await a.listen();
      const seed = new ArbiterClient(dataSock);
      clients.push(seed);
      const token = await seed.symbolize({ tool: "Bash", value: DIGEST_LINE, sessionKey: session, confidentiality: "no-model" });
      assert.match(token, /^\$MDU:nomodel_Bash\[[0-9a-f]{4,8}\]$/);

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
      // The production wiring (server-main.ts): the data client, and the
      // human-plane client that follows a restart.
      const proxyData = new ArbiterClient(dataSock);
      const proxyHuman = ArbiterClient.humanPlane(humanA, dataSock);
      clients.push(proxyData, proxyHuman);
      proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(proxyData, proxyHuman), upstream: fetcher, sessionKey: session, log: () => {} });
      const port = await proxy.listen(0);

      const goFile = join(dir, "go");
      const env: NodeJS.ProcessEnv = {
        ...process.env,
        MANDU_ARBITER_SOCK: dataSock,
        MANDU_ARBITER_HUMAN_SOCK: humanA,
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
      const proc = spawn(TSX_BIN, [RUN_TS, "--", process.execPath, AGENT], { env, stdio: ["ignore", "pipe", "pipe"] });
      child = proc;
      let human = "";
      let stderr = "";
      proc.stdout!.setEncoding("utf8");
      proc.stderr!.setEncoding("utf8");
      proc.stdout!.on("data", (c: string) => (human += c));
      proc.stderr!.on("data", (c: string) => (stderr += c));
      const closed = once(proc, "close") as Promise<[number | null]>;

      // The filter is up on A: its relay report reached A's human plane.
      const readerA = new ArbiterClient(humanA);
      clients.push(readerA);
      const deadline = Date.now() + 60000;
      while (!(await readerA.sessionRelay(session))) {
        assert.ok(Date.now() < deadline, `the reply filter never reported its relay; stderr: ${stderr}`);
        await new Promise((r) => setTimeout(r, 25));
      }

      // The restart: A goes, B comes up on the same data socket and DB with
      // its human socket at another path.
      await a.close();
      a = null;
      await new Promise((r) => setTimeout(r, 300));
      assert.ok(!existsSync(humanA), "A's human socket is gone");
      b = server(dir, "b.sock", logB);
      await b.listen();

      writeFileSync(goFile, "");
      const timer = setTimeout(() => proc.kill("SIGKILL"), 90000);
      const [code] = await closed;
      clearTimeout(timer);
      await proxy.close();
      assert.equal(code, 0, `the wrapper exits with the agent's code; stderr: ${stderr}`);

      // ── the human: the value, never the token ──
      const rows = await renderScreen(human);
      assert.ok(rows.includes(`  ${DIGEST_LINE}`), `the value on the token's row after the restart:\n${rows.join("\n")}\nstderr: ${stderr}`);
      assert.doesNotMatch(human, /\$MDU/, "no token byte on the human's terminal stream");
      assert.doesNotMatch(stderr, /placeholder lookup/, "no lookup failed: the client re-learned the socket on its first dial");

      // ── the model and the agent's world: only the token ──
      assert.equal(upstream.length, 2, "two model calls");
      for (const body of upstream) assert.ok(!body.includes("RESTARTCANARY"), "no original in a model request");
      const raw1 = existsSync(join(out, "raw1.sse")) ? readFileSync(join(out, "raw1.sse"), "utf8") : "";
      assert.ok(!raw1.includes("RESTARTCANARY"), "no original in the agent's stream");
      const msgs = (JSON.parse(upstream[1]!) as { messages: Array<{ role: string; content: unknown }> }).messages;
      assert.deepEqual(msgs.filter((m) => m.role === "assistant").at(-1)!.content, [{ type: "text", text: modelText }], "the model gets its own text back, token byte-exact");

      // ── the record, read on B's human plane ──
      const readerB = new ArbiterClient(humanB);
      clients.push(readerB);
      const events = (await readerB.events(session)) as unknown as Array<Record<string, unknown>>;
      const modes = events.filter((e) => e["kind"] === "relay_mode");
      assert.ok(modes.length >= 2, `the start record and the recovery record: ${JSON.stringify(events.map((e) => e["kind"]))}`);
      assert.ok(!("resolveFailure" in modes.at(-1)!), "the last record says the relay resolves");
      assert.ok(events.some((e) => e["kind"] === "desymbolize" && e["emitter"] === "reply-filter"), "the resolution is on B's record");
      assert.ok(await readerB.sessionRelay(session), "the filter re-reported its relay to B");
      assert.ok(![...logA, ...logB].some((l) => /refused on data channel: desymbolize/.test(l)), "nothing asked a data socket to desymbolize");
    } finally {
      child?.kill("SIGKILL");
      await proxy?.close().catch(() => {});
      for (const c of clients) c.close();
      await a?.close().catch(() => {});
      await b?.close().catch(() => {});
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
