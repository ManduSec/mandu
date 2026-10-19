/**
 * claude-bashmode-output — Claude Code's bash-mode output (`!cmd`) is
 * PROGRAM OUTPUT, over the REAL arbiter, its REAL IPC and the PRODUCTION
 * proxy wiring, in the `secrets` mode (supported-agents.md §2.4;
 * interceptors/anthropic-proxy/src/opencode-background.ts, kind `bashmode`).
 * The blocks are the shape Claude Code 2.1.289 sends
 * (tests/fixtures/claude-bashmode-2026-10-05.json, captured against a
 * scripted upstream): `<bash-input>{command}</bash-input>\n`, then
 * `<bash-stdout>{escaped}</bash-stdout><bash-stderr>{escaped}</bash-stderr>`.
 *
 *   labelled     `!cat` of a file the policy labels no-model, whose values
 *                the arbiter never registered (no read of it ever happened),
 *                reaches the model only as a symbol: before, the prompt
 *                filter read the block as harness text with the
 *                registered-value filter only, and it went out raw;
 *   unlabelled   `!cat` of an ordinary file goes out byte for byte;
 *   history      the masked block re-sent in a later request forwards the
 *                same (the prompt cache stays warm);
 *   the capture  the captured 2.1.289 request replayed, its file labelled:
 *                masked;
 *   FAIL-CLOSED  the arbiter unreachable: the output never reaches the
 *                model raw.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the built-in default: confidentiality ON, integrity OFF

type Block = { type: string; text: string; cache_control?: unknown };
type Message = { role: string; content: string | Block[] };
const here = dirname(fileURLToPath(import.meta.url));
const capture = JSON.parse(readFileSync(join(here, "..", "fixtures", "claude-bashmode-2026-10-05.json"), "utf8")) as { requests: Message[][] };

const CANARY = "BASHMODE-E2E-CANARY-3391";

interface Stack {
  tmp: string;
  vault: string;
  real: ArbiterClient;
  server: ArbiterServer;
  send: (messages: Message[]) => Promise<{ status: number; forwarded: string }>;
}

async function withStack(name: string, fn: (s: Stack) => Promise<void>, extraLabels: string[] = []): Promise<void> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-bashmode-"));
  const vault = join(tmp, "home", "vault");
  mkdirSync(vault, { recursive: true });
  const server = new ArbiterServer({
    socketPath: join(tmp, "arbiter.sock"), adminSocketPath: join(tmp, "admin.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [vault, ...extraLabels].map((path) => ({ path, level: "no-model" })) } as never,
  });
  await server.listen();
  const real = new ArbiterClient(join(tmp, "arbiter.sock"));
  await real.connect();
  const sessionKey = `bashmode-${name}-${process.pid}`; // unbound: the Claude Code spec, the arbiter's default
  const proxies: AnthropicProxy[] = [];
  try {
    await fn({
      tmp, vault, real, server,
      send: async (messages) => {
        const up = new MockUpstream({ sse: buildTextSse("ok") });
        const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(real), upstream: up.fetcher, sessionKey, log: () => {} });
        proxies.push(proxy);
        const port = await proxy.listen(0);
        const body = JSON.stringify({ model: "claude-sonnet-4-5", stream: true, tools: [{ name: "Bash", input_schema: { type: "object" } }], messages });
        const status = await new Promise<number>((resolve, reject) => {
          const r = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": sessionKey } }, (res) => {
            res.resume();
            res.on("end", () => resolve(res.statusCode ?? 0));
          });
          r.on("error", reject);
          r.end(body);
        });
        return { status, forwarded: up.requests.map((q) => q.bodyText).join("\n") };
      },
    });
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    real.close();
    await server.close().catch(() => {});
    rmSync(tmp, { recursive: true, force: true });
  }
}

const esc = (s: string): string => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
/** One `!cat` as Claude Code 2.1.289 sends it, after a reminder block, maybe followed by a typed prompt. */
function bashTurn(file: string, content: string, prompt?: string): Message[] {
  return [
    { role: "user", content: [
      { type: "text", text: "<system-reminder>\nToday's date is 2026-10-05.\n</system-reminder>" },
      { type: "text", text: `<bash-input>cat ${file}</bash-input>\n` },
      { type: "text", text: `<bash-stdout>${esc(content.replace(/\n$/, ""))}</bash-stdout><bash-stderr></bash-stderr>`, cache_control: { type: "ephemeral" } },
    ] },
    ...(prompt ? [{ role: "assistant", content: [{ type: "text", text: "ok" }] }, { role: "user", content: [{ type: "text", text: prompt }] }] : []),
  ];
}
const outBlock = (forwarded: string): string => ((JSON.parse(forwarded) as { messages: Message[] }).messages[0]!.content as Block[])[2]!.text;

test("labelled: `!cat` of a no-model file whose values were never registered reaches the model only as a symbol, in Claude Code's own tags; the command block stays", async () => {
  await withStack("labelled", async (s) => {
    const file = join(s.vault, "api.env");
    writeFileSync(file, `ACME_KEY=sk-live-${CANARY}\n`);
    const r = await s.send(bashTurn(file, `ACME_KEY=sk-live-${CANARY}\n`, "what does it say?"));
    assert.equal(r.status, 200);
    assert.ok(!r.forwarded.includes(CANARY), "INVARIANT: the bash-mode output never reaches the model un-symbolized");
    const out = outBlock(r.forwarded);
    assert.match(out, /^<bash-stdout>\$MDU:nomodel_Bash\[[0-9a-f]+\][\s\S]*<\/bash-stdout><bash-stderr><\/bash-stderr>$/);
    const sent = JSON.parse(r.forwarded) as { messages: Message[] };
    assert.equal((sent.messages[0]!.content as Block[])[1]!.text, `<bash-input>cat ${file}</bash-input>\n`, "the human's command is unchanged");
    assert.equal((sent.messages[2]!.content as Block[])[0]!.text, "what does it say?", "the human's prompt is unchanged");
  });
});

test("unlabelled: `!cat` of an ordinary file goes out byte for byte; history: a masked block re-sent forwards the same", async () => {
  await withStack("plain", async (s) => {
    const plain = join(s.tmp, "notes.txt");
    const turn = bashTurn(plain, 'build ok & <done> "really"\n');
    const r = await s.send(structuredClone(turn));
    assert.equal(outBlock(r.forwarded), (turn[0]!.content as Block[])[2]!.text, "verbatim");
    const file = join(s.vault, "api.env");
    const a = await s.send(bashTurn(file, `ACME_KEY=sk-live-${CANARY}\n`));
    const b = await s.send(bashTurn(file, `ACME_KEY=sk-live-${CANARY}\n`, "and now?"));
    assert.equal(outBlock(b.forwarded), outBlock(a.forwarded), "the same masked block in a later request");
  });
});

test("the capture: the real 2.1.289 request replayed parses as Claude Code sent it: a known secret in it is masked, the escaped unlabelled output goes out unchanged", async () => {
  await withStack("capture", async (s) => {
    // the captured `cat notes.txt` ran in a project of its own (a relative
    // path); make its value a known secret: a labelled file holding it, read once
    const file = join(s.vault, "notes.txt");
    writeFileSync(file, "API_KEY=sk-live-BASHMODE-CANARY-1\nsecond line\n");
    const pre = await s.send([
      { role: "user", content: "read it" },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_pre", name: "Read", input: { file_path: file } } as never] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_pre", content: "1\tAPI_KEY=sk-live-BASHMODE-CANARY-1\n2\tsecond line\n" } as never] },
    ]);
    assert.ok(!pre.forwarded.includes("BASHMODE-CANARY-1"));
    const r = await s.send(structuredClone(capture.requests[1]!));
    assert.equal(r.status, 200);
    assert.ok(!r.forwarded.includes("sk-live-BASHMODE-CANARY-1"), "INVARIANT: the captured bash-mode output is masked");
    const weird = ((capture.requests[1]![2]!.content) as Block[])[1]!.text;
    assert.ok(r.forwarded.includes(JSON.stringify(weird).slice(1, -1)), "the unlabelled weird.txt block goes out byte for byte");
  });
});

test("FAIL-CLOSED: the arbiter unreachable, a bash-mode output carrying the secret never reaches the model raw", async () => {
  await withStack("down", async (s) => {
    s.real.close();
    await s.server.close();
    const r = await s.send(bashTurn(join(s.vault, "api.env"), `ACME_KEY=sk-live-${CANARY}\n`));
    assert.ok(!r.forwarded.includes(CANARY), "INVARIANT: nothing carrying the secret was forwarded");
    assert.ok(r.status === 200 || r.status >= 500, `answered or refused (status ${r.status})`);
  });
});
