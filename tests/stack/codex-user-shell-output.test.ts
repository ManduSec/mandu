/**
 * codex-user-shell-output — Codex's user-run shell (`!cmd`) is PROGRAM
 * OUTPUT, over the REAL arbiter in `secrets`, its REAL IPC and the
 * PRODUCTION openai-proxy wiring (supported-agents.md §2.4;
 * interceptors/openai-proxy/src/user-shell.ts). The records are the shape
 * codex-cli 0.160.0 sends (tests/fixtures/codex-user-shell-2026-10-05.json):
 * a user message item `<user_shell_command>\n<command>\n…\n</command>\n<result>
 * \nExit code: N\nDuration: S seconds\nOutput:\n…\n</result>\n
 * </user_shell_command>`, nothing escaped, re-sent unchanged.
 *
 *   labelled     `!cat` of a file the policy labels no-model, whose values the
 *                arbiter never registered, reaches the model only as a symbol
 *                (before: a harness segment of the prompt filter, read by the
 *                registered-value filter only, so it went out raw);
 *   unlabelled   `!cat` of an ordinary file goes out byte for byte;
 *   history      the masked record re-sent forwards the same;
 *   the capture  the captured request replayed with its value a known secret:
 *                masked, and the unlabelled record unchanged;
 *   FAIL-CLOSED  the arbiter unreachable: the output never reaches the model raw.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter as OpenAiProxyArbiterAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { MockUpstream as OpenAiMockUpstream } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode

type Item = Record<string, unknown>;
const here = dirname(fileURLToPath(import.meta.url));
const capture = JSON.parse(readFileSync(join(here, "..", "fixtures", "codex-user-shell-2026-10-05.json"), "utf8")) as { requests: Item[][] };
const CANARY = "CODEX-USHELL-E2E-CANARY-6021";

const rec = (cmd: string, out: string) =>
  `<user_shell_command>\n<command>\n${cmd}\n</command>\n<result>\nExit code: 0\nDuration: 0.0235 seconds\nOutput:\n${out}\n</result>\n</user_shell_command>`;
const userMsg = (text: string): Item => ({ type: "message", role: "user", content: [{ type: "input_text", text }] });

interface Stack {
  tmp: string;
  vault: string;
  send: (items: Item[]) => Promise<{ status: number; forwarded: string }>;
  down: () => Promise<void>;
  register: (path: string) => Promise<{ symbol: string | null }>;
}

async function withStack(name: string, fn: (s: Stack) => Promise<void>): Promise<void> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-codex-ushell-"));
  const vault = join(tmp, "home", "vault");
  mkdirSync(vault, { recursive: true });
  const human = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({
    socketPath: join(tmp, "arbiter.sock"), humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, policyDocument: { version: 1, paths: [{ path: vault, level: "no-model" }] } as never,
  });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (sock: string): Promise<ArbiterClient> => { const c = new ArbiterClient(sock); await c.connect(); clients.push(c); return c; };
  const session = `codex-ushell-${name}-${process.pid}`;
  const upstream = new OpenAiMockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
  const proxy = new OpenAiProxy({ arbiter: new OpenAiProxyArbiterAdapter(await open(join(tmp, "arbiter.sock")), await open(human)), upstream: (a) => upstream.fetcher(a), sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    await fn({
      tmp, vault,
      send: async (items) => {
        const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, {
          method: "POST",
          headers: { "content-type": "application/json", "x-mandu-session-id": session },
          body: JSON.stringify({ model: "gpt-5.5", stream: true, instructions: "You are Codex.", input: items }),
        });
        await res.text();
        return { status: res.status, forwarded: upstream.requests.length > 0 ? upstream.requests.at(-1)!.bodyText : "" };
      },
      down: async () => { for (const c of clients) c.close(); await server.close(); },
      register: async (path) => (await open(join(tmp, "arbiter.sock"))).registerSecret({ path }),
    });
  } finally {
    await proxy.close();
    for (const c of clients) c.close();
    await server.close().catch(() => {});
    rmSync(tmp, { recursive: true, force: true });
  }
}

const recordOf = (forwarded: string, i: number): string => ((JSON.parse(forwarded).input as Item[])[i]!["content"] as Array<{ text: string }>)[0]!.text;

test("labelled: `!cat` of a no-model file whose values were never registered reaches the model only as a symbol, inside Codex's own record; the human's prompt stays", async () => {
  await withStack("labelled", async (s) => {
    const file = join(s.vault, "api.env");
    writeFileSync(file, `ACME_KEY=sk-live-${CANARY}\n`);
    const r = await s.send([userMsg(rec(`cat ${file}`, `ACME_KEY=sk-live-${CANARY}\n`)), userMsg("what did that print?")]);
    assert.equal(r.status, 200);
    assert.ok(!r.forwarded.includes(CANARY), "INVARIANT: the user shell's output never reaches the model un-symbolized");
    const t = recordOf(r.forwarded, 0);
    assert.ok(t.startsWith(`<user_shell_command>\n<command>\ncat ${file}\n</command>\n<result>\nExit code: 0\nDuration: 0.0235 seconds\nOutput:\n$MDU:nomodel_exec_command[`), t);
    assert.ok(t.endsWith("\n</result>\n</user_shell_command>"));
    assert.equal(recordOf(r.forwarded, 1), "what did that print?");
  });
});

test("unlabelled: `!cat` of an ordinary file goes out byte for byte; history: a masked record re-sent forwards the same", async () => {
  await withStack("plain", async (s) => {
    const plain = rec(`cat ${join(s.tmp, "notes.txt")}`, 'build ok & <done> "really"\n');
    const r = await s.send([userMsg(plain)]);
    assert.equal(recordOf(r.forwarded, 0), plain, "verbatim");
    const secret = rec(`cat ${join(s.vault, "api.env")}`, `ACME_KEY=sk-live-${CANARY}\n`);
    const a = await s.send([userMsg(secret), userMsg("p1")]);
    const b = await s.send([userMsg(secret), userMsg("p1"), { type: "message", role: "assistant", content: [{ type: "output_text", text: "ok" }] }, userMsg("p2")]);
    assert.equal(recordOf(b.forwarded, 0), recordOf(a.forwarded, 0), "the same masked record in a later request");
  });
});

test("the capture: the real 0.160.0 request replayed parses as Codex sent it: a known secret in it is masked, the unlabelled record goes out unchanged", async () => {
  await withStack("capture", async (s) => {
    // make the captured value a known secret: a labelled file holding it, registered
    const file = join(s.vault, "notes.txt");
    writeFileSync(file, "API_KEY=sk-live-CODEXSHELL-CANARY-1\nsecond line\n");
    assert.ok((await s.register(file)).symbol, "registered");
    const items = structuredClone(capture.requests[1]!);
    const r = await s.send(items);
    assert.equal(r.status, 200);
    assert.ok(!r.forwarded.includes("sk-live-CODEXSHELL-CANARY-1"), "INVARIANT: the captured user-shell output is masked");
    const weird = (items[1]!["content"] as Array<{ text: string }>)[0]!.text;
    assert.ok(weird.includes("forged"));
    assert.equal(recordOf(r.forwarded, 1), weird, "the unlabelled record goes out byte for byte");
  });
});

test("FAIL-CLOSED: the arbiter unreachable, a user-shell output carrying the secret never reaches the model raw", async () => {
  await withStack("down", async (s) => {
    await s.down();
    const r = await s.send([userMsg(rec(`cat ${join(s.vault, "api.env")}`, `ACME_KEY=sk-live-${CANARY}\n`))]);
    assert.ok(!r.forwarded.includes(CANARY), "INVARIANT: nothing carrying the secret was forwarded");
    assert.ok(r.status === 200 || r.status >= 500, `answered or refused (status ${r.status})`);
  });
});
