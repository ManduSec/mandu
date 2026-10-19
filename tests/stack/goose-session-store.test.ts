/**
 * goose-session-store — Goose's own session store and request log reach the
 * model only masked, over the REAL arbiter, its REAL IPC and the PRODUCTION
 * proxy wiring (`new ArbiterClientAdapter(new ArbiterClient(sock))`), in the
 * `secrets` mode, for a session bound to `goose` (supported-agents.md
 * §5.6.2; arbiter fs-outbound.ts SENSITIVE_PATHS, secret-catalog.ts
 * GOOSE_DATA_SHAPE_RE).
 *
 * goose 1.53.0 keeps every message and tool output in
 * `<data>/sessions/sessions.db` and writes the last ten model requests WHOLE
 * to `<state>/logs/llm_request.{0..9}.jsonl`, both as Goose built them,
 * before the model proxy symbolized anything. A labelled secret masked in
 * one turn is therefore on disk raw; a later `shell` `cat` (or `sqlite3`) of
 * either file put it in front of the model. Each case uses a FRESH arbiter
 * with no label on the file (an earlier session's file), at the default
 * location, under another XDG_DATA_HOME / XDG_STATE_HOME, and under a
 * GOOSE_PATH_ROOT (`<root>/data`, `<root>/state`).
 *
 *   CONTROL   the same text from a project file no rule knows reaches the
 *             model as is (the probe is real; the store's masking is the
 *             catalog's doing, not a value detector's).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the built-in default: confidentiality ON, integrity OFF

// Not secret-shaped on purpose: only the file's place can mask it.
const CANARY = "GOOSE-STORE-CANARY-4471";
const LOG_LINE = `{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":[{"type":"tool_result","content":"quarterly notes ${CANARY}"}]}]}`;

interface Stack {
  tmp: string;
  real: ArbiterClient;
  /** One `shell` turn (`command`, its result) through the production proxy:
   *  what the model received. */
  shell: (command: string, result: string) => Promise<string>;
}

async function withStack(name: string, fn: (s: Stack) => Promise<void>): Promise<void> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-goose-store-"));
  const server = new ArbiterServer({
    socketPath: join(tmp, "arbiter.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  const real = new ArbiterClient(join(tmp, "arbiter.sock"));
  await real.connect();
  const sessionKey = `goose-store-${name}-${process.pid}`;
  // what the launcher binds for `mandu goose` (context-proxy.ts)
  assert.equal((await real.setSessionSpec({ sessionKey, spec: "goose", requestedBy: "goose-session-store e2e" })).bound, "goose");
  const proxies: AnthropicProxy[] = [];
  try {
    await fn({
      tmp, real,
      shell: async (command, result) => {
        const up = new MockUpstream({ sse: buildTextSse("ok") });
        const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(real), upstream: up.fetcher, sessionKey, log: () => {} });
        proxies.push(proxy);
        const port = await proxy.listen(0);
        // Goose 1.53.0's shell turn: a plain-string tool result.
        const body = JSON.stringify({
          model: "claude-sonnet-4-5", stream: true,
          tools: [{ name: "shell", input_schema: { type: "object" } }],
          messages: [
            { role: "user", content: "look at the earlier session" },
            { role: "assistant", content: [{ type: "tool_use", id: "tu_cat", name: "shell", input: { command } }] },
            { role: "user", content: [{ type: "tool_result", tool_use_id: "tu_cat", content: result }] },
          ],
        });
        const status = await new Promise<number>((resolve, reject) => {
          const r = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "agent-session-id": "20261007_1", "x-mandu-session-id": sessionKey } }, (res) => {
            res.resume();
            res.on("end", () => resolve(res.statusCode ?? 0));
          });
          r.on("error", reject);
          r.end(body);
        });
        assert.equal(status, 200);
        return up.requests.map((q) => q.bodyText).join("\n");
      },
    });
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    real.close();
    await server.close().catch(() => {});
    rmSync(tmp, { recursive: true, force: true });
  }
}

test("CONTROL: the same text from a project file no rule knows reaches the model as is", async () => {
  await withStack("control", async (s) => {
    const file = join(s.tmp, "proj", "notes.jsonl");
    assert.equal((await s.real.pathLevel(file)).level, "public");
    const got = await s.shell(`cat ${file}`, `${LOG_LINE}\n`);
    assert.ok(got.includes(CANARY), "the probe is real: an unknown file's text goes out raw");
  });
});

test("the default locations: a shell cat of the request log, and sqlite3 on the session store, reach the model only masked", async () => {
  await withStack("default", async (s) => {
    for (const [command, path] of [
      ["cat ~/.local/state/goose/logs/llm_request.0.jsonl", "~/.local/state/goose/logs/llm_request.0.jsonl"],
      ["tail -n 5 ~/.local/state/goose/logs/llm_request.*.jsonl", "~/.local/state/goose/logs/llm_request.1.jsonl"],
      ["sqlite3 ~/.local/share/goose/sessions/sessions.db 'select content_json from messages'", "~/.local/share/goose/sessions/sessions.db"],
      ["cat ~/.local/state/goose/history.txt", "~/.local/state/goose/history.txt"],
    ] as const) {
      assert.equal((await s.real.pathLevel(path)).level, "no-model", `${path}: a catalog location`);
      const got = await s.shell(command, `${LOG_LINE}\n`);
      assert.ok(!got.includes(CANARY), `INVARIANT: \`${command}\` reaches the model only masked`);
    }
  });
});

test("another XDG_DATA_HOME / XDG_STATE_HOME and a GOOSE_PATH_ROOT: the same files, by shape, reach the model only masked", async () => {
  await withStack("relocated", async (s) => {
    for (const path of [
      join(s.tmp, "xdg-state", "goose", "logs", "llm_request.0.jsonl"),
      join(s.tmp, "xdg-data", "goose", "sessions", "sessions.db"),
      join(s.tmp, "groot", "state", "logs", "llm_request.4.jsonl"),
      join(s.tmp, "groot", "data", "sessions", "sessions.db"),
    ]) {
      assert.equal((await s.real.pathLevel(path)).level, "no-model", `${path}: a catalog shape`);
      const got = await s.shell(`cat ${path}`, `${LOG_LINE}\n`);
      assert.ok(!got.includes(CANARY), `INVARIANT: a cat of ${path} reaches the model only masked`);
    }
  });
});
