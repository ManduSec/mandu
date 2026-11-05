/**
 * tool-error-secret-path — a tool's own error about a secret path reaches the
 * model; the path's content never does (confidentiality.md §7.1, "A tool's
 * error about a secret path", 2026-10-26).
 *
 * Live on the Claude subscription drills of 2026-10-26: the model read a
 * secret-shaped file at a path where there was none. Read's "File does not
 * exist" and `cat`'s "No such file or directory" both came back as
 * placeholders, so the model never learned the path was wrong; and a Write
 * the kernel refused (EACCES) came back as a placeholder, and the model told
 * the human it was done.
 *
 * Real ArbiterServer, a no-model label over the workspace and the catalog's
 * own `.env` shape, and the PRODUCTION proxy wiring (`new
 * ArbiterClientAdapter(new ArbiterClient(sock))`) in front of a mock
 * upstream: what the upstream receives is what the model would. Asserted
 * both ways: each error (with Claude Code's budget tail) reaches the model as
 * written; each result that carries a byte of the real file (the file's
 * Read, an error line followed by its content, an error naming a path the
 * command did not) stays masked, and no secret byte is in any request.
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets");

const SECRET = "Lantern-Moss-2290-Quill-ERRTEST";
const BUDGET = "\n\n<system-reminder>\n<total_tokens>14956073 tokens left</total_tokens>\n</system-reminder>";

function post(port: number, body: string, session: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": session } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

test("a tool's error about a secret path reaches the model as written; the path's content stays masked (secrets axes)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-tool-error-"));
  const ws = join(dir, "ws");
  mkdirSync(join(ws, "api"), { recursive: true });
  mkdirSync(join(ws, "health"), { recursive: true });
  // the real file is under api/; the model looks at the workspace root
  const real = join(ws, "api", "http-client.private.env.json");
  writeFileSync(real, `${JSON.stringify({ staging: { user: "ops-admin", password: SECRET } }, null, 2)}\n`);
  const missing = join(ws, "http-client.private.env.json");
  const missingEnv = join(ws, "app", ".env"); // the catalog's shape, no label of the human's
  const lab = join(ws, "health", "lab-results.md");
  writeFileSync(lab, `LDL cholesterol: 5.4 mmol/L ${SECRET}\n`);
  const server = new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"), adminSocketPath: join(dir, "admin.sock"), dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
    policyDocument: { paths: [{ path: `${ws}/**`, level: "no-model" }] },
  });
  await server.listen();
  const client = new ArbiterClient(join(dir, "arbiter.sock"));
  await client.connect();
  const sessionKey = `tool-error-${process.pid}`;
  const proxies: AnthropicProxy[] = [];
  let n = 0;
  try {
    assert.equal((await client.setSessionSpec({ sessionKey, spec: "claude-code", requestedBy: "tool-error-secret-path e2e" })).bound, "claude-code");
    const forwarded = async (name: string, input: Record<string, unknown>, content: string): Promise<string> => {
      const up = new MockUpstream({ sse: buildTextSse("ok") });
      const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(client), upstream: up.fetcher, sessionKey, log: () => {} });
      proxies.push(proxy);
      const id = `tu_${n++}`;
      const r = await post(await proxy.listen(0), JSON.stringify({
        model: "claude-haiku-4-5", stream: true,
        messages: [
          { role: "user", content: "reset customer 1042's stuck order on staging" },
          { role: "assistant", content: [{ type: "tool_use", id, name, input }] },
          { role: "user", content: [{ type: "tool_result", tool_use_id: id, content, ...(content.startsWith("File does not exist") || content.startsWith("E") ? { is_error: true } : {}) }] },
        ],
      }), sessionKey);
      assert.equal(r.status, 200, r.body);
      const b: unknown = up.requests[up.requests.length - 1]!.body;
      const sent = Buffer.isBuffer(b) ? b.toString("utf8") : String(b);
      assert.ok(!sent.includes(SECRET), `CONFIDENTIALITY VIOLATION: the secret reached the model through ${name} ${JSON.stringify(input)}:\n${sent.slice(0, 2000)}`);
      return sent;
    };
    const quoted = (s: string) => JSON.stringify(s).slice(1, -1);

    // the errors reach the model as written
    const readMissing = `File does not exist. Note: your current working directory is ${ws}.`;
    for (const [name, input, content, shown] of [
      ["Read", { file_path: missing }, readMissing + BUDGET, readMissing],
      ["Read", { file_path: missingEnv }, readMissing + BUDGET, readMissing],
      ["Bash", { command: `cat ${missing} | jq -r '.staging'` }, `cat: ${missing}: No such file or directory` + BUDGET, `cat: ${missing}: No such file or directory`],
      ["Bash", { command: `CREDS=$(cat ${missing} | jq -r .staging.password)\necho ok` }, `Exit code 1\ncat: ${missing}: No such file or directory`, `cat: ${missing}: No such file or directory`],
      ["Write", { file_path: lab, content: "summary" }, `EACCES: permission denied, rename '${lab}.tmp.2.242f70b9302e' -> '${lab}'` + BUDGET, `EACCES: permission denied, rename '${lab}.tmp.2.242f70b9302e' -> '${lab}'`],
    ] as const) {
      const sent = await forwarded(name, input, content);
      assert.ok(sent.includes(quoted(shown)), `${name} ${JSON.stringify(input)}: the model reads the error as written:\n${sent.slice(0, 1500)}`);
    }

    // anything that carries the file's bytes stays masked
    for (const [name, input, content] of [
      ["Read", { file_path: real }, `1\t{\n2\t  "staging": {\n3\t    "user": "ops-admin",\n4\t    "password": "${SECRET}"\n5\t  }\n6\t}` + BUDGET],
      ["Read", { file_path: real }, readMissing], // the file IS there: no release
      ["Bash", { command: `cat ${missing}; cat ${real}` }, `cat: ${missing}: No such file or directory\n${JSON.stringify({ password: SECRET })}`],
      ["Bash", { command: `cat ${missing}` }, `cat: ${missing}: No such file or directory\n${SECRET}`],
      ["Bash", { command: `cat ${real}` }, `cat: ${SECRET}: No such file or directory`],
    ] as const) {
      const sent = await forwarded(name, input, content);
      assert.match(sent, /\$MDU:nomodel_/, `${name} ${JSON.stringify(input)}: masked:\n${sent.slice(0, 1500)}`);
      assert.ok(!sent.includes("No such file or directory") || !sent.includes(SECRET), "never the error with the secret");
    }
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    client.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
