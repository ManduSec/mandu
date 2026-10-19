/**
 * claude-bash-public-label — a human `public` label decides a Claude Code
 * Bash read by a RELATIVE path the way it decides a Read (2026-10-04,
 * confidentiality.md §6), over the REAL components: a real ArbiterServer in
 * `secrets` whose policy file labels the workspace's `test/fixtures/.env`
 * public and `vault/` no-model, the real anthropic-proxy over HTTP in its
 * production wiring (`new ArbiterClientAdapter(data, human)`), a mock model
 * behind it.
 *
 * Claude Code's Bash names no working directory (its shell starts where the
 * previous call left it), so before this change the token
 * `test/fixtures/.env` met only the catalog's `.env` shape and the fixture
 * the human made public came back as a symbol. Now the guard reports the
 * directory the kernel says each call's shell started in (`recordExecRoot`
 * `cwd`, read off `/proc/<pid>/cwd` while the exec was suspended; the
 * guard's reports are sent here on the human socket exactly as the guard
 * sends them, and the live form is tests/sandbox/guard/relative-path-label),
 * the proxy's callTaint binds the call to that shell, and classify reads the
 * token there.
 *
 *   - the public fixture read by a relative path reaches the model in clear;
 *   - a protected file read by a relative path stays masked: the catalog's
 *     `.env`, and a file under the human's no-model `vault/`;
 *   - the same command also reading a protected file stays masked;
 *   - a command that changes directory, and a call whose shell the guard
 *     named no directory for, keep the catalog's verdict (masked);
 *   - THE ORACLE: no protected file's value is in a request to the model.
 *
 * Unit and component twins: arbiter `call-start-dir.test.ts` (both).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const FIXTURE_VALUE = "fixture-not-a-key-PUBLIC-5182";
const SECRET_VALUE = "sk-live-BASH-REL-SECRET-73c1";
const VAULT_VALUE = "vault-BASH-REL-SECRET-0e44";

test("a Claude Code Bash read of a public-labelled file by a relative path reaches the model in clear; a protected file by a relative path, a mixed read, a cd and an unknown start directory stay masked (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-bash-public-label-"));
  const ws = join(tmp, "ws");
  mkdirSync(join(ws, "test", "fixtures"), { recursive: true });
  mkdirSync(join(ws, "vault"), { recursive: true });
  const fixture = join(ws, "test", "fixtures", ".env");
  writeFileSync(fixture, `API_KEY=${FIXTURE_VALUE}\n`);
  writeFileSync(join(ws, ".env"), `API_KEY=${SECRET_VALUE}\n`);
  writeFileSync(join(ws, "vault", "key.txt"), `${VAULT_VALUE}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${fixture}\n    level: public\n    recursive: false\n  - path: ${join(ws, "vault")}\n    level: no-model\n`);
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const guard = await open(humanSock); // the guard reports on the human socket (plan 13 D9)
  const human = await open(humanSock);
  const session = `bash-public-label-${process.pid}`;
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await open(sock), human), upstream: upstream.fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);

  /** One Bash call as it runs under Mandu: the proxy's record of the command
   *  it relayed (its response side), the guard's report of the agent's shell
   *  for it with the kernel's directory (`cwd`, or none), then the result
   *  sent back through the proxy. What the model got for it. */
  let n = 0;
  const bashCall = async (command: string, output: string, cwd: string | null): Promise<string> => {
    const id = `toolu_bpl_${n++}`;
    await human.recordCallCommand({ callId: id, command, sessionKey: session });
    await guard.recordExecRoot({
      procKey: `sh-${id}`, ancestors: ["agent-bpl-0"], session, callRoot: true,
      // Claude Code's shell, as it spawns it (its quoting of the command)
      argv: ["/bin/bash", "-c", `source /dev/null 2>/dev/null || true && eval '${command.replace(/'/g, `'"'"'`)}' && pwd -P >| /tmp/claude-x-cwd`],
      ...(cwd !== null ? { cwd } : {}),
    });
    const before = upstream.requests.length;
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({
        model: "claude-sonnet-4-5", stream: true, max_tokens: 256,
        tools: [{ name: "Bash", input_schema: { type: "object" } }],
        messages: [
          { role: "user", content: "go" },
          { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command } }] },
          { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: output }] },
        ],
      }),
    });
    assert.equal(res.status, 200, await res.text());
    assert.equal(upstream.requests.length, before + 1);
    const body = upstream.requests.at(-1)!.json() as { messages: Array<{ content: Array<{ content?: unknown }> }> };
    return JSON.stringify(body.messages[2]!.content[0]!.content);
  };

  try {
    // THE LIFT: the public fixture by a relative path, read where the kernel says the shell started
    const pub = await bashCall("cat test/fixtures/.env", `API_KEY=${FIXTURE_VALUE}\n`, ws);
    assert.ok(pub.includes(`API_KEY=${FIXTURE_VALUE}`), `utility: the human's public label must decide the Bash read by a relative path (over-block): ${pub}`);
    assert.ok(!pub.includes("$MDU:"), `no symbol minted for the public fixture: ${pub}`);
    const sub = await bashCall("rg '^API_KEY=' fixtures/.env", `API_KEY=${FIXTURE_VALUE}\n`, join(ws, "test"));
    assert.ok(sub.includes(`API_KEY=${FIXTURE_VALUE}`), `a shell that started in a subdirectory: ${sub}`);

    // protected files by a relative path: masked
    const masked: Array<[string, string, string, string | null]> = [
      ["the catalog's .env", "cat .env", `API_KEY=${SECRET_VALUE}\n`, ws],
      ["the human's no-model vault", "cat vault/key.txt", `${VAULT_VALUE}\n`, ws],
      ["a mixed read", "cat test/fixtures/.env .env", `API_KEY=${FIXTURE_VALUE}\nAPI_KEY=${SECRET_VALUE}\n`, ws],
      ["a cd in the command", "cd test && cat fixtures/.env", `API_KEY=${FIXTURE_VALUE}\n`, ws],
      ["no start directory from the guard", "cat test/fixtures/.env", `API_KEY=${FIXTURE_VALUE}\n`, null],
      ["another start directory", "cat test/fixtures/.env", `API_KEY=${FIXTURE_VALUE}\n`, join(tmp, "elsewhere")],
    ];
    for (const [what, command, output, cwd] of masked) {
      const seen = await bashCall(command, output, cwd);
      assert.ok(seen.includes("$MDU:"), `${what}: masked (fail-closed): ${seen}`);
      assert.ok(!seen.includes(SECRET_VALUE) && !seen.includes(VAULT_VALUE) && !seen.includes(FIXTURE_VALUE), `${what}: no byte of the result in clear: ${seen}`);
    }

    // THE ORACLE: no protected value reached the model
    const wire = upstream.requests.map((r) => r.bodyText).join("\n");
    assert.ok(!wire.includes(SECRET_VALUE), "CONFIDENTIALITY VIOLATION: the workspace .env's value is in a request to the model");
    assert.ok(!wire.includes(VAULT_VALUE), "CONFIDENTIALITY VIOLATION: the vault file's value is in a request to the model");
  } finally {
    await proxy.close();
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
