/**
 * codex-shell-public-label — a human `public` label decides a shell read the
 * way it decides a Read (2026-10-04, live drill conf-public-label-wins on
 * Codex), over the REAL components: a real ArbiterServer in `secrets` whose
 * policy file labels the workspace's `test/fixtures/.env` public, the real
 * openai-proxy over HTTP in its production wiring, a scripted model behind it.
 *
 * Codex's `exec_command` names the directory its command runs in
 * (`workdir`); the label store is keyed by absolute paths. Before, the
 * relative token `test/fixtures/.env` in `rg '^API_KEY=' test/fixtures/.env`
 * matched only the catalog's `.env` shape, so the fixture the human made
 * public came back to the model as `$MDU:nomodel_exec_command[…]`. Now the
 * token is also read in the call's workdir, where the human label decides it.
 *
 *   - the shell read of the public fixture reaches the model in clear;
 *   - the same command also reading the workspace's own `.env` (a catalog
 *     secret, NOT registered, so the path scan alone decides) stays masked;
 *   - a command that changes directory first, and a call with no workdir,
 *     keep the catalog's verdict (masked);
 *   - THE ORACLE: the secret `.env`'s value is in no request to the model.
 *
 * Unit twins: arbiter `label-derivation.test.ts`, `unmapped-input-label.test.ts`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter as OpenAiProxyArbiterAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { MockUpstream as OpenAiMockUpstream } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const FIXTURE_VALUE = "fixture-not-a-key-PUBLIC-4471";
const SECRET_VALUE = "sk-live-SHELL-LABEL-SECRET-9d2e";
const head = (chunk: string): string => `Chunk ID: ${chunk}\nWall time: 0.0123 seconds\nProcess exited with code 0\nOriginal token count: 9\nOutput:\n`;

function codexTurn(...items: unknown[]): unknown {
  return { model: "gpt-5.5", stream: true, instructions: "You are Codex.", input: [{ type: "message", role: "user", content: [{ type: "input_text", text: "go" }] }, ...items] };
}

function codexOutputOf(body: string, callId: string): string {
  const item = (JSON.parse(body).input as Array<Record<string, unknown>>).find((i) => i["type"] === "function_call_output" && i["call_id"] === callId)!;
  const o = item["output"];
  return typeof o === "string" ? o : (o as Array<{ text: string }>).map((p) => p.text).join("");
}

test("a shell read of a file the human labelled public reaches the model in clear; the same command also reading a secret stays masked; a directory change or no workdir keeps the mask (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-shell-public-label-"));
  const ws = join(tmp, "ws");
  mkdirSync(join(ws, "test", "fixtures"), { recursive: true });
  const fixture = join(ws, "test", "fixtures", ".env");
  writeFileSync(fixture, `API_KEY=${FIXTURE_VALUE}\n`);
  writeFileSync(join(ws, ".env"), `API_KEY=${SECRET_VALUE}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${fixture}\n    level: public\n    recursive: false\n`);
  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const session = `shell-public-label-${process.pid}`;
  const upstream = new OpenAiMockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
  const proxy = new OpenAiProxy({ arbiter: new OpenAiProxyArbiterAdapter(await open(sock), await open(human)), upstream: (a) => upstream.fetcher(a), sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const call = (id: string, cmd: string, workdir: string | null) => ({
    type: "function_call", call_id: id, name: "exec_command",
    arguments: JSON.stringify({ cmd, ...(workdir !== null ? { workdir } : {}) }),
  });
  const output = (id: string, chunk: string, text: string) => ({ type: "function_call_output", call_id: id, output: `${head(chunk)}${text}` });
  try {
    const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session },
      body: JSON.stringify(codexTurn(
        call("c_public", "rg '^API_KEY=' test/fixtures/.env", ws), output("c_public", "a1b2", `API_KEY=${FIXTURE_VALUE}\n`),
        call("c_both", "cat test/fixtures/.env .env", ws), output("c_both", "b2c3", `API_KEY=${FIXTURE_VALUE}\nAPI_KEY=${SECRET_VALUE}\n`),
        call("c_cd", "cd test && cat fixtures/.env", ws), output("c_cd", "c3d4", `API_KEY=${FIXTURE_VALUE}\n`),
        call("c_nowd", "cat test/fixtures/.env", null), output("c_nowd", "d4e5", `API_KEY=${FIXTURE_VALUE}\n`),
      )),
    });
    assert.equal(res.status, 200, await res.text());
    const toModel = upstream.requests[0]!.bodyText;

    // the shell read of the public fixture: in clear, as a Read of it would be
    const pub = codexOutputOf(toModel, "c_public");
    assert.ok(pub.includes(`API_KEY=${FIXTURE_VALUE}`), `utility: the human's public label must decide the shell read too (over-block): ${pub}`);
    assert.ok(!pub.includes("$MDU:"), `no symbol minted for the public fixture: ${pub}`);

    // the same command also reading the workspace's own .env: masked whole
    const both = codexOutputOf(toModel, "c_both");
    assert.ok(!both.includes(SECRET_VALUE), `CONFIDENTIALITY VIOLATION: the secret .env read alongside the public fixture reached the model raw: ${both}`);
    assert.ok(both.includes("$MDU:"), `the mixed read is a symbol: ${both}`);

    // no override where the base is not where the token is read
    for (const id of ["c_cd", "c_nowd"]) {
      const o = codexOutputOf(toModel, id);
      assert.ok(!o.includes(FIXTURE_VALUE) && o.includes("$MDU:"), `${id}: the catalog's verdict stands (fail-closed): ${o}`);
    }

    // THE ORACLE: the secret never reached the model
    assert.ok(!toModel.includes(SECRET_VALUE), "CONFIDENTIALITY VIOLATION: the secret .env's value is in the request to the model");

    // A call that names no workdir runs in the session's directory, which
    // Codex's own <environment_context> names: known for certain, the label decides
    const envCtx = (cwd: string) => ({ type: "message", role: "user", content: [{ type: "input_text", text: `<environment_context>\n  <cwd>${cwd}</cwd>\n  <shell>bash</shell>\n</environment_context>` }] });
    const second = async (...items: unknown[]): Promise<string> => {
      const r = await fetch(`http://127.0.0.1:${port}/v1/responses`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-mandu-session-id": session },
        body: JSON.stringify({ ...(codexTurn() as Record<string, unknown>), input: items }),
      });
      assert.equal(r.status, 200, await r.text());
      return upstream.requests.at(-1)!.bodyText;
    };
    const known = await second(
      envCtx(ws), { type: "message", role: "user", content: [{ type: "input_text", text: "go" }] },
      call("d_public", "rg '^API_KEY=' test/fixtures/.env", null), output("d_public", "e5f6", `API_KEY=${FIXTURE_VALUE}\n`),
      call("d_both", "cat test/fixtures/.env .env", null), output("d_both", "f6a7", `API_KEY=${FIXTURE_VALUE}\nAPI_KEY=${SECRET_VALUE}\n`),
    );
    assert.ok(codexOutputOf(known, "d_public").includes(`API_KEY=${FIXTURE_VALUE}`), `the session's cwd is the call's base: ${codexOutputOf(known, "d_public")}`);
    assert.ok(!codexOutputOf(known, "d_both").includes(SECRET_VALUE), "CONFIDENTIALITY VIOLATION: the mixed read without a workdir reached the model raw");
    // two different cwds in Codex's context: not certain, masked
    const unsure = await second(
      envCtx(ws), envCtx(join(tmp, "elsewhere")),
      call("e_public", "rg '^API_KEY=' test/fixtures/.env", null), output("e_public", "a7b8", `API_KEY=${FIXTURE_VALUE}\n`),
    );
    assert.ok(!codexOutputOf(unsure, "e_public").includes(FIXTURE_VALUE), `an uncertain session directory keeps the catalog's verdict: ${codexOutputOf(unsure, "e_public")}`);
    assert.ok(!known.includes(SECRET_VALUE) && !unsure.includes(SECRET_VALUE), "CONFIDENTIALITY VIOLATION: the secret is in a request to the model");
  } finally {
    await proxy.close();
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
