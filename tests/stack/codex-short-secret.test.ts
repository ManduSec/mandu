/**
 * codex-short-secret — plan 10 §11.15 over the REAL components: a short
 * secret (12 characters) read raw by one Codex call, whose result is masked
 * whole, is caught when a later clean-looking call prints it again.
 *
 *   a real ArbiterServer in `secrets` (a policy file labels two files, `mytool`
 *   their listed reader), the real openai-proxy over HTTP in its production
 *   wiring, a scripted model behind it. `vault.txt` holds one short line and
 *   is registered as the launcher registers a labelled file at launch;
 *   `.env` holds `API_KEY=<short>` and is NOT registered (labelled after the
 *   launch). Codex `mytool`s each; the guard's records say `mytool` read them raw.
 *
 * Before: the masked result's row was Codex's head plus the output (its
 * chunk id and wall time never recur), its line was under the 24-character
 * line floor, and the registered file's row kept its `\n`, so a later
 * output with the secret mid-line (`the key is <it>, ok`, from a copy the
 * guard never saw opened) reached the model raw. Now the value index
 * registers the file's value without its terminator and the
 * credential-shaped span of the masked result. Control: a short prose line
 * of the same masked output is not registered, and a later result carrying
 * it is forwarded raw.
 *
 * The two cases the maintainer decided (2026-10-03): `token.txt` (one line)
 * and `notes.md` (`password <it>` in prose) are labelled but never
 * registered at launch. The guard's report of `mytool`'s raw read makes the
 * arbiter register each file itself (case 2), and the notes file's bare
 * credential token is a piece of its row (case 1); each secret printed again
 * by a later call is masked. Each assertion fails with its rule disabled.
 * Unit twins: arbiter `value-pieces.test.ts`, `read-file-registration.test.ts`.
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
import { MockUpstream as OpenAiMockUpstream, buildExecCommandSse } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const VAULT_SECRET = "Tq7vZ2pX9kLm"; // 12 characters
const ENV_SECRET = "Hw4rN8sQ2yBd"; // 12 characters
const TOKEN_SECRET = "Pm3xK8vR2wQz"; // 12 characters, a one-line file never registered
const NOTES_SECRET = "Lb5nY7cT4hGs"; // 12 characters, a bare token in a notes file never registered
const SECRETS = [VAULT_SECRET, ENV_SECRET, TOKEN_SECRET, NOTES_SECRET];
const PROSE = "rotate monthly";
const head = (chunk: string): string => `Chunk ID: ${chunk}\nWall time: 0.0123 seconds\nProcess exited with code 0\nOriginal token count: 9\nOutput:\n`;

function codexTurn(...items: unknown[]): unknown {
  return { model: "gpt-5.5", stream: true, instructions: "You are Codex.", input: [{ type: "message", role: "user", content: [{ type: "input_text", text: "go" }] }, ...items] };
}

function codexOutputOf(body: string, callId: string): string {
  const item = (JSON.parse(body).input as Array<Record<string, unknown>>).find((i) => i["type"] === "function_call_output" && i["call_id"] === callId)!;
  const o = item["output"];
  return typeof o === "string" ? o : (o as Array<{ text: string }>).map((p) => p.text).join("");
}

test("a short secret read raw by one Codex call never reaches the model when a later clean-looking call prints it again; a short prose line of the same output is not registered (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-short-secret-stack-"));
  const vault = join(tmp, "vault.txt");
  writeFileSync(vault, `${VAULT_SECRET}\n`);
  const env = join(tmp, ".env");
  const ENV_FILE = `API_KEY=${ENV_SECRET}\n# ${PROSE}\n`;
  writeFileSync(env, ENV_FILE);
  // §11.15 cases 1 and 2: neither registered at launch (labelled later)
  const token = join(tmp, "token.txt");
  writeFileSync(token, `${TOKEN_SECRET}\n`);
  const notes = join(tmp, "notes.md");
  const NOTES_FILE = `# vault notes for the team\npassword ${NOTES_SECRET}\n${PROSE}\n`;
  writeFileSync(notes, NOTES_FILE);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n${[vault, env, token, notes].map((p) => `  - path: ${p}\n    level: no-model\n    readers: [{ app: mytool, prints: nothing }]\n`).join("")}`);
  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const guard = await open(human); // what the guard writes, on the human socket (plan 13 D9)
  const session = `short-secret-${process.pid}`;
  // the launcher registers a labelled file at launch (secret-setup.ts)
  const reg = await (await open(sock)).registerSecret({ path: vault, sessionKey: session });
  assert.ok(reg.symbol, reg.reason);
  let upstream = new OpenAiMockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
  const seen: string[] = [];
  const proxy = new OpenAiProxy({ arbiter: new OpenAiProxyArbiterAdapter(await open(sock), await open(human)), upstream: (a) => upstream.fetcher(a), sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const send = async (body: unknown, sse = "event: response.completed\ndata: {}\n\n"): Promise<string> => {
    upstream = new OpenAiMockUpstream({ sse });
    const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, { method: "POST", headers: { "content-type": "application/json", "x-mandu-session-id": session }, body: JSON.stringify(body) });
    assert.equal(res.status, 200, await res.text());
    const toModel = upstream.requests[0]!.bodyText;
    seen.push(toModel);
    return toModel;
  };
  /** One model turn asking for `cmd`, relayed (gated + recorded), and the guard's record of Codex's shell for it. */
  const relay = async (n: number, cmd: string): Promise<{ callId: string; call: unknown }> => {
    const callId = `call_ss_${n}`;
    await send(codexTurn(), buildExecCommandSse({ cmd, callId, itemId: `fc_${n}` }));
    await guard.recordExecRoot({ procKey: `ss-sh-${n}`, ancestors: ["ss-agent-0"], argv: ["/bin/bash", "-lc", cmd], session, callRoot: true });
    return { callId, call: { type: "function_call", call_id: callId, name: "exec_command", arguments: JSON.stringify({ cmd }) } };
  };
  /** `mytool` under call n's shell reads `path` raw (a listed reader). */
  const catReads = async (n: number, path: string): Promise<void> => {
    const chain = [`ss-sh-${n}`, "ss-agent-0"];
    await guard.recordExecRoot({ procKey: `ss-mytool-${n}`, ancestors: chain, argv: ["mytool", path], session });
    const d = await guard.decideSecretOpen({ path, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: `ss-mytool-${n}`, parentKey: chain[0], ancestorKeys: chain, session });
    assert.equal(d.verdict, "raw", `mytool is a listed reader: ${d.reason}`);
  };
  const output = (callId: string, text: string) => ({ type: "function_call_output", call_id: callId, output: text });
  try {
    // 1. Codex reads each file raw; each result is masked whole.
    const readVault = await relay(1, `mytool ${vault}`);
    await catReads(1, vault);
    const readEnv = await relay(2, `mytool ${env}`);
    await catReads(2, env);
    const readToken = await relay(6, `mytool ${token}`);
    await catReads(6, token);
    const readNotes = await relay(7, `mytool ${notes}`);
    await catReads(7, notes);
    const history = [
      readVault.call, output(readVault.callId, `${head("9a3f")}${VAULT_SECRET}\n`),
      readEnv.call, output(readEnv.callId, `${head("1b2c")}${ENV_FILE}`),
      readToken.call, output(readToken.callId, `${head("2c3d")}${TOKEN_SECRET}\n`),
      readNotes.call, output(readNotes.callId, `${head("3d4e")}${NOTES_FILE}`),
    ];
    const first = await send(codexTurn(...history));
    for (const id of [readVault.callId, readEnv.callId, readToken.callId, readNotes.callId]) {
      const o = codexOutputOf(first, id);
      assert.ok(SECRETS.every((x) => !o.includes(x)), `CONFIDENTIALITY VIOLATION: the reader's output reached the model raw: ${o}`);
    }

    // 2. Later calls in clean shells print the secrets again (a copy the
    //    guard never saw opened), and a short prose line of the .env output.
    const v = await relay(3, "mytool ./notes/copy-a.txt");
    const e = await relay(4, "mytool ./notes/copy-b.txt");
    const p = await relay(5, "mytool ./notes/readme.txt");
    const t = await relay(8, "mytool ./notes/copy-c.txt");
    const n = await relay(9, "mytool ./notes/copy-d.txt");
    const later = await send(codexTurn(
      ...history,
      v.call, output(v.callId, `${head("c0d1")}the key is ${VAULT_SECRET}, ok\n`),
      e.call, output(e.callId, `${head("d2e3")}export TOKEN=${ENV_SECRET}\n`),
      p.call, output(p.callId, `${head("e4f5")}${PROSE}\n`),
      t.call, output(t.callId, `${head("f6a7")}using ${TOKEN_SECRET} for the deploy\n`),
      n.call, output(n.callId, `${head("a8b9")}login with ${NOTES_SECRET}\n`),
    ));
    // §11.15 case 2: the one-line file the launch never registered, registered on the guard's report
    const tOut = codexOutputOf(later, t.callId);
    assert.ok(!tOut.includes(TOKEN_SECRET), `CONFIDENTIALITY VIOLATION: an unregistered one-line secret file reached the model in a later result: ${tOut}`);
    // §11.15 case 1: a bare credential token of a notes file (no shape the detectors know)
    const nOut = codexOutputOf(later, n.callId);
    assert.ok(!nOut.includes(NOTES_SECRET), `CONFIDENTIALITY VIOLATION: a notes file's short password reached the model in a later result: ${nOut}`);
    const vOut = codexOutputOf(later, v.callId);
    assert.ok(!vOut.includes(VAULT_SECRET), `CONFIDENTIALITY VIOLATION: the registered one-line secret file reached the model mid-line: ${vOut}`);
    const eOut = codexOutputOf(later, e.callId);
    assert.ok(!eOut.includes(ENV_SECRET), `CONFIDENTIALITY VIOLATION: the short key of a result masked whole reached the model in a later result: ${eOut}`);
    // control: the short prose line is no registered value (no over-masking)
    assert.ok(codexOutputOf(later, p.callId).startsWith(`${head("e4f5")}${PROSE}\n`), "utility: a short line that is not a secret is forwarded raw");

    // THE ORACLE: no request to the model carried either secret.
    const wire = seen.join("\n");
    assert.ok(SECRETS.every((x) => !wire.includes(x)), "the short secrets never reached the model");
  } finally {
    await proxy.close();
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
