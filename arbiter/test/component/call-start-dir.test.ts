/**
 * call-start-dir (component) — the directory a Claude Code Bash call's
 * relative paths are read in is the arbiter's own record, never a caller's
 * word (2026-10-04, confidentiality.md §6).
 *
 * A real ArbiterServer with both sockets, its policy labelling the
 * workspace's `test/fixtures/.env` public. `guard` and `proxy` are
 * production clients on the human socket (as the guard and the model proxy
 * send), `agent` one on the data socket (as a program the agent runs has).
 *
 *   - the guard reports the call's shell with the kernel's directory, the
 *     proxy's callTaint binds the call: a classify of the call (on either
 *     socket) reads `cat test/fixtures/.env` there, and the label lifts it;
 *   - the classify request's own `callStartDir` is dropped: a caller cannot
 *     name a directory;
 *   - the same report from the data socket is a claim: no directory is kept,
 *     and the token stays masked;
 *   - a protected file read by a relative path stays masked, and a call whose
 *     command changes directory too.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

test("a Bash call's relative path is read where the guard says its shell started, from the human plane only; a caller's callStartDir is dropped (secrets axes, explicit)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-start-dir-"));
  const ws = join(dir, "ws");
  mkdirSync(join(ws, "test", "fixtures"), { recursive: true });
  const fixture = join(ws, "test", "fixtures", ".env");
  writeFileSync(fixture, "API_KEY=fixture\n");
  writeFileSync(join(ws, ".env"), "API_KEY=secret\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${fixture}\n    level: public\n    recursive: false\n`);
  const human = join(dir, "human", "h.sock");
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: human, dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    policyPath: policy, log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  const guard = new ArbiterClient(human); await guard.connect();
  const proxy = new ArbiterClient(human); await proxy.connect();
  const agent = new ArbiterClient(join(dir, "a.sock")); await agent.connect();
  const session = "s-start-dir";
  let n = 0;
  /** One Bash call: the proxy records its command, the shell is reported
   *  (by `reporter`, with `cwd`), the proxy asks for its tree (which binds
   *  it), then classifies its result on `asker`. */
  const call = async (command: string, opts: { reporter?: ArbiterClient; cwd?: string; asker?: ArbiterClient; claimDir?: string } = {}): Promise<string | undefined> => {
    const callId = `toolu_sd_${n++}`;
    await proxy.recordCallCommand({ callId, command, sessionKey: session });
    await (opts.reporter ?? guard).recordExecRoot({
      procKey: `sh-${callId}`, ancestors: ["agent-0"], argv: ["/bin/bash", "-c", command], session, callRoot: true,
      ...(opts.cwd !== undefined ? { cwd: opts.cwd } : {}),
    });
    await proxy.callTaint(callId, { command, session });
    const r = await (opts.asker ?? agent).classify({
      tool: "Bash", value: "API_KEY=fixture\n", boundary: "model_context", origin: command, params: { command }, sessionKey: session, callId,
      ...(opts.claimDir !== undefined ? { callStartDir: opts.claimDir } : {}),
    } as Parameters<ArbiterClient["classify"]>[0]);
    return (r as { confidentiality?: string }).confidentiality;
  };
  try {
    // THE LIFT: the guard's directory, a recorder binding, the human label.
    assert.equal(await call("cat test/fixtures/.env", { cwd: ws }), "public", "read where the kernel says the shell started");
    assert.equal(await call("cat test/fixtures/.env", { cwd: ws, asker: proxy }), "public", "on either socket: the record is read, not written");
    assert.equal(await call("cat fixtures/.env", { cwd: join(ws, "test") }), "public");

    // What keeps the mask.
    assert.equal(await call("cat test/fixtures/.env"), "no-model", "the guard named no directory");
    assert.equal(await call("cat test/fixtures/.env", { cwd: join(ws, "test") }), "no-model", "another directory: not the labelled file");
    assert.equal(await call("cat .env", { cwd: ws }), "no-model", "a protected file by a relative path");
    assert.equal(await call("cat test/fixtures/.env .env", { cwd: ws }), "no-model", "a call that also reads a protected file");
    assert.equal(await call("cd test && cat fixtures/.env", { cwd: ws }), "no-model", "a directory change in the command");
    assert.equal(await call("cat test/fixtures/.env", { reporter: agent, cwd: ws }), "no-model", "the data socket's report is a claim: no call root, no directory");

    // A caller cannot name the directory: an unbound call with a claimed one.
    const r = await agent.classify({
      tool: "Bash", value: "API_KEY=fixture\n", boundary: "model_context", origin: "cat test/fixtures/.env",
      params: { command: "cat test/fixtures/.env" }, sessionKey: session, callId: "toolu_never_ran", callStartDir: ws,
    } as Parameters<ArbiterClient["classify"]>[0]);
    assert.equal((r as { confidentiality?: string }).confidentiality, "no-model", "a callStartDir in the request is dropped");
    assert.equal(await call("cat test/fixtures/.env", { cwd: join(ws, "test"), claimDir: ws }), "no-model", "nor does it replace the guard's");
  } finally {
    guard.close(); proxy.close(); agent.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
