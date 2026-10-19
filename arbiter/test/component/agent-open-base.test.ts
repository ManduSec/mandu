/**
 * agent-open-base (component) — a file tool's RELATIVE path is read at the
 * file the agent itself opened, as the guard saw the open, and a Bash call's
 * at the directory the kernel says its shell started in: the base follows
 * the agent's real directory across calls (2026-10-17, confidentiality.md
 * §6, "The base follows the shell").
 *
 * A real ArbiterServer with both sockets, its policy labelling the
 * workspace's `vault/` no-model. `guard` and `proxy` are production clients
 * on the human socket (as the guard and the model proxy send), `agent` one
 * on the data socket (as a program the agent runs has).
 *
 *   - the proxy records a Read call's relay, the guard reports the agent's
 *     own open of `<ws>/vault/plan.md` (`labelledLevel` with `agentOpen`),
 *     and a classify of `Read {file_path: "plan.md"}` (on either socket) is
 *     masked. Before: public, the plan in clear;
 *   - the same report from the data socket records nothing; an open before
 *     the call's relay is not the call's; a caller's `agentOpened` is
 *     dropped; an unlabelled file is not recorded;
 *   - a Bash call whose shell the guard reported in `<ws>/vault` (a `cd` in
 *     the call before moved it) reads `cat plan.md` there: masked; one
 *     reported with no directory keeps the fallback.
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

test("a Read's relative path is read at the file the guard saw the agent open, from the human plane only, in the call's window; a Bash call's at its shell's kernel directory (secrets axes, explicit)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-agent-open-"));
  const ws = join(dir, "ws");
  mkdirSync(join(ws, "vault"), { recursive: true });
  writeFileSync(join(ws, "vault", "plan.md"), "# plan\nthe vault plan\n");
  writeFileSync(join(ws, "plan.md"), "# plan\nthe open plan\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${join(ws, "vault")}\n    level: no-model\n    recursive: true\n`);
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
  const session = "s-agent-open";
  let n = 0;
  const classifyRead = async (callId: string, filePath: string, opts: { asker?: ArbiterClient; claim?: unknown } = {}): Promise<string | undefined> => {
    const r = await (opts.asker ?? agent).classify({
      tool: "Read", value: "# plan\n", boundary: "model_context", origin: filePath, params: { file_path: filePath }, sessionKey: session, callId,
      ...(opts.claim !== undefined ? { agentOpened: opts.claim } : {}),
    } as Parameters<ArbiterClient["classify"]>[0]);
    return (r as { confidentiality?: string }).confidentiality;
  };
  /** One Read call: the proxy records its relay, the agent opens `opened`
   *  (reported by `reporter`), the proxy classifies its result. */
  const readCall = async (filePath: string, opened: string | null, opts: { reporter?: ArbiterClient; asker?: ArbiterClient } = {}): Promise<string | undefined> => {
    const callId = `toolu_ao_${n++}`;
    await proxy.recordCallCommand({ callId, sessionKey: session });
    if (opened !== null) await (opts.reporter ?? guard).labelledLevel({ path: opened, session, agentOpen: true });
    return classifyRead(callId, filePath, opts);
  };
  try {
    // THE GAP CLOSED: the agent resolved `plan.md` in <ws>/vault.
    const rec = await guard.labelledLevel({ path: join(ws, "vault", "plan.md"), session, agentOpen: true });
    assert.equal(rec.level, "no-model");
    assert.equal(rec.recorded, true);
    assert.equal(await readCall("plan.md", join(ws, "vault", "plan.md")), "no-model", "read at the file the kernel saw the agent open");
    assert.equal(await readCall("./plan.md", join(ws, "vault", "plan.md"), { asker: proxy }), "no-model", "on either socket: the record is read, not written");
    assert.equal(await readCall("../vault/plan.md", join(ws, "vault", "plan.md")), "no-model");

    // What does not raise.
    assert.equal(await readCall("plan.md", null), "public", "no open in the call's window (the vault open was before its relay): the fallback");
    const open = await guard.labelledLevel({ path: join(ws, "plan.md"), session, agentOpen: true });
    assert.equal(open.recorded, undefined, "an unlabelled file is not recorded");
    assert.equal(await readCall("plan.md", join(ws, "plan.md")), "public", "the open workspace plan: in clear");
    const claimed = await agent.labelledLevel({ path: join(ws, "vault", "plan.md"), session, agentOpen: true });
    assert.equal(claimed.recorded, undefined, "the data socket's report is a claim: nothing recorded");
    assert.equal(await readCall("plan.md", join(ws, "vault", "plan.md"), { reporter: agent }), "public");
    // A caller cannot name an opened file (it could only raise, but the field is the arbiter's).
    assert.equal(await classifyRead("toolu_never_ran_x", "plan.md", { claim: [{ token: "plan.md", path: join(ws, "vault", "plan.md") }] }), "no-model",
      "an unrelayed call reads the whole session's opens (fail-closed)");
    await proxy.recordCallCommand({ callId: "toolu_relayed_claim", sessionKey: session });
    assert.equal(await classifyRead("toolu_relayed_claim", "plan.md", { claim: [{ token: "plan.md", path: join(ws, "vault", "plan.md") }] }), "public",
      "a caller's agentOpened is dropped: the arbiter's own record decides");

    // Bash: the kernel's start directory of the call's own shell.
    const bash = async (command: string, cwd?: string): Promise<string | undefined> => {
      const callId = `toolu_ao_${n++}`;
      await proxy.recordCallCommand({ callId, command, sessionKey: session });
      await guard.recordExecRoot({ procKey: `sh-${callId}`, ancestors: ["agent-0"], argv: ["/bin/bash", "-c", command], session, callRoot: true, ...(cwd !== undefined ? { cwd } : {}) });
      await proxy.callTaint(callId, { command, session });
      const r = await agent.classify({
        tool: "Bash", value: "# plan\n", boundary: "model_context", origin: command, params: { command }, sessionKey: session, callId,
      } as Parameters<ArbiterClient["classify"]>[0]);
      return (r as { confidentiality?: string }).confidentiality;
    };
    assert.equal(await bash("cat plan.md", join(ws, "vault")), "no-model", "after `cd vault` in the call before, the shell started in <ws>/vault");
    assert.equal(await bash("cat  plan.md", ws), "public", "after `cd ..`: the open workspace plan");
    assert.equal(await bash("cat   plan.md"), "public", "no directory observed: the fallback (the guard's own gate of the shell's open masks it under the guard)");
  } finally {
    guard.close(); proxy.close(); agent.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
