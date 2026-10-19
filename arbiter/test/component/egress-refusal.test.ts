/**
 * egress-refusal — confidentiality plan 10 §11.8, "Refused connections",
 * over the wire: the net-proxy reports a refused connection by process and
 * kind (`recordEgressRefusal`, an attested report), and `callTaint` folds it
 * into the tool call whose tree holds the process (`refusedEgress`: the
 * program and the kind, never a host), so the model proxies can say the
 * connection was refused. From the data socket nothing is recorded; an
 * unknown kind is refused; a refusal never lowers or raises the taint. A
 * refusal tied to no process (`procKeys: []`, `unattributed`, 2026-10-17)
 * folds into the call that was running then, by kind only.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

test("a refused connection folds into its call's callTaint as {app, kind}; the data socket records nothing; an unknown kind is refused", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-egress-refusal-"));
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const human = join(dir, "human", "h.sock");
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: human, dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false,
  });
  await s.listen();
  const guard = new ArbiterClient(human); await guard.connect();
  const agent = new ArbiterClient(join(dir, "a.sock")); await agent.connect();
  const session = "s-egress-refusal";
  try {
    const bind = async (callId: string, command: string, root: string): Promise<void> => {
      await guard.recordCallCommand({ callId, command, sessionKey: session });
      await guard.recordExecRoot({ procKey: root, ancestors: ["agent-0"], argv: ["/bin/bash", "-c", command], session, callRoot: true });
      await guard.recordExecRoot({ procKey: `${root}-curl`, parentKey: root, argv: ["/usr/bin/curl", "https://h.example"], session });
    };
    await bind("call_1", "curl -s https://h.example", "bash-1");
    assert.deepEqual(await guard.recordEgressRefusal({ procKeys: ["bash-1-curl"], kind: "tainted", sessionKey: session }), { recorded: true });
    const t = await guard.callTaint("call_1", { command: "curl -s https://h.example", session });
    assert.deepEqual(t.refusedEgress, [{ app: "curl", kind: "tainted" }]);
    assert.equal(t.level, null, "a refusal is not taint");
    assert.ok(!JSON.stringify(t).includes("h.example"), "never a host");
    // The egress proxy's this-machine refusal (net-proxy blocked-destinations.ts) is a kind of its own.
    assert.deepEqual(await guard.recordEgressRefusal({ procKeys: ["bash-1-curl"], kind: "this-machine", sessionKey: session }), { recorded: true });
    assert.deepEqual((await guard.callTaint("call_1", { command: "curl -s https://h.example", session })).refusedEgress, [{ app: "curl", kind: "tainted" }, { app: "curl", kind: "this-machine" }]);
    // A placeholder as the destination (2026-10-17) is a kind of its own too.
    assert.deepEqual(await guard.recordEgressRefusal({ procKeys: ["bash-1-curl"], kind: "symbol-destination", sessionKey: session }), { recorded: true });
    assert.deepEqual((await guard.callTaint("call_1", { command: "curl -s https://h.example", session })).refusedEgress?.map((r) => r.kind), ["tainted", "this-machine", "symbol-destination"]);

    // from the data socket: nothing recorded
    await bind("call_2", "curl -s https://h2.example", "bash-2");
    const forged = await agent.recordEgressRefusal({ procKeys: ["bash-2-curl"], kind: "tainted", sessionKey: session });
    assert.equal(forged.recorded, false);
    assert.equal((await guard.callTaint("call_2", { command: "curl -s https://h2.example", session })).refusedEgress, undefined);

    // an unknown kind (or no process) is refused outright
    await assert.rejects(guard.recordEgressRefusal({ procKeys: ["bash-1-curl"], kind: "evil.example", sessionKey: session }));
    await assert.rejects(guard.recordEgressRefusal({ procKeys: [], kind: "tainted", sessionKey: session }));

    // another call's tree does not carry it
    await bind("call_3", "curl -s https://h3.example", "bash-3");
    assert.equal((await guard.callTaint("call_3", { command: "curl -s https://h3.example", session })).refusedEgress, undefined);
  } finally {
    guard.close(); agent.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a refusal no process is tied to (procKeys: [], unattributed): folded into the calls running then as {app: \"\", kind, unattributed}; the data socket records nothing", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-egress-refusal-unattr-"));
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const human = join(dir, "human", "h.sock");
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: human, dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false,
  });
  await s.listen();
  const guard = new ArbiterClient(human); await guard.connect();
  const agent = new ArbiterClient(join(dir, "a.sock")); await agent.connect();
  const session = "s-egress-refusal-unattr";
  try {
    // Nothing running yet: nothing to tie the note to, nothing recorded.
    assert.equal((await guard.recordEgressRefusal({ procKeys: [], kind: "unattributed", sessionKey: session, unattributed: true })).recorded, false);

    const command = "python3 upload.py";
    await guard.recordCallCommand({ callId: "call_u", command, sessionKey: session });
    await guard.recordExecRoot({ procKey: "bash-u", ancestors: ["agent-0"], argv: ["/bin/bash", "-c", command], session, callRoot: true });
    // From the data socket: unattested, nothing recorded.
    assert.equal((await agent.recordEgressRefusal({ procKeys: [], kind: "unattributed", sessionKey: session, unattributed: true })).recorded, false);
    assert.deepEqual(await guard.recordEgressRefusal({ procKeys: [], kind: "unattributed", sessionKey: session, unattributed: true }), { recorded: true });
    assert.equal((await guard.recordEgressRefusal({ procKeys: [], kind: "unattributed", sessionKey: session, unattributed: true })).recorded, false, "the same kind again while the same call runs: one note");
    const t = await guard.callTaint("call_u", { command, session });
    assert.deepEqual(t.refusedEgress, [{ app: "", kind: "unattributed", unattributed: true }]);
    assert.equal(t.level, null, "a refusal is not taint");
    // procKeys: [] without the flag is still refused outright.
    await assert.rejects(guard.recordEgressRefusal({ procKeys: [], kind: "tainted", sessionKey: session }));
    // After the call's result was asked for, a refusal is not this call's.
    assert.equal((await guard.recordEgressRefusal({ procKeys: [], kind: "this-machine", sessionKey: session, unattributed: true })).recorded, false);
    assert.deepEqual((await guard.callTaint("call_u", { command, session })).refusedEgress, [{ app: "", kind: "unattributed", unattributed: true }], "stable on a later ask");
  } finally {
    guard.close(); agent.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
