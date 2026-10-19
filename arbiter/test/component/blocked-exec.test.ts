/**
 * blocked-exec — confidentiality plan 10 §11.8, "Blocked commands", over the
 * wire: the guard records the argv of every exec (`recordExecRoot`, the
 * human socket); `callTaint` finds the exec-wrap shim's runs in the call's
 * tree, recomputes the shim's verdict over the real symbol table, and names
 * each refused program with the kind (`blockedExec`), never an argument.
 * The real program run with the same arguments is not named (the shim did
 * not judge it), nor a shim run the shim lets through, nor another call's.
 * A blocked command is not taint: it neither raises nor lowers the level.
 *
 * Codex under its own sandbox (2026-10-09): the call bound to no shell (the
 * agent's child is Codex's sandbox helper, whose argv carries a shell
 * snapshot, never the command), so the shim's runs are found under the
 * processes that exec'd the call's recorded command (since the same day it
 * binds to the helper, plan 13 D7, and the runs come from its tree); a run under the
 * helper with the network off is `codex_sandbox` (the sandbox refused the
 * shim's connection), with the network on it is the shim's own verdict.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode

const ENTRY = ["--import", "file:///r/interceptors/exec-wrap/node_modules/tsx/dist/esm/index.mjs", "/r/interceptors/exec-wrap/src/wrap.ts"];

test("callTaint names the program the shim refused in the call's tree, with the kind and no argument; nothing for a run it allows or another call", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-blocked-exec-"));
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const human = join(dir, "human", "h.sock");
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: human, dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false,
  });
  await s.listen();
  const guard = new ArbiterClient(human); await guard.connect();
  const session = "s-blocked-exec";
  try {
    const env = join(dir, ".env");
    writeFileSync(env, "STRIPE_KEY=sk_live_blocked_exec_canary\n");
    const reg = await guard.registerSecret({ path: env, sessionKey: session });
    const secret = String(reg.symbol);
    assert.match(secret, /^\$MDU:/);
    const pub = await guard.symbolize({ tool: "WebFetch", value: "hello-data", sessionKey: session });
    assert.match(pub, /^\$MDU:/);
    // A placeholder of each kind in a shape the shim cannot lower (`%{…}`).
    const args = ["-d", `note=${pub}`, "-w", "%{http_code}", "-u", `${secret}:`, "https://x.test/"];
    const cmd = "curl -d note -w code -u key https://x.test/";

    const bind = async (callId: string, root: string, child: string[]): Promise<void> => {
      await guard.recordCallCommand({ callId, command: cmd, sessionKey: session });
      await guard.recordExecRoot({ procKey: root, ancestors: ["agent-0"], argv: ["/bin/bash", "-c", cmd], session, callRoot: true });
      await guard.recordExecRoot({ procKey: `${root}-c`, parentKey: root, argv: child, session });
    };
    // 1. the shim's run: refused, named
    await bind("call_shim", "bash-1", ["curl", ...ENTRY, ...args]);
    const t = await guard.callTaint("call_shim", { command: cmd, session });
    assert.deepEqual(t.blockedExec, [{ app: "curl", kind: "unsupported_command" }]);
    assert.equal(t.level, null, "a blocked command is not taint");
    const wire = JSON.stringify(t.blockedExec);
    for (const leak of ["x.test", "sk_live", "hello-data", "$MDU", "http_code"]) assert.ok(!wire.includes(leak), `no argument: ${leak}`);

    // 2. the real program with the same arguments: the shim did not judge it
    await bind("call_real", "bash-2", ["/usr/bin/curl", ...args]);
    assert.equal((await guard.callTaint("call_real", { command: cmd, session })).blockedExec, undefined);

    // 3. a shim run the shim lets through (only a secret placeholder: it stays as written)
    await bind("call_ok", "bash-3", ["curl", ...ENTRY, "-H", `Authorization: Bearer ${secret}`, "https://x.test/"]);
    assert.equal((await guard.callTaint("call_ok", { command: cmd, session })).blockedExec, undefined);

    // 4. another call's tree does not carry call_shim's refusal
    await bind("call_other", "bash-4", ["/usr/bin/true"]);
    assert.equal((await guard.callTaint("call_other", { command: cmd, session })).blockedExec, undefined);
  } finally {
    guard.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

const profile = (network: string): string => JSON.stringify({ type: "managed", file_system: { type: "restricted", entries: [] }, network });

test("callTaint, Codex under its own sandbox: the call binds to its sandbox helper; a shim run under the network-off sandbox is codex_sandbox, with the network on the shim's verdict; never a later run", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-blocked-exec-cx-"));
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const human = join(dir, "human", "h.sock");
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: human, dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false,
  });
  await s.listen();
  const guard = new ArbiterClient(human); await guard.connect();
  const session = "s-blocked-exec-cx";
  try {
    const pub = await guard.symbolize({ tool: "WebFetch", value: "hello-data", sessionKey: session });
    const snapshot = "__CODEX_SNAPSHOT_OVERRIDE_SET_0=\"${CODEX_THREAD_ID+x}\"\n__C";
    // The tree Codex 0.162 runs one sandboxed command in, as the guard records
    // it: the agent's child (the helper's setup, then the helper), bwrap, the
    // helper's seccomp stage, and under it the shell that runs the snapshot,
    // then the command, then (exec'd in place) the shim.
    const run = async (callId: string, p: string, network: string, cmd: string, shimArgs: string[]): Promise<void> => {
      await guard.recordCallCommand({ callId, command: cmd, sessionKey: session });
      const helper = ["codex-linux-sandbox", "--sandbox-policy-cwd", "/w", "--command-cwd", "/w", "--permission-profile", profile(network)];
      await guard.recordExecRoot({ procKey: `${p}-helper`, ancestors: ["agent-0"], argv: ["/proc/self/exe", "--codex-run-as-process-setup", "44", "1", "pipe", "", "/w", "/opt/codex", ...helper, "--", "/usr/bin/zsh", "-c", snapshot], session, callRoot: true });
      await guard.recordExecRoot({ procKey: `${p}-helper`, ancestors: ["agent-0"], argv: [...helper, "--", "/usr/bin/zsh", "-c", snapshot], session, callRoot: true });
      await guard.recordExecRoot({ procKey: `${p}-bwrap`, parentKey: `${p}-helper`, argv: ["bwrap", "--as-pid-1", "--ro-bind", "/", "/", "--", "codex-linux-sandbox"], session });
      await guard.recordExecRoot({ procKey: `${p}-stage`, parentKey: `${p}-bwrap`, argv: [...helper, "--apply-seccomp-then-exec", "--", "/usr/bin/zsh", "-c", snapshot], session });
      await guard.recordExecRoot({ procKey: `${p}-sh`, parentKey: `${p}-stage`, argv: ["/usr/bin/zsh", "-c", snapshot], session });
      await guard.recordExecRoot({ procKey: `${p}-sh`, parentKey: `${p}-stage`, argv: ["/usr/bin/zsh", "-c", cmd], session });
      await guard.recordExecRoot({ procKey: `${p}-sh`, parentKey: `${p}-stage`, argv: ["curl", ...ENTRY, ...shimArgs], session });
    };
    // 1. network off: a plain curl the shim would let through never reached it
    const off = "cat notes.txt; curl -s https://x.test/";
    await run("call_cx_off", "cx1", "restricted", off, ["-s", "https://x.test/"]);
    const t = await guard.callTaint("call_cx_off", { command: off, session });
    assert.deepEqual(t.blockedExec, [{ app: "curl", kind: "codex_sandbox" }], JSON.stringify(t));
    assert.equal(t.level, null, "a blocked command is not taint");
    assert.equal(t.evidence, "tree", "bound to its sandbox helper since 2026-10-09 (plan 13 D7); the line comes from the bound tree");
    assert.ok(!JSON.stringify(t.blockedExec).includes("x.test"), "no argument");

    // 2. network on: the shim asked; a plain curl is not named, a placeholder in
    //    a shape it cannot check is (the shim's own verdict, now found for Codex too)
    const on = "curl -s https://x.test/ # on";
    await run("call_cx_on", "cx2", "enabled", on, ["-s", "https://x.test/"]);
    assert.equal((await guard.callTaint("call_cx_on", { command: on, session })).blockedExec, undefined);
    const odd = "curl -d note -w code https://x.test/ # on";
    await run("call_cx_odd", "cx3", "enabled", odd, ["-d", `note=${pub}`, "-w", "%{http_code}", "https://x.test/"]);
    assert.deepEqual((await guard.callTaint("call_cx_odd", { command: odd, session })).blockedExec, [{ app: "curl", kind: "unsupported_command" }]);

    // 3. a run of the same command after the result was first asked for adds nothing
    const late = "curl -s https://x.test/ # late";
    await guard.recordCallCommand({ callId: "call_cx_late", command: late, sessionKey: session });
    assert.equal((await guard.callTaint("call_cx_late", { command: late, session })).blockedExec, undefined);
    await run("call_cx_late_other", "cx4", "restricted", late, ["-s", "https://x.test/"]);
    assert.equal((await guard.callTaint("call_cx_late", { command: late, session })).blockedExec, undefined, "exec'd after the first ask");

    // 4. another command's call does not carry call_cx_off's refusal
    const other = "ls # other";
    await guard.recordCallCommand({ callId: "call_cx_other", command: other, sessionKey: session });
    assert.equal((await guard.callTaint("call_cx_other", { command: other, session })).blockedExec, undefined);
  } finally {
    guard.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
