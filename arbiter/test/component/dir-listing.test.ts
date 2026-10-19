/**
 * dir-listing.test.ts — "A folder's names" (plan 10 §11.8, 2026-10-17) over
 * the real IPC: `callTaint` answers `twinOf` (the folders listed) with
 * `dirListing` for a shell result that is exactly a plain `ls` of the folders
 * the command names, read where the call's shell started, and ONLY on the
 * evidence the twin rules need (the recorder bound the call's tree and
 * nothing in it read a secret raw). No record, a raw read in the tree, an
 * `ls -l`, a chain, a byte no name gives, a command other than the one the
 * proxy recorded, or the axis off: no answer.
 *
 * Mandu-new test. A real ArbiterServer on a temp socket, the real client,
 * real folders.
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

const LISTING = "bank/:\nstatement-2026-09.md\n\nmail/inbox:\n1-dentist.md\n2-book-club.md";
const COMMAND = "ls mail/inbox bank/";

async function stack(confidentiality: boolean) {
  const dir = mkdtempSync(join(tmpdir(), "mandu-dir-listing-"));
  const ws = join(dir, "ws");
  mkdirSync(join(ws, "bank"), { recursive: true });
  mkdirSync(join(ws, "mail", "inbox"), { recursive: true });
  writeFileSync(join(ws, "bank", "statement-2026-09.md"), "Account DEMO-ACCT-000123\n");
  writeFileSync(join(ws, "mail", "inbox", "1-dentist.md"), "Tuesday 9:30?\n");
  writeFileSync(join(ws, "mail", "inbox", "2-book-club.md"), "Next month's book\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${join(ws, "bank")}\n    level: no-model\n    recursive: true\n`);
  const s = new ArbiterServer({ socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), policyPath: policy, log: () => {}, confidentiality, integrity: false });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's and the proxy's channel (plan 13 D9)
  await c.connect();
  let n = 0;
  return {
    ws, c,
    /** The proxy records the command, the guard reports the agent's shell
     *  for it (with the kernel's directory, or none); returns the call id. */
    async bound(command: string, cwd: string | null, session: string, recorded: string = command): Promise<string> {
      const callId = `call_dl_${n++}`;
      await c.recordCallCommand({ callId, command: recorded, sessionKey: session });
      await c.recordExecRoot({ procKey: `sh-${callId}`, ancestors: ["agent-dl-0"], argv: ["/bin/bash", "-c", recorded], session, callRoot: true, ...(cwd !== null ? { cwd } : {}) });
      return callId;
    },
    done: async () => { c.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); },
  };
}

test("the guard bound `ls mail/inbox bank/` and nothing in its tree read a secret: callTaint names both folders with dirListing", async () => {
  const k = await stack(true);
  try {
    const id = await k.bound(COMMAND, k.ws, "dl");
    const t = await k.c.callTaint(id, { command: COMMAND, session: "dl", output: LISTING });
    assert.notEqual(t.root, null);
    assert.equal(t.level, null);
    assert.deepEqual(t.twinOf, [join(k.ws, "bank"), join(k.ws, "mail", "inbox")]);
    assert.equal(t.dirListing, true);
    assert.equal(t.twinKeys, undefined);
    assert.equal(t.twinWhole, undefined);
    // a folder created since: the listing must hold it too
    writeFileSync(join(k.ws, "bank", "statement-2026-10.md"), "Account DEMO-ACCT-000123\n");
    const id2 = await k.bound(COMMAND, k.ws, "dl");
    assert.equal((await k.c.callTaint(id2, { command: COMMAND, session: "dl", output: LISTING })).twinOf, undefined, "the folder holds a name the output lacks");
    const id3 = await k.bound(COMMAND, k.ws, "dl");
    const now = LISTING.replace("statement-2026-09.md", "statement-2026-09.md\nstatement-2026-10.md");
    assert.equal((await k.c.callTaint(id3, { command: COMMAND, session: "dl", output: now })).dirListing, true);
  } finally { await k.done(); }
});

test("no record, no start directory, a raw read in the tree, ls -l, a chain, an extra line, another recorded command, the axis off: no dirListing (the mask stands)", async () => {
  const k = await stack(true);
  try {
    // no root recorded for the call: the text alone is not evidence
    const none = await k.c.callTaint("call_dl_noroot", { command: COMMAND, session: "dn", output: LISTING });
    assert.equal(none.twinOf, undefined);
    // the shell's directory unknown: a relative operand is read nowhere
    const nocwd = await k.bound(COMMAND, null, "dc");
    assert.equal((await k.c.callTaint(nocwd, { command: COMMAND, session: "dc", output: LISTING })).twinOf, undefined);
    // the misses
    const misses: Array<[string, string, string]> = [
      ["ls -l", "ls -l bank", "total 4\n-rw-r--r-- 1 u u 25 Oct 17 09:00 statement-2026-09.md"],
      ["ls -la, the names alone", "ls -la bank", "statement-2026-09.md"],
      ["a chain with cat", "ls bank && cat bank/statement-2026-09.md", "statement-2026-09.md\nAccount DEMO-ACCT-000123"],
      ["a chain, the listing alone", "ls bank; cat bank/statement-2026-09.md", "statement-2026-09.md"],
      ["a pipe", "ls bank | head", "statement-2026-09.md"],
      ["an extra line", "ls bank", "statement-2026-09.md\nAccount DEMO-ACCT-000123"],
    ];
    for (const [why, cmd, out] of misses) {
      const id = await k.bound(cmd, k.ws, `dm-${why}`);
      const t = await k.c.callTaint(id, { command: cmd, session: `dm-${why}`, output: out });
      assert.equal(t.twinOf, undefined, why);
      assert.equal(t.dirListing, undefined, why);
    }
    // the echoed command is not the one the proxy recorded for the call
    const other = await k.bound(COMMAND, k.ws, "do", "ls bank && cat bank/statement-2026-09.md");
    assert.equal((await k.c.callTaint(other, { command: COMMAND, session: "do", output: LISTING })).twinOf, undefined);
    // a process in the tree read a secret RAW
    const raw = await k.bound(COMMAND, k.ws, "dr");
    await k.c.processLineage({ childKey: `sh-${raw}-child`, parentKey: `sh-${raw}` });
    await k.c.taintProcessSecret({ procKey: `sh-${raw}-child`, path: join(k.ws, "bank", "statement-2026-09.md"), level: "no-model", app: "cat", session: "dr" });
    const tainted = await k.c.callTaint(raw, { command: COMMAND, session: "dr", output: LISTING });
    assert.equal(tainted.level, "no-model");
    assert.equal(tainted.twinOf, undefined);
  } finally { await k.done(); }
  const off = await stack(false);
  try {
    const id = await off.bound(COMMAND, off.ws, "doff");
    const t = await off.c.callTaint(id, { command: COMMAND, session: "doff", output: LISTING });
    assert.equal(t.twinOf, undefined);
    assert.equal(t.dirListing, undefined);
  } finally { await off.done(); }
});
