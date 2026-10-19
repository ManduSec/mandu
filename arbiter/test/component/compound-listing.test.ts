/**
 * compound-listing.test.ts — the classify op's offer of a folder's names
 * beside another command over a real ArbiterServer
 * (docs/design/confidentiality/folder-listing-compound.md §2, L0-L9).
 *
 * Offered: `tools/mail list; ls mail/inbox bank` on a bound clean tree with
 * the guard's record of its `ls`. Not offered: a raw read, an unbound call,
 * nothing recorded, a recorded command that differs, an `ls` the guard did
 * not see, two `ls`, a part naming a labelled file (or the folder through
 * git), a Codex guard start directory that differs from its `workdir`, a
 * `tty`, a registered value in the output, an output whose last lines are
 * not the listing.
 *
 * Run: npm run test:component
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const KEY = "sk_test_51Compound7Qm2Xv9Lk4Tz8Wp3";
const MAIL = "1  Dentist  Appointment reminder\n";
const DEMO = "tools/mail list; ls mail/inbox bank";
type Offer = { text: string; spans: unknown[]; listing?: { operands: string[]; part: string } };

async function stack() {
  const dir = mkdtempSync(join(tmpdir(), "mandu-compound-"));
  const ws = join(dir, "ws");
  for (const d of ["bank", "mail/inbox", "tools"]) mkdirSync(join(ws, d), { recursive: true });
  writeFileSync(join(ws, "bank", "statement.md"), "Account DEMO-1\n");
  writeFileSync(join(ws, "mail", "inbox", "1.md"), "x\n");
  writeFileSync(join(ws, ".env"), `STRIPE_SECRET_KEY=${KEY}\n`);
  const human = join(dir, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: human, dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: join(ws, "bank"), level: "no-model", recursive: true }] } as never,
  });
  await server.listen();
  const c = new ArbiterClient(human);
  await c.connect();
  const session = "cl";
  const reg = await c.registerSecret({ path: join(ws, ".env"), home: dir, sessionKey: session });
  assert.ok(reg.symbol, reg.reason);
  const LISTING = "bank:\nstatement.md\n\nmail/inbox:\n1.md\n";
  let n = 0;
  const call = async (command: string, output: string, o: { record?: string | null; bound?: boolean; children?: string[][]; before?: (root: string) => Promise<void>; params?: Record<string, unknown>; codex?: boolean; cwd?: string } = {}): Promise<Offer | undefined> => {
    const callId = `call_${++n}`;
    const root = `sh-${n}`;
    if (o.record !== null) await c.recordCallCommand({ callId, command: o.record ?? command, sessionKey: session });
    if (o.bound !== false) {
      await c.recordExecRoot({ procKey: root, ancestors: ["agent-0"], argv: ["/bin/bash", "-c", command], session, callRoot: true, cwd: o.cwd ?? ws });
      for (const [i, argv] of (o.children ?? [["tools/mail", "list"], ["ls", "mail/inbox", "bank"]]).entries()) await c.recordExecRoot({ procKey: `${root}-${i}`, parentKey: root, argv, session });
    }
    if (o.before) await o.before(root);
    await c.callTaint(callId, { command, session });
    const v = await c.classify(o.codex
      ? { tool: "exec_command", value: output, boundary: "model_context", origin: command, params: { cmd: command, workdir: ws, ...(o.params ?? {}) }, sessionKey: session, treeCallId: callId } as never
      : { tool: "Bash", value: output, boundary: "model_context", origin: command, params: { command, ...(o.params ?? {}) }, sessionKey: session, callId }) as { confidentiality?: string; pathRelease?: Offer };
    return v.pathRelease;
  };
  return { c, ws, call, LISTING, session, done: async () => { c.close(); await server.close(); rmSync(dir, { recursive: true, force: true }); } };
}

test("offered: the mail list beside the listing, the operands as written, the listing last", async () => {
  const k = await stack();
  try {
    const out = `${MAIL}${k.LISTING}`;
    assert.deepEqual(await k.call(DEMO, out), { text: out, spans: [], listing: { operands: ["mail/inbox", "bank"], part: "last" } });
    const first = `statement.md\n${MAIL}`;
    assert.deepEqual(await k.call("ls bank && tools/mail list", first, { children: [["ls", "bank"], ["tools/mail", "list"]] }), { text: first, spans: [], listing: { operands: ["bank"], part: "first" } });
  } finally { await k.done(); }
});

test("not offered: the evidence (L0, L7, L8)", async () => {
  const k = await stack();
  const out = `${MAIL}${k.LISTING}`;
  try {
    assert.equal(await k.call(DEMO, out, { before: async (root) => {
      await k.c.taintProcessSecret({ procKey: `${root}-0`, path: join(k.ws, "bank", "statement.md"), level: "no-model", app: "mail", session: k.session });
    } }), undefined, "a raw read");
    assert.equal(await k.call(DEMO, out, { bound: false }), undefined, "an unbound call");
    assert.equal(await k.call(DEMO, out, { record: null }), undefined, "nothing recorded");
    assert.equal(await k.call(DEMO, out, { record: "tools/mail list; ls mail" }), undefined, "a recorded command that differs");
    assert.equal(await k.call(DEMO, out, { children: [["tools/mail", "list"]] }), undefined, "an ls the guard did not see run");
    assert.equal(await k.call(DEMO, out, { children: [["tools/mail", "list"], ["ls", "mail/inbox", "bank"], ["ls", "bank"]] }), undefined, "two ls");
    assert.equal(await k.call(DEMO, out, { children: [["tools/mail", "list"], ["ls", "-l", "mail/inbox", "bank"]] }), undefined, "an ls run with other options");
  } finally { await k.done(); }
});

test("not offered: the other parts (L3, L4), Codex's base and tty (L6), the content (R7, L5)", async () => {
  const k = await stack();
  const out = `${MAIL}${k.LISTING}`;
  try {
    assert.equal(await k.call("cat bank/statement.md; ls mail/inbox bank", out, { children: [["cat", "bank/statement.md"], ["ls", "mail/inbox", "bank"]] }), undefined, "a part naming a statement");
    assert.equal(await k.call("git -C bank log; ls mail/inbox bank", out, { children: [["git", "-C", "bank", "log"], ["ls", "mail/inbox", "bank"]] }), undefined, "a part reaching the folder through git");
    assert.equal(await k.call("tools/mail list; ls mail/inbox bank", out, { params: { file_path: join(k.ws, "bank", "statement.md") } }), undefined, "a typed path naming a statement");
    assert.equal(await k.call("echo hi; ls mail/inbox bank", out, { children: [["echo", "hi"], ["ls", "mail/inbox", "bank"]] }), undefined, "a builtin");
    assert.ok(await k.call(DEMO, out, { codex: true }), "Codex: offered with its workdir the guard's start directory");
    assert.equal(await k.call(DEMO, out, { codex: true, params: { workdir: join(k.ws, "bank") } }), undefined, "Codex: a workdir that differs from the guard's start directory");
    assert.equal(await k.call(DEMO, out, { codex: true, params: { tty: true } }), undefined, "Codex: tty");
    assert.equal(await k.call(DEMO, `${MAIL}key ${KEY}\n${k.LISTING}`), undefined, "a registered value in the other part");
    assert.equal(await k.call(DEMO, `${MAIL}old Zx9Kp2mWq8Lr5Tv3Nc7Bd1\n${k.LISTING}`), undefined, "a bare token that reads as a credential");
    assert.equal(await k.call(DEMO, `${k.LISTING}${MAIL}`), undefined, "the listing not where its part is");
    assert.equal(await k.call(DEMO, `${MAIL}${k.LISTING}extra\n`), undefined, "a line after the listing");
  } finally { await k.done(); }
});
