/**
 * compound-listing — a folder's names beside another command
 * (docs/design/confidentiality/folder-listing-compound.md), over the REAL
 * components: a real ArbiterServer in `secrets` whose policy labels the
 * workspace's `bank/` no-model, both model proxies' production adapters, the
 * guard's records on the human socket (the shell, its `ls` and its other
 * program), and a real `ls`.
 *
 * demo-c2's command, `tools/mail list; ls mail/inbox bank`, came back as one
 * symbol because it names the labelled `bank/`. Proves:
 *   1. Claude Code and Codex: the mail list and the listing reach the model
 *      as printed, with the `listing:` line naming the operands as written;
 *   2. it holds across turns after the folder changes (L9);
 *   3. fail closed, masked whole: a part that names a statement (`cat
 *      bank/x.md; ls bank`), the listing in the middle, `cd bank && ls`, a
 *      statement line in the other part's output from a tree that read it raw,
 *      an `ls` the guard did not see run (a shell function standing in for
 *      it), a Codex `workdir` inside `bank/`;
 *   4. THE ORACLE: no statement byte is in any request to the model.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { rewriteRequest } from "../../interceptors/anthropic-proxy/src/rewrite-request.js";
import type { MessagesRequest } from "../../interceptors/anthropic-proxy/src/messages-types.js";
import { ArbiterClientAdapter as OpenAiAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { rewriteRequest as rewriteOpenAi } from "../../interceptors/openai-proxy/src/rewrite-request.js";
import type { ResponsesRequest } from "../../interceptors/openai-proxy/src/responses-types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const ACCT = "DEMO-ACCT-000555";
const STATEMENT = `# Maple Bank statement\nAccount ${ACCT}\nBalance 4,210.00\n`;
const MAIL = "1  Dentist        Appointment reminder\n2  Book club      Next month's book\n3  Jo Park        Q3 filing\n";
const DEMO = "tools/mail list; ls mail/inbox bank";
const SYMBOL_RE = /^\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\]/;
const HEAD = "Chunk ID: 5e1f\nWall time: 0.0123 seconds\nProcess exited with code 0\nOriginal token count: 12\nOutput:\n";

test("secrets: `tools/mail list; ls mail/inbox bank` reaches Claude Code and Codex with the listing line, across turns; a part naming a statement, the listing in the middle, cd, a raw read, an unseen ls and a workdir in bank/ stay one symbol; no statement byte reaches the model", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-compound-listing-"));
  const ws = join(tmp, "ws");
  for (const d of ["bank", "mail/inbox", "tools"]) mkdirSync(join(ws, d), { recursive: true });
  writeFileSync(join(ws, "bank", "statement-2026-09.md"), STATEMENT);
  for (const f of ["1-dentist.md", "2-book-club.md", "3-park-tax.md"]) writeFileSync(join(ws, "mail", "inbox", f), "x\n");
  writeFileSync(join(ws, "tools", "mail"), "#!/bin/sh\n", { mode: 0o755 });
  const sock = join(tmp, "a.sock");
  const human = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "db.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: join(ws, "bank"), level: "no-model", recursive: true }] } as never,
  });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string) => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const guard = await open(human);
  const h1 = await open(human);
  const h2 = await open(human);
  const claude = new ArbiterClientAdapter(await open(sock), h1);
  const codex = new OpenAiAdapter(await open(sock), h2);
  const session = "s-compound";
  const sent: string[] = [];
  let n = 0;
  const ls = (...args: string[]) => execFileSync("ls", args, { cwd: ws, encoding: "utf8", env: { PATH: process.env["PATH"] ?? "/usr/bin:/bin", LC_ALL: "C" } });
  /** The proxy's record of the command, the guard's record of the shell and
   *  of each program it ran (`children`), then `before`. */
  const bind = async (callId: string, command: string, shell: string[], children: string[][], before?: (root: string) => Promise<void>) => {
    await h1.recordCallCommand({ callId, command, sessionKey: session });
    const root = `sh-${++n}`;
    await guard.recordExecRoot({ procKey: root, ancestors: ["agent-0"], argv: shell, session, callRoot: true, cwd: ws });
    for (const [i, argv] of children.entries()) await guard.recordExecRoot({ procKey: `${root}-${i}`, parentKey: root, argv, session });
    if (before) await before(root);
  };
  const bashReq = (id: string, command: string, output: string): MessagesRequest => ({ model: "claude-test", messages: [
    { role: "user", content: "Go through the emails and take care of them; my statements are in bank/." },
    { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command } }] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: output }] },
  ] });
  const bash = async (command: string, output: string, o: { children?: string[][]; before?: (root: string) => Promise<void>; id?: string; again?: true } = {}): Promise<string> => {
    const id = o.id ?? `tu_${++n}`;
    if (o.again !== true) await bind(id, command, ["/bin/bash", "-c", command], o.children ?? [["tools/mail", "list"], ["ls", "mail/inbox", "bank"]], o.before);
    const out = await rewriteRequest(bashReq(id, command, output), { arbiter: claude, sessionKey: session });
    sent.push(JSON.stringify(out.request));
    return String((out.request.messages[2]!.content as Array<{ content: unknown }>)[0]!.content);
  };
  const exec = async (cmd: string, output: string, extra: Record<string, unknown> = {}): Promise<string> => {
    const id = `call_${++n}`;
    await bind(id, cmd, ["/bin/bash", "-lc", cmd], [["tools/mail", "list"], ["ls", "mail/inbox", "bank"]]);
    const req = { model: "gpt-test", input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "Go through my inbox." }] },
      { type: "function_call", call_id: id, name: "exec_command", arguments: JSON.stringify({ cmd, workdir: ws, ...extra }) },
      { type: "function_call_output", call_id: id, output },
    ] } as unknown as ResponsesRequest;
    const out = await rewriteOpenAi(req, { arbiter: codex, sessionKey: session });
    sent.push(JSON.stringify(out.request));
    return String((out.request.input as Array<{ type: string; output?: unknown }>).find((x) => x.type === "function_call_output")!.output);
  };
  const LINE = "[mandu:secret] listing: the last lines of this output are the names in mail/inbox, bank as ls printed them";
  try {
    // 1. the lift
    const listing = ls("mail/inbox", "bank");
    const output = `${MAIL}${listing}`;
    const got = await bash(DEMO, output.replace(/\n$/, ""), { id: "tu_demo" });
    assert.ok(got.startsWith(output.replace(/\n$/, "")), `the mail list and the listing as printed: ${got}`);
    assert.ok(got.includes(LINE), got);
    const cx = await exec(DEMO, `${HEAD}${output}`);
    assert.ok(cx.startsWith(`${HEAD}${output}`), `Codex: ${cx}`);
    assert.ok(cx.includes(LINE), cx);

    // 2. across turns: the folder changed (the mail tool renamed a message)
    renameSync(join(ws, "mail", "inbox", "3-park-tax.md"), join(ws, "mail", "inbox", "3-park-tax.seen.md"));
    const again = await bash(DEMO, output.replace(/\n$/, ""), { id: "tu_demo", again: true });
    assert.ok(again.startsWith(output.replace(/\n$/, "")), `turn 2, the history re-sent: ${again}`);

    // 3. fail closed
    const cases: Array<[string, string, string, string[][], ((root: string) => Promise<void>)?]> = [
      ["a part naming a statement", "cat bank/statement-2026-09.md; ls bank", `${STATEMENT}${ls("bank")}`, [["cat", "bank/statement-2026-09.md"], ["ls", "bank"]]],
      ["the listing in the middle", "tools/mail list; ls bank; tools/mail list", `${MAIL}${ls("bank")}${MAIL}`, [["tools/mail", "list"], ["ls", "bank"], ["tools/mail", "list"]]],
      ["cd before it", "cd bank && ls", ls("bank"), [["ls"]]],
      ["an ls the guard did not see run", DEMO, output, [["tools/mail", "list"]]],
      ["a tree that read a statement raw", DEMO, `Account ${ACCT}\n${listing}`, [["tools/mail", "list"], ["ls", "mail/inbox", "bank"]], async (root) => {
        await guard.taintProcessSecret({ procKey: `${root}-0`, path: join(ws, "bank", "statement-2026-09.md"), level: "no-model", app: "mail", session });
      }],
    ];
    for (const [why, command, out, children, before] of cases) {
      const t = await bash(command, out, { children, ...(before ? { before } : {}) });
      assert.match(t, SYMBOL_RE, `${why}: ${t}`);
      assert.ok(!t.includes("listing:"), why);
    }
    const inBank = await exec(DEMO, `${HEAD}${ls("mail/inbox", "bank")}`, { workdir: join(ws, "bank") });
    assert.ok(!inBank.includes("listing:"), `a Codex workdir inside bank/: ${inBank}`);

    // 4. THE ORACLE
    for (const s of sent) {
      assert.ok(!s.includes(ACCT), "CONFIDENTIALITY VIOLATION: a statement's account number reached the model");
      assert.ok(!s.includes("Balance 4,210.00"), "CONFIDENTIALITY VIOLATION: a statement's line reached the model");
    }
  } finally {
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
