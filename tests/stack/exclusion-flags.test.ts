/**
 * exclusion-flags — a search that excludes a labelled folder
 * (docs/design/confidentiality/exclusion-flags.md), through the PRODUCTION
 * wiring: both model proxies' adapters over a real ArbiterServer in
 * `secrets`, `bank/` labelled no-model, the guard's records on the human
 * socket.
 *
 * demo-c2's command, `grep -rIl -i park . --exclude-dir=bank`, used to come
 * back as one symbol because the word `--exclude-dir=bank` names the
 * labelled folder. Proves:
 *   1. Claude Code and Codex: its output (the matching file names) reaches the
 *      model as grep printed it;
 *   2. fail closed, masked whole: the two-word form `--exclude-dir bank`, a
 *      statement named beside the flag, `--exclude=bank`;
 *   3. THE ORACLE: no statement byte is in any request to the model.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
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

const ACCT = "DEMO-ACCT-000777";
const STATEMENT = `# Maple Bank statement\nAccount ${ACCT}\nPayee: Park Tax LLC\n`;
const HITS = "./mail/inbox/3-park-tax.md\n";
const DEMO = "grep -rIl -i park . --exclude-dir=bank";
const SYMBOL_RE = /^\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\]/;

test("secrets: demo-c2's grep that excludes the labelled folder reaches Claude Code and Codex as printed; the two-word form, a statement beside it and --exclude= stay one symbol; no statement byte reaches the model", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-exclusion-"));
  const ws = join(tmp, "ws");
  mkdirSync(join(ws, "bank"), { recursive: true });
  mkdirSync(join(ws, "mail", "inbox"), { recursive: true });
  writeFileSync(join(ws, "bank", "statement-2026-09.md"), STATEMENT);
  writeFileSync(join(ws, "mail", "inbox", "3-park-tax.md"), "Please upload your statement for Park Tax.\n");
  const sock = join(tmp, "a.sock");
  const human = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "db.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: join(ws, "bank"), level: "no-model", recursive: true }] } as never,
  });
  await server.listen();
  const guard = new ArbiterClient(human); await guard.connect();
  const h1 = new ArbiterClient(human); await h1.connect();
  const d1 = new ArbiterClient(sock); await d1.connect();
  const h2 = new ArbiterClient(human); await h2.connect();
  const d2 = new ArbiterClient(sock); await d2.connect();
  const claude = new ArbiterClientAdapter(d1, h1);
  const codex = new OpenAiAdapter(d2, h2);
  const session = "s-exclusion";
  const sent: string[] = [];
  let n = 0;
  const bind = async (callId: string, command: string, argv: string[]) => {
    await h1.recordCallCommand({ callId, command, sessionKey: session });
    await guard.recordExecRoot({ procKey: `sh-${++n}`, ancestors: ["agent-0"], argv, session, callRoot: true, cwd: ws });
  };
  const bash = async (command: string, output: string): Promise<string> => {
    const id = `tu_${++n}`;
    await bind(id, command, ["/bin/bash", "-c", command]);
    const req: MessagesRequest = { model: "claude-test", messages: [
      { role: "user", content: "Go through my inbox; my statements are in bank/." },
      { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: output }] },
    ] };
    const out = await rewriteRequest(req, { arbiter: claude, sessionKey: session });
    sent.push(JSON.stringify(out.request));
    return String((out.request.messages[2]!.content as Array<{ content: unknown }>)[0]!.content);
  };
  const exec = async (cmd: string, output: string): Promise<string> => {
    const id = `call_${++n}`;
    await bind(id, cmd, ["/bin/bash", "-lc", cmd]);
    const req = { model: "gpt-test", input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "Go through my inbox." }] },
      { type: "function_call", call_id: id, name: "exec_command", arguments: JSON.stringify({ cmd, workdir: ws }) },
      { type: "function_call_output", call_id: id, output },
    ] } as unknown as ResponsesRequest;
    const out = await rewriteOpenAi(req, { arbiter: codex, sessionKey: session });
    sent.push(JSON.stringify(out.request));
    return String((out.request.input as Array<{ type: string; output?: unknown }>).find((x) => x.type === "function_call_output")!.output);
  };
  try {
    // 1. the lift
    assert.equal(await bash(DEMO, HITS), HITS);
    assert.equal(await exec(DEMO, HITS), HITS);
    // 2. fail closed
    for (const [why, command, output] of [
      ["the two-word form", "grep -rIl -i park . --exclude-dir bank", `${HITS}./bank/statement-2026-09.md\n`],
      ["a statement beside the flag", "grep -i park . --exclude-dir=bank bank/statement-2026-09.md", STATEMENT],
      ["--exclude=, which keeps no folder out", "grep -ri park . --exclude=bank", `./bank/statement-2026-09.md:${STATEMENT}`],
    ] as const) {
      for (const [agent, got] of [["Claude Code", await bash(command, output)], ["Codex", await exec(command, output)]] as const) {
        assert.match(got, SYMBOL_RE, `${agent}, ${why}: ${got}`);
        assert.ok(!got.includes("Park Tax LLC"), `${agent}, ${why}`);
      }
    }
    // 3. THE ORACLE
    for (const s of sent) {
      assert.ok(!s.includes(ACCT), "CONFIDENTIALITY VIOLATION: a statement's account number reached the model");
      assert.ok(!s.includes("Payee: Park Tax LLC"), "CONFIDENTIALITY VIOLATION: a statement's line reached the model");
    }
  } finally {
    for (const c of [guard, h1, d1, h2, d2]) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
