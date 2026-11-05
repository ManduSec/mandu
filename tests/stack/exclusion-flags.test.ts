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
 *      model as grep printed it, and so does the same search spelled with an
 *      rg negated glob (`rg -il park . -g '!bank'`, 2026-10-27);
 *   2. fail closed, masked whole: the two-word form `--exclude-dir bank`, a
 *      statement named beside the flag, `--include=bank`, `--exclude-from=bank`,
 *      a statement named beside an rg negated glob, a positive glob over the
 *      folder, `xargs rg`, `bash -lc 'rg …'`;
 *   3. THE ORACLE: no statement byte is in any request to the model.
 *
 * And demo-notion-token's Codex leg (2026-10-27): `notes-app/.env` labelled
 * by the drill's pattern, Codex's exact first command (its only words naming
 * `.env` are rg negated globs) reaches Codex as printed, as a function call
 * and as the take's own code-mode cell; a command that names
 * the file beside the glob stays one symbol; no token byte reaches the model.
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

test("secrets: demo-c2's grep (and the rg spelling) that excludes the labelled folder reaches Claude Code and Codex as printed; the two-word form, a statement beside it, --include=, --exclude-from= and the unproven rg forms stay one symbol; no statement byte reaches the model", { timeout: 120_000 }, async () => {
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
    for (const rg of ["rg -il park . -g '!bank'", "rg -il park . --glob='!bank/**' | sort"]) {
      assert.equal(await bash(rg, HITS), HITS, `Claude Code: ${rg}`);
      assert.equal(await exec(rg, HITS), HITS, `Codex: ${rg}`);
    }
    // 2. fail closed
    for (const [why, command, output] of [
      ["the two-word form", "grep -rIl -i park . --exclude-dir bank", `${HITS}./bank/statement-2026-09.md\n`],
      ["a statement beside the flag", "grep -i park . --exclude-dir=bank bank/statement-2026-09.md", STATEMENT],
      ["--include=, never blanked", "grep -ri park . --include=bank", `./bank/statement-2026-09.md:${STATEMENT}`],
      ["--exclude-from=, which opens its file", "grep -ri park . --exclude-from=bank", `./bank/statement-2026-09.md:${STATEMENT}`],
      ["a statement beside an rg negated glob", "rg -i park -g '!bank' bank/statement-2026-09.md", STATEMENT],
      ["an rg positive glob over the folder", "rg -i park -g '!x' -g 'bank/**' .", `bank/statement-2026-09.md:${STATEMENT}`],
      ["xargs rg", "echo bank | xargs rg -i park -g '!bank'", `bank/statement-2026-09.md:${STATEMENT}`],
      ["bash -lc 'rg …'", "bash -lc \"rg -i park -g '!bank' bank\"", `bank/statement-2026-09.md:${STATEMENT}`],
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

// Made-up value (no real credential).
const NOTION_TOKEN = "secret_EXCLFLAGS_RG_4Kp9Zx2Lm7Qw3Vb8Nt5Hc1";
const CODEX_RG = `pwd && rg --files -g 'AGENTS.md' -g 'notes-app/**' -g 'meetings/**' -g '!notes-app/.env' | sort && echo '--- notes-app listing ---' && ls -la notes-app && echo '--- meeting file ---' && sed -n '1,240p' meetings/2026-10-16-team-sync.md && echo '--- scripts/config references ---' && rg -n "notion|env|dotenv|token|meeting" notes-app --glob '!*.env'`;

test("secrets: demo-notion-token's Codex leg — the exact first command (rg negated globs) reaches Codex as printed under the drill's pattern label; naming the file beside the glob stays one symbol; no token byte reaches the model", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-exclusion-rg-"));
  const ws = join(tmp, "ws-e1f0");
  for (const d of ["notes-app", "meetings"]) mkdirSync(join(ws, d), { recursive: true });
  writeFileSync(join(ws, "notes-app", ".env"), `NOTION_TOKEN='${NOTION_TOKEN}'\n`);
  writeFileSync(join(ws, "meetings", "2026-10-16-team-sync.md"), "# Team sync\nDecision: the weekly sync moves to Thursdays.\n");
  const sock = join(tmp, "a.sock");
  const human = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "db.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: "**/ws-*/notes-app/.env", level: "no-model", bindings: ["api.notion.com"], recursive: false }] } as never,
  });
  await server.listen();
  const guard = new ArbiterClient(human); await guard.connect();
  const h = new ArbiterClient(human); await h.connect();
  const d = new ArbiterClient(sock); await d.connect();
  const codex = new OpenAiAdapter(d, h);
  const session = "s-exclusion-rg";
  const sent: string[] = [];
  let n = 0;
  const exec = async (cmd: string, output: string): Promise<string> => {
    const id = `call_${++n}`;
    await h.recordCallCommand({ callId: id, command: cmd, sessionKey: session });
    await guard.recordExecRoot({ procKey: `sh-${n}`, ancestors: ["agent-0"], argv: ["/bin/bash", "-lc", cmd], session, callRoot: true, cwd: ws });
    const req = { model: "gpt-test", input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "Add today's meeting notes to Notion." }] },
      { type: "function_call", call_id: id, name: "exec_command", arguments: JSON.stringify({ cmd, workdir: ws }) },
      { type: "function_call_output", call_id: id, output },
    ] } as unknown as ResponsesRequest;
    const out = await rewriteOpenAi(req, { arbiter: codex, sessionKey: session });
    sent.push(JSON.stringify(out.request));
    return String((out.request.input as Array<{ type: string; output?: unknown }>).find((x) => x.type === "function_call_output")!.output);
  };
  try {
    const reg = await guard.registerSecret({ path: join(ws, "notes-app", ".env"), sessionKey: session });
    const field = String(reg.twin).match(/\$MDU:nomodel_Read\[[0-9a-f]+\]\.NOTION_TOKEN/)![0];
    const printed = `${ws}\nAGENTS.md\nmeetings/2026-10-16-team-sync.md\n--- notes-app listing ---\n.env\n--- meeting file ---\n# Team sync\nDecision: the weekly sync moves to Thursdays.\n--- scripts/config references ---\n`;
    // 1. the lift: the first command and Codex's retry
    assert.equal(await exec(CODEX_RG, printed), printed);
    assert.equal(await exec(CODEX_RG.replace("-g '!notes-app/.env'", "-g '!notes-app/.env' -g '!**/*.env'"), printed), printed, "Codex's retry");
    // the live take's own wire: a code-mode cell whose exec_command literal
    // holds the command, as the model capture has it
    {
      const id = "call_5f330d41d81e4e21a5fc86fceb573590";
      await h.recordCallCommand({ callId: id, command: CODEX_RG, sessionKey: session });
      await guard.recordExecRoot({ procKey: "sh-cell", ancestors: ["agent-0"], argv: ["/bin/bash", "-lc", CODEX_RG], session, callRoot: true, cwd: ws });
      const req = { model: "gpt-test", input: [
        { type: "message", role: "user", content: [{ type: "input_text", text: "Add today's meeting notes to Notion." }] },
        { type: "custom_tool_call", id: "ctc_rg", status: "completed", call_id: id, name: "exec",
          input: `const r = await tools.exec_command({cmd:${JSON.stringify(CODEX_RG)},"workdir":${JSON.stringify(ws)},"yield_time_ms":10000,"max_output_tokens":12000});\ntext(r.output);` },
        { type: "custom_tool_call_output", id: "ctco_rg", call_id: id, output: [{ type: "input_text", text: "Script completed\nWall time 0.4 seconds\nOutput:\n" }, { type: "input_text", text: printed }] },
      ] } as unknown as ResponsesRequest;
      const out = await rewriteOpenAi(req, { arbiter: codex, sessionKey: session });
      sent.push(JSON.stringify(out.request));
      const shown = ((out.request.input as Array<{ type: string; output?: unknown }>).find((x) => x.type === "custom_tool_call_output")!.output as Array<{ text: string }>).map((p) => p.text).join("");
      assert.equal(out.rewrites[0]!.symbolized, false, out.rewrites[0]!.reason);
      assert.ok(shown.includes(printed), `the code cell's output as printed: ${shown}`);
    }
    // 2. fail closed: the file named beside the glob, the glob double-quoted,
    // a later segment that reads the file
    for (const cmd of [
      "rg -n token notes-app/.env -g '!notes-app/.env'",
      "rg -n token -g \"!notes-app/.env\" notes-app",
      "rg -n token -g '!x' notes-app && cat notes-app/.env",
    ]) {
      const got = await exec(cmd, `notes-app/.env:1:NOTION_TOKEN='${field}'\nnotes-app/add-page.sh:3:curl -H "Authorization: Bearer $NOTION_TOKEN"\n`);
      assert.match(got, SYMBOL_RE, `${cmd}: ${got}`);
    }
    // 3. THE ORACLE
    for (const s of sent) assert.ok(!s.includes(NOTION_TOKEN), "CONFIDENTIALITY VIOLATION: the Notion token reached the model");
  } finally {
    for (const c of [guard, h, d]) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
