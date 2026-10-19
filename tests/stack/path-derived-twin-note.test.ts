/**
 * path-derived-twin-note — the path-derived note names the way to the
 * secret file itself (confidentiality.md §7.1, 2026-10-19), over the REAL
 * components: a real ArbiterServer in `secrets`, the launch's secret setup
 * as the launcher does it (`discoverSecrets` over HOME and the workspace,
 * `registerSecret` per file found), the guard's reports on the human socket,
 * and both model proxies' rewrite in their PRODUCTION wiring
 * (`new ArbiterClientAdapter(data, human)`).
 *
 * The gap it closes: demo-tax-extension under Mandu's defaults (2026-10-19,
 * 2 takes of 3). The model ran `ls -R taxes/; cat taxes/2025/* | head`, got
 * one symbol and a note that said only how to read the OTHER files, and gave
 * up ("Mandu locks it so that no model can read it"), though a read of the
 * tax return alone gives its document twin: each line's label, each value a
 * placeholder.
 *
 *   - the batch `cat` stays ONE symbol, and its note says how a read of the
 *     document on its own reads (each line's label, its value a symbol);
 *   - the follow-up `cat` of the document alone, served the twin, reaches
 *     the model as the twin; so does a Read of it;
 *   - a command naming a credential file and a human-labelled file with no
 *     shape gets the structured and the whole-file sentence;
 *   - NO false claim: a labelled file Mandu serves no twin of (written
 *     after the launch registered the others) gets the note without the
 *     sentence;
 *   - Codex (`exec_command` with its `workdir`) gets the same note;
 *   - THE ORACLE: no value of the document, the `.env` or the labelled file
 *     is in anything the model is sent.
 *
 * Unit twins: arbiter `named-twins.test.ts`, each proxy's
 * `path-derived-note.test.ts`.
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { rewriteRequest } from "../../interceptors/anthropic-proxy/src/rewrite-request.js";
import type { MessagesRequest } from "../../interceptors/anthropic-proxy/src/messages-types.js";
import { ArbiterClientAdapter as OpenAiAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { rewriteRequest as rewriteOpenAi } from "../../interceptors/openai-proxy/src/rewrite-request.js";
import type { ResponsesRequest } from "../../interceptors/openai-proxy/src/responses-types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode, the one a fresh install runs

const SSN = "934-52-1170";
const AGI = "68,452.31";
const NAME = "Alex Demo Rivera";
const STRIPE = "sk_live_twinnote_0123456789abcdef";
const DIARY = "Diary entry: met the lawyer about the TWINNOTE-DIARY-4471 settlement.";
const lines = (...l: string[]): string => `${l.join("\n")}\n`;
const FILES: Record<string, string> = {
  "taxes/2025/return-summary.txt": lines("TaxPal export - 2025 state income tax return, summary", "", `Name: ${NAME}`, `SSN: ${SSN}`,
    "Filing status: Single", `Adjusted gross income (AGI): ${AGI}`, "Total tax: 9,187.46", "Total payments: 8,240.19"),
  "taxes/2025/todo.txt": lines("file by April", "ask about the extension"),
  ".env": lines("PORT=3000", `STRIPE_SECRET_KEY=${STRIPE}`),
  "private/diary.txt": lines(DIARY),
};
const VAULT = "vault-TWINNOTE-UNREGISTERED-8812";
const VALUES = [SSN, AGI, NAME, STRIPE, "TWINNOTE-DIARY-4471", VAULT];
const SYMBOL_RE = /^\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\]\n\n\[mandu:secret\] masked: the command names /;
const BATCH = "ls -R taxes/; cat taxes/2025/* 2>/dev/null | head -100";
const LINES_SENTENCE = "To use each secret file taxes/2025/* matches itself, read it on its own (a file read of that one file, or `cat` with that file alone): you see each line's label as written and its value as a symbol you can pass to a command (a command that sends it is checked against the file's rules).";
const FIELDS_SENTENCE = "To use .env itself, read it on its own (a file read of .env, or `cat .env` alone): you see its keys and layout as written and each secret value as a symbol you can pass to a command (a command that sends it is checked against the file's rules).";
const WHOLE_SENTENCE = "To use private/diary.txt itself, read it on its own (a file read of private/diary.txt, or `cat private/diary.txt` alone): you see one symbol that stands for the whole file, which you can pass whole to a command where the file's content belongs (a command that sends it is checked against the file's rules).";

/** Claude Code's Read output: numbered lines. */
const claudeRead = (text: string) => text.replace(/\n$/, "").split("\n").map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n");

test("a batch cat of a labelled document is masked whole and its note names the read of the document alone; that read gives the twin; the structured and whole-file sentences; no sentence for a file with no twin; Codex alike; no value reaches the model (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-twin-note-"));
  const home = join(tmp, "home");
  const ws = join(tmp, "work", "papers");
  mkdirSync(home, { recursive: true });
  for (const [rel, text] of Object.entries(FILES)) {
    mkdirSync(dirname(join(ws, rel)), { recursive: true });
    writeFileSync(join(ws, rel), text);
  }
  const at = (rel: string): string => join(ws, rel);
  const sock = join(tmp, "a.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, dbPath: join(tmp, "db.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, policyPollMs: 0,
    // the human labels the diary; the tax return is the content tier's, the .env the catalog's
    policyDocument: { version: 1, paths: [{ path: at("private/diary.txt"), level: "no-model" }, { path: at("vault"), level: "no-model" }] } as never,
  });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const guard = await open(humanSock); // the guard reports on the human socket (plan 13 D9)
  const h1 = await open(humanSock);
  const data = await open(sock);
  const claude = new ArbiterClientAdapter(await open(sock), h1);
  const codex = new OpenAiAdapter(await open(sock), await open(humanSock));
  const session = `twin-note-${process.pid}`;
  const sent: string[] = [];
  let n = 0;
  try {
    assert.equal((await data.setSessionSpec({ sessionKey: session, spec: "claude-code", requestedBy: "twin-note e2e" })).bound, "claude-code");
    // The launch's secret setup (launcher/src/secret-setup.ts).
    const report = await data.discoverSecretsReport([home, ws], home);
    const twins = new Map<string, string | undefined>();
    for (const f of report.files) {
      const r = await data.registerSecret({ path: f.path, home, sessionKey: session });
      assert.ok(r.symbol, `${f.path}: ${r.reason}`);
      twins.set(f.path, typeof r.twin === "string" ? r.twin : undefined);
    }
    for (const rel of ["taxes/2025/return-summary.txt", ".env"]) assert.ok(twins.get(at(rel)), `${rel}: a structured twin (${[...twins.keys()].join(", ")})`);
    if (!twins.has(at("private/diary.txt"))) {
      const r = await data.registerSecret({ path: at("private/diary.txt"), home, sessionKey: session });
      assert.ok(r.symbol, r.reason);
      twins.set(at("private/diary.txt"), typeof r.twin === "string" ? r.twin : undefined);
    }
    assert.equal(twins.get(at("private/diary.txt")), undefined, "the labelled diary: the whole-file twin");
    assert.ok(!twins.has(at("taxes/2025/todo.txt")), "the to-do list is no secret");
    const taxTwin = twins.get(at("taxes/2025/return-summary.txt"))!;
    assert.ok(taxTwin.includes("SSN: $MDU:") && !taxTwin.includes(SSN), taxTwin);

    /** One Claude Code Bash call as it runs under Mandu: the proxy's record
     *  of the command, the guard's report of the agent's shell (with the
     *  kernel's directory, or none) and of each program's open served the
     *  twin, then the result through the rewrite. */
    const bash = async (command: string, output: string, cwd: string | null, opens: string[] = []): Promise<string> => {
      const id = `tu_tn_${++n}`;
      await h1.recordCallCommand({ callId: id, command, sessionKey: session });
      await guard.recordExecRoot({ procKey: `sh-${n}`, ancestors: ["agent-0"], argv: ["/bin/bash", "-c", command], session, callRoot: true, ...(cwd !== null ? { cwd } : {}) });
      for (const path of opens) {
        await guard.processLineage({ childKey: `cat-${n}`, parentKey: `sh-${n}`, session });
        const d = await guard.decideSecretOpen({ path, exe: "/usr/bin/cat", isAgent: false, exeSystem: true, openerEnv: [], procKey: `cat-${n}`, parentKey: `sh-${n}`, ancestorKeys: [`sh-${n}`, "agent-0"], session });
        assert.equal(d.verdict, "twin", `cat is served the twin of ${path}: ${d.reason}`);
      }
      const req: MessagesRequest = { model: "claude-test", messages: [
        { role: "user", content: "I won't finish my taxes by tomorrow. File an extension for me, using last year's return for the estimate." },
        { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: output }] },
      ] };
      const out = await rewriteRequest(req, { arbiter: claude, sessionKey: session });
      sent.push(JSON.stringify(out.request));
      return String((out.request.messages[2]!.content as Array<{ content: unknown }>)[0]!.content);
    };

    // 1. THE DEMO'S COMMAND: what the guard serves is the twin of the
    //    return and the to-do list as it is; the output is still ONE symbol,
    //    and the note says how to read the return alone.
    const listing = "taxes/:\n2025\n\ntaxes/2025:\nreturn-summary.txt\ntodo.txt\n";
    const batch = await bash(BATCH, `${listing}${taxTwin}${FILES["taxes/2025/todo.txt"]}`, ws, [at("taxes/2025/return-summary.txt")]);
    assert.match(batch, SYMBOL_RE, `masked whole: ${batch}`);
    assert.ok(batch.includes("names a secret file (taxes/2025/*)"), batch);
    assert.ok(batch.includes(`names no secret file. ${LINES_SENTENCE} Do not assume it worked`), `the note names the read of the document alone: ${batch}`);
    assert.ok(!batch.includes("return-summary") && !batch.includes("todo"), "no byte of the output");

    // 2. THE FOLLOW-UP: `cat` of the return alone, served the twin, reaches
    //    the model as the twin; a Read of it too.
    const alone = await bash("cat taxes/2025/return-summary.txt", taxTwin, ws, [at("taxes/2025/return-summary.txt")]);
    assert.ok(alone.includes("SSN: $MDU:") && alone.includes("Adjusted gross income (AGI): $MDU:"), `the twin reaches the model: ${alone}`);
    assert.match(alone, /\[mandu:secret\] twin: /);
    const readId = `tu_tn_${++n}`;
    const read = await rewriteRequest({ model: "claude-test", messages: [
      { role: "user", content: "go" },
      { role: "assistant", content: [{ type: "tool_use", id: readId, name: "Read", input: { file_path: at("taxes/2025/return-summary.txt") } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: readId, content: claudeRead(taxTwin) }] },
    ] } as MessagesRequest, { arbiter: claude, sessionKey: session });
    sent.push(JSON.stringify(read.request));
    assert.ok(JSON.stringify(read.request).includes("SSN: $MDU:"), "a Read of the return gives the twin");

    // 3. A credential file and a labelled file with no shape: the structured
    //    and the whole-file sentence, in the order the command names them.
    const mixed = await bash("cat .env private/diary.txt | wc -c", "73\n", ws);
    assert.match(mixed, SYMBOL_RE, mixed);
    assert.ok(mixed.includes(`names no secret file. ${FIELDS_SENTENCE} ${WHOLE_SENTENCE} Do not assume it worked`), mixed);

    // 4. NO FALSE CLAIM: a file under the labelled vault written after the
    //    launch registered the others has no twin a read would show: the
    //    note, without the sentence.
    mkdirSync(at("vault"), { recursive: true });
    writeFileSync(at("vault/key.txt"), `${VAULT}\n`);
    const unregistered = await bash("cat vault/* | head -3", `${VAULT}\n`, ws);
    assert.match(unregistered, SYMBOL_RE, unregistered);
    assert.ok(unregistered.includes("names a secret file (vault/*)"), unregistered);
    assert.ok(!unregistered.includes("To use") && !unregistered.includes("To read"), `no claim for a file with no twin: ${unregistered}`);

    // 5. Codex: `exec_command` with its `workdir`, the same note.
    const id = `call_tn_${++n}`;
    await h1.recordCallCommand({ callId: id, command: BATCH, sessionKey: session });
    await guard.recordExecRoot({ procKey: `sh-${n}`, ancestors: ["agent-0"], argv: ["/bin/bash", "-lc", BATCH], session, callRoot: true, cwd: ws });
    const head = "Chunk ID: 4f1c2a\nWall time: 0.0123 seconds\nProcess exited with code 0\nOutput:\n";
    const codexOut = await rewriteOpenAi({ model: "gpt-test", input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "File an extension for me." }] },
      { type: "function_call", call_id: id, name: "exec_command", arguments: JSON.stringify({ cmd: BATCH, workdir: ws }) },
      { type: "function_call_output", call_id: id, output: `${head}${listing}${taxTwin}` },
    ] } as unknown as ResponsesRequest, { arbiter: codex, sessionKey: session });
    sent.push(JSON.stringify(codexOut.request));
    const codexText = String((codexOut.request.input as Array<{ type: string; output?: unknown }>).find((x) => x.type === "function_call_output")!.output);
    assert.ok(codexText.includes(`names no secret file. ${LINES_SENTENCE} Do not assume it worked`), `Codex: ${codexText}`);

    // THE ORACLE: no value reached the model, in any request.
    for (const s of sent) {
      for (const v of VALUES) assert.ok(!s.includes(v), `CONFIDENTIALITY VIOLATION: ${v} reached the model:\n${s.slice(0, 2000)}`);
    }
  } finally {
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
