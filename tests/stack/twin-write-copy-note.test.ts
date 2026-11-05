/**
 * twin-write-copy-note — the model is told, at the call, that a write into a
 * protected file stays in its placeholder copy (plan 10 §4.1, "The model is
 * told at the call", 2026-10-27), over the REAL components: a real
 * ArbiterServer in `secrets`, the launch's secret setup as the launcher does
 * it (`discoverSecretsReport`, `registerSecret` per file found), the guard's
 * reports on the human socket, and both model proxies' rewrite in their
 * PRODUCTION wiring (`new ArbiterClientAdapter(data, human)`), the session's
 * launch recorded as the launcher records a Linux launch with the file guard
 * (`beginLaunch`, posture `confined`, on the walled human plane).
 *
 * The gap it closes: demo-orders-sync-debug (live, Haiku 4.5, 2026-10-27).
 * The model fixed a misnamed key by rewriting `orders-app/.env`: Edit's save
 * was refused (EACCES), `sed -i` too, and `cat > orders-app/.env << 'EOF'`
 * landed in the placeholder copy. The sync in the session read the copy and
 * worked, the model told the person "Fixed!", and the person's real .env
 * (and so their own sync) stayed as it was; only the launcher's end-of-session
 * line said so, to the person.
 *
 *   - the drill's three writes, in its order (Edit, `sed -i`, the heredoc),
 *     each reach the model with the `copy:` line naming the .env as the
 *     model wrote it: the change stays in the copy, the real file is
 *     unchanged, do not say it is fixed, change the script or tell the user;
 *   - the heredoc's result stays ONE symbol (the path-derived mask), the
 *     line beside its masked line: the line releases nothing;
 *   - a read of the .env and a write of a plain file get no `copy:` line;
 *   - a session with a `gated` launch, or none, gets no line (the claim
 *     would not hold there: a program's write may reach the real file);
 *   - Codex (`exec_command` with its `workdir`) gets the same line;
 *   - THE ORACLE: the passphrase is in nothing the model is sent.
 *
 * Unit twins: arbiter `twin-write-targets.test.ts` and component
 * `twin-writes-classify.test.ts`; each proxy's `twin-write-note.test.ts` and
 * `twin-write-copy-line.test.ts`.
 *
 * Mandu-new test (no reference origin).
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
import { twinWriteLine } from "../../interceptors/anthropic-proxy/src/twin-write-note.js";
import { ArbiterClientAdapter as OpenAiAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { rewriteRequest as rewriteOpenAi } from "../../interceptors/openai-proxy/src/rewrite-request.js";
import type { ResponsesRequest } from "../../interceptors/openai-proxy/src/responses-types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode, the one a fresh install runs

const PASS = "Juniper-Harbor-COPYNOTE-6038-Wren";
const ENV_TEXT = `ORDERHUB_URL=https://api.orderhub.test\nORDERHUB_USER=bakery-shop\nORDERHUB_PASSPHRASE='${PASS}'\nSYNC_WINDOW_HOURS=24\n`;
const SCRIPT = "#!/bin/sh\ncd \"$(dirname \"$0\")/..\" || exit 1\nset -a; . ./.env; set +a\npass=\"$ORDERHUB_PASSWORD\"\n";
const ENV = "orders-app/.env";
const SYMBOL_RE = /^\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\]\n\n\[mandu:secret\] masked: the command names /;

test("the drill's writes of a protected .env each carry the copy: line, the masks stand, no line for a read, a plain file or an unguarded session; Codex alike; the passphrase reaches no model (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-copy-note-"));
  const home = join(tmp, "home");
  const ws = join(tmp, "work");
  mkdirSync(home, { recursive: true });
  mkdirSync(join(ws, "orders-app", "bin"), { recursive: true });
  writeFileSync(join(ws, ENV), ENV_TEXT);
  writeFileSync(join(ws, "orders-app/bin/sync-orders.sh"), SCRIPT);
  const envAbs = join(ws, ENV);
  const sock = join(tmp, "a.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, dbPath: join(tmp, "db.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, policyPollMs: 0,
  });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const guard = await open(humanSock); // the guard reports on the human socket (plan 13 D9)
  const h1 = await open(humanSock);
  const data = await open(sock);
  const claude = new ArbiterClientAdapter(await open(sock), h1);
  const codex = new OpenAiAdapter(await open(sock), await open(humanSock));
  const session = `copy-note-${process.pid}`;
  const sent: string[] = [];
  let n = 0;
  try {
    assert.equal((await data.setSessionSpec({ sessionKey: session, spec: "claude-code", requestedBy: "copy-note e2e" })).bound, "claude-code");
    // The launcher's launch records (cache-epoch.ts beginLaunchRecord): this
    // session with the file guard; another one `gated`.
    await h1.beginLaunch({ pid: process.pid, mode: "secrets", posture: "confined", writeProtect: true, humanPlaneWalled: true, sessionId: session, home });
    await h1.beginLaunch({ pid: process.pid, mode: "secrets", posture: "gated", writeProtect: true, humanPlaneWalled: true, sessionId: `${session}-gated` });
    // The launch's secret setup (launcher/src/secret-setup.ts).
    const report = await data.discoverSecretsReport([home, ws], home);
    assert.ok(report.files.some((f) => f.path === envAbs), `the .env is found: ${report.files.map((f) => f.path).join(", ")}`);
    let twin = "";
    for (const f of report.files) {
      const r = await data.registerSecret({ path: f.path, home, sessionKey: session });
      assert.ok(r.symbol, `${f.path}: ${r.reason}`);
      if (f.path === envAbs) twin = String(r.twin);
    }
    assert.ok(twin.includes("ORDERHUB_PASSPHRASE='$MDU:") && !twin.includes(PASS), twin);
    const copyOf = (token: string): string => `[mandu:secret] ${twinWriteLine([token])}`;

    /** One Claude Code call as it runs under Mandu: for Bash, the proxy's
     *  record of the command and the guard's report of the agent's shell in
     *  the workspace; then the result through the rewrite. */
    const claudeCall = async (name: string, input: Record<string, unknown>, output: string, sessionKey = session): Promise<string> => {
      const id = `tu_cn_${++n}`;
      if (name === "Bash") {
        const command = String(input["command"]);
        await h1.recordCallCommand({ callId: id, command, sessionKey: session });
        await guard.recordExecRoot({ procKey: `sh-${n}`, ancestors: ["agent-0"], argv: ["/bin/bash", "-c", command], session, callRoot: true, cwd: ws });
      }
      const req: MessagesRequest = { model: "claude-test", messages: [
        { role: "user", content: "Our order sync to OrderHub stopped working after last night's deploy. Find out what broke, fix it, and run the sync again." },
        { role: "assistant", content: [{ type: "tool_use", id, name, input }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: output }] },
      ] };
      const out = await rewriteRequest(req, { arbiter: claude, sessionKey });
      sent.push(JSON.stringify(out.request));
      return String((out.request.messages[2]!.content as Array<{ content: unknown }>)[0]!.content);
    };

    // 1. Edit's save of the .env, refused: the tool's own error, then the line.
    const refused = `EACCES: permission denied, rename '${envAbs}.tmp.2.5f8d4674dd18' -> '${envAbs}'`;
    const edit = await claudeCall("Edit", { file_path: envAbs, old_string: "ORDERHUB_PASSPHRASE=", new_string: "ORDERHUB_PASSWORD=" }, refused);
    assert.equal(edit, `${refused}\n\n${copyOf(envAbs)}`, edit);

    // 2. sed -i, its rename refused: the line names the .env (never the script).
    const sed = await claudeCall("Bash", { command: `sed -i 's/ORDERHUB_PASSPHRASE/ORDERHUB_PASSWORD/' ${ENV}` }, "Exit code 4\nsed: cannot rename orders-app/sedkcbuoF: Permission denied");
    assert.ok(sed.endsWith(copyOf(ENV)), `sed -i: ${sed}`);

    // 3. THE DRILL'S HEREDOC: one symbol, its masked line, then the line.
    const heredoc = `cat > ${ENV} << 'EOF'\nORDERHUB_URL=https://api.orderhub.test\nORDERHUB_USER=bakery-shop\nORDERHUB_PASSWORD='$MDU:nomodel_Read[a169].ORDERHUB_PASSPHRASE'\nSYNC_WINDOW_HOURS=24\nEOF\n`;
    const written = await claudeCall("Bash", { command: heredoc, description: "Write the corrected .env file" }, "(Bash completed with no output)");
    assert.match(written, SYMBOL_RE, `masked whole: ${written}`);
    const lines = written.split("\n\n")[1]!.split("\n");
    assert.equal(lines.length, 2, written);
    assert.equal(lines[1], copyOf(ENV));
    for (const piece of ["A change written into it stays in that copy", "the user's real orders-app/.env is unchanged", "Do not tell the user it is fixed or saved.", "for example in the code or script that reads the file"]) {
      assert.ok(written.includes(piece), `${piece}: ${written}`);
    }

    // 4. No line: a read of the .env, a write of a plain file, an unguarded session.
    const read = await claudeCall("Bash", { command: `cat ${ENV}` }, twin);
    assert.ok(!read.includes("copy:"), read);
    const plain = await claudeCall("Bash", { command: "echo 'pass=\"$ORDERHUB_PASSPHRASE\"' > orders-app/bin/fix.txt" }, "");
    assert.ok(!plain.includes("copy:"), plain);
    for (const other of [`${session}-gated`, `${session}-unlaunched`]) {
      const t = await claudeCall("Bash", { command: heredoc }, "(Bash completed with no output)", other);
      assert.match(t, SYMBOL_RE, `${other}: the mask stands`);
      assert.ok(!t.includes("copy:"), `${other}: ${t}`);
    }

    // 5. Codex: `exec_command` with its `workdir`, the same line.
    const id = `call_cn_${++n}`;
    const cmd = `echo ORDERHUB_PASSWORD="'$MDU:nomodel_Read[a169].ORDERHUB_PASSPHRASE'" >> ${ENV}`;
    await h1.recordCallCommand({ callId: id, command: cmd, sessionKey: session });
    await guard.recordExecRoot({ procKey: `sh-${n}`, ancestors: ["agent-0"], argv: ["/bin/bash", "-lc", cmd], session, callRoot: true, cwd: ws });
    const head = "Chunk ID: 4f1c2a\nWall time: 0.0123 seconds\nProcess exited with code 0\nOutput:\n";
    const codexOut = await rewriteOpenAi({ model: "gpt-test", input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "Fix the order sync." }] },
      { type: "function_call", call_id: id, name: "exec_command", arguments: JSON.stringify({ cmd, workdir: ws }) },
      { type: "function_call_output", call_id: id, output: head },
    ] } as unknown as ResponsesRequest, { arbiter: codex, sessionKey: session });
    sent.push(JSON.stringify(codexOut.request));
    const codexText = String((codexOut.request.input as Array<{ type: string; output?: unknown }>).find((x) => x.type === "function_call_output")!.output);
    assert.ok(codexText.endsWith(copyOf(ENV)), `Codex: ${codexText}`);

    // THE ORACLE: the passphrase reached no model, in any request.
    for (const s of sent) assert.ok(!s.includes(PASS), `CONFIDENTIALITY VIOLATION: the passphrase reached the model:\n${s.slice(0, 2000)}`);
  } finally {
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
