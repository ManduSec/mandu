/**
 * large-file-pieces — plan 10 §11.18 over the REAL components: a real
 * ArbiterServer in `secrets`, the real AnthropicProxy over its PRODUCTION
 * adapter (`new ArbiterClientAdapter(new ArbiterClient(sock), human)`, as
 * anthropic-proxy/src/server-main.ts builds it), a canned upstream (the
 * model). The guard's facts are sent as the guard sends them, on the human
 * socket (`recordExecRoot`, `decideSecretOpen`, `labelWrittenPathTainted`),
 * and the proxy's record of each call's command binds every call to its
 * shell, so a clean call's output is judged by the value backstop alone (no
 * session-wide fallback masks it).
 *
 * The files are labelled but never registered at launch (labelled later):
 *   - `export.log`, 2 MiB of log lines with a short password deep inside;
 *   - `vault.db`, a binary file with a short token among its strings;
 *   - `.env`, read raw by `ssh-add`, which writes `session.json` (a session
 *     token only the copy holds) that its child reads raw (plan 13 D4: a
 *     holder of every source);
 *   - `archive.dump`, 17 MiB, over the piece bound, its reader cleared
 *     (`output: clear`), and `small.txt` with the same reader entry.
 *
 * Before: the self-registration skipped files over 1 MiB and binary files,
 * and the D4 grant registered nothing, so a later clean call printing the
 * password, the token or the session token (a copy the guard never saw
 * opened) reached the model raw. Now each is a symbol, and a cleared reader
 * of a file whose pieces are unknown is masked whole. Controls: a short
 * prose line of the log is forwarded raw, and the cleared reader of the
 * small file still is.
 * Unit twins: arbiter `large-file-pieces.test.ts`, `read-file-registration.test.ts`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { closeSync, ftruncateSync, mkdirSync, mkdtempSync, openSync, rmSync, writeFileSync, writeSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const READER = "/usr/bin/ssh-add";
const H = "c".repeat(64);
const SESSION = "large-pieces-stack";
const BIG_SECRET = "Rk4mW9xQ2pLs"; // 12 characters, deep in a 2 MiB file
const BIN_SECRET = "Gv7bN3kT8rYd"; // 12 characters, among a binary file's strings
const COPY_SECRET = "Jc2hP6wZ9sMf"; // 12 characters, only the holder's copy holds it
const SECRETS = [BIG_SECRET, BIN_SECRET, COPY_SECRET];
const PROSE = "INFO request served";

test("a piece of a labelled file over 1 MiB, a binary file's token and a value of a holder's raw-read copy reach the model only as symbols; a cleared reader of a file over the piece bound is masked whole (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-large-pieces-stack-"));
  const log = join(tmp, "export.log");
  writeFileSync(log, `${"2026-10-07 12:00:00 INFO request served in 12 ms\n".repeat(30_000)}login password ${BIG_SECRET}\n${"2026-10-07 12:00:01 INFO request served in 9 ms\n".repeat(20_000)}`);
  const db = join(tmp, "vault.db");
  writeFileSync(db, Buffer.concat([Buffer.from([0, 1, 2, 3]), Buffer.from("SQLite format 3"), Buffer.alloc(4096), Buffer.from(`api_token ${BIN_SECRET}`), Buffer.from([0, 0xff, 0xfe, 0])]));
  const env = join(tmp, ".env");
  writeFileSync(env, "STRIPE_KEY=sk_live_PIECES00000000000001\n");
  const dump = join(tmp, "archive.dump");
  const fd = openSync(dump, "w");
  writeSync(fd, `password ${BIG_SECRET}\n`);
  ftruncateSync(fd, 17 * 1024 * 1024); // over the 16 Mi-character bound
  closeSync(fd);
  const small = join(tmp, "small.txt");
  writeFileSync(small, "db.internal:5432:prod:app:Wq3eR5tY7uI9\n");
  const reader = [{ app: "ssh-add" }];
  const clear = [{ app: "ssh-add", output: "clear" }];
  const socketPath = join(tmp, "arbiter.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const arbiter = new ArbiterServer({
    socketPath, dbPath: join(tmp, "symbols.sqlite"), humanSocketPath: join(tmp, "human", "h.sock"),
    eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [
      { path: log, level: "no-model", readers: reader },
      { path: db, level: "no-model", readers: reader },
      { path: env, level: "no-model", readers: reader },
      { path: dump, level: "no-model", readers: clear },
      { path: small, level: "no-model", readers: clear },
    ] } as never,
  });
  await arbiter.listen();
  // The production clients with a longer deadline: the arbiter runs in THIS
  // process, so its synchronous work (the value index built over the 2 MiB
  // row's pieces on the first `filterPrompt` after it is registered, about
  // 0.1 s here and many times that on a loaded CI runner) runs on the
  // clients' event loop and counts against their 5 s request timer, which a
  // separate arbiter process never does. Expired, the proxy refuses the
  // request (502, fail-closed), a timing failure this test does not test.
  const timing = { requestTimeoutMs: 60_000 };
  const guard = new ArbiterClient(join(tmp, "human", "h.sock"), timing); // the guard's channel (plan 13 D9)
  await guard.connect();
  const real = new ArbiterClient(socketPath, timing);
  await real.connect();
  const realHuman = new ArbiterClient(join(tmp, "human", "h.sock"), timing);
  await realHuman.connect();
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(real, realHuman), upstream: upstream.fetcher, log: () => {} });
  const port = await proxy.listen(0);

  let n = 0;
  /** One Bash call: the proxy's record of its command, the agent's shell for
   *  it, and (when `reads`) the reader under it opening each file raw. */
  const call = async (command: string, reads: string[] = []): Promise<string> => {
    n++;
    const id = `toolu_lp_${n}`;
    const sh = `lp-sh-${n}`;
    await realHuman.recordCallCommand({ callId: id, command, sessionKey: SESSION });
    await guard.recordExecRoot({ procKey: sh, parentKey: "agent-0", argv: ["/bin/bash", "-lc", command], session: SESSION, callRoot: true });
    if (reads.length > 0) {
      await guard.recordExecRoot({ procKey: `lp-r-${n}`, parentKey: sh, argv: [READER, "-L"], session: SESSION });
      for (const path of reads) {
        const d = await guard.decideSecretOpen({ path, exe: READER, sha256: H, isAgent: false, procKey: `lp-r-${n}`, parentKey: sh, ancestorKeys: [sh], exeSystem: true, openerEnv: [], session: SESSION });
        assert.equal(d.verdict, "raw", `ssh-add is a listed reader of ${path}: ${d.reason}`);
      }
    }
    return id;
  };
  /** One Bash turn through the proxy; what the model received for its result. */
  const toModel = async (id: string, command: string, output: string): Promise<string> => {
    const body = JSON.stringify({
      model: "claude-opus-4", stream: true, system: "You are Claude Code.",
      messages: [
        { role: "user", content: "go" },
        { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: output }] },
      ],
    });
    const status = await new Promise<number>((resolve, reject) => {
      const r = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages",
        headers: { "content-type": "application/json", "x-mandu-session-id": SESSION } },
      (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); });
      r.on("error", reject);
      r.end(body);
    });
    assert.equal(status, 200);
    const sent = JSON.parse(upstream.requests.at(-1)!.bodyText) as { messages: Array<{ content?: unknown }> };
    for (const m of sent.messages) {
      if (!Array.isArray(m.content)) continue;
      for (const b of m.content as Array<Record<string, unknown>>) {
        if (b.type !== "tool_result" || b.tool_use_id !== id) continue;
        return typeof b.content === "string" ? b.content : (b.content as Array<{ text?: string }>).map((x) => x.text ?? "").join("");
      }
    }
    throw new Error(`no tool_result ${id} forwarded`);
  };
  const run = async (command: string, output: string, reads: string[] = []): Promise<string> => toModel(await call(command, reads), command, output);
  try {
    // 1. The reader reads each file raw (each result masked whole: rule i).
    for (const f of [log, db]) {
      const out = await run(`ssh-add -L ${f}`, `password ${BIG_SECRET}\napi_token ${BIN_SECRET}\n`, [f]);
      assert.ok(SECRETS.every((x) => !out.includes(x)), `CONFIDENTIALITY VIOLATION: the reader's output reached the model raw: ${out}`);
    }
    // 2. A holder of .env writes a session token to session.json; its child reads the copy raw (plan 13 D4).
    const holderCmd = "stripe-login --out session.json";
    const holderId = await call(holderCmd, [env]);
    const copy = join(tmp, "session.json");
    writeFileSync(copy, `{"session_token": "${COPY_SECRET}", "expires": 3600}\n`);
    assert.equal((await guard.labelWrittenPathTainted({ path: copy, procKey: `lp-r-${n}`, session: SESSION })).labeled, true);
    const child = await guard.decideSecretOpen({ path: copy, exe: "/usr/bin/node", isAgent: false, procKey: `lp-child-${n}`, parentKey: `lp-r-${n}`, ancestorKeys: [`lp-r-${n}`, `lp-sh-${n}`], exeSystem: true, openerEnv: [], session: SESSION });
    assert.equal(child.verdict, "raw", `a holder of every source reads its copy raw: ${child.reason}`);
    assert.ok(!(await toModel(holderId, holderCmd, `logged in\n${COPY_SECRET}\n`)).includes(COPY_SECRET), "the holder's own output is masked (rule i)");

    // 3. Later clean calls (no secret read in their tree) print each secret again.
    const bigOut = await run("cat notes/a.txt", `login with ${BIG_SECRET}\n`);
    assert.ok(!bigOut.includes(BIG_SECRET), `CONFIDENTIALITY VIOLATION: a short password of a 2 MiB labelled file reached the model: ${bigOut}`);
    const binOut = await run("strings notes/b.bin", `SQLite format 3\napi_token ${BIN_SECRET}\n`);
    assert.ok(!binOut.includes(BIN_SECRET), `CONFIDENTIALITY VIOLATION: a binary labelled file's token reached the model: ${binOut}`);
    const copyOut = await run("cat notes/c.json", `export TOKEN=${COPY_SECRET}\n`);
    assert.ok(!copyOut.includes(COPY_SECRET), `CONFIDENTIALITY VIOLATION: a value of a holder's raw-read copy reached the model: ${copyOut}`);
    // control: a short prose line of the log is no registered value, and the clean call is not masked session-wide
    const prose = await run("cat notes/d.txt", `${PROSE} ok\n`);
    assert.equal(prose, `${PROSE} ok\n`, "utility: a clean call's prose is forwarded raw");

    // 4. Fail-closed: a cleared reader of a file over the piece bound is masked whole; of a small file, released.
    // (a masked output is a registered value of its call: each call prints its own text)
    const dumpOut = await run("db-report --archive", "rows\n77\n", [dump]);
    assert.match(dumpOut, /^\$MDU:nomodel_Bash\[[^\]]*\]\n\n\[mandu:secret\] masked: ssh-add read [^;]*archive\.dump/, `a file whose pieces are unknown releases nothing (rule i, not a path in the command): ${dumpOut}`);
    const smallOut = await run("db-report --summary", "count\n1204\n", [small]);
    assert.ok(smallOut.startsWith("count\n1204\n"), `control: the cleared reader of a small file is released: ${smallOut}`);

    // THE ORACLE: no request to the model carried any of the secrets.
    const wire = upstream.requests.map((r) => r.bodyText).join("\n");
    assert.ok(SECRETS.every((x) => !wire.includes(x)), "the secrets never reached the model");
  } finally {
    await proxy.close();
    real.close();
    realHuman.close();
    guard.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
