/**
 * reader-output-rule — confidentiality plan 13 D3 over the REAL components:
 * a real ArbiterServer in `secrets`, the real AnthropicProxy over its
 * PRODUCTION adapter (`new ArbiterClientAdapter(new ArbiterClient(sock))`,
 * as anthropic-proxy/src/server-main.ts builds it), a canned upstream (the
 * model). The guard's facts are sent as the guard sends them
 * (`recordExecRoot` with the argv, `decideSecretOpen` with the opener's
 * identity), so the taint rows are the ones a live open writes.
 *
 * The law: `~/.pgpass` names `{app: ssh-add, output: clear}`; the board
 * minutes name `ssh-add` with no output rule. Per Bash result, what the MODEL
 * receives:
 *   - ssh-add holding `.pgpass` alone: its rows, raw (the pair the human cleared);
 *   - ssh-add holding the minutes: a symbol, the minutes' text absent (it was
 *     raw before: the program-wide rule cleared every file ssh-add read);
 *   - one ssh-add holding both: a symbol (every file must clear the program);
 *   - the legacy `apps: [{app: ssh-add, output: clear}]`: a symbol for both
 *     files (deprecated, clears nothing).
 * The printed text is a fragment the value backstop cannot match (shorter
 * than a whole line of the document), so only the output rule decides it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const PSQL = "/usr/bin/ssh-add";
const H = "c".repeat(64);
const DOC_CANARY = "D3DOC_CANARY_7731";
const PG_CANARY = "d3_pgpass_canary_0000000000000001";
const SESSION = "d3-stack";

interface Stack { port: number; upstream: MockUpstream; guard: ArbiterClient; proxyHuman: ArbiterClient; pgpass: string; doc: string; stop: () => Promise<void> }

async function boot(policy: (pgpass: string, doc: string) => Record<string, unknown>): Promise<Stack> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-d3-stack-"));
  const pgpass = join(tmp, ".pgpass");
  const doc = join(tmp, "board-minutes.md");
  writeFileSync(pgpass, `db.internal:5432:prod:app:${PG_CANARY}\n`);
  writeFileSync(doc, `# Board minutes\nacquisition target: ${DOC_CANARY} at 4.2x revenue, close in Q3\n`);
  const socketPath = join(tmp, "arbiter.sock");
  const arbiter = new ArbiterServer({
    socketPath, dbPath: join(tmp, "symbols.sqlite"), adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: join(tmp, "human", "h.sock"),
    eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: policy(pgpass, doc) as never,
  });
  await arbiter.listen();
  const admin = new ArbiterClient(join(tmp, "admin.sock"));
  await admin.connect();
  for (const p of [pgpass, doc]) assert.ok((await admin.registerSecret({ path: p })).symbol, `register ${p}`);
  // The proxy's arbiter: the production wiring, no bridge (server-main's two
  // clients: execGate and callTaint ride the human one, plan 13 D9).
  const real = new ArbiterClient(socketPath);
  await real.connect();
  const realHuman = new ArbiterClient(join(tmp, "human", "h.sock"));
  await realHuman.connect();
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(real, realHuman), upstream: upstream.fetcher, log: () => {} });
  const port = await proxy.listen(0);
  return {
    port, upstream, guard: admin, proxyHuman: realHuman, pgpass, doc,
    stop: async () => {
      await proxy.close();
      real.close();
      realHuman.close();
      admin.close();
      await arbiter.close();
      rmSync(tmp, { recursive: true, force: true });
    },
  };
}

/** The guard's record of a Bash call: the shell, its ssh-add child, and ssh-add's
 *  opens of `files` (the system binary, a clean loader environment). */
async function psqlCall(s: Stack, tag: string, command: string, files: string[], callId: string): Promise<void> {
  const sh = `${tag}-sh`;
  const sshAdd = `${tag}-psql`;
  // the proxy's record of the command it relayed for the call (its response
  // side; plan 13 D9 follow-up: the call is bound by it, not by the echo)
  await s.proxyHuman.recordCallCommand({ callId, command, sessionKey: SESSION });
  // the agent's own shell for the call (callRoot: plan 13 D7's recorder binds the call to it)
  await s.guard.recordExecRoot({ procKey: sh, parentKey: "agent-0", argv: ["/bin/bash", "-lc", command], session: SESSION, callRoot: true });
  await s.guard.recordExecRoot({ procKey: sshAdd, parentKey: sh, argv: [PSQL, "-c", command], session: SESSION });
  for (const path of files) {
    const d = await s.guard.decideSecretOpen({ path, exe: PSQL, sha256: H, isAgent: false, procKey: sshAdd, parentKey: sh, exeSystem: true, openerEnv: [], session: SESSION });
    assert.equal(d.verdict, "raw", `ssh-add is a listed reader of ${path}: ${d.reason}`);
  }
}

/** One Bash turn through the proxy; what the model received for its result. */
async function toModel(s: Stack, id: string, command: string, output: string): Promise<string> {
  const body = JSON.stringify({
    model: "claude-opus-4", stream: true, system: "You are Claude Code.",
    messages: [
      { role: "user", content: "What does the database say?" },
      { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: output }] },
    ],
  });
  const status = await new Promise<number>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port: s.port, method: "POST", path: "/v1/messages",
      headers: { "content-type": "application/json", "x-mandu-session-id": SESSION } },
    (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); });
    r.on("error", reject);
    r.end(body);
  });
  assert.equal(status, 200);
  const sent = JSON.parse(s.upstream.requests.at(-1)!.bodyText) as { messages: Array<{ content?: unknown }> };
  for (const m of sent.messages) {
    if (!Array.isArray(m.content)) continue;
    for (const b of m.content as Array<Record<string, unknown>>) {
      if (b.type !== "tool_result" || b.tool_use_id !== id) continue;
      return typeof b.content === "string" ? b.content : (b.content as Array<{ text?: string }>).map((x) => x.text ?? "").join("");
    }
  }
  throw new Error(`no tool_result ${id} forwarded`);
}

const PER_PAIR = (pgpass: string, doc: string) => ({
  version: 1,
  paths: [
    { path: pgpass, level: "no-model", readers: [{ app: "ssh-add", output: "clear" }] },
    { path: doc, level: "no-model", readers: ["ssh-add"] },
  ],
});

test("D3: ssh-add cleared for .pgpass reaches the model raw; ssh-add printing another labelled document reaches it as a symbol (production proxy wiring)", async () => {
  const s = await boot(PER_PAIR);
  try {
    const q1 = "psql -c 'select count(*) from users'";
    await psqlCall(s, "c1", q1, [s.pgpass], "toolu_d3_1");
    const f1 = await toModel(s, "toolu_d3_1", q1, "count\n1204\n");
    assert.ok(f1.startsWith("count\n1204\n"), `the cleared pair: rows reach the model (${f1})`);

    const q2 = `psql -c "\\copy minutes from '${s.doc}'" -c 'select target from minutes'`;
    await psqlCall(s, "c2", q2, [s.doc], "toolu_d3_2");
    const f2 = await toModel(s, "toolu_d3_2", q2, `target\n${DOC_CANARY}\n`);
    assert.ok(!f2.includes(DOC_CANARY), `the minutes' text reached the model: ${f2}`);
    assert.match(f2, /^\$MDU:nomodel_Bash\[/);
    assert.match(f2, /\[mandu:secret\] masked: ssh-add read .*board-minutes\.md/);
  } finally {
    await s.stop();
  }
});

test("D3: one ssh-add holding .pgpass (cleared) and the minutes (not) reaches the model as a symbol", async () => {
  const s = await boot(PER_PAIR);
  try {
    const q = `psql -c "\\copy minutes from '${s.doc}'" -c 'select target from minutes'`;
    await psqlCall(s, "b1", q, [s.pgpass, s.doc], "toolu_d3_both");
    const f = await toModel(s, "toolu_d3_both", q, `target\n${DOC_CANARY}\n`);
    assert.ok(!f.includes(DOC_CANARY), `a file that does not clear ssh-add was released by one that does: ${f}`);
    assert.match(f, /^\$MDU:nomodel_Bash\[/);
    // control: the same law releases a ssh-add holding .pgpass alone, so the
    // symbol above is the minutes' doing.
    const q2 = "psql -c 'select count(*) from users'";
    await psqlCall(s, "b2", q2, [s.pgpass], "toolu_d3_alone");
    assert.ok((await toModel(s, "toolu_d3_alone", q2, "count\n1204\n")).startsWith("count\n1204\n"));
  } finally {
    await s.stop();
  }
});

test("D3: the legacy program-wide apps: rule releases neither file (deprecated, mask by default)", async () => {
  const s = await boot((pgpass, doc) => ({
    version: 1,
    paths: [
      { path: pgpass, level: "no-model", readers: ["ssh-add"] },
      { path: doc, level: "no-model", readers: ["ssh-add"] },
    ],
    apps: [{ app: "ssh-add", output: "clear" }],
  }));
  try {
    const q = `psql -c "\\copy minutes from '${s.doc}'" -c 'select target from minutes'`;
    await psqlCall(s, "l1", q, [s.doc], "toolu_d3_legacy");
    const f = await toModel(s, "toolu_d3_legacy", q, `target\n${DOC_CANARY}\n`);
    assert.ok(!f.includes(DOC_CANARY), `the program-wide rule written for .pgpass released the minutes: ${f}`);
    assert.match(f, /^\$MDU:nomodel_Bash\[/);
    const q2 = "psql -c 'select count(*) from users'";
    await psqlCall(s, "l2", q2, [s.pgpass], "toolu_d3_legacy2");
    assert.match(await toModel(s, "toolu_d3_legacy2", q2, "count\n1204\n"), /^\$MDU:nomodel_Bash\[/);
  } finally {
    await s.stop();
  }
});
