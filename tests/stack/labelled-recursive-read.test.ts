/**
 * A labelled file the launch did not register, read by a recursive or
 * indirect read (confidentiality.md §6 "Read by a program the launch did not
 * see", 2026-10-17), across the REAL ArbiterServer in `secrets` and the REAL
 * anthropic-proxy in production wiring (`new ArbiterClientAdapter(new
 * ArbiterClient(sock), human)`), a mock model behind it.
 *
 * The workspace's `vault/` (a literal folder label) and `notes/*.md` (a
 * pattern) are labelled `no-model` MID-SESSION, by a policy.yaml edit, the
 * way a human labels a folder while the agent runs: no launch walk ever saw
 * the labels, and nothing calls `registerSecret` for the files. Each command
 * below prints the plan's line the way the real program would (`grep -r`,
 * `rg`, `git grep`, `tar`, `find -exec cat`, `os.walk`, a read from a shell
 * already inside the folder, a symlink made earlier or in the same command,
 * `curl file://`, `~user/…`); the model must never receive the plan's text.
 *
 * Before the change every case but the control reached the model in clear:
 * the file's text was never a registered value, and the text scan cannot
 * place a path it is not shown (a `grep -r .` hit names `./vault/plan.md`
 * relative to a start it may not know; `tar` names nothing). Now the label
 * act registers the files already under it (server.ts
 * `syncLabelRegistrations`), so the value backstop masks every print. A
 * file created under the label after that is the guard's to gate at the
 * open (confidentiality.md §6, "Read by a program the launch did not see").
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir, userInfo } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets");

/** The plan's text, assembled at run time. */
const PLAN = ["PLAN", "RECURSIVE", "LABELLED", "9c4d"].join("-");

test("a folder and a pattern labelled mid-session: every recursive and indirect read of their files reaches the model masked (secrets axes, explicit)", { timeout: 60_000 }, async () => {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mandu-recursive-")));
  const ws = join(tmp, "ws");
  for (const d of ["vault", "notes", "sub"]) mkdirSync(join(ws, d), { recursive: true });
  writeFileSync(join(ws, "vault", "plan.md"), `password: ${PLAN}\n`);
  writeFileSync(join(ws, "notes", "plan.md"), `password: ${PLAN}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, "version: 1\n");
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    policyPath: policy, policyPollMs: 50, log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const guard = await open(humanSock);
  const human = await open(humanSock);
  const session = `recursive-${process.pid}`;
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await open(sock), human), upstream: upstream.fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  let n = 0;
  /** One Bash call whose result is `output`; what the model received. */
  const bashCall = async (command: string, output: string, cwd: string | null): Promise<string> => {
    const id = `toolu_rr_${n++}`;
    await human.recordCallCommand({ callId: id, command, sessionKey: session });
    await guard.recordExecRoot({ procKey: `sh-${id}`, ancestors: ["agent-rr-0"], session, callRoot: true, argv: ["/bin/bash", "-c", command], ...(cwd !== null ? { cwd } : {}) });
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({
        model: "claude-sonnet-4-5", stream: true, max_tokens: 256,
        tools: [{ name: "Bash", input_schema: { type: "object" } }],
        messages: [
          { role: "user", content: "go" },
          { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command } }] },
          { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: output }] },
        ],
      }),
    });
    assert.equal(res.status, 200, await res.text());
    const body = upstream.requests.at(-1)!.json() as { messages: Array<{ content: Array<{ content?: unknown }> }> };
    return JSON.stringify(body.messages[2]!.content[0]!.content);
  };
  const line = `password: ${PLAN}`;
  const home = homedir();
  const tilde = ws.startsWith(home + "/") ? `~${userInfo().username}${ws.slice(home.length)}` : ws;
  const cases: Array<[string, string, string | null]> = [
    ["cat vault/plan.md", `${line}\n`, ws], // control: the scan places it
    ["grep -r password .", `./vault/plan.md:${line}\n`, ws],
    ["rg password", `vault/plan.md\n1:${line}\n`, ws],
    ["git grep -n password", `vault/plan.md:1:${line}\n`, ws],
    ["tar cf - . | tar xOf -", `${line}\n`, ws],
    ["find . -name '*.md' -exec cat {} +", `${line}\n`, ws],
    [`python3 -c "import os;[print(open(os.path.join(d,f)).read()) for d,_,fs in os.walk('.') for f in fs]"`, `${line}\n`, ws],
    ["cat plan.md", `${line}\n`, null], // a shell already in vault/, no start dir
    ["cat plan.md", `${line}\n`, null], // a shell already in notes/ (the pattern), no start dir
    ["cat v/plan.md", `${line}\n`, ws], // a symlink v -> vault made by an earlier call
    ["ln -s va* v2 && cat v2/plan.md", `${line}\n`, ws], // a symlink made in the same command
    [`curl -s file://${ws}/vault/plan.md`, `${line}\n`, ws],
    [`cat ${tilde}/vault/plan.md`, `${line}\n`, ws],
  ];
  try {
    // The labels arrive MID-SESSION: a policy.yaml edit the arbiter reloads.
    writeFileSync(policy, `version: 1\npaths:\n  - path: ${join(ws, "vault")}\n    level: no-model\n  - path: ${join(ws, "notes")}/*.md\n    level: no-model\n`);
    const deadline = Date.now() + 20_000;
    for (;;) {
      await new Promise((r) => setTimeout(r, 100));
      await server.labelRegistrationsSettled();
      const reg = server.dispatch({ id: 1, op: "secretRegistry" } as never) as { ok: true; result: { entries: Array<{ path: string }> } };
      const paths = new Set(reg.result.entries.map((e) => e.path));
      if (paths.has(join(ws, "vault", "plan.md")) && paths.has(join(ws, "notes", "plan.md"))) break;
      assert.ok(Date.now() < deadline, `the label act registered the files under it: ${[...paths].join(" ")}`);
    }
    const report: string[] = [];
    for (const [cmd, out, cwd] of cases) {
      const seen = await bashCall(cmd, out, cwd);
      report.push(`${seen.includes(PLAN) ? "LEAK  " : "masked"} | ${cmd} (start ${cwd === null ? "unknown" : "ws"})`);
    }
    assert.ok(report.every((r) => r.startsWith("masked")), report.join("\n"));
  } finally {
    await proxy.close();
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
