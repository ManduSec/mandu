/**
 * git-transport-printer (sandbox) — plan 13 D8 (11), continued 2026-10-07:
 * git's separately built transports are printers.
 *
 * `git-http-fetch` (git's dumb-HTTP fetch) and `git-http-push` (its WebDAV
 * push) are programs of their own in git's exec path, not links of git, and
 * they link git's `http.c`: libcurl opens `~/.netrc` for them, and
 * `GIT_TRACE_CURL=1 GIT_TRACE_REDACT=0` prints the `Authorization` header
 * they send, the `.netrc` password in it (base64). On the code before they
 * were on no printer list, so `{ app: git-http-fetch, prints: nothing }`,
 * the words Mandu's own hint suggests, let them read `.netrc` raw, and the
 * agent's code reading their stderr held the password. With the REAL guard
 * and arbiter, and the AnthropicProxy in its production wiring:
 *
 *   ~/.netrc  level no-model, readers: [{ app: git-http-fetch, prints: nothing },
 *             { app: git-http-push, prints: nothing }], bindings: [127.0.0.2]
 *   a server on 127.0.0.2 that answers 401 (Basic) to a request without a login
 *
 *   fetch  `GIT_TRACE_CURL=1 GIT_TRACE_REDACT=0 git-http-fetch -a <oid> http://127.0.0.2:…/r.git/`
 *   push   `… git-http-push --dry-run http://127.0.0.2:…/r.git/ HEAD`
 *
 * The oracle: each program ran and reached the server (the control: the
 * step is live), no form of the password (raw or base64 in the header)
 * reaches the agent's output, the server, or the model. Red on the code
 * before (both steps printed `Authorization: Basic <base64 of u:password>`
 * and sent it to the bound server). `git-imap-send` (IMAP) and
 * `git-http-backend` (a CGI server) are the same rule by name; their unit
 * and server-level proof is arbiter/test/unit/printer-git-transports.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import http from "node:http";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { agentNodeCopy, pickGuard } from "../../lib/native-guard.js";
import { holderReader, holderSkip } from "../../lib/holder-reader.js";
import { stateAxes } from "../../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const HERE = dirname(fileURLToPath(import.meta.url));
const GUARD = pickGuard(resolve(HERE, "..", "..", "..", "interceptors", "target"));
const has = (p: string): boolean => spawnSync("sh", ["-c", `command -v ${p}`]).status === 0;
/** git's exec path, where its transports live (Debian/Ubuntu/Arch, Fedora). */
const CORE = ["/usr/lib/git-core", "/usr/libexec/git-core"].find((d) => existsSync(join(d, "git-http-fetch")));
const skip = process.platform !== "linux" ? "Linux only"
  : !GUARD.path ? "mandu-net-guard is not built (scripts/build-native.sh)"
  : !has("git") ? "git is needed"
  : CORE === undefined ? "git-http-fetch is not installed (git built without curl)"
  : false;

const PASSWORD = `GIT_TRANSPORT_${process.pid}_p7Rq2`;
/** The header libcurl builds from `.netrc`: Basic, base64 of `u:<password>`. */
const BASIC = Buffer.from(`u:${PASSWORD}`).toString("base64");

/** The "agent": runs its Bash calls in order, prints what each returned. */
const AGENT_SOURCE = `import { spawnSync } from "node:child_process";
const cmds = JSON.parse(process.argv[2]);
const out = {};
for (const [k, cmd] of Object.entries(cmds)) {
  const r = spawnSync("bash", ["-c", cmd], { encoding: "utf8", timeout: 30000 });
  out[k] = (r.stdout ?? "") + (r.stderr ?? "");
}
process.stdout.write("AGENT_OUT " + JSON.stringify(out) + "\\n");
`;

function runGuarded(argv: string[], env: NodeJS.ProcessEnv): Promise<{ stdout: string; stderr: string; status: number | null }> {
  return new Promise((ok) => {
    const child = spawn(GUARD.path!, ["--allow", "127.0.0.0/8:*", "--", ...argv], { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", (c) => (stdout += String(c)));
    child.stderr.on("data", (c) => (stderr += String(c)));
    const timer = setTimeout(() => child.kill("SIGKILL"), 120_000);
    child.on("close", (status) => { clearTimeout(timer); ok({ stdout, stderr, status }); });
  });
}

/** A dumb-HTTP git server stand-in: 401 (Basic) without a login, 404 with
 *  one; keeps each request's method, path and Authorization header. */
function authServer(host: string): Promise<{ port: number; got: string[]; close: () => Promise<void> }> {
  return new Promise((ok) => {
    const got: string[] = [];
    const s = http.createServer((req, res) => {
      req.resume();
      const auth = req.headers.authorization;
      got.push(`${req.method} ${req.url} ${auth ?? "-"}`);
      if (auth === undefined) res.writeHead(401, { "WWW-Authenticate": 'Basic realm="r"', "Content-Length": "0" }).end();
      else res.writeHead(404, { "Content-Length": "0" }).end();
    });
    s.listen(0, host, () => ok({ port: (s.address() as { port: number }).port, got, close: () => new Promise((d) => s.close(() => d())) }));
  });
}

function post(port: number, body: unknown, session: string): Promise<number> {
  return new Promise((ok, fail) => {
    const req = http.request({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": session } },
      (res) => { res.resume(); res.on("end", () => ok(res.statusCode ?? 0)); });
    req.on("error", fail);
    req.end(JSON.stringify(body));
  });
}

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

test("git-http-fetch and git-http-push vouched for (prints: nothing) on ~/.netrc read no byte of it: no password in their GIT_TRACE_CURL output, at the server, or on the model's wire (secrets axes)", { skip, timeout: 240_000 }, async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-git-transport-"));
  const home = join(tmp, "home");
  const ws = join(tmp, "ws");
  mkdirSync(home, { recursive: true });
  mkdirSync(ws, { recursive: true });
  const netrc = join(home, ".netrc");
  writeFileSync(netrc, `machine 127.0.0.2 login u password ${PASSWORD}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, ["version: 1", "paths:", `  - path: ${netrc}`, "    level: no-model",
    "    readers: [{ app: git-http-fetch, prints: nothing }, { app: git-http-push, prints: nothing }]",
    '    bindings: ["127.0.0.2"]', ""].join("\n"));
  // a repository for the transports to run in (they need one)
  const repo = join(ws, "r");
  assert.equal(spawnSync("git", ["init", "-q", repo]).status, 0);

  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const client = new ArbiterClient(sock);
  await client.connect();
  const humanClient = new ArbiterClient(human);
  await humanClient.connect();
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const session = `git-transport-${process.pid}`;
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(client, humanClient), upstream: upstream.fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const remote = await authServer("127.0.0.2");
  try {
    const reg = await client.registerSecret({ path: netrc, home });
    assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
    const twin = join(tmp, "twin");
    writeFileSync(twin, typeof (reg as { twin?: unknown }).twin === "string" ? String((reg as { twin?: string }).twin) : `${reg.symbol}\n`);
    const secretPolicy = join(tmp, "secret-policy.json");
    const agentNode = agentNodeCopy(tmp);
    writeFileSync(secretPolicy, JSON.stringify({ unixDeny: [join(tmp, "human")], agentExe: agentNode, ask: "never", session, secrets: [{ path: netrc, twin, level: "no-model" }] }));

    const url = `http://127.0.0.2:${remote.port}/r.git/`;
    const trace = "GIT_TRACE_CURL=1 GIT_TRACE_REDACT=0 GIT_TERMINAL_PROMPT=0";
    const cmds: Record<string, string> = {
      fetch: `cd "$R" && ${trace} ${CORE}/git-http-fetch -a ${"1".repeat(40)} ${url}`,
      push: `cd "$R" && ${trace} ${CORE}/git-http-push --dry-run ${url} HEAD`,
    };
    // git-http-push is left out of a build without expat
    if (!existsSync(join(CORE!, "git-http-push"))) delete cmds["push"];
    const agentJs = join(tmp, "agent.mjs");
    writeFileSync(agentJs, AGENT_SOURCE);
    for (const [k, cmd] of Object.entries(cmds)) await humanClient.recordCallCommand({ callId: `toolu_gt_${k}`, command: cmd, sessionKey: session });
    const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, R: repo, MANDU_ARBITER_SOCK: sock, MANDU_NET_GUARD_SECRETS: secretPolicy, MANDU_NET_GUARD_STAT_TWINS: "1" };
    for (const k of Object.keys(env)) if (k.startsWith("GIT_")) delete env[k];
    const run = await runGuarded([agentNode, agentJs, JSON.stringify(cmds)], env);
    const line = (run.stdout ?? "").split("\n").find((l) => l.startsWith("AGENT_OUT "));
    if (!line && /seccomp|SECCOMP|user notification|ENOSYS|not supported/i.test(run.stderr ?? "")) {
      t.skip(`the guard cannot attach here: ${run.stderr.slice(0, 300)}`);
      return;
    }
    assert.ok(line, `the agent ran under the guard (status ${run.status}): ${run.stdout}\n${run.stderr}`);
    const got = JSON.parse(line!.slice("AGENT_OUT ".length)) as Record<string, string>;
    const show = JSON.stringify(got, null, 1);

    for (const k of Object.keys(cmds)) {
      // the control: the program ran and its trace is in the output
      assert.match(got[k]!, /http\.c|=> Send header/, `${k} ran with its curl trace on: ${show}`);
      assert.ok(!got[k]!.includes(BASIC) && !got[k]!.includes(PASSWORD),
        `CONFIDENTIALITY VIOLATION: ${k} (a printer vouched for with prints: nothing) read ~/.netrc raw and printed the login it sends: ${show}`);
    }
    // the control: each program reached the server
    assert.ok(remote.got.some((r) => r.startsWith("GET /r.git/")), `git-http-fetch reached the server: ${remote.got.join(" | ")}`);
    if (cmds["push"]) assert.ok(remote.got.some((r) => r.startsWith("PROPFIND /r.git/")), `git-http-push reached the server: ${remote.got.join(" | ")}`);
    assert.deepEqual(remote.got.filter((r) => r.includes(BASIC)), [], "CONFIDENTIALITY VIOLATION: the password left in a login header");

    // No form of it reaches the model.
    for (const [k, cmd] of Object.entries(cmds)) {
      const id = `toolu_gt_${k}`;
      assert.equal(await post(port, { model: "claude-sonnet-4-5", stream: true, max_tokens: 256, tools: [{ name: "Bash", input_schema: { type: "object" } }], messages: [
        { role: "user", content: "go" },
        { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command: cmd } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: got[k] ?? "" }] },
      ] }, session), 200);
    }
    const wire = upstream.requests.map((r) => r.bodyText).join("\n");
    assert.ok(!wire.includes(PASSWORD) && !wire.includes(BASIC), "no form of the password reached the model");
  } finally {
    await proxy.close();
    client.close();
    humanClient.close();
    await remote.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

/** The prefix class (the maintainer's decision of 2026-10-07): a helper of
 *  any name `git-credential-…` prints the password it reads, so the human's
 *  word cannot let it read a labelled file. The helper here is the test's
 *  own reader (tests/lib/holder-reader.c, which prints the files it is
 *  given), built twice: as `git-credential-mdu` and, the control, as
 *  `mdu-holder`, each pinned by path and hash with `prints: nothing`. */
const helperSkip = process.platform !== "linux" ? "Linux only"
  : !GUARD.path ? "mandu-net-guard is not built (scripts/build-native.sh)"
  : holderSkip();

test("a git credential helper of any name (git-credential-*), pinned by path and hash and vouched for, reads no byte of a labelled file under the real guard; the same program under another name does (secrets axes)", { skip: helperSkip, timeout: 240_000 }, async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-git-cred-"));
  const home = join(tmp, "home");
  mkdirSync(home, { recursive: true });
  const env = join(home, ".env");
  writeFileSync(env, `API_TOKEN=${PASSWORD}\n`);
  const helper = holderReader(tmp, "git-credential-mdu");
  const control = holderReader(tmp, "mdu-holder");
  assert.ok(helper && control, "the test's reader builds");
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, ["version: 1", "paths:", `  - path: ${env}`, "    level: no-model", `    readers: [${helper.yaml}, ${control.yaml}]`, ""].join("\n"));
  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const client = new ArbiterClient(sock);
  await client.connect();
  const humanClient = new ArbiterClient(human);
  await humanClient.connect();
  const session = `git-cred-${process.pid}`;
  try {
    const reg = await client.registerSecret({ path: env, home });
    assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
    const twin = join(tmp, "twin");
    writeFileSync(twin, typeof (reg as { twin?: unknown }).twin === "string" ? String((reg as { twin?: string }).twin) : `${reg.symbol}\n`);
    const secretPolicy = join(tmp, "secret-policy.json");
    const agentNode = agentNodeCopy(tmp);
    writeFileSync(secretPolicy, JSON.stringify({ unixDeny: [join(tmp, "human")], agentExe: agentNode, ask: "never", session, secrets: [{ path: env, twin, level: "no-model" }] }));
    const cmds: Record<string, string> = { helper: `"${helper.path}" "$F"`, control: `"${control.path}" "$F"` };
    const agentJs = join(tmp, "agent.mjs");
    writeFileSync(agentJs, AGENT_SOURCE);
    for (const [k, cmd] of Object.entries(cmds)) await humanClient.recordCallCommand({ callId: `toolu_gc_${k}`, command: cmd, sessionKey: session });
    const run = await runGuarded([agentNode, agentJs, JSON.stringify(cmds)], { ...process.env, HOME: home, F: env, MANDU_ARBITER_SOCK: sock, MANDU_NET_GUARD_SECRETS: secretPolicy, MANDU_NET_GUARD_STAT_TWINS: "1" });
    const line = (run.stdout ?? "").split("\n").find((l) => l.startsWith("AGENT_OUT "));
    if (!line && /seccomp|SECCOMP|user notification|ENOSYS|not supported/i.test(run.stderr ?? "")) {
      t.skip(`the guard cannot attach here: ${run.stderr.slice(0, 300)}`);
      return;
    }
    assert.ok(line, `the agent ran under the guard (status ${run.status}): ${run.stdout}\n${run.stderr}`);
    const got = JSON.parse(line!.slice("AGENT_OUT ".length)) as Record<string, string>;
    // the control: the same program under another name, vouched for, reads it
    assert.ok(got["control"]!.includes(PASSWORD), `the control (mdu-holder, pinned and vouched for) read the file raw: ${JSON.stringify(got)}`);
    assert.ok(!got["helper"]!.includes(PASSWORD), `CONFIDENTIALITY VIOLATION: git-credential-mdu (a credential helper, pinned with prints: nothing) read the file raw: ${JSON.stringify(got)}`);
  } finally {
    client.close();
    humanClient.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
