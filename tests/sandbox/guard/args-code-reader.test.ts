/**
 * args-code-reader (sandbox) — confidentiality plan 13 §3 D8, "code by
 * argument" (2026-10-02), with the REAL guard reading each opener's command
 * line and environment (args_code.rs).
 *
 *   the real mandu-net-guard (seccomp user notification, no root) around an
 *   "agent" that runs Bash calls, in `secrets`, against a real ArbiterServer
 *   loaded from a policy.yaml on disk:
 *     ~/.env   readers: [git, less, sed, vim, { app: sha256sum, prints: nothing }]
 *
 * Each listed program reads the file once with a plain command line (the
 * control), and once handed code by an option or a variable:
 *   git   `git hash-object`            vs `git -c alias.x='!true' hash-object`, `GIT_PAGER='sh -c cat' git …`
 *   less  `less F`                     vs `less +G F`, `LESSOPEN='|cat %s' less F`
 *   sed   `sed -n p F`, `sed --sandbox` vs `sed -n '1e true' F`
 *   vim   (always runs code: its vimrc, plugins, -c) `vim -es -c '%p' -c 'q!' F`
 * The oracle: the control (`sha256sum`, a listed leaf program; GNU's
 * `gnusha256sum` where uutils owns the name, tests/lib/gnu-coreutil.ts)
 * reads the real bytes; no handed-code invocation reads a byte of the file (no
 * canary, nothing counted), and no byte of it reaches the model through the
 * AnthropicProxy in its production wiring.
 * Since 2026-10-03 (plan 13 D8, printers admit nothing) less and sed are
 * printers: listed, they admit nothing, so their plain controls read no
 * byte either (asserted; until then they read the real file), and their
 * handed-code forms are refused before the argument rule is consulted
 * (args_code.rs still unit-tests those rules). Since 2026-10-04 (plan 13
 * §4.9 option (a)) git is one too: its plain `git hash-object` reads no
 * byte (until then it read the real file, the control), and its store
 * helper, the default reader of `.git-credentials`, reads the twin
 * (without the wire release, as here, an HTTPS login with it fails).
 * Red before the change: each handed-code invocation read the file raw (the
 * pin names the binary, not what it is told to run), and vim, a listed
 * reader, read it raw. tar's, ssh's, psql's and rsync's rules are
 * unit-tested only (args_code.rs): GNU tar could not archive a guarded
 * secret file then ("Cannot stat: Invalid argument" under the guard, fixed
 * 2026-10-03, tar-secret.test.ts), and the others need a server.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import http from "node:http";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { agentNodeCopy, pickGuard } from "../../lib/native-guard.js";
import { gnuCoreutil } from "../../lib/gnu-coreutil.js";
import { stateAxes } from "../../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const HERE = dirname(fileURLToPath(import.meta.url));
const GUARD = pickGuard(resolve(HERE, "..", "..", "..", "interceptors", "target"));
/** The control's leaf reader: GNU sha256sum (`gnusha256sum` where uutils owns
 *  the name; every uutils program is a printer, and a listed one reads no byte). */
const SUM = gnuCoreutil("sha256sum");
const has = (p: string): boolean => spawnSync("sh", ["-c", `command -v ${p}`]).status === 0;
const skip = process.platform !== "linux" ? "Linux only"
  : !GUARD.path ? "mandu-net-guard is not built (scripts/build-native.sh)"
  : !["git", "less", "sed"].every(has) ? "git, less and sed are needed"
  : SUM === undefined ? "no GNU sha256sum (the control's leaf reader; uutils' is a printer)"
  : false;

const CANARY = `ARGS_CODE_CANARY_${process.pid}_x7Qm2`;
const RAW = `DB_PASSWORD=${CANARY}\n`;
const CRED_PW = `credpw${process.pid}Zq8w`;

/** The "agent": runs its Bash calls, prints what each returned. */
const AGENT_SOURCE = `import { spawnSync } from "node:child_process";
const cmds = JSON.parse(process.argv[2]);
const out = {};
for (const [k, cmd] of Object.entries(cmds)) {
  const r = spawnSync("bash", ["-c", cmd], { encoding: "utf8" });
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

test("code by argument under the REAL guard: a listed reader handed code by an option or a variable reads no byte; the same reader with a plain command line reads the file; vim never does (secrets axes)", { skip, timeout: 300_000 }, async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-args-code-guard-"));
  const home = join(tmp, "home");
  mkdirSync(home, { recursive: true });
  const secret = join(home, ".env");
  writeFileSync(secret, RAW);
  // A known consumer's file with no reader list: git (its store helper) is
  // its consumer, a printer since 2026-10-04 (plan 13 §4.9).
  const creds = join(home, ".git-credentials");
  writeFileSync(creds, `https://builder:${CRED_PW}@git.example.com\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, [
    "version: 1",
    "paths:",
    `  - path: ${secret}`,
    "    level: no-model",
    `    readers: [git, less, sed, vim, { app: ${SUM!.app}, prints: nothing }]`,
    "",
  ].join("\n"));

  const logs: string[] = [];
  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: (l: string) => logs.push(l), confidentiality: true, integrity: false });
  await server.listen();
  const client = new ArbiterClient(sock);
  await client.connect();
  const humanClient = new ArbiterClient(human);
  await humanClient.connect();
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const session = `args-code-${process.pid}`;
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(client, humanClient), upstream: upstream.fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const reg = await client.registerSecret({ path: secret, home });
    assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
    const twin = join(tmp, "twin");
    writeFileSync(twin, typeof (reg as { twin?: unknown }).twin === "string" ? String((reg as { twin?: string }).twin) : `${reg.symbol}\n`);
    const regC = await client.registerSecret({ path: creds, home });
    const twinC = join(tmp, "twin-creds");
    writeFileSync(twinC, typeof (regC as { twin?: unknown }).twin === "string" ? String((regC as { twin?: string }).twin) : `${regC.symbol}\n`);
    const secretPolicy = join(tmp, "secret-policy.json");
    const agentNode = agentNodeCopy(tmp);
    writeFileSync(secretPolicy, JSON.stringify({ unixDeny: [join(tmp, "human")], agentExe: agentNode, ask: "never", session, secrets: [{ path: secret, twin, level: "no-model" }, { path: creds, twin: twinC, level: "no-model" }] }));

    const count = (cmd: string): string => `${cmd} 2>/dev/null | wc -c`;
    const show = (cmd: string): string => `${cmd} 2>&1 | head -c 600`;
    const fill = `printf 'protocol=https\\nhost=git.example.com\\n\\n' | GIT_TERMINAL_PROMPT=0 git`;
    const cmds: Record<string, string> = {
      gitOk: `git hash-object "$F"`,
      sumOk: `${SUM!.app} "$F"`,
      gitAlias: `git -c alias.x='!true' hash-object "$F"`,
      gitPager: `GIT_PAGER='sh -c cat' git hash-object "$F"`,
      lessOk: count(`less "$F"`),
      lessPlus: show(`less +G "$F"`),
      lessOpen: show(`LESSOPEN='|cat %s' less "$F"`),
      sedOk: count(`sed -n p "$F"`),
      sedSandbox: count(`sed --sandbox -n p "$F"`),
      sedE: show(`sed -n -e p -e '1e true' "$F"`),
      credStore: `${fill} -c credential.helper=store credential fill 2>&1 | sed -n 's/^password=//p'`,
      credHelper: `${fill} -c 'credential.helper=!f() { cat >/dev/null; }; f' -c credential.helper=store credential fill 2>&1 | head -c 400`,
      vim: has("vim") ? `vim -es -c '%p' -c 'q!' "$F" 2>&1 | head -c 400` : "echo no-vim",
    };
    const agentJs = join(tmp, "agent.mjs");
    writeFileSync(agentJs, AGENT_SOURCE);
    for (const [k, cmd] of Object.entries(cmds)) await humanClient.recordCallCommand({ callId: `toolu_ac_${k}`, command: cmd, sessionKey: session });
    const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, F: secret, MANDU_ARBITER_SOCK: sock, MANDU_NET_GUARD_SECRETS: secretPolicy };
    for (const n of ["GIT_PAGER", "PAGER", "LESSOPEN", "LESSCLOSE", "LESS", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "TAR_OPTIONS"]) delete env[n];
    const run = await runGuarded([agentNode, agentJs, JSON.stringify(cmds)], env);
    const line = (run.stdout ?? "").split("\n").find((l) => l.startsWith("AGENT_OUT "));
    if (!line && /seccomp|SECCOMP|user notification|ENOSYS|not supported/i.test(run.stderr ?? "")) {
      t.skip(`the guard cannot attach here: ${run.stderr.slice(0, 300)}`);
      return;
    }
    assert.ok(line, `the agent ran under the guard (status ${run.status}): ${run.stdout}\n${run.stderr}`);
    const got = JSON.parse(line!.slice("AGENT_OUT ".length)) as Record<string, string>;

    // The control reads the real file: a listed leaf program.
    const hash = spawnSync("git", ["hash-object", "--stdin"], { input: RAW, encoding: "utf8" }).stdout.trim();
    const sum = createHash("sha256").update(RAW).digest("hex");
    assert.match(got["sumOk"]!, new RegExp(`^${sum}\\b`), `sha256sum, listed, read the real file: ${got["sumOk"]}`);
    // Plan 13 §4.9 option (a): git is a printer, so even its plain command
    // line reads no byte (red before: it read the real file).
    assert.notEqual(got["gitOk"]!.trim(), hash, `CONFIDENTIALITY VIOLATION: a listed git read the real file: ${got["gitOk"]}`);
    const n = String(Buffer.byteLength(RAW));
    // Plan 13 D8, printers admit nothing: less and sed listed read no byte,
    // however plain their command line.
    for (const k of ["lessOk", "sedOk", "sedSandbox"]) assert.notEqual(got[k]!.trim(), n, `${k}: a listed printer read the real file (${got[k]})`);

    // git's store helper, the consumer of .git-credentials, is git: a
    // printer since 2026-10-04, it reads the twin (no wire release here),
    // so the password it hands out is the twin's symbol; with a `!` helper
    // beside it, the twin as well.
    const decided = logs.filter((l) => /decideSecretOpen/.test(l)).join("\n");
    assert.ok(!got["credStore"]!.includes(CRED_PW), `CONFIDENTIALITY VIOLATION: git's store helper read the real file: ${got["credStore"]}\n${decided}`);
    assert.match(got["credStore"]!, /\$MDU:/, `git's store helper read the twin: ${got["credStore"]}\n${decided}`);
    assert.ok(!got["credHelper"]!.includes(CRED_PW), `a store helper under a \`!\` helper's -c read the real file: ${got["credHelper"]}\n${decided}`);

    // No invocation handed code read a byte.
    const leaks: string[] = [];
    for (const k of ["gitOk", "gitAlias", "gitPager", "lessOk", "lessPlus", "lessOpen", "sedOk", "sedSandbox", "sedE", "vim"]) {
      const out = got[k] ?? "";
      if (out.includes(CANARY) || out.includes(hash)) leaks.push(`${k}: ${out.slice(0, 200)}`);
    }
    assert.deepEqual(leaks, [], "CONFIDENTIALITY VIOLATION: a reader handed code by its command line or environment read the file");

    // Nothing of the file reaches the model.
    for (const [k, cmd] of Object.entries(cmds)) {
      const id = `toolu_ac_${k}`;
      assert.equal(await post(port, { model: "claude-sonnet-4-5", stream: true, max_tokens: 256, tools: [{ name: "Bash", input_schema: { type: "object" } }], messages: [
        { role: "user", content: "go" },
        { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command: cmd } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: got[k] ?? "" }] },
      ] }, session), 200);
    }
    const wire = upstream.requests.map((r) => r.bodyText).join("\n");
    assert.ok(!wire.includes(CANARY) && !wire.includes(CRED_PW), "no byte of either file reached the model");
  } finally {
    await proxy.close();
    client.close();
    humanClient.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
