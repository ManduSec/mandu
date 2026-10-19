/**
 * reader-output-rule (sandbox) — confidentiality plan 13 D3 with the REAL
 * guard writing the taint records: the output declassifier is keyed by the
 * (file, program) pair.
 *
 *   the real mandu-net-guard (seccomp user notification, no root) around an
 *   "agent" that runs Bash calls, in `secrets`, against a real ArbiterServer
 *   loaded from a policy.yaml on disk (the strict loader and validator):
 *     ~/.pgpass       readers: [{ app: sha256sum, output: clear, prints: nothing },
 *                               { app: mdu-holder, path, sha256, output: clear }]
 *     board-minutes   readers: [{ app: mdu-holder, path, sha256 }]  (no output rule)
 *   `mdu-holder` is a reader the test builds and pins by path and hash
 *   (tests/lib/holder-reader.ts): until 2026-10-03 the test listed `cat`
 *   itself, which admits nothing since plan 13 D8's "printers admit
 *   nothing"; it stands in for psql, a program cleared for one file.
 *   `sha256sum` (GNU's: `gnusha256sum` where uutils owns the name) is a
 *   leaf reader named bare, for the first-use pin (until 2026-10-04 `wc`,
 *   a printer since: `wc --files0-from=<file>` prints each line as a name
 *   it cannot open). The calls: `holder .pgpass | wc -c` (the cleared
 *   pair), `sha256sum .pgpass` (the bare-name reader, cleared), `holder
 *   minutes | od …` (the holder on a file whose entry clears nothing; the
 *   output is a hex transform no value scan can see), and `holder .pgpass
 *   minutes | od …` (one process holding both). Each result goes to the
 *   model through the AnthropicProxy in its production wiring.
 *
 * The oracle: the minutes' bytes never reach the model, alone or beside the
 * cleared file; the cleared pairs' output does (the control that the rule is
 * read at all); the first-use pin the arbiter writes into policy.yaml for
 * sha256sum keeps the entry's `output:` (a system binary). Red before 2026-10-02:
 * the loader refused `output:` on a reader entry, and the program-wide
 * `apps:` rule was the only way to clear cat, which then cleared the minutes
 * too.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import http from "node:http";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
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
/** GNU sha256sum (a leaf reader, system binary, no printer): `gnusha256sum`
 *  where uutils owns `sha256sum` (every uutils program is a printer, one
 *  multi-call binary). */
const SUM = ["/usr/bin/gnusha256sum", "/usr/bin/sha256sum", "/bin/sha256sum"].find((p) => existsSync(p) && !realpathSync(p).startsWith("/usr/lib/cargo/"));
const skip = process.platform !== "linux" ? "Linux only" : !GUARD.path ? "mandu-net-guard is not built (scripts/build-native.sh)"
  : holderSkip() !== false || SUM === undefined ? "no C compiler (the pinned holder) or no GNU sha256sum (the bare-name reader)" : false;

const PG_CANARY = `PGPASS_D3_CANARY_${process.pid}`;
const DOC_CANARY = `D3_MINUTES_CANARY_${process.pid}`;
const hex = (s: string): string => Buffer.from(s).toString("hex");

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

test("D3: a reader's output rule is per (file, program): the REAL guard's records, the production proxy; the uncleared file never reaches the model (secrets axes)", { skip, timeout: 300_000 }, async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-d3-guard-"));
  const home = join(tmp, "home");
  mkdirSync(home, { recursive: true });
  const pgpass = join(home, ".pgpass");
  const minutes = join(home, "board-minutes.md");
  writeFileSync(pgpass, `db:5432:prod:app:${PG_CANARY}\n`);
  writeFileSync(minutes, `# Board minutes\nacquisition target: ${DOC_CANARY}\n`);
  const policy = join(tmp, "policy.yaml");
  const holder = holderReader(tmp)!;
  const sum = realpathSync(SUM!);
  const sumApp = sum.slice(sum.lastIndexOf("/") + 1);
  writeFileSync(policy, [
    "version: 1",
    "paths:",
    `  - path: ${pgpass}`,
    "    level: no-model",
    "    readers:",
    `      - { app: ${sumApp}, output: clear, prints: nothing }`,
    `      - { app: ${holder.app}, path: ${holder.path}, sha256: ${holder.sha256}, output: clear, prints: nothing }`,
    `  - path: ${minutes}`,
    "    level: no-model",
    `    readers: [${holder.yaml}]`,
    "",
  ].join("\n"));

  const sock = join(tmp, "arbiter.sock");
  // The human plane: the guard reports there, where it is believed (plan 13 D9).
  const human = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const client = new ArbiterClient(sock);
  await client.connect();
  // The proxies' second client (server-main): execGate and callTaint ride
  // the human socket, the only one the arbiter binds a call from (plan 13 D9).
  const humanClient = new ArbiterClient(human);
  await humanClient.connect();
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const session = `d3-guard-${process.pid}`;
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(client, humanClient), upstream: upstream.fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    // The launcher registers both files and writes the guard's policy file.
    const secrets: Array<{ path: string; twin: string; level: string }> = [];
    for (const [i, p] of [pgpass, minutes].entries()) {
      const reg = await client.registerSecret({ path: p, home });
      assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
      const twin = join(tmp, `twin-${i}`);
      writeFileSync(twin, typeof (reg as { twin?: unknown }).twin === "string" ? String((reg as { twin?: string }).twin) : `${reg.symbol}\n`);
      secrets.push({ path: p, twin, level: "no-model" });
    }
    const secretPolicy = join(tmp, "secret-policy.json");
    // agentExe: the agent's own binary, so the guard reports its Bash shells as
    // call roots (plan 13 D7: a call not bound to one is masked while the
    // session holds a raw read)
    const agentNode = agentNodeCopy(tmp);
    writeFileSync(secretPolicy, JSON.stringify({ unixDeny: [join(tmp, "human")], agentExe: agentNode, ask: "never", session, secrets }));

    // The files are named through the environment, as psql finds its
    // PGPASSFILE: a command that names a secret path is masked by the
    // proxy's path rule whatever the output rule says, so only a command
    // that does not name it shows what the rule alone decides.
    const cmds = {
      // (by name, on the PATH; before 2026-10-03 a command that started and
      // ended with a quote was read back differently by the call-root
      // recorder's signature, plan 13 D7 "The signature's quoting")
      cleared: `mdu-holder "$PGPASSFILE" | wc -c`,
      counted: `${sumApp} "$PGPASSFILE"`,
      minutes: `mdu-holder "$MINUTES" | od -An -tx1 | tr -d " \\n"`,
      both: `mdu-holder "$PGPASSFILE" "$MINUTES" | od -An -tx1 | tr -d " \\n"`,
    };
    const agentJs = join(tmp, "agent.mjs");
    writeFileSync(agentJs, AGENT_SOURCE);
    // The proxy's record of each call's command, made when it relayed the
    // call (its response side; plan 13 D9 follow-up: a call binds by it).
    for (const [k, cmd] of Object.entries(cmds)) await humanClient.recordCallCommand({ callId: `toolu_d3_${k}`, command: cmd, sessionKey: session });
    // Async: the arbiter answers the guard from THIS process's event loop.
    const run = await runGuarded([agentNode, agentJs, JSON.stringify(cmds)], { ...process.env, HOME: home, PGPASSFILE: pgpass, MINUTES: minutes, PATH: `${join(tmp, "bin")}:${process.env.PATH ?? "/usr/bin:/bin"}`, MANDU_ARBITER_SOCK: sock, MANDU_NET_GUARD_SECRETS: secretPolicy });
    const line = (run.stdout ?? "").split("\n").find((l) => l.startsWith("AGENT_OUT "));
    if (!line && /seccomp|SECCOMP|user notification|ENOSYS|not supported/i.test(run.stderr ?? "")) {
      t.skip(`the guard cannot attach here: ${run.stderr.slice(0, 300)}`);
      return;
    }
    assert.ok(line, `the agent ran under the guard (status ${run.status}): ${run.stdout}\n${run.stderr}`);
    const got = JSON.parse(line!.slice("AGENT_OUT ".length)) as Record<string, string>;
    // Preconditions: the holder got the real bytes of both files (so a leak is possible).
    const pgLen = String(Buffer.byteLength(`db:5432:prod:app:${PG_CANARY}\n`));
    assert.equal(got["cleared"]!.trim(), pgLen, `the holder read the real .pgpass: ${got["cleared"]}`);
    const pgSum = createHash("sha256").update(`db:5432:prod:app:${PG_CANARY}\n`).digest("hex");
    assert.equal(got["counted"]!.trim().split(/\s+/)[0], pgSum, `sha256sum read the real .pgpass: ${got["counted"]}`);
    const minutesHex = hex(`# Board minutes\nacquisition target: ${DOC_CANARY}\n`);
    assert.equal(got["minutes"]!.trim(), minutesHex, `the holder read the real minutes: ${got["minutes"]}`);
    assert.ok(got["both"]!.includes(minutesHex), `the holder read both: ${got["both"]}`);

    const send = async (command: string, result: string, id: string): Promise<string> => {
      const n = upstream.requests.length;
      assert.equal(await post(port, { model: "claude-sonnet-4-5", stream: true, max_tokens: 512, tools: [{ name: "Bash", input_schema: { type: "object" } }], messages: [
        { role: "user", content: "go" },
        { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: result }] },
      ] }, session), 200);
      assert.equal(upstream.requests.length, n + 1);
      const b = upstream.requests[n]!.json() as { messages: Array<{ content: Array<{ content: unknown }> }> };
      return JSON.stringify(b.messages[2]!.content[0]!.content);
    };
    const leaks: string[] = [];
    const cleared = await send(cmds.cleared, got["cleared"]!, "toolu_d3_cleared");
    assert.ok(cleared.includes(got["cleared"]!.trim()) && !cleared.includes("$MDU:"), `the cleared pair reaches the model as printed: ${cleared}`);
    const counted = await send(cmds.counted, got["counted"]!, "toolu_d3_counted");
    assert.ok(counted.includes(pgSum) && !counted.includes("$MDU:"), `the bare-name reader cleared for .pgpass reaches the model as printed: ${counted}`);
    const alone = await send(cmds.minutes, got["minutes"]!, "toolu_d3_minutes");
    if (alone.includes(minutesHex.slice(0, 24))) leaks.push("the holder printing the minutes");
    assert.match(alone, /\[mandu:secret\] masked: mdu-holder read .*board-minutes\.md/, alone);
    const both = await send(cmds.both, got["both"]!, "toolu_d3_both");
    if (both.includes(minutesHex.slice(0, 24))) leaks.push("the holder holding .pgpass (cleared) and the minutes");
    assert.match(both, /\$MDU:nomodel_Bash\[/, both);

    const wire = upstream.requests.map((r) => r.bodyText).join("\n");
    assert.ok(!wire.includes(PG_CANARY) && !wire.includes(DOC_CANARY), "neither file's bytes reached the model");
    assert.deepEqual(leaks, [], "CONFIDENTIALITY VIOLATION: a file whose entry clears nothing reached the model through a reader cleared for another file");

    // The first-use pin kept the entry's output (sha256sum is a system binary).
    const law = readFileSync(policy, "utf8");
    const esc = (x: string): string => x.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
    assert.match(law, new RegExp(`app: ${esc(sumApp)}[^\\n]*\\n?[\\s\\S]{0,200}path: ${esc(sum)}[\\s\\S]{0,200}output: clear|output: clear[\\s\\S]{0,200}path: ${esc(sum)}`), `the pin of .pgpass's bare-name reader keeps output: clear:\n${law}`);
  } finally {
    await proxy.close();
    client.close();
    humanClient.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
