/**
 * codex-sandbox-exec-wrap — the exec-wrap shim inside Codex's OWN command
 * sandbox (supported-agents.md §6.4), across real components: the real
 * `codex sandbox` (codex-linux-sandbox: bubblewrap + Landlock + seccomp), the
 * launcher's own shim writer, the real wrap.ts, a real ArbiterServer on the
 * `secrets` axes, and a local HTTP sink.
 *
 *   (1) Codex's workspace-write sandbox with its network OFF (Codex's
 *       default): its seccomp filter refuses every connect(2), the shim's
 *       dial to the arbiter included (EPERM). The shim fails closed (exit 77,
 *       nothing ran, nothing at the sink) and SAYS the sandbox refused it,
 *       not that the Mandu service is down.
 *   (2) The same sandbox with `sandbox_workspace_write.network_access = true`
 *       (the posture a drill replay runs both sides in): the shim reaches the
 *       arbiter, which decides the argv. A curl carrying a no-model secret's
 *       symbol runs with the PLACEHOLDER left as written (confidentiality.md
 *       §7.1, 2026-10-05; before, exit 77): the sink, reached with no egress
 *       proxy in between, gets the placeholder and never the value, and
 *   (3) a curl carrying ordinary text goes through to the sink.
 *
 * The secret's value is random per run (never written into this file).
 * Self-SKIPs without codex, without a codex whose sandbox starts on this host
 * (a stock Ubuntu's AppArmor userns restriction; launcher/src/codex-sandbox.ts),
 * without curl, or without exec-wrap's dependencies.
 *
 * Mandu-new test code (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { once } from "node:events";
import { randomBytes } from "node:crypto";
import { closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { writeExecShims } from "../../launcher/src/services/exec-shims.js";
import { Layout } from "../../launcher/src/services/layout.js";
import { stateAxes } from "../lib/axes.js";
import { unreachableMessage } from "../../interceptors/exec-wrap/src/gate.js";

stateAxes("secrets"); // the egress gate under test is the confidentiality axis's

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..");
const BLOCK_EXIT = 77;

const has = (cmd: string, args: string[]): boolean => spawnSync(cmd, args, { stdio: "ignore", timeout: 30_000 }).status === 0;
// /tmp left out of the writable roots: for each writable root codex makes
// read-only mount targets (.git, .agents, .codex) where they are missing, so
// with /tmp writable every run briefly created /tmp/.agents, /tmp/.codex and
// a /tmp/.git that made the suites running beside this one see /tmp as a git
// repository. The seccomp filter under test is the same either way; the
// test's own TMPDIR (below) stays writable.
const WORKSPACE_WRITE = ["-c", 'sandbox_mode="workspace-write"', "-c", "sandbox_workspace_write.exclude_slash_tmp=true"];
const NET_ON = ["-c", "sandbox_workspace_write.network_access=true"];

function skipReason(): string | false {
  if (process.platform !== "linux") return "Codex's Linux sandbox only";
  if (!has("codex", ["--version"])) return "codex is not installed";
  if (!has("curl", ["--version"])) return "curl is not installed";
  if (!existsSync(join(REPO, "interceptors", "exec-wrap", "node_modules"))) return "exec-wrap's dependencies are not installed (node scripts/install-deps.mjs interceptors/exec-wrap)";
  const home = mkdtempSync(join(tmpdir(), "mdu-cxsb-probe-"));
  try {
    const r = spawnSync("codex", ["sandbox", ...WORKSPACE_WRITE, "--", "true"], { cwd: home, env: { ...process.env, CODEX_HOME: home, TMPDIR: home }, stdio: "ignore", timeout: 60_000 });
    if (r.status !== 0) return "Codex's own sandbox does not start on this host (launcher/src/codex-sandbox.ts)";
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
  return false;
}
const skip = skipReason();

interface Run { code: number | null; out: string }

/** One command under `codex sandbox`, the agent's way: the shim dir first on
 *  PATH, the data socket in MANDU_ARBITER_SOCK. */
async function inCodexSandbox(o: { codexHome: string; ws: string; shimDir: string; sock: string; net: boolean; script: string; outFile: string }): Promise<Run> {
  const args = ["sandbox", ...WORKSPACE_WRITE, ...(o.net ? NET_ON : []), "--", "bash", "-c", o.script];
  // Output goes to a FILE, not a node pipe: node's stdio "pipes" are socket
  // pairs, and inside Codex's seccomp a node program cannot use a socket as
  // its stdout (libuv's handle probe calls getsockopt, which is refused, and
  // the writes are dropped). Codex's own runtime hands its commands real
  // pipes, which a file stands in for here.
  const fd = openSync(o.outFile, "w");
  try {
    const child = spawn("codex", args, {
      cwd: o.ws,
      env: {
        PATH: `${o.shimDir}:${process.env["PATH"] ?? "/usr/bin:/bin"}`,
        HOME: process.env["HOME"] ?? o.ws,
        CODEX_HOME: o.codexHome,
        // codex sandbox leaves codex-bwrap-synthetic-mount-targets-<uid> in its
        // TMPDIR: keep it inside the test's own dir, which is removed
        TMPDIR: o.codexHome,
        MANDU_ARBITER_SOCK: o.sock,
      },
      stdio: ["ignore", fd, fd],
    });
    const [code] = (await once(child, "exit")) as [number | null];
    return { code, out: readFileSync(o.outFile, "utf8") };
  } finally {
    closeSync(fd);
  }
}

test("exec-wrap inside Codex's sandbox: network off fails closed and says why; network on, a secret's placeholder runs as written, never its value", { skip, timeout: 240_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-cxsb-"));
  const home = join(dir, "home");
  const ws = join(home, "proj");
  const codexHome = join(dir, "codex-home");
  mkdirSync(ws, { recursive: true });
  mkdirSync(codexHome, { recursive: true });
  // a fresh value per run: the test never carries a secret of its own
  const secretValue = `cxsb-${randomBytes(12).toString("hex")}`;
  writeFileSync(join(ws, ".env"), `API_KEY=${secretValue}\n`);

  const sock = join(dir, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath: sock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    integrity: false, confidentiality: true, adminPolicyDir: null, packDir: null, log: () => {},
  });
  await server.listen();
  const client = new ArbiterClient(sock);
  await client.connect();

  const bodies: string[] = [];
  const sink: Server = createServer((req: IncomingMessage, res) => {
    let b = "";
    req.setEncoding("utf8");
    req.on("data", (c: string) => (b += c));
    req.on("end", () => { bodies.push(b); res.end("sink-ok\n"); });
  });
  sink.listen(0, "127.0.0.1");
  await once(sink, "listening");
  const url = `http://127.0.0.1:${(sink.address() as AddressInfo).port}/collect`;

  try {
    // the launcher's own registration: the .env's value becomes a no-model token
    const reg = await client.registerSecret({ path: join(ws, ".env"), home });
    const token = reg.twin?.match(/\$MDU:nomodel_[^\s'"]+/)?.[0];
    assert.ok(token, `the .env is registered with a no-model token: ${reg.reason}`);

    const shimDir = writeExecShims(["curl"], Layout.dev(REPO), sock, join(dir, "run"));
    const run = (net: boolean, script: string): Promise<Run> => inCodexSandbox({ codexHome, ws, shimDir, sock, net, script, outFile: join(dir, "out.txt") });

    // (1) Codex's default: network off. The dial is refused by its seccomp.
    const off = await run(false, `curl -s -d plain-off ${url}`);
    assert.equal(off.code, BLOCK_EXIT, `fail closed: ${off.out}`);
    // the shim's own EPERM wording (exec-wrap gate.ts), Codex's form: Codex sets
    // CODEX_SANDBOX_NETWORK_DISABLED=1 in the command's env; up to its detail line
    const said = unreachableMessage("curl", sock, { code: "EPERM", message: "" }, { codexNetworkOff: true }).split(" detail:")[0]!;
    assert.ok(off.out.includes(said), off.out);
    assert.match(off.out, /connect EPERM/, "the errno the message keys on");
    assert.doesNotMatch(off.out, /not answering/, "the service is up: the message must not say otherwise");

    // (2) network on: the shim reaches the arbiter, which leaves the secret's
    //     placeholder as written; curl runs and sends the placeholder, never the value
    const secret = await run(true, `curl -s -d '${token}' ${url}`);
    assert.equal(secret.code, 0, `the shim reached the arbiter and curl ran: ${secret.out}`);
    assert.match(secret.out, /sink-ok/);
    assert.doesNotMatch(secret.out, /refuses its connection|not answering|blocked curl/);
    assert.ok(!secret.out.includes(secretValue), "the secret's value appears nowhere");

    // (3) network on: ordinary text goes through to the sink
    const plain = await run(true, `curl -s -d plain-on ${url}`);
    assert.equal(plain.code, 0, `a non-secret send goes through: ${plain.out}`);
    assert.match(plain.out, /sink-ok/);

    assert.deepEqual(bodies, [token, "plain-on"], "the sink got the placeholder (never the value) and the ordinary send");
    assert.ok(!bodies.join("").includes(secretValue));
  } finally {
    client.close();
    sink.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
