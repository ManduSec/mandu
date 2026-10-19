/**
 * blind-tunnel-fork-live — plan 13 D6 (the P0 triage's 2a, 2026-10-07) over
 * the REAL components: a child forked AFTER a blind CONNECT, which reads a
 * secret and writes it into the tunnel it inherited from its parent, is
 * refused by the net-proxy before its chunk is written.
 *
 * Before the fix the proxy judged a blind tunnel's chunks against the
 * holders found at the CONNECT only (the parent), so the child's bytes
 * reached the unbound destination.
 *
 * The real ArbiterServer (secrets: confidentiality ON, integrity OFF), the
 * real NetProxy in its PRODUCTION wiring (`new ArbiterClientAdapter(new
 * ArbiterClient(sock), new ArbiterClient(humanSock))`) with its LIVE /proc
 * attribution (nothing injected: the per-chunk lookup reads the real
 * process table), TLS inspection off (the tunnel is blind), and a real TCP
 * destination recording every byte. A real python3 process opens the tunnel
 * through the proxy, sends a chunk, then forks (`os.fork`, no exec: the
 * child shares the client socket); the child opens the `.env` and sends
 * what it read. The test plays the guard: it reports the child's raw open
 * on the human socket (`decideSecretOpen`, with the child's live ancestor
 * chain, as mandu-net-guard does at the open). Asserted, with the
 * destination's record as the oracle:
 *   - control: the same run with no raw read reported delivers the child's
 *     chunk (the road works, the fork alone is not refused);
 *   - the child's chunk after its reported read never reaches the
 *     destination, and the proxy logs the tunnel's closing.
 *
 * GATED on Linux (/proc) and python3. Mandu-new (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createServer, type AddressInfo } from "node:net";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { NetProxy } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { ancestorKeys, provisionalProcKey } from "../../interceptors/net-proxy/src/conn-attr.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const hasPython = process.platform === "linux" && spawnSync("python3", ["-c", "import os; os.fork"], { stdio: "ignore" }).status === 0;
const GATE = process.platform !== "linux" ? "Linux only (/proc)" : !hasPython ? "python3 is not installed" : false;

/** The program: CONNECT through the proxy, one chunk, fork; the child reads
 *  `.env` once `go` exists and sends what it read. Every line it prints is a
 *  step the test waits on. */
const PROGRAM = String.raw`
import os, socket, sys, time
proxy_port, dest_port, env_path, go_path = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
s = socket.create_connection(("127.0.0.1", proxy_port))
s.sendall(("CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n" % (dest_port, dest_port)).encode())
head = b""
while b"\r\n\r\n" not in head:
    c = s.recv(1024)
    if not c:
        break
    head += c
print("STATUS " + head.split(b"\r\n")[0].decode(), flush=True)
s.sendall(b"before-fork;")
pid = os.fork()
if pid == 0:
    print("CHILD %d" % os.getpid(), flush=True)
    for _ in range(400):
        if os.path.exists(go_path):
            break
        time.sleep(0.025)
    with open(env_path) as f:
        value = f.read().strip()
    try:
        s.sendall(("after-fork:" + value + ";").encode())
        time.sleep(0.8)
        s.sendall(b"again;")
    except OSError as e:
        print("CHILD-SEND-ERROR " + type(e).__name__, flush=True)
    time.sleep(0.3)
    os._exit(0)
os.waitpid(pid, 0)
print("PARENT-DONE", flush=True)
`;

async function recorder() {
  const got: Buffer[] = [];
  const server = createServer((s) => {
    s.on("data", (c: Buffer) => got.push(c));
    s.on("error", () => {});
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { port: (server.address() as AddressInfo).port, text: () => Buffer.concat(got).toString("utf8"), close: () => server.close() };
}

test("2a LIVE: a child forked after a blind CONNECT that reads a secret cannot write it into the inherited tunnel (real arbiter, real net-proxy, live /proc)", { skip: GATE, timeout: 60_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-blind-fork-"));
  const ws = join(tmp, "ws");
  mkdirSync(ws, { recursive: true });
  const env = join(ws, ".env");
  const canary = `skliveFORK${randomBytes(12).toString("hex")}`;
  writeFileSync(env, `${canary}\n`);
  const prog = join(tmp, "fork.py");
  writeFileSync(prog, PROGRAM);
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath, humanSocketPath: humanPath, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    adminPolicyDir: null, packDir: null, confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: env, level: "no-model", bindings: ["bound.example"], readers: ["ssh-add"] }] },
  });
  await server.listen();
  const guard = new ArbiterClient(humanPath);
  await guard.connect();
  const data = new ArbiterClient(socketPath);
  await data.connect();
  const human = new ArbiterClient(humanPath);
  await human.connect();
  const logs: string[] = [];
  // The PRODUCTION wiring (the arbiter-client pattern's parity rule): the
  // adapter over the real clients, its new op counted as the proxy calls it.
  const adapter = new ArbiterClientAdapter(data as unknown as RealArbiterClient, human);
  let listed = 0;
  const forwarded = adapter.secretTaintedProcesses.bind(adapter);
  adapter.secretTaintedProcesses = async () => { listed++; return forwarded(); };
  const proxy = new NetProxy({
    allowThisMachine: true, // the destination listens on loopback (test only)
    arbiter: adapter,
    log: (m) => logs.push(m),
    sessionId: "s-blind-fork",
  });
  const proxyPort = await proxy.listen(0);
  const session = "s-blind-fork";

  /** One run of the program; `onChild` plays the guard before the child reads. */
  const run = async (tag: string, onChild: (childPid: number) => Promise<void>) => {
    const rec = await recorder();
    const go = join(tmp, `go-${tag}`);
    const child = spawn("python3", [prog, String(proxyPort), String(rec.port), env, go], { stdio: ["ignore", "pipe", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (d: Buffer) => { stderr += d.toString(); });
    const lines: string[] = [];
    const rl = createInterface({ input: child.stdout });
    const waitLine = (prefix: string): Promise<string> => new Promise((resolve, reject) => {
      const hit = lines.find((l) => l.startsWith(prefix));
      if (hit) return resolve(hit);
      const t = setTimeout(() => reject(new Error(`no "${prefix}" line (got ${JSON.stringify(lines)}; stderr ${stderr})`)), 15_000);
      rl.on("line", (l) => { if (l.startsWith(prefix)) { clearTimeout(t); resolve(l); } });
    });
    rl.on("line", (l) => lines.push(l));
    try {
      assert.equal(await waitLine("STATUS "), "STATUS HTTP/1.1 200 Connection Established", "the parent, holding nothing, opens the blind tunnel");
      const childPid = Number((await waitLine("CHILD ")).split(" ")[1]);
      // The parent's chunk is through before the child reads: a chunk the
      // proxy judges while a holder of a secret holds the socket is refused
      // whoever wrote it (it cannot tell), so the order is the test's.
      for (let i = 0; i < 300 && !rec.text().includes("before-fork;"); i++) await new Promise((r) => setTimeout(r, 10));
      assert.equal(rec.text(), "before-fork;", "the parent's chunk arrived");
      await onChild(childPid);
      writeFileSync(go, "");
      await waitLine("PARENT-DONE");
      await new Promise((r) => setTimeout(r, 200));
      return { got: rec.text(), lines };
    } finally {
      child.kill("SIGKILL");
      rec.close();
    }
  };

  try {
    assert.ok((await guard.registerSecret({ path: env })).symbol);

    // Control: no raw read reported → the child's chunk is delivered.
    const ctl = await run("ctl", async () => {});
    assert.equal(ctl.got, `before-fork;after-fork:${canary};again;`, "control: a fork that holds nothing keeps the tunnel working");

    let childKey = "";
    // The child reads the secret raw (the guard's report at its open).
    const taken = await run("read", async (pid) => {
      const procKey = provisionalProcKey(pid);
      childKey = procKey;
      const verdict = await guard.decideSecretOpen({
        path: env, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [],
        procKey, ancestorKeys: ancestorKeys(pid, (p) => readFileSync(`/proc/${p}/stat`, "utf8")), session,
      });
      assert.equal(verdict.verdict, "raw", "the child is let in raw, as a pinned reader would be");
    });
    // The op answered over the wire (not the fallback rescan): the child's
    // key is listed, and the proxy asked it before the chunks.
    assert.ok((await adapter.secretTaintedProcesses()).procKeys.includes(childKey), "secretTaintedProcesses lists the child the guard reported");
    assert.ok(listed >= 3, `the proxy asked the arbiter before each chunk (${listed})`);
    // THE ORACLE: the destination never saw the secret after the read.
    assert.equal(taken.got, "before-fork;", `nothing the child sent after its raw read reached the unbound destination (lines ${JSON.stringify(taken.lines)})`);
    assert.ok(!taken.got.includes(canary));
    assert.ok(logs.some((l) => /^BLOCK tunnel 127\.0\.0\.1:/.test(l)), `the proxy closed the tunnel (${JSON.stringify(logs)})`);
  } finally {
    await proxy.close();
    guard.close();
    data.close();
    human.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
