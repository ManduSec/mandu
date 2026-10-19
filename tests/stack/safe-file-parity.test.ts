/**
 * safe-file parity + e2e (runtime-instances.md §2, "planted paths"): the
 * files Mandu's services write by name in a session's scope dir never follow
 * a link planted there.
 *
 *   - The copies of safe-file.ts (launcher, anthropic-proxy, openai-proxy,
 *     net-proxy) are byte-identical: one helper, each package standalone.
 *   - The REAL proxy entrypoints (anthropic-proxy, openai-proxy, net-proxy
 *     `server-main.ts`, over a real ArbiterServer) publish their bound port
 *     through MANDU_PORT_FILE into a scope dir where another session's agent
 *     planted a link at `<port file>.tmp` and at the port file itself, each to
 *     a canary file: the canaries keep their bytes, and the port file is a
 *     regular file holding the port. Before the fix a plain
 *     `writeFileSync(<port file>.tmp)` wrote the port number into the canary
 *     (in an attack: a shell startup file) and the rename made the port file
 *     a link to it.
 *   - A port file whose directory is a link is refused: the linked-to
 *     directory gets nothing and the proxy stops, saying why (the launcher,
 *     which waits for the port file, then fails the launch: fail-closed).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets");

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const COPIES = ["interceptors/anthropic-proxy/src/safe-file.ts", "interceptors/openai-proxy/src/safe-file.ts", "interceptors/net-proxy/src/safe-file.ts"];

test("the copies of safe-file.ts are byte-identical to the launcher's", () => {
  const want = readFileSync(join(ROOT, "launcher/src/safe-file.ts"), "utf8");
  for (const c of COPIES) assert.equal(readFileSync(join(ROOT, c), "utf8"), want, `${c} drifted from launcher/src/safe-file.ts; copy the launcher's file out again`);
});

const PROXIES: Array<{ name: string; pkg: string; portVar: string }> = [
  { name: "anthropic-proxy", pkg: "interceptors/anthropic-proxy", portVar: "MANDU_PROXY_PORT" },
  { name: "openai-proxy", pkg: "interceptors/openai-proxy", portVar: "MANDU_PROXY_PORT" },
  { name: "net-proxy", pkg: "interceptors/net-proxy", portVar: "MANDU_NET_PROXY_PORT" },
];

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Start one proxy's real entrypoint; resolves once its ready line is out. */
async function startProxy(p: (typeof PROXIES)[number], sock: string, portFile: string): Promise<{ stop: () => Promise<void>; stderr: () => string; exited: () => boolean }> {
  const pkg = join(ROOT, p.pkg);
  const child = spawn(join(pkg, "node_modules", ".bin", "tsx"), [join(pkg, "src", "server-main.ts")], {
    cwd: pkg,
    env: { ...process.env, MANDU_ARBITER_SOCK: sock, [p.portVar]: "0", MANDU_PORT_FILE: portFile },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let err = "";
  child.stderr!.on("data", (d: Buffer) => { err += d.toString(); });
  for (let i = 0; i < 300 && !/ready/.test(err) && child.exitCode === null; i++) await sleep(100);
  return {
    stderr: () => err,
    exited: () => child.exitCode !== null,
    stop: async () => {
      child.kill("SIGTERM");
      await new Promise<void>((r) => { if (child.exitCode !== null) r(); child.once("exit", () => r()); setTimeout(r, 5000).unref(); });
    },
  };
}

for (const p of PROXIES) {
  test(`${p.name}: its port file never follows a link planted in the scope dir`, { timeout: 90_000 }, async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-safe-file-"));
    const server = new ArbiterServer({
      socketPath: join(dir, "arbiter.sock"), adminSocketPath: join(dir, "admin.sock"), dbPath: join(dir, "sym.db"),
      eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false,
    });
    await server.listen();
    try {
      // 1. Links at `<port file>.tmp` and at the port file, each to a canary.
      const scope = join(dir, "scope");
      mkdirSync(scope, { mode: 0o700 });
      const canaryTmp = join(dir, "bashrc-tmp");
      const canaryFinal = join(dir, "bashrc-final");
      writeFileSync(canaryTmp, "# my startup file\n");
      writeFileSync(canaryFinal, "# another file\n");
      const portFile = join(scope, `${p.name}.port`);
      symlinkSync(canaryTmp, `${portFile}.tmp`);
      symlinkSync(canaryFinal, portFile);
      const run = await startProxy(p, join(dir, "arbiter.sock"), portFile);
      try {
        assert.match(run.stderr(), /ready/, `${p.name} did not start: ${run.stderr()}`);
        for (let i = 0; i < 50 && lstatSync(portFile).isSymbolicLink(); i++) await sleep(100);
        assert.equal(readFileSync(canaryTmp, "utf8"), "# my startup file\n", "the link at <port file>.tmp was not written through");
        assert.equal(readFileSync(canaryFinal, "utf8"), "# another file\n", "the link at the port file was not written through");
        assert.ok(lstatSync(portFile).isFile(), "the port file is a regular file, the planted link replaced");
        const port = Number(readFileSync(portFile, "utf8"));
        assert.ok(Number.isInteger(port) && port > 0, `the port file holds the bound port (${port})`);
        assert.match(run.stderr(), new RegExp(`:${port}`), "the one the proxy serves");
        assert.equal(lstatSync(portFile).mode & 0o777, 0o600, "mode 0600");
        assert.deepEqual(readdirSync(scope).filter((n) => n.endsWith(".tmp") && n !== `${p.name}.port.tmp`), [], "no temp file left behind");
      } finally {
        await run.stop();
      }

      // 2. The port file's directory is a link (to a folder of the user's).
      const elsewhere = join(dir, "project");
      mkdirSync(elsewhere);
      const linkedScope = join(dir, "scope2");
      symlinkSync(elsewhere, linkedScope);
      const run2 = await startProxy(p, join(dir, "arbiter.sock"), join(linkedScope, "port"));
      try {
        for (let i = 0; i < 50 && !run2.exited(); i++) await sleep(100);
        assert.deepEqual(readdirSync(elsewhere), [], "nothing was written into the linked-to folder");
        assert.match(run2.stderr(), /refusing to write/, "the proxy says why it published no port");
        assert.ok(run2.exited(), "and stops");
      } finally {
        await run2.stop();
      }
    } finally {
      await server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
}

test("the port file appears where it should when nothing is planted (the control)", { timeout: 60_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-safe-file-ctl-"));
  const server = new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"), adminSocketPath: join(dir, "admin.sock"), dbPath: join(dir, "sym.db"),
    eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  try {
    const portFile = join(dir, "port");
    const run = await startProxy(PROXIES[0]!, join(dir, "arbiter.sock"), portFile);
    try {
      assert.match(run.stderr(), /ready/);
      for (let i = 0; i < 50 && !existsSync(portFile); i++) await sleep(100);
      assert.ok(Number(readFileSync(portFile, "utf8")) > 0);
    } finally {
      await run.stop();
    }
  } finally {
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
