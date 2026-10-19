/**
 * port-file.test — E2E: the REAL net-proxy entrypoint with
 * MANDU_NET_PROXY_PORT=0 publishes its kernel-assigned port via
 * MANDU_PORT_FILE (atomic tmp+rename), mirroring the model proxies
 * (runtime-instances.md §8). Before this, net-proxy was the one TCP service
 * with a fixed-port-only contract — two concurrent host stacks collided on
 * 8790 unless hand-pinned.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer, connect, type Server } from "node:net";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { once } from "node:events";

const PKG_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const TSX = join(PKG_DIR, "node_modules", ".bin", "tsx");
const SERVER_MAIN = join(PKG_DIR, "src", "server-main.ts");

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

test("PORT=0 → bound port published via MANDU_PORT_FILE; the port accepts connections", { timeout: 60_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-netportfile-"));
  const arbSock = join(dir, "arbiter.sock");
  const portFile = join(dir, "port");

  // Mock arbiter: accept + ignore (boot only awaits the socket connect).
  const arb: Server = createServer((s) => s.on("data", () => {}));
  arb.listen(arbSock);
  await once(arb, "listening");

  const child = spawn(TSX, [SERVER_MAIN], {
    cwd: PKG_DIR,
    env: {
      ...process.env,
      MANDU_ARBITER_SOCK: arbSock,
      MANDU_NET_PROXY_PORT: "0",
      MANDU_PORT_FILE: portFile,
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr!.on("data", (d: Buffer) => { stderr += d.toString(); });

  try {
    // tsx boot is the long pole; the file appears only via rename (atomic).
    for (let i = 0; i < 150 && !existsSync(portFile); i++) await sleep(100);
    assert.ok(existsSync(portFile), `port file published (stderr: ${stderr})`);
    const port = Number(readFileSync(portFile, "utf8"));
    assert.ok(Number.isInteger(port) && port > 0, `kernel-assigned port (${port})`);

    // The advertised port really is this proxy's listener.
    await new Promise<void>((resolve, reject) => {
      const s = connect({ host: "127.0.0.1", port });
      s.once("connect", () => { s.destroy(); resolve(); });
      s.once("error", reject);
    });
    assert.match(stderr, new RegExp(`ready .*:${port}`), "the ready line names the bound port");
  } finally {
    child.kill("SIGTERM");
    await new Promise<void>((r) => { child.once("exit", () => r()); setTimeout(r, 5000).unref(); });
    arb.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
