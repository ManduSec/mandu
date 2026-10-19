/**
 * lib/proc-wait — poll for a socket, a port or a port file to come up.
 *
 * Extracted verbatim from run-live.ts (agent-legibility split, behavior-preserving).
 * Generic process/network wait helpers used by the stack boot sequence. Not public
 * API — imported back by bootStack.
 */

import { existsSync, readFileSync } from "node:fs";
import { connect } from "node:net";

export async function waitForSocket(socketPath: string, tries = 100): Promise<boolean> {
  for (let i = 0; i < tries; i++) {
    if (existsSync(socketPath)) return true;
    await sleep(100);
  }
  return false;
}

/** Poll until a TCP host:port accepts a connection (a proxy is up). */
export async function waitForPort(host: string, port: number, tries = 100): Promise<boolean> {
  for (let i = 0; i < tries; i++) {
    const ok = await new Promise<boolean>((resolve) => {
      const s = connect(port, host);
      s.once("connect", () => {
        s.destroy();
        resolve(true);
      });
      s.once("error", () => resolve(false));
    });
    if (ok) return true;
    await sleep(100);
  }
  return false;
}

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Poll for a daemon's port file (MANDU_PORT_FILE: the port it bound on port 0,
 *  written atomically) and return the port, or null if it never appears. A
 *  picked-then-released port could be taken by a suite running alongside
 *  before the daemon binds it (test-organization.md §8.4); port 0 cannot. */
export async function waitForPortFile(portFile: string, tries = 100): Promise<number | null> {
  for (let i = 0; i < tries; i++) {
    if (existsSync(portFile)) {
      const port = Number(readFileSync(portFile, "utf8").trim());
      if (Number.isInteger(port) && port > 0) return port;
    }
    await sleep(100);
  }
  return null;
}
