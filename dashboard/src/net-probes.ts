/**
 * net-probes — the supervisor's connection-level probes, as free functions.
 *
 * Extracted VERBATIM from supervisor.ts (2026-07-16 split; behavior identical —
 * neither body ever touched `this`). Two probes:
 *   • checkReady — does a service's readiness endpoint (unix socket, TCP
 *     host:port, or the port a port file names) accept a connection right
 *     now? Ported from launcher
 *     mandu-run.sh `wait_for_socket()` to an active `net.connect()` probe.
 *   • helloProbe — one-shot `hello` handshake against the arbiter socket
 *     (runtime-instances.md): a raw NDJSON round-trip, no arbiter package
 *     import, so the dashboard stays standalone.
 */

import net from "node:net";
import { readFileSync } from "node:fs";

import type { ArbiterIdentity, ServiceDefinition } from "./supervisor/supervisor-defs.js";

export const READY_PROBE_INTERVAL_MS = 100; // mirrors wait_for_socket's 0.1s poll

/** The port a service wrote to its port file (MANDU_PORT_FILE: the port it
 *  bound on port 0), or null while the file is missing, empty, or not a port.
 *  Adapted from eval/lib/proc-wait.ts `waitForPortFile` (one read, no poll:
 *  the supervisor's readiness loop is the poll). */
export function readPortFile(path: string): number | null {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return null;
  }
  const port = Number(text.trim());
  return Number.isInteger(port) && port > 0 && port < 65536 ? port : null;
}

/** Resolve true when the readiness endpoint accepts a connection. A
 *  `port-file` endpoint is first resolved through its file. */
export function checkReady(
  ready: ServiceDefinition["ready"],
): Promise<boolean> {
  let opts: net.NetConnectOpts;
  if (ready.kind === "socket") opts = { path: ready.path };
  else if (ready.kind === "tcp") opts = { host: ready.host, port: ready.port };
  else {
    const port = readPortFile(ready.path);
    if (port === null) return Promise.resolve(false);
    opts = { host: ready.host, port };
  }
  return new Promise<boolean>((resolve) => {
    let sock: net.Socket;
    let settled = false;
    const done = (ok: boolean) => {
      if (settled) return;
      settled = true;
      try {
        sock.destroy();
      } catch {
        /* ignore */
      }
      resolve(ok);
    };
    try {
      sock = net.connect(opts);
    } catch {
      resolve(false);
      return;
    }
    // Per-probe timeout so a hung connect doesn't stall the probe interval.
    sock.setTimeout(READY_PROBE_INTERVAL_MS * 2);
    sock.once("connect", () => done(true));
    sock.once("error", () => done(false));
    sock.once("timeout", () => done(false));
  });
}

/**
 * One-shot `hello` handshake against the arbiter socket (runtime-instances.md):
 * a raw NDJSON round-trip (no arbiter package import — this package stays
 * standalone). Best-effort: any failure (old daemon without the op, timeout,
 * parse error) yields null; the caller treats identity as unknown.
 */
export function helloProbe(sockPath: string): Promise<ArbiterIdentity | null> {
  return new Promise((resolve) => {
    let settled = false;
    let buf = "";
    const done = (v: ArbiterIdentity | null): void => {
      if (settled) return;
      settled = true;
      try { sock.destroy(); } catch { /* ignore */ }
      resolve(v);
    };
    let sock: net.Socket;
    try {
      sock = net.connect({ path: sockPath });
    } catch {
      resolve(null);
      return;
    }
    sock.setTimeout(1500, () => done(null));
    sock.once("error", () => done(null));
    sock.once("connect", () => sock.write(JSON.stringify({ id: 1, op: "hello" }) + "\n"));
    sock.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      try {
        const resp = JSON.parse(buf.slice(0, nl)) as { ok?: boolean; result?: ArbiterIdentity };
        done(resp.ok && resp.result && typeof resp.result.pid === "number" ? resp.result : null);
      } catch {
        done(null);
      }
    });
  });
}
