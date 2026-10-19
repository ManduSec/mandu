/**
 * reserve-port — a loopback TCP port no other test can be handed while this
 * process lives (test-organization.md §8.4). For a server that must be told
 * its port before it starts, and for a "dead" endpoint a test expects a
 * refused connection from.
 *
 * Picking a port by binding port 0 and closing it races: another suite's
 * port-0 bind, or an outgoing connection, can be handed the same port before
 * it is used. This helper closes that race:
 *
 * - The port is chosen BELOW the host's ephemeral range
 *   (`/proc/sys/net/ipv4/ip_local_port_range`), which the kernel never hands
 *   out for a port-0 bind or a connect's source port.
 * - It is claimed by a UDP socket bound to the same number on 127.0.0.1 (no
 *   SO_REUSEADDR), held until this process exits. Every copy of this helper
 *   takes that claim first, so two concurrent reservations never share a port;
 *   the claim dies with the process, so nothing goes stale. (Node cannot hold
 *   a bound TCP port that does not listen; the UDP twin is the lock.)
 * - A TCP listen on 127.0.0.1 at the port, closed at once, proves nothing
 *   listens there when the reservation is returned.
 *
 * What stays possible: a process outside this scheme binding that exact
 * fixed port in the meantime. No suite in this repo binds a fixed port in
 * the range used (the 8192 ports just below the ephemeral range).
 *
 * Copies (each package keeps its own, no cross-package imports):
 * launcher/test/lib/reserve-port.ts, dashboard/test/unit/reserve-port.ts,
 * interceptors/inspect-mcp/test/helpers/reserve-port.ts,
 * tests/lib/reserve-port.ts. Keep them identical.
 */
import { createSocket, type Socket } from "node:dgram";
import { readFileSync } from "node:fs";
import { createServer } from "node:net";

/** How many ports below the ephemeral range are candidates. */
const SPAN = 8192;
/** The lowest candidate: unprivileged ports only. */
const FLOOR = 1024;

/** Claims held for the life of the process (a closed handle frees the port). */
const claims: Socket[] = [];

/** The host's ephemeral range, Linux's default when the proc file is absent. */
export function ephemeralRange(): { low: number; high: number } {
  try {
    const [low, high] = readFileSync("/proc/sys/net/ipv4/ip_local_port_range", "utf8").trim().split(/\s+/).map(Number);
    if (Number.isInteger(low) && Number.isInteger(high) && low > 0 && high >= low) return { low: low!, high: high! };
  } catch { /* not Linux: the default */ }
  return { low: 32768, high: 60999 };
}

/** The candidate ports: the SPAN just below the ephemeral range, else just
 *  above it; empty when the ephemeral range leaves no room either side. */
export function candidateRange(r = ephemeralRange()): { from: number; to: number } | null {
  if (r.low - 1 >= FLOOR) return { from: Math.max(FLOOR, r.low - SPAN), to: r.low - 1 };
  if (r.high + 1 <= 65535) return { from: r.high + 1, to: Math.min(65535, r.high + SPAN) };
  return null;
}

function claim(port: number): Promise<Socket | null> {
  return new Promise((res) => {
    const s = createSocket({ type: "udp4", reuseAddr: false });
    s.once("error", () => { try { s.close(); } catch { /* never bound */ } res(null); });
    s.bind({ port, address: "127.0.0.1", exclusive: true }, () => { s.removeAllListeners("error"); s.unref(); res(s); });
  });
}

function tcpFree(port: number): Promise<boolean> {
  return new Promise((res) => {
    const srv = createServer();
    srv.once("error", () => res(false));
    srv.listen({ port, host: "127.0.0.1", exclusive: true }, () => srv.close(() => res(true)));
  });
}

/** Reserve a loopback TCP port (see the header). Nothing listens on it when
 *  this resolves; a connection to 127.0.0.1:<port> is refused until the caller
 *  (or the server it hands the port to) listens there. */
export async function reservePort(): Promise<number> {
  const range = candidateRange();
  if (!range) throw new Error("reservePort: the ephemeral port range leaves no room for a reserved port");
  const width = range.to - range.from + 1;
  for (let i = 0; i < 256; i++) {
    const port = range.from + Math.floor(Math.random() * width);
    const c = await claim(port);
    if (!c) continue;
    if (await tcpFree(port)) { claims.push(c); return port; }
    c.close();
  }
  throw new Error(`reservePort: no free port in ${range.from}-${range.to} after 256 tries`);
}
