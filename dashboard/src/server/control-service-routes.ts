/**
 * server/control-service-routes — the `/api/control/<service>/*` supervisor
 * handlers (extracted VERBATIM from src/server.ts in the server.ts
 * decomposition; see server.ts for the route map and security posture).
 * handleControl in server.ts still owns the matching + the enabled/CSRF gating;
 * these are the per-route bodies it dispatches to.
 */

import { type IncomingMessage, type ServerResponse } from "node:http";
import { existsSync, createReadStream } from "node:fs";

import { json } from "./http-util.js";
import { type Supervisor, type ServiceId } from "../supervisor/supervisor.js";
import { SERVICE_IDS } from "../supervisor/supervisor-defs.js";

/** Valid control-plane service ids: exactly the supervisor's own list. A
 *  private copy here once lacked `test-arbiter`, so the developer view's
 *  Start / Restart / logs for it answered 404 (2026-09-30). */
export function isServiceId(s: string): s is ServiceId {
  return (SERVICE_IDS as string[]).includes(s);
}

export function controlDisabled(res: ServerResponse): void {
  json(res, 404, { error: "control plane disabled" });
}

export async function controlAction(
  sup: Supervisor,
  service: ServiceId,
  action: "start" | "stop" | "restart" | "replace",
  res: ServerResponse,
): Promise<void> {
  try {
    await sup[action](service);
    const status = sup.status().find((s) => s.id === service);
    json(res, 200, { service: status });
  } catch (err) {
    json(res, 503, { error: String((err as Error)?.message ?? err), service });
  }
}

/** Bring up the whole stack (arbiter first, then the proxies) and return the
 *  post-start status snapshot. Per-service failures surface in the snapshot's
 *  lastError/state rather than failing the whole call. */
export async function controlStartAll(sup: Supervisor, res: ServerResponse): Promise<void> {
  try {
    const services = await sup.startAll();
    json(res, 200, { services });
  } catch (err) {
    // Only the arbiter (started first, awaited) can reject startAll; surface the
    // current snapshot so the UI still reflects what came up.
    json(res, 503, { error: String((err as Error)?.message ?? err), services: sup.status() });
  }
}

/** Stop the whole stack and return the post-stop status snapshot. */
export async function controlStopAll(sup: Supervisor, res: ServerResponse): Promise<void> {
  const services = await sup.stopAll();
  json(res, 200, { services });
}

/**
 * Bounce the whole stack: stop everything, then bring it back up. This is the
 * button for "my services are wedged" — its blast radius is exactly the four
 * supervised services, unlike the dashboard's self-restart, which additionally
 * swaps the server rendering the page.
 *
 * ADOPTED services are neither stopped nor respawned (stopAll skips what it does
 * not own; startAll re-adopts the same listener). The snapshot's `adopted` flags
 * let the UI say so rather than implying they were bounced.
 */
export async function controlRestartAll(sup: Supervisor, res: ServerResponse): Promise<void> {
  try {
    await sup.stopAll();
    const services = await sup.startAll();
    json(res, 200, { services });
  } catch (err) {
    // Only the arbiter (started first, awaited) can reject startAll; surface the
    // snapshot so the UI still reflects what came back up.
    json(res, 503, { error: String((err as Error)?.message ?? err), services: sup.status() });
  }
}

/** SSE: live + backlog log lines for a supervised service (apiStream shape). */
export function controlLogsStream(
  sup: Supervisor,
  service: ServiceId,
  req: IncomingMessage,
  res: ServerResponse,
): void {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });
  // Backlog first, then the live tail.
  for (const line of sup.logs(service)) {
    res.write(`event: line\ndata: ${JSON.stringify(line)}\n\n`);
  }
  const unsubscribe = sup.subscribeLogs(service, (line) => {
    res.write(`event: line\ndata: ${JSON.stringify(line)}\n\n`);
  });
  const heartbeat = setInterval(() => res.write(`: ping\n\n`), 15_000);
  req.on("close", () => {
    clearInterval(heartbeat);
    unsubscribe();
  });
}

/**
 * GET the COMPLETE durable per-module log file as `text/plain` (the "full log
 * ↗" link target). `service` is already validated by isServiceId above; a
 * log may echo a value, so the read gate (read-gate.ts) serves it only with
 * the admin session from a page of this dashboard. A missing
 * file (the service never launched this process) responds 200 with an empty
 * body rather than 404 — the link always resolves to something openable.
 * Read after the lines the ring holds have reached the file
 * (Supervisor.logFileWritten): the file is written after the ring, and a
 * read in between lacked a line the live view had already shown.
 */
export async function controlLogFile(
  sup: Pick<Supervisor, "logFilePath" | "logFileWritten">,
  service: ServiceId,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  await sup.logFileWritten(service);
  if (res.destroyed) return;
  const path = sup.logFilePath(service);
  if (!existsSync(path)) {
    res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
    res.end("");
    return;
  }
  res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
  const stream = createReadStream(path);
  stream.on("error", () => {
    if (!res.headersSent) res.writeHead(500, { "Content-Type": "text/plain" });
    res.end();
  });
  req.on("close", () => stream.destroy());
  stream.pipe(res);
}
