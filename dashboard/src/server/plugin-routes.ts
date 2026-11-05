/**
 * server/plugin-routes — GET /api/plugins, the product's Plugins page
 * (dashboard.md §4.25aj). Mandu-new (no reference origin).
 *
 * It gathers what `mandu serve status` reads (launcher/src/serve-attachments.ts
 * gatherAttachments), from this machine's files and the protection service,
 * and hands the facts to the pure view model (view-model/plugins.ts):
 *
 *   - the declared sessions (`serve-attachments` in the Mandu home, the file
 *     `mandu openclaw install` writes and the pool reads);
 *   - whether the service's proxy pool runs: in this process (the service's
 *     own dashboard, `MANDU_SERVE=1`, whose pool state is read directly), or
 *     in another whose record (`<runtime>/attachments/pool.json`) names a
 *     live pid;
 *   - per session: its port file (trusted only as the contract says: a
 *     regular file of this user's no one else can write) and whether the
 *     proxy on that port answers as the session's (`/_mandu/identity`); its
 *     pool record's secret registration;
 *   - the attachments the arbiter holds, with when each began
 *     (`humanPlaneStatus`, read-only; none when it does not answer);
 *   - which sessions have a record (the session list), so a card links its
 *     session page only when there is one.
 *
 * Read-only, GET, open in the read gate: the answer names agents, sessions,
 * counts, states and fixed sentences; never a port (a local program that
 * learned it could speak to the proxy as the session), a path or a value.
 */

import { lstatSync, readFileSync } from "node:fs";
import { type ServerResponse } from "node:http";
import { join } from "node:path";

import { json } from "./http-util.js";
import { type EventSource } from "../event-source.js";
import {
  anthropicProxyPortFile,
  attachmentDir,
  identityProblem,
  parseDeclared,
  parsePortFile,
  poolMarkerFile,
  poolRecordPid,
  POOL_RECORD_FILE,
  portFileProblem,
  type ServiceIdentity,
} from "../attachment-contract.js";
import { isAttachmentKind } from "../confinement-posture.js";
import { probeServiceIdentity, type PoolEntry } from "../supervisor/attachment-pool.js";
import { pluginsPage, type PluginFacts, type PluginSessionFacts, type PluginsVM } from "../view-model/plugins.js";

/** Where the page reads from (server.ts builds it; tests inject it). */
export interface PluginDeps {
  source: EventSource;
  /** The stack's runtime directory (runtime-base.ts). */
  runtimeBase: string;
  /** The declared file (`serve-attachments` in the path table). */
  declaredFile: string;
  /** This process's own pool, when it runs one (server-main.ts, under
   *  `mandu serve`): `AttachmentPool.list`. */
  pool?: () => PoolEntry[];
  /** This user's uid (the port file's owner check); undefined skips it. */
  uid?: number;
  /** `GET /_mandu/identity` of a proxy on 127.0.0.1. */
  probe?: (port: number) => Promise<ServiceIdentity | null>;
  /** Is this pid alive (the pool record's)? */
  pidAlive?: (pid: number) => boolean;
}

function readText(path: string): string | null {
  try { return readFileSync(path, "utf8"); } catch { return null; }
}

function pidAliveHere(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch (e) { return (e as NodeJS.ErrnoException).code === "EPERM"; }
}

/** The pool record's secret registration (launcher serve-attachments.ts
 *  poolRecordSecrets, the same reading). */
function recordSecrets(text: string | null): PluginSessionFacts["secrets"] {
  if (text === null) return null;
  try {
    const s = (JSON.parse(text) as { secrets?: { found?: unknown; registered?: unknown; at?: unknown } }).secrets;
    if (s && typeof s.found === "number" && typeof s.registered === "number" && typeof s.at === "string") return { found: s.found, registered: s.registered, at: s.at };
  } catch { /* torn */ }
  return null;
}

/** Does a proxy answer as `session`'s on the port its port file names? */
async function answering(d: PluginDeps, session: string): Promise<boolean> {
  const file = anthropicProxyPortFile(d.runtimeBase, session);
  let st;
  try { st = lstatSync(file); } catch { return false; }
  if (portFileProblem({ isFile: st.isFile(), uid: st.uid, mode: st.mode }, d.uid) !== null) return false;
  const port = parsePortFile(readText(file) ?? "");
  if (port === null) return false;
  const id = await (d.probe ?? ((p: number) => probeServiceIdentity(p, 800)))(port);
  return identityProblem(id, session) === null;
}

/** The facts behind the page. */
export async function gatherPluginFacts(d: PluginDeps): Promise<PluginFacts> {
  const declared = parseDeclared(readText(d.declaredFile)).attachments;
  const alive = d.pidAlive ?? pidAliveHere;
  const markerPid = poolRecordPid(readText(poolMarkerFile(d.runtimeBase)) ?? "");
  const serviceRunning = d.pool !== undefined || (markerPid !== null && alive(markerPid));
  const own = new Map((d.pool?.() ?? []).map((e) => [e.session, e] as const));

  let live: Map<string, number | null> | null = null;
  let liveKinds = new Map<string, string>();
  try {
    const st = d.source.humanPlaneStatus ? await d.source.humanPlaneStatus() : null;
    if (st && Array.isArray(st.launches)) {
      live = new Map();
      for (const l of st.launches) {
        if (typeof l.attachment !== "string" || typeof l.session !== "string") continue;
        live.set(l.session, typeof l.begunAt === "number" ? l.begunAt : null);
        liveKinds.set(l.session, l.attachment);
      }
    }
  } catch {
    live = null;
    liveKinds = new Map();
  }

  // Declared first, in the file's order; then any the arbiter still holds
  // without a declaration (a detach whose hold has not run out).
  const rows: Array<{ session: string; kind: string; agent: string; declared: boolean }> = declared.map((a) => ({ session: a.session, kind: a.kind, agent: a.agent, declared: true }));
  for (const [session, kind] of liveKinds) {
    if (rows.some((r) => r.session === session)) continue;
    const m = /^[a-z]+:(.+)$/.exec(session);
    rows.push({ session, kind, agent: m ? m[1]! : session, declared: false });
  }

  const sessions: PluginSessionFacts[] = [];
  for (const r of rows) {
    if (!isAttachmentKind(r.kind)) continue;
    sessions.push({
      session: r.session,
      kind: r.kind,
      agent: r.agent,
      declared: r.declared,
      answering: serviceRunning ? await answering(d, r.session) : false,
      poolState: own.get(r.session)?.state ?? null,
      secrets: own.get(r.session)?.secrets ?? recordSecrets(readText(join(attachmentDir(d.runtimeBase, r.session), POOL_RECORD_FILE))),
      route: null,
      recorded: null,
    });
  }

  // The session list: which sessions have a record (the page link), and the
  // route check's word on each (openclaw-plugin.md §3.6): the arbiter's
  // newest BELIEVED posture record of the attachment, as the session list
  // derives it (session-health.ts `attachmentRoute`, never from a claim;
  // Home's route card reads the same). A lost route counts while the
  // attachment is live, as on Home (an ended one's last record says nothing
  // about now), or while that is not known.
  let known = new Set<string>();
  if (sessions.length > 0) {
    try {
      const byId = new Map(sessions.map((s) => [s.session, s] as const));
      for (const ref of await d.source.listSessions()) {
        const s = byId.get(ref.id);
        if (!s) continue;
        known.add(ref.id);
        const lost = ref.health?.attachmentRoute;
        if (lost && (live === null || live.has(ref.id))) {
          s.route = { state: "lost", problems: lost.problems.map((p) => p.detail), since: lost.since };
          const sec = ref.health?.secrets;
          if (sec) s.recorded = { posture: sec.posture, gap: sec.gap ?? null };
        } else if (ref.health) {
          s.route = { state: "ok" };
        }
      }
    } catch { known = new Set(); /* no links, no route word */ }
  }
  return { serviceRunning, sessions, live, known };
}

/** GET /api/plugins → `{ plugins: PluginsVM }`. */
export async function apiPlugins(d: PluginDeps, res: ServerResponse): Promise<void> {
  let vm: PluginsVM;
  try {
    vm = pluginsPage(await gatherPluginFacts(d));
  } catch {
    json(res, 500, { error: "the Plugins page could not be read" });
    return;
  }
  json(res, 200, { plugins: vm });
}
