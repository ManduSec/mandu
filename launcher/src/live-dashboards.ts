/**
 * live-dashboards — this user's registered dashboards and the URLs a person
 * opens on them (runtime-instances.md §10). `mandu dashboard`, `mandu
 * status`, a launch's banner and last line, and `mandu scan`'s pointer to
 * the Scan page (confidentiality-plan-17-past-sessions-scan.md §3 item 12)
 * all read them here. Moved out of subcommands.ts on 2026-10-22, so
 * scan-command.ts can read them without an import cycle.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { readdirSync } from "node:fs";
import { join } from "node:path";
import { runtimeBase } from "./arbiter-sock.js";
import { readDashManifestLite, realReapDeps } from "./reap.js";

type Env = Record<string, string | undefined>;

/** A registered dashboard this user runs (registry.ts manifest, lite). */
export interface LiveDashboard {
  id: string; pid: number; host: string; port: number; basePath?: string; signInSock?: string;
  /** It asks before any page (registry `signInMode` `password`,
   *  `basic-auth`, `account`, `no-account` or `account-unusable`; dashboard
   *  registry.ts), and with what (`signInWith`: the Mandu dashboard account,
   *  none yet, one that cannot be used, or a username and password; absent:
   *  an older dashboard's password). */
  passwordFirst?: boolean;
  signInWith?: "account" | "basic" | "no-account" | "account-unusable";
}

/** The URL a user opens for a registered dashboard: loopback for a wildcard
 *  bind, the dashboard's own base path (registry entry; entries from before
 *  2026-09-26 carry none and were served under /mandu), and a trailing /. */
export function dashboardUrl(d: { host: string; port: number; basePath?: string }): string {
  const prefix = (d.basePath ?? "/mandu").replace(/\/+$/, "");
  return `http://${connectHost(d.host)}:${d.port}${prefix}/`;
}

/** The URL of a dashboard's Scan page (dashboard.md §4.25ai): the page's
 *  own path under the dashboard's base path (home.js `routeHref('scan')`,
 *  page-routes.ts `/scan`). Pure. */
export function scanPageUrl(d: { host: string; port: number; basePath?: string }): string {
  return `${dashboardUrl(d)}scan`;
}

/** This user's registered dashboards whose process is alive, newest first. */
export function liveDashboards(env: Env, pidAlive: (pid: number) => boolean = realReapDeps.pidAlive): LiveDashboard[] {
  return registeredDashboards(env).filter((d) => pidAlive(d.pid));
}

/** The runtime registry the dashboard writes (dashboard/src/registry.ts,
 *  runtime-instances.md §10): `<runtimeBase>/dashboards/<id>.json`. Per user
 *  by construction (the runtime base lives under XDG_RUNTIME_DIR, the
 *  per-user TMPDIR, or the private 0700 /tmp/mandu-<uid>, §3b). */
export function registeredDashboards(env: Env): LiveDashboard[] {
  const dir = join(runtimeBase(env), "dashboards");
  let names: string[] = [];
  try { names = readdirSync(dir); } catch { return []; }
  const out: LiveDashboard[] = [];
  for (const name of names.filter((n) => n.endsWith(".json")).sort().reverse()) {
    const m = readDashManifestLite(join(dir, name));
    if (!m || typeof m.port !== "number" || m.port <= 0) continue;
    out.push({
      id: name.replace(/\.json$/, ""), pid: m.pid, host: m.host ?? "127.0.0.1", port: m.port,
      ...(typeof m.basePath === "string" ? { basePath: m.basePath } : {}),
      ...(typeof m.signInSock === "string" ? { signInSock: m.signInSock } : {}),
      ...(m.signInMode === "password" || m.signInMode === "basic-auth" || m.signInMode === "account" || m.signInMode === "no-account" || m.signInMode === "account-unusable" ? { passwordFirst: true } : {}),
      ...(m.signInMode === "account" ? { signInWith: "account" as const }
        : m.signInMode === "basic-auth" ? { signInWith: "basic" as const }
        : m.signInMode === "no-account" ? { signInWith: "no-account" as const }
        : m.signInMode === "account-unusable" ? { signInWith: "account-unusable" as const } : {}),
    });
  }
  return out;
}

/** A wildcard bind is reached over loopback. */
export function connectHost(host: string): string {
  return host === "0.0.0.0" || host === "::" || host === "" ? "127.0.0.1" : host;
}
