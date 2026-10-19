/**
 * extension-loader — how server-main finds the front-ends beyond the product
 * page (dashboard.md §4.25ac). The developer view is a module this package
 * does not import: a build that carries it has it at a known place, and one
 * that does not serves the product only.
 *
 * Where it looks, first found wins:
 *   1. `dashboard-dev.mjs` beside this bundle (launcher/dist/dashboard.mjs:
 *      the bundle build writes it when the developer view's source exists);
 *   2. from source, the module `dashboard/package.json` names in
 *      `mandu.devExtension` (relative to the package), when it exists.
 * No environment variable can name another module: the dashboard is the
 * human's view, and a module loaded into it runs with its sign-in.
 *
 * The module exports `createDashboardExtensions(ctx)`. A module that fails
 * to load or to build costs the developer view, never the product page: the
 * failure is logged and the server starts without it.
 */

import { existsSync, readFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { type DashboardExtension } from "./server/extension.js";
import { type DashboardSelfControl } from "./server/options.js";
import { type Supervisor } from "./supervisor/supervisor.js";

/** What server-main hands the developer view's module. */
export interface ExtensionBootContext {
  /** The repository root (or the installed package root). */
  repoRoot: string;
  /** The package's own launcher entry, when installed (not a checkout). */
  installedLauncher?: string;
  /** The live arbiter's socket, and the test tenant's socket and event dir. */
  arbiterSock: string;
  testArbiterSock: string;
  testEventDir: string;
  /** The process supervisor; none under DASHBOARD_CONTROL=0, and then no
   *  runners either. */
  supervisor?: Supervisor;
  /** The dashboard's own status and restart. */
  selfControl?: DashboardSelfControl;
  /** The product's front-end directory (the developer view wears its CSS). */
  publicDir: string;
  env: Record<string, string | undefined>;
  log: (msg: string) => void;
}

/** The module's export. */
export type CreateDashboardExtensions = (ctx: ExtensionBootContext) => Promise<DashboardExtension[]> | DashboardExtension[];

/** The developer view's module, or null when this build carries none.
 *  `here`: the directory of the running server-main (src/, or the bundle's
 *  dist/). */
export function resolveExtensionModule(here: string, exists: (p: string) => boolean = existsSync, read: (p: string) => string = (p) => readFileSync(p, "utf8")): string | null {
  const bundled = join(here, "dashboard-dev.mjs");
  if (exists(bundled)) return bundled;
  if (basename(here) !== "src") return null;
  const pkgDir = join(here, "..");
  let rel: unknown;
  try {
    rel = (JSON.parse(read(join(pkgDir, "package.json"))) as { mandu?: { devExtension?: unknown } }).mandu?.devExtension;
  } catch {
    return null;
  }
  if (typeof rel !== "string" || rel === "") return null;
  const path = resolve(pkgDir, rel);
  return exists(path) ? path : null;
}

/** Load and build the extensions; none when there is no module, or when it
 *  fails (logged). */
export async function loadExtensions(here: string, ctx: ExtensionBootContext): Promise<DashboardExtension[]> {
  const path = resolveExtensionModule(here);
  if (path === null) {
    ctx.log("no developer view in this build: serving the product page only");
    return [];
  }
  try {
    const mod = (await import(pathToFileURL(path).href)) as { createDashboardExtensions?: CreateDashboardExtensions };
    if (typeof mod.createDashboardExtensions !== "function") throw new Error("it exports no createDashboardExtensions");
    const extensions = await mod.createDashboardExtensions(ctx);
    ctx.log(`extensions: ${extensions.map((x) => `${x.name} at ${x.mount}/`).join(", ") || "none"} (${path})`);
    return extensions;
  } catch (err) {
    ctx.log(`the developer view did not load (${path}): ${(err as Error).message}; serving the product page only`);
    return [];
  }
}
