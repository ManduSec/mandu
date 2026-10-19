/**
 * sdk-route-stage — a route folder as a launch writes one, for the hook tests
 * (docs/design/agents/agent-sdks.md §3.6): the route as `route.json` beside
 * copies of the preload, its permission-mode rule and the Python hook, which
 * read it from there (never from the environment). Test helper; no test of
 * its own.
 */
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  CLAUDE_PERMISSION_RULE_ASSET, SDK_ROUTE_ASSET, SDK_ROUTE_DIR, SDK_ROUTE_PYTHON_ASSET, sdkRouteFiles, writeSdkRouteDir, type SdkRoute,
} from "../../src/sdk-route.js";

const SRC = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "src");

/** The bundle's own copies (the source tree's). */
export const SOURCES = {
  preload: join(SRC, SDK_ROUTE_ASSET),
  rule: join(SRC, CLAUDE_PERMISSION_RULE_ASSET),
  python: join(SRC, SDK_ROUTE_PYTHON_ASSET),
};

/** Write `route` into `<dir>/sdk-route/` (afresh) as a launch does, and
 *  return it with `require` (and `pythonPath`, when it has one) naming the
 *  copies there: put `--require=<require>` in NODE_OPTIONS and `pythonPath`
 *  on PYTHONPATH to load them. */
export function stageSdkRoute(dir: string, route: SdkRoute): SdkRoute {
  const f = sdkRouteFiles(join(dir, SDK_ROUTE_DIR));
  const staged: SdkRoute = { ...route, require: f.preload, ...(route.pythonPath !== undefined ? { pythonPath: f.pythonDir } : {}) };
  writeSdkRouteDir(f.dir, staged, SOURCES);
  return staged;
}
