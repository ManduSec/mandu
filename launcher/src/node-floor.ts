/**
 * node-floor — the ONE Node version floor, as a major.minor.patch, and the
 * comparison every gate uses.
 *
 * Why a minor matters (packaging.md, 2026-09-24): the arbiter
 * imports `node:sqlite` unguarded (arbiter/db/sqlite.ts), and Node removed
 * the `--experimental-sqlite` flag in 22.13.0. A major-only check (`>= 22`)
 * admitted 22.0–22.12, where the arbiter dies at import with a flag error the
 * user cannot read as "upgrade Node". Four gates state the floor — `engines`
 * in package.json, bin/mandu.mjs (runs before the bundle, so it cannot
 * import this), scripts/bootstrap.sh (bash), and `mandu doctor` (here) —
 * and test/unit/node-floor.test.ts pins the other three to this constant so
 * they cannot drift apart again.
 *
 * Also the second, advisory floor: the Node a PROGRAM in a session needs for
 * its web requests to go through Mandu's network proxy (nodeEnvProxyGap,
 * below). Pure: no I/O.
 */

/** The lowest Node release Mandu runs on. */
export const NODE_FLOOR = "22.13.0";

/** Parse "22.13.0" (or "v22.13.0") into numbers; null when unparseable. */
export function parseNodeVersion(version: string): [number, number, number] | null {
  const m = /^v?(\d+)\.(\d+)\.(\d+)/.exec(version.trim());
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

/** Does `version` satisfy the floor? Unparseable → false (fail closed). */
export function nodeMeetsFloor(version: string, floor: string = NODE_FLOOR): boolean {
  const v = parseNodeVersion(version);
  const f = parseNodeVersion(floor);
  if (!v || !f) return false;
  for (let i = 0; i < 3; i++) {
    if (v[i] > f[i]) return true;
    if (v[i] < f[i]) return false;
  }
  return true;
}

/**
 * The second Node floor: the one a Node PROGRAM in a session needs for its
 * web requests to go through Mandu's network proxy (where a placeholder it
 * sends is put back for the real value at the wire). The launcher sets
 * NODE_USE_ENV_PROXY=1 (env-compose.ts), and Node's own docs (doc/api/cli.md
 * `NODE_USE_ENV_PROXY`, doc/api/http.md "Built-in Proxy Support") date it:
 *
 *   fetch          added v24.0.0, backported to v22.21.0
 *   http / https   added v24.5.0, backported to v22.21.0 (the global agent
 *                  built with `proxyEnv`)
 *
 * No release line between them has it (23.x never did; 22 before .21 and 20
 * ignore the variable). The TLS-compat matrix measures it
 * (confidentiality-plan-13-reader-set-labels.md §10.2; its test lib
 * re-exports these). Below it the program goes around the proxy: nothing
 * leaks (it only ever held the placeholder), but its logins fail. This is
 * NOT Mandu's own floor above: Mandu runs on 22.13, and `mandu doctor` and
 * the launch only warn (nodeEnvProxyGap).
 */
export type NodeProxyApi = "fetch" | "https";

/** Does a Node of this `--version` route `api` through HTTPS_PROXY when
 *  NODE_USE_ENV_PROXY=1? An unparseable version ⇒ false. */
export function nodeHonorsEnvProxy(version: string, api: NodeProxyApi): boolean {
  const v = parseNodeVersion(version);
  if (!v) return false;
  const [major, minor] = v;
  if (major >= 25) return true;
  if (major === 24) return api === "fetch" ? true : minor >= 5;
  if (major === 22) return minor >= 21;
  return false;
}

/** What the `node` on a session's PATH does with the launcher's proxy
 *  variable: `absent` (no node there, or it did not answer), `ok`,
 *  `bypass` (the APIs that go around the proxy, never empty), or
 *  `unreadable` (it answered something that is not a version). Pure. */
export type NodeEnvProxyGap =
  | { state: "absent" }
  | { state: "ok"; version: string }
  | { state: "bypass"; version: string; apis: NodeProxyApi[] }
  | { state: "unreadable"; text: string };

export function nodeEnvProxyGap(versionText: string | null): NodeEnvProxyGap {
  const version = (versionText ?? "").trim();
  if (version === "") return { state: "absent" };
  if (parseNodeVersion(version) === null) return { state: "unreadable", text: version.split("\n")[0]!.slice(0, 80) };
  const apis = (["fetch", "https"] as const).filter((api) => !nodeHonorsEnvProxy(version, api));
  return apis.length === 0 ? { state: "ok", version } : { state: "bypass", version, apis: [...apis] };
}

/** The upgrade both warnings name: Node 22.21+ or 24.5+, by the line the
 *  user is on (a 24.0 to 24.4 lacks only http/https). */
export function nodeEnvProxyFix(version: string): string {
  const major = parseNodeVersion(version)?.[0];
  return major === 24
    ? "upgrade to Node 24.5 or newer (nvm install 24)"
    : "upgrade to Node 22.21 or newer, or 24.5 or newer (nvm install 22)";
}

/** Which requests a `bypass` gap covers, in plain words. */
export function bypassWords(apis: readonly NodeProxyApi[]): string {
  if (apis.length === 2) return "their web requests";
  return apis[0] === "https" ? "web requests made with http/https (fetch works)" : "web requests made with fetch";
}

/** The launch's one-line notice for a `bypass` gap (launch-banner.ts passes
 *  it through as it is, packaging.md "Launch display policy"), else null. */
export function nodeEnvProxyNotice(g: NodeEnvProxyGap): string | null {
  if (g.state !== "bypass") return null;
  return `mandu: ! Node ${g.version} on your PATH is too old for Mandu: Node programs in this session won't have your secrets filled in on ${bypassWords(g.apis)}; see \`mandu doctor\``;
}

/** Does `note` come from nodeEnvProxyNotice? (launch-banner.ts compactNotice) */
export function isNodeEnvProxyNotice(note: string): boolean {
  return /^mandu: ! Node \S+ on your PATH is too old for Mandu: /.test(note);
}
