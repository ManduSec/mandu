/**
 * sdk-route — a product built on an agent SDK, run as `mandu --target
 * claude|codex -- node app.js` (docs/design/agents/agent-sdks.md).
 *
 * The Claude Agent SDK and the TypeScript Codex SDK start the real CLI as a
 * child of the host program. Two of their options break the routing a plain
 * `mandu claude` / `mandu codex` gets: `env` REPLACES the child's
 * environment (ANTHROPIC_BASE_URL, the proxy and CA variables, MANDU_* are
 * gone), and Codex takes its provider only from its own command line, which
 * the SDK builds. The launcher closes both in the host's Node: it loads
 * sdk-route-preload.cjs (NODE_OPTIONS=--require), and every child the host
 * starts keeps this launch's routing, a
 * `codex` child gets the provider splice, and an agent CLI this launch does
 * not route refuses to start (the preload's header has the detail). An
 * agent child's routing comes from the launch's own values alone
 * (SdkRoute.launchRouting), never from the environment the host hands it.
 *
 * Three more deliveries carry the same route (agent-sdks.md §3):
 *   - a Python host loads sdk-route-python/sitecustomize.py (PYTHONPATH),
 *     which hooks every Popen and asks the preload itself to decide each
 *     agent child (the route names the Node binary to ask with);
 *   - the PATH shims (`<scope run dir>/sdk-shims/{claude,codex}`, first on
 *     the host's PATH and every child's) route or refuse an agent CLI found
 *     by name: a shell command string, a Bun or Deno host's bare `codex`;
 *   - a host the route cannot reach at all refuses the launch where its
 *     agent would run unrouted (sdkHostRefusal: a Bun or Deno host, or a
 *     Python started with -I/-E/-S, under --target codex).
 * A claude or shell launch the route does not serve (`mandu claude`,
 * `mandu -- bash`) gets only a `claude` PATH shim in the same folder
 * (writeClaudeShim), which routes a `claude` the session starts by name as
 * `mandu claude` is routed: the launch's routing variables put back in its
 * environment and imposed in its last `--settings` (claude-route.ts; a
 * settings file's `env` would otherwise re-point it around the model
 * proxy), the same refusals, and Claude Code's permission-mode rule
 * (claude-permission-rule.cjs). agent-sdks.md §3.5.
 *
 * Which launches get the route (sdkRouteApplies): every claude, codex or
 * shell launch whose argv[0] is a language runtime (types.ts hostRuntimeOf),
 * and every claude or codex launch whose argv[0] is neither the agent CLI
 * itself nor a POSIX shell (a wrapper the user vouched for with --target:
 * `./run-app.sh`, `env node app.js`), since the Node program inside it is the
 * same host. The agent binary itself keeps its own routing and gets none (a
 * Bun-built `claude` has no use for a Node preload), and so does a shell,
 * the live oracles' stand-in for an agent.
 *
 * Where the route lives (2026-10-18, agent-sdks.md §3.6): in a file the
 * agent cannot write, never in the environment. The launch copies the
 * preload, its permission-mode rule and the Python hook into
 * `<scope run dir>/sdk-route/` and writes the route beside them
 * (`route.json`, writeSdkRouteDir); each copy reads the route beside itself,
 * the PATH shims name the preload copy by full path, and both folders
 * (`sdk-route/`, `sdk-shims/`) are on the whole-agent guard's and the macOS
 * profile's write-protect list (sdkRouteWriteProtect). A route in
 * MANDU_SDK_ROUTE, where it rode before, is ignored and removed from every
 * child: a host the model steers could set it in a shell string and hand
 * the shims and the hooks a model base URL or proxy of its choosing.
 *
 * This module is the pure half: whether the route applies, the route (from
 * the composed launch), the variables that deliver it, the shims' text, the
 * refusal and the launch note. run.ts wires it after the env is composed
 * (and writes the route and the shims, writeSdkRouteDir, writeSdkShims and
 * writeClaudeShim, the only functions here that touch the filesystem).
 *
 * Mandu-new (no reference origin).
 */
import { chmodSync, closeSync, constants, copyFileSync, mkdirSync, openSync, rmSync, writeFileSync } from "node:fs";
import { basename, delimiter, join } from "node:path";
import { claudeRouteEnv } from "./claude-route.js";
import { isCodexBinary } from "./codex-argv.js";
import { codexProviderToml, isClaudeBinary, withNodeOption } from "./env-compose.js";
import { hostRuntimeOf, SHELL_BASENAMES, type LaunchPlan } from "./types.js";

/** The variable that carried the route before 2026-10-18: the hooks and the
 *  shims ignore it and remove it from every child (the header). */
export const SDK_ROUTE_ENV = "MANDU_SDK_ROUTE";
/** The launch's folder of route copies, in the scope run dir: the route
 *  file, the preload and its rule, and the Python hook's folder. */
export const SDK_ROUTE_DIR = "sdk-route";
/** The route file in it (the preload's and the Python hook's ROUTE_FILE). */
export const SDK_ROUTE_FILE = "route.json";
/** The PATH shims' folder, in the scope run dir. */
export const SDK_SHIM_DIR = "sdk-shims";
/** The preload's key in bundle-manifest.json `assets` (Layout.asset). */
export const SDK_ROUTE_ASSET = "sdk-route-preload.cjs";
/** The permission-mode rule's key in bundle-manifest.json `assets`: the
 *  preload requires it from beside itself (claude-permission-rule.cjs). */
export const CLAUDE_PERMISSION_RULE_ASSET = "claude-permission-rule.cjs";
/** The Python hook's key in bundle-manifest.json `assets`; its directory is
 *  what goes on PYTHONPATH (it holds nothing else). */
export const SDK_ROUTE_PYTHON_ASSET = "sdk-route-python/sitecustomize.py";
/** The agent CLIs the PATH shims stand in for. */
export const SDK_SHIM_NAMES = ["claude", "codex"] as const;

/** The route the preload enforces (its header). */
export interface SdkRoute {
  v: 1;
  target: LaunchPlan["target"];
  /** The routing variables, with this launch's values, put back in every
   *  child's environment. */
  env: Record<string, string>;
  /** The agent PATH, for a child whose environment has none. */
  path: string;
  /** The shim directories, put back at the head of every child's PATH (the
   *  SDK shims first). */
  pathPrefix: string[];
  /** The launch's copy of the preload (`<scope run dir>/sdk-route/`, which
   *  reads this route from beside itself), kept in every child's
   *  NODE_OPTIONS. */
  require: string;
  /** The launch's copy of the Python hook's directory (`sdk-route/python`),
   *  kept first on every child's PYTHONPATH. */
  pythonPath?: string;
  /** The Node binary the Python hook asks the preload's decision of. */
  node?: string;
  /** Claude Code is routed (ANTHROPIC_BASE_URL is in `env`). */
  anthropic: boolean;
  /** Every routing variable with the LAUNCH's own value (claude-route.ts
   *  claudeRouteEnv of the agent's whole environment: the routing
   *  variables, "" where the launch sets none, the cloud switches off): the
   *  one source of an agent child's routing. A `claude` child's last
   *  `--settings` imposes exactly these and its environment gets them back
   *  (one the launch does not set removed); a `codex` child's environment
   *  gets the proxy variables back. Never read from the child's own
   *  environment, which the host program (and through it the model)
   *  chooses: a routing variable the host added or changed there would be
   *  pinned into the overlay, where it wins (agent-sdks.md §3, §4). */
  launchRouting: Record<string, string>;
  /** Codex's provider splice, one TOML per way the child authenticates;
   *  null when this launch does not route Codex. */
  codex: {
    provider: string;
    toml: { OPENAI_API_KEY: string; CODEX_API_KEY: string; "sign-in": string };
    /** Also force `features.connectors=false` (the user's Codex config names
     *  that legacy key; codex-argv.ts CODEX_CONNECTORS_OFF). */
    connectorsOff?: boolean;
  } | null;
  /** Claude Code's permission mode (claude-permission-mode.ts): a `claude`
   *  child gets `--permission-mode default` unless its command line chose a
   *  mode or a settings scope it reads sets one. `scopes` are the scopes
   *  whose files set one for a Claude Code started in `cwd` with user
   *  config dir `configDir` (a child started elsewhere, whose project,
   *  local or user files Mandu did not read, is left alone). Absent: the
   *  preload leaves every child's mode alone. */
  claudeMode?: SdkClaudeMode;
}

/** The launch's answer for the preload's permission-mode decision. */
export interface SdkClaudeMode {
  cwd: string;
  configDir: string;
  scopes: Array<"managed" | "user" | "project" | "local">;
}

/** Where the route's other deliveries live (run.ts): the Python hook's
 *  directory, the Node binary, the PATH shims' directory. */
export interface SdkRouteDelivery {
  pythonPath?: string;
  node?: string;
  shimDir?: string;
}

/** How a launch's argv[0] relates to the route: a language runtime running a
 *  host program, a wrapper of the agent, or neither (the agent CLI itself, a
 *  shell, or a target the route does not serve). Pure. */
export function sdkRouteApplies(plan: Pick<LaunchPlan, "target" | "argv">): "runtime" | "wrapper" | null {
  const argv0 = plan.argv[0];
  if (plan.target !== "claude" && plan.target !== "codex" && plan.target !== "shell") return null;
  if (hostRuntimeOf(argv0) !== null) return "runtime";
  if (plan.target === "shell" || SHELL_BASENAMES.has(basename(argv0 ?? ""))) return null;
  if (plan.target === "claude" ? isClaudeBinary(argv0) : isCodexBinary(argv0)) return null;
  return "wrapper";
}

/** Variables never forced on a child: PATH, PYTHONPATH and NODE_OPTIONS are
 *  merged, the route rides its own variable, a masked secret variable
 *  carries the host's own value (already the placeholder when it came from
 *  the launch), and the human-plane socket is the reply filter's alone: it
 *  never reaches the agent's tree (human-plane.ts), so it is not even named
 *  in the route. */
const NOT_FORCED: ReadonlySet<string> = new Set([
  "PATH", "PYTHONPATH", "NODE_OPTIONS", SDK_ROUTE_ENV, "MANDU_LAUNCH_DISPLAY", "MANDU_LAUNCH_LOG", "MANDU_ARBITER_HUMAN_SOCK",
  // The reply filter's own layout hint, which it removes from its child
  // (reply-filter arbiter-client.ts childEnv): the PATH shims apply the route
  // as received, so it is not named in it either.
  "MANDU_REPLY_WRAP_RULE",
]);

/**
 * The route for this launch, or null when it gets none (sdkRouteApplies).
 * `composedEnv` is the launch's whole delta (mut.env), `masked` the secret
 * variables it masked, `inheritedEnv` the environment the agent inherits
 * under that delta (`launchRouting` is read from the two together, as the
 * agent gets them; run.ts checks it against the agent's environment). Pure.
 */
export function composeSdkRoute(
  plan: Pick<LaunchPlan, "target" | "argv" | "basePath" | "execBoxShimDir" | "shimDir" | "bwrapDir"
    | "openaiBaseUrl" | "openaiProxy" | "openaiProviderName" | "tllmEndpoint" | "codexConnectorsOff">,
  composedEnv: Record<string, string>,
  masked: readonly string[],
  preloadPath: string,
  claudeMode?: SdkClaudeMode,
  delivery: SdkRouteDelivery = {},
  inheritedEnv: Record<string, string | undefined> = {},
): SdkRoute | null {
  if (sdkRouteApplies(plan) === null) return null;
  const skip = new Set([...NOT_FORCED, ...masked]);
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(composedEnv)) if (!skip.has(k)) env[k] = v;
  const codex = plan.target === "codex"
    ? {
      provider: plan.openaiProviderName,
      toml: {
        OPENAI_API_KEY: codexProviderToml({ ...plan, codexAuth: "key", openaiEnvKey: "OPENAI_API_KEY" }),
        CODEX_API_KEY: codexProviderToml({ ...plan, codexAuth: "key", openaiEnvKey: "CODEX_API_KEY" }),
        "sign-in": codexProviderToml({ ...plan, codexAuth: "sign-in", openaiEnvKey: "OPENAI_API_KEY" }),
      },
      connectorsOff: plan.codexConnectorsOff === true,
    }
    : null;
  return {
    v: 1,
    target: plan.target,
    env,
    path: composedEnv["PATH"] ?? plan.basePath,
    pathPrefix: [delivery.shimDir, plan.execBoxShimDir, plan.shimDir, plan.bwrapDir]
      .filter((d): d is string => typeof d === "string" && d !== ""),
    require: preloadPath,
    ...(delivery.pythonPath ? { pythonPath: delivery.pythonPath } : {}),
    ...(delivery.node ? { node: delivery.node } : {}),
    anthropic: typeof env["ANTHROPIC_BASE_URL"] === "string",
    launchRouting: claudeRouteEnv({ ...inheritedEnv, ...composedEnv }),
    codex,
    ...(claudeMode !== undefined && plan.target !== "codex" ? { claudeMode } : {}),
  };
}

/** The NODE_OPTIONS entry that loads the preload (quoted when the path has
 *  whitespace, the form NODE_OPTIONS parses as one argument). Mirrored by
 *  the preload's routeEnv, which keeps it in every child. */
export function requireOption(preloadPath: string): string {
  return /\s/.test(preloadPath) ? `--require="${preloadPath}"` : `--require=${preloadPath}`;
}

/** `dir` first in a PATH-like list, once. */
export function withHead(dir: string, list: string | undefined): string {
  return [dir, ...(list ?? "").split(delimiter).filter((d) => d !== "" && d !== dir)].join(delimiter);
}

/** The variables that deliver the route to the host: NODE_OPTIONS with the
 *  preload copy added to `existing.nodeOptions` (the launch's or the user's
 *  own options, kept), PYTHONPATH with the Python hook's copy first, and PATH
 *  with the SDK shims first. Not the route itself, which each copy reads
 *  from the file beside it (writeSdkRouteDir). Pure. */
export function sdkRouteEnv(
  route: SdkRoute,
  existing: string | undefined | { nodeOptions?: string; pythonPath?: string; path?: string },
): Record<string, string> {
  const ex = typeof existing === "object" ? existing : { nodeOptions: existing };
  const out: Record<string, string> = {
    NODE_OPTIONS: withNodeOption(ex.nodeOptions, requireOption(route.require)),
  };
  if (route.pythonPath) out["PYTHONPATH"] = withHead(route.pythonPath, ex.pythonPath);
  const shims = route.pathPrefix[0];
  if (shims !== undefined && ex.path !== undefined) out["PATH"] = withHead(shims, ex.path);
  return out;
}

/** The paths of a launch's route folder `dir` (`<scope run dir>/sdk-route`):
 *  the route file and the copies the route names (`require` is `preload`,
 *  `pythonPath` is `pythonDir`). Pure. */
export function sdkRouteFiles(dir: string): { dir: string; route: string; preload: string; rule: string; pythonDir: string } {
  return {
    dir,
    route: join(dir, SDK_ROUTE_FILE),
    preload: join(dir, basename(SDK_ROUTE_ASSET)),
    rule: join(dir, basename(CLAUDE_PERMISSION_RULE_ASSET)),
    pythonDir: join(dir, "python"),
  };
}

/** Create `p` with `text`, failing if anything is there (a link included). */
function createExclusive(p: string, text: string, mode: number): void {
  const fd = openSync(p, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, mode);
  try { writeFileSync(fd, text); } finally { closeSync(fd); }
}

/**
 * Write the launch's route folder `dir` afresh (whatever was there removed
 * first): the route as `route.json`, and copies of the preload, its
 * permission-mode rule (which it requires from beside itself) and the
 * Python hook (`python/sitecustomize.py`) from the bundle (`sources`). The
 * copies read the route beside them, so `route.require` and
 * `route.pythonPath` must name these copies (sdkRouteFiles). The folder is
 * write-protected for the agent (sdkRouteWriteProtect).
 */
export function writeSdkRouteDir(dir: string, route: SdkRoute, sources: { preload: string; rule: string; python: string }): void {
  const f = sdkRouteFiles(dir);
  if (route.require !== f.preload || (route.pythonPath !== undefined && route.pythonPath !== f.pythonDir)) {
    throw new Error(`mandu: internal: the SDK route names hooks outside its folder ${dir}; refusing to launch.`);
  }
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(f.pythonDir, { recursive: true, mode: 0o755 });
  copyFileSync(sources.preload, f.preload, constants.COPYFILE_EXCL);
  copyFileSync(sources.rule, f.rule, constants.COPYFILE_EXCL);
  copyFileSync(sources.python, join(f.pythonDir, basename(SDK_ROUTE_PYTHON_ASSET)), constants.COPYFILE_EXCL);
  createExclusive(f.route, JSON.stringify(route), 0o644);
}

/** The write-protect entries (`deny`, Mandu's own files) for a launch's
 *  route folder and shim folder under `scopeRunDir`: the agent can then
 *  neither rewrite the route nor replace a shim (write-protect.ts; the
 *  Linux guard and the macOS profile both take the entry). Pure. */
export function sdkRouteWriteProtect(scopeRunDir: string): Array<{ path: string; answer: "deny"; label: string }> {
  return [SDK_ROUTE_DIR, SDK_SHIM_DIR].map((d) => ({ path: join(scopeRunDir, d), answer: "deny" as const, label: "Mandu's own files" }));
}

/** POSIX single-quoting. */
function shQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** One PATH shim: hands `name` and its arguments to the preload's `--exec`
 *  entry, which routes it by the route beside that copy of the preload
 *  (`preload`, baked in by full path: nothing in the caller's environment
 *  can redirect it), or refuses it, and runs the real one found further
 *  down PATH. Pure. */
export function sdkShimScript(name: string, node: string, preload: string, shimDir: string): string {
  return [
    "#!/bin/sh",
    `# Mandu's SDK route (agent-sdks.md §3): \`${name}\` found by name on PATH is routed or refused.`,
    `exec ${shQuote(node)} --no-warnings ${shQuote(preload)} --exec ${shQuote(shimDir)} ${name} "$@"`,
    "",
  ].join("\n");
}

/** Write the PATH shims into `dir` (created). The folder is write-protected
 *  for the agent (sdkRouteWriteProtect), so the agent cannot replace them. */
export function writeSdkShims(dir: string, node: string, preload: string): void {
  mkdirSync(dir, { recursive: true });
  for (const name of SDK_SHIM_NAMES) {
    const p = join(dir, name);
    rmSync(p, { force: true });
    writeFileSync(p, sdkShimScript(name, node, preload, dir), { mode: 0o755 });
    chmodSync(p, 0o755);
  }
}

/** What the `claude` shim of a claude or shell launch the SDK route does not
 *  serve applies (the preload's claudeShimSpawn): the launch's routing
 *  overlay (claude-route.ts claudeRouteEnv of the environment the agent is
 *  launched with: each routing variable with its value or "", the cloud
 *  switches off) and its answer for the permission-mode decision. */
export interface ClaudeShimRoute {
  env: Record<string, string>;
  claudeMode: SdkClaudeMode;
}

/** The `claude` shim's route for a launch whose agent gets `agentEnv`
 *  (the whole environment: the launch's delta over the inherited one).
 *  Pure. */
export function claudeShimRoute(agentEnv: Record<string, string | undefined>, claudeMode: SdkClaudeMode): ClaudeShimRoute {
  return { env: claudeRouteEnv(agentEnv), claudeMode };
}

/** The `claude` PATH shim of a claude or shell launch the SDK route does
 *  not serve (`mandu claude`, `mandu -- bash`): hands its arguments to the
 *  preload's `--claude` entry, which routes it as `mandu claude` is routed
 *  with this launch's route (`route`, baked in: nothing in the session's
 *  environment can change it) and runs the real `claude` found further down
 *  PATH. Pure. */
export function claudeShimScript(node: string, preload: string, shimDir: string, route: ClaudeShimRoute): string {
  return [
    "#!/bin/sh",
    "# Mandu (agent-sdks.md §3.5): a `claude` found by name on PATH keeps Mandu's model routing over its settings files, and starts in Claude Code's default permission mode unless it chose one.",
    `exec ${shQuote(node)} --no-warnings ${shQuote(preload)} --claude ${shQuote(shimDir)} ${shQuote(JSON.stringify(route))} "$@"`,
    "",
  ].join("\n");
}

/** Write the `claude` shim into `dir` (created; write-protected for the
 *  agent, sdkRouteWriteProtect). */
export function writeClaudeShim(dir: string, node: string, preload: string, route: ClaudeShimRoute): void {
  mkdirSync(dir, { recursive: true });
  const p = join(dir, "claude");
  rmSync(p, { force: true });
  writeFileSync(p, claudeShimScript(node, preload, dir, route), { mode: 0o755 });
  chmodSync(p, 0o755);
}

/** Whether a Python command line turns off the import of `sitecustomize`
 *  (`-I`, `-E` and `-S`, alone or in a cluster such as `-IB`), read up to
 *  the script, `-c` or `-m`. Pure. */
export function pythonSkipsSiteHook(argv: readonly string[]): string | null {
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i] ?? "";
    if (a === "--" || a === "-" || !a.startsWith("-")) return null;
    if (a.startsWith("--")) {
      if (a === "--check-hash-based-pycs") i++;
      continue;
    }
    const cluster = a.slice(1);
    for (let j = 0; j < cluster.length; j++) {
      const c = cluster[j]!;
      if (c === "I" || c === "E" || c === "S") return `-${c}`;
      if (c === "c" || c === "m") return null;
      if (c === "W" || c === "X") { if (j === cluster.length - 1) i++; break; }
    }
  }
  return null;
}

/**
 * Why this launch must not start, or null: a host the route cannot reach
 * under `--target codex`, whose codex would run with no Mandu provider (a
 * Bun or Deno host loads neither hook; a Python started with -I, -E or -S
 * skips its hook). Under claude the environment still routes the SDK's
 * default start, so the note warns instead. Pure.
 */
export function sdkHostRefusal(plan: Pick<LaunchPlan, "target" | "argv">): string | null {
  if (plan.target !== "codex" || sdkRouteApplies(plan) !== "runtime") return null;
  const cmd = basename(plan.argv[0] ?? "");
  const kind = hostRuntimeOf(plan.argv[0]);
  const skip = kind === "python" && /^python/.test(cmd) ? pythonSkipsSiteHook(plan.argv) : null;
  if (kind !== "other" && skip === null) return null;
  const why = kind === "other"
    ? `'${cmd}' loads neither of Mandu's SDK hooks (Node's NODE_OPTIONS, Python's PYTHONPATH)`
    : `'${cmd} ${skip}' skips Python's sitecustomize, which carries Mandu's SDK route`;
  return (
    `mandu: refusing to launch: ${why}, so a codex the program starts would send its model traffic past Mandu's ` +
    "proxy, with tool results unmasked. Run the host under Node (or Python without that flag), or start the agent " +
    "as `mandu codex` (agent-sdks.md)."
  );
}

/**
 * The launch note (truth in labeling): what the route covers, and, with
 * `WARNING` for the compact display, what it does not. null when the launch
 * gets no route.
 */
export function sdkHostNote(plan: Pick<LaunchPlan, "target" | "argv">): string | null {
  const applies = sdkRouteApplies(plan);
  if (applies === null) return null;
  const cmd = basename(plan.argv[0] ?? "");
  const routes = plan.target === "codex" ? "codex" : plan.target === "claude" ? "claude" : "claude, by its environment";
  const kind = hostRuntimeOf(plan.argv[0]);
  const host = kind === "python" ? "Python" : "Node";
  const active =
    `mandu: SDK route ACTIVE — every agent CLI a ${host} program under '${cmd}' starts keeps Mandu's routing (${routes}), ` +
    "even when it is given its own environment or another name, and an agent CLI this launch does not route, or one " +
    "started through a container or a remote host, refuses to start. An agent CLI a shell command string names is " +
    "routed by the PATH shims, unless the string gives its full path (agent-sdks.md).";
  if (applies === "wrapper" || kind === "node" || kind === "python") return active;
  return (
    `mandu: '${cmd}' loads neither of Mandu's SDK hooks (only the Node and Python programs it starts do). ` +
    "WARNING: an agent CLI it starts by its full path (the SDKs' bundled CLI) keeps only its environment's routing: " +
    "a `claude` given its own `env` or settings, or any `codex`, is NOT routed through Mandu; one it starts by name " +
    "meets the PATH shims. Run the host under Node, or start the agent as `mandu <agent>` (agent-sdks.md)."
  );
}
