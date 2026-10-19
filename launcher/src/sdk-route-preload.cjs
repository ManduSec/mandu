/**
 * sdk-route-preload — keeps Mandu's routing on every agent CLI a Node host
 * program starts (docs/design/agents/agent-sdks.md).
 *
 * WHY. A product built on an agent SDK runs as `mandu --target claude|codex
 * -- node app.js`. The SDK starts the real CLI as a child: the Claude Agent
 * SDK its bundled `claude`, the TypeScript Codex SDK its bundled `codex exec
 * --experimental-json`. Two things break the routing a plain `mandu claude` /
 * `mandu codex` gets (both read from the SDK sources, 2026-10-05):
 *   - the SDKs' `env` option REPLACES the child's environment (both
 *     TypeScript SDKs), so ANTHROPIC_BASE_URL, the proxy and CA variables
 *     and MANDU_* are gone, and the CLI talks to the vendor directly;
 *   - Codex takes its model provider only from its command line (`-c`), and
 *     the SDK builds that command line itself; nothing Mandu puts on the
 *     host's own argv reaches it.
 * The launcher therefore loads this file into the host's Node
 * (NODE_OPTIONS=--require), and every child the host starts goes through
 * routeSpawn with the launch's route (JSON, launcher/src/sdk-route.ts).
 *
 * WHERE THE ROUTE COMES FROM (2026-10-18, agent-sdks.md §3.6). The launch
 * copies this file, its permission-mode rule and the Python hook into its
 * own `<scope run dir>/sdk-route/`, beside the route it writes there
 * (`route.json`), and loads THAT copy. The route is read from the file beside
 * this one (`__dirname`), which the agent cannot redirect, and the folder is
 * on the whole-agent guard's (and the macOS profile's) write-protect list,
 * so the agent cannot rewrite it. Never from the environment: a route there
 * (the old MANDU_SDK_ROUTE) is ignored and removed from every child, since
 * a host the model steers could set it in a shell string (`MANDU_SDK_ROUTE=
 * '{…}' claude …`) and hand the shims and the hooks a model base URL or a
 * proxy of its choosing. The copy in the bundle has no route beside it and
 * routes nothing as a preload; a copy in a `sdk-route/` folder whose route is
 * missing or unreadable refuses every agent child (fail-closed).
 *   - the routing variables are put back, with the launch's values, in every
 *     child's environment (a host value for one of them is overridden; the
 *     shim directories are put back at the head of PATH);
 *   - a `codex` child gets the launch's provider splice, and Codex's own
 *     uploads off (codex-argv.ts CODEX_UPLOADS_OFF), at every command level
 *     (the same placement as codex-argv.ts codexSpliceOverrides), and a
 *     Codex command line Mandu refuses as a launch (a re-pointed provider, a
 *     server subcommand, `--remote`, `cloud`, an upload turned back on)
 *     throws instead of starting;
 *   - a `claude` child gets the routing in its last `--settings` too (merged
 *     into the SDK's inline one; claude-route.ts, the copy below held equal
 *     by the parity test), since Claude Code applies every settings
 *     source's `env` over its environment; a `--settings` file, a cloud
 *     provider switch or ANTHROPIC_UNIX_SOCKET throws instead of starting;
 *   - an agent child's routing is the LAUNCH's (the route's launchRouting,
 *     every routing variable with the launch's value or ""), never its own
 *     environment's: a `claude` child's overlay is built from those values
 *     alone and its routing variables are put back to them, a `codex`
 *     child's proxy variables too, so a proxy, base URL or NO_PROXY the
 *     host adds or changes for the child is overwritten, as the `claude`
 *     shim does (routedClaudeArgs, agent-sdks.md §3, §4);
 *   - a `claude` child that runs a session gets `--permission-mode default`
 *     unless its command line or a settings scope it reads chose a mode
 *     (claude-permission-rule.cjs, the one copy of the rule, which the
 *     launch applies too: without feature flags it would start in `auto`);
 *   - an agent CLI the launch does not route (a `codex` under a claude or
 *     shell launch, a `claude` under a codex launch) throws instead of
 *     starting: it would talk to its vendor with nothing masked.
 * A throw from spawn is the fail-closed answer: the SDK reports the error
 * and nothing reaches a model.
 *
 * Which children are agents (agentOf, agent-sdks.md §3.1): by the
 * executable's name, by the script a JS runtime runs (`node cli.js`), or by
 * the SDKs' own command line (a renamed CLI); one started through another
 * program (`docker exec … claude …`) throws.
 *
 * Scope: Node hosts (NODE_OPTIONS). The same file serves three more
 * deliveries as a program (cliMode): `--exec`, the PATH shims a shell
 * command string's `codex` meets (sdk-route.ts writeSdkShims);
 * `--claude`, the `claude` PATH shim of a claude or shell launch the route
 * does not serve, which routes a `claude` the session starts by name as
 * `mandu claude` is routed (the launch's routing variables, baked into the
 * shim, put back in its environment and imposed in its last `--settings`;
 * the same refusals; the permission-mode rule: claudeShimSpawn; sdk-route.ts
 * writeClaudeShim; agent-sdks.md §3.5, supported-agents.md §2.5); and
 * `--decide`, the decision the Python hook (sdk-route-python/
 * sitecustomize.py) asks for each agent child of a Python host
 * (agent-sdks.md §3.2, §3.3).
 *
 * Plain CommonJS with no dependency but its sibling claude-permission-
 * rule.cjs: it runs inside the user's program, from the source tree and
 * from the installed bundle alike (a launch copies both into its
 * `sdk-route/`) (bundle-manifest.json `assets`, both
 * files). The Codex argv logic mirrors codex-argv.ts; the parity unit test
 * (launcher/test/unit/sdk-route.test.ts) holds the two equal.
 *
 * Mandu-new (no reference origin).
 */
"use strict";

const path = require("node:path");
// The permission-mode rule, the one copy (the launch imports it too).
const permissionRule = require("./claude-permission-rule.cjs");

/** The variable that carried the route before 2026-10-18: ignored, and
 *  removed from every child (WHERE THE ROUTE COMES FROM, above). */
const ROUTE_ENV = "MANDU_SDK_ROUTE";
/** The launch's folder of route copies (sdk-route.ts SDK_ROUTE_DIR) and the
 *  route in it (SDK_ROUTE_FILE). */
const ROUTE_DIR = "sdk-route";
const ROUTE_FILE = "route.json";

// ── Codex argv (mirrors codex-argv.ts; held equal by the parity test) ──────

const ROOT_SUBCOMMANDS = new Set([
  "agents", "exec", "e", "review", "login", "logout", "mcp", "plugin", "app-server", "remote-control",
  "completion", "update", "doctor", "sandbox", "debug", "apply", "a", "resume", "queue", "archive",
  "delete", "migrate-rollouts", "unarchive", "fork", "cloud", "cloud-tasks", "exec-server", "features", "help",
]);
const CHILD_SUBCOMMANDS = {
  exec: new Set(["resume", "fork", "review", "help"]),
  e: new Set(["resume", "fork", "review", "help"]),
};
const VALUE_FLAGS = new Set([
  "-c", "--config", "--enable", "--disable", "--remote", "--remote-auth-token-env", "-i", "--image",
  "-m", "--model", "--local-provider", "-p", "--profile", "-s", "--sandbox", "-C", "--cd", "--add-dir",
  "-a", "--ask-for-approval", "--thread-source", "--output-schema", "--color", "-o", "--output-last-message",
]);
const SERVER_SUBCOMMANDS = new Set(["agents", "remote-control", "app-server", "exec-server"]);
const CLOUD_SUBCOMMANDS = new Set(["cloud", "cloud-tasks"]);

/** Codex's own uploads, forced off at every level (codex-argv.ts
 *  CODEX_UPLOADS_OFF; `[key, TOML value]`). */
const UPLOADS_OFF = [
  ["analytics.enabled", "false"],
  ["feedback.enabled", "false"],
  ["otel.exporter", '"none"'],
  ["otel.trace_exporter", '"none"'],
  ["otel.metrics_exporter", '"none"'],
  ["features.apps", "false"],
  ["features.connectors", "false"],
  ["check_for_update_on_startup", "false"],
];
/** Every launch's switches: UPLOADS_OFF but the legacy `connectors` key,
 *  which goes only where the route says the user's config names it
 *  (codex-argv.ts CODEX_UPLOADS_OFF_OVERRIDES, CODEX_CONNECTORS_OFF). */
const UPLOADS_OFF_OVERRIDES = UPLOADS_OFF.filter(([k]) => k !== "features.connectors").flatMap(([k, v]) => ["-c", `${k}=${v}`]);
const CONNECTORS_OFF = ["-c", "features.connectors=false"];
const UPLOAD_FEATURES = new Set(["apps", "connectors"]);

function overrideValue(v) {
  return String(v).trim().replace(/^["']|["']$/g, "").trim().toLowerCase();
}

/** codex-argv.ts codexUploadConflict: a `-c` that undoes one of UPLOADS_OFF. */
function uploadConflict(kv) {
  const s = String(kv);
  const eq = s.indexOf("=");
  const key = (eq < 0 ? s : s.slice(0, eq)).trim().replace(/["'\s]/g, "");
  const value = eq < 0 ? "" : s.slice(eq + 1);
  if (key === "") return false;
  for (const [k, v] of UPLOADS_OFF) {
    if (key === k) { if (overrideValue(value) !== overrideValue(v)) return true; continue; }
    if (key.startsWith(`${k}.`) || k.startsWith(`${key}.`)) return true;
  }
  return false;
}

/** basename without a Windows `.exe`. */
function exeName(file) {
  return path.basename(String(file)).replace(/\.exe$/i, "");
}

/** The splice: `overrides` after argv[0] and after every subcommand of the
 *  chain; flag values skipped; nothing after the first plain positional or
 *  `--` touched. `argv` includes argv[0]. */
function spliceCodex(argv, overrides) {
  const [head, ...rest] = argv;
  if (head === undefined) return [];
  const levels = [{ sub: null, tokens: [] }];
  let children = ROOT_SUBCOMMANDS;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    const level = levels[levels.length - 1];
    if (a === "--") { level.tokens.push(...rest.slice(i)); break; }
    if (a.startsWith("-")) {
      level.tokens.push(a);
      if (VALUE_FLAGS.has(a) && i + 1 < rest.length) level.tokens.push(rest[++i]);
      continue;
    }
    if (children.has(a)) {
      levels.push({ sub: a, tokens: [] });
      children = CHILD_SUBCOMMANDS[a] || new Set();
    } else {
      level.tokens.push(...rest.slice(i));
      break;
    }
  }
  const out = [head];
  for (const level of levels) {
    if (level.sub !== null) out.push(level.sub);
    out.push(...overrides, ...level.tokens);
  }
  return out;
}

function subcommandPath(argv) {
  let sub = null;
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") break;
    if (a.startsWith("-")) { if (VALUE_FLAGS.has(a)) i++; continue; }
    if (sub !== null) return { sub, next: a };
    if (!ROOT_SUBCOMMANDS.has(a)) return null;
    sub = a;
  }
  return sub === null ? null : { sub, next: null };
}

function reroutesProvider(kv) {
  const key = String(kv).split("=", 1)[0].trim().replace(/^["']|["']$/g, "");
  return key === "model_provider" || key === "model_providers" || key.startsWith("model_providers.");
}

/** Why Mandu refuses this Codex command line, or null (codex-argv.ts
 *  codexLaunchRefusal: a server, `--remote`, a re-pointed provider). */
function codexRefusal(argv) {
  const end = argv.includes("--") ? argv.indexOf("--") : argv.length;
  const flags = argv.slice(1, end);
  if (flags.some((a) => a === "--remote" || a.startsWith("--remote="))) return "--remote attaches to a Codex server Mandu did not start";
  const p = subcommandPath(argv);
  if (p !== null && SERVER_SUBCOMMANDS.has(p.sub)) return `\`codex ${p.sub}\` runs or attaches to a Codex server that serves clients outside the launch`;
  if (p !== null && CLOUD_SUBCOMMANDS.has(p.sub)) return `\`codex ${p.sub}\` runs the agent in Codex Cloud, on OpenAI's machines, past Mandu's model proxy`;
  if (p !== null && p.sub === "debug" && p.next === "app-server") return "`codex debug app-server` runs its turn in a child server that drops Mandu's routing";
  const hits = [];
  const uploads = [];
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") break;
    let kv;
    if (a === "-c" || a === "--config") kv = argv[++i];
    else if (a.startsWith("--config=")) kv = a.slice("--config=".length);
    else if (a.startsWith("-c") && !a.startsWith("--") && a.length > 2) kv = a.slice(2).replace(/^=/, "");
    if (kv !== undefined && reroutesProvider(kv)) hits.push(`-c ${String(kv).split("=", 1)[0].trim()}`);
    else if (kv !== undefined && uploadConflict(kv)) uploads.push(`-c ${String(kv).split("=", 1)[0].trim()}`);
    if (a === "--oss" || a === "--local-provider" || a.startsWith("--local-provider=")) hits.push(a.split("=", 1)[0]);
    let feature;
    if (a === "--enable") feature = argv[++i];
    else if (a.startsWith("--enable=")) feature = a.slice("--enable=".length);
    if (feature !== undefined && UPLOAD_FEATURES.has(String(feature).trim())) uploads.push(`--enable ${String(feature).trim()}`);
  }
  if (hits.length === 0 && uploads.length > 0) {
    return `${[...new Set(uploads)].join(", ")} turns one of Codex's own uploads back on (analytics, feedback, OpenTelemetry export, ChatGPT apps), which Mandu keeps off`;
  }
  if (hits.length === 0) return null;
  return `${[...new Set(hits)].join(", ")} chooses where Codex sends its model traffic, and another provider would receive tool results unmasked`;
}

// ── Claude Code settings (mirrors claude-route.ts; held equal by the parity test)

const CLAUDE_ROUTE_ENV_KEYS = [
  "ANTHROPIC_BASE_URL", "ANTHROPIC_CUSTOM_HEADERS", "CLAUDE_CODE_API_BASE_URL",
  "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy",
];
const CLAUDE_CLOUD_SWITCHES = [
  "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY",
  "CLAUDE_CODE_USE_ANTHROPIC_AWS", "CLAUDE_CODE_USE_ANTHROPIC_GOOGLE_CLOUD", "CLAUDE_CODE_USE_MANTLE",
];

function claudeSwitchOn(v) {
  return typeof v === "string" && ["1", "true", "yes", "on"].includes(v.trim().toLowerCase());
}

/** The `env` the last `--settings` re-imposes (claude-route.ts claudeRouteEnv). */
function claudeRouteEnv(env) {
  const out = {};
  for (const k of CLAUDE_ROUTE_ENV_KEYS) out[k] = typeof env[k] === "string" ? env[k] : "";
  for (const k of CLAUDE_CLOUD_SWITCHES) out[k] = "0";
  out.CLAUDE_CODE_USE_GATEWAY = claudeSwitchOn(env.CLAUDE_CODE_USE_GATEWAY) ? env.CLAUDE_CODE_USE_GATEWAY : "0";
  return out;
}

/** Why a Claude child's environment cannot be routed, or null. */
function claudeEnvRefusal(env) {
  const on = CLAUDE_CLOUD_SWITCHES.filter((k) => claudeSwitchOn(env[k]));
  if (on.length > 0) return `${on.join(", ")} sends Claude Code's model traffic to that cloud provider directly, around Mandu's model proxy`;
  if (typeof env.ANTHROPIC_UNIX_SOCKET === "string" && env.ANTHROPIC_UNIX_SOCKET.trim() !== "") {
    return "ANTHROPIC_UNIX_SOCKET sends Claude Code's model traffic to that socket, around Mandu's model proxy";
  }
  return null;
}

function isPlainObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** claude-sandbox.ts mergeSettings: objects merge, lists union, the rest from the overlay. */
function mergeSettings(base, overlay) {
  if (Array.isArray(base) && Array.isArray(overlay)) return [...new Set([...base, ...overlay])];
  if (isPlainObject(base) && isPlainObject(overlay)) {
    const out = { ...base };
    for (const [k, v] of Object.entries(overlay)) out[k] = k in out ? mergeSettings(out[k], v) : v;
    return out;
  }
  return overlay;
}

function inlineSettings(value) {
  const t = String(value).trim();
  if (!(t.startsWith("{") && t.endsWith("}"))) return null;
  try {
    const doc = JSON.parse(t);
    return isPlainObject(doc) ? doc : null;
  } catch {
    return null;
  }
}

/** A Claude child's arguments (WITHOUT argv[0]) with the overlay in the
 *  last `--settings` (claude-route.ts claudeRouteArgs with no prefix): merged
 *  into the last inline one, else a new one first. Returns the arguments, or
 *  `{ refusal }` for a `--settings` file. */
function claudeRouteArgs(args, overlay) {
  const out = [...args];
  let found = null;
  for (let i = 0; i < out.length; i++) {
    const a = out[i];
    if (a === "--") break;
    if (a === "--settings" && i + 1 < out.length) { found = { index: i, form: "split", value: out[i + 1] }; i++; continue; }
    if (typeof a === "string" && a.startsWith("--settings=")) found = { index: i, form: "eq", value: a.slice("--settings=".length) };
  }
  if (found === null) return { args: ["--settings", JSON.stringify(overlay), ...out] };
  const doc = inlineSettings(found.value);
  if (doc === null) return { refusal: `its --settings ${found.value} is not inline JSON, and Claude Code would read it instead of Mandu's routing` };
  const merged = JSON.stringify(mergeSettings(doc, overlay));
  if (found.form === "split") out[found.index + 1] = merged;
  else out[found.index] = `--settings=${merged}`;
  return { args: out };
}

// ── Claude Code's permission mode (the rule: claude-permission-rule.cjs,
//    the one copy the launch applies too) ────────────────────────────────────

/** A `--settings` / `--managed-settings` value as Claude Code reads it
 *  (claude-sandbox.ts parseClaudeSettingsValue): inline JSON, else a file
 *  of at most 2 MiB. Null when unreadable or not an object. */
function settingsValue(value) {
  const inline = inlineSettings(value);
  if (inline !== null) return inline;
  try {
    const fs = require("node:fs");
    const st = fs.statSync(String(value));
    if (!st.isFile() || st.size > 2 * 1024 * 1024) return null;
    const doc = JSON.parse(fs.readFileSync(String(value), "utf8"));
    return isPlainObject(doc) ? doc : null;
  } catch {
    return null;
  }
}

/** Claude Code's user config dir for a child environment (claude-sandbox.ts claudeConfigDir). */
function claudeConfigDir(env) {
  const d = typeof env.CLAUDE_CONFIG_DIR === "string" ? env.CLAUDE_CONFIG_DIR.trim() : "";
  if (d) return path.normalize(d);
  const home = typeof env.HOME === "string" && env.HOME !== "" ? env.HOME : require("node:os").homedir();
  return path.join(home, ".claude");
}

/**
 * A Claude child's arguments (WITHOUT argv[0]) with `--permission-mode
 * default` first, unless it chose a mode (claude-permission-rule.cjs): on
 * its command line, or in a settings scope it reads (`mode.scopes`,
 * computed by the launch for `mode.cwd` / `mode.configDir`). A child whose
 * project or local files (another `cwd`) or user files (another config dir)
 * the launch did not read is left alone, as is one running no session, and
 * every child when `mode` is absent. Pure but for reading a settings file
 * its command line names.
 */
function claudeModeArgs(args, mode, cwd, env) {
  if (!isPlainObject(mode) || !Array.isArray(mode.scopes)) return args;
  const decision = permissionRule.permissionModeDecision(args, settingsValue, (files) => {
    const set = ["managed", ...files].find((s) => mode.scopes.includes(s));
    if (set !== undefined) return `${set} settings (permissions.defaultMode)`;
    if ((files.includes("project") || files.includes("local")) && canonicalDir(cwd) !== canonicalDir(String(mode.cwd))) {
      return "another folder's project settings, which the launch did not read";
    }
    if (files.includes("user") && canonicalDir(claudeConfigDir(env)) !== canonicalDir(String(mode.configDir))) {
      return "another user config dir, which the launch did not read";
    }
    return null;
  });
  return permissionRule.withPermissionMode(args, decision);
}

/** A folder by its real path when it has one (the launch folder is). */
function canonicalDir(p) {
  const abs = path.resolve(p);
  try { return require("node:fs").realpathSync(abs); } catch { return abs; }
}

// ── the route ───────────────────────────────────────────────────────────────

/** The route the launcher composed, or null when absent or unreadable. */
function parseRoute(raw) {
  if (typeof raw !== "string" || raw === "") return null;
  try {
    const r = JSON.parse(raw);
    if (r === null || typeof r !== "object" || r.v !== 1 || typeof r.env !== "object" || r.env === null) return null;
    return r;
  } catch {
    return null;
  }
}

/** The route file beside this copy of the preload (WHERE THE ROUTE COMES
 *  FROM, in the header): `__dirname`, never a path the environment names. */
function ownRouteFile() {
  return path.join(__dirname, ROUTE_FILE);
}

/** Whether this copy is a launch's (it lives in a `sdk-route/` folder), so
 *  a route must be beside it. */
function ownRouteExpected() {
  return path.basename(__dirname) === ROUTE_DIR;
}

/** The route in `file`, or null when absent or unreadable. */
function readRouteFile(file) {
  let raw;
  try { raw = require("node:fs").readFileSync(file, "utf8"); } catch { return null; }
  return parseRoute(raw);
}

class RouteRefusal extends Error {
  constructor(message) {
    super(message);
    this.name = "ManduRouteRefusal";
    this.code = "MANDU_ROUTE_REFUSED";
  }
}

/** The child's environment with the launch's routing put back. Pure. */
function routeEnv(route, env) {
  const out = { ...env };
  for (const [k, v] of Object.entries(route.env)) out[k] = v;
  // The route rides the launch's file, never the environment: a value
  // there is a stale or forged one, and goes no further.
  delete out[ROUTE_ENV];
  const dirs = Array.isArray(route.pathPrefix) ? route.pathPrefix : [];
  const have = typeof out.PATH === "string" && out.PATH !== "" ? out.PATH.split(path.delimiter) : (route.path || "").split(path.delimiter);
  const rest = have.filter((d) => d !== "" && !dirs.includes(d));
  out.PATH = [...dirs, ...rest].join(path.delimiter);
  if (typeof route.pythonPath === "string" && route.pythonPath !== "") {
    // The Python hook (sdk-route-python/sitecustomize.py) rides into Python
    // children the same way, first on their PYTHONPATH.
    const cur = typeof out.PYTHONPATH === "string" && out.PYTHONPATH !== "" ? out.PYTHONPATH.split(path.delimiter) : [];
    out.PYTHONPATH = [route.pythonPath, ...cur.filter((d) => d !== "" && d !== route.pythonPath)].join(path.delimiter);
  }
  if (typeof route.require === "string" && route.require !== "") {
    // sdk-route.ts requireOption: quoted when the path has whitespace.
    const opt = /\s/.test(route.require) ? `--require="${route.require}"` : `--require=${route.require}`;
    const cur = typeof out.NODE_OPTIONS === "string" ? out.NODE_OPTIONS : "";
    if (!cur.split(/\s+/).includes(opt)) out.NODE_OPTIONS = cur.trim() === "" ? opt : `${cur.trim()} ${opt}`;
  }
  return out;
}

/** The Codex overrides for a child with this environment: the provider
 *  (routing first), then Codex's own uploads off (UPLOADS_OFF). The key
 *  variable the child carries decides `env_key` (OPENAI_API_KEY first, as
 *  Codex's own login does), a child with neither signs in (env-compose.ts
 *  codexProviderToml, computed by the launcher for each case). */
function codexOverrides(codex, env) {
  const has = (k) => typeof env[k] === "string" && env[k].trim() !== "";
  const toml = has("OPENAI_API_KEY") ? codex.toml.OPENAI_API_KEY : has("CODEX_API_KEY") ? codex.toml.CODEX_API_KEY : codex.toml["sign-in"];
  return [
    "-c", `model_provider=${codex.provider}`, "-c", `model_providers.${codex.provider}=${toml}`, ...UPLOADS_OFF_OVERRIDES,
    ...(codex.connectorsOff === true ? CONNECTORS_OFF : []),
  ];
}

/** Codex already carries the launch's routing (the npm `codex` launcher
 *  passes its argv on to the native binary, the host spliced it once). */
function codexRouted(codex, args) {
  return args.some((a, i) => (args[i - 1] === "-c" || args[i - 1] === "--config") && a === `model_provider=${codex.provider}`);
}

// ── which children are agent CLIs (agent-sdks.md §3, "Which children") ─────

/** Runtimes that run a script: a script that is an agent CLI is that agent.
 *  Node and Python children load this route themselves (NODE_OPTIONS,
 *  PYTHONPATH); Bun and Deno do not. */
const NODE_RUNTIMES = new Set(["node", "nodejs"]);
const OTHER_JS_RUNTIMES = new Set(["bun", "deno"]);
/** Options of each runtime that take the NEXT argument as their value (the
 *  `--opt=value` spelling needs no entry). A missing entry makes the value
 *  look like the script: that script is then no agent, so the child is
 *  judged by its arguments (the SDKs' command lines below), never let
 *  through as a routed agent it is not. */
const RUNTIME_VALUE_FLAGS = {
  node: new Set([
    "-r", "--require", "--import", "--loader", "--experimental-loader", "-C", "--conditions", "--input-type",
    "--title", "--env-file", "--env-file-if-exists", "--inspect-port", "--debug-port", "--watch-path", "--redirect-warnings",
    "--disable-warning", "--report-dir", "--report-directory", "--report-filename", "--diagnostic-dir", "--icu-data-dir",
    "--openssl-config", "--dns-result-order", "--unhandled-rejections", "--stack-trace-limit", "--max-http-header-size",
    "--experimental-config-file", "--localstorage-file", "--snapshot-blob", "--cpu-prof-dir", "--cpu-prof-name",
    "--heap-prof-dir", "--heap-prof-name", "--secure-heap", "--secure-heap-min", "--tls-keylog", "--tls-cipher-list",
    "--trace-event-categories", "--trace-event-file-pattern", "--heapsnapshot-signal", "--disable-proto", "--use-largepages",
  ]),
  bun: new Set([
    "-r", "--preload", "-c", "--config", "--cwd", "--env-file", "--tsconfig-override", "-d", "--define", "-l", "--loader",
    "--main-fields", "--port", "--conditions", "--install", "--extension-order", "--jsx-factory", "--jsx-fragment",
    "--jsx-import-source", "--jsx-runtime",
  ]),
  deno: new Set([
    "-c", "--config", "--import-map", "--lock", "--cert", "--location", "--seed", "--ext", "--env-file", "--inspect-wait",
  ]),
};
/** Runtime options that run code from the command line or stdin: no script. */
const RUNTIME_EVAL_FLAGS = new Set(["-e", "--eval", "-p", "--print"]);

/** The JS runtime a child is, or null. */
function jsRuntimeOf(file) {
  const n = exeName(file);
  if (NODE_RUNTIMES.has(n)) return "node";
  return OTHER_JS_RUNTIMES.has(n) ? n : null;
}

/** A Python runtime or runner: it loads the route's Python hook itself
 *  (PYTHONPATH, sdk-route-python/sitecustomize.py). */
function pythonRuntime(file) {
  const n = exeName(file);
  return n === "python" || n === "uv" || n === "uvx" || n === "pipx" || /^python\d(?:\.\d+)?$/.test(n);
}

/** The index in `args` (WITHOUT argv[0]) of the script a JS runtime runs, or
 *  -1 (inline code, stdin, a subcommand that runs none). */
function scriptIndex(runtime, args) {
  const values = RUNTIME_VALUE_FLAGS[runtime] || new Set();
  let i = 0;
  if (runtime !== "node" && args[0] === "run") i = 1;
  for (; i < args.length; i++) {
    const a = String(args[i]);
    if (a === "--") return i + 1 < args.length ? i + 1 : -1;
    if (a === "-") return -1;
    if (RUNTIME_EVAL_FLAGS.has(a) || a.startsWith("--eval=") || a.startsWith("--print=")) return -1;
    if (a.startsWith("-")) { if (values.has(a)) i++; continue; }
    return i;
  }
  return -1;
}

/** npm packages whose `cli.js` IS Claude Code (the Agent SDK before its
 *  native binaries bundled one). */
const CLAUDE_JS_PACKAGES = new Set(["@anthropic-ai/claude-code", "@anthropic-ai/claude-agent-sdk"]);

/** Which agent a script a JS runtime runs is, or null: by its name without
 *  the extension (the npm `.bin/claude` and `bin/codex.js`), or a `cli.js`
 *  of a Claude Code package. Reads at most that package's package.json. */
function jsAgentOf(script, cwd) {
  const s = String(script);
  const bare = path.basename(s).replace(/\.(?:[cm]?js|[cm]?ts|[jt]sx)$/i, "");
  if (bare === "claude" || bare === "codex") return bare;
  if (bare !== "cli") return null;
  const dir = path.dirname(path.resolve(cwd, s));
  try {
    const pkg = JSON.parse(require("node:fs").readFileSync(path.join(dir, "package.json"), "utf8"));
    if (pkg && CLAUDE_JS_PACKAGES.has(pkg.name)) return "claude";
  } catch { /* not a package root */ }
  return /[\\/]@anthropic-ai[\\/]claude-(?:code|agent-sdk)$/.test(dir) ? "claude" : null;
}

/** The value an option has before `--` (`--opt v` or `--opt=v`), or null. */
function optionValue(args, name) {
  for (let i = 0; i < args.length; i++) {
    const a = String(args[i]);
    if (a === "--") break;
    if (a === name) return i + 1 < args.length ? String(args[i + 1]) : null;
    if (a.startsWith(`${name}=`)) return a.slice(name.length + 1);
  }
  return null;
}

/** The Claude Agent SDKs' command line (TypeScript and Python): Claude Code's
 *  stream-json protocol both ways. Nothing else speaks it. */
function claudeSdkShape(args) {
  return optionValue(args, "--output-format") === "stream-json" && optionValue(args, "--input-format") === "stream-json";
}

/** The Codex SDKs' command line: `exec --experimental-json` (TypeScript) or
 *  `app-server` (Python), after any `-c` overrides. */
function codexSdkShape(args) {
  const p = subcommandPath(["codex", ...args]);
  if (p === null) return false;
  return ((p.sub === "exec" || p.sub === "e") && args.includes("--experimental-json")) || p.sub === "app-server";
}

/** An agent CLI started THROUGH another program (the Claude Agent SDK's
 *  `spawnClaudeCodeProcess` running `docker exec … claude …`, `ssh host
 *  codex exec …`, `env claude …`): a token naming the agent, followed by its
 *  SDK command line. Returns the agent, or null. */
function wrappedAgentOf(args) {
  for (let i = 0; i < args.length; i++) {
    const bare = path.basename(String(args[i])).replace(/\.(?:[cm]?js)$/i, "");
    if (bare !== "claude" && bare !== "codex") continue;
    const after = args.slice(i + 1);
    if (bare === "claude" ? claudeSdkShape(after) : codexSdkShape(after)) return bare;
  }
  return null;
}

/**
 * What a child is: `{ kind: "claude" | "codex", prefix, args }` for an agent
 * CLI (`prefix` the runtime's own arguments up to the script, `args` the
 * CLI's), `{ kind: "wrapped", agent }` for one started through another
 * program, or null. An agent is known by its executable's name (`claude`,
 * `codex`, wherever it lives), by the script a JS runtime runs (`node
 * cli.js`), or by the SDKs' own command line (a renamed binary, the SDK's
 * `pathToClaudeCodeExecutable` / `codexPathOverride` under another name).
 * A Node or Python child that runs no agent script is left to the route it
 * loads itself.
 */
function agentOf(file, args, cwd) {
  if (pythonRuntime(file)) return null;
  const runtime = jsRuntimeOf(file);
  let prefix = [];
  let rest = args;
  if (runtime !== null) {
    const i = scriptIndex(runtime, args);
    if (i < 0) return null;
    prefix = args.slice(0, i + 1);
    rest = args.slice(i + 1);
    const kind = jsAgentOf(args[i], cwd);
    if (kind !== null) return { kind, prefix, args: rest };
  } else {
    const n = exeName(file);
    if (n === "claude" || n === "codex") return { kind: n, prefix, args: rest };
  }
  if (runtime !== "node") {
    const wrapped = wrappedAgentOf(rest);
    if (wrapped !== null) return { kind: "wrapped", agent: wrapped };
  }
  if (claudeSdkShape(rest)) return { kind: "claude", prefix, args: rest };
  if (codexSdkShape(rest)) return { kind: "codex", prefix, args: rest };
  return null;
}

/** `codex app-server` serving its parent over stdio (the Python Codex SDK). */
function stdioAppServer(argv) {
  const p = subcommandPath(argv);
  if (p === null || p.sub !== "app-server") return false;
  const listen = optionValue(argv.slice(1), "--listen");
  return listen === null || listen === "stdio://";
}

function refuseUnrouted(file, agent, route) {
  const label = agent === "codex" ? "Codex" : "Claude Code";
  throw new RouteRefusal(
    `mandu: refusing to start ${file}: this launch does not route ${label} (target ${route.target}), so it would ` +
    `send tool results to its model unmasked. Run the program as \`mandu --target ${agent} -- …\`.`,
  );
}

/** A Codex child with the launch's routing (`{ args, env }`), or a throw:
 *  the provider splice (its base URL is the launch's, computed by the
 *  launcher), and the proxy variables Codex reads from its environment put
 *  back with the launch's values (one the launch does not set removed), so
 *  a host cannot add a proxy in front of the model proxy. */
function routeCodex(route, file, args, routedEnv) {
  if (!route.codex) refuseUnrouted(file, "codex", route);
  const outEnv = withLaunchValues(routedEnv, routeLaunchValues(route, file), PROXY_ROUTE_ENV_KEYS);
  return { args: codexArgs(route, file, args, outEnv), env: outEnv };
}

function codexArgs(route, file, args, outEnv) {
  if (codexRouted(route.codex, args)) return args;
  const why = codexRefusal(["codex", ...args]);
  if (why !== null && stdioAppServer(["codex", ...args])) {
    throw new RouteRefusal(
      `mandu: refusing to start ${file}: \`codex app-server\` (the Python Codex SDK) takes its threads' provider and ` +
      "config over its protocol, which Mandu does not read, so its model traffic cannot be held to Mandu's proxy " +
      "(agent-sdks.md §5). Use the TypeScript Codex SDK under Node, or `mandu codex`.",
    );
  }
  if (why !== null) throw new RouteRefusal(`mandu: refusing to start ${file}: ${why}.`);
  return spliceCodex(["codex", ...args], codexOverrides(route.codex, outEnv)).slice(1);
}

/** The keys of the launch's routing values (sdk-route.ts SdkRoute.launchRouting,
 *  ClaudeShimRoute.env): claude-route.ts claudeRouteEnv's, the routing
 *  variables and the provider switches. */
const CLAUDE_SHIM_KEYS = [...CLAUDE_ROUTE_ENV_KEYS, ...CLAUDE_CLOUD_SWITCHES, "CLAUDE_CODE_USE_GATEWAY"];
/** The routing variables a Codex child reads from its environment: the
 *  proxy ones (its provider, with its base URL, is the -c splice). */
const PROXY_ROUTE_ENV_KEYS = CLAUDE_ROUTE_ENV_KEYS.filter((k) => /_proxy$/i.test(k));

/** The launch's routing values as a route or a shim carries them, or null
 *  when they are not that: every key of CLAUDE_SHIM_KEYS a string. */
function launchRoutingOf(v) {
  if (!isPlainObject(v)) return null;
  const out = {};
  for (const k of CLAUDE_SHIM_KEYS) {
    if (typeof v[k] !== "string") return null;
    out[k] = v[k];
  }
  return out;
}

/** `env` with each of `keys` put back with the launch's value (`launch`),
 *  removed where the launch has none (""). A copy. */
function withLaunchValues(env, launch, keys) {
  const out = { ...env };
  for (const k of keys) {
    if (launch[k] === "") delete out[k];
    else out[k] = launch[k];
  }
  return out;
}

/**
 * A Claude Code child routed by the LAUNCH's values (`launch`: every
 * routing variable, "" where the launch sets none, the provider switches;
 * sdk-route.ts SdkRoute.launchRouting, ClaudeShimRoute.env), or a throw: the
 * one copy the SDK route (routeClaude) and the `claude` shim
 * (claudeShimSpawn) both apply. `args` are its arguments WITHOUT argv[0],
 * `env` the environment its caller hands it, which may add or re-point a
 * routing variable (`ANTHROPIC_BASE_URL=… claude`, an SDK `env` with its
 * own HTTPS_PROXY, an emptied NO_PROXY): each one is put back with the
 * launch's value (removed where the launch has none), and the overlay in
 * its last --settings is built from `launch` alone, never from `env`, so
 * no settings file it reads, nor one the agent writes mid-session, nor the
 * caller's environment re-points its model traffic (claude-route.ts). A
 * cloud provider switch or ANTHROPIC_UNIX_SOCKET in its environment and a
 * --settings FILE (Claude Code would read it instead of the overlay) throw;
 * `wayOut` ends the second refusal. Then Claude Code's default permission
 * mode unless the child chose one (claude-permission-rule.cjs), decided on
 * its own arguments. Returns `{ args, env }`. Pure but for reading a
 * settings file its command line names.
 */
function routedClaudeArgs(file, args, env, launch, claudeMode, cwd, wayOut) {
  const outEnv = withLaunchValues(env, launch, CLAUDE_ROUTE_ENV_KEYS);
  const why = claudeEnvRefusal(outEnv);
  if (why !== null) throw new RouteRefusal(`mandu: refusing to start ${file}: ${why}.`);
  const r = claudeRouteArgs(args, { env: launch });
  if (r.refusal !== undefined) throw new RouteRefusal(`mandu: refusing to start ${file}: ${r.refusal}. ${wayOut}`);
  const inject = claudeModeArgs(args, claudeMode, cwd, outEnv) !== args;
  return { args: inject ? ["--permission-mode", "default", ...r.args] : r.args, env: outEnv };
}

/** The route's launch values, or a throw (a route without them, which only
 *  a hand-built or version-skewed one is, cannot route an agent). */
function routeLaunchValues(route, file) {
  const launch = launchRoutingOf(route.launchRouting);
  if (launch === null) {
    throw new RouteRefusal(`mandu: refusing to start ${file}: Mandu's route carries no launch routing values, so its routing would come from the environment its caller chose.`);
  }
  return launch;
}

/** A Claude Code child with the launch's routing (`{ args, env }`), or a throw. */
function routeClaude(route, file, args, outEnv, cwd) {
  if (!route.anthropic) refuseUnrouted(file, "claude", route);
  return routedClaudeArgs(file, args, outEnv, routeLaunchValues(route, file), route.claudeMode, cwd,
    "Pass the SDK's `settings` as an object, not a file path.");
}

/** The `claude` shim's route as baked into the shim (sdk-route.ts
 *  ClaudeShimRoute), or null when it is not one: every key of the overlay a
 *  string, and a base URL. */
function parseClaudeShimRoute(raw) {
  let r;
  try { r = JSON.parse(String(raw)); } catch { return null; }
  if (!isPlainObject(r)) return null;
  const env = launchRoutingOf(r.env);
  if (env === null || env.ANTHROPIC_BASE_URL.trim() === "") return null;
  return { env, claudeMode: r.claudeMode };
}

/**
 * A `claude` the session starts by name, routed as `mandu claude` is (the
 * `claude` shim; claude-route.ts), by the launch's values baked into the
 * shim (`shim.env`, never this environment's): routedClaudeArgs. Returns
 * `{ args, env }`; throws a RouteRefusal.
 */
function claudeShimSpawn(shim, file, args, env, cwd) {
  return routedClaudeArgs(file, args, env, shim.env, shim.claudeMode, cwd,
    "Pass those settings inline (--settings '{…}') or put them in .claude/settings.local.json.");
}

/**
 * Route one child the host starts. `file` is what is executed, `args` its
 * arguments WITHOUT argv[0], `env` its environment (the inherited one when
 * the host passed none). Returns the arguments and environment to start it
 * with; throws a ManduRouteRefusal for a child that must not start. `cwd`
 * is the folder it starts in (default this process's). Pure but for
 * reading a settings file a `claude` child's command line names and the
 * package.json beside a `cli.js` a runtime runs.
 */
function routeSpawn(route, file, args, env, cwd) {
  const here = typeof cwd === "string" && cwd !== "" ? cwd : process.cwd();
  if (route === null) {
    // A launch's copy whose route is missing or unreadable (install, below):
    // nothing to put back, and an agent child would run unrouted.
    if (agentOf(file, args, here) === null) return { args, env };
    throw new RouteRefusal(
      `mandu: refusing to start ${file}: Mandu's route file (${ownRouteFile()}) is missing or unreadable, so it would run unrouted.`,
    );
  }
  const outEnv = routeEnv(route, env);
  const agent = agentOf(file, args, here);
  if (agent === null) return { args, env: outEnv };
  if (agent.kind === "wrapped") {
    throw new RouteRefusal(
      `mandu: refusing to start ${file}: it starts ${agent.agent} through another program (a container, a remote ` +
      "host, a wrapper), where Mandu can neither route its model traffic nor confine it. Start the agent CLI " +
      "directly (the SDK's default spawn).",
    );
  }
  const routed = agent.kind === "codex"
    ? routeCodex(route, file, agent.args, outEnv)
    : routeClaude(route, file, agent.args, outEnv, here);
  return { args: routed.args === agent.args ? args : [...agent.prefix, ...routed.args], env: routed.env };
}

// ── the child_process hooks ─────────────────────────────────────────────────

function envFromPairs(pairs) {
  const env = {};
  for (const p of pairs || []) {
    const i = p.indexOf("=");
    if (i > 0) env[p.slice(0, i)] = p.slice(i + 1);
  }
  return env;
}

function pairsFromEnv(env) {
  return Object.entries(env).filter(([, v]) => v !== undefined).map(([k, v]) => `${k}=${v}`);
}

/** Split a (file, args?, options?) call the way child_process does. */
function splitCall(file, args, options) {
  if (Array.isArray(args)) return { file, args, options: options || {} };
  return { file, args: [], options: (args !== null && typeof args === "object" ? args : options) || {} };
}

function install(route) {
  const cp = require("node:child_process");
  const proto = cp.ChildProcess && cp.ChildProcess.prototype;
  if (!proto || proto.__manduSdkRoute) return;
  // Every asynchronous start (spawn, execFile, exec, fork) reaches
  // ChildProcess#spawn with its arguments normalized: file, args (argv[0]
  // first) and envPairs (the explicit env or process.env).
  const origSpawn = proto.spawn;
  proto.spawn = function manduRoutedSpawn(options) {
    if (options && typeof options.file === "string" && Array.isArray(options.args)) {
      const r = routeSpawn(route, options.file, options.args.slice(1), envFromPairs(options.envPairs), options.cwd);
      options.args = [options.args[0], ...r.args];
      options.envPairs = pairsFromEnv(r.env);
    }
    return origSpawn.call(this, options);
  };
  Object.defineProperty(proto, "__manduSdkRoute", { value: true });
  // The synchronous starts normalize internally; route them at the export.
  const wrapSync = (name, hasArgs) => {
    const orig = cp[name];
    if (typeof orig !== "function") return;
    cp[name] = function manduRoutedSync(file, args, options) {
      if (!hasArgs) {
        const opts = (args !== null && typeof args === "object") ? args : {};
        const r = routeSpawn(route, "/bin/sh", [], opts.env || process.env, opts.cwd);
        return orig.call(this, file, { ...opts, env: r.env });
      }
      const c = splitCall(file, args, options);
      const r = routeSpawn(route, c.file, c.args, c.options.env || process.env, c.options.cwd);
      return orig.call(this, c.file, r.args, { ...c.options, env: r.env });
    };
  };
  wrapSync("spawnSync", true);
  wrapSync("execFileSync", true);
  wrapSync("execSync", false);
  try { require("node:module").syncBuiltinESMExports(); } catch { /* older Node: CommonJS callers only */ }
}

/**
 * The route as this process received it: a routing variable is forced on
 * children only when this process itself carries it, with the value it
 * carries (read once, before the program's own code runs). What the launch
 * composed but a wrapper in between removed (the reply filter keeps its own
 * variables to itself) is never put back. Pure.
 */
function effectiveRoute(route, ownEnv) {
  const env = {};
  for (const k of Object.keys(route.env)) if (typeof ownEnv[k] === "string") env[k] = ownEnv[k];
  return { ...route, env };
}

// ── the command-line entries: the PATH shims and the Python hook ───────────

/** `name`'s next executable on PATH outside `shimDir`, or null
 *  (claude-permission-rule.cjs; the launch uses the same lookup). */
function realExecutable(name, pathValue, shimDir) {
  return permissionRule.realExecutable(name, pathValue, shimDir, require("node:fs"), path);
}

/** Run `real` in place of this process (`process.execve`), or, on a Node
 *  without it (before 22.15 / 23.11), as a child, passing signals on and
 *  its end back. */
function runInPlace(real, name, args, env, fail) {
  if (typeof process.execve === "function") {
    process.execve(real, [name, ...args], env);
    return;
  }
  const child = require("node:child_process").spawn(real, args, { stdio: "inherit", env, argv0: name });
  const sigs = ["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT", "SIGUSR2", "SIGWINCH"];
  for (const s of sigs) process.on(s, () => { try { child.kill(s); } catch { /* gone */ } });
  child.on("error", (e) => fail(`mandu: ${name}: ${e.message}`));
  child.on("exit", (code, signal) => {
    if (signal) {
      for (const s of sigs) process.removeAllListeners(s);
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code === null ? 1 : code);
  });
}

/**
 * The PATH shim (`<scope run dir>/sdk-shims/{claude,codex}`, sdk-route.ts
 * sdkShimScript): an agent CLI found by name on PATH (a shell command string
 * `exec("codex …")`, a Bun, Deno or Python host's `spawn("codex")`) is
 * routed as a child of the preload would be, or refused, by the launch's
 * route beside this copy (the shim names it by full path). No route there:
 * refused (it would run unrouted). Exits with the CLI's status.
 */
function shimMain(shimDir, name, args) {
  const fail = (why) => { process.stderr.write(`${why}\n`); process.exit(126); };
  // The launch's route, from the file beside this copy (the shim names this
  // copy by its full path, baked in at launch), never from the environment,
  // which the caller chose (`MANDU_SDK_ROUTE='{…}' codex …`).
  const received = readRouteFile(ownRouteFile());
  if (received === null) {
    fail(`mandu: refusing to start ${name}: Mandu's shim finds no route (${ownRouteFile()} is missing or unreadable), so it would run unrouted.`);
  }
  const real = realExecutable(name, process.env.PATH, shimDir);
  if (real === null) fail(`mandu: ${name}: command not found on PATH (past Mandu's shim)`);
  let r;
  try {
    // The launch's route, NOT narrowed to this process's own variables
    // (effectiveRoute): this environment is the one the host chose for its
    // child, which may have dropped or re-pointed a routing variable.
    r = routeSpawn(received, real, args, process.env, process.cwd());
  } catch (e) {
    fail(e instanceof RouteRefusal ? e.message : `mandu: refusing to start ${name}: ${String(e && e.message || e)}`);
  }
  runInPlace(real, name, r.args, r.env, fail);
}

/**
 * The `claude` shim (`<scope run dir>/sdk-shims/claude` of a claude or
 * shell launch the SDK route does not serve; sdk-route.ts claudeShimScript):
 * a `claude` found by name anywhere in the session (a shell's, a script's,
 * the agent's own Bash tool's) is routed as `mandu claude` is
 * (claudeShimSpawn; `routeJson` is the launch's ClaudeShimRoute, baked into
 * the shim, which the agent cannot write), or refused. A route that does not
 * parse refuses: the `claude` would run with whatever its settings files
 * say. Exits with the CLI's status.
 */
function claudeShimMain(shimDir, routeJson, args) {
  const fail = (why) => { process.stderr.write(`${why}\n`); process.exit(126); };
  const shim = parseClaudeShimRoute(routeJson);
  if (shim === null) fail("mandu: refusing to start claude: Mandu's shim carries no routing, so it could send its model traffic around Mandu's model proxy.");
  const real = realExecutable("claude", process.env.PATH, shimDir);
  if (real === null) fail("mandu: claude: command not found on PATH (past Mandu's shim)");
  let r;
  try {
    r = claudeShimSpawn(shim, real, args, process.env, process.cwd());
  } catch (e) {
    fail(e instanceof RouteRefusal ? e.message : `mandu: refusing to start claude: ${String(e && e.message || e)}`);
  }
  runInPlace(real, "claude", r.args, r.env, fail);
}

/**
 * The Python hook's decision (sdk-route-python/sitecustomize.py): one JSON
 * request `{own, file, args, env, cwd}` on stdin, the answer `{args, env}`
 * or `{refusal}` on stdout. routeSpawn is the one copy of the decision. The
 * route is the launch's file beside this copy, as for a Node host; `own` is
 * the Python process's own values of the route's variables, which only
 * narrow it as effectiveRoute does for a Node host (an agent child's
 * routing is the file's launchRouting whatever `own` says). A route in the
 * request is ignored.
 */
function decideMain() {
  const chunks = [];
  process.stdin.on("data", (c) => chunks.push(c));
  process.stdin.on("end", () => {
    let answer;
    try {
      const req = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      const own = readRouteFile(ownRouteFile());
      if (own === null) throw new RouteRefusal(`mandu: refusing to start it: Mandu's route file (${ownRouteFile()}) is missing or unreadable`);
      const route = isPlainObject(req.own) ? effectiveRoute(own, req.own) : own;
      const args = Array.isArray(req.args) ? req.args.map(String) : [];
      answer = routeSpawn(route, String(req.file), args, req.env || {}, typeof req.cwd === "string" ? req.cwd : undefined);
    } catch (e) {
      answer = { refusal: e instanceof RouteRefusal ? e.message : `mandu: refusing to start it: ${String(e && e.message || e)}` };
    }
    process.stdout.write(JSON.stringify(answer));
  });
}

/** This file run as a program (`node sdk-route-preload.cjs
 *  --exec|--claude|--decide …`), also when NODE_OPTIONS loads it first:
 *  Node then runs it once, at the --require, with process.argv already the
 *  program's. */
function cliMode() {
  const mode = process.argv[2];
  if (mode !== "--exec" && mode !== "--claude" && mode !== "--decide") return null;
  try {
    const fs = require("node:fs");
    return fs.realpathSync(process.argv[1] || "") === fs.realpathSync(__filename) ? mode : null;
  } catch {
    return null;
  }
}

const CLI = cliMode();
if (CLI === "--exec") shimMain(process.argv[3] || "", process.argv[4] || "", process.argv.slice(5));
else if (CLI === "--claude") claudeShimMain(process.argv[3] || "", process.argv[4] || "", process.argv.slice(5));
else if (CLI === "--decide") decideMain();

// Loaded as a preload: a launch's copy applies the route beside it (a
// missing or unreadable one refuses every agent child: install(null)); the
// bundle's own copy, which has none, routes nothing. MANDU_SDK_ROUTE is
// never read (WHERE THE ROUTE COMES FROM, in the header).
if (CLI === null && ownRouteExpected()) {
  const received = readRouteFile(ownRouteFile());
  install(received === null ? null : effectiveRoute(received, process.env));
}

module.exports = {
  ROUTE_ENV, ROUTE_DIR, ROUTE_FILE, parseRoute, readRouteFile, effectiveRoute, routeEnv, routeSpawn, spliceCodex, codexRefusal, codexOverrides, RouteRefusal, install,
  agentOf, scriptIndex, realExecutable,
  claudeRouteEnv, claudeEnvRefusal, claudeRouteArgs, claudeModeArgs, parseClaudeShimRoute, claudeShimSpawn, CLAUDE_SHIM_KEYS,
  PROXY_ROUTE_ENV_KEYS, launchRoutingOf,
  UPLOADS_OFF, UPLOADS_OFF_OVERRIDES, CONNECTORS_OFF, uploadConflict,
};
