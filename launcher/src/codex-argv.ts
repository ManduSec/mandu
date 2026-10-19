/**
 * codex-argv — where the launcher's `-c` overrides go in a Codex argv, and the
 * user overrides a launch refuses (docs/design/distribution/portable-wrapper.md, "The
 * Codex config splice", and os-test-matrix.md §10.14).
 *
 * WHY (probe-verified 2026-09-27, codex-cli 0.154, found by the fresh-agents
 * VM suite, os-test-matrix.md §10.14): Codex has a separate `-c/--config`
 * list at EVERY command level (root, `exec`, `exec resume`, `review`, …), and
 * the innermost level that has ANY `-c` replaces the outer lists wholesale.
 * The launcher routed Codex with `-c model_provider=mandu -c
 * model_providers.mandu={…}` spliced right after argv[0], i.e. at the root.
 * So `mandu codex exec -c model_reasoning_effort=low "…"` dropped both
 * overrides, Codex fell back to its built-in `openai` provider and talked to
 * api.openai.com directly: tool results reached the model raw, and the launch
 * looked protected. `OPENAI_BASE_URL` is not honored by 0.154 either, so no
 * env var backs the argv route up. Within ONE level the last `-c` for a key
 * wins, so a user's `-c model_provider=openai` re-points the provider even
 * with our overrides present.
 *
 * The fix, both pure and unit-tested (test/unit/codex-argv.test.ts):
 *   - codexSpliceOverrides: the overrides go after argv[0] (as before) AND
 *     after every subcommand in the chain, so whichever level holds the user's
 *     `-c` also holds ours;
 *   - codexLaunchRefusal: a user override that re-points the model provider
 *     (`model_provider`, `model_providers.*`, `--oss`, `--local-provider`) is
 *     refused before anything launches. Fail-closed: the launcher cannot
 *     route a provider it did not configure.
 *
 * Who receives the overrides depends on argv[0] (codexOverridesReach):
 *   - the `codex` binary: the full splice above, and codexLaunchRefusal;
 *   - a wrapper script under `--target codex` (any other program): the
 *     overrides right after argv[0] only, and no refusal check. `--target` is
 *     the user vouching that the wrapper IS their codex (parse.ts), and the
 *     overrides are its only route: Codex reads no env var for its provider,
 *     so a wrapper that passes its arguments on to codex stays routed only
 *     because it receives them. Dropping them there would be the
 *     silent-unprotected shape (portable-wrapper.md, "The Codex config
 *     splice");
 *   - a POSIX shell (types.ts SHELL_BASENAMES): NONE. A shell is plainly not
 *     codex and cannot pass them on: `sh -c <script>` took the first override
 *     as its script and never ran the user's. env-compose.ts leaves them out
 *     and says at launch that a codex started from the shell is not routed
 *     (codexShellNote), the same truth-in-labeling as the `shell` target;
 *   - a language runtime running a host program (types.ts hostRuntimeOf:
 *     `node app.js`, `python3 app.py`; 2026-10-05, agent-sdks.md): NONE.
 *     The runtime would take them as its own options (`node -c` is node's
 *     --check, so `mandu --target codex -- node app.js` never started), and
 *     the codex the program starts through the Codex SDK is routed by the
 *     SDK route instead (sdk-route.ts, sdk-route-preload.cjs: the same
 *     splice, applied to the child's own argv).
 *
 * `--no-daemon` (probe-verified 2026-09-30, codex-cli 0.159.1,
 * differential-interactive.md §16): Codex 0.159 runs the agent in a shared
 * background server, one per CODEX_HOME, that detaches (own session, parent
 * init), outlives the TUI and hosts the tool runner. Any `-c` makes Codex
 * run embedded instead (the agent inside the launched process) and put
 * `⚠ 1 warning` in the footer. Embedded is what Mandu needs: the agent stays
 * inside the scope, sandbox, shims and proxies the launcher set up, where a
 * server started outside Mandu would run its tools past every chokepoint.
 * So the launcher asks for embedded mode by name (CODEX_NO_DAEMON, composed
 * when codexTakesNoDaemon holds), which clears the warning. Only the root
 * and root-level `resume` / `fork` take the flag (`exec` rejects it), and
 * clap rejects it twice at one level, so the splice drops it where a level
 * cannot take it or the user already gave it. The same reasoning refuses
 * `--remote` and `codex agents` (codexLaunchRefusal): both attach to a
 * server Mandu did not start.
 *
 * The server subcommands (2026-10-02, codex-cli 0.159.1 `--help` per level,
 * portable-wrapper.md "The Codex config splice"): codexLaunchRefusal also
 * refuses every root subcommand that starts, manages or attaches to a Codex
 * server, since such a server serves clients outside the launch or outlives
 * it (SERVER_SUBCOMMANDS: `remote-control`, `app-server`, `exec-server`),
 * and `debug app-server`, whose child agent server was probed to drop the
 * launcher's `-c` routing and send its turn straight to api.openai.com.
 * Allowed: subcommands that run in the launched process or as a plain
 * child that dies with it (`exec`, `review`, `resume`, `fork`, `sandbox`,
 * `mcp`, `queue` without `--remote`, which only writes the queue database
 * under CODEX_HOME, and the bookkeeping ones). A `mcp-server`
 * subcommand, absent from 0.154 and 0.159.1, would be a stdio child too.
 * `codex cloud` (alias `cloud-tasks`) is refused since 2026-10-07: it sends
 * the prompt to OpenAI's cloud as a task, where the agent runs on OpenAI's
 * machines, reads and writes there, and never passes Mandu's model proxy.
 *
 * Codex's own uploads (2026-10-07, read from the codex-cli 0.160.0 source
 * and checked against 0.136.0, the oldest tested; supported-agents.md
 * §5.3.4 rule 1, §5.5): CODEX_UPLOADS_OFF goes to every command level with
 * the routing overrides. Each key turns off a channel that carries data off
 * the machine past the model proxy, or a call nobody needs under Mandu:
 *   - `analytics.enabled=false`: the analytics events Codex posts to
 *     chatgpt.com (ids, model, tool names) and, through it, the Statsig
 *     metrics to ab.chatgpt.com (the metrics exporter is forced off when
 *     analytics is);
 *   - `feedback.enabled=false`: the feedback report, which uploads the
 *     session's rollout (raw tool output) and logs to Sentry;
 *   - `otel.exporter` / `otel.trace_exporter` / `otel.metrics_exporter =
 *     "none"`: a user's own OpenTelemetry collector, whose log and trace
 *     events carry tool arguments and up to 2 KiB of each tool's output;
 *   - `features.apps=false`: ChatGPT apps, whose file parameters make Codex
 *     read the named local file and upload its bytes to chatgpt.com. Its
 *     legacy alias `connectors` is a trap: Codex applies feature keys in name
 *     order, so a config's `connectors = true` turns apps back on after
 *     `apps = false`. Forcing `features.connectors=false` always would print
 *     Codex's "`[features].connectors` is deprecated" notice on every launch
 *     (probed on 0.160.0), so it is forced only when one of the user's config
 *     layers names `connectors` (CODEX_CONNECTORS_OFF, codexConfigNamesConnectors;
 *     that config already prints the notice);
 *   - `check_for_update_on_startup=false`: the TUI's release check.
 * A `-c` override outranks every config.toml layer (system, user, profile,
 * project; 0.160.0 config_layer_source.rs), but within one level the last
 * `-c` for a key wins, so a user's own `-c` (or `--enable apps`) that sets
 * one of these keys otherwise, or replaces its table, is refused
 * (codexUploadConflict). Every key exists in 0.136.0, and probed on 0.136.0,
 * 0.144.1 and 0.160.0 (2026-10-07) the set starts Codex with no warning
 * (0.160.0 names an unknown key in a startup warning; none of these is one).
 */
import { basename } from "node:path";
import { compareAgentVersions, parseAgentVersion } from "./agent-versions.js";
import { SHELL_BASENAMES, hostRuntimeOf } from "./types.js";

/** Codex's own upload channels, forced off at every command level (see the
 *  header): `[key, TOML value]`. The SDK preload holds an equal copy
 *  (sdk-route-preload.cjs, the parity test). */
export const CODEX_UPLOADS_OFF: ReadonlyArray<readonly [string, string]> = [
  ["analytics.enabled", "false"],
  ["feedback.enabled", "false"],
  ["otel.exporter", '"none"'],
  ["otel.trace_exporter", '"none"'],
  ["otel.metrics_exporter", '"none"'],
  ["features.apps", "false"],
  ["features.connectors", "false"],
  ["check_for_update_on_startup", "false"],
];

/** The switches every Codex launch carries, as `-c` tokens: CODEX_UPLOADS_OFF
 *  but the legacy `connectors` key (CODEX_CONNECTORS_OFF; see the header). */
export const CODEX_UPLOADS_OFF_OVERRIDES: readonly string[] = CODEX_UPLOADS_OFF
  .filter(([k]) => k !== "features.connectors")
  .flatMap(([k, v]) => ["-c", `${k}=${v}`]);

/** `connectors` off, for a launch whose Codex config names that legacy key. */
export const CODEX_CONNECTORS_OFF: readonly string[] = ["-c", "features.connectors=false"];

/** Does this Codex config file name the legacy `connectors` feature key
 *  (`[features]` `connectors = …`, `features.connectors = …`, an inline
 *  `features = { connectors = … }`, a profile's)? A line scan,
 *  conservative: a false hit only adds Codex's deprecation notice. Pure. */
export function codexConfigNamesConnectors(text: string): boolean {
  for (const raw of text.split("\n")) {
    const line = raw.replace(/(^|\s)#.*$/, "").trim();
    if (/(^|[.{,\s])["']?connectors["']?\s*=/.test(line)) return true;
  }
  return false;
}

/** The feature names `--enable` may not turn on (they are forced off). */
const UPLOAD_FEATURES = new Set(["apps", "connectors"]);

/** A config value as Codex would compare it: quotes and spaces off,
 *  lowercase. */
function overrideValue(v: string): string {
  return v.trim().replace(/^["']|["']$/g, "").trim().toLowerCase();
}

/** Does this user `-c key=value` undo one of CODEX_UPLOADS_OFF? It does when
 *  it sets one of those keys to another value, sets a key below one (an
 *  exporter's own table), or replaces a table that holds one (`-c
 *  features={…}`, `-c otel={…}`). The same value is harmless. Pure. */
export function codexUploadConflict(kv: string): boolean {
  const eq = kv.indexOf("=");
  const key = (eq < 0 ? kv : kv.slice(0, eq)).trim().replace(/["'\s]/g, "");
  const value = eq < 0 ? "" : kv.slice(eq + 1);
  if (key === "") return false;
  for (const [k, v] of CODEX_UPLOADS_OFF) {
    if (key === k) { if (overrideValue(value) !== overrideValue(v)) return true; continue; }
    if (key.startsWith(`${k}.`) || k.startsWith(`${key}.`)) return true;
  }
  return false;
}

/** Asks Codex for embedded mode: the agent runs in the launched process. */
export const CODEX_NO_DAEMON = "--no-daemon";
/** The first Codex the flag is verified on. An older one that lacks it would
 *  refuse to start, so the gate is the verified version, not a guess. */
const NO_DAEMON_SINCE = parseAgentVersion("0.159.1")!;
/** Root-level subcommands that take `--no-daemon` (0.159.1 help). */
const NO_DAEMON_SUBCOMMANDS = new Set(["resume", "fork"]);

/** Whether this Codex version takes `--no-daemon`. False for an unread
 *  version (a wrapper, a failed probe): Codex that old errors on the flag,
 *  and the `-c` overrides already keep it embedded, so leaving it out costs
 *  only the footer warning. Pure. */
export function codexTakesNoDaemon(version: string | null | undefined): boolean {
  const v = parseAgentVersion(version);
  return v !== null && compareAgentVersions(v, NO_DAEMON_SINCE) >= 0;
}

/** Subcommands per level (`codex --help`, `codex exec --help`, 0.154). Every
 *  one takes its own `-c`. Aliases included (`e` = exec, `a` = apply). */
const ROOT_SUBCOMMANDS = new Set([
  "agents", "exec", "e", "review", "login", "logout", "mcp", "plugin", "app-server", "remote-control",
  "completion", "update", "doctor", "sandbox", "debug", "apply", "a", "resume", "queue", "archive",
  "delete", "migrate-rollouts", "unarchive", "fork", "cloud", "cloud-tasks", "exec-server", "features", "help",
]);
const CHILD_SUBCOMMANDS: Readonly<Record<string, ReadonlySet<string>>> = {
  exec: new Set(["resume", "fork", "review", "help"]),
  e: new Set(["resume", "fork", "review", "help"]),
};

/** Flags that take a value, at the root and at `exec` (0.154 help). A value
 *  is never read as a subcommand (`-m exec` names a model). */
const VALUE_FLAGS = new Set([
  "-c", "--config", "--enable", "--disable", "--remote", "--remote-auth-token-env", "-i", "--image",
  "-m", "--model", "--local-provider", "-p", "--profile", "-s", "--sandbox", "-C", "--cd", "--add-dir",
  "-a", "--ask-for-approval", "--thread-source", "--output-schema", "--color", "-o", "--output-last-message",
]);

export function isCodexBinary(arg0: string | undefined): boolean {
  return arg0 !== undefined && basename(arg0) === "codex";
}

/** Whether a `--target codex` argv[0] receives the routing overrides at all:
 *  false for a POSIX shell and for a language runtime running a host
 *  program, neither of which is codex and both of which would take them as
 *  their own options (see the header). */
export function codexOverridesReach(arg0: string | undefined): boolean {
  return arg0 !== undefined && !SHELL_BASENAMES.has(basename(arg0)) && hostRuntimeOf(arg0) === null;
}

/**
 * The agent argv with `overrides` spliced after argv[0] and after every
 * subcommand token of the chain. Tokens after `--` are never touched. A
 * non-codex argv[0] (a wrapper) gets the overrides after argv[0] only. The
 * caller decides WHETHER there are any: env-compose.ts composes none for a
 * shell (codexOverridesReach), and an empty list leaves the argv as it is.
 * CODEX_NO_DAEMON among the overrides lands only at a level that takes it
 * and where the user did not give it (see the header).
 */
export function codexSpliceOverrides(argv: readonly string[], overrides: readonly string[]): string[] {
  const [head, ...rest] = argv;
  if (head === undefined) return [];
  if (!isCodexBinary(head)) return [head, ...overrides, ...rest];
  // One entry per command level: its subcommand token (none at the root),
  // the user's tokens there, and whether the user gave --no-daemon there.
  const levels: { sub: string | null; tokens: string[]; noDaemon: boolean }[] = [{ sub: null, tokens: [], noDaemon: false }];
  let children: ReadonlySet<string> = ROOT_SUBCOMMANDS;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!;
    const level = levels[levels.length - 1]!;
    if (a === "--") { level.tokens.push(...rest.slice(i)); break; }
    if (a.startsWith("-")) {
      level.tokens.push(a);
      if (a === CODEX_NO_DAEMON) level.noDaemon = true;
      if (VALUE_FLAGS.has(a) && i + 1 < rest.length) level.tokens.push(rest[++i]!);
      continue;
    }
    if (children.has(a)) {
      levels.push({ sub: a, tokens: [], noDaemon: false });
      children = CHILD_SUBCOMMANDS[a] ?? new Set();
    } else {
      // The first positional that is not a subcommand (the prompt, a session
      // id): no subcommand can follow it.
      level.tokens.push(...rest.slice(i));
      break;
    }
  }
  const out = [head];
  levels.forEach((level, depth) => {
    if (level.sub !== null) out.push(level.sub);
    const takesNoDaemon = depth === 0 || (depth === 1 && NO_DAEMON_SUBCOMMANDS.has(level.sub!));
    out.push(...(takesNoDaemon && !level.noDaemon ? overrides : overrides.filter((t) => t !== CODEX_NO_DAEMON)));
    out.push(...level.tokens);
  });
  return out;
}

/** The root subcommand of a Codex argv (`exec`, `app-server`, …), skipping
 *  root options and their values, or null (the TUI, or a prompt first).
 *  Nothing after `--`. Pure. */
export function codexSubcommand(argv: readonly string[]): string | null {
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--") return null;
    if (a.startsWith("-")) {
      if (VALUE_FLAGS.has(a)) i++;
      continue;
    }
    return ROOT_SUBCOMMANDS.has(a) ? a : null;
  }
  return null;
}

/** The command level of each token of a Codex argv: 0 for the root's
 *  flags, +1 for each subcommand of the chain (the subcommand token itself
 *  carries its new level), as codexSpliceOverrides walks it; flags after
 *  the first positional that is not a subcommand (the prompt, a session id)
 *  belong to the innermost level, where clap parses them. -1 for argv[0], a
 *  flag's value, a positional, and `--` and what follows it. Codex reads
 *  only the innermost level's `-c` list once a level has its own, and Mandu
 *  puts its own `-c` at every level. Pure. */
export function codexArgvLevels(argv: readonly string[]): number[] {
  const out: number[] = argv.map(() => -1);
  let level = 0;
  let children: ReadonlySet<string> = ROOT_SUBCOMMANDS;
  let chain = true;
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--") break;
    if (a.startsWith("-")) {
      out[i] = level;
      if (VALUE_FLAGS.has(a) && i + 1 < argv.length) i++;
      continue;
    }
    if (!chain || !children.has(a)) { chain = false; continue; }
    level++;
    out[i] = level;
    children = CHILD_SUBCOMMANDS[a] ?? new Set();
  }
  return out;
}

/** The directory a Codex argv runs in, from its last `-C` / `--cd` (any
 *  level, before `--`), or null. */
export function codexArgvCd(argv: readonly string[]): string | null {
  let cd: string | null = null;
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--") break;
    if ((a === "-C" || a === "--cd") && i + 1 < argv.length) { cd = argv[++i]!; continue; }
    if (a.startsWith("--cd=")) { cd = a.slice("--cd=".length); continue; }
    if (a.startsWith("-C") && a.length > 2 && !a.startsWith("--")) { cd = a.slice(2).replace(/^=/, ""); continue; }
    if (VALUE_FLAGS.has(a)) i++;
  }
  return cd;
}

/** `codex app-server` options that take a value (0.159.3 `codex app-server
 *  --help`). */
const APP_SERVER_VALUE_FLAGS = new Set([
  "-c", "--config", "--enable", "--disable", "--listen", "--code-mode-host", "--ws-auth", "--ws-token-file",
  "--ws-token-sha256", "--ws-shared-secret-file", "--ws-issuer", "--ws-audience", "--ws-max-clock-skew-seconds",
]);

/** Is this a bare `codex app-server` (an IDE's backend, which serves
 *  sessions)? Not when it names a subcommand of its own (`daemon`, `proxy`,
 *  `generate-*`, `help`), possibly after its options, nor with `--help` /
 *  `-h` / `--version` / `-V`. Pure. */
export function codexBareAppServer(argv: readonly string[]): boolean {
  if (!isCodexBinary(argv[0])) return false;
  let i = 1;
  for (; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--") return false;
    if (a.startsWith("-")) {
      if (INFO_FLAGS.has(a)) return false;
      if (VALUE_FLAGS.has(a)) i++;
      continue;
    }
    if (a !== "app-server") return false;
    break;
  }
  if (i >= argv.length) return false;
  for (i++; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--") return i + 1 === argv.length;
    if (INFO_FLAGS.has(a)) return false;
    if (a.startsWith("-")) {
      if (APP_SERVER_VALUE_FLAGS.has(a)) i++;
      continue;
    }
    return false; // a subcommand of its own, or a token clap rejects
  }
  return true;
}
/** The root-level subcommand of a Codex argv and the first positional after
 *  it (its own subcommand, or an argument), or null for the TUI. Flag values
 *  are skipped; tokens after `--` are prompt text. */
function codexSubcommandPath(argv: readonly string[]): { sub: string; next: string | null } | null {
  let sub: string | null = null;
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--") break;
    if (a.startsWith("-")) { if (VALUE_FLAGS.has(a)) i++; continue; }
    if (sub !== null) return { sub, next: a };
    if (!ROOT_SUBCOMMANDS.has(a)) return null;
    sub = a;
  }
  return sub === null ? null : { sub, next: null };
}

/** Root subcommands refused under Mandu, each with why: every one starts,
 *  manages or attaches to a Codex server that serves clients outside the
 *  launch or outlives it (codex-cli 0.159.1; see the header). */
const SERVER_SUBCOMMANDS: ReadonlyMap<string, string> = new Map([
  ["agents", "it attaches to a Codex server Mandu did not start, and that server runs the agent and its tools outside Mandu's protection"],
  ["remote-control", "it starts or manages Codex's background server with remote control on, which detaches from the launch and takes work from outside it"],
  ["app-server", "it runs Codex's agent server, or manages or attaches to its background daemon, which serves clients outside the launch and can outlive it"],
  ["exec-server", "it runs Codex's command-execution server, which listens for clients outside the launch"],
]);
/** `debug app-server` starts a child agent server that does not take the
 *  launcher's `-c` routing (probed 2026-10-02: its turn went to
 *  api.openai.com), so its model traffic would skip Mandu's model proxy. */
/** `codex cloud` (and its alias): the task runs on OpenAI's machines. */
const CLOUD_REASON =
  "it sends your prompt to Codex Cloud as a task, which runs the agent on OpenAI's machines, past Mandu's model proxy and every other protection";
const CLOUD_SUBCOMMANDS = new Set(["cloud", "cloud-tasks"]);
const DEBUG_APP_SERVER_REASON =
  "it runs a model turn in a child agent server that does not take Mandu's model routing, so the turn would skip Mandu's model proxy";

/** The subcommands that run a model turn (0.159 `codex --help`). */
const MODEL_SUBCOMMANDS = new Set(["exec", "e", "review", "resume", "fork"]);
const INFO_FLAGS = new Set(["--version", "-V", "--help", "-h"]);

/**
 * Whether this Codex argv starts a model session: no subcommand (the TUI, a
 * prompt given as the first positional) or one of MODEL_SUBCOMMANDS, and no
 * `--help` / `--version` before `--`. Every other subcommand (`login`, `mcp`,
 * `completion`, `app-server`, …) answers false: the caller (agent-login.ts
 * codexKeyRefusal) refuses only where Codex is certain to need its model key.
 * False for a non-codex argv[0].
 */
export function codexTalksToModel(argv: readonly string[]): boolean {
  if (!isCodexBinary(argv[0])) return false;
  let sawModelSub = false;
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--") return true;
    if (a.startsWith("-")) {
      if (INFO_FLAGS.has(a)) return false;
      if (VALUE_FLAGS.has(a)) i++;
      continue;
    }
    if (sawModelSub) continue; // `exec resume`, a prompt, a session id
    if (MODEL_SUBCOMMANDS.has(a)) { sawModelSub = true; continue; }
    if (ROOT_SUBCOMMANDS.has(a)) return false;
    // The first positional that is not a subcommand is the prompt; a later
    // `--help` is prompt text too.
    return true;
  }
  return true;
}

/** Config keys that choose where Codex sends model traffic. */
function reroutesProvider(kv: string): boolean {
  const key = kv.split("=", 1)[0]!.trim().replace(/^["']|["']$/g, "");
  return key === "model_provider" || key === "model_providers" || key.startsWith("model_providers.");
}

/** The refusal message for a Codex argv that re-points the model provider,
 *  starts, manages or attaches to a Codex server (SERVER_SUBCOMMANDS,
 *  `--remote`, `debug app-server`), runs in Codex Cloud (`cloud`), or turns
 *  one of Codex's own uploads back on (codexUploadConflict, `--enable
 *  apps`), or null when it may launch. Wrappers (non-codex argv[0]) are not
 *  checked. */
export function codexLaunchRefusal(argv: readonly string[]): string | null {
  if (!isCodexBinary(argv[0])) return null;
  const remote = argv.slice(1, argv.includes("--") ? argv.indexOf("--") : undefined)
    .find((a) => a === "--remote" || a.startsWith("--remote="));
  const path = codexSubcommandPath(argv);
  let refused: { what: string; why: string } | null = null;
  if (remote !== undefined) refused = { what: "--remote", why: SERVER_SUBCOMMANDS.get("agents")! };
  else if (path !== null && SERVER_SUBCOMMANDS.has(path.sub)) refused = { what: `\`codex ${path.sub}\``, why: SERVER_SUBCOMMANDS.get(path.sub)! };
  else if (path !== null && CLOUD_SUBCOMMANDS.has(path.sub)) refused = { what: `\`codex ${path.sub}\``, why: CLOUD_REASON };
  else if (path?.sub === "debug" && path.next === "app-server") refused = { what: "`codex debug app-server`", why: DEBUG_APP_SERVER_REASON };
  if (refused !== null) {
    return (
      `mandu: refusing to launch codex with ${refused.what}: ${refused.why}. Run codex without it; under Mandu the ` +
      "agent runs in the process Mandu launched."
    );
  }
  const hits: string[] = [];
  const uploads: string[] = [];
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--") break;
    let kv: string | undefined;
    if (a === "-c" || a === "--config") kv = argv[++i];
    else if (a.startsWith("--config=")) kv = a.slice("--config=".length);
    // An attached short value (`-ckv`, or `-c=kv`: clap strips one `=`).
    else if (a.startsWith("-c") && !a.startsWith("--") && a.length > 2) kv = a.slice(2).replace(/^=/, "");
    if (kv !== undefined && reroutesProvider(kv)) hits.push(`-c ${kv.split("=", 1)[0]!.trim()}`);
    else if (kv !== undefined && codexUploadConflict(kv)) uploads.push(`-c ${kv.split("=", 1)[0]!.trim()}`);
    if (a === "--oss" || a === "--local-provider" || a.startsWith("--local-provider=")) hits.push(a.split("=", 1)[0]!);
    // `--enable <feature>` is `-c features.<feature>=true`, appended after
    // every root `-c` (0.160.0 cli/src/main.rs).
    let feature: string | undefined;
    if (a === "--enable") feature = argv[++i];
    else if (a.startsWith("--enable=")) feature = a.slice("--enable=".length);
    if (feature !== undefined && UPLOAD_FEATURES.has(feature.trim())) uploads.push(`--enable ${feature.trim()}`);
  }
  if (hits.length === 0 && uploads.length > 0) {
    return (
      `mandu: refusing to launch codex with ${[...new Set(uploads)].join(", ")}: Mandu keeps Codex's own uploads ` +
      "and calls home off (analytics, feedback reports, OpenTelemetry export, ChatGPT apps and connectors, the update " +
      "check): some carry your session's tool output or local files off the machine past Mandu's model proxy. Drop the option."
    );
  }
  if (hits.length === 0) return null;
  return (
    `mandu: refusing to launch codex with ${[...new Set(hits)].join(", ")}: it chooses where Codex sends its model ` +
    "traffic, and Mandu protects Codex by routing that traffic through its own provider. Another provider would " +
    "receive tool results unmasked. Drop the option (set the model with -m / -c model=…). To use your own model, " +
    "declare its base URL under policy.yaml models: with wire: openai-chat and set MANDU_OPENAI_BASE_URL to it."
  );
}
