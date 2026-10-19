/**
 * goose-argv — the Goose launch shapes `mandu goose` accepts, and where the
 * launcher's `--with-extension` splice goes. An ALLOWLIST (fail-closed):
 * every shape not listed here is refused before anything launches
 * (supported-agents.md §5.6).
 *
 * WHY (goose 1.53.0, read from its `--help` and source, 2026-10-05): the
 * launcher protects a Goose process whose agent loop runs INSIDE the wrap
 * and reads the env routing the launcher sets (env-compose.ts). `goose
 * session` and `goose run` build the agent in this process; the rest do not:
 *   - `serve`: the desktop backend (ACP over HTTP and WebSocket) and, with
 *     `--enable-scheduler`, its scheduler: a long-lived server whose sessions
 *     and scheduled jobs outlive the launch. `gateway` (alias `gw`): the
 *     Telegram and other chat-platform gateways, messaging ingress outside
 *     the session (supported-agents.md §5.3.4 rule 3). `schedule` (`sched`):
 *     jobs that fire later in whichever process runs the scheduler. `acp
 *     --enable-scheduler`: scheduled recipes fire inside the ACP server, each
 *     with the provider its recipe names. `roam` (a build feature):
 *     peer-to-peer session sharing with paired devices.
 *   - `--container <id>`: runs the stdio and built-in extensions as `docker
 *     exec … goose mcp <name>`, outside the wrap.
 *   - `--sub-recipe`: a sub-recipe runs only as `delegate{source}`, which
 *     the wire refuses (tool-gate-surface.ts: a sub-recipe's settings name
 *     its subagent's provider above the env), so it could never run.
 *   - `--with-builtin code_execution`: code mode, model-written TypeScript
 *     that calls tools in process (decision D4); its tool call is refused on
 *     the wire anyway, so a launch that asks for it is refused up front.
 *   - `session export|import|list|remove|rename|diagnostics`, `configure`,
 *     `info`, `doctor`, `update`, `skills`, `plugin`, `local-models`, `term`,
 *     `completion`, `mcp`, `recipe`: management, run them without `mandu`.
 *     `session export --nostr` in particular publishes a session (with every
 *     tool output it held) to public Nostr relays. `recipe open` hands the
 *     recipe to Goose Desktop, outside this launch.
 *   - bare `goose`: runs `goose configure` when there is no config, an
 *     interactive setup, not the agent. Bare `mandu goose` is mapped to
 *     `goose session` (gooseDefaultArgv), as bare `mandu openclaw` is mapped
 *     to `openclaw chat`.
 * Allowed: `session` (alias `s`) without a management subcommand, `run`
 * (with `--recipe`: goose-recipe.ts reads the recipe before the launch and
 * pins the provider), `review` (its `goose run` children inherit the routing
 * env; goose-route.ts checks its `--provider`), `acp` (an ACP server on
 * stdio: the launcher relays the editor's stream, goose-acp-relay.ts),
 * `help`, `--help`, `--version`.
 *
 * An argv the launcher cannot read as Goose (a wrapper script passed with
 * `--target goose`) is not checked: `--target` is the user vouching for the
 * wrapper, the contract parse.ts applies to every wrapper target. Such a
 * wrapper gets no `--with-extension` splice either (no U-LLM mount).
 *
 * Pure; unit-tested in test/unit/goose-argv.test.ts.
 */
import { basename } from "node:path";

export interface GooseArgv {
  /** the subcommand as typed (`s` stays `s`), or "" for bare `goose [flags]` */
  sub: string;
  /** the subcommand with its alias resolved (`s` → `session`, …) */
  command: string;
  /** index in argv of the subcommand token, -1 when bare */
  subIndex: number;
  /** args after the subcommand */
  rest: string[];
  /** flags before the subcommand (Goose's top level takes -h / -V only) */
  globals: string[];
}

const ALIASES: Readonly<Record<string, string>> = { s: "session", sched: "schedule", gw: "gateway", lm: "local-models" };

/** Is argv[0] the `goose` binary (not a wrapper script)? */
export function isGooseBinary(argv0: string | undefined): boolean {
  return argv0 !== undefined && basename(argv0) === "goose";
}

/** Read an agent argv as a Goose invocation, or null when argv[0] is not the
 *  `goose` binary (a wrapper script). */
export function readGooseArgv(argv: readonly string[]): GooseArgv | null {
  if (argv.length === 0 || basename(argv[0]!) !== "goose") return null;
  let i = 1;
  const globals: string[] = [];
  while (i < argv.length && argv[i]!.startsWith("-")) globals.push(argv[i++]!);
  if (i >= argv.length) return { sub: "", command: "", subIndex: -1, rest: [], globals };
  const sub = argv[i]!;
  return { sub, command: ALIASES[sub] ?? sub, subIndex: i, rest: argv.slice(i + 1), globals };
}

const HELP_OR_VERSION = new Set(["-h", "--help", "-V", "--version"]);

/** Is this `goose acp` serving an editor on stdio (not its help)? The
 *  launch then relays the stream (goose-acp-relay.ts) and runs no reply
 *  filter. Pure. */
export function gooseAcpLaunch(argv: readonly string[]): boolean {
  const g = readGooseArgv(argv);
  return g !== null && g.command === "acp" && !g.globals.some((f) => HELP_OR_VERSION.has(f)) && !g.rest.some((a) => a === "-h" || a === "--help");
}

/** Bare `goose [flags]` runs as `goose session`: the agent inside Mandu, not
 *  the `configure` setup bare Goose falls back to without a config. Help and
 *  version flags, every subcommand and a wrapper pass unchanged. Pure. */
export function gooseDefaultArgv(argv: readonly string[]): readonly string[] {
  const g = readGooseArgv(argv);
  if (!g || g.sub !== "" || g.globals.some((f) => HELP_OR_VERSION.has(f))) return argv;
  return [...argv, "session"];
}

/** `goose session` subcommands (1.53.0): management, not the agent. */
const SESSION_MANAGEMENT = new Set(["list", "remove", "export", "import", "diagnostics", "rename", "help"]);

/** Flags of `session` / `run` that take a value (1.53.0 `--help`), so a value
 *  is never read as a subcommand or a flag. */
const VALUE_FLAGS: ReadonlySet<string> = new Set([
  "-n", "--name", "--session-id", "--path", "--system", "--max-tool-repetitions", "--max-turns", "--container",
  "--with-extension", "--with-streamable-http-extension", "--with-builtin", "--provider", "--model",
  "-i", "--instructions", "-t", "--text", "--recipe", "--params", "--sub-recipe", "--output-format",
]);

/** Flags of `review` that take a value (1.53.0 `goose review --help`). Its own
 *  set: `-s` is `--check-scope <DIR>` here but `run`'s value-less
 *  `--interactive`, and a shared set would skip the token after `run -s`. */
const REVIEW_VALUE_FLAGS: ReadonlySet<string> = new Set([
  "--prompt", "--model", "--provider", "--override-model", "--turn-limit", "-i", "--instructions",
  "-f", "--files", "-c", "--check-filter", "-s", "--check-scope", "--severity",
]);

/** The value-taking flags of a (resolved) subcommand. */
export function gooseValueFlags(command: string): ReadonlySet<string> {
  return command === "review" ? REVIEW_VALUE_FLAGS : VALUE_FLAGS;
}

/** The value of every occurrence of `flag` (`--flag v` and `--flag=v`) in
 *  args, skipping other flags' values (`valueFlags`: the subcommand's,
 *  gooseValueFlags; `session` / `run`'s by default). Pure. */
export function gooseFlagValues(args: readonly string[], flag: string, valueFlags: ReadonlySet<string> = VALUE_FLAGS): string[] {
  const out: string[] = [];
  for (let k = 0; k < args.length; k++) {
    const a = args[k]!;
    if (a === "--") break;
    if (a === flag) { if (k + 1 < args.length) out.push(args[k + 1]!); k++; continue; }
    if (a.startsWith(`${flag}=`)) { out.push(a.slice(flag.length + 1)); continue; }
    if (valueFlags.has(a)) k++;
  }
  return out;
}

const hasFlag = (args: readonly string[], flag: string): boolean =>
  args.some((a) => a === flag || a.startsWith(`${flag}=`));

/** The refusal message for a Goose launch shape outside the allowlist, or
 *  null when it may launch. */
export function gooseLaunchRefusal(argv: readonly string[]): string | null {
  const g = readGooseArgv(argv);
  if (!g) return null; // a wrapper: --target vouches for it (see the header)
  // Help and version print and exit, whatever the subcommand.
  if (g.globals.some((f) => HELP_OR_VERSION.has(f)) || g.command === "help" || g.rest.some((a) => a === "-h" || a === "--help")) return null;
  const shown = `goose${g.sub ? ` ${g.sub}` : ""}`;
  const refuse = (why: string, instead = "Use `mandu goose` (= `goose session`) or `mandu goose run …`: the agent runs inside Mandu.") =>
    `mandu: refusing \`${shown}\`: ${why} ${instead}`;

  switch (g.command) {
    case "session":
    case "run": {
      if (g.command === "session") {
        const first = g.rest.find((a, k) => !a.startsWith("-") && !(k > 0 && VALUE_FLAGS.has(g.rest[k - 1]!)));
        if (first !== undefined && SESSION_MANAGEMENT.has(first)) {
          return first === "export"
            ? refuse(
                "`goose session export` is management, and with --nostr it publishes the whole session (every tool output " +
                  "it held) to public Nostr relays, past Mandu's model proxy.",
                "Run it without `mandu` if you mean to.",
              )
            : refuse(`\`goose session ${first}\` manages saved sessions; it is not the agent.`, "Run it without `mandu`.");
        }
      }
      if (hasFlag(g.rest, "--container")) {
        return refuse("--container runs Goose's extensions inside a container (docker exec), outside this confinement.");
      }
      if (hasFlag(g.rest, "--sub-recipe")) {
        return refuse(
          "--sub-recipe: a sub-recipe runs only through `delegate` with a `source`, which Mandu refuses on the wire " +
            "(a sub-recipe's settings name its subagent's provider above the environment Mandu routes), so it could never run.",
          "Run the sub-recipe as its own recipe: `mandu goose run --recipe <file>`.",
        );
      }
      if (g.command === "session" && hasFlag(g.rest, "--recipe")) {
        return refuse("`goose session` takes no recipe.", "Use `mandu goose run --recipe <file>`.");
      }
      const builtins = gooseFlagValues(g.rest, "--with-builtin").flatMap((v) => v.split(",")).map((s) => s.trim());
      if (builtins.includes("code_execution")) {
        return refuse(
          "code mode (code_execution) runs model-written TypeScript that calls tools inside Goose, where Mandu cannot check which tool gets which input.",
          "Leave code_execution off: Goose then calls each tool directly, and Mandu checks every call.",
        );
      }
      return null;
    }
    case "":
      // gooseDefaultArgv maps bare `mandu goose` to `goose session`; a caller
      // that skips the mapping gets the reason.
      return refuse("bare `goose` runs `goose configure` when there is no config: an interactive setup, not the agent.");
    case "serve":
      return refuse(
        "`goose serve` is the desktop backend: a long-lived server whose sessions (and, with --enable-scheduler, " +
          "scheduled jobs) run outside this launch.",
      );
    case "gateway":
      return refuse("`goose gateway` connects Goose to chat platforms (Telegram and others): messaging ingress Mandu does not confine.");
    case "schedule":
      return refuse("`goose schedule` manages jobs that fire later in another Goose process, outside this launch.", "Run it without `mandu`.");
    case "acp": {
      // The editor's stream goes through the launcher's ACP relay
      // (goose-acp-relay.ts); what the argv itself can turn on is checked here.
      if (hasFlag(g.rest, "--enable-scheduler")) {
        return refuse(
          "--enable-scheduler runs scheduled recipes in this process at times of their own, each with the provider its recipe names.",
          "Run `mandu goose acp` without it.",
        );
      }
      const acpBuiltins = gooseFlagValues(g.rest, "--with-builtin").flatMap((v) => v.split(",")).map((s) => s.trim());
      if (acpBuiltins.includes("code_execution")) {
        return refuse(
          "code mode (code_execution) runs model-written TypeScript that calls tools inside Goose, where Mandu cannot check which tool gets which input.",
          "Leave code_execution off: Goose then calls each tool directly, and Mandu checks every call.",
        );
      }
      return null;
    }
    case "review":
      // Each check (and each file of the main pass) is a `goose run` child of
      // this process: inside the wrap, routed by the env it inherits. Its
      // `--provider` is checked with the others (goose-route.ts).
      return null;
    case "recipe":
      return refuse(
        "`goose recipe` validates, lists or links recipes (and `recipe open` hands one to Goose Desktop); it runs no agent.",
        "Run it without `mandu`; run a recipe with `mandu goose run --recipe <file>`.",
      );
    case "roam":
      return refuse("`goose roam` shares sessions with paired devices peer to peer, outside Mandu.");
    default:
      return refuse(
        `\`goose ${g.sub}\` is not an agent shape Mandu confines (allowed: session, run, review, acp, --help, --version).`,
        "Run management commands without `mandu`; use `mandu goose` for the agent.",
      );
  }
}

/** Quote one token the way Goose's `split_command_args` (goose 1.53.0
 *  crates/goose/src/utils.rs) reads it back: a token with whitespace or a
 *  double quote, or one that starts with a single quote, is wrapped in
 *  single quotes, inside which every character is literal. A token that needs
 *  wrapping and holds a single quote cannot be written: null. */
export function gooseQuoteToken(t: string): string | null {
  if (t === "") return "''";
  if (!/[\s"]/.test(t) && !t.startsWith("'")) return t;
  if (t.includes("'")) return null;
  return `'${t}'`;
}

/** The `--with-extension` value for one stdio MCP server, named `name`
 *  (`[name:]ENV=val … command args…`, goose 1.53.0 `parse_stdio_extension`):
 *  the explicit name makes its tools `<name>__<tool>`, the spelling the
 *  arbiter recognizes (inspect-tool.ts). null when a token cannot be quoted
 *  for Goose, or an env key is not a plain identifier. Pure. */
export function gooseExtensionArg(
  name: string,
  server: { command: string; args: readonly string[]; env: Readonly<Record<string, string>> },
): string | null {
  if (!/^[A-Za-z0-9_-]{2,}$/.test(name)) return null;
  const parts: string[] = [];
  for (const [k, v] of Object.entries(server.env)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)) return null;
    const q = gooseQuoteToken(`${k}=${v}`);
    if (q === null) return null;
    parts.push(q);
  }
  // Goose reads leading KEY=VALUE tokens as env until the first token
  // without `=`: the command must not contain one.
  if (server.command.includes("=")) return null;
  for (const t of [server.command, ...server.args]) {
    const q = gooseQuoteToken(t);
    if (q === null) return null;
    parts.push(q);
  }
  return `${name}:${parts.join(" ")}`;
}

/** Where the launcher's `--with-extension` flags go: right after the
 *  `session` / `run` subcommand (the flags belong to it; Goose's top level
 *  takes none). argv unchanged for a wrapper, a bare or help/version argv,
 *  any other subcommand, or no extensions. Pure. */
export function gooseSpliceExtensions(argv: readonly string[], extensionArgs: readonly string[]): string[] {
  const g = readGooseArgv(argv);
  if (!g || extensionArgs.length === 0 || (g.command !== "session" && g.command !== "run")) return [...argv];
  const at = g.subIndex + 1;
  return [...argv.slice(0, at), ...extensionArgs, ...argv.slice(at)];
}
