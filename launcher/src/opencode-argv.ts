/**
 * opencode-argv — the OpenCode 2 launch shapes `mandu opencode` accepts (every
 * 2.x launch, agent-versions.ts), and the `--standalone` each of them
 * gets. An ALLOWLIST (fail-closed): every shape, subcommand and
 * flag not listed here is refused before anything launches
 * (supported-agents.md §2.3, part 1 of "What full OpenCode 2 support needs").
 *
 * WHY (OpenCode 2.0.23, read from its `--help` and its bundled code, and
 * probed with two scripted local upstreams, 2026-10-05): OpenCode 2's CLI is
 * a CLIENT of an OpenCode server, and the server runs the model calls and the
 * tools. By default the client joins the user's BACKGROUND SERVICE (found
 * through `$XDG_STATE_HOME/opencode/service.json`, started on demand as
 * `opencode serve --service`, a daemon that outlives the launch), which runs
 * with the configuration and environment it was started with: a service
 * started outside Mandu sends the turn to its own endpoint, around the
 * model proxy, and runs the tools outside every confinement. `--standalone`
 * instead spawns a PRIVATE server (`opencode serve --stdio --port 0`), a
 * child of the client that inherits this launch's routing and wrap, writes
 * no service registration, and is stopped with the client (SIGTERM). So:
 *   - bare `opencode [dir]` (the TUI), `opencode run …` and `opencode mini`
 *     are allowed, and get `--standalone` (after `opencode` for the TUI,
 *     after the subcommand for `run` / `mini`: OpenCode reads a flag only
 *     there; one put before a subcommand is a usage error);
 *   - `--server <url>` (join that server instead) is refused: the model calls
 *     and tools run in that server, with its settings;
 *   - `serve` (a server other clients drive), `service` (the background
 *     service itself), `pair` (links that connect a browser or app to it),
 *     `api` (a request to the running server), `acp` (an ACP server; not a
 *     shape Mandu has checked) are refused, as OpenClaw's Gateway shapes are
 *     (openclaw-argv.ts);
 *   - `session`, `auth`, `mcp`, `plugin`, `models`, `stats`, `reload`,
 *     `debug`, `upgrade` / `update`, `uninstall` are management: run them
 *     without `mandu` (`auth export` prints credentials; `models`, `stats`
 *     and `reload` talk to the background service);
 *   - `--wizard` builds a command interactively, and the command it builds is
 *     never checked: refused;
 *   - a flag OpenCode 2.0.23 does not list for the shape is refused (a later
 *     release could add one that changes where the session runs), and so is
 *     a `--flag=value` spelling of a switch (`--standalone=false`).
 * `--help` / `-h` / `--version` / `-v` print and exit (verified on 2.0.23):
 * the argv passes unchanged, for an allowed shape wherever the flag stands
 * outside a value, for a refused subcommand only right after it.
 *
 * Applied to OpenCode 2 (agent-versions.ts opencodeGeneration): the parse
 * step does not know the version, so run.ts applies this right after the
 * version check. An argv the launcher cannot read as OpenCode (a wrapper
 * script passed with `--target opencode`) is not checked: `--target` is the
 * user vouching for the wrapper, the contract parse.ts applies to every
 * wrapper target.
 *
 * OPENCODE 1 (`opencode1LaunchArgv`, 2026-10-11) gets the same refusal of
 * its server and management subcommands, with the same message; its argv is
 * otherwise passed unchanged (1.x has no background service, so no
 * `--standalone`, and its flags are not allowlisted). Found on a live walk
 * of the first-session tour: `mandu opencode serve` ran inside the session
 * (and failed there), `mandu opencode auth list` ran. Read from 1.18.13's
 * `opencode --help`: the TUI (`opencode [project]`) and `run` are allowed;
 * `serve`, `web` (a server a browser drives), `attach` and `run --attach`
 * (join a running server), `acp`, `pr` (checks out a branch, then starts
 * OpenCode: a shape not checked) and `github` are refused, and so are the
 * management commands `providers` / `auth`, `mcp`, `agent`, `session`,
 * `export`, `import`, `db`, `models`, `stats`, `plugin` / `plug`, `debug`,
 * `upgrade`, `uninstall`, `completion`. OpenCode 1 reads a subcommand after
 * its flags (yargs), so a TUI argv whose positional names a subcommand is
 * refused too (`opencode --print-logs serve` is `serve`). The TUI flags
 * that make its built-in server listen (`--port`, `--hostname`, `--mdns`:
 * LISTEN_FLAGS_V1) are refused as well.
 *
 * OpenCode 2 has no such TUI flag: `--port` / `--hostname` are flags of
 * `serve` only (refused), the allowlist refuses them on every allowed
 * shape, and the private server `--standalone` spawns is `serve --stdio
 * --port 0`, whose hostname is the `--hostname` flag or 127.0.0.1 (the
 * service configuration is read only in `--service` mode; 2.0.23's bundled
 * `serve`): an ephemeral loopback port whatever the configuration says.
 *
 * What `--standalone` does not cover: an `opencode run` the AGENT starts in
 * its own shell joins the user's service unless the kernel rungs refuse the
 * connect (they do: landlock-net and the net guard admit only Mandu's
 * loopback ports; supported-agents.md §2.3 has the measurement). Under those
 * rungs the private server itself runs because the guard performs its
 * ephemeral loopback bind and admits its client, and only its client, to it
 * (run.ts sets `plan.ownServerExe`; net-supervisor own_server.rs, §2.3.1).
 *
 * CONFIDENTIALITY ON is allowed only with its guards in force
 * (opencode2-confidentiality.ts, run.ts, 2026-10-05). The private server is a
 * loopback HTTP server, and the agent's own tools run as its children: a
 * `shell` command can read the server's password from `/proc/$PPID/environ`
 * (OPENCODE_PASSWORD) and the session id from OPENCODE_SESSION_ID, and call
 * `POST /api/session/<id>/shell` (or `/synthetic`, `/prompt`): the command's
 * output would reach the model as "The following shell command was executed
 * by the user: <shell …>…</shell>", a USER message (measured on 2.0.23). The
 * guard's allowance admits only the client to that port, and the proxy reads
 * those texts as tool output; so in a confidentiality-ON mode the launch
 * needs the guard (and the write-protect guard and the config lockdown),
 * and is refused without them.
 *
 * Pure; unit-tested in test/unit/opencode-argv.test.ts.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code, modeled on
 * goose-argv.ts and openclaw-argv.ts.
 */
import { basename } from "node:path";

/** The OpenCode 2 release this allowlist was read from. */
export const OPENCODE2_ARGV_VERSION = "2.0.23";

/** The flag that keeps the server private (a child of the client). */
export const STANDALONE_FLAG = "--standalone";

/** Every subcommand OpenCode 2.0.23 lists (`opencode --help`). */
const SUBCOMMANDS = new Set([
  "upgrade", "update", "uninstall", "acp", "api", "debug", "auth", "mcp", "plugin", "models", "stats",
  "mini", "run", "session", "service", "reload", "pair", "serve",
]);

const HELP_OR_VERSION = new Set(["-h", "--help", "-v", "--version"]);

interface FlagSpec {
  /** switches (no value) */
  bool: ReadonlySet<string>;
  /** flags that take a value (`--flag v` or `--flag=v`) */
  value: ReadonlySet<string>;
}

/** Global flags every shape takes (`--wizard` is refused separately). */
const GLOBAL_BOOL = ["-h", "--help", "-v", "--version", "--print-logs"];
const GLOBAL_VALUE = ["--log-level", "--completions"];

const spec = (bool: string[], value: string[]): FlagSpec => ({
  bool: new Set([...GLOBAL_BOOL, ...bool]),
  value: new Set([...GLOBAL_VALUE, ...value]),
});

/** The allowed shapes and their flags, from each one's `--help` (2.0.23),
 *  without `--server` (refused). "" is the TUI (`opencode [dir]`). */
const SHAPES: Readonly<Record<"" | "run" | "mini", FlagSpec>> = {
  "": spec(["--standalone", "--auto", "--continue", "-c"], ["--session", "-s", "--prompt"]),
  run: spec(
    ["--standalone", "--continue", "-c", "--fork", "--thinking", "--auto"],
    ["--session", "-s", "--model", "-m", "--agent", "--format", "--file", "-f", "--title"],
  ),
  mini: spec(
    ["--standalone", "--continue", "-c", "--fork", "--replay", "--no-replay"],
    ["--session", "-s", "--replay-limit", "--model", "-m", "--agent", "--prompt"],
  ),
};

export interface Opencode2Argv {
  /** the subcommand, or "" for the TUI (`opencode [flags] [dir]`) */
  sub: string;
  /** index in argv of the subcommand token, -1 for the TUI */
  subIndex: number;
}

/** Read an agent argv as an OpenCode invocation (`opencode` or `opencode2`),
 *  or null when argv[0] is neither (a wrapper script). The subcommand is
 *  argv[1] when it names one; anything else is the TUI. Pure. */
export function readOpencode2Argv(argv: readonly string[]): Opencode2Argv | null {
  if (argv.length === 0) return null;
  const b0 = basename(argv[0]!);
  if (b0 !== "opencode" && b0 !== "opencode2") return null;
  const first = argv[1];
  if (first !== undefined && SUBCOMMANDS.has(first)) return { sub: first, subIndex: 1 };
  return { sub: "", subIndex: -1 };
}

/** The flag name of a token: `--name` of `--name=v`; the token itself otherwise. */
function flagName(tok: string): string {
  return tok.startsWith("--") && tok.includes("=") ? tok.slice(0, tok.indexOf("=")) : tok;
}

/** Why each refused subcommand is refused, and what to do instead (OpenCode 2). */
function subcommandRefusal(sub: string): { why: string; instead: string } {
  const outside = "Run it without `mandu`.";
  switch (sub) {
    case "serve":
      return {
        why: "`opencode serve` starts an OpenCode server that other clients (a browser, an app, `--server`) drive: their model calls and tools would run in it, outside what this launch checks.",
        instead: "Use `mandu opencode` (the TUI) or `mandu opencode run …`: they run with a private server inside Mandu.",
      };
    case "service":
      return {
        why: "`opencode service` manages the background service, which runs the model calls and tools of every OpenCode client that joins it, with its own settings, outside Mandu.",
        instead: outside,
      };
    case "pair":
      return { why: "`opencode pair` prints links that connect a browser or app to the background server, outside Mandu.", instead: outside };
    case "api":
      return { why: "`opencode api` sends a request to a running server (the background service by default), outside this launch.", instead: outside };
    case "acp":
      return {
        why: "`opencode acp` (an Agent Client Protocol server) is not a shape Mandu has checked yet.",
        instead: "Use `mandu opencode` (the TUI) or `mandu opencode run …`.",
      };
    case "session":
      return { why: "`opencode session` manages saved sessions (`session export` prints a whole session, tool output included); it is not the agent.", instead: outside };
    case "auth":
      return { why: "`opencode auth` manages credentials (`auth export` prints them); it is not the agent.", instead: outside };
    case "mcp":
      return { why: "`opencode mcp` edits the MCP server configuration and signs in to MCP servers; it is not the agent.", instead: outside };
    case "plugin":
      return { why: "`opencode plugin` installs and removes plugins; it is not the agent.", instead: outside };
    case "models":
    case "stats":
    case "reload":
      return { why: `\`opencode ${sub}\` talks to the background service; it is not the agent.`, instead: outside };
    case "debug":
      return { why: "`opencode debug` is a troubleshooting tool; it is not the agent.", instead: outside };
    case "upgrade":
    case "update":
    case "uninstall":
      return { why: `\`opencode ${sub}\` changes the OpenCode installation; it is not the agent.`, instead: outside };
    default:
      return {
        why: `\`opencode ${sub}\` is not an agent shape Mandu confines (allowed: the TUI, run, mini, --help, --version).`,
        instead: outside,
      };
  }
}

/**
 * The launch argv for OpenCode 2: the user's argv with `--standalone` added
 * where it belongs, or the refusal. Pure. A wrapper (argv[0] not `opencode` /
 * `opencode2`) passes unchanged.
 */
export function opencode2LaunchArgv(argv: readonly string[]): { argv: string[]; refusal: null } | { argv: null; refusal: string } {
  const oc = readOpencode2Argv(argv);
  if (oc === null) return { argv: [...argv], refusal: null };
  const bin = basename(argv[0]!);
  const shown = `${bin}${oc.sub ? ` ${oc.sub}` : ""}`;
  const refuse = (why: string, instead: string) => ({ argv: null, refusal: `mandu: refusing \`${shown}\`: ${why} ${instead}` });
  const flags = oc.sub === "" || oc.sub === "run" || oc.sub === "mini" ? SHAPES[oc.sub] : null;
  const from = oc.sub === "" ? 1 : oc.subIndex + 1;
  const tokens = argv.slice(from);

  if (flags === null) {
    // `opencode <sub> --help` prints and exits. Only right after the
    // subcommand: further on, Mandu does not know the subcommand's value
    // flags, so it cannot tell a `--help` from a flag's value.
    if (tokens[0] !== undefined && HELP_OR_VERSION.has(tokens[0])) return { argv: [...argv], refusal: null };
    const r = subcommandRefusal(oc.sub);
    return refuse(r.why, r.instead);
  }

  const instead = "Use `mandu opencode` (the TUI), `mandu opencode run …` or `mandu opencode mini`: Mandu runs them with a private server.";
  let standalone = false;
  for (let k = 0; k < tokens.length; k++) {
    const tok = tokens[k]!;
    if (tok === "--") break; // the rest is the message
    if (!tok.startsWith("-") || tok === "-") {
      // A positional: the TUI's directory, run's message. A subcommand name
      // here means flags were put before it.
      if (oc.sub === "" && SUBCOMMANDS.has(tok)) {
        return refuse(
          `\`${tok}\` comes after other arguments; OpenCode reads a subcommand only as the first argument, with its flags after it.`,
          `Write it as \`${bin} ${tok} [flags]\`.`,
        );
      }
      continue;
    }
    const name = flagName(tok);
    if (name === "--server") {
      return refuse(
        "--server joins that OpenCode server instead, and the server runs the model calls and tools with its own settings, outside this launch.",
        "Leave --server out: Mandu runs OpenCode with a private server (--standalone) inside the session.",
      );
    }
    if (name === "--wizard") {
      return refuse("--wizard builds a command interactively, and Mandu cannot check the command it builds.", "Type the command instead.");
    }
    if (flags.value.has(name)) {
      if (name === tok) k++; // `--flag value`
      continue;
    }
    if (flags.bool.has(name) && name === tok) {
      if (tok === STANDALONE_FLAG) standalone = true;
      if (HELP_OR_VERSION.has(tok)) return { argv: [...argv], refusal: null };
      continue;
    }
    return refuse(
      `${tok} is not a flag Mandu knows for \`${shown}\` (OpenCode ${OPENCODE2_ARGV_VERSION}); an unknown flag could change where the session runs.`,
      `Leave it out, or run it without \`mandu\`. ${instead}`,
    );
  }
  if (standalone) return { argv: [...argv], refusal: null };
  const at = oc.sub === "" ? 1 : oc.subIndex + 1;
  return { argv: [...argv.slice(0, at), STANDALONE_FLAG, ...argv.slice(at)], refusal: null };
}

// ── OpenCode 1 ───────────────────────────────────────────────────────────────

/** The OpenCode 1 release the OpenCode 1 command list was read from. */
export const OPENCODE1_ARGV_VERSION = "1.18.13";

/** Every subcommand and alias OpenCode 1.18.13 lists (`opencode --help`). */
const SUBCOMMANDS_V1 = new Set([
  "completion", "acp", "mcp", "attach", "run", "debug", "providers", "auth", "agent", "upgrade", "uninstall",
  "serve", "web", "models", "stats", "export", "import", "github", "pr", "session", "plugin", "plug", "db",
]);

/** The OpenCode 1 subcommands Mandu launches (besides the TUI). */
const ALLOWED_V1 = new Set(["run"]);

/** OpenCode 1.18.13's TUI flags that take a value, skipped when looking for
 *  a subcommand among the positionals (`opencode --prompt serve` is the TUI
 *  with a prompt). An unknown flag's value is read as a positional, which
 *  can only refuse more. */
const TUI_VALUE_V1 = new Set([
  "--log-level", "--port", "--hostname", "--mdns-domain", "--cors", "--model", "-m", "--session", "-s", "--prompt",
  "--agent", "--replay-limit",
]);

/**
 * The OpenCode 1 TUI flags that make its built-in server LISTEN (any
 * spelling: `--port 4096`, `--port=4096`, `--mdns`, `--mdns=true`). Read
 * from 1.18.13's bundled TUI handler (2026-10-11): the TUI talks to its
 * server in-process (`http://opencode.internal`, a worker RPC, no socket)
 * unless `--port` or `--hostname` is in the argv before `--` or `--mdns`
 * turns mDNS on (which also defaults the hostname to 0.0.0.0); then the
 * worker listens on that address and another client could drive the agent.
 * `--mdns-domain` and `--cors` only shape a listener these start, and
 * `--no-mdns` keeps it off: allowed. The TUI resolves these from the argv
 * alone; the `server` block of OpenCode's configuration is read only by
 * `serve`, `web` and `acp` (refused above), and no environment variable sets
 * them. `run --port` is declared but never read in 1.18.13 (`run` talks to
 * its server in-process too): allowed.
 */
const LISTEN_FLAGS_V1 = new Set(["--port", "--hostname", "--mdns"]);

/** Why each refused OpenCode 1 subcommand is refused, and what to do instead. */
function subcommandRefusalV1(sub: string): { why: string; instead: string } {
  const outside = "Run it without `mandu`.";
  const inside = "Run it without `mandu`, or use `mandu opencode` (the TUI) or `mandu opencode run …` to work inside Mandu.";
  switch (sub) {
    case "serve":
      return {
        why: "`opencode serve` starts an OpenCode server that other clients (`opencode attach`, `run --attach`, a browser) drive: their model calls and tools would run in it, outside what this launch checks.",
        instead: inside,
      };
    case "web":
      return { why: "`opencode web` starts an OpenCode server and opens its web interface: what the browser asks runs in that server, outside what this launch checks.", instead: inside };
    case "attach":
      return { why: "`opencode attach` joins a running OpenCode server, and that server runs the model calls and tools with its own settings, outside this launch.", instead: inside };
    case "acp":
      return { why: "`opencode acp` (an Agent Client Protocol server) is not a shape Mandu has checked yet.", instead: inside };
    case "pr":
      return {
        why: "`opencode pr` checks out a GitHub pull request's branch and then starts OpenCode, a shape Mandu has not checked.",
        instead: "Check the branch out first (`gh pr checkout <number>`), then run `mandu opencode`.",
      };
    case "github":
      return { why: "`opencode github` installs and runs OpenCode's GitHub agent (in GitHub Actions); it is not an agent shape Mandu confines.", instead: outside };
    case "providers":
    case "auth":
      return { why: `\`opencode ${sub}\` manages providers and their credentials; it is not the agent.`, instead: outside };
    case "mcp":
      return { why: "`opencode mcp` edits the MCP server configuration and signs in to MCP servers; it is not the agent.", instead: outside };
    case "agent":
      return { why: "`opencode agent` manages agent definitions; it is not the agent.", instead: outside };
    case "session":
      return { why: "`opencode session` manages saved sessions; it is not the agent.", instead: outside };
    case "export":
      return { why: "`opencode export` prints a whole saved session, tool output included; it is not the agent.", instead: outside };
    case "import":
      return { why: "`opencode import` imports a saved session from a file or URL; it is not the agent.", instead: outside };
    case "db":
      return { why: "`opencode db` opens OpenCode's own database (saved sessions, tool output included) in a SQL shell; it is not the agent.", instead: outside };
    case "plugin":
    case "plug":
      return { why: `\`opencode ${sub}\` installs a plugin and changes the configuration; it is not the agent.`, instead: outside };
    case "models":
      return { why: "`opencode models` lists the available models; it is not the agent.", instead: outside };
    case "stats":
      return { why: "`opencode stats` shows token usage and cost; it is not the agent.", instead: outside };
    case "debug":
      return { why: "`opencode debug` is a troubleshooting tool; it is not the agent.", instead: outside };
    case "upgrade":
    case "uninstall":
      return { why: `\`opencode ${sub}\` changes the OpenCode installation; it is not the agent.`, instead: outside };
    case "completion":
      return { why: "`opencode completion` prints a shell completion script; it is not the agent.", instead: outside };
    default:
      return {
        why: `\`opencode ${sub}\` is not an agent shape Mandu confines (allowed: the TUI, run, --help, --version).`,
        instead: outside,
      };
  }
}

/**
 * The launch argv for OpenCode 1: the user's argv unchanged, or the refusal
 * of a server or management subcommand (and of `run --attach`). Pure. A
 * wrapper (argv[0] not `opencode` / `opencode2`) passes unchanged.
 */
export function opencode1LaunchArgv(argv: readonly string[]): { argv: string[]; refusal: null } | { argv: null; refusal: string } {
  const pass: { argv: string[]; refusal: null } = { argv: [...argv], refusal: null };
  if (argv.length === 0) return pass;
  const bin = basename(argv[0]!);
  if (bin !== "opencode" && bin !== "opencode2") return pass;
  const refuseSub = (sub: string): { argv: null; refusal: string } => {
    const r = subcommandRefusalV1(sub);
    return { argv: null, refusal: `mandu: refusing \`${bin} ${sub}\`: ${r.why} ${r.instead}` };
  };
  const first = argv[1];
  const sub = first !== undefined && SUBCOMMANDS_V1.has(first) ? first : "";
  const tokens = argv.slice(sub === "" ? 1 : 2);

  if (sub !== "" && !ALLOWED_V1.has(sub)) {
    // `opencode <sub> --help` prints and exits; only right after the
    // subcommand, as for OpenCode 2.
    if (tokens[0] !== undefined && HELP_OR_VERSION.has(tokens[0])) return pass;
    return refuseSub(sub);
  }
  if (sub === "run") {
    for (const tok of tokens) {
      if (tok === "--") break; // the rest is the message
      if (flagName(tok) === "--attach") {
        return {
          argv: null,
          refusal: `mandu: refusing \`${bin} run\`: --attach joins a running OpenCode server, and that server runs the model calls and tools with its own settings, outside this launch. Leave --attach out: Mandu runs \`opencode run\` inside the session.`,
        };
      }
    }
    return pass;
  }
  // The TUI. OpenCode 1 takes a subcommand after its flags, so a positional
  // that names one is that subcommand (fail closed: also after `--`).
  for (let k = 0; k < tokens.length; k++) {
    const tok = tokens[k]!;
    if (tok === "--") continue;
    if (tok.startsWith("-") && tok !== "-") {
      const name = flagName(tok);
      if (LISTEN_FLAGS_V1.has(name)) {
        return {
          argv: null,
          refusal: `mandu: refusing \`${bin}\`: ${name} makes OpenCode's built-in server listen on a network port, where another client (a browser, \`opencode attach\`, any program that reaches the port) could drive the agent outside what this launch checks. Leave ${name} out: without it the OpenCode 1 TUI talks to its server in-process, with no port open.`,
        };
      }
      if (TUI_VALUE_V1.has(tok)) k++; // `--flag value`
      continue;
    }
    if (!SUBCOMMANDS_V1.has(tok)) continue;
    if (ALLOWED_V1.has(tok)) {
      return {
        argv: null,
        refusal: `mandu: refusing \`${bin}\`: \`${tok}\` comes after other arguments, where Mandu does not read a subcommand. Write it as \`${bin} ${tok} [flags]\`.`,
      };
    }
    return refuseSub(tok);
  }
  return pass;
}
