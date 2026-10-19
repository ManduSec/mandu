/**
 * openclaw-argv — the OpenClaw launch shapes `mandu openclaw` accepts. An
 * ALLOWLIST (fail-closed): every shape not listed here is refused before
 * anything launches.
 *
 * WHY (probe-verified 2026-09-27, openclaw 2026.6.35): the launcher can only
 * protect an OpenClaw process whose agent loop runs INSIDE the wrap and reads
 * the routing config the launcher writes (services/agent-config.ts). Many
 * OpenClaw subcommands do not:
 *   - `tui`, `agent` (without --local), `acp`, `acp client`: Gateway CLIENTS.
 *     The model calls and tools run in the Gateway process, which read its own
 *     config at start and is usually already running outside the wrap (one
 *     listened on the default port 18789 on the dev host). The session looks
 *     protected and protects nothing.
 *   - `gateway start|restart|install|call|…`: drive the Gateway SERVICE
 *     (systemd/launchd) or an already-running Gateway, i.e. outside the wrap.
 *   - bare `openclaw`: onboarding (no config yet) or Crestodian, the setup and
 *     repair assistant: a TUI whose model-assisted planner falls back to the
 *     Claude Code CLI or the Codex app-server harness, which can install
 *     plugins and start or restart the Gateway service. Not the coding agent,
 *     and not a shape whose model traffic this launch routes. `crestodian`
 *     likewise. Bare `mandu openclaw` is mapped to `chat` by parse.ts
 *     (openclawDefaultArgv; decided 2026-09-29): the coding agent is what a
 *     user starting OpenClaw under Mandu means. The refusal below stays for
 *     any caller that skips that mapping.
 *   - `--container <name>` / OPENCLAW_CONTAINER: runs the CLI inside a
 *     Podman/Docker container, outside the wrap.
 *   - everything else (config, models, plugins, channels, message, infer, …):
 *     management or one-off commands with no reason to run under Mandu; run
 *     them without `mandu`.
 * Allowed: `chat` / `terminal` (aliases of `tui --local`), `tui --local`,
 * `agent --local` (the embedded runtime: the agent loop inside the launcher's
 * child), `gateway` / `gateway run` (the Gateway itself under the wrap, so it
 * IS confined and routed), and `--help` / `--version`. The Gateway-client
 * shapes (`tui`, `agent`, `acp`) open with MANDU_OPENCLAW_GATEWAY_CLIENT=1 for
 * a user whose Gateway was itself started under Mandu.
 *
 * An argv the launcher cannot read as OpenClaw (a wrapper script passed with
 * `--target openclaw`) is not checked: `--target` is the user vouching for the
 * wrapper, the same contract parse.ts applies to every wrapper target.
 *
 * Pure; unit-tested in test/unit/openclaw-argv.test.ts.
 */
import { basename } from "node:path";

/** Global options that take a value (`openclaw --help`, 2026.6.35). */
const VALUE_FLAGS = new Set(["--profile", "--container", "--log-level"]);

export interface OpenclawArgv {
  /** the subcommand, or "" for a bare `openclaw [global flags]` */
  sub: string;
  /** args after the subcommand */
  rest: string[];
  /** every global flag before the subcommand (names only) */
  globals: string[];
}

/** Read an agent argv as an OpenClaw invocation, or null when it is not
 *  recognizably one (a wrapper script). Handles the npm bin (`openclaw …`),
 *  a source checkout (`node <dir>/openclaw.mjs …`) and `npx openclaw …`. */
export function readOpenclawArgv(argv: readonly string[]): OpenclawArgv | null {
  if (argv.length === 0) return null;
  let i: number;
  const b0 = basename(argv[0]!);
  if (b0 === "openclaw" || b0 === "openclaw.mjs") i = 1;
  else if ((b0 === "node" || b0 === "bun") && argv[1] && basename(argv[1]) === "openclaw.mjs") i = 2;
  else if ((b0 === "npx" || b0 === "pnpx" || b0 === "bunx") && argv[1] === "openclaw") i = 2;
  else return null;
  const globals: string[] = [];
  while (i < argv.length && argv[i]!.startsWith("-")) {
    const a = argv[i]!;
    const name = a.includes("=") ? a.slice(0, a.indexOf("=")) : a;
    globals.push(name);
    i += VALUE_FLAGS.has(a) ? 2 : 1;
  }
  if (i >= argv.length) return { sub: "", rest: [], globals };
  return { sub: argv[i]!, rest: argv.slice(i + 1), globals };
}

const HELP_OR_VERSION = new Set(["-h", "--help", "-V", "--version"]);

/** Bare `openclaw [global flags]` (no subcommand) runs as `openclaw [global
 *  flags] chat`, the coding agent inside Mandu, instead of onboarding or
 *  Crestodian (which Mandu does not route). Help and version flags, every
 *  subcommand and a wrapper script pass unchanged. Pure. */
export function openclawDefaultArgv(argv: readonly string[]): readonly string[] {
  const oc = readOpenclawArgv(argv);
  if (!oc || oc.sub !== "" || oc.globals.some((g) => HELP_OR_VERSION.has(g))) return argv;
  return [...argv, "chat"];
}

/** The shapes whose agent loop runs in THIS launch's child, in its working
 *  directory: `chat` / `terminal`, `tui --local`, `agent --local`. Not the
 *  Gateway (a long-lived service with its own sessions), not a wrapper the
 *  launcher cannot read. services/agent-config.ts points OpenClaw's workspace
 *  at the launch directory for exactly these. Pure. */
export function openclawRunsLocally(argv: readonly string[]): boolean {
  const oc = readOpenclawArgv(argv);
  if (!oc) return false;
  if (oc.sub === "chat" || oc.sub === "terminal") return true;
  return (oc.sub === "tui" || oc.sub === "agent") && oc.rest.includes("--local");
}
const GATEWAY_CLIENT_OPT_IN = "MANDU_OPENCLAW_GATEWAY_CLIENT";

/** The refusal message for an OpenClaw launch shape outside the allowlist, or
 *  null when it may launch. */
export function openclawLaunchRefusal(
  argv: readonly string[],
  env: Record<string, string | undefined>,
): string | null {
  const oc = readOpenclawArgv(argv);
  if (!oc) return null; // a wrapper: --target vouches for it (see the header)
  const all = [...oc.globals, oc.sub, ...oc.rest];
  if (all.some((a) => HELP_OR_VERSION.has(a)) || oc.sub === "help") return null;

  const shown = `openclaw${oc.sub ? ` ${oc.sub}` : ""}`;
  const refuse = (why: string, instead = "Use `mandu openclaw chat` (= `openclaw tui --local`): the agent runs inside Mandu.") =>
    `mandu: refusing \`${shown}\`: ${why} ${instead}`;

  if (oc.globals.includes("--container") || (env["OPENCLAW_CONTAINER"] ?? "") !== "") {
    return refuse("--container / OPENCLAW_CONTAINER runs OpenClaw inside a container, outside this confinement.");
  }
  const optedIn = env[GATEWAY_CLIENT_OPT_IN] === "1";
  const gatewayClient = (what: string) =>
    optedIn
      ? null
      : refuse(
          `${what} drives an OpenClaw Gateway, and the Gateway (where the model calls and tools run) is a separate ` +
            `process OUTSIDE this confinement that never reads Mandu's routing config, so the session would look ` +
            `protected and protect nothing.`,
          `Use \`mandu openclaw chat\` (= \`openclaw tui --local\`) or \`mandu openclaw agent --local …\`, which run ` +
            `the agent inside Mandu. If the Gateway you connect to was itself started under Mandu ` +
            `(\`mandu openclaw gateway\`), set ${GATEWAY_CLIENT_OPT_IN}=1.`,
        );

  switch (oc.sub) {
    case "chat":
    case "terminal":
      return null;
    case "tui":
    case "agent":
      return oc.rest.includes("--local") ? null : gatewayClient(`\`${shown}\` without --local`);
    case "acp":
      return gatewayClient(`\`openclaw acp\` (an ACP bridge to the Gateway${oc.rest[0] === "client" ? ", spawned by `acp client`" : ""})`);
    case "gateway": {
      // `gateway [flags]` and `gateway run` run the Gateway in the foreground,
      // i.e. as this launch's child. (A flag value such as `--port 1` is not a
      // subcommand: the only bare words `gateway` accepts are subcommands.)
      const valueFlags = new Set(["--port", "--bind", "--auth", "--password", "--password-file", "--token", "--tailscale", "--ws-log", "--raw-stream-path"]);
      let sub: string | undefined;
      for (let k = 0; k < oc.rest.length; k++) {
        const a = oc.rest[k]!;
        if (a.startsWith("-")) { if (valueFlags.has(a)) k++; continue; }
        sub = a; break;
      }
      if (sub === undefined || sub === "run") return null;
      return refuse(
        `\`openclaw gateway ${sub}\` manages the Gateway SERVICE or talks to a running Gateway, outside this confinement.`,
        "Run the Gateway itself under Mandu with `mandu openclaw gateway` (or `gateway run`), or run management commands without `mandu`.",
      );
    }
    case "":
      return refuse(
        "bare `openclaw` starts onboarding or Crestodian, the setup and repair assistant, whose model planner can fall " +
          "back to the Claude Code CLI or Codex and which can start the Gateway service: not a shape Mandu routes.",
      );
    case "crestodian":
      return refuse(
        "Crestodian is the setup and repair assistant: its model planner can fall back to the Claude Code CLI or Codex " +
          "and it can install plugins and start the Gateway service, outside what Mandu routes.",
      );
    default:
      return refuse(
        `\`openclaw ${oc.sub}\` is not an agent shape Mandu confines (allowed: chat, terminal, tui --local, ` +
          `agent --local, gateway [run], --help, --version).`,
        "Run management commands without `mandu`; use `mandu openclaw chat` for the agent.",
      );
  }
}
