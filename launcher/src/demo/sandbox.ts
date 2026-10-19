/**
 * demo/sandbox — the throwaway world `mandu demo` runs in (mandu-demo.md §5).
 *
 * Everything the demo's services could write lands under ONE temp directory:
 * HOME and every XDG root, the symbol database, the event store, the runtime
 * dir (sockets, port files, logs), the policy file and the config file. The
 * user's real HOME, config, symbol table and running Mandu stack are never
 * read or written: the demo env is built from a small allow-list of the
 * caller's env (PATH, locale, terminal, node), never from a copy of it, so an
 * exported MANDU_ARBITER_SOCK or ANTHROPIC_API_KEY cannot leak in.
 *
 * Pure except `createSandbox` (mkdtemp + mkdir). Mandu-new (no reference origin).
 */
import { mkdirSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { manduPath } from "../generated/mandu-paths.js";

type Env = Record<string, string | undefined>;

/** The Unix socket limit (sun_path, incl. NUL) on the strictest platform we
 *  run on (macOS 104; Linux is 108). A socket path must stay BELOW it. */
export const SOCK_PATH_MAX = 104;

export interface SandboxPaths {
  root: string;
  /** The fake project: YOUR files (the real fake `.env`). */
  project: string;
  /** The project as the agent sees it under Mandu: the same files, with
   *  `.env` replaced by Mandu's placeholder copy (a real session mounts that
   *  copy over the file; the demo keeps it beside it). */
  agentView: string;
  home: string;
  /** The sandbox's Mandu home (MANDU_HOME): its symbol DB, events and (absent)
   *  config.toml, so nothing of the caller's `~/.mandu` is read or written. */
  manduHome: string;
  /** Runtime dir: sockets, port files, service logs. */
  run: string;
  arbiterSock: string;
  /** Port files the services publish (MANDU_PORT_FILE). */
  claudeProxyPortFile: string;
  codexProxyPortFile: string;
  netProxyPortFile: string;
  /** The egress proxy's session CA (its TLS inspection). */
  mitmCaDir: string;
  /** The stand-in sites' CA and certificate. */
  sitesDir: string;
  /** The egress proxy's host routes to the stand-in sites. */
  routesFile: string;
  symbolDb: string;
  eventDir: string;
  /** Where the agent's reply is staged for the reply filter's child. */
  replyFile: string;
  /** Every request body the model received, one JSON line each (kept with
   *  --keep): `{"wire": …, "body": …}`. */
  modelRequests: string;
}

/** The layout under `root`. Pure. The socket sits one level down with a
 *  short name so the whole path stays well under SOCK_PATH_MAX. */
export function sandboxPaths(root: string): SandboxPaths {
  const run = join(root, "run");
  const home = join(root, "home");
  const manduHome = join(root, "mandu");
  return {
    root,
    project: join(root, "project"),
    agentView: join(root, "agent-view"),
    home,
    manduHome,
    run,
    arbiterSock: join(run, "a.sock"),
    claudeProxyPortFile: join(run, "anthropic-proxy.port"),
    codexProxyPortFile: join(run, "openai-proxy.port"),
    netProxyPortFile: join(run, "net-proxy.port"),
    mitmCaDir: join(run, "egress-ca"),
    sitesDir: join(run, "sites"),
    routesFile: join(run, "sites.yaml"),
    symbolDb: manduPath("symbol-db", { MANDU_HOME: manduHome }, home),
    eventDir: manduPath("events", { MANDU_HOME: manduHome }, home),
    replyFile: join(run, "reply.txt"),
    modelRequests: join(run, "model-requests.jsonl"),
  };
}

/** True when a Unix socket path fits (bytes, with room for the NUL). Pure. */
export function sockPathFits(path: string): boolean {
  return Buffer.byteLength(path, "utf8") < SOCK_PATH_MAX;
}

/** The longest arbiter instance id (arbiter/ipc/instance.ts `instanceId`:
 *  `yyyymmdd-hhmm-<rev ≤16>-p<pid ≤7 digits>`, 39), rounded up. */
const INSTANCE_ID_MAX = 40;

/** The longest socket path a sandbox at `root` binds: the arbiter's
 *  human-plane socket, `<runtime dir>/human/<instance id>.sock`
 *  (arbiter-human-plane.md §3), which is longer than `run/a.sock`. Pure. */
export function longestSockPath(root: string): string {
  return join(sandboxPaths(root).run, "mandu", "human", `${"x".repeat(INSTANCE_ID_MAX)}.sock`);
}

/**
 * Pick the temp base: $TMPDIR when every socket path it yields fits, else
 * /tmp (a long TMPDIR, e.g. a CI or sandboxed tool dir, would truncate a
 * socket at bind(2), and the arbiter refuses to start). The 16 bytes budget
 * for `/mandu-demo-XXXXXX`. Pure.
 */
export function pickTempBase(tmpdir: string): string {
  const root = join(tmpdir, "mandu-demo-XXXXXX");
  return sockPathFits(sandboxPaths(root).arbiterSock) && sockPathFits(longestSockPath(root)) ? tmpdir : "/tmp";
}

/** Env names carried over from the caller: what node, git-free tools and the
 *  terminal need. Nothing MANDU_*, ANTHROPIC_*, HOME or XDG_* is inherited. */
const INHERIT = ["PATH", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "COLORTERM", "NO_COLOR", "TZ", "NODE_OPTIONS", "NODE_EXTRA_CA_CERTS"];

/** The sandbox's XDG roots and TMPDIR, each under the sandbox. Pure. */
function sandboxRoots(p: SandboxPaths): Record<string, string> {
  return {
    XDG_CONFIG_HOME: join(p.home, ".config"),
    XDG_STATE_HOME: join(p.home, ".local", "state"),
    XDG_DATA_HOME: join(p.home, ".local", "share"),
    XDG_CACHE_HOME: join(p.home, ".cache"),
    XDG_RUNTIME_DIR: p.run,
    TMPDIR: join(p.root, "tmp"),
  };
}

/**
 * The env every demo process runs under. Pure. `mode` is stated twice on
 * purpose: MANDU_MODE for the arbiter's named mode AND the explicit axis
 * pair, so the demo shows `secrets` whatever the caller's config says (the
 * sandbox's Mandu home has no config.toml).
 */
export function sandboxEnv(caller: Env, p: SandboxPaths): Record<string, string> {
  const env: Record<string, string> = {};
  for (const k of INHERIT) {
    const v = caller[k];
    if (v !== undefined && v !== "") env[k] = v;
  }
  if (!env["PATH"]) env["PATH"] = "/usr/local/bin:/usr/bin:/bin";
  const roots = sandboxRoots(p);
  return {
    ...env,
    HOME: p.home,
    ...roots,
    // Mandu's own locations inside the sandbox, from the path table
    // (on-disk-layout.md §5): the whole home moves with MANDU_HOME.
    MANDU_HOME: p.manduHome,
    MANDU_POLICY_FILE: manduPath("policy", { ...roots, MANDU_HOME: p.manduHome }, p.home),
    MANDU_RUNTIME_DIR: manduPath("runtime-dir", roots, p.home),
    MANDU_ARBITER_SOCK: p.arbiterSock,
    MANDU_MODE: "secrets",
    MANDU_CONFIDENTIALITY: "1",
    MANDU_INTEGRITY: "0",
    // The dashboard supervisor is not part of the demo.
    MANDU_AUTOSTART_SUPERVISOR: "0",
    // Should anything in the demo's tree run npm: no update check (it would
    // be a network call and a notice).
    NPM_CONFIG_UPDATE_NOTIFIER: "false",
    // node (and tsx) flush a compile cache into TMPDIR as they EXIT, which
    // races the sandbox's removal right after the services are stopped.
    NODE_DISABLE_COMPILE_CACHE: "1",
  };
}

/** Create the sandbox tree under a fresh temp dir. */
export function createSandbox(tmpBase: string): SandboxPaths {
  const root = mkdtempSync(join(tmpBase, "mandu-demo-"));
  const p = sandboxPaths(root);
  for (const d of [p.project, p.agentView, p.home, p.run, p.manduHome, join(root, "tmp")]) {
    mkdirSync(d, { recursive: true, mode: 0o700 });
  }
  return p;
}
