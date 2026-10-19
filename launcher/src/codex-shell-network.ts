/**
 * codex-shell-network — turn the network of Codex's OWN command sandbox on for
 * a `mandu codex` launch, out loud (supported-agents.md §6.5).
 *
 * WHY (measured 2026-10-04, codex-cli 0.160, supported-agents.md §6.4): Codex
 * runs every shell command in `codex-linux-sandbox`, and in its workspace-write
 * mode with the network off (Codex's default) a seccomp filter refuses every
 * `connect(2)`, Unix sockets included. Its ERRNO answer outranks the guard's
 * user-notification one in the kernel's filter stack, so Mandu's checks never
 * see the call: the exec-wrap shim cannot ask the arbiter (exit 77, "the
 * sandbox this command runs in refuses its connection to Mandu"), and a
 * `curl` with a bound key, the request Mandu exists to let through, can never
 * run. Under Claude Code the same request works.
 *
 * DECISION (2026-10-05, revising §6.4's "never touch Codex's sandbox"): a
 * launch adds `-c sandbox_workspace_write.network_access=true` by default,
 * and says so on every launch. Only where Mandu's own walls stand in for the
 * one it opens:
 *   - the connect guard came up (net-guard: every connect decided by
 *     destination; the Unix-socket allow-list that refuses the D-Bus session
 *     bus, docker and the like, which a bare Codex with its network on leaves
 *     reachable: exec-routing.md §4.3);
 *   - the confidentiality axis is on (that allow-list rides it; in `off`
 *     nothing is enforced, so Codex's wall is the only one);
 *   - Linux (the guard's platform). macOS's sandbox choice is handled
 *     separately by codex-sandbox.ts; this option does not restore it when
 *     Mandu's whole-agent Seatbelt profile turns it off.
 * And never over the user's own choice: an explicit network setting anywhere
 * Codex reads one (the command line, the user / profile / project / system
 * config files, a permission profile) or an administrator's managed sandbox
 * settings keep Codex as configured. The scan over-detects on purpose (a
 * commented-out line does not count, any other mention does): a false hit
 * only leaves Codex at its own default, the safe direction. A command line
 * that picks a sandbox where the key does nothing (`-s read-only`,
 * `danger-full-access`, the bypass flag) gets no splice and no notice.
 *
 * Opt-out: `--no-codex-shell-network`, `MANDU_CODEX_SHELL_NETWORK=0`, or
 * `codex-shell-network = false` in ~/.mandu/config.toml.
 *
 * Pure decision (`codexShellNetworkDecision`, unit-tested); the one I/O
 * wrapper reads the candidate config files (`readCodexNetworkLayers`).
 * Mandu-new (no reference origin).
 */
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

/** The override a launch adds (spliced at every Codex command level). */
export const CODEX_SHELL_NETWORK_OVERRIDE = ["-c", "sandbox_workspace_write.network_access=true"] as const;

/** Codex's system-wide config layers (0.160 binary strings). */
export const CODEX_SYSTEM_CONFIG = "/etc/codex/config.toml";
export const CODEX_MANAGED_FILES = ["/etc/codex/managed_config.toml", "/etc/codex/requirements.toml"] as const;

/** One config file Codex may read, with its text (null = absent/unreadable). */
export interface CodexConfigLayer {
  path: string;
  /** `managed`: an administrator's file; any sandbox or network setting there decides. */
  kind: "user" | "managed";
  text: string | null;
}

export interface CodexShellNetworkInput {
  /** plan.codexShellNetwork: undefined = default (on), false = opted out, true = asked. */
  wanted: boolean | undefined;
  /** The user's Codex argv, argv[0] included. */
  argv: readonly string[];
  layers: readonly CodexConfigLayer[];
  /** The connect guard came up for this launch (run.ts applyNetGuard). */
  guarded: boolean;
  /** The confidentiality axis is on for this launch (effective). */
  confidentiality: boolean;
  linux: boolean;
}

export type CodexShellNetworkDecision =
  | { open: true; note: string }
  | { open: false; reason: "opted-out" | "user-setting" | "managed" | "sandbox-mode" | "no-guard" | "not-linux" | "off-axis"; note: string | null };

/** Codex flags that take a value (a value is never read as a flag). */
const VALUE_FLAGS = new Set([
  "-c", "--config", "--enable", "--disable", "--remote", "--remote-auth-token-env", "-i", "--image",
  "-m", "--model", "--local-provider", "-p", "--profile", "-s", "--sandbox", "-C", "--cd", "--add-dir",
  "-a", "--ask-for-approval", "--thread-source", "--output-schema", "--color", "-o", "--output-last-message",
]);

/** A `-c` key that sets the shell network, or a permission profile (which
 *  carries its own network setting). */
function networkKey(key: string): boolean {
  const k = key.trim().replace(/["']/g, "");
  return k === "sandbox_workspace_write" || k.endsWith("network_access") || k.includes(".network_access") ||
    k === "default_permissions" || k === "permissions" || k.startsWith("permissions.") ||
    (k.startsWith("profiles.") && (k.endsWith(".sandbox_workspace_write") || k.endsWith(".default_permissions")));
}

/** What the command line says: an explicit network setting, the sandbox it
 *  picks, and the profile it names. Tokens after `--` are prompt text. Pure. */
export function codexArgvSandbox(argv: readonly string[]): { networkSet: string | null; sandbox: string | null; profile: string | null } {
  let networkSet: string | null = null;
  let sandbox: string | null = null;
  let profile: string | null = null;
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--") break;
    let kv: string | undefined;
    if (a === "-c" || a === "--config") kv = argv[++i];
    else if (a.startsWith("--config=")) kv = a.slice("--config=".length);
    else if (a.startsWith("-c") && a.length > 2 && !a.startsWith("--")) kv = a.slice(2);
    else if (a === "-s" || a === "--sandbox") { sandbox = argv[++i] ?? null; continue; }
    else if (a.startsWith("--sandbox=")) { sandbox = a.slice("--sandbox=".length); continue; }
    else if (a === "-p" || a === "--profile") { profile = argv[++i] ?? null; continue; }
    else if (a.startsWith("--profile=")) { profile = a.slice("--profile=".length); continue; }
    else if (a === "--full-auto") { sandbox = "workspace-write"; continue; }
    else if (a === "--dangerously-bypass-approvals-and-sandbox" || a === "--yolo") { sandbox = "danger-full-access"; continue; }
    else if (VALUE_FLAGS.has(a)) { i++; continue; }
    if (kv === undefined) continue;
    const eq = kv.indexOf("=");
    if (eq <= 0) continue;
    const key = kv.slice(0, eq);
    if (networkKey(key)) networkSet = `-c ${kv}`;
    if (key.trim() === "sandbox_mode") sandbox = kv.slice(eq + 1).trim().replace(/^["']|["']$/g, "");
  }
  return { networkSet, sandbox, profile };
}

/** The file's text without its whole-line comments. A trailing `# …` stays:
 *  a mention there over-detects, the safe side. */
function uncommented(text: string): string {
  return text.split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
}

/** A user layer sets the shell network, or a permission profile. */
const USER_NETWORK = /\bnetwork_access\b|^\s*default_permissions\s*=|^\s*\[\s*permissions\b|^\s*permissions\s*[.=]/m;
/** A managed layer constrains the sandbox or the network at all. */
const MANAGED_SANDBOX = /network|sandbox|permissions/;

/** The first config layer that holds the user's (or an administrator's)
 *  network choice, or null. Pure. */
export function codexConfigNetworkSetting(layers: readonly CodexConfigLayer[]): CodexConfigLayer | null {
  for (const l of layers) {
    if (l.text === null) continue;
    const t = uncommented(l.text);
    if ((l.kind === "managed" ? MANAGED_SANDBOX : USER_NETWORK).test(t)) return l;
  }
  return null;
}

/** The launch line (full form; launch-banner.ts compactNotice shortens it). */
export const OPEN_NOTE =
  "mandu: Codex's command sandbox network is ON for this launch (-c sandbox_workspace_write.network_access=true): " +
  "commands Codex runs can reach Mandu's checks and the network, and Mandu's connect guard and egress gate decide " +
  "where they connect and what they send. Codex's own default keeps it off: --no-codex-shell-network, " +
  "MANDU_CODEX_SHELL_NETWORK=0, or codex-shell-network = false in ~/.mandu/config.toml";

/** Decide. Pure. */
export function codexShellNetworkDecision(input: CodexShellNetworkInput): CodexShellNetworkDecision {
  if (input.wanted === false) return { open: false, reason: "opted-out", note: null };
  // On macOS the other adapter may disable Codex's sandbox altogether.
  // Its network key then has no effect, so claiming it was kept is misleading.
  if (!input.linux) return { open: false, reason: "not-linux", note: null };
  const cli = codexArgvSandbox(input.argv);
  if (cli.sandbox !== null && cli.sandbox !== "workspace-write") {
    // The key does nothing in that sandbox: nothing to splice, nothing to say.
    return { open: false, reason: "sandbox-mode", note: null };
  }
  if (cli.networkSet !== null) {
    return { open: false, reason: "user-setting", note: `mandu: Codex's command sandbox network left as your command line sets it (${cli.networkSet})` };
  }
  const layer = codexConfigNetworkSetting(input.layers);
  if (layer !== null) {
    return layer.kind === "managed"
      ? { open: false, reason: "managed", note: `mandu: Codex's command sandbox network left as your administrator's ${layer.path} sets it` }
      : { open: false, reason: "user-setting", note: `mandu: Codex's command sandbox network left as ${layer.path} sets it` };
  }
  // Mandu's walls must stand in for the one this opens. Each stays quiet in
  // the compact display: the guard's own absence is already a loud line.
  if (!input.confidentiality) {
    return { open: false, reason: "off-axis", note: "mandu: Codex's command sandbox network stays off (Codex's default): nothing is enforced in this mode" };
  }
  if (!input.guarded) {
    return {
      open: false,
      reason: "no-guard",
      note: "mandu: Codex's command sandbox network stays off (Codex's default): Mandu's connect guard is not running, so nothing would decide where commands connect",
    };
  }
  return { open: true, note: OPEN_NOTE };
}

/**
 * The config files Codex may read for this launch, in no particular order:
 * the user's (`$CODEX_HOME/config.toml`, the named profile's
 * `<name>.config.toml`), each `.codex/config.toml` from the working
 * directories up to `/`, and the system and managed files. Never throws.
 */
export function readCodexNetworkLayers(opts: {
  home: string;
  codexHome?: string;
  cwds: readonly string[];
  profile: string | null;
  readFile?: (p: string) => string | null;
}): CodexConfigLayer[] {
  const read = opts.readFile ?? ((p: string) => { try { return readFileSync(p, "utf8"); } catch { return null; } });
  const codexHome = opts.codexHome !== undefined && opts.codexHome !== "" ? opts.codexHome : join(opts.home, ".codex");
  const userPaths = [join(codexHome, "config.toml")];
  if (opts.profile !== null && /^[\w.-]+$/.test(opts.profile)) userPaths.push(join(codexHome, `${opts.profile}.config.toml`));
  for (const cwd of opts.cwds) {
    for (let d = resolve(cwd); ; d = dirname(d)) {
      userPaths.push(join(d, ".codex", "config.toml"));
      if (dirname(d) === d) break;
    }
  }
  userPaths.push(CODEX_SYSTEM_CONFIG);
  const seen = new Set<string>();
  const out: CodexConfigLayer[] = [];
  for (const p of userPaths) {
    if (seen.has(p)) continue;
    seen.add(p);
    out.push({ path: p, kind: "user", text: read(p) });
  }
  for (const p of CODEX_MANAGED_FILES) out.push({ path: p, kind: "managed", text: read(p) });
  return out;
}
