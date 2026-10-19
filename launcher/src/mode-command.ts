/**
 * mode-command — `mandu mode [name]` (docs/design/architecture/protection-modes.md §3.2).
 *
 *   mandu mode          print the RUNNING mode (what the attached arbiter
 *                         reports) and the SAVED mode (what config.toml makes
 *                         the next cold start run), then the four modes
 *   mandu mode <name>   save the mode to config.toml through the surgical
 *                         editor (config-edit.ts). Nothing running changes:
 *                         the axes are read once at arbiter start, so the
 *                         command says when a restart is needed.
 *
 * No typed confirmation here, unlike the dashboard's OFF gate: the command
 * line IS the typed intent. A change that turns an axis off prints what stops
 * being covered instead.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code.
 */
import { existsSync, readFileSync } from "node:fs";
import { resolveArbiterSock } from "./arbiter-sock.js";
import { readArbiterAxes, type ArbiterAxes } from "./axis-preflight.js";
import { configPath, parseToml } from "./config.js";
import { writeModeToConfig } from "./config-edit.js";
import {
  DEFAULT_MODE, MODE_AXES, MODES, integrityFrozenMessage, integrityOptedIn, modeHelpLines, modeOf,
  MODE_SUMMARY, parseMode, resolveRequestedAxes, type AxisLevel, type Mode,
} from "./mode.js";

type Env = Record<string, string | undefined>;

export interface ModeCommandDeps {
  /** The axes the arbiter at `sock` reports; {} when none answers. */
  readAxes: (sock: string) => Promise<ArbiterAxes>;
  sockExists: (sock: string) => boolean;
  readFile: (p: string) => string | null;
  writeMode: (path: string, mode: Mode) => void;
  out: (line: string) => void;
  err: (line: string) => void;
}

export const realModeDeps: ModeCommandDeps = {
  readAxes: (sock) => readArbiterAxes(sock, 1500),
  sockExists: (sock) => existsSync(sock),
  readFile: (p) => { try { return existsSync(p) ? readFileSync(p, "utf8") : null; } catch { return null; } },
  writeMode: writeModeToConfig,
  out: (l) => process.stdout.write(l + "\n"),
  err: (l) => process.stderr.write(l + "\n"),
};

/** What the config FILE says (one precedence level). Lenient like the launch
 *  read: an unknown `mode` value is reported, never silently mapped. */
export function configLevel(text: string | null): { level: AxisLevel; badMode?: string } {
  if (text === null) return { level: {} };
  const cfg = parseToml(text);
  const bool = (k: string): boolean | undefined => (k in cfg ? cfg[k] === true || cfg[k] === "true" : undefined);
  const raw = typeof cfg["mode"] === "string" ? (cfg["mode"] as string) : undefined;
  let mode: Mode | undefined;
  let badMode: string | undefined;
  try { mode = parseMode(raw, "config.toml"); } catch { badMode = raw; }
  return {
    level: { mode, integrity: bool("integrity"), confidentiality: bool("confidentiality") },
    ...(badMode !== undefined ? { badMode } : {}),
  };
}

/** The mode the next COLD start runs from this config level alone. */
export function savedMode(level: AxisLevel): { mode: Mode; explicit: boolean } {
  const req = resolveRequestedAxes([level]);
  const d = MODE_AXES[DEFAULT_MODE];
  return {
    mode: modeOf({
      integrity: req.integrity ?? d.integrity,
      confidentiality: req.confidentiality ?? d.confidentiality,
    }),
    explicit: req.integrity !== undefined || req.confidentiality !== undefined,
  };
}

function runningMode(axes: ArbiterAxes): Mode | undefined {
  if (axes.integrity === undefined || axes.confidentiality === undefined) return undefined;
  return modeOf({ integrity: axes.integrity, confidentiality: axes.confidentiality });
}

/** What stops being covered when going from `from` to `to` (one line each). */
export function downgradeLines(from: Mode, to: Mode): string[] {
  const a = MODE_AXES[from], b = MODE_AXES[to];
  const out: string[] = [];
  if (a.integrity && !b.integrity) {
    out.push("untrusted text (web pages, files from outside, tool output) will reach the AI unmasked and can steer it");
  }
  if (a.confidentiality && !b.confidentiality) {
    out.push("secret files (keys, tokens, credentials) will behave like ordinary files and can leave the machine");
  }
  return out;
}

/**
 * @param userEnv the env BEFORE config.toml was folded into it (run.ts keeps
 *   the snapshot), so a MANDU_MODE / axis variable reported here is one the
 *   user really exported, not the config file echoing back.
 */
export async function runMode(
  rest: string[], env: Env, userEnv: Env, deps: ModeCommandDeps = realModeDeps,
): Promise<number> {
  const args = rest.filter((a) => !a.startsWith("-"));
  if (args.length > 1) { deps.err(`mandu mode: expected one mode name (${MODES.join("|")})`); return 2; }
  const path = configPath(env);
  const { level, badMode } = configLevel(path ? deps.readFile(path) : null);
  const saved = savedMode(level);
  const sock = resolveArbiterSock(env).sock;
  const running = deps.sockExists(sock) ? runningMode(await deps.readAxes(sock)) : undefined;

  if (args.length === 0) {
    deps.out(`running: ${running ?? "nothing running"}${running ? `  (arbiter at ${sock})` : ""}`);
    deps.out(
      `saved:   ${saved.mode}${saved.explicit ? "" : "  (nothing saved: the built-in default)"}` +
        (path ? `  (${path})` : ""),
    );
    if (badMode !== undefined) deps.out(`warning: config.toml has mode = "${badMode}", which is not a mode; it is ignored`);
    const exported = ["MANDU_MODE", "MANDU_INTEGRITY", "MANDU_CONFIDENTIALITY"].filter((k) => (userEnv[k] ?? "") !== "");
    if (exported.length > 0) deps.out(`note: ${exported.join(", ")} is exported in this shell and beats the saved mode`);
    if (running && running !== saved.mode) {
      deps.out("The running arbiter started before the saved mode changed. `mandu stop`, then launch again, to apply it.");
    }
    deps.out("");
    if (MODE_AXES[saved.mode].integrity && !integrityOptedIn(env)) {
      deps.out(`warning: the saved mode ${saved.mode} is frozen; a launch refuses it (docs/design/architecture/protection-modes.md). \`mandu mode secrets\` to change it.`);
    }
    deps.out("modes:");
    for (const l of modeHelpLines()) deps.out(l);
    deps.out("change it: mandu mode <name>   one launch only: mandu --mode <name> claude");
    return 0;
  }

  let wanted: Mode;
  try { wanted = parseMode(args[0], "mandu mode")!; } catch (e) { deps.err((e as Error).message); return 2; }
  // The integrity modes are frozen (docs/design/architecture/protection-modes.md §10): saving
  // one would only make every later launch refuse, so say so now instead.
  if (MODE_AXES[wanted].integrity && !integrityOptedIn(env)) { deps.err(integrityFrozenMessage(`\`mandu mode ${wanted}\``)); return 2; }
  if (!path) { deps.err("mandu mode: cannot resolve the config path (neither MANDU_HOME nor HOME is set)"); return 2; }
  try { deps.writeMode(path, wanted); } catch (e) { deps.err(`mandu mode: could not write ${path}: ${(e as Error).message}`); return 1; }
  deps.out(`mandu: saved mode ${wanted} to ${path}`);
  deps.out(`  ${MODE_SUMMARY[wanted]}`);
  for (const l of downgradeLines(running ?? saved.mode, wanted)) deps.out(`  no longer covered: ${l}`);
  if (running && running !== wanted) {
    deps.out(`The running arbiter is still in mode ${running}. Modes are read once at arbiter start: \`mandu stop\`, then launch again.`);
  }
  return 0;
}
