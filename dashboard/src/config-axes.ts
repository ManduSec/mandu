/**
 * config-axes — read + surgically edit the protection keys (`mode`, plus the
 * two axis keys `integrity`, `confidentiality`) in the launcher's unified
 * config file (`~/.mandu/config.toml`), and resolve them into the
 * arbiter's spawn env (dashboard.md §4.19: the Protection drawer's durable
 * setup surface + the supervisor's "posture nobody runs" guard).
 *
 * THE FOUR MODES (docs/design/architecture/protection-modes.md): every axis pair has a
 * name (secrets / injection / full / off). The mode table, DEFAULT_MODE and
 * `modeOf` here MIRROR launcher/src/mode.ts (THE source of truth);
 * tests/stack/axis-defaults-parity.test.ts fails when they drift.
 * Resolution INSIDE the file: an axis key beats the `mode` key for that axis
 * only; an axis with neither falls to DEFAULT_MODE's value. Never an error:
 * an unknown mode string is ignored on read (treated as absent) and reported
 * as `badMode`.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): the config-path resolution, the TOML
 * subset, and the env-precedence rule are a NARROW MIRROR of
 * launcher/src/config.ts (`configPath`, `parseToml`, `applyConfigDefaults`) —
 * that file is the precedence source of truth (flags > env > config >
 * defaults; config fills only env keys that are `undefined`). Mirrored, not
 * imported: the dashboard package typechecks standalone (the same decoupling
 * rationale as server/approval-routes.ts vs arbiter/**). If the launcher's
 * resolution ever changes, change this in the same commit.
 *
 * Two hard rules this module enforces:
 *   - SURGICAL edits only: a write may touch nothing but the managed
 *     `integrity = …` / `confidentiality = …` lines (replaced in place, every
 *     matching line so the launcher's last-wins read stays coherent) or an
 *     appended block (one provenance comment line, added once). EVERY other
 *     byte is preserved verbatim — the config file is the user's, not ours.
 *   - The axis DEFAULTS here are DERIVED from `MODE_AXES[DEFAULT_MODE]`,
 *     which mirrors the arbiter's flag modules
 *     (arbiter/policy/{integrity,confidentiality}-flag.ts). DEFAULT_MODE is
 *     the ONE constant in this package that names the default; nothing else
 *     (TS or browser JS) may hardcode it: the browser reads `defaultMode`
 *     from the GET payload. `effective` = axis key ?? mode's axis ?? default
 *     = what the next COLD arbiter start runs.
 *   - SELF-CONSISTENT writes: a mode write re-aligns any EXISTING axis lines
 *     to the mode's pair (never appends axis lines); a single-axis write
 *     rewrites an EXISTING `mode` line to the name of the resulting pair. The
 *     file never contradicts itself.
 */

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

import { manduPath } from "./generated/mandu-paths.js";

type Env = Record<string, string | undefined>;
type TomlValue = string | number | boolean;

/** The two managed axis keys (config.toml spelling = launcher CONFIG_TO_ENV). */
export const AXIS_KEYS = ["integrity", "confidentiality"] as const;
export type AxisKey = (typeof AXIS_KEYS)[number];

/** config key → the MANDU_* env var it seeds (launcher CONFIG_TO_ENV rows). */
export const AXIS_ENV: Record<AxisKey, string> = {
  integrity: "MANDU_INTEGRITY",
  confidentiality: "MANDU_CONFIDENTIALITY",
};

// ── the four modes (MIRROR of launcher/src/mode.ts) ──────────────────────────

export const MODES = ["secrets", "injection", "full", "off"] as const;
export type Mode = (typeof MODES)[number];

export const MODE_AXES: Record<Mode, Record<AxisKey, boolean>> = {
  secrets: { integrity: false, confidentiality: true },
  injection: { integrity: true, confidentiality: false },
  full: { integrity: true, confidentiality: true },
  off: { integrity: false, confidentiality: false },
};

/** The modes the product offers. `injection` and `full` turn the FROZEN
 *  integrity axis on (docs/design/architecture/protection-modes.md §10): the arbiter refuses
 *  them without INTEGRITY_OPT_IN_ENV, so this surface refuses to save them
 *  without it too (mirror of launcher/src/mode.ts PRODUCT_MODES). */
export const PRODUCT_MODES: readonly Mode[] = ["secrets", "off"];

/** The opt-in that unlocks the frozen integrity axis. Mirrors
 *  arbiter/policy/integrity-flag.ts (the parity test checks the name). */
export const INTEGRITY_OPT_IN_ENV = "MANDU_EXPERIMENTAL_INTEGRITY";

/** Only an explicit "1"/"true"/"on"/"yes" opts in (the arbiter's rule). */
export function integrityOptedIn(env: Env): boolean {
  const v = (env[INTEGRITY_OPT_IN_ENV] ?? "").trim().toLowerCase();
  return v === "1" || v === "true" || v === "on" || v === "yes";
}

/** The mode a COLD arbiter start runs when nothing states the axes. Must equal
 *  launcher/src/mode.ts DEFAULT_MODE and the arbiter flag modules' built-in
 *  defaults (the parity test checks). THE one place this package names it. */
export const DEFAULT_MODE: Mode = "secrets";

/** Every axis pair has exactly one name. */
export function modeOf(axes: Record<AxisKey, boolean>): Mode {
  if (axes.confidentiality) return axes.integrity ? "full" : "secrets";
  return axes.integrity ? "injection" : "off";
}

export function isMode(v: unknown): v is Mode {
  return typeof v === "string" && (MODES as readonly string[]).includes(v);
}

/** The launcher's lenient mode-name normalization (mode.ts parseMode: trim +
 *  lowercase). Returns the Mode, or null when the string names none. */
function normalizeMode(raw: string): Mode | null {
  const s = raw.trim().toLowerCase();
  return isMode(s) ? s : null;
}

/** The arbiter's boot defaults, DERIVED from the default mode. */
export const AXIS_DEFAULTS: Record<AxisKey, boolean> = { ...MODE_AXES[DEFAULT_MODE] };

/** `configured` per axis: the file's value, or null when the key is absent. */
export interface ConfiguredAxes {
  integrity: boolean | null;
  confidentiality: boolean | null;
}

/** The §4.19 frozen GET /api/config/axes shape. */
export interface AxesState {
  ok: true;
  /** The resolved config path (MANDU_HOME, else HOME), null only when
   *  neither is set. */
  path: string | null;
  exists: boolean;
  configured: ConfiguredAxes;
  defaults: Record<AxisKey, boolean>;
  /** axis key ?? the file mode's axis ?? default: what the next COLD arbiter
   *  start runs. */
  effective: Record<AxisKey, boolean>;
  /** The file's VALID `mode` value, or null (absent, or not one of the four). */
  mode: Mode | null;
  /** The file's INVALID `mode` string, only when one is present. It is
   *  ignored by every reader (launcher and supervisor alike) and reported. */
  badMode?: string;
  /** modeOf(effective): the name of the pair the next cold start runs. */
  effectiveMode: Mode;
  /** The built-in default mode (the UI's "default" tag follows this). */
  defaultMode: Mode;
  /** True when this dashboard's env opted into the FROZEN integrity axis
   *  (INTEGRITY_OPT_IN_ENV). False ⇒ the UI offers only PRODUCT_MODES and a
   *  POST that turns integrity on is refused (docs/design/architecture/protection-modes.md §10). */
  integrityAllowed: boolean;
}

/** A POST body's validated payload: only the keys the caller set. */
export type AxesUpdate = Partial<Record<AxisKey, boolean>>;

/** What the config file says about its `mode` key. */
export interface ConfiguredMode {
  mode: Mode | null;
  badMode?: string;
}

// ── path resolution (mirror of launcher configPath) ──────────────────────────

/** Resolve the config path: the path table's `config-toml`
 *  (on-disk-layout.md §5): $MANDU_HOME/config.toml, else
 *  $HOME/.mandu/config.toml. null when neither is set. The launcher resolves
 *  the same entry; a test isolates by pointing MANDU_HOME at a temp dir (no
 *  config.toml there = nothing configured). */
export function resolveConfigPath(env: Env): string | null {
  if (!env["MANDU_HOME"] && !env["HOME"]) return null;
  return manduPath("config-toml", env, env["HOME"] ?? "");
}

// ── read (mirror of launcher parseToml + bool coercion) ──────────────────────

/** The launcher's TOML subset (key = value, [sections] flattened, # comments,
 *  strings/bools/ints; lenient — unparseable lines skipped; duplicate keys:
 *  LAST wins). Mirrored from launcher/src/config.ts parseToml. */
export function parseTomlSubset(text: string): Record<string, TomlValue> {
  const out: Record<string, TomlValue> = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("[")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    let rest = line.slice(eq + 1).trim();
    if (!key) continue;
    const q = rest[0];
    if (q === '"' || q === "'") {
      const end = rest.indexOf(q, 1);
      if (end > 0) out[key] = rest.slice(1, end);
      continue;
    }
    const ci = rest.indexOf(" #"); // strip an inline comment
    if (ci >= 0) rest = rest.slice(0, ci).trim();
    if (rest === "true") out[key] = true;
    else if (rest === "false") out[key] = false;
    else if (/^-?\d+$/.test(rest)) out[key] = parseInt(rest, 10);
    else if (/^-?\d*\.\d+$/.test(rest)) out[key] = parseFloat(rest);
    else out[key] = rest;
  }
  return out;
}

/** The launcher's bool coercion for a config value (config.ts `coerce`, kind
 *  "bool"): only `true` / `"true"` count as on; any other present value is off.
 *  Absent key → null (so `effective` can fall back to the arbiter default). */
function coerceBool(cfg: Record<string, TomlValue>, key: string): boolean | null {
  if (!(key in cfg)) return null;
  const v = cfg[key]!;
  return v === true || v === "true";
}

/** Parse the two managed keys out of config-file text. */
export function configuredAxes(text: string): ConfiguredAxes {
  const cfg = parseTomlSubset(text);
  return {
    integrity: coerceBool(cfg, "integrity"),
    confidentiality: coerceBool(cfg, "confidentiality"),
  };
}

/** Parse the `mode` key out of config-file text (launcher mode-command.ts
 *  `configLevel` semantics: a string value, trimmed + lowercased; an empty
 *  string is absent; an unknown name is reported as `badMode`, never mapped). */
export function configuredMode(text: string): ConfiguredMode {
  const raw = parseTomlSubset(text)["mode"];
  if (typeof raw !== "string" || raw.trim() === "") return { mode: null };
  const mode = normalizeMode(raw);
  return mode !== null ? { mode } : { mode: null, badMode: raw };
}

/** axis key ?? mode's axis ?? default, per axis independently. */
function effectiveAxesOf(configured: ConfiguredAxes, mode: Mode | null): Record<AxisKey, boolean> {
  const fromMode = mode !== null ? MODE_AXES[mode] : AXIS_DEFAULTS;
  return {
    integrity: configured.integrity ?? fromMode.integrity,
    confidentiality: configured.confidentiality ?? fromMode.confidentiality,
  };
}

/** The config file's text, or null when it is absent: ENOENT, and ENOTDIR
 *  alike (a home under a non-directory, such as the test scripts'
 *  `MANDU_HOME=/dev/null/...`, has no config). Any other read failure is
 *  null too: an unreadable file configures nothing. */
function safeRead(p: string): string | null {
  try {
    return readFileSync(p, "utf8");
  } catch {
    return null;
  }
}

/** The full §4.19 GET shape for the resolved config file. A missing/unreadable
 *  file reads as "nothing configured" (all nulls) — the defaults then rule,
 *  which is exactly what a cold arbiter start would run. */
export function readAxesState(env: Env, read: (p: string) => string | null = safeRead): AxesState {
  const path = resolveConfigPath(env);
  const text = path ? read(path) : null;
  const configured =
    text === null ? { integrity: null, confidentiality: null } : configuredAxes(text);
  const cm: ConfiguredMode = text === null ? { mode: null } : configuredMode(text);
  const effective = effectiveAxesOf(configured, cm.mode);
  return {
    ok: true,
    path,
    exists: text !== null,
    configured,
    defaults: { ...AXIS_DEFAULTS },
    effective,
    mode: cm.mode,
    ...(cm.badMode !== undefined ? { badMode: cm.badMode } : {}),
    effectiveMode: modeOf(effective),
    defaultMode: DEFAULT_MODE,
    integrityAllowed: integrityOptedIn(env),
  };
}

// ── surgical write ────────────────────────────────────────────────────────────

/** The one comment line the appended block carries (added ONCE per file, ever —
 *  a later append that finds it anywhere in the file adds only key lines). */
export const PROVENANCE_COMMENT =
  "# integrity / confidentiality below are managed by the Mandu dashboard (Protection drawer)";

/** Match every top-level assignment line for one managed key. A commented-out
 *  line (`# integrity = …`) never matches; a longer key (`fs-integrity`) never
 *  matches (the char before/after the key breaks the pattern). */
function managedLineRe(key: string): RegExp {
  return new RegExp(`^([ \\t]*)${key}[ \\t]*=[ \\t]*([^\\r\\n]*)$`, "gm");
}

/** Replace every `key = …` line in place (indent + any inline `# …` comment
 *  preserved); returns [text, replacedAny]. BYTE-IDENTICAL to the launcher's
 *  launcher/src/config-edit.ts `replaceManaged`: a `#` inside a quoted value
 *  is not a comment. */
function replaceManaged(text: string, key: string, rendered: string): [string, boolean] {
  let replaced = false;
  const out = text.replace(managedLineRe(key), (_m, indent: string, rest: string) => {
    replaced = true;
    const unquoted = rest.replace(/^(["'])[^"']*\1/, "");
    const hash = unquoted.indexOf("#");
    const inline = hash >= 0 ? `  ${unquoted.slice(hash)}` : "";
    return `${indent}${key} = ${rendered}${inline}`;
  });
  return [out, replaced];
}

/**
 * The generic surgical editor both managed-key families ride (the protection
 * axes and the sandbox switches, policy-surface.md §4 Settings). Same
 * two hard rules as the header: touch only the managed lines named in
 * `updates` (in `order`), append what is absent under `comment` (added once).
 */
function applyManagedEdit(
  text: string,
  updates: Record<string, boolean | undefined>,
  order: readonly string[],
  comment: string,
): string {
  let out = text;
  const toAppend: string[] = [];
  for (const key of order) {
    const value = updates[key];
    if (value === undefined) continue;
    let replaced: boolean;
    [out, replaced] = replaceManaged(out, key, value ? "true" : "false");
    if (!replaced) toAppend.push(`${key} = ${value ? "true" : "false"}`);
  }
  if (toAppend.length > 0) {
    if (out.length > 0 && !out.endsWith("\n")) out += "\n";
    if (!out.includes(comment)) {
      out += (out.length > 0 ? "\n" : "") + comment + "\n";
    }
    out += toAppend.join("\n") + "\n";
  }
  return out;
}

/**
 * Apply an axis update to config-file TEXT (pure — the FS wrapper below feeds
 * it). Each updated key: every existing `key = …` line is replaced in place
 * (indent + any inline `# …` comment preserved; replacing ALL occurrences keeps
 * the launcher's last-wins read coherent with what we wrote); a key with no
 * existing line is appended at EOF as a bare TOML boolean, under the
 * provenance comment (added once). Every other byte is preserved verbatim.
 */
export function applyAxesEdit(text: string, updates: AxesUpdate): string {
  let out = applyManagedEdit(text, updates, AXIS_KEYS, PROVENANCE_COMMENT);
  // SELF-CONSISTENT: when the file HAS a `mode` line, rewrite it to the name
  // of the resulting effective pair, so `mode = "full"` never sits beside a
  // freshly written `integrity = false`. A file without a mode line gains
  // none (the single-axis write stays the narrow act it always was). A
  // commented-out `# mode = …` is not a mode line and stays untouched.
  if (managedLineRe("mode").test(out)) {
    const resulting = modeOf(effectiveAxesOf(configuredAxes(out), configuredMode(out).mode));
    [out] = replaceManaged(out, "mode", `"${resulting}"`);
  }
  return out;
}

/** The one comment line an appended `mode` line carries (added ONCE). Same
 *  constant VALUE as launcher/src/config-edit.ts MODE_PROVENANCE_COMMENT. */
export const MODE_PROVENANCE_COMMENT =
  "# mode below is managed by Mandu (`mandu mode`, or the dashboard's Protection drawer)";

/**
 * Pure: apply `mode = "<name>"` to config TEXT. A BYTE-IDENTICAL MIRROR of
 * launcher/src/config-edit.ts `applyModeEdit` (the parity test feeds both the
 * same inputs). Sets the `mode` line (every occurrence replaced in place, else
 * appended under the comment, comment added once) and RE-ALIGNS any EXISTING
 * axis line to the mode's pair. It never appends axis lines: inside one level
 * an axis key beats the mode, so a stale `integrity = true` left beside
 * `mode = "secrets"` would silently win.
 */
export function applyModeEdit(text: string, mode: Mode): string {
  let out = text;
  for (const axis of AXIS_KEYS) {
    [out] = replaceManaged(out, axis, MODE_AXES[mode][axis] ? "true" : "false");
  }
  let replaced: boolean;
  [out, replaced] = replaceManaged(out, "mode", `"${mode}"`);
  if (!replaced) {
    if (out.length > 0 && !out.endsWith("\n")) out += "\n";
    if (!out.includes(MODE_PROVENANCE_COMMENT)) {
      out += (out.length > 0 ? "\n" : "") + MODE_PROVENANCE_COMMENT + "\n";
    }
    out += `mode = "${mode}"\n`;
  }
  return out;
}

/**
 * Read-modify-write the resolved config file with {@link applyAxesEdit}.
 * Creates the file (and its parent dir) when absent; writes via tmp+rename so
 * a concurrently-starting launcher never reads a torn file. Throws when no
 * config path is resolvable (neither MANDU_HOME nor HOME) or on an
 * FS failure — the route surfaces that as an error, never a silent success.
 * Returns the post-write state (the POST responds with the GET shape).
 */
export function writeAxes(env: Env, updates: AxesUpdate): AxesState {
  return rewriteConfig(env, "axes", (prior) => applyAxesEdit(prior, updates));
}

/** Read-modify-write the resolved config file with {@link applyModeEdit}
 *  (same creation, tmp+rename and throw rules as {@link writeAxes}). */
export function writeMode(env: Env, mode: Mode): AxesState {
  return rewriteConfig(env, "mode", (prior) => applyModeEdit(prior, mode));
}

function rewriteConfig(env: Env, tag: string, edit: (prior: string) => string): AxesState {
  const path = resolveConfigPath(env);
  if (!path) {
    throw new Error(
      "cannot resolve the config path — neither MANDU_HOME nor HOME is set",
    );
  }
  mkdirSync(dirname(path), { recursive: true });
  const prior = existsSync(path) ? readFileSync(path, "utf8") : "";
  const tmp = `${path}.tmp-${tag}-${process.pid}`;
  writeFileSync(tmp, edit(prior));
  renameSync(tmp, path);
  return readAxesState(env);
}

// ── arbiter spawn-env resolution (the supervisor plumbing) ────────────────────

/**
 * Resolve the config file's `mode` + axis keys into the explicit MANDU_*
 * axis env fill for the supervisor's ARBITER spawn: the launcher's precedence,
 * reimplemented narrowly (launcher/src/config.ts `applyConfigDefaults` +
 * launcher/src/mode.ts). An EXPLICITLY SET process env axis var wins for that
 * axis (config fills only keys that are `undefined`; an empty-string export is
 * still "set", exactly the launcher's rule). A process env MANDU_MODE speaks
 * for BOTH axes (the file is not consulted for them) and is translated into
 * the axis vars. Inside the file an axis key beats the `mode` key for that
 * axis only. An axis stated NOWHERE yields nothing (the arbiter's own boot
 * defaults rule).
 * Values are the launcher's coerced "1"/"0" spellings, which the arbiter's
 * flag modules parse. Called AT SPAWN TIME (supervisor.launch), not at
 * construction, so a Protection-drawer config edit lands on the very next
 * restart — without this the drawer would claim an effect the restart does
 * not deliver (the §4.19 "posture nobody runs" guard).
 */
export function arbiterAxisSpawnEnv(
  processEnv: Env,
  read: (p: string) => string | null = safeRead,
): Record<string, string> {
  // An exported MANDU_MODE speaks for BOTH axes at the env level (launcher
  // applyConfigDefaults): nothing is seeded from the file's axis or mode keys
  // then. The env mode is TRANSLATED here into whichever axis var is not
  // explicitly set, so the spawn env always carries explicit axes (the arbiter
  // also reads MANDU_MODE itself, arbiter/policy/protection-mode.ts, and an
  // inherited bogus value makes it refuse to start unless both axes are stated). An
  // MANDU_MODE that names none of the four is IGNORED (treated as absent,
  // the same never-an-error rule as the file's `mode` key), so the file still
  // speaks: the launcher refuses such a launch outright, and the supervisor
  // has nobody to refuse, so it keeps the configured intent instead of
  // silently dropping to the arbiter defaults.
  const envMode = normalizeMode(processEnv["MANDU_MODE"] ?? "");
  const envNamesMode = envMode !== null;
  const envModeFill: Record<string, string> = {};
  if (envMode !== null) {
    for (const key of AXIS_KEYS) {
      if (processEnv[AXIS_ENV[key]] !== undefined) continue; // explicit env wins
      envModeFill[AXIS_ENV[key]] = MODE_AXES[envMode][key] ? "1" : "0";
    }
  }
  const path = resolveConfigPath(processEnv);
  if (!path) return envModeFill;
  const text = read(path);
  if (text === null) return envModeFill;
  const out: Record<string, string> = { ...envModeFill };
  if (!envNamesMode) {
    const configured = configuredAxes(text);
    const fileMode = configuredMode(text).mode;
    for (const key of AXIS_KEYS) {
      // Inside the file an axis key beats the mode for that axis only.
      const v = configured[key] ?? (fileMode !== null ? MODE_AXES[fileMode][key] : null);
      if (v === null) continue; // stated nowhere → the arbiter default rules
      const envKey = AXIS_ENV[key];
      if (processEnv[envKey] !== undefined) continue; // explicit env wins
      out[envKey] = v ? "1" : "0";
    }
  }
  // The data-law document (policy-surface.md §2.1): the launcher's
  // `policy-file` key seeds MANDU_POLICY_FILE for the arbiter the SUPERVISOR
  // spawns, with the launcher's precedence (an explicit env var wins). The
  // arbiter expands `~` itself and refuses to start on an invalid file.
  const policyFile = parseTomlSubset(text)["policy-file"];
  if (typeof policyFile === "string" && policyFile.trim() !== "" && processEnv["MANDU_POLICY_FILE"] === undefined) {
    out["MANDU_POLICY_FILE"] = policyFile;
  }
  return out;
}

// ── the sandbox switches (Settings → Sandbox; policy-surface.md §4) ──
//
// The launcher's boolean wrap keys in the SAME config.toml (launcher
// CONFIG_TO_ENV rows), read and written with the same surgical editor. These
// apply at the NEXT `mandu` launch — the launcher reads the file when it
// wraps an agent; nothing running changes. Defaults MIRROR launcher/src/
// parse.ts (the tri-state rungs are ON unless opted out; `no-kernel` and
// `landlock-net-strict` are opt-IN; `fs-sync` unset = auto: on for git
// repos). If the launcher's defaults change, change this table in the same
// commit — the "posture nobody runs" guard applies here as much as to the
// axes.

export type SandboxDefault = boolean | "auto";

export interface SandboxKeyMeta {
  env: string;
  default: SandboxDefault;
  /** One plain sentence: what the switch wraps around the agent. */
  summary: string;
  /** Which chokepoint the switch belongs to (grouping in the UI). */
  group: "exec" | "network" | "filesystem" | "reply" | "kernel";
  /** true = a KERNEL-tier rung (needs the kernel features; degrades where
   *  absent; `no-kernel` drops all of them at once). */
  kernel: boolean;
}

export const SANDBOX_KEYS = [
  "exec-box",
  "exec-clean-box",
  "exec-wrap",
  "landlock-net",
  "landlock-net-strict",
  "net-guard",
  "net-guard-git",
  "net-proxy",
  "fs-sync",
  "fs-sync-eager",
  "reply-filter",
  "no-kernel",
] as const;
export type SandboxKey = (typeof SANDBOX_KEYS)[number];

export const SANDBOX_META: Record<SandboxKey, SandboxKeyMeta> = {
  "exec-box": { env: "MANDU_EXEC_BOX", default: true, group: "exec", kernel: true,
    summary: "Run read-only commands in a box that sees the masked files (AgentView) and has no network" },
  "exec-clean-box": { env: "MANDU_EXEC_CLEAN_BOX", default: true, group: "exec", kernel: true,
    summary: "Boxed commands run clean: their output can be trusted as-is when it matches what was expected" },
  "exec-wrap": { env: "MANDU_EXEC_WRAP", default: true, group: "exec", kernel: false,
    summary: "Route network-fetching commands (curl, wget, nc) through the protection service" },
  "landlock-net": { env: "MANDU_LANDLOCK_NET", default: true, group: "network", kernel: true,
    summary: "Limit which TCP ports the whole agent may connect to (Landlock)" },
  "landlock-net-strict": { env: "MANDU_LANDLOCK_NET_STRICT", default: false, group: "network", kernel: true,
    summary: "Fail the launch instead of degrading when the port limit cannot be applied" },
  "net-guard": { env: "MANDU_NET_GUARD", default: true, group: "network", kernel: true,
    summary: "Check every outgoing connection by address and domain before it is made" },
  "net-guard-git": { env: "MANDU_NET_GUARD_GIT", default: true, group: "network", kernel: true,
    summary: "Let the workspace's git remotes through the connection check automatically" },
  "net-proxy": { env: "MANDU_NET_PROXY", default: true, group: "network", kernel: false,
    summary: "Send the agent's web traffic through the protection service's proxy" },
  "fs-sync": { env: "MANDU_FS_SYNC", default: "auto", group: "filesystem", kernel: false,
    summary: "Keep the masked copy of the workspace in step with the real one (auto: on for git repositories)" },
  "fs-sync-eager": { env: "MANDU_FS_SYNC_EAGER", default: true, group: "filesystem", kernel: false,
    summary: "Sync the masked copy at every tool call, not only at turn boundaries" },
  "reply-filter": { env: "MANDU_REPLY_FILTER", default: true, group: "reply", kernel: false,
    summary: "Show you the original text where the AI's reply contains a masked value" },
  "no-kernel": { env: "MANDU_NO_KERNEL", default: false, group: "kernel", kernel: false,
    summary: "Portable posture: turn off every kernel-level protection at once (boxing, port limits, connection check)" },
};

export interface SandboxKeyState {
  key: SandboxKey;
  env: string;
  group: SandboxKeyMeta["group"];
  kernel: boolean;
  summary: string;
  /** The file's value, or null when the key is absent. */
  configured: boolean | null;
  default: SandboxDefault;
  /** configured ?? default — what the next launch runs. */
  effective: SandboxDefault;
}

export interface SandboxState {
  ok: true;
  path: string | null;
  exists: boolean;
  keys: SandboxKeyState[];
}

export type SandboxUpdate = Partial<Record<SandboxKey, boolean>>;

export const SANDBOX_PROVENANCE_COMMENT =
  "# sandbox switches below are managed by the Mandu dashboard (Settings → Sandbox)";

export function readSandboxState(env: Env, read: (p: string) => string | null = safeRead): SandboxState {
  const path = resolveConfigPath(env);
  const text = path ? read(path) : null;
  const cfg = text === null ? {} : parseTomlSubset(text);
  const keys = SANDBOX_KEYS.map((key): SandboxKeyState => {
    const meta = SANDBOX_META[key];
    const configured = coerceBool(cfg, key);
    return {
      key, env: meta.env, group: meta.group, kernel: meta.kernel, summary: meta.summary,
      configured, default: meta.default, effective: configured ?? meta.default,
    };
  });
  return { ok: true, path, exists: text !== null, keys };
}

export function applySandboxEdit(text: string, updates: SandboxUpdate): string {
  return applyManagedEdit(text, updates, SANDBOX_KEYS, SANDBOX_PROVENANCE_COMMENT);
}

/** Read-modify-write like {@link writeAxes} (tmp + rename; throws on no path). */
export function writeSandbox(env: Env, updates: SandboxUpdate): SandboxState {
  const path = resolveConfigPath(env);
  if (!path) {
    throw new Error(
      "cannot resolve the config path — neither MANDU_HOME nor HOME is set",
    );
  }
  mkdirSync(dirname(path), { recursive: true });
  const prior = existsSync(path) ? readFileSync(path, "utf8") : "";
  const next = applySandboxEdit(prior, updates);
  const tmp = `${path}.tmp-sandbox-${process.pid}`;
  writeFileSync(tmp, next);
  renameSync(tmp, path);
  return readSandboxState(env);
}
