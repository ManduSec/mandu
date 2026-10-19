/**
 * claude-sandbox — coexistence with Claude Code's OWN sandbox and credential
 * mask (plan 10 §12.3, `docs/design/confidentiality/confidentiality-plan-10-flow-taint.md`).
 *
 * A user may run Claude Code's `/sandbox` under Mandu. Two facts to design
 * around, both checked at launch and by `mandu doctor`:
 *
 *  - Two seccomp filters stack (the kernel runs both). Mandu's interposer is
 *    installed by the launcher OUTSIDE Claude Code's bubblewrap, so it sees the
 *    sandboxed command's opens too. Claude Code's optional unix-socket filter
 *    must not cut the arbiter socket off from the shims that run inside its
 *    box: the launcher passes the socket through
 *    `sandbox.network.allowUnixSockets` (a literal path list) on `--settings`.
 *  - Two masks on one file is a double placeholder: Claude Code's sentinel
 *    copy (`sandbox.credentials.files`, mode `mask`) over Mandu's structured
 *    twin; likewise `sandbox.credentials.envVars` over the env-var symbols.
 *    Mandu's twin is the one to keep: it covers the AI's own reads and the
 *    whole process tree, theirs covers sandboxed Bash only. The launcher warns
 *    once per overlap and names the setting file to edit.
 *
 * Settings shape and precedence per the Claude Code settings reference
 * (2026-09): managed > `--settings` > project local > project > user; list
 * keys MERGE across files, `mask` entries are honored from user / managed /
 * `--settings` only (a project file's mask entries are ignored, so they are
 * not an overlap here). Pure decision logic; `checkClaudeSandbox` is the one
 * I/O wrapper. Mandu-new (no reference origin).
 *
 * macOS (measured 2026-09-29 on macOS 26.5.1; decided 2026-10-02). Claude
 * Code's sandbox there is Seatbelt (`sandbox-exec` per command), and macOS
 * refuses a sandbox inside Mandu's whole-agent profile (`sandbox_apply:
 * Operation not permitted`), so with it on every sandboxed Bash command
 * fails. When Mandu's profile really wraps the launch, Mandu turns Claude
 * Code's sandbox off for the session (planDarwinClaudeSandbox): it asks
 * Claude Code itself (`claude sandbox status`, read-only, no model) whether
 * the sandbox would be on, adds `{"sandbox":{"enabled":false}}` to the LAST
 * `--settings` of the launch (the user's own when they passed one: Claude
 * Code reads only the last, and merges it over user, project and local
 * settings, never over managed ones), asks again that it is now off, and
 * prints ONE line saying so and what that gives up. It keeps the sandbox, and
 * the WARNING, when the run's own `--settings` turns it on, when managed
 * settings keep it on (the second probe still answers on), when a settings
 * source Mandu reads cannot be read or parsed (or is an administrator's
 * policy helper), when the run passes `--managed-settings` or
 * `--project-config-root`, when the sandbox is on from a source Mandu does
 * not read, when `permissions.blockReadsOutsideWorkingDirectories` is set,
 * or when its read rules (`sandbox.credentials`,
 * `sandbox.filesystem.denyRead`, `permissions.deny` `Read(...)`) name
 * files, folders or variables Mandu does not protect (they apply to Bash
 * only inside its sandbox). Mandu reads the sources Claude Code 2.1.286
 * reads, parsed as it parses them: the user file (CLAUDE_CONFIG_DIR, or
 * `cowork_settings.json`), the project and local files (the local one also
 * at the repository root and, in a linked worktree, at the main checkout),
 * the managed file and its `managed-settings.d/*.json` drop-ins, the
 * server-managed cache (`remote-settings.json`) and, on macOS, the forced
 * MDM preferences (`com.anthropic.claudecode`, per account). Without the
 * probe (a Claude Code below CLAUDE_SANDBOX_STATUS_SINCE) the settings
 * files decide. The managed settings file is
 * platform-specific (/Library/Application Support/ClaudeCode on macOS); the
 * `allowUnixSockets` overlay above is for a launch with no outer profile, in
 * every spelling Seatbelt may compare (it matches CANONICAL paths only).
 */
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { userInfo } from "node:os";
import { basename, dirname, isAbsolute, join, normalize, relative as relative_, resolve } from "node:path";
import { compareAgentVersions, parseAgentVersion } from "./agent-versions.js";
import { touchesHumanPlane } from "./human-plane.js";

export type ClaudeSettingsScope = "managed" | "user" | "project" | "local";

export interface ClaudeSettingsFile {
  path: string;
  scope: ClaudeSettingsScope;
  /** A property list (macOS MDM preferences), read as JSON through
   *  `plutil`; absent = a JSON file. */
  format?: "plist";
}

export interface ClaudeCredentialFile {
  /** As written in the settings file (`~/…`, `./…`, absolute). */
  path: string;
  /** Expanded per the file's prefix rules: `~/` → home; `./` → the project
   *  directory for project files, `~/.claude` for the user file. */
  resolved: string;
  mode: string;
  source: string;
}

export interface ClaudeCredentialEnv {
  name: string;
  mode: string;
  source: string;
}

/** What Claude Code's settings say about its sandbox, merged across files. */
export interface ClaudeSandboxView {
  /** `sandbox.enabled` is true in at least one file (the merge is
   *  precedence-ordered, but a launch-time warning errs on the side of
   *  telling the user: any file that turns it on is named). */
  enabled: boolean;
  enabledBy: string[];
  /** `mask`-mode credential entries from the scopes that may set them. */
  files: ClaudeCredentialFile[];
  envVars: ClaudeCredentialEnv[];
  /** `sandbox.filesystem.denyRead` entries and `permissions.deny`
   *  `Read(...)` rules (every scope; `permission` marks the latter, whose
   *  `resolved` is empty when Mandu cannot resolve it): like the credential
   *  rules, they apply to Bash only inside Claude Code's sandbox. */
  denyRead?: Array<{ path: string; resolved: string; source: string; permission?: boolean }>;
  /** Sources that set `permissions.blockReadsOutsideWorkingDirectories`. */
  blockReadsOutside?: string[];
  /** The managed-scope sources that turn the sandbox on. */
  enabledByManaged?: string[];
  allowUnixSockets: string[];
  /** The settings files that existed and parsed, in read order. */
  sources: string[];
  /** Files that existed but did not parse (named, never silent). */
  errors: string[];
  /** Sources that exist but could not be read at all (an MDM property list
   *  `plutil` could not convert). Optional: absent = none. */
  unreadable?: string[];
}

export interface ClaudeSandboxAssessment {
  notes: string[];
  doubleMaskedFiles: Array<{ path: string; source: string }>;
  doubleMaskedEnv: Array<{ name: string; source: string }>;
  /** The `--settings` overlay the launch splices (null when the sandbox is off). */
  settingsOverlay: Record<string, unknown> | null;
}

/** The managed settings path Claude Code reads on Linux. */
export const CLAUDE_MANAGED_SETTINGS = "/etc/claude-code/managed-settings.json";
/** …and on macOS. */
export const CLAUDE_MANAGED_SETTINGS_DARWIN = "/Library/Application Support/ClaudeCode/managed-settings.json";

/** The managed settings file for a platform. */
export function claudeManagedSettings(platform: NodeJS.Platform = process.platform): string {
  return platform === "darwin" ? CLAUDE_MANAGED_SETTINGS_DARWIN : CLAUDE_MANAGED_SETTINGS;
}

/** Where Claude Code's settings live beyond the fixed files: the user
 *  config dir, the repository root and its canonical root (a linked
 *  worktree's main checkout), the managed drop-ins (names in
 *  `managed-settings.d`), the server-managed cache, and the user whose MDM
 *  preferences apply (macOS). */
export interface ClaudeSettingsLocations {
  configDir?: string;
  /** The user file names in the config dir (default `settings.json`). */
  userFiles?: readonly string[];
  gitRoot?: string | null;
  canonicalRoot?: string | null;
  dropIns?: readonly string[];
  remote?: boolean;
  mdmUser?: string;
}

/** Claude Code's forced MDM preferences on macOS (per-user, then
 *  device-level), domain `com.anthropic.claudecode` (2.1.286). */
export function claudeMdmPlists(user: string): string[] {
  return [
    ...(user ? [`/Library/Managed Preferences/${user}/com.anthropic.claudecode.plist`] : []),
    "/Library/Managed Preferences/com.anthropic.claudecode.plist",
  ];
}

/** The settings files a launch in `cwd` for the user at `home` is subject to,
 *  lowest precedence first (the reference's merge order, reversed). */
export function claudeSettingsFiles(
  home: string,
  cwd: string,
  platform: NodeJS.Platform = process.platform,
  opts: ClaudeSettingsLocations = {},
): ClaudeSettingsFile[] {
  // CLAUDE_CONFIG_DIR moves the user file; the local file is read at the
  // repository root too (a launch from a subfolder) and, in a linked
  // worktree, at the main checkout (Claude Code reads it there).
  const configDir = opts.configDir ?? join(home, ".claude");
  const localAt = (root: string | null | undefined): ClaudeSettingsFile[] =>
    root && normalize(root) !== normalize(cwd) ? [{ path: join(root, ".claude", "settings.local.json"), scope: "local" }] : [];
  const managedDir = dirname(claudeManagedSettings(platform));
  const dropIns = [...(opts.dropIns ?? [])].filter((n) => n.endsWith(".json") && !n.startsWith(".") && !n.includes("/")).sort();
  const all: ClaudeSettingsFile[] = [
    ...(opts.userFiles ?? ["settings.json"]).map((n) => ({ path: join(configDir, n), scope: "user" as const })),
    { path: join(cwd, ".claude", "settings.json"), scope: "project" },
    ...localAt(opts.canonicalRoot),
    ...localAt(opts.gitRoot),
    { path: join(cwd, ".claude", "settings.local.json"), scope: "local" },
    ...(opts.remote ? [{ path: join(configDir, "remote-settings.json"), scope: "managed" as const }] : []),
    ...(platform === "darwin" && opts.mdmUser !== undefined ? claudeMdmPlists(opts.mdmUser).map((path) => ({ path, scope: "managed" as const, format: "plist" as const })) : []),
    { path: claudeManagedSettings(platform), scope: "managed" },
    ...dropIns.map((n) => ({ path: join(managedDir, "managed-settings.d", n), scope: "managed" as const })),
  ];
  // A launch from HOME itself makes the project file the user file: one read,
  // under its higher-trust scope (the first entry), never a doubled note.
  const seen = new Set<string>();
  return all.filter((f) => (seen.has(f.path) ? false : (seen.add(f.path), true)));
}

/** Scopes whose `mask` entries Claude Code honors (a project's are ignored). */
const MASK_SCOPES = new Set<ClaudeSettingsScope>(["user", "managed"]);

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Expand a settings path the way Claude Code 2.1.286 does for a sandbox
 *  rule of its file: trimmed; `//x` is `/x`; `~` and `~/` are the home; an
 *  absolute path stays; anything else is relative to the file's root (the
 *  config dir for the user file, the working directory for the others). */
export function expandClaudeSettingsPath(p: string, file: ClaudeSettingsFile, home: string, cwd: string): string {
  const t = p.trim();
  if (t.startsWith("//")) return normalize(t.slice(1));
  if (t === "~") return normalize(home);
  if (t.startsWith("~/")) return normalize(join(home, t.slice(2)));
  if (isAbsolute(t)) return normalize(t);
  return normalize(resolve(file.scope === "user" ? dirname(file.path) : cwd, t));
}

/** A `permissions.deny` `Read(<path>)` rule's path, which Claude Code also
 *  read-denies inside its sandbox, and whether Mandu can resolve it: `//x`
 *  is `/x` and `~/x` is under the home; a `/x` is relative to the settings
 *  root and anything else to the working directory, which Mandu does not
 *  try (such a rule never counts as covered). Null for another rule. */
export function claudeReadDenyPath(rule: string, home: string): { written: string; resolved: string | null } | null {
  const m = /^\s*Read\((.+)\)\s*$/s.exec(rule);
  if (!m) return null;
  const c = claudeRuleContent(m[1]!);
  if (c.startsWith("//")) return { written: rule.trim(), resolved: normalize(c.slice(1)) };
  if (c === "~") return { written: rule.trim(), resolved: normalize(home) };
  if (c.startsWith("~/")) return { written: rule.trim(), resolved: normalize(join(home, c.slice(2))) };
  return { written: rule.trim(), resolved: null };
}

/** A permission rule's content as Claude Code reads it (2.1.286): it saves
 *  `(`, `)` and a backslash escaped with a backslash, so those are
 *  unescaped, then a backslash before a character that is not a glob one is
 *  dropped. */
export function claudeRuleContent(raw: string): string {
  const t = raw.trim().replaceAll("\\(", "(").replaceAll("\\)", ")").replaceAll("\\\\", "\\");
  return t.replace(/\\([^*?[\]{}])/g, "$1");
}

/** Parse a settings file's text the way Claude Code does: blank is `{}`, a
 *  leading byte-order mark is dropped. Throws what JSON.parse throws. */
function parseSettingsText(text: string): unknown {
  if (text.trim() === "") return {};
  return JSON.parse(text.startsWith("\uFEFF") ? text.slice(1) : text);
}

/** Merge the `sandbox` sections of the files that exist. Pure. */
export function readClaudeSandbox(
  files: Array<ClaudeSettingsFile & { text: string | null; unreadable?: boolean }>,
  home: string,
  cwd: string,
): ClaudeSandboxView {
  const view: ClaudeSandboxView = { enabled: false, enabledBy: [], files: [], envVars: [], allowUnixSockets: [], sources: [], errors: [] };
  for (const f of files) {
    if (f.unreadable === true) { (view.unreadable ??= []).push(f.path); continue; }
    if (f.text === null) continue;
    let doc: unknown;
    try {
      doc = parseSettingsText(f.text);
    } catch (e) {
      view.errors.push(`${f.path}: ${(e as Error).message}`);
      continue;
    }
    if (!isRecord(doc)) { view.errors.push(`${f.path}: not a JSON object`); continue; }
    view.sources.push(f.path);
    // An administrator's policy helper computes managed settings Mandu cannot
    // see (its static payloads included): their rules are unknown.
    if (f.scope === "managed" && (doc["policyHelper"] != null || doc["policyHelpers"] != null)) {
      (view.unreadable ??= []).push(`${f.path} (its policyHelper)`);
    }
    // Claude Code's sandbox also read-denies every `Read(...)` deny rule, and
    // with blockReadsOutsideWorkingDirectories every home and volume outside
    // the working directories.
    const perms = doc["permissions"];
    if (isRecord(perms)) {
      if (Array.isArray(perms["deny"])) {
        for (const r of perms["deny"]) {
          const d = typeof r === "string" ? claudeReadDenyPath(r, home) : null;
          if (d !== null) (view.denyRead ??= []).push({ path: d.written, resolved: d.resolved ?? "", source: f.path, permission: true });
        }
      }
      if (perms["blockReadsOutsideWorkingDirectories"] === true) (view.blockReadsOutside ??= []).push(f.path);
    }
    const sb = doc["sandbox"];
    if (!isRecord(sb)) continue;
    if (sb["enabled"] === true) {
      view.enabled = true;
      view.enabledBy.push(f.path);
      if (f.scope === "managed") (view.enabledByManaged ??= []).push(f.path);
    }
    const fsr = sb["filesystem"];
    if (isRecord(fsr) && Array.isArray(fsr["denyRead"])) {
      for (const d of fsr["denyRead"]) {
        if (typeof d !== "string" || d === "") continue;
        (view.denyRead ??= []).push({ path: d, resolved: expandClaudeSettingsPath(d, f, home, cwd), source: f.path });
      }
    }
    const net = sb["network"];
    if (isRecord(net) && Array.isArray(net["allowUnixSockets"])) {
      for (const s of net["allowUnixSockets"]) if (typeof s === "string" && s !== "" && !view.allowUnixSockets.includes(s)) view.allowUnixSockets.push(s);
    }
    const cred = sb["credentials"];
    if (!isRecord(cred)) continue;
    if (Array.isArray(cred["files"])) {
      for (const e of cred["files"]) {
        if (!isRecord(e) || typeof e["path"] !== "string") continue;
        const mode = typeof e["mode"] === "string" ? e["mode"] : "deny";
        if (mode === "mask" && !MASK_SCOPES.has(f.scope)) continue; // ignored by Claude Code itself
        view.files.push({ path: e["path"], resolved: expandClaudeSettingsPath(e["path"], f, home, cwd), mode, source: f.path });
      }
    }
    if (Array.isArray(cred["envVars"])) {
      for (const e of cred["envVars"]) {
        if (!isRecord(e) || typeof e["name"] !== "string") continue;
        const mode = typeof e["mode"] === "string" ? e["mode"] : "deny";
        if (mode === "mask" && !MASK_SCOPES.has(f.scope)) continue;
        view.envVars.push({ name: e["name"], mode, source: f.path });
      }
    }
  }
  return view;
}

/**
 * Every spelling of a Unix socket path a sandbox's path filter may compare.
 * Linux: the path as given (Claude Code's bubblewrap/seccomp side takes it
 * literally; unchanged). macOS: Seatbelt matches CANONICAL paths only, and
 * the arbiter's socket is reached through the rendezvous `current` link
 * under $TMPDIR (/var/folders/… → /private/var/folders/…): the given
 * spelling, its realpath, and the /private form of each /var, /tmp or /etc
 * spelling. Pure over `realpath`.
 */
export function unixSocketSpellings(
  sock: string,
  platform: NodeJS.Platform,
  realpath: (p: string) => string | null,
): string[] {
  const out = [sock];
  if (platform !== "darwin" || sock === "") return out;
  const add = (p: string | null): void => { if (p && !out.includes(p)) out.push(p); };
  add(realpath(sock));
  for (const p of [...out]) if (/^\/(var|tmp|etc)(\/|$)/.test(p)) add(`/private${p}`);
  return out;
}

const defaultRealpath = (p: string): string | null => { try { return realpathSync(p); } catch { return null; } };
const defaultReadFile = (p: string): string | null => { try { return readFileSync(p, "utf8"); } catch { return null; } };

/** Read each settings source: a JSON file through `readFile` (absent =
 *  null), an MDM property list through `readPlistJson` when it exists (one
 *  that exists but cannot be converted is `unreadable`: Claude Code may
 *  read what Mandu cannot). Pure over its readers. */
export function readClaudeSettingsSources(
  files: readonly ClaudeSettingsFile[],
  io: { readFile: (p: string) => string | null; readPlistJson: (p: string) => string | null; exists: (p: string) => boolean },
): Array<ClaudeSettingsFile & { text: string | null; unreadable?: boolean }> {
  return files.map((f) => {
    if (f.format !== "plist") return { ...f, text: io.readFile(f.path) };
    if (!io.exists(f.path)) return { ...f, text: null };
    const json = io.readPlistJson(f.path);
    return json === null ? { ...f, text: null, unreadable: true } : { ...f, text: json };
  });
}

/** The root Claude Code reads the local settings file at: for a linked
 *  worktree (`<root>/.git` is a FILE), its main checkout, checked the way
 *  Claude Code 2.1.286 checks it (`gitdir:` → `commondir`, whose
 *  `worktrees/` holds the gitdir, whose `gitdir` points back to this
 *  `.git`); else `root`. Pure over `readFile` and `realpath`. */
export function claudeCanonicalRoot(
  root: string,
  readFile: (p: string) => string | null = defaultReadFile,
  realpath: (p: string) => string | null = defaultRealpath,
): string {
  const text = readFile(join(root, ".git"));
  if (text === null) return root; // a directory (a main checkout), or none
  const t = text.trim();
  if (!t.startsWith("gitdir:")) return root;
  const gitdir = resolve(root, t.slice("gitdir:".length).trim());
  const common = readFile(join(gitdir, "commondir"));
  if (common === null) return root;
  const commonDir = resolve(gitdir, common.trim());
  if (dirname(gitdir) !== join(commonDir, "worktrees")) return root;
  const back = readFile(join(gitdir, "gitdir"));
  if (back === null) return root;
  const canon = (p: string): string => realpath(p) ?? normalize(p);
  if (canon(resolve(gitdir, back.trim())) !== join(canon(root), ".git")) return root;
  return basename(commonDir) === ".git" ? dirname(commonDir) : commonDir;
}

/** Everything claudeSettingsFiles needs that takes I/O, for a launch or the
 *  doctor in `cwd`: CLAUDE_CONFIG_DIR, the repository root and its
 *  canonical root, the managed drop-ins, the server-managed cache, the MDM
 *  user. */
export function claudeSettingsLocations(
  env: Record<string, string | undefined>,
  home: string,
  cwd: string,
  platform: NodeJS.Platform,
  io: { exists?: (p: string) => boolean; readFile?: (p: string) => string | null; listDir?: (dir: string) => string[] | null; realpath?: (p: string) => string | null; user?: string } = {},
): ClaudeSettingsLocations {
  const gitRoot = findGitRoot(cwd, io.exists ?? existsSync);
  const listDir = io.listDir ?? defaultListDir;
  return {
    configDir: claudeConfigDir(env, home),
    gitRoot,
    canonicalRoot: gitRoot !== null ? claudeCanonicalRoot(gitRoot, io.readFile ?? defaultReadFile, io.realpath ?? defaultRealpath) : null,
    dropIns: listDir(join(dirname(claudeManagedSettings(platform)), "managed-settings.d")) ?? [],
    remote: true,
    // Claude Code names the per-user MDM file after os.userInfo().username.
    ...(platform === "darwin" ? { mdmUser: io.user ?? osUserName(env) } : {}),
    ...(coworkUserFile(env) !== null ? { userFiles: coworkUserFile(env)! } : {}),
  };
}

function osUserName(env: Record<string, string | undefined>): string {
  try { return userInfo().username; } catch { return env["USER"] ?? ""; }
}

/** CLAUDE_CODE_USE_COWORK_PLUGINS makes Claude Code read
 *  `cowork_settings.json` as the user file instead of `settings.json`: the
 *  file names to read (both when the value is not clearly on or off), or
 *  null for the default. */
function coworkUserFile(env: Record<string, string | undefined>): string[] | null {
  const v = (env["CLAUDE_CODE_USE_COWORK_PLUGINS"] ?? "").trim();
  if (/^(|0|false|no|off)$/i.test(v)) return null;
  return /^(1|true|yes|on)$/i.test(v) ? ["cowork_settings.json"] : ["settings.json", "cowork_settings.json"];
}

function defaultListDir(dir: string): string[] | null {
  try { return readdirSync(dir); } catch { return null; }
}

/**
 * What the launch says and does about it. `confined` are the paths Mandu
 * registered (twins), `maskedEnv` the variables it replaced by symbols.
 * Overlaps are by normalized path / exact name. A `deny` entry on a confined
 * file is NOT an overlap (the sandboxed command gets EACCES instead of the
 * twin; strictly more restrictive, nothing to undo) but is mentioned once.
 *
 * `platform` (default this process's) and `outerSeatbelt` (macOS: the launch
 * wraps the agent in Mandu's Seatbelt profile, i.e. it protects secrets;
 * default true on macOS) pick the macOS wording: a WARNING that Claude Code's
 * sandbox cannot start inside Mandu's profile, naming the setting.
 */
export function assessClaudeSandbox(
  view: ClaudeSandboxView,
  opts: {
    confined: readonly string[];
    maskedEnv: readonly string[];
    arbiterSock: string;
    platform?: NodeJS.Platform;
    outerSeatbelt?: boolean;
    realpath?: (p: string) => string | null;
    humanDirs?: readonly string[];
  },
): ClaudeSandboxAssessment {
  const platform = opts.platform ?? process.platform;
  const outerSeatbelt = platform === "darwin" && (opts.outerSeatbelt ?? true);
  const notes: string[] = [];
  for (const err of view.errors) notes.push(`WARNING: mandu: Claude Code settings file could not be parsed: ${err}`);
  const confined = new Set(opts.confined.map((p) => normalize(p)));
  const masked = new Set(opts.maskedEnv);
  const doubleMaskedFiles = view.files.filter((f) => f.mode === "mask" && confined.has(f.resolved)).map((f) => ({ path: f.path, source: f.source }));
  const deniedToo = view.files.filter((f) => f.mode !== "mask" && confined.has(f.resolved));
  const doubleMaskedEnv = view.envVars.filter((e) => e.mode === "mask" && masked.has(e.name)).map((e) => ({ name: e.name, source: e.source }));

  if (view.enabled && outerSeatbelt) {
    // ONE line, a WARNING (the compact launch display shows it).
    notes.push(
      `WARNING: mandu: Claude Code's own sandbox is ON (${view.enabledBy.join(", ")}), and on macOS it cannot start inside ` +
      "Mandu's Seatbelt profile (macOS refuses a sandbox inside a sandbox: sandbox_apply: Operation not permitted), so every " +
      `Bash command Claude Code sandboxes will fail. Turn it off for sessions under mandu: set "sandbox": { "enabled": false } in ` +
      `${view.enabledBy.join(" and ")} (or run /sandbox in Claude Code). Mandu's profile still keeps every program the AI runs ` +
      "from reading your credential files.",
    );
  } else if (view.enabled && platform === "darwin") {
    notes.push(
      `mandu: Claude Code's own sandbox is ON (${view.enabledBy.join(", ")}): its Bash runs in its own Seatbelt sandbox (no Mandu ` +
      "profile around this launch). The arbiter socket is passed through sandbox.network.allowUnixSockets, in every spelling macOS " +
      "compares, so the shims inside it keep their channel (plan 10 §12.3).",
    );
  } else if (view.enabled) {
    notes.push(
      `mandu: Claude Code's own sandbox is ON (${view.enabledBy.join(", ")}): its Bash runs in a second bubblewrap inside ` +
      "Mandu's; Mandu's guard still sees those commands' opens and connects (the two seccomp filters stack). " +
      "The arbiter socket is passed through sandbox.network.allowUnixSockets so the shims inside it keep their channel (plan 10 §12.3).",
    );
  }
  if (doubleMaskedFiles.length > 0) {
    const bySource = new Map<string, string[]>();
    for (const f of doubleMaskedFiles) bySource.set(f.source, [...(bySource.get(f.source) ?? []), f.path]);
    for (const [source, paths] of bySource) {
      notes.push(
        `WARNING: mandu: ${paths.length} credential file${paths.length === 1 ? " is" : "s are"} masked TWICE — by Claude Code's ` +
        `sandbox.credentials.files in ${source} (${paths.join(", ")}) and by Mandu's structured twin. Inside Claude Code's sandbox a ` +
        "command reads their sentinel copy instead of Mandu's twin, so field symbols and reader rules do not apply there. Remove " +
        `${paths.length === 1 ? "that entry" : "those entries"} from ${source}: Mandu's twin covers the AI's own reads and the whole ` +
        "process tree, Claude Code's covers sandboxed Bash only (plan 10 §12.3).",
      );
    }
  }
  if (deniedToo.length > 0) {
    notes.push(
      `mandu: Claude Code's sandbox DENIES ${deniedToo.length} file${deniedToo.length === 1 ? "" : "s"} Mandu confines ` +
      `(${deniedToo.map((f) => f.path).join(", ")}, ${[...new Set(deniedToo.map((f) => f.source))].join(", ")}): inside its box those reads ` +
      "fail instead of showing the twin. Stricter, not a conflict; remove the entries if a sandboxed command needs the twin.",
    );
  }
  if (doubleMaskedEnv.length > 0) {
    const bySource = new Map<string, string[]>();
    for (const e of doubleMaskedEnv) bySource.set(e.source, [...(bySource.get(e.source) ?? []), e.name]);
    for (const [source, names] of bySource) {
      notes.push(
        `WARNING: mandu: ${names.length} environment variable${names.length === 1 ? " is" : "s are"} masked TWICE — by Claude Code's ` +
        `sandbox.credentials.envVars in ${source} (${names.join(", ")}) and by Mandu's env-var symbols. The value Mandu hands the agent ` +
        `is already a symbol; Claude Code's mask then replaces the symbol with its own sentinel and its proxy has no real value to inject. ` +
        `Remove ${names.length === 1 ? "that entry" : "those entries"} from ${source} (plan 10 §12.3).`,
      );
    }
  }
  // The arbiter's HUMAN PLANE (arbiter-human-plane.md) never rides through
  // the overlay: an entry that equals, contains or lies in a human-plane
  // directory is left out (whoever named it, the arbiter socket included),
  // and one in the user's own settings is named (the guard and the twin wrap
  // still refuse the connect; Claude Code merges the file's list with ours).
  const humanDirs = opts.humanDirs ?? [];
  const ownHuman = view.allowUnixSockets.filter((p) => touchesHumanPlane(p, humanDirs));
  if (ownHuman.length > 0) {
    notes.push(
      `WARNING: mandu: Claude Code's sandbox.network.allowUnixSockets names Mandu's human-plane socket directory (${ownHuman.join(", ")}): ` +
      "Mandu leaves it out of its own overlay and its guard refuses those connects anyway; remove the entry.",
    );
  }
  const socks = unixSocketSpellings(opts.arbiterSock, platform, opts.realpath ?? defaultRealpath);
  const settingsOverlay = view.enabled
    ? { sandbox: { network: { allowUnixSockets: [...new Set([...view.allowUnixSockets, ...socks])].filter((p) => !touchesHumanPlane(p, humanDirs)) } } }
    : null;
  return { notes, doubleMaskedFiles, doubleMaskedEnv, settingsOverlay };
}

/** Plain recursive merge for the settings overlay: objects merge, string
 *  lists union, anything else is taken from the overlay. */
export function mergeSettings(base: unknown, overlay: unknown): unknown {
  if (Array.isArray(base) && Array.isArray(overlay)) return [...new Set([...base, ...overlay])];
  if (isRecord(base) && isRecord(overlay)) {
    const out: Record<string, unknown> = { ...base };
    for (const [k, v] of Object.entries(overlay)) out[k] = k in out ? mergeSettings(out[k], v) : v;
    return out;
  }
  return overlay;
}

/**
 * Splice the overlay into the launch's `--settings` argument: merged into an
 * existing inline JSON `--settings` (commander keeps the LAST `--settings`,
 * so two of them would drop the first: the TUI pin, env-compose.ts), appended
 * as a new one otherwise. A `--settings <file>` (not inline JSON) is left
 * alone and the overlay added after it — Claude Code merges both.
 */
export function mergeClaudeSettingsArg(argvPrefix: string[], overlay: Record<string, unknown>): void {
  for (let i = 0; i + 1 < argvPrefix.length; i++) {
    if (argvPrefix[i] !== "--settings") continue;
    const raw = argvPrefix[i + 1]!;
    if (!raw.trimStart().startsWith("{")) continue;
    try {
      const cur = JSON.parse(raw) as unknown;
      if (isRecord(cur)) { argvPrefix[i + 1] = JSON.stringify(mergeSettings(cur, overlay)); return; }
    } catch { /* not ours; fall through and append */ }
  }
  argvPrefix.push("--settings", JSON.stringify(overlay));
}

/** The I/O wrapper the launch and doctor call. `platform` defaults to this
 *  process's; `outerSeatbelt` (macOS) to true: pass false for a launch that
 *  does not wrap the agent in Mandu's profile (secret protection off). */
export function checkClaudeSandbox(opts: {
  home: string;
  cwd: string;
  confined: readonly string[];
  maskedEnv: readonly string[];
  arbiterSock: string;
  humanDirs?: readonly string[];
  readFile?: (p: string) => string | null;
  platform?: NodeJS.Platform;
  outerSeatbelt?: boolean;
  realpath?: (p: string) => string | null;
  /** Where the settings live beyond the fixed files (claudeSettingsLocations). */
  locations?: ClaudeSettingsLocations;
  /** Reads an MDM property list as JSON, and whether a path exists. */
  readPlistJson?: (p: string) => string | null;
  exists?: (p: string) => boolean;
}): ClaudeSandboxAssessment & { view: ClaudeSandboxView } {
  const platform = opts.platform ?? process.platform;
  const readFile = opts.readFile ?? defaultReadFile;
  const files = readClaudeSettingsSources(claudeSettingsFiles(opts.home, opts.cwd, platform, opts.locations ?? {}), {
    readFile,
    readPlistJson: opts.readPlistJson ?? (() => null),
    exists: opts.exists ?? existsSync,
  });
  const view = readClaudeSandbox(files, opts.home, opts.cwd);
  return { ...assessClaudeSandbox(view, { ...opts, platform }), view };
}

// ── macOS: turning Claude Code's own sandbox off for the session ─────────────

/** The LAST `--settings` of a Claude Code argv before `--` (Claude Code reads
 *  only that one), with its position and spelling, or null. */
export function claudeArgvSettings(argv: readonly string[]): { index: number; form: "split" | "eq"; value: string } | null {
  let found: { index: number; form: "split" | "eq"; value: string } | null = null;
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--") break;
    if (a === "--settings" && i + 1 < argv.length) { found = { index: i, form: "split", value: argv[i + 1]! }; i++; continue; }
    if (a.startsWith("--settings=")) found = { index: i, form: "eq", value: a.slice("--settings=".length) };
  }
  return found;
}

/** The options of an argv that change which settings Claude Code reads
 *  (`--setting-sources`, `--managed-settings`, `--project-config-root`), in
 *  either spelling, to repeat on the status probe. The whole argv is
 *  scanned: Claude Code may take a `--` as an option's value and read on. */
export function claudeArgvSettingSources(argv: readonly string[]): string[] {
  const out: string[] = [];
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    for (const o of ["--setting-sources", "--managed-settings", "--project-config-root"]) {
      if (a === o && i + 1 < argv.length) { out.push(a, argv[i + 1]!); i++; break; }
      if (a.startsWith(`${o}=`)) { out.push(a); break; }
    }
  }
  return out;
}

/** A `--settings` value as Claude Code reads it: inline JSON when it looks
 *  like an object, else a file of at most 2 MiB. Null when it cannot be read
 *  or is not a JSON object. */
export function parseClaudeSettingsValue(value: string, readFile: (p: string) => string | null): Record<string, unknown> | null {
  const t = value.trim();
  const text = t.startsWith("{") && t.endsWith("}") ? t : readFile(value);
  if (text === null) return null;
  try {
    const doc = JSON.parse(text) as unknown;
    return isRecord(doc) ? doc : null;
  } catch {
    return null;
  }
}

/** What `claude sandbox status` (read-only, no model; Claude Code 2.1.286)
 *  answers: is the sandbox on, and from which source. */
export interface ClaudeSandboxStatus { enabled: boolean; source: string | null }

/** Parse the status probe's output: its last JSON line, which must carry a
 *  `statusVersion` and a boolean `enabled`. Null otherwise. */
export function parseClaudeSandboxStatus(out: string): ClaudeSandboxStatus | null {
  const lines = out.split("\n").map((l) => l.trim()).filter((l) => l.startsWith("{"));
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const doc = JSON.parse(lines[i]!) as unknown;
      if (isRecord(doc) && typeof doc["statusVersion"] === "number" && typeof doc["enabled"] === "boolean") {
        return { enabled: doc["enabled"], source: typeof doc["enabledSource"] === "string" ? doc["enabledSource"] : null };
      }
    } catch { /* not this line */ }
  }
  return null;
}

/** Run the status probe with `args` (`--settings` / `--setting-sources` of
 *  the launch) in `cwd` (project settings are read from there), or null when
 *  this Claude Code has none (an older one) or it fails. */
export function realClaudeSandboxStatus(bin: string, args: readonly string[], env: Record<string, string | undefined>, cwd: string): ClaudeSandboxStatus | null {
  // A Claude Code without the subcommand could take "sandbox status" for a
  // prompt: the caller runs this only on a version that has it
  // (CLAUDE_SANDBOX_STATUS_SINCE), and the child gets no credential and a
  // dead model endpoint, so no model turn can happen outside Mandu.
  const probeEnv: Record<string, string | undefined> = { ...env, ANTHROPIC_BASE_URL: "http://127.0.0.1:9", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1" };
  for (const k of ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"]) delete probeEnv[k];
  const r = spawnSync(bin, [...args, "sandbox", "status"], { cwd, env: probeEnv as NodeJS.ProcessEnv, encoding: "utf8", timeout: 5000, stdio: ["ignore", "pipe", "pipe"] });
  return r.status === 0 && typeof r.stdout === "string" ? parseClaudeSandboxStatus(r.stdout) : null;
}

/** The oldest Claude Code checked to have `claude sandbox status`
 *  (2.1.284, 2.1.285 and 2.1.286 on this Mac, 2026-10-02). */
export const CLAUDE_SANDBOX_STATUS_SINCE = "2.1.284";

/** May a launch run the status probe on this Claude Code (its `--version`
 *  output)? Only on a version known to have it: an older one takes
 *  "sandbox status" for a prompt. Unknown = no. */
export function claudeStatusProbeAllowed(version: string | null | undefined): boolean {
  const v = parseAgentVersion(version ?? null);
  return v !== null && compareAgentVersions(v, parseAgentVersion(CLAUDE_SANDBOX_STATUS_SINCE)!) >= 0;
}

/** A settings file Claude Code would read for `--settings <path>` (a regular
 *  file of at most 2 MiB). */
export function readClaudeSettingsFile(p: string): string | null {
  try {
    const st = statSync(p);
    if (!st.isFile() || st.size > 2 * 1024 * 1024) return null;
    return readFileSync(p, "utf8");
  } catch {
    return null;
  }
}

/** Claude Code subcommands that start no session (no model, no Bash). */
export const CLAUDE_NON_SESSION: ReadonlySet<string> = new Set([
  "mcp", "config", "doctor", "update", "upgrade", "install", "migrate-installer", "setup-token", "plugin", "plugins", "sandbox", "auth",
  "auto-mode", "import", "project", "ultrareview", "gateway",
]);

/** Does this Claude Code argv start a session (the TUI or `-p`)? Not for
 *  `--version` / `--help` before `--`, nor a subcommand that runs no
 *  session. */
export function claudeRunsSession(argv: readonly string[]): boolean {
  if (argv[1] !== undefined && CLAUDE_NON_SESSION.has(argv[1])) return false;
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--") break;
    if (a === "--version" || a === "-v" || a === "--help" || a === "-h") return false;
  }
  return true;
}

/** The ONE launch line when Mandu turns Claude Code's sandbox off (the
 *  attention pattern "own sandbox is OFF for this session", launch-banner.ts). */
export const CLAUDE_SANDBOX_OFF_NOTE =
  "mandu: Claude Code's own sandbox is OFF for this session: macOS cannot start it inside Mandu's profile. " +
  "Mandu's profile still keeps your credential files from the commands Claude runs, but Claude Code's own limits " +
  "on where they write and connect do not apply, and Bash asks for permission as usual.";
/** …in a mode whose profile blocks no credential file (mode `off`). */
export const CLAUDE_SANDBOX_OFF_NOTE_NO_CREDS =
  "mandu: Claude Code's own sandbox is OFF for this session: macOS cannot start it inside Mandu's profile. " +
  "In this mode Mandu's profile does not block your credential files either, Claude Code's own limits on where " +
  "its commands write and connect do not apply, and Bash asks for permission as usual.";

const defaultIsDir = (p: string): boolean => { try { return statSync(p).isDirectory(); } catch { return false; } };
const defaultHasContent = (p: string): boolean => { try { return statSync(p).size > 0; } catch { return false; } };
/** How deep Mandu's secret discovery walks below a root (arbiter
 *  secret-discovery.ts MAX_DEPTH): a file's folder at most this deep. */
const DISCOVERY_DEPTH = 4;

const KEEPS = "and on macOS it cannot start inside Mandu's Seatbelt profile (sandbox_apply: Operation not permitted), so every Bash command it sandboxes will fail";

/** The plan for one macOS launch whose Mandu profile is applied: the notes,
 *  and the argv and prefix to launch with when Mandu turns the sandbox off
 *  (copies; the inputs are not changed). Pure over `probe` and `readFile`;
 *  `confined` / `maskedEnv` are what Mandu protects itself (read-blocks or
 *  twins, env-var symbols), `credsBlocked` whether this launch's profile
 *  blocks credential files at all (not in mode `off`), `managedPath` the
 *  managed settings file for the no-probe fallback. The order of the checks
 *  is the order of what must not be overridden: the run's own choice, a
 *  `--settings` FILE (never copied onto the command line, where every
 *  program the agent runs can read it), managed settings (the second probe),
 *  a source Mandu reads but cannot parse, the sandbox on from a source Mandu
 *  does not read (their rules unknown), then protections only Claude Code's
 *  sandbox gives. */
export function planDarwinClaudeSandbox(input: {
  argv: readonly string[];
  argvPrefix: readonly string[];
  view: ClaudeSandboxView;
  confined: readonly string[];
  maskedEnv: readonly string[];
  probe: (args: string[]) => ClaudeSandboxStatus | null;
  readFile: (p: string) => string | null;
  home?: string;
  credsBlocked?: boolean;
  managedPath?: string;
  realpath?: (p: string) => string | null;
  /** Is this path a folder? Optional: absent = stat it. */
  isDir?: (p: string) => boolean;
  /** Is this path a file with something in it (Mandu protects only those)?
   *  Optional: absent = stat it. */
  hasContent?: (p: string) => boolean;
  /** Where Mandu's secret discovery looks (HOME and the launch folder): a
   *  file elsewhere cannot be protected by a label. Optional: absent = any
   *  file counts as reachable. */
  scanRoots?: readonly string[];
}): { notes: string[]; off: boolean; argv?: string[]; argvPrefix?: string[] } {
  const realpath = input.realpath ?? defaultRealpath;
  const credsBlocked = input.credsBlocked !== false;
  const stillProtects = credsBlocked ? "; Mandu's profile still keeps every program the AI runs from reading your credential files" : "";
  const user = claudeArgvSettings(input.argv);
  const sources = claudeArgvSettingSources(input.argv);
  const before = input.probe([...sources, ...(user ? ["--settings", user.value] : [])]);
  // Options that add or move a settings source Mandu does not read (an
  // embedding host's managed settings, another project config root): the
  // probe sees them; without it, Mandu cannot tell whether they turn the
  // sandbox on, and says so.
  const moved = claudeArgvSettingsMoves(input.argv);
  if (before === null && moved.length > 0 && !input.view.enabled) {
    return { notes: [`WARNING: mandu: this run passes ${moved.join(" and ")}, settings Mandu does not read: if they turn Claude Code's own sandbox on, ${KEEPS.replace(/^and /, "")}.`], off: false };
  }
  const wouldBeOn = before !== null ? before.enabled : input.view.enabled;
  if (!wouldBeOn) return { notes: [], off: false };
  const named = input.view.enabledBy.length > 0 ? ` (${input.view.enabledBy.join(", ")})` : "";
  const keep = (where: string, why: string): { notes: string[]; off: false } => ({ notes: [`WARNING: mandu: Claude Code's own sandbox is ON${where}, ${KEEPS}. ${why}`], off: false });
  if (moved.length > 0) {
    return keep(named, `This run passes ${moved.join(" and ")}, settings Mandu does not read, so it cannot check what their sandbox rules protect and leaves it on.`);
  }

  let userParsed: Record<string, unknown> | null = null;
  if (user) {
    userParsed = parseClaudeSettingsValue(user.value, input.readFile);
    const sb = userParsed?.["sandbox"];
    const t = user.value.trim();
    const inline = t.startsWith("{") && t.endsWith("}");
    if (isRecord(sb) && sb["enabled"] === true) {
      // Mandu never turns it off for a --settings FILE, so the advice for
      // one names both steps.
      return keep(" for this run (your --settings)", inline
        ? `Drop sandbox.enabled from that --settings and Mandu turns it off for the session${stillProtects}.`
        : `Drop sandbox.enabled from that settings file (${user.value}) and pass its settings inline (Mandu does not copy a settings file onto the command line, where every program the AI runs could read it), and Mandu turns it off for the session${stillProtects}.`);
    }
    if (!inline) {
      return keep(named, `This run's --settings is a file (${user.value}): Mandu does not copy a settings file onto the command line, where every program the AI runs could read it, so it leaves the sandbox on. Pass those settings inline and Mandu turns it off for the session.`);
    }
    if (userParsed === null) return keep(named, "Mandu could not add its setting to this run's --settings (not a JSON object), so it leaves the sandbox on.");
  }

  const overlay = { sandbox: { enabled: false } };
  const argv: string[] = [...input.argv];
  const argvPrefix: string[] = [...input.argvPrefix];
  let finalSettings: string;
  if (user && userParsed) {
    finalSettings = JSON.stringify(mergeSettings(userParsed, overlay));
    if (user.form === "split") argv[user.index + 1] = finalSettings;
    else argv[user.index] = `--settings=${finalSettings}`;
  } else {
    mergeClaudeSettingsArg(argvPrefix, overlay);
    const own = claudeArgvSettings(["claude", ...argvPrefix]);
    finalSettings = own ? own.value : JSON.stringify(overlay);
  }
  const after = input.probe([...sources, "--settings", finalSettings]);
  // Without the probe: any managed source that turns it on (the managed
  // file, a drop-in, the server-managed cache, MDM preferences).
  const managedOn = after !== null ? after.enabled
    : (input.view.enabledByManaged?.length ?? 0) > 0 || (input.managedPath !== undefined && input.view.enabledBy.includes(input.managedPath));
  if (managedOn) return keep(" by your organization's managed settings", "Mandu cannot turn managed settings off: ask your administrator to allow it off for sessions under mandu.");
  // A source Mandu reads but cannot parse or convert (or an administrator's
  // policy helper) may hold rules Claude Code applies, so it is not
  // overridden.
  const unread = [...(input.view.unreadable ?? []), ...input.view.errors.map((e) => e.replace(/: .*$/, ""))];
  if (unread.length > 0) {
    return keep(named, `Mandu cannot read ${[...new Set(unread)].join(", ")}, so it cannot check what its sandbox rules protect and leaves it on: fix that file, or turn the sandbox off for sessions under mandu ("sandbox": { "enabled": false }, or /sandbox).`);
  }
  // Claude Code says it is on, but no settings source Mandu reads turns it
  // on: the one that does may also hold rules Mandu cannot check, so it is
  // not overridden.
  if (before !== null && !input.view.enabled) {
    return keep(" from settings Mandu cannot read", 'Mandu cannot check what their sandbox rules protect, so it leaves it on: turn it off for sessions under mandu ("sandbox": { "enabled": false }, or /sandbox).');
  }
  const flagRules = userParsed ? sandboxRulesOf(userParsed) : { files: [], envVars: [], denyRead: [], readRules: [], blockReadsOutside: false };
  // Reads outside the working directories, blocked only inside its sandbox:
  // Mandu has nothing like it.
  const blockOutside = [...(input.view.blockReadsOutside ?? []), ...(flagRules.blockReadsOutside ? ["this run's --settings"] : [])];
  if (blockOutside.length > 0) {
    return keep(named, `Its permissions.blockReadsOutsideWorkingDirectories (${blockOutside.join(", ")}) keeps the commands Claude runs from reading any home or volume outside the working directories, which Mandu does not do, so it leaves it on: drop that setting for sessions under mandu and Mandu turns Claude Code's sandbox off for the session.`);
  }

  // Its credential and read-deny rules apply only inside its sandbox: off, a
  // file or variable they protect and Mandu does not would become readable.
  // Mandu protects single files that exist, so a folder or a glob, a
  // relative path (resolved by Claude Code against a root Mandu does not
  // second-guess), and a missing or empty file never count as covered,
  // whatever policy.yaml labels; each gets advice that can work.
  const canon = (p: string): string => realpath(p) ?? normalize(p);
  const protectedFiles = new Set(credsBlocked ? input.confined.map(canon) : []);
  const protectedEnv = new Set(credsBlocked ? input.maskedEnv : []);
  const home = input.home ?? "";
  const isDir = input.isDir ?? defaultIsDir;
  const hasContent = input.hasContent ?? defaultHasContent;
  const expandFlag = (p: string): string | null => {
    const t = p.trim();
    if (t.startsWith("//")) return normalize(t.slice(1));
    if (t === "~") return home;
    if (t.startsWith("~/")) return join(home, t.slice(2));
    return isAbsolute(t) ? normalize(t) : null;
  };
  const labelable: string[] = [];
  const notSingleFiles: string[] = [];
  const relative: string[] = [];
  const absent: string[] = [];
  const outside: string[] = [];
  // Where Mandu's secret discovery looks (a label elsewhere finds nothing):
  // under each root, files at most DISCOVERY_DEPTH folders down.
  const roots = (input.scanRoots ?? []).map(canon);
  const discoverable = (p: string): boolean => roots.length === 0 || roots.some((r) => {
    const rel = relative_(r, p);
    return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel) && rel.split("/").length - 1 <= DISCOVERY_DEPTH;
  });
  const pathRule = (written: string, resolved: string | null): void => {
    const w = written.trim();
    const read = /^Read\((.*)\)$/s.exec(w);
    const inner = read ? claudeRuleContent(read[1]!) : w;
    if (inner.endsWith("/") || /[*?[\]{}]/.test(inner.replace(/\\[*?[\]{}]/g, ""))) { notSingleFiles.push(w); return; }
    if (resolved === null || resolved === "" || !isAbsolute(resolved) || !/^(\/|~)/.test(inner)) { relative.push(w); return; }
    if (isDir(resolved)) { notSingleFiles.push(w); return; }
    if (protectedFiles.has(canon(resolved))) return;
    if (!hasContent(resolved)) { absent.push(w); return; }
    if (!discoverable(canon(resolved))) { outside.push(w); return; }
    labelable.push(w);
  };
  for (const f of input.view.files) pathRule(f.path, f.resolved);
  for (const d of input.view.denyRead ?? []) pathRule(d.path, d.resolved);
  for (const p of [...flagRules.files, ...flagRules.denyRead]) pathRule(p, expandFlag(p));
  for (const r of flagRules.readRules) pathRule(r, claudeReadDenyPath(r, home)?.resolved ?? null);
  for (const e of input.view.envVars) if (!protectedEnv.has(e.name)) labelable.push(`$${e.name}`);
  for (const n of flagRules.envVars) if (!protectedEnv.has(n)) labelable.push(`$${n}`);
  if (labelable.length + notSingleFiles.length + relative.length + absent.length + outside.length > 0) {
    const inSecrets = credsBlocked ? "" : "in mode secrets, ";
    const list = (xs: string[]): string => [...new Set(xs)].join(", ");
    const parts: string[] = [];
    if (labelable.length > 0) parts.push(`${list(labelable)}, which Mandu does not protect: ${inSecrets}label them in Mandu's policy (policy.yaml)`);
    if (notSingleFiles.length > 0) {
      parts.push(`${list(notSingleFiles)}, which ${notSingleFiles.length === 1 ? "is" : "are"} not a single file Mandu can protect: ` +
        `${inSecrets}list the files themselves instead (and label those in Mandu's policy), or remove that entry for sessions under mandu`);
    }
    if (relative.length > 0) {
      parts.push(`${list(relative)}, which ${relative.length === 1 ? "is a relative path" : "are relative paths"} Mandu does not resolve: ` +
        `${inSecrets}write ${relative.length === 1 ? "it" : "them"} as an absolute path (\`//path\` in a Read rule) and label that file in Mandu's policy, or remove that entry for sessions under mandu`);
    }
    if (absent.length > 0) {
      parts.push(`${list(absent)}, which ${absent.length === 1 ? "is" : "are"} missing or empty on this Mac (Mandu protects only files that exist when the session starts, so a label cannot help): ` +
        "remove that entry for sessions under mandu");
    }
    if (outside.length > 0) {
      parts.push(`${list(outside)}, which ${outside.length === 1 ? "lies" : "lie"} outside where Mandu looks for files to protect (your home folder and this launch's folder, ${DISCOVERY_DEPTH} folders deep), so a label cannot help: ` +
        "remove that entry for sessions under mandu");
    }
    return keep(named, `Mandu leaves it on because its sandbox rules (sandbox.credentials, sandbox.filesystem.denyRead, permissions.deny Read rules) protect ${parts.join("; and ")}; then Mandu turns Claude Code's sandbox off for the session.`);
  }
  return { notes: [credsBlocked ? CLAUDE_SANDBOX_OFF_NOTE : CLAUDE_SANDBOX_OFF_NOTE_NO_CREDS], off: true, argv, argvPrefix };
}

/** The options of a Claude Code argv that add or move a settings source
 *  Mandu does not read: `--managed-settings` (an embedding host's managed
 *  settings) and `--project-config-root` (another folder's project and
 *  local files), in either spelling, anywhere (Claude Code may take a `--`
 *  as an option's value and read on; a false match only keeps the
 *  sandbox). */
export function claudeArgvSettingsMoves(argv: readonly string[]): string[] {
  const out = new Set<string>();
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    for (const o of ["--managed-settings", "--project-config-root"]) if (a === o || a.startsWith(`${o}=`)) out.add(o);
  }
  return [...out];
}

/** The sandbox rules of one settings object (a run's own `--settings`):
 *  credential files and variables (both modes: Claude Code honours `mask`
 *  from `--settings`), read-denies and `permissions.deny` `Read(...)`
 *  rules, as written, and whether it blocks reads outside the working
 *  directories. */
function sandboxRulesOf(doc: Record<string, unknown>): { files: string[]; envVars: string[]; denyRead: string[]; readRules: string[]; blockReadsOutside: boolean } {
  const out = { files: [] as string[], envVars: [] as string[], denyRead: [] as string[], readRules: [] as string[], blockReadsOutside: false };
  const perms = doc["permissions"];
  if (isRecord(perms)) {
    if (Array.isArray(perms["deny"])) for (const r of perms["deny"]) if (typeof r === "string" && /^\s*Read\(.+\)\s*$/s.test(r)) out.readRules.push(r);
    out.blockReadsOutside = perms["blockReadsOutsideWorkingDirectories"] === true;
  }
  const sb = doc["sandbox"];
  if (!isRecord(sb)) return out;
  const cred = sb["credentials"];
  if (isRecord(cred)) {
    if (Array.isArray(cred["files"])) for (const e of cred["files"]) if (isRecord(e) && typeof e["path"] === "string") out.files.push(e["path"]);
    if (Array.isArray(cred["envVars"])) for (const e of cred["envVars"]) if (isRecord(e) && typeof e["name"] === "string") out.envVars.push(e["name"]);
  }
  const fsr = sb["filesystem"];
  if (isRecord(fsr) && Array.isArray(fsr["denyRead"])) for (const d of fsr["denyRead"]) if (typeof d === "string" && d !== "") out.denyRead.push(d);
  return out;
}

/** Claude Code's user config directory: CLAUDE_CONFIG_DIR, else ~/.claude. */
export function claudeConfigDir(env: Record<string, string | undefined>, home: string): string {
  const d = env["CLAUDE_CONFIG_DIR"]?.trim();
  return d ? normalize(d) : join(home, ".claude");
}

/** The repository root above `cwd` (the nearest folder with a `.git`), or
 *  null. */
export function findGitRoot(cwd: string, exists: (p: string) => boolean = existsSync): string | null {
  let dir = normalize(cwd);
  for (;;) {
    if (exists(join(dir, ".git"))) return dir;
    const up = dirname(dir);
    if (up === dir) return null;
    dir = up;
  }
}

