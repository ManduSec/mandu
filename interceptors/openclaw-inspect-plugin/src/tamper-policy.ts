/**
 * tamper-policy — the `before_tool_call` refusal of a tool call that names
 * Mandu's own state, the OpenClaw config that routes the model through Mandu,
 * or stopping the Mandu service (docs/design/agents/openclaw-plugin.md §3.6).
 *
 * Mandu OpenClaw plugin (interceptors/openclaw-inspect-plugin). PURE: the
 * paths come in a TamperContext the registrar builds once; nothing here reads
 * the environment or the filesystem. Mandu-new (no reference origin).
 *
 * A POLICY AGAINST OBVIOUS ATTEMPTS, NOT A BOUNDARY. The plugin runs inside
 * the Gateway, and the agent's programs run as the same user as Mandu: they
 * can edit `openclaw.json`, stop the service or read `~/.mandu` by any route
 * this check does not spell (a relative path after `cd ~`, a variable built
 * from pieces, `bash -c "$(base64 -d …)"`, a script file written first and
 * run second). This catches a model that asks plainly, and says why, so the
 * human can do it themselves. Running the Gateway itself under
 * `mandu openclaw gateway` is the confined form; the posture sentence of an
 * attachment session says so.
 *
 * WHAT IT READS: every string in the tool call's params (nested objects and
 * arrays, bounded), and the host's `derivedPaths` hint, for every tool: the
 * shell's `command`, a read or write tool's `path`, an `apply_patch` body, a
 * URL. A match anywhere refuses the call.
 *
 * THE RULES (each with near-miss negatives in test/unit/tamper-policy.test.ts):
 *   mandu-state      `~/.mandu` (also `$HOME/.mandu`, `${HOME}/.mandu`, the
 *                    home spelled out), `$MANDU_HOME`, `$MANDU_RUNTIME_DIR`,
 *                    `$XDG_RUNTIME_DIR/mandu`, the systemd / launchd unit
 *                    files named mandu*, and every path in `manduPaths` (the
 *                    Mandu home, the runtime dir and the arbiter sockets
 *                    the installer and the plugin config name), each as a
 *                    whole path component (`~/.mandu-notes` passes).
 *   openclaw-config  `openclaw.json` as a file name, the resolved config path,
 *                    the config directory's other top-level `.json` / `.json5`
 *                    files (its `$include` files), the variables
 *                    `OPENCLAW_CONFIG_PATH` / `OPENCLAW_STATE_DIR` /
 *                    `OPENCLAW_INCLUDE_ROOTS`, the state directory itself and
 *                    its `extensions` folder (the installed plugins), and the
 *                    commands that rewrite the config (`openclaw config
 *                    set|unset|patch`, `openclaw configure|onboard|setup|
 *                    reset|uninstall`, `openclaw plugins disable|uninstall|
 *                    remove`). The state directory's other contents (the
 *                    agent's own workspace, `~/.openclaw/workspace`, its
 *                    sessions) pass.
 *   mandu-service    `mandu serve stop|uninstall|disable`, `mandu stop`,
 *                    `mandu reap`, `mandu mode <anything>`, `systemctl …
 *                    stop|disable|mask|kill|revert … mandu…`, `launchctl …
 *                    unload|bootout|remove|kill|stop|disable … mandu…`,
 *                    `pkill|killall … mandu`, `kill … $(pgrep|pidof … mandu)`.
 *                    `mandu serve status|start`, `systemctl --user status
 *                    mandu…`, `mandu doctor` pass.
 */

/** Which rule refused the call (the event's ruleRef id is `openclaw:tamper:<rule>`). */
export type TamperRule = "mandu-state" | "openclaw-config" | "mandu-service";

export type TamperVerdict =
  | { block: false }
  | { block: true; rule: TamperRule; what: string; reason: string };

/** The paths the rules name, resolved once by the registrar (absolute). */
export interface TamperContext {
  /** The account's home (the `~` the rules expand). */
  home: string;
  /** Mandu's own state: its home, its runtime dir, the arbiter sockets. */
  manduPaths: readonly string[];
  /** The OpenClaw config the Gateway reads ($OPENCLAW_CONFIG_PATH, else
   *  `<state>/openclaw.json`). */
  openclawConfigPath: string;
  /** OpenClaw's state directory ($OPENCLAW_STATE_DIR, else `~/.openclaw`). */
  openclawStateDir: string;
}

/** Bounds on what one call is scanned for (a call past them is scanned up
 *  to them: the policy is not a boundary, see the header). */
const MAX_STRINGS = 1024;
const MAX_DEPTH = 12;
const MAX_TOTAL_CHARS = 4 * 1024 * 1024;

/** Every string in `value` (objects, arrays, nested), bounded. Object KEYS
 *  are included: a patch format or a tool may carry a path as a key. */
export function collectStrings(value: unknown, out: string[] = [], depth = 0, budget = { chars: MAX_TOTAL_CHARS }): string[] {
  if (out.length >= MAX_STRINGS || depth > MAX_DEPTH || budget.chars <= 0) return out;
  if (typeof value === "string") {
    const s = value.length > budget.chars ? value.slice(0, budget.chars) : value;
    budget.chars -= s.length;
    out.push(s);
  } else if (Array.isArray(value)) {
    for (const v of value) collectStrings(v, out, depth + 1, budget);
  } else if (value !== null && typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      collectStrings(k, out, depth + 1, budget);
      collectStrings(v, out, depth + 1, budget);
    }
  }
  return out;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** A path ends here: not followed by a name character (a `.` counts only
 *  when a name character follows it, so `~/.mandu.` at a sentence's end is
 *  the path and `~/.mandu.bak` is not). */
const PATH_END = "(?![A-Za-z0-9_-]|\\.[A-Za-z0-9_])";
/** A path starts here: not preceded by a name character (so
 *  `/srv/x/home/u/.mandu` is not `/home/u/.mandu`; `file:///home/u/.mandu`
 *  and `//home/u/.mandu` are). */
const PATH_START = "(?<![A-Za-z0-9_.-])";

function trimSlash(p: string): string {
  return p.length > 1 ? p.replace(/\/+$/, "") : p;
}

/** The spellings of an absolute path the rules match: itself and, under the
 *  home, `~/…`, `$HOME/…` and `${HOME}/…`. */
function spellings(abs: string, home: string): string[] {
  const p = trimSlash(abs);
  const h = trimSlash(home);
  const out = [p];
  if (h !== "" && h !== "/" && (p === h || p.startsWith(`${h}/`))) {
    const rel = p.slice(h.length);
    out.push(`~${rel}`, `$HOME${rel}`, `\${HOME}${rel}`);
  }
  return out;
}

/** A regex matching any spelling of `abs` as a whole path (or a path under it
 *  when `under` is set). */
function pathRe(abs: string, home: string, under: boolean): RegExp {
  const alts = spellings(abs, home).map(escapeRe).join("|");
  return new RegExp(`${PATH_START}(?:${alts})${under ? "(?:/|" + PATH_END + ")" : PATH_END}`);
}

interface CompiledRule {
  rule: TamperRule;
  what: string;
  re: RegExp;
}

/** One command segment: no newline, `;`, `|` or `&` between the words. */
const SEG = "[^\\n;|&]*";

/** The fixed rules (no context needed). */
const FIXED_RULES: readonly CompiledRule[] = [
  // Mandu's own state, by its well-known spellings.
  { rule: "mandu-state", what: "~/.mandu (Mandu's own state)", re: new RegExp(`${PATH_START}(?:~|\\$HOME|\\$\\{HOME\\})/\\.mandu${PATH_END}`) },
  { rule: "mandu-state", what: "$MANDU_HOME (Mandu's own state)", re: /\$\{?MANDU_HOME\b/ },
  { rule: "mandu-state", what: "$MANDU_RUNTIME_DIR (Mandu's runtime dir)", re: /\$\{?MANDU_RUNTIME_DIR\b/ },
  { rule: "mandu-state", what: "$XDG_RUNTIME_DIR/mandu (Mandu's runtime dir)", re: new RegExp(`\\$\\{?XDG_RUNTIME_DIR\\}?/mandu${PATH_END}`) },
  { rule: "mandu-state", what: "the Mandu service's unit file", re: /(?:systemd\/user|LaunchAgents)\/[^\s'"]*mandu/i },
  // The OpenClaw config.
  { rule: "openclaw-config", what: "openclaw.json (the config that routes the model through Mandu)", re: /(?<![A-Za-z0-9_-])openclaw\.json(?![A-Za-z0-9_])/ },
  { rule: "openclaw-config", what: "an OPENCLAW_* config variable", re: /\bOPENCLAW_(?:CONFIG_PATH|STATE_DIR|INCLUDE_ROOTS)\b/ },
  { rule: "openclaw-config", what: "`openclaw config set|unset|patch`", re: new RegExp(`\\bopenclaw\\b${SEG}\\bconfig\\s+(?:set|unset|patch)\\b`) },
  { rule: "openclaw-config", what: "an OpenClaw command that rewrites its config", re: new RegExp(`\\bopenclaw\\s+(?:configure|onboard|setup|reset|uninstall)\\b`) },
  { rule: "openclaw-config", what: "`openclaw plugins disable|uninstall|remove`", re: new RegExp(`\\bopenclaw\\b${SEG}\\bplugins?\\s+(?:disable|uninstall|remove|rm)\\b`) },
  // Stopping or uninstalling the Mandu service.
  { rule: "mandu-service", what: "`mandu serve stop|uninstall|disable`", re: new RegExp(`\\bmandu\\b${SEG}\\bserve\\s+(?:stop|uninstall|disable)\\b`) },
  { rule: "mandu-service", what: "`mandu stop` / `mandu reap`", re: /\bmandu\s+(?:stop|reap)\b/ },
  { rule: "mandu-service", what: "`mandu mode` (changes what Mandu protects)", re: /\bmandu\s+mode\s+(?!-h\b|--help\b)[A-Za-z]/ },
  { rule: "mandu-service", what: "stopping the Mandu service with systemctl", re: new RegExp(`\\bsystemctl\\b${SEG}\\b(?:stop|disable|mask|kill|revert)\\b${SEG}mandu`) },
  { rule: "mandu-service", what: "stopping the Mandu service with launchctl", re: new RegExp(`\\blaunchctl\\b${SEG}\\b(?:unload|bootout|remove|kill|stop|disable)\\b${SEG}mandu`) },
  { rule: "mandu-service", what: "killing Mandu's processes", re: new RegExp(`\\b(?:pkill|killall)\\b${SEG}mandu`) },
  { rule: "mandu-service", what: "killing Mandu's processes", re: /\bkill\b[^\n;|&]*\$\((?:[^)]*\b(?:pgrep|pidof)\b[^)]*mandu)/ },
];

/** The rules that need the context's paths. Compiled per context. */
function contextRules(ctx: TamperContext): CompiledRule[] {
  const rules: CompiledRule[] = [];
  for (const p of ctx.manduPaths) {
    if (typeof p !== "string" || !p.startsWith("/") || trimSlash(p) === "/") continue;
    rules.push({ rule: "mandu-state", what: `${p} (Mandu's own state)`, re: pathRe(p, ctx.home, true) });
  }
  const cfg = trimSlash(ctx.openclawConfigPath);
  if (cfg.startsWith("/")) {
    rules.push({ rule: "openclaw-config", what: `${cfg} (the OpenClaw config)`, re: pathRe(cfg, ctx.home, false) });
    // The config directory's other top-level JSON files: its `$include`s
    // live there (an include must stay inside the config's directory unless
    // OPENCLAW_INCLUDE_ROOTS says otherwise), and a model entry in one
    // could carry its own baseUrl around the proxy.
    const dir = cfg.slice(0, cfg.lastIndexOf("/")) || "/";
    if (dir !== "/") {
      const alts = spellings(dir, ctx.home).map(escapeRe).join("|");
      rules.push({
        rule: "openclaw-config",
        what: `a JSON file in ${dir} (the OpenClaw config's directory)`,
        re: new RegExp(`${PATH_START}(?:${alts})/[^/\\s'"\`]+\\.json5?(?![A-Za-z0-9_])`),
      });
    }
  }
  const state = trimSlash(ctx.openclawStateDir);
  if (state.startsWith("/") && state !== "/") {
    const alts = spellings(state, ctx.home).map(escapeRe).join("|");
    // The state dir as a whole (`rm -rf ~/.openclaw`, `~/.openclaw/`,
    // `~/.openclaw/*`), and its installed plugins. Its other contents pass.
    rules.push({
      rule: "openclaw-config",
      what: `${state} (OpenClaw's state directory)`,
      re: new RegExp(`${PATH_START}(?:${alts})(?:/\\*|/(?=$|[\\s'"\`;|&)])|${PATH_END}(?!/))`),
    });
    rules.push({
      rule: "openclaw-config",
      what: `${state}/extensions (OpenClaw's installed plugins)`,
      re: new RegExp(`${PATH_START}(?:${alts})/extensions${PATH_END}`),
    });
  }
  return rules;
}

/** A compiled policy for one context (the registrar builds it once). */
export interface TamperPolicy {
  decide(toolName: string, params: unknown, derivedPaths?: readonly string[]): TamperVerdict;
}

/** Build the policy for `ctx`. */
export function compileTamperPolicy(ctx: TamperContext): TamperPolicy {
  const rules = [...FIXED_RULES, ...contextRules(ctx)];
  return {
    decide(toolName: string, params: unknown, derivedPaths?: readonly string[]): TamperVerdict {
      const strings = collectStrings(params);
      for (const p of derivedPaths ?? []) if (typeof p === "string") strings.push(p);
      for (const s of strings) {
        for (const r of rules) {
          if (r.re.test(s)) {
            return { block: true, rule: r.rule, what: r.what, reason: refusalText(toolName, r) };
          }
        }
      }
      return { block: false };
    },
  };
}

/** One-shot form (tests, callers with a single call). */
export function tamperDecision(
  toolName: string,
  params: unknown,
  ctx: TamperContext,
  derivedPaths?: readonly string[],
): TamperVerdict {
  return compileTamperPolicy(ctx).decide(toolName, params, derivedPaths);
}

function refusalText(toolName: string, r: CompiledRule): string {
  return (
    `Mandu refused this ${toolName} call: it names ${r.what}. Mandu's OpenClaw plugin refuses tool calls that ` +
    "touch Mandu's own state, change the OpenClaw config that sends the model through Mandu, or stop the Mandu " +
    "service. If this is really wanted, ask the human to do it outside the agent."
  );
}
