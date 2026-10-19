/**
 * claude-permission-mode — Claude Code starts in the permission mode it
 * would start in without Mandu (supported-agents.md §2, "Claude Code's
 * permission mode under Mandu"; decided 2026-10-09).
 *
 * WHY (measured on Claude Code 2.1.290 through 2.1.295, 2026-10-09). The
 * launch sets CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 (exec-routing.md
 * §7.4, run.ts). With it Claude Code fetches no feature flags, and without
 * them it starts in permission mode `auto` (its own classifier approves
 * commands), in the TUI and in `-p` alike; the flags it is served otherwise
 * keep it in `default` (manual approval). So under Mandu a user got a Claude
 * Code that asked less than the same Claude Code without Mandu.
 *
 * THE RULE lives in claude-permission-rule.cjs (its header: the choices,
 * the non-choice `--allow-dangerously-skip-permissions`, the sessions that
 * take the flag), the ONE copy the launch, the SDK route's preload and the
 * PATH shim a shell's `claude` meets all apply. In short: the launch passes
 * `--permission-mode default` to a Claude Code session unless the user
 * already chose a mode on the command line (`--permission-mode`,
 * `--dangerously-skip-permissions`, `--inherit-permission-mode`, the last
 * `--settings`, a `--managed-settings`) or in a settings source Claude Code
 * reads for this launch: the managed sources (always read), and the user,
 * project and local files unless `--setting-sources` leaves them out
 * (`--restricted` drops all three).
 * A managed source Mandu cannot read (a macOS MDM property list `plutil`
 * could not convert) counts as a choice: it may set one.
 * A command-line flag outranks every settings source in Claude Code
 * (measured: `defaultMode: "acceptEdits"` in the user file with
 * `--permission-mode default` started in `default`), so injecting the flag
 * over a settings choice would override the user; hence the settings check.
 *
 * Claude Code takes `default` as `manual`'s older name (2.1.295 lists
 * `manual` in its help and still accepts `default`; measured on 2.1.290 –
 * 2.1.295: the transcript's `permissionMode` is `default` either way).
 *
 * This module is the launch's typed half: it feeds the rule the settings
 * sources the launch read (claude-route.ts layers) and computes, for the
 * preload and the PATH shim, which scopes set a mode for the launch folder
 * (claudeModeScopes).
 *
 * Pure. Mandu-new (no reference origin).
 */
import { parseClaudeSettingsValue, type ClaudeSettingsScope } from "./claude-sandbox.js";
import * as rule from "./claude-permission-rule.cjs";

/** What the launch adds: Claude Code's default (manual-approval) mode. */
export const CLAUDE_DEFAULT_PERMISSION_ARGS: readonly string[] = rule.DEFAULT_PERMISSION_ARGS;

/** The file scopes `--setting-sources` selects among. */
export const CLAUDE_FILE_SCOPES = ["user", "project", "local"] as const;
export type ClaudeFileScope = (typeof CLAUDE_FILE_SCOPES)[number];

/** The flag on a Claude Code command line (argv[0] first) that chose the
 *  permission mode, as written, or null. */
export function claudeArgvModeFlag(argv: readonly string[]): string | null {
  return rule.argvModeFlag(argv.slice(1));
}

/** The file scopes Claude Code reads for this command line (argv[0]
 *  first): all three unless `--setting-sources` names some, none under
 *  `--restricted`. Managed sources and `--settings` are always read. */
export function claudeArgvFileScopes(argv: readonly string[]): ReadonlySet<ClaudeFileScope> {
  return new Set(rule.argvFileScopes(argv.slice(1)));
}

/** A settings document's `permissions.defaultMode`, when it sets one. */
export function settingsDefaultMode(doc: unknown): string | null {
  return rule.settingsDefaultMode(doc);
}

/** A settings file's text as Claude Code parses it (blank is `{}`, a
 *  byte-order mark dropped); null when it does not parse (Claude Code skips
 *  it). */
function parseSettingsText(text: string): unknown {
  if (text.trim() === "") return {};
  try { return JSON.parse(text.startsWith("﻿") ? text.slice(1) : text) as unknown; } catch { return null; }
}

/** One settings source as the launch read it (claude-sandbox.ts
 *  readClaudeSettingsSources; claude-route.ts layers, whose `global`
 *  config file holds no permissions and is skipped). */
export interface ClaudeModeLayer {
  path: string;
  scope: ClaudeSettingsScope | "global";
  text: string | null;
  unreadable?: boolean;
}

/** Per scope, whether a source of it sets a mode (managed: or cannot be
 *  read). What the SDK route and the PATH shim carry, computed at the
 *  launch folder. Pure. */
export function claudeModeScopes(layers: readonly ClaudeModeLayer[]): Array<ClaudeSettingsScope> {
  const out = new Set<ClaudeSettingsScope>();
  for (const l of layers) {
    if (l.scope === "global") continue;
    if (l.unreadable === true) { if (l.scope === "managed") out.add("managed"); continue; }
    if (l.text === null) continue;
    if (settingsDefaultMode(parseSettingsText(l.text)) !== null) out.add(l.scope);
  }
  return [...out];
}

/** The mode a source of the command line itself sets (`--permission-mode`,
 *  `--dangerously-skip-permissions`, `--inherit-permission-mode`, the last
 *  `--settings`, a `--managed-settings`), described, or null. `readFile`
 *  reads a settings file named there. Pure over it. */
export function claudeArgvModeChoice(argv: readonly string[], readFile: (p: string) => string | null): string | null {
  return rule.argvModeChoice(argv.slice(1), (v) => parseClaudeSettingsValue(v, readFile));
}

/** Why the launch leaves the mode alone, or null to inject. */
export type ClaudeModeDecision = rule.ModeDecision;

/**
 * The launch's decision for a Claude Code command line (argv[0] first) and
 * the settings sources Claude Code reads for it: the rule
 * (claude-permission-rule.cjs) over the layers the launch read. Pure over
 * `readFile`.
 */
export function claudePermissionModeDecision(
  argv: readonly string[],
  layers: readonly ClaudeModeLayer[],
  readFile: (p: string) => string | null,
): ClaudeModeDecision {
  return rule.permissionModeDecision(argv.slice(1), (v) => parseClaudeSettingsValue(v, readFile), (fileScopes) => {
    const files = new Set<string>(fileScopes);
    for (const l of layers) {
      if (l.scope === "global") continue;
      if (l.scope !== "managed" && !files.has(l.scope)) continue;
      if (l.unreadable === true) {
        if (l.scope === "managed") return `${l.path} (unreadable)`;
        continue;
      }
      if (l.text === null) continue;
      if (settingsDefaultMode(parseSettingsText(l.text)) !== null) return `${l.path} (permissions.defaultMode)`;
    }
    return null;
  });
}
