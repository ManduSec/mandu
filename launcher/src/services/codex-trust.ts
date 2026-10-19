/**
 * services/codex-trust — inherit the human's directory-trust decision for the
 * AgentView twin (target codex only). The codex sibling of claude-trust.ts.
 *
 * Codex keys "Do you trust the contents of this directory?" on the REPOSITORY
 * ROOT it resolves for the cwd, as `[projects."<root>"] trust_level =
 * "trusted"` tables in `$CODEX_HOME/config.toml`. Under Mandu the cwd is
 * the AgentView worktree, and codex resolves ITS root as the worktree's
 * parent (the view-state workspace dir — measured 2026-09-05: answering
 * "Yes, continue" wrote `[projects."~/.mandu/workspaces/<ws>-<hash>"]`).
 * The twin is a worktree OF the folder the human trusted, so the decision
 * transfers: when the human's repository root is trusted, both the state dir
 * and the AgentView path are marked trusted. Nothing else is rewritten — the
 * file is scanned line-wise for the exact table headers and new tables are
 * APPENDED (always valid TOML at EOF); a table that already exists is never
 * duplicated (codex would refuse a duplicate key). Trust the human never gave
 * is never granted. UTILITY-ONLY, best-effort.
 *
 * Mandu-new (no reference origin).
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { publishFile } from "../safe-file.js";

export interface CodexTrustInput {
  /** `$CODEX_HOME` when set, else `$HOME/.codex`. */
  codexHome: string;
  /** The human's repository root (the fs rung's HumanView git root). */
  humanRoot: string;
  /** Paths codex may key the twin on: the AgentView path and its parent. */
  agentPaths: string[];
}

export type CodexTrustResult =
  | { action: "inherited"; file: string; added: string[] }
  | { action: "already-trusted" | "human-not-trusted" | "no-config"; file: string }
  | { action: "error"; file: string; reason: string };

/** The `[projects."<path>"]` header codex writes (double- or single-quoted key). */
function isProjectHeader(line: string, path: string): boolean {
  const t = line.trim();
  return t === `[projects.${JSON.stringify(path)}]` || t === `[projects.'${path}']`;
}

/** Does `text` carry `[projects."<path>"]` with `trust_level = "trusted"`
 *  before the next table header? Pure. */
export function codexPathTrusted(text: string, path: string): boolean {
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (!isProjectHeader(lines[i]!, path)) continue;
    for (let j = i + 1; j < lines.length; j++) {
      const t = lines[j]!.trim();
      if (t.startsWith("[")) break;
      if (/^trust_level\s*=\s*["']trusted["']/.test(t)) return true;
    }
  }
  return false;
}

/** Any `[projects."<path>"]` table at all (trusted or not) — never duplicate. */
export function codexPathHasTable(text: string, path: string): boolean {
  return text.split("\n").some((l) => isProjectHeader(l, path));
}

export function inheritCodexTrust(input: CodexTrustInput): CodexTrustResult {
  const file = join(input.codexHome, "config.toml");
  if (!existsSync(file)) return { action: "no-config", file };
  try {
    const text = readFileSync(file, "utf8");
    if (!codexPathTrusted(text, input.humanRoot)) return { action: "human-not-trusted", file };
    const missing = input.agentPaths.filter((p) => !codexPathHasTable(text, p));
    if (missing.length === 0) return { action: "already-trusted", file };
    const tail = missing.map((p) => `\n[projects.${JSON.stringify(p)}]\ntrust_level = "trusted"\n`).join("");
    const next = (text.endsWith("\n") || text === "" ? text : text + "\n") + tail;
    // A fresh exclusive temp beside it, renamed over it (safe-file.ts): a
    // link planted at a predictable temp name is never written through. The
    // codex home is the user's, and may be a link they made.
    publishFile(file, next, { mode: 0o600, dirMayBeLink: true });
    return { action: "inherited", file, added: missing };
  } catch (e) {
    return { action: "error", file, reason: e instanceof Error ? e.message : String(e) };
  }
}
