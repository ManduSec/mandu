/**
 * services/claude-trust — inherit the human's workspace-trust decision for
 * the AgentView twin (target claude only).
 *
 * Claude Code keys its "Accessing workspace … Quick safety check" dialog on
 * the CWD, and under Mandu the cwd is the AgentView worktree
 * (`~/.mandu/workspaces/<ws>-<hash>/agentview`) — a path the human never
 * chose, shown on first launch with the default answer "No, exit" (measured
 * live 2026-09-05: the first `mandu claude` in a project the user already
 * trusted exited on Enter). The twin is a git worktree OF the folder the human
 * trusted, so the decision transfers: when `projects[<human cwd>]` in
 * `.claude.json` carries `hasTrustDialogAccepted: true`, the same flag is set
 * for the AgentView path. Nothing else is touched, trust the human never gave
 * is never granted, and the file is only rewritten when the flag is missing
 * (read-modify-write with a same-directory rename). UTILITY-ONLY, best-effort:
 * a failure warns and the dialog simply appears.
 *
 * Mandu-new (no reference origin).
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { publishFile } from "../safe-file.js";

export interface TrustInheritInput {
  /** `$CLAUDE_CONFIG_DIR` when set, else `$HOME` — where `.claude.json` lives. */
  configDir: string;
  /** The HumanView workspace the human launched in (the trust source). */
  humanCwd: string;
  /** The AgentView twin claude will actually run in (the trust target). */
  agentCwd: string;
}

export type TrustInheritResult =
  | { action: "inherited"; file: string }
  | { action: "already-trusted" | "human-not-trusted" | "no-config" | "same-path"; file: string }
  | { action: "error"; file: string; reason: string };

/** The `.claude.json` path claude reads for a given config dir. */
export function claudeJsonPath(configDir: string): string {
  return join(configDir, ".claude.json");
}

export function inheritWorkspaceTrust(input: TrustInheritInput): TrustInheritResult {
  const file = claudeJsonPath(input.configDir);
  if (input.humanCwd === input.agentCwd) return { action: "same-path", file };
  if (!existsSync(file)) return { action: "no-config", file };
  try {
    const doc = JSON.parse(readFileSync(file, "utf8")) as { projects?: Record<string, Record<string, unknown>> };
    const projects = doc.projects;
    if (!projects || typeof projects !== "object") return { action: "human-not-trusted", file };
    if (projects[input.humanCwd]?.["hasTrustDialogAccepted"] !== true) return { action: "human-not-trusted", file };
    if (projects[input.agentCwd]?.["hasTrustDialogAccepted"] === true) return { action: "already-trusted", file };
    projects[input.agentCwd] = { ...(projects[input.agentCwd] ?? {}), hasTrustDialogAccepted: true };
    // Same-directory temp + rename: claude never sees a half-written file;
    // the temp is fresh and exclusive, so a link planted at a predictable
    // temp name is never written through (safe-file.ts). The config dir is
    // the user's, and may be a link they made.
    publishFile(file, JSON.stringify(doc, null, 2) + "\n", { mode: 0o600, dirMayBeLink: true });
    return { action: "inherited", file };
  } catch (e) {
    return { action: "error", file, reason: e instanceof Error ? e.message : String(e) };
  }
}

/**
 * The human's answer to Claude Code's "Detected a custom API key in your
 * environment. Do you want to use this API key?" dialog, carried over to the
 * placeholder the agent's environment holds instead of the key
 * (agent-sign-in.md §3.8). Claude Code keys the answer by the key's last 20
 * characters (`customApiKeyResponses.approved` / `.rejected` in
 * `.claude.json`), so the placeholder, whose last characters differ, raised
 * the dialog again with "No (recommended)" as its default: measured in the
 * replay drills (every interactive turn waited on it). When the real key's
 * suffix is approved (or rejected), the placeholder's is added to the same
 * list; a key never answered is left alone (the dialog appears, as it would
 * for the key). Only suffixes already Claude Code's own are read, and only
 * the placeholder's is written: no key material. UTILITY-ONLY, best-effort.
 */
export type ApiKeyApprovalResult =
  | { action: "approved" | "rejected"; file: string }
  | { action: "already" | "never-answered" | "no-config"; file: string }
  | { action: "error"; file: string; reason: string };

/** Claude Code's key normalization for that dialog: the last 20 characters. */
export function claudeApiKeySuffix(key: string): string {
  return key.slice(-20);
}

export function inheritApiKeyApproval(input: { configDir: string; realKey: string; placeholder: string }): ApiKeyApprovalResult {
  const file = claudeJsonPath(input.configDir);
  if (!existsSync(file)) return { action: "no-config", file };
  try {
    const doc = JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>;
    const raw = doc["customApiKeyResponses"];
    const r = raw !== null && typeof raw === "object" && !Array.isArray(raw) ? raw as Record<string, unknown> : {};
    const list = (k: string): string[] => (Array.isArray(r[k]) ? (r[k] as unknown[]).filter((x): x is string => typeof x === "string") : []);
    const approved = list("approved");
    const rejected = list("rejected");
    const real = claudeApiKeySuffix(input.realKey);
    const ph = claudeApiKeySuffix(input.placeholder);
    let action: "approved" | "rejected";
    if (approved.includes(real)) {
      if (approved.includes(ph)) return { action: "already", file };
      approved.push(ph);
      action = "approved";
    } else if (rejected.includes(real)) {
      if (rejected.includes(ph)) return { action: "already", file };
      rejected.push(ph);
      action = "rejected";
    } else {
      return { action: "never-answered", file };
    }
    doc["customApiKeyResponses"] = { ...r, approved, rejected };
    publishFile(file, JSON.stringify(doc, null, 2) + "\n", { mode: 0o600, dirMayBeLink: true });
    return { action, file };
  } catch (e) {
    return { action: "error", file, reason: e instanceof Error ? e.message : String(e) };
  }
}
