/**
 * claude-transcript — parse + locate Claude Code's OWN session transcript JSONL
 * (~/.claude/projects/<cwd-slug>/<uuid>.jsonl). The pure, filesystem-only half of
 * the history-fidelity oracle: turn the client's recorded transcript into
 * `ClaudeHistory` ground truth and find the file on disk. Extracted VERBATIM from
 * claude-history.ts (overnight-cleanup 2026-07-12) so the parser/locator lives
 * apart from the dashboard-render comparators that consume it; claude-history.ts
 * re-exports these names, so importers are unchanged. Covered by
 * tests/stack/claude-history.test.ts.
 *
 * PROVENANCE: Mandu-new — no reference (adfi-openclaw) origin. The projects
 * JSONL is a Claude-INTERNAL format with no published schema, so every rule here
 * is calibrated against a real transcript and kept deliberately CONSERVATIVE — we
 * only assert properties that are stable across the shapes observed.
 */

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

// stripHarnessTags is the SAME harness-noise stripper the dashboard applies to a
// user message before it becomes an input card (dual-lanes.ts stripHarnessNoise
// is stripHarnessTags + a [system-reminder]-line filter). We mirror it here so
// ground-truth prompts are cleaned identically to the rendered cards — otherwise
// a prompt Claude Code appended a <system-reminder> to would never match.
import { stripHarnessTags } from "../../dashboard/src/transcript.js";

// ── The parsed ground truth ───────────────────────────────────────────────────

export interface ClaudeHistory {
  /** Typed user prompts, in order (slash-command / meta / tool-result records
   *  excluded; harness tag-noise stripped, so these are what the human typed). */
  prompts: string[];
  /** The LAST assistant prose turn — the delivered reply. Contains $MDU:*
   *  tokens verbatim (history is recorded POST-proxy), matching the dashboard's
   *  AgentView response text. null when the run ended without any assistant text
   *  (e.g. a tool-use-only final). */
  finalText: string | null;
  /** Every `tool_use` block name the assistant issued, in order (may repeat). */
  toolNames: string[];
  /** Every `tool_result` block's `is_error`, in order — the tool's own verdict
   *  on its run (differential P2 compares it across sides, §16). */
  toolErrors: boolean[];
}

/** A user-message body that is a slash-command RECORD, not a typed prompt: Claude
 *  Code leaves the command's own bookkeeping inline as tag spans. (isMeta records
 *  are dropped earlier; this catches the non-meta command-name/stdout records.) */
const COMMAND_NOISE_PREFIXES = [
  "<command-name>",
  "<command-message>",
  "<command-args>",
  "<command-contents>",
  "<local-command-caveat>",
  "<local-command-stdout>",
  "<local-command-stderr>",
];

function isCommandNoise(body: string): boolean {
  const t = body.trimStart();
  return COMMAND_NOISE_PREFIXES.some((p) => t.startsWith(p));
}

/** Clean a user body to what the dashboard renders as an input card: strip the
 *  harness tag spans (the typed prompt is buried under them in Claude Code turns)
 *  and drop lone `[system-reminder]` placeholder lines, then trim. This is
 *  byte-for-byte the dashboard's stripHarnessNoise + trim, applied to BOTH sides
 *  of every prompt comparison so cleaning can never introduce a spurious diff. */
export function cleanPromptText(body: string): string {
  return stripHarnessTags(body)
    .split("\n")
    .filter((line) => !/^\s*\[system-reminder\]\s*$/.test(line))
    .join("\n")
    .trim();
}

interface RawRecord {
  type?: string;
  isMeta?: boolean;
  isSidechain?: boolean;
  requestId?: string;
  message?: { content?: unknown };
}

/**
 * Parse the projects JSONL text into ground truth. Pure + tolerant: a corrupt
 * line is skipped, never thrown on (the file can be mid-write). Rules (calibrated
 * against the real incident transcript):
 *   - typed prompt: `type=="user"`, `isMeta!=true`, `isSidechain!=true`, and
 *     `message.content` is a STRING (array content = a tool_result, not a prompt),
 *     excluding slash-command records (isCommandNoise).
 *   - assistant turn: `type=="assistant"`, `message.content` is a block array;
 *     `tool_use` blocks contribute `.name`, `text` blocks contribute prose.
 *   - finalText: the prose of the LAST requestId group that carried any text. A
 *     turn's thinking/text/tool_use arrive as SEPARATE records sharing one
 *     requestId, so grouping by requestId reassembles a turn's full prose (joined
 *     with "\n", matching the proxy's transcript) and a trailing tool-use-only
 *     turn (no text) correctly leaves the last PROSE turn as the delivered reply.
 *   - sidechains are excluded throughout (a subagent / quarantine U-LLM writes its
 *     own transcript; the main session's file should carry none, but be safe).
 */
export function parseClaudeHistory(jsonl: string): ClaudeHistory {
  const prompts: string[] = [];
  const toolNames: string[] = [];
  const toolErrors: boolean[] = [];
  const proseByRequest = new Map<string, string[]>();
  const requestOrder: string[] = []; // requestIds that carried text, first-seen order
  let anon = 0;

  for (const line of jsonl.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let rec: RawRecord;
    try {
      rec = JSON.parse(trimmed) as RawRecord;
    } catch {
      continue; // tolerate a partial/corrupt line (file may be mid-write)
    }
    if (rec.isSidechain === true) continue;
    const content = rec.message?.content;

    if (rec.type === "user") {
      if (rec.isMeta === true) continue;
      if (Array.isArray(content)) {
        for (const raw of content as Array<Record<string, unknown>>) {
          if (raw && typeof raw === "object" && raw.type === "tool_result") toolErrors.push(raw.is_error === true);
        }
        continue;
      }
      if (typeof content !== "string") continue;
      if (isCommandNoise(content)) continue;
      const text = cleanPromptText(content);
      if (text) prompts.push(text);
      continue;
    }

    if (rec.type === "assistant") {
      if (!Array.isArray(content)) continue;
      const reqId = rec.requestId ?? `#anon${anon++}`;
      for (const raw of content as Array<Record<string, unknown>>) {
        if (!raw || typeof raw !== "object") continue;
        if (raw.type === "tool_use" && typeof raw.name === "string") {
          toolNames.push(raw.name);
        } else if (raw.type === "text" && typeof raw.text === "string") {
          if (!proseByRequest.has(reqId)) {
            proseByRequest.set(reqId, []);
            requestOrder.push(reqId);
          }
          proseByRequest.get(reqId)!.push(raw.text);
        }
      }
    }
  }

  const lastReq = requestOrder[requestOrder.length - 1];
  const finalText = lastReq ? (proseByRequest.get(lastReq)!.join("\n").trim() || null) : null;
  return { prompts, finalText, toolNames, toolErrors };
}

// ── Locator ───────────────────────────────────────────────────────────────────

/** Claude Code names the projects dir by replacing "/" and "." in the spawn CWD
 *  with "-". NOTE: this is fragile for fsSync scenarios — their agentview CWD
 *  carries %2F-encoded human paths, which the slug mangles further — so
 *  locateTranscript prefers a session-UUID scan over trusting this. */
export function slugifyCwd(cwd: string): string {
  return cwd.replace(/[/.]/g, "-");
}

/** The deterministic path when the session UUID is known (--session-id). */
export function historyPathFor(homeDir: string, cwd: string, sessionUuid: string): string {
  return join(homeDir, ".claude", "projects", slugifyCwd(cwd), `${sessionUuid}.jsonl`);
}

export interface LocateOpts {
  homeDir: string;
  /** Explicit projects root — `<CLAUDE_CONFIG_DIR>/projects` when the run
   *  isolates its config dir (the differential harness does; the config dir
   *  REPLACES `~/.claude`, so the homeDir-derived default would miss).
   *  Overrides the `homeDir` derivation when set. */
  projectsRoot?: string;
  /** The CWD claude was spawned with (agentCwd — the AgentView twin for fsSync). */
  cwd: string;
  /** When the installed CLI supports `--session-id <uuid>`: the pre-generated
   *  UUID names the transcript file, so it can be located deterministically. */
  sessionUuid?: string;
  /** Fallback (no --session-id): only consider files modified at/after this ms. */
  sinceMs?: number;
  /** Fallback: prefer the candidate whose first typed prompt matches this. */
  firstPrompt?: string;
}

function listJsonl(dir: string, sinceMs?: number): string[] {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return [];
  }
  return entries
    .filter((n) => n.endsWith(".jsonl"))
    .map((n) => join(dir, n))
    .map((p) => ({ p, m: safeMtime(p) }))
    .filter((x) => x.m !== null && (sinceMs === undefined || x.m >= sinceMs))
    .sort((a, b) => (b.m ?? 0) - (a.m ?? 0)) // newest first
    .map((x) => x.p);
}

function safeMtime(p: string): number | null {
  try {
    return statSync(p).mtimeMs;
  } catch {
    return null;
  }
}

/** Scan every project dir for `<uuid>.jsonl` — the UUID is globally unique, so
 *  this is slug-quirk-proof (the fsSync %2F-mangled slug can't be reconstructed
 *  reliably, but the filename is exact). */
function scanForUuid(projectsRoot: string, uuid: string): string | null {
  let dirs: string[];
  try {
    dirs = readdirSync(projectsRoot);
  } catch {
    return null;
  }
  const target = `${uuid}.jsonl`;
  for (const d of dirs) {
    const candidate = join(projectsRoot, d, target);
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

/**
 * Find the transcript file. With a known session UUID (--session-id supported):
 * try the reconstructed slug path, then scan all project dirs for the UUID —
 * a genuine miss returns null (the caller records a FAILED check, since `claude
 * -p` DOES write history). Without a UUID (older CLI): fall back to the newest
 * *.jsonl in the slug dir whose first prompt matches the scenario prompt.
 */
export function locateTranscript(opts: LocateOpts): string | null {
  const projectsRoot = opts.projectsRoot ?? join(opts.homeDir, ".claude", "projects");
  if (opts.sessionUuid) {
    const direct = join(projectsRoot, slugifyCwd(opts.cwd), `${opts.sessionUuid}.jsonl`);
    if (existsSync(direct)) return direct;
    return scanForUuid(projectsRoot, opts.sessionUuid);
  }
  const dir = join(projectsRoot, slugifyCwd(opts.cwd));
  const candidates = listJsonl(dir, opts.sinceMs);
  if (opts.firstPrompt) {
    const want = cleanPromptText(opts.firstPrompt);
    for (const f of candidates) {
      try {
        const h = parseClaudeHistory(readFileSync(f, "utf8"));
        if (h.prompts[0] !== undefined && cleanPromptText(h.prompts[0]) === want) return f;
      } catch {
        /* skip unreadable */
      }
    }
  }
  return candidates[0] ?? null; // newest, or null when none
}
