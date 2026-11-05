/**
 * The command a sentence tells you to start your agent with (dashboard.md
 * §4.25, *Protection is off when nothing runs*): the agents this person
 * uses, not always Claude Code and Codex. Home's hero, Running now's and
 * History's empty rows, Settings › Protection, the scan card and the Scan
 * page's two sentences all draw from it. Fixed command words only: no session,
 * file or host enters them. Pure.
 */
import { AGENTS, type Agent } from "../generated/agents.js";

/** What a page says when Mandu knows no agent of yours (no scan, no
 *  recorded session): today's two. */
export const START_FALLBACK: readonly string[] = ["mandu claude", "mandu codex"];

/** The most commands one sentence names. */
const START_MAX = 2;

/** The scan's agent key as the agent Mandu runs (`claude-code` is
 *  `mandu claude`); undefined for one Mandu does not run (Gemini CLI,
 *  Copilot CLI, Cursor: the scan reads them, Mandu cannot start them). */
function runnable(a: string | undefined): Agent | undefined {
  const k = a === "claude-code" ? "claude" : a;
  return (AGENTS as readonly string[]).includes(k ?? "") ? (k as Agent) : undefined;
}

/**
 * The commands to name, `["mandu goose"]` or `["mandu opencode", "mandu
 * claude"]`: the agents of the sessions recorded under Mandu (`recordedKinds`,
 * newest session first), then those of the last scan by its session count,
 * highest first (ties in AGENTS order); only the agents Mandu runs; at most
 * two; none known, START_FALLBACK.
 */
export function startCommands(scanSessions: Readonly<Record<string, number>> | null | undefined, recordedKinds: readonly (string | undefined)[]): string[] {
  const out: Agent[] = [];
  const add = (a: Agent | undefined): void => { if (a !== undefined && !out.includes(a)) out.push(a); };
  for (const k of recordedKinds) add(runnable(k));
  const scanned = Object.entries(scanSessions ?? {})
    .map(([k, n]) => [runnable(k), typeof n === "number" && Number.isFinite(n) ? n : 0] as const)
    .filter((e): e is readonly [Agent, number] => e[0] !== undefined && e[1] > 0)
    .sort(([a, x], [b, y]) => y - x || AGENTS.indexOf(a) - AGENTS.indexOf(b));
  for (const [a] of scanned) add(a);
  return out.length === 0 ? [...START_FALLBACK] : out.slice(0, START_MAX).map((a) => `mandu ${a}`);
}

export type StartPart = { kind: "text"; text: string; start?: true } | { kind: "code"; text: string; start?: true };

/** The commands as a sentence names them: `a`, or `a` (or `b`). `tag`:
 *  every part (the codes and the "(or …)" words) carries `start: true`, so
 *  the Scan page, built once per kept scan, draws the run from Home's
 *  `start` instead (dashboard.md §4.25ai). */
export function startCommandParts(cmds: readonly string[], tag = false): StartPart[] {
  const list = cmds.length > 0 ? cmds : START_FALLBACK;
  const part = (kind: "text" | "code", text: string): StartPart => (tag ? { kind, text, start: true } : { kind, text });
  const out: StartPart[] = [part("code", list[0]!)];
  if (list.length > 1) out.push(part("text", " (or "), part("code", list[1]!), part("text", ")"));
  return out;
}
