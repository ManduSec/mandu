/**
 * view-model/attachment-route — Home's notice when an attached OpenClaw
 * Gateway's config no longer routes through Mandu (docs/design/agents/
 * openclaw-plugin.md §3.6; dashboard.md §4.25 *Home notices*).
 *
 * The service checks each attached session's OpenClaw config every 30
 * seconds and on every change; when it no longer sends the model's requests
 * through Mandu, or no longer loads Mandu's plugin, or cannot be read, the
 * arbiter records a believed posture saying so (session-health.ts
 * `attachmentRoute`). This projects those sessions into one loud card: which
 * session, what changed, the honest limit (the Gateway reads its config when
 * it starts), and the fix. It goes away when the route comes back (the
 * arbiter's newer record) or when the attachment ends. Product vocabulary
 * only (home-view-model.test.ts sweeps it). Pure: no I/O, no clock.
 */

import type { SessionRef } from "../event-source/contract.js";
import type { HomeTextPart } from "./ask-words.js";
import type { HumanPlaneVM } from "./human-plane.js";

/** One session whose route is lost. */
export interface HomeRouteLostItem {
  session: string;
  /** What changed, one sentence per problem the service found. */
  problems: string[];
  /** The config the service checked; null when not recorded. */
  config: string | null;
  /** When Mandu recorded it (ms); null when not known. */
  since: number | null;
  /** "openclaw:main: the Mandu plugin is disabled …; …", `parts` joined. */
  words: string;
  parts: HomeTextPart[];
}

/** The card: a headline, a sentence, each session, the fix. */
export interface HomeRouteLost {
  headline: string;
  sentence: string;
  items: HomeRouteLostItem[];
  fix: string;
  fixParts: HomeTextPart[];
}

/** The fix as parts, the commands as code in the order they run, each
 *  marked `run` so the page gives it a Copy (dashboard.md §4.25b). */
export const ROUTE_FIX_PARTS: readonly HomeTextPart[] = [
  { kind: "text", text: "Run " },
  { kind: "code", text: "mandu openclaw install", run: true },
  { kind: "text", text: " in a terminal to write Mandu's route back, then " },
  { kind: "code", text: "openclaw gateway restart", run: true },
  { kind: "text", text: " so the Gateway reads it. Mandu never changes your config by itself. If you made the change on purpose, " },
  { kind: "code", text: "mandu openclaw uninstall", run: true },
  { kind: "text", text: " detaches Mandu for good." },
];

/** The sessions whose route is lost, as one card; null when none is. A
 *  session counts while its attachment is live: when the human plane's
 *  status is known, only the attachments it lists (an ended one's last
 *  record says nothing about now); unknown, every one (a loud notice may
 *  not wait on an answer the page did not get). */
export function homeRouteLost(sessions: readonly Pick<SessionRef, "id" | "health">[], humanPlane?: HumanPlaneVM): HomeRouteLost | null {
  const known = humanPlane !== undefined && humanPlane.state !== "unknown";
  const live = new Set((humanPlane?.launches ?? []).filter((l) => l.attachment !== undefined && l.session !== null).map((l) => l.session!));
  const items: HomeRouteLostItem[] = [];
  for (const s of sessions) {
    const r = s.health?.attachmentRoute;
    if (!r || (known && !live.has(s.id))) continue;
    const problems = r.problems.map((p) => p.detail);
    const parts: HomeTextPart[] = [
      { kind: "code", text: s.id },
      { kind: "text", text: `: ${problems.length > 0 ? problems.join("; ") : "the config no longer routes it through Mandu"}` },
      ...(r.config !== null ? [{ kind: "text" as const, text: " (in " }, { kind: "code" as const, text: r.config }, { kind: "text" as const, text: ")" }] : []),
    ];
    items.push({ session: s.id, problems, config: r.config, since: r.since, words: parts.map((p) => p.text).join(""), parts });
    if (items.length >= 5) break;
  }
  if (items.length === 0) return null;
  const fixParts = [...ROUTE_FIX_PARTS];
  return {
    headline: "Your OpenClaw Gateway's config no longer goes through Mandu.",
    sentence:
      "Mandu checks your OpenClaw config, and it was changed so that the AI's requests, or Mandu's plugin, no longer go through Mandu. " +
      "A Gateway already running keeps the config it loaded until it restarts; once it runs with this one (now, if it restarted since), the AI can read your secrets as they are, not masked.",
    items,
    fix: fixParts.map((p) => p.text).join(""),
    fixParts,
  };
}
