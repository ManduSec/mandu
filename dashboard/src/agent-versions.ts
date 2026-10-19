/**
 * agent-versions — the agent versions Mandu was TESTED with, as the dashboard
 * reads them (release checklist e4; docs/design/agents/supported-agents.md).
 *
 * MIRROR of launcher/src/agent-versions.ts (the dashboard does not import the
 * launcher package; tests/stack/agent-versions-parity.test.ts
 * holds the table and the check equal). Used by session-health.ts (the
 * inspector's health chip) and view-model/home.ts (the product page's plain
 * notice under an agent row, and a preview agent's tag).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code.
 */

import { AGENTS, type Agent } from "./generated/agents.js";

/** Every agent has a tested range (the agent registry's generated copy). */
export type VersionedAgent = Agent;

export interface TestedRange {
  name: string;
  min: string;
  max: string;
  evidence: string;
  /** supported / preview: mirror of the launcher's SupportStatus. */
  status: SupportStatus;
}

/** Mirror of the launcher's SupportStatus (supported-agents.md §2.0). */
export type SupportStatus = "supported" | "preview";

export const TESTED_AGENT_VERSIONS: Record<VersionedAgent, TestedRange> = {
  claude: {
    name: "Claude Code",
    min: "2.1.273",
    max: "2.1.295",
    evidence: "the CI image pin (scripts/ci/pins.env): 2.1.273 until 2026-10-09, 2.1.295 since; live batteries on 2.1.273 and 2.1.281 with every advertised tool mapped; 2.1.285: 32 sessions, 38 tools all mapped, and the claude differential lane 70/70 in the CI guest with the secret bind on; 2.1.287: every advertised tool mapped, the claude differential lane 70/70 on the host (guard-only) and in the CI guest with the secret bind on; 2.1.292: every advertised tool mapped (23, DesignSync and PushNotification new), the claude differential lane 70/70 on the host, the per-push replay drills and the agent-SDK suite; 2.1.294: the live drills on haiku (2026-10-08/09 pre-release run and reruns, tool_surface all known), the interactive surface (31 tools: Artifact, ArtifactComments, ArtifactData, EndConversation, SendFeedback newly mapped, the Artifact uploads gated, !1058) and the headless 23 all mapped; 2.1.295: every advertised tool mapped (headless 23; the interactive 31 after !1058), the claude differential lane 70/70 on the host (65 CI shards), the per-push replay drills (7), the agent-SDK suite (9); the fresh-agents VM legs on ubuntu-2404 and 2604 75/75 with 2.1.295 (!1067: the Bash leg's failure was the scripted model answering Claude Code's auto-mode classifier with no verdict, not 2.1.295); a live leg (haiku, mode secrets, 2026-10-09: conf-read-exfil, util-quote-line pass); the CI guest's pin since 2026-10-09: the per-push replay-drill kind in the guest (52 entries, the claude differential shards among them) all green",
    status: "supported",
  },
  codex: {
    name: "Codex",
    min: "0.136.0",
    max: "0.162.0",
    evidence: "openai-proxy wire verified on codex 0.136 (responses API) and 0.154 (script-cell exec, MCP); 0.159.1: the agent-fake Codex suites, and live on the ChatGPT backend (a plain and a tool turn, codex-e2e, compaction); 0.160.0: the agent-fake Codex suites (the policy tools on both wires included), the per-push replay drills, the agent-SDK suite, the codex differential lane 7/7, every advertised tool on both wires mapped; 0.162.0: the agent-fake Codex suites (the policy tools on both wires included), the per-push replay drills, the agent-SDK suite, the codex differential lane 7/7, every advertised tool on both wires mapped (the same tools as 0.160; the classic wire's prompt now a developer message, pinned, !1055); live on the ChatGPT backend (conf-read-exfil, 2026-10-09); the CI guest's pin since 2026-10-09 (0.144.1 before): the per-push replay-drill kind, the codex sandbox entries (shell-network, sandbox-refusal-note, sandbox-call-binding) and the codex differential lane 7/7 in the guest, fidelity-permission-prompt on the on-request posture with no fold",
    status: "supported",
  },
  openclaw: {
    name: "OpenClaw",
    min: "2026.3.12",
    max: "2026.9.9",
    evidence: "multi-agent e2e lanes on openclaw 2026.3.12 and 2026.7.1; fresh-agents legs through mandu on 2026.3.12, 2026.6.35, 2026.7.1 and 2026.9.6 (Node 24); every tool 2026.9.6 advertises in each Tool Search mode is mapped, refused on the wire, or a dispatcher gated as the tool it runs; 2026.9.9: fresh-agents legs through mandu (Node 24, ubuntu-2404 and 2604, scripted model, secrets mode; 75/75 with every agent at its latest, !1067); integration.openclaw-e2e 8/8 (!1074: inspect_symbol direct-only past 9.x's Tool Search; the replay engine reads 9.x's internal-context block, SQLite transcript and masked stored replies); every tool 2026.9.9 advertises in each Tool Search mode (default, tools, directory, off) is mapped, refused on the wire, or a dispatcher gated as the tool it runs; Code Mode (exec{code}, wait) refused on the wire and off in the run config (!1060); a live leg (haiku, mode secrets, 2026-10-09: conf-read-exfil, conf-public-label-wins, util-write-file, util-shell-echo pass)",
    status: "supported",
  },
  opencode: {
    name: "OpenCode",
    min: "1.18.13",
    max: "1.18.35",
    evidence: "multi-agent e2e lane on opencode 1.18.13; 1.18.35: the multi-agent e2e lane and the scripted-model replay catalog (integration.opencode-e2e, opencode-hermetic, replay.opencode util/conf/policy, opencode-project-plugins; the real-binary launcher component tests); tool surface unchanged from 1.18.13, all known to the inbound spec; a live leg (haiku, mode secrets, 2026-10-09: conf-read-exfil, conf-read-control, no leak)",
    status: "preview",
  },
  goose: {
    name: "Goose",
    min: "1.53.0",
    max: "1.54.0",
    evidence: "the CI guest's pin 1.53.0: the replay suites (integration.goose-e2e, replay-push.goose per push, replay.goose nightly, 41 catalog scripts), the real-binary launcher component tests (goose-real, goose-delivery), every advertised tool mapped, gated, refused or masked whole (load / load_skill mapped only under the guard; the tool_surface unknown list empty since !1056); a live leg (scripts/drills-live.sh goose, haiku, mode secrets, 2026-10-05: conf-read-exfil and conf-read-control pass, no leak, hermetic); 1.54.0: the replay suites (integration.goose-e2e 20/20, replay-push.goose 2/2, replay.goose catalog 36 pass, 2 kernel-lane skips), the real-binary launcher component tests (goose-real, goose-delivery and the other goose-* files, 40/40), the same tool surface as 1.53.0, every advertised tool mapped, gated, refused or masked whole (!1056); a live leg (haiku, mode secrets, 2026-10-09: conf-read-exfil, conf-read-control, conf-public-label-wins pass)",
    status: "preview",
  },
};

/** A later generation with a tested range of its own (OpenCode 2): a version
 *  whose major is `major` is judged against it. Mirror of the launcher's. */
export interface TestedGeneration extends TestedRange {
  major: number;
}

export const TESTED_AGENT_GENERATIONS: Partial<Record<VersionedAgent, readonly TestedGeneration[]>> = {
  opencode: [
    {
      major: 2,
      name: "OpenCode",
      min: "2.0.23",
      max: "2.0.26",
      evidence: "npm @opencode/cli 2.0.23: the 2.x e2e and replay suites (integration.replay-opencode2, the CI guest's pin); the real-binary launcher component and sandbox tests; a live check (scripts/drills-live.sh opencode2, haiku, mode secrets: conf-read-exfil, conf-net-exfil-blocked and conf-read-control pass, 2026-10-05); npm @opencode/cli 2.0.26: the 2.x e2e and replay suites (integration.replay-opencode2, opencode2-e2e, replay.opencode2 util/conf/policy); the real-binary launcher component and sandbox tests (opencode2-own-server, -agent-identity, -shell-output, opencode-project-plugins); tool surface identical to 2.0.23 (every tool mapped but execute, which the proxy refuses); a live leg (haiku, mode secrets, 2026-10-09: conf-read-exfil and conf-read-control pass)",
      status: "preview",
    },
  ],
};

interface Parsed {
  raw: string;
  parts: [number, number, number];
  prerelease: string | null;
}

/** First `X.Y.Z` in a version string; a numeric-only suffix is a packaging
 *  revision (ignored), a lettered one a prerelease. Same rule as the launcher. */
export function parseAgentVersion(output: string | null | undefined): Parsed | null {
  if (!output) return null;
  const m = /(?:^|[^\d.])v?(\d{1,6})\.(\d{1,6})\.(\d{1,6})(?:-([0-9A-Za-z][0-9A-Za-z.-]*))?/.exec(output);
  if (!m) return null;
  const suffix = m[4] ?? null;
  const prerelease = suffix !== null && /[A-Za-z]/.test(suffix) ? suffix : null;
  const parts: [number, number, number] = [Number(m[1]), Number(m[2]), Number(m[3])];
  return { raw: `${parts.join(".")}${prerelease ? `-${prerelease}` : ""}`, parts, prerelease };
}

function compare(a: Parsed, b: Parsed): number {
  for (let i = 0; i < 3; i++) {
    if (a.parts[i]! !== b.parts[i]!) return a.parts[i]! < b.parts[i]! ? -1 : 1;
  }
  if (a.prerelease === b.prerelease) return 0;
  if (a.prerelease === null) return 1;
  if (b.prerelease === null) return -1;
  return a.prerelease < b.prerelease ? -1 : 1;
}

export type RangeVerdict = "tested" | "newer" | "older" | "unknown";

export interface AgentVersionCheck {
  agent: VersionedAgent;
  name: string;
  version: string | null;
  verdict: RangeVerdict;
  min: string;
  max: string;
}

export function isVersionedAgent(a: unknown): a is VersionedAgent {
  return (AGENTS as readonly unknown[]).includes(a);
}

/** The range a parsed version is judged against: its generation's when the
 *  agent has one for that major, else the agent's own. Same rule as the launcher. */
export function testedRangeOf(agent: VersionedAgent, v: Parsed | null): TestedRange {
  const gen = v === null ? undefined : TESTED_AGENT_GENERATIONS[agent]?.find((g) => g.major === v.parts[0]);
  return gen ?? TESTED_AGENT_VERSIONS[agent];
}

/** Place a version string against the agent's tested range (its
 *  generation's, testedRangeOf). Pure. */
export function checkAgentVersion(agent: VersionedAgent, versionOutput: string | null): AgentVersionCheck {
  const v = parseAgentVersion(versionOutput);
  const r = testedRangeOf(agent, v);
  const base = { agent, name: r.name, min: r.min, max: r.max };
  if (v === null) return { ...base, version: null, verdict: "unknown" };
  const verdict: RangeVerdict =
    compare(v, parseAgentVersion(r.min)!) < 0 ? "older" : compare(v, parseAgentVersion(r.max)!) > 0 ? "newer" : "tested";
  return { ...base, version: v.raw, verdict };
}

export function rangeWords(c: { min: string; max: string }): string {
  return c.min === c.max ? c.min : `${c.min} to ${c.max}`;
}

/** The plain label of a tested line: the agent's name, or `<name> <major>`
 *  for a generation ("OpenCode 2"). Mirror of the launcher's. */
export function rangeLabel(r: TestedRange | TestedGeneration): string {
  return "major" in r ? `${r.name} ${r.major}` : r.name;
}

/** The major of the later generation a version belongs to (2 for an
 *  OpenCode 2.x, `TESTED_AGENT_GENERATIONS`), or null for the agent's first
 *  line or an unreadable version. The product page names the session by it
 *  ("OpenCode 2", home.ts `agentName`). Dashboard-only, over the mirrored
 *  table. Pure. */
export function generationOf(agent: VersionedAgent, version: string | null): number | null {
  const line = testedRangeOf(agent, parseAgentVersion(version));
  return "major" in line ? (line as TestedGeneration).major : null;
}

/** The status of the line a version belongs to (testedRangeOf); an
 *  unreadable version is judged on the agent's first line. Mirror of the
 *  launcher's. Pure. */
export function supportStatusOf(agent: VersionedAgent, version: string | null): SupportStatus {
  return testedRangeOf(agent, parseAgentVersion(version)).status;
}

/** The label of the PREVIEW line a version belongs to ("Goose", "OpenCode
 *  2"; supported-agents.md §2.0), or null for a supported one. Pure. */
export function previewLineOf(agent: VersionedAgent, version: string | null): string | null {
  const line = testedRangeOf(agent, parseAgentVersion(version));
  return line.status === "preview" ? rangeLabel(line) : null;
}

/** Where a preview agent's problems are reported. Mirror of the launcher's. */
export const ISSUES_URL = "https://github.com/mandusec/mandu/issues";
