/**
 * agent-versions — the agent versions Mandu was TESTED with, and the check a
 * launch and `mandu doctor` run against them (open-source release checklist
 * e4; docs/design/agents/supported-agents.md).
 *
 * Why: Mandu recovers the tool boundary from the agent's model-API traffic
 * (anthropic-proxy / openai-proxy) and classifies each tool's output by name
 * (arbiter/policy/claude-code-inbound.ts). A newer agent can advertise tools
 * the inbound spec has never seen, or change its request shape. An unknown
 * tool's output FAILS CLOSED (masked whole when injection protection is on),
 * so the drift costs usefulness rather than safety, but nothing used to say
 * the installed agent was outside what was tested. Now the launch prints one
 * WARNING line and doctor prints a row. A warning, never a refusal: a version
 * probe can be wrong, and the fail-closed spec still holds. The one exception
 * is OpenCode (opencodeLaunchRefusal below): there the version decides
 * whether the model traffic goes through the proxy at all, not how well the
 * agent works, so only OpenCode 1 and 2 launch, 2 with its launch argv
 * rewritten by opencode-argv.ts (MANDU_OPENCODE2=0 turns 2 off), and both
 * with their server and management subcommands refused there. Goose
 * (in the table since 2026-10-06) gets the warning like the rest: its
 * routing is decided by goose-route.ts, not by its version.
 *
 * Each tested line also carries its SUPPORT STATUS (SupportStatus):
 * `supported`, or `preview` (Goose and OpenCode 2, 2026-10-07; OpenCode 1,
 * 2026-10-09), which gets one launch line (launchPreviewNotice) and a word
 * on its doctor row.
 *
 * A GENERATION is tested on its own range (TESTED_AGENT_GENERATIONS):
 * OpenCode 2 is a rewrite, not a later 1.x, so 2.0.23 is judged against
 * OpenCode 2's range and 1.18.13 against OpenCode 1's.
 *
 * ONE SOURCE OF TRUTH per package: this table is mirrored in
 * dashboard/src/agent-versions.ts (the dashboard does not import the
 * launcher), and tests/stack/agent-versions-parity.test.ts
 * holds the two equal. Change both in one commit, with the evidence.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { availableParallelism, loadavg, tmpdir } from "node:os";
import { basename, join } from "node:path";
import { isAgent, type Agent } from "./generated/agents.js";

/** The agents with a tested range: every agent of the agent registry
 *  (generated/agents.ts, a copy of scripts/agents/agent-registry.mjs;
 *  supported-agents.md §5.7), so a new agent fails the type check in
 *  TESTED_AGENT_VERSIONS until its range is written. */
export type VersionedAgent = Agent;

export interface TestedRange {
  /** Plain product name. */
  name: string;
  /** Lowest and highest version the test batteries ran against (inclusive). */
  min: string;
  max: string;
  /** Where the range comes from (kept short; the design doc has the detail). */
  evidence: string;
  /** How fully Mandu supports it (SupportStatus); `preview` gets one launch
   *  notice (launchPreviewNotice) and a word on its doctor row. */
  status: SupportStatus;
}

/**
 * An agent's support status (supported-agents.md §2.0). `supported`: Mandu's
 * batteries and live checks cover it. `preview` (decided 2026-10-07 for
 * 0.2.0): it launches with every protection, but was tested less than Claude
 * Code and Codex (no live battery; the first-session tour never ran on it
 * live), so each launch says so in one line and asks for problem reports.
 * A status, never a refusal. Goose and OpenCode 2 (new in 0.2.0-beta.3) are
 * the previews, and OpenCode 1 since 2026-10-09 (its evidence is as thin: one
 * e2e lane, no drill, no per-push replay, no tour).
 */
export type SupportStatus = "supported" | "preview";

/**
 * The tested ranges. Raise `max` only after a battery ran green on the new
 * version AND its advertised tool surface is fully mapped (the `tool_surface`
 * event reads "all known to the inbound spec").
 */
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

/** A later generation of an agent with a tested range of its own: a version
 *  whose major is `major` is judged against it, never against the agent's. */
export interface TestedGeneration extends TestedRange {
  major: number;
}

/**
 * The generations tested apart from TESTED_AGENT_VERSIONS (which holds each
 * agent's first line). `name` stays the agent's, so a warning reads
 * "OpenCode 2.0.27 is newer than tested (… OpenCode 2.0.23 to 2.0.26)"; the README row
 * is `<name> <major>` ("OpenCode 2").
 */
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

/** The range a parsed version is judged against: its generation's when the
 *  agent has one for that major, else the agent's own. Pure. */
export function testedRangeOf(agent: VersionedAgent, v: AgentVersion | null): TestedRange {
  const gen = v === null ? undefined : TESTED_AGENT_GENERATIONS[agent]?.find((g) => g.major === v.parts[0]);
  return gen ?? TESTED_AGENT_VERSIONS[agent];
}

/** The plain label of a tested line: the agent's name, or `<name> <major>`
 *  for a generation ("OpenCode 2", the README row's spelling). */
export function rangeLabel(r: TestedRange | TestedGeneration): string {
  return "major" in r ? `${r.name} ${r.major}` : r.name;
}

/** The status of the line a probed version belongs to (testedRangeOf);
 *  an unreadable version is judged on the agent's first line. Pure. */
export function supportStatusOf(agent: VersionedAgent, version: string | null): SupportStatus {
  return testedRangeOf(agent, parseAgentVersion(version)).status;
}

/** Where a preview notice sends problem reports. */
export const ISSUES_URL = "https://github.com/mandusec/mandu/issues";

/** The switch that hides the preview notice (`preview-notice = false` in
 *  config.toml sets it): "0", "false", "off" or "no". */
export const PREVIEW_NOTICE_ENV = "MANDU_PREVIEW_NOTICE";

/** The ONE launch line for a preview agent: already short, so the compact
 *  display passes it through as is (launch-banner.ts compactNotice). */
export function previewNotice(label: string): string {
  return `mandu: ! ${label} support is a preview: tested less than Claude Code and Codex; report problems at ${ISSUES_URL}`;
}

/** Does `note` come from previewNotice? (launch-banner.ts compactNotice) */
export function isPreviewNotice(note: string): boolean {
  return /^mandu: ! .+ support is a preview: tested less than /.test(note);
}

/**
 * The preview notice for this launch, or null. Keyed on the TARGET (a Goose
 * started through a wrapper script is still Goose) and, for OpenCode, on the
 * generation run.ts settled (opencodeGeneration: 2 for `opencode2` or a
 * probed 2.x, 1 for a probed 1.x). An OpenCode whose generation is not
 * known (a wrapper script) gets the notice only when every OpenCode line is a
 * preview (both are, since 2026-10-09), named plain "OpenCode". Null for a
 * supported agent, a `--version` launch, and under MANDU_PREVIEW_NOTICE=0.
 * Pure.
 */
export function launchPreviewNotice(
  target: string,
  argv: readonly string[],
  opencodeGen: 1 | 2 | null,
  env: Record<string, string | undefined>,
): string | null {
  const off = (env[PREVIEW_NOTICE_ENV] ?? "").trim().toLowerCase();
  if (off === "0" || off === "false" || off === "off" || off === "no") return null;
  if (VERSION_FLAGS.has(argv[1] ?? "")) return null;
  if (!(target in TESTED_AGENT_VERSIONS)) return null;
  const agent = target as VersionedAgent;
  if (agent === "opencode" && opencodeGen !== null) {
    const line: TestedRange | TestedGeneration =
      TESTED_AGENT_GENERATIONS.opencode?.find((g) => g.major === opencodeGen) ?? TESTED_AGENT_VERSIONS.opencode;
    return line.status === "preview" ? previewNotice(rangeLabel(line)) : null;
  }
  // The generation is not known (a wrapper script): claim only what every
  // tested line of the agent says, under the agent's own name.
  const first = TESTED_AGENT_VERSIONS[agent];
  if ((TESTED_AGENT_GENERATIONS[agent] ?? []).some((g) => g.status !== first.status)) return null;
  return first.status === "preview" ? previewNotice(rangeLabel(first)) : null;
}

/** A parsed version: the numeric triple plus any suffix after `-`. */
export interface AgentVersion {
  raw: string;
  parts: [number, number, number];
  /** A prerelease tag (`beta.1`, `rc2`): sorts BELOW its release, semver-style. */
  prerelease: string | null;
}

/**
 * Pull the first `X.Y.Z` out of a `--version` output. Tolerates the shapes the
 * agents print: `2.1.281 (Claude Code)`, `codex-cli 0.154.0`,
 * `OpenClaw 2026.3.12 (a712433)`, `2026.7.1-2`, `v1.18.13`. A numeric-only
 * suffix (`-2`) is a packaging revision and ignored; a suffix with a letter is
 * a prerelease. Null when no triple is present.
 */
export function parseAgentVersion(output: string | null | undefined): AgentVersion | null {
  if (!output) return null;
  const m = /(?:^|[^\d.])v?(\d{1,6})\.(\d{1,6})\.(\d{1,6})(?:-([0-9A-Za-z][0-9A-Za-z.-]*))?/.exec(output);
  if (!m) return null;
  const suffix = m[4] ?? null;
  const prerelease = suffix !== null && /[A-Za-z]/.test(suffix) ? suffix : null;
  const parts: [number, number, number] = [Number(m[1]), Number(m[2]), Number(m[3])];
  return { raw: `${parts.join(".")}${prerelease ? `-${prerelease}` : ""}`, parts, prerelease };
}

/** -1 / 0 / 1. A prerelease sorts below the same triple without one. */
export function compareAgentVersions(a: AgentVersion, b: AgentVersion): number {
  for (let i = 0; i < 3; i++) {
    if (a.parts[i]! !== b.parts[i]!) return a.parts[i]! < b.parts[i]! ? -1 : 1;
  }
  if (a.prerelease === b.prerelease) return 0;
  if (a.prerelease === null) return 1;
  if (b.prerelease === null) return -1;
  return a.prerelease < b.prerelease ? -1 : 1;
}

/** Where a version sits against its agent's tested range. */
export type RangeVerdict = "tested" | "newer" | "older" | "unknown";

export interface AgentVersionCheck {
  agent: VersionedAgent;
  name: string;
  /** The parsed version, or null when it could not be read. */
  version: string | null;
  verdict: RangeVerdict;
  min: string;
  max: string;
}

/** Place a `--version` output against the agent's tested range (its
 *  generation's, testedRangeOf). Pure. */
export function checkAgentVersion(agent: VersionedAgent, versionOutput: string | null): AgentVersionCheck {
  const v = parseAgentVersion(versionOutput);
  const r = testedRangeOf(agent, v);
  const base = { agent, name: r.name, min: r.min, max: r.max };
  if (v === null) return { ...base, version: null, verdict: "unknown" };
  const lo = parseAgentVersion(r.min)!;
  const hi = parseAgentVersion(r.max)!;
  const verdict: RangeVerdict = compareAgentVersions(v, lo) < 0 ? "older" : compareAgentVersions(v, hi) > 0 ? "newer" : "tested";
  return { ...base, version: v.raw, verdict };
}

/** The tested range in words: "2.1.273 to 2.1.281", or "1.18.13" for one. */
export function rangeWords(c: { min: string; max: string }): string {
  return c.min === c.max ? c.min : `${c.min} to ${c.max}`;
}

/**
 * The ONE launch line for a version outside the tested range, or null when it
 * is inside. Says what the risk is, truthfully: an unknown tool's output is
 * masked whole (fail closed), so the agent may work less well; a changed
 * request format could stop the session. Carries `WARNING` so the compact
 * display prints it (launch-banner.ts isAttentionNote).
 */
export function versionWarning(c: AgentVersionCheck): string | null {
  const range = `Mandu was tested with ${c.name} ${rangeWords(c)}`;
  const risk =
    "tools it adds that Mandu does not know are treated as untrusted (their output is masked, so the agent may work less well), " +
    "and a changed request format can stop the session. The dashboard marks any unknown tool; `mandu doctor` shows this check.";
  switch (c.verdict) {
    case "tested":
      return null;
    case "newer":
      return `mandu: WARNING — ${c.name} ${c.version} is newer than tested (${range}): ${risk}`;
    case "older":
      return `mandu: WARNING — ${c.name} ${c.version} is older than tested (${range}): ` +
        `upgrade it if anything misbehaves; older releases send a different request format.`;
    case "unknown":
      return `mandu: WARNING — could not read the ${c.name} version (${range}), so this launch is not checked against it.`;
  }
}

/** Which agent a launch starts, when its version can be probed: the target
 *  must be a versioned agent AND argv[0] must really be that binary. A wrapper
 *  script launched with `--target claude` is not run with `--version` (it may
 *  not understand the flag); the same rule agent-login.ts uses. OpenCode 2's
 *  own command `opencode2` counts as the `opencode` binary too, unless
 *  `opts.opencode2` is false (MANDU_OPENCODE2=0, below): then `opencode2` is
 *  refused by name and never run, not even for `--version`. */
export function versionedAgentOf(target: string, argv: readonly string[], opts: { opencode2?: boolean } = {}): VersionedAgent | null {
  const base = (argv[0] ?? "").split("/").pop() ?? "";
  if (isAgent(target) && base === target) {
    return target;
  }
  if (target === "opencode" && base === OPENCODE2_BIN && opts.opencode2 !== false) return "opencode";
  return null;
}

/**
 * OpenCode: the version decides the ROUTING, so it is a refusal, not a
 * warning (supported-agents.md §2.3). npm `@opencode/cli` 2.0 (GA
 * 2026-09-11) installs the same `opencode` command as OpenCode 1 (npm
 * `opencode-ai`), plus `opencode2`. Its `opencode` and `opencode run` hand
 * the session to a BACKGROUND SERVICE (`opencode service`, found through
 * `$XDG_STATE_HOME/opencode/service.json`) by default, and that service runs
 * the model turns and the tools with the configuration it was started with
 * (probe-verified on 2.0.22: a run carrying Mandu's routing sent both of its
 * requests to a user service's own endpoint, never to the proxy). So a 2.x
 * launch is admitted only with its argv rewritten by opencode-argv.ts
 * `opencode2LaunchArgv` (`--standalone`: a private server, a child of the
 * agent inside the wrap; every shape that joins or drives a server outside
 * the launch refused), and with the confidentiality axis on only while its
 * guards are in force (run.ts, opencode2-confidentiality.ts). Run.ts knows
 * which rule applies only from the probed major, so:
 *
 *   - majors 1 and 2 launch (2 as `opencode` or `opencode2`; `opencode2` must
 *     report major 2). Supported by default since 2026-10-05, after a live
 *     check (supported-agents.md §2.3); before that, 2.x needed the opt-in
 *     MANDU_EXPERIMENTAL_OPENCODE2=1, which is no longer read (a no-op).
 *   - MANDU_OPENCODE2=0 turns 2.x off: refused by name (`opencode2` never
 *     run, not even for `--version`).
 *   - every other major is refused: OpenCode 2's prereleases are published as
 *     `0.0.0-beta-…` and `0.0.0-dev-…` (npm dist-tags of `@opencode/cli` and
 *     `@opencode-ai/cli`), and OpenCode 0.x (2025) is long out of range.
 *   - a version Mandu cannot read is refused: the probe is what tells the
 *     two generations apart.
 */
export const OPENCODE_V1_MAJOR = 1;

/** OpenCode 2's major: launched with the argv rule and its guards. */
export const OPENCODE_V2_MAJOR = 2;

/** The switch that turns OpenCode 2 off (on by default). */
export const OPENCODE2_ENV = "MANDU_OPENCODE2";

/** OpenCode 2 is on unless MANDU_OPENCODE2 says an explicit no ("0",
 *  "false", "off", "no"); any other value, or none, leaves it on. The old
 *  opt-in MANDU_EXPERIMENTAL_OPENCODE2 is not read. */
export function opencode2Enabled(env: Record<string, string | undefined>): boolean {
  const v = (env[OPENCODE2_ENV] ?? "").trim().toLowerCase();
  return !(v === "0" || v === "false" || v === "off" || v === "no");
}

/** One OpenCode generation's tested range. */
export function opencodeTested(major: 1 | 2): TestedRange {
  return TESTED_AGENT_GENERATIONS.opencode?.find((g) => g.major === major) ?? TESTED_AGENT_VERSIONS.opencode;
}

/** The install line for one generation (its tested max). */
export function opencodeInstall(major: 1 | 2): string {
  return `npm i -g ${major === OPENCODE_V1_MAJOR ? "opencode-ai" : "@opencode/cli"}@${opencodeTested(major).max}`;
}

/** The basename only OpenCode 2's package installs. */
const OPENCODE2_BIN = "opencode2";

/** argv[0]'s basename when it is OpenCode's own command (`opencode`,
 *  `opencode2`), null for anything else (a wrapper script). */
function opencodeBase(argv: readonly string[]): string | null {
  const base = (argv[0] ?? "").split("/").pop() ?? "";
  return base === "opencode" || base === OPENCODE2_BIN ? base : null;
}

const VERSION_FLAGS = new Set(["--version", "-v", "-V"]);

/**
 * The refusal for an OpenCode launch Mandu cannot route, or null. Pure:
 * `check` is launchVersionCheck's answer for this launch (null when it did
 * not probe). Refuses an OpenCode whose major version is neither 1 nor 2
 * (`opencode2` must report 2), one whose version could not be read, and,
 * with `opts.opencode2` false (MANDU_OPENCODE2=0, opencode2Enabled), every
 * 2.x: `opencode2` by name, unprobed. A wrapper script launched with
 * `--target opencode` is not probed (the same rule as the version check) and
 * not refused here; a `--version` launch makes no model call and is let
 * through.
 */
export function opencodeLaunchRefusal(
  target: string,
  argv: readonly string[],
  check: AgentVersionCheck | null,
  opts: { opencode2?: boolean; probeWhy?: string | null } = {},
): string | null {
  if (target !== "opencode") return null;
  const base = opencodeBase(argv);
  if (base === null) return null;
  const v2On = opts.opencode2 !== false;
  const v1 = rangeWords(opencodeTested(1));
  const v2 = rangeWords(opencodeTested(2));
  const turnedOff =
    `${OPENCODE2_ENV}=0 turns OpenCode 2 off. Unset ${OPENCODE2_ENV} to run it, ` +
    `or use OpenCode 1 (${opencodeInstall(1)}).`;
  if (base === OPENCODE2_BIN && !v2On) {
    return `mandu: refusing to launch ${argv[0]}: it is OpenCode 2's command, and ${turnedOff}`;
  }
  if (VERSION_FLAGS.has(argv[1] ?? "")) return null;
  const supported = v2On
    ? `Mandu supports OpenCode 1 (npm opencode-ai; tested with ${v1}) and OpenCode 2 (npm @opencode/cli; tested with ${v2}).`
    : `Mandu supports OpenCode 1 (npm opencode-ai; tested with ${v1}); ${OPENCODE2_ENV}=0 turns OpenCode 2 off.`;
  const install = v2On
    ? `Install one of them (${opencodeInstall(1)}, or ${opencodeInstall(2)}).`
    : `Install OpenCode 1 (${opencodeInstall(1)}).`;
  if (check === null || check.version === null) {
    return (
      `mandu: refusing to launch ${argv[0]}: could not read its version (\`${argv[0]} --version\`` +
      `${opts.probeWhy ? `: ${opts.probeWhy}` : ""}), ` +
      "so Mandu cannot tell OpenCode 1 from OpenCode 2, and OpenCode 2 must be started with its own private server " +
      `so that its model calls go through Mandu. ${supported} ${install}`
    );
  }
  const major = parseAgentVersion(check.version)?.parts[0] ?? null;
  if (major === OPENCODE_V2_MAJOR && !v2On) {
    return `mandu: refusing to launch OpenCode ${check.version}: ${turnedOff}`;
  }
  const admitted = base === OPENCODE2_BIN
    ? major === OPENCODE_V2_MAJOR
    : major === OPENCODE_V1_MAJOR || major === OPENCODE_V2_MAJOR;
  if (!admitted) {
    const which = base === OPENCODE2_BIN ? ` (${argv[0]} is OpenCode 2's command, so it must report version 2)` : "";
    return `mandu: refusing to launch OpenCode ${check.version}${which}. ${supported} ${install}`;
  }
  return null;
}

/**
 * Which OpenCode generation a launch starts: 2 for `opencode2` or a probed
 * major 2, 1 for a probed major 1, null otherwise (another target, a wrapper
 * script, an unprobed or unreadable launch). run.ts applies the OpenCode 2
 * argv rule (opencode-argv.ts) to generation 2 and the OpenCode 1 one to
 * generation 1, after opencodeLaunchRefusal let the launch through. Pure.
 */
export function opencodeGeneration(target: string, argv: readonly string[], check: AgentVersionCheck | null): 1 | 2 | null {
  if (target !== "opencode") return null;
  const base = opencodeBase(argv);
  if (base === null) return null;
  if (base === OPENCODE2_BIN) return 2;
  const major = parseAgentVersion(check?.version ?? null)?.parts[0] ?? null;
  if (major === OPENCODE_V2_MAJOR) return 2;
  if (major === OPENCODE_V1_MAJOR) return 1;
  return null;
}

/** Probe budget on an idle host. A real `--version` answers in tens of
 *  milliseconds there; the budget is for a binary that hangs. It was 3 s,
 *  which a loaded CI guest's OpenCode 1 (a large single-file binary) missed:
 *  the launch was refused as "could not read its version" three tests in a
 *  row (pipelines 9495, 9518, 9554; supported-agents.md §2.3). */
export const VERSION_PROBE_TIMEOUT_MS = 10_000;
/** The load-scaled budget never exceeds this. */
export const VERSION_PROBE_MAX_MS = 60_000;

/** The probe's budget: VERSION_PROBE_TIMEOUT_MS stretched by the 1-minute
 *  load average per usable CPU when that exceeds 1, capped (the rule of
 *  services/primitives.ts serviceReadyDeadlineMs). Pure over `host`. */
export function versionProbeTimeoutMs(
  host: { load1: number; ncpu: number } = { load1: loadavg()[0] ?? 0, ncpu: availableParallelism() },
): number {
  const ratio = host.ncpu > 0 && Number.isFinite(host.load1) ? host.load1 / host.ncpu : 1;
  return Math.round(Math.min(VERSION_PROBE_MAX_MS, VERSION_PROBE_TIMEOUT_MS * Math.max(1, ratio)));
}

/** `<bin> --version`'s output, or why there is none. */
export interface VersionProbe {
  version: string | null;
  /** Why `version` is null ("timed out after 10000 ms", "exit 2: …"). */
  why: string | null;
}

/** Run `<bin> --version`, time-bounded, and say why it gave nothing: a
 *  missing binary, a timeout, a non-zero exit or empty output. Never throws. */
export function probeAgentVersionWhy(
  bin: string,
  env?: Record<string, string | undefined>,
  timeoutMs: number = versionProbeTimeoutMs(),
): VersionProbe {
  try {
    const r = spawnSync(bin, ["--version"], {
      encoding: "utf8",
      timeout: timeoutMs,
      stdio: ["ignore", "pipe", "pipe"],
      ...(env ? { env: env as NodeJS.ProcessEnv } : {}),
    });
    const err = (r.stderr ?? "").trim().split("\n")[0]?.slice(0, 200) ?? "";
    if (r.error) {
      const code = (r.error as NodeJS.ErrnoException).code;
      return { version: null, why: code === "ETIMEDOUT" ? `timed out after ${timeoutMs} ms` : r.error.message };
    }
    if (r.status !== 0) {
      return { version: null, why: r.signal ? `killed by ${r.signal}` : `exit ${r.status}${err ? `: ${err}` : ""}` };
    }
    const out = `${r.stdout ?? ""}\n${r.stderr ?? ""}`.trim();
    return out === "" ? { version: null, why: "it printed nothing" } : { version: out, why: null };
  } catch (e) {
    return { version: null, why: (e as Error).message };
  }
}

/** Run `<bin> --version`, time-bounded. Null on a missing binary, a timeout,
 *  a non-zero exit or empty output. Never throws. */
export function probeAgentVersion(
  bin: string,
  env?: Record<string, string | undefined>,
  timeoutMs: number = versionProbeTimeoutMs(),
): string | null {
  return probeAgentVersionWhy(bin, env, timeoutMs).version;
}

/** `probeAgentVersion` for a probe that must only look (`mandu doctor`).
 *  Codex sets up its helper links under `$CODEX_HOME/tmp/arg0` at every
 *  start, `--version` included (codex-cli 0.155.1, measured 2026-10-01), so
 *  its probe gets a throwaway CODEX_HOME, removed after: the user's
 *  `~/.codex` is not touched. OpenCode (1.18.13 and 2.0.23, measured
 *  2026-10-05) makes its XDG folders at every start, and 2.x writes a log
 *  there on `--version`: its probe gets throwaway XDG folders the same way.
 *  Goose (1.53.0, measured 2026-10-06) writes a log under
 *  `$XDG_STATE_HOME/goose/logs` on `--version` and nothing under HOME once
 *  the XDG folders are set: the same throwaway XDG folders.
 *  Null when that folder cannot be made. */
export function probeAgentVersionLooking(bin: string, env: Record<string, string | undefined> = process.env): string | null {
  const base = basename(bin);
  const xdg = base === "opencode" || base === OPENCODE2_BIN || base === "goose";
  if (base !== "codex" && !xdg) return probeAgentVersion(bin, env);
  let home: string | null = null;
  try {
    home = mkdtempSync(join(tmpdir(), `mandu-${base === "goose" || base === "codex" ? base : "opencode"}-version-`));
    const own: Record<string, string> = xdg
      ? {
          XDG_CONFIG_HOME: join(home, "config"), XDG_DATA_HOME: join(home, "data"),
          XDG_STATE_HOME: join(home, "state"), XDG_CACHE_HOME: join(home, "cache"),
        }
      : { CODEX_HOME: home };
    return probeAgentVersion(bin, { ...env, ...own });
  } catch {
    return null;
  } finally {
    if (home !== null) rmSync(home, { recursive: true, force: true });
  }
}

/**
 * The launch check: probe the agent this launch starts and return the check
 * plus its warning line (null when in range or not probed). `probe` is
 * injectable for tests. `opencode2` is probed too unless `opts.opencode2` is
 * false (MANDU_OPENCODE2=0; versionedAgentOf).
 */
export function launchVersionCheck(
  target: string,
  argv: readonly string[],
  probe: (bin: string) => string | null = (bin) => probeAgentVersion(bin),
  opts: { opencode2?: boolean } = {},
): { check: AgentVersionCheck; note: string | null } | null {
  const agent = versionedAgentOf(target, argv, opts);
  if (agent === null) return null;
  // A launch that only asks the agent for its version needs no check.
  if (argv[1] === "--version" || argv[1] === "-v" || argv[1] === "-V") return null;
  const check = checkAgentVersion(agent, probe(argv[0]!));
  return { check, note: versionWarning(check) };
}
