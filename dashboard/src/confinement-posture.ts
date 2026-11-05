/**
 * confinement-posture — the ONE vocabulary for how well secrets are kept from
 * the agent's world on this host (docs/design/confidentiality/rootless-confinement-ubuntu-2404.md
 * §2; confidentiality.md §10.1). The launch notice, `mandu doctor`, the
 * `launch_posture` event and the dashboard chip all read the names and the
 * honest sentences from here, so they cannot drift apart.
 *
 *   confined      raw secret bytes are ABSENT from the agent's world (Linux:
 *                 the whole-agent guard serving the twins by descriptor, with
 *                 the bwrap bind mount as a second layer where the host can
 *                 mount it; `bindGap` says when it cannot). Since
 *                 2026-09-28 (sandbox-security-review finding 7) confined
 *                 REQUIRES the guard: the bind alone misses a secret file the
 *                 host replaces while the agent runs.
 *   read-blocked  secret files are UNREADABLE to the agent tree; a read fails
 *                 instead of returning a symbol (macOS: the whole-agent Seatbelt
 *                 profile, seatbelt-profile.ts, which also keeps the files and
 *                 their folders from being renamed, seals Mandu's own state,
 *                 and carries the write-protect, network and Unix-socket
 *                 rules; the rootless Linux Landlock variant is a spike, §5).
 *                 No reader is ever handed the real file there, so a launch
 *                 names no pinned readers.
 *   gated         neither. Track A only: model-context masking + egress gates.
 *                 A subprocess CAN read raw secret files. On a host whose
 *                 bwrap can mount but with no guard around the launch (gap
 *                 `no-guard` / `guard-off`) the bind still goes up as a
 *                 partial layer; see `bindOnlyLines` for what it covers.
 *
 * COVERAGE (2026-10-25, docs/design/agents/openclaw-plugin.md §3.4). The
 * posture is decided over what a session's protection COVERS, one row per
 * chokepoint (`Coverage`: model context, files, exec, egress, replies,
 * Mandu's own state), by `resolvePosture`. A wrapped launch's host facts
 * derive into a coverage (`hostCoverage`), so `resolveHostPosture` is
 * `resolvePosture(hostCoverage(facts))`; an ATTACHMENT (Mandu attached to an
 * agent it does not run, the OpenClaw plugin first) declares its coverage
 * (`ATTACHMENT_COVERAGE`) and gets a gap of its own (`AttachmentGap`), with
 * its own sentence where the posture's generic one would claim too much. An
 * attachment whose service found its route lost (openclaw-plugin.md §3.6)
 * declares less (`attachmentCoverage`: the model context, exec and replies
 * rows may be `none`); a model context that is not the proxy decides first,
 * `gated` with the `RouteGap` `model-route-lost`.
 *
 * PURE: every host fact is an input, so the whole decision table is unit-tested
 * with no privilege. The `gated` posture must never borrow the `confined` claim.
 *
 * One module, three copies (the launcher, the dashboard, the arbiter: each
 * package stays standalone); the source is launcher/src/confinement-posture.ts:
 * change it, then run `node scripts/copies/module-copies.mjs generate`. It
 * imports nothing, so a copy needs nothing else.
 *
 * Mandu-new (no reference origin).
 */

export type ConfinementPosture = "confined" | "read-blocked" | "gated";

export const POSTURES: readonly ConfinementPosture[] = ["confined", "read-blocked", "gated"];

/** One honest sentence per posture; shown wherever the posture name is. */
export const POSTURE_SENTENCE: Record<ConfinementPosture, string> = {
  "confined": "Programs the AI runs get a masked copy of each credential file, never the real one. A program you allow to read a file gets the real contents, and what it prints is masked before the AI sees it.",
  "read-blocked": "Programs the AI runs cannot open your credential files: a read fails instead of returning a masked copy.",
  "gated": "The AI sees your secrets masked and a secret is sent out only where a rule or your OK allows, but programs the AI runs can still read your credential files.",
};

/** The one-command upgrade (§3.2). Run WITHOUT sudo: it explains, then asks
 *  for sudo itself for the one install step (`sudo mandu` commonly fails
 *  anyway: root's PATH lacks an nvm / npm-global `mandu`). */
export const SETUP_COMMAND = "mandu setup";

/** Why confinement cannot be established on this host, as a stable code. */
export type HostGap =
  | "apparmor-userns"   // Ubuntu >= 23.10: bwrap carries no `userns` AppArmor grant — `mandu setup` fixes it
  | "userns-off"        // another kernel knob / container policy denies the namespace
  | "no-bwrap"          // bubblewrap is not installed
  | "bwrap-nesting"     // the bind wrap would stop every sandbox the agent's tools start (Ubuntu 26.04's bwrap profile) — `mandu setup` fixes it
  | "no-sandbox-exec"   // macOS without sandbox-exec
  | "unsupported-os"    // Windows
  // The two below leave the bind mount up as a partial layer (bind-only):
  | "no-guard"          // the whole-agent guard (mandu-net-guard) is unavailable: no binary for this host, or one that cannot start (a container's seccomp profile)
  | "guard-off";        // the user turned the guard off (--no-net-guard, MANDU_NET_GUARD=0, net-guard = false, --no-kernel)

/** Every HostGap, for the vocabulary parity tests (the dashboard mirrors the
 *  fixes). A Record so a new code that is not listed fails to compile. */
const GAP_SET: Record<HostGap, true> = {
  "apparmor-userns": true, "userns-off": true, "no-bwrap": true, "bwrap-nesting": true,
  "no-sandbox-exec": true, "unsupported-os": true, "no-guard": true, "guard-off": true,
};
export const HOST_GAPS: readonly HostGap[] = Object.keys(GAP_SET) as HostGap[];

/** Why an ATTACHMENT is not confined: Mandu is attached to an agent it does
 *  not run, so no host fact is involved; the code names the attachment kind
 *  (docs/design/agents/openclaw-plugin.md §3.4). */
export type AttachmentGap =
  | "openclaw-plugin"; // a plugin inside the user's own OpenClaw Gateway, beside the resident service

const ATTACHMENT_GAP_SET: Record<AttachmentGap, true> = { "openclaw-plugin": true };
export const ATTACHMENT_GAPS: readonly AttachmentGap[] = Object.keys(ATTACHMENT_GAP_SET) as AttachmentGap[];

/** Why model calls may reach the model WITHOUT crossing Mandu's proxy: an
 *  attachment whose service found the agent's own config no longer routing
 *  every model call through it (openclaw-plugin.md §3.6, the route check).
 *  Not an attachment kind: the kind stays on the record beside it. */
export type RouteGap =
  | "model-route-lost"; // the agent's config dropped Mandu's route (or cannot be read)

const ROUTE_GAP_SET: Record<RouteGap, true> = { "model-route-lost": true };
export const ROUTE_GAPS: readonly RouteGap[] = Object.keys(ROUTE_GAP_SET) as RouteGap[];

/** Every gap a posture can carry. */
export type PostureGap = HostGap | AttachmentGap | RouteGap;
export const POSTURE_GAPS: readonly PostureGap[] = [...HOST_GAPS, ...ATTACHMENT_GAPS, ...ROUTE_GAPS];

/** Is `v` a route gap (model calls may go around the proxy)? */
export function isRouteGap(v: unknown): v is RouteGap {
  return typeof v === "string" && Object.prototype.hasOwnProperty.call(ROUTE_GAP_SET, v);
}

/** Is `v` an attachment kind (= its gap code)? */
export function isAttachmentKind(v: unknown): v is AttachmentGap {
  return typeof v === "string" && Object.prototype.hasOwnProperty.call(ATTACHMENT_GAP_SET, v);
}

function isHostGap(v: unknown): v is HostGap {
  return typeof v === "string" && Object.prototype.hasOwnProperty.call(GAP_SET, v);
}

/** The gaps under which the bind mount still goes up (a partial layer): the
 *  host can mount, but no guard is around the launch. */
export function isBindOnlyGap(gap: PostureGap | string | undefined): gap is "no-guard" | "guard-off" {
  return gap === "no-guard" || gap === "guard-off";
}

export interface HostFacts {
  platform: "linux" | "darwin" | "win32";
  /** `bwrap` on PATH (Linux). */
  bwrap: boolean;
  /** The userns probe passed (Linux; src/userns.ts `probeUserns`). */
  userns: boolean;
  /** kernel.apparmor_restrict_unprivileged_userns reads 1 (Linux). */
  apparmorRestricted: boolean;
  /** `/usr/bin/sandbox-exec` is there (macOS; checked by that path, never a
   *  PATH lookup: seatbelt-profile.ts `sandboxExecAvailable`). */
  sandboxExec: boolean;
  /** A rootless Landlock `read-blocked` backend is built AND the kernel
   *  supports it. Always false today: the backend is a spike (§5), so a
   *  Landlock-capable Linux host without userns still resolves to `gated`. */
  landlockReadBlock: boolean;
  /** The whole-agent guard (`mandu-net-guard`) is available on this Linux
   *  host: it traps `open()` and serves every registered secret by descriptor
   *  (plan 10 §11.7 / §8 phase 6), so no user namespace is needed to confine.
   *  Absent/false = the pre-phase-6 table. */
  guard?: boolean;
  /** The user turned the guard off for launches (--no-net-guard,
   *  MANDU_NET_GUARD=0, `net-guard = false`, --no-kernel): names the gap
   *  `guard-off` instead of `no-guard`. Only read when `guard` is not true. */
  guardOff?: boolean;
  /** A sandbox can start INSIDE the bind wrap (secret-twins.ts
   *  `nestedSandboxProbeArgv`). false on Ubuntu 26.04, whose bwrap profile
   *  bars a user namespace to everything a bwrap sandbox runs: the bind would
   *  break Codex's shell and Mandu's exec box. Absent = not probed (as true). */
  nesting?: boolean;
}

/** A posture and why it is not the best one. `G`: the gaps it may carry. */
export interface Posture<G extends PostureGap = PostureGap> {
  posture: ConfinementPosture;
  /** Set iff the session cannot reach its platform's best posture. */
  gap?: G;
  /** `confined` by the guard ALONE: the bind-mount layer is unavailable for
   *  this reason. Not a gap in the guarantee (raw bytes are still absent from
   *  the agent's world); `mandu setup` adds the bind as a second layer. */
  bindGap?: HostGap;
}

/** A wrapped launch's posture: host gaps only. */
export type HostPosture = Posture<HostGap>;

// ── Coverage: what a session's protection covers, per chokepoint ─────────────

/** The model context: every model call crosses Mandu's model proxy, the
 *  row every session Mandu protects starts with; or `none`, an attachment
 *  whose service found the agent's own config no longer sending every model
 *  call through it, or could not read that config (openclaw-plugin.md §3.6). */
export type ModelContextCoverage = "proxy" | "none";

/** The files the agent's programs open. `G`: the gaps an uncovered row names. */
export type FileCoverage<G extends PostureGap = PostureGap> =
  /** The whole-agent guard serves each secret's placeholder copy by
   *  descriptor (`confined`); `mountGap`: why the bind mount is not a second
   *  layer. */
  | { by: "guard"; mountGap?: HostGap }
  /** A read of a secret file fails (`read-blocked`: macOS Seatbelt, or the
   *  Landlock spike, which names the host gap it stands in for). */
  | { by: "read-deny"; why?: HostGap }
  /** The bind mount alone, no guard (finding 7): a partial layer, `gated`. */
  | { by: "mount"; why: "no-guard" | "guard-off" }
  /** Real files. */
  | { by: "none"; why: G };

/** The programs the agent runs: a sandbox (the wrapper's exec box and shims),
 *  a policy that refuses calls by their text (an attachment's
 *  `before_tool_call`), or nothing (an attachment whose plugin the agent's
 *  config no longer loads, §3.6). */
export type ExecCoverage = "sandbox" | "policy" | "none";

/** Where a secret may go: the egress gate (the wrapper's network proxy and
 *  kernel confine), or nothing checks the programs' own connections. */
export type EgressCoverage = "gate" | "none";

/** Where a reply shows real values: the terminal's reply filter, a chat
 *  channel's outgoing hook (an attachment), or nothing checks the replies
 *  (an attachment whose plugin is no longer loaded, §3.6). */
export type ReplyCoverage = "terminal" | "chat" | "none";

/** Mandu's own state (its home, its sockets): hidden from and write-protected
 *  against the agent's programs, the human plane walled off; or readable. */
export type OwnStateCoverage = "walled" | "readable";

interface CoverageRest {
  modelContext: ModelContextCoverage;
  exec: ExecCoverage;
  egress: EgressCoverage;
  replies: ReplyCoverage;
}

/** What a session's protection covers. A covered files row (`guard`,
 *  `read-deny`) stands only beside a walled own state: a program that reads
 *  Mandu's own records reads what the placeholders stand for, so the type
 *  has no such pair. */
export type Coverage<G extends PostureGap = PostureGap> = CoverageRest & (
  | { files: { by: "guard"; mountGap?: HostGap } | { by: "read-deny"; why?: HostGap }; ownState: "walled" }
  | { files: { by: "mount"; why: "no-guard" | "guard-off" } | { by: "none"; why: G }; ownState: OwnStateCoverage }
);

/** A coverage whose model calls all cross the proxy (every wrapped launch's,
 *  and an attachment's as registered). */
export type ProxiedCoverage<G extends PostureGap = PostureGap> = Coverage<G> & { modelContext: "proxy" };

/** The posture a coverage gets: THE decision (`resolveHostPosture` is this
 *  over a launch's host facts). Model calls that do not all cross the proxy
 *  decide first (`gated`, gap `model-route-lost`: a model may read a secret
 *  as it is, whatever the files row covers); otherwise the files row names
 *  it, and the type keeps a covered files row beside a walled own state. Pure. */
export function resolvePosture<G extends PostureGap>(c: ProxiedCoverage<G>): Posture<G | HostGap>;
export function resolvePosture<G extends PostureGap>(c: Coverage<G>): Posture<G | HostGap | RouteGap>;
export function resolvePosture<G extends PostureGap>(c: Coverage<G>): Posture<G | HostGap | RouteGap> {
  if (c.modelContext === "none") return { posture: "gated", gap: "model-route-lost" };
  const f = c.files;
  switch (f.by) {
    case "guard": return f.mountGap !== undefined ? { posture: "confined", bindGap: f.mountGap } : { posture: "confined" };
    case "read-deny": return f.why !== undefined ? { posture: "read-blocked", gap: f.why } : { posture: "read-blocked" };
    case "mount": return { posture: "gated", gap: f.why };
    case "none": return { posture: "gated", gap: f.why };
  }
}

/** The rows a wrapped launch covers beyond its files: the wrapper's model
 *  proxy, exec box, egress gate and reply filter. */
const WRAPPER_REST: CoverageRest & { modelContext: "proxy" } = { modelContext: "proxy", exec: "sandbox", egress: "gate", replies: "terminal" };

/** What a wrapped launch on this host covers. The files row is the host
 *  decision; Mandu's own state is walled where the files are covered (the
 *  guard and the Seatbelt profile seal it) and counted readable otherwise.
 *  `egressGateOff`: the user turned the egress gate off. Pure. */
export function hostCoverage(f: HostFacts, o: { egressGateOff?: boolean } = {}): ProxiedCoverage<HostGap> {
  const rest: CoverageRest & { modelContext: "proxy" } = { ...WRAPPER_REST, ...(o.egressGateOff === true ? { egress: "none" as const } : {}) };
  const files = hostFiles(f);
  return files.by === "guard" || files.by === "read-deny"
    ? { ...rest, files, ownState: "walled" }
    : { ...rest, files, ownState: "readable" };
}

/** The files row of a wrapped launch on this host. Pure. */
function hostFiles(f: HostFacts): FileCoverage<HostGap> {
  if (f.platform === "win32") return { by: "none", why: "unsupported-os" };
  if (f.platform === "darwin") return f.sandboxExec ? { by: "read-deny" } : { by: "none", why: "no-sandbox-exec" };
  if (f.bwrap && f.userns) {
    // Bind-only (sandbox-security-review-2026-09-28 finding 7): without the
    // guard a secret file the HOST replaces while the agent runs (a token
    // refresh, an editor save) detaches the twin bind and the new real file
    // is readable; only the guard's by-path open catches that. So the bind
    // alone is `gated`, and the bind still goes up as a partial layer.
    if (f.guard !== true) return { by: "mount", why: f.guardOff === true ? "guard-off" : "no-guard" };
    // The bind can mount but would stop nested sandboxes: with the guard the
    // twins go out by descriptor and the bind stays off (§14.1 item 6).
    if (f.nesting === false) return { by: "guard", mountGap: "bwrap-nesting" };
    return { by: "guard" };
  }
  const gap: HostGap = !f.bwrap ? "no-bwrap" : f.apparmorRestricted ? "apparmor-userns" : "userns-off";
  // Phase 6 (plan 10 §11.7): the guard serves the twins by descriptor, so a
  // host that cannot mount the bind is still confined. The bind stays a
  // second layer where it CAN mount (belt and braces; the maintainer's
  // decision after the 2026-09-24 soak, plan 10 §8 phase 6).
  if (f.guard === true) return { by: "guard", mountGap: gap };
  return f.landlockReadBlock ? { by: "read-deny", why: gap } : { by: "none", why: gap };
}

/** The posture a launch on this host gets: THE decision, made by the launch
 *  (secret-setup.ts, over the facts it probes) and previewed by `mandu
 *  doctor` (gatherConfinement), so the two cannot disagree (a unit test runs
 *  the launch over every host shape against this). Pure. */
export function resolveHostPosture(f: HostFacts): HostPosture {
  return resolvePosture(hostCoverage(f));
}

/** What each attachment kind covers (docs/design/agents/openclaw-plugin.md
 *  §3.4). The OpenClaw plugin: model calls through the proxy (full); real
 *  files (output masked only when it reaches the model); exec by policy
 *  (`before_tool_call`); no egress check of a program's own connections;
 *  replies by the plugin's `message_sending`; Mandu's own state readable by
 *  the Gateway's programs. */
export const ATTACHMENT_COVERAGE: Readonly<Record<AttachmentGap, ProxiedCoverage<AttachmentGap>>> = {
  "openclaw-plugin": {
    modelContext: "proxy",
    files: { by: "none", why: "openclaw-plugin" },
    exec: "policy",
    egress: "none",
    replies: "chat",
    ownState: "readable",
  },
};

/** What an attachment of `kind` covers once its service found part of its
 *  route lost (openclaw-plugin.md §3.6, the route check): `modelContext`,
 *  model calls no longer all cross the proxy (or the service cannot read the
 *  config that says so); `policy`, the plugin's tool-call policy and reply
 *  check are no longer loaded. Every other row stays the kind's. Pure. */
export function attachmentCoverage(kind: AttachmentGap, lost: { modelContext?: boolean; policy?: boolean } = {}): Coverage<AttachmentGap> {
  const c = ATTACHMENT_COVERAGE[kind];
  return {
    ...c,
    ...(lost.modelContext === true ? { modelContext: "none" as const } : {}),
    ...(lost.policy === true ? { exec: "none" as const, replies: "none" as const } : {}),
  };
}

/** Why an attachment of `kind` may not declare `c`, or null. An attachment
 *  claims its kind's coverage or less, never more: its files row, own state
 *  and egress row are the kind's, and the model context, exec and replies
 *  rows are the kind's or `none` (a route found lost, §3.6). The arbiter's
 *  rule for `beginAttachment` and `updateAttachment`. Pure. */
export function attachmentCoverageProblem(kind: AttachmentGap, c: Coverage): string | null {
  const k = ATTACHMENT_COVERAGE[kind];
  if (c.files.by !== "none" || c.files.why !== kind) return `its files row is {by: "none", why: "${kind}"}`;
  if (c.ownState !== k.ownState) return `its own-state row is "${k.ownState}"`;
  if (c.egress !== k.egress) return `its egress row is "${k.egress}"`;
  if (c.modelContext !== k.modelContext && c.modelContext !== "none") return `its model-context row is "${k.modelContext}" or "none"`;
  if (c.exec !== k.exec && c.exec !== "none") return `its exec row is "${k.exec}" or "none"`;
  if (c.replies !== k.replies && c.replies !== "none") return `its replies row is "${k.replies}" or "none"`;
  return null;
}

/** Each attachment kind's session-id prefix: an attachment's session is
 *  `<prefix><name>` (`openclaw:<agentId>`, openclaw-plugin.md §3.3), so it
 *  never names a launch's scope id. */
export const ATTACHMENT_SESSION_PREFIX: Readonly<Record<AttachmentGap, string>> = {
  "openclaw-plugin": "openclaw:",
};

/** The session id an attachment of `kind` registers for `name` (an OpenClaw
 *  agent id): every character outside `[A-Za-z0-9._-]` becomes `-`, cut to
 *  the 128 a session id may hold; an empty name is `default`. Pure. */
export function attachmentSessionId(kind: AttachmentGap, name: string): string {
  const prefix = ATTACHMENT_SESSION_PREFIX[kind];
  const clean = name.replace(/[^A-Za-z0-9._-]/g, "-").slice(0, 128 - prefix.length);
  return prefix + (clean === "" ? "default" : clean);
}

/** A coverage read off the wire (an attachment's registration), or null when
 *  it is not one exactly: every row present with a known value, no other
 *  key, and a covered files row only beside a walled own state. Pure. */
export function parseCoverage(v: unknown): Coverage | null {
  if (!isPlainObject(v)) return null;
  const keys = ["modelContext", "files", "exec", "egress", "replies", "ownState"];
  if (Object.keys(v).length !== keys.length || !keys.every((k) => Object.prototype.hasOwnProperty.call(v, k))) return null;
  const { modelContext, exec, egress, replies, ownState } = v;
  if (modelContext !== "proxy" && modelContext !== "none") return null;
  if (exec !== "sandbox" && exec !== "policy" && exec !== "none") return null;
  if (egress !== "gate" && egress !== "none") return null;
  if (replies !== "terminal" && replies !== "chat" && replies !== "none") return null;
  if (ownState !== "walled" && ownState !== "readable") return null;
  const files = parseFiles(v["files"]);
  if (files === null) return null;
  const rest: CoverageRest = { modelContext, exec, egress, replies };
  if (files.by === "guard" || files.by === "read-deny") return ownState === "walled" ? { ...rest, files, ownState } : null;
  return { ...rest, files, ownState };
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function parseFiles(v: unknown): FileCoverage | null {
  if (!isPlainObject(v)) return null;
  const n = Object.keys(v).length;
  switch (v["by"]) {
    case "guard": {
      const g = v["mountGap"];
      if (n === 1) return { by: "guard" };
      return n === 2 && isHostGap(g) ? { by: "guard", mountGap: g } : null;
    }
    case "read-deny": {
      const why = v["why"];
      if (n === 1) return { by: "read-deny" };
      return n === 2 && isHostGap(why) ? { by: "read-deny", why } : null;
    }
    case "mount": {
      const why = v["why"];
      return n === 2 && (why === "no-guard" || why === "guard-off") ? { by: "mount", why } : null;
    }
    case "none": {
      const why = v["why"];
      return n === 2 && (isHostGap(why) || isAttachmentKind(why)) ? { by: "none", why } : null;
    }
    default:
      return null;
  }
}

/** Where the posture's sentence would claim too much for a gap, the gap's
 *  own. The OpenClaw plugin: `gated`'s sentence promises an egress check the
 *  attachment does not make. */
export const GAP_SENTENCE: Readonly<Partial<Record<PostureGap, string>>> = {
  "openclaw-plugin": "The AI sees your secrets masked, because every model call goes through Mandu. But the programs OpenClaw runs read your real files, connect anywhere unchecked and can read Mandu's own records, and keeping Mandu switched on is a rule, not a wall.",
  "model-route-lost": "The OpenClaw config no longer sends every model call through Mandu, so once the Gateway runs with it the AI can read your secrets as they are, not masked. The programs OpenClaw runs also read your real files and connect anywhere unchecked.",
};

/** The one honest sentence for a posture with its gap. Pure. */
export function postureSentence(p: { posture: ConfinementPosture; gap?: string }): string {
  const own = p.gap !== undefined && Object.prototype.hasOwnProperty.call(GAP_SENTENCE, p.gap)
    ? GAP_SENTENCE[p.gap as PostureGap]
    : undefined;
  return own ?? POSTURE_SENTENCE[p.posture];
}

/** The bind-only gaps (sandbox-security-review-2026-09-28 finding 7): the
 *  mount layer is up, so a short note says what it covers and what it misses
 *  (the dashboard's tooltip, after the sentence). */
export const PARTIAL_NOTE: Readonly<Partial<Record<PostureGap, string>>> = {
  "no-guard": "The mount layer still puts a masked copy over each credential file, but Mandu's file guard is not available, so a file replaced while the AI runs is readable.",
  "guard-off": "The mount layer still puts a masked copy over each credential file, but Mandu's file guard is turned off, so a file replaced while the AI runs is readable.",
};

/** The doctor lines under a `confined`-by-the-guard posture: what the bind
 *  layer would add and how to get it. Empty for a bind-backed posture. */
export function guardOnlyLines(p: HostPosture): string[] {
  if (p.posture !== "confined" || p.bindGap === undefined) return [];
  const { cause, fix } = gapExplanation(p.bindGap);
  const lines = [
    "protected by Mandu's file guard alone (it hands every program the placeholder copies); the extra mount layer is not in use",
    // bwrap-nesting: the mount COULD go up, and is left off on purpose.
    `mount layer ${p.bindGap === "bwrap-nesting" ? "off" : "unavailable"}: ${cause}`,
  ];
  if (fix !== null) {
    lines.push(`optional second layer: ${fix}${fix === SETUP_COMMAND ? "   (adds the mount layer; asks for sudo once)" : ""}`);
  }
  return lines;
}

/** The doctor lines under a bind-only `gated` posture (no guard): what the
 *  mount layer still covers and what it does not. Empty otherwise. */
export function bindOnlyLines(p: Posture): string[] {
  if (p.posture !== "gated" || !isBindOnlyGap(p.gap)) return [];
  return [
    "partial layer in use: the mount layer puts a placeholder copy over each credential file found at launch",
    "not covered without the file guard: a credential file replaced while the AI runs (a token refresh, an editor save) is readable, and no program can be allowed to read the real file",
  ];
}

/** Cause line + fix command for a gap, in plain words. */
export function gapExplanation(gap: PostureGap): { cause: string; fix: string | null } {
  switch (gap) {
    case "apparmor-userns":
      return { cause: "Ubuntu restricts unprivileged user namespaces (AppArmor).", fix: SETUP_COMMAND };
    case "userns-off":
      return { cause: "This host does not allow unprivileged user namespaces.", fix: null };
    case "no-bwrap":
      // Mandu runs the distribution's bubblewrap and ships none
      // (rootless-confinement-ubuntu-2404.md §0.7, decision A).
      return {
        cause: "bubblewrap (`bwrap`) is not installed (Mandu uses your distribution's, never one inside the working directory). " +
          "Fedora: sudo dnf install bubblewrap. Ubuntu 24.04 and later: after installing it, mandu setup adds the AppArmor grant.",
        fix: "sudo apt install bubblewrap",
      };
    case "bwrap-nesting":
      return {
        cause: "this host's bubblewrap AppArmor profile lets no sandbox start inside another, and the mount layer would stop the sandboxes the agent's tools start (Codex's shell, Mandu's command box).",
        // Mandu's own bubblewrap lets a sandbox nest (bwrap-grant.ts).
        fix: SETUP_COMMAND,
      };
    case "no-sandbox-exec":
      return { cause: "`/usr/bin/sandbox-exec` is unavailable on this Mac.", fix: null };
    case "unsupported-os":
      return { cause: "Secret confinement is not implemented for Windows.", fix: null };
    case "no-guard":
      return {
        cause: "Mandu's file guard (mandu-net-guard) is not available here (no binary for this machine, which a source checkout builds with scripts/build-native.sh, or a binary that cannot start here, as under a container's default seccomp profile), so a credential file replaced while the AI runs (a token refresh, an editor save) is readable.",
        fix: null,
      };
    case "guard-off":
      return {
        cause: "Mandu's file guard is turned off (--no-net-guard, MANDU_NET_GUARD=0, net-guard = false in config.toml, or --no-kernel), so a credential file replaced while the AI runs (a token refresh, an editor save) is readable. Drop the opt-out to confine.",
        fix: null,
      };
    case "model-route-lost":
      // Two commands, in order (openclaw-plugin.md §3.6): no one-command fix.
      return {
        cause: "Your OpenClaw config was changed so that model calls no longer all go through Mandu (the Mandu plugin or its Anthropic route was removed or changed, a model has its own endpoint, or the config cannot be read). A Gateway already running keeps the config it loaded until it restarts. Run `mandu openclaw install` again, then `openclaw gateway restart`.",
        fix: null,
      };
    case "openclaw-plugin":
      // No one-command fix: the confined form is another way to run the
      // Gateway, said in the cause (openclaw-plugin.md §3.6).
      return {
        cause: "Mandu is attached to your OpenClaw Gateway as a plugin, not running it: model calls go through Mandu, but the files the Gateway's programs open, their own network connections and Mandu's own records are not protected, and Mandu only refuses the plain attempts to switch it off. Run the Gateway under `mandu openclaw gateway` to confine it.",
        fix: null,
      };
  }
}

/**
 * The multi-line stderr notice for a launch that is not `confined`/`read-blocked`
 * by host condition. First line carries the posture name; stable text (the
 * banner's attention rule and the posture oracles match on "secrets are GATED").
 */
export function gatedNotice(gap: PostureGap, o: { egressGateOff?: boolean } = {}): string[] {
  const { cause, fix } = gapExplanation(gap);
  const routeLost = isRouteGap(gap);
  const attached = isAttachmentKind(gap) || routeLost;
  const lines = [
    // An attachment is not a host condition: the same line says where.
    attached ? "mandu: secrets are GATED, not confined, in this OpenClaw Gateway." : "mandu: secrets are GATED, not confined, on this host.",
    `  ${cause}`,
    isBindOnlyGap(gap)
      ? "  A mount layer still puts a placeholder over each credential file found at launch; a file replaced while the agent runs is not covered."
      : routeLost
        ? "  Model calls that go around Mandu carry your secrets as they are, and programs the agent runs can read your credential files."
        : attached
          ? "  Programs the agent runs can still read your credential files, and nothing checks where they send them."
          : "  Programs the agent runs can still read your credential files.",
  ];
  // Under `gated` the egress gate is what keeps a raw secret from leaving
  // (POSTURE_SENTENCE.gated); turned off, that half of the sentence is
  // false, so the notice says so. Under confined / read-blocked the launch
  // stays quiet about the opt-out (release checklist a1: the deliberate,
  // silent way to run without the gate; no raw secret is in reach there).
  if (o.egressGateOff === true) lines.push(EGRESS_GATE_OFF_LINE);
  if (fix !== null) lines.push(`  One-time upgrade:  ${fix}${fix === SETUP_COMMAND ? "   (asks for sudo once)" : ""}`);
  lines.push("  Details:           mandu doctor");
  return lines;
}

/** The gated notice's line when the user also turned the egress gate off. */
export const EGRESS_GATE_OFF_LINE =
  "  The egress gate is also off (--no-net-proxy, MANDU_NET_PROXY=0 or net-proxy = false in config.toml): " +
  "what those programs send is not checked, so a credential file they read can be sent anywhere.";

/** What went wrong: the host cannot confine (a known condition), or the
 *  arbiter failed mid-setup (an incident). */
export type ConfinementFailure = "host" | "arbiter";

export interface StrictnessOpts {
  /** --require-confinement / MANDU_REQUIRE_CONFINEMENT / config. */
  requireConfinement: boolean;
  /** --best-effort. */
  bestEffort: boolean;
}

/**
 * Refuse the launch, or degrade to `gated`? (§3.1)
 *   - require-confinement always refuses (it wins over --best-effort: a managed
 *     deployment's config must not be undone by a flag meant for dev boxes).
 *   - a HOST gap degrades by default: root stays optional.
 *   - an ARBITER failure is an incident, not a host condition: it refuses
 *     unless --best-effort, exactly as before.
 */
export function onConfinementFailure(kind: ConfinementFailure, o: StrictnessOpts): "refuse" | "degrade" {
  if (o.requireConfinement) return "refuse";
  if (kind === "host") return "degrade";
  return o.bestEffort ? "degrade" : "refuse";
}
