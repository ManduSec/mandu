/**
 * doctor — `mandu doctor` (packaging.md §7): a load-bearing honesty surface.
 * It reports the prerequisites, the layout, arbiter reachability, and — the
 * point — WHICH tier each chokepoint is enforced at, so a user can never believe
 * they have kernel enforcement while running the wrapper-tier npm package
 * (privilege-model.md §2 context → wrapper → kernel).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code.
 */
import { inNetworks, loadTlsMaterial, probeTls, type EndpointTlsConfig, type TlsMaterial } from "./endpoint-tls.js";
import { accessSync, constants, existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { delimiter, isAbsolute, join } from "node:path";
import { connect, isIP } from "node:net";
import { execFileSync, spawnSync } from "node:child_process";
import {
  APPLE_GIT_SHIM, hardenedGitArgs, hardenedGitEnv, isSeatbeltGitSandbox, probeGitSandboxOutcome, resolveGitBinary, SANDBOX_EXEC, type GitSandboxProbe,
} from "./hardened-git.js";
import { resolveArbiterSock } from "./arbiter-sock.js";
import { Layout, type LayoutMode } from "./services/layout.js";
import type { AgentLine } from "./generated/agents.js";
import {
  bindOnlyLines,
  gapExplanation,
  guardOnlyLines,
  POSTURE_SENTENCE,
  resolveHostPosture,
  type HostPosture,
} from "./confinement-posture.js";
import { probeBwrapSymlink, symlinkProbeRow, type SymlinkProbeResult } from "./bwrap-symlink-probe.js";
import { loadConfigEnv } from "./config.js";
import { parse as parseLaunch } from "./parse.js";
import { resolveNativeBin, type NativeBinName } from "./services/native-bins.js";
import { APPARMOR_USERNS_SYSCTL, probeUserns, usernsGapHint } from "./userns.js";
import { homedir } from "node:os";
import { checkClaudeSandbox, claudeManagedSettings, claudeSettingsLocations } from "./claude-sandbox.js";
import { nestedSandboxProbeArgv } from "./secret-twins.js";
import { sandboxExecAvailable } from "./seatbelt-profile.js";
import {
  ADMIN_BWRAP_FIX,
  adminBwrapRefusedReason,
  commandAvailable,
  copySourceBwrap,
  DISTRO_BWRAP_PROFILE_FILE,
  legacyGrantWarning,
  MANDU_BWRAP,
  manduBwrapInForceHere,
  manduBwrapStale,
  realBwrapGrantDeps,
  resolveWrapBwrap,
  staleLegacyProfiles,
  SYSTEM_BWRAP,
  type LegacyProfile,
} from "./bwrap-grant.js";
import { adminBwrap, type AdminBwrap } from "./bwrap-path.js";
import { NODE_FLOOR, bypassWords, nodeEnvProxyFix, nodeEnvProxyGap, nodeMeetsFloor, type NodeEnvProxyGap } from "./node-floor.js";
import { GOOSE_KEYCHAIN_VIA, probeAgentLogin, realGooseKeyringItem, realLoginProbeDeps, type GooseSubagentLogin, type LoginProbeDeps, type LoginStatus } from "./agent-login.js";
import { gatherWslFacts, wslVersion, type WslFacts } from "./wsl.js";
import {
  checkAgentVersion, OPENCODE2_ENV, OPENCODE_V1_MAJOR, OPENCODE_V2_MAJOR, opencode2Enabled, opencodeInstall, opencodeTested, parseAgentVersion,
  probeAgentVersionLooking, rangeWords, supportStatusOf, type AgentVersionCheck,
} from "./agent-versions.js";
import {
  assessCodexSandbox, codexLayerReaders, codexSandboxRow, gatherCodexSandbox, realCodexSandboxDeps,
  realCodexSandboxProbe, realReadPlistJson, type CodexSandboxAssessment,
} from "./codex-sandbox.js";
import { cloudLocalModelEntries, hasModelsSection, localModelLevelLines, policyFilePath, type CloudLocalEntry } from "./policy-level-spelling.js";
import { addressReach, endpointApiBase, endpointPlacement, helperEndpointName, hostClass, isCloudBackedModel, isPlainHttpLocal, parseOrigin, systemLookup, type AddressReach, readModelEndpoints, selectTllmEndpoint, tllmUpstream, type HostClass, type ModelEndpointsRead, type ModelWire } from "./model-endpoints.js";
import { ndjsonCall } from "./secret-setup.js";
import { homeRows, realHomeFacts, type HomeFacts } from "./doctor-home.js";
import { doctorUpdateFacts, launcherVersion, updateChannel, updateRows, type UpdateFacts } from "./update-check.js";
import { commitWords, gatherVersionReport, realVersionDeps, type Problem, type VersionReport } from "./version-report.js";
import { expandTrust, isTrusted, mountDestination, readTrustLookups, visibleRemoteMounts, type RemoteMountFacts, type TrustLookup } from "./remote-mounts.js";

type Env = Record<string, string | undefined>;

/** The four architecture chokepoints and the tier the npm package enforces each
 *  at. `kernelCrate` is the native supervisor that raises it to the kernel
 *  tier. Since 2026-09-24 the npm package SHIPS the prebuilt bins for
 *  linux-x64 (`nativeBin` names the one that proves the crate is present);
 *  they attach without root (privilege-model.md §0). */
const CHOKEPOINTS = [
  { name: "model-API", tier: "context", component: "anthropic-proxy / openai-proxy", kernelCrate: null, nativeBin: null },
  { name: "network", tier: "wrapper", component: "net-proxy", kernelCrate: "net-supervisor", nativeBin: "mandu-net-guard" },
  { name: "filesystem", tier: "wrapper", component: "fs-sync", kernelCrate: "fs-supervisor", nativeBin: null },
  { name: "exec", tier: "wrapper", component: "exec-wrap", kernelCrate: "exec-supervisor", nativeBin: "mandu-exec-box" },
] as const;

export interface DoctorFacts {
  node: { version: string; ok: boolean };
  /** The `node` a program in a session runs (the first on the user's PATH,
   *  which a launch keeps: env-compose.ts only prepends Mandu's own shims),
   *  and whether it honours the launcher's NODE_USE_ENV_PROXY
   *  (node-floor.ts nodeEnvProxyGap; plan 13 §10.2). Absent: no node on
   *  PATH, or a fixture without the probe. */
  pathNode?: { path: string; gap: NodeEnvProxyGap };
  git: string | null;
  agents: { claude: boolean; codex: boolean };
  /** Is each agent logged in (agent-login.ts; existence checks only, never a
   *  credential's contents)? Optional so older fixtures still type. */
  logins?: { claude: LoginStatus; codex: LoginStatus; goose?: LoginStatus };
  /** Each installed agent's version against Mandu's tested range
   *  (agent-versions.ts); null for an agent that is not installed. Optional
   *  so older fixtures still type. */
  versions?: {
    claude: AgentVersionCheck | null;
    codex: AgentVersionCheck | null;
    opencode?: OpencodeVersionFacts | null;
    goose?: AgentVersionCheck | null;
  };
  /** Can Codex's own command sandbox run here (codex-sandbox.ts)? Optional
   *  so older fixtures still type. */
  codexSandbox?: CodexSandboxAssessment;
  /** Mandu's own bubblewrap (bwrap-grant.ts): in force, older than the system
   *  bwrap, and any pre-2026-09-27 Mandu grant still installed. Optional so
   *  older fixtures still type. */
  bwrapGrant?: BwrapGrantFacts;
  /** Does the bwrap a launch would run follow a symlink in a mount
   *  destination (CVE-2026-87766)? Warn only. Optional for older fixtures. */
  bwrapSymlink?: SymlinkProbeResult;
  /** Does Mandu's own git on the AI's repositories run in its sandbox here
   *  (hardened-git.ts probeGitSandboxOutcome, git-hardening.md)? Optional for older
   *  fixtures. */
  gitSandbox?: GitSandboxFacts;
  /** `bundled`: a checkout running its own prebuilt launcher/dist
   *  (packaging.md §5.1). Optional for older fixtures. */
  layout: { mode: LayoutMode; root: string; bundled?: boolean };
  /** Plan 14 §14.5: the names-only model's row (what `--model names` would
   *  use). Optional so older fixtures still type. */
  policyModel?: PolicyModelFacts;
  arbiter: { sock: string; reachable: boolean };
  /** `mandu version`'s report (version-report.ts): this mandu's commit, the
   *  other installs on PATH, the running services' release and build, and
   *  the problems among them. Optional for older fixtures. */
  install?: VersionReport;
  /** kernel-tier supervisor binaries present on this host (dev builds only; the
   *  npm package ships none). Keyed by crate name. */
  kernel: Record<string, boolean>;
  /** The secret-confinement posture a launch on this host would get
   *  (rootless-confinement-ubuntu-2404.md §3.3), and the kernel-knob detail
   *  behind a gap (src/userns.ts `usernsGapHint`). */
  confinement: HostPosture & { detail?: string };
  /** Plan 10 §12.3: what Claude Code's own settings say about ITS sandbox and
   *  credential mask, so a user sees the double-mask hazard before a launch.
   *  null = no settings file carries a `sandbox` section. */
  claudeSandbox: { enabled: boolean; enabledBy: string[]; maskedFiles: number; maskedEnvVars: number; sources: string[]; rules?: number; unreadable?: string[]; managedOn?: string[] } | null;
  /** Windows Subsystem for Linux, from the kernel release string: 2 (a real
   *  Linux kernel), 1 (a syscall translation layer, no Landlock or seccomp
   *  user notification), or null (not WSL). Optional for older fixtures. */
  wsl?: 1 | 2 | null;
  /** The WSL detail rows (wsl.ts): kernel gates, Windows interop, systemd,
   *  a working folder on a Windows drive. null off WSL; optional for older
   *  fixtures. */
  wslDetail?: WslFacts | null;
  /** policy.yaml `models:` (confidentiality-plan-11 D6): the declared
   *  endpoints with their probe results, and the `local-model` labels that no
   *  model can read without one. Optional so older fixtures still type. */
  models?: ModelsFacts;
  /** Mandu's folder: loose modes (doctor-home.ts). Optional so older
   *  fixtures still type. */
  home?: HomeFacts;
  /** Plan 13 §4.9: the network and FUSE mounts visible here, which make the
   *  guard serve readers the placeholder unless policy.yaml trusts them
   *  (remote-mounts.ts). Linux only; optional so older fixtures still type. */
  remoteMounts?: RemoteMountFacts;
  /** The host platform. macOS gets its own wording: the kernel guards are
   *  Linux only, the Seatbelt read-block is what stands in for them, and an
   *  agent sandbox cannot start inside Mandu's profile. Optional: absent
   *  renders as Linux (older fixtures). */
  platform?: "linux" | "darwin" | "win32";
  /** Yama's `ptrace_scope` (`/proc/sys/kernel/yama/ptrace_scope`): the
   *  value, or null when the file is absent (no Yama in this kernel) or
   *  unreadable. Every same-account boundary (the dashboard sign-in, the
   *  human plane, the reply filter) assumes it is 1 or more
   *  (rootless-confinement-ubuntu-2404.md §3.3). Linux only; optional for
   *  older fixtures (absent renders no row). */
  ptraceScope?: { value: number | null };
  /** Is a newer Mandu release out (update-check.ts, packaging.md §11.5)?
   *  Optional: absent renders no row (older fixtures). */
  update?: UpdateFacts;
}

/** The sandbox Mandu's sandboxed git runners (the launcher's launch-prep
 *  runner, the arbiter's history scan, lock resolver and prepared copies;
 *  hardened-git.ts, git-hardening.md §5) would get here, by a fresh probe:
 *  on (the bubblewrap it runs, Linux), Seatbelt (macOS), turned off by
 *  MANDU_GIT_SANDBOX=0, unavailable (no bubblewrap can start one, Linux), or
 *  none for another reason the probe established (`gap`: an unprivileged
 *  hardening left unused, a ✗; else a ·, e.g. a probe that could not finish
 *  or a command inside another Seatbelt profile). A running arbiter keeps
 *  the answer its own probe got. */
export type GitSandboxFacts =
  | { state: "on"; bwrap: string }
  | { state: "seatbelt"; sandboxExec: string; git: string }
  | { state: "off" }
  | { state: "unavailable" }
  | { state: "none"; why: string; gap: boolean; fix?: string };

/** One declared model endpoint, probed (D6). */
export interface ModelRowFacts {
  name: string;
  url: string;
  wire: ModelWire;
  model?: string;
  local: boolean;
  /** The entry the quarantined helper uses (helperEndpointName). */
  helper?: boolean;
  hostClass: HostClass;
  host: string;
  /** A short TCP connect succeeded; null = not checked. */
  reachable: boolean | null;
  /** `wire: openai-chat` with a `model`: is it listed at GET {url}/v1/models?
   *  null = not checked (another wire, no model named, unreachable, or the
   *  listing could not be read). */
  modelListed: boolean | null;
  /** A `local: true` endpoint's listing names cloud-backed models (plan 11
   *  §8 item 3): the server relays requests for them to its vendor. Absent
   *  when none are listed or the listing was not read. */
  cloudListed?: string[];
  /** Plan 12 D2: a `local: true` entry on another machine over plain http.
   *  `allowed` = the entry says `allow_plain_http: true`; `refused` = it does
   *  not (only an older arbiter serves such an entry; the helper and the
   *  launch refuse it). Absent otherwise. */
  plainHttp?: "allowed" | "refused";
  /** Plan 12 D1: `host` (this computer) | `network` (another machine). */
  placement: "host" | "network";
  /** Plan 12 D6, a `network` endpoint only: the addresses its host resolved
   *  to (a literal address is itself) and where they are. Absent when not
   *  checked (no resolver injected). */
  addresses?: string[];
  reach?: AddressReach;
  /** Plan 12 D3/D6: one TLS handshake with the entry's checks, for a
   *  reachable https entry that is local on another machine or names `tls:`.
   *  `checks` names what was configured ("your CA", "a pinned key", "a
   *  client certificate"); absent when not checked. */
  tls?: { checks: string[]; ok: boolean; reason?: string };
  /** Plan 12 D4: the entry's `perimeter.networks` against the addresses
   *  above. `outside` is the first address outside (null: the name did not
   *  resolve, which a launch refuses too). Absent when the entry has no
   *  perimeter or its addresses were not looked up. */
  perimeter?: { networks: string[]; ok: boolean; outside?: string | null };
  /** Plan 12 D4: the host is under `perimeter.domains` (words only). */
  orgDomain?: true;
  /** Plan 12 D5: set by the administrator (its file), and locked. */
  adminFile?: string;
  locked?: true;
}

export interface ModelsFacts {
  /** `arbiter` = the endpoints are the law in force (the `modelEndpoints` op);
   *  `file` = the arbiter did not answer, so only the policy file's lines were
   *  scanned and no endpoint was probed. */
  source: "arbiter" | "file";
  endpoints: ModelRowFacts[];
  /** The policy file has a `models:` section (line scan; meaningful when
   *  source is `file`). */
  declaredInFile: boolean;
  /** Lines of the policy file labeling a path `level: local-model`. */
  localModelLines: number[];
  policyPath: string | null;
  /** A user-set ANTHROPIC_BASE_URL checked against the declared entries
   *  (plan 11 §5, phase 3): `match` = the `wire: anthropic` entry a launch
   *  would keep the model proxy in front of, null when none (the launch skips
   *  the proxy); `refused` = the match is plain http to another machine, which
   *  a launch refuses. Meaningful only when `source` is `arbiter`. Absent when
   *  the variable is unset; optional so older fixtures still type. */
  anthropicBaseUrl?: { url: string; match: { name: string; local: boolean } | null; refused?: boolean };
  /** The same facts for Codex's MANDU_OPENAI_BASE_URL, matched against
   *  `wire: openai-chat` entries (plan 11 §7.2). */
  openaiBaseUrl?: { url: string; match: { name: string; local: boolean } | null; refused?: boolean };
  /** Entries in the policy FILE declaring a cloud-backed model `local: true`
   *  (plan 11 §8 item 3; line scan). The arbiter refuses such a file, so a
   *  running one never reports them: doctor reads the file itself because it
   *  may be one the arbiter has not loaded, or refused and kept the old law
   *  over. Absent when there are none. */
  cloudLocalInFile?: CloudLocalEntry[];
  /** Paths labeled `local-model` outside the policy file (the dashboard's
   *  Rules page, an import), from the arbiter's `pathLabels` op: the line
   *  scan above cannot see them. Absent when the arbiter did not answer. */
  localModelLabels?: string[];
  /** Plan 12 D5: the administrator's layer in force (its files, the lock). */
  admin?: { files: string[]; locked: boolean; conflicts?: string[]; refused?: string[] };
}

/** WSL generation (wsl.ts; kept exported here for existing callers). */
export { wslVersion };

/** The commands whose version the doctor reads: every agent line of the
 *  agent registry (generated/agents.ts) but OpenClaw, which has no doctor
 *  version row (its version is checked at launch only, agent-versions.ts
 *  versionedAgentOf). */
export type DoctorVersionBin = Exclude<AgentLine, "openclaw">;

/** Injectable probes so runDoctor is unit-testable without a real host. */
export interface DoctorDeps {
  nodeVersion: () => string;
  /** `mandu version`'s report (version-report.ts). Optional: a fixture
   *  without it shows no install report, never the host's. */
  versionReport?: (env: Env, layout: Layout) => Promise<VersionReport>;
  /** The first `node` on `env`'s PATH and its `--version` text (null: it
   *  did not answer), or null when PATH has none. Optional: a fixture
   *  without it reports nothing, never the host's node. */
  pathNode?: (env: Env) => { path: string; versionText: string | null } | null;
  gitVersion: () => string | null;
  commandExists: (cmd: string) => boolean;
  socketReachable: (sock: string) => Promise<boolean>;
  fileExists: (p: string) => boolean;
  platform: () => "linux" | "darwin" | "win32";
  /** The userns probe (src/userns.ts `probeUserns`). */
  usernsOk: () => boolean;
  /** Read a kernel knob file; null when absent. */
  readKnob: (path: string) => string | null;
  /** policy.yaml `remote_mounts.trust_lookups` from the running arbiter
   *  (remote-mounts.ts `readTrustLookups`); null when it cannot be asked.
   *  Optional: absent reads none (null). */
  trustLookups?: (sock: string) => Promise<TrustLookup[] | null>;
  /** Resolve a native supervisor bin (services/native-bins.ts `resolveNativeBin`:
   *  env override, the bundled prebuilt, the checkout's target/, PATH). The
   *  guard's presence is what makes a no-userns host `confined` (plan 10
   *  §11.7). Optional so older callers and test fixtures still type; the
   *  default is the real resolver. */
  nativeBin?: (name: NativeBinName) => string | null;
  /** `<bin> --version` output, or null (agent-versions.ts
   *  probeAgentVersionLooking: codex gets a throwaway CODEX_HOME, OpenCode
   *  and Goose throwaway XDG folders).
   *  Optional so older fixtures still type; absent reads as "could not read". */
  agentVersion?: (bin: DoctorVersionBin) => string | null;
  /** Codex's own bwrap probe (codex-sandbox.ts). Optional: a fixture without
   *  it answers with its `usernsOk`, never the host's bwrap. */
  codexBwrapProbe?: () => boolean;
  /** Resolve a model endpoint's host name (plan 12 D6). Optional: without it
   *  a name is not resolved and doctor gives no address hint. */
  lookupHost?: (name: string) => Promise<string[]>;
  /** One TLS handshake with an entry's checks (endpoint-tls.ts probeTls).
   *  Optional: without it no TLS row is given. */
  probeTls?: (host: string, port: number, m: TlsMaterial) => Promise<{ ok: true } | { ok: false; reason: string }>;
  /** Can a sandbox start inside the secret bind wrap (secret-twins.ts
   *  `nestedSandboxProbeArgv`)? Optional: a fixture without it answers true,
   *  never the host's bwrap. */
  nestingOk?: () => boolean;
  /** Mandu's own bubblewrap facts. Optional: a fixture without it reports
   *  none, never the host's. */
  bwrapGrant?: () => BwrapGrantFacts;
  /** The CVE-2026-87766 probe of the bwrap a launch would run
   *  (bwrap-symlink-probe.ts). Optional: a fixture without it reports
   *  nothing, never the host's bwrap. */
  bwrapSymlink?: () => SymlinkProbeResult;
  /** The declared model endpoints from the running arbiter (model-endpoints.ts
   *  `readModelEndpoints`). Optional: a fixture without it reads as "the
   *  arbiter did not answer", never the host's arbiter. */
  modelEndpoints?: (sock: string) => Promise<ModelEndpointsRead>;
  /** The paths the running arbiter labels `local-model` that are NOT policy
   *  file lines (null = could not read). Optional: absent = not checked. */
  localModelLabels?: (sock: string) => Promise<string[] | null>;
  /** A short TCP connect to a declared endpoint. Optional: absent = not
   *  checked, so a fixture never touches the network. */
  probeTcp?: (host: string, port: number) => Promise<boolean>;
  /** The model ids GET {url}/v1/models lists (null = could not read).
   *  Optional: absent = not checked. */
  listModels?: (url: string, token: string | undefined) => Promise<string[] | null>;
  /** Mandu's folder (doctor-home.ts). Optional: a fixture without it
   *  reports nothing, never the host's folder. */
  homeFacts?: (env: Env) => HomeFacts;
  /** Mandu's own git sandbox (gitSandboxFacts over the real probe, run with
   *  doctor's env). Optional: a fixture without it reports nothing, never
   *  the host's. */
  gitSandbox?: (env: Env) => GitSandboxFacts;
  /** macOS: the administrator source that keeps Codex's own sandbox on
   *  (codex-sandbox.ts codexAdminSandboxLock: /etc/codex, forced MDM
   *  preferences, the cloud cache). Optional: a fixture without it reports
   *  none, never the host's. */
  codexAdminLock?: (env: Env) => string | null;
  /** The entries of a folder (Claude Code's managed-settings.d), or null.
   *  Optional: a fixture without it lists none, never the host's. */
  listDir?: (dir: string) => string[] | null;
  /** A property list read as JSON (Claude Code's MDM preferences), or null.
   *  Optional: absent reads none. */
  readPlistJson?: (p: string) => string | null;
  /** Goose's login facts beyond the env and a file's existence: its
   *  config.yaml text, and whether the system keyring holds its item
   *  (agent-login.ts realGooseKeyringItem: existence only, never a value).
   *  Optional: a fixture without it reads no config and asks no keyring. */
  gooseLogin?: (env: Env) => Pick<LoginProbeDeps, "readGooseConfig" | "keyringItem">;
  /** A fresh release check (update-check.ts doctorUpdateFacts). Optional: a
   *  fixture without it asks nothing, never GitHub. `installed`: the
   *  launcher runs from an installed package. */
  updateFacts?: (env: Env, installed: boolean) => Promise<UpdateFacts>;
}

/** The cases where a macOS launch keeps Claude Code's sandbox on instead
 *  (planDarwinClaudeSandbox), so the doctor never promises otherwise. */
function claudeKeepCaveats(L: string[], cs: NonNullable<DoctorFacts["claudeSandbox"]>): void {
  if ((cs.rules ?? 0) > 0) {
    L.push("    a launch keeps it on and warns instead when its rules (sandbox.credentials, sandbox.filesystem.denyRead,");
    L.push("    permissions.deny Read, blockReadsOutsideWorkingDirectories) protect what Mandu does not");
  }
  if ((cs.unreadable ?? []).length > 0) {
    L.push(`    a launch keeps it on and warns instead: Mandu cannot read ${cs.unreadable!.join(", ")}`);
  }
}

/** Why the macOS probe found none, from facts the doctor gathers only then:
 *  is SANDBOX_EXEC there, is this process inside another Seatbelt profile
 *  (sandbox-exec cannot apply even an allow-everything profile: exit 71),
 *  and which git resolveGitBinary picks ("transient": its run could not be
 *  judged). */
export interface DarwinGitSandboxMiss {
  sandboxExec: boolean;
  nested: boolean;
  git: string | null | "transient";
}

/** The git sandbox row's facts from a fresh probe's answer (the probe
 *  Mandu's git runners use, hardened-git.ts probeGitSandboxOutcome) and,
 *  when it found none, the facts that say why. Pure. */
export function gitSandboxFacts(input: {
  env: Env;
  platform: string;
  probe: GitSandboxProbe;
  /** macOS, when the probe found none (DarwinGitSandboxMiss). */
  darwin?: DarwinGitSandboxMiss;
}): GitSandboxFacts {
  if (input.env["MANDU_GIT_SANDBOX"] === "0") return { state: "off" };
  const s = input.probe.sandbox;
  if (s !== null) return isSeatbeltGitSandbox(s) ? { state: "seatbelt", sandboxExec: s.sandboxExec, git: s.git } : { state: "on", bwrap: s.bwrap };
  const unfinished = { state: "none", why: "the probe could not finish (a timeout, or no free process); Mandu's git probes again later", gap: false } as const;
  if (input.probe.transient) return unfinished;
  if (input.platform === "linux") return { state: "unavailable" };
  if (input.platform === "darwin") {
    const d = input.darwin;
    if (d === undefined || !d.sandboxExec) return { state: "none", why: `no ${SANDBOX_EXEC} here`, gap: true };
    if (d.nested) {
      // The outer profile (the agent's own, when the agent runs `mandu`)
      // confines this command's git: no gap.
      return { state: "none", why: "this command runs inside another sandbox profile, which macOS cannot nest a second one in", gap: false };
    }
    if (d.git === "transient") return unfinished;
    if (d.git === null) return { state: "none", why: "no git found on PATH", gap: true };
    if (d.git === APPLE_GIT_SHIM) {
      // Still the shim only when its --exec-path named no git: what a Mac
      // without the Command Line Tools answers.
      return { state: "none", why: `${APPLE_GIT_SHIM} named no real git to run`, gap: true, fix: "xcode-select --install (the Command Line Tools)" };
    }
    return { state: "none", why: `${SANDBOX_EXEC} could not run ${d.git} under the git profile`, gap: true };
  }
  return { state: "none", why: "the sandbox is built for Linux and macOS", gap: false };
}

/** Is this process inside a Seatbelt profile? sandbox-exec then cannot apply
 *  even an allow-everything one (exit 71, "sandbox_apply: Operation not
 *  permitted"). */
function insideSeatbeltProfile(): boolean {
  const r = spawnSync(SANDBOX_EXEC, ["-p", "(version 1)(allow default)", "/usr/bin/true"], { stdio: "ignore", timeout: 10_000 });
  return r.status === 71;
}

/** The real facts: a fresh probe (never the process's cached answer: the
 *  row says what a Mandu service started now would get; a running arbiter
 *  keeps what its own probe found), and on a macOS miss the facts that say
 *  why. */
export function realGitSandboxFacts(env: Env): GitSandboxFacts {
  const probe = probeGitSandboxOutcome({ env });
  const platform = process.platform;
  if (probe.sandbox !== null || probe.transient || platform !== "darwin" || env["MANDU_GIT_SANDBOX"] === "0") {
    return gitSandboxFacts({ env, platform, probe });
  }
  const sandboxExec = sandboxExecAvailable();
  const nested = sandboxExec && insideSeatbeltProfile();
  const git = sandboxExec && !nested ? resolveGitBinary(env["PATH"] !== undefined ? { path: env["PATH"] } : {}) : null;
  return gitSandboxFacts({ env, platform, probe, darwin: { sandboxExec, nested, git } });
}

export interface BwrapGrantFacts {
  inForce: boolean;
  stale: boolean;
  legacy: LegacyProfile[];
  /** Ubuntu's own bwrap-userns-restrict is in /etc/apparmor.d. */
  distroBwrap: boolean;
  /** An administrator's `bwrap_path` (bwrap-path.ts). Absent: none. */
  admin?: AdminBwrap;
}

/** A short TCP connect (1 s) to a declared model endpoint: reachability,
 *  nothing sent. */
function realProbeTcp(host: string, port: number): Promise<boolean> {
  return new Promise((res) => {
    const c = connect({ host, port });
    const done = (ok: boolean): void => { clearTimeout(t); c.destroy(); res(ok); };
    const t = setTimeout(() => done(false), 1000);
    c.once("connect", () => done(true));
    c.once("error", () => done(false));
  });
}

/** GET {url}/v1/models (1.5 s): the OpenAI-compatible listing Ollama and vLLM
 *  serve. The endpoint's own bearer token (policy.yaml `token_env`) rides
 *  along when set, since the operator declared it for this endpoint. */
async function realListModels(url: string, token: string | undefined): Promise<string[] | null> {
  try {
    const r = await fetch(`${endpointApiBase(url)}/v1/models`, {
      signal: AbortSignal.timeout(1500),
      ...(token ? { headers: { authorization: `Bearer ${token}` } } : {}),
    });
    if (!r.ok) return null;
    const body = (await r.json()) as { data?: Array<{ id?: unknown }> };
    return Array.isArray(body.data) ? body.data.map((d) => d.id).filter((id): id is string => typeof id === "string") : null;
  } catch {
    return null;
  }
}

/** The first executable `node` on `env`'s PATH and what `node --version`
 *  says, run with the user's environment (a version manager's shim needs
 *  its own variables), as a program in a session would start it. */
export function realPathNode(env: Env): { path: string; versionText: string | null } | null {
  for (const dir of (env["PATH"] ?? "").split(delimiter)) {
    if (dir === "" || !isAbsolute(dir)) continue;
    const p = join(dir, "node");
    try {
      if (!statSync(p).isFile()) continue;
      accessSync(p, constants.X_OK);
    } catch { continue; }
    const childEnv: Record<string, string> = {};
    for (const [k, v] of Object.entries(env)) if (v !== undefined) childEnv[k] = v;
    try {
      const out = execFileSync(p, ["--version"], { env: childEnv, timeout: 3000, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
      return { path: p, versionText: out };
    } catch {
      return { path: p, versionText: null };
    }
  }
  return null;
}

export const realDoctorDeps: DoctorDeps = {
  nodeVersion: () => process.versions.node,
  versionReport: (env, layout) => gatherVersionReport(realVersionDeps(env, layout)),
  pathNode: realPathNode,
  gitVersion: () => {
    const r = spawnSync("git", hardenedGitArgs(["--version"]), { encoding: "utf8", env: hardenedGitEnv() });
    return r.status === 0 ? (r.stdout.trim().split(/\s+/)[2] ?? r.stdout.trim()) : null;
  },
  commandExists: commandAvailable,
  socketReachable: (sock) =>
    new Promise((res) => {
      if (!existsSync(sock)) return res(false);
      const c = connect(sock);
      const done = (ok: boolean): void => { c.destroy(); res(ok); };
      c.once("connect", () => done(true));
      c.once("error", () => done(false));
      setTimeout(() => done(false), 500);
    }),
  fileExists: existsSync,
  platform: () => (process.platform === "darwin" ? "darwin" : process.platform === "win32" ? "win32" : "linux"),
  usernsOk: () => probeUserns(),
  readKnob: (path) => { try { return readFileSync(path, "utf8"); } catch { return null; } },
  trustLookups: (sock) => readTrustLookups(sock),
  agentVersion: (bin) => probeAgentVersionLooking(bin),
  gooseLogin: (env) => ({ readGooseConfig: realLoginProbeDeps(env).readGooseConfig!, keyringItem: realGooseKeyringItem(env) }),
  codexBwrapProbe: realCodexSandboxProbe,
  nestingOk: () => {
    const bwrap = resolveWrapBwrap();
    if (bwrap === null) return false;
    const [cmd, ...args] = nestedSandboxProbeArgv(bwrap);
    return spawnSync(cmd!, args, { stdio: "ignore", timeout: 10_000 }).status === 0;
  },
  bwrapGrant: () => {
    const readText = (p: string): string | null => { try { return readFileSync(p, "utf8"); } catch { return null; } };
    return {
      inForce: manduBwrapInForceHere(),
      stale: manduBwrapStale(realBwrapGrantDeps, copySourceBwrap()),
      legacy: staleLegacyProfiles(readText),
      distroBwrap: existsSync(DISTRO_BWRAP_PROFILE_FILE),
      admin: adminBwrap(),
    };
  },
  bwrapSymlink: () => {
    const bwrap = resolveWrapBwrap();
    return bwrap === null ? { bwrap: "bwrap", verdict: "unknown", detail: "no bubblewrap outside the working directory" } : probeBwrapSymlink(bwrap);
  },
  modelEndpoints: (sock) => readModelEndpoints(sock, 1500),
  localModelLabels: realLocalModelLabels,
  probeTcp: realProbeTcp,
  listModels: realListModels,
  homeFacts: realHomeFacts,
  gitSandbox: realGitSandboxFacts,
  lookupHost: systemLookup,
  probeTls: (host, port, m) => probeTls(host, port, m),
  codexAdminLock: (env) => realCodexSandboxDeps(env).codexAdminLock?.() ?? null,
  listDir: (dir) => { try { return readdirSync(dir); } catch { return null; } },
  readPlistJson: realReadPlistJson,
  updateFacts: (env, installed) =>
    doctorUpdateFacts({ env, version: launcherVersion(), installed, interactive: process.stdout.isTTY === true, channel: updateChannel(Layout.detect(import.meta.url, env)) }),
};

/** Did the user turn the whole-agent guard off for launches? The launch's
 *  own parse (flags aside) over env + config.toml, so doctor names the same
 *  `guard-off` gap a launch would. */
export function guardOptedOut(env: Env, readConfig?: (p: string) => string | null): boolean {
  try {
    return parseLaunch(["--target", "shell", "--", "true"], { ...loadConfigEnv(env, readConfig), ...env }).netGuard === false;
  } catch {
    return false;
  }
}

/** The confinement posture a launch here would get. The SAME probe and
 *  resolution the launch uses, so doctor cannot promise what a launch won't do.
 *  `env` (optional) names a guard the user turned off (`guard-off`). */
export function gatherConfinement(deps: DoctorDeps, env?: Env): DoctorFacts["confinement"] {
  const platform = deps.platform();
  const linux = platform === "linux";
  const bwrap = linux && deps.commandExists("bwrap");
  const userns = linux && bwrap && deps.usernsOk();
  const guardOff = linux && env !== undefined && guardOptedOut(env, deps.readKnob);
  const host = resolveHostPosture({
    platform,
    bwrap,
    userns,
    apparmorRestricted: linux && deps.readKnob(APPARMOR_USERNS_SYSCTL)?.trim() === "1",
    // /usr/bin/sandbox-exec by path, the binary a launch wraps with (never a
    // PATH lookup: seatbelt-profile.ts SANDBOX_EXEC), as secret-setup.ts asks.
    sandboxExec: platform === "darwin" && sandboxExecAvailable(deps.commandExists),
    landlockReadBlock: false,
    // The SAME resolver the launch uses (net-guard-setup.ts), so doctor cannot
    // promise a guard the launch will not find.
    // A guard the user turned off is no guard (sandbox-security-review
    // finding 7: without it the bind alone is `gated`, gap `guard-off`).
    guard: linux && !guardOff && (deps.nativeBin ?? resolveNativeBin)("mandu-net-guard") !== null,
    guardOff,
    // The launch runs the same probe before it binds (secret-setup.ts).
    ...(userns ? { nesting: deps.nestingOk?.() ?? true } : {}),
  });
  const usernsGap = host.gap === "apparmor-userns" || host.gap === "userns-off";
  return { ...host, ...(usernsGap ? { detail: usernsGapHint(deps.readKnob) } : {}) };
}

/** Claude Code's own sandbox settings (plan 10 §12.3), read with the same
 *  file reader the knobs use. Pure given `readKnob`. */
export function gatherClaudeSandbox(env: Env, deps: DoctorDeps, cwd: string = process.cwd()): DoctorFacts["claudeSandbox"] {
  const home = env["HOME"] ?? homedir();
  const platform = deps.platform();
  const exists = (p: string): boolean => deps.fileExists(p);
  const { view } = checkClaudeSandbox({
    home, cwd, confined: [], maskedEnv: [], arbiterSock: "", readFile: deps.readKnob, platform,
    // The sources a launch reads (claude-sandbox.ts claudeSettingsLocations).
    locations: claudeSettingsLocations(env, home, cwd, platform === "darwin" ? "darwin" : "linux", {
      exists, readFile: deps.readKnob, listDir: deps.listDir ?? (() => null),
    }),
    readPlistJson: deps.readPlistJson ?? (() => null),
    exists,
  });
  const denyRead = (view.denyRead?.length ?? 0) + (view.blockReadsOutside?.length ?? 0);
  const unreadable = (view.unreadable?.length ?? 0) + view.errors.length;
  // An administrator's policy helper or an MDM file Mandu cannot convert
  // counts too: a launch keeps the sandbox for it.
  const hasSandbox = view.enabled || view.files.length > 0 || view.envVars.length > 0 || denyRead > 0 || view.allowUnixSockets.length > 0 || (view.unreadable?.length ?? 0) > 0;
  if (!hasSandbox) return null;
  return {
    enabled: view.enabled,
    enabledBy: view.enabledBy,
    maskedFiles: view.files.filter((f) => f.mode === "mask").length,
    maskedEnvVars: view.envVars.filter((e) => e.mode === "mask").length,
    sources: view.sources,
    rules: view.files.length + view.envVars.length + denyRead,
    ...(unreadable > 0 ? { unreadable: [...(view.unreadable ?? []), ...view.errors.map((e) => e.replace(/: .*$/, ""))] } : {}),
    ...((view.enabledByManaged?.length ?? 0) > 0 ? { managedOn: view.enabledByManaged! } : {}),
  };
}

/** The arbiter socket this deployment would use (arbiter-sock.ts — the same
 *  env → `current` → legacy order the launch itself resolves; doctor used to
 *  hardcode the legacy fixed path and misreport a promoted arbiter as absent). */
function arbiterSock(env: Env): string {
  return resolveArbiterSock(env).sock;
}

/** Does a built kernel supervisor binary exist for `crate` in a dev checkout? */
function kernelBinaryPresent(repoRoot: string, crate: string, fileExists: (p: string) => boolean): boolean {
  return ["release", "debug"].some((profile) =>
    fileExists(join(repoRoot, "interceptors", "target", profile, crate)),
  );
}

/** Gather the facts doctor reports. */
export async function gatherFacts(env: Env, layout: Layout, deps: DoctorDeps): Promise<DoctorFacts> {
  const version = deps.nodeVersion();
  const sock = arbiterSock(env);
  const root = layout.mode === "dev" ? layout.repoRoot : layout.pkgRoot;
  const kernel: Record<string, boolean> = {};
  const loginDeps = { env, home: env["HOME"] || homedir(), fileExists: deps.fileExists, platform: deps.platform() };
  const nativeBin = deps.nativeBin ?? resolveNativeBin;
  const agents = { claude: deps.commandExists("claude"), codex: deps.commandExists("codex") };
  const opencodeBin = deps.commandExists("opencode") ? "opencode" : deps.commandExists("opencode2") ? "opencode2" : null;
  // No probe injected ⇒ no version read (a fixture never runs the host's agent).
  const versionOf = deps.agentVersion ?? ((): string | null => null);
  for (const cp of CHOKEPOINTS) {
    if (cp.kernelCrate) {
      kernel[cp.kernelCrate] =
        kernelBinaryPresent(root, cp.kernelCrate, deps.fileExists) ||
        (cp.nativeBin !== null && nativeBin(cp.nativeBin) !== null);
    }
  }
  const arbiterReachable = await deps.socketReachable(sock);
  const git = deps.gitVersion();
  const pathNode = deps.pathNode?.(env) ?? null;
  return {
    node: { version, ok: nodeMeetsFloor(version) },
    ...(pathNode === null ? {} : {
      pathNode: {
        path: pathNode.path,
        // A node that did not answer is "could not read", never "no node".
        gap: pathNode.versionText === null ? { state: "unreadable", text: "" } : nodeEnvProxyGap(pathNode.versionText),
      },
    }),
    git,
    ...(deps.gitSandbox && git !== null ? { gitSandbox: deps.gitSandbox(env) } : {}),
    agents,
    logins: {
      claude: probeAgentLogin("claude", loginDeps),
      codex: probeAgentLogin("codex", loginDeps),
      // Goose's row only where goose is installed (supported-agents.md §5.6.1).
      ...(deps.commandExists("goose") ? { goose: probeAgentLogin("goose", { ...loginDeps, ...deps.gooseLogin?.(env) }) } : {}),
    },
    versions: {
      claude: agents.claude ? checkAgentVersion("claude", versionOf("claude")) : null,
      codex: agents.codex ? checkAgentVersion("codex", versionOf("codex")) : null,
      // OpenCode: `opencode` (1 or 2), else OpenCode 2's own `opencode2`;
      // which generation it is decides whether a launch is refused
      // (supported-agents.md §2.3).
      opencode: opencodeBin === null ? null : {
        bin: opencodeBin,
        check: checkAgentVersion("opencode", versionOf(opencodeBin)),
        opencode2: opencode2Enabled(env),
      },
      goose: deps.commandExists("goose") ? checkAgentVersion("goose", versionOf("goose")) : null,
    },
    codexSandbox: assessCodexSandbox(gatherCodexSandbox({
      platform: deps.platform,
      commandExists: deps.commandExists,
      readKnob: deps.readKnob,
      bwrapProbe: deps.codexBwrapProbe ?? deps.usernsOk,
      manduBwrapInForce: () => deps.bwrapGrant?.().inForce ?? false,
      // macOS: what Codex's config layers say (codex-sandbox.ts
      // codexLayerReaders: /etc/codex, $CODEX_HOME, the project's
      // .codex/config.toml), read through the same reader; nothing of them is
      // printed. With an administrator's requirement, they decide whether
      // Mandu turns the sandbox off for each session.
      ...codexLayerReaders({ ...env, HOME: env["HOME"] || homedir() }, process.cwd(), deps.readKnob, (p) => deps.fileExists(p)),
      ...(deps.codexAdminLock ? { codexAdminLock: () => deps.codexAdminLock!(env) } : {}),
      // macOS: is a profile around the launch? The same /usr/bin/sandbox-exec
      // check as the confinement row, never a PATH lookup of the bare name.
      // No credsBlocked: the doctor knows the host, not the mode a launch
      // runs in, so its row says "in mode secrets" (codexSandboxRow).
    }, agents.codex, deps.platform() === "darwin" ? { outerSeatbelt: sandboxExecAvailable(deps.commandExists) } : {})),
    platform: deps.platform(),
    layout: { mode: layout.mode, root, bundled: layout.bundled },
    arbiter: { sock, reachable: arbiterReachable },
    kernel,
    confinement: gatherConfinement(deps, env),
    ...(deps.bwrapGrant && deps.platform() === "linux" ? { bwrapGrant: deps.bwrapGrant() } : {}),
    ...(deps.bwrapSymlink && deps.platform() === "linux" ? { bwrapSymlink: deps.bwrapSymlink() } : {}),
    claudeSandbox: gatherClaudeSandbox(env, deps),
    wsl: deps.platform() === "linux" ? wslVersion(deps.readKnob("/proc/sys/kernel/osrelease")) : null,
    wslDetail: deps.platform() === "linux"
      ? gatherWslFacts({ readFile: deps.readKnob, fileExists: deps.fileExists, cwd: process.cwd() })
      : null,
    models: await gatherModels(env, deps, sock, arbiterReachable),
    policyModel: {
      offered: (env["MANDU_EXPERIMENTAL_POLICY_MODEL"] ?? "") === "1",
      mode: env["MANDU_ULLM_MODE"] ?? "auto",
      apiKey: (env["ANTHROPIC_API_KEY"] ?? "").trim() !== "",
    },
    ...(deps.homeFacts ? { home: deps.homeFacts(env) } : {}),
    ...(deps.updateFacts ? { update: await deps.updateFacts(env, layout.mode === "installed") } : {}),
    ...(deps.platform() === "linux" ? { ptraceScope: ptraceScopeFacts(deps.readKnob) } : {}),
    ...(deps.platform() === "linux"
      ? {
        remoteMounts: {
          visible: visibleRemoteMounts(deps.readKnob("/proc/self/mountinfo") ?? ""),
          trusted: arbiterReachable && deps.trustLookups ? await trustedHere(deps.trustLookups, sock, env) : null,
        },
      }
      : {}),
  };
}

async function trustedHere(read: (sock: string) => Promise<TrustLookup[] | null>, sock: string, env: Env): Promise<TrustLookup[] | null> {
  const t = await read(sock);
  return t === null ? null : expandTrust(t, env["HOME"] || homedir());
}

/** The rows for the network and FUSE mounts (plan 13 §4.9) under "Your
 *  secrets": none visible, or each one, trusted or not, with how to trust
 *  it. Pure. */
export function remoteMountRows(r: RemoteMountFacts | undefined): string[] {
  if (r === undefined) return [];
  if (r.visible.length === 0) return [`  ${OK} no network or FUSE mount is visible: a program you named as a reader gets the real file`];
  const rows: string[] = [];
  const trust = r.trusted ?? [];
  for (const m of r.visible) {
    if (isTrusted(m, trust)) {
      rows.push(`  ${DOT} ${m.mount} (${m.type} from ${m.source}): trusted for lookups in policy.yaml, so readers get the real file; its server sees the names they look up there`);
    } else {
      rows.push(`  ${DOT} ${m.mount} (${m.type} from ${m.source}) is a network or FUSE mount: while it is visible, a program you named as a reader gets the placeholder instead of the real file, since its server would see every name that program looks up there`);
      rows.push(`    to allow real reads: policy.yaml remote_mounts: trust_lookups: [{ mount: ${m.mount}, type: ${m.type} }], or bind the secret to ${mountDestination(m)}`);
    }
  }
  if (r.trusted === null) rows.push("    (policy.yaml remote_mounts: not read: the Mandu service is not running)");
  return rows;
}

/** Is `model` among the listed ids? Ollama lists `llama3.2:latest` for a
 *  model pulled as `llama3.2`, so an implied `:latest` matches. Pure. */
export function modelListedIn(ids: readonly string[], model: string): boolean {
  const bare = (m: string): string => m.replace(/:latest$/, "");
  return ids.some((id) => id === model || bare(id) === bare(model));
}

/**
 * The `models:` facts (confidentiality-plan-11 D6).
 *
 * Why the endpoints come from the ARBITER and not from parsing policy.yaml
 * here: the arbiter owns the law (it validates `models:`, refuses a bad
 * entry, and hot-reloads the file), so its answer is exactly what a launch
 * would enforce; a second parser here could show rows for an entry the
 * arbiter refused, or miss one it accepted. It also keeps the launcher free
 * of runtime dependencies (js-yaml would be its first, in every bundle and
 * the license manifest) for a diagnostic. With no arbiter running, the file
 * is only line-scanned (as for the level spellings above): whether a
 * `models:` section exists and which paths say `local-model`, which is all
 * the hint needs.
 */
export async function gatherModels(
  env: Env,
  deps: Pick<DoctorDeps, "readKnob" | "modelEndpoints" | "probeTcp" | "listModels" | "localModelLabels" | "lookupHost" | "probeTls">,
  sock: string,
  arbiterReachable: boolean,
): Promise<ModelsFacts> {
  const policyPath = policyFilePath(env);
  const text = policyPath === null ? null : deps.readKnob(policyPath);
  const localModelLines = text === null ? [] : localModelLevelLines(text);
  const declaredInFile = text !== null && hasModelsSection(text);
  const cloudInFile = text === null ? [] : cloudLocalModelEntries(text);
  const cloudFacts = cloudInFile.length > 0 ? { cloudLocalInFile: cloudInFile } : {};
  const read = arbiterReachable && deps.modelEndpoints ? await deps.modelEndpoints(sock) : null;
  const baseUrl = env["ANTHROPIC_BASE_URL"] || undefined;
  const openaiUrl = env["MANDU_OPENAI_BASE_URL"] || undefined;
  if (read === null || read.status === "unavailable") {
    return {
      source: "file", endpoints: [], declaredInFile, localModelLines, policyPath,
      ...(baseUrl ? { anthropicBaseUrl: { url: baseUrl, match: null } } : {}),
      ...(openaiUrl ? { openaiBaseUrl: { url: openaiUrl, match: null } } : {}),
      ...cloudFacts,
    };
  }
  // The same pure match a launch runs (run.ts), so the row says exactly what
  // the next launch will do with this variable.
  const matchFacts = (url: string, wire: "anthropic" | "openai"): NonNullable<ModelsFacts["anthropicBaseUrl"]> => {
    const hit = selectTllmEndpoint(url, read.endpoints, wire);
    let refused = false;
    if (hit !== null) { try { tllmUpstream(hit.url); } catch { refused = true; } }
    return {
      url,
      match: hit === null ? null : { name: hit.name, local: hit.local },
      ...(refused ? { refused: true } : {}),
    };
  };
  const baseUrlFacts = baseUrl ? matchFacts(baseUrl, "anthropic") : undefined;
  const openaiUrlFacts = openaiUrl ? matchFacts(openaiUrl, "openai") : undefined;
  const endpoints: ModelRowFacts[] = [];
  const helperName = helperEndpointName(read.endpoints);
  for (const e of read.endpoints) {
    const o = parseOrigin(e.url)!; // asModelEndpoint accepted only parseable urls
    const placement = endpointPlacement(e.url) ?? "network";
    // Plan 12 D6: where a network endpoint really is. A literal address is
    // itself; a name is resolved (the doctor's own lookup, used for this row
    // only).
    let where: { addresses: string[]; reach: AddressReach } | null = null;
    if (placement === "network") {
      const addresses = isIP(o.host) !== 0 ? [o.host] : deps.lookupHost ? await deps.lookupHost(o.host) : null;
      if (addresses !== null) where = { addresses, reach: addressReach(addresses) };
    }
    // Plan 12 D4: the perimeter against those addresses, as the launch checks.
    let perimeterFact: ModelRowFacts["perimeter"] | undefined;
    if (e.local && placement === "network" && e.perimeter && where !== null) {
      const bad = where.addresses.find((a) => !inNetworks(a, e.perimeter!));
      const ok = where.addresses.length > 0 && bad === undefined;
      perimeterFact = { networks: [...e.perimeter], ok, ...(ok ? {} : { outside: bad ?? null }) };
    }
    const reachable = deps.probeTcp ? await deps.probeTcp(o.host, o.port) : null;
    // Plan 12 D3/D6: the entry's TLS checks, in one handshake (doctor runs
    // outside the agent's world, so it reads the client key itself).
    let tlsFact: ModelRowFacts["tls"] | undefined;
    // Not to an address outside the perimeter: the row above already refuses it.
    if (reachable === true && o.scheme === "https" && deps.probeTls && perimeterFact?.ok !== false && (e.tls !== undefined || (e.local && placement === "network"))) {
      const checks = tlsChecksWords(e.tls);
      try {
        const r = await deps.probeTls(o.host, o.port, e.tls ? loadTlsMaterial(e.tls) : {});
        tlsFact = r.ok ? { checks, ok: true } : { checks, ok: false, reason: r.reason };
      } catch (err) {
        tlsFact = { checks, ok: false, reason: (err as Error).message };
      }
    }
    let modelListed: boolean | null = null;
    let cloudListed: string[] = [];
    // The listing is read for an openai-chat entry that names a model (is it
    // loaded?) and for every `local: true` entry (does the server also serve
    // cloud-backed models? plan 11 §8 item 3). Once per endpoint.
    const wantListed = e.wire === "openai-chat" && e.model !== undefined;
    if (reachable === true && (wantListed || e.local) && deps.listModels) {
      const ids = await deps.listModels(e.url, e.tokenEnv ? env[e.tokenEnv] : undefined);
      if (wantListed) modelListed = ids === null ? null : modelListedIn(ids, e.model!);
      if (e.local && ids !== null) cloudListed = ids.filter(isCloudBackedModel);
    }
    endpoints.push({
      name: e.name,
      url: e.url,
      wire: e.wire,
      ...(e.model !== undefined ? { model: e.model } : {}),
      local: e.local,
      ...(e.name === helperName ? { helper: true } : {}),
      host: o.host,
      hostClass: hostClass(o.host),
      reachable,
      modelListed,
      ...(cloudListed.length > 0 ? { cloudListed } : {}),
      ...(isPlainHttpLocal(e) ? { plainHttp: e.allowPlainHttp === true ? "allowed" as const : "refused" as const } : {}),
      placement,
      ...(where !== null ? where : {}),
      ...(tlsFact ? { tls: tlsFact } : {}),
      ...(perimeterFact ? { perimeter: perimeterFact } : {}),
      ...(e.orgDomain ? { orgDomain: true as const } : {}),
      ...(e.adminFile ? { adminFile: e.adminFile, ...(e.locked ? { locked: true as const } : {}) } : {}),
    });
  }
  const labels = deps.localModelLabels ? await deps.localModelLabels(sock) : null;
  return {
    source: "arbiter", endpoints, declaredInFile, localModelLines, policyPath,
    ...(read.admin ? { admin: read.admin } : {}),
    ...(labels !== null && labels.length > 0 ? { localModelLabels: labels } : {}),
    ...(baseUrlFacts ? { anthropicBaseUrl: baseUrlFacts } : {}),
    ...(openaiUrlFacts ? { openaiBaseUrl: openaiUrlFacts } : {}),
    ...cloudFacts,
  };
}

/** The running arbiter's `local-model` labels that are not policy file
 *  lines (plan 11 D6): the dashboard's Rules page and imports write labels
 *  the line scan cannot see. null = the arbiter did not answer. */
async function realLocalModelLabels(sock: string): Promise<string[] | null> {
  try {
    const r = await ndjsonCall<{ labels?: Array<{ path?: unknown; level?: unknown; source?: unknown }> }>(sock, "pathLabels", {}, 1500);
    return (r.labels ?? [])
      .filter((l) => l.level === "local-model" && l.source !== "policy-file" && typeof l.path === "string")
      .map((l) => l.path as string)
      .sort();
  } catch {
    return null;
  }
}

/** The doctor rows for `models:` (D6). Empty when there is nothing to say
 *  (no endpoint declared and no path labeled local-model). Pure. */
/** The configured checks in words, for the doctor row and the probe. MIRROR
 *  of dashboard/src/model-probe.ts `tlsChecksWords`. Pure. */
export function tlsChecksWords(t: EndpointTlsConfig | undefined): string[] {
  if (!t) return [];
  return [
    ...(t.caFile ? ["your CA"] : []),
    ...(t.pinSha256 && t.pinSha256.length > 0 ? ["a pinned key"] : []),
    ...(t.clientCert ? ["a client certificate"] : []),
  ];
}

/** What `mandu policy suggest --model names` would use (plan 14 §14.5). */
export interface PolicyModelFacts {
  /** MANDU_EXPERIMENTAL_POLICY_MODEL=1 (§14.6: offered only behind it until
   *  the quality bar is recorded). */
  offered: boolean;
  /** MANDU_ULLM_MODE (auto when unset). */
  mode: string;
  /** ANTHROPIC_API_KEY is set (its value is never read here). */
  apiKey: boolean;
}

/** The helper's default model, as inspect-mcp's selectUllmConfig would pick
 *  it (a key: the API; else `claude`, else `codex` on PATH). Pure. */
export function defaultHelperWords(p: PolicyModelFacts, agents: { claude: boolean; codex: boolean }): string | null {
  const mode = p.mode.trim().toLowerCase();
  if (mode === "api") return p.apiKey ? "Claude through the Anthropic API (ANTHROPIC_API_KEY)" : null;
  if (mode !== "cli" && p.apiKey) return "Claude through the Anthropic API (ANTHROPIC_API_KEY)";
  if (agents.claude) return "Claude through `claude -p` (your Claude Code login)";
  if (agents.codex) return "Codex through `codex exec` (your Codex login)";
  return null;
}

/** The names-only model's rows (plan 14 §14.5): what T1 would use, the
 *  declared entries `--endpoint` may pick, and whether T2 has a local model
 *  (T2 itself is not built yet). Pure. */
export function policyModelRows(p: PolicyModelFacts | undefined, agents: { claude: boolean; codex: boolean }, m: ModelsFacts | undefined): string[] {
  if (p === undefined) return [];
  const rows: string[] = [];
  const helper = defaultHelperWords(p, agents);
  const declared = m?.source === "arbiter" ? m.endpoints.map((e) => `${e.name} (${e.local ? "your own model" : "an outside model"})`) : [];
  rows.push(p.offered
    ? `  ${DOT} names only (--model names): on request, after you see every name; it would use ${helper ?? "no model: set ANTHROPIC_API_KEY or put claude on PATH"}` +
      `${declared.length > 0 ? `, or with --endpoint: ${declared.join(", ")}` : ""}`
    : `  ${DOT} names only (--model names): not offered yet (its quality bar is not met; MANDU_EXPERIMENTAL_POLICY_MODEL=1 to try it); it would use ${helper ?? "no model (no ANTHROPIC_API_KEY, no claude or codex on PATH)"}`);
  // Plan 14 §14.11: T2 goes only to a declared local entry naming no
  // cloud-backed model (the arbiter's resolveLocalEndpoint, again here).
  const locals = m?.source === "arbiter" ? m.endpoints.filter((e) => e.local && !(e.model !== undefined && isCloudBackedModel(e.model))).map((e) => e.name) : [];
  const t2Model = locals.length === 0
    ? "no model of your own is declared, so it cannot run: declare one with local: true under models: in policy.yaml"
    : locals.length === 1
      ? `it would use only your own model ${locals[0]}`
      : `it would use only your own model, the one you name with --endpoint (${locals.join(", ")})`;
  rows.push(p.offered
    ? `  ${locals.length === 0 ? NO : DOT} file contents (--model contents): on request, after you see every file it would read; ${t2Model}`
    : `  ${DOT} file contents (--model contents): not offered yet (its quality bar is not settled; MANDU_EXPERIMENTAL_POLICY_MODEL=1 to try it); ${t2Model}`);
  return rows;
}

export function modelRows(m: ModelsFacts | undefined): string[] {
  if (m === undefined) return [];
  const rows: string[] = [];
  // Plan 12 D5: who owns the list, before the entries.
  if (m.admin) {
    if (m.admin.files.length > 0) {
      rows.push(
        `  ${DOT} your administrator's policy: ${m.admin.files.join(", ")}; ` +
          (m.admin.locked
            ? "your own models are locked: you can remove one of theirs or add an outside model, not add or change your own"
            : "not locked: an entry of the same name in policy.yaml changes one of theirs"),
      );
    }
    // The administrator wins a conflict: the user's side is not in force.
    for (const c of m.admin.conflicts ?? []) {
      rows.push(`  ${NO} not in force, your administrator's policy wins: ${c.replace(/^models\[\d+\](\.[a-z_]+)?: /, "")}; change policy.yaml to match`);
    }
    if ((m.admin.refused ?? []).length > 0) {
      rows.push(`  ${NO} your administrator's policy changed and cannot be used, so the one read before stays in force: ${m.admin.refused!.join("; ")}`);
    }
  }
  for (const e of m.endpoints) {
    const own = `your own model, ${e.placement === "host" ? "on this computer" : e.orgDomain || e.perimeter?.ok ? "on your organization's network" : "on your network"}`;
    const what = `${e.name}: ${e.url} (${e.wire}${e.model ? `, model ${e.model}` : ""}, ${e.local ? own : "an outside model"}${e.helper ? ", the helper uses it" : ""}${e.adminFile ? ", set by your administrator" : ""})`;
    if (e.reachable === null) {
      rows.push(`  ${DOT} ${what}: reachability not checked`);
    } else if (!e.reachable) {
      // An administrator's entry is fixed in their file, not in policy.yaml;
      // a name with no address here was never dialed, so "start the model
      // server" would send the person the wrong way.
      const fix = e.adminFile ? `ask your administrator (${e.adminFile})` : "fix the url in policy.yaml";
      rows.push(e.reach === "unresolved" && isIP(e.host) === 0
        ? `  ${NO} ${what}: not reachable: ${e.host} does not resolve here; check the address, or connect to the network it is on${e.adminFile ? `, or ${fix}` : ""}`
        : `  ${NO} ${what}: not reachable; start the model server, or ${fix}`);
    } else if (e.modelListed === false) {
      rows.push(`  ${NO} ${what}: reachable, but ${e.model} is not listed at ${endpointApiBase(e.url)}/v1/models; load it on the server (for Ollama: ollama pull ${e.model})`);
    } else {
      rows.push(`  ${OK} ${what}: reachable${e.modelListed === true ? `, ${e.model} is listed` : ""}`);
    }
    // Plan 12 D3/D6: the TLS facts, or why the handshake was refused.
    if (e.tls?.ok === true) {
      rows.push(`  ${OK} ${e.name}: TLS checked${e.tls.checks.length > 0 ? ` (${e.tls.checks.join(", ")})` : " (the system's trusted CAs)"}`);
    } else if (e.tls?.ok === false) {
      rows.push(`  ${NO} ${e.name}: TLS refused: ${e.tls.reason ?? "unknown"}; nothing is sent to this model until it passes`);
    }
    // Plan 12 D4: the perimeter, as the launch and every connection check it.
    if (e.perimeter?.ok === true) {
      rows.push(`  ${OK} ${e.name}: every address (${(e.addresses ?? []).slice(0, 3).join(", ")}) is inside perimeter.networks`);
    } else if (e.perimeter?.ok === false) {
      rows.push(
        `  ${NO} ${e.name}: ${e.perimeter.outside ? `${e.host === e.perimeter.outside ? "is at" : "resolves to"} ${e.perimeter.outside}, outside perimeter.networks (${e.perimeter.networks.join(", ")})` : "does not resolve here, so it cannot be checked against perimeter.networks"}; ` +
          "a launch refuses this entry and nothing is sent to it",
      );
    }
    // Plan 12 D6: graded by where the address really is, not by its spelling.
    // With a perimeter the row above says it; without one, a hint.
    if (e.local && e.placement === "network" && e.reach === "public" && e.perimeter === undefined) {
      const literal = isIP(e.host) !== 0;
      const shown = (e.addresses ?? []).filter((a) => hostClass(a) === "public").slice(0, 3).join(", ");
      rows.push(
        `    hint: ${e.host} ${literal ? "is a public address" : `resolves to a public address (${shown})`}; if it is your organization's private-link endpoint, ` +
        "list its network under perimeter: networks in policy.yaml; otherwise make sure your organization controls that server. Mandu proves the data went to the address you named, not what that server does with it next",
      );
    } else if (e.local && e.placement === "network" && e.reach === "unresolved" && e.perimeter === undefined) {
      rows.push(`    hint: ${e.host} does not resolve on this machine; ${e.adminFile ? `ask your administrator (${e.adminFile})` : "check the name in policy.yaml"}`);
    }
    // Plan 12 D2: never quiet. `allowed` is the operator's choice, still
    // graded ✗ because the bytes cross a network in the clear.
    if (e.plainHttp === "allowed") {
      rows.push(
        `  ${NO} ${e.name}: plain http to another machine, allowed by allow_plain_http: files labeled local-model the helper sends there cross the network unencrypted; ` +
          "use https or a loopback tunnel (ssh -L) to close this",
      );
    } else if (e.plainHttp === "refused") {
      rows.push(
        `  ${NO} ${e.name}: plain http to another machine: the helper and a launch refuse this entry; ` +
          "use https, a loopback tunnel (ssh -L), or add allow_plain_http: true to accept it",
      );
    }
    // Plan 11 §8 item 3. An arbiter with the rule never reports such an entry
    // (it refuses the file); an older one does, and a launch refuses it.
    if (e.local && e.model !== undefined && isCloudBackedModel(e.model)) {
      rows.push(
        `  ${NO} ${e.name}: model ${e.model} runs on the vendor's servers (a cloud model), so this entry cannot be local: true; ` +
          "name a model that runs on your own machine, or remove local: true",
      );
    }
    if (e.local && e.cloudListed && e.cloudListed.length > 0) {
      const shown = e.cloudListed.slice(0, 5).join(", ") + (e.cloudListed.length > 5 ? ` and ${e.cloudListed.length - 5} more` : "");
      rows.push(
        `  ${DOT} ${e.name} also serves models that run on the vendor's servers (${shown}); requests for them leave this machine, ` +
          "so never choose one as your main model or as this entry's model",
      );
    }
  }
  const reported = new Set(m.endpoints.filter((e) => e.local && e.model !== undefined && isCloudBackedModel(e.model)).map((e) => e.name));
  for (const c of m.cloudLocalInFile ?? []) {
    if (c.name !== null && reported.has(c.name)) continue;
    rows.push(
      `  ${NO} ${m.policyPath} line ${c.line}: models: ${c.name ?? "(unnamed)"} says local: true, but its model ${c.model} runs on the vendor's servers (a cloud model); ` +
        "Mandu refuses this file until the entry names a model that runs on your own machine or drops local: true",
    );
  }
  // A declared OUTSIDE model reads no local-model file either (D2): what
  // counts is a `local: true` entry. The file scan cannot tell, so it keeps
  // the coarser "any models: section" test.
  const noOwnModel = m.source === "arbiter" ? !m.endpoints.some((e) => e.local) : !m.declaredInFile;
  const labeled = m.localModelLabels ?? [];
  if (noOwnModel && (m.localModelLines.length > 0 || labeled.length > 0)) {
    const where = [
      ...(m.localModelLines.length > 0 ? [`${m.policyPath}, line${m.localModelLines.length === 1 ? "" : "s"} ${m.localModelLines.join(", ")}`] : []),
      ...(labeled.length > 0 ? [`labeled on the Rules page: ${labeled.slice(0, 3).join(", ")}${labeled.length > 3 ? ` and ${labeled.length - 3} more` : ""}`] : []),
    ].join("; ");
    rows.push(
      `  ${NO} files labeled local-model are read by no model until you declare your own model in policy.yaml ` +
      `(${where}; add a models: entry with local: true)`,
    );
  }
  if (m.source === "file" && m.declaredInFile) {
    rows.push(`  ${DOT} ${m.policyPath} declares models: start Mandu (any launch starts it) and run mandu doctor again to check them`);
  }
  rows.push(...baseUrlRows(m));
  return rows;
}

/** The base-URL rows (plan 11 §5 phase 3, §7.2 for Codex): does a launch keep the
 *  model proxy in front of it? Pure. */
function baseUrlRows(m: ModelsFacts): string[] {
  return [
    ...baseUrlRowsFor(m.source, m.anthropicBaseUrl, "ANTHROPIC_BASE_URL", "anthropic"),
    ...baseUrlRowsFor(m.source, m.openaiBaseUrl, "MANDU_OPENAI_BASE_URL", "openai-chat"),
  ];
}

function baseUrlRowsFor(
  source: ModelsFacts["source"],
  b: ModelsFacts["anthropicBaseUrl"],
  knob: string,
  wire: string,
): string[] {
  if (b === undefined) return [];
  if (source === "file") {
    return [`  ${DOT} ${knob} is set (${b.url}): start Mandu and run mandu doctor again to check it against models:`];
  }
  if (b.match !== null && b.refused) {
    return [
      `  ${NO} ${knob} is models: ${b.match.name}, but a launch refuses it: it is plain http on another machine, ` +
        "and Mandu's model proxy sends the conversation over plain http only to this machine; put the model behind https or run it on this machine",
    ];
  }
  if (b.match !== null) {
    return [`  ${OK} ${knob} is models: ${b.match.name} (${b.match.local ? "your own model" : "an outside model"}); the model proxy stays in front of it`];
  }
  return [
    `  ${NO} ${knob} (${b.url}) is not declared under models:, so a launch skips the model proxy for it and the model ` +
      `reads file contents unprotected; declare it under models: with wire: ${wire} (local: true if it is your own model)`,
  ];
}

const OK = "✓";  // ✓
const NO = "✗";  // ✗
const DOT = "·"; // ·

/** One login row (agent-login.ts). A missing codex login is a note, not a
 *  failure, while codex itself is absent: it only matters for `mandu codex`. */
export function loginRow(agent: "claude" | "codex" | "goose", s: LoginStatus, relevant: boolean): string {
  if (agent === "goose") return gooseLoginRow("goose login", s);
  if (s.state === "found" && s.signIn === true) {
    return `  ${OK} ${agent} login: signed in (${s.via}); \`mandu ${agent}\` passes that sign-in through its model proxy`;
  }
  if (s.state === "found") return `  ${OK} ${agent} login: found (${s.via})`;
  if (s.state === "unknown") {
    return `  ${DOT} ${agent} login: cannot tell (Claude Code keeps it in the macOS Keychain); if it says "Not logged in": ${s.howTo}`;
  }
  return relevant
    ? `  ${NO} ${agent} login: none found; ${s.howTo}`
    : `  ${DOT} ${agent} login: none found (only needed for \`mandu codex\`: ${s.howTo})`;
}

/** A Goose login row: the session's (`goose login`) or its subagents'
 *  (gooseSubagentLoginRow). Supported-agents.md §5.6.1. */
function gooseLoginRow(label: string, s: Pick<GooseSubagentLogin, "state" | "via" | "keyring" | "howTo">): string {
  // On Linux a key in the system keyring is out of the agent's reach under
  // a protected launch (the session bus is refused); the macOS Keychain is
  // left reachable (seatbelt-setup.ts).
  const keyringOut = "which `mandu goose` keeps out of the agent's reach (its session bus also runs programs outside the protection)";
  if (s.state === "found" && s.keyring === true) return `  ${NO} ${label}: in the system keyring, ${keyringOut}; ${s.howTo}`;
  if (s.state === "found" && s.via === GOOSE_KEYCHAIN_VIA) {
    return `  ${OK} ${label}: found (${s.via}); \`mandu goose\` leaves the Keychain reachable, so Goose reads it there ` +
      "(Mandu never sees that key, so it cannot mask it if a tool prints it)";
  }
  if (s.state === "found") {
    return s.via !== undefined && /_API_KEY$/.test(s.via)
      ? `  ${OK} ${label}: found (${s.via})`
      : `  ${OK} ${label}: found (${s.via}); \`mandu goose\` lets Goose read it and masks its values in what reaches the model`;
  }
  if (s.state === "unknown") {
    return `  ${DOT} ${label}: no key variable and no secrets.yaml, and the system keyring was not asked; on Linux ` +
      `a key there is one ${keyringOut}; ${s.howTo}`;
  }
  return `  ${NO} ${label}: none found; ${s.howTo}`;
}

/** The subagents' own Goose login row, when GOOSE_SUBAGENT_PROVIDER puts
 *  them on a provider with another key variable (agent-login.ts
 *  `subagent`); null otherwise. */
export function gooseSubagentLoginRow(s: LoginStatus): string | null {
  const sub = s.subagent;
  if (sub === undefined) return null;
  return gooseLoginRow(`goose subagent login (${sub.provider}, from GOOSE_SUBAGENT_PROVIDER)`, sub);
}

/** One agent-version row (agent-versions.ts; supported-agents.md). Outside
 *  the tested range is a ✗ with what it costs; never a refusal. A preview
 *  agent's row (Goose, OpenCode 1 and 2; SupportStatus) ends with that word. */
export function versionRow(c: AgentVersionCheck): string {
  const range = `tested: ${rangeWords(c)}`;
  const preview = supportStatusOf(c.agent, c.version) === "preview" ? `; ${PREVIEW_WORDS}` : "";
  switch (c.verdict) {
    case "tested":
      return `  ${OK} ${c.name} ${c.version}: a tested version (${range})${preview}`;
    case "newer":
      return `  ${NO} ${c.name} ${c.version}: newer than tested (${range}); tools it adds that Mandu does not know are masked whole, so the agent may work less well${preview}`;
    case "older":
      return `  ${NO} ${c.name} ${c.version}: older than tested (${range}); upgrade it if anything misbehaves${preview}`;
    case "unknown":
      return `  ${DOT} ${c.name}: could not read its version (${range})${preview}`;
  }
}

/** What a preview agent's doctor row adds (agent-versions.ts SupportStatus). */
export const PREVIEW_WORDS = "a preview: tested less than Claude Code and Codex";

/** OpenCode's doctor facts: which command, its version check (against its
 *  generation's tested range), and whether OpenCode 2 is on (it is unless
 *  MANDU_OPENCODE2=0; agent-versions.ts opencode2Enabled). */
export interface OpencodeVersionFacts {
  bin: "opencode" | "opencode2";
  check: AgentVersionCheck;
  opencode2: boolean;
}

/** The OpenCode row (supported-agents.md §2.3): OpenCode 1 and 2 read like
 *  every agent's version row, 2 with what its launches get; OpenCode 2 under
 *  MANDU_OPENCODE2=0, an unreadable version and any other major say that
 *  `mandu opencode` refuses them. */
export function opencodeVersionRow(o: OpencodeVersionFacts): string {
  const c = o.check;
  const major = parseAgentVersion(c.version)?.parts[0] ?? null;
  if (c.version === null) {
    return `  ${DOT} OpenCode (${o.bin}): could not read its version, so \`mandu opencode\` refuses it (it cannot tell OpenCode 1 from 2)`;
  }
  if (major === OPENCODE_V1_MAJOR && o.bin === "opencode") return versionRow(c);
  if (major === OPENCODE_V2_MAJOR) {
    return o.opencode2
      ? `${versionRow(c)}; OpenCode 2: each launch gets a private server (--standalone) that only OpenCode itself can reach, ` +
          "and secrets mode runs only where the kernel connect guard, the write-protect guard and its config lockdown all run " +
          "(a launch without them is refused and says which is missing)"
      : `  ${NO} OpenCode ${c.version} is OpenCode 2: ${OPENCODE2_ENV}=0 turns it off, so \`mandu opencode\` refuses it; ` +
          `unset ${OPENCODE2_ENV} to run it`;
  }
  return (
    `  ${NO} OpenCode ${c.version} (${o.bin}): \`mandu opencode\` refuses it ` +
    `(Mandu supports OpenCode 1, tested: ${rangeWords(opencodeTested(1))}, and OpenCode 2, tested: ${rangeWords(opencodeTested(2))}); ` +
    `install one of them (${opencodeInstall(1)}, or ${opencodeInstall(2)})`
  );
}

/** The WSL2 detail rows (wsl.ts). `guard`: is the connect guard installed
 *  (it refuses the interop socket and AF_VSOCK for the whole agent)? */
export function wslRows(w: WslFacts | null, guard: boolean): string[] {
  if (w === null || w.version !== 2) return [];
  const rows: string[] = [];
  rows.push(w.landlock
    ? `  ${OK} kernel ${w.kernel}: Landlock ${w.landlockNet ? "with TCP rules" : "for files (TCP rules need 6.7)"}`
    : `  ${NO} kernel ${w.kernel} predates Landlock (5.13): the command box has no file-access layer below its mounts; run: wsl --update`);
  if (w.interop === "enabled") {
    rows.push(guard
      ? `  ${OK} Windows interop is on; Mandu keeps it from the AI: boxed commands cannot reach it, and the connect guard refuses it for everything else`
      : `  ${NO} Windows interop is on and the connect guard is not installed: a Windows program the AI starts outside the command box runs outside Mandu. Turn interop off in /etc/wsl.conf ([interop] enabled=false)`);
  } else {
    rows.push(`  ${OK} Windows interop is off`);
  }
  rows.push(w.systemd
    ? `  ${OK} systemd is running (the dashboard's background service can start)`
    : `  ${DOT} systemd is off in this distribution, so the dashboard's background service cannot start; enable it in /etc/wsl.conf ([boot] systemd=true), then: wsl --shutdown`);
  if (w.workspaceDrive) {
    rows.push(`  ${NO} this folder is on a Windows drive (${w.workspaceDrive.mountPoint}): slow, and edits made from Windows are only picked up at the AI's next tool call; move the project into the Linux file system (for example ~/src)`);
  }
  return rows;
}

/** What each chokepoint is called in the report, and the kernel guard that
 *  backs it, in the product's plain words (dashboard rule-words.ts register). */
const PLAIN_CHOKEPOINT: Record<string, { label: string; layer: string; guard: string | null }> = {
  "model-API": { label: "AI requests", layer: "Mandu's model proxy masks what the AI reads", guard: null },
  network: { label: "network", layer: "Mandu's network proxy", guard: "connect guard" },
  filesystem: { label: "files", layer: "Mandu's file sync", guard: "file guard" },
  exec: { label: "commands", layer: "Mandu's command wrapper", guard: "command box" },
};

/** The rows for Mandu's own bubblewrap (bwrap-grant.ts) under "Your
 *  secrets". A leftover pre-2026-09-27 grant is a ✗ with its fix. Pure. */
export function bwrapGrantRows(g: BwrapGrantFacts | undefined): string[] {
  if (g === undefined) return [];
  const rows: string[] = [];
  const legacy = legacyGrantWarning(g.legacy, g.distroBwrap);
  if (legacy !== null) rows.push(`  ${NO} ${legacy}`);
  if (g.admin?.kind === "path") {
    rows.push(`  ${OK} bubblewrap: your administrator's (${g.admin.path}, bwrap_path in ${g.admin.file}); Mandu runs it in place of the one on PATH`);
  } else if (g.admin?.kind === "refused") {
    rows.push(`  ${NO} ${adminBwrapRefusedReason(g.admin.why)}`);
    rows.push(`    fix: ${ADMIN_BWRAP_FIX}`);
  }
  if (g.inForce) {
    rows.push(`  ${OK} Mandu's own bubblewrap: installed (${MANDU_BWRAP}); the mount layer runs it, and the AI's own sandboxes can start inside it`);
    const source = g.admin?.kind === "path" ? g.admin.path : SYSTEM_BWRAP;
    if (g.stale) rows.push(`    it is older than ${source} (bubblewrap was updated since \`mandu setup\`): run \`mandu setup\` to refresh the copy`);
  }
  return rows;
}

/** The row for Mandu's own git on the AI's repositories (git-hardening.md
 *  §5): its hardening always holds; the sandbox is the defense in depth on
 *  top. Scoped to the git that gets the sandbox (the launcher's launch-prep
 *  runner and the arbiter's background scan, resolver and prepared copies;
 *  the dashboard's and fs-sync's git and the arbiter's single reads run
 *  hardened only), and prospective: what that git gets on this host now.
 *  A gap is a ✗: an unprivileged hardening left unused (CONTRIBUTING.md, the
 *  non-root-privilege principle). Pure. */
export function gitSandboxRows(g: GitSandboxFacts | undefined): string[] {
  if (g === undefined) return [];
  const what = "Mandu's background and launch-prep git on folders the AI can change";
  switch (g.state) {
    case "on":
      return [`  ${OK} ${what}: hardened, and run in a sandbox with no network and a read-only view (${g.bwrap})`];
    case "seatbelt":
      return [`  ${OK} ${what}: hardened, and run in a sandbox with no network, a read-only view and no other program (${g.sandboxExec}, git ${g.git})`];
    case "off":
      return [`  ${DOT} ${what}: hardened; its sandbox is turned off (MANDU_GIT_SANDBOX=0)`];
    case "unavailable":
      return [
        `  ${NO} ${what}: hardened, but not in a sandbox: no bubblewrap here can start one`,
        "    fix: a bubblewrap that can create a user namespace (sudo apt install bubblewrap; on Ubuntu, then mandu setup)",
      ];
    case "none":
      return g.gap
        ? [`  ${NO} ${what}: hardened, but not in a sandbox: ${g.why}`, ...(g.fix !== undefined ? [`    fix: ${g.fix}`] : [])]
        : [`  ${DOT} ${what}: hardened, not in a sandbox here: ${g.why}`];
  }
}

/** Render the doctor report from gathered facts. Pure (testable). The
 *  wording follows the dashboard product page (plain words: the AI,
 *  placeholder, needs your OK); component names ride in parentheses so a
 *  bug report still names the part. `posture: <name>` stays verbatim: the
 *  fresh-install VM suite and the dashboard chip use the same names. */
/** Yama's knob (rootless-confinement-ubuntu-2404.md §3.3). */
export const YAMA_PTRACE_SCOPE = "/proc/sys/kernel/yama/ptrace_scope";

/** Read Yama's `ptrace_scope` through the doctor's knob reader: its value, or
 *  null when the file is absent or does not hold a number. Pure over `read`. */
export function ptraceScopeFacts(read: (path: string) => string | null): { value: number | null } {
  const raw = read(YAMA_PTRACE_SCOPE);
  const t = raw === null ? "" : raw.trim();
  return { value: /^[0-9]+$/.test(t) ? Number(t) : null };
}

const PTRACE_SCOPE_WEAK =
  "any program running as you, the AI's included, can read the memory of your other programs " +
  "(Mandu's service, the dashboard and its sign-in links, the reply filter), so the walls Mandu keeps " +
  "between programs of your account are weaker. Mandu's file guard refuses this either way. A warning only.";

/** The doctor's Yama row, or null when not checked (off Linux). At 1 or
 *  more a program can trace only its own children (1), only with
 *  CAP_SYS_PTRACE (2), or never (3); at 0, or with no Yama, any program of
 *  the account can trace any other. */
export function ptraceScopeRow(f: DoctorFacts["ptraceScope"]): string | null {
  if (f === undefined) return null;
  const v = f.value;
  if (v === null) {
    return `  ${NO} Yama is not in this kernel (no ${YAMA_PTRACE_SCOPE}): ${PTRACE_SCOPE_WEAK} ` +
      "fix: a kernel built with Yama (CONFIG_SECURITY_YAMA, as Ubuntu, Debian and Fedora ship it)";
  }
  if (v === 0) {
    return `  ${NO} Yama ptrace_scope is 0: ${PTRACE_SCOPE_WEAK} ` +
      "fix: sudo sysctl kernel.yama.ptrace_scope=1 (to keep it: a line kernel.yama.ptrace_scope = 1 in /etc/sysctl.d/10-ptrace.conf)";
  }
  const how = v === 1
    ? "a program can read the memory only of the programs it started"
    : v === 2 ? "only an administrator can read another program's memory" : "no program can read another's memory";
  return `  ${OK} Yama ptrace_scope ${v}: ${how}, so the AI's programs cannot read Mandu's service or the dashboard's`;
}

/**
 * The rows for the `node` on PATH (plan 13 §10.2): a Node program in a
 * session uses Mandu's network proxy only when its Node honours
 * NODE_USE_ENV_PROXY (22.21+ or 24.5+; 24.0 to 24.4 for fetch alone). Below
 * that its requests go around the proxy: nothing leaks (they carry the
 * placeholders), but the real values are never filled in, so its logins
 * fail with no explanation. A warning, never a failure: Mandu itself runs
 * on 22.13. None when PATH has no node.
 */
export function pathNodeRows(p: DoctorFacts["pathNode"]): string[] {
  if (!p) return [];
  const g = p.gap;
  switch (g.state) {
    case "absent":
      return [];
    case "ok":
      return [`  ${OK} node on your PATH is ${g.version} (${p.path}): Node programs in a Mandu session send their web requests through Mandu`];
    case "bypass":
      return [
        `  ${NO} node on your PATH is ${g.version} (${p.path}): Node programs in a Mandu session won't have your secrets filled in on ${bypassWords(g.apis)}, so their logins fail (nothing leaks)`,
        `    fix: ${nodeEnvProxyFix(g.version)}`,
      ];
    case "unreadable":
      return [
        `  ${DOT} could not read the version of the node on your PATH (${p.path}${g.text === "" ? ": no answer" : `: "${g.text}"`}): Node programs in a Mandu session`,
        "    need Node 22.21 or newer, or 24.5 or newer, to have your secrets filled in on their web requests",
      ];
  }
}

export function renderDoctor(f: DoctorFacts): string {
  const L: string[] = [];
  L.push("Mandu doctor");
  L.push("");

  L.push("What Mandu needs");
  L.push(f.node.ok
    ? `  ${OK} Node.js ${f.node.version} (${NODE_FLOOR} or newer)`
    : `  ${NO} Node.js ${f.node.version} is TOO OLD: Mandu needs ${NODE_FLOOR} or newer (nvm install 22)`);
  for (const row of pathNodeRows(f.pathNode)) L.push(row);
  L.push(f.git ? `  ${OK} git ${f.git}` : `  ${NO} git not found: without it the AI works in your folder directly, with no separate working copy`);
  L.push(f.agents.claude ? `  ${OK} Claude Code is installed (claude)` : `  ${NO} Claude Code is not installed: npm i -g @anthropic-ai/claude-code`);
  L.push(f.agents.codex ? `  ${OK} Codex is installed (codex)` : `  ${DOT} Codex is not installed (only needed for \`mandu codex\`)`);
  if (f.logins) {
    L.push(loginRow("claude", f.logins.claude, true));
    L.push(loginRow("codex", f.logins.codex, f.agents.codex));
    if (f.logins.goose) {
      L.push(loginRow("goose", f.logins.goose, true));
      const sub = gooseSubagentLoginRow(f.logins.goose);
      if (sub !== null) L.push(sub);
    }
  }
  if (f.versions) {
    for (const c of [f.versions.claude, f.versions.codex]) if (c !== null) L.push(versionRow(c));
    if (f.versions.opencode) L.push(opencodeVersionRow(f.versions.opencode));
    if (f.versions.goose) L.push(versionRow(f.versions.goose));
  }
  const codexBox = f.codexSandbox ? codexSandboxRow(f.codexSandbox) : null;
  if (codexBox !== null) L.push(codexBox);
  L.push("");

  if (f.wsl === 2) {
    L.push("Platform");
    L.push(`  ${OK} Linux on WSL2: a real Linux kernel, so everything below applies as on any Linux. Mandu's WSL2 handling is tested on a simulated WSL2 host, not yet on Windows itself.`);
    for (const row of wslRows(f.wslDetail ?? null, f.kernel["net-supervisor"] === true)) L.push(row);
    L.push("");
  } else if (f.wsl === 1) {
    L.push("Platform");
    L.push(`  ${NO} WSL1: not a Linux kernel, so Mandu cannot protect your credential files here. Convert this distribution to WSL2: wsl --set-version <distro> 2`);
    L.push("");
  }

  L.push("Installed");
  L.push(f.layout.mode === "installed"
    ? `  from the npm package: ${f.layout.root}`
    : `  from a source checkout (${f.layout.bundled ? "its prebuilt bundle, rebuilt when the source changes" : "run with tsx"}): ${f.layout.root}`);
  if (f.update) {
    L.push(`  version ${f.update.version}`);
    L.push(...updateRows(f.update, { ok: OK, no: NO, dot: DOT }));
  }
  const commit = f.install ? commitWords(f.install.self) : null;
  if (commit !== null) L.push(`  commit ${commit}`);
  // The install's problems (another mandu on PATH, an environment that
  // forces another tree); the services' own are under "Mandu service".
  const isService = (p: Problem): boolean => p.id.startsWith("services-");
  for (const p of f.install?.problems.filter((p) => !isService(p)) ?? []) {
    L.push(`  ${NO} ${p.problem}`);
    L.push(`      fix: ${p.fix}`);
  }
  L.push("");

  L.push("Mandu service");
  const svcProblems = f.install?.problems.filter(isService) ?? [];
  if (!f.arbiter.reachable) {
    L.push(`  ${DOT} not running yet: the first launch starts it (${f.arbiter.sock})`);
  } else if (svcProblems.length === 0) {
    L.push(`  ${OK} running (${f.arbiter.sock})`);
  } else {
    for (const p of svcProblems) {
      L.push(`  ${NO} ${p.problem}`);
      L.push(`      fix: ${p.fix}`);
    }
  }
  if (f.install && f.install.problems.length > 0) L.push("  (`mandu version` shows every mandu install and service it compared)");
  L.push("");

  if (f.home) {
    L.push("Mandu's folder (`mandu paths` lists everything in it)");
    for (const row of homeRows(f.home)) L.push(row);
    L.push("");
  }

  L.push("Your secrets (what a launch that protects secrets gets)");
  const c = f.confinement;
  const head = c.posture === "gated"
    ? `${NO} credential files are NOT protected from programs the AI runs (posture: gated)`
    : `${OK} credential files are protected (posture: ${c.posture}${c.bindGap !== undefined ? ", by the guard alone" : ""})`;
  L.push(`  ${head}`);
  L.push(`    ${POSTURE_SENTENCE[c.posture]}`);
  for (const line of guardOnlyLines(c)) L.push(`    ${line}`);
  for (const line of bindOnlyLines(c)) L.push(`    ${line}`);
  for (const row of bwrapGrantRows(f.bwrapGrant)) L.push(row);
  for (const row of remoteMountRows(f.remoteMounts)) L.push(row);
  const yamaRow = ptraceScopeRow(f.ptraceScope);
  if (yamaRow !== null) L.push(yamaRow);
  const cveRow = symlinkProbeRow(f.bwrapSymlink);
  if (cveRow !== null) L.push(cveRow);
  if (c.gap) {
    const { cause, fix } = gapExplanation(c.gap);
    L.push(`    cause: ${cause}`);
    if (c.detail) L.push(`    detail: ${c.detail}`);
    if (fix !== null) L.push(`    fix: ${fix}`);
    L.push("    to refuse to launch instead of running unprotected: --require-confinement (config: require-confinement = true)");
  }
  const cs = f.claudeSandbox;
  // macOS with the Seatbelt read-block: Mandu's profile wraps the agent, and
  // macOS refuses a sandbox inside it (sandbox_apply: Operation not
  // permitted), so Claude Code's sandbox cannot start under mandu.
  const macProfile = f.platform === "darwin" && c.posture === "read-blocked";
  if (cs === null) {
    L.push(`  ${DOT} Claude Code's own sandbox: off (no sandbox section in its settings)`);
  } else {
    const masks = `${cs.maskedFiles} credential file${cs.maskedFiles === 1 ? "" : "s"} and ${cs.maskedEnvVars} environment variable${cs.maskedEnvVars === 1 ? "" : "s"} masked by Claude Code itself`;
    // Any managed source: the managed file, a drop-in, the server-managed
    // cache, MDM preferences.
    const managed = cs.managedOn ?? cs.enabledBy.filter((p) => p === claudeManagedSettings("darwin"));
    if (macProfile && cs.enabled && managed.length > 0) {
      L.push(`  ${NO} Claude Code's own sandbox: ON by your organization's managed settings (${managed.join(", ")}): on macOS it cannot`);
      L.push("    start inside Mandu's Seatbelt profile, so every command it sandboxes fails under mandu (sandbox_apply: Operation not permitted)");
      L.push("    fix: ask your administrator to allow it off for sessions under mandu (Mandu cannot turn managed settings off)");
      L.push(`    ${masks}`);
    } else if (macProfile && cs.enabled) {
      L.push(`  ${OK} Claude Code's own sandbox: ON (${cs.enabledBy.join(", ")}): under mandu on macOS Mandu turns it off for each session,`);
      L.push("    since it cannot start inside Mandu's Seatbelt profile; Mandu's profile still keeps your credential files from the commands the AI runs");
      claudeKeepCaveats(L, cs);
      L.push(`    ${masks}`);
    } else if (macProfile) {
      L.push(`  ${OK} Claude Code's own sandbox: configured but off: ${masks}`);
      L.push("    if it is turned on, Mandu turns it off for each session under mandu (on macOS it cannot start inside Mandu's profile)");
      claudeKeepCaveats(L, cs);
    } else {
      L.push(`  ${cs.enabled ? DOT : OK} Claude Code's own sandbox: ${cs.enabled ? `ON (${cs.enabledBy.join(", ")})` : "configured but off"}: ${masks}`);
      L.push("    a launch warns when both mask the same file; with the sandbox on, Mandu adds its own socket to");
      L.push("    sandbox.network.allowUnixSockets so the two work together");
    }
  }
  L.push("");

  const models = modelRows(f.models);
  if (models.length > 0) {
    L.push("Your own models (policy.yaml models:)");
    for (const row of models) L.push(row);
    L.push("");
  }
  const suggestModel = policyModelRows(f.policyModel, f.agents, f.models);
  if (suggestModel.length > 0) {
    L.push("A model for policy suggestions (mandu policy suggest --model)");
    for (const row of suggestModel) L.push(row);
    L.push("");
  }

  // The kernel guards are Linux kernel features (bubblewrap, Landlock,
  // seccomp): off Linux there is nothing to install or build, so the table
  // and the summary say "Linux only" and name what stands in for them.
  const linuxGuards = f.platform === undefined || f.platform === "linux";
  L.push("What Mandu enforces on this machine");
  for (const cp of CHOKEPOINTS) {
    const p = PLAIN_CHOKEPOINT[cp.name]!;
    const guard = cp.kernelCrate === null || p.guard === null
      ? ""
      : !linuxGuards
        ? `; kernel ${p.guard}: Linux only (${cp.kernelCrate})${cp.name === "filesystem" && macProfile ? "; a Seatbelt profile blocks reads of your credential files" : ""}`
        : f.kernel[cp.kernelCrate]
          ? `; kernel ${p.guard}: installed (${cp.kernelCrate}), on without root where the kernel allows`
          : `; kernel ${p.guard}: not installed (${cp.kernelCrate}), this layer alone`;
    L.push(`  ${p.label.padEnd(12)}${p.layer} (${cp.component})${guard}`);
  }
  for (const row of gitSandboxRows(f.gitSandbox)) L.push(row);
  L.push("");

  const anyKernel = Object.values(f.kernel).some(Boolean);
  L.push("Summary");
  L.push("  Mandu sits between the AI and its model service, and wraps the network, files and");
  L.push("  commands of the programs the AI starts. All of it runs without root.");
  if (!linuxGuards) {
    L.push(`  The kernel guards are Linux only${f.platform === "darwin" ? "; macOS has none of them" : ""}.`);
    if (macProfile) {
      L.push("  On macOS a Seatbelt profile (sandbox-exec) keeps every program the AI starts from");
      L.push("  reading your credential files (posture: read-blocked). The network and command");
      L.push("  wrappers hold only programs that follow Mandu's settings (its proxy, its wrappers).");
    } else {
      L.push("  A program that ignores Mandu's settings (its proxy, its wrappers) is not held by");
      L.push("  anything on this machine, and it can read your credential files.");
    }
    return L.join("\n") + "\n";
  }
  L.push(
    anyKernel
      ? "  The kernel guards are installed: they hold every program the AI starts, even one that"
      : "  The kernel guards are not installed here, so a program that ignores Mandu's settings",
  );
  L.push(
    anyKernel
      ? "  ignores Mandu's settings, wherever this kernel supports them."
      : "  (its proxy, its wrappers) is not held by the kernel. The npm package includes them for",
  );
  if (!anyKernel) L.push("  Linux x64; on other machines they are built from source.");
  return L.join("\n") + "\n";
}

/** `mandu doctor` — gather + render + print. Always exits 0 (a diagnostic). */
export async function runDoctor(env: Env, layout: Layout, deps: DoctorDeps = realDoctorDeps): Promise<number> {
  const facts = await gatherFacts(env, layout, deps);
  try {
    if (deps.versionReport) facts.install = await deps.versionReport(env, layout);
  } catch {
    // The install report is triage on top; doctor's own rows stand without it.
  }
  process.stdout.write(renderDoctor(facts));
  return 0;
}
