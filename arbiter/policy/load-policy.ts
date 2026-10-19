/**
 * load-policy — load the data-trust policy from a YAML file.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Lifted from
 *     https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/policy/load-policy.ts
 *   Purpose: parse the YAML policy that defines the origin rules (URL / CHANNEL
 *   / DIR allow/blocklists) and per-tool inbound overrides. This is "where the
 *   actual per-tool schema/origin rules come from" — a YAML file. The reference
 *   ships its default ruleset two ways: (1) the TypeScript TOOL_INBOUND_SPEC
 *   built-in (lifted to tool-inbound.ts), and (2) optional YAML overrides loaded
 *   here (the only YAML in the repo is eval-policies/pinchbench.yaml, which is an
 *   EXEC/command policy — out of scope for this inbound lift). So Mandu's
 *   starting inbound policy IS the built-in TOOL_INBOUND_SPEC; this loader is the
 *   mechanism for layering origin lists + tool overrides on top of it.
 *
 *   Adaptation for Mandu — FLAGGED:
 *     - RESTORED (this lift): the `inbound.command` (exec/COMMAND) config shape
 *       (`CommandEntryConfig`) and `getExplicitUntrustedDirPolicyPaths`, which
 *       sub-step 1 had dropped. The COMMAND entries feed
 *       exec-inbound.mergeCommandOverrides via createPolicyEngine; the explicit
 *       untrusted-dir paths are consumed by the FS view-sync / exec layers (the
 *       exec-supervisor's trusted-path resolver). The INBOUND category shapes
 *       (url / channel / dir, new + legacy) and `tools` are preserved exactly.
 *     - Logger messages re-prefixed [Mandu] → [Mandu-policy].
 *
 * ── Config shapes (preferred) ──
 *   inbound:
 *     url:     { default: UNTRUSTED, trustedList: [...] }
 *     channel: { default: TRUSTED,   untrustedList: [...] }
 *     dir:     { default: TRUSTED,   untrustedList: [...] }
 *   tools:
 *     <toolName>: { inbound: <SchemaNode> }
 */

import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import yaml from "js-yaml";

import type { ToolPolicyEntry } from "./tool-overrides.js";
import type { PromptFiltersConfig } from "../prompt-filter/policy.js";

export interface CategoryPolicyConfig {
  default?: "TRUSTED" | "UNTRUSTED";
  trustedList?: string[];
  untrustedList?: string[];
}

// ── Legacy config shapes (deprecated, still parsed for back-compat) ───

export interface LegacyChannelTrustPolicyConfig {
  untrustedChannels?: string[];
}

export interface LegacyUrlTrustPolicyConfig {
  trustedUrls?: string[];
}

export interface LegacyDirTrustPolicyConfig {
  untrustedDirs?: string[];
}

/**
 * A per-command exec-output (COMMAND-category) override. Feeds
 * exec-inbound.mergeCommandOverrides via createPolicyEngine, refining the
 * blanket "exec/Bash stdout is UNTRUSTED" baseline for a pinned command id.
 */
export interface CommandEntryConfig {
  id: string;
  aliases?: string[];
  schema?: Record<string, unknown>;
  trustErrors?: boolean;
  trustHelp?: boolean;
  subcommands?: Record<string, {
    schema: Record<string, unknown>;
    allowedFlags?: string[];
    trustErrors?: boolean;
    trustHelp?: boolean;
  }>;
}

/** A locked-file label declared in the document (policy-surface.md
 *  §2.1): the same act as the dashboard's "Lock it", as law on disk. */
export interface PathLabelEntry {
  /** Absolute path or `~/…`. */
  path: string;
  /** public | any-model | local-model | no-model */
  level: string;
  /** Destinations a any-model path may be released to. */
  bindings?: string[];
  /** Covers the subtree (default true). */
  recursive?: boolean;
  /** Plan 10 §2.4: a regex with ONE capturing group; group 1 of every match
   *  is a secret span of the file, overriding the catalog's shape extractor
   *  (Claude Code's `credentials.files.extract` contract). Expert-only. */
  extract?: string;
  /** Plan 10 §2.1: the programs that may open the RAW file (and are tainted
   *  by it). A bare name, or a pin `{app, path, sha256}` (§11.2). Absent =
   *  every program gets the structured twin; present = exhaustive. An entry
   *  may carry `output: secret | clear | mask` (and `mask:`), what the model
   *  sees of that program's output once it holds THIS file (Plan 13 D3). */
  readers?: Array<string | { app: string; path?: string; sha256?: string; from?: string; output?: "secret" | "clear" | "mask"; mask?: string[]; script?: string; scriptSha256?: string; prints?: "nothing" }>;
  /** With `readers`: what every other program gets (default deny, §3.3). */
  others?: "deny" | "twin";
  /** Plan 13 §5.2: per-value bindings of a structured file, keyed by the
   *  field name its symbol carries (`*` globs). A value without an entry
   *  takes `bindings`; the whole file may go only where every value may
   *  (value-bindings.ts). */
  values?: Record<string, { bindings?: string[] }>;
}

/** An object of a repository labelled by its id (confidentiality-plan-14
 *  §8.2): the blob with this content hash, in every repository. `id` is
 *  `sha1:<40 hex>` or `sha256:<64 hex>`, lowercase; it names content, never
 *  holds it. */
/** One `sensitivity_labels:` entry (plan 14 §14.1): a Purview label's GUID,
 *  optionally its tenant (`site`), the person's name for it and the level a
 *  file carrying it is suggested at (`public`: mapped, suggests nothing). */
export interface SensitivityLabelEntry {
  id: string;
  site?: string;
  name: string;
  /** public | any-model | local-model | no-model */
  level: string;
}

export interface BlobLockEntry {
  id: string;
  /** public | any-model | local-model | no-model */
  level: string;
  /** Where it was found, for the person reading the file (at most 200
   *  characters, one line). Never a value. */
  note?: string;
}

/** Plan 10 §2.2: what a tainted app's output becomes before the model sees it.
 *  DEPRECATED (Plan 13 D3, 2026-10-02): a program-wide rule clears nothing
 *  any more (it cleared every file the program read); the rule lives on the
 *  reader entry of one file, `paths[].readers: [{ app, output }]`. Still
 *  validated and compiled (the delta and the dashboard read it); the
 *  validator warns. */
export interface AppEntry {
  app: string;
  output: "secret" | "clear" | "mask";
  /** `mask` only: regexes whose matches are the secret spans of the output. */
  mask?: string[];
}

/** A user rule (§2.5): today one kind — `release` — "untrusted data from
 *  `from` may (allow) / may not (block) be released to `to`"; `audit` evaluates
 *  and counts without deciding; `off` keeps the row but ignores it. Hosts may
 *  be literal or `@list` references into `lists`. */
export interface UserRuleEntry {
  id: string;
  kind: "release";
  /** Origin host(s); absent = any origin. */
  from?: { host?: string };
  /** Destination host(s); "*" = any destination. */
  to: { host: string };
  mode: "allow" | "block" | "audit" | "off";
  reason?: string;
  by?: string;
  added?: string;
  /** ISO date/time after which the rule is ignored; null/absent = never. */
  expires?: string | null;
}

/** An operator-set disposition on a built-in egress rule that ASKS by default:
 *  `block` denies without asking (nothing is queued). */
export interface RuleDisposition {
  mode: "ask" | "block";
}

/** A destination's REACHABILITY rule (policy-surface.md §2.3, stage
 *  4b): may the agent's processes connect there at all. Exported to the
 *  launcher's connect-guard at launch as an EXTRA allow that keeps the
 *  permissive `*:443` fallback (never as a curation that would drop it) —
 *  so it applies at the NEXT launch, in every posture (strict included).
 *  Release (may masked data be SENT there) is the separate `user_rules`
 *  half. `connect: deny` is reserved: the guard is allow-list only today. */
export interface DestinationEntry {
  /** Host: literal, `*.suffix`, IP/CIDR, `*`, or `@list`. */
  host: string;
  /** TCP/UDP port, or "*" (any). Default 443. */
  port?: number | "*";
  /** Default "tcp". */
  proto?: "tcp" | "udp";
  connect: "allow" | "deny";
  reason?: string;
}

/** Plan 10 §11.4 / §12.1: the environment-variable half of the secret
 *  catalog, as the law may extend it. `secrets` ADDS variable names (or
 *  `PREFIX_*` patterns) whose whole value is a secret beyond the built-in
 *  name shapes; `exempt` names variables the built-in shapes would mask
 *  that must reach the agent in the clear. The agent's own credential and
 *  Mandu's routing variables stay exempt whatever this says. */
export interface EnvSecretsEntry {
  secrets?: string[];
  exempt?: string[];
  /** Variables filled at launch from a keystore or a command instead of the
   *  shell (comparisons.md §3.4): the value is registered as a secret and
   *  the agent's environment gets its placeholder, released at `bindings`. */
  sources?: EnvSourceEntry[];
}

export interface EnvSourceEntry {
  name: string;
  /** `cmd:<shell command>` · `keyring:<service>/<account>` · `op://<vault>/<item>/<field>` */
  source: string;
  /** Hosts the value may be sent to without an ask (confidentiality.md §2). */
  bindings?: string[];
}

/**
 * One declared model endpoint (plan 11 D2). The list is law: an endpoint on
 * it with `local: true` may read `local-model` data in the quarantined helper
 * role; every endpoint NOT on it is external. `local` is never inferred from
 * the address (a loopback gateway may forward to a cloud vendor).
 */
export interface ModelEndpointEntry {
  /** Unique name; `inspect-mcp` passes it on `resolve(deep, endpoint)`. */
  name: string;
  /** http(s) origin, optionally with a path prefix. */
  url: string;
  /** Wire protocol: `anthropic` (Messages API, the default) or `openai-chat`. */
  wire?: "anthropic" | "openai-chat";
  /** The model name to request, when the server serves several. */
  model?: string;
  /** Declared to run on hardware the operator controls. Default false. */
  local?: boolean;
  /** Name of an environment variable holding a bearer token (never the token). */
  token_env?: string;
  /** The quarantined helper's model when several entries are `local: true`.
   *  At most one entry, and only a `local: true` one; without it the helper
   *  uses the first `local: true` entry. */
  helper?: boolean;
  /** Plan 12 D2: accept plain http to a `local: true` entry on another
   *  machine (the helper only; refused on an https url). Default false. */
  allow_plain_http?: boolean;
  /** Plan 12 D3: how Mandu checks this endpoint's identity when it dials it
   *  (the helper, the model proxy's upstream, doctor). https only. */
  tls?: ModelTlsEntry;
  /** Plan 12 D5: `{ name, disabled: true }` in the user's file removes the
   *  administrator's entry of that name (admin-layer.ts); nothing else. */
  disabled?: boolean;
}

/** policy.yaml `models[].tls` (plan 12 D3). Paths only: a key never goes in
 *  the file. `~/` is the user's home. */
export interface ModelTlsEntry {
  /** A PEM bundle added to the default trust store for this endpoint only. */
  ca_file?: string;
  /** base64 SHA-256 of a SubjectPublicKeyInfo; any one in the chain matches. */
  pin_sha256?: string[];
  /** A client certificate (PEM) and its private key, for mutual TLS. Both or neither. */
  client_cert?: string;
  client_key?: string;
}

export interface PolicyFileConfig {
  /** Document format version (1). */
  version?: number;
  /** Named reusable host/URL/path lists, referenced as `@name`. */
  lists?: Record<string, string[]>;
  paths?: PathLabelEntry[];
  /** Plan 14 §8.2: repository objects labelled by id (`lock-blob`). */
  blobs?: BlobLockEntry[];
  rules?: Record<string, RuleDisposition>;
  user_rules?: UserRuleEntry[];
  /** Reachability rules exported to the launcher's connect-guard (§2.3, 4b). */
  destinations?: DestinationEntry[];
  /** Plan 10 §2.2: per-app output rules once tainted. */
  apps?: AppEntry[];
  /** Plan 10 §11.4: environment-variable names to add to / exempt from the mask. */
  env?: EnvSecretsEntry;
  /** Who may use the ssh-agent socket (comparisons.md §3.5). Absent =
   *  every program may, as without Mandu. */
  ssh_agent?: { readers: Array<string | { app: string; path?: string; sha256?: string; from?: string }> };
  /** Paths no program in the agent's tree may delete or rename (the guard
   *  refuses with EACCES). Absolute or `~/…`. Absent = no delete guard. */
  protect?: string[];
  /** Plan 10 §11.18: tools Mandu has no mapping for whose results the
   *  person lets through (mapped-tools.ts). Absent = none: every such
   *  result is masked whole with the confidentiality axis on. */
  mapped_tools?: string[];
  /** confidentiality.md §2.3: the default catalog's issuer bindings (a key
   *  whose format names its issuer goes to that issuer's API host, in the
   *  Authorization header over HTTPS, without asking). Absent or `true`:
   *  on; `false`: off; a mapping: on except the issuers and value names it
   *  lists (issuer-bindings.ts). */
  issuer_bindings?: boolean | { issuers_off?: string[]; values_off?: string[] };
  /** Plan 11 D2: declared model endpoints (absent = none; every model is external). */
  models?: ModelEndpointEntry[];
  /** Plan 12 D4: the organization's networks. `networks` (CIDRs) holds a
   *  `local: true` endpoint on another machine to addresses inside them, at
   *  launch and at every connection; `domains` only changes the words
   *  doctor and the dashboard use. */
  perimeter?: { networks?: string[]; domains?: string[] };
  /** Plan 14 §14.1 (4a): the Purview / MIP sensitivity labels the person
   *  maps to levels. It changes what the scans SUGGEST (a labelled Office
   *  file becomes a `lock-path` suggestion), never what is enforced. Also
   *  allowed in the administrator's layer (admin-layer.ts). */
  sensitivity_labels?: SensitivityLabelEntry[];
  /** Confidentiality plan 15 §6: the prompt filter's switches (which
   *  filters run on the human's prompt, each category's action, the
   *  exceptions). The patterns live in packs (prompt-filter/packs.ts). Also
   *  allowed in the administrator's layer, with `locked: true`. */
  prompt_filters?: PromptFiltersConfig;
  inbound?: {
    // New
    url?: CategoryPolicyConfig;
    channel?: CategoryPolicyConfig;
    dir?: CategoryPolicyConfig;
    /** Per-command exec-output overrides (COMMAND category). Restored in this
     * lift; merged by exec-inbound.mergeCommandOverrides. */
    command?: CommandEntryConfig[];
    // Legacy (deprecated)
    "channel-trust"?: LegacyChannelTrustPolicyConfig;
    "url-trust"?: LegacyUrlTrustPolicyConfig;
    "dir-trust"?: LegacyDirTrustPolicyConfig;
  };
  /**
   * Per-tool inbound/outbound overrides. Merged on top of the built-in
   * TOOL_INBOUND_SPEC / outbound resolve maps by `mergeToolOverrides`. See
   * policy/tool-overrides.ts.
   */
  tools?: Record<string, ToolPolicyEntry>;
  /** Unix sockets the agent's tree may connect to beyond the built-in list
   *  (guard-settings.ts; sandbox-security-review-2026-09-28 finding 1):
   *  paths (absolute or `~/`) and `@abstract` names. A relaxation. */
  unix_sockets?: { allow?: string[] };
  /** More paths the agent's tree may not change (`deny`) or must ask before
   *  changing (`ask`), and built-in "runs later" entries dropped
   *  (`unprotect`, a relaxation) (guard-settings.ts; findings 2 and 6). */
  write_protect?: { deny?: string[]; ask?: string[]; unprotect?: string[] };
  /** Network and FUSE mounts whose servers may see what a program holding
   *  a secret looks up there, by mount point and type (guard-settings.ts;
   *  plan 13 §4.9). A relaxation. */
  remote_mounts?: { trust_lookups?: { mount: string; type: string }[] };
}

/**
 * Return explicit DIR policy paths whose file contents should be treated as
 * untrusted data sources. Only enumerable paths are returned; allowlist mode
 * with default=UNTRUSTED has an unbounded untrusted set and cannot be seeded.
 *
 * Restored in this lift: consumed by the FS view-sync / exec layers (e.g. the
 * exec-supervisor's trusted-path resolver, which must NOT treat an explicitly
 * untrusted dir as a trusted script source for command rewriting).
 */
export function getExplicitUntrustedDirPolicyPaths(policyFile: PolicyFileConfig | null): string[] {
  const dirNew = policyFile?.inbound?.dir;
  if (dirNew) {
    return dirNew.default === "UNTRUSTED" ? [] : (dirNew.untrustedList ?? []);
  }
  return policyFile?.inbound?.["dir-trust"]?.untrustedDirs ?? [];
}

interface Logger {
  info(msg: string): void;
  warn(msg: string): void;
}

/**
 * Where the active policy came from — OBSERVABILITY for the dashboard's Policy
 * panel ("law source", policy-surface.md §9.8). Decides nothing; computed once
 * at arbiter start (policy load itself is once-at-start, so the start-time fact
 * is the honest one).
 *
 *   kind "builtin" — no policy file: the built-in inbound spec + intrinsic
 *                    category defaults are the whole law.
 *   kind "file"    — a YAML policy file layers origin lists / overrides on the
 *                    built-ins. `sections` says which parts it actually set.
 *   kind "custom"  — an injected PolicyEngine (tests / embedders); the server
 *                    did not load it and can vouch for nothing beyond that.
 */
export interface PolicyLawSource {
  kind: "builtin" | "file" | "custom";
  /** The path as configured (may be relative); absent for kind "builtin"/"custom". */
  configuredPath?: string;
  /** The absolute path the loader resolved; absent for kind "builtin"/"custom". */
  resolvedPath?: string;
  /** Whether the configured file existed (and parsed) at arbiter start. A
   * configured-but-missing/unparseable file reports kind "builtin" with
   * found:false — the law actually in force IS the built-ins. */
  found?: boolean;
  /** Which parts the loaded file set (only for kind "file"). */
  sections?: {
    url: boolean;
    channel: boolean;
    dir: boolean;
    commandEntries: number;
    toolOverrides: number;
  };
}

const SILENT_LOG: Logger = { info: () => {}, warn: () => {} };

/** Describe the law source for a policyPath (see PolicyLawSource). Re-parses
 * the file fail-soft via loadPolicyFile — a miss or parse error degrades to
 * the honest "built-ins are the law" answer, never a throw. */
export function describeLawSource(
  policyPath: string | undefined,
  basePath: string,
): PolicyLawSource {
  if (!policyPath) return { kind: "builtin" };
  const resolvedPath = resolve(basePath, policyPath);
  const parsed = loadPolicyFile(policyPath, basePath, SILENT_LOG);
  if (parsed === null) {
    return { kind: "builtin", configuredPath: policyPath, resolvedPath, found: false };
  }
  const inbound = parsed.inbound ?? {};
  return {
    kind: "file",
    configuredPath: policyPath,
    resolvedPath,
    found: true,
    sections: {
      url: inbound.url !== undefined || inbound["url-trust"] !== undefined,
      channel: inbound.channel !== undefined || inbound["channel-trust"] !== undefined,
      dir: inbound.dir !== undefined || inbound["dir-trust"] !== undefined,
      commandEntries: inbound.command?.length ?? 0,
      toolOverrides: Object.keys(parsed.tools ?? {}).length,
    },
  };
}

/**
 * Load the data-trust policy from a YAML file.
 * Returns null if policyPath is not set or the file does not exist (the engine
 * then runs on the built-in TOOL_INBOUND_SPEC + intrinsic category defaults).
 */
export function loadPolicyFile(
  policyPath: string | undefined,
  basePath: string,
  log: Logger,
): PolicyFileConfig | null {
  if (!policyPath) return null;

  const resolved = resolve(basePath, policyPath);
  if (!existsSync(resolved)) {
    log.warn(`[Mandu-policy] policy file not found: ${resolved}`);
    return null;
  }

  try {
    const content = readFileSync(resolved, "utf-8");
    const parsed = yaml.load(content) as PolicyFileConfig;
    log.info(`[Mandu-policy] loaded policy file: ${resolved}`);
    return parsed;
  } catch (err) {
    log.warn(`[Mandu-policy] failed to load policy file ${resolved}: ${err}`);
    return null;
  }
}
