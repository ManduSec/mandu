/**
 * secret-discovery — which files get masked out of the agent's world
 * (docs/design/confidentiality/confidentiality.md, §7.2/§7.3).
 *
 * Walks the given roots (HOME + the workspace) and returns the catalog-matching
 * files the launcher will twin (Linux) or deny (macOS). `secret-catalog.ts` is
 * the single matcher — this module only decides WHICH files exist, are
 * readable, and are safe to mask. One exception reads content (2026-10-19,
 * secret-discovery.md §2.6): the catalog's content tier, which reads each
 * small JSON, YAML or TOML config file the walk meets (found-labels.ts
 * decides which) and lists it when a credential is in it. The report
 * carries paths and field names, never a value.
 *
 * THE FOOTGUN THIS MODULE EXISTS TO AVOID (plan decision 3): the fs-gate's
 * SENSITIVE_PATHS includes the AGENT'S OWN credentials (`~/.claude`,
 * `~/.claude.json`, `~/.codex`, …). Those are denied to the agent *as a tool
 * user*, but the agent RUNTIME reads them to start and authenticate — and the
 * runtime lives INSIDE the sandbox we are building. Masking them makes Claude
 * Code unable to launch. Two lists keep the launched agent working, each
 * asserted by a test; do not "simplify" them away by reusing SENSITIVE_PATHS
 * directly:
 *   - AGENT_STORES, excluded in EVERY launch: each agent's own data (its
 *     session store and transcripts, every tool output, its settings), which
 *     it reads and writes raw. Twinning another agent's store would add
 *     nothing over the catalog's path mask and exhaust MAX_FILES.
 *   - AGENT_LOGIN_FILES, keyed by agent (secret-discovery.md §1.10,
 *     2026-10-09): the files an agent logs in with. Only the logins THIS
 *     launch runs on are excluded (`keptLoginOwners`: the launched agent's,
 *     and the AI helper's when it runs that agent's CLI); every other
 *     agent's login is discovered, registered and twinned like any catalog
 *     secret, and a policy.yaml label applies to it. Before, the one global
 *     list left `~/.codex/auth.json` raw and unregistered under `mandu
 *     claude`, and Claude Code's logins raw under `mandu codex`. A caller
 *     that names no launch (an older launcher, `mandu doctor --secrets`
 *     without `--target`) keeps every agent's login out, as before.
 *
 * Only READABLE REGULAR FILES are returned: /etc/shadow is already unreadable
 * to this uid, so masking it is theater (and the bind would fail).
 *
 * MANDU'S OWN STATE (secret-discovery.md §1.9, 2026-09-24): the
 * view state base (the Mandu home's `state/`) is fs-sync's —
 * the arbiter's DB, one shadow repo per workspace, and the AgentView
 * worktrees whose text files fs-sync SYMBOLIZED at seed. The HOME walk PRUNES
 * it and the whole Mandu home around it (`mandu-state`; on-disk-layout.md
 * §3): walking it found the AgentView copies of every
 * workspace ever tracked by the DEPTH of the default base (`.env` at the
 * worktree root sits exactly at MAX_DEPTH; anything nested was already out of
 * reach, and a deeper base leaves all of them raw), spent the file cap on
 * them (137 of 161 on the reference host), and flooded the ledger with the
 * shadow repos' `depth` records. The AgentView copies that matter — those of
 * THIS launch's workspace roots — are found instead THROUGH THE VIEW MAP fs-sync
 * persists (`<stateBase>/workspaces/<id>/workspace.json` → `agentview/`),
 * walked as roots of their own at depth 0; a copy fs-sync already masked
 * (its whole content is symbols) is skipped as `agentview-symbolized`, a raw
 * one is discovered and twinned like its HumanView original.
 *
 * MANDU'S OWN INSTALL (open-source-release checklist a5, 2026-09-26): the
 * installer (`scripts/install.sh`) puts the package in its own npm prefix
 * `~/.local/share/mandu/pkg` and, when the host's Node is too old, a Node in
 * `~/.local/share/mandu/node`. Both sit at MAX_DEPTH under HOME, so their
 * `bin/` and `lib/` were `depth` records and every launch of a fresh install
 * WARNED "secrets NOT covered by the walk" about Mandu's own files. The walk
 * now PRUNES Mandu's own install trees (`mandu-install`), and ONLY those:
 * the running package's root (when it runs from an installed `node_modules/
 * @mandusec/mandu`), and the `pkg`/`node` children of an installer prefix
 * (MANDU_PREFIX, `~/.local/share/mandu`, or the
 * prefix the running package sits in) whose `pkg` really holds the
 * `@mandusec/mandu` package. Matched by REALPATH, never by name: a `pkg` or
 * `node` directory anywhere else is walked as before, and the prefix itself
 * is walked (a stray `~/.local/share/mandu/.env` is still found). See
 * `manduInstallTrees`.
 *
 * Mandu-new (no reference origin).
 */
import { readdirSync, readFileSync, realpathSync, statSync, lstatSync, accessSync, constants } from "fs";
import { homedir } from "os";
import * as path from "path";
import { fileURLToPath } from "url";
import { manduPath } from "../src/generated/mandu-paths.js";
import { AGENTS, type Agent } from "../src/generated/agents.js";
import {
  DOCUMENT_FILE_PROBE_MAX_BYTES, DOCUMENT_FILE_PROBE_MAX_FILES, DOCUMENT_FILE_PROBE_MAX_TOTAL, DOCUMENT_PROBE_MAX_BYTES, DOCUMENT_PROBE_MAX_FILES,
  DOCUMENT_PROBE_MAX_TOTAL, documentProbeCandidate, inSoftwareProject, personalDocumentKind,
} from "./personal-documents.js";
import { documentFormatOf, extractDocumentText, readDocumentBytes, type DocumentTextRead } from "./document-text.js";

/** A PDF or Office document's verdict (§2.8): its kind, `clean` (its text
 *  read and no document found, or no text at all: a scan), or `unread`
 *  (encrypted, unreadable, too long). */
type DocumentFileVerdict = string | "clean" | "unread";

/** The verdicts of the PDF and Office documents a walk extracted, by path,
 *  size, modification time and inode, for this process's lifetime (the
 *  discovery worker serves the arbiter for its lifetime): a launch re-reads
 *  only a file that changed. At most DOCUMENT_FILE_VERDICTS_MAX, the oldest
 *  forgotten first. */
const DOCUMENT_FILE_VERDICTS = new Map<string, DocumentFileVerdict>();
const DOCUMENT_FILE_VERDICTS_MAX = 4096;

function rememberDocumentVerdict(key: string, v: DocumentFileVerdict): void {
  if (DOCUMENT_FILE_VERDICTS.size >= DOCUMENT_FILE_VERDICTS_MAX) {
    const oldest = DOCUMENT_FILE_VERDICTS.keys().next().value;
    if (oldest !== undefined) DOCUMENT_FILE_VERDICTS.delete(oldest);
  }
  DOCUMENT_FILE_VERDICTS.set(key, v);
}

/** One extraction's verdict. Pure. */
export function documentFileVerdict(path: string, r: DocumentTextRead): DocumentFileVerdict {
  if (r.kind === "no-text") return "clean";
  if (r.kind !== "text") return "unread";
  return personalDocumentKind(path, r.text) ?? "clean";
}
import { catalogPrefixesUnder, CONTENT_RULE, DOCUMENT_RULE, isContentRule, GOOSE_DATA_SHAPE_RE, normalizedPrefixes, OPENCODE_DATA_SHAPE_RE, pathConfidentiality, type LabelLookup, type SecretCatalogMatch } from "./secret-catalog.js";
import { CONTENT_PROBE_MAX_FILES, CONTENT_PROBE_MAX_TOTAL, contentProbeCandidate, credentialInDataFile, readCandidate, type ProbeTier } from "./found-labels.js";
import { isSecret, maxConfidentiality, type ConfidentialityLevel } from "../symbol-table/confidentiality.js";
import { getSymbolPattern, hasSymbols } from "../symbol-table/symbol-table.js";

/** The agents whose own data Mandu leaves raw in every launch (AGENT_STORES):
 *  every agent of the agent registry (src/generated/agents.ts, a copy of
 *  scripts/agents/agent-registry.mjs; supported-agents.md §5.7) but OpenClaw,
 *  whose data has no entry here (it is walked like any other file). A
 *  deliberate subset, not the agent list: a store left raw is never masked,
 *  so a new agent fails the type check in AGENT_STORES until its store is
 *  decided (its paths, or its name added to this exclusion). */
export type StoreOwner = Exclude<Agent, "openclaw">;

/**
 * Each agent's own DATA, NEVER masked in any launch, even though the catalog
 * matches it: the session store and transcripts (every tool output as the
 * agent saw it), settings, caches. The agent runtime reads and writes these
 * from inside the sandbox; twinning them bricks it, and another agent's store
 * would add nothing over the catalog's path mask (a command that names it is
 * masked for the AI) while its transcripts used up MAX_FILES. (The fs-gate
 * still asks before the agent READS them as a tool.) The login files inside
 * them are AGENT_LOGIN_FILES, judged per launch. Any spelling the catalog's
 * OPENCODE_DATA_SHAPE_RE / GOOSE_DATA_SHAPE_RE matches is a store too
 * (`storeOwnerOf`).
 */
export const AGENT_STORES: Readonly<Record<StoreOwner, readonly string[]>> = {
  claude: ["~/.claude"],
  codex: ["~/.codex"],
  // OpenCode's own data (opencode.db, OpenCode 2's shell output files): the
  // catalog labels it no-model (secret-catalog.ts), and OpenCode must keep
  // reading and writing it raw.
  opencode: ["~/.local/share/opencode"],
  // Goose's own data and state (the session store, the request log, the
  // prompt history, the CLI logs): labelled no-model by the catalog, read
  // and written raw by Goose itself. Goose's login (secrets.yaml) is keyed
  // by the launcher (agent-login.ts agentOwnCredentialFiles).
  goose: ["~/.local/share/goose", "~/.local/state/goose"],
};

/** The agents whose login files are keyed per launch (AGENT_LOGIN_FILES). */
export type LoginOwner = "claude" | "codex" | "opencode";
export const LOGIN_OWNERS: readonly LoginOwner[] = ["claude", "codex", "opencode"];

/**
 * The files each agent LOGS IN with, at their default places (a directory
 * entry covers what is inside it). Only the logins a launch runs on are left
 * raw (`keptLoginOwners`); in every other launch each is a catalog secret
 * like the rest: discovered, registered and twinned (a structured twin of a
 * JSON file keeps its keys), its values known to the egress gate. Where the
 * agent's environment moves them, `agentLoginPaths` adds those spellings
 * (LOGIN_ENV): `$CLAUDE_CONFIG_DIR/.credentials.json` and `.claude.json`,
 * `$CODEX_HOME/auth.json`, `$XDG_DATA_HOME/opencode/auth.json`.
 */
export const AGENT_LOGIN_FILES: Readonly<Record<LoginOwner, readonly string[]>> = {
  // Claude Code's subscription login, its global config (which also holds
  // the MCP servers' tokens), and the Anthropic SDK's own store.
  claude: ["~/.claude/.credentials.json", "~/.claude.json", "~/.anthropic"],
  // Codex's sign-in (an OpenAI key or ChatGPT tokens) and the OpenAI SDK's store.
  codex: ["~/.codex/auth.json", "~/.openai"],
  // OpenCode's provider keys.
  opencode: ["~/.local/share/opencode/auth.json"],
};

/** The variables that MOVE an agent's login file (AGENT_LOGIN_FILES). The
 *  arbiter is shared and cannot read the session's environment, so the
 *  launcher sends these names and ONLY these (they hold paths); a mirror of
 *  the list lives in launcher/src/secret-setup.ts, pinned by
 *  tests/stack/login-env-parity.test.ts. */
export const LOGIN_ENV: readonly string[] = ["CLAUDE_CONFIG_DIR", "CODEX_HOME", "XDG_DATA_HOME"];

/** The LOGIN_ENV subset of `raw` (a wire field, so untrusted in shape):
 *  known names with absolute string values only. Pure. */
export function pickLoginEnv(raw: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (raw === null || typeof raw !== "object") return out;
  for (const name of LOGIN_ENV) {
    const v = (raw as Record<string, unknown>)[name];
    if (typeof v === "string" && v.startsWith("/")) out[name] = v;
  }
  return out;
}

/** Every spelling of `owner`'s login files for this home and environment
 *  (AGENT_LOGIN_FILES, then the LOGIN_ENV ones), normalized and deduped. A
 *  variable that is not an absolute path is ignored. Pure. */
export function agentLoginPaths(owner: LoginOwner, home: string, env: Readonly<Record<string, string | undefined>> = {}): string[] {
  const abs = (v: string | undefined): string | null => (typeof v === "string" && v.startsWith("/") ? plainPath(v) : null);
  const out = AGENT_LOGIN_FILES[owner].map((raw) => plainPath(expandHome(raw, home)));
  if (owner === "claude") {
    const dir = abs(env["CLAUDE_CONFIG_DIR"]);
    if (dir !== null) out.push(path.posix.join(dir, ".credentials.json"), path.posix.join(dir, ".claude.json"));
  } else if (owner === "codex") {
    const dir = abs(env["CODEX_HOME"]);
    if (dir !== null) out.push(path.posix.join(dir, "auth.json"));
  } else {
    const dir = abs(env["XDG_DATA_HOME"]);
    if (dir !== null) out.push(path.posix.join(dir, "opencode", "auth.json"));
  }
  return [...new Set(out)];
}

/** Which agent logs in with `p` (equal to or inside one of its
 *  `agentLoginPaths`), or null. Pure. */
export function loginOwnerOf(p: string, home: string, env: Readonly<Record<string, string | undefined>> = {}): LoginOwner | null {
  const norm = plainPath(p);
  for (const owner of LOGIN_OWNERS) {
    if (agentLoginPaths(owner, home, env).some((l) => isSelfOrAncestor(l, norm))) return owner;
  }
  return null;
}

/** The launch targets this version knows (keptLoginOwners): the launcher's
 *  (launcher/src/types.ts TARGETS), every agent of the agent registry and
 *  `shell`. A known target keeps only the logins keptLoginOwners names for
 *  it; an unknown one keeps every agent's. So a launch of an agent the
 *  registry gains keeps fewer logins raw, never more. */
export const KNOWN_TARGETS: ReadonlySet<string> = new Set<string>([...AGENTS, "shell"]);

/**
 * The agents whose login files a launch leaves RAW: the launched agent's
 * (`target`), and the AI helper's when it runs an agent's CLI in the
 * agent's world (`ullmBinary`: inspect-mcp's `claude -p` or `codex exec`,
 * launcher/src/parse.ts; absent in the helper's API mode or without the
 * helper). A `shell` target keeps Claude Code's: its routing is Claude
 * Code's (an `ANTHROPIC_BASE_URL`), so a `claude` started inside it is
 * protected and must log in. `openclaw` keeps Claude Code's and Codex's:
 * OpenClaw reads both itself (its `claude-cli` and `codex-cli` auth
 * profiles read `~/.claude/.credentials.json` and `$CODEX_HOME/auth.json`,
 * and its Codex app-server harness, its default for OpenAI's own endpoint,
 * reads `~/.codex/auth.json`). goose keeps none here (Goose's secrets.yaml
 * is keyed by the launcher). No target, or one this version does not know:
 * every agent's, the behavior before per-launch keying (an older launcher,
 * a dry run that names no agent). Pure.
 */
export function keptLoginOwners(target: string | undefined, ullmBinary?: string): ReadonlySet<LoginOwner> {
  if (target === undefined || !KNOWN_TARGETS.has(target)) return new Set(LOGIN_OWNERS);
  const kept = new Set<LoginOwner>();
  if (target === "claude" || target === "shell" || target === "openclaw") kept.add("claude");
  if (target === "codex" || target === "openclaw") kept.add("codex");
  if (target === "opencode") kept.add("opencode");
  if (ullmBinary === "claude" || ullmBinary === "codex") kept.add(ullmBinary);
  return kept;
}

/**
 * The verdict on another agent's login file, one this launch does not keep
 * (secret-discovery.md §1.10): a human label decides (either way, as for any
 * file); otherwise the catalog's secret verdict, and where the catalog has
 * none (a login an agent's variable moved, `CODEX_HOME=~/.config/codex`,
 * `CLAUDE_CONFIG_DIR=~/.claude-work`), `no-model` under the rule
 * `agent-login:<agent>`, as the default place is. The walk, the
 * registration (`registerSecret`) and `mandu why` ask the same. Pure.
 */
export function agentLoginConfidentiality(match: SecretCatalogMatch, owner: LoginOwner): SecretCatalogMatch {
  if (match.rule !== null && match.rule.startsWith("label:")) return match;
  if (match.rule !== null && isSecret(match.level)) return match;
  return { level: "no-model", bindings: [], rule: `agent-login:${owner}` };
}

/**
 * What a SESSION tells a value gate about the logins it leaves raw
 * (secret-discovery.md §1.10 "In the session that runs the agent"): its
 * launched agent and AI helper's CLI (the walk's keying), whether it left
 * every agent's login readable (MANDU_OTHER_AGENT_LOGINS=raw), and where its
 * agents log in (HOME, LOGIN_ENV). The launcher hands it to the session's
 * net-proxy, which sends it with each tripwire scan.
 */
export interface SessionLogins {
  home: string;
  target?: string;
  ullmBinary?: string;
  otherLoginsRaw?: boolean;
  loginEnv?: Record<string, string>;
}

/** `raw` (a wire field) as a SessionLogins, or null when it is not one (no
 *  absolute `home`): then nothing is exempt. Pure. */
export function parseSessionLogins(raw: unknown): SessionLogins | null {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  if (typeof r["home"] !== "string" || !r["home"].startsWith("/")) return null;
  const loginEnv = pickLoginEnv(r["loginEnv"]);
  return {
    home: plainPath(r["home"]),
    ...(typeof r["target"] === "string" && r["target"] !== "" ? { target: r["target"] } : {}),
    ...(typeof r["ullmBinary"] === "string" && r["ullmBinary"] !== "" ? { ullmBinary: r["ullmBinary"] } : {}),
    ...(r["otherLoginsRaw"] === true ? { otherLoginsRaw: true } : {}),
    ...(Object.keys(loginEnv).length > 0 ? { loginEnv } : {}),
  };
}

/**
 * Every spelling of the login files a session leaves raw: the kept owners'
 * (`keptLoginOwners`, the same keying as the walk), or every agent's under
 * MANDU_OTHER_AGENT_LOGINS=raw. Another session may have registered them
 * (registration is global and durable); in THIS session their rows are
 * inert to the egress tripwire, as they were before they were registered
 * anywhere. Only login files: a session cannot exempt any other path. Pure.
 */
export function sessionLoginPaths(s: SessionLogins): string[] {
  const owners = s.otherLoginsRaw === true ? new Set(LOGIN_OWNERS) : keptLoginOwners(s.target, s.ullmBinary);
  const out = new Set<string>();
  for (const o of owners) for (const p of agentLoginPaths(o, s.home, s.loginEnv ?? {})) out.add(p);
  return [...out];
}

/** Is `origin` (a registered row's path) one of `paths` or inside one (a
 *  login directory such as `~/.anthropic`)? Pure. */
export function originUnder(origin: string, paths: readonly string[]): boolean {
  if (!origin.startsWith("/")) return false;
  const norm = plainPath(origin);
  return paths.some((p) => isSelfOrAncestor(p, norm));
}

/** Whose own data `p` is (inside one of AGENT_STORES for this home, or
 *  matched by the catalog's OpenCode / Goose data shapes), or null. A login
 *  file inside a store is still reported here; callers ask `loginOwnerOf`
 *  first. Pure. */
export function storeOwnerOf(p: string, home: string): StoreOwner | null {
  const norm = path.posix.normalize(p);
  for (const [owner, dirs] of storesFor(home)) {
    if (dirs.some((d) => norm === d || norm.startsWith(d + "/"))) return owner;
  }
  if (OPENCODE_DATA_SHAPE_RE.test(norm)) return "opencode";
  if (GOOSE_DATA_SHAPE_RE.test(norm)) return "goose";
  return null;
}

/** What `p` is to an agent, for `mandu why`: one of its login files (kept
 *  raw only by a launch of that agent), one of its stores (raw in every
 *  launch), or neither. Pure. */
export function agentFileOf(p: string, home: string, env: Readonly<Record<string, string | undefined>> = {}): { kind: "login"; agent: LoginOwner } | { kind: "store"; agent: StoreOwner } | null {
  const login = loginOwnerOf(p, home, env);
  if (login !== null) return { kind: "login", agent: login };
  const store = storeOwnerOf(p, home);
  return store === null ? null : { kind: "store", agent: store };
}

/**
 * Directories never walked (noise, size, and no credentials of interest).
 *
 * Cost note (2026-09-17): this walk runs SYNCHRONOUSLY inside the arbiter on
 * every `mandu` launch, so its cost is both launch latency and a freeze of
 * every other client of a shared arbiter. A developer HOME reached 140k
 * entries at depth 4; `~/.ccache` alone was 60k of them. The toolchain and
 * editor caches below hold no credential shapes the catalog knows (compiler
 * objects, package tarballs, node/rust toolchains, the VS Code server), so
 * pruning them loses nothing the twins would have masked. `~/.cargo` is NOT
 * pruned: `~/.cargo/credentials.toml` is a real secret.
 */
export const SKIP_DIRS: ReadonlySet<string> = new Set([
  ".git", "node_modules", "target", "dist", "build", ".venv", "venv",
  "__pycache__", ".cache", ".next",
  ".ccache", ".npm", ".nvm", ".rustup", ".vscode-server", ".vscode-server-insiders",
]);

/**
 * macOS HOME folders never walked (2026-09-29), as DIRECT CHILDREN OF HOME
 * only (a project's own `Library/` or `Music/` folder is walked as before).
 * `~/Library` is app data: Containers, Group Containers, Caches, Mail,
 * Messages; tens of thousands of entries at depth 4 on a used Mac, parts of
 * it TCC-protected (macOS 14+ asks "access data from other apps" on the
 * terminal's behalf, and a denied folder only fills the ledger), and no
 * credential shape the catalog knows OUTSIDE the paths it names there, which
 * are still visited (`catalogPrefixesUnder`, the same re-entry SKIP_DIRS
 * gets). `~/.Trash`, `~/Pictures`, `~/Music`, `~/Movies`: deleted files and
 * media, TCC-protected, no credential shapes. Measured on the development
 * Mac: secret-discovery.md §1. Applied when the host is macOS
 * (DiscoveryOptions.platform, default this process's). Never over a label
 * (`darwinPrune`).
 *
 * Every HOME walk prunes them, through ONE helper (`darwinHomeSkipDirs`,
 * also exposed as `discoveryPrunes(…).homeSkip`), so the walks cannot drift
 * (2026-09-30): this discovery walk, the workspace scan's home tier
 * (secret-workspace-scan.ts) and the known-repository walk (known-repos.ts
 * `findRepositories`). The known-repository walk re-enters them for labels
 * by the same rule (`darwinPrune`: the registry's `label` source walks up
 * from a label, never down to a repository below a labelled folder); the
 * workspace scan re-enters for nothing (a file a label or the catalog
 * covers is never opened, so the prune loses no key finding; it does lose
 * sensitivity labels and model candidates under `Library/CloudStorage` and
 * `Library/Mobile Documents`, plan 14 §11.3). Each says why in its header;
 * only discovery visits catalog paths.
 */
export const DARWIN_HOME_SKIP: readonly string[] = ["Library", ".Trash", "Pictures", "Music", "Movies"];

/** The exact paths of DARWIN_HOME_SKIP under `home` (direct children only)
 *  when `platform` is macOS, else none. The one source of the macOS HOME
 *  prune for every walk (see DARWIN_HOME_SKIP). Pure. */
export function darwinHomeSkipDirs(home: string, platform: NodeJS.Platform = process.platform): ReadonlySet<string> {
  return new Set(platform === "darwin" ? DARWIN_HOME_SKIP.map((n) => path.posix.join(home, n)) : []);
}

/**
 * Package caches and installed third-party packages under HOME
 * (secret-discovery.md §1.9 F): the ONE list of trees whose too-deep
 * directories are recorded as `package-cache` instead of `depth`.
 *
 * It changes the LEDGER, never the walk: these trees are walked exactly as
 * before (to MAX_DEPTH, catalog matches inside them discovered and twinned),
 * only a directory below MAX_DEPTH INSIDE one of them is named
 * `package-cache`, which the launch notice does not count and
 * `mandu doctor --secrets` still lists. Each entry is a tree the package
 * manager fills with downloaded or installed third-party code, never a place
 * a user keeps a credential; the credential files those tools DO read sit
 * OUTSIDE them and stay ordinary walk targets (`~/.cargo/credentials.toml`,
 * `~/.m2/settings.xml`, `~/.gradle/gradle.properties`, `~/.gem/credentials`,
 * `~/.npmrc`). A `*` matches within one path segment (a Python version).
 * These are the HOME-relative defaults; a cache the session's environment
 * MOVES (CARGO_HOME, GOMODCACHE, …) is resolved by RELOCATED_PACKAGE_CACHES
 * from the variables the launcher sends (`DiscoveryOptions.cacheEnv`).
 *
 * Not listed because SKIP_DIRS already prunes them whole (no `depth` record
 * can arise there): `~/.npm`, everything under `~/.cache` (pip, yarn v1,
 * pnpm metadata, go-build), `~/.nvm`, `~/.rustup`.
 */
export const PACKAGE_CACHE_DIRS: readonly string[] = [
  "~/.cargo/registry", // Cargo: crate index, archives, unpacked crate sources
  "~/.cargo/git", // Cargo: git dependencies (bare repos, checkouts)
  "~/go/pkg/mod", // Go module cache (default GOPATH)
  "~/.local/share/pnpm/store", // pnpm content-addressable store (pnpm ≥ 7)
  "~/.pnpm-store", // pnpm store (older default)
  "~/.yarn/berry/cache", // Yarn 2+ global cache
  "~/.bun/install/cache", // Bun package cache
  "~/.m2/repository", // Maven local repository
  "~/.gradle/caches", // Gradle dependency and build caches
  "~/.gradle/wrapper/dists", // Gradle distributions the wrapper downloads
  "~/.nuget/packages", // NuGet global packages folder
  "~/.gem/ruby", // RubyGems user installs
  "~/.local/share/gem/ruby", // RubyGems user installs (XDG layout)
  "~/.local/lib/python*/site-packages", // pip --user installs
  "~/.pyenv/versions", // pyenv's installed Pythons and their packages
  "~/.vscode/extensions", // VS Code extensions (third-party code)
  "~/.cursor/extensions", // Cursor extensions (third-party code)
  // OpenTUI, OpenCode's terminal UI library: the tree-sitter grammars and
  // queries it unpacks (`tree-sitter/languages`, `tree-sitter/queries`, depth
  // 5). Without it every launch after OpenCode's first said "2 places were
  // not searched for secrets" (live first-session walk, 2026-10-11).
  "~/.local/share/opentui",
  // Found on a developer home, 2026-10-11 (secret-discovery.md §1.9 H): the
  // shell plugins oh-my-zsh ships and the ones it clones into its custom
  // folder (third-party code; the user's own `custom/*.zsh` sit above the
  // cap and are walked), the RustSec advisory database cargo-audit and
  // cargo-deny clone, Ollama's downloaded models, and TeX Live's per-user
  // generated caches (`luatex-cache/generic/names`).
  "~/.oh-my-zsh/plugins",
  "~/.oh-my-zsh/custom/plugins",
  "~/.cargo/advisory-db",
  "~/.ollama/models",
  "~/.texlive*/texmf-var",
];

/**
 * The package caches an environment variable MOVES away from its default
 * (secret-discovery.md §1.9 G, 2026-10-09). `CARGO_HOME=/data/cargo` puts
 * Cargo's registry at `/data/cargo/registry`, where the HOME-relative
 * PACKAGE_CACHE_DIRS never match, so its too-deep directories were counted
 * as `depth` in the launch notice. Each row names the variable, the trees
 * under its value that are the cache (`""` = the value itself), and the
 * default it replaces: a PACKAGE_CACHE_DIRS entry, or a SKIP_DIRS cache the
 * default walk prunes whole.
 *
 * A moved cache is treated as a PACKAGE_CACHE_DIRS tree, never as a SKIP_DIRS
 * prune: it is still WALKED to MAX_DEPTH (a catalog match inside it is still
 * discovered and twinned), only a directory below MAX_DEPTH inside it is
 * recorded as the quiet `package-cache` instead of `depth`. Pruning a moved
 * tree whole would make the walk's coverage depend on the session's
 * environment; recording it differently only changes the count.
 *
 * The arbiter is shared by every launch, so the variables are the LAUNCH's
 * (the launcher sends exactly these names, `pickPackageCacheEnv`; a mirror of
 * the name list lives in launcher/src/secret-setup.ts, pinned by
 * tests/stack/package-cache-env-parity.test.ts), never the arbiter's own.
 * `relocatedPackageCaches` ignores a value that is not absolute or that
 * contains HOME or a walk root (`GOMODCACHE=$HOME` must not quiet HOME).
 */
export const RELOCATED_PACKAGE_CACHES: ReadonlyArray<{ env: string; under: readonly string[]; replaces: string }> = [
  { env: "CARGO_HOME", under: ["registry", "git"], replaces: "~/.cargo/registry, ~/.cargo/git" },
  { env: "GOMODCACHE", under: [""], replaces: "~/go/pkg/mod" },
  { env: "GOPATH", under: ["pkg/mod"], replaces: "~/go/pkg/mod" }, // a `:` list: each entry
  { env: "GRADLE_USER_HOME", under: ["caches", "wrapper/dists"], replaces: "~/.gradle/caches, ~/.gradle/wrapper/dists" },
  { env: "RUSTUP_HOME", under: [""], replaces: "~/.rustup (SKIP_DIRS)" },
  { env: "NVM_DIR", under: [""], replaces: "~/.nvm (SKIP_DIRS)" },
  { env: "npm_config_cache", under: [""], replaces: "~/.npm (SKIP_DIRS)" },
  { env: "NPM_CONFIG_CACHE", under: [""], replaces: "~/.npm (SKIP_DIRS)" },
  { env: "XDG_CACHE_HOME", under: [""], replaces: "~/.cache (SKIP_DIRS)" },
  { env: "PIP_CACHE_DIR", under: [""], replaces: "~/.cache/pip (SKIP_DIRS)" },
  { env: "YARN_CACHE_FOLDER", under: [""], replaces: "~/.cache/yarn (SKIP_DIRS)" },
];

/** The variable names RELOCATED_PACKAGE_CACHES reads, in table order. */
export const PACKAGE_CACHE_ENV: readonly string[] = [...new Set(RELOCATED_PACKAGE_CACHES.map((r) => r.env))];

/** The PACKAGE_CACHE_ENV subset of `raw` (a wire field, so untrusted in
 *  shape): known names with non-empty string values only. Pure. */
export function pickPackageCacheEnv(raw: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (raw === null || typeof raw !== "object") return out;
  for (const name of PACKAGE_CACHE_ENV) {
    const v = (raw as Record<string, unknown>)[name];
    if (typeof v === "string" && v !== "") out[name] = v;
  }
  return out;
}

/** Is `dir` equal to `p` or an ancestor of it? Both normalized absolute. */
function isSelfOrAncestor(dir: string, p: string): boolean {
  return p === dir || p.startsWith(dir.endsWith("/") ? dir : dir + "/");
}

/** A normalized absolute path without its trailing `/` (but `/` itself). */
function plainPath(p: string): string {
  const n = path.posix.normalize(p);
  return n.length > 1 && n.endsWith("/") ? n.slice(0, -1) : n;
}

/**
 * The absolute package-cache trees `env` moves (RELOCATED_PACKAGE_CACHES),
 * normalized and deduped. A value that is not absolute, or a tree that is
 * HOME, a walk root, or an ancestor of either, is ignored: it would quiet
 * the user's own trees, not a cache. Pure.
 */
export function relocatedPackageCaches(
  env: Readonly<Record<string, string | undefined>>,
  home: string,
  roots: readonly string[] = [],
): string[] {
  const guarded = [home, ...roots].map(plainPath);
  const out = new Set<string>();
  for (const row of RELOCATED_PACKAGE_CACHES) {
    const raw = env[row.env];
    if (typeof raw !== "string" || raw === "") continue;
    const values = row.env === "GOPATH" ? raw.split(":") : [raw];
    for (const v of values) {
      if (!v.startsWith("/")) continue;
      for (const sub of row.under) {
        const tree = plainPath(sub === "" ? v : path.posix.join(v, sub));
        if (guarded.some((g) => isSelfOrAncestor(tree, g))) continue;
        out.add(tree);
      }
    }
  }
  return [...out];
}

/** Depth cap for the walk (a credential lives near the top of its root). */
export const MAX_DEPTH = 4;
/** Hard cap on masked files — a runaway walk must not produce a 10k-bind argv. */
export const MAX_FILES = 256;
/** The label roots' own budget (`DiscoveryOptions.labelRoots`, 2026-10-17):
 *  the files found under the human's labels count against this, not against
 *  MAX_FILES, so a HOME full of catalog matches cannot crowd out a folder the
 *  human labelled, and a labelled folder cannot crowd out `~/.ssh`. */
export const MAX_LABEL_FILES = 256;
/** How many `skipped` records a report carries verbatim; beyond it only the
 *  per-reason counts grow (a HOME has thousands of agent-auth entries). */
export const MAX_SKIP_RECORDS = 200;
/** An AgentView copy larger than this is not content-checked: it is treated
 *  as raw and discovered (fail toward masking). Catalog matches are small. */
export const AGENTVIEW_CONTENT_CAP = 1 << 20;

/** Options for the walk beyond its roots and home. */
export interface DiscoveryOptions {
  /** fs-sync's view state base (the one the launcher sends);
   *  default `<home>/.mandu/state`, the same default fs-sync uses. Pruned from
   *  the walk; the AgentView copies of the workspace roots are found through
   *  the view map it holds. */
  stateBase?: string;
  /** The environment the install-prefix candidates are read from
   *  (MANDU_PREFIX); default `process.env`. A test knob. */
  installEnv?: Readonly<Record<string, string | undefined>>;
  /** The directory the running Mandu code lives in (its package root is
   *  found from here); default this module's own directory, `null` = none.
   *  A test knob. */
  selfDir?: string | null;
  /** The host platform: on `darwin` the HOME walk prunes DARWIN_HOME_SKIP.
   *  Default this process's. A test knob. */
  platform?: NodeJS.Platform;
  /** The label paths in force (the human and derived label stores' keys:
   *  absolute literals, or gitignore-style patterns), so the macOS HOME
   *  prune never hides a labeled file: a literal under a pruned folder is
   *  visited like a catalog-pinned path, and a pattern that could match
   *  under it (or a label on the folder or an ancestor) keeps the folder
   *  walked. Absent: only the folder's own label is consulted
   *  (`darwinPrune`). */
  labelPaths?: readonly string[];
  /** Confidentiality plan 13 D4: the derived labels' paths (files a process
   *  holding a secret, or a high session, wrote). Each is a candidate
   *  wherever it lies, outside the roots and below the depth cap included,
   *  judged as a file root is (the label must still classify secret: an
   *  exact human `public` label over it wins). Considered after the walk,
   *  so the catalog's own finds keep their place under MAX_FILES. */
  derivedPaths?: readonly string[];
  /** The places the human's labels above `public` lie (2026-10-17,
   *  confidentiality.md §6 "Read by a program the launch did not see"): each
   *  literal label's path and each pattern's literal directory prefix
   *  (label-lookup.ts `labelWalkRoots`). Each is walked as a root of its own,
   *  from depth 0, wherever it lies (outside HOME and the workspace, or below
   *  the depth cap from them), after every other pass and under its own
   *  budget, MAX_LABEL_FILES. A directory root is never entered by another
   *  root's walk (it is walked once, by itself). What it finds is judged as
   *  everything else is: a pattern's prefix is only where to look, the label
   *  lookup still decides which files there are secret. */
  labelRoots?: readonly string[];
  /** The LAUNCH's values of PACKAGE_CACHE_ENV (`CARGO_HOME`, `GOMODCACHE`,
   *  …): the caches they move are recorded like PACKAGE_CACHE_DIRS
   *  (`relocatedPackageCaches`). Absent: the defaults only. */
  cacheEnv?: Readonly<Record<string, string | undefined>>;
  /** The launched agent (the launcher's `--target`): its login files stay
   *  raw (`keptLoginOwners`), every other agent's are discovered. Absent:
   *  every agent's login stays raw, as before per-launch keying. */
  target?: string;
  /** The CLI the AI helper runs in the agent's world (`claude` / `codex`),
   *  absent when it runs none (API mode, no helper): its logins stay raw
   *  too. */
  ullmBinary?: string;
  /** The LAUNCH's values of LOGIN_ENV (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`,
   *  `XDG_DATA_HOME`): where it moves an agent's login file
   *  (`agentLoginPaths`). Absent: the default places only. */
  loginEnv?: Readonly<Record<string, string | undefined>>;
  /** The catalog's CONTENT tier (found-labels.ts, secret-discovery.md
   *  §2.6): read each config-file candidate the walk meets and list it when
   *  it holds a credential (`found`), or report a found label's file it
   *  read clean (`cleared`). Default on; `false` walks names only (and
   *  reads no document either, §2.7). */
  contentTier?: boolean;
  /** The found labels' paths (files an earlier walk found a credential in):
   *  each is a candidate wherever it lies, as a derived path is. */
  foundPaths?: readonly string[];
}

/** Does `p` hold a wildcard (a gitignore-style pattern, path-labels.ts)? */
function isPattern(p: string): boolean {
  return /[*?[]/.test(p);
}

/** A pattern's literal directory prefix (its leading wildcard-free
 *  segments), or "" when it has none or is relative (it can match anywhere). */
function patternPrefix(p: string): string {
  if (!p.startsWith("/")) return "";
  const i = p.search(/[*?[]/);
  const cut = p.lastIndexOf("/", i);
  return cut <= 0 ? "" : p.slice(0, cut);
}

function segmentPrefix(ancestor: string, p: string): boolean {
  return p === ancestor || p.startsWith(ancestor.endsWith("/") ? ancestor : ancestor + "/");
}

/**
 * What the macOS HOME prune does with one DARWIN_HOME_SKIP folder: `walk` it
 * after all (a label covers the folder, or a pattern could match inside it),
 * or prune it and visit exactly the labeled literals under it (the catalog's
 * pinned paths are added by the caller, as for SKIP_DIRS). Pure.
 */
export function darwinPrune(
  dir: string,
  labelPaths: readonly string[] | undefined,
  resolveLabel?: LabelLookup,
): { walk: true } | { walk: false; visit: string[] } {
  // A label on the folder or an ancestor (a recursive directory label)
  // decides for everything inside it: walk, as before the prune.
  if (resolveLabel?.(dir)) return { walk: true };
  const visit: string[] = [];
  for (const raw of labelPaths ?? []) {
    const p = raw.length > 1 && raw.endsWith("/") ? raw.slice(0, -1) : raw;
    if (isPattern(p)) {
      const pre = patternPrefix(p);
      // `**/…`, a relative pattern, or one rooted above/inside the folder
      if (pre === "" || segmentPrefix(pre, dir) || segmentPrefix(dir, pre)) return { walk: true };
      continue;
    }
    if (segmentPrefix(p, dir)) return { walk: true }; // a literal label on the folder or above it
    if (segmentPrefix(dir, p) && !visit.includes(p)) visit.push(p);
  }
  return { walk: false, visit };
}

/** fs-sync's default state base for a home: the path table's `view-state`
 *  under `<home>/.mandu` (fs-sync/src/layout.ts `defaultStateBase` resolves
 *  the same entry). */
export function defaultStateBase(home: string): string {
  return manduPath("view-state", {}, home);
}

export interface DiscoveredSecret {
  /** Absolute path of the file to mask. */
  path: string;
  /** Level the catalog assigned (always a secret level — public never lands here). */
  level: ConfidentialityLevel;
  /** Which catalog rule matched, for the audit/event trail. */
  rule: string;
  /** Another agent's login file (AGENT_LOGIN_FILES), one this launch does
   *  not run on: the launcher leaves it readable under
   *  MANDU_OTHER_AGENT_LOGINS=raw and names it in the launch note. */
  agentLogin?: LoginOwner;
}

/**
 * Why a candidate was NOT discovered (secret-discovery.md §1.3): the
 * "not covered" half of the inventory. Under a "your keys cannot leave"
 * default the user must be told what the walk left raw, so every silent
 * `continue` in the walk has a name here.
 *
 *   agent-auth          an agent's own data (AGENT_STORES): never masked, in any launch
 *   agent-login         a login file this launch runs on (AGENT_LOGIN_FILES,
 *                       `keptLoginOwners`): left raw, the agent logs in with it
 *   symlinked-directory a directory symlink: never descended (points out of the root)
 *   dangling-symlink    a symlinked file whose target is missing or not a regular file
 *   unreadable          a catalog match this uid cannot read (masking is theater)
 *   depth               a directory below MAX_DEPTH: not walked (a secret in it is RAW)
 *   count               a catalog match beyond MAX_FILES: not masked (RAW)
 *   unreadable-dir      a directory the walk could not list
 *   mandu-state       Mandu's own view state base: not walked (its
 *                       AgentView copies are found through the view map)
 *   agentview-symbolized an AgentView copy fs-sync already masked (whole
 *                       content is symbols): nothing raw to twin
 *   mandu-install     Mandu's own install tree (the installer's npm
 *                       prefix and Node, the running package): not walked
 *   package-cache       a directory below MAX_DEPTH inside a package cache
 *                       (PACKAGE_CACHE_DIRS): not walked, as `depth`, but
 *                       downloaded third-party code, so not a launch WARNING
 *   special-file        a catalog match that is a socket, FIFO or device
 *                       (an ssh-agent socket under ~/.ssh): no file to mask
 */
export type SkipReason =
  | "agent-auth"
  | "agent-login"
  | "symlinked-directory"
  | "dangling-symlink"
  | "unreadable"
  | "depth"
  | "count"
  | "unreadable-dir"
  | "mandu-state"
  | "agentview-symbolized"
  | "mandu-install"
  | "package-cache"
  | "special-file";

/** The reasons that are expected and plentiful — recorded after the
 *  consequential ones so those survive the record cap. */
const QUIET_REASONS: ReadonlySet<SkipReason> = new Set<SkipReason>(["agent-auth", "agent-login", "agentview-symbolized", "package-cache", "special-file"]);

export interface SkippedCandidate {
  path: string;
  reason: SkipReason;
}

/** The structured discovery result: the files to mask plus everything the
 *  walk deliberately left out. `counts` is complete; `skipped` is capped at
 *  MAX_SKIP_RECORDS entries (the most consequential reasons — depth, count,
 *  unreadable, dangling — are recorded first, agent-auth last). */
export interface SecretDiscoveryReport {
  files: DiscoveredSecret[];
  skipped: SkippedCandidate[];
  counts: Record<SkipReason, number>;
  /** The caps the walk ran under, so a renderer can say "depth 4" honestly
   *  (`maxLabelFiles`: the label roots' own budget, MAX_LABEL_FILES). */
  limits: { maxDepth: number; maxFiles: number; maxLabelFiles?: number };
  /** True when MAX_FILES stopped the walk before it finished: files beyond
   *  the cap — matches or not — were never examined. */
  truncated: boolean;
  /** Where the `depth` records lie, grouped (secret-discovery.md §1.9 H):
   *  each folder DEPTH_AREA_LEVELS below its walk root (`~/project/app`)
   *  with how many too-deep directories lie under it, the most first, at
   *  most MAX_DEPTH_AREAS of them. Counted over EVERY `depth` record (the
   *  `skipped` list is capped), so a notice can say where they are. */
  depthAreas: DepthArea[];
  /** The content tier (found-labels.ts, secret-discovery.md §2.6): the
   *  config files this walk read and found a credential in (each also in
   *  `files`, rule `content:secret-key`), with the field that decided it
   *  (never a value); the found labels' files it read and found none in
   *  (`cleared`: the arbiter drops their labels); and what it read
   *  (`content`: files read, files a cap left unread). Absent from an
   *  older arbiter's report. The personal documents (personal-documents.ts,
   *  §2.7) are in `found` too, `kind: "document"`, their kind the field
   *  (`bank-statement`), each in `files` with rule
   *  `content:personal-document`; `documents` counts what their own caps
   *  let the walk read. */
  found?: Array<{ path: string; field: string; kind?: "document" }>;
  cleared?: string[];
  content?: { read: number; capped: number };
  documents?: { read: number; capped: number };
}

/** One folder holding `count` directories below the depth cap. */
export interface DepthArea {
  path: string;
  count: number;
}

/** How far below its walk root a `depth` record's folder is named: two
 *  segments name a project (`~/project/app`, `~/.oh-my-zsh/plugins`). */
export const DEPTH_AREA_LEVELS = 2;
/** How many folders `depthAreas` carries (the rest are counted only). */
export const MAX_DEPTH_AREAS = 20;

/** The `depthAreas` of a walk: the folder each too-deep directory lies in,
 *  DEPTH_AREA_LEVELS below the deepest directory root that holds it (its
 *  walk root), counted, the most first (then by path), capped. Pure. */
export function depthAreasOf(dirs: Iterable<string>, dirRoots: readonly string[]): DepthArea[] {
  const counts = new Map<string, number>();
  for (const dir of dirs) {
    let root = "";
    for (const r of dirRoots) if (r.length > root.length && isSelfOrAncestor(r, dir)) root = r;
    const rel = root === "" ? dir.split("/").filter(Boolean) : dir.slice(root.length).split("/").filter(Boolean);
    const area = root === "" ? "/" + rel.slice(0, DEPTH_AREA_LEVELS).join("/") : path.posix.join(root, ...rel.slice(0, DEPTH_AREA_LEVELS));
    counts.set(area, (counts.get(area) ?? 0) + 1);
  }
  return [...counts]
    .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .slice(0, MAX_DEPTH_AREAS)
    .map(([p, count]) => ({ path: p, count }));
}

function expandHome(p: string, home: string): string {
  if (p === "~") return home;
  if (p.startsWith("~/")) return path.posix.join(home, p.slice(2));
  return p;
}

/** The stores expanded for ONE home, once per home: this runs on every
 *  entry of the walk (see the cost note on SKIP_DIRS). */
const storesByHome = new Map<string, ReadonlyArray<[StoreOwner, readonly string[]]>>();
function storesFor(home: string): ReadonlyArray<[StoreOwner, readonly string[]]> {
  let list = storesByHome.get(home);
  if (!list) {
    list = (Object.entries(AGENT_STORES) as Array<[StoreOwner, readonly string[]]>)
      .map(([owner, dirs]) => [owner, dirs.map((raw) => path.posix.normalize(expandHome(raw, home)))] as [StoreOwner, readonly string[]]);
    storesByHome.set(home, list);
  }
  return list;
}

/** Every agent's login files at their default places for ONE home, once per
 *  home (`isAgentAuthPath`). */
const loginsByHome = new Map<string, readonly string[]>();
function defaultLoginPaths(home: string): readonly string[] {
  let list = loginsByHome.get(home);
  if (!list) {
    list = LOGIN_OWNERS.flatMap((o) => agentLoginPaths(o, home));
    loginsByHome.set(home, list);
  }
  return list;
}

/** PACKAGE_CACHE_DIRS compiled for ONE home, once per home (one RegExp each:
 *  the root, then a `/`, so only what lies strictly INSIDE a cache matches). */
const cachesByHome = new Map<string, readonly RegExp[]>();
function packageCachePatterns(home: string): readonly RegExp[] {
  let list = cachesByHome.get(home);
  if (!list) {
    list = PACKAGE_CACHE_DIRS.map((raw) => {
      const abs = path.posix.normalize(expandHome(raw, home));
      const src = abs.split("*").map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("[^/]*");
      return new RegExp(`^${src}/`);
    });
    cachesByHome.set(home, list);
  }
  return list;
}

/** Is `p` strictly inside one of PACKAGE_CACHE_DIRS (for this home), or
 *  inside one of `moved` (absolute trees, `relocatedPackageCaches`)? */
export function isPackageCachePath(p: string, home: string = homedir(), moved: readonly string[] = []): boolean {
  const norm = path.posix.normalize(p);
  return packageCachePatterns(home).some((re) => re.test(norm)) || moved.some((m) => norm !== m && isSelfOrAncestor(m, norm));
}

/** Is `p` an agent's own file: inside one of its stores (AGENT_STORES, the
 *  data shapes) or one of its login files at their default places
 *  (AGENT_LOGIN_FILES), whichever agent and whatever launch? The walks that
 *  only PRUNE use it (the workspace scan, the known-repository walk, the WSL
 *  profile list); discovery decides per launch (`keptLoginOwners`). */
export function isAgentAuthPath(p: string, home: string = homedir()): boolean {
  const norm = plainPath(p);
  if (defaultLoginPaths(home).some((l) => isSelfOrAncestor(l, norm))) return true;
  return storeOwnerOf(norm, home) !== null;
}

/** Is this AgentView copy already fs-sync's mask — its whole content symbols
 *  (one `$MDU:` token per seeded file, whitespace aside)? A human-edited twin
 *  that carries raw lines beside a token is NOT (discovered and twinned); an
 *  unreadable, oversized or otherwise unverifiable copy is NOT either (fail
 *  toward masking). Reads the file; never returns any of it. */
function agentViewCopyIsSymbolized(p: string): boolean {
  try {
    const st = statSync(p);
    if (st.size > AGENTVIEW_CONTENT_CAP) return false;
    const text = readFileSync(p, "utf8");
    if (!hasSymbols(text)) return false;
    const pat = new RegExp(getSymbolPattern().source, "g");
    return text.replace(pat, "").trim() === "";
  } catch {
    return false;
  }
}

function realOrNormalized(p: string): string {
  try {
    return realpathSync(p);
  } catch {
    return path.posix.normalize(p);
  }
}

/**
 * The AgentView worktrees of `roots`, found THROUGH the view map fs-sync
 * persists: every `<stateBase>/workspaces/<id>/workspace.json` whose
 * `workspacePath` is one of the roots or an ancestor of one (a launch from a
 * subdirectory of its git root) names `<id>/agentview` as a root to walk.
 * An unreadable or malformed entry is ignored; a missing or symlinked
 * `agentview` is not walked. Sorted, so the walk (and the report) is stable.
 */
export function agentViewRoots(stateBase: string, roots: readonly string[]): string[] {
  const wsDir = path.posix.join(stateBase, "workspaces");
  let ids: string[];
  try {
    ids = readdirSync(wsDir);
  } catch {
    return [];
  }
  const wanted = roots.map(realOrNormalized);
  const out: string[] = [];
  for (const id of ids.sort()) {
    const dir = path.posix.join(wsDir, id);
    let ws: string | null = null;
    try {
      const meta = JSON.parse(readFileSync(path.posix.join(dir, "workspace.json"), "utf8")) as { workspacePath?: unknown };
      if (typeof meta.workspacePath === "string" && meta.workspacePath.startsWith("/")) ws = path.posix.normalize(meta.workspacePath);
    } catch {
      continue;
    }
    if (ws === null) continue;
    const prefix = ws.endsWith("/") ? ws : ws + "/";
    if (!wanted.some((r) => r === ws || r.startsWith(prefix))) continue;
    const av = path.posix.join(dir, "agentview");
    let st: ReturnType<typeof lstatSync> | undefined;
    try { st = lstatSync(av, { throwIfNoEntry: false }); } catch { st = undefined; }
    if (!st || !st.isDirectory()) continue;
    out.push(av);
  }
  return out;
}

/** The npm package name Mandu ships as (launcher/package.json). */
export const MANDU_PACKAGE_NAME = "@mandusec/mandu";

/** The installer's default prefix for a home (scripts/install.sh `PREFIX`):
 *  the path table's `install-prefix` without its MANDU_PREFIX override. */
export function defaultInstallPrefix(home: string): string {
  return manduPath("install-prefix", {}, home);
}

/** The `name` in `<dir>/package.json`: undefined when there is no
 *  package.json, null when it names nothing usable. */
function packageName(dir: string): string | null | undefined {
  let raw: string;
  try {
    raw = readFileSync(path.posix.join(dir, "package.json"), "utf8");
  } catch {
    return undefined;
  }
  try {
    const name = (JSON.parse(raw) as { name?: unknown }).name;
    return typeof name === "string" ? name : null;
  } catch {
    return null;
  }
}

/** `p`'s realpath when it resolves to a directory, else null. */
function realDir(p: string): string | null {
  try {
    const r = realpathSync(p);
    return statSync(r).isDirectory() ? r : null;
  } catch {
    return null;
  }
}

/** `<realParent>/<name>` when it is a directory itself (not a link), else null. */
function plainChildDir(realParent: string, name: string): string | null {
  const p = path.posix.join(realParent, name);
  try {
    return lstatSync(p, { throwIfNoEntry: false })?.isDirectory() === true ? p : null;
  } catch {
    return null;
  }
}

/**
 * The root of the INSTALLED Mandu package the code in `selfDir` belongs to:
 * the nearest ancestor with a package.json, when that names `@mandusec/mandu`
 * AND sits in a `node_modules` tree (an npm install; a repo checkout's
 * `launcher/` is a workspace, never pruned). Realpath, or null.
 */
export function installedPackageRoot(selfDir: string | null): string | null {
  if (selfDir === null) return null;
  let dir = realDir(selfDir);
  for (let i = 0; dir !== null && i < 8; i++) {
    const name = packageName(dir);
    if (name !== undefined) {
      return name === MANDU_PACKAGE_NAME && dir.split("/").includes("node_modules") ? dir : null;
    }
    const up = path.posix.dirname(dir);
    if (up === dir) return null;
    dir = up;
  }
  return null;
}

/** Is `dir` the installer's npm prefix for Mandu: does it hold the
 *  `@mandusec/mandu` package at `lib/node_modules/@mandusec/mandu`? */
function isManduNpmPrefix(dir: string): boolean {
  return packageName(path.posix.join(dir, "lib", "node_modules", "@mandusec", "mandu")) === MANDU_PACKAGE_NAME;
}

/** Is `dir` a Node distribution as the installer unpacks it (the nodejs.org
 *  tarball layout: `bin/node` + `include/node/node_version.h`)? */
function isNodeDist(dir: string): boolean {
  try {
    return statSync(path.posix.join(dir, "bin", "node")).isFile()
      && statSync(path.posix.join(dir, "include", "node", "node_version.h")).isFile();
  } catch {
    return false;
  }
}

/** This module's own directory (the running Mandu code). */
function defaultSelfDir(): string | null {
  try {
    return path.posix.dirname(fileURLToPath(import.meta.url));
  } catch {
    return null;
  }
}

/**
 * Mandu's own install trees, as REALPATHS (checklist a5; see the header):
 * what the walk prunes as `mandu-install`. Each is verified on disk, never
 * assumed from a name:
 *
 *   - the running package's root, when it runs from an installed
 *     `…/node_modules/@mandusec/mandu` (`installedPackageRoot`);
 *   - for each installer prefix candidate (`env.MANDU_PREFIX`,
 *     `<home>/.local/share/mandu`, and the prefix
 *     the running package sits in when it is `<prefix>/pkg/lib/node_modules/
 *     @mandusec/mandu`): `<prefix>/pkg` when it holds the `@mandusec/mandu`
 *     package, and then `<prefix>/node` when it is a Node distribution. The
 *     prefix itself is NOT a tree: anything else in it is walked.
 *
 * Relative candidates are ignored. Sorted, deduplicated.
 */
export function manduInstallTrees(
  home: string,
  opts: { env?: Readonly<Record<string, string | undefined>>; selfDir?: string | null } = {},
): string[] {
  const env = opts.env ?? process.env;
  const selfDir = opts.selfDir === undefined ? defaultSelfDir() : opts.selfDir;
  const trees = new Set<string>();
  const prefixes: string[] = [];
  const self = installedPackageRoot(selfDir);
  if (self !== null) {
    trees.add(self);
    const suffix = "/pkg/lib/node_modules/@mandusec/mandu";
    if (self.endsWith(suffix)) prefixes.push(self.slice(0, -suffix.length));
  }
  // The table's `install-prefix` (MANDU_PREFIX when set) and its default.
  // XDG_DATA_HOME names no prefix: the table and the installer ignore it.
  prefixes.push(manduPath("install-prefix", env, home), defaultInstallPrefix(home));
  for (const p of prefixes) {
    if (!p.startsWith("/")) continue;
    const prefix = realDir(p);
    if (prefix === null) continue;
    // A real directory, never a link: a `pkg` symlink would name a tree
    // elsewhere (the walk never descends a directory link anyway).
    const pkg = plainChildDir(prefix, "pkg");
    if (pkg === null || !isManduNpmPrefix(pkg)) continue;
    trees.add(pkg);
    const node = plainChildDir(prefix, "node");
    if (node !== null && isNodeDist(node)) trees.add(node);
  }
  return [...trees].sort();
}

function isReadableFile(p: string): boolean {
  try {
    // stat (follows a symlinked FILE to its target): the walk above already
    // refused symlinked DIRECTORIES; here a link to something unreadable
    // (~/.aws/creds → /etc/shadow) fails the R_OK check below, so we never
    // mask what we cannot read.
    const st = statSync(p, { throwIfNoEntry: false });
    if (!st || !st.isFile()) return false;
    accessSync(p, constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * Discover the secret files to mask under `roots` (typically HOME + the
 * workspace roots). Readable regular files only; the agent's own auth is
 * excluded; the walk is depth- and count-capped. Deterministic order (sorted)
 * so the resulting bind argv — and therefore the tests — are stable.
 *
 * The files-only view of `discoverSecretsReport`; kept for the callers that
 * need nothing else.
 */
export function discoverSecretFiles(
  roots: readonly string[],
  home: string = homedir(),
  resolveLabel?: LabelLookup,
  opts: DiscoveryOptions = {},
): DiscoveredSecret[] {
  return discoverSecretsReport(roots, home, resolveLabel, opts).files;
}

/** The walk's prunes of Mandu's own trees, for one home (shared with the
 *  plan 14 §13 workspace scan, secret-workspace-scan.ts, so the two walks
 *  cannot drift). */
export interface DiscoveryPrunes {
  /** The launch's view state base (normalized); its view map is read. */
  stateBase: string;
  /** Mandu's own state, never walked (`mandu-state`): the base, the Mandu
   *  home around it, and the defaults. Normalized absolute paths. */
  stateDirs: ReadonlySet<string>;
  /** Is this directory (`full`, its basename `name`) one of Mandu's own
   *  install trees (`mandu-install`), matched by REALPATH? */
  isInstallTree: (full: string, name: string) => boolean;
  /** macOS (`opts.platform`): HOME's app-data and media folders, by their
   *  exact path under this home (`darwinHomeSkipDirs`); empty elsewhere.
   *  Discovery re-enters them for labels and catalog paths (`darwinPrune`);
   *  the workspace scan, which needs neither, prunes them outright. */
  homeSkip: ReadonlySet<string>;
}

/** The prunes `discoverSecretsReport` applies besides SKIP_DIRS and the
 *  agents' own files (AGENT_STORES, the kept AGENT_LOGIN_FILES; a walk that
 *  only prunes uses `isAgentAuthPath`). Pure but for the install trees'
 *  realpaths, read once here and once per directory whose basename is one
 *  of theirs. */
export function discoveryPrunes(home: string, opts: DiscoveryOptions = {}): DiscoveryPrunes {
  const stateBase = path.posix.normalize(expandHome(opts.stateBase ?? defaultStateBase(home), home));
  // Pruned: the launch's base, the conventional default, and the Mandu home
  // around each — a base under a moved MANDU_HOME leaves the default behind,
  // and that is still Mandu's own state, not the user's credentials. Since
  // on-disk-layout.md phase 4 the base is always the home's `state/`, so its
  // parent IS the moved home: pruned there, a home deeper than the walk's
  // depth limit is recorded as Mandu's, not as "below depth". The view map is
  // read from the launch's base only (the one this launch's fs-sync writes).
  const homeOf = (base: string): string[] => (path.posix.basename(base) === "state" ? [path.posix.dirname(base)] : []);
  const stateDirs = new Set(
    [stateBase, ...homeOf(stateBase), defaultStateBase(home), manduPath("mandu-home", {}, home)]
      .map((p) => path.posix.normalize(p)),
  );
  // Mandu's own install trees (header; `manduInstallTrees`), matched by
  // REALPATH. Only a directory whose basename is one of theirs pays the
  // realpath: this check runs on every directory of the walk.
  const installTrees = new Set(manduInstallTrees(home, { env: opts.installEnv, selfDir: opts.selfDir }));
  const installNames = new Set([...installTrees].map((t) => path.posix.basename(t)));
  const isInstallTree = (full: string, name: string): boolean => {
    if (!installNames.has(name)) return false;
    try { return installTrees.has(realpathSync(full)); } catch { return false; }
  };
  return { stateBase, stateDirs, isInstallTree, homeSkip: darwinHomeSkipDirs(home, opts.platform ?? process.platform) };
}

/** The walk with its "not covered" ledger (secret-discovery.md §1
 *  §3): the same files as `discoverSecretFiles`, plus every candidate the
 *  walk skipped and why, and whether a cap truncated it. */
export function discoverSecretsReport(
  roots: readonly string[],
  home: string = homedir(),
  resolveLabel?: LabelLookup,
  opts: DiscoveryOptions = {},
): SecretDiscoveryReport {
  const out = new Map<string, DiscoveredSecret>();
  const counts: Record<SkipReason, number> = {
    "agent-auth": 0, "agent-login": 0, "symlinked-directory": 0, "dangling-symlink": 0, "unreadable": 0,
    "depth": 0, "count": 0, "unreadable-dir": 0, "mandu-state": 0, "agentview-symbolized": 0,
    "mandu-install": 0, "package-cache": 0, "special-file": 0,
  };
  // The agents' login files, per launch (secret-discovery.md §1.10): the
  // ones this launch runs on stay raw (`agent-login`), every other agent's is
  // judged like any file below (labels, then the catalog), and tagged.
  const loginEnv = opts.loginEnv ?? {};
  const kept = keptLoginOwners(opts.target, opts.ullmBinary);
  const loginLists = LOGIN_OWNERS.map((o) => [o, agentLoginPaths(o, home, loginEnv)] as const);
  const allLogins = [...new Set(loginLists.flatMap(([, ls]) => ls))];
  const loginOf = (p: string): LoginOwner | null => {
    for (const [owner, ls] of loginLists) if (ls.some((l) => isSelfOrAncestor(l, p))) return owner;
    return null;
  };
  /** What an agent's file is to this launch: `kept` (a login it runs on,
   *  skipped as `agent-login`), `store` (an agent's own data, skipped as
   *  `agent-auth`), another agent's login (judged like any file), or null. */
  const agentFile = (p: string): { kind: "kept" } | { kind: "store" } | { kind: "other"; owner: LoginOwner } | null => {
    const owner = loginOf(p);
    if (owner !== null) return kept.has(owner) ? { kind: "kept" } : { kind: "other", owner };
    return storeOwnerOf(p, home) !== null ? { kind: "store" } : null;
  };
  /** The verdict on `p`: labels, then the catalog; for another agent's
   *  login with neither, `no-model` (`agentLoginConfidentiality`: a login a
   *  variable moved out of the catalog's places is a login all the same). */
  const judge = (p: string, owner: LoginOwner | undefined): SecretCatalogMatch => {
    const m = pathConfidentiality(p, home, resolveLabel);
    return owner === undefined ? m : agentLoginConfidentiality(m, owner);
  };
  /** Other agents' login files the walk reached (the moved-login pass
   *  below visits the rest). */
  const loginsReached = new Set<string>();
  // macOS: HOME's app-data and media folders (`homeSkip`, DARWIN_HOME_SKIP),
  // by their exact path under this home, pruned like SKIP_DIRS
  // (catalog-pinned subpaths and labeled literals still visited).
  const { stateBase, stateDirs, isInstallTree, homeSkip } = discoveryPrunes(home, opts);
  // The roots, each walked ONCE (§1.9 G): a workspace that IS HOME sent
  // `[home, home]` and doubled every count and every record.
  const rootList = [...new Set(roots.map((root) => plainPath(expandHome(root, home))))];
  // The directory roots (spelled as the walk spells them). A directory one
  // root's walk finds too deep that ANOTHER root's walk reaches within
  // MAX_DEPTH (the workspace under HOME: `~/proj/a/b/c` is depth 5 from HOME,
  // depth 3 from `~/proj`) is walked, not missed: no `depth` record (§1.9 F).
  // Sound because every prune is by basename or by absolute path, the same in
  // both walks, and the HOME walk reached it through real directories only.
  const dirRoots: string[] = [];
  for (const r of rootList) {
    try { if (statSync(r, { throwIfNoEntry: false })?.isDirectory()) dirRoots.push(r); } catch { /* not walked: covers nothing */ }
  }
  // The label roots (opts.labelRoots, 2026-10-17): every one that is not a
  // root already, and never `/` (a pattern with no literal prefix, which the
  // guard gates at the open; walking the whole filesystem is no bounded walk).
  const labelRootList = [...new Set((opts.labelRoots ?? []).map((r) => plainPath(expandHome(r, home))))]
    .filter((r) => r.startsWith("/") && r !== "/" && !rootList.includes(r));
  // Spelled through no symlink: a bind over a path with a symlinked parent
  // bricks the launch (the 2026-09-05 note in `consider`), so a label root
  // that is not its own real path is not walked (its files are still gated
  // by the guard at the open, and judged where a real root reaches them).
  const realSpelled = (p: string): boolean => { try { return realpathSync(p) === p; } catch { return false; } };
  const labelDirRoots: string[] = [];
  for (const r of labelRootList) {
    try { if (statSync(r, { throwIfNoEntry: false })?.isDirectory() && realSpelled(r)) labelDirRoots.push(r); } catch { /* not walked: covers nothing */ }
  }
  const allDirRoots = [...dirRoots, ...labelDirRoots];
  const walkedFromAnotherRoot = (dir: string): boolean => allDirRoots.some((r) => {
    const prefix = r.endsWith("/") ? r : r + "/";
    return dir.startsWith(prefix) && dir.slice(prefix.length).split("/").length <= MAX_DEPTH;
  });
  // A directory root INSIDE another (the workspace under HOME, a labelled
  // folder under either) is walked by its own root from depth 0, which
  // reaches everything the outer walk would, deeper: the outer walk does not
  // enter it (§1.9 G), so its subtree is walked once and its records are not
  // counted twice.
  const nestedRoots = new Set(allDirRoots.filter((r) => allDirRoots.some((o) => o !== r && isSelfOrAncestor(o, r))));
  // The caches the launch's environment moves (RELOCATED_PACKAGE_CACHES).
  const movedCaches = relocatedPackageCaches(opts.cacheEnv ?? {}, home, dirRoots);
  // Two tiers so the consequential records survive the cap: agent-auth and
  // the AgentView copies fs-sync masked are expected and plentiful
  // (~/.claude/* alone), the rest are what a user must see. Merged at the
  // end, consequential first.
  const skippedMain: SkippedCandidate[] = [];
  const skippedQuiet: SkippedCandidate[] = [];
  // Every `depth` record's directory, for `depthAreas` (the records cap).
  const deepDirs: string[] = [];
  let truncated = false;
  const skip = (p: string, reason: SkipReason): void => {
    counts[reason] += 1;
    if (QUIET_REASONS.has(reason)) {
      if (skippedQuiet.length < MAX_SKIP_RECORDS) skippedQuiet.push({ path: p, reason });
    } else if (skippedMain.length < MAX_SKIP_RECORDS) {
      skippedMain.push({ path: p, reason });
    }
  };
  // A cap hit is recorded once per entry it stops, but only while the walk is
  // still enumerating: the first time MAX_FILES is reached inside a directory
  // the REST of that directory's entries are unexamined, and so is every
  // directory not yet visited. `truncated` says so; the `count` records name
  // the catalog matches we did see and could not mask.
  // The cap in force: MAX_FILES, then the label roots' own budget on top of
  // what the passes before them found (MAX_LABEL_FILES).
  let limit = MAX_FILES;
  const capped = (): boolean => out.size >= limit;

  // The content tier (found-labels.ts, secret-discovery.md §2.6): a config
  // file a walk root's walk meets is READ, within its own caps, and listed
  // when it holds a credential. `root` is the directory root the walk
  // descends from (null: a pass that reads no content); the tier is HOME's
  // (a tool's dot-directory only) or a workspace's.
  const contentOn = opts.contentTier !== false;
  const found: Array<{ path: string; field: string; kind?: "document" }> = [];
  const cleared = new Set<string>();
  const content = { read: 0, capped: 0, bytes: 0 };
  const documents = { read: 0, capped: 0, bytes: 0 };
  const documentFiles = { read: 0, bytes: 0 };
  // The document tier's project test (personal-documents.ts
  // `inSoftwareProject`): each directory's names, listed once.
  const listings = new Map<string, ReadonlySet<string>>();
  const listing = (dir: string): ReadonlySet<string> => {
    let names = listings.get(dir);
    if (names === undefined) {
      try { names = new Set(readdirSync(dir)); } catch { names = new Set(); }
      listings.set(dir, names);
    }
    return names;
  };
  /** The content tier's verdict on one regular file: its deciding field (a
   *  config file's credential, or a personal document's kind), `clean`
   *  (read, nothing found), or null (not a candidate, or unread). */
  const probe = (full: string, root: string | null): { field: string; kind?: "document" } | "clean" | null => {
    if (!contentOn || root === null) return null;
    const tier: ProbeTier = isSelfOrAncestor(root, home) ? "home" : "workspace";
    const base = tier === "home" ? home : root;
    if (!isSelfOrAncestor(base, full) || full === base) return null;
    const rel = full.slice(base.endsWith("/") ? base.length : base.length + 1).split("/");
    if (contentProbeCandidate(rel, tier)) {
      if (content.read >= CONTENT_PROBE_MAX_FILES || content.bytes >= CONTENT_PROBE_MAX_TOTAL) { content.capped++; return null; }
      const text = readCandidate(full);
      if (text === null) return null;
      content.read++;
      content.bytes += text.length;
      const field = credentialInDataFile(full, text);
      return field === null ? "clean" : { field };
    }
    // A personal document (§2.7): a text file outside any software project
    // below the walk root (its directories from the root's child down).
    if (!documentProbeCandidate(rel, tier)) return null;
    const dirs: string[] = [];
    for (let i = 0, d = base; i < rel.length - 1; i++) dirs.push((d = path.posix.join(d, rel[i]!)));
    if (inSoftwareProject(dirs, listing)) return null;
    // A PDF or Office document (§2.8): its text extracted (document-text.ts)
    // and decided as a text document's, within its own caps; a verdict is
    // remembered by size, time and inode (`DOCUMENT_FILE_VERDICTS`).
    const format = documentFormatOf(full);
    if (format !== null) {
      const st = lstatSync(full, { throwIfNoEntry: false });
      if (!st || !st.isFile() || st.size === 0 || st.size > DOCUMENT_FILE_PROBE_MAX_BYTES) return null;
      const key = `${full}\u0000${st.size}\u0000${st.mtimeMs}\u0000${st.ino}`;
      let verdict = DOCUMENT_FILE_VERDICTS.get(key);
      if (verdict === undefined) {
        if (documentFiles.read >= DOCUMENT_FILE_PROBE_MAX_FILES || documentFiles.bytes >= DOCUMENT_FILE_PROBE_MAX_TOTAL) { documents.capped++; return null; }
        const bytes = readDocumentBytes(full, DOCUMENT_FILE_PROBE_MAX_BYTES);
        if (bytes === null) return null;
        documentFiles.read++;
        documentFiles.bytes += bytes.length;
        documents.read++;
        verdict = documentFileVerdict(full, extractDocumentText(bytes, format));
        rememberDocumentVerdict(key, verdict);
      }
      // An encrypted, unreadable or too long file is UNREAD: an earlier
      // label stays (raise-only), none is added.
      if (verdict === "unread") return null;
      return verdict === "clean" ? "clean" : { field: verdict, kind: "document" };
    }
    if (documents.read >= DOCUMENT_PROBE_MAX_FILES || documents.bytes >= DOCUMENT_PROBE_MAX_TOTAL) { documents.capped++; return null; }
    const text = readCandidate(full, DOCUMENT_PROBE_MAX_BYTES);
    if (text === null) return null;
    documents.read++;
    documents.bytes += text.length;
    const kind = personalDocumentKind(full, text);
    return kind === null ? "clean" : { field: kind, kind: "document" };
  };

  // `agentView`: this root is an AgentView worktree reached through the view
  // map — a catalog match whose content fs-sync already symbolized is not a
  // raw secret and is skipped by name; everything else is discovered as usual.
  const visit = (dir: string, depth: number, agentView = false, root: string | null = null): void => {
    if (depth > MAX_DEPTH) {
      if (walkedFromAnotherRoot(dir)) return;
      const reason = isPackageCachePath(dir, home, movedCaches) ? "package-cache" : "depth";
      skip(dir, reason);
      if (reason === "depth") deepDirs.push(dir);
      return;
    }
    if (capped()) { truncated = true; return; }
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      skip(dir, "unreadable-dir");
      return; // unreadable dir — nothing we could mask in it anyway
    }
    for (const name of entries) {
      // Past the cap the REST of this directory is still classified (bounded:
      // one readdir's worth of lstat + catalog match) so a match the cap
      // leaves raw is named `count`; directories not yet visited are not
      // entered at all — that is what `truncated` reports.
      consider(path.posix.join(dir, name), name, depth, agentView, root);
    }
  };

  // One directory entry: skip it, descend into it, or register it.
  const consider = (full: string, name: string, depth: number, agentView: boolean, root: string | null = null): void => {
    // Mandu's own state base is never walked (see the header): its
    // AgentView copies are reached through the view map below, the rest
    // of it (the arbiter's DB, the shadow repos) holds no catalog shape.
    if (stateDirs.has(full)) { skip(full, "mandu-state"); return; }
    // THE footgun (see header): the logins this launch runs on and every
    // agent's own data stay raw. Another agent's login goes on below.
    const agent = agentFile(full);
    if (agent?.kind === "kept") { skip(full, "agent-login"); return; }
    if (agent?.kind === "store") {
      skip(full, "agent-auth");
      // The login files inside a store (`~/.claude/.credentials.json`,
      // `~/.codex/auth.json`) are judged on their own. A store that is a
      // file, or one this uid cannot list, has none to visit (lstat throws
      // ENOTDIR / EACCES there, not only ENOENT).
      for (const l of allLogins) {
        if (l === full || !isSelfOrAncestor(full, l)) continue;
        let there = false;
        try { there = lstatSync(l, { throwIfNoEntry: false }) !== undefined; } catch { there = false; }
        if (there) consider(l, path.posix.basename(l), depth + 1, agentView);
      }
      return;
    }
    const otherLogin = agent?.kind === "other" ? agent.owner : undefined;
    // lstat, never stat, for the walk decision: a SYMLINKED DIRECTORY is
    // NEVER descended — it points out of the root by construction. Found the
    // hard way (2026-09-05): `~/tools/linux → /mnt/…` dragged a kernel tree's
    // `Documentation/security/credentials.rst` into the registry via the
    // `*credentials*` shape, and the twin bind over that unresolved path
    // bricked EVERY launch on the host (bwrap cannot mkdir a mount point
    // through a symlinked parent). A symlinked FILE stays a candidate: the
    // launcher's twin planner binds on its resolved target.
    const lst = lstatSync(full, { throwIfNoEntry: false });
    if (!lst) return;
    if (lst.isSymbolicLink()) {
      // `throwIfNoEntry` covers ENOENT only: a symlink LOOP (a → b → a)
      // throws ELOOP out of stat and, uncaught, refused every launch on a
      // home that had one (fixture-home table, 2026-09-24). A loop is a
      // dangling link for our purposes: nothing to mask.
      let target: ReturnType<typeof statSync> | undefined;
      try { target = statSync(full, { throwIfNoEntry: false }); } catch { target = undefined; }
      if (!target || !target.isFile()) {
        // A directory link is the 2026-09-05 brick; a dangling link is
        // nothing to mask. Both are named only when they LOOK like a secret
        // (a catalog match), so the ledger is not every link in HOME.
        const looks = pathConfidentiality(full, home, resolveLabel);
        if (looks.rule !== null && isSecret(looks.level)) {
          skip(full, target?.isDirectory() ? "symlinked-directory" : "dangling-symlink");
        } else if (target?.isDirectory()) {
          skip(full, "symlinked-directory");
        }
        return;
      }
    } else if (lst.isDirectory()) {
      if (nestedRoots.has(full)) return; // walked as a root of its own (above)
      if (isInstallTree(full, name)) { skip(full, "mandu-install"); return; }
      // macOS HOME prune (DARWIN_HOME_SKIP): never over a label; a labeled
      // literal inside the folder is visited like a catalog-pinned path.
      const mac = homeSkip.has(full) ? darwinPrune(full, opts.labelPaths, resolveLabel) : null;
      if (SKIP_DIRS.has(name) || (mac !== null && !mac.walk)) {
        // Pruned wholesale, except a credential the catalog names inside
        // it (`~/.cache/huggingface/token`, a `~/Library/…` path): visit
        // exactly those paths.
        const pinned = new Set(catalogPrefixesUnder(full, home));
        if (mac !== null && !mac.walk) for (const p of mac.visit) pinned.add(p);
        for (const p of pinned) {
          if (lstatSync(p, { throwIfNoEntry: false })) consider(p, path.posix.basename(p), depth + 1, agentView);
        }
        return;
      }
      if (capped()) { truncated = true; return; }
      // Only descend into a directory if it is itself catalog-matching (e.g.
      // ~/.ssh, ~/.aws) or we are still shallow enough that a project-local
      // secret (.env) could live below it.
      visit(full, depth + 1, agentView, root);
      return;
    }
    // The USER label wins over the catalog (Plan 6, §6) — so a labeled file
    // (or any file under a labeled directory) is discovered and twinned by
    // this same walk, and a file the user labeled `public` is NOT.
    if (otherLogin !== undefined) loginsReached.add(full);
    let match = judge(full, otherLogin);
    // The content tier: a config file no label and no path rule covers (or
    // one only an earlier walk's found label covers) is read. A credential
    // in it lists it; none in it clears an earlier found label.
    // A personal document likewise (§2.7): found lists it, read clean
    // clears its label.
    if (otherLogin === undefined && !agentView && (match.rule === null || isContentRule(match.rule))) {
      const v = lst.isFile() ? probe(full, root) : null;
      if (v === "clean") {
        if (isContentRule(match.rule)) cleared.add(full);
        return;
      }
      if (v !== null) {
        found.push({ path: full, field: v.field, ...(v.kind ? { kind: v.kind } : {}) });
        match = { level: "no-model", bindings: [], rule: v.kind === "document" ? DOCUMENT_RULE : CONTENT_RULE };
      }
    }
    // BOTH conditions. A `public` USER LABEL returns a non-null rule with a
    // non-secret level — checking only `rule` (which sufficed while the
    // catalog was the sole source, since it never emits a public rule) would
    // twin a file the human explicitly declassified.
    if (match.rule === null || !isSecret(match.level)) return;
    // A socket, FIFO or device named like a secret (the ssh-agent's socket
    // under ~/.ssh) holds no file to mask: named, but not as `unreadable`,
    // which is kept for a REGULAR file this uid cannot read (§1.9 F). `lst`
    // here is never a link (a link reaches this line only to a regular file).
    if (lst.isSocket() || lst.isFIFO() || lst.isCharacterDevice() || lst.isBlockDevice()) { skip(full, "special-file"); return; }
    if (!isReadableFile(full)) { skip(full, "unreadable"); return; } // /etc/shadow etc. — masking is theater
    if (agentView && agentViewCopyIsSymbolized(full)) { skip(full, "agentview-symbolized"); return; }
    if (out.size >= limit) { skip(full, "count"); truncated = true; return; }
    out.set(full, { path: full, level: match.level, rule: match.rule, ...(otherLogin !== undefined ? { agentLogin: otherLogin } : {}) });
  };

  const walked = new Set<string>();
  for (const r of rootList) {
    walked.add(r);
    let st: ReturnType<typeof statSync> | undefined;
    try { st = statSync(r, { throwIfNoEntry: false }); } catch { st = undefined; } // ELOOP, EACCES: not a root we can walk
    if (!st) continue;
    if (st.isFile()) {
      const agent = agentFile(r);
      if (agent?.kind === "kept") { skip(r, "agent-login"); continue; }
      if (agent?.kind === "store") { skip(r, "agent-auth"); continue; }
      if (agent?.kind === "other") loginsReached.add(r);
      const match = judge(r, agent?.kind === "other" ? agent.owner : undefined);
      if (match.rule !== null && isSecret(match.level)) {
        if (!isReadableFile(r)) skip(r, "unreadable");
        else if (out.size >= limit) { skip(r, "count"); truncated = true; }
        else out.set(r, { path: r, level: match.level, rule: match.rule, ...(agent?.kind === "other" ? { agentLogin: agent.owner } : {}) });
      }
      continue;
    }
    visit(r, 0, false, r);
  }
  // The AgentView copies of the workspace roots, THROUGH the view map: each
  // worktree is a root of its own (depth 0), so a nested copy is found at the
  // same depth as its HumanView original, wherever the state base lives.
  for (const av of agentViewRoots(stateBase, [...walked])) {
    if (!walked.has(av)) visit(av, 0, true);
  }
  // Plan 13 D4: every derived file, wherever the walk could not reach it. A
  // path that is gone, not a regular file, or no longer classifies secret is
  // skipped without a record (the label outlives its file by design).
  // The found labels' files likewise (the content tier): one this walk read
  // clean is not listed (its label is dropped with this report).
  for (const raw of [...(opts.derivedPaths ?? []), ...(opts.foundPaths ?? [])]) {
    const p = path.posix.normalize(raw);
    if (!p.startsWith("/") || out.has(p) || cleared.has(p)) continue;
    const agent = agentFile(p);
    if (agent?.kind === "kept") { skip(p, "agent-login"); continue; }
    if (agent?.kind === "store") { skip(p, "agent-auth"); continue; }
    let st: ReturnType<typeof statSync> | undefined;
    try { st = statSync(p, { throwIfNoEntry: false }); } catch { st = undefined; }
    if (!st || !st.isFile()) continue;
    if (agent?.kind === "other") loginsReached.add(p);
    const match = judge(p, agent?.kind === "other" ? agent.owner : undefined);
    if (match.rule === null || !isSecret(match.level)) continue;
    if (!isReadableFile(p)) { skip(p, "unreadable"); continue; }
    if (out.size >= limit) { skip(p, "count"); truncated = true; continue; }
    out.set(p, { path: p, level: match.level, rule: match.rule, ...(agent?.kind === "other" ? { agentLogin: agent.owner } : {}) });
  }
  // §1.10: a login an agent's variable MOVED (CODEX_HOME, CLAUDE_CONFIG_DIR,
  // XDG_DATA_HOME) is visited by its own path for every agent this launch
  // does not keep, wherever it is: under no walked root, or below the depth
  // cap. The default places are in HOME, which the launch walks.
  const defaultLogins = new Set(LOGIN_OWNERS.flatMap((o) => agentLoginPaths(o, home)));
  for (const [owner, ls] of loginLists) {
    if (kept.has(owner)) continue;
    for (const p of ls) {
      if (defaultLogins.has(p) || loginsReached.has(p) || out.has(p)) continue;
      const agent = agentFile(p);
      if (agent?.kind !== "other") continue;
      let st: ReturnType<typeof statSync> | undefined;
      try { st = statSync(p, { throwIfNoEntry: false }); } catch { st = undefined; }
      if (!st || !st.isFile()) continue;
      const match = judge(p, agent.owner);
      if (match.rule === null || !isSecret(match.level)) continue;
      if (!isReadableFile(p)) { skip(p, "unreadable"); continue; }
      if (out.size >= limit) { skip(p, "count"); truncated = true; continue; }
      out.set(p, { path: p, level: match.level, rule: match.rule, agentLogin: agent.owner });
    }
  }

  // The label roots (opts.labelRoots, 2026-10-17), last and under their own
  // budget: a folder the human labelled that lies outside HOME and the
  // workspace, below the depth cap from them, or past the file cap, is
  // walked from its own top, so the launch registers (and twins) what is in
  // it, and the value backstop knows those values when a program the guard
  // does not gate prints them. A labelled FILE is judged as a file root is.
  limit = out.size + MAX_LABEL_FILES;
  for (const r of labelRootList) {
    let st: ReturnType<typeof statSync> | undefined;
    try { st = statSync(r, { throwIfNoEntry: false }); } catch { st = undefined; }
    if (!st) continue;
    if (st.isDirectory()) {
      if (labelDirRoots.includes(r)) visit(r, 0);
      else skip(r, "symlinked-directory");
      continue;
    }
    if (!st.isFile() || out.has(r) || !realSpelled(path.posix.dirname(r))) continue;
    const agent = agentFile(r);
    if (agent?.kind === "kept") { skip(r, "agent-login"); continue; }
    if (agent?.kind === "store") { skip(r, "agent-auth"); continue; }
    const match = judge(r, agent?.kind === "other" ? agent.owner : undefined);
    if (match.rule === null || !isSecret(match.level)) continue;
    if (!isReadableFile(r)) { skip(r, "unreadable"); continue; }
    if (out.size >= limit) { skip(r, "count"); truncated = true; continue; }
    out.set(r, { path: r, level: match.level, rule: match.rule, ...(agent?.kind === "other" ? { agentLogin: agent.owner } : {}) });
  }

  const files = [...out.values()].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const skipped = [...skippedMain, ...skippedQuiet].slice(0, MAX_SKIP_RECORDS);
  return {
    files, skipped, counts, limits: { maxDepth: MAX_DEPTH, maxFiles: MAX_FILES, maxLabelFiles: MAX_LABEL_FILES }, truncated, depthAreas: depthAreasOf(deepDirs, dirRoots),
    // Every file found, a listed one or one past the file cap (a `count`
    // record): its label gates it at the open all the same.
    found, cleared: [...cleared].sort(), content: { read: content.read, capped: content.capped },
    documents: { read: documents.read, capped: documents.capped },
  };
}

/**
 * Directory names below which the guard's CATALOG gate never gates a file a
 * basename shape matches, beyond SKIP_DIRS (2026-10-17, confidentiality.md §6
 * "Read by a program the launch did not see"): the trees Python's installers
 * fill with third-party code, wherever they lie (a virtualenv's, a conda
 * install's, the system's). A library's own `credentials.json` or a test
 * fixture's `server.key` there is no credential of the user's, and gating it
 * would hand every program that imports the library a placeholder. The walk
 * never meets them below its depth cap; the gate has no depth cap.
 */
export const CATALOG_GATE_SKIP_DIRS: readonly string[] = ["site-packages", "dist-packages"];

/** Why the gate's verdict is `public` for a file the catalog names
 *  (`gateVerdict`): the walk's own prunes, and the gate's own two. */
export type GatePrune = "agent-auth" | "mandu-state" | "skipped-dir" | "package-cache" | "other-owner";

export interface GateVerdictOptions {
  /** This process's uid (the guard's and the user's); default
   *  `process.getuid()`. A test knob. */
  uid?: number;
  /** Mandu state directories besides each home's defaults (the arbiter's
   *  own database directory). */
  stateDirs?: readonly string[];
}

/**
 * The catalog's prefixes the guard gates opens under (2026-10-17,
 * confidentiality.md §6 "Read by a program the launch did not see"): each
 * SECRET_PREFIXES entry normalized for every one of `homes` (the arbiter's
 * HOME and the session's launch HOME), shipped as a root of its own by
 * `labelRootsSince`; never an agent's own store or login (`isAgentAuthPath`
 * under any of the homes), which the walk never masks either. Sorted,
 * without repeats. Pure.
 */
export function catalogGateRoots(homes: readonly string[]): string[] {
  const hs = [...new Set(homes.filter((h) => h.startsWith("/") && h !== "/").map(plainPath))];
  const out = new Set<string>();
  for (const h of hs) {
    for (const p of normalizedPrefixes(h)) {
      if (hs.some((x) => isAgentAuthPath(p, x))) continue;
      out.add(p);
    }
  }
  return [...out].sort();
}

/**
 * The verdict on ONE regular file the launch did not register, for the
 * guard's gate at the open (`labelledLevel`, 2026-10-17, confidentiality.md
 * §6 "Read by a program the launch did not see"): the WALK's rule without
 * its budget. The level is `pathConfidentiality`'s (a label, then the
 * catalog; the stricter over `homes`, the arbiter's HOME and the session's
 * launch HOME); a human or derived label decides wherever the file lies.
 * When the CATALOG decides, the walk's prunes apply as if the walk had
 * reached the file (it is never too deep or past the cap here), so the gate
 * never twins what a launch would not have:
 *
 *   agent-auth     an agent's own store or login (`isAgentAuthPath`);
 *   mandu-state    Mandu's own state (the homes' state bases and Mandu
 *                  homes), but a raw AgentView copy, which the walk reaches
 *                  through the view map;
 *   skipped-dir    a directory below the home (below `/` outside every home;
 *                  below the prefix, for a prefix rule) named in SKIP_DIRS, or
 *                  for a basename shape in CATALOG_GATE_SKIP_DIRS;
 *   package-cache  inside PACKAGE_CACHE_DIRS (third-party code the walk
 *                  records below its depth cap and never reaches);
 *   other-owner    a basename shape outside every home on a file another
 *                  account owns (a system package's `credentials.json`): the
 *                  catalog speaks for the user's own files.
 *
 * The content is never read (as the walk never reads it) but for the
 * AgentView rule. Pure but for that read and the owner's `stat`.
 */
export function gateVerdict(
  rawPath: string,
  homes: readonly string[],
  resolveLabel?: LabelLookup,
  opts: GateVerdictOptions = {},
): SecretCatalogMatch & { pruned?: GatePrune } {
  const NONE: SecretCatalogMatch = { level: "public", bindings: [], rule: null };
  if (!rawPath.startsWith("/")) return NONE;
  const p = plainPath(rawPath);
  const hs = [...new Set(homes.filter((h) => h.startsWith("/") && h !== "/").map(plainPath))];
  if (hs.length === 0) return NONE;
  let m: SecretCatalogMatch | null = null;
  for (const h of hs) {
    const x = pathConfidentiality(p, h, resolveLabel);
    if (m === null || maxConfidentiality(m.level, x.level) !== m.level) m = x;
  }
  if (m === null || m.rule === null || !isSecret(m.level)) return m ?? NONE;
  const prefixRule = m.rule.startsWith("prefix:");
  if (!prefixRule && !m.rule.startsWith("shape:")) return m; // a label decides
  const pruned = (why: GatePrune): SecretCatalogMatch & { pruned: GatePrune } => ({ ...NONE, pruned: why });
  if (hs.some((h) => isAgentAuthPath(p, h))) return pruned("agent-auth");
  const state = [...hs.flatMap((h) => [defaultStateBase(h), manduPath("mandu-home", {}, h)]), ...(opts.stateDirs ?? [])].map(plainPath);
  const inState = state.find((d) => isSelfOrAncestor(d, p));
  if (inState !== undefined) {
    const below = p.slice(inState.length + 1).split("/");
    if (!below.slice(0, -1).includes("agentview") || agentViewCopyIsSymbolized(p)) return pruned("mandu-state");
  }
  // The directory the walk would have started from: the prefix (a prefix
  // rule), else the deepest home holding the file, else `/`.
  let base = "/";
  if (prefixRule) {
    for (const h of hs) for (const pre of normalizedPrefixes(h)) if (isSelfOrAncestor(pre, p) && pre.length > base.length) base = pre;
  } else {
    for (const h of hs) if (isSelfOrAncestor(h, p) && h.length > base.length) base = h;
  }
  const dirs = (base === "/" ? p.slice(1) : p.slice(base.length + 1)).split("/").slice(0, -1);
  if (dirs.some((d) => SKIP_DIRS.has(d) || (!prefixRule && CATALOG_GATE_SKIP_DIRS.includes(d)))) return pruned("skipped-dir");
  if (hs.some((h) => isPackageCachePath(p, h))) return pruned("package-cache");
  if (!prefixRule && !hs.some((h) => isSelfOrAncestor(h, p))) {
    const uid = opts.uid ?? process.getuid?.();
    let owner: number | undefined;
    try { owner = statSync(p, { throwIfNoEntry: false })?.uid; } catch { owner = undefined; }
    // Unknown (gone, unreadable): judged as named (fail-closed).
    if (uid !== undefined && owner !== undefined && owner !== uid) return pruned("other-owner");
  }
  return m;
}
