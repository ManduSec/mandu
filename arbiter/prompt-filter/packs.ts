/**
 * packs — the prompt filter's pattern packs (confidentiality-plan-15-prompt-filter.md
 * §4.2, phase 2). Mandu-new (no reference origin).
 *
 * A pack is a YAML file of detectors, no code:
 *
 *   pack: acme-dlp                 # its id: what `prompt_filters.filters` switches
 *   version: 3
 *   description: Acme's data-loss patterns
 *   patterns:
 *     - id: card
 *       category: pii.payment-card
 *       regex: '\b(?:\d[ -]?){13,19}\b'
 *       check: luhn                 # optional built-in validator (validators.ts)
 *       level: no-model             # optional: the level a `mask` mints at
 *   keywords:
 *     - category: acme.codename
 *       match: word                 # word (default) | substring
 *       salt: 9f2c…                 # hashed: salted SHA-256 (hashKeyword), word match only
 *       hashes: [5d41…, 7c21…]
 *       max_words: 2                # the longest hashed keyword's word count (default 3)
 *     - category: acme.codename
 *       words: [falcon, osprey]     # plain keywords (a person's own pack)
 *
 * Packs live in `~/.mandu/prompt-filters/*.yaml` (the person's; the agent can
 * neither read nor write the Mandu home) and `/etc/mandu/prompt-filters.d/*.yaml`
 * (the administrator's, read-only to the person). A pack does nothing until
 * `prompt_filters.filters` turns it on, and nothing it finds acts until a
 * category's action says so (policy.ts).
 *
 * - Regexes run under RE2 (regex.ts): a pattern the engine rejects fails the
 *   pack.
 * - Validators are built in and named (validators.ts): a pack cannot ship code.
 * - Keywords may be HASHED: an organization's list of project names is itself
 *   confidential, and a hashed list can sit on every laptop without disclosing
 *   it. The filter hashes each word, and each run of up to `max_words` words,
 *   of the text with the group's salt (`hashKeyword`).
 * - SIGNED packs: a detached Ed25519 signature `<file>.sig` over the file's
 *   exact bytes, verified against the trusted keys in the pack-keys directory
 *   (consumer-packs.ts, the same keys and format). With `signed_only: true` an
 *   unsigned pack of the PERSON's is ignored; the administrator's directory is
 *   trusted by its location.
 *
 * PLUGIN PACKS (§4.3, phase 3): a pack may instead name an out-of-process
 * plugin and the categories it may report (never both patterns and a plugin):
 *
 *   pack: acme-classifier
 *   version: 1
 *   plugin:
 *     exec: /usr/bin/node                # absolute; pinned by sha256
 *     sha256: 3f1c…
 *     script: /opt/acme/classify.mjs     # optional: an interpreter's script, pinned too
 *     script_sha256: 9a0b…
 *     modules:                           # optional: every other file it loads, pinned too
 *       - { path: /opt/acme/lib/rules.mjs, sha256: 77de… }
 *     args: [--strict]                   # optional, after the script
 *     cost: model                        # model (default) | inline
 *     endpoint: required                 # required: the policy names a local model (§5); none (default)
 *     deadline_ms: 5000                  # default 5000, at most 30000
 *   categories:                          # the ONLY categories its findings may carry
 *     - category: pii.person
 *       level: no-model                  # what a `mask` mints at (default no-model)
 *
 * `modules:` pins the files the plugin loads besides its program and script
 * (an interpreter's imports, a rules file), each by path and SHA-256, at
 * most MAX_PLUGIN_MODULES, each under the directory of the script (of the
 * program when there is none). The plugin runs from a verified copy of that
 * directory's pinned files only (plugin-pin.ts): its own directory is not
 * readable to it, so a file it did not pin does not load, and a pinned one
 * that changed fails the run (§13.5 item 6).
 *
 * A plugin pack is a FILE only: the pack editor treats it as read-only and the
 * agent gets no plugin edit (§12, 2026-10-03). A plugin's categories never sit
 * under a built-in filter's (`secret.registered`, `secret.shape`).
 *
 * A pack that does not validate is refused WHOLE and named with its problems;
 * a filter switched on whose pack is missing or refused fails as §4.4 says
 * (`on_error`, engine.ts).
 */
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import yaml from "js-yaml";

import { loadPackKeys, verifyPackSignature } from "../policy/consumer-packs.js";
import { parseConfidentialityLevel, type ConfidentialityLevel } from "../symbol-table/confidentiality.js";
import type { FilterContext, Finding, PromptFilter, ScanResult } from "./filter.js";
import { BUILTIN_FILTER_IDS, CATEGORY_RE, FILTER_ID_RE } from "./policy.js";
import { compileRegex, type CompiledRegex } from "./regex.js";
import { VALIDATOR_NAMES, VALIDATORS } from "./validators.js";

/** The administrator's packs. A build may change it; nothing at run time can. */
export const ADMIN_PROMPT_PACK_DIR = "/etc/mandu/prompt-filters.d";

export const MAX_PACK_BYTES = 1024 * 1024;
export const MAX_PATTERNS = 500;
export const MAX_KEYWORDS = 10_000;
export const MAX_KEYWORD_WORDS = 8;
export const DEFAULT_MAX_WORDS = 3;
const PATTERN_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const LEVELS = ["any-model", "local-model", "no-model"] as const;

export type PackSource = "user" | "admin";

export interface PackPattern {
  id: string;
  category: string;
  regex: string;
  check?: string;
  level?: ConfidentialityLevel;
}

/** One more file a plugin loads, pinned (§4.3, §13.5 item 6). */
export interface PluginModulePin {
  path: string;
  sha256: string;
}

/** A plugin's pin and run settings (§4.3). */
export interface PluginSpec {
  exec: string;
  sha256: string;
  script?: string;
  scriptSha256?: string;
  /** The other files it loads, each under the script's (else the
   *  program's) directory. */
  modules?: PluginModulePin[];
  args: string[];
  cost: "model" | "inline";
  endpoint: "required" | "none";
  deadlineMs: number;
}

/** A category a plugin may report, and the level a `mask` of it mints at. */
export interface PluginCategory {
  category: string;
  level?: ConfidentialityLevel;
}

export const DEFAULT_PLUGIN_DEADLINE_MS = 5000;
export const MAX_PLUGIN_DEADLINE_MS = 30_000;
export const MAX_PLUGIN_ARGS = 16;
export const MAX_PLUGIN_CATEGORIES = 64;
export const MAX_PLUGIN_MODULES = 256;
/** Category prefixes only the built-in filters report. */
export const RESERVED_CATEGORY_PREFIXES: readonly string[] = ["secret.registered", "secret.shape"];

export interface PackKeywordGroup {
  category: string;
  match: "word" | "substring";
  /** Hashed: the salt, the hashes and the n-gram bound. */
  salt?: string;
  hashes?: string[];
  maxWords?: number;
  /** Plain words. */
  words?: string[];
  level?: ConfidentialityLevel;
}

/** A pack as its file says it, validated. */
export interface PackDocument {
  pack: string;
  version: number | string;
  description?: string;
  patterns: PackPattern[];
  keywords: PackKeywordGroup[];
  /** A plugin pack (§4.3): the plugin and its declared categories. */
  plugin?: PluginSpec;
  categories?: PluginCategory[];
}

export interface LoadedPromptPack {
  doc: PackDocument;
  source: PackSource;
  file: string;
  /** The trusted key that signed it, or null (unsigned). */
  signedBy: string | null;
  /** sha256 of the file's bytes (prefix). */
  digest: string;
}

/** A pack file that could not be used: refused whole. */
export interface PackProblem {
  file: string;
  source: PackSource;
  /** The id the file claims, when it says one. */
  pack?: string;
  problems: string[];
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Lowercased NFKC form of one word, the unit keywords are compared in. */
function normWord(w: string): string {
  return w.normalize("NFKC").toLowerCase();
}

/** A word of text: letters, digits, `_`. */
const WORD_RE = /[\p{L}\p{N}_]+/gu;

/** The words of `s`, with their positions. */
export function wordsOf(s: string): Array<{ w: string; start: number; end: number }> {
  const out: Array<{ w: string; start: number; end: number }> = [];
  WORD_RE.lastIndex = 0;
  for (let m = WORD_RE.exec(s); m !== null; m = WORD_RE.exec(s)) out.push({ w: normWord(m[0]), start: m.index, end: m.index + m[0].length });
  return out;
}

/** A keyword as its hash is taken: its words, lowercased NFKC, one space apart. */
export function normalizeKeyword(k: string): string {
  return wordsOf(k).map((x) => x.w).join(" ");
}

/** The hash a pack stores for `keyword` under `salt`: hex SHA-256 of
 *  `<salt>:<normalized keyword>`. Pure. */
export function hashKeyword(salt: string, keyword: string): string {
  return createHash("sha256").update(`${salt}:${normalizeKeyword(keyword)}`).digest("hex");
}

/** Validate a parsed pack; problems name the pack's own fields. Pure. */
export function validatePack(raw: unknown): { doc: PackDocument } | { problems: string[] } {
  const p: string[] = [];
  if (!isPlainObject(raw)) return { problems: ["a pack must be a mapping with pack, version, patterns and/or keywords"] };
  for (const k of Object.keys(raw)) {
    if (k === "signature") p.push("signature: sign a pack with a detached <file>.sig (scripts/sign-pack.mjs), not inline");
    else if (!["pack", "version", "description", "patterns", "keywords", "plugin", "categories"].includes(k)) p.push(`${k}: unknown key (allowed: pack, version, description, patterns, keywords, plugin, categories)`);
  }
  const id = raw.pack;
  if (typeof id !== "string" || !FILTER_ID_RE.test(id)) p.push("pack: the pack's id is lowercase letters, digits, . _ - (at most 64)");
  else if (BUILTIN_FILTER_IDS.includes(id)) p.push(`pack: '${id}' is a built-in filter's id`);
  const version = raw.version;
  if (!(typeof version === "number" && Number.isInteger(version) && version >= 0) && !(typeof version === "string" && /^[0-9A-Za-z._-]{1,32}$/.test(version))) {
    p.push("version: must be a whole number or a short version string");
  }
  if (raw.description !== undefined && (typeof raw.description !== "string" || raw.description.length > 500)) p.push("description: must be a string of at most 500 characters");
  const patterns: PackPattern[] = [];
  if (raw.patterns !== undefined) {
    if (!Array.isArray(raw.patterns)) p.push("patterns: must be a list");
    else if (raw.patterns.length > MAX_PATTERNS) p.push(`patterns: at most ${MAX_PATTERNS}`);
    else {
      const ids = new Set<string>();
      raw.patterns.forEach((x, i) => {
        const at = `patterns[${i}]`;
        const r = validatePattern(x);
        if ("problems" in r) { for (const q of r.problems) p.push(`${at}.${q}`); return; }
        if (ids.has(r.pattern.id)) p.push(`${at}.id: '${r.pattern.id}' repeats`);
        ids.add(r.pattern.id);
        patterns.push(r.pattern);
      });
    }
  }
  const keywords: PackKeywordGroup[] = [];
  if (raw.keywords !== undefined) {
    if (!Array.isArray(raw.keywords)) p.push("keywords: must be a list");
    else {
      let total = 0;
      raw.keywords.forEach((x, i) => {
        const at = `keywords[${i}]`;
        if (!isPlainObject(x)) { p.push(`${at}: must be a mapping`); return; }
        for (const k of Object.keys(x)) {
          if (!["category", "match", "salt", "hashes", "max_words", "words", "level"].includes(k)) p.push(`${at}.${k}: unknown key (allowed: category, match, salt, hashes, max_words, words, level)`);
        }
        if (typeof x.category !== "string" || !CATEGORY_RE.test(x.category)) p.push(`${at}.category: must be a dotted category such as acme.codename`);
        const match = x.match === undefined ? "word" : x.match;
        if (match !== "word" && match !== "substring") p.push(`${at}.match: must be word or substring`);
        const hashed = x.hashes !== undefined || x.salt !== undefined;
        if (hashed && x.words !== undefined) p.push(`${at}: a group is hashed (salt, hashes) or plain (words), not both`);
        const level = levelOf(x.level, `${at}.level`, p);
        if (hashed) {
          if (typeof x.salt !== "string" || x.salt.length < 8 || x.salt.length > 128) p.push(`${at}.salt: must be a string of 8 to 128 characters`);
          if (!Array.isArray(x.hashes) || x.hashes.length === 0 || !x.hashes.every((h) => typeof h === "string" && HEX64_RE.test(h.toLowerCase()))) {
            p.push(`${at}.hashes: must be a non-empty list of hex SHA-256 values`);
          } else total += x.hashes.length;
          if (match !== "word") p.push(`${at}.match: hashed keywords match whole words only`);
          if (x.max_words !== undefined && !(Number.isInteger(x.max_words) && (x.max_words as number) >= 1 && (x.max_words as number) <= MAX_KEYWORD_WORDS)) {
            p.push(`${at}.max_words: must be 1 to ${MAX_KEYWORD_WORDS}`);
          }
          keywords.push({
            category: String(x.category), match: "word", salt: String(x.salt),
            hashes: Array.isArray(x.hashes) ? (x.hashes as unknown[]).map((h) => String(h).toLowerCase()) : [],
            maxWords: typeof x.max_words === "number" ? x.max_words : DEFAULT_MAX_WORDS,
            ...(level ? { level } : {}),
          });
        } else {
          if (x.max_words !== undefined) p.push(`${at}.max_words: only for hashed keywords`);
          if (!Array.isArray(x.words) || x.words.length === 0) { p.push(`${at}.words: must be a non-empty list (or give salt and hashes)`); return; }
          const bad = (x.words as unknown[]).findIndex((w) => typeof w !== "string" || w.trim() === "" || w.length > 200 || /[\r\n]/.test(w) || (match === "word" && normalizeKeyword(w) === ""));
          if (bad >= 0) p.push(`${at}.words[${bad}]: must be a one-line word or phrase${match === "word" ? " with a letter or digit" : ""}`);
          if (match === "word" && (x.words as unknown[]).some((w) => typeof w === "string" && normalizeKeyword(w).split(" ").length > MAX_KEYWORD_WORDS)) {
            p.push(`${at}.words: a keyword has at most ${MAX_KEYWORD_WORDS} words`);
          }
          total += x.words.length;
          keywords.push({ category: String(x.category), match: match === "substring" ? "substring" : "word", words: (x.words as unknown[]).map(String), ...(level ? { level } : {}) });
        }
      });
      if (total > MAX_KEYWORDS) p.push(`keywords: at most ${MAX_KEYWORDS} in all`);
    }
  }
  let plugin: PluginSpec | undefined;
  let categories: PluginCategory[] | undefined;
  if (raw.plugin !== undefined) {
    if (raw.patterns !== undefined || raw.keywords !== undefined) p.push("plugin: a pack is patterns and keywords, or a plugin, not both");
    const r = validatePlugin(raw.plugin);
    if ("problems" in r) for (const q of r.problems) p.push(`plugin.${q}`);
    else plugin = r.plugin;
    const c = validatePluginCategories(raw.categories);
    if ("problems" in c) for (const q of c.problems) p.push(q);
    else categories = c.categories;
  } else if (raw.categories !== undefined) {
    p.push("categories: only a plugin pack declares categories (a pattern or keyword says its own)");
  }
  if (raw.plugin === undefined && patterns.length === 0 && keywords.length === 0 && p.length === 0) p.push("a pack needs at least one pattern or keyword group, or a plugin");
  if (p.length > 0) return { problems: p };
  return {
    doc: {
      pack: id as string, version: version as number | string,
      ...(typeof raw.description === "string" ? { description: raw.description } : {}),
      patterns, keywords,
      ...(plugin ? { plugin, categories: categories ?? [] } : {}),
    },
  };
}

const cleanAbs = (v: unknown): v is string =>
  typeof v === "string" && v.startsWith("/") && v.length <= 4096 && !/[\0\n\r]/.test(v)
  && !v.split("/").some((seg) => seg === ".." || seg === ".");
const isHex64 = (v: unknown): v is string => typeof v === "string" && HEX64_RE.test(v.toLowerCase());

/** Validate a pack's `plugin:` (problems name its fields). Pure. */
export function validatePlugin(x: unknown): { plugin: PluginSpec } | { problems: string[] } {
  const p: string[] = [];
  if (!isPlainObject(x)) return { problems: ["must be a mapping { exec, sha256, script?, script_sha256?, modules?, args?, cost?, endpoint?, deadline_ms? }"] };
  const keys = ["exec", "sha256", "script", "script_sha256", "modules", "args", "cost", "endpoint", "deadline_ms"];
  for (const k of Object.keys(x)) if (!keys.includes(k)) p.push(`${k}: unknown key (allowed: ${keys.join(", ")})`);
  if (!cleanAbs(x.exec)) p.push("exec: must be an absolute path (no . or .. parts)");
  if (!isHex64(x.sha256)) p.push("sha256: must be the program's hex SHA-256 (sha256sum <exec>)");
  if (x.script !== undefined || x.script_sha256 !== undefined) {
    if (!cleanAbs(x.script)) p.push("script: must be an absolute path (no . or .. parts)");
    if (!isHex64(x.script_sha256)) p.push("script_sha256: must be the script's hex SHA-256");
  }
  const modules: PluginModulePin[] = [];
  if (x.modules !== undefined) {
    // The modules sit under the directory of the file that loads them: the
    // script's, else the program's. The copy keeps their paths below it.
    const main = typeof x.script === "string" ? x.script : x.exec;
    const base = typeof main === "string" ? main.slice(0, Math.max(1, main.lastIndexOf("/"))) : "";
    const under = base === "/" ? "/" : `${base}/`;
    if (!Array.isArray(x.modules) || x.modules.length === 0 || x.modules.length > MAX_PLUGIN_MODULES) {
      p.push(`modules: must be a list of 1 to ${MAX_PLUGIN_MODULES} { path, sha256 }`);
    } else {
      const seen = new Set<string>();
      x.modules.forEach((m, i) => {
        const at = `modules[${i}]`;
        if (!isPlainObject(m)) { p.push(`${at}: must be a mapping { path, sha256 }`); return; }
        for (const k of Object.keys(m)) if (k !== "path" && k !== "sha256") p.push(`${at}.${k}: unknown key (allowed: path, sha256)`);
        if (!cleanAbs(m.path)) p.push(`${at}.path: must be an absolute path (no . or .. parts)`);
        else if (base === "" || !m.path.startsWith(under) || m.path === main) p.push(`${at}.path: must be a file under ${base || "the script's directory"} other than ${typeof x.script === "string" ? "the script" : "the program"} (the plugin runs from a copy of that directory's pinned files)`);
        else if (seen.has(m.path)) p.push(`${at}.path: ${m.path} is listed twice`);
        if (!isHex64(m.sha256)) p.push(`${at}.sha256: must be the file's hex SHA-256 (sha256sum <path>)`);
        if (typeof m.path === "string") seen.add(m.path);
        if (cleanAbs(m.path) && isHex64(m.sha256)) modules.push({ path: m.path, sha256: (m.sha256 as string).toLowerCase() });
      });
    }
  }
  let args: string[] = [];
  if (x.args !== undefined) {
    if (!Array.isArray(x.args) || x.args.length > MAX_PLUGIN_ARGS || !x.args.every((a) => typeof a === "string" && a.length <= 256 && !/[\0\n\r]/.test(a))) {
      p.push(`args: must be a list of at most ${MAX_PLUGIN_ARGS} one-line strings`);
    } else args = x.args as string[];
  }
  if (x.cost !== undefined && x.cost !== "model" && x.cost !== "inline") p.push("cost: must be model or inline");
  if (x.endpoint !== undefined && x.endpoint !== "required" && x.endpoint !== "none") p.push("endpoint: must be required (the policy names a local model) or none");
  if (x.deadline_ms !== undefined && !(Number.isInteger(x.deadline_ms) && (x.deadline_ms as number) >= 100 && (x.deadline_ms as number) <= MAX_PLUGIN_DEADLINE_MS)) {
    p.push(`deadline_ms: must be 100 to ${MAX_PLUGIN_DEADLINE_MS}`);
  }
  if (p.length > 0) return { problems: p };
  return {
    plugin: {
      exec: x.exec as string, sha256: (x.sha256 as string).toLowerCase(),
      ...(typeof x.script === "string" ? { script: x.script, scriptSha256: (x.script_sha256 as string).toLowerCase() } : {}),
      ...(modules.length > 0 ? { modules } : {}),
      args, cost: x.cost === "inline" ? "inline" : "model", endpoint: x.endpoint === "required" ? "required" : "none",
      deadlineMs: typeof x.deadline_ms === "number" ? x.deadline_ms : DEFAULT_PLUGIN_DEADLINE_MS,
    },
  };
}

/** Validate a plugin pack's `categories:`. Pure. */
export function validatePluginCategories(x: unknown): { categories: PluginCategory[] } | { problems: string[] } {
  const p: string[] = [];
  if (!Array.isArray(x) || x.length === 0 || x.length > MAX_PLUGIN_CATEGORIES) {
    return { problems: [`categories: a plugin pack declares 1 to ${MAX_PLUGIN_CATEGORIES} categories its findings may carry`] };
  }
  const out: PluginCategory[] = [];
  const seen = new Set<string>();
  x.forEach((c, i) => {
    const at = `categories[${i}]`;
    const entry: unknown = typeof c === "string" ? { category: c } : c;
    if (!isPlainObject(entry)) { p.push(`${at}: must be a category or { category, level? }`); return; }
    for (const k of Object.keys(entry)) if (k !== "category" && k !== "level") p.push(`${at}.${k}: unknown key (allowed: category, level)`);
    const cat = entry.category;
    if (typeof cat !== "string" || !CATEGORY_RE.test(cat)) { p.push(`${at}.category: must be a dotted category such as pii.person`); return; }
    if (RESERVED_CATEGORY_PREFIXES.some((r) => cat === r || cat.startsWith(`${r}.`) || r.startsWith(`${cat}.`))) {
      p.push(`${at}.category: ${cat} is a built-in filter's category; a plugin may not report it`);
      return;
    }
    if (seen.has(cat)) p.push(`${at}.category: ${cat} repeats`);
    seen.add(cat);
    const level = levelOf(entry.level, `${at}.level`, p);
    out.push({ category: cat, ...(level ? { level } : {}) });
  });
  if (p.length > 0) return { problems: p };
  return { categories: out };
}

function levelOf(v: unknown, at: string, p: string[]): ConfidentialityLevel | undefined {
  if (v === undefined) return undefined;
  if (typeof v !== "string" || !(LEVELS as readonly string[]).includes(v)) {
    p.push(`${at}: must be one of ${LEVELS.join(", ")}`);
    return undefined;
  }
  return parseConfidentialityLevel(v);
}

/** Validate one pattern (problems name its fields). Pure. */
export function validatePattern(x: unknown): { pattern: PackPattern } | { problems: string[] } {
  const p: string[] = [];
  if (!isPlainObject(x)) return { problems: ["must be a mapping { id, category, regex, check?, level? }"] };
  for (const k of Object.keys(x)) {
    if (!["id", "category", "regex", "check", "level"].includes(k)) p.push(`${k}: unknown key (allowed: id, category, regex, check, level)`);
  }
  if (typeof x.id !== "string" || !PATTERN_ID_RE.test(x.id)) p.push("id: letters, digits, . _ - (at most 64)");
  if (typeof x.category !== "string" || !CATEGORY_RE.test(x.category)) p.push("category: must be a dotted category such as pii.email");
  const re = compileRegex(x.regex);
  if (typeof re === "string") p.push(`regex: ${re}`);
  if (x.check !== undefined && (typeof x.check !== "string" || !VALIDATOR_NAMES.includes(x.check))) p.push(`check: must be one of ${VALIDATOR_NAMES.join(", ")}`);
  const level = levelOf(x.level, "level", p);
  if (p.length > 0) return { problems: p };
  return {
    pattern: {
      id: x.id as string, category: x.category as string, regex: x.regex as string,
      ...(typeof x.check === "string" ? { check: x.check } : {}),
      ...(level ? { level } : {}),
    },
  };
}

/** Parse and validate a pack file's text. */
export function parsePackText(text: string): { doc: PackDocument } | { problems: string[] } {
  let raw: unknown;
  try {
    raw = yaml.load(text);
  } catch (err) {
    return { problems: [`not YAML: ${String((err as Error).message).split("\n")[0]}`] };
  }
  return validatePack(raw);
}

/** The pack as its file is written (the pack editor's output). */
export function packToYaml(doc: PackDocument): string {
  const out: Record<string, unknown> = { pack: doc.pack, version: doc.version };
  if (doc.description !== undefined) out.description = doc.description;
  if (doc.plugin) {
    const pl = doc.plugin;
    out.plugin = {
      exec: pl.exec, sha256: pl.sha256,
      ...(pl.script ? { script: pl.script, script_sha256: pl.scriptSha256 } : {}),
      ...(pl.modules && pl.modules.length > 0 ? { modules: pl.modules.map((m) => ({ path: m.path, sha256: m.sha256 })) } : {}),
      ...(pl.args.length > 0 ? { args: pl.args } : {}),
      cost: pl.cost, endpoint: pl.endpoint, deadline_ms: pl.deadlineMs,
    };
    out.categories = (doc.categories ?? []).map((c) => ({ ...c }));
  }
  if (doc.patterns.length > 0) out.patterns = doc.patterns.map((p) => ({ ...p }));
  if (doc.keywords.length > 0) {
    out.keywords = doc.keywords.map((k) => ({
      category: k.category,
      ...(k.match !== "word" ? { match: k.match } : {}),
      ...(k.salt !== undefined ? { salt: k.salt, hashes: k.hashes, ...(k.maxWords !== undefined && k.maxWords !== DEFAULT_MAX_WORDS ? { max_words: k.maxWords } : {}) } : { words: k.words }),
      ...(k.level ? { level: k.level } : {}),
    }));
  }
  return `# A Mandu prompt filter pack (docs/design/confidentiality/confidentiality-plan-15-prompt-filter.md §4.2).\n${yaml.dump(out, { lineWidth: -1, noRefs: true })}`;
}

/** Every `*.yaml` / `*.yml` file of a directory, sorted ([] when absent). */
function packFiles(dir: string | null): string[] {
  if (dir === null || !existsSync(dir)) return [];
  try {
    return readdirSync(dir).filter((n) => /\.ya?ml$/.test(n)).sort().map((n) => join(dir, n)).filter((f) => {
      try { return statSync(f).isFile(); } catch { return false; }
    });
  } catch {
    return [];
  }
}

/** What the pack directories hold, cheaply (names, sizes, mtimes, inodes,
 *  and the signatures'): a changed signature reloads the packs. */
export function packDirsSignature(dirs: ReadonlyArray<string | null>, keysDir: string | null): string {
  const sig = (f: string): unknown => {
    try { const st = statSync(f); return [f, st.size, st.mtimeMs, st.ino]; } catch { return [f]; }
  };
  const parts: unknown[] = [];
  for (const d of dirs) for (const f of packFiles(d)) parts.push(sig(f), sig(`${f}.sig`));
  if (keysDir !== null && existsSync(keysDir)) {
    try { for (const n of readdirSync(keysDir).sort()) parts.push(sig(join(keysDir, n))); } catch { /* unreadable: no keys */ }
  }
  return JSON.stringify(parts);
}

export interface LoadedPacks {
  packs: LoadedPromptPack[];
  problems: PackProblem[];
  /** Digest over every usable pack (part of the cache key). */
  digest: string;
}

/**
 * Read the administrator's packs, then the person's. A file that does not
 * validate, or whose id an earlier file (or a built-in) took, is refused
 * whole; the administrator's file wins a clash. Never throws.
 */
export function loadPromptPacks(opts: { userDir: string | null; adminDir: string | null; keysDir: string | null }): LoadedPacks {
  const keys = opts.keysDir === null ? [] : loadPackKeys(opts.keysDir);
  const packs: LoadedPromptPack[] = [];
  const problems: PackProblem[] = [];
  const taken = new Map<string, string>();
  for (const [source, dir] of [["admin", opts.adminDir], ["user", opts.userDir]] as const) {
    for (const file of packFiles(dir)) {
      let bytes: Buffer;
      try {
        if (statSync(file).size > MAX_PACK_BYTES) { problems.push({ file, source, problems: [`larger than ${MAX_PACK_BYTES} bytes`] }); continue; }
        bytes = readFileSync(file);
      } catch (err) {
        problems.push({ file, source, problems: [`unreadable: ${(err as Error).message}`] });
        continue;
      }
      const r = parsePackText(bytes.toString("utf8"));
      if ("problems" in r) { problems.push({ file, source, problems: r.problems }); continue; }
      const was = taken.get(r.doc.pack);
      if (was !== undefined) { problems.push({ file, source, pack: r.doc.pack, problems: [`the pack id '${r.doc.pack}' is already used by ${was}`] }); continue; }
      let signedBy: string | null = null;
      if (existsSync(`${file}.sig`)) {
        signedBy = verifyPackSignature(bytes, readFileSync(`${file}.sig`, "utf8"), keys);
        if (signedBy === null) { problems.push({ file, source, pack: r.doc.pack, problems: [`its signature (${file}.sig) does not verify against any trusted key`] }); continue; }
      }
      taken.set(r.doc.pack, file);
      packs.push({ doc: r.doc, source, file, signedBy, digest: createHash("sha256").update(bytes).digest("hex").slice(0, 16) });
    }
  }
  const digest = createHash("sha256").update(JSON.stringify(packs.map((p) => [p.doc.pack, p.source, p.digest, p.signedBy]))).digest("hex").slice(0, 16);
  return { packs, problems, digest };
}

interface CompiledPattern {
  pattern: PackPattern;
  re: CompiledRegex;
  check?: (s: string) => boolean;
}

/** A pack as a filter (§4): patterns and keywords, inline cost. */
export class PackFilter implements PromptFilter {
  readonly id: string;
  readonly cost = "inline" as const;
  readonly categories: readonly string[];
  private readonly compiled: CompiledPattern[];
  private readonly plainWord: Array<{ group: PackKeywordGroup; phrases: Map<string, number> }>;
  private readonly plainSub: Array<{ group: PackKeywordGroup; res: RegExp[] }>;
  private readonly hashed: Array<{ group: PackKeywordGroup; set: Set<string> }>;

  constructor(readonly pack: LoadedPromptPack) {
    if (pack.doc.plugin) throw new Error(`pack ${pack.doc.pack}: a plugin pack runs as a plugin (plugin-filter.ts), not as patterns`);
    this.id = pack.doc.pack;
    this.categories = [...new Set([...pack.doc.patterns.map((p) => p.category), ...pack.doc.keywords.map((k) => k.category)])];
    this.compiled = pack.doc.patterns.map((pattern) => {
      const re = compileRegex(pattern.regex);
      if (typeof re === "string") throw new Error(`pack ${this.id}: pattern ${pattern.id}: ${re}`);
      return { pattern, re, ...(pattern.check ? { check: VALIDATORS[pattern.check] } : {}) };
    });
    this.plainWord = pack.doc.keywords.filter((k) => k.words && k.match === "word").map((group) => {
      const phrases = new Map<string, number>();
      for (const w of group.words!) {
        const n = normalizeKeyword(w);
        phrases.set(n, n.split(" ").length);
      }
      return { group, phrases };
    });
    this.plainSub = pack.doc.keywords.filter((k) => k.words && k.match === "substring").map((group) => ({
      group,
      res: group.words!.map((w) => new RegExp(w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "giu")),
    }));
    this.hashed = pack.doc.keywords.filter((k) => k.hashes).map((group) => ({ group, set: new Set(group.hashes) }));
  }

  scan(text: string, _ctx: FilterContext): ScanResult {
    const findings: Finding[] = [];
    for (const c of this.compiled) {
      for (const m of c.re.matches(text)) {
        if (c.check && !c.check(text.slice(m.start, m.end))) continue;
        findings.push({ start: m.start, end: m.end, category: c.pattern.category, rule: c.pattern.id, ...(c.pattern.level ? { level: c.pattern.level } : {}) });
      }
    }
    if (this.plainWord.length > 0 || this.hashed.length > 0) {
      const words = wordsOf(text);
      for (let i = 0; i < words.length; i++) {
        let phrase = "";
        for (let n = 1; n <= MAX_KEYWORD_WORDS && i + n - 1 < words.length; n++) {
          phrase = n === 1 ? words[i]!.w : `${phrase} ${words[i + n - 1]!.w}`;
          const span = { start: words[i]!.start, end: words[i + n - 1]!.end };
          for (const g of this.plainWord) {
            if (g.phrases.get(phrase) === n) findings.push({ ...span, category: g.group.category, rule: "keyword", ...(g.group.level ? { level: g.group.level } : {}) });
          }
          for (const g of this.hashed) {
            if (n > (g.group.maxWords ?? DEFAULT_MAX_WORDS)) continue;
            const h = createHash("sha256").update(`${g.group.salt}:${phrase}`).digest("hex");
            if (g.set.has(h)) findings.push({ ...span, category: g.group.category, rule: "keyword", ...(g.group.level ? { level: g.group.level } : {}) });
          }
        }
      }
    }
    for (const g of this.plainSub) {
      for (const re of g.res) {
        re.lastIndex = 0;
        for (let m = re.exec(text); m !== null; m = re.exec(text)) {
          if (m[0] === "") { re.lastIndex++; continue; }
          findings.push({ start: m.index, end: m.index + m[0].length, category: g.group.category, rule: "keyword", ...(g.group.level ? { level: g.group.level } : {}) });
        }
      }
    }
    return { findings, skipped: 0 };
  }
}

/** Ordinary prose and code, no credential and no personal data: a pattern
 *  that matches here will mask ordinary prompts (§8.1, the pattern check). */
export const ORDINARY_CORPUS = [
  "Could you look at the failing test in the parser module and tell me why the second case times out?",
  "Please refactor this function so that it returns early when the list is empty, and add a docstring.",
  "The meeting moved to Thursday at 3 pm; the agenda is the release plan, the open bugs and the hiring update.",
  "for (let i = 0; i < items.length; i++) { total += items[i].price * items[i].quantity; }",
  "def load(path):\n    with open(path) as f:\n        return json.load(f)",
  "Version 2.4.1 fixed the memory leak reported in issue 1287; upgrade with npm install foo@2.4.1.",
  "Our quarterly revenue grew 12 percent, mostly from the new subscription tier launched in March.",
  "Summarize the README in three bullet points and suggest a better title for the project.",
  "git commit -m \"fix: handle the empty response from the API\" && git push origin feature/retry",
  "The build failed at step 7 of 12 with exit code 137, which usually means the container ran out of memory.",
  "SELECT id, name, created_at FROM users WHERE active = true ORDER BY created_at DESC LIMIT 50;",
  "Write a haiku about autumn leaves falling on a quiet river in the evening light.",
].join("\n\n");

/** How often `pattern` matches `text` and the ordinary corpus (§8.1). */
export function patternMatchCounts(pattern: PackPattern, sample = ""): { corpus: number; sample: number } {
  const re = compileRegex(pattern.regex);
  if (typeof re === "string") return { corpus: 0, sample: 0 };
  const check = pattern.check ? VALIDATORS[pattern.check] : undefined;
  const count = (t: string): number => re.matches(t).filter((m) => !check || check(t.slice(m.start, m.end))).length;
  return { corpus: count(ORDINARY_CORPUS), sample: sample === "" ? 0 : count(sample) };
}
