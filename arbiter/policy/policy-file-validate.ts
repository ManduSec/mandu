/**
 * policy-file-validate — STRICT validation of the operator's data-law
 * document (`policy.yaml`) plus its default location
 * (docs/design/ui/policy-surface.md §2.1, stage 2).
 *
 * `load-policy.ts` is deliberately fail-SOFT (a miss or parse error degrades to
 * the built-ins with a warning) because the reference implementation used it
 * for optional overlays. For a security daemon that is the wrong boot
 * behavior: a user file may TIGHTEN the law (an operator who wrote "treat
 * ~/Downloads as untrusted" must not silently run without it), and a typo
 * that turns into "built-ins are the law" is exactly the silent divergence
 * between the file on disk and the law in force that §2.1 rules out. So the
 * daemon (ipc/server-main.ts) resolves the path, and if a file EXISTS it must
 * validate here or the arbiter REFUSES TO START with every error listed. A
 * missing file is fine (built-ins, reported as such by the law source).
 *
 * Validation is structural + a few semantic contradictions the engine would
 * otherwise ignore silently (a `trustedList` under `default: TRUSTED`). It
 * accepts exactly the shapes load-policy.ts / tool-overrides.ts consume.
 */
import { checkGuardSettings, GUARD_SETTINGS_KEYS } from "./guard-settings.js";
import { appRuleRefusal, hashPrints, hostProgramOf, readerOutputRefusal, readerPrints, readerRunsCode, readerVetted, renamedCopyOf, scriptInterpreterFamily, scriptPrints } from "./flow-taint.js";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import yaml from "js-yaml";
import { manduPath } from "../src/generated/mandu-paths.js";

import type { PolicyFileConfig } from "./load-policy.js";
import { BUILTIN_ORIGIN_DEFAULT } from "./policy-engine.js";
import { compilePathGlob, hasGlobMeta } from "./path-glob.js";
import { isValueKey, VALUE_KEY_MAX } from "./value-bindings.js";
import { RULES } from "./rule-ref.js";
import { isCloudBackedModel } from "./cloud-model.js";
import { isPlainHttpToNetwork } from "./model-placement.js";
import { checkModelTls } from "./model-tls.js";
import { normalizeGuid } from "./sensitivity-labels.js";
import { checkLiteralsInPerimeter, checkPerimeter, compilePerimeter } from "./model-perimeter.js";
import { checkPromptEndpoints, checkPromptFilters, promptLockProblems } from "../prompt-filter/policy.js";
import { ADMIN_POLICY_DIR, adminLockProblems, effectiveModels, getAdminLayer, hasAdminLayer, loadAdminLayer, NO_ADMIN_LAYER, setAdminLayer, type AdminLayer } from "./admin-layer.js";
import { checkIssuerBindings } from "./issuer-bindings.js";
import { checkMappedTools } from "./mapped-tools.js";

/** Where the document lives when MANDU_POLICY_FILE is unset: the path
 *  table's `policy` entry (on-disk-layout.md §3, §5),
 *  `${MANDU_HOME:-~/.mandu}/policy.yaml`. */
export function defaultPolicyFilePath(env: NodeJS.ProcessEnv = process.env): string {
  return manduPath("policy", env, env.HOME || homedir());
}

/** The configured path (MANDU_POLICY_FILE, `~` expanded, made absolute) or
 *  the default. Never undefined: the law source can then always name the file
 *  it looked for, found or not. */
export function resolvePolicyFilePath(env: NodeJS.ProcessEnv = process.env, cwd = process.cwd()): string {
  const raw = env.MANDU_POLICY_FILE;
  if (!raw || raw.trim() === "") return defaultPolicyFilePath(env);
  const home = env.HOME || homedir();
  const expanded = raw === "~" ? home : raw.startsWith("~/") ? join(home, raw.slice(2)) : raw;
  return isAbsolute(expanded) ? expanded : resolve(cwd, expanded);
}

export class PolicyFileError extends Error {
  constructor(readonly path: string, readonly problems: string[]) {
    super(
      `policy file ${path} is invalid — the arbiter refuses to start rather than run a different law than the one on disk:\n` +
        problems.map((p) => `  - ${p}`).join("\n"),
    );
    this.name = "PolicyFileError";
  }
}

const TRUST = new Set(["TRUSTED", "UNTRUSTED"]);
const OUTBOUND_FIELD = new Set(["resolve", "not_resolve", "no_symbols_expected"]);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function checkKeys(obj: Record<string, unknown>, allowed: string[], at: string, out: string[]): void {
  // The top level also takes the guard's host lists (guard-settings.ts, which
  // validates them); kept out of the literal list below so that list stays
  // one line per owner.
  const all = at === "policy" ? [...allowed, ...GUARD_SETTINGS_KEYS] : allowed;
  for (const k of Object.keys(obj)) {
    if (!all.includes(k)) out.push(`${at}: unknown key '${k}' (allowed: ${all.join(", ")})`);
  }
}

function checkStringList(v: unknown, at: string, out: string[]): void {
  if (!Array.isArray(v)) {
    out.push(`${at}: must be a list of strings`);
    return;
  }
  v.forEach((item, i) => {
    if (typeof item !== "string" || item.trim() === "") out.push(`${at}[${i}]: must be a non-empty string`);
  });
}

function checkCategory(v: unknown, at: string, out: string[], cat: "url" | "channel" | "dir"): void {
  if (!isPlainObject(v)) {
    out.push(`${at}: must be a mapping with default / trustedList / untrustedList`);
    return;
  }
  checkKeys(v, ["default", "trustedList", "untrustedList"], at, out);
  if ("default" in v && !TRUST.has(v.default as string)) {
    out.push(`${at}.default: must be TRUSTED or UNTRUSTED (got ${JSON.stringify(v.default)})`);
  }
  if ("trustedList" in v) checkStringList(v.trustedList, `${at}.trustedList`, out);
  if ("untrustedList" in v) checkStringList(v.untrustedList, `${at}.untrustedList`, out);
  // Contradictions the engine would ignore silently: the list the mode does
  // not read. (allowlist ⇔ default UNTRUSTED reads trustedList; blocklist ⇔
  // default TRUSTED reads untrustedList.) Judged under the EFFECTIVE default:
  // an absent `default` is the category's built-in one (policy-engine.ts
  // BUILTIN_ORIGIN_DEFAULT; before 2026-09-25 it meant TRUSTED for every
  // category, so `url: { untrustedList: [...] }` trusted the rest of the web).
  // A file that relied on the old reading is refused here with the fix,
  // rather than silently run as a different law.
  const def = TRUST.has(v.default as string) ? (v.default as string) : BUILTIN_ORIGIN_DEFAULT[cat];
  const implicit = !("default" in v) ? ` (the built-in default for ${cat}; write default: ${def === "TRUSTED" ? "UNTRUSTED" : "TRUSTED"} if you meant the other mode)` : "";
  if (def === "TRUSTED" && "trustedList" in v) {
    out.push(`${at}: 'trustedList' has no effect under default TRUSTED${implicit} (everything is trusted unless listed in untrustedList)`);
  }
  if (def === "UNTRUSTED" && "untrustedList" in v) {
    out.push(`${at}: 'untrustedList' has no effect under default UNTRUSTED${implicit} (nothing is trusted unless listed in trustedList)`);
  }
}

function checkSchemaNode(v: unknown, at: string, out: string[], depth = 0): void {
  if (depth > 32) {
    out.push(`${at}: schema nesting too deep`);
    return;
  }
  if (typeof v === "string") {
    if (!TRUST.has(v)) out.push(`${at}: a leaf must be TRUSTED or UNTRUSTED (got ${JSON.stringify(v)})`);
    return;
  }
  if (!isPlainObject(v)) {
    out.push(`${at}: must be TRUSTED, UNTRUSTED, a {category, role} marker, or a mapping of fields`);
    return;
  }
  if ("role" in v || "category" in v) {
    // A KeySpec / DataSpec marker.
    if (typeof v.category !== "string" || v.category === "") out.push(`${at}.category: must be a category id (URL, CHANNEL, DIR, …)`);
    if (v.role === "key") {
      checkKeys(v, ["category", "role"], at, out);
    } else if (v.role === "data") {
      checkKeys(v, ["category", "role", "keyField"], at, out);
      if (typeof v.keyField !== "string" || v.keyField === "") out.push(`${at}.keyField: a data marker needs the field its key comes from`);
    } else {
      out.push(`${at}.role: must be "key" or "data" (got ${JSON.stringify(v.role)})`);
    }
    return;
  }
  if ("__items" in v) {
    checkKeys(v, ["__items"], at, out);
    checkSchemaNode(v.__items, `${at}.__items`, out, depth + 1);
    return;
  }
  for (const [field, child] of Object.entries(v)) checkSchemaNode(child, `${at}.${field}`, out, depth + 1);
}

function checkOutbound(v: unknown, at: string, out: string[]): void {
  if (v === "resolve" || v === "not_resolve") return;
  if (!isPlainObject(v)) {
    out.push(`${at}: must be "resolve", "not_resolve", or a mapping of field → resolve | not_resolve | no_symbols_expected`);
    return;
  }
  for (const [field, policy] of Object.entries(v)) {
    if (!OUTBOUND_FIELD.has(policy as string)) {
      out.push(`${at}.${field}: must be resolve | not_resolve | no_symbols_expected (got ${JSON.stringify(policy)})`);
    }
  }
}

function checkCommandEntries(v: unknown, at: string, out: string[]): void {
  if (!Array.isArray(v)) {
    out.push(`${at}: must be a list of command entries`);
    return;
  }
  v.forEach((entry, i) => {
    const here = `${at}[${i}]`;
    if (!isPlainObject(entry)) {
      out.push(`${here}: must be a mapping with an 'id'`);
      return;
    }
    checkKeys(entry, ["id", "aliases", "schema", "trustErrors", "trustHelp", "subcommands"], here, out);
    if (typeof entry.id !== "string" || entry.id.trim() === "") out.push(`${here}.id: must be the command's canonical name`);
    if ("aliases" in entry) checkStringList(entry.aliases, `${here}.aliases`, out);
    if ("schema" in entry && !isPlainObject(entry.schema)) out.push(`${here}.schema: must be a mapping`);
    for (const flag of ["trustErrors", "trustHelp"]) {
      if (flag in entry && typeof entry[flag] !== "boolean") out.push(`${here}.${flag}: must be true or false`);
    }
    if ("subcommands" in entry && !isPlainObject(entry.subcommands)) out.push(`${here}.subcommands: must be a mapping of subcommand → { schema, … }`);
  });
}

/**
 * Every problem with a parsed document, as `path: message` strings; [] means
 * valid. Pure — the caller decides what a problem costs (the daemon: refuse).
 */
export const LEVELS: ReadonlySet<string> = new Set(["public", "any-model", "local-model", "no-model"]);

/**
 * The level names retired on 2026-09-27, each with the name that replaced it
 * (confidentiality.md). They are refused like any other
 * unknown level, never translated; the map only lets the error say what to
 * write instead. Spelled in pieces so a mechanical rename cannot rewrite them.
 */
export const RETIRED_LEVELS: ReadonlyMap<string, string> = new Map([
  [["secret", "strict"].join("-"), "no-model"],
  [["secret", "model-ok"].join("-"), "any-model"],
]);

export const USER_RULE_MODES: ReadonlySet<string> = new Set(["allow", "block", "audit", "off"]);
export const DISPOSITION_MODES: ReadonlySet<string> = new Set(["ask", "block"]);
const LIST_REF = /^@([A-Za-z0-9_.-]+)$/;
/** A `lists:` name (the part after `@`). */
export const LIST_NAME_RE = /^[A-Za-z0-9_.-]+$/;

/** Built-in rule ids an operator may set a disposition on: egress rules that
 *  ASK by default (a deny or an allow has nothing to tighten into a block). */
export function dispositionableRuleIds(): string[] {
  return Object.entries(RULES)
    .filter(([id, r]) => id.startsWith("egress:") && (r as { outcome: string }).outcome === "deny+approval")
    .map(([id]) => id);
}

function checkListRefs(values: unknown, lists: Set<string>, at: string, out: string[]): void {
  if (!Array.isArray(values)) return; // shape errors are reported by checkStringList
  values.forEach((v, i) => {
    if (typeof v !== "string") return;
    const m = LIST_REF.exec(v);
    if (m && !lists.has(m[1]!)) out.push(`${at}[${i}]: references list '@${m[1]}' which is not defined under lists`);
  });
}

function checkHostRef(v: unknown, lists: Set<string>, at: string, out: string[]): void {
  if (typeof v !== "string" || v.trim() === "") {
    out.push(`${at}: must be a host, "*", or an @list reference`);
    return;
  }
  const m = LIST_REF.exec(v);
  if (m && !lists.has(m[1]!)) out.push(`${at}: references list '@${m[1]}' which is not defined under lists`);
}

function checkPaths(v: unknown, at: string, out: string[]): void {
  if (!Array.isArray(v)) {
    out.push(`${at}: must be a list of { path, level, bindings?, recursive?, extract?, readers?, others?, values? }`);
    return;
  }
  v.forEach((entry, i) => {
    const here = `${at}[${i}]`;
    if (!isPlainObject(entry)) {
      out.push(`${here}: must be a mapping with 'path' and 'level'`);
      return;
    }
    checkKeys(entry, ["path", "level", "bindings", "recursive", "extract", "readers", "others", "values"], here, out);
    if ("values" in entry) checkValues(entry.values, `${here}.values`, out);
    if ("readers" in entry) checkReaders(entry.readers, `${here}.readers`, out, { withOutput: true });
    if ("others" in entry && entry.others !== "deny" && entry.others !== "twin") out.push(`${here}.others: must be deny or twin`);
    if ("others" in entry && !("readers" in entry)) out.push(`${here}.others: only meaningful with a readers list`);
    const p = entry.path;
    if (typeof p === "string" && hasGlobMeta(p)) {
      // A gitignore-style PATTERN (path-glob.ts): anchored at '/', '~/' or a
      // leading '**' segment. Every reason it does not parse is listed; a law
      // with a pattern that means something else than its author wrote never loads.
      const r = compilePathGlob(p);
      if ("errors" in r) for (const e of r.errors) out.push(`${here}.path: pattern ${JSON.stringify(p)}: ${e}`);
    } else if (typeof p !== "string" || !(p.startsWith("/") || p === "~" || p.startsWith("~/"))) {
      out.push(`${here}.path: must be an absolute path or ~/…, or a pattern anchored at '/', '~/' or '**/' (got ${JSON.stringify(p)})`);
    }
    if (!LEVELS.has(entry.level as string)) {
      const renamed = RETIRED_LEVELS.get(entry.level as string);
      const hint = renamed ? `; that name was retired on 2026-09-27, write ${renamed}` : "";
      out.push(`${here}.level: must be public | any-model | local-model | no-model (got ${JSON.stringify(entry.level)}${hint})`);
    }
    if ("bindings" in entry) checkStringList(entry.bindings, `${here}.bindings`, out);
    if ("recursive" in entry && typeof entry.recursive !== "boolean") out.push(`${here}.recursive: must be true or false`);
    if ("extract" in entry) {
      if (typeof entry.extract !== "string" || entry.extract === "") out.push(`${here}.extract: must be a non-empty regex string`);
      else {
        try {
          if (new RegExp(entry.extract).exec("")?.length === 1 && !/\((?!\?)/.test(entry.extract)) out.push(`${here}.extract: needs one capturing group (the secret span)`);
        } catch (e) {
          out.push(`${here}.extract: invalid regex (${(e as Error).message})`);
        }
      }
    }
  });
}

/** Plan 13 §5.2: `values: { KEY: { bindings: [host, …] } }`, KEY the field
 *  name the file's symbols carry, `*` globs allowed. Accepted at every
 *  level: under `public` it decides nothing (nothing of the file is
 *  secret), and the dashboard's label menu keeps it there rather than drop
 *  what the person wrote. */
function checkValues(v: unknown, at: string, out: string[]): void {
  if (!isPlainObject(v) || Object.keys(v).length === 0) {
    out.push(`${at}: must be a mapping of field names to { bindings: [host, …] }`);
    return;
  }
  for (const [key, entry] of Object.entries(v)) {
    const here = `${at}.${JSON.stringify(key)}`;
    if (!isValueKey(key)) out.push(`${here}: a field name has no space or control character and at most ${VALUE_KEY_MAX} characters ('*' matches any run)`);
    if (!isPlainObject(entry)) {
      out.push(`${here}: must be a mapping { bindings: [host, …] }`);
      continue;
    }
    checkKeys(entry, ["bindings"], here, out);
    if (!("bindings" in entry)) out.push(`${here}.bindings: required (an empty list keeps the value from leaving without an ask)`);
    else checkStringList(entry.bindings, `${here}.bindings`, out);
  }
}

/** A `blobs:` id (confidentiality-plan-14 §8.2): the object format and the
 *  full object name, lowercase. */
export const BLOB_ID_RE = /^(sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$/;
/** A `blobs:` note: one line for the person reading the file. */
export const BLOB_NOTE_MAX = 200;

/** Plan 14 §8.2: `blobs: [{ id, level, note? }]`, one entry per id. */
function checkBlobs(v: unknown, at: string, out: string[]): void {
  if (!Array.isArray(v)) {
    out.push(`${at}: must be a list of { id: sha1:<40 hex> | sha256:<64 hex>, level, note? }`);
    return;
  }
  const seen = new Set<string>();
  v.forEach((entry, i) => {
    const here = `${at}[${i}]`;
    if (!isPlainObject(entry)) { out.push(`${here}: must be a mapping with 'id' and 'level'`); return; }
    checkKeys(entry, ["id", "level", "note"], here, out);
    if (typeof entry.id !== "string" || !BLOB_ID_RE.test(entry.id)) {
      out.push(`${here}.id: must be sha1:<40 hex digits> or sha256:<64 hex digits>, lowercase (got ${JSON.stringify(entry.id)})`);
    } else if (seen.has(entry.id)) {
      out.push(`${here}.id: ${entry.id} is listed twice`);
    } else seen.add(entry.id);
    if (!LEVELS.has(entry.level as string)) {
      const renamed = RETIRED_LEVELS.get(entry.level as string);
      const hint = renamed ? `; that name was retired on 2026-09-27, write ${renamed}` : "";
      out.push(`${here}.level: must be public | any-model | local-model | no-model (got ${JSON.stringify(entry.level)}${hint})`);
    }
    if ("note" in entry && (typeof entry.note !== "string" || entry.note.length > BLOB_NOTE_MAX || /[\u0000-\u001f\u007f]/.test(entry.note))) {
      out.push(`${here}.note: must be one line of at most ${BLOB_NOTE_MAX} characters`);
    }
  });
}

/** Plan 10 §2.2: `apps: [{ app, output, mask? }]`. An interpreter may only be
 *  `secret` (an agent-authored script would read a secret and print it). */
function checkApps(v: unknown, at: string, out: string[]): void {
  if (!Array.isArray(v)) {
    out.push(`${at}: must be a list of { app, output: secret | clear | mask, mask? }`);
    return;
  }
  v.forEach((entry, i) => {
    const here = `${at}[${i}]`;
    if (!isPlainObject(entry)) { out.push(`${here}: must be a mapping with 'app' and 'output'`); return; }
    checkKeys(entry, ["app", "output", "mask"], here, out);
    if (typeof entry.app !== "string" || entry.app.trim() === "" || entry.app.includes("/")) out.push(`${here}.app: must be a program name`);
    checkOutputRule(entry, here, out, (output) => (typeof entry.app === "string" ? appRuleRefusal({ app: entry.app, output }) : null));
  });
}

/** An `output:` (and `mask:`) on an `apps:` entry or a reader entry: one of
 *  the three rules; `mask` needs at least one valid regex and only `mask`
 *  takes one; `refusal` names a program that may not carry the rule. */
function checkOutputRule(entry: Record<string, unknown>, here: string, out: string[], refusal: (output: "clear" | "mask") => string | null): void {
  const output = entry["output"];
  if (output !== "secret" && output !== "clear" && output !== "mask") out.push(`${here}.output: must be secret, clear or mask (got ${JSON.stringify(output)})`);
  if (output === "clear" || output === "mask") {
    const why = refusal(output);
    if (why) out.push(`${here}: ${why}`);
  }
  const mask = entry["mask"];
  if (output === "mask") {
    if (!Array.isArray(mask) || mask.length === 0) out.push(`${here}.mask: a mask rule needs at least one regex`);
    else mask.forEach((m: unknown, j: number) => {
      if (typeof m !== "string" || m === "") { out.push(`${here}.mask[${j}]: must be a non-empty regex string`); return; }
      try { new RegExp(m); } catch (e) { out.push(`${here}.mask[${j}]: invalid regex (${(e as Error).message})`); }
    });
  } else if ("mask" in entry) out.push(`${here}.mask: only meaningful with output: mask`);
}

/** Plan 10 §11.4: `env: { secrets?: [NAME | PREFIX_*], exempt?: [NAME | PREFIX_*] }`.
 *  A name is an environment-variable identifier, `*` allowed as a glob; the
 *  same name in both lists is a contradiction the loader refuses. */
const ENV_NAME_PATTERN_RE = /^[A-Za-z_*][A-Za-z0-9_*]*$/;
function checkEnv(v: unknown, at: string, out: string[]): void {
  if (!isPlainObject(v)) {
    out.push(`${at}: must be a mapping with 'secrets' and/or 'exempt' lists of variable names`);
    return;
  }
  checkKeys(v, ["secrets", "exempt", "sources"], at, out);
  if ("sources" in v) checkEnvSources(v["sources"], `${at}.sources`, out);
  const seen: Record<"secrets" | "exempt", Set<string>> = { secrets: new Set(), exempt: new Set() };
  for (const key of ["secrets", "exempt"] as const) {
    if (!(key in v)) continue;
    const list = v[key];
    if (!Array.isArray(list)) { out.push(`${at}.${key}: must be a list of variable names (PREFIX_* allowed)`); continue; }
    list.forEach((n: unknown, i: number) => {
      if (typeof n !== "string" || !ENV_NAME_PATTERN_RE.test(n)) { out.push(`${at}.${key}[${i}]: must be a variable name or PREFIX_* pattern (got ${JSON.stringify(n)})`); return; }
      if (n === "*") { out.push(`${at}.${key}[${i}]: '*' alone would ${key === "secrets" ? "mask" : "exempt"} every variable`); return; }
      seen[key].add(n);
    });
  }
  for (const n of seen.secrets) if (seen.exempt.has(n)) out.push(`${at}: ${JSON.stringify(n)} is in both secrets and exempt`);
}

/** A reader list (`paths[].readers`, `ssh_agent.readers`): program names or
 *  `{ app, path?, sha256?, from? }` pins. On a file's list (`withOutput`) an
 *  entry may also carry its output rule, `output: secret | clear | mask` and
 *  `mask:` (Plan 13 D3); a program that runs code may only be `secret`
 *  (`readerOutputRefusal`), unless the entry pins the script it runs:
 *  `script:` (absolute, canonical) and `scriptSha256:` (Plan 13 R5), only
 *  for an interpreter whose script can be pinned (`scriptInterpreterFamily`). */
const SCRIPT_PATH_RE = /^\/(?:[^/]+\/)*[^/]+$/;
function checkReaders(readers: unknown, at: string, out: string[], opts: { withOutput?: boolean } = {}): void {
  if (!Array.isArray(readers)) out.push(`${at}: must be a list of app names or { app, path?, sha256?, from?, prints?${opts.withOutput ? ", output?, mask?, script?, scriptSha256?" : ""} } pins`);
  else readers.forEach((r: unknown, j: number) => {
    const rh = `${at}[${j}]`;
    if (typeof r === "string") { if (r.trim() === "" || r.includes("/")) out.push(`${rh}: a bare reader is a program name, not a path (got ${JSON.stringify(r)})`); return; }
    if (!isPlainObject(r)) { out.push(`${rh}: must be an app name or { app, path?, sha256? }`); return; }
    checkKeys(r, opts.withOutput ? ["app", "path", "sha256", "from", "output", "mask", "script", "scriptSha256", "prints"] : ["app", "path", "sha256", "from", "prints"], rh, out);
    // Plan 13 D8 (12): the human's word that the program keeps the file's
    // contents out of what it prints, writes and sends.
    if ("prints" in r && r.prints !== "nothing") out.push(`${rh}.prints: the only value is nothing (prints: nothing, your word that ${typeof r.app === "string" ? r.app : "the program"} keeps what it reads out of what it prints)`);
    const script = typeof r.script === "string" ? r.script : undefined;
    if (opts.withOutput && ("output" in r || "mask" in r)) {
      checkOutputRule(r, rh, out, (output) => (typeof r.app === "string" ? readerOutputRefusal(r.app, output, script) : null));
    }
    if (opts.withOutput && "script" in r) {
      // Plan 13 R5: the (interpreter, script) pin.
      if (script === undefined || !SCRIPT_PATH_RE.test(script) || script.split("/").some((c) => c === "." || c === "..")) {
        out.push(`${rh}.script: must be the script's absolute path, written as the file's own (no ., .. or //)`);
      }
      if (typeof r.app === "string" && scriptInterpreterFamily(r.app) === null) {
        out.push(/^ruby(\.|$)/.test(r.app)
          ? `${rh}.script: ruby loads code from the user's gem directory, which the agent can write, so a ruby script cannot be pinned`
          : `${rh}.script: pins the script an interpreter runs (python, node, a shell or perl); ${r.app} is not one`);
      }
    }
    if (opts.withOutput && "scriptSha256" in r) {
      if (!("script" in r)) out.push(`${rh}.scriptSha256: only meaningful with script:`);
      if (typeof r.scriptSha256 !== "string" || !/^[0-9a-f]{64}$/.test(r.scriptSha256)) out.push(`${rh}.scriptSha256: must be 64 hex characters`);
    }
    if ("from" in r && (typeof r.from !== "string" || r.from.trim() === "" || r.from.includes("/"))) out.push(`${rh}.from: must be the program name that starts this reader (e.g. git)`);
    if (typeof r.app !== "string" || r.app.trim() === "") out.push(`${rh}.app: must be a program name`);
    if ("path" in r && (typeof r.path !== "string" || !r.path.startsWith("/"))) out.push(`${rh}.path: must be an absolute executable path`);
    if ("sha256" in r && (typeof r.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(r.sha256))) out.push(`${rh}.sha256: must be 64 hex characters`);
  });
}

/**
 * Plan 13 D8 and §8 decision (b): the advice a valid document still
 * deserves. Not errors (the arbiter starts, the law is in force as
 * written): a reader that is a shell, an interpreter or a command launcher
 * (`readerRunsCode`) without a `script:` pin admits nothing since
 * 2026-10-02 (`entryAdmitsNothing`; it runs whatever code the agent hands
 * it). Since 2026-10-03 (Plan 13 D8, printers admit nothing) the same
 * holds for a program that prints or copies a file (`readerPrints`: cat,
 * head, base64, cp, …) in any form, a pin by path and hash included: it
 * would hand the bytes to whatever reads its output. A warning rather than
 * a refusal, chosen so a law written before the change still loads (a
 * refusal would stop every session until the file is edited) while the
 * entry is already inert at runtime. One line per such reader, naming
 * where it is and what to write instead.
 */
export function policyWarnings(doc: unknown): string[] {
  const out: string[] = [];
  if (!isPlainObject(doc)) return out;
  const scan = (readers: unknown, at: string, what: string): void => {
    if (!Array.isArray(readers)) return;
    readers.forEach((r: unknown, j: number) => {
      const app = typeof r === "string" ? r : isPlainObject(r) && typeof r.app === "string" ? r.app : null;
      if (app === null) return;
      // Plan 13 D8, printers admit nothing (2026-10-03), for a file's reader
      // list and, since leftover (3b) of !437, the ssh-agent socket's: a
      // printer that connects to it (`socat`, `openssl s_client -unix`)
      // relays the agent to whatever drives it; the guard refuses it
      // (secret_open.rs `socket_reader_match`).
      const pinnedPath = isPlainObject(r) && typeof r.path === "string" ? r.path : null;
      // Plan 13 D8 (12): the human's word cannot lift a printer or a program
      // that runs code; the warning says so.
      const vouched = isPlainObject(r) && r.prints === "nothing";
      const noWord = vouched ? ` prints: nothing cannot change that.` : "";
      // 2026-10-07: a script named as a printer (a git credential helper,
      // `…/git-credential-netrc`) admits nothing, whatever runs it.
      const pinnedScript = isPlainObject(r) && typeof r.script === "string" ? r.script : undefined;
      if (scriptPrints(pinnedScript)) {
        const s = pinnedScript!.slice(pinnedScript!.lastIndexOf("/") + 1);
        out.push(`${at}[${j}]: ${app} running ${s} is a printer: a git credential helper prints the password it reads (\`get\` answers password=…) to whatever reads its output (which can be the AI's own code), so this entry admits nothing: ${s} reads ${what} raw through no interpreter; it gets what any other program gets. With TLS inspection on, git still logs in to an HTTPS remote with the copy of a credential file whose password is a placeholder.` + noWord);
        return;
      }
      if (readerPrints(app)|| (pinnedPath !== null && readerPrints(pinnedPath))) {
        // Plan 13 §4.9 option (a) (2026-10-04): git is a printer; say how
        // and what still works, since it is also a credential consumer.
        const bases = [app, ...(pinnedPath !== null ? [pinnedPath] : [])].map((n) => n.slice(n.lastIndexOf("/") + 1));
        const git = bases.some((n) => /^git(-|\.|$)/.test(n));
        // git's transports, separate programs (2026-10-07): how they print
        // is not `git diff`'s
        const transport = bases.some((n) => /^git-(remote-|http-|imap-send)/.test(n));
        const helper = bases.some((n) => n.startsWith("git-credential-"));
        const how = helper
          ? "a git credential helper prints the password it reads (`get` answers password=…)"
          : transport
          ? "it prints the login it sends (GIT_TRACE_CURL=1 with GIT_TRACE_REDACT=0), the one it read from .netrc included, or, git-http-backend, a file a request names,"
          : "it prints any file it is pointed at (git diff --no-index /dev/null <file>, git grep --no-index, git config -f <file> --list)";
        out.push((at === "ssh_agent.readers"
          ? `${at}[${j}]: ${app} prints or copies what it reads, so on the ssh-agent's list it would relay your ssh-agent to whatever drives it (which can be the AI's own code); this entry admits nothing: no ${app} reaches your ssh-agent through it. Name the program that uses the agent instead (e.g. ssh, ssh-add${git ? ", or { app: ssh, from: git } for the ssh git starts" : ""}).`
          : git
            ? `${at}[${j}]: ${app} is a printer: ${how} to whatever reads its output (which can be the AI's own code), so this entry admits nothing: no ${app} reads ${what} raw through it, a pin by path and hash included; it gets what any other program gets. With TLS inspection on, git still logs in to an HTTPS remote with the copy of .git-credentials or .netrc whose password is a placeholder; for an ssh key, name ssh ({ app: ssh, from: git } for the ssh git starts).`
            : `${at}[${j}]: ${app} prints or copies the bytes it reads to whatever reads its output (which can be the AI's own code), so this entry admits nothing: no ${app} reads ${what} raw through it, a pin by path and hash included; it gets what any other program gets. Name the program that uses the secret instead (e.g. pg_dump, aws), not one that prints it.`) + noWord);
        return;
      }
      // The !437 leftover (2): a pin whose hash is a printer's on this host
      // (a copy under another name) is that printer.
      const pinnedSha = isPlainObject(r) && typeof r.sha256 === "string" ? r.sha256 : undefined;
      if (at !== "ssh_agent.readers" && hashPrints(pinnedSha)) {
        out.push(`${at}[${j}]: ${app} is a copy of a program that prints or copies the bytes it reads (its sha256 is that of a printer installed on this host: ${hostProgramOf("prints", pinnedSha) || "such as cat"}), so this entry admits nothing: no ${app} reads ${what} raw through it; it gets what any other program gets. Name the program that uses the secret instead (e.g. pg_dump, aws), not one that prints it.` + noWord);
        return;
      }
      // Plan 13 §8 decision (b) by content (2026-10-03): a pin whose hash is
      // a code-running program's on this host (`cp /usr/bin/python3
      // ~/bin/mytool`) is that program, and a renamed copy carries no
      // script pin (its interpreter is named by `app:`).
      const copy = at !== "ssh_agent.readers" && pinnedSha !== undefined
        ? renamedCopyOf({ app, ...(pinnedPath !== null ? { path: pinnedPath } : {}), sha256: pinnedSha }) : null;
      if (copy?.kind === "runsCode") {
        out.push(`${at}[${j}]: ${app} is a copy of ${copy.of} (its sha256 is that of ${copy.of} installed on this host), a program that runs any code it is given, so this entry admits nothing: no ${app} reads ${what} raw through it, whatever it is named, a script pin included. Name the program that needs the file instead (e.g. pg_dump, aws), or, for a script of your own out of the agent's reach, pin it with the installed interpreter ({ app: ${copy.of}, script: /absolute/path/of/the/script }).` + noWord);
        return;
      }
      const scriptPin = isPlainObject(r) && typeof r.script === "string";
      if (readerRunsCode(app) && !scriptPin) {
        const pinnable = scriptInterpreterFamily(app) !== null && at !== "ssh_agent.readers";
        out.push(`${at}[${j}]: ${app} runs any code it is given (a shell, an interpreter or a launcher), so this entry admits nothing: no ${app} reads ${what} raw through it, inline code (${app} -c …) included. Name the program that needs the file instead (e.g. pg_dump, aws)${pinnable ? `, or, for a script of your own out of the agent's reach, pin it with the interpreter ({ app: ${app}, script: /absolute/path/of/the/script, prints: nothing })` : ""}.${noWord}`);
        return;
      }
      // Plan 13 D8 (12), the allow-list (2026-10-04): a program that is not
      // vetted reads the placeholder copy unless the entry carries the
      // human's word. A pin is no word: Mandu writes pins too.
      if (vouched || (!scriptPin && readerVetted(pinnedPath ?? app))) return;
      const named = scriptPin ? `${app} running ${String((r as { script: string }).script)}` : app;
      const fix = scriptPin ? `{ app: ${app}, script: ${String((r as { script: string }).script)}, prints: nothing }` : `{ app: ${app}, prints: nothing }`;
      out.push(at === "ssh_agent.readers"
        ? `${at}[${j}]: ${named} is not a program Mandu knows keeps what it reads out of what it prints, so it does not reach your ssh-agent through this entry. If you are sure it does, write ${fix}.`
        : `${at}[${j}]: ${named} is not a program Mandu knows keeps a file's contents out of what it prints, so it reads the placeholder copy of ${what}. If you are sure it does, write ${fix}.`);
    });
  };
  if (Array.isArray(doc.paths)) {
    doc.paths.forEach((e: unknown, i: number) => {
      if (isPlainObject(e) && "readers" in e) scan(e.readers, `paths[${i}].readers`, typeof e.path === "string" ? e.path : "the file");
    });
  }
  if (isPlainObject(doc.ssh_agent)) scan(doc.ssh_agent.readers, "ssh_agent.readers", "your ssh-agent");
  // Plan 13 D3: the program-wide output rule is deprecated. It cleared the
  // program's output for every file it read, not only the one the rule was
  // written for, so it now clears nothing; the rule belongs on the reader
  // entry of that file.
  if (Array.isArray(doc.apps)) {
    doc.apps.forEach((e: unknown, i: number) => {
      if (!isPlainObject(e) || typeof e.app !== "string" || (e.output !== "clear" && e.output !== "mask")) return;
      const entry = e.output === "mask" ? `{ app: ${e.app}, output: mask, mask: [...] }` : `{ app: ${e.app}, output: ${e.output} }`;
      out.push(`apps[${i}]: a program-wide output rule is deprecated and no longer clears anything: ${e.app}'s output stays masked after it reads any secret. It applied to every file ${e.app} reads, not only the one you meant. Write it on the reader entry of that file instead: paths: [{ path: <the file>, readers: [${entry}] }].`);
    });
  }
  return out;
}

/** `ssh_agent: { readers }` (comparisons.md §3.5): who may use the
 *  ssh-agent socket ($SSH_AUTH_SOCK). */
function checkSshAgent(v: unknown, at: string, out: string[]): void {
  if (!isPlainObject(v)) { out.push(`${at}: must be { readers: [...] }`); return; }
  checkKeys(v, ["readers"], at, out);
  if (!("readers" in v)) out.push(`${at}.readers: required (the programs that may use the ssh-agent)`);
  else checkReaders(v["readers"], `${at}.readers`, out);
}

/** `env.sources` (comparisons.md §3.4): `{ name, source, bindings? }`. */
export const ENV_SOURCE_RE = /^(cmd:\S.*|keyring:[^/\s]+\/\S+|op:\/\/\S+)$/;
const ENV_VAR_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const BINDING_HOST_RE = /^(\*\.)?[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:\d+)?$/;
function checkEnvSources(v: unknown, at: string, out: string[]): void {
  if (!Array.isArray(v)) { out.push(`${at}: must be a list of { name, source, bindings? }`); return; }
  const names = new Set<string>();
  v.forEach((e: unknown, i: number) => {
    const here = `${at}[${i}]`;
    if (!isPlainObject(e)) { out.push(`${here}: must be { name, source, bindings? }`); return; }
    checkKeys(e, ["name", "source", "bindings"], here, out);
    if (typeof e["name"] !== "string" || !ENV_VAR_NAME_RE.test(e["name"])) out.push(`${here}.name: must be a variable name (got ${JSON.stringify(e["name"])})`);
    else if (names.has(e["name"])) out.push(`${here}.name: ${e["name"]} has two sources`);
    else names.add(e["name"]);
    if (typeof e["source"] !== "string" || !ENV_SOURCE_RE.test(e["source"])) {
      out.push(`${here}.source: must be cmd:<command>, keyring:<service>/<account> or op://<vault>/<item>/<field> (got ${JSON.stringify(e["source"])})`);
    }
    if ("bindings" in e) {
      const b = e["bindings"];
      if (!Array.isArray(b) || b.some((h) => typeof h !== "string" || !BINDING_HOST_RE.test(h))) out.push(`${here}.bindings: must be a list of host names`);
    }
  });
}

function checkDispositions(v: unknown, at: string, out: string[]): void {
  if (!isPlainObject(v)) {
    out.push(`${at}: must be a mapping of built-in rule id → { mode: ask | block }`);
    return;
  }
  const allowed = new Set(dispositionableRuleIds());
  for (const [id, d] of Object.entries(v)) {
    const here = `${at}.${id}`;
    if (!allowed.has(id)) {
      out.push(`${here}: not a built-in rule that asks by default (allowed: ${[...allowed].join(", ")})`);
      continue;
    }
    if (!isPlainObject(d)) {
      out.push(`${here}: must be { mode: ask | block }`);
      continue;
    }
    checkKeys(d, ["mode"], here, out);
    if (!DISPOSITION_MODES.has(d.mode as string)) out.push(`${here}.mode: must be ask or block (got ${JSON.stringify(d.mode)})`);
  }
}

function checkUserRules(v: unknown, lists: Set<string>, at: string, out: string[]): void {
  if (!Array.isArray(v)) {
    out.push(`${at}: must be a list of rules`);
    return;
  }
  const ids = new Set<string>();
  v.forEach((rule, i) => {
    const here = `${at}[${i}]`;
    if (!isPlainObject(rule)) {
      out.push(`${here}: must be a mapping`);
      return;
    }
    checkKeys(rule, ["id", "kind", "from", "to", "mode", "reason", "by", "added", "expires", "audit"], here, out);
    if (typeof rule.id !== "string" || rule.id.trim() === "") out.push(`${here}.id: must be a non-empty string`);
    else if (ids.has(rule.id)) out.push(`${here}.id: duplicate id '${rule.id}'`);
    else ids.add(rule.id);
    if (rule.kind !== "release") out.push(`${here}.kind: must be "release" (got ${JSON.stringify(rule.kind)})`);
    if ("from" in rule) {
      if (!isPlainObject(rule.from)) out.push(`${here}.from: must be { host }`);
      else {
        checkKeys(rule.from, ["host"], `${here}.from`, out);
        if ("host" in rule.from) checkHostRef(rule.from.host, lists, `${here}.from.host`, out);
      }
    }
    if (!isPlainObject(rule.to)) out.push(`${here}.to: must be { host } ("*" = any destination)`);
    else {
      checkKeys(rule.to, ["host"], `${here}.to`, out);
      checkHostRef(rule.to.host, lists, `${here}.to.host`, out);
    }
    if (!USER_RULE_MODES.has(rule.mode as string)) out.push(`${here}.mode: must be allow | block | audit | off (got ${JSON.stringify(rule.mode)})`);
    if ("expires" in rule && rule.expires !== null && (typeof rule.expires !== "string" || Number.isNaN(Date.parse(rule.expires)))) {
      out.push(`${here}.expires: must be an ISO date/time or null (got ${JSON.stringify(rule.expires)})`);
    }
    for (const s of ["reason", "by", "added"]) {
      if (s in rule && typeof rule[s] !== "string") out.push(`${here}.${s}: must be a string`);
    }
    if ("audit" in rule) out.push(`${here}.audit: use mode: audit instead`);
  });
}

/** `destinations:` (policy-surface.md §2.3, stage 4b) — reachability
 *  rules for the launcher's connect-guard. Allow-only today: the guard is an
 *  allow-list (first match, deny the rest), so a `deny` has nothing to attach
 *  to until the guard grows a deny rule — refused with the alternative. */
function checkDestinations(v: unknown, lists: Set<string>, at: string, out: string[]): void {
  if (!Array.isArray(v)) {
    out.push(`${at}: must be a list of { host, port?, proto?, connect }`);
    return;
  }
  v.forEach((d, i) => {
    const here = `${at}[${i}]`;
    if (!isPlainObject(d)) {
      out.push(`${here}: must be a mapping`);
      return;
    }
    checkKeys(d, ["host", "port", "proto", "connect", "reason"], here, out);
    checkHostRef(d.host, lists, `${here}.host`, out);
    if ("port" in d && d.port !== "*" && !(typeof d.port === "number" && Number.isInteger(d.port) && d.port >= 1 && d.port <= 65535)) {
      out.push(`${here}.port: must be an integer 1–65535 or "*" (got ${JSON.stringify(d.port)})`);
    }
    if ("proto" in d && d.proto !== "tcp" && d.proto !== "udp") out.push(`${here}.proto: must be tcp | udp (got ${JSON.stringify(d.proto)})`);
    if (d.connect === "deny") {
      out.push(`${here}.connect: "deny" is not enforceable yet — the connect-guard is allow-list only (every unlisted destination is already denied under --landlock-net-strict / --net-allow); to stop masked data from being SENT there use user_rules (kind: release, mode: block)`);
    } else if (d.connect !== "allow") {
      out.push(`${here}.connect: must be "allow" (got ${JSON.stringify(d.connect)})`);
    }
    if ("reason" in d && typeof d.reason !== "string") out.push(`${here}.reason: must be a string`);
  });
}

/** A `sensitivity_labels:` name: the person's words for a label, one line. */
export const SENSITIVITY_LABEL_NAME_MAX = 64;

/**
 * Plan 14 §14.1: `sensitivity_labels: [{ id, site?, name, level }]`. `id`
 * and `site` are GUIDs (braces and case optional; compared lowercase without
 * braces), one entry per (id, site); `name` is 1-64 characters on one line;
 * `level` one of the four. The section changes what the scans suggest, never
 * what is enforced.
 */
export function checkSensitivityLabels(v: unknown, at: string, out: string[]): void {
  if (!Array.isArray(v)) {
    out.push(`${at}: must be a list of { id: <label GUID>, site?: <tenant GUID>, name, level }`);
    return;
  }
  const seen = new Set<string>();
  v.forEach((entry, i) => {
    const here = `${at}[${i}]`;
    if (!isPlainObject(entry)) { out.push(`${here}: must be a mapping with 'id', 'name' and 'level'`); return; }
    checkKeys(entry, ["id", "site", "name", "level"], here, out);
    const id = normalizeGuid(entry.id);
    if (id === null) out.push(`${here}.id: must be a label GUID like 9fbde396-1a24-4c79-8edf-9254a0f35055 (got ${JSON.stringify(entry.id)})`);
    const site = "site" in entry ? normalizeGuid(entry.site) : null;
    if ("site" in entry && site === null) out.push(`${here}.site: must be a tenant GUID like 5b3c2d4e-0000-4000-8000-000000000000 (got ${JSON.stringify(entry.site)})`);
    if (id !== null && (site !== null || !("site" in entry))) {
      const k = `${id}|${site ?? ""}`;
      if (seen.has(k)) out.push(`${here}.id: ${id}${site ? ` (site ${site})` : ""} is listed twice`);
      else seen.add(k);
    }
    if (typeof entry.name !== "string" || entry.name.trim() === "" || entry.name.length > SENSITIVITY_LABEL_NAME_MAX || /[\u0000-\u001f\u007f-\u009f]/.test(entry.name)) {
      out.push(`${here}.name: must be one line of 1 to ${SENSITIVITY_LABEL_NAME_MAX} characters (the label's name in your words)`);
    }
    if (!LEVELS.has(entry.level as string)) {
      const renamed = RETIRED_LEVELS.get(entry.level as string);
      const hint = renamed ? `; that name was retired on 2026-09-27, write ${renamed}` : "";
      out.push(`${here}.level: must be public | any-model | local-model | no-model (got ${JSON.stringify(entry.level)}${hint})`);
    }
  });
}

/** A model endpoint name (plan 11 D2): what `resolve(deep, endpoint)` names. */
export const MODEL_NAME_RE = /^[A-Za-z0-9_.-]{1,64}$/;
const ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** policy.yaml `models:` (plan 11 D2). Shape, plus two content rules: a
 *  `local: true` entry may not name a cloud-backed model (plan 11 §8 item 3,
 *  cloud-model.ts), and a `local: true` entry on another machine must use
 *  https unless it says `allow_plain_http: true` (plan 12 D2,
 *  model-placement.ts). The proxy and forwarder addresses a `local: true` entry
 *  may not name are per session and known to the launcher, which refuses
 *  such a launch (plan 11 §5 note); inspect-mcp refuses to send to them as
 *  well. */
function checkModels(v: unknown, at: string, out: string[]): void {
  if (!Array.isArray(v)) {
    out.push(`${at}: must be a list of { name, url, wire?, model?, local?, token_env?, helper?, allow_plain_http?, tls? }`);
    return;
  }
  const names = new Set<string>();
  let helperAt: string | null = null;
  v.forEach((entry, i) => {
    const here = `${at}[${i}]`;
    if (!isPlainObject(entry)) {
      out.push(`${here}: must be a mapping with 'name' and 'url'`);
      return;
    }
    // Plan 12 D5: `{ name, disabled: true }` removes an administrator's entry
    // (admin-layer.ts judges the name); it carries nothing else.
    if ("disabled" in entry) {
      if (entry.disabled !== true) out.push(`${here}.disabled: must be true (leave it out otherwise)`);
      checkKeys(entry, ["name", "disabled"], here, out);
      if (typeof entry.name !== "string" || !MODEL_NAME_RE.test(entry.name)) out.push(`${here}.name: must be 1-64 letters, digits, _ . - (got ${JSON.stringify(entry.name)})`);
      else if (names.has(entry.name)) out.push(`${here}.name: '${entry.name}' is declared twice`);
      else names.add(entry.name);
      return;
    }
    checkKeys(entry, ["name", "url", "wire", "model", "local", "token_env", "helper", "allow_plain_http", "tls"], here, out);
    // Plan 12 D3: the endpoint's identity checks (files read and parsed here).
    checkModelTls(entry, here, out);
    if (typeof entry.name !== "string" || !MODEL_NAME_RE.test(entry.name)) {
      out.push(`${here}.name: must be 1-64 letters, digits, _ . - (got ${JSON.stringify(entry.name)})`);
    } else if (names.has(entry.name)) {
      out.push(`${here}.name: '${entry.name}' is declared twice`);
    } else {
      names.add(entry.name);
    }
    let url: URL | null = null;
    try { url = typeof entry.url === "string" ? new URL(entry.url) : null; } catch { url = null; }
    if (url === null || (url.protocol !== "http:" && url.protocol !== "https:") || url.username !== "" || url.password !== "") {
      out.push(`${here}.url: must be an http(s) URL with no credentials in it (got ${JSON.stringify(entry.url)})`);
    }
    if ("wire" in entry && entry.wire !== "anthropic" && entry.wire !== "openai-chat") {
      out.push(`${here}.wire: must be anthropic or openai-chat (got ${JSON.stringify(entry.wire)})`);
    }
    if ("model" in entry && (typeof entry.model !== "string" || entry.model === "")) out.push(`${here}.model: must be a non-empty string`);
    if ("local" in entry && typeof entry.local !== "boolean") out.push(`${here}.local: must be true or false`);
    // Plan 11 §8 item 3: a cloud-backed model name (Ollama's `:cloud` /
    // `-cloud` tags) runs on the vendor's servers behind the same loopback
    // API, so the entry cannot be the operator's own model (cloud-model.ts).
    // A non-local entry may name one: it is external either way.
    if (entry.local === true && typeof entry.model === "string" && isCloudBackedModel(entry.model)) {
      out.push(
        `${here}.model: '${entry.model}' runs on the vendor's servers (a cloud model), so '${typeof entry.name === "string" ? entry.name : `models[${i}]`}' cannot be local: true; ` +
          "name a model that runs on your own machine, or remove local: true",
      );
    }
    // Plan 12 D2: a `local: true` entry on another machine (placement
    // `network`) receives local-model files, so plain http would carry them
    // across the network in the clear. Refused unless the entry opts out
    // explicitly; the opt-out is meaningless (and refused) on https.
    if ("allow_plain_http" in entry && typeof entry.allow_plain_http !== "boolean") {
      out.push(`${here}.allow_plain_http: must be true or false`);
    } else if (entry.allow_plain_http === true && url !== null && url.protocol === "https:") {
      out.push(`${here}.allow_plain_http: the url is already https, so there is nothing to allow; remove allow_plain_http`);
    }
    if (entry.local === true && typeof entry.url === "string" && isPlainHttpToNetwork(entry.url) && entry.allow_plain_http !== true) {
      const label = typeof entry.name === "string" ? entry.name : `models[${i}]`;
      out.push(
        `${here}.url: '${label}' is on another machine and would receive local-model files in the clear; ` +
          "use https, reach it through a loopback tunnel (ssh -L), or add allow_plain_http: true to accept that",
      );
    }
    if ("token_env" in entry && (typeof entry.token_env !== "string" || !ENV_NAME_RE.test(entry.token_env))) {
      out.push(`${here}.token_env: must be an environment variable NAME (the token itself never goes in policy.yaml)`);
    }
    // `helper: true` picks the quarantined helper's model among several
    // local entries. The helper reads local-model data, so only an entry
    // declared `local: true` can be it, and only one entry can.
    if ("helper" in entry) {
      const label = typeof entry.name === "string" ? entry.name : `models[${i}]`;
      if (typeof entry.helper !== "boolean") out.push(`${here}.helper: must be true or false`);
      else if (entry.helper && entry.local !== true) {
        out.push(`${here}.helper: '${label}' is not local: true, and the helper only uses your own models; add local: true or remove helper: true`);
      } else if (entry.helper) {
        if (helperAt !== null) out.push(`${here}.helper: only one model can be the helper's ('${helperAt}' already is)`);
        else helperAt = label;
      }
    }
  });
}

/**
 * The problems that span the user's document and the administrator's layer
 * (plan 12 D5): the lock (`adminLockProblems`) and, with a layer in force, a
 * literal address outside the merged perimeter and a second helper. The
 * administrator wins each (`effectiveModels` leaves the user's side out), so
 * these can be tolerated where refusing would let a user file hold the
 * administrator back (`validatePolicyDocument`'s `tolerate`). Pure.
 */
export function layerProblems(doc: unknown, admin: AdminLayer = getAdminLayer()): string[] {
  if (!isPlainObject(doc)) return [];
  const out = adminLockProblems(doc as PolicyFileConfig, admin);
  // Plan 15 §6: a person's prompt filter entry a locked administrator's row
  // keeps out of force.
  out.push(...promptLockProblems((doc as PolicyFileConfig).prompt_filters, admin.promptFilters ?? []));
  if (hasAdminLayer(admin)) {
    const merged = effectiveModels(doc as PolicyFileConfig, admin);
    try {
      checkLiteralsInPerimeter(merged.models, compilePerimeter(merged.perimeter), "models", out);
    } catch { /* an unusable perimeter is checkPerimeter's to report */ }
    const helpers = mergedHelpers(doc as PolicyFileConfig, admin);
    if (helpers.length > 1) out.push(`models: only one model can be the helper's (${helpers.join(", ")} are)`);
  }
  return out;
}

/** The helpers of both layers before the merge picks one (for the problem). */
function mergedHelpers(doc: PolicyFileConfig, admin: AdminLayer): string[] {
  const names = new Map<string, string>();
  for (const m of admin.models) if (m.entry.helper === true && m.entry.local === true) names.set(m.entry.name, `'${m.entry.name}' in ${m.file}`);
  for (const u of Array.isArray(doc.models) ? doc.models : []) {
    if (!isPlainObject(u) || typeof u.name !== "string") continue;
    if (u.disabled === true || !(u.helper === true && u.local === true)) { names.delete(u.name); continue; }
    // Under the lock a user's own local entry is not in force at all (the
    // lock's problem names it), so it is no second helper.
    if (admin.locked && !admin.models.some((m) => m.entry.name === u.name)) continue;
    if (!names.has(u.name)) names.set(u.name, `'${u.name}'`);
  }
  return [...names.values()];
}

/** A layer problem's identity, without the entry's position in the list
 *  (an edit elsewhere in `models:` moves it). */
const layerKey = (p: string): string => p.replace(/^models\[\d+\]/, "models");

export interface ValidateOptions {
  /**
   * Which layer problems (`layerProblems`) a document may keep: "all" (the
   * document is read as the law at start, where the administrator wins and
   * a refusal would stop Mandu), or the document in force (a write may keep
   * the conflicts it already had, and is refused for one it ADDS). Default:
   * none (every layer problem is a problem).
   */
  tolerate?: "all" | PolicyFileConfig | null;
}

/** `admin`: the administrator's layer the document is judged against
 *  (plan 12 D5; default the one in force, `admin-layer.ts`). */
export function validatePolicyDocument(doc: unknown, admin: AdminLayer = getAdminLayer(), opts: ValidateOptions = {}): string[] {
  const out: string[] = [];
  if (doc === null || doc === undefined) return out; // an empty file is a valid "no overrides"
  if (!isPlainObject(doc)) return ["policy: the document must be a mapping (top-level keys: version, lists, inbound, tools, paths, blobs, rules, user_rules, destinations, apps, env, ssh_agent, protect, models, perimeter, sensitivity_labels, prompt_filters)"];
  checkKeys(doc, ["version", "lists", "inbound", "tools", "paths", "blobs", "rules", "user_rules", "destinations", "apps", "env", "ssh_agent", "protect", "mapped_tools", "issuer_bindings", "models", "perimeter", "sensitivity_labels", "prompt_filters", "models_locked"], "policy", out);
  if ("models_locked" in doc) out.push(`policy.models_locked: only your administrator's files (${ADMIN_POLICY_DIR}) can lock the models; remove it here`);
  if ("version" in doc && doc.version !== 1) out.push(`policy.version: must be 1 (got ${JSON.stringify(doc.version)})`);
  const lists = new Set<string>();
  if ("lists" in doc) {
    if (!isPlainObject(doc.lists)) out.push("lists: must be a mapping of name → list of strings");
    else {
      for (const [name, values] of Object.entries(doc.lists)) {
        if (!LIST_NAME_RE.test(name)) out.push(`lists.${name}: names are letters, digits, _ . -`);
        checkStringList(values, `lists.${name}`, out);
        lists.add(name);
      }
    }
  }
  if ("paths" in doc) checkPaths(doc.paths, "paths", out);
  if ("blobs" in doc) checkBlobs(doc.blobs, "blobs", out);
  if ("apps" in doc) checkApps(doc.apps, "apps", out);
  if ("env" in doc) checkEnv(doc.env, "env", out);
  if ("ssh_agent" in doc) checkSshAgent(doc.ssh_agent, "ssh_agent", out);
  checkGuardSettings(doc, out); // unix_sockets:, write_protect: (sandbox review 2026-09-28)
  if ("protect" in doc) {
    if (!Array.isArray(doc.protect)) out.push("protect: must be a list of absolute or ~/ paths");
    else (doc.protect as unknown[]).forEach((p, i) => {
      if (typeof p !== "string" || !(p.startsWith("/") || p === "~" || p.startsWith("~/"))) out.push(`protect[${i}]: must be an absolute or ~/ path (got ${JSON.stringify(p)})`);
      else if (p === "/" || p === "~") out.push(`protect[${i}]: ${p} would forbid every delete; name the folders to protect`);
    });
  }
  if ("mapped_tools" in doc) checkMappedTools(doc.mapped_tools, "mapped_tools", out);
  if ("issuer_bindings" in doc) checkIssuerBindings(doc.issuer_bindings, "issuer_bindings", out);
  if ("rules" in doc) checkDispositions(doc.rules, "rules", out);
  if ("user_rules" in doc) checkUserRules(doc.user_rules, lists, "user_rules", out);
  if ("destinations" in doc) checkDestinations(doc.destinations, lists, "destinations", out);
  if ("models" in doc) checkModels(doc.models, "models", out);
  // Plan 12 D4: the organization's networks, and a literal address outside them.
  if ("perimeter" in doc) checkPerimeter(doc.perimeter, "perimeter", out);
  // Plan 14 §14.1: the sensitivity labels mapped to levels.
  if ("sensitivity_labels" in doc) checkSensitivityLabels(doc.sensitivity_labels, "sensitivity_labels", out);
  // Plan 15 §6: the prompt filter's switches.
  if ("prompt_filters" in doc) {
    checkPromptFilters(doc.prompt_filters, "prompt_filters", out);
    // Phase 3 (§5): a classifier's endpoint is a declared local: true
    // model of either layer, never a cloud-backed one.
    checkPromptEndpoints(doc.prompt_filters, effectiveModels(doc as PolicyFileConfig, admin).models, "prompt_filters", out, isCloudBackedModel);
  }
  // Plan 12 D5: the checks that span both layers (the lock, a literal
  // outside the merged perimeter, a second helper), less what `tolerate`
  // lets the document keep. Without a layer, a literal outside the
  // document's own perimeter is the document's own problem, always.
  if (!hasAdminLayer(admin)) {
    const own = effectiveModels(doc as PolicyFileConfig, admin);
    checkLiteralsInPerimeter(own.models, compilePerimeter(own.perimeter), "models", out);
  }
  const layer = layerProblems(doc, admin);
  if (opts.tolerate === undefined) out.push(...layer);
  else if (opts.tolerate !== "all") {
    const kept = new Set(layerProblems(opts.tolerate, admin).map(layerKey));
    out.push(...layer.filter((p) => !kept.has(layerKey(p))));
  }
  if ("inbound" in doc) {
    const inbound = doc.inbound;
    if (!isPlainObject(inbound)) {
      out.push("inbound: must be a mapping (url / channel / dir / command)");
    } else {
      checkKeys(inbound, ["url", "channel", "dir", "command", "url-trust", "channel-trust", "dir-trust"], "inbound", out);
      for (const cat of ["url", "channel", "dir"] as const) {
        if (!(cat in inbound)) continue;
        checkCategory(inbound[cat], `inbound.${cat}`, out, cat);
        if (isPlainObject(inbound[cat])) {
          const c = inbound[cat] as Record<string, unknown>;
          checkListRefs(c.trustedList, lists, `inbound.${cat}.trustedList`, out);
          checkListRefs(c.untrustedList, lists, `inbound.${cat}.untrustedList`, out);
        }
      }
      if ("command" in inbound) checkCommandEntries(inbound.command, "inbound.command", out);
      // Legacy shapes (still parsed by load-policy.ts).
      const legacy: Array<[string, string]> = [
        ["url-trust", "trustedUrls"],
        ["channel-trust", "untrustedChannels"],
        ["dir-trust", "untrustedDirs"],
      ];
      for (const [key, listKey] of legacy) {
        if (!(key in inbound)) continue;
        const v = inbound[key];
        if (!isPlainObject(v)) {
          out.push(`inbound.${key}: must be a mapping with '${listKey}' (deprecated shape)`);
          continue;
        }
        checkKeys(v, [listKey], `inbound.${key}`, out);
        if (listKey in v) checkStringList(v[listKey], `inbound.${key}.${listKey}`, out);
      }
    }
  }
  if ("tools" in doc) {
    const tools = doc.tools;
    if (!isPlainObject(tools)) {
      out.push("tools: must be a mapping of tool name → { inbound?, outbound? }");
    } else {
      for (const [name, entry] of Object.entries(tools)) {
        const at = `tools.${name}`;
        if (!isPlainObject(entry)) {
          out.push(`${at}: must be a mapping with 'inbound' and/or 'outbound'`);
          continue;
        }
        checkKeys(entry, ["inbound", "outbound"], at, out);
        if (!("inbound" in entry) && !("outbound" in entry)) out.push(`${at}: needs 'inbound' and/or 'outbound' (an empty override changes nothing)`);
        if ("inbound" in entry) checkSchemaNode(entry.inbound, `${at}.inbound`, out);
        if ("outbound" in entry) checkOutbound(entry.outbound, `${at}.outbound`, out);
      }
    }
  }
  return out;
}

export interface StrictPolicyFile {
  path: string;
  /** false when no file exists at `path` (the built-ins are the law). */
  found: boolean;
  config: PolicyFileConfig | null;
}

/**
 * Read + parse + validate the document at `path`. A missing file is
 * `{found:false}`; an unreadable, unparseable or invalid one THROWS
 * {@link PolicyFileError} with every problem — the daemon turns that into a
 * refused start.
 */
export function loadPolicyFileStrict(path: string): StrictPolicyFile {
  if (!existsSync(path)) return { path, found: false, config: null };
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    throw new PolicyFileError(path, [`cannot read the file: ${(err as Error).message}`]);
  }
  let doc: unknown;
  try {
    doc = yaml.load(text);
  } catch (err) {
    throw new PolicyFileError(path, [`YAML parse error: ${(err as Error).message.split("\n")[0]}`]);
  }
  // At start the administrator wins a conflict (the entry is not in force,
  // and the arbiter names it) rather than stop Mandu.
  const problems = validatePolicyDocument(doc, getAdminLayer(), { tolerate: "all" });
  if (problems.length > 0) throw new PolicyFileError(path, problems);
  return { path, found: true, config: (doc ?? {}) as PolicyFileConfig };
}

/**
 * Plan 12 D5: read the administrator's layer (`dir`, default
 * `/etc/mandu/policy.d`; null = none), validate each file's `models` and
 * `perimeter` with the user file's own rules, and make it the layer in force.
 * Throws `AdminLayerError` (the daemon refuses to start) when a file cannot
 * be used: a broken layer must not silently drop the organization's lock.
 */
export function installAdminLayer(dir: string | null = ADMIN_POLICY_DIR): AdminLayer {
  return setAdminLayer(readAdminLayer(dir));
}

/** Read and validate the layer without putting it in force (the arbiter's
 *  re-read when a file changes). Throws `AdminLayerError`. */
export function readAdminLayer(dir: string | null = ADMIN_POLICY_DIR): AdminLayer {
  return loadAdminLayer(dir, (d) => validatePolicyDocument(d, NO_ADMIN_LAYER));
}
