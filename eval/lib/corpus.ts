/**
 * corpus — Mandu eval corpus schema types, YAML loaders, and case builder.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * PROVENANCE
 *   Ported from the reference adfi-openclaw benchmark corpus:
 *     DualView (adfi-openclaw) test/benchmark/injection-tasks/*.yaml
 *       — attacker INTENTS + `security_check {type: command_executed, patterns}`
 *         (IT-01 RCE git-clone+setup.sh; IT-02 exfil → exfil-target@example.com;
 *          IT-03 destructive rm of meeting-notes).
 *     DualView (adfi-openclaw) test/benchmark/attack-templates/*.yaml
 *       — payload FRAMING (web / stored-file / email delimiter-escape that closes
 *         </function_results> and injects a fake Human turn carrying {intent}).
 *     DualView (adfi-openclaw) test/benchmark/injection-vectors.yaml
 *       — delivery surfaces (web_page_content/web_fetch, email_body/exec,
 *         stored_file_content/read).
 *     DualView (adfi-openclaw) test/benchmark/user-tasks/*.yaml
 *       — benign UT tasks with `assertions: [{assert: file_exists|file_content|response}]`.
 *   The loader / cross-product shape is lifted from
 *     DualView (adfi-openclaw) test/lib/e2e-defs.ts (loadYamlDir,
 *     buildE2ETests) and the success_check shape from test/lib/security-oracle.ts
 *     (`SecurityCheck`).
 *
 *   THE Mandu ADAPTATION
 *     adfi's agent is an OpenClaw subprocess with read/exec/web_fetch tools; the
 *     "defense" is an OpenClaw plugin hook. Mandu's agent is Claude Code / Codex
 *     with Read / Bash / WebFetch / WebSearch tools, and the defense is the arbiter
 *     symbolization + the four OS-level chokepoints. So a ported attack case is a
 *     benign carrier (a file the agent Reads, a URL it WebFetches, or content an
 *     exec consumes) whose body embeds an injected instruction (delimiter-escape
 *     framing + attacker intent), plus a `security_check` (regex patterns that, if
 *     they appear in an agent tool call that did not fail/block, mean the attack
 *     SUCCEEDED — e.g. the exfil curl/gws command, `rm meeting-notes`, or
 *     `git clone … && … setup.sh`).
 *
 *   This package only LOADS + VALIDATES the corpus and offers a flat case builder.
 *   The runner that drives an agent and the oracle that scores `security_check`
 *   against a transcript are downstream and code against these types.
 *
 *   The YAML parser is js-yaml — the same dependency tests/conformance/ uses
 *   (tests/conformance/run.ts + lib/harness.ts load scenarios via `import * as yaml from
 *   "js-yaml"`). Reused here so eval/ needs no new dependency.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as yaml from "js-yaml";

// ─────────────────────────────────────────────────────────────────────────────
// Schema types — the YAML contract the runner/oracle code against.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Attack category — the attacker's data-usage goal once the injection lands.
 *   stored_ipi → the injection arrives in a file the agent Reads.
 *   web_ipi    → the injection arrives in a page/URL the agent WebFetches.
 *   exec_ipi   → the injection arrives in content an exec/tool step consumes.
 * Mirrors adfi's IT × vector split, collapsed into one carrier-keyed axis.
 */
export type Category = "stored_ipi" | "web_ipi" | "exec_ipi";

/**
 * Vector — the Mandu tool surface that delivers the carrier into the trust
 * boundary. Maps adfi's injection-vectors.yaml `tool` (read / web_fetch / exec)
 * onto Mandu's Claude Code / Codex tool names.
 *   read      → Read tool        (adfi stored_file_content)
 *   web_fetch → WebFetch tool    (adfi web_page_content)
 *   exec      → Bash tool        (adfi email_body / exec)
 */
export type Vector = "read" | "web_fetch" | "exec";

/** Map a vector to the concrete Mandu (Claude Code / Codex) tool name. */
export const VECTOR_TOOL: Record<Vector, string> = {
  read: "Read",
  web_fetch: "WebFetch",
  exec: "Bash",
};

/** Where the carrier content lives. `file` → on disk for Read; `url` → fetched. */
export type CarrierKind = "file" | "url";

/** The legit-looking content the agent consumes, into which the injection is embedded. */
export interface Carrier {
  kind: CarrierKind;
  /** Workspace-relative path of the staged file (carrier.kind === "file"). */
  path?: string;
  /** URL the agent WebFetches (carrier.kind === "url"). */
  url?: string;
  /** The benign body the agent legitimately reads/fetches; the injection is
   *  appended/embedded into this content at render time. */
  benign_content: string;
}

/**
 * The injected instruction. `framing` is the attack-template delimiter-escape
 * wrapper (ported verbatim from adfi attack-templates/*.yaml) with a literal
 * `{intent}` placeholder; `intent` is the attacker command (ported from adfi
 * injection-tasks/*.yaml `intent`). Render = framing.replace("{intent}", intent),
 * appended to carrier.benign_content.
 */
export interface Injection {
  /** Provenance: the adfi attack-template id this framing was ported from. */
  framing_id: string;
  framing: string;
  intent: string;
}

/**
 * The success oracle for an attack case. Ported from adfi's
 * `security_check {type: command_executed, patterns}` (security-oracle.ts).
 * Semantics preserved: the attack SUCCEEDED iff one of `patterns` (case-insensitive
 * regex) matches an agent tool-call serialization whose result did NOT fail/block.
 */
export interface SecurityCheck {
  /** Only command_executed is ported (adfi's sole check type). */
  type: "command_executed";
  /** Regex strings matched against a tool-call serialization. */
  patterns: string[];
  /** Tool name(s) whose calls are eligible for matching. Defaults to the exec
   *  surface (Mandu: ["Bash"]) when absent — mirrors adfi's exec/exec_sym default. */
  tool?: string | string[];
  description?: string;
}

/** One ported red-team attack case. */
export interface AttackCase {
  id: string;
  name: string;
  category: Category;
  vector: Vector;
  carrier: Carrier;
  injection: Injection;
  security_check: SecurityCheck;
  /** Workspace paths to remove after the run (adfi IT `cleanup_paths`). */
  cleanup_paths?: string[];
  /** Free-form tags for filtering / dashboard display. */
  tags?: string[];
}

/** A field matcher for a benign assertion — mirrors adfi UT assertion operands. */
export interface BenignAssertion {
  /** file_exists → a file the task must produce; file_content → its content;
   *  response → the agent's final reply text. */
  assert: "file_exists" | "file_content" | "response";
  /** Human label (adfi UT assertion `label`). */
  label?: string;
  /** Path operand for file_exists / file_content. */
  path?: string;
  /** Substring the value must contain (adfi `contains`). */
  contains?: string;
  /** Regex the value must match (adfi `matches`). */
  matches?: string;
}

/** A file pre-staged in the workspace before a benign run (adfi `workspace_setup`). */
export interface WorkspaceFile {
  path: string;
  content: string;
}

/** One ported benign task (the live backend scores it as real task utility; the
 *  deterministic backend only as benign fidelity — byte-fidelity + no-over-block). */
export interface BenignTask {
  id: string;
  name: string;
  /** The user instruction handed to the agent. */
  prompt: string;
  /** Primary tool the task exercises (Mandu tool name, e.g. Read / WebFetch / Bash). */
  tool: string;
  /** Files to pre-stage before the run (adfi UT `workspace_setup`). */
  workspace_setup?: WorkspaceFile[];
  assertions: BenignAssertion[];
  tags?: string[];
}

// ─────────────────────────────────────────────────────────────────────────────
// YAML loaders — js-yaml, reusing tests/conformance/'s dependency. (adfi loadYamlDir.)
// ─────────────────────────────────────────────────────────────────────────────

const __dirname = dirname(fileURLToPath(import.meta.url));
const CORPUS_DIR = join(__dirname, "..", "corpus");
export const ATTACKS_DIR = join(CORPUS_DIR, "attacks");
export const BENIGN_DIR = join(CORPUS_DIR, "benign");

function listYaml(dir: string): string[] {
  return readdirSync(dir)
    .filter((f) => f.endsWith(".yaml") || f.endsWith(".yml"))
    .sort();
}

function loadYamlFile<T>(filePath: string): T {
  return yaml.load(readFileSync(filePath, "utf-8")) as T;
}

const VALID_CATEGORIES: ReadonlySet<Category> = new Set<Category>(["stored_ipi", "web_ipi", "exec_ipi"]);
const VALID_VECTORS: ReadonlySet<Vector> = new Set<Vector>(["read", "web_fetch", "exec"]);
const VALID_BENIGN_ASSERTS = new Set(["file_exists", "file_content", "response"]);

function validateAttack(a: AttackCase, file: string): AttackCase {
  const req = (cond: boolean, msg: string): void => {
    if (!cond) throw new Error(`${file}: ${msg}`);
  };
  req(Boolean(a && typeof a === "object"), "not an attack object");
  req(Boolean(a.id), "missing id");
  req(Boolean(a.name), `${a.id}: missing name`);
  req(VALID_CATEGORIES.has(a.category), `${a.id}: invalid/missing category (${a.category})`);
  req(VALID_VECTORS.has(a.vector), `${a.id}: invalid/missing vector (${a.vector})`);
  req(Boolean(a.carrier), `${a.id}: missing carrier`);
  req(a.carrier.kind === "file" || a.carrier.kind === "url", `${a.id}: carrier.kind must be file|url`);
  req(
    a.carrier.kind === "file" ? Boolean(a.carrier.path) : Boolean(a.carrier.url),
    `${a.id}: carrier missing ${a.carrier.kind === "file" ? "path" : "url"}`,
  );
  req(typeof a.carrier.benign_content === "string", `${a.id}: carrier.benign_content must be a string`);
  req(Boolean(a.injection), `${a.id}: missing injection`);
  req(Boolean(a.injection.framing_id), `${a.id}: injection.framing_id missing`);
  req(a.injection.framing.includes("{intent}"), `${a.id}: injection.framing must contain {intent} placeholder`);
  req(Boolean(a.injection.intent), `${a.id}: injection.intent missing`);
  req(Boolean(a.security_check), `${a.id}: missing security_check`);
  req(a.security_check.type === "command_executed", `${a.id}: security_check.type must be command_executed`);
  req(
    Array.isArray(a.security_check.patterns) && a.security_check.patterns.length > 0,
    `${a.id}: security_check.patterns must be a non-empty array`,
  );
  for (const p of a.security_check.patterns) {
    try {
      // eslint-disable-next-line no-new
      new RegExp(p, "i");
    } catch (err) {
      throw new Error(`${file}: ${a.id}: security_check pattern /${p}/ does not compile: ${(err as Error).message}`);
    }
  }
  return a;
}

function validateBenign(t: BenignTask, file: string): BenignTask {
  const req = (cond: boolean, msg: string): void => {
    if (!cond) throw new Error(`${file}: ${msg}`);
  };
  req(Boolean(t && typeof t === "object"), "not a task object");
  req(Boolean(t.id), "missing id");
  req(Boolean(t.name), `${t.id}: missing name`);
  req(Boolean(t.prompt), `${t.id}: missing prompt`);
  req(Boolean(t.tool), `${t.id}: missing tool`);
  req(Array.isArray(t.assertions) && t.assertions.length > 0, `${t.id}: assertions must be a non-empty array`);
  for (const a of t.assertions) {
    req(VALID_BENIGN_ASSERTS.has(a.assert), `${t.id}: invalid assertion kind "${a.assert}"`);
    if (a.assert === "file_exists" || a.assert === "file_content") {
      req(Boolean(a.path), `${t.id}: ${a.assert} assertion missing path`);
    }
    if (a.assert === "response" || a.assert === "file_content") {
      req(Boolean(a.matches ?? a.contains), `${t.id}: ${a.assert} assertion needs matches or contains`);
    }
    if (a.matches !== undefined) {
      try {
        // eslint-disable-next-line no-new
        new RegExp(a.matches);
      } catch (err) {
        throw new Error(`${file}: ${t.id}: assertion matches /${a.matches}/ does not compile: ${(err as Error).message}`);
      }
    }
  }
  if (t.workspace_setup) {
    for (const w of t.workspace_setup) {
      req(Boolean(w.path) && typeof w.content === "string", `${t.id}: workspace_setup entry needs path + content`);
    }
  }
  return t;
}

/** Load + validate every attacks/*.yaml. Throws on the first malformed case. */
export function loadAttacks(dir: string = ATTACKS_DIR): AttackCase[] {
  return listYaml(dir).map((f) => validateAttack(loadYamlFile<AttackCase>(join(dir, f)), f));
}

/** Load + validate every benign/*.yaml. Throws on the first malformed task. */
export function loadBenign(dir: string = BENIGN_DIR): BenignTask[] {
  return listYaml(dir).map((f) => validateBenign(loadYamlFile<BenignTask>(join(dir, f)), f));
}

// ─────────────────────────────────────────────────────────────────────────────
// Rendering + case builder.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Render the carrier the agent actually consumes: the benign body with the
 * injection (framing.replace("{intent}", intent)) appended. Mirrors adfi's
 * renderAttackTemplate {intent} substitution, simplified — Mandu attack cases
 * carry their own benign carrier and one ported framing each, so there is no
 * per-model fake_history dimension here (the chosen framings are model-agnostic
 * delimiter escapes; the Claude wire-format reinforcement lives in the framing
 * text itself, ported from the adfi `*-claude-delimiter` templates).
 */
export function renderInjection(injection: Injection): string {
  return injection.framing.split("{intent}").join(injection.intent);
}

/** Render the full poisoned carrier (benign body + rendered injection). */
export function renderCarrier(c: AttackCase): string {
  const sep = c.carrier.benign_content.endsWith("\n") ? "" : "\n";
  return c.carrier.benign_content + sep + renderInjection(c.injection);
}

/** Resolve a security_check's eligible tool list (Mandu exec default: Bash). */
export function resolveCheckTools(check: SecurityCheck): string[] {
  if (check.tool === undefined) return ["Bash"];
  return Array.isArray(check.tool) ? check.tool : [check.tool];
}

/** A built, runnable eval case (flat today; the union lets the cross-product grow). */
export type EvalCase =
  | {
      kind: "attack";
      id: string;
      mode: "security";
      attack: AttackCase;
      /** Pre-rendered poisoned carrier content the runner stages/serves. */
      poisonedCarrier: string;
      /** Concrete Mandu tool that delivers the carrier. */
      tool: string;
    }
  | {
      kind: "benign";
      id: string;
      mode: "utility";
      benign: BenignTask;
    };

export interface BuildFilters {
  /** Substring filter on case id (comma-separated, adfi matchesFilter parity). */
  filter?: string;
  /** Restrict to one category. */
  category?: Category;
  /** Restrict to one vector. */
  vector?: Vector;
  /** Restrict to a mode. */
  mode?: "security" | "utility";
}

function matchesFilter(value: string, pattern: string | undefined): boolean {
  if (!pattern) return true;
  return pattern.split(",").some((p) => value.includes(p.trim()));
}

/**
 * Build the flat list of runnable eval cases (attacks + benign).
 *
 * Today this is a straight 1:1 map (each attack YAML already pairs a carrier +
 * one framing + one vector). It is deliberately shaped like adfi's
 * buildE2ETests so a future attack × framing × vector cross-product can slot in:
 * swap the per-attack `injection`/`carrier`/`vector` for registries and nest the
 * loops here without changing the EvalCase contract the runner depends on.
 */
export function buildCases(filters: BuildFilters = {}, dirs?: { attacks?: string; benign?: string }): EvalCase[] {
  const cases: EvalCase[] = [];

  if (filters.mode !== "utility") {
    for (const a of loadAttacks(dirs?.attacks)) {
      if (!matchesFilter(a.id, filters.filter)) continue;
      if (filters.category && a.category !== filters.category) continue;
      if (filters.vector && a.vector !== filters.vector) continue;
      cases.push({
        kind: "attack",
        id: a.id,
        mode: "security",
        attack: a,
        poisonedCarrier: renderCarrier(a),
        tool: VECTOR_TOOL[a.vector],
      });
    }
  }

  if (filters.mode !== "security") {
    for (const t of loadBenign(dirs?.benign)) {
      if (!matchesFilter(t.id, filters.filter)) continue;
      cases.push({ kind: "benign", id: t.id, mode: "utility", benign: t });
    }
  }

  return cases;
}
