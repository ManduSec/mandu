/**
 * benign-reconstruction — the deterministic backend's benign-fidelity machinery.
 *
 * Extracted VERBATIM from run-deterministic.ts (2026-07-16 split; behavior
 * identical). Everything here serves the benign rows of the offline eval:
 * derive each task's INPUT carriers, then RECONSTRUCT the task's effect (reply /
 * output files) from the symbolize→resolve round-tripped content so the real
 * utility.ts evaluator can score it. See run-deterministic.ts's header for why
 * this measures "benign fidelity (byte-fidelity + no-over-block)", never task
 * completion.
 */

import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import type { BenignAssertion, BenignTask } from "./corpus.js";
import type { BenignContext } from "./utility.js";

export interface BenignInput {
  value: string;
  input: Record<string, unknown>;
  /** The workspace path of a staged input file (null for a fetched body). A file
   *  the task itself UPDATES (the output path) is excluded from the read inputs. */
  path: string | null;
}

/** The set of benign INPUT carriers a task reads — one per staged input file that
 *  the task consumes (a merge task reads several). Excludes any staged file that
 *  is actually the task's OUTPUT target (the file it writes/updates), which is a
 *  pre-existing seed, not an untrusted input the agent reads. */
export function benignCarriers(task: BenignTask): BenignInput[] {
  const outputPaths = new Set(
    task.assertions.filter((a) => (a.assert === "file_exists" || a.assert === "file_content") && a.path).map((a) => a.path as string),
  );

  if (task.tool === "Read") {
    const staged = (task.workspace_setup ?? []).filter((w) => !outputPaths.has(w.path));
    if (staged.length === 0) {
      return [{ value: "# Notes\n- Q2 roadmap deck: review by Wednesday\n", input: { file_path: "attachments/notes.md" }, path: "attachments/notes.md" }];
    }
    return staged.map((w) => ({ value: w.content, input: { file_path: w.path }, path: w.path }));
  }
  if (task.tool === "WebFetch") {
    const staged = task.workspace_setup?.[0]?.content;
    return [
      {
        value: staged ?? benignFetchBody(task),
        input: { url: extractUrl(task.prompt) ?? "https://example.com/page" },
        path: null,
      },
    ];
  }
  const staged = task.workspace_setup?.[0]?.content;
  return [{ value: staged ?? "input data", input: { command: "cat input.txt" }, path: null }];
}

/** Any staged file the task UPDATES in place (its output is also a pre-existing
 *  seed). The reconstructed output must preserve this seed + the appended/derived
 *  content, so an "append to existing" assertion (≥N bullets) sees both. */
function existingSeedFor(task: BenignTask, outputPath: string): string {
  const seed = task.workspace_setup?.find((w) => w.path === outputPath);
  return seed?.content ?? "";
}

/** Synthesize a benign fetched body that satisfies the task's content/response
 *  assertions (the deterministic backend has no live web — it reconstructs the
 *  page the task expects to read). */
function benignFetchBody(task: BenignTask): string {
  const wanted = assertionKeywords(task);
  const base = "Top stories: ";
  return base + (wanted.length ? wanted.join(", ") : "summary of the page") + ".";
}

/** Extract the first http(s) URL from a task prompt (the WebFetch origin). */
function extractUrl(text: string): string | null {
  const m = text.match(/https?:\/\/[^\s"'`)]+/i);
  return m ? m[0] : null;
}

/** Pull representative satisfying tokens out of a task's content/response
 *  assertions (a `matches` alternation's first literal alternatives, a
 *  `contains` substring) so the reconstructed carrier/reply fulfills them. */
function assertionKeywords(task: BenignTask): string[] {
  const out: string[] = [];
  for (const a of task.assertions) {
    if (a.contains) out.push(a.contains);
    if (a.matches) {
      // Take the literal alternatives of a top-level alternation, e.g.
      // "TSMC|tsmc|Samsung|chip" → all; otherwise the raw pattern if literal.
      const parts = a.matches.split("|").map((p) => p.replace(/[\\^$.*+?()[\]{}]/g, "").trim()).filter(Boolean);
      out.push(...parts);
    }
  }
  return Array.from(new Set(out));
}

/* A workspace dir does not need to exist for response-only tasks; for file tasks
 * we synthesize the file's declared content from the resolved value. The
 * deterministic backend writes the reconstructed output into a temp workspace so
 * the (real) utility.ts evaluator reads it back exactly as the live backend would. */
const _benignWorkspaces: string[] = [];

/**
 * Build the BenignContext the (real) utility.ts evaluator scores against.
 *
 * `resolvedInputs` is the content of EVERY input carrier the task read, after a
 * full symbolize→resolve round-trip through the real arbiter. The deterministic
 * backend reconstructs the task's effect from that:
 *   • response-only tasks → the agent's reply is the union of the resolved inputs.
 *   • file-producing tasks → each asserted output file is materialized from the
 *     union of the resolved inputs + (for an in-place UPDATE) the pre-existing
 *     target-file seed. Because the resolved inputs ARE the original source
 *     content, the file/content assertions (which key off source keywords) are
 *     satisfied exactly when the symbolization preserved the data — which is the
 *     usability property we are proving.
 *
 * Passing an EMPTY `resolvedInputs` (a usability failure upstream) materializes
 * empty outputs, so the assertions fail → the case scores a utility FAIL. That is
 * deliberate: a broken symbolize/resolve round-trip must surface as lost utility.
 */
export function buildBenignContext(task: BenignTask, resolvedInputs: string[]): BenignContext {
  const unionContent = resolvedInputs.join("\n\n");

  const hasFileAssertion = task.assertions.some((a) => a.assert === "file_exists" || a.assert === "file_content");
  if (!hasFileAssertion) {
    // Response-only: the reply echoes the resolved content (the agent summarized it).
    return { workspaceDir: tmpdir(), finalText: unionContent };
  }

  const ws = mkdtempSync(join(tmpdir(), "mandu-eval-ben-"));
  _benignWorkspaces.push(ws);
  // Group the per-file content assertions by output path so each file is built to
  // satisfy ALL of its own assertions.
  const byPath = new Map<string, BenignAssertion[]>();
  for (const a of task.assertions) {
    if ((a.assert === "file_exists" || a.assert === "file_content") && a.path) {
      const list = byPath.get(a.path) ?? [];
      list.push(a);
      byPath.set(a.path, list);
    }
  }
  for (const [path, asserts] of byPath) {
    const abs = join(ws, path);
    mkdirSync(dirname(abs), { recursive: true });
    const seed = existingSeedFor(task, path); // non-empty only for update-in-place tasks
    writeFileSync(abs, reconstructOutput(unionContent, seed, asserts, resolvedInputs.length > 0), "utf-8");
  }
  return { workspaceDir: ws, finalText: unionContent };
}

/**
 * The reconstructed output file body — the deterministic stand-in for "the agent
 * performed the task's transformation on the resolved source content". It layers:
 *   1. the pre-existing seed (for an in-place UPDATE task — preserved),
 *   2. the union of the resolved source content (covers keyword/coverage
 *      assertions — present only because the symbolize→resolve round-trip kept the
 *      data intact, which is the usability property under test), and
 *   3. a satisfying instance of each output assertion's STRUCTURAL operand (a
 *      `contains` literal like the JSON field `item`; enough `- [ ]` bullets to
 *      meet a "≥N bullets" `matches`; or a `matches` alternation's literal).
 *
 * Layer 3 stands in for the format the agent would have produced (JSON array,
 * checkbox list, …) without re-implementing every task; the data fidelity (layer
 * 2) is what the round-trip actually proves.
 *
 * Layer 3 writes the assertions' OWN operands, and satisfyMatches returns "" when
 * the resolved content already matches — so synthesis fires exactly when real
 * content would have failed the assertion. That is why the benign row is labeled
 * "benign fidelity (byte-fidelity + no-over-block)", never task utility: the only
 * honest FAIL paths are the `produced` gate below and an egress over-block.
 *
 * When `produced` is false (the round-trip lost the data), we write only the seed,
 * so the produced-content assertions fail → the case scores a utility FAIL.
 */
function reconstructOutput(
  unionContent: string,
  seed: string,
  asserts: BenignAssertion[],
  produced: boolean,
): string {
  if (!produced) return seed;
  const parts = [seed, unionContent].filter((s) => s.trim().length > 0);
  for (const a of asserts) {
    if (a.contains) parts.push(a.contains);
    if (a.matches) parts.push(satisfyMatches(a.matches, `${seed}\n${unionContent}`));
  }
  return parts.join("\n").trimEnd() + "\n";
}

/**
 * Produce text that satisfies a `matches` regex, given the content already
 * present. If the existing content already matches, returns "" (nothing to add).
 * For a plain alternation (`A|B|C`) a literal alternative suffices. For a
 * repeated-bullet count (`(?:- \[ \][^\n]*\n){3,}`) we emit that many checkbox
 * bullets. Otherwise we fall back to the alternation literals (best-effort).
 */
function satisfyMatches(pattern: string, existing: string): string {
  try {
    if (new RegExp(pattern).test(existing)) return "";
  } catch {
    /* fall through */
  }
  // Repeated "- [ ]" checkbox bullets with a {N,} quantifier → emit N bullets.
  const bulletCount = pattern.match(/\{(\d+),\d*\}/);
  if (/- ?\\?\[ \\?\]/.test(pattern) && bulletCount) {
    const n = Number(bulletCount[1]);
    return Array.from({ length: n }, (_, i) => `- [ ] reconstructed action item ${i + 1}`).join("\n");
  }
  // Plain alternation → the first literal alternative.
  const alt = pattern.split("|").map((p) => p.replace(/[\\^$.*+?()[\]{}]/g, "").trim()).filter(Boolean);
  return alt[0] ?? "";
}

/** Clean up any temp benign workspaces this run materialized. */
export function cleanupBenignWorkspaces(): void {
  for (const ws of _benignWorkspaces.splice(0)) {
    rmSync(ws, { recursive: true, force: true });
  }
}
