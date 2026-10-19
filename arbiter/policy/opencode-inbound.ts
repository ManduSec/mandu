/**
 * opencode-inbound — the inbound data-trust ruleset for the OPENCODE agent
 * (SST/anomalyco `opencode`, npm `opencode-ai`).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   DERIVED from claude-code-inbound.ts, which is itself a re-map of the lifted
 *   OpenClaw ruleset. The schema vocabulary (KeySpec / DataSpec / __items /
 *   literal TRUSTED|UNTRUSTED), the resolver, and the trust categories
 *   (URL / DIR) are unchanged. Only the tool NAMES and their param keys are
 *   OpenCode-specific — and every posture decision below is inherited from the
 *   corresponding Claude Code entry rather than re-litigated, so the two agents
 *   cannot silently diverge on what "trusted" means.
 *
 * TOOL SURFACE — ESTABLISHED FROM THE WIRE, NOT FROM DOCS (2026-08-05).
 *   The names and param keys below were read out of a real `opencode run`
 *   request body captured against a local /v1/messages endpoint
 *   (docs/design/testing/agent-e2e-harness.md §2.4). Observed on opencode 1.18.13:
 *     bash, edit, glob, grep, read, skill, task, todowrite, webfetch, write
 *   Note `filePath` (camelCase) — NOT Claude Code's `file_path`. Keying the
 *   wrong param name is a silent fail-closed, so this is load-bearing.
 *
 *   Four further tools exist conditionally (registry.ts): `websearch`,
 *   `apply_patch`, `question`, and `lsp`/`execute`/`plan_exit` behind flags.
 *   The ones whose posture is unambiguous are mapped below so a config change
 *   that enables them does not silently degrade; the rest are deliberately
 *   omitted (fail-closed UNTRUSTED by omission).
 *
 * OPENCODE 2 (npm `@opencode/cli`), ONE SPEC FOR BOTH GENERATIONS (2026-10-05).
 *   Captured off the wire of 2.0.23 (test/fixtures/opencode2-tool-surface-
 *   2026-10-05.json, with each tool's result): edit glob grep question read
 *   shell skill subagent webfetch websearch write execute. `bash` is now
 *   `shell` (same posture), `task` is `subagent` (same posture), and `read` /
 *   `write` / `edit` take `path` instead of `filePath`. The session spec
 *   `opencode` serves both generations: a name only one of them sends never
 *   appears on the other's wire. `execute` (code mode) stays unmapped and the
 *   proxy refuses it (tool-gate-surface.ts). 2.x's `read` frames a text file
 *   differently (`Read file <path>, lines A-B` then `n: <line>`, no trailer),
 *   and opencodeReadRenderingText below reads both frames.
 *
 * SECURITY INVARIANT (carried over, unchanged):
 *   TRUSTED is granted ONLY on an explicit rule match. An unlisted tool, an
 *   unlisted result field, or a data field whose origin (URL / DIR) is not on
 *   the trusted list fails closed to UNTRUSTED in policy-interface.ts /
 *   resolve-schema.ts. The proxy over-symbolizes when in doubt and never
 *   under-symbolizes.
 *
 * MCP NAMING (differs from Claude Code):
 *   OpenCode surfaces MCP tools as `<server>_<tool>` (ONE underscore), not
 *   Claude Code's `mcp__<server>__<tool>`. So there is no `mcp__` prefix family
 *   to match here, and the getToolInboundSpec prefix rule (which is gated to the
 *   claude-code spec) correctly does not apply. Every third-party MCP tool
 *   therefore fail-closes UNTRUSTED by omission, which is the right default.
 *   On the confidentiality axis a tool neither this table nor
 *   OPENCODE_GATE_SURFACE names has no mapping: its result is masked whole
 *   unless policy.yaml `mapped_tools:` lists it (mapped-tools.ts,
 *   confidentiality plan 10 §11.18).
 *
 *   Mandu's OWN MCP tools are mapped outside this table, spec-independently,
 *   because Mandu mounts them on every agent and each spelling is one Mandu
 *   itself produces (inspect-tool.ts, policy-tool.ts; tool-inbound.ts
 *   getToolInboundSpec):
 *     mandu-inspect_inspect_symbol     → the pure-symbolic inspect rule
 *     mandu-inspect_declassify_symbol  → the same whole-result UNTRUSTED
 *       object Claude Code's `mcp__mandu-inspect__declassify_symbol` reaches;
 *       a result passes only when the arbiter recognizes it as exactly the
 *       value it released to this session (server.ts
 *       declassifyResultTrusted), so the two agents share one verdict
 *       (agent-e2e-harness.md §8.5, 2026-09-29)
 *     mandu-policy_*                   → the token-only policy rule
 *   They are deliberately NOT entries here: an exact entry would also stop
 *   the input scan (inboundSpecNamesInput), which Claude Code keeps for
 *   declassify_symbol, and the two agents must not diverge on it.
 */

import type { SchemaNode, ToolSpec } from "./schema-types.js";

export const OPENCODE_INBOUND_SPEC: Record<string, ToolSpec> = {
  // ── Local filesystem reads ──────────────────────────────────────────────
  // `read` returns file content. Same posture as Claude Code's `Read`: the
  // per-field schema serves field-addressed callers, and there is
  // DELIBERATELY NO `wholeResult` rule, so the live whole-result path stays
  // FAIL-CLOSED UNTRUSTED. The full argument is in claude-code-inbound.ts's
  // Read entry and applies verbatim here (DIR's intrinsic default is
  // blocklist-empty, so a whole-result DIR DataSpec would forward every file's
  // bytes raw; and the stored-IPI chain — a poisoned file written by a shell,
  // then read — has no other live backstop).
  // OpenCode 2 names the file `path` (2.0.23); a field-addressed 2.x caller
  // finds no `params.filePath` key, so its content resolves fail-closed.
  read: {
    paramsKeys: { filePath: { category: "DIR", role: "key" }, path: { category: "DIR", role: "key" } },
    schema: {
      content: { category: "DIR", role: "data", keyField: "params.filePath" },
      filePath: { category: "DIR", role: "key" },
      path: { category: "DIR", role: "key" },
      offset: "TRUSTED",
      limit: "TRUSTED",
    } satisfies SchemaNode,
  },

  // ── Local filesystem writes / edits — agent-authored metadata ───────────
  // These echo back what the AGENT produced (paths, byte counts, the diff it
  // authored). No freshly-ingested external data → TRUSTED metadata.
  // (mirrors Claude Code Write / Edit / MultiEdit / NotebookEdit)
  write: { schema: "TRUSTED" },
  edit: { schema: "TRUSTED" },
  // `apply_patch` is the same class: the agent authored the patch and the
  // result echoes application metadata. Mapped even though it was absent from
  // the observed surface, so enabling it does not silently fail-close.
  apply_patch: { schema: "TRUSTED" },

  // `todowrite` echoes the agent's own todo list → TRUSTED metadata.
  todowrite: { schema: "TRUSTED" },

  // ── Shell ───────────────────────────────────────────────────────────────
  // `bash` stdout/stderr is attacker-reachable (a command may cat untrusted
  // files, curl URLs, …) → plaintext UNTRUSTED. The analogue of Claude Code's
  // `Bash` and OpenClaw's `exec`.
  //
  // NB the exposed id is pinned to `bash` upstream for compatibility (their
  // tool/shell/id.ts notes a rename is deferred to opencode 2.0) — re-check
  // this entry on a major version bump.
  bash: { schema: "UNTRUSTED" },
  // OpenCode 2's name for it (2.0.23: `shell{command,workdir,timeout,
  // background}`; the result is the output, then "Exited with code N" in a
  // second text block on a non-zero exit). The rename the note above expected.
  shell: { schema: "UNTRUSTED" },

  // ── Code search / filesystem namespace ──────────────────────────────────
  // `glob` returns only the list of PATHS the agent's own pattern matched — no
  // file content → TRUSTED metadata. (mirrors Claude Code Glob)
  glob: { schema: "TRUSTED" },

  // `grep` returns matched CONTENT LINES from files → FILE CONTENT →
  // UNTRUSTED, the same posture as `read`. OpenCode's grep has no
  // output_mode param (observed params: pattern, path, include), so unlike
  // Claude Code's Grep there is no paths-only branch to carve out as trusted —
  // the literal is the whole story.
  grep: { schema: "UNTRUSTED" },

  // ── External network ────────────────────────────────────────────────────
  // `webfetch` body is EXTERNAL content → UNTRUSTED, keyed off the requested
  // URL so an operator-trusted origin can still resolve TRUSTED. Metadata the
  // agent itself supplied or the fetch layer derived stays TRUSTED.
  // (mirrors Claude Code WebFetch / OpenClaw web_fetch)
  webfetch: {
    paramsKeys: { url: { category: "URL", role: "key" } },
    schema: {
      url: { category: "URL", role: "key" },
      format: "TRUSTED",
      status: "TRUSTED",
      contentType: "TRUSTED",
      title: { category: "URL", role: "data", keyField: "params.url" },
      content: { category: "URL", role: "data", keyField: "params.url" },
      text: { category: "URL", role: "data", keyField: "params.url" },
    } satisfies SchemaNode,
  },

  // `websearch` — each result's title/snippet is EXTERNAL, keyed off that
  // result's own url (the resolver walks __items and resolves keyField against
  // each item). No whole-result rule: a flattened result mixes per-URL items,
  // so whole-result stays fail-closed. (mirrors Claude Code WebSearch)
  websearch: {
    schema: {
      query: "TRUSTED",
      results: {
        __items: {
          url: { category: "URL", role: "key" },
          title: { category: "URL", role: "data", keyField: "url" },
          snippet: { category: "URL", role: "data", keyField: "url" },
          content: { category: "URL", role: "data", keyField: "url" },
        },
      },
    } satisfies SchemaNode,
  },

  // ── Subagents / skills ──────────────────────────────────────────────────
  // `task` spawns a subagent whose final result can carry attacker-influenced
  // text (the subagent may itself have read untrusted data) → UNTRUSTED.
  // (mirrors Claude Code Task/Agent)
  task: { schema: "UNTRUSTED" },
  // OpenCode 2's name for it (2.0.23): the result is the child session's
  // final answer in `<subagent sessionID=… state="completed">…</subagent>`.
  subagent: { schema: "UNTRUSTED" },

  // `skill` expands a skill body, which is workspace-file content and
  // third-party-authorable in a cloned repo → UNTRUSTED.
  // (mirrors Claude Code Skill/SlashCommand)
  skill: { schema: "UNTRUSTED" },

  // ── User-authored ───────────────────────────────────────────────────────
  // `question` relays the USER's own answer — the same trust root as the user
  // prompt, which is never symbolized → TRUSTED.
  // (mirrors Claude Code AskUserQuestion)
  question: { schema: "TRUSTED" },

  // DELIBERATELY UNMAPPED (fail-closed UNTRUSTED by omission, on purpose — a
  // new tool must be mapped with a provenance justification before its results
  // pass raw): `lsp` (diagnostics embed source spans), `execute` (code-mode
  // arbitrary execution — strictly a superset of bash's threat model; on
  // OpenCode 2 it is on by default and the proxy refuses every call, so its
  // result is only the refusal),
  // `plan_exit`, `invalid`, and every third-party MCP `<server>_<tool>`
  // (Mandu's own MCP tools are mapped spec-independently: see the header).
};

/** The trailer OpenCode's `read` closes the content with (1.18.13 and
 *  1.18.32, read from the compiled binary): digits and fixed words only. The
 *  "Output capped at …" form is not accepted (its size text is not pinned
 *  here), so a capped read fails the content test and stays masked. */
const OPENCODE_READ_TRAILER_RE =
  /^\((?:End of file - total \d{1,12} lines|Showing lines \d{1,12}-\d{1,12} of \d{1,12}\. Use offset=\d{1,12} to continue\.)\)$/;

/** OpenCode 2's marker on a line it cut at 2000 characters (2.0.23). */
const OPENCODE2_LINE_CUT = "... (line truncated to 2000 chars)";

/**
 * OpenCode 2's `read` frame of a text file (2.0.23, captured in
 * test/fixtures/opencode2-tool-surface-2026-10-05.json) → the text of the
 * lines it carries. The frame is EXACTLY
 *
 *   Read file {the path as the call named it}, lines {A}-{B}
 *   {A}: {line}
 *   …
 *   {B}: {line}
 *
 * with no trailer. `paths` are the spellings the call named; the header must
 * name one of them. A cut read (its `[Output truncated. Continue reading with
 * offset: N]` line), a cut line, an empty file (`…, 0 lines`), a directory
 * (`Read directory …`), an error envelope and any line count other than
 * B-A+1 are null. Pure; never throws.
 */
export function opencode2ReadFrameText(value: string, paths: readonly string[]): string | null {
  if (typeof value !== "string") return null;
  const nl = value.indexOf("\n");
  if (nl < 0) return null;
  const head = value.slice(0, nl);
  let range: RegExpExecArray | null = null;
  for (const p of paths) {
    const prefix = `Read file ${p}, lines `;
    if (p !== "" && head.startsWith(prefix)) {
      range = /^(\d{1,9})-(\d{1,9})$/.exec(head.slice(prefix.length));
      if (range) break;
    }
  }
  if (!range) return null;
  const a = Number(range[1]);
  const b = Number(range[2]);
  if (a < 1 || b < a) return null;
  const lines = value.slice(nl + 1).split("\n");
  if (lines.length !== b - a + 1 || lines.length > 4000) return null;
  const out: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const m = /^(\d{1,9}): ([\s\S]*)$/.exec(lines[i]!);
    if (!m || Number(m[1]) !== a + i) return null;
    if (m[2]!.endsWith(OPENCODE2_LINE_CUT)) return null;
    out.push(m[2]!);
  }
  return out.join("\n");
}

/**
 * OpenCode's `read` rendering of a text file, reduced to the file text it
 * carries, for the structured read-twin rule (plan 10 §2.4 and §11.8;
 * policy-interface.ts runs the content test). OpenCode 2's frame (`Read file
 * …`) is read by opencode2ReadFrameText; OpenCode 1's rendering is EXACTLY
 *
 *   <path>{abs path}</path>
 *   <type>file</type>
 *   <content>
 *   {n}: {line}          (consecutive numbers from the offset)
 *   …
 *
 *   (End of file - total N lines)      or  (Showing lines A-B of C. Use offset=K to continue.)
 *   </content>
 *
 * `paths` are the spellings the call named (the param, its HumanView form):
 * the `<path>` must be one of them, absolute, so the header carries nothing
 * the model did not already send. Anything else (a `<system-reminder>` after
 * the content, which carries an instruction file's text, a directory
 * listing, a gap in the numbering) is null and the result stays masked.
 * Pure; never throws.
 */
export function opencodeReadRenderingText(value: string, paths: readonly string[]): string | null {
  if (typeof value !== "string") return null;
  if (value.startsWith("Read file ")) return opencode2ReadFrameText(value, paths);
  const lines = value.replace(/\s+$/, "").split("\n");
  if (lines.length < 6 || lines.length > 4000) return null;
  const head = /^<path>(.*)<\/path>$/.exec(lines[0]!);
  if (!head || !head[1]!.startsWith("/") || !paths.includes(head[1]!)) return null;
  if (lines[1] !== "<type>file</type>" || lines[2] !== "<content>") return null;
  if (lines[lines.length - 1] !== "</content>") return null;
  if (!OPENCODE_READ_TRAILER_RE.test(lines[lines.length - 2]!)) return null;
  if (lines[lines.length - 3] !== "") return null;
  const body = lines.slice(3, lines.length - 3);
  if (body.length === 0) return null;
  const out: string[] = [];
  let expect: number | null = null;
  for (const line of body) {
    const m = /^(\d{1,9}): ([\s\S]*)$/.exec(line);
    if (!m) return null;
    const n = Number(m[1]);
    if (expect !== null && n !== expect) return null;
    expect = n + 1;
    out.push(m[2]!);
  }
  return out.join("\n");
}
