/**
 * goose-inbound — the inbound data-trust ruleset for the GOOSE agent
 * (aaif-goose/goose, the `goose` CLI; formerly block/goose).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   DERIVED from claude-code-inbound.ts by way of opencode-inbound.ts, which
 *   is the same re-map for OpenCode. The schema vocabulary (literal
 *   TRUSTED | UNTRUSTED), the resolver and the trust categories are
 *   unchanged. Only the tool NAMES are Goose's, and every posture below is
 *   inherited from the Claude Code entry it mirrors, so the agents cannot
 *   silently diverge on what "trusted" means.
 *
 * TOOL SURFACE — READ OFF THE WIRE, NOT FROM DOCS (2026-10-05).
 *   The names below are the `tools[]` of real goose 1.53.0 requests captured
 *   against a local /v1/messages stand-in
 *   (arbiter/test/fixtures/goose-tool-surface-2026-10-05.json; a unit test
 *   holds this table and the gate table to it). The default surface of
 *   `goose run` / `goose session`:
 *     analyze, apps__{create,delete,iterate,list}_app, delegate, edit,
 *     extensionmanager__{list_resources, manage_extensions, read_resource,
 *     search_available_extensions}, load, load_skill, read_image, shell,
 *     tree, write
 *   Platform extensions marked `unprefixed_tools` expose bare names; every
 *   other extension's tools are `<extension key>__<tool>` (DOUBLE underscore).
 *   goose 1.54.0 (2026-10-08) advertises the same names with the same input
 *   fields, on the default surface and with each opt-in builtin (captured
 *   2026-10-09 the same way, supported-agents.md §5.6).
 *
 *   EVERY TOOL RESULT IS A PLAIN STRING on the wire (captured): `shell`
 *   answers stderr, then stdout, then "Command exited with code N" when
 *   non-zero, not the `{stdout, stderr, exit_code}` object its description
 *   names (that is the structuredContent Goose keeps for itself). So each
 *   entry is a whole-result literal; there are no fields to address.
 *
 *   There is NO file-read tool: Goose reads a file through `shell` (`cat`),
 *   so a file's bytes arrive as shell output, UNTRUSTED, with the exec-output
 *   legs (callTaint, the value backstop) applying.
 *
 * SECURITY INVARIANT (carried over, unchanged):
 *   TRUSTED is granted ONLY on an explicit rule match. An unlisted tool fails
 *   closed to UNTRUSTED in policy-interface.ts. The proxy over-symbolizes when
 *   in doubt and never under-symbolizes.
 *
 * DELIBERATELY UNMAPPED (fail-closed UNTRUSTED by omission, AND the
 *   unmapped-input scan, which raises a result's level for every labeled
 *   path its input names; secret-catalog.ts labelForUnmappedInput):
 *   `analyze` (function and import names read out of source files),
 *   `read_image` (a local image's bytes or a fetched URL's),
 *   `computercontroller__{pdf,docx,xlsx}_tool` (a document's text),
 *   `summarize__summarize` (an LLM summary of the files in `paths`). Each
 *   reads a file in process and names it in an input field, which is exactly
 *   what the scan exists for; each is mapped by GOOSE_GATE_SURFACE (its path
 *   field gated), so its result is not masked for being unmapped
 *   (mapped-tools.ts) and the session-health answer does not count it unknown.
 *   Masked whole BY DECISION (mapped-tools.ts MASKED_BY_DECISION):
 *   `extensionmanager__list_resources` / `extensionmanager__read_resource`
 *   (the MCP resources of the extension the model names). Refused
 *   (tool-gate-surface.ts): `extensionmanager__manage_extensions`, every
 *   `apps__*` but `list_apps`, the scheduler, the orchestrator's agent
 *   control. Also unmapped: `chatrecall__chatrecall`, `memory__*` (retrieved
 *   memories), `orchestrator__list_sessions` / `view_session`,
 *   `tutorial__*`, `autovisualiser__*`, code mode's `list_functions` /
 *   `get_function_details` (harness-mapped), and every third-party MCP
 *   `<key>__<tool>`.
 *
 * NAME-ADDRESSED READERS (2026-10-09): `load` and `load_skill` read a file
 *   the model names by a NAME, not a path (a recipe or agent under
 *   `.agents/recipes`, `.agents/agents`, GOOSE_RECIPE_PATH; a skill under
 *   `.agents/skills`, `.goose/skills`, `.claude/skills`, `~/.agents/skills`,
 *   and a skill's supporting file as `load_skill{name: "<skill>/<file>"}`),
 *   read in Goose's own process. No input field holds the path, so the
 *   model-context gates cannot see which file it is; what keeps a labelled
 *   file's bytes from the model is the guard, which hands Goose's process
 *   the file's twin on open (rootless-confinement-ubuntu-2404.md §0.1).
 *   So the entries below hold ONLY in a session the guard confines: the
 *   arbiter maps the two tools only for a session whose launch claimed
 *   posture `confined` on the attested human plane (mapped-tools.ts
 *   GUARD_MAPPED_TOOLS). In any other session (posture `gated`, no launch
 *   record, the human plane exposed) their results are masked whole, as an
 *   unmapped tool's, and policy.yaml `mapped_tools:` does not lift that
 *   (fail-closed). launcher/test/kernel/goose-readers.test.ts holds both on
 *   the real goose: the twin under the guard, a whole mask without it.
 *
 * MCP NAMING: Goose surfaces an MCP server's tools as `<key>__<tool>`, the key
 *   being the extension's name as given (`--with-extension
 *   'mandu-inspect:<cmd>'` → `mandu-inspect__inspect_symbol`). Mandu's own
 *   tools are mapped spec-independently (inspect-tool.ts, policy-tool.ts),
 *   NOT here, for the reason opencode-inbound.ts gives (an exact entry would
 *   stop the input scan declassify_symbol keeps). On the confidentiality
 *   axis a tool neither this table nor GOOSE_GATE_SURFACE names (every
 *   extension's, the unmapped built-in extensions') has no mapping: its
 *   result is masked whole unless policy.yaml `mapped_tools:` lists it
 *   (mapped-tools.ts, confidentiality plan 10 §11.18).
 */

import type { ToolSpec } from "./schema-types.js";

export const GOOSE_INBOUND_SPEC: Record<string, ToolSpec> = {
  // ── Shell ───────────────────────────────────────────────────────────────
  // `shell{command, timeout_secs}` runs `bash -c` in the launch directory.
  // Its output is attacker-reachable (a command may cat untrusted files,
  // curl URLs, …) → UNTRUSTED. The analogue of Claude Code's `Bash`.
  shell: { schema: "UNTRUSTED" },

  // ── Local filesystem writes / edits — agent-authored metadata ───────────
  // `write{path, content}` → "Created <path> (N lines)", `edit{path, before,
  // after}` → "Edited <path> (A lines -> B lines)" (captured): an echo of
  // what the AGENT produced. (mirrors Claude Code Write / Edit)
  write: { schema: "TRUSTED" },
  edit: { schema: "TRUSTED" },

  // ── Filesystem namespace ────────────────────────────────────────────────
  // `tree{path, depth}` → file NAMES with line counts ("notes.txt  [1]"), no
  // file content → TRUSTED metadata. (mirrors Claude Code Glob)
  tree: { schema: "TRUSTED" },

  // ── Subagents ───────────────────────────────────────────────────────────
  // `delegate` returns a subagent's final text, which can carry
  // attacker-influenced content (the subagent may have read untrusted data)
  // → UNTRUSTED. Its `working_dir` is gated as a path (tool-gate-surface.ts),
  // its `provider` and `source` refused. (mirrors Claude Code Agent/Task)
  delegate: { schema: "UNTRUSTED" },

  // ── Recipes, agents and skills (summon and skills platform extensions) ──
  // `load{source, cancel, peek}`: with no `source`, the list of recipes,
  // sub-recipes and agents (names, descriptions read out of their files) and
  // the finished background tasks; with a recipe or agent name, its body
  // ("# Loaded: <name> (<kind>)\n\n<content>"); with a background task id
  // (`delegate{async: true}`), that subagent's result. `load_skill{name,
  // args}`: a skill's SKILL.md rendered with `args`, or a supporting file of
  // it by `<skill>/<relative path>`. Workspace-file content (a cloned repo
  // can carry a poisoned recipe or skill) and a subagent's answer →
  // UNTRUSTED. Name-addressed, so mapped only under the guard: see
  // NAME-ADDRESSED READERS above. (the postures of Claude Code Skill /
  // SlashCommand and TaskOutput; read from goose 1.54.0's summon.rs and
  // skills/client.rs)
  load: { schema: "UNTRUSTED" },
  load_skill: { schema: "UNTRUSTED" },

  // ── Listings of Goose's own registries ──────────────────────────────────
  // `apps__list_apps{}` → "Found N app(s):\n- <name> (WxH): <description>"
  // from the apps directory in Goose's data dir; the descriptions are
  // whatever created the app → UNTRUSTED. (Every other `apps__*` tool is
  // refused, tool-gate-surface.ts.)
  apps__list_apps: { schema: "UNTRUSTED" },
  // `extensionmanager__search_available_extensions{}` → the names and
  // descriptions of the configured extensions that can be enabled or
  // disabled (config.yaml, no env, no command) → UNTRUSTED.
  extensionmanager__search_available_extensions: { schema: "UNTRUSTED" },

  // ── Agent-authored bookkeeping ──────────────────────────────────────────
  // `todo__todo_write{content}` (opt-in builtin) echoes the agent's own todo
  // list → TRUSTED metadata. (mirrors Claude Code TodoWrite)
  todo__todo_write: { schema: "TRUSTED" },
};
