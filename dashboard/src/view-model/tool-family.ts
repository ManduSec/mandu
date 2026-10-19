/**
 * view-model/tool-family — what a tool call does, from each supported
 * agent's own tool names (dashboard.md §4.25b, *Every agent's steps read in
 * words*).
 *
 * Mandu-new (no reference origin). WHY: the session page matched tool names
 * by hand-kept lists and read Claude Code's path fields only. An OpenCode 1
 * session read "Read `a file`" for every `read{filePath}`, Codex's
 * `shell_command` "Used `shell_command`", and *Your secrets* called an
 * OpenCode or OpenClaw `read` of a secret file "Output of a `read` step"
 * where Claude Code's `Read` reads "The file …". One table names every supported agent's
 * tools by what they do. The names are the ones on the wire, as each agent's
 * gate surface records them (the arbiter's tool-gate-surface.ts; Codex's in
 * the openai-proxy), and the stack test `dashboard-agent-tool-words` keeps
 * the two in step.
 *
 * Names match whatever their case, as the page's regexes did before this
 * table (no two agents' names differ only by case). A name not in the table
 * has no family, and the page says "Used <tool>", the agent's own word. Pure.
 */

/** What a tool call does, in the page's terms. */
export type ToolFamily = "read" | "write" | "edit" | "exec" | "fetch" | "web-search" | "file-search" | "list";

/** Each supported agent's tools, by lower-cased name. The inspector words
 *  them by hand (its app.js `PR_TOOL_FAMILIES`), and
 *  `app-js-call-names.test.ts` checks it names every tool here. */
export const FAMILY: Readonly<Record<string, ToolFamily>> = {
  // Claude Code. `Monitor{command}` runs a command (its gate surface's exec map).
  read: "read", write: "write", edit: "edit", multiedit: "edit", notebookedit: "edit",
  bash: "exec", monitor: "exec", webfetch: "fetch", websearch: "web-search",
  grep: "file-search", glob: "file-search", ls: "list",
  // Codex: unified exec, the classic and string shells, its file tools.
  // `apply_patch` (OpenClaw's too) names its files only inside its patch
  // text: the page reads them there (patch-files.ts), whichever form the
  // call took (Codex's freeform one is recorded as `{input}`).
  exec_command: "exec", shell: "exec", shell_command: "exec", local_shell: "exec",
  read_file: "read", list_dir: "list", grep_files: "file-search", web_search: "web-search", apply_patch: "edit",
  // OpenCode 1 and 2 share Claude Code's lower-cased names above (`read`,
  // `write`, `edit`, `bash`, `glob`, `grep`, `webfetch`, `websearch`) and
  // 2.x's `shell` with Codex. OpenClaw: `exec`, `web_fetch`, `ls` (its
  // `read`, `write`, `edit` and `web_search` are above). Goose: `tree` (its
  // `shell`, `write` and `edit` are above).
  exec: "exec", web_fetch: "fetch", tree: "list",
  // Older or generic names the page has always worded.
  view: "read", write_file: "write", create_file: "write", fetch: "fetch", search: "file-search", find: "file-search",
};

/** The family of a tool, or null when the page has no words for it. An
 *  editor tool named `str_replace…` edits. */
export function toolFamily(tool: string): ToolFamily | null {
  const k = tool.toLowerCase();
  return FAMILY[k] ?? (k.startsWith("str_replace") ? "edit" : null);
}

/** The fields a tool names its file or folder in, in the order they are
 *  read: Claude Code's and Codex's `file_path`, OpenCode 1's `filePath`,
 *  OpenCode 2's, OpenClaw's and Goose's `path`, Claude Code's
 *  `notebook_path`, Codex's `dir_path`. */
export const PATH_FIELDS = ["file_path", "filePath", "path", "notebook_path", "dir_path"] as const;

/** The file or folder a call's arguments name, or null. */
export function pathArg(args: Readonly<Record<string, unknown>>): string | null {
  for (const f of PATH_FIELDS) {
    const v = args[f];
    if (typeof v === "string" && v.trim()) return v;
  }
  return null;
}
