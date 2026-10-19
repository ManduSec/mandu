/** Explicit structured stdout selection, independent of the pipe/PTY decision. */
export type ReplyOutputFormat = "text" | "json" | "stream-json" | "passthrough";

// Skip known value-taking options so their values cannot impersonate format flags.
// Unknown flag grammars are not inferred; ambiguous explicit formats pass through.
const REQUIRED_VALUE_FLAGS = new Set([
  "--model", "--fallback-model", "--system-prompt", "--append-system-prompt",
  "--system-prompt-file", "--append-system-prompt-file", "--input-format",
  "--json-schema", "--permission-mode", "--max-turns", "--max-budget-usd",
  "--mcp-config", "--settings", "--setting-sources", "--session-id",
  "--agent", "--agents", "--tools", "--allowedTools",
  "--allowed-tools", "--disallowedTools", "--disallowed-tools", "--add-dir",
]);
// Claude Code 2.1.267 local --help: these values are optional. An adjacent
// option (especially --output-format) is not their value.
const OPTIONAL_VALUE_FLAGS = new Set([
  "--cloud", "--debug", "-d", "--from-pr", "--prompt-suggestions",
  "--remote-control", "--resume", "-r", "--teleport", "--worktree", "-w",
]);

export function replyOutputFormat(cmd: readonly string[]): ReplyOutputFormat {
  if (cmd[0]?.split("/").pop() !== "claude") return "text";
  let format: string | undefined;
  for (let i = 1; i < cmd.length; i++) {
    const arg = cmd[i]!;
    if (arg === "--") break;
    if (REQUIRED_VALUE_FLAGS.has(arg)) { i++; continue; }
    if (OPTIONAL_VALUE_FLAGS.has(arg)) {
      if (cmd[i + 1] !== undefined && !cmd[i + 1]!.startsWith("-")) i++;
      continue;
    }
    if (arg === "--output-format" || arg.startsWith("--output-format=")) {
      const value = arg === "--output-format" ? cmd[++i] : arg.slice("--output-format=".length);
      if (format !== undefined || value === undefined || value.startsWith("--")) return "passthrough";
      format = value;
    }
  }
  if (format === undefined || format === "text") return "text";
  return format === "json" || format === "stream-json" ? format : "passthrough";
}

/** Launcher-only transport metadata is consumed before --, never sent to the
 * child and never inherited by nested agents. Unknown enum values pass through. */
export function parseReplyInvocation(argv: readonly string[]): { cmd: string[]; outputFormat?: ReplyOutputFormat } {
  const prefix = "--mandu-output-format=";
  if (argv[0]?.startsWith(prefix) && argv[1] === "--") {
    const value = argv[0].slice(prefix.length);
    const outputFormat: ReplyOutputFormat = value === "text" || value === "json" || value === "stream-json" ? value : "passthrough";
    return { cmd: argv.slice(2), outputFormat };
  }
  return { cmd: argv[0] === "--" ? argv.slice(1) : [...argv] };
}
