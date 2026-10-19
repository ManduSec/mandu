/**
 * own-write-notice — the confidentiality release of a whole-content write's
 * own success notice (confidentiality-plan-15-prompt-filter.md §13.10, "A
 * Write's own result"; confidentiality.md §7.1, "The write notice").
 *
 * PROVENANCE: NEW Mandu code (2026-10-11). The notice shapes are read off
 * the agents themselves: Claude Code 2.1.296's Write
 * (`mapToolResultToToolResultBlockParam`: "File created successfully at:
 * <path>" / "The file <path> has been updated successfully." with its fixed
 * suffixes), OpenCode 2.0.23's `write` (arbiter/test/fixtures/
 * opencode2-tool-surface-2026-10-05.json: "Created file successfully:
 * <path>") and Goose 1.53's `write` (read off the wire 2026-10-05:
 * "Created <path> (N lines)"). Added 2026-10-11, read off the installed
 * packages of the CI pins (scripts/ci/pins.env): OpenCode 1.18.13's `write`
 * (npm opencode-ai, the compiled tool in its binary: `let b="Wrote file
 * successfully."`, then only LSP diagnostics appended) and OpenClaw
 * 2026.7.1-2's `write` (npm openclaw, dist/sessions-*.js
 * `createWriteToolDefinition`: "Successfully wrote ${content.length} bytes
 * to ${path}"; 2026.9.9's dist/tools-*.mjs prints
 * `Buffer.byteLength(content, "utf8")` in the same sentence).
 *
 * THE FAILURE (drill conf-derived-label-next-session, 2026-10-08): a
 * HIGH session's Write is labelled at its watermark on disk at the tool_use
 * (Plan 9), so the Write's own result, classified by its `file_path` like
 * any result of a call that names the path, came back to the model as
 * `$MDU:anymodel_Write[…]`. The model could not tell whether its write had
 * worked, beside a request it could read.
 *
 * THE RULE. A write tool's result is `public` when it is, surrounding
 * whitespace aside, EXACTLY one of the agent's fixed success notices whose
 * only free spans are taken from the call's own input: the path equal to
 * the input's path field as the model wrote it, and (Goose) a line count or
 * (OpenClaw) a length equal to that of the input's `content`. OpenCode 1's
 * sentence has no free span at all. The input must carry `content` as
 * a string (a whole-content write the model authored). So the released text
 * is a function of the model's own tool_use input and a choice among at most
 * eight fixed notices: it holds no byte the model did not write, and no byte
 * of the file on disk. Claude Code's token-budget reminder after the notice
 * (the harness's count of tokens left, digits only, appended to every tool
 * result) is the one thing that may follow it. Everything else the tool can
 * answer keeps the path-derived mask: a notice with anything before or
 * after it (any other reminder block, diagnostics, an echoed snippet of the
 * file as older Claude Code versions printed on an update), a lookalike,
 * another path, a count that is
 * not the content's, OpenClaw's other answer "No changes made to <path>.
 * The file already has identical content." (a choice made on the file's
 * bytes, see below), another agent's notice, another tool (an `Edit`,
 * whose surrounding lines the model may never have read raw), a
 * field-addressed request.
 *
 * The bits the choice carries: whether the file was created or replaced
 * (Claude Code; whether a file existed at the path the model named:
 * metadata, never content, and Claude Code refuses to replace a file the
 * model has not Read), and whether the human edited the proposed content
 * in the permission dialog (the human's act, not the file's bytes). On
 * OpenClaw, a raw success notice also tells by elimination that the file did
 * not already hold exactly the model's `content` (else OpenClaw answers "No
 * changes made…", which stays masked): one exact whole-file guess, and a
 * wrong guess replaces the file, so the guess cannot be repeated against the
 * same bytes.
 *
 * Keyed by SPEC IDENTITY in the caller (policy-interface.ts): the tool
 * resolves to exactly that agent's built-in write entry, so a policy.yaml
 * tool rule (another object) or another agent's session never takes it.
 * Pure.
 */

/** The agents whose write notice is pinned. `opencode` is both generations
 *  (one session spec, opencode-inbound.ts); `openclaw` is the defended
 *  agent's spec (`openclaw-agent`), never the lifted reference one. */
export type OwnWriteNoticeAgent = "claude-code" | "opencode" | "goose" | "openclaw";

/** Claude Code 2.1.296's fixed suffixes after the head sentence: the human
 *  edited the proposed content, and the "file state is current" note
 *  (absent when the human edited it; absent on older versions). */
export const CC_USER_MODIFIED = " The user modified your proposed content before accepting it.";
export const CC_STATE_CURRENT = " (file state is current in your context — no need to Read it back)";

/** The `content` input's line counts a notice may print: Rust's
 *  `str::lines` (a final newline ends the last line) and the plain split. */
function lineCounts(content: string): number[] {
  if (content === "") return [0];
  const parts = content.split("\n");
  const rust = parts[parts.length - 1] === "" ? parts.length - 1 : parts.length;
  return rust === parts.length ? [rust] : [rust, parts.length];
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v !== "" ? v : undefined);

/** Every notice `agent`'s write tool may answer this call with, or [] when
 *  the call is not a whole-content write with a path. */
export function ownWriteNotices(agent: OwnWriteNoticeAgent, params: Record<string, unknown> | undefined): string[] {
  if (params === undefined || typeof params["content"] !== "string") return [];
  const content = params["content"] as string;
  switch (agent) {
    case "claude-code": {
      const path = str(params["file_path"]);
      if (path === undefined) return [];
      const heads = [`File created successfully at: ${path}`, `The file ${path} has been updated successfully.`];
      const tails = ["", CC_USER_MODIFIED, CC_STATE_CURRENT, CC_USER_MODIFIED + CC_STATE_CURRENT];
      return heads.flatMap((h) => tails.map((t) => h + t));
    }
    case "opencode": {
      // Each generation's sentence under its own field: OpenCode 2 names the
      // path `path` and prints it; OpenCode 1 names it `filePath` and answers
      // a fixed sentence with no free span.
      const out: string[] = [];
      const path = str(params["path"]);
      if (path !== undefined) out.push(`Created file successfully: ${path}`);
      if (str(params["filePath"]) !== undefined) out.push("Wrote file successfully.");
      return out;
    }
    case "goose": {
      const path = str(params["path"]);
      return path === undefined ? [] : lineCounts(content).map((n) => `Created ${path} (${n} lines)`);
    }
    case "openclaw": {
      // "bytes": 2026.7.1-2 prints the string's length (UTF-16 units),
      // 2026.9.9 its UTF-8 byte length; both of the model's own `content`.
      const path = str(params["path"]);
      if (path === undefined) return [];
      const counts = [...new Set([content.length, Buffer.byteLength(content, "utf8")])];
      return counts.map((n) => `Successfully wrote ${n} bytes to ${path}`);
    }
  }
}

/** Claude Code appends its token-budget reminder (the harness's count of
 *  tokens left, digits only: claude-code-inbound.ts
 *  isHarnessTokenBudgetReminder) to every tool result, a Write's included
 *  (seen in the drill's replay, 2.1.296). One or two such blocks after the
 *  notice, the count bounded to 12 digits, and nothing else. */
const CC_TRAILING_BUDGET_RE =
  /(?:\s*<system-reminder>\s*<total_tokens>\d{1,12} tokens left<\/total_tokens>\s*<\/system-reminder>){1,2}\s*$/;

/** Is `value` EXACTLY (surrounding whitespace aside) one of the notices
 *  `agent`'s write tool answers this call with? On Claude Code the notice
 *  may be followed by the harness's token-budget block(s), nothing else. */
export function isOwnWriteNotice(agent: OwnWriteNoticeAgent, value: string, params: Record<string, unknown> | undefined): boolean {
  if (typeof value !== "string") return false;
  let v = value.trim();
  if (agent === "claude-code") v = v.replace(CC_TRAILING_BUDGET_RE, "");
  if (v === "") return false;
  return ownWriteNotices(agent, params).includes(v);
}
