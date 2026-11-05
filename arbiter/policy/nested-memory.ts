/**
 * nested-memory — Claude Code's project notes attached to a tool result
 * (confidentiality.md §7.1, "Project notes attached to a Read").
 *
 * When Claude Code reads a file in a directory whose project notes
 * (`CLAUDE.md`, `CLAUDE.local.md`) it has not loaded yet, it APPENDS them to
 * that Read's result as a reminder block of its own:
 *
 *     <system-reminder>
 *     Contents of /abs/dir/CLAUDE.md:
 *
 *     <the file's text>
 *     </system-reminder>
 *
 * (a description may follow the path: "Contents of …/CLAUDE.md (project
 * instructions, checked into the codebase):"), then its token-budget block.
 * Claude Code then counts the notes as in context: a later Read of that
 * CLAUDE.md answers "This file is already in your context" with no byte of
 * it. Masked with the secret file the Read was of, the notes never reached
 * the model at all (live 2026-10-28, live-claude-final-20261028-a,
 * demo-env-to-production: the Read of shop-app/.env carried the project's
 * notes, the model never saw the Launchdeck API they describe, guessed its
 * paths and the deploy never happened).
 *
 * A block counts as the notes only when it is VERIFIED: the path is an
 * absolute path to a file named `CLAUDE.md` or `CLAUDE.local.md`, and the
 * block's text is that file's text on disk now (the caller reads it), and
 * the caller found that text no secret (it classifies it as a Read of that
 * path). A forged block (a tool's own output imitating the shape) can then
 * pass nothing but what a Read of that file would: the file's own,
 * non-secret text. Anything else in the tail keeps today's rule (the proxy
 * drops it). Pure; loop-based, no backtracking regex over adversarial input.
 */

import { isHarnessTokenBudgetReminder } from "./claude-code-inbound.js";

const OPEN = "<system-reminder>";
const CLOSE = "</system-reminder>";
const HEAD = `${OPEN}\nContents of `;

/** The memory file names Claude Code attaches this way. */
export const MEMORY_FILE_RE = /(?:^|\/)CLAUDE(?:\.local)?\.md$/;

/** One parsed notes block: the file it names and the text it carries. */
export interface MemoryBlock { path: string; content: string }

/** The notes block `block` is (a whole `<system-reminder>…</system-reminder>`
 *  span, surrounding whitespace allowed), or null. */
export function memoryBlockOf(block: string): MemoryBlock | null {
  const b = block.trim();
  if (!b.startsWith(HEAD) || !b.endsWith(`\n${CLOSE}`)) return null;
  const headEnd = b.indexOf(":\n\n", HEAD.length);
  if (headEnd < 0) return null;
  let path = b.slice(HEAD.length, headEnd);
  if (path.includes("\n")) return null;
  // an optional description: "<path> (project instructions, …)"
  const desc = / \([^()\n]{1,120}\)$/.exec(path);
  if (desc) path = path.slice(0, desc.index);
  if (!path.startsWith("/") || !MEMORY_FILE_RE.test(path)) return null;
  const content = b.slice(headEnd + 3, b.length - CLOSE.length - 1);
  if (content.includes(CLOSE)) return null;
  return { path, content };
}

/** The trailing complete reminder blocks of `value` and what precedes them. */
function trailingBlocks(value: string): { body: string; blocks: string[] } {
  const blocks: string[] = [];
  let end = value.length;
  for (;;) {
    let i = end;
    while (i > 0 && /\s/.test(value[i - 1]!)) i--;
    if (i < CLOSE.length || !value.startsWith(CLOSE, i - CLOSE.length)) break;
    const open = value.lastIndexOf(OPEN, i - CLOSE.length);
    if (open < 0) break;
    blocks.unshift(value.slice(open, i));
    end = open;
  }
  return { body: value.slice(0, end), blocks };
}

/** Does the file at `path` hold `content` now, and is that text no secret?
 *  (the caller's: it reads the disk and classifies). */
export type MemoryVerifier = (path: string, content: string) => boolean;

/** A tail block Claude Code's runtime wrote: its token-budget block, or a
 *  VERIFIED notes block. */
function harnessBlock(block: string, verify: MemoryVerifier): "budget" | "memory" | null {
  if (isHarnessTokenBudgetReminder(block)) return "budget";
  const m = memoryBlockOf(block);
  return m !== null && verify(m.path, m.content) ? "memory" : null;
}

/** `value` past its trailing runtime blocks (budget blocks and verified
 *  notes blocks, in any order), when every trailing block is one and at
 *  least one notes block is among them: `{ body, stripped: true }`, the
 *  body trimmed at its end. Otherwise `value` unchanged. Grants no trust. */
export function withoutVerifiedMemoryTail(value: string, verify: MemoryVerifier): { body: string; stripped: boolean } {
  const { body, blocks } = trailingBlocks(value);
  if (blocks.length === 0) return { body: value, stripped: false };
  const kinds = blocks.map((b) => harnessBlock(b, verify));
  if (kinds.some((k) => k === null) || !kinds.includes("memory")) return { body: value, stripped: false };
  const trimmed = body.trimEnd();
  return trimmed === "" ? { body: value, stripped: false } : { body: trimmed, stripped: true };
}

/** Is `value` ENTIRELY runtime blocks, at least one of them a verified notes
 *  block (the tail the proxy asks about on its own)? */
export function isVerifiedMemoryTail(value: string, verify: MemoryVerifier): boolean {
  const { body, blocks } = trailingBlocks(value);
  if (body.trim() !== "" || blocks.length === 0) return false;
  const kinds = blocks.map((b) => harnessBlock(b, verify));
  return kinds.every((k) => k !== null) && kinds.includes("memory");
}

/** The text a notes block may carry for a file whose text is `file`:
 *  exactly the file, its final newline kept or dropped. */
export function memoryContentMatches(content: string, file: string): boolean {
  return content === file || content === file.replace(/\n$/, "") || `${content}\n` === file;
}
