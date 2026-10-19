/**
 * apply-patch — read the target paths out of an `apply_patch` input, the
 * `*** Begin Patch` format (arbiter tool-gate-surface.ts PatchToolFields).
 *
 * PROVENANCE: the parser below is a port of OpenClaw's own
 * (openclaw 2026.6.35, src/agents/apply-patch.ts: parsePatchText,
 * checkPatchBoundariesLenient, parseOneHunk, parseUpdateFileChunk; read from
 * the published dist, agent-tools-*.js). It is Codex's apply_patch grammar.
 * Only what decides WHICH LINES ARE FILE HEADERS is kept, line for line, so
 * the proxy and the agent read the same headers from the same text: the trim
 * of the whole input, the lenient `<<EOF` heredoc wrapper, the per-hunk
 * consumption rules (an Add hunk eats `+` lines; an Update hunk eats chunk
 * lines until a line that starts with `***`). The hunk bodies are not kept.
 *
 * FAIL-CLOSED: every input OpenClaw's parser throws on, this one rejects with
 * the same message (the proxy then refuses the call whole; OpenClaw parses
 * before it applies anything, so a patch it cannot parse changes nothing
 * either way). A later OpenClaw that parses more loosely than this port sees
 * its extra patches refused, never passed ungated.
 *
 * The header paths are spliced back by line (`rewritePatchPaths`) so the view
 * map can move them between the views without touching a content line.
 */

export const BEGIN_PATCH_MARKER = "*** Begin Patch";
export const END_PATCH_MARKER = "*** End Patch";
export const ADD_FILE_MARKER = "*** Add File: ";
export const DELETE_FILE_MARKER = "*** Delete File: ";
export const UPDATE_FILE_MARKER = "*** Update File: ";
export const MOVE_TO_MARKER = "*** Move to: ";
const EOF_MARKER = "*** End of File";
const CHANGE_CONTEXT_MARKER = "@@ ";
const EMPTY_CHANGE_CONTEXT_MARKER = "@@";

/** One path a patch names, where it names it. */
export interface PatchPath {
  /** What the patch does to the path. `move` is the destination of an
   *  Update's `*** Move to:` (written); the Update's own path is the source
   *  (read, then removed). */
  kind: "add" | "delete" | "update" | "move";
  /** The path as OpenClaw reads it (the header line trimmed, the marker
   *  removed). */
  path: string;
  /** Its line in the ORIGINAL text (0-based; `\n` / `\r\n` separated). */
  line: number;
  marker: string;
}

export type PatchParse =
  | { ok: true; paths: PatchPath[] }
  | { ok: false; error: string };

/** True when `kind` puts bytes on disk at the path (the derived label's
 *  concern): an added file, an updated file, a move's destination. */
export function patchWrites(kind: PatchPath["kind"]): boolean {
  return kind !== "delete";
}

/** Parse one patch. Pure; never throws. */
export function parseApplyPatch(input: unknown): PatchParse {
  if (typeof input !== "string") return { ok: false, error: "Invalid patch: input is not a string." };
  try {
    return { ok: true, paths: parsePatchText(input) };
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }
}

function parsePatchText(input: string): PatchPath[] {
  const trimmed = input.trim();
  if (!trimmed) throw new Error("Invalid patch: input is empty.");
  // Lines the whole-input trim removed ahead of the first kept line: the
  // offset from a line of `trimmed` to the same line of `input`.
  const lead = input.slice(0, input.length - input.trimStart().length);
  let offset = lead.split(/\r?\n/).length - 1;
  const { lines: validated, heredoc } = checkPatchBoundariesLenient(trimmed.split(/\r?\n/));
  if (heredoc) offset += 1;
  const out: PatchPath[] = [];
  const lastLineIndex = validated.length - 1;
  let remaining = validated.slice(1, lastLineIndex);
  let index = 1; // index of remaining[0] in `validated`
  let lineNumber = 2;
  while (remaining.length > 0) {
    const { found, consumed } = parseOneHunk(remaining, lineNumber);
    for (const f of found) out.push({ ...f, line: offset + index + f.at });
    lineNumber += consumed;
    index += consumed;
    remaining = remaining.slice(consumed);
  }
  return out;
}

function checkPatchBoundariesLenient(lines: string[]): { lines: string[]; heredoc: boolean } {
  const strictError = checkPatchBoundariesStrict(lines);
  if (!strictError) return { lines, heredoc: false };
  if (lines.length < 4) throw new Error(strictError);
  const first = lines[0];
  const last = lines.at(-1);
  if (last && (first === "<<EOF" || first === "<<'EOF'" || first === "<<\"EOF\"") && last.endsWith("EOF")) {
    const inner = lines.slice(1, -1);
    const innerError = checkPatchBoundariesStrict(inner);
    if (!innerError) return { lines: inner, heredoc: true };
    throw new Error(innerError);
  }
  throw new Error(strictError);
}

function checkPatchBoundariesStrict(lines: string[]): string | null {
  const firstLine = lines[0]?.trim();
  const lastLine = lines[lines.length - 1]?.trim();
  if (firstLine === BEGIN_PATCH_MARKER && lastLine === END_PATCH_MARKER) return null;
  if (firstLine !== BEGIN_PATCH_MARKER) return "The first line of the patch must be '*** Begin Patch'";
  return "The last line of the patch must be '*** End Patch'";
}

type Found = Omit<PatchPath, "line"> & { at: number };

function parseOneHunk(lines: string[], lineNumber: number): { found: Found[]; consumed: number } {
  if (lines.length === 0) throw new Error(`Invalid patch hunk at line ${lineNumber}: empty hunk`);
  const firstLine = lines[0]!.trim();
  if (firstLine.startsWith(ADD_FILE_MARKER)) {
    let consumed = 1;
    for (const addLine of lines.slice(1)) {
      if (addLine.startsWith("+")) consumed += 1;
      else break;
    }
    return { found: [{ kind: "add", path: firstLine.slice(ADD_FILE_MARKER.length), marker: ADD_FILE_MARKER, at: 0 }], consumed };
  }
  if (firstLine.startsWith(DELETE_FILE_MARKER)) {
    return { found: [{ kind: "delete", path: firstLine.slice(DELETE_FILE_MARKER.length), marker: DELETE_FILE_MARKER, at: 0 }], consumed: 1 };
  }
  if (firstLine.startsWith(UPDATE_FILE_MARKER)) {
    const targetPath = firstLine.slice(UPDATE_FILE_MARKER.length);
    const found: Found[] = [{ kind: "update", path: targetPath, marker: UPDATE_FILE_MARKER, at: 0 }];
    let remaining = lines.slice(1);
    let consumed = 1;
    const moveCandidate = remaining[0]?.trim();
    if (moveCandidate?.startsWith(MOVE_TO_MARKER)) {
      found.push({ kind: "move", path: moveCandidate.slice(MOVE_TO_MARKER.length), marker: MOVE_TO_MARKER, at: 1 });
      remaining = remaining.slice(1);
      consumed += 1;
    }
    let chunks = 0;
    while (remaining.length > 0) {
      if (remaining[0]!.trim() === "") {
        remaining = remaining.slice(1);
        consumed += 1;
        continue;
      }
      if (remaining[0]!.startsWith("***")) break;
      const chunkLines = parseUpdateFileChunk(remaining, lineNumber + consumed, chunks === 0);
      chunks += 1;
      remaining = remaining.slice(chunkLines);
      consumed += chunkLines;
    }
    if (chunks === 0) throw new Error(`Invalid patch hunk at line ${lineNumber}: Update file hunk for path '${targetPath}' is empty`);
    return { found, consumed };
  }
  throw new Error(
    `Invalid patch hunk at line ${lineNumber}: '${lines[0]}' is not a valid hunk header. ` +
      "Valid hunk headers: '*** Add File: {path}', '*** Delete File: {path}', '*** Update File: {path}'",
  );
}

/** How many lines one Update chunk consumes (OpenClaw parseUpdateFileChunk,
 *  its line accounting only). */
function parseUpdateFileChunk(lines: string[], lineNumber: number, allowMissingContext: boolean): number {
  if (lines.length === 0) throw new Error(`Invalid patch hunk at line ${lineNumber}: Update hunk does not contain any lines`);
  let startIndex = 0;
  if (lines[0] === EMPTY_CHANGE_CONTEXT_MARKER) startIndex = 1;
  else if (lines[0]!.startsWith(CHANGE_CONTEXT_MARKER)) startIndex = 1;
  else if (!allowMissingContext) {
    throw new Error(`Invalid patch hunk at line ${lineNumber}: Expected update hunk to start with a @@ context marker, got: '${lines[0]}'`);
  }
  if (startIndex >= lines.length) throw new Error(`Invalid patch hunk at line ${lineNumber + 1}: Update hunk does not contain any lines`);
  let parsedLines = 0;
  for (const line of lines.slice(startIndex)) {
    if (line === EOF_MARKER) {
      if (parsedLines === 0) throw new Error(`Invalid patch hunk at line ${lineNumber + 1}: Update hunk does not contain any lines`);
      parsedLines += 1;
      break;
    }
    const marker = line[0];
    if (!marker || marker === " " || marker === "+" || marker === "-") {
      parsedLines += 1;
      continue;
    }
    if (parsedLines === 0) {
      throw new Error(
        `Invalid patch hunk at line ${lineNumber + 1}: Unexpected line found in update hunk: '${line}'. ` +
          "Every line should start with ' ' (context line), '+' (added line), or '-' (removed line)",
      );
    }
    break;
  }
  return parsedLines + startIndex;
}

/** Replace the paths of some headers. `next` maps a PatchPath's index in
 *  `paths` to its new path; every other line (content included) is left
 *  byte for byte. Pure. */
export function rewritePatchPaths(input: string, paths: readonly PatchPath[], next: ReadonlyMap<number, string>): string {
  if (next.size === 0) return input;
  // split keeping each separator, so `\n` / `\r\n` survive exactly
  const parts = input.split(/(\r?\n)/);
  for (const [i, path] of next) {
    const p = paths[i];
    if (!p) continue;
    const at = p.line * 2; // parts alternate line, separator
    const line = parts[at];
    if (line === undefined) continue;
    const m = line.indexOf(p.marker);
    if (m < 0) continue;
    parts[at] = line.slice(0, m + p.marker.length) + path;
  }
  return parts.join("");
}
