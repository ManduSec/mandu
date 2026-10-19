/**
 * view-model/patch-files — the files an `apply_patch` call touches, read off
 * its patch text's file headers (dashboard.md §4.25b, *Every agent's steps
 * read in words*, "A patch names its files").
 *
 * Mandu-new (no reference origin). WHY: `apply_patch` (Codex's freeform and
 * JSON forms, OpenClaw's) names its files only inside the patch, so the
 * session page read "Edited `a file`" for every patch. The patch is the
 * `*** Begin Patch` format (Codex's grammar; OpenClaw's parser is a port of
 * it, and the anthropic-proxy's gate reads the same headers,
 * `interceptors/anthropic-proxy/src/apply-patch.ts`):
 *
 *   *** Add File: <path>       a new file (its lines follow, each `+`)
 *   *** Update File: <path>    a changed file (`@@` chunks follow)
 *   *** Move to: <path>        right after an Update: the file's new name
 *   *** Delete File: <path>    a removed file
 *
 * This reader only NAMES files for a page; it decides nothing, so it is
 * lenient where the gate's parser is strict: a header is a line that starts
 * with its marker at the first column (a patch's content lines start with
 * ` `, `+` or `-`, so a file that merely contains a header's text is never
 * read as one), and a malformed patch yields the headers it has. Pure.
 *
 * The input is the call's arguments as recorded, what the AI wrote (its
 * masked items as placeholders): the JSON form's `{"input": "<patch>"}`
 * (Codex's JSON tool, OpenClaw's, and Codex's freeform tool as the
 * openai-proxy records it), OpenCode's `{"patchText": …}`, a bare JSON
 * string (the request transcript's `→ apply_patch("<patch>")`), or the patch
 * text itself. A Codex code-mode cell's `tools.apply_patch("…")` reaches it
 * as the first form: the openai-proxy records each patch whose text is a
 * literal as `apply_patch({"input": …})` under the cell's call id
 * (cell-patch-calls.ts there), so one step may hold several patches
 * (`patchFilesOf`).
 */

/** One file a patch touches. `move`: an Update renamed to `to`. */
export interface PatchFile {
  kind: "add" | "update" | "delete" | "move";
  path: string;
  /** The new name, for a `move` only. */
  to?: string;
}

/** Each supported agent's patch tool, by lower-cased name. */
const PATCH_TOOLS: ReadonlySet<string> = new Set(["apply_patch"]);

/** True for a tool whose input is a patch in the `*** Begin Patch` format. */
export function isPatchTool(tool: string): boolean {
  return PATCH_TOOLS.has(tool.toLowerCase());
}

/** The argument fields a patch tool carries its patch in, in the order read:
 *  Codex's and OpenClaw's `input`, OpenCode's `patchText`, a generic
 *  `patch`. */
const PATCH_FIELDS = ["input", "patchText", "patch"] as const;

/** The patch text out of a call's recorded arguments, or null. */
export function patchText(input: string | null | undefined): string | null {
  if (typeof input !== "string" || input.trim() === "") return null;
  let v: unknown;
  try {
    v = JSON.parse(input);
  } catch {
    return input; // the patch itself
  }
  if (typeof v === "string") return v;
  if (v && typeof v === "object" && !Array.isArray(v)) {
    for (const f of PATCH_FIELDS) {
      const s = (v as Record<string, unknown>)[f];
      if (typeof s === "string" && s.trim() !== "") return s;
    }
  }
  return null;
}

const ADD = "*** Add File: ";
const UPDATE = "*** Update File: ";
const DELETE = "*** Delete File: ";
const MOVE = "*** Move to: ";

/** The files several patch calls touch, in order, each listed once: a Codex
 *  code-mode cell may patch more than once, and every patch is recorded
 *  under the cell's one call id (§4.25b "A patch in a code cell"). */
export function patchFilesOf(inputs: readonly (string | null | undefined)[]): PatchFile[] {
  const out: PatchFile[] = [];
  const push = dedupPush(out);
  for (const input of inputs) for (const f of patchFiles(input)) push(f);
  return out;
}

/** A pusher that lists a file named the same way once. */
function dedupPush(out: PatchFile[]): (f: PatchFile) => void {
  const seen = new Set<string>();
  return (f) => {
    const key = `${f.kind}\u0000${f.path}\u0000${f.to ?? ""}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push(f);
  };
}

/** The files a patch call touches, in the patch's order (a file named twice
 *  the same way is listed once); empty when it names none. */
export function patchFiles(input: string | null | undefined): PatchFile[] {
  const text = patchText(input);
  if (text === null) return [];
  const out: PatchFile[] = [];
  const push = dedupPush(out);
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trimEnd();
    const header = (marker: string): string | null => {
      if (!line.startsWith(marker)) return null;
      const p = line.slice(marker.length).trim();
      return p === "" ? null : p;
    };
    const add = header(ADD);
    if (add !== null) { push({ kind: "add", path: add }); continue; }
    const del = header(DELETE);
    if (del !== null) { push({ kind: "delete", path: del }); continue; }
    const upd = header(UPDATE);
    if (upd !== null) {
      // A rename is the Update's very next line.
      const next = (lines[i + 1] ?? "").trim();
      const to = next.startsWith(MOVE) ? next.slice(MOVE.length).trim() : "";
      if (to !== "") {
        push({ kind: "move", path: upd, to });
        i++;
      } else {
        push({ kind: "update", path: upd });
      }
    }
  }
  return out;
}
