/**
 * twin-write-note — the `copy:` line of the `[mandu:secret]` note: the call
 * wrote (or tried to replace) a protected file, and the change stays in the
 * file's placeholder copy (confidentiality-plan-10-flow-taint.md §4.1, "The
 * model is told at the call", and §11.8; 2026-10-27).
 *
 * Mandu-new (no reference origin).
 *
 * A write into a registered secret file lands in the session's twin, never in
 * the real file, and a rename onto the file is refused. The launcher tells the
 * person at the session's end; the model was told nothing, so in
 * demo-orders-sync-debug it rewrote `orders-app/.env` with `cat > … << 'EOF'`,
 * watched the sync succeed in the session (the sync read the copy), and told
 * the person "Fixed!" while their real file was unchanged. The arbiter now
 * answers, on the classify of such a call's result, the tokens of the call's
 * own input that it writes and that name such a file (`twinWrites`, arbiter
 * twin-write-targets.ts); this module takes the ones the input holds verbatim
 * and words the line.
 *
 * Static text and the model's own tokens: no byte of the result, no value, so
 * the line is no oracle. It explains only: no mask is raised or lowered by it.
 * The arbiter answers `twinWrites` only for a session the file guard
 * confines (an attested `confined` launch: the twins are Mandu's there; under
 * `gated` a program's write may reach the real file, and the claim would be
 * false), so the proxies add the line wherever the answer names a token.
 *
 * One module, two copies (both model proxies); the source is
 * interceptors/anthropic-proxy/src/twin-write-note.ts: change it, then run
 * `node scripts/copies/module-copies.mjs generate`.
 */

/** At most this many paths are named. */
const TWIN_WRITE_PATHS_MAX = 3;

/** The arbiter's `twinWrites` the line may name: strings the call's own
 *  input holds verbatim in one of its top-level string fields (the command,
 *  the `file_path`), at most 3, each short and on one line. Anything else is
 *  dropped: no line is better than a wrong one. Pure. */
export function twinWriteTokens(answer: unknown, input: Readonly<Record<string, unknown>> | null | undefined): string[] {
  if (!Array.isArray(answer) || input === null || input === undefined || typeof input !== "object") return [];
  const own = Object.values(input).filter((v): v is string => typeof v === "string");
  const out: string[] = [];
  for (const p of answer as unknown[]) {
    if (out.length >= TWIN_WRITE_PATHS_MAX) break;
    if (typeof p !== "string" || p === "" || p.length > 200 || /[\u0000-\u001f\u007f]/.test(p) || out.includes(p)) continue;
    if (own.some((s) => s.includes(p))) out.push(p);
  }
  return out;
}

/** The `copy:` line (without the `[mandu:secret]` marker), naming the
 *  paths as the model wrote them (`twinWriteTokens`, at least one).
 *  Byte-identical in both proxies (this module). Pure. */
export function twinWriteLine(paths: readonly string[]): string {
  const named = paths.join(", ");
  return paths.length === 1
    ? `copy: ${named} is a protected file: you and the programs you run see and change only its placeholder copy, never the user's real file. A change written into it stays in that copy, and replacing the file (sed -i, mv onto it, a file tool's or an editor's save) is refused. Programs you run in this session read the copy, so a run here may work after the change, but the copy never reaches the user's real file: Mandu discards it with the session, so the user's real ${named} is unchanged and their own runs will not see the change. Do not tell the user it is fixed or saved. Make the change where it is not secret instead (for example in the code or script that reads the file), or tell the user exactly what to change in ${named} themselves.`
    : `copy: ${named} are protected files: you and the programs you run see and change only their placeholder copies, never the user's real files. A change written into one stays in its copy, and replacing one (sed -i, mv onto it, a file tool's or an editor's save) is refused. Programs you run in this session read the copies, so a run here may work after the change, but the copies never reach the user's real files: Mandu discards them with the session, so the user's real ${named} are unchanged and their own runs will not see the change. Do not tell the user it is fixed or saved. Make the change where it is not secret instead (for example in the code or script that reads the files), or tell the user exactly what to change in them themselves.`;
}
