/**
 * twin-write-targets — the files a call WRITES, read off the model's own
 * tool input, for the `copy:` line of the `[mandu:secret]` note
 * (confidentiality-plan-10-flow-taint.md §4.1, "The model is told at the
 * call", 2026-10-27).
 *
 * Mandu-new (no reference origin).
 *
 * ── THE GAP ─────────────────────────────────────────────────────────────────
 *
 * A write into a registered secret file lands in the session's placeholder
 * copy (the twin) and never reaches the real file; a rename onto it is
 * refused (plan 10 §4.1, write-protection.md §2). The launcher tells the
 * PERSON at the session's end. The model was told nothing: in
 * demo-orders-sync-debug (2026-10-27) Edit's save of `orders-app/.env` was
 * refused (EACCES on the rename), `sed -i` too, and `cat > orders-app/.env
 * << 'EOF'` "worked" (its output masked whole, path-derived); the sync run in
 * the session then read the copy and succeeded, and the model told the
 * person "Fixed!" while their real .env was unchanged.
 *
 * ── THE ANSWER ──────────────────────────────────────────────────────────────
 *
 * The arbiter's classify op answers `twinWrites`: the path tokens, as the
 * model wrote them, that the call writes and that name a registered secret
 * file Mandu serves a twin of (named-twins.ts `namedTwinsFor`). This module
 * is the first half: the WRITE targets of a shell command (an output
 * redirection, `tee`, the destination of `cp` / `mv` / `install` / `ln`,
 * the files of `sed -i` / `perl -i`, `dd of=`, `truncate`). The second
 * half, which of them are such files, is the server's (the file system and
 * the registry).
 *
 * Built from the model's own command only, never from a result byte or a
 * file's content, so the line it feeds can be no oracle: it says what Mandu
 * does with a write to that path, a fact of the path, not of a value. It
 * explains only: no mask is raised or lowered by it. A target this reader
 * misses gets no line (the safe direction for a note); a word it takes for
 * a target that is not one is dropped by the server unless it names a
 * registered secret file the command also names.
 *
 * Pure.
 */

import { dequoted, shellWords } from "./secret-catalog.js";

/** At most this many targets are answered (the proxies name at most 3). */
export const TWIN_WRITE_TARGETS_MAX = 6;
/** A longer command is not read (a heredoc of a whole file is well under). */
const COMMAND_MAX = 64 * 1024;
/** A longer target token is dropped. */
const TOKEN_MAX = 400;

/** Words that run the next word as the command (`sudo tee x`). */
const WRAPPERS: ReadonlySet<string> = new Set(["builtin", "command", "exec", "env", "nohup", "time", "sudo", "doas", "nice", "ionice", "stdbuf"]);
/** The destination is the last operand. */
const LAST_OPERAND: ReadonlySet<string> = new Set(["cp", "mv", "install", "ln", "rsync"]);
/** Every operand is a file the program rewrites in place, with `-i`. */
const IN_PLACE: ReadonlySet<string> = new Set(["sed", "gsed", "perl"]);

/** The command with each heredoc's body removed (`cat > f << 'EOF'` …
 *  `EOF`), its operator and delimiter too, and line continuations joined:
 *  a body is data, and a `>` in it is no redirection. Pure. */
export function withoutHeredocBodies(command: string): string {
  const lines = command.replace(/\\\r?\n/g, " ").split("\n");
  const out: string[] = [];
  const pending: Array<{ delim: string; tabs: boolean }> = [];
  const HEREDOC_RE = /(?<!<)<<(-?)[ \t]*(?:'([^'\n]*)'|"([^"\n]*)"|\\?([A-Za-z_][A-Za-z0-9_]*))/g;
  for (const line of lines) {
    if (pending.length > 0) {
      const { delim, tabs } = pending[0]!;
      if ((tabs ? line.replace(/^\t+/, "") : line) === delim) pending.shift();
      continue;
    }
    out.push(line.replace(HEREDOC_RE, (_m, dash: string, sq?: string, dq?: string, bare?: string) => {
      pending.push({ delim: sq ?? dq ?? bare ?? "", tabs: dash === "-" });
      return " ";
    }));
  }
  return out.join("\n");
}

/** The redirection a separator word ends with, and what came before it
 *  (`;>`, `&&>`): null for a separator with none. */
const REDIRECT_TAIL_RE = /(&>>|&>|>>|>\||>&|>|<<<|<<-|<<|<>|<&|<)$/;

/** The files a shell command writes, as the model wrote each (dequoted):
 *  see the header. In order, each once, at most
 *  {@link TWIN_WRITE_TARGETS_MAX}. Pure. */
export function shellWriteTargets(command: string): string[] {
  if (typeof command !== "string" || command === "" || command.length > COMMAND_MAX) return [];
  const words = shellWords(withoutHeredocBodies(command));
  const out: string[] = [];
  const add = (w: string): void => {
    if (w === "" || w.length > TOKEN_MAX || w === "-" || /^\d+$/.test(w) || /^\/dev\//.test(w) || out.includes(w)) return;
    out.push(w);
  };
  let cmd: string | null = null;
  let first = true;
  let args: string[] = [];
  /** What the next plain word is: a write target, a word to pass over
   *  (an input's source, a descriptor), or an ordinary word. */
  let next: "target" | "skip" | null = null;
  const endSegment = (): void => {
    if (cmd !== null) {
      for (const t of segmentTargets(cmd, args)) add(t);
    }
    cmd = null; first = true; args = []; next = null;
  };
  for (const { w, sep } of words) {
    if (sep) {
      const m = REDIRECT_TAIL_RE.exec(w);
      const before = m ? w.slice(0, -m[1]!.length) : w;
      if (before !== "") endSegment();
      if (!m) continue;
      const op = m[1]!;
      next = op === ">" || op === ">>" || op === ">|" || op === "&>" || op === "&>>" || op === "<>" ? "target"
        : op === ">&" ? "target" // `>&file` is `&>file`; a descriptor (`2>&1`) is dropped by `add`
          : "skip";
      continue;
    }
    const bare = dequoted(w);
    if (next === "target") { next = null; add(bare); continue; }
    if (next === "skip") { next = null; continue; }
    if (first) {
      if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(bare) || WRAPPERS.has(bare)) continue;
      first = false;
      cmd = bare.slice(bare.lastIndexOf("/") + 1);
      continue;
    }
    args.push(bare);
  }
  endSegment();
  return out.slice(0, TWIN_WRITE_TARGETS_MAX);
}

/** The write targets of one simple command, by its program. Pure. */
function segmentTargets(cmd: string, args: readonly string[]): string[] {
  const operands = args.filter((a) => !a.startsWith("-"));
  if (cmd === "tee") return operands;
  if (cmd === "truncate") return operands;
  if (cmd === "dd") return args.filter((a) => a.startsWith("of=")).map((a) => a.slice(3));
  if (LAST_OPERAND.has(cmd)) {
    // `cp -t DIR …` writes into a directory, never onto a named file
    if (args.some((a) => a === "-t" || a.startsWith("--target-directory") || /^-[A-Za-z]*t$/.test(a))) return [];
    return operands.length >= 2 ? [operands[operands.length - 1]!] : [];
  }
  if (IN_PLACE.has(cmd) && args.some((a) => /^-[A-Za-z]*i/.test(a) || a.startsWith("--in-place"))) return operands;
  return [];
}
