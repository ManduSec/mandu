/**
 * clean-tree-release — the path-derived mask's clean-tree release
 * (docs/design/confidentiality/clean-tree-release.md). Mandu-new (no
 * reference origin).
 *
 * A shell command whose text names a secret file gets the file's level from
 * the path rules, and the model proxy masks its whole result: `git rm
 * --cached .env && git status` came back as one symbol, though git never
 * printed the file (demo-c4). The arbiter offers a release of such a result
 * when the call's recorded tree read no secret, every secret path the
 * command names is a registered credential file (the counterfactual reading,
 * rule R4), and the output carries none of those files' secret bytes in any
 * form Mandu looks for. This module holds the pure parts: which tools, the
 * placeholder test (R2), the counterfactual lookup (R4) and the content
 * checks beyond the value-only release's own (R7c, R7d). The arbiter
 * (ipc/server.ts `pathReleaseOffer`) runs the tree, the value backstop and
 * the residue scan; the model proxies take the offer only on their own
 * evidence (rewrite-request.ts `acceptPathReleaseOffer`).
 *
 * PURE: no I/O (the caller passes `exists`), no symbol table.
 */
import { posix } from "node:path";

import type { LabelLookup } from "./secret-catalog.js";
import type { LabelDecision } from "./path-labels.js";
import { entropy, locateSecretShapes } from "./secret-detectors.js";
import { isSecret } from "../symbol-table/confidentiality.js";

/** R1: the shell command tools whose path-derived result may be released
 *  (Claude Code's `Bash`, OpenCode's `bash`, Goose's `shell`, Codex's
 *  `exec_command`, `shell` and `local_shell`, OpenClaw's `exec`). Never a
 *  file read, an MCP tool or a background poll. */
export const PATH_RELEASE_TOOLS: ReadonlySet<string> = new Set(["Bash", "bash", "shell", "exec_command", "local_shell", "exec"]);

/** R7d: a masked value of a named credential file this long or longer is
 *  looked for verbatim in the released text. */
export const PATH_RELEASE_OWN_VALUE_MIN = 6;

/** R2: does the call carry a placeholder anywhere in its input or origin
 *  (`MDU:` in any case, whatever surrounds it)? A command that carries one
 *  may be run with the value it stands for, and print it. Fail-closed on a
 *  value that cannot be serialized. Pure. */
export function callHoldsPlaceholder(parts: readonly unknown[]): boolean {
  for (const p of parts) {
    if (p === undefined) continue;
    let s: string;
    try {
      s = typeof p === "string" ? p : JSON.stringify(p) ?? "";
    } catch {
      return true;
    }
    if (/MDU:/i.test(s)) return true;
  }
  return false;
}

/** What the counterfactual reading may call public (R4). */
export interface CounterfactualPlaces {
  /** The registered credential files C: each reads as an explicit `public`
   *  label, which overrides the catalog as a human label does. */
  credentialFiles: ReadonlySet<string>;
  /** Every path a registry row names: never an empty place. */
  registered: ReadonlySet<string>;
  /** Is anything at this absolute path (`lstat`; an error other than
   *  ENOENT counts as something)? */
  exists: (path: string) => boolean;
  /** The request's own source strings (its origin and every string of its
   *  input, both spellings): never answered. The text scan asks the lookup
   *  about a WHOLE command as one path (`confidentialityForOrigin`), where
   *  an exact label on the string short-circuits the token scan: an answer
   *  for one would call the command public without reading its tokens. */
  sources: ReadonlySet<string>;
  /** Every directory the command's words are read in, when each is known
   *  (`commandDirsReached`, no change of directory the walk did not
   *  follow); null otherwise, and a relative token then keeps its own
   *  reading. */
  dirs: readonly string[] | null;
  /** The words of every command text (`commandWords`): the only strings the
   *  blank-holding rule may answer. */
  words?: ReadonlySet<string>;
}

/**
 * R4: the label lookup of the counterfactual reading, over `base` (the
 * engine's own). Answered differently from `base` only for a path no label
 * covers:
 *   - a file in C: `public`;
 *   - a relative token (as the scan passes it: `.env`, read by the catalog's
 *     name rule wherever it lies): `public` when it resolves to a file in C
 *     in at least ONE directory the command's words are read in, and in
 *     every other one to a file in C, an empty place (nothing on disk, no
 *     registry row) or a path a label calls public;
 *   - an absolute path with nothing on disk that no registry row names:
 *     `public` only when it is such an other resolution of such a token (the
 *     scan reads `.env` where the call started too, `/ws/.env`, after
 *     `cd storefront`): the `emptyAt` set below.
 * Review round 3: the first rule called EVERY empty place public, and git
 * prints from its object store what no longer lies on disk (`git show
 * HEAD:config/.env.production`, `git log -p -- old/.env`), which the
 * path-derived mask was the only thing to hold; now a token reads public
 * only for its link to a registered credential file. Never a source string,
 * a string holding a line break or a NUL, nor a `~` token. The roots the
 * scan reads for a token it cannot place lose exactly the literal roots of
 * the files in C. Pure (`exists` is the caller's).
 */
export function counterfactualLookup(base: LabelLookup, places: CounterfactualPlaces): LabelLookup {
  const { credentialFiles, registered, exists, sources, dirs } = places;
  const words = places.words ?? new Set<string>();
  const publicAt = (p: string): LabelDecision => ({ level: "public", bindings: [], via: p });
  const emptyPlace = (abs: string): boolean => posix.normalize(abs) === abs && !registered.has(abs) && !exists(abs);
  /** May `abs` stand beside a file in C as another resolution of one token? */
  const otherOk = (abs: string): boolean => {
    if (credentialFiles.has(abs)) return true;
    const d = base(abs);
    if (d !== null) return !isSecret(d.level);
    return emptyPlace(abs);
  };
  // The absolute places that are another directory's resolution of a token
  // naming a file in C: for each file in C under a directory of the walk,
  // its path relative to that directory, resolved in each other directory.
  const emptyAt = new Set<string>();
  for (const c of credentialFiles) {
    for (const d2 of dirs ?? []) {
      if (!c.startsWith(`${d2}/`)) continue;
      const t = c.slice(d2.length + 1);
      for (const d1 of dirs ?? []) {
        const q = posix.resolve(d1, t);
        if (q !== c) emptyAt.add(q);
      }
    }
  }
  const emptyEverywhere = (t: string): boolean => (dirs ?? []).length > 0 && (dirs ?? []).every((dir) => {
    const abs = posix.resolve(dir, t);
    return base(abs) === null && emptyPlace(abs);
  });
  const f: LabelLookup = (p: string) => {
    if (sources.has(p) || /[\r\n\0]/.test(p)) return base(p);
    if (credentialFiles.has(p)) return publicAt(p);
    const d = base(p);
    if (d !== null || p === "" || p.startsWith("~")) return d;
    if (p.startsWith("/")) {
      if (emptyAt.has(p) && emptyPlace(p)) return publicAt(p);
      // the absolute reading of a blank-holding token, where it lies empty
      const rel = (dirs ?? []).map((dir) => p.startsWith(`${dir}/`) ? p.slice(dir.length + 1) : null).find((r) => r !== null && /\s/.test(r) && words.has(r) && !/^[^\s:]*:/.test(r));
      return typeof rel === "string" && emptyEverywhere(rel) ? publicAt(p) : d;
    }
    if (dirs === null || dirs.length === 0) return d;
    let named = false;
    for (const dir of dirs) {
      const abs = posix.resolve(dir, p);
      if (credentialFiles.has(abs)) { named = true; continue; }
      if (!otherOk(abs)) return d;
    }
    // A token holding a blank is a quoted message or script the scan also
    // reads word by word (an index filter's `'git rm --cached .env'`): with
    // nothing at any of its places it reads public too (§4 item 5).
    return named || (/\s/.test(p) && words.has(p) && !/^[^\s:]*:/.test(p) && emptyEverywhere(p)) ? publicAt(p) : d;
  };
  if (base.roots !== undefined) {
    const roots = base.roots;
    f.roots = () => roots().filter((r) => !(r.matches === undefined && credentialFiles.has(r.path)));
  }
  return f;
}

type CommandTok = { text: string; start: number; end: number } | { op: string };

/** A command's words (quotes removed, with their spans) and control and
 *  redirection operators, as `messageSpans` and `commandWords` read it; null
 *  for an unterminated quote. Pure. */
function commandTokens(command: string): CommandTok[] | null {
  const toks: CommandTok[] = [];
  let i = 0;
  const n = command.length;
  while (i < n) {
    const c = command[i]!;
    if (c === " " || c === "\t") { i++; continue; }
    const op = /^(?:&&|\|\||;|\||&|\(|\)|\n|\d*>>?&?\d*|<)/.exec(command.slice(i));
    if (op && op[0] !== "") { toks.push({ op: op[0] }); i += op[0].length; continue; }
    const start = i;
    let text = "";
    while (i < n && !/[\s;|&()<>]/.test(command[i]!)) {
      const q = command[i]!;
      if (q === "'" || q === '"') {
        const e = command.indexOf(q, i + 1);
        if (e < 0) return null;
        text += command.slice(i + 1, e);
        i = e + 1;
        continue;
      }
      if (q === "\\" && i + 1 < n) { text += command[i + 1]; i += 2; continue; }
      text += q;
      i++;
    }
    toks.push({ text, start, end: i });
  }
  return toks;
}

/** The words of `command` as the shell passes them (quotes removed), for
 *  the counterfactual's blank-holding rule (R4): a token holding a blank
 *  reads public only when it is one such word (implementation review of
 *  exclusion-flags.md: the whole command string, blanked differently, was
 *  read as one empty place). Empty for an unterminated quote. Pure. */
export function commandWords(command: string): string[] {
  const toks = commandTokens(command);
  return toks === null ? [] : toks.flatMap((t) => ("op" in t ? [] : [t.text]));
}

/**
 * R4: the spans of `command` that are message text no program opens: every
 * argument of `printf` and `echo` (up to a redirection or the segment's
 * end), and the message of `git commit -m MSG` / `--message=MSG` /
 * `--message MSG` / `-mMSG`. The counterfactual reads the command with them
 * blanked, so a message that mentions `.env` (`git commit -m 'Stop tracking
 * .env'`, `printf '.env\n' >> .gitignore`) is not read as a path no file
 * lies at (review round 3 made such empty readings secret). None at all when
 * the command holds `$` or a backquote (an expansion runs a command) or an
 * unterminated quote. Pure.
 */
export function messageSpans(command: string): Array<{ start: number; end: number }> {
  if (/[$`]/.test(command)) return [];
  const toks = commandTokens(command);
  if (toks === null) return [];
  const spans: Array<{ start: number; end: number }> = [];
  let seg: Array<{ text: string; start: number; end: number }> = [];
  let redirected = false;
  const flush = (): void => {
    const name = seg[0]?.text;
    if (name === "printf" || name === "echo") {
      for (const w of seg.slice(1)) spans.push({ start: w.start, end: w.end });
    } else if (name === "git") {
      const sub = seg.findIndex((w, k) => k > 0 && !w.text.startsWith("-"));
      if (sub > 0 && seg[sub]!.text === "commit") {
        for (let k = sub + 1; k < seg.length; k++) {
          const t = seg[k]!.text;
          if ((t === "-m" || t === "--message") && seg[k + 1]) { spans.push({ start: seg[k + 1]!.start, end: seg[k + 1]!.end }); k++; }
          else if (/^--message=/.test(t) || /^-m./.test(t)) spans.push({ start: seg[k]!.start, end: seg[k]!.end });
        }
      }
    }
    seg = [];
    redirected = false;
  };
  for (const t of toks) {
    if ("op" in t) {
      if (/[<>]/.test(t.op)) { redirected = true; continue; }
      flush();
      continue;
    }
    // a redirection's target is a path the shell opens: never message text
    if (redirected) { redirected = false; continue; }
    seg.push(t);
  }
  flush();
  return spans;
}

/** `text` with each span blanked by spaces of its length. Pure. */
export function blankSpans(text: string, spans: ReadonlyArray<{ start: number; end: number }>): string {
  let out = text;
  for (const s of spans) out = out.slice(0, s.start) + " ".repeat(s.end - s.start) + out.slice(s.end);
  return out;
}

/** The plain `cd` / `pushd` words at a command's place (`cd x`, `(cd x`,
 *  `&& pushd x`), which `commandDirsReached` follows. */
const PLAIN_CD_RE = /(^|[\s;&|(])(?:cd|pushd)(?=\s)/g;

/**
 * R4: the directories every word of `command` is read in, or null when one
 * is not known or when the command may change directory in a way the walk
 * does not follow: a computed target (`unresolvedDirChange`), a `cd` the
 * walk did not count (inside a quoted script, an `eval`, a `\cd`), or any
 * other change `directoryMayChange` sees once the walk's own `cd`s are
 * taken out (`popd`, `-C`, `--work-tree`, `chdir`, `source`, `$C ..`), a
 * line break, a lone `&` or a brace group.
 * `walk` is `commandDirsReached`. Pure.
 */
export function wordDirectories(
  command: string,
  start: string | null,
  walk: (command: string, start: string | null) => { dirs: string[]; cds: number } | null,
  catalog: { directoryMayChange: (text: string) => boolean; unresolvedDirChange: (text: string) => boolean },
): string[] | null {
  // A line break, a background job's lone `&` (`2>&1` and `&>` are
  // redirections), a `{ …; }` group: separators the walk does not model
  // (review round 2)
  if (start === null || /[\r\n{}]/.test(command) || /(?<![&<>])&(?![&>])/.test(command)) return null;
  const reached = walk(command, start);
  if (reached === null || catalog.unresolvedDirChange(command)) return null;
  let plain = 0;
  const rest = command.replace(PLAIN_CD_RE, (_m, lead: string) => { plain++; return `${lead}:`; });
  if (plain !== reached.cds || catalog.directoryMayChange(rest)) return null;
  return reached.dirs;
}

/**
 * R7e (review round 1 of the design, finding 2): a bare token that reads as
 * a credential, with no vendor prefix and no `name=` beside it, which the
 * shapes miss (`Zx9Kp2mWq8Lr5Tv3Nc7Bd1`: an old value no registry row holds,
 * read through a gap). A run of 16 or more letters, digits and `_-+/=` that
 * holds an upper-case letter, a lower-case letter and a digit, at 3.5 bits a
 * character or more. Not a path (`/` with a `.`), hex alone (git's object and
 * commit ids) nor a UUID. Coarse on purpose: a false hit masks the result
 * whole, as before. The first such token, or null. Pure.
 */
export function bareCredentialToken(text: string): string | null {
  for (const m of text.matchAll(/[A-Za-z0-9_+/=-]{16,}/g)) {
    const t = m[0];
    if (/^[0-9a-fA-F]+$/.test(t) || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(t)) continue;
    if (!/[A-Z]/.test(t) || !/[a-z]/.test(t) || !/[0-9]/.test(t)) continue;
    if (entropy(t) < 3.5) continue;
    return t;
  }
  return null;
}

/**
 * R7c and R7d over the text the release would carry, each replaced span
 * cut out (`residueCheckText`): the reason it is refused, or null. A
 * credential shape anywhere (`locateSecretShapes`: a key no registry row
 * holds, an old version of the file no object twin hid), or a masked value
 * of a named credential file of `PATH_RELEASE_OWN_VALUE_MIN` characters or
 * more, verbatim. Pure.
 */
export function pathReleaseContentProblem(checkText: string, ownValues: readonly string[]): string | null {
  if (locateSecretShapes(checkText, { maxHits: 1 }).length > 0) return "a credential shape";
  if (bareCredentialToken(checkText) !== null) return "a bare token that reads as a credential";
  for (const v of ownValues) {
    const value = v.replace(/\r?\n$/, "");
    if (value.length >= PATH_RELEASE_OWN_VALUE_MIN && checkText.includes(value)) return "a masked value of a named credential file";
  }
  return null;
}
