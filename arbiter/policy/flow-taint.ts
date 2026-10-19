/**
 * flow-taint — the decision core of plan 10
 * (docs/design/confidentiality/confidentiality-plan-10-flow-taint.md §2, §3, §11): who may
 * open a secret file raw, what a tainted process's output becomes, and how
 * the rules of a tool call's process tree fold. PURE: no I/O, no store, no
 * privilege; the interposer (phase 2) and the proxy (phase 3) call these with
 * facts they observed, and the tests here are the oracle for both.
 *
 * Vocabulary: a READER is an app named on a file's `readers:` list, matched by
 * a PIN (resolved executable path + sha256, §11.2) or, until first use, by
 * bare name; the AGENT process (the LLM's own binary) is never a reader and
 * always gets the twin; a file with NO reader list serves the structured twin
 * to everyone; a file WITH one denies everyone else (§3.3) unless `others:
 * twin`. An untrusted-lineage process is never a reader (§3.5).
 *
 * Mandu-new (no reference origin).
 */
import { INTERPRETERS } from "./exec-identifier.js";
import { secretFileShape } from "./secret-extract.js";
import { bindingCovers, isPathBinding } from "./host-bindings.js";

/** A reader entry as the law writes it: a bare app name, or a pin. */
export type ReaderEntry = string | ReaderPin;
export interface ReaderPin {
  app: string;
  /** Resolved executable path, taken from the real file at approval. */
  path?: string;
  /** sha256 of that executable, hex. */
  sha256?: string;
  /** Lineage condition (comparisons.md §3.5): this reader counts only
   *  when a process of this app name started it, e.g. `{ app: ssh, from: git }`
   *  lets git's ssh read the key and refuses an ssh the agent runs directly. */
  from?: string;
  /** Plan 13 D3: what this reader's output becomes for the model once it
   *  holds THIS file (`readerOutputRule`). Absent = `secret`. A statement
   *  about one (file, program) pair, never about the program elsewhere. */
  output?: OutputRule;
  /** `output: mask` only: regexes whose matches are the secret spans. */
  mask?: string[];
  /** Plan 13 D8 (12), the human's word (2026-10-04): the program keeps the
   *  file's contents out of what it prints, writes and sends. Lets an
   *  unvetted program (not on `VETTED_READERS`) read raw; never a printer
   *  or a program that runs code (`entryAdmitsNothing`). Independent of
   *  `output:`. Mandu writes it only for an *Always allow* answered on the
   *  warning question (`trust:`), and keeps it on a first-use pin. */
  prints?: "nothing";
  /** Plan 13 R5: the script this interpreter must be running (absolute,
   *  canonical). The entry then names the PAIR: it matches only an opener
   *  the guard reports running exactly this file, out of the agent's reach,
   *  isolated from per-user code and not traced (`scriptFactsProblem`), and
   *  it may carry `output: clear | mask` although the interpreter runs code
   *  (`readerOutputRefusal`). */
  script?: string;
  /** sha256 of the script, hex; taken at first use from the out-of-reach
   *  file when absent (`withPinnedReader`). */
  scriptSha256?: string;
}

/** Plan 13 R5: the script an interpreter that opened a secret runs, as the
 *  guard read it (`script_identity.rs`). */
export interface ScriptFacts {
  /** The script operand, absolute and canonical. */
  path: string;
  /** sha256 of the file, hex (absent: unreadable). */
  sha256?: string;
  /** The file and every directory above it are out of the agent's reach. */
  system: boolean;
  /** The interpreter loads no per-user code (python `-I`/`-s`, node
   *  `--no-global-search-paths`, zsh `-f`). */
  isolated: boolean;
  /** Another process ptraces the opener. */
  traced: boolean;
}

/** What a tainted app's stdout becomes before the model sees it (§2.2). */
export type OutputRule = "secret" | "clear" | "mask";
export interface AppRule {
  app: string;
  output: OutputRule;
  /** Rule `mask` only: regexes whose matches are the secret spans. */
  mask?: string[];
}

/** The process the interposer saw at the open. */
export interface OpenerFacts {
  /** `/proc/<pid>/exe`, resolved. */
  exe: string;
  /** sha256 of that file, hex, when the caller computed it. */
  sha256?: string;
  /** The LLM's own process (or one of its MCP servers): never a reader. */
  isAgent?: boolean;
  /** Integrity taint on the lineage (network-origin, §3.5). */
  integrityTainted?: boolean;
  /** The opener's ancestors, nearest first (the guard walks /proc): each
   *  one's resolved executable and whether it is TRUSTED as a `from:`
   *  parent (out of the agent's reach and run with a clean loader
   *  environment, Plan 13 D8). Undefined = unknown: a `from:` reader then
   *  does not match. */
  ancestors?: ReadonlyArray<{ exe: string; trusted?: boolean }>;
  /** Plan 13 D8: the executable (the inode it runs) and every directory
   *  above it are out of the agent's reach (unwritable by its uid). Only
   *  such a binary is pinned on first use. Undefined = unknown = not. */
  exeSystem?: boolean;
  /** Plan 13 D8: the loader / interpreter variables (LD_PRELOAD,
   *  PYTHONPATH, NODE_OPTIONS, …) the opener runs with set to a value the
   *  launch did not give, by name, and `code:<path>` for an executable file
   *  mapped into it that the agent can write (a preloaded library), and
   *  `args:<program> <option>` for an option or variable that hands the
   *  program code to run (`git -c alias.x=!sh`, `ssh -o ProxyCommand=…`,
   *  `less +!cmd`; the guard's `args_code.rs`, `argsCodeProblem`), and
   *  `runs:<family>` for a binary whose content is a language interpreter's
   *  (`python`, `node`, …) under a name the code-running list does not know
   *  (the guard's `runtime_of`, Plan 13 §8 decision (b) by content), and
   *  `pkg:<package>` for a binary whose content is a program of a package
   *  of printers or launchers (`coreutils`, `findutils`, `util-linux`, …)
   *  under a name neither list knows (the guard's `content_of`, Plan 13 D8
   *  (13), `contentPackageOf`). `[]` = checked and clean; undefined = not
   *  checked, which counts as unclean: such an opener is no reader. */
  loaderEnv?: readonly string[];
  /** Plan 13 R5: for an interpreter, the script it runs (the guard's
   *  facts). Absent: not an interpreter, or no script it could pin
   *  (`scriptProblem` says why): a `script:` entry then never matches. */
  script?: ScriptFacts;
  scriptProblem?: string;
}

/** Plan 13 D8: why an opener cannot be the program its name or pin says,
 *  from its loader environment, or null when it is clean. */
export function loaderEnvProblem(opener: OpenerFacts): string | null {
  if (opener.loaderEnv === undefined) return "its loader environment was not checked";
  const own = opener.loaderEnv.filter((n) => !n.startsWith("args:") && !n.startsWith("runs:") && !n.startsWith("pkg:"));
  if (own.length === 0) return null;
  const vars = own.filter((n) => !n.startsWith("code:"));
  const code = own.filter((n) => n.startsWith("code:")).map((n) => n.slice("code:".length));
  const parts = [
    ...(vars.length ? [`it runs with ${vars.join(", ")} set to a value the launch did not give`] : []),
    ...(code.length ? [`it has code loaded from ${code.join(", ")}, a file the agent can write`] : []),
  ];
  return `${parts.join("; ")}, so it may run code the agent wrote`;
}

/** Plan 13 D8, code by argument (2026-10-02): why this opener runs code
 *  its command line or environment hands it (the guard's `args:` findings:
 *  `git -c core.pager=…`, `ssh -o ProxyCommand=…`, `sftp -b`, `psql -f`,
 *  `less +!cmd`, `sed s///e`, `tar --to-command`, `rsync -e`, by option or
 *  variable NAME), or null. Such an invocation is the agent's program, not
 *  the one a human named: like inline code in an interpreter (decision (b))
 *  it is no reader, is never prompted for, and a verdict about it is keyed
 *  by its run (decision (c)). So is an executable the guard found, by its
 *  content, to be an interpreter under another name (`runtimeOf`, Plan 13
 *  §8 decision (b) by content, 2026-10-03). Pure. */
export function argsCodeProblem(opener: OpenerFacts): string | null {
  const found = (opener.loaderEnv ?? []).filter((n) => n.startsWith("args:")).map((n) => n.slice("args:".length));
  const runs = runtimeOf(opener);
  const parts = [
    ...(runs !== null ? [`its executable is, by its content, a ${runs} interpreter, which runs code it is given (a build no name or installed program's hash identifies)`] : []),
    ...(found.length ? [`its command line or environment hands it code to run (${found.join(", ")})`] : []),
  ];
  return parts.length ? parts.join("; ") : null;
}

/** Plan 13 §8 decision (b) by content (2026-10-03): the interpreter family
 *  the guard found in the opener's executable (`runs:<family>`, the
 *  guard's `runtime_of`: CPython's `Py_BytesMain`, node's `node::Start`,
 *  …), reported only for a binary whose name does not already say it runs
 *  code: a pyenv python renamed `mytool`, an nvm node, a static busybox,
 *  none byte-identical to an installed program (`hashRunsCode`). Such an
 *  opener is the agent's program, as one an `args:` finding names is: no
 *  reader, never prompted for, no prior verdict (`argsCodeProblem`). Pure. */
export function runtimeOf(opener: OpenerFacts): string | null {
  const f = (opener.loaderEnv ?? []).filter((n) => n.startsWith("runs:")).map((n) => n.slice("runs:".length));
  return f.length ? f.join(", ") : null;
}

/** Plan 13 D8 (13), P0 item 14 (2026-10-07): the package of printers or
 *  launchers the guard found in the opener's executable (`pkg:<package>`,
 *  the guard's `content_of`: GNU coreutils' own name, findutils',
 *  util-linux's version, grep's usage line, …), reported only for a binary
 *  whose name neither list knows and that runs no interpreter: a GNU `env`,
 *  `cat` or `xargs` of another version or a static build, renamed, no
 *  installed program's hash. Such an opener is a printer
 *  (`openerPrints`). Pure. */
export function contentPackageOf(opener: OpenerFacts): string | null {
  const f = (opener.loaderEnv ?? []).filter((n) => n.startsWith("pkg:")).map((n) => n.slice("pkg:".length));
  return f.length ? f.join(", ") : null;
}

/** How a package the guard names (`pkg:<package>`) is said to the human. */
const PACKAGE_NAMES: Readonly<Record<string, string>> = {
  coreutils: "GNU coreutils", findutils: "GNU findutils", "util-linux": "util-linux", diffutils: "GNU diffutils",
  sed: "GNU sed", grep: "GNU grep", tar: "GNU tar",
};

/** An opener that prints or copies a file's bytes, or runs a program that
 *  may: by its name or path, a copy of an installed printer by its hash
 *  (`binaryPrints`), or a program of a package of printers or launchers by
 *  its content (`contentPackageOf`, P0 item 14). Pure. */
export function openerPrints(opener: OpenerFacts): boolean {
  return binaryPrints(opener) || contentPackageOf(opener) !== null;
}

/** Why `openerPrints` holds for this opener, in words: by name, by hash, or
 *  by content. */
function printerWhy(opener: OpenerFacts): string {
  const base = basenameOf(opener.exe);
  if (readerPrints(opener.exe)) {
    return `${base} prints or copies the bytes it reads to whatever reads its output, so it never gets the real file (plan 13 D8, printers admit nothing)`;
  }
  if (hashPrints(opener.sha256)) {
    return `${base} is a copy of a program that prints or copies the bytes it reads (byte for byte ${hostProgramOf("prints", opener.sha256) || "a printer"} on this host), so it never gets the real file (plan 13 D8, printers admit nothing)`;
  }
  const pkg = (contentPackageOf(opener) ?? "").split(", ").map((p) => PACKAGE_NAMES[p] ?? p).join(", ");
  return `${base} is, by its content, a program of ${pkg}, whose programs print the files they read or run another program (no name or installed program's hash says which one it is), so it never gets the real file (plan 13 D8 (13))`;
}

export interface OpenDecision {
  /** raw = real bytes + taint; twin = the structured twin; deny = EACCES;
   *  ask = hold the open and raise an Inbox row (§11.1). */
  verdict: "raw" | "twin" | "deny" | "ask";
  /** The reader entry that matched, when `raw`. */
  reader?: ReaderPin;
  /** `raw` through a bare name: the caller writes this pin back (§11.2). */
  pinNeeded?: boolean;
  /** Plan 13 D8 (12): `ask` about a program that is neither vetted nor
   *  vouched for: the question is the warning one (`trust:`), and an
   *  *Always allow* writes `prints: nothing`. */
  unvetted?: boolean;
  why: string;
}

export interface FilePolicy {
  /** Absent = no reader list (twin for all). */
  readers?: ReaderEntry[];
  /** With a reader list: what everyone else gets (default deny). */
  others?: "deny" | "twin";
}

export interface DecideOpenOptions {
  /** Prompt (verdict `ask`) for a non-reader whose app is in the consumer
   *  table for this file, instead of serving the twin (§11.1). */
  askKnownConsumers?: boolean;
  /** `always` prompts for any non-reader; `never` never prompts. */
  ask?: "known" | "always" | "never";
  /** Plan 10 §11.13.1: this file's twin works for its known consumers over
   *  the wire (every secret value is one the session proxy puts back at the
   *  registry its key names, and this session's proxy inspects TLS). A known
   *  consumer of a file with no reader list then gets the twin instead of the
   *  raw bytes. `why` is the reason it reports. */
  wireTwin?: { why: string };
}

export function basenameOf(p: string): string {
  return p.slice(p.lastIndexOf("/") + 1);
}

/** §12.2: the denial reason recorded when a held open's ceiling passes with
 *  the Inbox row still pending. The proxy's `[mandu:secret]` note renders a
 *  denial of this shape as its "held:" form (§11.8, `isHeldTimeoutReason`),
 *  the other denials as "denied:". */
export function heldTimeoutReason(heldMs: number): string {
  return `held for ${Math.max(1, Math.round(heldMs / 1000))} s, nobody answered; the approval is still waiting in the dashboard`;
}
export function isHeldTimeoutReason(reason: string): boolean {
  return /^held for \d+ s, nobody answered\b/.test(reason);
}

/** A program's hash as the guard reports it: 64 hex digits. */
const SHA256_HEX = /^[0-9a-f]{64}$/;
/** The tail of a subject that carries a hash. */
const SUBJECT_HASH = /#([0-9a-f]{64})$/;

/** Plan 13 §8 decision (c): what a verdict about a program that runs code
 *  names besides its binary. `script`: the script it runs, canonical path
 *  and hash, under R5's checks (`verdictProgramOf`); `run`: one process (its
 *  proc key), for a program running no script R5 pins: an answer about it
 *  is about that run only and is never reused (a protected write's hold;
 *  an open of such a program is never asked about, decision (b)). */
export type VerdictProgram = { script: string; scriptSha256: string } | { run: string };

/** The markers a program's part of a subject starts with. A binary whose own
 *  path spells one gets no verdict at all (`binaryVerdictSubject` null), so
 *  a binary's subject never contains one and every subject reads back one
 *  way. */
const PROGRAM_MARKER = /#(?:script|run):/;
const SUBJECT_SCRIPT = /#script:([^#]*)#([0-9a-f]{64})$/;
const SUBJECT_RUN = /#run:([^#]*)$/;

/**
 * The Inbox subject of a human verdict about one BINARY, which is also the
 * key the verdict is found by: `<kind>:<exe>#<sha256>`, the resolved
 * executable and the hash of the inode it runs, never its basename. `open`
 * is a held secret open (Plan 10 §11.1; Plan 13 D8: an `open:psql` verdict
 * admitted every binary named psql, the agent's own copy included); `write`
 * a held change to a file that runs later (write-protection.md §2.1, the D8
 * follow-up: `write:vim` admitted an agent-written /tmp/x/vim).
 *
 * Plan 13 §8 decision (c): for a program that runs code (an interpreter or
 * a shell) the binary does not say what ran, so `program` adds it: the
 * script, `<binary>#script:<path, URI-encoded>#<script sha256>` (allowing
 * `python3 /opt/a.py` allows no other script and no inline code), or one
 * run, `<binary>#run:<proc key, URI-encoded>` (an answer for that process
 * alone).
 *
 * Without a hash (the guard could not read the file) the path alone, as a
 * pin without `sha256` matches by path (§11.2). The subject is one-to-one: a
 * path that itself ends in `#` or in `#` and 64 hex digits gets one more `#`,
 * so an unreadable file named `/w/tool#<hash>` never spells the key of the
 * binary /w/tool with that hash; a path containing `#script:` or `#run:`
 * gets no subject (null), so no binary spells a program's key; a script
 * path and a proc key are URI-encoded (no `#`). A `sha256` (or script hash)
 * that is not 64 hex digits answers null (the caller refuses or drops it).
 */
export function binaryVerdictSubject(kind: "open" | "write" | "trust", exe: string, sha256?: string, program?: VerdictProgram): string | null {
  if (PROGRAM_MARKER.test(exe)) return null;
  let base: string;
  if (sha256 !== undefined && sha256 !== "") {
    const h = sha256.toLowerCase();
    if (!SHA256_HEX.test(h)) return null;
    base = `${kind}:${exe}#${h}`;
  } else {
    base = exe.endsWith("#") || SUBJECT_HASH.test(exe) ? `${kind}:${exe}#` : `${kind}:${exe}`;
  }
  if (program === undefined) return base;
  if ("script" in program) {
    const sh = program.scriptSha256.toLowerCase();
    if (!program.script.startsWith("/") || !SHA256_HEX.test(sh)) return null;
    return `${base}#script:${encodeURIComponent(program.script)}#${sh}`;
  }
  return program.run === "" ? null : `${base}#run:${encodeURIComponent(program.run)}`;
}

function decodeSubjectPart(s: string): string {
  try { return decodeURIComponent(s); } catch { return s; }
}

/** The parts of a binary verdict's subject (`binaryVerdictSubject`): its
 *  kind, the program's name (the basename), the executable path and hash
 *  when the subject carries them, and (decision (c)) the script and its hash
 *  or the run it names. A subject written before 2026-10-02 (`open:psql`,
 *  `write:vim`) has the name only; one about an interpreter written before
 *  decision (c) has its binary alone (`staleInterpreterVerdict`). */
export function binaryVerdictParts(subject: string): { kind: string; app: string; exe?: string; sha256?: string; script?: string; scriptSha256?: string; run?: string } {
  const colon = subject.indexOf(":");
  const kind = colon >= 0 ? subject.slice(0, colon) : "";
  let rest = subject.slice(colon + 1);
  const program: { script?: string; scriptSha256?: string; run?: string } = {};
  const run = SUBJECT_RUN.exec(rest);
  const script = run ? null : SUBJECT_SCRIPT.exec(rest);
  if (run) {
    program.run = decodeSubjectPart(run[1]!);
    rest = rest.slice(0, run.index);
  } else if (script) {
    program.script = decodeSubjectPart(script[1]!);
    program.scriptSha256 = script[2]!;
    rest = rest.slice(0, script.index);
  }
  const m = SUBJECT_HASH.exec(rest);
  const exe = m ? rest.slice(0, -m[0].length) : rest.endsWith("#") ? rest.slice(0, -1) : rest;
  return { kind, app: basenameOf(exe), ...(exe.includes("/") ? { exe } : {}), ...(m ? { sha256: m[1]! } : {}), ...program };
}

/** Plan 13 §8 decision (c): a verdict about a program that runs code which
 *  names no script and no run: written before the decision, it names the
 *  interpreter alone, and no opener or writer is keyed that way any more, so
 *  it applies to nothing (the dashboard and `mandu why` say so). A renamed
 *  copy of such a program (its hash, `hashRunsCode`) is one too. */
export function staleInterpreterVerdict(subject: string): boolean {
  const p = binaryVerdictParts(subject);
  return (p.kind === "open" || p.kind === "write" || p.kind === "trust") && p.script === undefined && p.run === undefined
    && binaryRunsCode({ app: p.app, ...(p.exe !== undefined ? { exe: p.exe } : {}), ...(p.sha256 !== undefined ? { sha256: p.sha256 } : {}) });
}

/** Plan 13 D8, printers admit nothing (2026-10-03): an `open:` verdict
 *  about a printer (`readerPrints`) applies to nothing; no answer, old or
 *  new, lets a printer read a secret raw (the dashboard and `mandu why` say
 *  so, and it is never asked again). A `write:` verdict is not concerned. */
export function printerOpenVerdict(subject: string): boolean {
  const p = binaryVerdictParts(subject);
  return (p.kind === "open" || p.kind === "trust") && (binaryPrints({ app: p.app, ...(p.exe !== undefined ? { exe: p.exe } : {}), ...(p.sha256 !== undefined ? { sha256: p.sha256 } : {}) }) || scriptPrints(p.script));
}

/** Plan 13 D8 (12), the allow-list (2026-10-04): an `open:` verdict about a
 *  program that is not vetted (`readerVetted`) was given to a question that
 *  never said the program might print the file, so it applies to nothing:
 *  the program is asked again under `trust:`, with the warning. */
export function unvettedOpenVerdict(subject: string): boolean {
  const p = binaryVerdictParts(subject);
  return p.kind === "open" && p.script === undefined && p.run === undefined && !printerOpenVerdict(subject) && !staleInterpreterVerdict(subject)
    && !binaryVetted({ app: p.app, ...(p.exe !== undefined ? { exe: p.exe } : {}), ...(p.sha256 !== undefined ? { sha256: p.sha256 } : {}) });
}

/** A verdict about a program by its NAME alone (`open:psql`, `write:vim`):
 *  the form before 2026-10-02 (Plan 13 D8 and its write follow-up). Every
 *  key since names the program's file (`open:/usr/bin/psql#<sha256>`), and
 *  `decideSecretOpen` / `decideProtectedWrite` name no program without an
 *  absolute path, so such a verdict is consulted for nothing: a pending one
 *  is retired, an answered one is marked (dashboard.md §4.34 "Answers that
 *  no longer apply"). Pure. */
export function nameOnlyVerdict(subject: string): boolean {
  const p = binaryVerdictParts(subject);
  return (p.kind === "open" || p.kind === "trust" || p.kind === "write") && p.exe === undefined;
}

/** Why an ANSWERED verdict about a program applies to nothing, as a word the
 *  dashboard says in its own terms, or null: `name-only` (`nameOnlyVerdict`),
 *  `printer` (`printerOpenVerdict`), `interpreter` (`staleInterpreterVerdict`)
 *  or `unvetted` (`unvettedOpenVerdict`, and an `open:` answer naming a
 *  script). Attached at read time to every listed row (server
 *  `withProvenance`). Pure. */
export function verdictNoLongerApplies(subject: string): "name-only" | "printer" | "interpreter" | "unvetted" | null {
  if (printerOpenVerdict(subject)) return "printer";
  if (staleInterpreterVerdict(subject)) return "interpreter";
  const p = binaryVerdictParts(subject);
  if (unvettedOpenVerdict(subject) || (p.kind === "open" && p.script !== undefined)) return "unvetted";
  // Last, so a name-only row about a printer keeps the stronger reason.
  if (nameOnlyVerdict(subject)) return "name-only";
  return null;
}

/** The !437 leftover (4) (2026-10-03): why an Inbox question about a
 *  program (an `open:` or `write:` row) can no longer take effect, or null.
 *  A question about a printer (`printerOpenVerdict`, filed before printers
 *  admitted nothing) or one naming an interpreter alone
 *  (`staleInterpreterVerdict`, filed before §8 decisions (b) and (c)), or,
 *  since 2026-10-11, one naming a program by its name only
 *  (`nameOnlyVerdict`, filed before 2026-10-02), is consulted for no opener, so an answer would change nothing: such a
 *  PENDING row is retired (removed from the store and listed nowhere: the
 *  server's `retireMootQuestions`) and an answer to it is refused with this
 *  reason (`resolveEgressApproval`). An answered one stays, marked, so the
 *  human sees what no longer applies (`whyPath`). Pure. */
export function mootQuestionReason(subject: string): string | null {
  const p = binaryVerdictParts(subject);
  if (printerOpenVerdict(subject)) {
    return `${p.app} prints or copies the bytes it reads to whatever reads its output, so no answer lets it read the file raw (plan 13 D8, printers admit nothing); it gets what any other program gets and is never asked about again`;
  }
  if (staleInterpreterVerdict(subject)) {
    return `this question names ${p.app} alone, which runs any code it is given, not the script it runs, so no answer would apply to anything (plan 13 §8 decisions (b) and (c)); a script of yours is asked about on its own`;
  }
  if (unvettedOpenVerdict(subject) || (p.kind === "open" && p.script !== undefined)) {
    return `this question did not say that ${p.app} may print what it reads, so no answer to it counts (plan 13 D8 (12)); ${p.app} is asked about again, with that said`;
  }
  if (nameOnlyVerdict(subject)) {
    return `this question names ${p.app || "a program"} by its name only, as Mandu asked before 2026-10-02; questions now name the program's file and its contents, so no answer to it applies to anything; ${p.app || "the program"} is asked about again by its file`;
  }
  return null;
}

/** Plan 13 §8 decision (c): what a verdict about this opener or writer must
 *  name besides its binary. `undefined`: it runs no code it is given (the
 *  binary alone, D8); the script and its hash when it runs one R5's checks
 *  pin (`inlineCodeProblem` null); `null` when it runs code no script pin
 *  can name (inline code, stdin, an agent-writable script, …): no reusable
 *  verdict exists for it. Pure. */
export function verdictProgramOf(opener: OpenerFacts): { script: string; scriptSha256: string } | null | undefined {
  if (argsCodeProblem(opener) !== null) return null;
  if (!openerRunsCode(opener)) return undefined;
  if (inlineCodeProblem(opener) !== null || opener.script === undefined || opener.script.sha256 === undefined) return null;
  return { script: opener.script.path, scriptSha256: opener.script.sha256 };
}

/** The key of a held open (§11.1, Plan 13 D8): `binaryVerdictSubject`, and
 *  a malformed hash keys by the path alone; with decision (c)'s `program`
 *  for an interpreter running a pinned script. Null: no verdict can name
 *  this program (its path spells a program marker). */
export function openVerdictSubject(exe: string, sha256?: string, program?: { script: string; scriptSha256: string }): string | null {
  return binaryVerdictSubject("open", exe, sha256, program) ?? binaryVerdictSubject("open", exe, undefined, program);
}

/** Plan 13 D8 (12): the key of the warning question about an unvetted
 *  opener (`trust:<exe>#<sha256>[#script:…]`), the `open:` key's form under
 *  its own kind, so an answer given to the old question, which never said
 *  the program might print the file, does not count for it. */
export function trustVerdictSubject(exe: string, sha256?: string, program?: { script: string; scriptSha256: string }): string | null {
  return binaryVerdictSubject("trust", exe, sha256, program) ?? binaryVerdictSubject("trust", exe, undefined, program);
}

/** The key of a held change to a protected file (write-protection.md §2.1):
 *  `binaryVerdictSubject`, null for a malformed hash (refused). */
export function writeVerdictSubject(exe: string, sha256?: string, program?: VerdictProgram): string | null {
  return binaryVerdictSubject("write", exe, sha256, program);
}

/** The parts of an `open:` subject (`binaryVerdictParts` without the kind). */
export function openVerdictParts(subject: string): { app: string; exe?: string; sha256?: string; script?: string; scriptSha256?: string; run?: string } {
  const { kind: _kind, ...parts } = binaryVerdictParts(subject.startsWith("open:") ? subject : `open:${subject}`);
  return parts;
}

/**
 * Programs that run code they are given: shells, language interpreters and
 * command launchers (Plan 13 D8). As a reader of a secret file such a program
 * admits whatever the agent writes: `readers: [bash]` lets `bash -c 'cat
 * .env | …'` hold the raw bytes, because the pin names the interpreter, not
 * the program it runs. Since 2026-10-02 (Plan 13 §8 decision (b)) such an
 * entry admits nothing (`entryAdmitsNothing`, `matchReader`) and such an
 * opener is a reader only as a pinned `(interpreter, script)` pair
 * (`inlineCodeProblem`); the validator and the dashboard warn on the inert
 * entry and name the script form. Superset of exec-identifier's
 * INTERPRETERS; mirrored in dashboard/src/view-model/reader-runs-code.ts and
 * the guard's secret_open.rs (the ssh-agent socket's readers), all pinned
 * equal by tests/stack/reader-identity.test.ts. Matched under a
 * distribution's prefix as a printer is (`READER_NAME_PREFIXES`: `gnuenv`,
 * `gtimeout`, `uu-env`), and every file of a multi-call binary's directory
 * is one (`MULTICALL_PRINTER_DIRS`: uutils' `env` is there): Plan 13 D8,
 * leftover (3a) of !437 (2026-10-03).
 */
export const CODE_RUNNING_READERS: ReadonlySet<string> = new Set<string>([
  ...INTERPRETERS,
  // shells
  "dash", "ash", "ksh", "mksh", "fish", "csh", "tcsh", "busybox",
  // language runtimes
  "php", "lua", "luajit", "tclsh", "wish", "Rscript", "R", "julia", "java", "jshell", "guile", "racket", "pwsh", "osascript",
  // programs that run another program, or a script, from their arguments
  "env", "xargs", "find", "make", "awk", "gawk", "mawk", "nawk", "nohup", "timeout", "nice", "stdbuf", "setsid", "watch", "script", "sudo", "doas",
  // editors, debuggers, tracers and shells of a command language that run
  // what they are given or load (an rc file, -c, a plugin, `.shell`), Plan 13
  // D8 "code by argument" (2026-10-02)
  "vi", "vim", "nvim", "ex", "view", "rvim", "rview", "vimdiff", "gvim", "gview", "evim", "vimx", "emacs", "emacsclient", "ed", "red",
  "gdb", "lldb", "strace", "ltrace", "sqlite3", "expect", "m4",
  // more launchers
  "time", "parallel", "flock", "chroot", "unshare", "nsenter", "bwrap", "firejail", "systemd-run", "su", "runuser", "pkexec", "taskset", "ionice", "chrt", "prlimit",
  // multi-call binaries that carry a shell or a launcher (`toybox sh`,
  // `coreutils env`), beside busybox (Plan 13 D8 leftover (3a), 2026-10-03)
  "toybox", "coreutils",
  // relays that run a program from their arguments and hand it the socket
  // (`nc -e`, `ncat --sh-exec` / `--lua-exec`, `socat EXEC:` / `SYSTEM:`); as
  // a reader of the ssh-agent socket each hands the agent's signing to
  // whatever drives it (leftover (3b))
  "nc", "ncat", "netcat", "socat",
  // fetch and transfer clients that run a command they are given, by an
  // option or by an rc file in $HOME the agent can write (2026-10-03): the
  // ftp clients' `!cmd` and `get f |cmd` (tnftp, netkit's, inetutils');
  // aria2c's `--on-download-start/-pause/-stop/-complete/-error` and
  // `--on-bt-download-complete` hooks (also from ~/.aria2/aria2.conf);
  // lftp's `!` and `shell`; sftp's `!`; wget's and wget2's
  // `--use-askpass=<command>` (and wget2's `--plugin`); rclone's
  // `--password-command` and backend commands; `gio launch`; `kioclient
  // exec`; the text browsers' `!`, mailcap viewers and local CGI; httpie's
  // plugins. Most are printers too (`PRINTER_READERS`), which already
  // admitted nothing; on this list they are named for what they are
  "ftp", "tnftp", "netkit-ftp", "pftp", "inetutils-ftp", "aria2c", "lftp", "sftp", "wget", "wget2", "rclone",
  "gio", "kioclient", "kioclient5", "kioclient6", "lynx", "w3m", "elinks", "links", "links2", "http", "https", "httpie",
  // more editors that run a command or load code from an rc file (a
  // modeline, `:!`, `%sh{}`, M-!, a plugin), beside vim and emacs above
  "nvi", "elvis", "vis", "kak", "hx", "helix", "joe", "jstar", "jmacs", "jpico", "rjoe", "jed", "mg", "zile", "jove",
  "mcedit", "mc", "ne", "xemacs",
  // more launchers: run the program named in their arguments
  "valgrind", "perf", "rr", "setpriv", "sg", "unbuffer", "faketime", "torsocks", "proxychains", "proxychains4",
  "fakeroot", "eatmydata", "xvfb-run", "dbus-run-session", "tmux", "screen", "entr",
  // build tools and task runners that run the commands of a build file or of
  // their arguments (2026-10-04, probed): `cmake -P <script>` and `cmake -E
  // env <cmd>`, `ctest -S`, `ninja -f`, `go run` / `go generate`, `cargo
  // build` (the package's build.rs), `rustup run`, `run-parts <dir>`, and
  // the like; `npm` and `cargo` are consumer-table programs (`.npmrc`,
  // `.cargo/credentials`) that run the package's code, served the twin as
  // node is (decision (b))
  "cmake", "ctest", "cpack", "ninja", "samu", "go", "cargo", "rustup", "bazel", "bazelisk", "buck", "buck2", "please",
  "just", "task", "mage", "xmake", "premake", "qmake", "qtchooser", "bmake", "pmake", "remake", "gn",
  "scons", "meson", "muon", "gradle", "mvn", "ant", "sbt", "rake", "npm", "corepack", "pnpx",
  "nix", "nix-shell", "nix-build", "nix-instantiate", "guix", "dotnet", "terraform", "tofu", "packer", "podman", "buildah",
  "run-parts", "at", "batch",
  // more language runtimes and REPLs
  "nodejs", "pypy", "pypy3", "jython", "ipython", "irb", "erb", "jruby", "php-cgi", "php-fpm", "raku", "rakudo", "perl6", "hy",
  "erl", "erlexec", "beam", "escript", "elixir", "iex", "mix", "ocaml", "ocamlrun", "utop", "swipl", "gprolog",
  "sbcl", "clisp", "ecl", "csi", "gsi", "scheme", "chez", "chezscheme", "petite", "raco",
  "kotlin", "scala", "groovy", "clojure", "clj", "bb", "jrunscript", "mono", "runghc", "runhaskell", "ghci",
  "nim", "crystal", "zig", "dart", "swift", "tcc", "qjs", "gjs", "gforth", "wasmtime", "wasmer",
  "dc", "bc", "octave", "octave-cli", "gnuplot", "maxima",
  // more shells
  "rbash", "yash", "posh", "elvish", "nushell", "xonsh", "osh", "ysh",
  // the names these install as (P0 item 14, 2026-10-07): nushell's binary,
  // the public-domain ksh line (OpenBSD's ksh ported), Racket's two builds
  "nu", "oksh", "loksh", "pdksh", "racketbc", "racketcs",
  // TeX engines (`\write18`, `\directlua`)
  "tex", "etex", "pdftex", "xetex", "luatex", "luahbtex", "luajittex", "latex", "pdflatex", "xelatex", "lualatex", "mpost", "context", "mtxrun",
]);

/** Does this reader name (a bare name, a pin's `app` or `path`) run code it
 *  is given? Matched as `appNameMatches` matches a binary (`python3` →
 *  `python3.12`), also under a distribution's prefix (`gnuenv`, `genv`,
 *  `uu-env`: `READER_NAME_PREFIXES`), and a path inside a multi-call
 *  binary's directory always is one (uutils' `env` is there). */
export function readerRunsCode(app: string): boolean {
  if (MULTICALL_PRINTER_DIRS.some((d) => app.startsWith(d))) return true;
  for (const n of readerNameForms(basenameOf(app))) {
    if (CODE_RUNNING_READERS.has(n)) return true;
    for (const name of CODE_RUNNING_READERS) if (appNameMatches(n, name)) return true;
  }
  return false;
}

/** Does this opener run code it is given: by its executable's name
 *  (`readerRunsCode`) or, a renamed copy, by its hash (`hashRunsCode`)? */
export function openerRunsCode(opener: { exe: string; sha256?: string }): boolean {
  return readerRunsCode(basenameOf(opener.exe)) || hashRunsCode(opener.sha256);
}

/**
 * Programs whose job is to copy or print a file's bytes (Plan 13 D8,
 * "printers admit nothing", the maintainer's decision of 2026-10-03, §8). A
 * printer hands the file to whatever reads its output, which can be code
 * the agent wrote (`cat .env | python3 -c '…'`, `. <(cat .env)`); that code
 * is confined for content (a holder, D2) but not for metadata (§4.9: the
 * names of files it creates, sizes, times), so no printer ever gets the raw
 * bytes. As a reader entry a printer admits nothing (`entryAdmitsNothing`,
 * a bare name or a pin by path and hash alike); as an opener it gets what a
 * non-reader of the file gets (the twin, or the refusal its `others:`
 * gives), is never prompted for, and no prior answer counts for it.
 * Matched by basename as `readerRunsCode` matches (`appNameMatches`). Fail-
 * closed: a program that can print a file's bytes when asked is listed even
 * when printing is not its main job (`sort`, `diff`, `jq`, an archiver;
 * since 2026-10-04 `file -f`, `date -f`, `wc --files0-from`, `cc -E` and an
 * `@file` response file, `nroff`, `msgcat`: plan 13 D8 (9)).
 * A program that fetches or transfers a URL or a file is one too when a
 * local file is among what it takes (`curl file:///…`, `wget -i <file>`,
 * `scp a b`, `gio cat`, `lynx -dump file://…`; the !437 leftover (1),
 * 2026-10-03), the consumer table's `curl` and `scp` included: the printer
 * rule wins over a consumer row (`decideOpen`; `curl` still gets `.netrc`'s
 * twin under the wire release). Since 2026-10-04 `git` is one too (plan
 * 13 §4.9 option (a)): `git diff --no-index /dev/null <file>`, `git grep
 * --no-index`, `git config -f <file> --list`, `git hash-object -w` then
 * `git show` print any named file; as the consumer table's reader of
 * `.git-credentials` and `.netrc` it still gets the twin the wire release
 * serves, and `ssh` (not git) reads the ssh keys. `psql` and `pg_restore`
 * are printers too (probed 2026-10-04, plan 13 D8 (12)). The other
 * consumers (pg_dump, aws, gh, npm, docker, kubectl, helm, ssh, twine,
 * cargo) are not printers. `busybox` and `awk` are in
 * `CODE_RUNNING_READERS` too. A binary byte-identical to a host printer,
 * under any name, is one too (`hashPrints`). Mirrored in
 * dashboard/src/view-model/reader-runs-code.ts and in the guard's
 * secret_open.rs, which judges the ssh-agent socket's readers with it
 * (pinned equal by tests/stack/reader-identity.test.ts); the arbiter
 * decides every file open.
 */
export const PRINTER_READERS: ReadonlySet<string> = new Set<string>([
  // print or page a file
  "cat", "tac", "head", "tail", "less", "more", "most", "pg", "nl", "rev", "pr", "pv", "bat", "batcat",
  "zless", "zmore", "bzless", "bzmore", "xzless", "xzmore", "zstdless", "lzless", "lzmore",
  // copy a file
  "tee", "dd", "cp", "install", "rsync", "socat", "xclip", "xsel", "wl-copy",
  // encode or dump its bytes
  "base64", "base32", "basenc", "uuencode", "uudecode", "xxd", "od", "hexdump", "hd", "hexyl", "strings",
  // filter, reorder or reshape its lines
  "sed", "awk", "gawk", "mawk", "nawk", "cut", "paste", "join", "sort", "uniq", "shuf", "tr", "fold", "fmt", "column",
  "expand", "unexpand", "look", "tsort", "ptx", "split", "csplit",
  "grep", "egrep", "fgrep", "rg", "ag", "ack", "zgrep", "zegrep", "zfgrep", "xzgrep", "bzgrep", "zstdgrep",
  // compare (prints the differing lines or bytes)
  "diff", "diff3", "sdiff", "cmp", "comm", "colordiff", "wdiff", "zdiff", "zcmp", "xzdiff", "xzcmp", "bzdiff", "bzcmp",
  // convert its encoding or line ends
  "iconv", "recode", "uconv", "dos2unix", "unix2dos", "mac2unix", "unix2mac",
  // compress or archive (the archive holds the bytes, `-c` prints them)
  "gzip", "gunzip", "zcat", "pigz", "unpigz", "bzip2", "bunzip2", "bzcat", "pbzip2", "xz", "unxz", "xzcat", "pixz",
  "lzma", "unlzma", "lzcat", "lzip", "lzop", "lz4", "unlz4", "lz4cat", "zstd", "unzstd", "zstdcat", "zstdmt", "brotli",
  "tar", "gtar", "bsdtar", "bsdcat", "bsdcpio", "zip", "unzip", "funzip", "7z", "7za", "7zr", "cpio", "pax", "ar",
  // structured data processors (print a value, or the document)
  "jq", "gojq", "jaq", "yq", "xq", "tomlq", "dasel", "gron", "mlr", "xmllint", "xmlstarlet", "envsubst",
  // crypto tools that print or transform a file (`openssl enc -base64 -in`,
  // `gpg --store`); neither is a consumer-table program
  "openssl", "gpg", "gpg2",
  // editors with no code-running list entry, which show the file on the
  // terminal the agent reads
  "nano", "pico", "micro",
  // multi-call binaries: every printer above under one name
  "busybox", "toybox", "coreutils",
  // fetch or transfer a URL or a file, a local one included (the !437
  // leftover (1), 2026-10-03): `curl file:///…`, `wget -i <file>` (it
  // reports each line it cannot use), `aria2c -i <file>` (the same),
  // httpie's and xh's `--offline … @<file>` (prints the request), `lftp -c
  // 'cat file:…'`, `rclone cat <path>`, `scp a b` and `sftp -D` (a local
  // copy), `gio cat`, a text browser's `-dump file://…`
  "curl", "curlie", "wget", "wget2", "aria2c", "http", "https", "xh", "xhs", "lftp", "rclone", "scp", "sftp",
  "gio", "gvfs-cat", "gvfs-copy", "kioclient", "kioclient5", "kioclient6", "lynx", "w3m", "links", "links2", "elinks",
  // the Postgres client tools that print a file (probed 2026-10-04 against a
  // throwaway server: `psql -f <file>` and `\i <file>` / `\copy t from
  // <file>` on its standard input print the file's lines; `pg_restore -f -
  // <dump>` prints the dump as SQL): plan 13 D8 (12). psql also runs a shell
  // command it is given (`\!`, a backquoted `\set`). pg_dump prints no file
  // (a `--filter` file's well-formed patterns echo when unmatched only).
  "psql", "pg_restore",
  // the other SQL and database shells (2026-10-07, P0 (D)), by their
  // documented commands: each prints a file it is pointed at and runs a
  // command or code it is given, from its command line, its standard input
  // or an rc file the agent can write (`~/.my.cnf`'s `[mysql] pager=`,
  // `~/.duckdbrc`, `~/.mongoshrc.js`), as psql does: mysql's and mariadb's
  // `source <file>` (the server's error quotes the lines) and `\!` / `pager`;
  // mysqlsh's `\source` and `\system`; duckdb's `.read`, `.shell` and
  // `read_text('<file>')`; usql's `\i` and `\!`; sqlcmd's `:r` and `!!`;
  // sqlplus's `@<file>` and `HOST`; clickhouse's `file('<file>')` table
  // function; the MongoDB shells' `cat('<file>')` and `load()` (JavaScript).
  // Unprobed (none installed on the probe host): listed fail-closed
  "mysql", "mariadb", "mysqlsh", "duckdb", "usql", "sqlcmd", "sqlplus", "clickhouse", "clickhouse-client", "clickhouse-local",
  "mongosh", "mongo",
  // read names, dates or hosts from a file and print each one it cannot
  // use (2026-10-04): `file -f <file>` ("<line>: cannot open"), `date -f`,
  // `wc` / `du --files0-from=<file>`, `logger -s -f`, `ssh-keyscan -f`
  "file", "date", "wc", "du", "logger", "ssh-keyscan",
  // typeset or format a document or a manual page, whose text is the
  // output (`nroff <file>`, `man -l <file>`, `ul`), or echo the lines they
  // reject (`tic <file>`, `whatis -C <file>`); `scriptreplay` replays one
  "groff", "nroff", "troff", "preconv", "soelim", "zsoelim", "tbl", "eqn", "neqn", "pic", "refer", "grn", "grotty", "mandoc",
  "man", "whatis", "apropos", "lexgrog", "ul", "colcrt", "tic", "scriptreplay",
  // compile, assemble or link: `cpp <file>` and `cc -E` print it, an
  // `@<file>` response file comes back word by word in the errors (gcc,
  // clang, binutils), `objcopy -I binary <file> /dev/stdout` copies it,
  // `objdump -s -b binary` dumps it, a parser generator quotes what it
  // rejects; gettext's catalog tools print the catalog (`msgcat <file>`)
  "cpp", "cc", "c++", "gcc", "g++", "cc1", "cc1plus", "collect2", "clang", "clang++", "clang-cpp", "rustc",
  "as", "ld", "gold", "nm", "ranlib", "c++filt", "objcopy", "objdump", "readelf", "size", "strip", "elfedit", "gprof", "addr2line",
  "bison", "yacc", "byacc", "rpcgen",
  "msgcat", "msguniq", "msgconv", "msggrep", "msgattrib", "msgen", "msgmerge", "msginit", "msgcomm", "msgfilter", "msgexec",
  "msgfmt", "msgunfmt", "xgettext",
  // git (plan 13 §4.9 option (a), the maintainer's decision of 2026-10-04):
  // `git diff --no-index /dev/null <file>`, `git grep --no-index -h .
  // <file>`, `git config -f <file> --list`, `git hash-object -w <file>` then
  // `git show`. Its credential helper `git-credential-store` is git itself
  // (a link of the one binary, which picks its builtin from argv[0]; the
  // consumer table names it), and git's HTTP transport `git-remote-http`
  // (`-https`, `-ftp`, `-ftps` are links of it) is the program that opens
  // `.netrc` for git and prints the header it sends under `GIT_TRACE_CURL`
  // with `GIT_TRACE_REDACT=0`. The builtins in git's exec path (`git-diff`,
  // `git-cat-file`, …) are links of git: the same printer by its hash
  // (`program-hashes.ts` scans git's exec path). Not every name there is
  // (2026-10-07): git builds a few programs of their own. `git-http-fetch`,
  // `git-http-push` and `git-imap-send` link git's `http.c`, so libcurl
  // opens `.netrc` for them and `GIT_TRACE_CURL` prints the header they
  // send; `git-http-backend`, the CGI server, sends a file named by its
  // request (`objects/info/alternates`, a symlink to any file, comes back
  // whole). The others are scripts (the interpreter is the opener) or open
  // no file they are named (`git-daemon`, `git-shell`, `scalar` run git for
  // that; `git-sh-i18n--envsubst` reads its standard input)
  "git", "git-credential-store", "git-remote-http", "git-remote-https", "git-remote-ftp", "git-remote-ftps",
  "git-http-fetch", "git-http-push", "git-imap-send", "git-http-backend",
]);

/** Name prefixes that make a program a printer whatever follows (the
 *  maintainer's decision of 2026-10-07, plan 13 D8 (11)): a git credential
 *  helper prints `password=<secret>` on `get`, its protocol
 *  (gitcredentials(7)), and the standalone ones are programs of their own
 *  under no printer name (`git-credential-libsecret`, `-osxkeychain`, the
 *  Credential Manager, `git-credential-netrc`, a third party's). A script
 *  so named is one too (`scriptPrints`). Mirrored in
 *  dashboard/src/view-model/reader-runs-code.ts and the guard's
 *  secret_open.rs, pinned equal by tests/stack/reader-identity.test.ts. */
export const PRINTER_NAME_PREFIXES: readonly string[] = ["git-credential-"];

/** Does this name (a basename) start with a printer prefix and carry
 *  something after it? */
function printerPrefixed(base: string): boolean {
  return PRINTER_NAME_PREFIXES.some((p) => base.length > p.length && base.startsWith(p));
}

/** Is this script (a path, as a `script:` pin or the guard's facts name
 *  it) a printer by its name (`PRINTER_NAME_PREFIXES`:
 *  `…/git-credential-netrc`, a Perl script)? An interpreter running it is
 *  that printer. */
export function scriptPrints(path: string | undefined): boolean {
  return path !== undefined && printerPrefixed(basenameOf(path));
}

/** Directories of a multi-call binary that picks its program from `argv[0]`
 *  (uutils coreutils, Ubuntu's coreutils since 26.04: `/usr/bin/cat` links
 *  to `/usr/lib/cargo/bin/coreutils/cat`, one inode hard-linked under every
 *  name). Any file there is every program of the set, `cat` included
 *  (`exec -a cat …/coreutils/wc .env` prints the file), so each one is a
 *  printer whatever its name. */
const MULTICALL_PRINTER_DIRS: readonly string[] = ["/usr/lib/cargo/bin/coreutils/"];

/** Prefixes a distribution puts before a printer's name for a second copy
 *  of it: Ubuntu 26.04 ships GNU coreutils as `gnucat`, `gnuhead`, … beside
 *  uutils' `cat`; Homebrew's GNU tools are `gcat`, `gsed`, `gtar`; some
 *  packages name uutils' programs `uu-cat` / `uu_cat`. */
const READER_NAME_PREFIXES: readonly string[] = ["gnu", "g", "uu-", "uu_"];

/**
 * Plan 13 D8 (12), the allow-list (the maintainer's decision of 2026-10-04):
 * the programs vetted not to print a file they are pointed at, the only
 * ones that read a secret raw without the human's word (`prints: nothing`).
 * `ssh` and `ssh-add` were probed on Ubuntu 26.04. Not vetted: `psql` and
 * `pg_restore` (printers, probed 2026-10-04), `pg_dump` (no file printed,
 * but a `--filter` file's well-formed patterns echo: not "probed not to
 * print"), `git` and `git-credential-store` (printers), the cloud CLIs
 * (`aws`, `gh`, `docker`, `kubectl`, `helm`: unprobed), every program that
 * runs code. Mirrored in dashboard/src/view-model/reader-runs-code.ts and
 * the guard's secret_open.rs (the ssh-agent socket's readers), pinned equal
 * by tests/stack/reader-identity.test.ts.
 */
export const VETTED_READERS: ReadonlySet<string> = new Set<string>(["ssh", "ssh-add"]);

/** Is this reader name (a bare name, a pin's `app` or `path`, an opener's
 *  executable) a vetted reader? Its basename exactly, or through a version
 *  or alternatives suffix (`appNameMatches`, `withoutVersion`: `psql16`
 *  stays unvetted, `ssh.openssh` is ssh), and never a printer or a program
 *  that runs code by any name rule. */
export function readerVetted(app: string): boolean {
  if (readerPrints(app) || readerRunsCode(app)) return false;
  const base = basenameOf(app);
  for (const name of VETTED_READERS) if (appNameMatches(base, name)) return true;
  return false;
}

/** A vetted program by its name or path (`readerVetted`), and no copy of a
 *  printer or of a program that runs code by its hash. */
export function binaryVetted(b: { exe?: string; app?: string; path?: string; sha256?: string }): boolean {
  if (binaryPrints(b) || binaryRunsCode(b)) return false;
  const name = b.exe ?? b.path ?? b.app;
  return name !== undefined && readerVetted(name);
}

/** Does this reader entry carry the human's word (`prints: nothing`, D8
 *  (11))? Never for an entry that admits nothing (a printer or a program
 *  that runs code, by name, path or hash; a script pin is the pair). */
export function entryVouches(entry: ReaderEntry): boolean {
  const pin = pinOf(entry);
  return pin.prints === "nothing" && !entryAdmitsNothing(pin);
}

/** Why a reader entry, as written, gives its program only the twin, or
 *  null: it names a program neither vetted nor vouched for (D8 (12)). An
 *  entry that admits nothing has its own reason (`entryAdmitsNothing`). */
export function entryReadsTwin(entry: ReaderEntry): boolean {
  const pin = pinOf(entry);
  if (entryAdmitsNothing(pin) || entryVouches(pin)) return false;
  if (pin.script !== undefined) return true;
  return !binaryVetted({ app: pin.app, ...(pin.path !== undefined ? { path: pin.path } : {}), ...(pin.sha256 !== undefined ? { sha256: pin.sha256 } : {}) });
}

/** A trailing version a distribution puts on a program's name, after a
 *  letter: `php8.5`, `lua5.4`, `tclsh8.6`, `ruby3.3`, `gcc-15`, `clang-18`
 *  (2026-10-04). `appNameMatches` takes only a suffix that starts with a
 *  dot (`python3.12`, `xz.alt`), so these were known only by their host
 *  hash. The name without it, or null. Mirrored in the dashboard and the
 *  guard (`without_version`). */
export function withoutVersion(name: string): string | null {
  const m = /^(.*[A-Za-z+])[-_]?\d+(?:\.\d+)*$/.exec(name);
  return m ? m[1]! : null;
}

/** A program's basename and the names it stands for under a distribution's
 *  prefix (`gnucat` → `cat`, `uu-env` → `env`) or without a trailing
 *  version (`php8.5` → `php`, `gnused4` → `sed`). */
function readerNameForms(base: string): string[] {
  // A prefix alone names no program (`gnu` is not `g` + `nu`).
  const forms = [base, ...READER_NAME_PREFIXES.filter((p) => !READER_NAME_PREFIXES.includes(base) && base.length > p.length && base.startsWith(p)).map((p) => base.slice(p.length))];
  return [...forms, ...forms.map(withoutVersion).filter((n): n is string => n !== null)];
}

/** Does this reader name (a bare name, a pin's `app` or its `path`, an
 *  opener's executable) print or copy a file's bytes (`PRINTER_READERS`,
 *  or a name under `PRINTER_NAME_PREFIXES`)?
 *  Matched as `readerRunsCode` matches, also under a distribution's prefix
 *  (`READER_NAME_PREFIXES`), and a path inside a multi-call binary's
 *  directory always is one. */
export function readerPrints(app: string): boolean {
  if (MULTICALL_PRINTER_DIRS.some((d) => app.startsWith(d))) return true;
  for (const n of readerNameForms(basenameOf(app))) {
    if (PRINTER_READERS.has(n) || printerPrefixed(n)) return true;
    for (const name of PRINTER_READERS) if (appNameMatches(n, name)) return true;
  }
  return false;
}

/** What a host program's hash says it is: a printer (`PRINTER_READERS`) or
 *  a program that runs code it is given (`CODE_RUNNING_READERS`). */
export type HostProgramKind = "prints" | "runsCode";

/** The sha256 of every printer and every code-running program on this host
 *  (`program-hashes.ts` scans the system bin directories for `readerPrints`
 *  and `readerRunsCode` names, the multi-call binaries included), each with
 *  the name it was found under (`python3.12`, `cat`), set by the arbiter at
 *  start and on its periodic re-scan. Only ever added to while the arbiter
 *  runs (a program updated in place keeps its old hash here). */
const HOST_PROGRAM_HASHES: Record<HostProgramKind, Map<string, string>> = { prints: new Map(), runsCode: new Map() };

/** Add host programs' hashes (hex, any case), each alone or as `[sha256,
 *  name]`; the first name seen for a hash is kept. */
export function addHostProgramHashes(kind: HostProgramKind, hashes: Iterable<string | readonly [string, string]>): void {
  for (const h of hashes) {
    const [sha, name] = typeof h === "string" ? [h, ""] : h;
    const k = sha.toLowerCase();
    if (SHA256_HEX.test(k) && !HOST_PROGRAM_HASHES[kind].has(k)) HOST_PROGRAM_HASHES[kind].set(k, name);
  }
}

/** Add host printers' hashes (`addHostProgramHashes("prints", …)`). */
export function addPrinterHashes(hashes: Iterable<string | readonly [string, string]>): void {
  addHostProgramHashes("prints", hashes);
}

/** Add host code-running programs' hashes (`addHostProgramHashes("runsCode", …)`). */
export function addCodeRunnerHashes(hashes: Iterable<string | readonly [string, string]>): void {
  addHostProgramHashes("runsCode", hashes);
}

/** For tests: forget every host program hash, printers' and code runners'. */
export function clearHostProgramHashesForTest(): void {
  HOST_PROGRAM_HASHES.prints.clear();
  HOST_PROGRAM_HASHES.runsCode.clear();
}

/** For tests: `clearHostProgramHashesForTest`, by the name !451's tests use. */
export const clearPrinterHashesForTest = clearHostProgramHashesForTest;

/** The installed program a hash is byte for byte (`python3.12`, `cat`), of
 *  the kind asked, or undefined: the name the host scan found it under (""
 *  when it was added without one). */
export function hostProgramOf(kind: HostProgramKind, sha256: string | undefined): string | undefined {
  return sha256 === undefined ? undefined : HOST_PROGRAM_HASHES[kind].get(sha256.toLowerCase());
}

/** Plan 13 D8, the !437 leftover (2) (2026-10-03): is this binary, by its
 *  content hash, a copy of a printer on this host, whatever its name or
 *  place? A copy of GNU cat the human pins as `{ app: mytool, path, sha256
 *  }` is cat, and admits nothing like cat. Not covered, stated: a printer
 *  that is not byte-identical to one installed here (another version, a
 *  build of its own) and a script that prints. */
export function hashPrints(sha256: string | undefined): boolean {
  return hostProgramOf("prints", sha256) !== undefined;
}

/** A printer by its name or path (`readerPrints`) or by its content
 *  (`hashPrints`): an opener as the guard reports it, or a reader pin. */
export function binaryPrints(b: { exe?: string; app?: string; path?: string; sha256?: string }): boolean {
  return (b.exe !== undefined && readerPrints(b.exe)) || (b.app !== undefined && readerPrints(b.app))
    || (b.path !== undefined && readerPrints(b.path)) || hashPrints(b.sha256);
}

/** Plan 13 §8 decision (b) by content (2026-10-03): is this binary, by its
 *  hash, a copy of a program on this host that runs code it is given (a
 *  shell, an interpreter, a launcher, an editor: `CODE_RUNNING_READERS`),
 *  whatever its name or place? The human's `cp /usr/bin/python3
 *  ~/bin/mytool`, pinned as `{ app: mytool, path, sha256 }`, is python3 and
 *  admits nothing, like python3 named alone. Not covered, stated: such a
 *  program that is not byte-identical to one installed here (another
 *  version, a build of its own, a static download). */
export function hashRunsCode(sha256: string | undefined): boolean {
  return hostProgramOf("runsCode", sha256) !== undefined;
}

/** A program that runs code it is given, by its name or path
 *  (`readerRunsCode`) or by its content (`hashRunsCode`): an opener as the
 *  guard reports it, or a reader pin. */
export function binaryRunsCode(b: { exe?: string; app?: string; path?: string; sha256?: string }): boolean {
  return (b.exe !== undefined && readerRunsCode(b.exe)) || (b.app !== undefined && readerRunsCode(b.app))
    || (b.path !== undefined && readerRunsCode(b.path)) || hashRunsCode(b.sha256);
}

/** The installed program a binary is a renamed copy of, by its hash, when
 *  its own name and path do not already say what it is (`{ app: mytool,
 *  sha256: <python3's> }` → runsCode, `python3.12`), or null. The refusal,
 *  `mandu why` and the policy warnings name it. Pure over the scan. */
export function renamedCopyOf(b: { exe?: string; app?: string; path?: string; sha256?: string }): { kind: HostProgramKind; of: string } | null {
  const named = (f: (n: string) => boolean): boolean => (b.exe !== undefined && f(b.exe)) || (b.app !== undefined && f(b.app)) || (b.path !== undefined && f(b.path));
  if (named(readerPrints)) return null;
  const p = hostProgramOf("prints", b.sha256);
  if (p !== undefined) return { kind: "prints", of: p || "a printer" };
  if (named(readerRunsCode)) return null;
  const r = hostProgramOf("runsCode", b.sha256);
  return r !== undefined ? { kind: "runsCode", of: r || "a program that runs code" } : null;
}

/** Plan 13 R5: the interpreters whose script a reader entry may pin, by
 *  family. Ruby is not one: its user gem directory (under $HOME, the
 *  agent's to write) loads code with no flag to turn it off. */
const SCRIPT_FAMILIES: ReadonlyArray<{ family: string; names: readonly string[] }> = [
  { family: "python", names: ["python", "python2", "python3", "pypy", "pypy3"] },
  { family: "node", names: ["node", "nodejs"] },
  { family: "shell", names: ["sh", "bash", "dash", "ash", "ksh", "mksh", "zsh"] },
  { family: "perl", names: ["perl"] },
];

/** The R5 family of a reader name (`python3` → python), or null when the
 *  program cannot carry a `script:` pin. */
export function scriptInterpreterFamily(app: string): string | null {
  const base = basenameOf(app);
  for (const f of SCRIPT_FAMILIES) if (f.names.some((n) => appNameMatches(base, n))) return f.family;
  return null;
}

/** Plan 13 R5: why the guard's script facts do not let `opener` be the
 *  `(interpreter, script)` pair `pin` names, or null when they do (the
 *  interpreter's own identity is matchReader's). Each fact absent counts
 *  against the opener. Pure. */
export function scriptFactsProblem(pin: ReaderPin, opener: OpenerFacts): string | null {
  if (pin.script === undefined) return null;
  const f = opener.script;
  if (f === undefined) return opener.scriptProblem ? `it runs no script that can be pinned: ${opener.scriptProblem}` : "the guard reported no script for it";
  if (f.path !== pin.script) return `it runs ${f.path}, not ${pin.script}`;
  if (f.system !== true) return `${f.path} (or a directory above it) is a file the agent can write`;
  if (f.isolated !== true) return "the interpreter may load per-user code the agent can write (run python with -I or -s, node with --no-global-search-paths, zsh with -f)";
  if (f.traced !== false) return "another process traces it, and can change the code it runs";
  if (typeof f.sha256 !== "string" || !SHA256_HEX.test(f.sha256)) return `the hash of ${f.path} could not be read`;
  if (pin.scriptSha256 !== undefined && pin.scriptSha256 !== f.sha256) return `${f.path} changed since it was pinned`;
  return null;
}

/**
 * Plan 13 §8, decision (b) (2026-10-02): a program that runs code it is
 * given (`readerRunsCode`: a shell, an interpreter, a launcher) is a reader
 * only as an `(interpreter, script)` pair whose script R5's checks pin. Why
 * this opener is no reader on those grounds (inline code, a module, stdin,
 * an agent-writable or relative script, no isolation, a trace, a program
 * whose script cannot be pinned), or null when it is not such a program or
 * it runs a script every check passes. No entry and no answer in the Inbox
 * makes such an opener a reader: the code it runs is the agent's to choose,
 * so the human would be approving code nobody showed them. Pure.
 */
export function inlineCodeProblem(opener: OpenerFacts): string | null {
  const byArgs = argsCodeProblem(opener);
  if (byArgs !== null) return byArgs;
  const base = basenameOf(opener.exe);
  if (!openerRunsCode(opener)) return null;
  // A renamed copy of an interpreter (its hash, `hashRunsCode`) carries no
  // script pin: an entry's script grammar is its interpreter's name.
  const copy = renamedCopyOf({ exe: opener.exe, ...(opener.sha256 !== undefined ? { sha256: opener.sha256 } : {}) });
  if (copy !== null) return `${base} is a copy of ${copy.of} (byte for byte a program on this host that runs code it is given), and a renamed copy's script cannot be pinned`;
  if (scriptInterpreterFamily(base) === null) return `${base} runs code it is given, and no script of it can be pinned`;
  if (opener.script === undefined) return opener.scriptProblem ? `it runs no script that can be pinned: ${opener.scriptProblem}` : "the guard reported no script for it";
  return scriptFactsProblem({ app: base, script: opener.script.path }, opener);
}

/** Plan 13 §8, decision (b): a reader entry that names a program running
 *  code it is given and pins no script (`readers: [bash]`, `{ app: python3,
 *  path, sha256 }`) admits no opener at all: the pin names the interpreter,
 *  not the program. Pure. */
export function entryAdmitsNothing(entry: ReaderEntry): boolean {
  const pin = pinOf(entry);
  // Plan 13 D8, printers admit nothing (2026-10-03): a printer by its name
  // or its pinned path admits nothing in any form, a pin by path and hash
  // and a `script:` entry included (no printer has a script grammar); and
  // (the !437 leftover (2)) a pin whose hash is a host printer's, whatever
  // its `app:` name or path (`hashPrints`).
  if (binaryPrints(pin)) return true;
  // Plan 13 §8 decision (b) by content (2026-10-03): a pin whose hash is a
  // host program that runs code (`hashRunsCode`: python3 copied as mytool)
  // is that program, and admits nothing without a script pin; with one, a
  // renamed copy still admits nothing (a script pin's interpreter is named
  // by its `app:`, which a renamed copy does not carry: `matchReader`).
  // A script named as a printer (`…/git-credential-netrc`, 2026-10-07) is
  // one, whatever interpreter runs it.
  if (pin.script !== undefined) return scriptPrints(pin.script) || renamedCopyOf(pin)?.kind === "runsCode";
  return binaryRunsCode(pin);
}

/** Plan 13 R5: the guard's `script` facts off the wire, or undefined when
 *  absent or malformed (each field of the wrong type counts as absent, and
 *  an absent fact counts against the opener). Pure. */
export function parseScriptFacts(v: unknown): ScriptFacts | undefined {
  if (v === null || typeof v !== "object") return undefined;
  const o = v as Record<string, unknown>;
  if (typeof o.path !== "string" || !o.path.startsWith("/")) return undefined;
  if (typeof o.system !== "boolean" || typeof o.isolated !== "boolean" || typeof o.traced !== "boolean") return undefined;
  return {
    path: o.path,
    ...(typeof o.sha256 === "string" ? { sha256: o.sha256.toLowerCase() } : {}),
    system: o.system, isolated: o.isolated, traced: o.traced,
  };
}

export function pinOf(entry: ReaderEntry): ReaderPin {
  return typeof entry === "string" ? { app: entry } : entry;
}

/** Does an executable's basename name this program? Exactly, or the file a
 *  name resolves to through a version or an alternatives link (`python3` names
 *  `python3.12`, `nc` names `nc.openbsd`). The suffix needs a leading dot and
 *  only letters and digits, so `ssh` never names `ssh2` and `python3` never
 *  names `python3.12-config`. A name is a convenience, not the boundary: the
 *  first-use pin (path and hash) is. */
export function appNameMatches(base: string, name: string): boolean {
  return base === name || (base.startsWith(name) && /^(\.[A-Za-z0-9]+)+$/.test(base.slice(name.length)));
}

/** Does this opener match a reader entry? A pin needs path AND hash to agree
 *  (a rebuilt binary misses and must be re-approved); a bare name matches the
 *  executable's basename and asks to be pinned (the caller decides whether
 *  the binary may be pinned: `decideOpen`, Plan 13 D8). A `from:` condition
 *  counts only under a TRUSTED ancestor of that name: a basename is the
 *  program's choice, so a copy of sh named git is not git. A pin that
 *  matches wins over a bare name listed before it (Plan 13 D3: a bare
 *  `{ app: psql, output: clear }` kept for the system copy beside a pin the
 *  human approved for another binary of that name). */
export function matchReader(readers: readonly ReaderEntry[], opener: OpenerFacts): { pin: ReaderPin; pinNeeded: boolean; scriptPinNeeded?: boolean } | null {
  const base = basenameOf(opener.exe);
  // Plan 13 D8, printers admit nothing (2026-10-03): no entry names a
  // printer, whatever its form, nor a copy of one under another name, nor a
  // program of a printers' or launchers' package by its content (P0 item
  // 14), nor an interpreter running a script a printer's name names (a git
  // credential helper, P0 3b).
  if (openerPrints(opener) || scriptPrints(opener.script?.path)) return null;
  // Plan 13 §8 decision (b): an opener that runs code it is given is named
  // only by an entry that pins its script; a renamed copy of one (its
  // hash) is one (2026-10-03).
  const runsCode = openerRunsCode(opener);
  let byName: ReaderPin | null = null;
  let scriptByName: ReaderPin | null = null;
  for (const e of readers) {
    const pin = pinOf(e);
    if (pin.script === undefined && (runsCode || entryAdmitsNothing(pin))) continue;
    if (pin.script !== undefined && scriptPrints(pin.script)) continue;
    // A lineage-conditional reader matches only under its parent app.
    if (pin.from !== undefined && !(opener.ancestors ?? []).some((a) => a.trusted === true && appNameMatches(basenameOf(a.exe), pin.from!))) continue;
    // Plan 13 R5: an entry naming a script matches only the pair, on the
    // guard's facts; its script hash is pinned on first use (the file is
    // out of the agent's reach, or the facts would not pass).
    if (pin.script !== undefined && (scriptInterpreterFamily(pin.app) === null || scriptFactsProblem(pin, opener) !== null)) continue;
    const scriptPinNeeded = pin.script !== undefined && pin.scriptSha256 === undefined;
    if (pin.path !== undefined || pin.sha256 !== undefined) {
      if (pin.path !== undefined && pin.path !== opener.exe) continue;
      if (pin.sha256 !== undefined && pin.sha256 !== opener.sha256) continue;
      return { pin, pinNeeded: false, ...(scriptPinNeeded ? { scriptPinNeeded } : {}) };
    }
    if (!appNameMatches(base, pin.app)) continue;
    // A script entry, by the interpreter's name, beats a bare name.
    if (pin.script !== undefined) { if (scriptByName === null) scriptByName = pin; }
    else if (byName === null) byName = pin;
  }
  if (scriptByName) return { pin: scriptByName, pinNeeded: true, ...(scriptByName.scriptSha256 === undefined ? { scriptPinNeeded: true } : {}) };
  return byName ? { pin: byName, pinNeeded: true } : null;
}

/**
 * Plan 10 §11.2 with Plan 13 D3: the reader list after `pin` is written for
 * the binary that just read the file, or null when it is already there. The
 * entry that matched (a bare name, or a `{ app, from? }` without a pin) is
 * replaced by the pin, which keeps its `from:`. Its `output:` (and `mask:`)
 * goes with the pin only to a binary out of the agent's reach (`system`, the
 * first-use pin of D8): a binary the human approved from a place the agent
 * can write was promised a masked output (the Inbox row says so), so the pin
 * is appended without it and the entry stays for the system copy. Pure.
 */
export function withPinnedReader(readers: readonly ReaderEntry[], pin: ReaderPin, opts: { system: boolean }): ReaderEntry[] | null {
  const out = [...readers];
  if (pin.script !== undefined) return withPinnedScript(out, pin, opts);
  const sameAt = out.findIndex((r) => typeof r !== "string" && r.script === undefined && r.app === pin.app && r.path === pin.path && r.from === pin.from);
  if (sameAt >= 0) {
    // Plan 13 D8 (12): an *Always allow* on the warning question adds the
    // human's word to a pin already there.
    const same = out[sameAt] as ReaderPin;
    if (pin.prints !== "nothing" || same.prints === "nothing") return null;
    out[sameAt] = { ...same, prints: "nothing" };
    return out;
  }
  const bareAt = out.findIndex((r) => (typeof r === "string" && r === pin.app && pin.from === undefined)
    || (typeof r !== "string" && r.script === undefined && r.app === pin.app && r.path === undefined && r.sha256 === undefined && r.from === pin.from));
  // The human's word goes with the pin: the one the answer carries, or the
  // one the human wrote on the bare name that matched (D8 (12)).
  const id: ReaderPin = { app: pin.app, ...(pin.path !== undefined ? { path: pin.path } : {}), ...(pin.sha256 !== undefined ? { sha256: pin.sha256 } : {}), ...(pin.from !== undefined ? { from: pin.from } : {}), ...(pin.prints === "nothing" ? { prints: "nothing" as const } : {}) };
  if (bareAt < 0) { out.push(id); return out; }
  const bare = pinOf(out[bareAt]!);
  // The pin that replaces the entry keeps the word the human wrote on it.
  const kept: ReaderPin = bare.prints === "nothing" ? { ...id, prints: "nothing" } : id;
  const carries = bare.output !== undefined && bare.output !== "secret";
  if (!carries) { out[bareAt] = kept; return out; }
  if (!opts.system) { out.push(id); return out; }
  out[bareAt] = { ...kept, output: bare.output!, ...(bare.mask ? { mask: [...bare.mask] } : {}) };
  return out;
}

/** Plan 13 R5: `withPinnedReader` for an `(interpreter, script)` pin: the
 *  script entry that matched (same app, script and `from:`, whatever of its
 *  interpreter and script hash is pinned agreeing) takes the interpreter's
 *  path and hash and the script's hash. Its `output:` stays when the
 *  interpreter is out of the agent's reach (`system`) or the human had
 *  pinned it already (the script is always out of reach: the facts would
 *  not pass otherwise); else the pin is appended without it and the entry
 *  stays. */
function withPinnedScript(out: ReaderEntry[], pin: ReaderPin, opts: { system: boolean }): ReaderEntry[] | null {
  const same = (r: ReaderPin) => r.app === pin.app && r.script === pin.script && r.from === pin.from;
  const exactAt = out.findIndex((r) => typeof r !== "string" && same(r) && r.path === pin.path && r.sha256 === pin.sha256 && r.scriptSha256 === pin.scriptSha256);
  if (exactAt >= 0) {
    const exact = out[exactAt] as ReaderPin;
    if (pin.prints !== "nothing" || exact.prints === "nothing") return null;
    out[exactAt] = { ...exact, prints: "nothing" };
    return out;
  }
  const at = out.findIndex((r) => typeof r !== "string" && same(r)
    && (r.path === undefined || r.path === pin.path) && (r.sha256 === undefined || r.sha256 === pin.sha256)
    && (r.scriptSha256 === undefined || r.scriptSha256 === pin.scriptSha256));
  const id: ReaderPin = {
    app: pin.app,
    ...(pin.path !== undefined ? { path: pin.path } : {}),
    ...(pin.sha256 !== undefined ? { sha256: pin.sha256 } : {}),
    ...(pin.from !== undefined ? { from: pin.from } : {}),
    script: pin.script!,
    ...(pin.scriptSha256 !== undefined ? { scriptSha256: pin.scriptSha256 } : {}),
    ...(pin.prints === "nothing" ? { prints: "nothing" as const } : {}),
  };
  if (at < 0) { out.push(id); return out; }
  const entry = pinOf(out[at]!);
  // The pin that replaces the entry keeps the word the human wrote on it.
  const kept: ReaderPin = entry.prints === "nothing" ? { ...id, prints: "nothing" } : id;
  const carries = entry.output !== undefined && entry.output !== "secret";
  if (!carries) { out[at] = kept; return out; }
  const humanPinned = entry.path !== undefined && entry.sha256 !== undefined;
  if (!opts.system && !humanPinned) { out.push(id); return out; }
  out[at] = { ...kept, output: entry.output!, ...(entry.mask ? { mask: [...entry.mask] } : {}) };
  return out;
}

/** Can the wire release serve a program (plan 10 §11.5,
 *  docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md §10)? `served`: the program speaks HTTPS
 *  through the session's egress proxy and trusts its CA, so a placeholder it
 *  sends is put back at a bound host and a twin would do. Otherwise `why` says
 *  what stops it, and the program must hold the bytes as a reader. */
export interface WireRelease {
  served: boolean;
  why: string;
}

/** The consumer table (§11.3): a secret file's canonical programs. Every entry
 *  is rule (i); the prompt of §11.1 fires for these and no others. Keyed by
 *  the file's shape or basename. `wire` is the TLS compatibility matrix's
 *  verdict for these programs. */
export const CONSUMER_TABLE: ReadonlyArray<{ test: (path: string) => boolean; apps: readonly string[]; wire: WireRelease }> = [
  { test: (p) => basenameOf(p) === ".pgpass", apps: ["psql", "pg_dump", "pg_restore"],
    wire: { served: false, why: "the Postgres wire protocol, not HTTP: the egress proxy never sees the password" } },
  { test: (p) => /\/\.aws\/(credentials|config)$/.test(p), apps: ["aws"],
    wire: { served: false, why: "SigV4 signs each request with the secret key: a placeholder cannot be put back after signing" } },
  { test: (p) => /\/\.config\/gh\/hosts\.yml$/.test(p), apps: ["gh"],
    wire: { served: true, why: "Go: honors HTTPS_PROXY and SSL_CERT_FILE; a bearer token in a header" } },
  { test: (p) => basenameOf(p) === ".npmrc", apps: ["npm", "yarn", "pnpm", "node"],
    wire: { served: true, why: "Node: NODE_EXTRA_CA_CERTS and NODE_USE_ENV_PROXY; a bearer token in a header" } },
  { test: (p) => /\/\.docker\/config\.json$/.test(p), apps: ["docker"],
    wire: { served: false, why: "the Docker daemon, outside the session, makes the registry requests" } },
  { test: (p) => /\/\.kube\/config$/.test(p), apps: ["kubectl", "helm"],
    wire: { served: false, why: "trusts only the cluster CA in the kubeconfig, so it refuses the inspection certificate" } },
  { test: (p) => /\/\.ssh\/id_[a-z0-9]+$/.test(p), apps: ["ssh", "git", "scp", "ssh-add"],
    wire: { served: false, why: "SSH: the key signs the handshake, and SSH is not HTTP" } },
  // git's opener of `.netrc` is its HTTP transport, `git-remote-http(s)`
  // (libcurl's netrc option), never `git` itself (2026-10-04, plan 13 D8
  // (11)), and for a dumb-HTTP fetch and a WebDAV push the programs it
  // starts, `git-http-fetch` and `git-http-push` (2026-10-07); all are
  // printers, served the wire release's twin. `git-imap-send` reads it too,
  // but speaks IMAP, which the wire release does not serve
  { test: (p) => basenameOf(p) === ".netrc" || basenameOf(p) === "_netrc", apps: ["curl", "git", "git-remote-http", "git-remote-https", "git-http-fetch", "git-http-push"],
    wire: { served: true, why: "curl and git: CURL_CA_BUNDLE / GIT_SSL_CAINFO; basic auth in a header" } },
  // git's `store` credential helper (2026-10-02, plan 10 §11.13): the helper
  // is git itself (`git credential-store`, a builtin; some packages also
  // ship it under its own name). Both are printers since 2026-10-04 (plan
  // 13 §4.9 option (a)): served the twin under the wire release, else what
  // a non-reader gets, so without TLS inspection the twin's symbol for the
  // password fails the login.
  { test: (p) => basenameOf(p) === ".git-credentials" || /\/git\/credentials$/.test(p), apps: ["git", "git-credential-store"],
    wire: { served: true, why: "git: GIT_SSL_CAINFO; basic auth in a header" } },
  { test: (p) => basenameOf(p) === ".pypirc", apps: ["twine"],
    wire: { served: true, why: "Python requests: REQUESTS_CA_BUNDLE; basic auth in a header" } },
  { test: (p) => /\/\.cargo\/credentials(\.toml)?$/.test(p), apps: ["cargo"],
    wire: { served: true, why: "cargo: CARGO_HTTP_CAINFO (its libcurl ignores SSL_CERT_FILE); a token in a header" } },
];

/** Rows added by signed consumer packs (consumer-packs.ts), set once by the
 *  arbiter at start. Consulted AFTER the built-in table: a pack adds, it can
 *  never override a built-in row. */
let PACK_ROWS: ReadonlyArray<{ test: (path: string) => boolean; apps: readonly string[]; wire: WireRelease | null }> = [];

export function setPackConsumers(rows: ReadonlyArray<{ basename?: string; pathSuffix?: string; apps: string[]; wire?: WireRelease }>): void {
  PACK_ROWS = rows.map((r) => ({
    test: (p: string) => (r.basename !== undefined && basenameOf(p) === r.basename) || (r.pathSuffix !== undefined && p.endsWith(r.pathSuffix)),
    apps: [...r.apps],
    wire: r.wire ?? null,
  }));
}

/** The wire-release verdict for a secret file's known consumers, or null when
 *  the file has none. */
export function consumerWireRelease(path: string): WireRelease | null {
  for (const row of CONSUMER_TABLE) if (row.test(path)) return row.wire;
  for (const row of PACK_ROWS) if (row.test(path)) return row.wire;
  return null;
}

export function knownConsumers(path: string): readonly string[] {
  for (const row of CONSUMER_TABLE) if (row.test(path)) return row.apps;
  for (const row of PACK_ROWS) if (row.test(path)) return row.apps;
  return [];
}

/**
 * The open decision (§3.3, §3.5, §11.1, §11.3). Order: the agent process →
 * twin; an integrity-tainted lineage → deny; a known consumer of a file
 * whose twin works over the wire (`wireTwin`, §11.13.1; not under `ask:
 * always`) → the twin, listed or not; no reader list → a KNOWN
 * consumer of the file (the consumer table, §11.3) reads raw as a default
 * reader (pinned on first use), anyone else gets the twin (or `ask`
 * under `ask: always`); a listed reader → raw; anyone else → `ask` under
 * `ask: always`, else the twin under an explicit `others: twin` (§11.13.1:
 * it wins over the known-consumer prompt), else `ask` under `ask: known` for
 * a known consumer, else deny.
 *
 * Plan 13 D8, after the wire twin: an opener whose loader environment is
 * unchecked or set by someone other than the launch (`loaderEnvProblem`) is
 * no reader and never prompts (the human would be approving the agent's
 * code): the twin where non-readers get it, else deny. A first-use pin (a
 * bare name, a `from:`-only entry, a known consumer) is taken only from a
 * binary out of the agent's reach (`exeSystem`); any other binary of that
 * name asks the human under `ask: known` / `always` (the answer pins it by
 * path and hash) and is a non-reader under `never`. A full pin (path and
 * hash) the human wrote or approved needs neither.
 */
export function decideOpen(path: string, file: FilePolicy, opener: OpenerFacts, opts: DecideOpenOptions = {}): OpenDecision {
  if (opener.isAgent) return { verdict: "twin", why: "the agent's own process always reads the twin" };
  if (opener.integrityTainted) return { verdict: "deny", why: "untrusted-lineage process: never a reader (§3.5)" };
  const ask = opts.ask ?? (opts.askKnownConsumers ? "known" : "never");
  const base = basenameOf(opener.exe);
  // Plan 13 D8, printers admit nothing (the maintainer's decision of
  // 2026-10-03): a program that prints or copies a file's bytes hands them
  // to whatever reads its output, which can be the agent's code, whose
  // metadata exits (§4.9) are not followed. It gets what a non-reader of
  // the file gets, listed or not, a known consumer's row or not, and is
  // never prompted for (an answer would put the agent's downstream code
  // behind the human's Allow).
  // A copy of a printer under another name is one (`hashPrints`, the !437
  // leftover (2)). A consumer-table printer (curl for `.netrc`) still gets
  // the twin the wire release serves it, listed or not (a twin holds no
  // secret byte).
  // A program of a package of printers or launchers, by its content (the
  // guard's `pkg:` finding: a non-identical GNU env renamed), is one too
  // (P0 item 14, plan 13 D8 (13)).
  const known = knownConsumers(path).includes(base);
  const printingScript = scriptPrints(opener.script?.path) ? basenameOf(opener.script!.path) : null;
  if (openerPrints(opener) || printingScript !== null) {
    const why = printingScript !== null
      ? `${base} running ${printingScript} prints what it reads (a git credential helper prints the password on get), so it never gets the real file (plan 13 D8, printers admit nothing)`
      : printerWhy(opener);
    return !file.readers || file.others === "twin" || (known && opts.wireTwin !== undefined) ? { verdict: "twin", why } : { verdict: "deny", why };
  }
  if (known && ask !== "always" && opts.wireTwin) {
    // §11.13.1: the consumer needs no raw byte; it sends the symbol and the
    // session proxy puts the value back at its bound registry. No taint.
    // Also when it is LISTED: the first raw read of a default reader writes
    // its pin into the list (§11.2), so on any host where npm ran once the
    // list names node, and a human's `readers: [node]` reads the same. A twin
    // is never less confidential than the raw file; the launch-level opt-out
    // (MANDU_WIRE_TWIN=0) restores the raw read.
    return { verdict: "twin", why: `${base} is a known consumer of ${basenameOf(path)}, served its twin: ${opts.wireTwin.why}` };
  }
  const envProblem = loaderEnvProblem(opener);
  if (envProblem !== null) {
    const why = `${opener.exe} is not the program its name or pin says: ${envProblem}`;
    return !file.readers || file.others === "twin" ? { verdict: "twin", why } : { verdict: "deny", why };
  }
  // Plan 13 D8, code by argument: an invocation whose command line or
  // environment hands it code is the agent's program, never a reader, and
  // never prompted for (the human would approve code nobody showed them).
  // A renamed copy of a program that runs code (its hash) has no script
  // form; said first, as what it is, also when the guard's content finding
  // (`runs:`) says the same of it.
  const copy = renamedCopyOf({ exe: opener.exe, ...(opener.sha256 !== undefined ? { sha256: opener.sha256 } : {}) });
  const copyWhy = copy?.kind === "runsCode"
    ? `${base} is a copy of ${copy.of}, a program that runs code it is given (byte for byte one on this host), so it never gets the real file (plan 13 §8 decision (b))`
    : null;
  const argsProblem = argsCodeProblem(opener);
  if (argsProblem !== null) {
    const why = copyWhy ?? `${base} is not the program a human could name: ${argsProblem}`;
    return !file.readers || file.others === "twin" ? { verdict: "twin", why } : { verdict: "deny", why };
  }
  // Plan 13 §8 decision (b): inline code (or any code no script pin can
  // name) is no reader and is never prompted for, whatever the list says.
  const codeProblem = inlineCodeProblem(opener);
  if (codeProblem !== null) {
    const why = copyWhy ?? `${base} runs code it is given and reads a secret only as a pinned script ({ app: ${base}, script: /absolute/path }): ${codeProblem}`;
    return !file.readers || file.others === "twin" ? { verdict: "twin", why } : { verdict: "deny", why };
  }
  // A first-use pin needs a binary the agent cannot have written.
  const reachable = opener.exeSystem !== true;
  const unpinnable = `${opener.exe} is in a place the agent can write, so it is not pinned without you`;
  // Plan 13 D8 (12), the allow-list (2026-10-04): raw bytes only to a
  // vetted reader, or to a program its entry vouches for (`prints:
  // nothing`); every other program gets the twin, and is asked about with
  // the warning (`unvetted`, the `trust:` question).
  const vetted = binaryVetted(opener);
  const notVetted = `${base} is not a program Mandu knows keeps a file's contents out of what it prints (plan 13 D8 (12))`;
  if (!file.readers) {
    if (known && ask !== "always") {
      if (!vetted) {
        return ask === "known" ? { verdict: "ask", unvetted: true, why: `${base} is a known consumer of ${basenameOf(path)}, but ${notVetted}` } : { verdict: "twin", why: `${notVetted}: it reads the twin` };
      }
      if (reachable) {
        return ask === "known" ? { verdict: "ask", why: `${base} is a known consumer of ${basenameOf(path)}, but ${unpinnable}` } : { verdict: "twin", why: unpinnable };
      }
      return { verdict: "raw", reader: { app: base }, pinNeeded: true, why: `${base} is a known consumer of ${basenameOf(path)} (consumer table, §11.3), vetted: a default reader` };
    }
    if (ask === "always") {
      return { verdict: "ask", ...(vetted ? {} : { unvetted: true }), why: `${base} opened ${basenameOf(path)} and prompting is on for every program` };
    }
    return { verdict: "twin", why: "no reader list: structured twin for every program" };
  }
  const m = matchReader(file.readers, opener);
  if (m && !vetted && !entryVouches(m.pin)) {
    // Listed, but neither vetted nor vouched for: the twin (the human named
    // it, the placeholders keep it working), or the warning question under
    // `ask: always`, whose *Always allow* writes the human's word.
    if (ask === "always") return { verdict: "ask", unvetted: true, why: `${m.pin.app} is a listed reader, but ${notVetted}` };
    return { verdict: "twin", why: `${notVetted}: it reads the twin. If you are sure it does, write { app: ${m.pin.app}, prints: nothing }` };
  }
  if (m && !(m.pinNeeded && reachable)) {
    const what = m.pin.script !== undefined ? `listed reader ${m.pin.app} running ${m.pin.script}` : `listed reader ${m.pin.app}`;
    return { verdict: "raw", reader: m.pin, pinNeeded: m.pinNeeded || m.scriptPinNeeded === true, why: vetted ? `${what} (vetted)` : `${what} (prints: nothing)` };
  }
  if (m && ask !== "never") return { verdict: "ask", ...(vetted ? {} : { unvetted: true }), why: `${m.pin.app} is a listed reader, but ${unpinnable}` };
  if (ask === "always") {
    return { verdict: "ask", ...(vetted ? {} : { unvetted: true }), why: `${base} is not on the reader list` };
  }
  // §11.13.1: an explicit `others: twin` is the human's answer for every
  // program not on the list, so a known consumer is served the twin rather
  // than held for a prompt (a twin holds no secret byte). Only `always`,
  // the human's wish to be asked about every program, still prompts.
  if (file.others === "twin") return { verdict: "twin", why: "not a listed reader; others: twin" };
  if (ask === "known" && known) {
    return { verdict: "ask", ...(vetted ? {} : { unvetted: true }), why: `${base} is not on the reader list` };
  }
  return { verdict: "deny", why: "not a listed reader; a reader list is exhaustive (§3.3)" };
}

// ── output rules and the fold (§2.2, §3.2) ──────────────────────────────────

const RULE_RANK: Record<OutputRule, number> = { clear: 0, mask: 1, secret: 2 };

/** One taint row as the fold reads it (`SecretTaintRow`): the file, the
 *  opener's name, and, for a raw read the arbiter granted, the binary and
 *  how it was let in. */
export interface OutputRow {
  path: string;
  app: string;
  /** The opener's resolved executable, as the guard reported it. */
  exe?: string;
  /** sha256 of that executable, when the guard computed it. */
  sha256?: string;
  /** `reader`: the opener matched an entry of the file's reader list (or
   *  was a known consumer); `verdict`: a human let it in from the Inbox.
   *  Absent: unknown (a row written by hand, or before 2026-10-02). */
  via?: "reader" | "verdict" | "session";
  /** Plan 13 R5: the script the interpreter ran and its hash, recorded
   *  only when the guard's facts would let a `script:` entry match (out of
   *  reach, isolated, not traced). */
  script?: string;
  scriptSha256?: string;
  /** Plan 13 R5: the process started another program in the call's tree
   *  (a lineage child): a script's cleared output may then be that
   *  program's, found on a PATH the agent can write. */
  spawned?: boolean;
}

/** Does reader entry `p` name the binary of this row? A pin by path and
 *  hash must agree with the row's executable; a bare name matches its
 *  basename (`appNameMatches`). */
function entryNamesBinary(p: ReaderPin, row: OutputRow): boolean {
  if (p.path !== undefined || p.sha256 !== undefined) {
    if (row.exe === undefined) return false;
    if (p.path !== undefined && p.path !== row.exe) return false;
    if (p.sha256 !== undefined && p.sha256 !== row.sha256) return false;
    return true;
  }
  return appNameMatches(basenameOf(row.exe ?? row.app), p.app);
}

/** Plan 13 R5: does script entry `p` name this row's (interpreter, script)
 *  pair? */
function entryNamesScript(p: ReaderPin, row: OutputRow): boolean {
  return p.script !== undefined && row.script === p.script
    && (p.scriptSha256 === undefined || p.scriptSha256 === row.scriptSha256) && entryNamesBinary(p, row);
}

/** Plan 13 D3: why a reader entry may not carry `output: clear | mask`, or
 *  null. A program that runs code it is given (`readerRunsCode`: a shell, an
 *  interpreter, a launcher such as `find` or `awk`) prints whatever the
 *  agent's script makes it print. Stricter than `appRuleRefusal` (the
 *  interpreters alone), which the legacy `apps:` table keeps. */
export function readerOutputRefusal(app: string, output: OutputRule, script?: string): string | null {
  if (output === "secret" || !readerRunsCode(app)) return null;
  // Plan 13 R5: an interpreter pinned with the script it runs is that
  // program, and its output may be cleared like a leaf program's.
  if (script !== undefined && scriptInterpreterFamily(app) !== null) return null;
  return `${app} runs any code it is given (a shell, an interpreter or a launcher): a script the agent writes would make it print the file; only a leaf program's output may be clear or mask`;
}

/**
 * Plan 13 D3: what one taint row lets the model see of its process's output.
 * The rule is the one written on the reader entry of THAT file for THAT
 * binary (`readers: [{ app: psql, output: clear }]`); every other case is
 * `secret`:
 *   - the row was not granted through the reader list (`via` absent, or a
 *     human verdict from the Inbox, whose row promised a masked output);
 *   - the file has no reader list, or no entry names the binary (a pin by
 *     path and hash must be that executable, a bare name its basename);
 *   - the program runs code it is given (the runtime belt to the
 *     validator's `readerOutputRefusal`), unless the entry pins the script
 *     it runs (Plan 13 R5: the row's script and hash are that entry's, and
 *     the process started no other program, `spawned` false; unknown
 *     counts as started).
 * Several entries naming the binary fold to the strictest. The program-wide
 * `apps:` table is not read (deprecated 2026-10-02, plan 13 §8). The caller
 * folds the rows of a tree with `foldRules`, so a process holding two files
 * is released only when both clear it: the intersection, as for bindings
 * (D1). Pure.
 */
export function readerOutputRule(row: OutputRow, readers: readonly ReaderEntry[] | undefined): AppRule {
  const base = basenameOf(row.exe ?? row.app);
  const secret: AppRule = { app: base, output: "secret" };
  if (row.via !== "reader" || !readers) return secret;
  const pins = readers.map(pinOf);
  // Plan 13 R5: an entry naming this row's script speaks for it; else the
  // entries that name no script (a script entry for another script names
  // nothing here).
  const scripted = pins.filter((p) => entryNamesScript(p, row));
  const hits = scripted.length > 0 ? scripted : pins.filter((p) => p.script === undefined && entryNamesBinary(p, row));
  if (hits.length === 0) return secret;
  return foldRules(hits.map((p): AppRule => {
    const output = p.output ?? "secret";
    if (readerOutputRefusal(base, output, p.script) !== null || readerOutputRefusal(p.app, output, p.script) !== null) return secret;
    // A cleared script that started another program: what it printed may
    // be that program's (fail-closed).
    if (p.script !== undefined && output !== "secret" && row.spawned !== false) return secret;
    return output === "mask" ? { app: base, output, mask: [...(p.mask ?? [])] } : { app: base, output };
  }));
}

/** The strictest rule wins: secret > mask > clear. Masks of every `mask` rule
 *  in the tree are unioned when the fold lands on `mask`. */
export function foldRules(rules: readonly AppRule[]): AppRule {
  if (rules.length === 0) return { app: "", output: "secret" };
  let best = rules[0]!;
  for (const r of rules.slice(1)) if (RULE_RANK[r.output] > RULE_RANK[best.output]) best = r;
  if (best.output === "mask") {
    const masks = new Set<string>();
    for (const r of rules) if (r.output === "mask") for (const m of r.mask ?? []) masks.add(m);
    return { app: best.app, output: "mask", mask: [...masks] };
  }
  return { app: best.app, output: best.output };
}

/** The app names that may carry `clear` or `mask`: never an interpreter. */
export function appRuleRefusal(rule: AppRule): string | null {
  if (rule.output === "secret") return null;
  if (INTERPRETERS.has(basenameOf(rule.app))) {
    return `${rule.app} is an interpreter: an agent-authored script would read a secret and print it; only leaf programs may be clear or mask`;
  }
  return null;
}

/** Which file shapes the consumer table knows (for the dashboard's "known consumer" chip). */
export function hasKnownShape(path: string): boolean {
  return secretFileShape(path) !== null || knownConsumers(path).length > 0;
}

// ── confidentiality plan 13 D1: a holder's destinations are an INTERSECTION ──

/** Does binding `outer` admit every destination `inner` does? From the one
 *  binding rule (host-bindings.ts, confidentiality.md §2.2), which the gate
 *  and the net-proxy match by too. */
export { bindingCovers } from "./host-bindings.js";

/**
 * Plan 13 D1 (§4.2: the join of two labels is the intersection of their
 * release sets): the destinations a holder of several data may reach are the
 * ones EVERY datum's bindings admit. `perDatum` holds one binding list per
 * datum (per file until §5.2's `values:` exists); a datum bound nowhere
 * empties the result, and no datum at all gives nothing (an untainted holder
 * is never asked this). A binding survives when each list covers it
 * (`bindingCovers`), so `*.amazonaws.com` ∩ `s3.amazonaws.com` and
 * `example.com` ∩ `api.example.com` keep the narrower name. Sorted, deduplicated (two spellings of one host by case
 * collapse to the first seen). Pure.
 */
export function intersectBindings(perDatum: ReadonlyArray<readonly string[]>): string[] {
  if (perDatum.length === 0) return [];
  const sets = perDatum.map((s) => [...new Set(s.map((b) => b.trim()).filter((b) => b !== ""))]);
  const kept: string[] = [];
  const seen = new Set<string>();
  for (const set of sets) {
    for (const b of set) {
      const k = isPathBinding(b) ? b : b.toLowerCase();
      if (seen.has(k)) continue;
      if (sets.every((other) => other.some((c) => bindingCovers(c, b)))) {
        seen.add(k);
        kept.push(b);
      }
    }
  }
  return kept.sort();
}
