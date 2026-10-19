/**
 * host-runnable — does a program a test's scripted command names run on this
 * host? A static judgment, pure given its deps: the program as the shell
 * would find it on PATH, then whether the kernel can start it.
 *
 * Why (test-organization.md §8.12): a scripted tool call names a program by
 * its bare name (`base64 -d`, `python3 tool.py`), and the host's PATH decides
 * what runs. When that is a file the host cannot start, both sides of a
 * paired run fail the same way, and the checks then grade a broken tool, not
 * Mandu. The 2026-10-04 case was a dead pip entry point shadowing
 * /usr/bin/base64; the forms caught here are the ones a static look proves:
 *   - an ELF for another CPU (e_machine not the host's, no binfmt_misc
 *     handler for it): execve fails with ENOEXEC;
 *   - an ELF whose program interpreter (PT_INTERP: a musl or 32-bit loader)
 *     is not on the host: execve fails with ENOENT;
 *   - a `#!` script whose interpreter is gone (an absolute path that does not
 *     exist or is not executable), or whose `#!/usr/bin/env X` finds no X on
 *     PATH: the shell reports 126 or 127;
 * each followed through a `#!` chain (an interpreter that is itself a
 * script). What a static look cannot prove is left alone: a program that
 * starts and then fails (the pip entry point whose interpreter lacks its
 * module raised ModuleNotFoundError), a name not on PATH (the run reports
 * that itself), a shell builtin (no PATH lookup), a file that is neither
 * ELF nor `#!` (the shell runs it as a script).
 */
import { accessSync, constants, readdirSync, readFileSync, openSync, readSync, closeSync, statSync } from "node:fs";
import { basename, isAbsolute, join } from "node:path";

export interface RunnableDeps {
  /** Up to `n` bytes from the start of `p`, or null when it cannot be read. */
  readHead?: (p: string, n: number) => Uint8Array | null;
  /** Bytes [off, off+n) of `p`, or null (an ELF's interpreter string past the head). */
  readAt?: (p: string, off: number, n: number) => Uint8Array | null;
  /** Is `p` a regular file the caller may execute? */
  isExecFile?: (p: string) => boolean;
  /** Does `p` exist (any type)? */
  exists?: (p: string) => boolean;
  /** The PATH the run uses (default process.env.PATH). */
  path?: string;
  /** Node's arch name of the host (default process.arch). */
  arch?: string;
  /** The ELF machines an enabled binfmt_misc handler runs (qemu-user), default
   *  read from /proc/sys/fs/binfmt_misc. */
  foreignMachines?: () => ReadonlySet<number>;
}

/** Node arch → the ELF e_machine its kernel runs natively (native-targets.mjs
 *  NATIVE_TARGETS carries the shipped two). */
const HOST_MACHINE: Record<string, number> = { x64: 62, arm64: 183, ia32: 3, arm: 40, riscv64: 243, ppc64: 21, s390x: 22, loong64: 258, mips: 8, mipsel: 8 };
/** The 32-bit machine a 64-bit kernel also starts (its loader may be missing,
 *  which the PT_INTERP check then says). */
const COMPAT_MACHINE: Record<number, number[]> = { 62: [3], 183: [40], 21: [20] };
/** qemu-user's binfmt_misc handler names → e_machine. */
const QEMU_MACHINE: Record<string, number> = { x86_64: 62, aarch64: 183, i386: 3, arm: 40, riscv64: 243, ppc64: 21, ppc64le: 21, s390x: 22, loongarch64: 258, mips: 8, mipsel: 8 };
const MACHINE_NAME: Record<number, string> = { 3: "x86", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64", 22: "s390x", 40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V", 258: "LoongArch" };

/** bash's builtins and keywords that run without a PATH lookup. */
export const SHELL_BUILTINS: ReadonlySet<string> = new Set([
  ".", ":", "[", "alias", "bg", "bind", "break", "builtin", "caller", "cd", "command", "compgen", "complete", "continue",
  "declare", "dirs", "disown", "echo", "enable", "eval", "exec", "exit", "export", "false", "fc", "fg", "getopts", "hash",
  "help", "history", "jobs", "kill", "let", "local", "logout", "mapfile", "popd", "printf", "pushd", "pwd", "read",
  "readarray", "readonly", "return", "set", "shift", "shopt", "source", "suspend", "test", "times", "trap", "true", "type",
  "typeset", "ulimit", "umask", "unalias", "unset", "wait",
]);

function defaultReadAt(p: string, off: number, n: number): Uint8Array | null {
  let fd: number | null = null;
  try {
    fd = openSync(p, "r");
    const buf = Buffer.alloc(n);
    const got = readSync(fd, buf, 0, n, off);
    return buf.subarray(0, got);
  } catch { return null; } finally { if (fd !== null) try { closeSync(fd); } catch { /* closed */ } }
}

function defaultIsExecFile(p: string): boolean {
  try { if (!statSync(p).isFile()) return false; accessSync(p, constants.X_OK); return true; } catch { return false; }
}

function defaultExists(p: string): boolean {
  try { statSync(p); return true; } catch { return false; }
}

/** The machines qemu-user's enabled binfmt_misc handlers run on this host. */
export function binfmtForeignMachines(dir = "/proc/sys/fs/binfmt_misc"): ReadonlySet<number> {
  const out = new Set<number>();
  let names: string[] = [];
  try { names = readdirSync(dir); } catch { return out; }
  for (const n of names) {
    const m = /^qemu-(.+)$/.exec(n);
    const machine = m ? QEMU_MACHINE[m[1]!] : undefined;
    if (machine === undefined) continue;
    try { if (readFileSync(join(dir, n), "utf8").split("\n")[0]?.trim() === "enabled") out.add(machine); } catch { /* unreadable: not counted */ }
  }
  return out;
}

interface Resolved {
  readHead: (p: string, n: number) => Uint8Array | null;
  readAt: (p: string, off: number, n: number) => Uint8Array | null;
  isExecFile: (p: string) => boolean;
  exists: (p: string) => boolean;
  path: string;
  arch: string;
  foreign: () => ReadonlySet<number>;
}

function resolveDeps(d: RunnableDeps): Resolved {
  const readAt = d.readAt ?? defaultReadAt;
  let foreign: ReadonlySet<number> | null = null;
  return {
    readAt,
    readHead: d.readHead ?? ((p, n) => readAt(p, 0, n)),
    isExecFile: d.isExecFile ?? defaultIsExecFile,
    exists: d.exists ?? defaultExists,
    path: d.path ?? process.env["PATH"] ?? "",
    arch: d.arch ?? process.arch,
    foreign: () => (foreign ??= (d.foreignMachines ?? binfmtForeignMachines)()),
  };
}

/** Where the shell finds `name` on `path` (the first executable regular file),
 *  or null. A name with a slash is not looked up. */
export function resolveOnPath(name: string, deps: RunnableDeps = {}): string | null {
  if (name === "" || name.includes("/")) return null;
  const r = resolveDeps(deps);
  for (const dir of r.path.split(":")) {
    if (dir === "" || !isAbsolute(dir)) continue; // the cwd entry: the run's own, not the host's
    const p = join(dir, name);
    if (r.isExecFile(p)) return p;
  }
  return null;
}

/** The ELF facts the kernel acts on, or null when `head` is no ELF. */
export function elfFacts(head: Uint8Array): { machine: number; interp: { off: number; size: number } | null; interpInHead: string | null } | null {
  if (head.length < 20 || head[0] !== 0x7f || head[1] !== 0x45 || head[2] !== 0x4c || head[3] !== 0x46) return null;
  const is64 = head[4] === 2;
  const le = head[5] === 1;
  if ((head[4] !== 1 && head[4] !== 2) || (head[5] !== 1 && head[5] !== 2)) return null;
  const dv = new DataView(head.buffer, head.byteOffset, head.byteLength);
  const u16 = (o: number): number | null => (o + 2 <= head.length ? dv.getUint16(o, le) : null);
  const u32 = (o: number): number | null => (o + 4 <= head.length ? dv.getUint32(o, le) : null);
  const word = (o: number): number | null => {
    if (!is64) return u32(o);
    if (o + 8 > head.length) return null;
    const v = dv.getBigUint64(o, le);
    return v > BigInt(Number.MAX_SAFE_INTEGER) ? null : Number(v);
  };
  const machine = u16(18)!;
  const phoff = word(is64 ? 32 : 28);
  const phentsize = u16(is64 ? 54 : 42);
  const phnum = u16(is64 ? 56 : 44);
  let interp: { off: number; size: number } | null = null;
  if (phoff !== null && phentsize !== null && phnum !== null && phentsize > 0) {
    for (let i = 0; i < phnum; i++) {
      const at = phoff + i * phentsize;
      const type = u32(at);
      if (type === null) break; // the program headers run past the head: no judgment on the interpreter
      if (type !== 3) continue; // PT_INTERP
      const off = word(at + (is64 ? 8 : 4));
      const size = word(at + (is64 ? 32 : 16));
      if (off !== null && size !== null && size > 0 && size < 4096) interp = { off, size };
      break;
    }
  }
  let interpInHead: string | null = null;
  if (interp && interp.off + interp.size <= head.length) interpInHead = cString(head.subarray(interp.off, interp.off + interp.size));
  return { machine, interp, interpInHead };
}

function cString(b: Uint8Array): string {
  const end = b.indexOf(0);
  return Buffer.from(end === -1 ? b : b.subarray(0, end)).toString("latin1");
}

/** A `#!` line's interpreter and its one argument (Linux passes the rest of
 *  the line as one), or null when `head` does not start with `#!`. */
export function shebang(head: Uint8Array): { interp: string; arg: string } | null {
  if (head.length < 2 || head[0] !== 0x23 || head[1] !== 0x21) return null;
  const nl = head.indexOf(0x0a);
  const line = Buffer.from(head.subarray(2, nl === -1 ? head.length : nl)).toString("utf8").trim();
  const m = /^(\S+)\s*(.*)$/.exec(line);
  return m ? { interp: m[1]!, arg: m[2]!.trim() } : { interp: "", arg: "" };
}

/** The program `env`'s arguments run: past its options and assignments
 *  (`-S` splits the rest into words, as `env -S` does). */
export function envProgram(arg: string): string | null {
  const words = arg.split(/\s+/).filter(Boolean);
  for (let i = 0; i < words.length; i++) {
    const w = words[i]!;
    if (w === "-S" || w === "--split-string") continue;
    if (w.startsWith("-S")) { words.splice(i + 1, 0, ...w.slice(2).split(/\s+/).filter(Boolean)); continue; }
    if (w === "-u" || w === "--unset" || w === "-C" || w === "--chdir") { i++; continue; }
    if (w.startsWith("-")) continue;
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) continue;
    return w;
  }
  return null;
}

/** Why the kernel cannot start `file` on this host, or null when it can (or
 *  when a static look cannot tell). Follows a `#!` chain up to four deep, the
 *  kernel's own limit being near it. */
export function whyNotRunnable(file: string, deps: RunnableDeps = {}, depth = 0): string | null {
  const r = resolveDeps(deps);
  if (depth > 4) return null;
  const head = r.readHead(file, 4096);
  if (head === null) return null;
  const elf = elfFacts(head);
  if (elf) {
    const host = HOST_MACHINE[r.arch];
    if (host !== undefined && elf.machine !== host && !(COMPAT_MACHINE[host] ?? []).includes(elf.machine) && !r.foreign().has(elf.machine)) {
      return `${file} is an ELF for ${MACHINE_NAME[elf.machine] ?? `machine ${elf.machine}`} (e_machine ${elf.machine}), and this host runs ${MACHINE_NAME[host] ?? r.arch} (e_machine ${host}) with no binfmt_misc handler for it`;
    }
    if (elf.interp) {
      const interp = elf.interpInHead ?? (() => { const b = r.readAt(file, elf.interp!.off, elf.interp!.size); return b === null ? null : cString(b); })();
      if (interp !== null && interp !== "" && isAbsolute(interp) && !r.exists(interp)) {
        return `${file} needs the program interpreter ${interp} (its PT_INTERP), which is not on this host`;
      }
    }
    return null;
  }
  const sb = shebang(head);
  if (sb === null) return null;
  if (sb.interp === "") return `${file} starts with an empty #! line`;
  if (!isAbsolute(sb.interp)) return null; // relative to the run's cwd: not the host's to judge
  if (!r.exists(sb.interp)) return `${file} is a script for ${sb.interp} (its #! line), which does not exist on this host`;
  if (!r.isExecFile(sb.interp)) return `${file} is a script for ${sb.interp} (its #! line), which is not an executable file`;
  if (basename(sb.interp) === "env") {
    const prog = envProgram(sb.arg);
    if (prog === null) return null;
    const found = prog.includes("/") ? (r.isExecFile(prog) ? prog : null) : resolveOnPath(prog, deps);
    if (found === null) return `${file} is a script run by \`${sb.interp} ${sb.arg}\` (its #! line), and ${prog} is not on PATH`;
    return whyNotRunnable(found, deps, depth + 1);
  }
  return whyNotRunnable(sb.interp, deps, depth + 1);
}

// ── the programs a shell command line runs ───────────────────────────────────

type Tok = { op: string } | { word: string; plain: boolean };

/** Shell tokens: words (quotes removed; `plain` false when a quote, `$` or
 *  backquote made it) and the operators that start a new command. A
 *  heuristic, not a parser: it only needs the command words. */
function shellTokens(cmd: string): Tok[] {
  const out: Tok[] = [];
  let w = "";
  let has = false;
  let plain = true;
  const flush = (): void => { if (has) out.push({ word: w, plain }); w = ""; has = false; plain = true; };
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i]!;
    if (c === "\\") { if (i + 1 < cmd.length && cmd[i + 1] !== "\n") { w += cmd[i + 1]; has = true; } i++; continue; }
    if (c === "'") { const j = cmd.indexOf("'", i + 1); const end = j === -1 ? cmd.length : j; w += cmd.slice(i + 1, end); has = true; plain = false; i = end; continue; }
    if (c === '"') {
      let j = i + 1;
      for (; j < cmd.length && cmd[j] !== '"'; j++) { if (cmd[j] === "\\") j++; }
      w += cmd.slice(i + 1, j); has = true; plain = false; i = j; continue;
    }
    if (c === "$" && cmd[i + 1] === "(") { flush(); out.push({ op: "$(" }); i++; continue; }
    if (c === "`") { flush(); out.push({ op: "`" }); continue; }
    if (c === "$") { w += c; has = true; plain = false; continue; }
    if (c === ";" || c === "&" || c === "|" || c === "(" || c === ")" || c === "\n") {
      flush();
      const two = cmd.slice(i, i + 2);
      if (two === "&&" || two === "||" || two === ";;" || two === "|&") { out.push({ op: two }); i++; } else out.push({ op: c });
      continue;
    }
    if (c === "<" || c === ">") {
      // a redirection: its operator (with a leading fd number) and then its target word
      if (has && /^\d+$/.test(w)) { w = ""; has = false; plain = true; } else flush();
      let j = i;
      while (j < cmd.length && (cmd[j] === "<" || cmd[j] === ">" || cmd[j] === "&")) j++;
      out.push({ op: "redir" });
      i = j - 1;
      continue;
    }
    if (c === " " || c === "\t") { flush(); continue; }
    w += c; has = true;
  }
  flush();
  return out;
}

/** Words after which the next word is a command again. */
const RESTART = new Set(["if", "then", "else", "elif", "do", "while", "until", "!", "{", "time", "exec", "command", "nohup", "builtin"]);
/** Words after which no command word follows until the next operator. */
const NO_COMMAND = new Set(["for", "case", "select", "function", "fi", "done", "esac", "}", "in", "[[", "]]", "(("]);

/**
 * The programs `cmd` runs by name: each command word (the first word of a
 * simple command, past leading assignments and `env`'s own options,
 * `command`/`exec`/`nohup`/`time` included), in order, without repeats.
 * Words made by an expansion or a quote are left out: what they name is the
 * run's, not the line's.
 */
export function shellCommandWords(cmd: string): string[] {
  const out: string[] = [];
  let atStart = true;
  let skipRedirTarget = false;
  let afterEnv = false;
  let inBackquote = false;
  for (const t of shellTokens(cmd)) {
    if ("op" in t) {
      if (t.op === "redir") { skipRedirTarget = true; continue; }
      afterEnv = false; skipRedirTarget = false;
      // a closing `)` or backquote ends a substitution or subshell: what
      // follows is its arguments or an operator, not a command
      if (t.op === "`") { inBackquote = !inBackquote; atStart = inBackquote; continue; }
      atStart = t.op !== ")";
      continue;
    }
    if (skipRedirTarget) { skipRedirTarget = false; continue; }
    if (!atStart) continue;
    const w = t.word;
    if (afterEnv && (w.startsWith("-") || /^[A-Za-z_][A-Za-z0-9_]*=/.test(w))) continue;
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) continue; // an assignment before the command
    if (RESTART.has(w)) continue;
    if (NO_COMMAND.has(w)) { atStart = false; continue; }
    if (t.plain && !out.includes(w)) out.push(w);
    if (t.plain && w === "env") { afterEnv = true; continue; }
    atStart = false; afterEnv = false;
  }
  return out;
}

export interface UnrunnableTool { tool: string; path: string; why: string }

/**
 * The programs `commands` run by name that resolve, on `deps.path`, to a file
 * this host cannot start. Builtins and the names in `exclude` (programs the
 * run itself puts on PATH) are not looked up; an absolute path is judged as
 * named; a relative one (`./build.sh`) is the run's own.
 */
export function unrunnableTools(commands: readonly string[], exclude: ReadonlySet<string> = new Set(), deps: RunnableDeps = {}): UnrunnableTool[] {
  const r = resolveDeps(deps);
  const seen = new Set<string>();
  const out: UnrunnableTool[] = [];
  for (const cmd of commands) {
    for (const tool of shellCommandWords(cmd)) {
      if (seen.has(tool)) continue;
      seen.add(tool);
      if (SHELL_BUILTINS.has(tool) || exclude.has(tool)) continue;
      let path: string | null;
      if (isAbsolute(tool)) path = r.isExecFile(tool) ? tool : null;
      else if (tool.includes("/")) path = null;
      else path = resolveOnPath(tool, deps);
      if (path === null) continue;
      const why = whyNotRunnable(path, deps);
      if (why !== null) out.push({ tool, path, why });
    }
  }
  return out;
}

/** The refusal for unrunnable tools, or null. */
export function unrunnableToolsRefusal(found: readonly UnrunnableTool[]): string | null {
  if (found.length === 0) return null;
  const list = found.map((f) => `\`${f.tool}\` resolves to ${f.path}: ${f.why}`).join("; ");
  return `the script runs a program this host cannot start (${list}). Both sides would fail the same way and the checks would grade the broken tool, not Mandu. ` +
    "Put a working program first on PATH (or remove the broken one), or install the missing interpreter.";
}
