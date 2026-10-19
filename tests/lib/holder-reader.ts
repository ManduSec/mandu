/**
 * A raw holder a sandbox test controls, for the tests whose subject is what
 * HAPPENS to a secret once a process holds it (pipe taint, socket flows, the
 * call tree, the egress gate), not who may read it.
 *
 * Until 2026-10-03 such tests listed `cat` as the file's reader. Plan 13 D8,
 * "printers admit nothing" (the maintainer's decision of that day,
 * docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md §3 D8 and §8):
 * a program that prints or copies a file (cat, head, base64, cp, curl, …)
 * admits nothing as a reader, in any form, and since the !437 leftover (2)
 * of the same day neither does a binary byte-identical to a printer on the
 * host under another name (the renamed GNU cat these tests used next). A
 * test now BUILDS a tiny reader of its own, `holder-reader.c` beside this
 * file (`mdu-holder FILE…` prints them, `mdu-holder -o DST FILE…` copies), with
 * the host's C compiler into `<dir>/bin/<name>`, and pins THAT file by path
 * and hash: a pin the human wrote names one exact binary they vouch for
 * (plan 13 §4.9). Every CI guest has `cc` (build-essential); a host without
 * one SKIPs the suites that need it.
 */
import { chmodSync, existsSync, mkdirSync, readFileSync, realpathSync } from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export interface HolderReader {
  /** The binary's real path (the guard reports the canonical executable). */
  path: string;
  sha256: string;
  /** Its reader-entry name (`mdu-holder`). */
  app: string;
  /** The reader entry, in policy.yaml's flow form. */
  yaml: string;
  /** The same entry as an object, for a `policyDocument`. */
  entry: { app: string; path: string; sha256: string; prints: "nothing" };
}

/** The holder's C source. */
export const HOLDER_SOURCE = join(dirname(fileURLToPath(import.meta.url)), "holder-reader.c");

/** The host's C compiler (`cc`, else `gcc`, else `clang`), or null. */
export function holderCompiler(): string | null {
  for (const c of ["/usr/bin/cc", "/usr/bin/gcc", "/usr/bin/clang", "/bin/cc"]) if (existsSync(c)) return c;
  return null;
}

/** Why a suite needing the holder must SKIP on this host, or false. */
export function holderSkip(): string | false {
  return holderCompiler() === null ? "no C compiler (cc) to build the pinned reader (tests/lib/holder-reader.c)" : false;
}

/** Build the holder into `<dir>/bin/<name>` and return its pin; null when
 *  the host has no C compiler or the build fails (a test SKIPs). */
export function holderReader(dir: string, name = "mdu-holder"): HolderReader | null {
  const cc = holderCompiler();
  if (cc === null) return null;
  mkdirSync(join(dir, "bin"), { recursive: true });
  const dst = join(dir, "bin", name);
  const r = spawnSync(cc, ["-O2", "-o", dst, HOLDER_SOURCE], { encoding: "utf8" });
  if (r.status !== 0 || !existsSync(dst)) return null;
  chmodSync(dst, 0o755);
  const path = realpathSync(dst);
  const sha256 = createHash("sha256").update(readFileSync(path)).digest("hex");
  return { path, sha256, app: name, yaml: `{ app: ${name}, path: ${path}, sha256: ${sha256}, prints: nothing }`, entry: { app: name, path, sha256, prints: "nothing" as const } };
}

/**
 * For a test under the REAL launcher, whose policy.yaml is written before
 * the launch makes its workspace (no path to pin a copy at): the stdlib's
 * base64.py, canonical, when python3 has one. The reader entry is the R5
 * script pin `{ app: python3, script: <it> }` (out of the agent's reach,
 * run with `-I`); `/usr/bin/python3 -I <it> <file> | base64 -d` hands the
 * file's bytes on, as `cat <file>` did (plan 13 D2: the pipe's reader holds
 * them). By its absolute path, so no exec-box shim stands in for python3.
 */
export function stdlibBase64(): string | null {
  const r = spawnSync("/usr/bin/python3", ["-I", "-c", "import base64, os; print(os.path.realpath(base64.__file__))"], { encoding: "utf8" });
  const p = (r.stdout ?? "").trim();
  return r.status === 0 && p.endsWith("base64.py") ? p : null;
}

/**
 * The `base64` that decodes the reader's output on the pipe, by absolute
 * path: the first `base64` on PATH (then /usr/bin, /bin) that actually
 * decodes, or null. A suite with none SKIPs with that reason.
 *
 * Not the bare word: a host can shadow coreutils with a `base64` that does
 * not run (2026-10-04, a dev host's /usr/local/bin/base64 was a pip
 * entry point of the `codext` package, installed for a Python the host no
 * longer runs; it died with ModuleNotFoundError). The holder then sourced
 * an empty `.env`, so the suite's own liveness control failed and its
 * oracle ("the unbound host never saw the key") could only hold vacuously.
 * Probing the candidate keeps that host failure out of the suite: the
 * pipe's decoder is the test's plumbing, not its subject.
 */
export function workingBase64(path = process.env.PATH ?? "", fallbacks: readonly string[] = ["/usr/bin", "/bin"]): string | null {
  const seen = new Set<string>();
  for (const dir of [...path.split(":"), ...fallbacks]) {
    if (!dir.startsWith("/")) continue;
    const cand = join(dir, "base64");
    if (!existsSync(cand)) continue;
    let real: string;
    try { real = realpathSync(cand); } catch { continue; }
    if (seen.has(real)) continue;
    seen.add(real);
    if (base64Decodes(cand)) return cand;
  }
  return null;
}

/** Whether `bin -d` turns a known encoding back into its bytes. */
export function base64Decodes(bin: string): boolean {
  const r = spawnSync(bin, ["-d"], { input: "bWR1LWJhc2U2NC1wcm9iZQ==\n", encoding: "utf8", timeout: 10_000 });
  return r.status === 0 && r.stdout === "mdu-base64-probe";
}
