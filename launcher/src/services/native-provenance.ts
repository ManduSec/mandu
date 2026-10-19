/**
 * services/native-provenance — may a checkout use another checkout's native
 * bin? (packaging.md §5.2; the writer is scripts/native-provenance.mjs, run
 * by scripts/build-native.sh.)
 *
 * The launcher resolves its native bins (mandu-net-guard, mandu-exec-box,
 * mandu-landlock-apply) from its OWN checkout's interceptors/target/ first
 * (native-bins.ts). A git worktree made for a change that does not touch the
 * native crates has none: building them takes minutes, so its launches ran
 * gated, and a gated launch is unconfined, which holds every git-history
 * cache seal void for every other launch while it runs (plan 14 §11.2). This
 * module lets such a worktree use the MAIN checkout's bin, under one rule:
 * the bin carries a provenance record written when it was built, its bytes
 * still hash to the record, and every source the record names hashes the
 * same in THIS checkout (a file the record says was absent must be absent
 * here too). So the bin is exactly what this checkout's sources build; a bin
 * with no record, a bin changed since, or one source byte of difference is
 * refused with the reason, and the launch keeps today's behavior (the next
 * candidate, else gated with the hint to run scripts/build-native.sh).
 *
 * Trust: the record is a file of the same user, as are the bins and the
 * checkout's own target/ (which the launcher has always used on sight); the
 * record adds no new principal, it only refuses a bin of another source
 * tree. A same-user writer that swaps the bin after the check is the same
 * writer that could swap this checkout's own bins (plan 14 §11.2 S3's line).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";

export const PROVENANCE_FORMAT = "mandu-native-provenance/1";
export const PROVENANCE_SUFFIX = ".provenance.json";
/** A record naming more sources than this is not believed. */
const MAX_SOURCES = 5000;

export interface ProvenanceDeps {
  readFile?: (p: string) => Buffer;
  exists?: (p: string) => boolean;
}

const rd = (d: ProvenanceDeps) => d.readFile ?? ((p: string) => readFileSync(p));
const ex = (d: ProvenanceDeps) => d.exists ?? existsSync;
const sha256 = (b: Buffer): string => createHash("sha256").update(b).digest("hex");

/**
 * The main checkout of the git worktree at `repoRoot`, or null when
 * `repoRoot` is not a linked worktree (its `.git` is a directory, or absent,
 * or not of the shape git writes). Read from the files git keeps (`.git`:
 * `gitdir: <dir>`; `<dir>/commondir`), no git process.
 */
export function mainCheckoutOf(repoRoot: string, deps: ProvenanceDeps = {}): string | null {
  const dotGit = join(repoRoot, ".git");
  let text: string;
  try {
    if (statSync(dotGit).isDirectory()) return null;
    text = rd(deps)(dotGit).toString("utf8");
  } catch {
    return null;
  }
  const m = /^gitdir: (.+)$/m.exec(text);
  if (!m) return null;
  const gitdir = resolve(repoRoot, m[1]!.trim());
  let common: string;
  try {
    common = resolve(gitdir, rd(deps)(join(gitdir, "commondir")).toString("utf8").trim());
  } catch {
    return null;
  }
  if (basename(common) !== ".git") return null;
  const main = dirname(common);
  return main === resolve(repoRoot) ? null : main;
}

/** A path a record may name: relative, inside the interceptors dir. */
function safeRel(rel: string): boolean {
  return rel !== "" && rel.length <= 512 && !isAbsolute(rel) && !rel.includes("\0") && !rel.includes("\\")
    && rel.split("/").every((s) => s !== "" && s !== "." && s !== "..");
}

/**
 * Was the bin at `binPath` built from exactly the sources under
 * `interceptorsDir` (this checkout's)? `{ ok: true }`, or the first reason it
 * is not. Never throws.
 */
export function verifyNativeProvenance(binPath: string, name: string, interceptorsDir: string, deps: ProvenanceDeps = {}): { ok: true } | { ok: false; why: string } {
  const read = rd(deps);
  const exists = ex(deps);
  let rec: Record<string, unknown>;
  try {
    rec = JSON.parse(read(`${binPath}${PROVENANCE_SUFFIX}`).toString("utf8")) as Record<string, unknown>;
  } catch {
    return { ok: false, why: "it has no provenance record (built before scripts/build-native.sh wrote one, or by plain cargo)" };
  }
  if (rec === null || typeof rec !== "object" || rec.format !== PROVENANCE_FORMAT || rec.bin !== name
    || typeof rec.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(rec.sha256) || !Number.isSafeInteger(rec.size)
    || !Array.isArray(rec.features) || !rec.features.includes("kernel")
    || rec.sources === null || typeof rec.sources !== "object" || Array.isArray(rec.sources)) {
    return { ok: false, why: "its provenance record is not of the expected shape" };
  }
  const sources = Object.entries(rec.sources as Record<string, unknown>);
  if (sources.length === 0 || sources.length > MAX_SOURCES) return { ok: false, why: "its provenance record names no sources, or too many" };
  let bin: Buffer;
  try { bin = read(binPath); } catch { return { ok: false, why: "it cannot be read" }; }
  if (bin.length !== rec.size || sha256(bin) !== rec.sha256) return { ok: false, why: "it changed after its provenance was recorded (rebuilt by plain cargo?)" };
  for (const [rel, want] of sources) {
    if (!safeRel(rel) || (want !== null && (typeof want !== "string" || !/^[0-9a-f]{64}$/.test(want)))) {
      return { ok: false, why: "its provenance record names a source it may not" };
    }
    const here = join(interceptorsDir, rel);
    if (want === null) {
      if (exists(here)) return { ok: false, why: `interceptors/${rel} exists here but not where it was built` };
      continue;
    }
    let got: string;
    try { got = sha256(read(here)); } catch { return { ok: false, why: `interceptors/${rel} is missing here` }; }
    if (got !== want) return { ok: false, why: `interceptors/${rel} differs from the source it was built from` };
  }
  return { ok: true };
}

/** One answer per bin file state, for the launch (resolution runs several
 *  times per launch; the bins are megabytes). */
const memo = new Map<string, { key: string; result: { ok: true } | { ok: false; why: string } }>();

/** What the last {@link sharedCheckoutBin} call per bin name refused, for the
 *  build hint (native-bins.ts). */
const refusals = new Map<string, string>();

/** The main checkout's bin `name`, when it was built from exactly this
 *  worktree's native sources (release first, then debug, as for the
 *  checkout's own); null otherwise, with the refusal kept for the hint. */
export function sharedCheckoutBin(name: string, repoRoot: string, deps: ProvenanceDeps = {}): string | null {
  refusals.delete(name);
  const main = mainCheckoutOf(repoRoot, deps);
  if (main === null) return null;
  const exists = ex(deps);
  const why: string[] = [];
  for (const profile of ["release", "debug"]) {
    const bin = join(main, "interceptors", "target", profile, name);
    if (!exists(bin)) continue;
    let key: string;
    try {
      const st = statSync(bin);
      const rs = statSync(`${bin}${PROVENANCE_SUFFIX}`, { throwIfNoEntry: false });
      key = `${repoRoot}\0${st.ino}:${st.size}:${st.mtimeMs}:${st.ctimeMs}\0${rs ? `${rs.ino}:${rs.mtimeMs}:${rs.ctimeMs}` : "-"}`;
    } catch {
      key = "";
    }
    const hit = key !== "" ? memo.get(bin) : undefined;
    const result = hit !== undefined && hit.key === key ? hit.result : verifyNativeProvenance(bin, name, join(repoRoot, "interceptors"), deps);
    if (key !== "") memo.set(bin, { key, result });
    if (result.ok) return bin;
    why.push(`${bin}: ${result.why}`);
  }
  if (why.length > 0) refusals.set(name, why.join("; "));
  return null;
}

/** Did this process verify the bin at `binPath` as another checkout's,
 *  built from this checkout's sources? */
export function verifiedSharedBin(binPath: string): boolean {
  return memo.get(binPath)?.result.ok === true;
}

/** Why the main checkout's `name` was not used by the last resolution, or null. */
export function sharedBinRefusal(name: string): string | null {
  return refusals.get(name) ?? null;
}

/** Forget the memo and the refusals (tests). */
export function resetSharedBins(): void {
  memo.clear();
  refusals.clear();
}
