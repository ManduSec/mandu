/**
 * native-targets.mjs — the platform tags the @mandusec/mandu bundle ships
 * prebuilt native bins for, and the pure rules build-bundle.mjs follows to
 * copy them (packaging.md §5, packaging.md §11.3).
 *
 * One npm tarball carries every tag's bins side by side under
 * dist/native/<platform>-<arch>/; the launcher picks its own tag at run time
 * (services/native-bins.ts `nativePlatformTag`). Adding an architecture is a
 * row here, a `scripts/build-native.sh --target <triple>` line in
 * scripts/ci/release-pack.sh, and the rust target in the CI image.
 *
 * Kept free of side effects so launcher/test/unit/native-targets.test.ts can
 * pin it without building anything.
 */

/** tag → how its bins are built and recognized. `elfMachine` is the ELF
 *  e_machine the copied bin must carry: a bin built for the wrong CPU would
 *  land in the right directory and fail every exec with ENOEXEC. */
export const NATIVE_TARGETS = {
  "linux-x64": { triple: "x86_64-unknown-linux-gnu", elfMachine: 62, strip: ["x86_64-linux-gnu-strip"] },
  "linux-arm64": { triple: "aarch64-unknown-linux-gnu", elfMachine: 183, strip: ["aarch64-linux-gnu-strip"] },
};

/**
 * Parse `MANDU_NATIVE_BIN_DIRS`: `<tag>=<dir>[,<tag>=<dir>...]`. Throws on a
 * malformed entry, an unknown tag or a repeated tag, so a typo in the release
 * job fails the pack instead of silently shipping one architecture.
 */
export function parseNativeBinDirs(spec) {
  const out = {};
  for (const raw of spec.split(",")) {
    const entry = raw.trim();
    if (!entry) continue;
    const eq = entry.indexOf("=");
    if (eq <= 0 || eq === entry.length - 1) throw new Error(`MANDU_NATIVE_BIN_DIRS: "${entry}" is not <tag>=<dir>`);
    const tag = entry.slice(0, eq).trim();
    const dir = entry.slice(eq + 1).trim();
    if (!(tag in NATIVE_TARGETS)) {
      throw new Error(`MANDU_NATIVE_BIN_DIRS: unknown tag "${tag}" (known: ${Object.keys(NATIVE_TARGETS).join(", ")})`);
    }
    if (tag in out) throw new Error(`MANDU_NATIVE_BIN_DIRS: "${tag}" given twice`);
    out[tag] = dir;
  }
  return out;
}

/**
 * Where each tag's bins come from. `MANDU_NATIVE_BIN_DIRS` (the release job,
 * every shipped tag) wins; otherwise the host's own tag from
 * `MANDU_NATIVE_BIN_DIR`, else `<repoRoot>/interceptors/target/release` (a
 * developer's `npm pack`, the fresh-install packer).
 */
export function nativeSources({ env, repoRoot, hostTag }) {
  const multi = env.MANDU_NATIVE_BIN_DIRS;
  if (multi && multi.trim()) {
    return Object.entries(parseNativeBinDirs(multi)).map(([tag, dir]) => ({ tag, dir }));
  }
  const dir = env.MANDU_NATIVE_BIN_DIR || `${repoRoot}/interceptors/target/release`;
  return [{ tag: hostTag, dir }];
}

/** The ELF e_machine of a file's first bytes, or null when it is not ELF. */
export function elfMachine(buf) {
  if (!buf || buf.length < 20) return null;
  if (buf[0] !== 0x7f || buf[1] !== 0x45 || buf[2] !== 0x4c || buf[3] !== 0x46) return null;
  // EI_DATA: 1 = little endian, 2 = big endian.
  if (buf[5] === 1) return buf[18] | (buf[19] << 8);
  if (buf[5] === 2) return (buf[18] << 8) | buf[19];
  return null;
}

/** Why a bin may not ship under `tag`, or null when it may. A tag this table
 *  does not know (a developer packing on another host) is not checked. */
export function nativeBinMismatch(tag, buf) {
  const target = NATIVE_TARGETS[tag];
  if (!target) return null;
  const m = elfMachine(buf);
  if (m === null) return `not an ELF executable (expected ${tag})`;
  if (m !== target.elfMachine) return `ELF machine ${m}, but ${tag} needs ${target.elfMachine}`;
  return null;
}

/** The strip tools to try, in order. The host's plain `strip` only knows its
 *  own architecture, so it is offered for the host tag alone; a cross copy
 *  that no tool can strip ships unstripped. */
export function stripCandidates(tag, hostTag) {
  const own = NATIVE_TARGETS[tag]?.strip ?? [];
  return [...own, "llvm-strip", ...(tag === hostTag ? ["strip"] : [])];
}
