/**
 * runtime-registry — the entries of Mandu's runtime base that Mandu processes
 * OUTSIDE the agent's confinement read, write through or delete from
 * (runtime-instances.md §2, "planted paths"; confidentiality.md §7.3).
 *
 * One list, three uses:
 *   - the macOS whole-agent Seatbelt profile write-denies every entry
 *     (seatbelt-setup.ts `applySeatbelt`, through `runtimeRegistryPaths`);
 *   - the Linux whole-agent guard's write-protect list carries every entry,
 *     `dirs` plain, `names` as `name`, `prefixes` as `prefix`, and the base
 *     itself as `self` (write-protect.ts `runtimeRegistryProtect`, 2026-10-07);
 *   - a scope id may never name one (parse.ts, through `scopeIdProblem`):
 *     the scope's dir `<base>/<id>` would otherwise be a registry entry, and
 *     either the profile would have to leave that entry writable or the
 *     launch's own files would land in it.
 *
 *   instances/          the arbiter's instance dirs: its socket, its manifest
 *                       (written by the arbiter), removed by the arbiter's
 *                       start-up sweep and `mandu reap` when their pid is dead
 *   current             the rendezvous link every client dials through
 *   .current.tmp-<pid>  the promotion's temporary link, renamed over `current`
 *   arbiter.sock        the legacy fixed socket path (client resolution step 3)
 *   dashboards/         the dashboards' registry (each dashboard writes its
 *                       entry through a temp name; `mandu reap` and every
 *                       dashboard start remove dead entries)
 *   dashboard.log       `mandu dashboard`'s log, opened for append
 *   dashboard-<pid>.port(.tmp)
 *                       `mandu dashboard`'s port rendezvous, written by the
 *                       dashboard through a temp name
 *   vm-guests/          the VM test harness guests' registry (`mandu reap`
 *                       removes each entry's scratch dir)
 *   logs/               the supervisor's and the launcher's autostart logs,
 *                       opened for append by processes outside the profile
 *   test/               the test tenant's arbiter socket
 *   release-check/      the release check's gate (release-gate.ts): each
 *                       launch's pending marker, read by the next launch's
 *                       session scan, and the per-stack restart lock. A
 *                       forged marker would take a real session out of that
 *                       scan, and the stack would be replaced under it
 *                       (runtime-instances.md §4.1)
 *
 * The human plane's `human/` is not on the list: its own component denies
 * the agent every connect, read and write there, under the launch's base and
 * every other registry base alike (seatbelt-setup.ts; arbiter-human-plane.md
 * §5). A scope id may not name it either.
 *
 * tests/integration/test/e2e/runtime-registry-parity.test.ts holds this list
 * to the packages that own the names, and scans their sources for any other
 * entry joined onto the runtime base.
 *
 * Mandu-new (no reference origin). Pure.
 */
import { normalizeAbs, type SeatbeltRuntime } from "./seatbelt-profile.js";

/** The registry, relative to the runtime base. */
export const RUNTIME_REGISTRY: { readonly dirs: readonly string[]; readonly names: readonly string[]; readonly prefixes: readonly string[] } = {
  /** Denied as a `subpath`: the directory and everything below it. */
  dirs: ["dashboards", "instances", "logs", "release-check", "test", "vm-guests"],
  /** Denied as a `literal`: the entry itself (`current` is a link). */
  names: ["arbiter.sock", "current", "dashboard.log"],
  /** Denied as a `prefix`: every name that starts with it. */
  prefixes: [".current.tmp-", "dashboard-"],
};

/** The human plane's directory under the base (instance.ts HUMAN_DIR). */
const HUMAN_DIR = "human";

/** The key under which two names may be the same file on the default macOS
 *  volume, which ignores case and Unicode normalization (as Seatbelt's path
 *  match does there; seatbelt-setup.ts `sameFileKey` is the same fold). The
 *  registry's names are lowercase ASCII, so they are their own key. */
export function foldedName(p: string): string {
  return p.toUpperCase().toLowerCase().normalize("NFD");
}

/** Every registry entry under the runtime base `base`, absolute; empty for a
 *  relative base or `/`. */
export function runtimeRegistryPaths(base: string): SeatbeltRuntime {
  const b = normalizeAbs(base);
  if (b === null || b === "/") return { dirs: [], names: [], prefixes: [] };
  return {
    dirs: RUNTIME_REGISTRY.dirs.map((n) => `${b}/${n}`),
    names: RUNTIME_REGISTRY.names.map((n) => `${b}/${n}`),
    prefixes: RUNTIME_REGISTRY.prefixes.map((n) => `${b}/${n}`),
  };
}

/**
 * Why `id` cannot name a scope, or null when it can. The scope's dir is
 * `<runtime base>/<id>`, so the id must be ONE path component (no `/`, not
 * `.` or `..`, no NUL) and must not be a runtime registry entry, the human
 * plane's directory, or a name the registry's prefixes cover. `dashboard*`
 * is kept out as a whole, the dashboards' own namespace in the base.
 *
 * The comparison ignores case and Unicode normalization (`foldedName`), on
 * every platform: the default macOS volume, and Seatbelt's path match there,
 * treat `Instances` as `instances`, so an exact match let `--id Instances`
 * make the arbiter's registry the session's own (writable) folder. On a
 * case-sensitive Linux file system this only refuses a few more names.
 */
export function scopeIdProblem(id: string): string | null {
  if (id === "") return "it is empty";
  if (id.includes("/")) return "it holds a `/` (it must be one folder name)";
  if (id.includes("\0")) return "it holds a NUL byte";
  if (id === "." || id === "..") return `\`${id}\` is not a folder name`;
  const k = foldedName(id);
  if ([...RUNTIME_REGISTRY.dirs, ...RUNTIME_REGISTRY.names, HUMAN_DIR].includes(k)) {
    return `\`${id}\` is one of Mandu's own entries in the runtime folder (the match ignores case)`;
  }
  const prefix = [...RUNTIME_REGISTRY.prefixes, "dashboard"].find((p) => k.startsWith(p));
  if (prefix !== undefined) return `a name starting \`${prefix}\` belongs to Mandu's own entries in the runtime folder`;
  return null;
}
