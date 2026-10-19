/**
 * test-runtime — a Mandu runtime dir of the test file's own, for code under
 * test that resolves the runtime base from an env the test hands it
 * (docs/design/testing/test-organization.md §8.7).
 *
 * Why: an env that names no runtime dir (a test's `{}`, or `{ HOME }`) makes
 * the runtime-base rule (src/runtime-base.ts) answer the path table's
 * `/tmp/mandu`, a name every account on the host shares. Such a test then
 * reads (and, through an autostart, creates) the real `/tmp/mandu`: where
 * another user made it first, the product's ownership check refuses it and
 * the test fails with "the Mandu runtime dir /tmp/mandu is owned by uid …"
 * (about 80 launcher tests on a shared dev host, 2026-10-09); where nobody
 * did, the test leaves a `/tmp/mandu` of its own that refuses every other
 * account's Mandu. Neither depends on the code under test. Since the rule
 * became per-user (2026-10-09) the answer is `/tmp/mandu-<uid>`, which no
 * other account can make for us, but it is still the developer's REAL
 * runtime dir (a running stack's `current` link, its registry), so a test
 * keeps out of it all the same.
 *
 * `withTestRuntime(env)` adds `XDG_RUNTIME_DIR=<a private temp dir>` to an
 * env that sets none of MANDU_RUNTIME_DIR, XDG_RUNTIME_DIR and TMPDIR, so
 * the base is `<that dir>/mandu`, absent until something makes it, gone when
 * the file's process exits. An env that names one is the test's own choice
 * (the rule's tests pin TMPDIR on purpose) and is returned unchanged.
 */
import { tmpDir } from "./tmp-dir.js";

type Env = Record<string, string | undefined>;

let dir: string | undefined;

/** This test file's private runtime dir (0700 under TMPDIR, made on first use,
 *  removed when the process exits). */
export function testRuntimeDir(): string {
  dir ??= tmpDir("mandu-test-rt-");
  return dir;
}

/** `env` with this file's runtime dir as XDG_RUNTIME_DIR when it names no
 *  runtime dir (MANDU_RUNTIME_DIR, XDG_RUNTIME_DIR or TMPDIR); else `env`. */
export function withTestRuntime<E extends Env>(env: E): E {
  if (env["MANDU_RUNTIME_DIR"] || env["XDG_RUNTIME_DIR"] || env["TMPDIR"]) return env;
  return { ...env, XDG_RUNTIME_DIR: testRuntimeDir() };
}

/** `fn` with its env argument (position `envArg`) passed through
 *  withTestRuntime: a test file imports the function under test under
 *  another name and calls this wrapper, so no call site can forget. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function hermetic<F extends (...args: any[]) => any>(fn: F, envArg: number): F {
  return ((...args: unknown[]) => {
    const a = [...args];
    if (a[envArg] !== undefined) a[envArg] = withTestRuntime(a[envArg] as Env);
    return fn(...a);
  }) as F;
}
