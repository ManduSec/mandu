/**
 * older-arbiter.fixture — a REAL arbiter (ArbiterServer from this tree) that
 * says it is another Mandu release, running as a resident stack's arbiter
 * would: titled `mandu-arbiter`, bound inside `<base>/instances/<id>/`,
 * promoted to `<base>/current`, stopped by SIGTERM (it unlinks its socket and
 * removes its instance dir, as the real daemon does).
 *
 * Used by tests/stack/arbiter-version-skew.test.ts, the release check of
 * runtime-instances.md §4.1: a launch after an upgrade finds this on the
 * rendezvous. Only the reported `version` (and, given, `build` and the code
 * rev) differs from the real daemon.
 *
 * Usage: node --import tsx older-arbiter.fixture.ts <base> <version|none> <state dir> [<bundle|-> <rev>]
 *   `none` = a release from before the check (hello reports no version).
 *   `<bundle> <rev>` = hello's `build` (another build of a release; `-` for
 *   no bundle), the rev standing as the code rev too.
 * Prints `ready <sock>` on stdout once promoted.
 *
 * Mandu-new test plumbing (no reference origin).
 */
import { rmSync } from "node:fs";
import { join } from "node:path";
import { createInstanceDir, instanceId, promoteInstance } from "../../arbiter/ipc/instance.js";
import { ArbiterServer } from "../../arbiter/ipc/server.js";

process.title = "mandu-arbiter";

const [base, version, stateDir, bundle, rev] = process.argv.slice(2);
if (!base || !version || !stateDir) {
  console.error("usage: older-arbiter.fixture.ts <base> <version|none> <state dir>");
  process.exit(2);
}
const codeRev = rev ?? "old0000";
const id = instanceId(new Date(), codeRev, process.pid);
const paths = createInstanceDir(base, id);
const server = new ArbiterServer({
  socketPath: paths.sockPath,
  dbPath: join(stateDir, "older-symbols.db"),
  eventDir: join(stateDir, "older-events"),
  identity: {
    instanceId: id, gitRev: codeRev, gitDirty: false, version: version === "none" ? null : version,
    ...(bundle !== undefined ? { build: { bundle: bundle === "-" ? null : bundle, rev: codeRev } } : {}),
  },
  log: () => {},
});
await server.listen();
promoteInstance(base, id);
process.stdout.write(`ready ${paths.sockPath}\n`);

let stopping = false;
process.on("SIGTERM", () => {
  if (stopping) return;
  stopping = true;
  void server.close().finally(() => {
    rmSync(paths.dir, { recursive: true, force: true });
    process.exit(0);
  });
});
