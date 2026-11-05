/**
 * live-db-scenario.fixture — this side of the live database client suite
 * (docs/design/testing/live-clients.md §2), run by tests/lib/netns.ts with
 * the peer (live-db-peer.fixture.ts) up at 10.77.0.2: each launch the test
 * wrote (tests/lib/live-clients.ts runLaunch: the real launcher around the
 * stand-in `claude`, whose Bash tool runs the real `psql` and `mysql`).
 *
 * Writes { launches: LiveLaunchResult[] } to the scenario's `result` file and
 * prints one JSON line naming it, or { error }.
 * env: LIVE_DB_SCENARIO (the scenario JSON the test wrote: its scratch dir,
 * its result file and its launches).
 * PROVENANCE: NEW Mandu test code.
 */
import { readFileSync, writeFileSync } from "node:fs";

import { runLaunch, type LiveLaunch, type LiveLaunchResult } from "../lib/live-clients.js";

async function main(): Promise<void> {
  const spec = JSON.parse(readFileSync(process.env["LIVE_DB_SCENARIO"]!, "utf8")) as { scratch: string; result: string; launches: LiveLaunch[] };
  const launches: LiveLaunchResult[] = [];
  for (const l of spec.launches) launches.push(await runLaunch(l, spec.scratch));
  // A file, not stdout: a pipe write of this size is not done when the
  // process exits.
  writeFileSync(spec.result, JSON.stringify({ launches }));
  process.stdout.write(JSON.stringify({ result: spec.result }) + "\n");
  process.exit(0);
}

main().catch((e) => {
  process.stdout.write(JSON.stringify({ error: String((e as Error).stack ?? e) }) + "\n");
  process.exit(1);
});
