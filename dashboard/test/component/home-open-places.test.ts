/**
 * home-open-places.test — dashboard.md §4.25q *Home warns about open
 * places*, over the real DashboardServer: with Mandu's folder in a temporary
 * MANDU_HOME whose session history (`events`) is chmod 0755, GET /api/home
 * carries `openPlaces` naming it by what it holds; after chmod 0700 the next
 * read carries none (no cache: the card goes on the next poll). The answer
 * names places only: never a path, a mode or a byte of a file there (a
 * canary value in a file under `events` and in the symbol database).
 *
 * Axes: display only, no arbiter runs; the file source serves no session
 * and no snapshot, so no axis is read or decided here.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { DashboardServer } from "../../src/server.js";
import { FileEventSource } from "../../src/event-source.js";
import { LOCATION_DESCRIPTIONS } from "../../src/data-locations.js";
import type { HomeVM } from "../../src/view-model/home.js";
import { tmpDir } from "../unit/tmp-dir.js";

const CANARY = "sk-live-canary-open-places-41f9";

const dir = tmpDir("mandu-home-open-places-");
const home = join(dir, "u");
const mandu = join(home, ".mandu");
const sessions = join(dir, "sessions");
mkdirSync(join(mandu, "state"), { recursive: true });
mkdirSync(sessions);
chmodSync(home, 0o700);
chmodSync(mandu, 0o700);
chmodSync(join(mandu, "state"), 0o700);
writeFileSync(join(mandu, "state", "mandu.db"), `${CANARY}\n`, { mode: 0o600 });
mkdirSync(join(mandu, "events"));
writeFileSync(join(mandu, "events", "s1.ndjson"), `{"value":"${CANARY}"}\n`, { mode: 0o600 });

const server = new DashboardServer({ source: new FileEventSource(sessions), configEnv: { HOME: home, MANDU_HOME: mandu }, fileBrowserHome: home, log: () => {} });
after(async () => {
  await server.close();
  rmSync(dir, { recursive: true, force: true });
});

test("GET /api/home lists the session history while others can open it, by what it holds only, and stops on the next read once it is 0700", async () => {
  const base = `http://127.0.0.1:${await server.listen(0)}`;
  const read = async (): Promise<{ vm: HomeVM; raw: string }> => {
    const res = await fetch(`${base}/api/home`);
    assert.equal(res.status, 200);
    const raw = await res.text();
    return { vm: JSON.parse(raw) as HomeVM, raw };
  };

  chmodSync(join(mandu, "events"), 0o755); // the umask must not decide the test
  const loose = await read();
  assert.deepEqual(loose.vm.openPlaces, [{ name: "events", holds: LOCATION_DESCRIPTIONS.events }]);
  const card = JSON.stringify(loose.vm.openPlaces);
  assert.ok(!card.includes(dir) && !card.includes("~/"), "never a path");
  assert.doesNotMatch(card, /0755/, "never a mode");
  assert.ok(!loose.raw.includes(CANARY), "never a byte of a file there");

  chmodSync(join(mandu, "events"), 0o700);
  const tight = await read();
  assert.ok(!("openPlaces" in tight.vm), "owner-only again: none, on the very next read");

  // The symbol database readable by others: listed, the rest still owner-only.
  chmodSync(join(mandu, "state", "mandu.db"), 0o644);
  const db = await read();
  assert.deepEqual(db.vm.openPlaces?.map((p) => p.name), ["symbol-db"]);
  assert.ok(!db.raw.includes(CANARY));
});
