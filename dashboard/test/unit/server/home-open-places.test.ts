/**
 * home-open-places.test — Home warns when other people on this computer can
 * open places in Mandu's folder (dashboard.md §4.25q *Home warns about open
 * places*): the projection (src/data-locations.ts `openPlacesOf` over
 * `buildDataLocations` with a fake `StatFn`) and `buildHome` (GET /api/home)
 * carrying it as `openPlaces`.
 *
 * Pins:
 * - the rule is the fold's note's: a place in Mandu's folder that is there
 *   and whose mode lets group or others in; owner-only places, missing
 *   places and places outside the folder are never listed; a developer
 *   store counts, as the note counts it;
 * - each listed place carries its name and its `holds` words only, never a
 *   path or a mode;
 * - buildHome sets `openPlaces` only when some place is open; none open, no
 *   reader (a test seam) or a reader that throws: no field.
 *
 * Axes: no arbiter answers, so nothing is masked or decided here; `secrets`
 * is the configured mode the hero reads (the default, no config file).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { buildDataLocations, LOCATION_DESCRIPTIONS, openPlacesOf, type StatFn } from "../../../src/data-locations.js";
import { manduPath, type ManduPathEnv, type ManduPathName } from "../../../src/generated/mandu-paths.js";
import { buildHome, HomeFacts, type HomeDeps } from "../../../src/server/home-routes.js";
import type { EventSource } from "../../../src/event-source.js";

const HOME = "/home/u";
const ENV = { HOME };

/** A filesystem where each named place is there with its mode; the rest of
 *  Mandu's folder and state at 0700 when `base` is true; anything else absent. */
function fakeStat(modes: Partial<Record<ManduPathName, number>>, base = true): StatFn {
  const at = new Map<string, number>();
  if (base) for (const name of ["mandu-home", "state-root"] as ManduPathName[]) at.set(manduPath(name, ENV as ManduPathEnv, HOME), 0o040700);
  for (const [name, mode] of Object.entries(modes)) at.set(manduPath(name as ManduPathName, ENV as ManduPathEnv, HOME), mode!);
  return (p) => (at.has(p) ? { mode: at.get(p)! } : null);
}
const open = (modes: Partial<Record<ManduPathName, number>>) => openPlacesOf(buildDataLocations(ENV, HOME, fakeStat(modes), () => false));

test("openPlacesOf: owner-only places list none", () => {
  assert.deepEqual(open({ "symbol-db": 0o100600, events: 0o040700, policy: 0o100600 }), []);
});

test("openPlacesOf: the session history at 0755 is listed by its name and what it holds, never its path or mode", () => {
  const places = open({ "symbol-db": 0o100600, events: 0o040755 });
  assert.deepEqual(places, [{ name: "events", holds: LOCATION_DESCRIPTIONS.events }]);
  assert.match(places[0]!.holds, /real values behind masked ones/);
  assert.doesNotMatch(JSON.stringify(places), /\/home\/u|~|0755/);
});

test("openPlacesOf: a developer store at 0755 is listed, as the fold's note counts it; group-readable alone counts too", () => {
  assert.deepEqual(open({ "docker-e2e-home": 0o040755 }).map((p) => p.name), ["docker-e2e-home"]);
  assert.deepEqual(open({ "symbol-db": 0o100640 }).map((p) => p.name), ["symbol-db"], "group bits alone let others in");
  // Several: in the table's order.
  assert.deepEqual(open({ events: 0o040755, "symbol-db": 0o100644, "mandu-home": 0o040755 }).map((p) => p.name), ["mandu-home", "symbol-db", "events"]);
});

test("openPlacesOf: a missing place is never listed; nor a place outside Mandu's folder", () => {
  // Nothing there at all, not even the folder.
  assert.deepEqual(openPlacesOf(buildDataLocations(ENV, HOME, fakeStat({}, false), () => false)), []);
  // A dangling symlink has no mode: there, but nothing to warn about.
  const sym = manduPath("events", ENV as ManduPathEnv, HOME);
  assert.deepEqual(openPlacesOf(buildDataLocations(ENV, HOME, fakeStat({}), (p) => p === sym)), []);
  // The install dir at 0755 is outside the folder (no owner-only verdict).
  const prefix = manduPath("install-prefix", ENV as ManduPathEnv, HOME);
  const outside: StatFn = (p) => (p === prefix ? { mode: 0o040755 } : null);
  assert.deepEqual(openPlacesOf(buildDataLocations(ENV, HOME, outside, () => false)), []);
});

function deps(openPlaces?: HomeDeps["openPlaces"]): HomeDeps {
  // No arbiter and Mandu not running: buildHome answers the "off" page
  // (home-not-running.test.ts), enough to carry the card's field.
  const source = {
    listSessions: async () => { throw new Error("connect ENOENT"); },
    policySnapshot: async () => { throw new Error("connect ENOENT"); },
  } as unknown as EventSource;
  return {
    source,
    facts: new HomeFacts(source, HOME),
    approvals: undefined,
    testRuns: [],
    watchRuns: [],
    env: { MANDU_HOME: "/nonexistent/mandu-home-open-places" },
    home: HOME,
    notRunning: () => ({ everRan: false }),
    ...(openPlaces ? { openPlaces } : {}),
  };
}

test("buildHome: openPlaces carries the open places; none open, no reader or a reader that throws: no field", async () => {
  const listed = [{ name: "symbol-db" as const, holds: LOCATION_DESCRIPTIONS["symbol-db"] }];
  const vm = await buildHome(deps(() => listed));
  assert.deepEqual(vm.openPlaces, listed);
  for (const [why, reader] of [["none open", () => []], ["no reader", undefined], ["a reader that throws", () => { throw new Error("EACCES"); }]] as const) {
    const quiet = await buildHome(deps(reader as HomeDeps["openPlaces"]));
    assert.ok(!("openPlaces" in quiet), why);
  }
});
