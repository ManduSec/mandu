/**
 * foreign-home-parity.test — the two halves of runtime-instances.md §13 agree:
 * the launcher's rewrite of a shared-stack autostart under a foreign HOME
 * (launcher/src/arbiter.ts sharedStackHomeEnv) and the arbiter's refusal to
 * promote a foreign-HOME instance at the account's rendezvous
 * (arbiter/ipc/instance.ts foreignHomePromotion), MANDU_HOME included.
 *
 * Over every combination of HOME, MANDU_HOME, an XDG root and the runtime
 * base: the arbiter refuses exactly the envs the launcher rewrites; every
 * rewritten env is one the arbiter promotes; and after the rewrite the Mandu
 * home (the arbiter's stores) never lies inside the foreign HOME. A launch
 * whose rewrite the arbiter still refused would wait for a `current` that
 * never comes; an env the arbiter promotes with its stores in a scratch HOME
 * is the 2026-09-28 incident.
 *
 * Run: npm test  (integration)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";

import { foreignHomePromotion } from "../../arbiter/ipc/instance.js";
import { sharedStackHomeEnv } from "../../launcher/src/arbiter.js";
import { manduPath } from "../../launcher/src/generated/mandu-paths.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // no arbiter process: two pure decisions; stated per the suite rule

const ACCOUNT = { home: "/home/u", rendezvous: "/run/user/1001/mandu" };
const FOREIGN = "/tmp/scratch/home";

const HOMES: (string | undefined)[] = ["/home/u", "/home/u/", FOREIGN, `${FOREIGN}/`, undefined];
const MANDU_HOMES: (string | undefined)[] = [undefined, "", `${FOREIGN}/.mandu`, `${FOREIGN}/x/mh`, "/data/mandu", "/home/u/.mandu", "/tmp/scratch/home-other"];
const XDG_STATE: (string | undefined)[] = [undefined, `${FOREIGN}/.local/state`, "/x/state"];
const BASES = [ACCOUNT.rendezvous, `${ACCOUNT.rendezvous}/`, "/tmp/iso/mandu"];

function envOf(home?: string, manduHome?: string, xdg?: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  if (home !== undefined) env["HOME"] = home;
  if (manduHome !== undefined) env["MANDU_HOME"] = manduHome;
  if (xdg !== undefined) env["XDG_STATE_HOME"] = xdg;
  return env;
}

const inside = (p: string, dir: string): boolean => resolve(p) === resolve(dir) || resolve(p).startsWith(resolve(dir) + "/");

test("the arbiter refuses exactly what the launcher rewrites, and promotes every rewritten env", () => {
  let cases = 0;
  let rewritten = 0;
  for (const home of HOMES) for (const mh of MANDU_HOMES) for (const xdg of XDG_STATE) for (const base of BASES) {
    const env = envOf(home, mh, xdg);
    const label = JSON.stringify({ env, base });
    const rewrite = sharedStackHomeEnv(env, base, ACCOUNT);
    const refusal = foreignHomePromotion(base, env, ACCOUNT);
    assert.equal(refusal !== null, rewrite !== null, `${label}: refusal ${refusal} vs rewrite ${JSON.stringify(rewrite)}`);
    cases++;
    if (rewrite === null) continue;
    rewritten++;
    const after: NodeJS.ProcessEnv = { ...env, ...rewrite.set };
    for (const k of rewrite.unset) delete after[k];
    assert.equal(foreignHomePromotion(base, after, ACCOUNT), null, `${label}: the rewritten env is promoted`);
    assert.equal(after["HOME"], ACCOUNT.home, label);
    const stores = manduPath("mandu-home", after, after["HOME"]!);
    assert.ok(!inside(stores, FOREIGN), `${label}: after the rewrite the Mandu home ${stores} is outside the foreign HOME`);
    // A MANDU_HOME set elsewhere was set on purpose: both sides keep it.
    if (mh && !inside(mh, FOREIGN)) assert.equal(after["MANDU_HOME"], mh, label);
  }
  assert.equal(cases, HOMES.length * MANDU_HOMES.length * XDG_STATE.length * BASES.length);
  assert.ok(rewritten > 20, `the matrix exercises the rewrite (${rewritten} cases)`);
});

test("an account the platform cannot name: neither side guesses", () => {
  for (const mh of MANDU_HOMES) {
    const env = envOf(FOREIGN, mh);
    assert.equal(sharedStackHomeEnv(env, ACCOUNT.rendezvous, null), null);
    assert.equal(foreignHomePromotion(ACCOUNT.rendezvous, env, null), null);
  }
});
