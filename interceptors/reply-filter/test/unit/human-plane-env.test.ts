/**
 * human-plane-env — the reply filter's reach to the arbiter's HUMAN plane
 * (docs/design/architecture/arbiter-human-plane.md), the pure half:
 *   - humanSockFromEnv reads ONLY $MANDU_ARBITER_HUMAN_SOCK — a set data
 *     socket ($MANDU_ARBITER_SOCK) is never a fallback;
 *   - childEnv drops the human-plane socket from the agent's env and keeps
 *     everything else (the data socket included: the agent's own tools use it).
 * Mandu-new (no reference origin). No arbiter is built here.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { childEnv, humanSockFromEnv, HUMAN_SOCK_ENV } from "../../src/arbiter-client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // pure env logic; states its axes (protection-modes.md §4)

test("humanSockFromEnv: the human socket when set, null otherwise — never the data socket", () => {
  assert.equal(HUMAN_SOCK_ENV, "MANDU_ARBITER_HUMAN_SOCK");
  assert.equal(humanSockFromEnv({ MANDU_ARBITER_HUMAN_SOCK: "/run/h/x.sock" }), "/run/h/x.sock");
  assert.equal(humanSockFromEnv({}), null);
  assert.equal(humanSockFromEnv({ MANDU_ARBITER_HUMAN_SOCK: "" }), null, "empty is unset");
  assert.equal(
    humanSockFromEnv({ MANDU_ARBITER_SOCK: "/run/data.sock" }),
    null,
    "a data socket alone names no human plane",
  );
});

test("childEnv: the agent's env loses MANDU_ARBITER_HUMAN_SOCK and keeps the rest", () => {
  const parent = {
    MANDU_ARBITER_HUMAN_SOCK: "/run/h/x.sock",
    MANDU_ARBITER_SOCK: "/run/data.sock",
    PATH: "/usr/bin",
    MANDU_SCOPE_ID: "s1",
  };
  const env = childEnv(parent);
  assert.equal(HUMAN_SOCK_ENV in env, false);
  assert.equal(env.MANDU_ARBITER_SOCK, "/run/data.sock");
  assert.equal(env.PATH, "/usr/bin");
  assert.equal(env.MANDU_SCOPE_ID, "s1");
  assert.equal(parent.MANDU_ARBITER_HUMAN_SOCK, "/run/h/x.sock", "the wrapper's own env is not mutated");
});
