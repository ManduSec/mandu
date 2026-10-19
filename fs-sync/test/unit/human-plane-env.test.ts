/**
 * human-plane-env — fs-sync reaches the arbiter only over its HUMAN plane
 * (docs/design/architecture/arbiter-human-plane.md): humanSockFromEnv reads ONLY
 * $MANDU_ARBITER_HUMAN_SOCK, so a set data socket ($MANDU_ARBITER_SOCK) is
 * never a fallback. Mandu-new (no reference origin). No arbiter is built here.
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";

import { HUMAN_SOCK_ENV, humanSockFromEnv } from "../../src/arbiter-client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // pure env logic; states its axes (protection-modes.md §4)

test("humanSockFromEnv: the human socket when set; null otherwise — never the data socket", () => {
  assert.equal(HUMAN_SOCK_ENV, "MANDU_ARBITER_HUMAN_SOCK");
  assert.equal(humanSockFromEnv({ MANDU_ARBITER_HUMAN_SOCK: "/run/mandu/human/x.sock" }), "/run/mandu/human/x.sock");
  assert.equal(humanSockFromEnv({}), null);
  assert.equal(humanSockFromEnv({ MANDU_ARBITER_HUMAN_SOCK: "" }), null);
  assert.equal(humanSockFromEnv({ MANDU_ARBITER_SOCK: "/run/mandu/current/arbiter.sock" }), null);
});
