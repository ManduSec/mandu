/**
 * shown — the placeholders the relay has shown the agent (shown.ts;
 * devtools-relay.md §3.2, *A placeholder that names nothing*): remembered
 * most recent last, at most MAX_SHOWN, and the nearest to a mistyped one
 * first (secrets axes, explicit: no arbiter here).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { stateAxes } from "../axes.js";
import { MAX_HINTS, MAX_SHOWN, ShownPlaceholders, editDistance } from "../../src/shown.js";

stateAxes("secrets");

const KEY = "$MDU:nomodel_Read[062f].STRIPE_SECRET_KEY";
const HOOK = "$MDU:nomodel_Read[062f].WEBHOOK_SIGNING_SECRET";
const OTHER = "$MDU:nomodel_Env[9a1c]";

test("editDistance: character edits", () => {
  assert.equal(editDistance("", ""), 0);
  assert.equal(editDistance("abc", "abc"), 0);
  assert.equal(editDistance("abc", "abd"), 1);
  assert.equal(editDistance("abc", "ab"), 1);
  assert.equal(editDistance("", "abc"), 3);
  assert.equal(editDistance("kitten", "sitting"), 3);
});

test("nearest: the closest first, the more recent on a tie, never the token itself", () => {
  const s = new ShownPlaceholders();
  s.add([KEY, HOOK]);
  s.add([OTHER]);
  const typo = "$MDU:nomodel_Read[062e].STRIPE_SECRET_KEY";
  assert.deepEqual(s.nearest(typo), [KEY, HOOK, OTHER]);
  assert.deepEqual(s.nearest(typo, 1), [KEY]);
  assert.deepEqual(s.nearest(KEY), [HOOK, OTHER], "the token itself is not a hint");
  const t = new ShownPlaceholders();
  t.add(["$MDU:a[0001]", "$MDU:a[0002]"]);
  assert.deepEqual(t.nearest("$MDU:a[0000]"), ["$MDU:a[0002]", "$MDU:a[0001]"], "a tie goes to the last shown");
  assert.deepEqual(new ShownPlaceholders().nearest(typo), [], "none shown, none named");
});

test("a placeholder shown again moves to the most recent; the oldest go past MAX_SHOWN; at most MAX_HINTS named", () => {
  const s = new ShownPlaceholders();
  const many = Array.from({ length: MAX_SHOWN + 10 }, (_, i) => `$MDU:k[${i.toString(16).padStart(4, "0")}]`);
  s.add(many);
  assert.equal(s.size, MAX_SHOWN);
  assert.ok(!s.nearest("$MDU:k[0000]", MAX_SHOWN).includes("$MDU:k[0000]"), "the oldest forgotten");
  assert.equal(s.nearest("$MDU:k[ffff]").length, MAX_HINTS);
  s.add([many[20]!]);
  s.add(["$MDU:z[0000]"]);
  assert.equal(s.size, MAX_SHOWN);
  assert.ok(s.nearest("$MDU:k[0014].X", MAX_SHOWN).includes(many[20]!), "kept: it was shown again");
});
