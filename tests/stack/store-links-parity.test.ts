/**
 * Parity — the store-link rule (confidentiality-plan-14 §11.2 residual (c))
 * lives twice by the standalone-package policy: the arbiter's daemon refuses
 * to start (arbiter/db/store-links.ts) and the launcher refuses a protecting
 * launch (launcher/src/store-links.ts). Both must name the same stores and
 * find the same problems, or one would let through what the other refuses.
 * Axes: secrets (the rule protects that mode's stores).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { linkSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as arbiter from "../../arbiter/db/store-links.js";
import * as launcher from "../../launcher/src/store-links.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets");

test("parity: the arbiter's and the launcher's store-link rules name the same stores and find the same problems", () => {
  assert.deepEqual([...launcher.STORE_DIRS], [...arbiter.STORE_DIRS]);
  assert.deepEqual([...launcher.STORE_FILES], [...arbiter.STORE_FILES]);
  const root = mkdtempSync(join(tmpdir(), "mdu-store-links-parity-"));
  try {
    const home = join(root, "h");
    const mh = join(home, ".mandu");
    const planted = join(root, "planted");
    mkdirSync(join(mh, "state"), { recursive: true });
    mkdirSync(join(mh, "cache"), { recursive: true });
    mkdirSync(planted);
    symlinkSync(planted, join(mh, "events"));
    symlinkSync(planted, join(mh, "cache", "object-twins"));
    writeFileSync(join(mh, "state", "mandu.db"), "");
    linkSync(join(mh, "state", "mandu.db"), join(planted, "alias.db"));
    const a = arbiter.storeLinkProblems({ HOME: home }, home);
    const l = launcher.storeLinkProblems({ HOME: home }, home);
    assert.equal(a.length, 3, a.join("\n"));
    assert.deepEqual(l, a);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
