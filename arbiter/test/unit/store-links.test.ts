/**
 * store-links — Mandu's stores of originals must resolve inside its home
 * (confidentiality-plan-14 §11.2 residual (c), db/store-links.ts), over a
 * real filesystem in a temp dir: a store directory swapped for a symlink to
 * a directory outside the home, a symlinked path component, a symlinked or
 * hard-linked symbol DB (or companion) are problems; a relocated home (the
 * home itself a symlink), a link that stays inside the home, missing stores
 * and the config files are not. Axes: none (the layout check runs on every
 * axis; stated for MANDU_AXES_STRICT).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { linkSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { storeLinkProblems, storeLinkRefusal, realStoreLinkFs } from "../../db/store-links.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the layout check is axis-independent; secrets is the default it protects

function world() {
  const root = mkdtempSync(join(tmpdir(), "mdu-store-links-"));
  const home = join(root, "home");
  const mh = join(home, ".mandu");
  mkdirSync(join(mh, "state"), { recursive: true, mode: 0o700 });
  mkdirSync(join(mh, "events"), { recursive: true, mode: 0o700 });
  const outside = join(root, "outside");
  mkdirSync(outside, { recursive: true });
  return { root, home, mh, outside, env: { HOME: home }, done: () => rmSync(root, { recursive: true, force: true }) };
}

test("a sound home has no problem; a missing home has none either", () => {
  const w = world();
  try {
    writeFileSync(join(w.mh, "state", "mandu.db"), "");
    assert.deepEqual(storeLinkProblems(w.env, w.home), []);
    assert.deepEqual(storeLinkProblems({ HOME: join(w.root, "nobody") }, join(w.root, "nobody")), []);
  } finally { w.done(); }
});

test("state/ swapped for a symlink to a directory outside the home is a problem (every original would land there)", () => {
  const w = world();
  try {
    rmSync(join(w.mh, "state"), { recursive: true });
    symlinkSync(w.outside, join(w.mh, "state"));
    writeFileSync(join(w.outside, "mandu.db"), "");
    const p = storeLinkProblems(w.env, w.home);
    assert.ok(p.some((x) => /state resolves to .*outside, outside Mandu's home/.test(x)), p.join("\n"));
    assert.ok(p.some((x) => /mandu\.db lies in .*outside/.test(x)), p.join("\n"));
    assert.match(storeLinkRefusal(p, "refusing to start"), /^refusing to start: Mandu's stores must lie inside its home/);
  } finally { w.done(); }
});

test("events/, a cache dir, or a deeper store swapped for an outside symlink is a problem; a link inside the home is not", () => {
  const w = world();
  try {
    rmSync(join(w.mh, "events"), { recursive: true });
    symlinkSync(w.outside, join(w.mh, "events"));
    mkdirSync(join(w.mh, "cache"), { recursive: true });
    symlinkSync(w.outside, join(w.mh, "cache", "object-twins"));
    const p = storeLinkProblems(w.env, w.home);
    assert.ok(p.some((x) => x.includes(join(w.mh, "events")) && /outside/.test(x)), p.join("\n"));
    assert.ok(p.some((x) => x.includes("object-twins") && /outside/.test(x)), p.join("\n"));
    rmSync(join(w.mh, "events"));
    rmSync(join(w.mh, "cache", "object-twins"));
    mkdirSync(join(w.mh, "elsewhere-inside"), { mode: 0o700 });
    symlinkSync(join(w.mh, "elsewhere-inside"), join(w.mh, "events"));
    assert.deepEqual(storeLinkProblems(w.env, w.home), [], "a link that stays inside the home");
  } finally { w.done(); }
});

test("the symbol DB (or a companion) as a symlink, or with a second hard link, is a problem", () => {
  const w = world();
  try {
    writeFileSync(join(w.outside, "x.db"), "");
    symlinkSync(join(w.outside, "x.db"), join(w.mh, "state", "mandu.db"));
    assert.ok(storeLinkProblems(w.env, w.home).some((x) => /mandu\.db is a symlink/.test(x)));
    rmSync(join(w.mh, "state", "mandu.db"));
    writeFileSync(join(w.mh, "state", "mandu.db"), "");
    linkSync(join(w.mh, "state", "mandu.db"), join(w.outside, "alias.db"));
    assert.ok(storeLinkProblems(w.env, w.home).some((x) => /mandu\.db has 2 hard links/.test(x)));
    rmSync(join(w.outside, "alias.db"));
    symlinkSync(join(w.outside, "x.db"), join(w.mh, "state", "mandu.db-wal"));
    assert.ok(storeLinkProblems(w.env, w.home).some((x) => /mandu\.db-wal is a symlink/.test(x)));
  } finally { w.done(); }
});

test("a relocated home (the home itself a symlink) and config files kept elsewhere are not problems", () => {
  const w = world();
  try {
    const real = join(w.root, "real-mandu");
    mkdirSync(join(real, "state"), { recursive: true });
    writeFileSync(join(real, "state", "mandu.db"), "");
    rmSync(w.mh, { recursive: true });
    symlinkSync(real, w.mh);
    writeFileSync(join(w.outside, "policy.yaml"), "version: 1\n");
    symlinkSync(join(w.outside, "policy.yaml"), join(real, "policy.yaml"));
    assert.deepEqual(storeLinkProblems(w.env, w.home), []);
  } finally { w.done(); }
});

test("an owner other than the user is a problem (the fs seam)", () => {
  const fs = { ...realStoreLinkFs, uid: 4242 };
  const w = world();
  try {
    assert.ok(storeLinkProblems(w.env, w.home, fs).some((x) => /owned by uid \d+, not 4242/.test(x)));
  } finally { w.done(); }
});
