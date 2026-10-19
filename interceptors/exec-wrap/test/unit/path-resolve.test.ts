/**
 * path-resolve.test — the real-command PATH search EXCLUDES the shim dir.
 *
 * This is the anti-recursion guard: when the chokepoint allows a command, it must
 * exec the REAL binary, not its own shim (which would re-invoke the wrapper
 * forever). We stub the executable predicate so no real binary is required.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { findRealCommand, normalizeDir } from "../../src/path-resolve.js";

test("skips the shim dir and returns the next matching PATH entry", () => {
  const shim = "/tmp/mandu-shim.abc";
  // Both the shim dir AND the real dir 'contain' curl per the stub; the search
  // must SKIP the shim and return the real one.
  const found = findRealCommand("curl", {
    path: `${shim}:/usr/bin:/bin`,
    shimDir: shim,
    isExecutable: (p) => p === `${shim}/curl` || p === "/usr/bin/curl",
  });
  assert.equal(found, "/usr/bin/curl");
});

test("returns null if the only candidate is in the shim dir (no real command)", () => {
  const shim = "/tmp/mandu-shim.abc";
  const found = findRealCommand("curl", {
    path: `${shim}:/usr/bin`,
    shimDir: shim,
    isExecutable: (p) => p === `${shim}/curl`, // only the shim has it
  });
  assert.equal(found, null);
});

test("tolerates a trailing slash on the shim dir (normalized comparison)", () => {
  const shim = "/tmp/mandu-shim.abc";
  const found = findRealCommand("wget", {
    path: `${shim}/:/usr/bin`, // PATH lists the shim WITH a trailing slash
    shimDir: shim, // shimDir WITHOUT one
    isExecutable: (p) => p === `${shim}/wget` || p === "/usr/bin/wget",
  });
  assert.equal(found, "/usr/bin/wget");
});

test("a command containing '/' is taken as a path, not a PATH lookup", () => {
  const found = findRealCommand("/opt/custom/nc", {
    path: "/usr/bin",
    shimDir: "/tmp/shim",
    isExecutable: (p) => p === "/opt/custom/nc",
  });
  assert.equal(found, "/opt/custom/nc");
});

test("returns null when nothing on PATH matches", () => {
  const found = findRealCommand("nc", {
    path: "/usr/bin:/bin",
    shimDir: "/tmp/shim",
    isExecutable: () => false,
  });
  assert.equal(found, null);
});

test("normalizeDir strips a single trailing slash but keeps root '/'", () => {
  assert.equal(normalizeDir("/tmp/shim/"), "/tmp/shim");
  assert.equal(normalizeDir("/tmp/shim"), "/tmp/shim");
  assert.equal(normalizeDir("/"), "/");
});
