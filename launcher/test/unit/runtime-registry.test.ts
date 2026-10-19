/**
 * runtime-registry.test — Mandu's runtime registry entries (runtime-registry.ts;
 * runtime-instances.md §2): the one list the macOS profile write-denies and
 * that no scope id may name.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { RUNTIME_REGISTRY, runtimeRegistryPaths, scopeIdProblem } from "../../src/runtime-registry.js";
import { runtimeRegistryPaths as fromSetup } from "../../src/seatbelt-setup.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // pure lists; the profile they feed is the secrets-mode enactment

test("runtimeRegistryPaths: every entry an unconfined Mandu process reads, writes through or deletes from, dashboard.log and dashboard-<pid>.port(.tmp) included", () => {
  assert.deepEqual(runtimeRegistryPaths("/tmp/mandu-501/"), {
    dirs: ["/tmp/mandu-501/dashboards", "/tmp/mandu-501/instances", "/tmp/mandu-501/logs", "/tmp/mandu-501/release-check", "/tmp/mandu-501/test", "/tmp/mandu-501/vm-guests"],
    names: ["/tmp/mandu-501/arbiter.sock", "/tmp/mandu-501/current", "/tmp/mandu-501/dashboard.log"],
    prefixes: ["/tmp/mandu-501/.current.tmp-", "/tmp/mandu-501/dashboard-"],
  });
  for (const bad of ["", "rel/mandu", "/"]) assert.deepEqual(runtimeRegistryPaths(bad), { dirs: [], names: [], prefixes: [] }, JSON.stringify(bad));
  assert.equal(fromSetup, runtimeRegistryPaths, "seatbelt-setup re-exports the same function");
  // Each entry is one component directly in the base.
  for (const n of [...RUNTIME_REGISTRY.dirs, ...RUNTIME_REGISTRY.names, ...RUNTIME_REGISTRY.prefixes]) assert.ok(!n.includes("/") && n !== "", n);
});

test("scopeIdProblem: one folder name that is none of the registry's entries, the human plane's dir, or a name its prefixes cover", () => {
  for (const ok of ["s1", "named-scope", "1790000000-4242", "instances.old", "logs2", "current-x", ".current.tmpX", "humans"]) {
    assert.equal(scopeIdProblem(ok), null, ok);
  }
  const why = (id: string): string => scopeIdProblem(id) ?? "";
  assert.match(why(""), /empty/);
  for (const id of ["a/b", "instances/x", "/x", "x/"]) assert.match(why(id), /holds a `\/`/, id);
  assert.match(why("x\0y"), /NUL/);
  for (const id of [".", ".."]) assert.match(why(id), /not a folder name/, id);
  for (const id of ["instances", "current", "arbiter.sock", "dashboards", "dashboard.log", "vm-guests", "logs", "test", "human", "release-check", "Release-Check"]) {
    assert.match(why(id), /one of Mandu's own entries in the runtime folder/, id);
  }
  assert.match(why(".current.tmp-99"), /starting `\.current\.tmp-`/);
  assert.match(why("dashboard-4242.port"), /starting `dashboard-`/);
  assert.match(why("dashboardX"), /starting `dashboard`/);
  // Case and Unicode are folded (the default macOS volume, and Seatbelt's
  // match there, treat `Instances` as `instances`), on every platform.
  for (const id of ["Instances", "HUMAN", "Current", "Logs", "Dashboards", "ARBITER.SOCK", "teſt"]) {
    assert.match(why(id), /one of Mandu's own entries in the runtime folder \(the match ignores case\)/, id);
  }
  assert.match(why("Dashboard-x"), /starting `dashboard-`/);
  assert.match(why(".CURRENT.TMP-1"), /starting `\.current\.tmp-`/);
});
