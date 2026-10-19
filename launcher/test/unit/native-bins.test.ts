/**
 * native-bins.test — resolveNativeBin's order: env override → target/release →
 * target/debug → PATH → null (docs/design/integrity/exec-routing.md §7).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildHintFor,
  defaultRepoRoot,
  installedNativeDir,
  isInstalledLayout,
  shippedNativeTags,
  NATIVE_BIN_BUILD_HINT,
  nativeBinBuildHint,
  nativeBinsExistFor,
  nativePlatformTag,
  resolveNativeBin,
} from "../../src/services/native-bins.js";
import { tmpDir } from "../lib/tmp-dir.js";

function repo(): string {
  const root = mkdtempSync(join(tmpdir(), "native-bins-"));
  mkdirSync(join(root, "interceptors", "target", "release"), { recursive: true });
  mkdirSync(join(root, "interceptors", "target", "debug"), { recursive: true });
  return root;
}
const touch = (p: string): string => { writeFileSync(p, "#!/bin/sh\n"); return p; };

test("null when nothing is built and no override/PATH match", () => {
  const root = repo();
  assert.equal(resolveNativeBin("mandu-exec-box", { repoRoot: root, env: { PATH: "" } }), null);
  rmSync(root, { recursive: true, force: true });
});

test("the installed package's prebuilt bin (dist/native/<tag>) wins over the checkout's target/ and PATH; absent dir → the old order", () => {
  const root = repo();
  const rel = touch(join(root, "interceptors", "target", "release", "mandu-net-guard"));
  const inst = join(root, "dist", "native", "linux-x64");
  mkdirSync(inst, { recursive: true });
  const bundled = touch(join(inst, "mandu-net-guard"));
  assert.equal(resolveNativeBin("mandu-net-guard", { repoRoot: root, env: { PATH: "" }, installedDir: inst }), bundled);
  assert.equal(resolveNativeBin("mandu-net-guard", { repoRoot: root, env: { PATH: "" }, installedDir: null }), rel);
  // a bin the package does not ship falls through to the checkout / PATH order
  assert.equal(resolveNativeBin("mandu-exec-box", { repoRoot: root, env: { PATH: "" }, installedDir: inst }), null);
  // the env override still wins over the bundled bin
  const ovr = touch(join(root, "override-guard"));
  assert.equal(resolveNativeBin("mandu-net-guard", { repoRoot: root, env: { PATH: "", MANDU_NET_GUARD_BIN: ovr }, installedDir: inst }), ovr);
  rmSync(root, { recursive: true, force: true });
});

test("installedNativeDir / isInstalledLayout: only a module under dist/ has a native dir; the hint names the package gap there, cargo in a checkout", () => {
  assert.equal(isInstalledLayout("/opt/mandu/dist"), true);
  assert.equal(isInstalledLayout("/repo/launcher/src/services"), false);
  assert.equal(installedNativeDir("/opt/mandu/dist", "linux-x64"), "/opt/mandu/dist/native/linux-x64");
  assert.equal(installedNativeDir("/repo/launcher/src/services", "linux-x64"), null);
  assert.equal(nativePlatformTag("linux", "x64"), "linux-x64");
  // Pinned to linux: the hints are platform-aware (macOS has no native bins).
  assert.match(buildHintFor("mandu-net-guard", false, [], "linux"), /^build with: cd interceptors && cargo build -p net-supervisor/);
  const installedHint = buildHintFor("mandu-net-guard", true, ["linux-arm64", "linux-x64"], "linux");
  assert.match(installedHint, /this @mandusec\/mandu package has no prebuilt mandu-net-guard/);
  assert.match(installedHint, /ships it for linux-arm64, linux-x64/);
  assert.match(buildHintFor("mandu-net-guard", true, [], "linux"), /packed without native bins/);
  assert.match(nativeBinBuildHint(true, [], "linux"), /no prebuilt native bins/);
  assert.equal(nativeBinBuildHint(false, [], "linux"), NATIVE_BIN_BUILD_HINT);
});

test("on macOS the hints say Linux only and name the Seatbelt profile: never a cargo line, from a checkout or the package", () => {
  assert.equal(nativeBinsExistFor("linux"), true);
  assert.equal(nativeBinsExistFor("darwin"), false);
  assert.equal(nativeBinsExistFor("win32"), false);
  for (const installed of [false, true]) {
    const all = nativeBinBuildHint(installed, ["linux-arm64", "linux-x64"], "darwin");
    assert.match(all, /^the native bins are Linux only/);
    assert.match(all, /Seatbelt profile \(sandbox-exec\)/);
    assert.doesNotMatch(all, /cargo|build with|source checkout builds|darwin-/);
    const one = buildHintFor("mandu-exec-box", installed, [], "darwin");
    assert.match(one, /^mandu-exec-box is Linux only/);
    assert.doesNotMatch(one, /cargo|build with/);
  }
  // another non-Linux platform: Linux only, no Seatbelt claim, no cargo line
  const win = nativeBinBuildHint(false, [], "win32");
  assert.match(win, /Linux only/);
  assert.doesNotMatch(win, /Seatbelt|cargo/);
});

test("release wins over debug", () => {
  const root = repo();
  const rel = touch(join(root, "interceptors", "target", "release", "mandu-exec-box"));
  touch(join(root, "interceptors", "target", "debug", "mandu-exec-box"));
  assert.equal(resolveNativeBin("mandu-exec-box", { repoRoot: root, env: { PATH: "" } }), rel);
  rmSync(root, { recursive: true, force: true });
});

test("debug used when release is absent", () => {
  const root = repo();
  const dbg = touch(join(root, "interceptors", "target", "debug", "mandu-landlock-apply"));
  assert.equal(resolveNativeBin("mandu-landlock-apply", { repoRoot: root, env: { PATH: "" } }), dbg);
  rmSync(root, { recursive: true, force: true });
});

test("env override wins over the built artifacts (per-bin var)", () => {
  const root = repo();
  touch(join(root, "interceptors", "target", "release", "mandu-exec-box"));
  const over = touch(join(root, "my-exec-box"));
  assert.equal(
    resolveNativeBin("mandu-exec-box", { repoRoot: root, env: { MANDU_EXEC_BOX_BIN: over, PATH: "" } }),
    over,
  );
  // the landlock var is independent.
  const overLl = touch(join(root, "my-apply"));
  assert.equal(
    resolveNativeBin("mandu-landlock-apply", { repoRoot: root, env: { MANDU_LANDLOCK_APPLY: overLl, PATH: "" } }),
    overLl,
  );
  rmSync(root, { recursive: true, force: true });
});

test("a set-but-missing override falls through to the built artifact", () => {
  const root = repo();
  const dbg = touch(join(root, "interceptors", "target", "debug", "mandu-exec-box"));
  assert.equal(
    resolveNativeBin("mandu-exec-box", { repoRoot: root, env: { MANDU_EXEC_BOX_BIN: "/nope/missing", PATH: "" } }),
    dbg,
  );
  rmSync(root, { recursive: true, force: true });
});

test("PATH lookup as the last resort", () => {
  const root = repo(); // nothing under target/
  const bindir = mkdtempSync(join(tmpdir(), "path-"));
  const onPath = touch(join(bindir, "mandu-exec-box"));
  assert.equal(resolveNativeBin("mandu-exec-box", { repoRoot: root, env: { PATH: `/nonexistent:${bindir}` } }), onPath);
  rmSync(root, { recursive: true, force: true });
  rmSync(bindir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Freshness (2026-09-17): a bin older than the source it was built from is
// reported STALE via cargo's own `<bin>.d` dep-info; anything unjudgeable is
// null (never a false alarm). The failure this guards: a fixed sandbox.rs +
// a never-rebuilt target/debug bin looked healthy at launch and failed every
// boxed command for a whole session.
import { utimesSync } from "node:fs";
import {
  nativeBinStaleness, parseDepInfoSources, staleNativeBinNote,
} from "../../src/services/native-bins.js";

const at = (p: string, secondsAgo: number): void => {
  const t = new Date(Date.now() - secondsAgo * 1000);
  utimesSync(p, t, t);
};

test("parseDepInfoSources: cargo's one-line `<bin>: a b c` form, escaped spaces, garbage → []", () => {
  assert.deepEqual(parseDepInfoSources("/t/debug/x: /s/a.rs /s/b.rs\n"), ["/s/a.rs", "/s/b.rs"]);
  assert.deepEqual(parseDepInfoSources("/t/x: /s/with\\ space.rs /s/c.rs"), ["/s/with space.rs", "/s/c.rs"]);
  assert.deepEqual(parseDepInfoSources("/t/x:"), []);
  assert.deepEqual(parseDepInfoSources(""), []);
  assert.deepEqual(parseDepInfoSources("no colon here"), []);
});

test("stale: a source newer than the bin names that source", () => {
  const root = repo();
  const bin = touch(join(root, "interceptors", "target", "debug", "mandu-exec-box"));
  const old = touch(join(root, "old.rs")), fresh = touch(join(root, "sandbox.rs"));
  writeFileSync(`${bin}.d`, `${bin}: ${old} ${fresh}\n`);
  at(old, 3000); at(bin, 2000); at(fresh, 1000);
  const s = nativeBinStaleness(bin);
  assert.ok(s, "stale");
  assert.equal(s!.newestSource, fresh);
  assert.equal(s!.sources, 2);
  assert.ok(s!.newestSourceMtimeMs > s!.binMtimeMs);
  const note = staleNativeBinNote("mandu-exec-box", bin)!;
  assert.match(note, /WARNING/);
  assert.match(note, /is STALE/);
  assert.ok(note.includes(fresh), "names the newer source");
  assert.match(note, /cargo build -p exec-supervisor --features kernel --bins/);
  rmSync(root, { recursive: true, force: true });
});

test("fresh: bin newer than every source → null (no note)", () => {
  const root = repo();
  const bin = touch(join(root, "interceptors", "target", "debug", "mandu-net-guard"));
  const a = touch(join(root, "a.rs"));
  writeFileSync(`${bin}.d`, `${bin}: ${a}\n`);
  at(a, 2000); at(bin, 1000);
  assert.equal(nativeBinStaleness(bin), null);
  assert.equal(staleNativeBinNote("mandu-net-guard", bin), null);
  rmSync(root, { recursive: true, force: true });
});

test("unjudgeable is never stale: no .d beside the bin, or every source gone", () => {
  const root = repo();
  const bare = touch(join(root, "on-path-bin"));
  assert.equal(nativeBinStaleness(bare), null, "no dep-info → unknown → null");
  const bin = touch(join(root, "interceptors", "target", "release", "mandu-landlock-apply"));
  writeFileSync(`${bin}.d`, `${bin}: ${join(root, "moved-away.rs")}\n`);
  assert.equal(nativeBinStaleness(bin), null, "no surviving source → null");
  // A deleted source alongside a surviving older one: still fresh.
  const a = touch(join(root, "a.rs"));
  writeFileSync(`${bin}.d`, `${bin}: ${join(root, "gone.rs")} ${a}\n`);
  at(a, 2000); at(bin, 1000);
  assert.equal(nativeBinStaleness(bin), null);
  // Injected probes (the setups' unit tests use the same seam).
  assert.equal(nativeBinStaleness("/x/bin", { readFile: () => "/x/bin: /x/s.rs", mtimeMs: () => null }), null);
  const s = nativeBinStaleness("/x/bin", {
    readFile: () => "/x/bin: /x/s.rs",
    mtimeMs: (p) => (p === "/x/bin" ? 1000 : 2000),
  });
  assert.equal(s?.newestSource, "/x/s.rs");
  rmSync(root, { recursive: true, force: true });
});

test("shippedNativeTags: the installed package's dist/native/<tag> dirs, sorted; [] in a checkout or with no native dir", () => {
  const root = tmpDir("native-tags-");
  const dist = join(root, "dist");
  mkdirSync(join(dist, "native", "linux-x64"), { recursive: true });
  mkdirSync(join(dist, "native", "linux-arm64"), { recursive: true });
  assert.deepEqual(shippedNativeTags(dist), ["linux-arm64", "linux-x64"]);
  assert.match(nativeBinBuildHint(true, shippedNativeTags(dist), "linux"), /ships them for linux-arm64, linux-x64/);
  // a checkout is never "installed", whatever sits beside it
  assert.deepEqual(shippedNativeTags(join(root, "src")), []);
  // an installed layout packed without bins
  const bare = join(tmpDir("native-tags-"), "dist");
  mkdirSync(bare);
  assert.deepEqual(shippedNativeTags(bare), []);
  rmSync(root, { recursive: true, force: true });
});

test("a checkout's own launcher/dist is not an installed layout: its native bins keep coming from interceptors/target (packaging.md §5.1)", () => {
  const checkout = (p: string) => p === "/repo/launcher/src/run.ts";
  assert.equal(isInstalledLayout("/repo/launcher/dist", checkout), false, "dist/ beside src/run.ts");
  assert.equal(isInstalledLayout("/opt/mandu/dist", checkout), true, "an installed dist has no src/");
  // The repo root from where this module runs: src/services (source) or dist (bundle).
  assert.equal(defaultRepoRoot("/repo/launcher/src/services"), "/repo");
  assert.equal(defaultRepoRoot("/repo/launcher/dist"), "/repo");
});
