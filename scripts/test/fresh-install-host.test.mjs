// fresh-install-host.test.mjs — the fresh-install VM suite's host prep
// (scripts/matrix/suites/fresh-install.host.sh; docs/design/testing/os-test-matrix.md
// §10.3.2) packs from a CLEAN checkout, the way the release tag's `install`
// job runs it: it installs every package the launcher's bundle build reads
// (scripts/install-deps.mjs --bundle; v0.2.0-beta.8's job failed "Could not
// resolve js-yaml" in the developer view, which no hand-kept list installed),
// builds the native bins with the CI pin's Rust (a clean checkout has no
// target/, and a bundle without them is not the `confined` one the targets
// declare), and lets a failed pack say why (npm --loglevel=error, not --silent).
//
// The host script runs in a throwaway tree: the real script and its Rust
// helper, with install-deps, build-native, npm, rustup and cargo stubbed
// (each logs its call; nothing is installed, built or packed).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const PIN = /^RUST_VERSION=(.+)$/m.exec(readFileSync(join(REPO, "scripts", "ci", "pins.env"), "utf8"))[1];

/** A tree holding the host script and what it runs; `cargo: false` leaves
 *  cargo and rustup off PATH, `installFails` makes install-deps fail. */
function tree({ cargo = true, installFails = false } = {}) {
  const t = mkdtempSync(join(tmpdir(), "fresh-install-host-"));
  const log = join(t, "calls.log");
  const put = (rel, text, mode) => {
    mkdirSync(dirname(join(t, rel)), { recursive: true });
    writeFileSync(join(t, rel), text);
    if (mode) chmodSync(join(t, rel), mode);
  };
  const copy = (rel) => { mkdirSync(dirname(join(t, rel)), { recursive: true }); copyFileSync(join(REPO, rel), join(t, rel)); };
  copy("scripts/matrix/suites/fresh-install.host.sh");
  copy("scripts/matrix/lib/rust-toolchain.sh");
  copy("scripts/ci/pins.env");
  put("scripts/matrix/suites/fresh-install/stub-claude.sh", "#!/bin/sh\n");
  put("scripts/install-deps.mjs", `import { appendFileSync } from "node:fs"; appendFileSync(${JSON.stringify(log)}, "install-deps " + process.argv.slice(2).join(" ") + "\\n"); process.exit(${installFails ? 1 : 0});\n`);
  put("scripts/build-native.sh", `#!/bin/sh\necho "build-native RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN" >> ${JSON.stringify(log)}\n`, 0o755);
  mkdirSync(join(t, "launcher"));
  put("bin/npm", `#!/bin/sh\necho "npm $*" >> ${JSON.stringify(log)}\n: > "$ARTIFACT_DIR/mandusec-mandu-0.0.0.tgz"\n`, 0o755);
  symlinkSync(process.execPath, join(t, "bin", "node"));
  if (cargo) {
    put("bin/rustup", `#!/bin/sh\n[ "$1 $2" = "toolchain list" ] && echo "${PIN}-x86_64-unknown-linux-gnu"\nexit 0\n`, 0o755);
    put("bin/cargo", "#!/bin/sh\necho cargo-stub\n", 0o755);
  }
  mkdirSync(join(t, "art"));
  return { t, log };
}

/** PATH: the tree's stubs, then the system's, minus any dir holding a cargo or rustup. */
function pathFor(t) {
  const sys = (process.env.PATH ?? "").split(delimiter).filter((d) => d && !existsSync(join(d, "cargo")) && !existsSync(join(d, "rustup")));
  return [join(t, "bin"), ...sys].join(delimiter);
}

function prep(t, env = {}) {
  return spawnSync("bash", [join(t, "scripts/matrix/suites/fresh-install.host.sh")], {
    encoding: "utf8",
    env: { ...process.env, PATH: pathFor(t), ARTIFACT_DIR: join(t, "art"), REPO_ROOT: t, FRESH_INSTALL_LIVE: "0", MANDU_NATIVE_BIN_DIR: "", ...env },
  });
}

const calls = (log) => (existsSync(log) ? readFileSync(log, "utf8").trim().split("\n") : []);

test("a clean checkout: the bundle's packages installed, the native bins built under the CI Rust pin, then the pack", () => {
  const { t, log } = tree();
  try {
    const r = prep(t);
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(calls(log), [
      "install-deps --bundle",
      `build-native RUSTUP_TOOLCHAIN=${PIN}`,
      `npm pack --loglevel=error --pack-destination ${join(t, "art")}`,
    ]);
    assert.ok(existsSync(join(t, "art", "claude")) && existsSync(join(t, "art", "COMMIT")), "the stub agent and the commit are in the artifacts");
  } finally {
    rmSync(t, { recursive: true, force: true });
  }
});

test("MANDU_NATIVE_BIN_DIR set by the caller: those bins are packed as they are, nothing is built", () => {
  const { t, log } = tree();
  try {
    const r = prep(t, { MANDU_NATIVE_BIN_DIR: join(t, "elsewhere") });
    assert.equal(r.status, 0, r.stderr);
    assert.ok(!calls(log).some((c) => c.startsWith("build-native")), calls(log).join("\n"));
    assert.ok(calls(log).includes("install-deps --bundle"));
  } finally {
    rmSync(t, { recursive: true, force: true });
  }
});

test("no cargo on PATH: a note, no build, the pack still runs (the target's fresh-posture label judges the bundle)", () => {
  const { t, log } = tree({ cargo: false });
  try {
    const r = prep(t);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stderr, /no cargo on PATH; packing with whatever native bins/);
    assert.deepEqual(calls(log).map((c) => c.split(" ")[0]), ["install-deps", "npm"]);
  } finally {
    rmSync(t, { recursive: true, force: true });
  }
});

test("a failed install of the bundle's packages fails the prep before any build or pack", () => {
  const { t, log } = tree({ installFails: true });
  try {
    const r = prep(t);
    assert.notEqual(r.status, 0);
    assert.deepEqual(calls(log), ["install-deps --bundle"]);
  } finally {
    rmSync(t, { recursive: true, force: true });
  }
});
