/**
 * install-sh — scripts/install.sh, the `curl | sh` installer
 * (packaging.md §3, comparisons.md §3.1), driven offline: a stub `node`
 * on PATH decides the Node branch, and a file:// Node mirror (a stub Node
 * tarball + a real SHASUMS256.txt) exercises the download, the checksum and
 * the wrapper without the network. The real package is installed by the e2e
 * (test/component/install-sh.test.ts).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpDir } from "../lib/tmp-dir.js";

const INSTALL = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "scripts", "install.sh");
const OS = process.platform === "darwin" ? "darwin" : "linux";
const ARCH = process.arch === "arm64" ? "arm64" : "x64";
const TOOLS = ["sh", "awk", "sed", "tar", "gzip", "mkdir", "rm", "mktemp", "dirname", "uname", "id", "chmod", "cat", "env", "sha256sum", "shasum", "curl", "wget", "printf", "touch"];

/** A PATH holding only the tools the script needs, plus `extra` (name → script). */
function sandboxPath(root: string, extra: Record<string, string> = {}): string {
  const bin = join(root, "sysbin");
  mkdirSync(bin, { recursive: true });
  for (const t of TOOLS) {
    const w = spawnSync("sh", ["-c", `command -v ${t}`], { encoding: "utf8" }).stdout.trim();
    if (w) writeFileSync(join(bin, t), `#!/bin/sh\nexec ${w} "$@"\n`, { mode: 0o755 });
  }
  for (const [name, body] of Object.entries(extra)) writeFileSync(join(bin, name), body, { mode: 0o755 });
  return bin;
}

function install(args: string[], env: Record<string, string>): { code: number | null; out: string } {
  const r = spawnSync("sh", [INSTALL, ...args], { encoding: "utf8", env, timeout: 60_000 });
  return { code: r.status, out: r.stdout + r.stderr };
}

const stubNode = (version: string): string =>
  `#!/bin/sh\nif [ "$1" = "--version" ]; then echo ${version}; exit 0; fi\necho "stub node $*"\n`;

test("dry run: a Node below the floor on PATH plans a verified pinned download; nothing is written", () => {
  const root = tmpDir("mdu-install-");
  const PATH = sandboxPath(root, { node: stubNode("v22.12.0") });
  const r = install(["--dry-run", "--prefix", join(root, "p"), "--bin-dir", join(root, "b")], { PATH, HOME: root });
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /v22\.12\.0, below Mandu's floor 22\.13\.0/);
  assert.match(r.out, new RegExp(`would run: .*node-v22\\.22\\.1-${OS}-${ARCH}\\.tar\\.gz`));
  assert.match(r.out, /would run: .*SHASUMS256\.txt/);
  assert.ok(!existsSync(join(root, "p")) && !existsSync(join(root, "b")), "a dry run changes nothing");
});

test("dry run: a Node that meets the floor is used as is (no download)", () => {
  const root = tmpDir("mdu-install-");
  const PATH = sandboxPath(root, { node: stubNode("v24.1.0") });
  const r = install(["--dry-run", "--prefix", join(root, "p"), "--bin-dir", join(root, "b")], { PATH, HOME: root });
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /using Node v24\.1\.0/);
  assert.doesNotMatch(r.out, /node-v22/);
});

/** A file:// Node mirror whose tarball holds a stub node + a stub npm that
 *  "installs" @mandusec/mandu into the given --prefix. */
function mirror(root: string, tamper = false, arch = ARCH, nativeTag?: string): string {
  const name = `node-v22.22.1-${OS}-${arch}`;
  const stage = join(root, "stage", name, "bin");
  mkdirSync(stage, { recursive: true });
  writeFileSync(join(stage, "node"), `#!/bin/sh\nif [ "$1" = "--version" ]; then echo v22.22.1; exit 0; fi\nshift\n[ "$1" = "--version" ] && echo mandu 0.1.0-stub\n`, { mode: 0o755 });
  writeFileSync(join(stage, "npm"),
    `#!/bin/sh\nwhile [ $# -gt 0 ]; do [ "$1" = "--prefix" ] && P="$2"; shift; done\n` +
    `mkdir -p "$P/lib/node_modules/@mandusec/mandu/bin" && echo "// stub" > "$P/lib/node_modules/@mandusec/mandu/bin/mandu.mjs"\n` +
    (nativeTag ? `mkdir -p "$P/lib/node_modules/@mandusec/mandu/dist/native/${nativeTag}"\n` : ""), { mode: 0o755 });
  const dist = join(root, "mirror", "v22.22.1");
  mkdirSync(dist, { recursive: true });
  const tgz = join(dist, `${name}.tar.gz`);
  assert.equal(spawnSync("tar", ["-czf", tgz, "-C", join(root, "stage"), name]).status, 0);
  const sum = createHash("sha256").update(readFileSync(tgz)).digest("hex");
  writeFileSync(join(dist, "SHASUMS256.txt"), `${tamper ? "0".repeat(64) : sum}  ${name}.tar.gz\n`);
  return `file://${join(root, "mirror")}`;
}

test("no Node on PATH: the pinned Node is downloaded, verified, and the wrapper runs Mandu with it", () => {
  const root = tmpDir("mdu-install-");
  const PATH = sandboxPath(root);
  const r = install(["--prefix", join(root, "p"), "--bin-dir", join(root, "b")], { PATH, HOME: root, MANDU_NODE_MIRROR: mirror(root) });
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /verified node-v22\.22\.1-.*sha256 [0-9a-f]{64}/);
  assert.match(r.out, /installed mandu 0\.1\.0-stub/);
  assert.ok(existsSync(join(root, "p/pkg/lib/node_modules/@mandusec/mandu/.mandu-installer")), "the installer records its release channel");
  const wrapper = readFileSync(join(root, "b", "mandu"), "utf8");
  assert.ok(wrapper.includes(join(root, "p", "node", "bin", "node")), "the wrapper pins the installed Node, not PATH's");
  assert.match(r.out, /add .* to your PATH/);
});

test("a checksum mismatch refuses to install anything", () => {
  const root = tmpDir("mdu-install-");
  const PATH = sandboxPath(root);
  const r = install(["--prefix", join(root, "p"), "--bin-dir", join(root, "b")], { PATH, HOME: root, MANDU_NODE_MIRROR: mirror(root, true) });
  assert.notEqual(r.code, 0);
  assert.match(r.out, /checksum mismatch .* not installing/);
  assert.ok(!existsSync(join(root, "p", "node")), "no Node was unpacked");
  assert.ok(!existsSync(join(root, "b", "mandu")), "no command was written");
});

test("a --node-version below the floor is refused before anything runs", () => {
  const root = tmpDir("mdu-install-");
  const r = install(["--dry-run", "--node-version", "20.11.0"], { PATH: sandboxPath(root), HOME: root });
  assert.notEqual(r.code, 0);
  assert.match(r.out, /below Mandu's floor 22\.13\.0/);
});

test("the script is POSIX sh (dash parses it) and names its settings in --help", () => {
  const dash = spawnSync("sh", ["-c", "command -v dash"], { encoding: "utf8" }).stdout.trim();
  if (dash) assert.equal(spawnSync(dash, ["-n", INSTALL]).status, 0, "dash -n");
  const r = spawnSync("sh", [INSTALL, "--help"], { encoding: "utf8" });
  assert.equal(r.status, 0);
  for (const s of ["MANDU_PACKAGE", "MANDU_PREFIX", "MANDU_BIN_DIR", "MANDU_NODE_VERSION", "MANDU_NODE_MIRROR", "--dry-run"]) {
    assert.ok(r.stdout.includes(s), s);
  }
});

/** A Node install on PATH (an nvm-style dir) meeting the floor: a stub node
 *  that answers `<entry> --version` with `tag`, plus a stub npm beside it. */
function pathNode(dir: string, tag: string): string {
  const bin = join(dir, "bin");
  mkdirSync(bin, { recursive: true });
  writeFileSync(join(bin, "node"), `#!/bin/sh\nif [ "$1" = "--version" ]; then echo v24.1.0; exit 0; fi\nshift\n[ "$1" = "--version" ] && echo "mandu ${tag}"\n`, { mode: 0o755 });
  writeFileSync(join(bin, "npm"),
    `#!/bin/sh\nwhile [ $# -gt 0 ]; do [ "$1" = "--prefix" ] && P="$2"; shift; done\n` +
    `mkdir -p "$P/lib/node_modules/@mandusec/mandu/bin" && echo "// stub" > "$P/lib/node_modules/@mandusec/mandu/bin/mandu.mjs"\n`, { mode: 0o755 });
  return bin;
}

// Release checklist d8: the wrapper pinned the absolute path of the PATH
// Node it was installed with (often an nvm dir), and `nvm uninstall` then
// broke `mandu` with "not found". It still prefers that Node, but falls
// back to the node on PATH when it is gone, and says what to do when there is
// none at all.
test("a PATH Node that later disappears: the wrapper falls back to the node on PATH, and explains when there is none", () => {
  const root = tmpDir("mdu-install-");
  const sys = sandboxPath(root);
  const nvm = pathNode(join(root, "nvm", "v24.1.0"), "0.1.0-installed-node");
  const r = install(["--prefix", join(root, "p"), "--bin-dir", join(root, "b")], { PATH: `${sys}:${nvm}`, HOME: root });
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /using Node v24\.1\.0 at .*nvm/);
  const mandu = join(root, "b", "mandu");
  const run = (PATH: string) => spawnSync(mandu, ["--version"], { encoding: "utf8", env: { PATH, HOME: root } });

  // The installed-with Node still exists: it wins over a different node on PATH.
  const later = pathNode(join(root, "later"), "0.1.0-path-node");
  assert.equal(run(`${sys}:${later}`).stdout.trim(), "mandu 0.1.0-installed-node");

  // `nvm uninstall`: the recorded Node is gone → the node on PATH runs Mandu.
  rmSync(join(root, "nvm"), { recursive: true, force: true });
  const fell = run(`${sys}:${later}`);
  assert.equal(fell.status, 0, fell.stderr);
  assert.equal(fell.stdout.trim(), "mandu 0.1.0-path-node");

  // No Node anywhere: a clear message and exit 127, not a bare "not found".
  const none = run(sys);
  assert.equal(none.status, 127);
  assert.match(none.stderr, /no Node to run on: .*nvm.* is gone and there is no node on PATH/);
  assert.match(none.stderr, /install Node 22\.13\.0 or newer, or re-run the Mandu installer/);
});

/** A `uname` that reports Linux on `machine` (the installer reads -s and -m). */
const unameOn = (machine: string): string =>
  `#!/bin/sh\ncase "$1" in -m) echo ${machine} ;; *) echo Linux ;; esac\n`;

// Release checklist e2: one tarball carries linux-x64 and linux-arm64 native
// bins (packaging.md §11.3); the installer fetches the Node for this CPU and says
// whether the package has this CPU's helpers.
test("an aarch64 machine gets the linux-arm64 Node and is told its prebuilt helpers are included", () => {
  if (OS !== "linux") return;
  const root = tmpDir("mdu-install-");
  const PATH = sandboxPath(root, { uname: unameOn("aarch64") });
  const r = install(["--prefix", join(root, "p"), "--bin-dir", join(root, "b")],
    { PATH, HOME: root, MANDU_NODE_MIRROR: mirror(root, false, "arm64", "linux-arm64") });
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /verified node-v22\.22\.1-linux-arm64\.tar\.gz/);
  assert.match(r.out, /prebuilt confinement helpers for linux-arm64: included/);
});

test("a package without this CPU's helpers installs, and the installer says so", () => {
  if (OS !== "linux") return;
  const root = tmpDir("mdu-install-");
  const PATH = sandboxPath(root, { uname: unameOn("aarch64") });
  const r = install(["--prefix", join(root, "p"), "--bin-dir", join(root, "b")],
    { PATH, HOME: root, MANDU_NODE_MIRROR: mirror(root, false, "arm64", "linux-x64") });
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /no prebuilt confinement helpers for linux-arm64; Mandu runs, and mandu doctor/);
});

test("a 32-bit CPU is refused before anything is downloaded, naming the supported ones", () => {
  const root = tmpDir("mdu-install-");
  const PATH = sandboxPath(root, { uname: unameOn("armv7l") });
  const r = install(["--dry-run", "--prefix", join(root, "p"), "--bin-dir", join(root, "b")], { PATH, HOME: root });
  assert.notEqual(r.code, 0);
  assert.match(r.out, /unsupported CPU armv7l: Mandu supports 64-bit x86 \(x86_64\) and 64-bit ARM \(aarch64\)/);
  assert.doesNotMatch(r.out, /would run/);
});

// --sha256: a tarball (path or URL) is checked before npm sees it, so a
// release's own install.sh installs exactly the published file or nothing.

/** A PATH Node (meets the floor) whose stub npm records the spec it was handed, then "installs". */
function recordingNode(root: string): { bin: string; spec: string } {
  const bin = join(root, "pathnode", "bin");
  const spec = join(root, "npm-spec");
  mkdirSync(bin, { recursive: true });
  writeFileSync(join(bin, "node"), `#!/bin/sh\nif [ "$1" = "--version" ]; then echo v24.1.0; exit 0; fi\nshift\n[ "$1" = "--version" ] && echo "mandu 0.2.0-stub"\n`, { mode: 0o755 });
  writeFileSync(join(bin, "npm"),
    `#!/bin/sh\nfor a; do last="$a"; done\nwhile [ $# -gt 0 ]; do [ "$1" = "--prefix" ] && P="$2"; shift; done\n` +
    `printf '%s\\n' "$last" > "${spec}"; [ -f "$last" ] && sha256sum "$last" | awk '{print $1}' >> "${spec}"\n` +
    `mkdir -p "$P/lib/node_modules/@mandusec/mandu/bin" && echo "// stub" > "$P/lib/node_modules/@mandusec/mandu/bin/mandu.mjs"\n`, { mode: 0o755 });
  return { bin, spec };
}

/** A stand-in package tarball and its SHA-256. */
function tarball(root: string): { file: string; sum: string } {
  const file = join(root, "mandusec-mandu-9.9.9.tgz");
  writeFileSync(file, "not really a tarball, but bytes to hash\n");
  return { file, sum: createHash("sha256").update(readFileSync(file)).digest("hex") };
}

test("--sha256 with a URL: the tarball is downloaded, verified, and npm installs the checked file", () => {
  const root = tmpDir("mdu-install-");
  const { bin, spec } = recordingNode(root);
  const { file, sum } = tarball(root);
  const r = install(["--package", `file://${file}`, "--sha256", sum.toUpperCase(), "--prefix", join(root, "p"), "--bin-dir", join(root, "b")],
    { PATH: `${bin}:${sandboxPath(root)}`, HOME: root });
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, new RegExp(`verified file://.*mandusec-mandu-9\\.9\\.9\\.tgz \\(sha256 ${sum}\\)`));
  const [handed, handedSum] = readFileSync(spec, "utf8").trim().split("\n");
  assert.notEqual(handed, `file://${file}`, "npm gets the downloaded copy, never the URL");
  assert.equal(handedSum, sum, "and that copy is the verified one");
});

test("--sha256 mismatch: nothing reaches npm and no command is written", () => {
  const root = tmpDir("mdu-install-");
  const { bin, spec } = recordingNode(root);
  const { file } = tarball(root);
  const r = install(["--package", `file://${file}`, "--sha256", "0".repeat(64), "--prefix", join(root, "p"), "--bin-dir", join(root, "b")],
    { PATH: `${bin}:${sandboxPath(root)}`, HOME: root });
  assert.notEqual(r.code, 0);
  assert.match(r.out, /checksum mismatch for file:\/\/.* not installing/);
  assert.ok(!existsSync(spec), "npm never ran");
  assert.ok(!existsSync(join(root, "b", "mandu")));
});

test("--sha256 refuses a malformed hash and an npm spec", () => {
  const root = tmpDir("mdu-install-");
  const { bin } = recordingNode(root);
  const env = { PATH: `${bin}:${sandboxPath(root)}`, HOME: root };
  const bad = install(["--sha256", "abc123", "--prefix", join(root, "p"), "--bin-dir", join(root, "b")], env);
  assert.notEqual(bad.code, 0);
  assert.match(bad.out, /--sha256 takes 64 hex digits/);
  const spec = install(["--sha256", "a".repeat(64), "--prefix", join(root, "p"), "--bin-dir", join(root, "b")], env);
  assert.notEqual(spec.code, 0);
  assert.match(spec.out, /--sha256 needs a tarball path or URL; @mandusec\/mandu is neither/);
});

test("a release's copy: its default package and hash apply to that package only", () => {
  const root = tmpDir("mdu-install-");
  const { bin, spec } = recordingNode(root);
  const { file, sum } = tarball(root);
  // What the release publisher writes: the two PACKAGE_DEFAULT lines rewritten.
  const copy = join(root, "install.sh");
  const src = readFileSync(INSTALL, "utf8");
  const rewritten = src
    .replace(/^PACKAGE_DEFAULT=".*"$/m, `PACKAGE_DEFAULT="file://${file}"`)
    .replace(/^PACKAGE_DEFAULT_SHA256=".*"$/m, `PACKAGE_DEFAULT_SHA256="${sum}"`);
  assert.notEqual(rewritten, src, "install.sh keeps the two lines the publisher rewrites");
  writeFileSync(copy, rewritten);
  const env = { PATH: `${bin}:${sandboxPath(root)}`, HOME: root };
  const run = (args: string[]) => {
    const r = spawnSync("sh", [copy, "--prefix", join(root, "p"), "--bin-dir", join(root, "b"), ...args], { encoding: "utf8", env, timeout: 60_000 });
    return { code: r.status, out: r.stdout + r.stderr };
  };
  const plain = run([]);
  assert.equal(plain.code, 0, plain.out);
  assert.match(plain.out, /verified file:\/\//);

  // Another tarball named by --package is not held to the default's hash.
  const other = join(root, "other.tgz");
  writeFileSync(other, "a different build\n");
  const custom = run(["--package", other]);
  assert.equal(custom.code, 0, custom.out);
  assert.doesNotMatch(custom.out, /verified|mismatch/);
  assert.equal(readFileSync(spec, "utf8").split("\n")[0], other);
});

// A private repository's release cannot be fetched by curl: the tester
// downloads the release's files and runs its install.sh in that folder. The
// release copy then installs the tarball beside it, held to the same SHA-256.
test("a release's copy run next to its tarball installs that file (no download), still hash-checked", () => {
  const root = tmpDir("mdu-install-");
  const { bin, spec } = recordingNode(root);
  const dl = join(root, "Downloads");
  mkdirSync(dl, { recursive: true });
  const name = "mandusec-mandu-9.9.9.tgz";
  writeFileSync(join(dl, name), "the release's tarball\n");
  const sum = createHash("sha256").update(readFileSync(join(dl, name))).digest("hex");
  const copy = join(dl, "install.sh");
  writeFileSync(copy, readFileSync(INSTALL, "utf8")
    .replace(/^PACKAGE_DEFAULT=".*"$/m, `PACKAGE_DEFAULT="https://example.invalid/releases/download/v9.9.9/${name}"`)
    .replace(/^PACKAGE_DEFAULT_SHA256=".*"$/m, `PACKAGE_DEFAULT_SHA256="${sum}"`));
  const env = { PATH: `${bin}:${sandboxPath(root)}`, HOME: root };
  const run = () => {
    const r = spawnSync("sh", [copy, "--prefix", join(root, "p"), "--bin-dir", join(root, "b")], { cwd: dl, encoding: "utf8", env, timeout: 60_000 });
    return { code: r.status, out: r.stdout + r.stderr };
  };
  const ok = run();
  assert.equal(ok.code, 0, ok.out);
  assert.match(ok.out, new RegExp(`verified \\./${name.replace(/\./g, "\\.")} \\(sha256 ${sum}\\)`));
  assert.doesNotMatch(ok.out, /example\.invalid/, "no download was attempted");
  assert.equal(readFileSync(spec, "utf8").split("\n")[0], `./${name}`);

  // A different file under the release's name is refused.
  writeFileSync(join(dl, name), "something else\n");
  rmSync(spec);
  const bad = run();
  assert.notEqual(bad.code, 0);
  assert.match(bad.out, /checksum mismatch for \.\/mandusec-mandu-9\.9\.9\.tgz .* not installing/);
  assert.ok(!existsSync(spec), "npm never ran");
});
