/**
 * code-runner-copies — three gaps in the code-running list (confidentiality
 * plan 13 §8 decision (b) and D8, 2026-10-03), each red on the code before:
 *
 *   (1) a renamed copy of an interpreter (or any code-running program) the
 *       human pins by path and hash (`cp /usr/bin/python3 ~/bin/mytool`,
 *       `{ app: mytool, path, sha256 }`) was that pin's program: it read the
 *       secret raw and ran whatever code the agent handed it. Now a binary
 *       whose sha256 is a host code-running program's (`hashRunsCode`,
 *       `program-hashes.ts`, the generalized `printer-hashes.ts` of !451) is
 *       that program under any name: as an entry it admits nothing, as an
 *       opener it gets what a non-reader gets and is never asked about; the
 *       refusal, `mandu why` (`readersCopyOf`) and the policy warnings name
 *       the program it is a copy of.
 *   (2) fetch and transfer clients that run a command (tnftp `ftp`'s `!cmd`,
 *       aria2c's `--on-download-*` hooks, lftp, sftp, wget's
 *       `--use-askpass`, rclone, `gio launch`, the text browsers, …), more
 *       editors and more launchers were not on the code-running list.
 *   (3) `vim -c` and modelines: verified closed since !368 (editors on the
 *       list): an editor reader admits nothing, in any form, a script pin
 *       included; pinned here so it stays closed.
 *
 * Axes: secrets.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { linkSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  addCodeRunnerHashes, addPrinterHashes, binaryRunsCode, clearHostProgramHashesForTest, decideOpen, entryAdmitsNothing, hashPrints, hashRunsCode,
  inlineCodeProblem, matchReader, mootQuestionReason, readerPrints, readerRunsCode, renamedCopyOf, staleInterpreterVerdict, verdictProgramOf,
  withoutVersion,
} from "../../policy/flow-taint.js";
import { refreshProgramHashes, scanPrinterHashes, scanProgramHashes } from "../../policy/program-hashes.js";
import { policyWarnings } from "../../policy/policy-file-validate.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const sha = (b: string): string => createHash("sha256").update(b).digest("hex");
const PY = sha("pretend this is CPython 3.12");
const LEAF = sha("a leaf program of the human's");
const ENV = "/w/.env";

/** Run `fn` with only the given host hashes known, then restore the host's. */
function withHashes(fn: () => void, hashes: { runsCode?: Array<[string, string]>; prints?: Array<[string, string]> }): void {
  clearHostProgramHashesForTest();
  try {
    addCodeRunnerHashes(hashes.runsCode ?? []);
    addPrinterHashes(hashes.prints ?? []);
    fn();
  } finally {
    clearHostProgramHashesForTest();
    refreshProgramHashes({ minIntervalMs: 0 });
  }
}

// ── (1) a renamed copy of an interpreter ────────────────────────────────────

test("(1) before the host's interpreters are known (the code before the fix), a pinned renamed python3 read raw", () => {
  clearHostProgramHashesForTest();
  try {
    const pin = { app: "mytool", path: "/home/u/bin/mytool", sha256: PY, prints: "nothing" as const };
    assert.equal(entryAdmitsNothing(pin), false);
    assert.equal(decideOpen(ENV, { readers: [pin] }, { exe: pin.path, sha256: PY, exeSystem: false, loaderEnv: [] }).verdict, "raw");
  } finally {
    refreshProgramHashes({ minIntervalMs: 0 });
  }
});

test("(1) a pin whose hash is a host interpreter's admits nothing, whatever its name; the opener gets the refusal or the twin, never a question", () => {
  withHashes(() => {
    const pin = { app: "mytool", path: "/home/u/bin/mytool", sha256: PY, prints: "nothing" as const };
    const opener = { exe: pin.path, sha256: PY, exeSystem: false, loaderEnv: [] as string[] };
    assert.equal(hashRunsCode(PY.toUpperCase()), true);
    assert.equal(hashPrints(PY), false);
    assert.equal(binaryRunsCode(pin), true);
    assert.deepEqual(renamedCopyOf(pin), { kind: "runsCode", of: "python3.12" });
    assert.equal(entryAdmitsNothing(pin), true);
    assert.equal(matchReader([pin], opener), null);
    assert.match(inlineCodeProblem(opener) ?? "", /mytool is a copy of python3\.12/);
    assert.equal(verdictProgramOf(opener), null, "no verdict can name it: never asked, never a standing answer");
    for (const ask of ["never", "known", "always"] as const) {
      const d = decideOpen(ENV, { readers: [pin] }, opener, { ask });
      assert.equal(d.verdict, "deny", `${ask}: ${d.why}`);
      assert.match(d.why, /mytool is a copy of python3\.12, a program that runs code it is given/);
      assert.equal(decideOpen(ENV, { readers: [pin], others: "twin" }, opener, { ask }).verdict, "twin");
    }
    // a system-installed copy, bare-named in the list: its hash decides
    const sys = { exe: "/usr/local/bin/mytool", sha256: PY, exeSystem: true, loaderEnv: [] as string[] };
    assert.equal(decideOpen(ENV, { readers: ["mytool"] }, sys, { ask: "always" }).verdict, "deny");
    // a pin by path alone: the opener's hash decides
    assert.equal(decideOpen(ENV, { readers: [{ app: "mytool", path: sys.exe }] }, sys, { ask: "always" }).verdict, "deny");
    // a script pin on the renamed copy admits nothing (its interpreter is named by app:)
    const scripted = { ...pin, script: "/opt/tools/load.py" };
    assert.equal(entryAdmitsNothing(scripted), true);
    assert.equal(matchReader([scripted], { ...opener, script: { path: "/opt/tools/load.py", sha256: LEAF, system: true, isolated: true, traced: false } }), null);
    // the installed interpreter's own script pin, at another path, is still the human's to make
    assert.equal(entryAdmitsNothing({ app: "python3", path: "/home/u/bin/mytool", sha256: PY, script: "/opt/tools/load.py" }), false);
    // an old answer about the copy, naming no script, applies to nothing
    assert.equal(staleInterpreterVerdict(`open:/home/u/bin/mytool#${PY}`), true);
    assert.match(mootQuestionReason(`open:/home/u/bin/mytool#${PY}`) ?? "", /names mytool alone, which runs any code/);
    assert.equal(staleInterpreterVerdict(`open:/home/u/bin/mytool#${LEAF}`), false);
    // a binary with another hash is still the human's program
    const tool = { app: "acme-load", path: "/opt/acme/acme-load", sha256: LEAF, prints: "nothing" as const };
    assert.equal(entryAdmitsNothing(tool), false);
    assert.equal(renamedCopyOf(tool), null);
    assert.equal(decideOpen(ENV, { readers: [tool] }, { exe: tool.path, sha256: LEAF, exeSystem: false, loaderEnv: [] }).verdict, "raw");
  }, { runsCode: [[PY, "python3.12"]] });
});

test("(1) renamedCopyOf names only a copy: python3 by its own name is no copy, and a printer's hash wins over an interpreter's", () => {
  const BB = sha("pretend this is busybox");
  withHashes(() => {
    assert.equal(renamedCopyOf({ app: "python3", path: "/usr/bin/python3.12", sha256: PY }), null);
    assert.equal(renamedCopyOf({ exe: "/usr/bin/python3.12", sha256: PY }), null);
    assert.deepEqual(renamedCopyOf({ app: "box", sha256: BB }), { kind: "prints", of: "busybox" });
    assert.equal(renamedCopyOf({ app: "box" }), null, "no hash, no copy");
  }, { runsCode: [[PY, "python3.12"], [BB, "busybox"]], prints: [[BB, "busybox"]] });
});

test("(1) policyWarnings: a pin whose hash is an interpreter's says what it is a copy of and names the installed interpreter's script form", () => {
  withHashes(() => {
    const w = policyWarnings({ version: 1, paths: [{ path: ENV, level: "no-model", readers: [
      { app: "mytool", path: "/home/u/bin/mytool", sha256: PY },
      { app: "mytool", path: "/home/u/bin/mytool", sha256: PY, script: "/opt/a.py" },
      { app: "acme-load", path: "/opt/acme/acme-load", sha256: LEAF, prints: "nothing" },
    ] }] });
    assert.ok(w.some((l) => l.startsWith("paths[0].readers[0]: mytool is a copy of python3.12 (its sha256 is that of python3.12 installed on this host), a program that runs any code it is given, so this entry admits nothing")), w.join("\n"));
    assert.ok(w.some((l) => l.startsWith("paths[0].readers[1]: mytool is a copy of python3.12")), w.join("\n"));
    assert.ok(w.some((l) => l.includes("{ app: python3.12, script: /absolute/path/of/the/script }")), w.join("\n"));
    assert.ok(!w.some((l) => l.includes("readers[2]")), w.join("\n"));
  }, { runsCode: [[PY, "python3.12"]] });
});

test("(1) scanProgramHashes hashes printers and code-running programs by name or link, each kind once per inode, names the file a link resolves to, and nothing else", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-program-scan-"));
  try {
    const bin = join(dir, "bin"); const lib = join(dir, "lib");
    mkdirSync(bin); mkdirSync(lib);
    writeFileSync(join(lib, "python3.12"), "PY-BYTES");
    symlinkSync(join(lib, "python3.12"), join(bin, "python3"));
    writeFileSync(join(bin, "bash"), "BASH-BYTES");
    linkSync(join(bin, "bash"), join(bin, "sh")); // one inode, two names
    writeFileSync(join(bin, "busybox"), "BB-BYTES"); // a printer and a shell
    writeFileSync(join(bin, "tnftp"), "FTP-BYTES");
    writeFileSync(join(bin, "cat"), "CAT-BYTES");
    writeFileSync(join(bin, "mytool"), "MYTOOL-BYTES");
    mkdirSync(join(bin, "perl")); // a directory named like an interpreter
    const got = scanProgramHashes([bin, join(dir, "missing")]);
    assert.deepEqual([...got.runsCode.keys()].sort(), [sha("PY-BYTES"), sha("BASH-BYTES"), sha("BB-BYTES"), sha("FTP-BYTES")].sort());
    assert.deepEqual([...got.prints.keys()].sort(), [sha("BB-BYTES"), sha("CAT-BYTES")].sort());
    assert.equal(got.runsCode.get(sha("PY-BYTES")), "python3.12", "named by the file the link resolves to");
    assert.equal(got.runsCode.get(sha("FTP-BYTES")), "tnftp");
    assert.ok(!got.runsCode.has(sha("MYTOOL-BYTES")) && !got.prints.has(sha("MYTOOL-BYTES")));
    assert.deepEqual([...scanPrinterHashes([bin])].sort(), [sha("BB-BYTES"), sha("CAT-BYTES")].sort(), "the printers' scan, as !451 shipped it");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── (2) fetchers, editors and launchers that run a command ──────────────────

const NEW_CODE_RUNNERS = [
  "ftp", "tnftp", "netkit-ftp", "pftp", "inetutils-ftp", "aria2c", "lftp", "sftp", "wget", "wget2", "rclone",
  "gio", "kioclient", "kioclient5", "kioclient6", "lynx", "w3m", "elinks", "links", "links2", "http", "https", "httpie",
  "nvi", "elvis", "vis", "kak", "hx", "helix", "joe", "jstar", "jmacs", "jpico", "rjoe", "jed", "mg", "zile", "jove", "mcedit", "mc", "ne", "xemacs",
  "valgrind", "perf", "rr", "setpriv", "sg", "unbuffer", "faketime", "torsocks", "proxychains", "proxychains4",
  "fakeroot", "eatmydata", "xvfb-run", "dbus-run-session", "tmux", "screen", "entr",
];

test("(2) tnftp's ftp, aria2c (--on-download-*), the other fetchers that run a command, more editors and launchers run code: listed, bare or pinned, they admit nothing and are never asked about", () => {
  for (const name of NEW_CODE_RUNNERS) {
    assert.ok(readerRunsCode(name), name);
    assert.equal(entryAdmitsNothing(name), true, name);
    assert.equal(entryAdmitsNothing({ app: name, path: `/usr/bin/${name}`, sha256: LEAF }), true, `${name} pinned`);
    const opener = { exe: `/usr/bin/${name}`, sha256: LEAF, exeSystem: true, loaderEnv: [] as string[] };
    assert.equal(matchReader([name, { app: name, path: opener.exe, sha256: LEAF }], opener), null, name);
    const d = decideOpen(ENV, { readers: [name] }, opener, { ask: "always" });
    assert.equal(d.verdict, "deny", `${name}: ${d.why}`);
  }
  // under an alternatives name and a distribution's prefix
  for (const n of ["/usr/bin/tnftp", "ftp.tnftp", "uu-ftp", "netkit-ftp"]) assert.ok(readerRunsCode(n), n);
  // the fetchers that run nothing they are given stay printers only, and the
  // vetted consumers stay off the code-running list
  // (cargo runs the package's build.rs: on the list since 2026-10-04, (4) below)
  for (const n of ["curl", "curlie", "xh", "scp", "gvfs-cat", "axel", "psql", "aws", "gh", "git", "ssh", "docker", "kubectl"]) assert.equal(readerRunsCode(n), false, n);
  assert.ok(readerPrints("aria2c") && readerPrints("wget") && readerPrints("lftp"), "still printers too");
});

test("(2) the aria2c hook: an aria2c run with --on-download-complete is no reader in any form (it was a printer already; now named for what it runs)", () => {
  const opener = { exe: "/usr/bin/aria2c", sha256: LEAF, exeSystem: true, loaderEnv: [] as string[] };
  assert.equal(verdictProgramOf(opener), null, "no standing answer can name an aria2c run");
  for (const others of [undefined, "twin"] as const) {
    const d = decideOpen(ENV, { readers: [{ app: "aria2c", path: "/usr/bin/aria2c", sha256: LEAF }], ...(others ? { others } : {}) }, opener, { ask: "always" });
    assert.equal(d.verdict, others === "twin" ? "twin" : "deny", d.why);
  }
});

// ── (3) vim -c and modelines: closed by !368 ────────────────────────────────

test("(3) vim -c / a modeline: an editor reader admits nothing, bare, pinned by path and hash, or with a script pin; its opener is never asked about (closed since !368, pinned here)", () => {
  for (const ed of ["vim", "vi", "nvim", "ex", "view", "gvim", "vimdiff", "emacs", "nvi", "kak", "hx"]) {
    const opener = { exe: `/usr/bin/${ed}`, sha256: LEAF, exeSystem: true, loaderEnv: [] as string[] };
    assert.equal(entryAdmitsNothing(ed), true, ed);
    assert.equal(entryAdmitsNothing({ app: ed, path: opener.exe, sha256: LEAF }), true, `${ed} pinned`);
    assert.equal(matchReader([{ app: ed, script: "/opt/x.vim" }], { ...opener, script: { path: "/opt/x.vim", sha256: LEAF, system: true, isolated: true, traced: false } }), null, `${ed}: no script form`);
    assert.match(inlineCodeProblem(opener) ?? "", /no script of it can be pinned/, ed);
    const d = decideOpen(ENV, { readers: [ed, { app: ed, path: opener.exe, sha256: LEAF }] }, opener, { ask: "always" });
    assert.equal(d.verdict, "deny", `${ed}: ${d.why}`);
  }
  // vim.basic, the file /usr/bin/vim resolves to on Debian, is vim
  assert.ok(readerRunsCode("/usr/bin/vim.basic") && readerRunsCode("vim.tiny"));
});

// ── (4) build tools, more runtimes, versioned names (2026-10-04) ────────────

/** Programs that run code from a build file or an argument, joined to the
 *  list on 2026-10-04 (probed: `cmake -P`, `ninja -f`, `go run`, `cargo
 *  build` with a build.rs, `run-parts`, `tex -shell-escape`). Red before:
 *  each was no code runner, so a reader entry naming it read raw and ran
 *  the agent's code with the bytes. */
const BUILD_TOOLS = [
  "cmake", "ctest", "cpack", "ninja", "go", "cargo", "rustup", "bazel", "just", "scons", "meson", "gradle", "mvn", "ant", "rake",
  "npm", "corepack", "nix-shell", "terraform", "podman", "run-parts", "at",
  "nodejs", "pypy3", "irb", "erb", "erl", "beam.smp", "escript", "elixir", "ocaml", "swipl", "sbcl", "kotlin", "groovy", "mono",
  "runghc", "zig", "dart", "tcc", "qjs", "gforth", "wasmtime", "dc", "bc", "octave", "gnuplot", "rbash", "yash", "nushell",
  "tex", "pdftex", "xetex", "luatex", "lualatex", "pdflatex",
];

test("(4) build tools, more runtimes and the TeX engines run code: listed, bare or pinned, they admit nothing and are never asked about", () => {
  for (const name of BUILD_TOOLS) {
    assert.ok(readerRunsCode(name), name);
    assert.equal(entryAdmitsNothing(name), true, name);
    const opener = { exe: `/usr/bin/${name}`, sha256: LEAF, exeSystem: true, loaderEnv: [] as string[] };
    const d = decideOpen(ENV, { readers: [name] }, opener, { ask: "always" });
    assert.equal(d.verdict, "deny", `${name}: ${d.verdict} ${d.why}`);
    assert.equal(decideOpen(ENV, { readers: [name], others: "twin" }, opener, { ask: "always" }).verdict, "twin", name);
  }
  // still no code runners: the leaf consumers, the checksum tools, gofmt
  for (const n of ["psql", "aws", "gh", "git", "ssh", "docker", "kubectl", "twine", "sha256sum", "gofmt", "stat"]) assert.equal(readerRunsCode(n), false, n);
});

test("(4) cargo, a consumer-table program that runs the package's build.rs, reads ~/.cargo/credentials only as the twin (the wire release's, or the default's without it), as node reads .npmrc", () => {
  const cred = "/h/.cargo/credentials.toml";
  const cargo = { exe: "/usr/bin/cargo", sha256: LEAF, exeSystem: true, loaderEnv: [] as string[] };
  for (const ask of ["never", "known"] as const) {
    assert.equal(decideOpen(cred, {}, cargo, { ask }).verdict, "twin", ask);
    assert.equal(decideOpen(cred, {}, cargo, { ask, wireTwin: { why: "test" } }).verdict, "twin", ask);
  }
  assert.equal(decideOpen(cred, { readers: ["cargo"] }, cargo, { ask: "always" }).verdict, "deny");
});

test("(4) a versioned name is its program: php8.5, lua5.4, tclsh8.6, ruby3.3, perl5.40.1 run code; gcc-15, clang-18 print; withoutVersion takes only a version after a letter", () => {
  for (const n of ["php8.5", "/usr/bin/php8.5", "lua5.4", "lua5.1", "tclsh8.6", "wish8.6", "ruby3.3", "irb3.3", "perl5.40.1", "guile-3.0", "node22", "python3.14"]) {
    assert.ok(readerRunsCode(n), n);
    const opener = { exe: n.startsWith("/") ? n : `/usr/bin/${n}`, sha256: LEAF, exeSystem: true, loaderEnv: [] as string[] };
    assert.equal(decideOpen(ENV, { readers: [n] }, opener, { ask: "always" }).verdict, "deny", n);
  }
  for (const n of ["gcc-15", "clang-18", "cpp-14", "g++-15"]) assert.ok(readerPrints(n), n);
  assert.equal(withoutVersion("php8.5"), "php");
  assert.equal(withoutVersion("gcc-15"), "gcc");
  assert.equal(withoutVersion("perl5.40.1"), "perl");
  assert.equal(withoutVersion("x86_64"), null);
  assert.equal(withoutVersion("1.2"), null);
  assert.equal(withoutVersion("a.1"), null);
  assert.equal(withoutVersion("a1."), null);
  assert.equal(withoutVersion("psql"), null);
  for (const n of ["psql16", "aws2", "kubectl1.30", "sha256sum", "base64x"]) assert.equal(readerRunsCode(n), false, n);
});

/** Each build tool as probed: the invocation that runs a command it is
 *  handed (it creates `M`), where the program is installed. */
const RUNS_WHEN_ASKED: ReadonlyArray<{ app: string; setup: (dir: string, m: string) => string[] }> = [
  { app: "cmake", setup: (d, m) => { writeFileSync(join(d, "s.cmake"), `execute_process(COMMAND touch ${m})\n`); return ["-P", join(d, "s.cmake")]; } },
  { app: "ctest", setup: (d, m) => { writeFileSync(join(d, "t.cmake"), `execute_process(COMMAND touch ${m})\n`); return ["-S", join(d, "t.cmake")]; } },
  { app: "ninja", setup: (d, m) => { writeFileSync(join(d, "build.ninja"), `rule t\n  command = touch ${m}\nbuild x: t\n`); return ["-C", d, "-f", "build.ninja"]; } },
  { app: "run-parts", setup: (d, m) => { mkdirSync(join(d, "rp")); writeFileSync(join(d, "rp", "a"), `#!/bin/sh\ntouch ${m}\n`, { mode: 0o755 }); return [join(d, "rp")]; } },
];

test("(4) each such build tool, where installed, runs a command it is handed (a marker file, no secret)", { skip: process.platform !== "linux" }, (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-runs-when-asked-"));
  try {
    let ran = 0;
    for (const { app, setup } of RUNS_WHEN_ASKED) {
      if (spawnSync("sh", ["-c", `command -v ${app}`]).status !== 0) continue;
      const dir = mkdtempSync(join(tmp, `${app}-`));
      const m = join(dir, "marker");
      const r = spawnSync(app, setup(dir, m), { cwd: dir, encoding: "utf8", timeout: 30_000 });
      if (r.error) continue;
      ran++;
      assert.ok(spawnSync("test", ["-e", m]).status === 0, `${app} ran the command it was handed: ${r.stdout}${r.stderr}`);
      assert.ok(readerRunsCode(app), `${app} is on the code-running list`);
    }
    if (ran === 0) t.skip("none of the build tools is installed here");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
