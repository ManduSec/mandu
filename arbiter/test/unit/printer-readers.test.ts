/**
 * printer-readers — confidentiality plan 13 D8, "printers admit nothing"
 * (the maintainer's decision of 2026-10-03, plan 13 §8): a program whose job
 * is to copy or print a file's bytes (`PRINTER_READERS`: cat, head, base64,
 * cp, tar, jq, …) hands them to whatever reads its output, which can be the
 * agent's code, whose metadata exits (plan 13 §4.9) are not followed. So a
 * printer named in a secret file's `readers:` admits nothing, in any form
 * (a bare name, a `from:` entry, a pin by path and hash); a printer opener
 * gets what a non-reader of the file gets (the twin, or the refusal its
 * `others:` gives), is never prompted for under any `ask` mode, and no past
 * answer for it counts. Non-printer readers and the consumer table's vetted
 * programs are unchanged, except those that print: `curl` and `scp` (the
 * !437 leftover (1)) and, since 2026-10-04 (plan 13 §4.9 option (a)), `git`
 * with its credential helper and its HTTP transport.
 *
 * Each `raw` → `twin`/`deny` here was `raw` on the code before the decision
 * (a listed `cat` read the file raw; an *Always* for /usr/bin/cat admitted
 * it). Axes: secrets.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  CODE_RUNNING_READERS, PRINTER_READERS, addPrinterHashes, clearPrinterHashesForTest, decideOpen, entryAdmitsNothing, hashPrints, knownConsumers, matchReader,
  printerOpenVerdict, readerPrints,
} from "../../policy/flow-taint.js";
import { SCAN_DIRS, refreshProgramHashes, scanProgramHashes } from "../../policy/program-hashes.js";
import { policyWarnings } from "../../policy/policy-file-validate.js";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const SYS = { exeSystem: true, loaderEnv: [] as string[] };
const H = "c".repeat(64);

test("the printer list: at least the programs the decision names, and none of the vetted consumers", () => {
  const named = [
    "cat", "tac", "head", "tail", "less", "more", "most", "pg", "nl", "tee", "dd", "cp", "install", "rsync", "base64", "base32", "basenc",
    "xxd", "od", "hexdump", "strings", "sed", "awk", "gawk", "mawk", "cut", "paste", "sort", "uniq", "tr", "fold", "fmt", "column",
    "grep", "egrep", "fgrep", "rg", "diff", "cmp", "comm", "iconv", "gzip", "gunzip", "zcat", "bzip2", "bzcat", "xz", "xzcat", "zstd",
    "zstdcat", "tar", "zip", "unzip", "cpio", "split", "csplit", "jq", "yq", "envsubst", "openssl", "gpg", "busybox", "toybox",
  ];
  for (const n of named) assert.ok(readerPrints(n), n);
  for (const n of ["ssh-add", "pg_dump", "aws", "gh", "npm", "docker", "kubectl", "helm", "ssh", "ssh-add", "twine", "cargo"]) {
    assert.equal(readerPrints(n), false, `${n} is a vetted consumer, not a printer`);
  }
  // plan 13 D8 (11), 2026-10-04: git prints any file it is named for (§4.9
  // option (a)) and its credential helper prints what it stores
  for (const n of ["git", "git-credential-store", "/usr/lib/git-core/git-credential-store"]) assert.ok(readerPrints(n), n);
  // the !437 leftover (1): what fetches or transfers a URL or a file, a
  // local one included, is a printer, the consumer table's curl and scp too
  for (const n of ["curl", "curlie", "wget", "wget2", "aria2c", "http", "https", "xh", "xhs", "lftp", "rclone", "scp", "sftp", "gio", "gvfs-cat", "lynx", "w3m", "links", "elinks", "rsync", "socat", "openssl", "xxd", "od", "hexdump"]) {
    assert.ok(readerPrints(n), n);
  }
  // ...but not what only speaks to the network from its standard input
  for (const n of ["nc", "ncat", "netcat", "nc.openbsd", "axel", "ssh", "telnet"]) assert.equal(readerPrints(n), false, n);
  // the consumer table names no printer but curl (.netrc), scp (ssh keys)
  // and, since 2026-10-04 (plan 13 §4.9), git and its credential helper
  // (.git-credentials, .netrc, ssh keys), where the printer rule wins
  // (`decideOpen`)
  for (const p of ["/h/.pgpass", "/h/.aws/credentials", "/h/.config/gh/hosts.yml", "/h/.npmrc", "/h/.docker/config.json", "/h/.kube/config", "/h/.ssh/id_ed25519", "/h/.netrc", "/h/.git-credentials", "/h/.pypirc", "/h/.cargo/credentials.toml"]) {
    for (const app of knownConsumers(p)) assert.equal(readerPrints(app), ["curl", "scp", "git", "git-credential-store", "git-remote-http", "git-remote-https", "git-http-fetch", "git-http-push", "psql", "pg_restore"].includes(app), `${app} (${p})`);
  }
  // busybox runs code and prints: in both lists
  assert.ok(CODE_RUNNING_READERS.has("busybox") && PRINTER_READERS.has("busybox"));
  // matched as a name resolves (an alternatives target), never a longer name
  assert.equal(readerPrints("python3"), false, "an interpreter is the code-running list's");
  assert.ok(readerPrints("/usr/bin/cat"));
  assert.ok(readerPrints("xz.alt"));
  assert.equal(readerPrints("category"), false);
  assert.equal(readerPrints("catalog-tool"), false);
  // uutils coreutils: every program in its directory is the one binary that
  // picks its job from argv[0], so `cat` too
  assert.ok(readerPrints("/usr/lib/cargo/bin/coreutils/wc"));
  assert.ok(readerPrints("/usr/lib/cargo/bin/coreutils/sha256sum"));
  assert.equal(readerPrints("/usr/bin/sha256sum"), false, "a separate GNU sha256sum is not a printer");
  // a distribution's second copy under a prefix: Ubuntu 26.04's gnucat,
  // Homebrew's gsed, uutils' uu-cat
  for (const n of ["gnucat", "/usr/bin/gnucat", "gnucp", "gnuhead", "gnubase64", "gsed", "gtar", "gcat", "uu-cat", "uu_head"]) assert.ok(readerPrints(n), n);
  for (const n of ["gh", "gnu", "g", "gcloud", "go", "gnome-keyring", "uu-", "gnusha256sum"]) assert.equal(readerPrints(n), false, n);
});

test("NEW: every printer, listed by name, admits nothing: deny (the list is exhaustive), the twin under others: twin, never asked", () => {
  for (const name of PRINTER_READERS) {
    const opener = { exe: `/usr/bin/${name}`, sha256: H, ...SYS };
    assert.equal(entryAdmitsNothing(name), true, name);
    assert.equal(matchReader([name], opener), null, name);
    for (const ask of ["never", "known", "always"] as const) {
      const d = decideOpen("/ws/.env", { readers: [name] }, opener, { ask });
      assert.equal(d.verdict, "deny", `${name} (${ask}): ${d.verdict} ${d.why}`);
      assert.match(d.why, /prints or copies/);
      assert.equal(decideOpen("/ws/.env", { readers: [name], others: "twin" }, opener, { ask }).verdict, "twin", `${name} (${ask})`);
      // no reader list: the twin, as any program not a known consumer
      assert.equal(decideOpen("/ws/.env", {}, opener, { ask }).verdict, "twin", `${name} (${ask}, no list)`);
    }
  }
});

test("NEW: a printer pinned by path and hash, renamed in the entry, or with a from: parent still admits nothing", () => {
  const cat = { exe: "/usr/bin/cat", sha256: H, ...SYS, ancestors: [{ exe: "/usr/bin/git", trusted: true }] };
  const forms = [
    { app: "cat", path: "/usr/bin/cat", sha256: H },
    { app: "cat", path: "/usr/bin/cat", sha256: H, output: "clear" as const },
    { app: "mycat", path: "/usr/bin/cat", sha256: H },
    { app: "cat", from: "git" },
    { app: "cat", script: "/opt/tools/x.py" },
  ];
  for (const e of forms) {
    assert.equal(entryAdmitsNothing(e), true, JSON.stringify(e));
    assert.equal(matchReader([e], cat), null, JSON.stringify(e));
    assert.equal(decideOpen("/ws/.env", { readers: [e] }, cat, { ask: "always" }).verdict, "deny", JSON.stringify(e));
  }
  // an agent-written binary named cat, pinned by the human: still a printer
  const ws = { exe: "/ws/bin/cat", sha256: H, exeSystem: false, loaderEnv: [] as string[] };
  assert.equal(decideOpen("/ws/.env", { readers: [{ app: "cat", path: "/ws/bin/cat", sha256: H }] }, ws, { ask: "always" }).verdict, "deny");
  // a uutils program by any name is a printer
  const wc = { exe: "/usr/lib/cargo/bin/coreutils/wc", sha256: H, ...SYS };
  assert.equal(decideOpen("/ws/.env", { readers: ["wc"] }, wc).verdict, "deny");
  assert.equal(entryAdmitsNothing({ app: "wc", path: "/usr/lib/cargo/bin/coreutils/wc", sha256: H }), true);
});

/** 2026-10-04: programs that print a named file when asked although printing
 *  is not their job, each with the invocation that does it (`F` the file).
 *  Red before: none was on the list, so `file` named in a `.env`'s
 *  `readers:` read it raw and `file -f .env | python3 …` handed the agent's
 *  code every line (tests/sandbox/guard/printer-downstream.test.ts). */
const PRINTS_WHEN_ASKED: ReadonlyArray<{ app: string; argv: (f: string) => string[] }> = [
  { app: "file", argv: (f) => ["-f", f] },
  { app: "date", argv: (f) => ["-f", f] },
  { app: "wc", argv: (f) => [`--files0-from=${f}`] },
  { app: "du", argv: (f) => [`--files0-from=${f}`] },
  { app: "cpp", argv: (f) => [f] },
  { app: "gcc", argv: (f) => ["-E", "-x", "c", f] },
  { app: "gcc", argv: (f) => [`@${f}`] },
  { app: "ld", argv: (f) => [`@${f}`] },
  { app: "nm", argv: (f) => [`@${f}`] },
  { app: "nroff", argv: (f) => [f] },
  { app: "tic", argv: (f) => [f] },
  { app: "msgcat", argv: (f) => [f] },
];

test("NEW (2026-10-04): what prints a named file when asked is a printer: file -f, date -f, wc/du --files0-from, cpp/cc -E, @file response files, objcopy, nroff, tic, msgcat", () => {
  for (const n of [
    "file", "date", "wc", "du", "logger", "ssh-keyscan", "groff", "nroff", "troff", "preconv", "soelim", "tbl", "man", "whatis", "ul", "tic",
    "cpp", "cc", "c++", "gcc", "g++", "cc1", "clang", "clang++", "rustc", "as", "ld", "ld.bfd", "nm", "objcopy", "objdump", "strip", "c++filt",
    "bison", "yacc", "msgcat", "msgfmt", "xgettext", "gnuwc", "gnudate", "/usr/bin/file", "/usr/lib/gcc/x86_64-linux-gnu/14/cc1",
  ]) {
    assert.ok(readerPrints(n), n);
    const opener = { exe: n.startsWith("/") ? n : `/usr/bin/${n}`, sha256: H, ...SYS };
    assert.equal(decideOpen("/ws/.env", { readers: [n] }, opener, { ask: "always" }).verdict, "deny", n);
    assert.equal(decideOpen("/ws/.env", { readers: [n], others: "twin" }, opener, { ask: "always" }).verdict, "twin", n);
  }
  // still leaf programs: a checksum (its -c prints only a well-formed
  // line's name field), ssh-keygen, stat, ls
  for (const n of ["sha256sum", "/usr/bin/gnusha256sum", "md5sum", "ssh-keygen", "stat", "ls"]) assert.equal(readerPrints(n), false, n);
});

test("NEW (2026-10-04): each such program, where installed, does print a file it is pointed at (a dummy token, never a secret)", { skip: process.platform !== "linux" }, (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-prints-when-asked-"));
  try {
    const f = join(tmp, "probe.env");
    const token = `PROBE_${process.pid}_x7Qm`;
    writeFileSync(f, `API_TOKEN=${token}\n`);
    let ran = 0;
    for (const { app, argv } of PRINTS_WHEN_ASKED) {
      if (spawnSync("sh", ["-c", `command -v ${app}`]).status !== 0) continue;
      const r = spawnSync(app, argv(f), { cwd: tmp, encoding: "utf8", timeout: 10_000, env: { ...process.env, PAGER: "cat", MANPAGER: "cat", LC_ALL: "C" } });
      if (r.error) continue;
      ran++;
      assert.ok(`${r.stdout}${r.stderr}`.includes(token), `${app} ${argv("F").join(" ")} printed the file's line: ${r.stdout}${r.stderr}`);
      assert.ok(readerPrints(app), `${app} is on the printer list`);
    }
    if (ran === 0) t.skip("none of the programs is installed here");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("non-printer readers are unchanged: a listed leaf reads raw, a known consumer is a default reader, an unlisted one is asked", () => {
  const sshAdd = { exe: "/usr/bin/ssh-add", sha256: H, ...SYS };
  assert.equal(entryAdmitsNothing("ssh-add"), false);
  const d = decideOpen("/ws/.env", { readers: ["cat", "ssh-add"] }, sshAdd);
  assert.equal(d.verdict, "raw", d.why);
  assert.equal(decideOpen("/ws/.env", { readers: [{ app: "ssh-add", path: "/usr/bin/ssh-add", sha256: H }] }, sshAdd).verdict, "raw");
  assert.equal(decideOpen("/h/.ssh/id_test", {}, sshAdd).verdict, "raw", "the consumer table's default reader");
  assert.equal(decideOpen("/h/.ssh/id_test", { readers: ["cat"] }, sshAdd, { ask: "known" }).verdict, "ask", "a known consumer not listed is still asked");
  // a renamed copy the human pinned by path and hash is that program, not a printer
  const tool = { exe: "/opt/acme/bin/acme-load", sha256: H, exeSystem: false, loaderEnv: [] as string[] };
  assert.equal(decideOpen("/ws/.env", { readers: [{ app: "acme-load", path: "/opt/acme/bin/acme-load", sha256: H, prints: "nothing" }] }, tool).verdict, "raw");
  assert.equal(decideOpen("/ws/.env", { readers: [{ app: "acme-load", path: "/opt/acme/bin/acme-load", sha256: H }] }, tool).verdict, "twin", "a pin alone is no word (D8 (12))");
});

/** Plan 13 §4.9 option (a), the maintainer's decision of 2026-10-04: git
 *  prints any named file (`git diff --no-index /dev/null <file>`, `git grep
 *  --no-index`, `git config -f <file> --list`), so it joins the printers.
 *  Each `twin`/`deny` below was `raw` on the code before: a listed git, and
 *  git as the default reader of `.git-credentials`, `.netrc` and the ssh
 *  keys, read the real file. */
test("NEW (2026-10-04): git is a printer: listed, it admits nothing; as the consumer table's reader it gets the twin the wire release serves; ssh still reads the keys", () => {
  const gito = { exe: "/usr/bin/git", sha256: H, ...SYS };
  const wire = { wireTwin: { why: "git: git_SSL_CAINFO; basic auth in a header" } };
  for (const n of ["git", "/usr/bin/git", "/usr/lib/git-core/git", "git-credential-store", "/usr/lib/git-core/git-credential-store", "git-remote-http", "git-remote-https", "git-remote-ftp", "git-remote-ftps", "git.real"]) {
    assert.ok(readerPrints(n), n);
    assert.ok(entryAdmitsNothing(n), n);
  }
  // not every name that starts like git's
  for (const n of ["gitk", "git-lfs", "gitlab-runner", "gitea", "gh"]) assert.equal(readerPrints(n), false, n);
  for (const ask of ["never", "known", "always"] as const) {
    // a .env listing git: deny, the twin under others: twin, never asked
    const d = decideOpen("/ws/.env", { readers: ["git"] }, gito, { ask });
    assert.equal(d.verdict, "deny", `${ask}: ${d.why}`);
    assert.match(d.why, /prints or copies/);
    assert.equal(decideOpen("/ws/.env", { readers: ["git"], others: "twin" }, gito, { ask }).verdict, "twin", ask);
    assert.equal(decideOpen("/ws/.env", { readers: [{ app: "git", path: "/usr/bin/git", sha256: H }] }, gito, { ask }).verdict, "deny", `${ask}: a pin by path and hash too`);
  }
  for (const p of ["/h/.git-credentials", "/h/.config/git/credentials", "/h/.netrc"]) {
    // .netrc's opener for git is its HTTP transport (on the row since
    // 2026-10-04: red before, a listed .netrc refused it under the wire
    // release); .git-credentials' is git or its store helper
    for (const exe of p.endsWith(".netrc") ? ["/usr/bin/git", "/usr/lib/git-core/git-remote-https", "/usr/lib/git-core/git-remote-http"] : ["/usr/bin/git", "/usr/lib/git-core/git-credential-store"]) {
      const o = { ...gito, exe };
      // the wire release (TLS inspection): its twin, listed or not, as before for the unlisted
      assert.equal(decideOpen(p, {}, o, { ask: "known", ...wire }).verdict, "twin", `${p} ${exe}`);
      assert.equal(decideOpen(p, { readers: ["git"] }, o, { ask: "known", ...wire }).verdict, "twin", `${p} ${exe} listed`);
      assert.equal(decideOpen(p, { readers: ["ssh-add"] }, o, { ask: "always", ...wire }).verdict, "twin", `${p} ${exe} not listed`);
      // without it: what a non-reader gets (the twin with no list; red before: raw)
      const d = decideOpen(p, {}, o, { ask: "known" });
      assert.equal(d.verdict, "twin", `${p} ${exe}: ${d.why}`);
      assert.equal(decideOpen(p, { readers: ["git"] }, o, { ask: "known" }).verdict, "deny", `${p} ${exe} listed, no wire release`);
    }
  }
  // the ssh keys: git is on the row, but ssh (which git starts) is the reader
  const key = "/h/.ssh/id_ed25519";
  assert.equal(decideOpen(key, {}, gito, { ask: "known" }).verdict, "twin", "git diff --no-index of the key: no raw byte (red before: raw)");
  const ssh = { exe: "/usr/bin/ssh", sha256: H, ...SYS, ancestors: [{ exe: "/usr/lib/git-core/git", trusted: true }] };
  assert.equal(decideOpen(key, {}, ssh).verdict, "raw", "ssh, a default reader of its key");
  assert.equal(decideOpen(key, { readers: [{ app: "ssh", from: "git" }] }, ssh).verdict, "raw", "{ app: ssh, from: git } still admits the ssh git starts");
  assert.equal(decideOpen(key, { readers: [{ app: "ssh", from: "git" }] }, gito).verdict, "deny", "but not git itself");
});

test("NEW (2026-10-04): a link or copy of git under any name (git-diff, git-cat-file in git's exec path) is git, a printer, by its hash; git's exec path is scanned", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-git-core-"));
  clearPrinterHashesForTest();
  try {
    const bin = join(dir, "bin"); const core = join(dir, "git-core");
    mkdirSync(bin); mkdirSync(core);
    writeFileSync(join(bin, "git"), "git-BYTES");
    linkSync(join(bin, "git"), join(core, "git-diff")); // a hard link (git's own make install default)
    symlinkSync(join(bin, "git"), join(core, "git-cat-file")); // a symbolic link (Ubuntu 26.04)
    writeFileSync(join(core, "git-remote-http"), "REMOTE-HTTP-BYTES");
    writeFileSync(join(core, "git-shell"), "SHELL-BYTES");
    const git_SHA = createHash("sha256").update("git-BYTES").digest("hex");
    const found = scanProgramHashes([bin, core]);
    assert.deepEqual([...found.prints.keys()].sort(), [git_SHA, createHash("sha256").update("REMOTE-HTTP-BYTES").digest("hex")].sort(), "git and its HTTP transport; git-shell is no printer by name");
    addPrinterHashes(found.prints);
    // git run as git-diff (a hard link keeps its name in /proc/<pid>/exe)
    const diff = { exe: join(core, "git-diff"), sha256: git_SHA, exeSystem: true, loaderEnv: [] as string[] };
    assert.equal(readerPrints(diff.exe), false, "not by its name");
    const d = decideOpen("/ws/.env", { readers: [{ app: "git-diff", path: diff.exe, sha256: git_SHA }] }, diff, { ask: "always" });
    assert.equal(d.verdict, "deny", d.why);
    assert.match(d.why, /copy of a program that prints/);
    assert.equal(decideOpen("/h/.git-credentials", {}, diff, { ask: "known" }).verdict, "twin");
    assert.ok(policyWarnings({ version: 1, paths: [{ path: "/ws/.env", level: "no-model", readers: [{ app: "mdu-gitcopy", path: "/opt/x/mdu-gitcopy", sha256: git_SHA }] }] })
      .some((l) => /mdu-gitcopy is a copy of a program that prints/.test(l)));
    // the production scan covers git's exec path (Debian/Ubuntu/Arch and Fedora)
    assert.ok(SCAN_DIRS.includes("/usr/lib/git-core") && SCAN_DIRS.includes("/usr/libexec/git-core"), SCAN_DIRS.join(" "));
  } finally {
    clearPrinterHashesForTest();
    refreshProgramHashes({ minIntervalMs: 0 });
    rmSync(dir, { recursive: true, force: true });
  }
});

test("NEW (2026-10-04): on this host, the installed git's builtins (git-credential-store, git-diff) hash as git, a printer", { skip: !existsSync("/usr/lib/git-core/git-credential-store") && !existsSync("/usr/libexec/git-core/git-credential-store") ? "git's exec path is not installed here" : false }, () => {
  refreshProgramHashes({ minIntervalMs: 0 });
  const core = existsSync("/usr/lib/git-core/git-credential-store") ? "/usr/lib/git-core" : "/usr/libexec/git-core";
  for (const n of ["git-credential-store", "git-diff", "git-cat-file"]) {
    const p = join(core, n);
    if (!existsSync(p)) continue;
    const sha = createHash("sha256").update(readFileSync(p)).digest("hex");
    assert.ok(hashPrints(sha), `${p} is git by its hash`);
  }
});

test("NEW (2026-10-04): policyWarnings says git is a printer, how it prints, and what still works", () => {
  const w = policyWarnings({
    version: 1,
    paths: [
      { path: "/h/.git-credentials", level: "no-model", readers: [{ app: "git", path: "/usr/bin/git", sha256: H }] },
      { path: "/ws/.env", level: "no-model", readers: ["git-credential-store", "ssh-add"] },
    ],
    ssh_agent: { readers: ["git", { app: "ssh", from: "git" }] },
  });
  assert.ok(w.some((l) => l.startsWith("paths[0].readers[0]: git is a printer") && /git diff --no-index/.test(l) && /admits nothing/.test(l) && /TLS inspection/.test(l)), w.join("\n"));
  assert.ok(w.some((l) => l.startsWith("paths[1].readers[0]: git-credential-store is a printer")), w.join("\n"));
  assert.ok(!w.some((l) => l.startsWith("paths[1].readers[1]")), "ssh-add earns none");
  assert.ok(w.some((l) => l.startsWith("ssh_agent.readers[0]: git prints or copies") && /from: git/.test(l)), w.join("\n"));
  assert.ok(!w.some((l) => l.startsWith("ssh_agent.readers[1]")), "{ app: ssh, from: git } earns none");
});

test("printerOpenVerdict: an open answer about a printer applies to nothing; a write answer and a leaf program's stand", () => {
  assert.equal(printerOpenVerdict(`open:/usr/bin/cat#${H}`), true);
  assert.equal(printerOpenVerdict(`open:/usr/lib/cargo/bin/coreutils/wc#${H}`), true);
  assert.equal(printerOpenVerdict("open:head"), true, "a row from before 2026-10-02 names the program alone");
  assert.equal(printerOpenVerdict(`open:/usr/bin/ssh-add#${H}`), false);
  assert.equal(printerOpenVerdict(`open:/usr/bin/git#${H}`), true, "an Always for git given before 2026-10-04 applies to nothing");
  assert.equal(printerOpenVerdict(`write:/usr/bin/tee#${H}`), false, "a held change to a protected file is another question");
});

test("policyWarnings names a printer reader (any form) as admitting nothing; on the ssh-agent socket's list too (leftover (3b))", () => {
  const w = policyWarnings({
    version: 1,
    paths: [
      { path: "/ws/.env", level: "no-model", readers: ["cat", "ssh-add", { app: "mycat", path: "/usr/bin/cat", sha256: H }] },
    ],
    ssh_agent: { readers: ["ssh", "socat"] },
  });
  assert.equal(w.filter((l) => /prints or copies/.test(l)).length, 3, w.join("\n"));
  assert.ok(w.some((l) => l.startsWith("paths[0].readers[0]: cat prints or copies") && /admits nothing/.test(l) && /a pin by path and hash included/.test(l)), w.join("\n"));
  assert.ok(w.some((l) => l.startsWith("paths[0].readers[2]: mycat prints or copies")), w.join("\n"));
  assert.ok(!w.some((l) => l.startsWith("paths[0].readers[1]")), "ssh-add earns no warning");
  assert.ok(w.some((l) => l.startsWith("ssh_agent.readers[1]: socat prints or copies") && /admits nothing/.test(l)), w.join("\n"));
  assert.ok(!w.some((l) => l.startsWith("ssh_agent.readers[0]")), "ssh earns no warning");
});

/** A real server, both sockets, a policy file on disk. */
async function rig(fn: (r: { guard: ArbiterClient; admin: ArbiterClient; s: ArbiterServer; dir: string; secret: string; policy: string }) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-printer-"));
  const secret = join(dir, ".env");
  writeFileSync(secret, "API_KEY=printer_canary_0000000001\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [cat, base64, ssh-add]\n    others: twin\n`);
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), policyPath: policy, policyPollMs: 0, log: () => {}, confidentiality: true, integrity: false,
  });
  await s.listen();
  const guard = new ArbiterClient(join(dir, "human", "h.sock")); await guard.connect();
  const admin = new ArbiterClient(join(dir, "admin.sock")); await admin.connect();
  try { await fn({ guard, admin, s, dir, secret, policy }); } finally { guard.close(); admin.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); }
}

test("NEW, over a real server: a listed cat gets the twin, no taint, no pin, no Inbox row under ask: always; ssh-add beside it reads raw", async () => {
  await rig(async ({ guard, admin, secret, policy }) => {
    for (const [exe, n] of [["/usr/bin/cat", 1], ["/usr/bin/base64", 2], ["/usr/lib/cargo/bin/coreutils/cat", 3]] as const) {
      const d = await guard.decideSecretOpen({ path: secret, exe, sha256: H, isAgent: false, exeSystem: true, openerEnv: [], procKey: `p-${n}`, session: "pr", ask: "always" });
      assert.equal(d.verdict, "twin", `${exe}: ${d.verdict} ${d.reason}`);
      assert.equal(d.approvalId, undefined, "never asked about");
      assert.equal((await guard.processSecretTaint(`p-${n}`)).level, null, "no taint row");
    }
    assert.ok(!readFileSync(policy, "utf8").includes("/usr/bin/cat"), "no pin written");
    assert.deepEqual((await admin.egressApprovals("pending")).filter((a) => a.symbol.startsWith("open:")), [], "no Inbox row");
    const raw = await guard.decideSecretOpen({ path: secret, exe: "/usr/bin/ssh-add", sha256: H, isAgent: false, exeSystem: true, openerEnv: [], procKey: "q-1", session: "pr" });
    assert.equal(raw.verdict, "raw", raw.reason);
    // `mandu why` / the dashboard: the entries are marked, the printers named
    const why = await admin.whyPath(secret);
    assert.deepEqual(why.readersAdmitNothing, [true, true, false]);
    assert.deepEqual(why.readersPrint, [true, true, false]);
  });
});

test("NEW, over a real server: a past Always (and a once) for /usr/bin/cat no longer counts and is not spent; whyPath marks it", async () => {
  await rig(async ({ guard, admin, s, secret }) => {
    const store = (s as unknown as { egressApprovals: { recordPending(sym: string, d: string, r: string): { id: string }; resolve(id: string, approve: boolean, scope: "once" | "always"): unknown } }).egressApprovals;
    const always = store.recordPending(`open:/usr/bin/cat#${H}`, secret, "cat wants to read it");
    store.resolve(always.id, true, "always"); // answered by an arbiter before the decision
    const once = store.recordPending(`open:/usr/bin/head#${H}`, secret, "head wants to read it");
    store.resolve(once.id, true, "once");
    for (const [exe, n] of [["/usr/bin/cat", 1], ["/usr/bin/head", 2]] as const) {
      const d = await guard.decideSecretOpen({ path: secret, exe, sha256: H, isAgent: false, exeSystem: true, openerEnv: [], procKey: `v-${n}`, session: "pv", ask: "known" });
      assert.equal(d.verdict, "twin", `${exe}: ${d.verdict} ${d.reason}`);
      assert.doesNotMatch(d.reason, /human-approved/);
      assert.equal((await guard.processSecretTaint(`v-${n}`)).level, null);
    }
    const rows = await admin.egressApprovals();
    assert.equal(rows.find((r) => r.id === once.id)?.consumedAt ?? null, null, "the once is not spent");
    const why = await admin.whyPath(secret);
    const opens = why.verdicts.filter((v) => v.kind !== "write");
    assert.ok(opens.length === 2 && opens.every((v) => v.printer === true), JSON.stringify(opens));
  });
});

test("NEW, over a real server: a printer holding every source of a derived copy gets its twin; a leaf holder still reads it raw", async () => {
  await rig(async ({ guard, dir, secret }) => {
    assert.ok((await guard.registerSecret({ path: secret })).symbol);
    assert.equal((await guard.decideSecretOpen({ path: secret, exe: "/usr/bin/ssh-add", sha256: H, isAgent: false, exeSystem: true, openerEnv: [], procKey: "dc-1" })).verdict, "raw");
    const copy = join(dir, "copy.txt");
    writeFileSync(copy, "API_KEY=printer_canary_0000000001\n");
    assert.equal((await guard.labelWrittenPathTainted({ path: copy, procKey: "dc-1" })).labeled, true);
    const cat = await guard.decideSecretOpen({ path: copy, exe: "/usr/bin/cat", sha256: H, isAgent: false, exeSystem: true, openerEnv: [], procKey: "dc-2", parentKey: "dc-1" });
    assert.equal(cat.verdict, "twin", cat.reason);
    const leaf = await guard.decideSecretOpen({ path: copy, exe: "/usr/bin/ssh-add", sha256: H, isAgent: false, exeSystem: true, openerEnv: [], procKey: "dc-3", parentKey: "dc-1" });
    assert.equal(leaf.verdict, "raw", leaf.reason);
  });
});

test("NEW (2026-10-04), over a real server: git is never asked about, gets no raw byte and no taint; whyPath marks git and its credential helper as printing consumers", async () => {
  await rig(async ({ guard, admin, dir, secret, policy }) => {
    for (const [exe, n] of [["/usr/bin/git", 1], ["/usr/lib/git-core/git-credential-store", 2]] as const) {
      const d = await guard.decideSecretOpen({ path: secret, exe, sha256: H, isAgent: false, exeSystem: true, openerEnv: [], procKey: `git-${n}`, session: "pg", ask: "always" });
      assert.equal(d.verdict, "twin", `${exe}: ${d.verdict} ${d.reason}`);
      assert.match(String(d.reason), /prints or copies/);
      assert.equal(d.approvalId, undefined, "never asked about, even under ask: always");
      assert.equal((await guard.processSecretTaint(`git-${n}`)).level, null, "no taint row");
    }
    assert.ok(!readFileSync(policy, "utf8").includes("/usr/bin/git"), "no pin written");
    assert.deepEqual((await admin.egressApprovals("pending")).filter((a) => a.symbol.startsWith("open:")), [], "no Inbox row");
    const gc = await admin.whyPath(join(dir, ".git-credentials"));
    assert.deepEqual(gc.consumers, ["git", "git-credential-store"]);
    assert.deepEqual(gc.consumersPrint, [true, true]);
    const pg = await admin.whyPath(join(dir, ".pgpass"));
    // psql and pg_restore print a file (plan 13 D8 (12)'s correction); pg_dump does not
    assert.deepEqual(pg.consumersPrint, [true, false, true]);
  });
});
