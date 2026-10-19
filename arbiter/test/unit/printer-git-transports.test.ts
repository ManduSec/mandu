/**
 * printer-git-transports — git's separately built transports are printers
 * (plan 13 D8 (11), extended 2026-10-07).
 *
 * Since 2026-10-04 `git` is a printer (plan 13 §4.9 option (a)), with its
 * credential helper and its HTTP transport `git-remote-http`. The three
 * copies of the printer list then said that every other name in git's exec
 * path is a link of git, a printer by its hash. Not so: git's own Makefile
 * builds `git-http-fetch`, `git-http-push`, `git-imap-send` and
 * `git-http-backend` as programs of their own (Ubuntu's `git` package ships
 * all four as separate ELF files). The first three link git's `http.c`, so
 * libcurl opens `~/.netrc` for them, and `GIT_TRACE_CURL=1
 * GIT_TRACE_REDACT=0` prints the `Authorization` header they send;
 * `git-http-backend` (the CGI server) sends a file named in its request
 * (`objects/info/alternates`, a symlink to any file, comes back whole). On
 * the code before, none was on the list and the hash scan skipped them (it
 * hashes only files whose name is a printer), so a `{ app: git-http-fetch,
 * prints: nothing }` (the very words Mandu's own hint suggests) read
 * `.netrc` raw under every `ask` mode, with no warning.
 *
 * Each NEW test was red on that code; the CONTROL tests run the same checks
 * over `git-remote-http`, a printer since 2026-10-04, and were green.
 * Axes: secrets.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { decideOpen, entryAdmitsNothing, hashPrints, knownConsumers, readerPrints } from "../../policy/flow-taint.js";
import { refreshProgramHashes } from "../../policy/program-hashes.js";
import { policyWarnings } from "../../policy/policy-file-validate.js";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const SYS = { exeSystem: true, loaderEnv: [] as string[] };
const H = "e".repeat(64);
/** git's separately built programs that read `.netrc` (libcurl, git's
 *  `http.c`) or send a named file (`git-http-backend`). */
const TRANSPORTS = ["git-http-fetch", "git-http-push", "git-imap-send", "git-http-backend"] as const;
/** The control: a printer since 2026-10-04. */
const CONTROL = ["git-remote-http"] as const;
const CORE = ["/usr/lib/git-core", "/usr/libexec/git-core"].find((d) => existsSync(join(d, "git-http-fetch")));

function printsByName(names: readonly string[]): void {
  for (const n of names) {
    for (const form of [n, `/usr/lib/git-core/${n}`, `/usr/libexec/git-core/${n}`]) {
      assert.ok(readerPrints(form), `${form} is a printer`);
      assert.ok(entryAdmitsNothing(form), `${form} admits nothing`);
      assert.ok(entryAdmitsNothing({ app: form, prints: "nothing" }), `${form}: the human's word cannot lift it`);
    }
  }
}

function vouchedEntryReadsNothingRaw(names: readonly string[]): void {
  for (const n of names) {
    const o = { exe: `/usr/lib/git-core/${n}`, sha256: H, ...SYS };
    for (const ask of ["never", "known", "always"] as const) {
      for (const p of ["/h/.netrc", "/ws/.env"]) {
        const d = decideOpen(p, { readers: [{ app: n, prints: "nothing" }] }, o, { ask });
        assert.notEqual(d.verdict, "raw", `${n} ${p} ${ask}: ${d.why}`);
        assert.notEqual(d.verdict, "ask", `${n} ${p} ${ask}: never asked about`);
        assert.match(d.why, /prints or copies/, `${n} ${p} ${ask}`);
        // others: twin gives the twin, never a byte
        assert.equal(decideOpen(p, { readers: [{ app: n, prints: "nothing" }], others: "twin" }, o, { ask }).verdict, "twin", `${n} ${p} ${ask}`);
      }
    }
    const w = policyWarnings({ version: 1, paths: [{ path: "/h/.netrc", level: "no-model", readers: [{ app: n, prints: "nothing" }] }] });
    assert.ok(w.some((l) => l.startsWith(`paths[0].readers[0]: ${n} is a printer`) && /admits nothing/.test(l) && /prints: nothing cannot change that/.test(l)), `${n}: ${w.join("\n")}`);
  }
}

function installedPrintByHash(names: readonly string[]): void {
  refreshProgramHashes({ minIntervalMs: 0 });
  for (const n of names) {
    const p = join(CORE!, n);
    if (!existsSync(p)) continue; // a build without curl or expat leaves some out
    const sha = createHash("sha256").update(readFileSync(p)).digest("hex");
    assert.ok(hashPrints(sha), `${p} is a printer by its hash`);
    // a copy under another name, pinned by path and hash, admits nothing
    assert.ok(entryAdmitsNothing({ app: "mdu-fetch", path: "/opt/x/mdu-fetch", sha256: sha, prints: "nothing" }), `a renamed copy of ${n}`);
    const d = decideOpen("/h/.netrc", { readers: [{ app: "mdu-fetch", path: "/opt/x/mdu-fetch", sha256: sha, prints: "nothing" }] }, { exe: "/opt/x/mdu-fetch", sha256: sha, ...SYS }, { ask: "always" });
    assert.equal(d.verdict, "deny", `${n} renamed: ${d.why}`);
  }
}

const noCore = CORE === undefined ? "git's exec path with git-http-fetch is not installed here" : false;

test("NEW: git-http-fetch, git-http-push, git-imap-send and git-http-backend are printers by name (any path form), and admit nothing", () => {
  printsByName(TRANSPORTS);
});
test("CONTROL: git-remote-http is a printer by name, and admits nothing", () => {
  printsByName(CONTROL);
});

test("NEW: a listed { app: git-http-fetch, prints: nothing } (or -push, -imap-send, -backend) reads no file raw under any ask mode, and policyWarnings says why", () => {
  vouchedEntryReadsNothingRaw(TRANSPORTS);
});
test("CONTROL: a listed { app: git-remote-http, prints: nothing } reads no file raw under any ask mode", () => {
  vouchedEntryReadsNothingRaw(CONTROL);
});
test("NEW: policyWarnings says how a transport prints (the login it sends), not `git diff`'s way", () => {
  for (const n of [...TRANSPORTS, ...CONTROL]) {
    const w = policyWarnings({ version: 1, paths: [{ path: "/h/.netrc", level: "no-model", readers: [n] }] });
    assert.ok(w.some((l) => l.startsWith(`paths[0].readers[0]: ${n} is a printer`) && /GIT_TRACE_CURL/.test(l) && !/git diff --no-index/.test(l)), `${n}: ${w.join("\n")}`);
  }
  // git itself keeps its own words
  assert.ok(policyWarnings({ version: 1, paths: [{ path: "/h/.netrc", level: "no-model", readers: ["git"] }] }).some((l) => /git diff --no-index/.test(l)));
});

test("NEW: on this host the installed transports are printers by their hash (git's exec path is scanned)", { skip: noCore }, () => {
  installedPrintByHash(TRANSPORTS);
});
test("CONTROL: on this host the installed git-remote-http is a printer by its hash", { skip: noCore }, () => {
  installedPrintByHash(CONTROL);
});

test("NEW: git-http-fetch and git-http-push (spawned by git for a dumb-HTTP fetch and a WebDAV push) are .netrc's known consumers: served the twin under the wire release, else what a non-reader gets; git-imap-send (IMAP, not HTTP) is not", () => {
  assert.deepEqual([...knownConsumers("/h/.netrc")], ["curl", "git", "git-remote-http", "git-remote-https", "git-http-fetch", "git-http-push"]);
  const wire = { wireTwin: { why: "git: GIT_SSL_CAINFO; basic auth in a header" } };
  for (const n of ["git-http-fetch", "git-http-push"]) {
    const o = { exe: `/usr/lib/git-core/${n}`, sha256: H, ...SYS };
    assert.equal(decideOpen("/h/.netrc", {}, o, { ask: "known", ...wire }).verdict, "twin", n);
    assert.equal(decideOpen("/h/.netrc", { readers: ["curl"] }, o, { ask: "known", ...wire }).verdict, "twin", `${n}, not listed: the wire twin`);
    assert.equal(decideOpen("/h/.netrc", { readers: [{ app: n, prints: "nothing" }] }, o, { ask: "always", ...wire }).verdict, "twin", `${n}, vouched: the wire twin, no raw byte`);
    assert.equal(decideOpen("/h/.netrc", { readers: [{ app: n, prints: "nothing" }] }, o, { ask: "known" }).verdict, "deny", `${n}, vouched, no wire release`);
  }
  const imap = { exe: "/usr/lib/git-core/git-imap-send", sha256: H, ...SYS };
  assert.equal(decideOpen("/h/.netrc", { readers: [{ app: "git-imap-send", prints: "nothing" }] }, imap, { ask: "known", ...wire }).verdict, "deny", "IMAP: no wire twin, a listed printer is refused");
  assert.equal(decideOpen("/h/.netrc", {}, imap, { ask: "known", ...wire }).verdict, "twin", "with no list: the twin every program gets");
});

test("NEW, over a real server: { app: git-http-fetch, prints: nothing } on ~/.netrc gets no raw byte, no taint and no Inbox row; whyPath marks the entry", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-git-transport-"));
  const netrc = join(dir, ".netrc");
  writeFileSync(netrc, "machine git.example login u password git_transport_canary_0001\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${netrc}\n    level: no-model\n    readers: [{ app: git-http-fetch, prints: nothing }, { app: git-imap-send, prints: nothing }, ssh-add]\n`);
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), policyPath: policy, policyPollMs: 0, log: () => {}, confidentiality: true, integrity: false,
  });
  await s.listen();
  const guard = new ArbiterClient(join(dir, "human", "h.sock")); await guard.connect();
  const admin = new ArbiterClient(join(dir, "admin.sock")); await admin.connect();
  try {
    for (const [exe, n] of [["/usr/lib/git-core/git-http-fetch", 1], ["/usr/lib/git-core/git-imap-send", 2], ["/usr/libexec/git-core/git-http-push", 3]] as const) {
      for (const ask of ["never", "known", "always"] as const) {
        const key = `gt-${n}-${ask}`;
        const d = await guard.decideSecretOpen({ path: netrc, exe, sha256: H, isAgent: false, exeSystem: true, openerEnv: [], procKey: key, session: "gt", ask });
        assert.notEqual(d.verdict, "raw", `${exe} ${ask}: ${d.reason}`);
        assert.equal(d.approvalId, undefined, `${exe} ${ask}: never asked about`);
        assert.equal((await guard.processSecretTaint(key)).level, null, `${exe} ${ask}: no taint row`);
      }
    }
    assert.deepEqual((await admin.egressApprovals("pending")).filter((a) => a.symbol.startsWith("open:")), [], "no Inbox row");
    // the control beside them: ssh-add, a vetted reader, reads it raw
    assert.equal((await guard.decideSecretOpen({ path: netrc, exe: "/usr/bin/ssh-add", sha256: H, isAgent: false, exeSystem: true, openerEnv: [], procKey: "gt-c", session: "gt" })).verdict, "raw");
    const why = await admin.whyPath(netrc);
    assert.deepEqual(why.readersPrint, [true, true, false]);
    assert.deepEqual(why.readersAdmitNothing, [true, true, false]);
    assert.ok(why.consumers.includes("git-http-fetch") && why.consumers.includes("git-http-push"), JSON.stringify(why.consumers));
  } finally {
    guard.close(); admin.close(); await s.close(); rmSync(dir, { recursive: true, force: true });
  }
});
