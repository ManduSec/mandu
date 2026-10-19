/**
 * write-protect e2e (sandbox-security-review-2026-09-28 findings 2 and 6),
 * across the REAL components: the launcher's main() builds the list and the
 * guard policy file, the REAL mandu-net-guard traps the agent tree's writes,
 * and a REAL ArbiterServer holds the `ask` ones in its Inbox, answered on the
 * admin channel as the dashboard would. The "agent" is a bash script in a
 * throwaway HOME.
 *
 *   - Mandu's own policy.yaml: every change refused, the file unchanged,
 *     its mode included (chmod), and no node (mkfifo) made beside it; a
 *     chmod and a mkfifo elsewhere are performed.
 *   - ~/.bashrc: the append waits; "allow once" lets exactly that one through;
 *     the next append waits again and, unanswered, is refused at the ceiling.
 *   - The answer names the BINARY (write-protection.md §2.1, the Plan 13 D8
 *     follow-up): after "always" for the system's tee (GNU's: `gnutee` where
 *     uutils owns the name, tests/lib/gnu-coreutil.ts), a copy of tee in the
 *     workspace (same bytes, another path) is held under its own row and,
 *     unanswered, refused; the system's tee run with LD_PRELOAD is refused at
 *     once with no row; the system's tee itself still goes through.
 *
 *   - Plan 13 §8 decision (c): an interpreter's answer names the script it
 *     runs (the guard's R5 facts): after "always" for python3 running the
 *     stdlib's tarfile.py, python3 running pickletools.py and `python3 -c`
 *     are each held under their own row and, unanswered, refused; the
 *     answered pair still goes through. The agent's shell appending to
 *     ~/.bashrc above is keyed by its run.
 *
 * Self-SKIPs where the guard is not built (scripts/build-native.sh) or the
 * kernel has no seccomp user notification.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { main } from "../../launcher/test/lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { axesEnv, stateAxes } from "../lib/axes.js";
import { pickGuard } from "../lib/native-guard.js";
import { gnuCoreutil } from "../lib/gnu-coreutil.js";

stateAxes("injection"); // the confidentiality axis OFF: write protection must hold anyway

const HERE = dirname(fileURLToPath(import.meta.url));
const TARGET = resolve(HERE, "..", "..", "interceptors", "target");
// The newest FRESH build (lib/native-guard.ts): a stale bin tests an older guard.
const PICK = pickGuard(TARGET);
const GUARD = PICK.path;
/** The system's tee as a plain binary: GNU's (`gnutee` where uutils owns the
 *  name). uutils' tee is the multi-call binary every uutils program is, which
 *  Mandu counts as running code, so an Always for it covers one run
 *  (`write:<exe>#<sha256>#run:<proc>`), not the binary this test pins. */
const TEE = gnuCoreutil("tee");
const skip = process.platform !== "linux" || !GUARD ? "mandu-net-guard is not built (scripts/build-native.sh)"
  : TEE === undefined ? "no GNU tee (uutils' tee is a multi-call binary, answered per run)" : false;


test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD }, () => {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
});
test("the agent tree cannot change Mandu's policy, and a .bashrc change waits for the human", { skip, timeout: 120_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-wp-e2e-"));
  const home = join(dir, "home");
  mkdirSync(join(home, ".mandu", "packs"), { recursive: true });
  const law = join(home, ".mandu", "policy.yaml");
  writeFileSync(law, "# the law\n");
  chmodSync(law, 0o600);
  const fifo = join(home, ".mandu", "packs", "fifo");
  const freeFile = join(dir, "free.sh");
  const freeFifo = join(dir, "free.fifo");
  const rc = join(home, ".bashrc");
  writeFileSync(rc, "# startup\n");
  const out = join(dir, "out");
  const go = join(dir, "go");
  // The D8 follow-up: the system's tee as the guard sees it (/proc/<pid>/exe
  // is the resolved path), a copy in the workspace, and a harmless library
  // to preload (the system's libc; in an attack, the agent's own).
  const tee = TEE!.path;
  const ws = join(realpathSync(dir), "ws");
  mkdirSync(ws);
  const teeCopy = join(ws, "tee");
  const libc = execFileSync("sh", ["-c", `ldd ${tee} | awk '/libc\\.so/ {print $3; exit}'`], { encoding: "utf8" }).trim();
  const sock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  // The human plane: the guard reports there, where its protected-write holds
  // are believed (plan 13 D9: from the data socket they are refused).
  const server = new ArbiterServer({ socketPath: sock, adminSocketPath: adminSock, humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "sym.db"), eventDir: join(dir, "events"), log: () => {} });
  await server.listen();
  const admin = new ArbiterClient(adminSock);
  await admin.connect();
  const lines: string[] = [];
  const orig = console.error;
  const savedBin = process.env["MANDU_NET_GUARD_BIN"];
  const savedAsk = process.env["MANDU_SECRETS_ASK_TIMEOUT"];
  const savedManduHome = process.env["MANDU_HOME"];
  try {
    // 1. the law; 2. .bashrc (held, answered once); 3. wait for the test's
    //    go-ahead, then .bashrc again (held, unanswered: refused at 3 s).
    const script =
      `echo 'relax: all' >> ${law} 2>/dev/null; echo "law=$?" > ${out}; ` +
      `mv ${law} ${law}.gone 2>/dev/null; echo "mv=$?" >> ${out}; ` +
      // Finding 3: remove the arbiter's socket (to stand up an impostor).
      `rm ${sock} 2>/dev/null; echo "sock=$?" >> ${out}; ` +
      // write-protection.md §4: a mode change and a node (mknodat) under
      // Mandu's own files; the same two elsewhere are performed.
      `chmod 666 ${law} 2>/dev/null; echo "chmod=$?" >> ${out}; ` +
      `mkfifo ${fifo} 2>/dev/null; echo "mkfifo=$?" >> ${out}; ` +
      `echo x > ${freeFile}; chmod 750 ${freeFile}; echo "freechmod=$?" >> ${out}; ` +
      `mkfifo ${freeFifo}; echo "freefifo=$?" >> ${out}; ` +
      // write-protection.md §2 "Extended attributes": an attribute change of
      // Mandu's own file is refused; the same elsewhere is performed. Recorded
      // as skip where setfattr is missing.
      `if command -v setfattr >/dev/null; then ` +
      `setfattr -n user.mandu_e2e -v 1 ${law} 2>/dev/null; echo "xattr=$?" >> ${out}; ` +
      `setfattr -n user.mandu_e2e -v 1 ${freeFile} 2>/dev/null; echo "freexattr=$?" >> ${out}; ` +
      `else echo "xattr=skip" >> ${out}; fi; ` +
      `echo one >> ${rc}; echo "rc1=$?" >> ${out}; ` +
      `while [ ! -e ${go} ]; do sleep 0.1; done; ` +
      `echo two >> ${rc} 2>/dev/null; echo "rc2=$?" >> ${out}; ` +
      // The D8 follow-up: the system's tee (held; the test answers Always),
      // then a copy of it in the workspace, then the system's tee with
      // LD_PRELOAD, then the system's tee again.
      `echo tee1 | ${tee} -a ${rc} >/dev/null 2>&1; echo "tee1=$?" >> ${out}; ` +
      `cp ${tee} ${teeCopy}; echo copy | ${teeCopy} -a ${rc} >/dev/null 2>&1; echo "copy=$?" >> ${out}; ` +
      (libc ? `echo preload | LD_PRELOAD=${libc} ${tee} -a ${rc} >/dev/null 2>&1; echo "preload=$?" >> ${out}; ` : `echo "preload=skip" >> ${out}; `) +
      `echo tee2 | ${tee} -a ${rc} >/dev/null 2>&1; echo "tee2=$?" >> ${out}`;
    console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
    process.env["MANDU_NET_GUARD_BIN"] = GUARD!;
    process.env["MANDU_SECRETS_ASK_TIMEOUT"] = "3000";
    process.env["MANDU_HOME"] = join(home, ".mandu");
    const run = main(
      ["--target", "claude", "--no-scope", "--no-landlock-net", "--no-reply-filter", "--no-net-proxy", "--no-exec-box", "--", "bash", "-c", script],
      {
        HOME: home, PWD: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
        MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: join(home, ".mandu"), MANDU_MODE: "injection", ...axesEnv("injection"), XDG_RUNTIME_DIR: dir,
      },
    );
    // The first .bashrc append is held: answer it once, as the Inbox would.
    const deadline = Date.now() + 60_000;
    let heldId: string | undefined;
    while (!heldId && Date.now() < deadline) {
      heldId = (await admin.egressApprovals("pending")).find((e) => e.symbol.startsWith("write:") && e.destination === rc)?.id;
      if (!heldId) await new Promise((r) => setTimeout(r, 100));
    }
    assert.ok(heldId, `no Inbox row for ${rc}; launcher said:\n${lines.join("\n")}`);
    await admin.resolveEgressApproval(heldId!, true, "once");
    // Let the agent try again once the answer is spent.
    while (!readFileSync(out, "utf8").includes("rc1=") && Date.now() < deadline) await new Promise((r) => setTimeout(r, 100));
    writeFileSync(go, "");
    // The system's tee asks under its binary: answer Always.
    let teeRow: { id: string; symbol: string } | undefined;
    while (!teeRow && Date.now() < deadline) {
      // By name too (`write:tee`, an arbiter before the D8 follow-up), so the
      // run goes on and the copy's assertion below is what fails there.
      teeRow = (await admin.egressApprovals("pending")).find((e) => (e.symbol.startsWith(`write:${tee}#`) || e.symbol === "write:tee") && e.destination === rc);
      if (!teeRow) await new Promise((r) => setTimeout(r, 100));
    }
    assert.ok(teeRow, `no Inbox row for ${tee}; launcher said:\n${lines.join("\n")}`);
    await admin.resolveEgressApproval(teeRow!.id, true, "always");
    // The copy asks under its own path (left unanswered: refused at 3 s).
    let copyRow: { reason: string } | undefined;
    while (!copyRow && Date.now() < deadline && !readFileSync(out, "utf8").includes("copy=")) {
      copyRow = (await admin.egressApprovals("pending")).find((e) => e.symbol.startsWith(`write:${teeCopy}#`) && e.destination === rc);
      if (!copyRow) await new Promise((r) => setTimeout(r, 100));
    }
    const code = await run;
    console.error = orig;
    const got = Object.fromEntries(readFileSync(out, "utf8").trim().split("\n").map((l) => l.split("=") as [string, string]));
    assert.equal(code, 0, lines.join("\n"));
    assert.notEqual(got["law"], "0", "the append to Mandu's policy.yaml went through");
    assert.notEqual(got["mv"], "0", "Mandu's policy.yaml was renamed away");
    assert.equal(readFileSync(law, "utf8"), "# the law\n");
    assert.notEqual(got["sock"], "0", "the arbiter's socket was removed from inside the agent");
    assert.ok(existsSync(sock), "the arbiter's socket is gone");
    assert.notEqual(got["chmod"], "0", "Mandu's policy.yaml was opened to every user");
    assert.equal(statSync(law).mode & 0o7777, 0o600, "policy.yaml's mode changed");
    assert.notEqual(got["mkfifo"], "0", "a node was made under Mandu's own files");
    assert.ok(!existsSync(fifo), "a FIFO exists under Mandu's own files");
    assert.equal(got["freechmod"], "0", "a chmod elsewhere was refused");
    assert.equal(statSync(freeFile).mode & 0o7777, 0o750, "the chmod elsewhere was not performed");
    assert.equal(got["freefifo"], "0", "a mkfifo elsewhere was refused");
    assert.ok(lstatSync(freeFifo).isFIFO(), "the mkfifo elsewhere made no FIFO");
    // The attribute check proves something only where the filesystem takes a
    // user attribute at all: judged on the free file's result.
    if (got["xattr"] !== "skip" && got["freexattr"] === "0") {
      assert.notEqual(got["xattr"], "0", `an extended attribute was set on Mandu's policy.yaml; launcher said:\n${lines.join("\n")}`);
    }
    assert.equal(got["rc1"], "0", "the once-allowed .bashrc append failed");
    assert.notEqual(got["rc2"], "0", "the unanswered .bashrc append went through");
    // The D8 follow-up: the answer was about one binary.
    assert.equal(got["tee1"], "0", "the always-allowed system tee was refused");
    assert.notEqual(got["copy"], "0", `a workspace copy of tee rode the system tee's Always; launcher said:\n${lines.join("\n")}`);
    // 126: the copy never ran, so it was never asked about (CI pipelines
    // 11765 and 11856: the guard still held the copy cp had just written
    // open for writing, and the exec met ETXTBSY; guard-written-exec.test.ts).
    assert.notEqual(got["copy"], "126", `the workspace copy of tee never ran (exit 126: its exec was refused); launcher said:\n${lines.join("\n")}`);
    assert.ok(copyRow, `the workspace copy was not asked about under its own path (its run exited ${got["copy"]}); launcher said:\n${lines.join("\n")}`);
    assert.match(teeRow!.symbol, new RegExp(`^write:${tee.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")}#[0-9a-f]{64}$`), "keyed by the binary's path and hash");
    assert.match(copyRow!.reason, /The agent could have written this program\./);
    if (got["preload"] !== "skip") assert.notEqual(got["preload"], "0", "the system tee run with LD_PRELOAD rode its Always");
    assert.equal((await admin.egressApprovals("pending")).filter((e) => e.symbol.startsWith(`write:${tee}#`)).length, 0, "the preloaded tee was put in front of the human");
    assert.equal(got["tee2"], "0", "the system tee's Always stopped working");
    assert.equal(readFileSync(rc, "utf8"), "# startup\none\ntee1\ntee2\n");
  } finally {
    console.error = orig;
    if (savedBin === undefined) delete process.env["MANDU_NET_GUARD_BIN"]; else process.env["MANDU_NET_GUARD_BIN"] = savedBin;
    if (savedAsk === undefined) delete process.env["MANDU_SECRETS_ASK_TIMEOUT"]; else process.env["MANDU_SECRETS_ASK_TIMEOUT"] = savedAsk;
    if (savedManduHome === undefined) delete process.env["MANDU_HOME"]; else process.env["MANDU_HOME"] = savedManduHome;
    admin.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

/** The stdlib's tarfile.py and pickletools.py, canonical, when python3 has them. */
function stdlibScripts(): { tar: string; pkt: string } | null {
  try {
    const out = execFileSync("python3", ["-I", "-c", "import tarfile, pickletools, os; print(os.path.realpath(tarfile.__file__)); print(os.path.realpath(pickletools.__file__))"], { encoding: "utf8" }).trim().split("\n");
    return out.length === 2 && out[0]!.endsWith("tarfile.py") && out[1]!.endsWith("pickletools.py") ? { tar: out[0]!, pkt: out[1]! } : null;
  } catch {
    return null;
  }
}
const STD = process.platform === "linux" ? stdlibScripts() : null;

test("decision (c) LIVE: an Always for python3 running tarfile.py admits neither pickletools.py nor python3 -c changing ~/.profile", { skip: skip || (!STD ? "python3 with a stdlib tarfile.py and pickletools.py is not installed" : false), timeout: 120_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-wp-c-"));
  const home = join(dir, "home");
  mkdirSync(join(home, ".mandu"), { recursive: true });
  const prof = join(home, ".profile");
  writeFileSync(prof, "# profile\n");
  const src = join(dir, "payload.txt");
  writeFileSync(src, "payload\n");
  const pkl = join(dir, "one.pickle");
  execFileSync("python3", ["-c", "import pickle, sys; open(sys.argv[1], 'wb').write(pickle.dumps(1))", pkl]);
  const out = join(dir, "out");
  const sock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  const server = new ArbiterServer({ socketPath: sock, adminSocketPath: adminSock, humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "sym.db"), eventDir: join(dir, "events"), log: () => {} });
  await server.listen();
  const admin = new ArbiterClient(adminSock);
  await admin.connect();
  const lines: string[] = [];
  const orig = console.error;
  const saved = { bin: process.env["MANDU_NET_GUARD_BIN"], ask: process.env["MANDU_SECRETS_ASK_TIMEOUT"], home: process.env["MANDU_HOME"] };
  const { tar, pkt } = STD!;
  try {
    // 1. python3 running tarfile.py (held; the test answers Always); 2. the
    //    same pair again; 3. python3 running pickletools.py; 4. python3 -c;
    //    5. the answered pair once more.
    const script =
      `cd ${dir}; ` +
      `python3 -I ${tar} -c ${prof} payload.txt >/dev/null 2>&1; echo "tar1=$?" > ${out}; ` +
      `python3 -I ${tar} -c ${prof} payload.txt >/dev/null 2>&1; echo "tar2=$?" >> ${out}; ` +
      `python3 -I ${pkt} -o ${prof} ${pkl} >/dev/null 2>&1; echo "pkt=$?" >> ${out}; ` +
      `python3 -I -c 'import sys; open(sys.argv[1], "a").write("inline\\n")' ${prof} >/dev/null 2>&1; echo "inline=$?" >> ${out}; ` +
      `python3 -I ${tar} -c ${prof} payload.txt >/dev/null 2>&1; echo "tar3=$?" >> ${out}`;
    console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
    process.env["MANDU_NET_GUARD_BIN"] = GUARD!;
    process.env["MANDU_SECRETS_ASK_TIMEOUT"] = "3000";
    process.env["MANDU_HOME"] = join(home, ".mandu");
    const run = main(
      ["--target", "claude", "--no-scope", "--no-landlock-net", "--no-reply-filter", "--no-net-proxy", "--no-exec-box", "--", "bash", "-c", script],
      {
        HOME: home, PWD: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
        MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: join(home, ".mandu"), MANDU_MODE: "injection", ...axesEnv("injection"), XDG_RUNTIME_DIR: dir,
      },
    );
    const deadline = Date.now() + 60_000;
    let tarRow: { id: string; symbol: string } | undefined;
    while (!tarRow && Date.now() < deadline) {
      tarRow = (await admin.egressApprovals("pending")).find((e) => e.symbol.startsWith("write:") && e.destination === prof);
      if (!tarRow) await new Promise((r) => setTimeout(r, 100));
    }
    assert.ok(tarRow, `no Inbox row for ${prof}; launcher said:\n${lines.join("\n")}`);
    await admin.resolveEgressApproval(tarRow!.id, true, "always");
    const code = await run;
    console.error = orig;
    const got = Object.fromEntries(readFileSync(out, "utf8").trim().split("\n").map((l) => l.split("=") as [string, string]));
    assert.equal(code, 0, lines.join("\n"));
    // The row named the interpreter AND the script (the guard's R5 facts).
    assert.match(tarRow!.symbol, new RegExp(`#script:${encodeURIComponent(tar).replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")}#[0-9a-f]{64}$`), `the row names tarfile.py: ${tarRow!.symbol}`);
    assert.equal(got["tar1"], "0", "the answered change failed");
    assert.equal(got["tar2"], "0", "the Always for python3 running tarfile.py stopped working");
    assert.notEqual(got["pkt"], "0", "python3 running pickletools.py rode the Always for tarfile.py");
    assert.notEqual(got["inline"], "0", "python3 -c rode the Always for tarfile.py");
    assert.equal(got["tar3"], "0", "the answered pair, once more");
    const rows = (await admin.egressApprovals("pending")).filter((e) => e.destination === prof).map((e) => e.symbol);
    assert.ok(rows.some((r) => r.includes(`#script:${encodeURIComponent(pkt)}#`)), `pickletools.py asked under its own row: ${rows.join(" | ")}`);
    assert.ok(rows.some((r) => /#run:[^#]+$/.test(r)), `python3 -c asked under a row for its run: ${rows.join(" | ")}`);
    assert.doesNotMatch(readFileSync(prof, "utf8"), /inline/, "the inline write reached ~/.profile");
  } finally {
    console.error = orig;
    if (saved.bin === undefined) delete process.env["MANDU_NET_GUARD_BIN"]; else process.env["MANDU_NET_GUARD_BIN"] = saved.bin;
    if (saved.ask === undefined) delete process.env["MANDU_SECRETS_ASK_TIMEOUT"]; else process.env["MANDU_SECRETS_ASK_TIMEOUT"] = saved.ask;
    if (saved.home === undefined) delete process.env["MANDU_HOME"]; else process.env["MANDU_HOME"] = saved.home;
    admin.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
