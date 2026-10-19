/**
 * policy.yaml restore-on-deny and the guard's host lists, e2e
 * (sandbox-security-review-2026-09-28 finding 2's residual and the fix
 * session's items 5 and 6; arbiter/policy/policy-restore.ts,
 * arbiter/policy/guard-settings.ts), across the REAL components:
 *
 *   1. A REAL ArbiterServer polls a real policy.yaml. A relaxing hand edit is
 *      held; the human declines it on the ADMIN channel; the file is written
 *      back to the law in force, a `restore` config_change is on the audit
 *      stream, and the Inbox row keeps the declined text (admin only: the
 *      data socket never sees it). The declined content is then written
 *      again while the arbiter is DOWN; a new ArbiterServer over the same
 *      mandu.db restores the file before loading it, and the declined rule is
 *      not the law.
 *   2. A disk edit adding a `write_protect.unprotect` entry is held (a
 *      relaxation), and the launcher's `guardSettings` read does not see it
 *      until a human approves; a `deny` addition applies at once.
 *   3. The launcher's main() in `secrets` mode, the REAL mandu-net-guard and a
 *      REAL ArbiterServer whose policy.yaml lists a host socket under
 *      `unix_sockets.allow`, a file under `write_protect.deny` and `~/.bashrc`
 *      under `write_protect.unprotect`: the agent's tree reaches that socket
 *      (refused without the entry: unix-allow-list.test.ts), cannot change the
 *      denied file, and changes .bashrc with no Inbox hold. Self-SKIPs where
 *      the guard is not built (scripts/build-native.sh) or python3 is absent.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createServer, type Server } from "node:net";
import { once } from "node:events";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ADMIN_SESSION_ID, ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { main } from "../../launcher/test/lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { stateAxes } from "../lib/axes.js";
import { pickGuard } from "../lib/native-guard.js";

stateAxes("secrets"); // restore-on-deny is axis-independent; leg 3's socket list is the confidentiality axis's

const INITIAL = "version: 1\npaths:\n  - { path: /home/u/repo/.env, level: no-model }\n";
const RELAX = INITIAL + "user_rules:\n  - { id: hand, kind: release, to: { host: attacker.example }, mode: allow }\n";

let bump = 0;
function writeDisk(file: string, text: string): void {
  writeFileSync(file, text);
  const t = new Date(Date.now() + 5_000 + ++bump * 1_000);
  utimesSync(file, t, t);
}

async function waitFor<T>(get: () => Promise<T | undefined>, ms: number, what: string): Promise<T> {
  const deadline = Date.now() + ms;
  for (;;) {
    const v = await get();
    if (v !== undefined) return v;
    if (Date.now() > deadline) assert.fail(`timed out: ${what}`);
    await new Promise((r) => setTimeout(r, 25));
  }
}

async function startArbiter(dir: string, file: string): Promise<{ server: ArbiterServer; data: ArbiterClient; admin: ArbiterClient }> {
  const sock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    log: () => {}, policyPath: file, policyPollMs: 40,
  });
  await server.listen();
  const data = new ArbiterClient(sock);
  await data.connect();
  const admin = new ArbiterClient(adminSock);
  await admin.connect();
  return { server, data, admin };
}

const userRuleIds = (inForce: unknown): string[] =>
  ((inForce as { user_rules?: Array<{ id: string }> } | null)?.user_rules ?? []).map((r) => r.id);


test("a declined policy.yaml relaxation is restored on disk and is not the law after a restart", { timeout: 60_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-restore-e2e-"));
  const file = join(dir, "policy.yaml");
  writeFileSync(file, INITIAL);
  let a = await startArbiter(dir, file);
  try {
    writeDisk(file, RELAX);
    const held = await waitFor(async () => (await a.admin.policyProposals("pending")).proposals.find((p) => p.diskHash), 10_000, "the relaxing edit was never held");
    assert.deepEqual(userRuleIds((await a.admin.policyDocument()).inForce), [], "held, not the law");
    assert.equal(held.diskText, RELAX, "admin: the Inbox row carries the hand edit");
    const seenByData = (await a.data.policyProposals("pending")).proposals.find((p) => p.id === held.id);
    assert.ok(seenByData);
    assert.equal("diskText" in seenByData!, false, "the data socket never reads a hand edit's text");

    const r = await a.admin.resolvePolicyProposal(held.id, "denied", "dashboard");
    assert.equal(r.proposal.status, "denied");
    assert.equal(r.restored, true);
    assert.equal(readFileSync(file, "utf8"), INITIAL, "the file matches the law in force");
    const ev = (await a.admin.events(ADMIN_SESSION_ID)).find((e) => e.kind === "config_change" && (e as { policyChange?: { via?: string } }).policyChange?.via === "restore");
    assert.ok(ev, "a `restore` config_change is on the audit stream for the dashboard");
    // The row keeps the declined text after the verdict.
    assert.equal((await a.admin.policyProposals("denied")).proposals.find((p) => p.id === held.id)?.diskText, RELAX);

    // Down: the declined content comes back (a program, a sync tool, a stale editor buffer).
    a.data.close();
    a.admin.close();
    await a.server.close();
    writeFileSync(file, RELAX);
    a = await startArbiter(dir, file);
    assert.equal(readFileSync(file, "utf8"), INITIAL, "restored at start, before it was loaded");
    const doc = await a.admin.policyDocument();
    assert.deepEqual(userRuleIds(doc.inForce), [], "the declined rule is NOT the law after the restart");
    assert.equal((await a.admin.policyProposals("pending")).proposals.length, 0, "no new card for declined content");
  } finally {
    a.data.close();
    a.admin.close();
    await a.server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a write_protect opt-out on disk is held until a human approves; a deny addition applies at once", { timeout: 60_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-guard-settings-e2e-"));
  const file = join(dir, "policy.yaml");
  writeFileSync(file, "version: 1\n");
  const a = await startArbiter(dir, file);
  try {
    writeDisk(file, "version: 1\nwrite_protect:\n  deny: [~/notes]\n");
    await waitFor(async () => ((await a.data.guardSettings()).writeProtect.deny.includes("~/notes") ? true : undefined), 10_000, "the deny addition never applied");
    assert.equal((await a.admin.policyProposals("pending")).proposals.length, 0, "a tightening waits for nobody");

    writeDisk(file, "version: 1\nwrite_protect:\n  deny: [~/notes]\n  unprotect: [~/.gitconfig]\nunix_sockets:\n  allow: [\"@my-helper\"]\n");
    const held = await waitFor(async () => (await a.admin.policyProposals("pending")).proposals.find((p) => p.diskHash), 10_000, "the opt-out was never held");
    const subjects = held.relaxes.map((x) => x.subject).sort();
    assert.deepEqual(subjects, ["unix_sockets @my-helper", "write_protect.unprotect ~/.gitconfig"]);
    const before = await a.data.guardSettings();
    assert.deepEqual(before, { unixAllow: [], writeProtect: { deny: ["~/notes"], ask: [], unprotect: [] }, trustLookups: [] }, "the launcher does not see a held relaxation");
    await a.admin.resolvePolicyProposal(held.id, "approved", "dashboard");
    assert.deepEqual(await a.data.guardSettings(), { unixAllow: ["@my-helper"], writeProtect: { deny: ["~/notes"], ask: [], unprotect: ["~/.gitconfig"] }, trustLookups: [] });

    // Opting out of Mandu's own files is refused by validation: the law stays.
    writeDisk(file, "version: 1\nwrite_protect:\n  unprotect: [~/.mandu]\n");
    await waitFor(async () => ((await a.admin.policyDocument()).status.valid === false ? true : undefined), 10_000, "the invalid file was never refused");
    assert.match((await a.admin.policyDocument()).status.problems.join("\n"), /Mandu's own files/);
    assert.deepEqual((await a.data.guardSettings()).writeProtect.unprotect, ["~/.gitconfig"], "the law in force is unchanged");
  } finally {
    a.data.close();
    a.admin.close();
    await a.server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

const HERE = dirname(fileURLToPath(import.meta.url));
const TARGET = resolve(HERE, "..", "..", "interceptors", "target");
// The newest FRESH build (lib/native-guard.ts): a stale bin tests an older guard.
const PICK = pickGuard(TARGET);
const GUARD = PICK.path;
const PY = spawnSync("python3", ["-c", "print(1)"]).status === 0;
const skipGuard = process.platform !== "linux" || !GUARD ? "mandu-net-guard is not built (scripts/build-native.sh)" : !PY ? "python3 is not installed" : false;
test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD }, () => {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
});

const CLIENT = `import socket, sys
s = socket.socket(socket.AF_UNIX)
try:
    s.connect(sys.argv[1]); print(0)
except OSError as e:
    print(e.errno)
`;

test("policy.yaml's socket extra, deny path and opt-out reach the real guard", { skip: skipGuard, timeout: 120_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-guard-law-e2e-"));
  const home = join(dir, "home");
  mkdirSync(home, { recursive: true });
  writeFileSync(join(dir, "client.py"), CLIENT);
  const hostSock = join(dir, "host.sock");
  const otherSock = join(dir, "other.sock");
  const notes = join(home, "notes.txt");
  const rc = join(home, ".bashrc");
  writeFileSync(notes, "keep\n");
  writeFileSync(rc, "# startup\n");
  const out = join(dir, "out");
  const hosts: Server[] = [];
  for (const p of [hostSock, otherSock]) {
    const h = createServer((c) => c.end());
    h.listen(p);
    await once(h, "listening");
    hosts.push(h);
  }
  const law = join(dir, "policy.yaml");
  writeFileSync(law, `version: 1\nunix_sockets:\n  allow: [${hostSock}]\nwrite_protect:\n  deny: [~/notes.txt]\n  unprotect: [~/.bashrc]\n`);
  const a = await startArbiter(dir, law);
  const lines: string[] = [];
  const orig = console.error;
  const saved = { bin: process.env["MANDU_NET_GUARD_BIN"], home: process.env["HOME"], manduHome: process.env["MANDU_HOME"], ask: process.env["MANDU_SECRETS_ASK_TIMEOUT"] };
  try {
    const script =
      `echo "listed=$(python3 ${dir}/client.py ${hostSock})" > ${out}; ` +
      `echo "other=$(python3 ${dir}/client.py ${otherSock})" >> ${out}; ` +
      `echo more >> ${notes} 2>/dev/null; echo "notes=$?" >> ${out}; ` +
      `echo alias >> ${rc} 2>/dev/null; echo "rc=$?" >> ${out}`;
    console.error = (...x: unknown[]) => { lines.push(x.map(String).join(" ")); };
    process.env["MANDU_NET_GUARD_BIN"] = GUARD!;
    process.env["HOME"] = home;
    process.env["MANDU_HOME"] = join(home, ".mandu");
    // Were .bashrc still held, an unanswered hold would refuse it in 2 s.
    process.env["MANDU_SECRETS_ASK_TIMEOUT"] = "2000";
    const code = await main(
      ["--target", "claude", "--no-scope", "--no-landlock-net", "--no-reply-filter", "--no-net-proxy", "--no-exec-box", "--", "bash", "-c", script],
      {
        HOME: home, PWD: dir, MANDU_ARBITER_SOCK: join(dir, "arbiter.sock"), PATH: process.env["PATH"],
        MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: join(home, ".mandu"), MANDU_MODE: "secrets", XDG_RUNTIME_DIR: dir,
      },
    );
    console.error = orig;
    const got = Object.fromEntries(readFileSync(out, "utf8").trim().split("\n").map((l) => l.split("=") as [string, string]));
    assert.equal(code, 0, lines.join("\n"));
    assert.equal(got["listed"], "0", `the socket policy.yaml lists must be reachable; got ${got["listed"]}\n${lines.join("\n")}`);
    assert.equal(got["other"], "13", "a host socket policy.yaml does not list stays refused (EACCES)");
    assert.notEqual(got["notes"], "0", "the write_protect.deny file was changed");
    assert.equal(readFileSync(notes, "utf8"), "keep\n");
    assert.equal(got["rc"], "0", `the unprotected .bashrc append was refused or held\n${lines.join("\n")}`);
    assert.equal(readFileSync(rc, "utf8"), "# startup\nalias\n");
    assert.equal((await a.admin.egressApprovals("pending")).filter((e) => e.symbol.startsWith("write:")).length, 0, "no Inbox hold for .bashrc");
  } finally {
    console.error = orig;
    for (const [k, v] of [["MANDU_NET_GUARD_BIN", saved.bin], ["HOME", saved.home], ["MANDU_HOME", saved.manduHome], ["MANDU_SECRETS_ASK_TIMEOUT", saved.ask]] as const) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
    for (const h of hosts) h.close();
    a.data.close();
    a.admin.close();
    await a.server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
