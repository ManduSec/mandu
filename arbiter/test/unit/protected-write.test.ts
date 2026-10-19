/**
 * protected-write.test — the arbiter half of the write-protect hold
 * (sandbox-security-review-2026-09-28 finding 6): `decideProtectedWrite`
 * files a pending Inbox row and answers `ask`; a human verdict for (program,
 * file) decides the next ask; the hold's ceiling answers `deny` and leaves
 * the row pending; a label the launcher does not write is never shown.
 *
 * The verdict names one BINARY (write-protection.md §2.1, the Plan 13 D8
 * follow-up): keyed `write:<exe>#<sha256>`, so approving /usr/bin/vim admits
 * no other binary named vim (an agent-written /tmp/x/vim) nor a rebuilt one;
 * a writer run with a loader variable the launch did not give, or with code
 * the agent could have written mapped in, or whose environment the guard did
 * not report, is refused outright: it neither matches nor spends a prior
 * answer and is never put in front of the human.
 *
 * Plan 13 §8 decision (c) (2026-10-02): a writer that runs code (a shell, an
 * interpreter) is named with the script it runs, under R5's checks
 * (`write:<exe>#<sha256>#script:<path>#<sha256>`), so allowing python3
 * running a.py allows neither b.py nor `python3 -c`; one running no pinnable
 * script (`bash -c 'echo … >> ~/.bashrc'`) is asked about each run
 * (`…#run:<procKey>`), an Always kept as once; a row naming the interpreter
 * alone (before the decision) matches nothing.
 *
 * The guard asks on the HUMAN socket (plan 13 D9: a data-socket ask is
 * refused, test/component/guard-report-attestation); the human answers on the
 * ADMIN channel.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

let workdir: string;
let server: ArbiterServer;
let data: ArbiterClient;
let admin: ArbiterClient;
let guard: ArbiterClient;

before(async () => {
  workdir = mkdtempSync(join(tmpdir(), "mandu-protected-write-"));
  server = new ArbiterServer({
    socketPath: join(workdir, "arbiter.sock"),
    adminSocketPath: join(workdir, "admin.sock"),
    humanSocketPath: join(workdir, "human", "h.sock"),
    dbPath: join(workdir, "symbols.db"),
    eventDir: join(workdir, "events"),
    log: () => {},
  });
  await server.listen();
  data = new ArbiterClient(join(workdir, "arbiter.sock"));
  await data.connect();
  admin = new ArbiterClient(join(workdir, "admin.sock"));
  guard = new ArbiterClient(join(workdir, "human", "h.sock"));
  await guard.connect();
  await admin.connect();
});

after(async () => {
  data.close();
  guard.close();
  admin.close();
  await server.close();
  rmSync(workdir, { recursive: true, force: true });
});

async function pendingFor(path: string) {
  return (await admin.egressApprovals("pending")).filter((e) => e.destination === path);
}

const SHA = "a".repeat(64);
type Facts = { path: string; sha256?: string; system: boolean; isolated: boolean; traced: boolean };
type Ask = { path: string; exe: string; procKey: string; label?: string; session?: string; heldMs?: number; sha256?: string; exeSystem?: boolean; openerEnv?: string[]; script?: Facts; scriptProblem?: string };
/** The guard's question with the identity facts it reports since the D8
 *  follow-up (the binary's hash, a binary out of the agent's reach, a clean
 *  environment); each test overrides the fact it is about. */
function ask(args: Ask) {
  return guard.decideProtectedWrite({ sha256: SHA, exeSystem: true, openerEnv: [], ...args });
}

test("decideProtectedWrite: the first ask files one pending row and answers ask; asking again keeps the one row", async () => {
  const path = "/home/u/.bashrc";
  const a = await ask({ path, exe: "/usr/bin/bash", procKey: "bash-1", label: "a shell startup file", session: "s1" });
  assert.equal(a.verdict, "ask");
  assert.ok(a.approvalId);
  const again = await ask({ path, exe: "/usr/bin/bash", procKey: "bash-1", label: "a shell startup file", session: "s1" });
  assert.equal(again.verdict, "ask");
  const rows = await pendingFor(path);
  assert.equal(rows.length, 1, "one row per (program, file)");
  // Plan 13 §8 decision (c): bash runs code no script pin names here (the
  // guard reported no script), so the row names the binary and this run.
  assert.equal(rows[0]!.symbol, `write:/usr/bin/bash#${SHA}#run:bash-1`, "keyed by the binary, path and hash (D8 follow-up), and the run (decision (c))");
  assert.match(rows[0]!.reason, /^bash \(\/usr\/bin\/bash\) running code that is not a pinned script wants to change \/home\/u\/\.bashrc \(a shell startup file\)/);
  assert.match(rows[0]!.reason, /Your answer covers this change only; the next one asks again\./);
  assert.doesNotMatch(rows[0]!.reason, /could have written/, "a binary out of the agent's reach carries no such note");
  // a leaf program's row names its binary alone, as before
  await ask({ path, exe: "/usr/bin/tee", procKey: "tee-0", label: "a shell startup file" });
  assert.ok((await pendingFor(path)).some((r) => r.symbol === `write:/usr/bin/tee#${SHA}`));
});

test("decideProtectedWrite: allow once lets exactly one change through, then it asks again", async () => {
  const path = "/home/u/.profile";
  const a = await ask({ path, exe: "/usr/bin/tee", procKey: "tee-1", label: "a shell startup file" });
  assert.equal(a.verdict, "ask");
  await admin.resolveEgressApproval(a.approvalId!, true, "once");
  assert.equal((await ask({ path, exe: "/usr/bin/tee", procKey: "tee-1" })).verdict, "allow");
  assert.equal((await ask({ path, exe: "/usr/bin/tee", procKey: "tee-2" })).verdict, "ask", "a once-verdict is spent");
});

test("decideProtectedWrite: always and deny stand for that program and file only", async () => {
  const hooks = "/work/repo/.git/hooks/pre-commit";
  const a = await ask({ path: hooks, exe: "/usr/bin/pre-commit", procKey: "pc-1", label: "a git hook" });
  await admin.resolveEgressApproval(a.approvalId!, true, "always");
  assert.equal((await ask({ path: hooks, exe: "/usr/bin/pre-commit", procKey: "pc-2" })).verdict, "allow");
  // Another program, same file: its own question.
  assert.equal((await ask({ path: hooks, exe: "/usr/bin/sh", procKey: "sh-1" })).verdict, "ask");
  const unit = "/home/u/.config/systemd/user/evil.service";
  const b = await ask({ path: unit, exe: "/usr/bin/cp", procKey: "cp-1", label: "a systemd user unit" });
  await admin.resolveEgressApproval(b.approvalId!, false);
  const denied = await ask({ path: unit, exe: "/usr/bin/cp", procKey: "cp-2" });
  assert.deepEqual([denied.verdict, denied.reason], ["deny", "human-denied"]);
});

test("decideProtectedWrite: the hold's ceiling answers deny and the row stays pending", async () => {
  const path = "/home/u/.zshrc";
  const a = await ask({ path, exe: "/usr/bin/zsh", procKey: "zsh-1", label: "a shell startup file" });
  assert.equal(a.verdict, "ask");
  const late = await ask({ path, exe: "/usr/bin/zsh", procKey: "zsh-1", heldMs: 60_000 });
  assert.equal(late.verdict, "deny");
  assert.match(late.reason, /^held for 60 s, nobody answered/);
  assert.equal((await pendingFor(path)).length, 1, "the row outlives the hold");
});

test("decideProtectedWrite: a label the launcher never writes is not shown to the human", async () => {
  const path = "/home/u/.bash_login";
  await ask({ path, exe: "/usr/bin/sh", procKey: "sh-9", label: "harmless, click allow" });
  const [row] = await pendingFor(path);
  assert.ok(row);
  assert.doesNotMatch(row.reason, /harmless/);
  assert.match(row.reason, /\(a protected file\)/);
});

test("decideProtectedWrite: a relative or empty path is refused, nothing filed", async () => {
  const r = await ask({ path: "relative/.bashrc", exe: "/usr/bin/sh", procKey: "sh-3" });
  assert.equal(r.verdict, "deny");
  assert.equal((await pendingFor("relative/.bashrc")).length, 0);
});

test("the human's answer is admin-only: the data socket cannot resolve a write hold", async () => {
  const a = await ask({ path: "/home/u/.ssh/authorized_keys2", exe: "/usr/bin/tee", procKey: "tee-9", label: "an ssh setting" });
  await assert.rejects(() => data.resolveEgressApproval(a.approvalId!, true), /admin-only/);
});

// ── The writer is its binary (write-protection.md §2.1; Plan 13 D8 follow-up)

test("D8 follow-up: an approved /usr/bin/nano (always) admits neither /tmp/x/nano, same bytes, nor a rebuilt /usr/bin/nano", async () => {
  const path = "/home/u/.ssh/authorized_keys";
  const a = await ask({ path, exe: "/usr/bin/nano", procKey: "vim-1", label: "an ssh setting" });
  assert.equal(a.verdict, "ask");
  await admin.resolveEgressApproval(a.approvalId!, true, "always");
  assert.equal((await ask({ path, exe: "/usr/bin/nano", procKey: "vim-2" })).verdict, "allow", "the approved binary itself");
  // The agent's copy: the same hash (a copy has the same bytes), another
  // path, in a directory the agent can write.
  const copy = await ask({ path, exe: "/tmp/x/nano", procKey: "copy-1", exeSystem: false, label: "an ssh setting" });
  assert.equal(copy.verdict, "ask", `the copy is not the binary the human allowed (got ${copy.verdict}: ${copy.reason})`);
  const rows = await pendingFor(path);
  assert.deepEqual(rows.map((r) => r.symbol), [`write:/tmp/x/nano#${SHA}`], "the copy asks under its own path");
  assert.match(rows[0]!.reason, /^nano \(\/tmp\/x\/nano\) wants to change .*The agent could have written this program\./, "the Inbox says where the program lives");
  // The same path, another binary (rebuilt, or swapped in place).
  const rebuilt = await ask({ path, exe: "/usr/bin/nano", procKey: "vim-3", sha256: "b".repeat(64) });
  assert.equal(rebuilt.verdict, "ask", "a rebuilt nano is another key");
});

test("D8 follow-up: a once given /usr/bin/nano is not spent by /tmp/x/nano", async () => {
  const path = "/home/u/.ssh/config";
  const a = await ask({ path, exe: "/usr/bin/nano", procKey: "vim-1", label: "an ssh setting" });
  await admin.resolveEgressApproval(a.approvalId!, true, "once");
  assert.equal((await ask({ path, exe: "/tmp/x/nano", procKey: "copy-1", exeSystem: false })).verdict, "ask", "the copy does not spend the once");
  assert.equal((await ask({ path, exe: "/usr/bin/nano", procKey: "vim-2" })).verdict, "allow", "the once is still there for the real program");
  assert.equal((await ask({ path, exe: "/usr/bin/nano", procKey: "vim-3" })).verdict, "ask", "and spent by it");
});

test("D8 follow-up: nano run with LD_PRELOAD, with agent-writable code mapped in, or with an unreported environment is refused, matches no approval, spends none and files no row", async () => {
  const path = "/home/u/.config/systemd/user/backup.service";
  const a = await ask({ path, exe: "/usr/bin/nano", procKey: "vim-1", label: "a systemd user unit" });
  await admin.resolveEgressApproval(a.approvalId!, true, "once");
  const cases: Array<[string, string[] | undefined, RegExp]> = [
    ["pre-1", ["LD_PRELOAD"], /LD_PRELOAD/],
    ["map-1", ["code:/tmp/x/libhook.so"], /\/tmp\/x\/libhook\.so/],
    ["unk-1", undefined, /not checked/],
  ];
  for (const [procKey, openerEnv, why] of cases) {
    const base = { path, exe: "/usr/bin/nano", procKey, label: "a systemd user unit", sha256: SHA, exeSystem: true };
    // `openerEnv` absent = an older guard, or one that could not read it.
    const r = await guard.decideProtectedWrite(openerEnv ? { ...base, openerEnv } : base);
    assert.equal(r.verdict, "deny", `${procKey}: ${r.verdict} (${r.reason})`);
    assert.match(r.reason, why);
    assert.equal(r.approvalId, undefined, "never put in front of the human");
  }
  assert.equal((await pendingFor(path)).length, 0, "no row filed for an unclean writer");
  assert.equal((await ask({ path, exe: "/usr/bin/nano", procKey: "vim-2" })).verdict, "allow", "the once is still there for the clean program");
});

test("code by argument (plan 13 D8, 2026-10-02): vim runs code it is given (its vimrc and plugins, -c), so a change it makes is asked about per run and an Always for it is no standing answer", async () => {
  const path = "/home/u/.ssh/rc";
  const a = await ask({ path, exe: "/usr/bin/vim", procKey: "vimc-1", label: "an ssh setting" });
  assert.equal(a.verdict, "ask");
  const rows = await pendingFor(path);
  assert.deepEqual(rows.map((r) => r.symbol), [`write:/usr/bin/vim#${SHA}#run:vimc-1`], "keyed by its run, like a shell (decision (c))");
  await admin.resolveEgressApproval(a.approvalId!, true, "always");
  assert.equal((await ask({ path, exe: "/usr/bin/vim", procKey: "vimc-1" })).verdict, "allow", "the answer covers that run");
  assert.equal((await ask({ path, exe: "/usr/bin/vim", procKey: "vimc-2" })).verdict, "ask", "the next run asks again");
});

test("D8 follow-up: a verdict recorded under the old key (write:vim) no longer matches; the binary is asked once more", async () => {
  const path = "/home/u/.bash_profile";
  // A row an arbiter before 2026-10-02 wrote, answered Always.
  const store = (server as unknown as { egressApprovals: { recordPending(s: string, d: string, r: string): { id: string }; resolve(id: string, approve: boolean, scope: "once" | "always"): unknown } }).egressApprovals;
  const old = store.recordPending("write:vim", path, "vim wants to change it");
  store.resolve(old.id, true, "always"); // answered by that arbiter (an answer now is refused: it would change nothing)
  const r = await ask({ path, exe: "/usr/bin/vim", procKey: "vim-1", label: "a shell startup file" });
  assert.equal(r.verdict, "ask", `the old basename row admitted the write (${r.reason})`);
  assert.equal((await ask({ path, exe: "/tmp/x/vim", procKey: "copy-1", exeSystem: false })).verdict, "ask", "nor any binary named vim");
});

test("D8 follow-up: no executable, a relative one, or a hash that is not one is refused and nothing is filed", async () => {
  const path = "/home/u/.config/autostart/x.desktop";
  assert.equal((await ask({ path, exe: "", procKey: "gone-1", label: "an autostart entry" })).verdict, "deny");
  assert.equal((await ask({ path, exe: "vim", procKey: "rel-1", label: "an autostart entry" })).verdict, "deny");
  assert.equal((await ask({ path, exe: "/usr/bin/vim", procKey: "bad-1", sha256: "not-a-hash#x", label: "an autostart entry" })).verdict, "deny");
  assert.equal((await pendingFor(path)).length, 0);
});

test("D8 follow-up: without a hash the path alone keys the verdict, and a file named like path#hash cannot pose as that binary", async () => {
  const path = "/home/u/.pam_environment";
  const a = await ask({ path, exe: "/opt/tool/sync", procKey: "s-1", sha256: undefined, label: "a login environment file" });
  await admin.resolveEgressApproval(a.approvalId!, true, "always");
  assert.equal((await ask({ path, exe: "/opt/tool/sync", procKey: "s-2", sha256: undefined })).verdict, "allow");
  // The human allowed /w/tool by path and hash; a file the guard cannot
  // hash whose NAME spells that path and hash is another key.
  const b = await ask({ path, exe: "/w/tool", procKey: "t-1", label: "a login environment file" });
  await admin.resolveEgressApproval(b.approvalId!, true, "always");
  const spoof = await ask({ path, exe: `/w/tool#${SHA}`, procKey: "t-2", sha256: undefined, exeSystem: false });
  assert.equal(spoof.verdict, "ask", `a name spelled like path#hash matched the approval (${spoof.reason})`);
});

test("whyPath lists a write verdict by the binary's path, never the hash", async () => {
  const path = "/home/u/.config/git/config";
  const a = await ask({ path, exe: "/usr/bin/git", procKey: "git-1", label: "a git setting" });
  await admin.resolveEgressApproval(a.approvalId!, true, "always");
  const w = await admin.whyPath(path);
  const v = w.verdicts.find((x) => x.kind === "write");
  assert.ok(v, JSON.stringify(w.verdicts));
  assert.deepEqual(v, { kind: "write", app: "git", exe: "/usr/bin/git", status: "approved", scope: "always" });
  assert.ok(!JSON.stringify(w).includes(SHA), "the hash is not shown");
});

// ── Plan 13 §8 decision (c): an interpreter writer is named with its script ──

const PY = "/usr/bin/python3.12";
const facts = (path: string, over: Partial<Facts> = {}): Facts => ({ path, sha256: "c".repeat(64), system: true, isolated: true, traced: false, ...over });

test("DECISION (c): an Always for python3 running a.py names the script: python3 running b.py, a changed a.py and python3 -c are each asked; an agent-writable script is asked per run", async () => {
  const path = "/home/u/.config/systemd/user/sync.service";
  const A = "/opt/tools/a.py";
  const a = await ask({ path, exe: PY, procKey: "py-a1", label: "a systemd user unit", script: facts(A) });
  assert.equal(a.verdict, "ask");
  const [row] = await pendingFor(path);
  assert.equal(row?.symbol, `write:${PY}#${SHA}#script:${encodeURIComponent(A)}#${"c".repeat(64)}`);
  assert.match(row!.reason, /^python3\.12 \(\/usr\/bin\/python3\.12\) running \/opt\/tools\/a\.py wants to change/);
  await admin.resolveEgressApproval(a.approvalId!, true, "always");
  assert.equal((await ask({ path, exe: PY, procKey: "py-a2", script: facts(A) })).verdict, "allow", "the answered pair, standing");
  assert.equal((await ask({ path, exe: PY, procKey: "py-b1", script: facts("/opt/tools/b.py") })).verdict, "ask", "another script: its own question");
  assert.equal((await ask({ path, exe: PY, procKey: "py-a3", script: facts(A, { sha256: "e".repeat(64) }) })).verdict, "ask", "a changed a.py: asked again");
  const inline = await ask({ path, exe: PY, procKey: "py-c1", scriptProblem: "inline code (python -c)" });
  assert.equal(inline.verdict, "ask", `python3 -c is not what the human allowed (${inline.reason})`);
  // R5's checks decide whether a script can be named: an agent-writable one,
  // an unisolated or a traced run is keyed by its run.
  for (const [k, f] of [["ws", facts("/home/u/ws/a.py", { system: false })], ["iso", facts(A, { isolated: false })], ["tr", facts(A, { traced: true })]] as const) {
    const r = await ask({ path, exe: PY, procKey: `py-${k}`, script: f });
    assert.equal(r.verdict, "ask", k);
    assert.ok((await pendingFor(path)).some((p) => p.symbol === `write:${PY}#${SHA}#run:py-${k}`), `${k}: keyed by its run`);
  }
});

test("DECISION (c): an interpreter running inline code gets no reusable verdict: an Always is kept as once, for that run only", async () => {
  const path = "/home/u/.bashrc.d/env.sh";
  const BASH = "/usr/bin/bash";
  const a = await ask({ path, exe: BASH, procKey: "sh-r1", label: "a shell startup file", scriptProblem: "inline code (sh -c)" });
  assert.equal(a.verdict, "ask");
  const resolved = await admin.resolveEgressApproval(a.approvalId!, true, "always");
  assert.equal(resolved.scope, "once", "an Always on a run's row is kept as once");
  assert.equal((await ask({ path, exe: BASH, procKey: "sh-r2", scriptProblem: "inline code (sh -c)" })).verdict, "ask", "another run is asked");
  assert.equal((await ask({ path, exe: BASH, procKey: "sh-r1", scriptProblem: "inline code (sh -c)" })).verdict, "allow", "the answered run's change goes through");
  assert.equal((await ask({ path, exe: BASH, procKey: "sh-r1", scriptProblem: "inline code (sh -c)" })).verdict, "ask", "and its next change is asked again");
});

test("DECISION (c): a verdict naming the interpreter alone (before the decision) matches nothing; whyPath names the script and marks the old answer", async () => {
  const path = "/home/u/.profile.d/x.sh";
  const store = (server as unknown as { egressApprovals: { recordPending(s: string, d: string, r: string): { id: string }; resolve(id: string, approve: boolean, scope: "once" | "always"): unknown } }).egressApprovals;
  const old = store.recordPending(`write:${PY}#${SHA}`, path, "python3 wants to change it");
  store.resolve(old.id, true, "always"); // answered before the decision
  assert.equal((await ask({ path, exe: PY, procKey: "old-1", label: "a shell startup file", script: facts("/opt/tools/a.py") })).verdict, "ask", "a script run is not admitted by the interpreter-only row");
  assert.equal((await ask({ path, exe: PY, procKey: "old-2", scriptProblem: "inline code (python -c)" })).verdict, "ask", "nor inline code");
  const a = await ask({ path, exe: PY, procKey: "new-1", script: facts("/opt/tools/a.py") });
  await admin.resolveEgressApproval(a.approvalId!, true, "always");
  const w = await admin.whyPath(path);
  const writes = w.verdicts.filter((v) => v.kind === "write");
  assert.ok(writes.some((v) => v.script === "/opt/tools/a.py" && v.status === "approved" && !v.stale), JSON.stringify(writes));
  assert.ok(writes.some((v) => v.stale === true && v.exe === PY && v.script === undefined), JSON.stringify(writes));
  assert.ok(writes.some((v) => v.run === true), "the pending run rows are listed as runs");
});
