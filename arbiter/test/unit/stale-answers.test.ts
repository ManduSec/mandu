/**
 * stale-answers — questions and answers about a program by its NAME alone
 * (`open:ssh-add`, `write:tee`, the form before 2026-10-02) apply to nothing,
 * and the Approvals page is told so (dashboard.md §4.34 "Answers that no
 * longer apply"; the work ledger's "name-only open:/write: rows still list
 * in Approvals").
 *
 *   - `nameOnlyVerdict` / `mootQuestionReason` / `verdictNoLongerApplies`:
 *     a name-only open, trust or write is moot (a printer or an interpreter
 *     keeps its own, stronger reason); a program named by its file is not;
 *   - durable, over a real server: a PENDING name-only question an older
 *     arbiter left in the DB is retired at start (listed nowhere, its answer
 *     refused, saying why); an ANSWERED one stays listed, marked
 *     `noLongerApplies: "name-only"` on every listing (the panel's snapshot
 *     and `egressApprovals`), as a printer's is `printer`; a live answer
 *     carries no mark;
 *   - an opener whose program has no absolute path files no question: no
 *     answer could name it (as `decideProtectedWrite` refuses such a writer).
 *
 * Axes: secrets.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { mootQuestionReason, nameOnlyVerdict, verdictNoLongerApplies } from "../../policy/flow-taint.js";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { EgressApprovalStore } from "../../policy/egress-approvals.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const H = "c".repeat(64);

test("a program named by its name only is moot; by its file it is not; a printer or an interpreter keeps its own reason", () => {
  for (const s of ["open:ssh-add", "trust:ssh-add", "write:nano", "write:tee"]) {
    assert.equal(nameOnlyVerdict(s), true, s);
    assert.match(mootQuestionReason(s) ?? "", /by its name only, as Mandu asked before 2026-10-02/, s);
    assert.equal(verdictNoLongerApplies(s), "name-only", s);
  }
  for (const s of [`open:/usr/bin/ssh-add#${H}`, `write:/usr/bin/nano#${H}`, "$MDU:nomodel_Read[0123abcd]", "fs:Read:read", "exec-escalate:network"]) {
    assert.equal(nameOnlyVerdict(s), false, s);
  }
  assert.equal(mootQuestionReason(`open:/usr/bin/ssh-add#${H}`), null, "a vetted program by its file is live");
  assert.equal(verdictNoLongerApplies(`open:/usr/bin/ssh-add#${H}`), null);
  assert.match(mootQuestionReason("open:head") ?? "", /prints or copies/, "a printer's reason first");
  assert.equal(verdictNoLongerApplies("open:head"), "printer");
  assert.equal(verdictNoLongerApplies(`write:/usr/bin/bash#${H}`), "interpreter");
  assert.equal(verdictNoLongerApplies(`open:/opt/tools/loader#${H}`), "unvetted");
});

test("durable: a pending name-only question is retired at start and its answer refused; an answered one is listed, marked; a live answer is not; an opener with no path files no question", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-stale-answers-"));
  const secret = join(dir, ".pgpass");
  writeFileSync(secret, "db:5432:*:u:stale_answers_canary_01\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n`);
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const dbPath = join(dir, "db.sqlite");
  // The rows an arbiter before 2026-10-02 wrote: questions and answers by name.
  const old = new EgressApprovalStore({ dbPath });
  const pendingOpen = old.recordPending("open:ssh-add", secret, "ssh-add wants to read it as a program", "s-old");
  const pendingWrite = old.recordPending("write:nano", join(dir, ".bashrc"), "nano wants to change it", "s-old");
  const answered = old.recordPending("write:tee", join(dir, ".bashrc"), "tee wants to change it", "s-old");
  old.resolve(answered.id, true, "always");
  const printer = old.recordPending(`open:/usr/bin/cat#${H}`, secret, "cat wants to read it", "s-old");
  old.resolve(printer.id, true, "always");
  const live = old.recordPending(`open:/usr/bin/ssh-add#${H}`, secret, "ssh-add wants to read it", "s-old");
  old.resolve(live.id, false, "always");
  old.close();
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath, eventDir: join(dir, "events"), policyPath: policy, policyPollMs: 0, log: () => {}, confidentiality: true, integrity: false,
  });
  await s.listen();
  const guard = new ArbiterClient(join(dir, "human", "h.sock")); await guard.connect();
  const admin = new ArbiterClient(join(dir, "admin.sock")); await admin.connect();
  try {
    // Pending name-only questions: gone from the DB at start, listed nowhere.
    const onDisk = new EgressApprovalStore({ dbPath });
    const left = onDisk.list().map((r) => r.id).sort();
    onDisk.close();
    assert.deepEqual(left, [answered.id, printer.id, live.id].sort(), "only the answers are left on disk");
    assert.deepEqual(await admin.egressApprovals("pending"), []);
    for (const row of [pendingOpen, pendingWrite]) {
      await assert.rejects(admin.resolveEgressApproval(row.id, true, "once"), /no longer applies: this question names (ssh-add|nano) by its name only/);
    }
    // Answered: listed, marked, on both listings the dashboard reads.
    const mark = (rows: Array<{ id: string; noLongerApplies?: string }>) => Object.fromEntries(rows.map((r) => [r.id, r.noLongerApplies ?? null]));
    const expected = { [answered.id]: "name-only", [printer.id]: "printer", [live.id]: null };
    assert.deepEqual(mark((await admin.policySnapshot()).verdicts as Array<{ id: string; noLongerApplies?: string }>), expected, "the panel's snapshot");
    assert.deepEqual(mark(await admin.egressApprovals() as Array<{ id: string; noLongerApplies?: string }>), expected, "the approvals listing");
    // An opener the guard could not name by its file: no question, no answer consulted.
    const d = await guard.decideSecretOpen({ path: secret, exe: "ssh-add", sha256: H, isAgent: false, exeSystem: true, openerEnv: [], procKey: "noname-1", session: "s-new", ask: "always" });
    assert.notEqual(d.verdict, "raw", `${d.verdict} ${d.reason}`);
    assert.notEqual(d.verdict, "ask", "no question no answer could name");
    assert.equal(d.approvalId, undefined);
    assert.deepEqual(await admin.egressApprovals("pending"), [], "nothing filed");
    // By its file, the same program is asked (the live question form).
    const named = await guard.decideSecretOpen({ path: secret, exe: "/opt/tools/pgtool", sha256: H, isAgent: false, exeSystem: false, openerEnv: [], procKey: "named-1", session: "s-new", ask: "always" });
    assert.equal(named.verdict, "ask", named.reason);
  } finally { guard.close(); admin.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); }
});
