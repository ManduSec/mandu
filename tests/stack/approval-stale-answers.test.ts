/**
 * approval-stale-answers — questions and answers about a program by its
 * name alone (before 2026-10-02) across the REAL components (dashboard.md
 * §4.34 "Answers that no longer apply"). Mandu-new.
 *
 * An older arbiter's rows in the DB (a pending `open:ssh-add` and
 * `write:nano`, an answered `write:tee` Always allow, an answered printer,
 * a live answer by file), then a real ArbiterServer (`secrets` axes) on that
 * DB, a real DashboardServer over a real ArbiterEventSource with the real
 * admin-socket client behind its approval routes:
 *
 *   S1  the pending name-only questions are in no listing: Approvals waits on
 *       nothing, and an answer from a stale page is refused (409, why);
 *   S2  /api/home's Answered earlier and /api/policy/panel mark the answered
 *       name-only and printer rows with why, and offer no change; the live
 *       answer keeps its Allow instead;
 *   S3  the served Approvals page reads "No longer applies" and the why under
 *       the words, with no button on that row.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { EgressApprovalStore } from "../../arbiter/policy/egress-approvals.js";
import { DashboardServer, type ApprovalsArbiter } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { PolicyPanelVM } from "../../dashboard/src/view-model/policy-panel.js";
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";

stateAxes("secrets");

const H = "e".repeat(64);
const CSRF = { "X-Mandu-Control": "1" };

test("name-only questions are retired, and answers that apply to nothing say so with no change offered, across the real arbiter and dashboard", { timeout: 60_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-approval-stale-"));
  const home = join(tmp, "home");
  mkdirSync(home, { recursive: true });
  const secret = join(home, ".pgpass");
  writeFileSync(secret, "db:5432:*:u:stale_stack_canary_01\n");
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n`);
  const dbPath = join(tmp, "symbols.sqlite");
  const old = new EgressApprovalStore({ dbPath });
  const pendingOpen = old.recordPending("open:ssh-add", secret, "ssh-add wants to read it", "s-old");
  const pendingWrite = old.recordPending("write:nano", join(home, ".bashrc"), "nano wants to change it", "s-old");
  const name = old.recordPending("write:tee", join(home, ".bashrc"), "tee wants to change it", "s-old");
  old.resolve(name.id, true, "always");
  const printer = old.recordPending(`open:/usr/bin/cat#${H}`, secret, "cat wants to read it", "s-old");
  old.resolve(printer.id, true, "always");
  const live = old.recordPending(`open:/usr/bin/ssh-add#${H}`, secret, "ssh-add wants to read it", "s-old");
  old.resolve(live.id, false, "always");
  old.close();

  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath,
    dbPath, eventDir: join(tmp, "events"), policyPath, policyPollMs: 0, log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const approvalsArbiter: ApprovalsArbiter = {
    egressApprovals: (status) => admin.egressApprovals(status),
    resolveEgressApproval: (approvalId, approve, scope) => admin.resolveEgressApproval(approvalId, approve, scope),
  };
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter, fileBrowserHome: home, configEnv: { MANDU_HOME: join(tmp, "mandu-home") }, log: () => {},
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  try {
    // S1: the pending name-only questions wait on nothing.
    const vm = (await (await pageFetch(`${base}/api/home`)).json()) as HomeVM;
    assert.deepEqual(vm.waiting.map((a) => a.id), [], "no name-only question is waiting");
    for (const row of [pendingOpen, pendingWrite]) {
      const r = await pageFetch(`${base}/api/egress/approvals/${row.id}/approve-once`, { method: "POST", headers: { ...CSRF, Cookie: dashboard.adminCookie() } });
      assert.equal(r.status, 409, `${row.id}: a stale page's answer is refused`);
      assert.match(((await r.json()) as { error: string }).error, /by its name only/);
    }

    // S2: the answers, marked on both routes.
    const answered = (id: string) => vm.answered.find((a) => a.id === id)!;
    assert.match(answered(name.id).staleNote ?? "", /^This answer no longer applies: it names the program by its name only/);
    assert.deepEqual(answered(name.id).actions, []);
    assert.match(answered(printer.id).staleNote ?? "", /prints what it reads/);
    assert.deepEqual(answered(printer.id).actions, []);
    assert.ok(!("staleNote" in answered(live.id)));
    assert.deepEqual(answered(live.id).actions.map((a) => a.label), ["Allow instead"]);
    const panel = ((await (await pageFetch(`${base}/api/policy/panel`)).json()) as { panel: PolicyPanelVM }).panel;
    const row = panel.queue.find((r) => r.id === name.id)!;
    assert.equal(row.noLongerApplies, "name-only");
    assert.equal(row.staleNote, answered(name.id).staleNote);
    assert.deepEqual(row.actions, []);

    // S3: the served page.
    const sel = `#approvals-answered .row.answered[data-id="${name.id}"]`;
    await servedProductPage(base, "/approvals", (doc) => doc.querySelector(sel) !== null, (doc) => {
      const r = doc.querySelector(sel);
      assert.ok(r, "the served page lists the answer");
      assert.equal(r.querySelector(".answered-stale").textContent, answered(name.id).staleNote);
      assert.equal(r.querySelector(".outcome").textContent, "No longer applies");
      assert.equal(r.querySelectorAll("button").length, 0, "no change offered");
      assert.ok(!(doc.body.textContent ?? "").includes("stale_stack_canary_01"), "no value on the page");
    });
  } finally {
    await dashboard.close();
    admin.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
