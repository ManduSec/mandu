/**
 * E2E: fs-sync refuses to materialize symlinks — P5 of the portable fs core
 * (fs-sync.md §1.4 gap class 3: "name resolves elsewhere — aliasing").
 *
 * Real temp git repo + mock arbiter, both directions:
 *   ingress  a symlink TRACKED in the HumanView repo (pointing at a secret
 *            outside the workspace) is neutralized to an inert regular marker
 *            in the AgentView — the secret's bytes never appear there, and the
 *            HumanView's own link is untouched;
 *   egress   a symlink the AGENT plants in the AgentView (pointing at a secret)
 *            is refused by syncToHuman — no link and no target-content file
 *            materializes in the HumanView, the SYMLINK conflict is logged, and
 *            innocent files in the same sync still propagate;
 *   IO       readForAgent / captureAgentWrite throw on symlink paths rather
 *            than read/write THROUGH them; human-edit reconciliation skips a
 *            human-planted link instead of importing its target as trusted.
 */

import { strict as assert } from "node:assert";
import {
  existsSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { ViewSync, SYMLINK_MARKER } from "../../src/view-sync.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { makeTempRepo, gitIn } from "../helpers/temp-repo.js";

const SECRET = "TOP-SECRET-KEY-MATERIAL-9a8b7c";

/** A file OUTSIDE any workspace, standing in for ~/.ssh/id_rsa. */
function makeOutsideSecret(): { path: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-secret-"));
  const p = join(dir, "id_rsa");
  writeFileSync(p, SECRET);
  return { path: p, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test("ingress: a repo-tracked symlink is neutralized in the AgentView; the HumanView link survives", async () => {
  const secret = makeOutsideSecret();
  const repo = makeTempRepo({ "notes.md": "# notes\n" });
  try {
    // Track a symlink pointing OUT of the workspace, like an attacker's commit.
    symlinkSync(secret.path, join(repo.workspacePath, "leak"));
    gitIn(repo.workspacePath, ["add", "leak"]);
    gitIn(repo.workspacePath, ["commit", "-qm", "add leak symlink"]);

    const dv = new ViewSync({
      workspacePath: repo.workspacePath,
      arbiter: new MockArbiter(),
      stateBase: repo.stateBase,
    });
    await dv.initialize();

    // The AgentView twin is a REGULAR inert marker — not a link, no secret.
    const agentLeak = join(dv.agentViewPath, "leak");
    assert.ok(existsSync(agentLeak));
    assert.equal(lstatSync(agentLeak).isSymbolicLink(), false, "AgentView leak is not a symlink");
    const content = readFileSync(agentLeak, "utf8");
    assert.equal(content, SYMLINK_MARKER);
    assert.ok(!content.includes(SECRET));
    assert.ok(!content.includes(secret.path), "marker carries no attacker bytes (not even the target)");

    // The HumanView's own link is untouched and still points at the secret.
    assert.equal(lstatSync(join(repo.workspacePath, "leak")).isSymbolicLink(), true);

    // readForAgent through the (human-side) link path refuses… the AgentView
    // twin is now a regular marker, so the read serves the MARKER, never the
    // secret — assert the stronger property: no secret bytes come back.
    const served = await dv.readForAgent("leak");
    assert.ok(!served.toString("utf8").includes(SECRET));
  } finally {
    secret.cleanup();
  }
});

test("lazy re-init: syncToHuman's late worktree materialization ALSO neutralizes tracked symlinks (P5)", async () => {
  // The AgentView worktree can be materialized on a SECOND path: syncToHuman's
  // lazy re-init when the worktree is missing / was never initialized. That
  // checkout materializes repo-tracked symlinks exactly like initialize(), so
  // it must run the SAME neutralization — otherwise the agent (CWD = worktree)
  // reads straight through a live `leak -> secret` link (gap class 3).
  const secret = makeOutsideSecret();
  const repo = makeTempRepo({ "notes.md": "# notes\n" });
  try {
    symlinkSync(secret.path, join(repo.workspacePath, "leak"));
    gitIn(repo.workspacePath, ["add", "leak"]);
    gitIn(repo.workspacePath, ["commit", "-qm", "add leak symlink"]);

    const dv = new ViewSync({
      workspacePath: repo.workspacePath,
      arbiter: new MockArbiter(),
      stateBase: repo.stateBase,
    });
    // NOTE: no initialize() — syncToHuman hits the lazy materialization path.
    assert.equal(dv.isInitialized(), false);
    await dv.syncToHuman({ toolName: "Write", callId: "t1" });

    // The lazily-created worktree's tracked symlink is an inert marker, never a
    // live link to the secret.
    const agentLeak = join(dv.agentViewPath, "leak");
    assert.ok(existsSync(agentLeak));
    assert.equal(lstatSync(agentLeak).isSymbolicLink(), false, "lazily-materialized leak must be neutralized");
    assert.equal(readFileSync(agentLeak, "utf8"), SYMLINK_MARKER);
    assert.ok(!readFileSync(agentLeak, "utf8").includes(SECRET));
    // The HumanView's own link is untouched (step-2 SYMLINK guard).
    assert.equal(lstatSync(join(repo.workspacePath, "leak")).isSymbolicLink(), true);
  } finally {
    secret.cleanup();
  }
});

test("egress: an agent-planted symlink never syncs to the HumanView; innocent files still do", async () => {
  const secret = makeOutsideSecret();
  const repo = makeTempRepo({ "notes.md": "# notes\n" });
  try {
    const dv = new ViewSync({
      workspacePath: repo.workspacePath,
      arbiter: new MockArbiter(),
      stateBase: repo.stateBase,
    });
    await dv.initialize();

    // The "agent" plants a symlink at the secret AND writes an innocent file.
    symlinkSync(secret.path, join(dv.agentViewPath, "exfil"));
    dv.captureAgentWrite("report.md", "all good\n");

    const synced = await dv.syncToHuman({ toolName: "Write", callId: "t1" });

    // The innocent file propagated; the symlink did NOT — in ANY form.
    assert.ok(synced.includes("report.md"));
    assert.ok(!synced.includes("exfil"));
    const humanExfil = join(repo.workspacePath, "exfil");
    assert.equal(existsSync(humanExfil), false, "no file/link materialized in the HumanView");
    // And the secret's CONTENT was not smuggled anywhere in the HumanView.
    assert.ok(!readFileSync(join(repo.workspacePath, "report.md"), "utf8").includes(SECRET));

    // The refusal is auditable: a SYMLINK entry in conflicts.log.
    const conflicts = readFileSync(dv.layout.conflictsLogPath, "utf8");
    assert.match(conflicts, /"race":"SYMLINK"/);
    assert.match(conflicts, /exfil/);
  } finally {
    secret.cleanup();
  }
});

test("IO guards: readForAgent and captureAgentWrite refuse symlink paths outright", async () => {
  const secret = makeOutsideSecret();
  const repo = makeTempRepo({ "notes.md": "# notes\n" });
  try {
    const dv = new ViewSync({
      workspacePath: repo.workspacePath,
      arbiter: new MockArbiter(),
      stateBase: repo.stateBase,
    });
    await dv.initialize();

    // Agent-side link planted AFTER init (neutralization already ran).
    symlinkSync(secret.path, join(dv.agentViewPath, "alias.md"));
    await assert.rejects(() => dv.readForAgent("alias.md"), /symbolic link/);
    assert.throws(() => dv.captureAgentWrite("alias.md", "x"), /symbolic link/);
    // The secret file was NOT written through the link.
    assert.equal(readFileSync(secret.path, "utf8"), SECRET);
  } finally {
    secret.cleanup();
  }
});

test("human-edit reconcile: a human-planted symlink is skipped, its target never imported as trusted", async () => {
  const secret = makeOutsideSecret();
  const repo = makeTempRepo({ "notes.md": "# notes\n" });
  try {
    const dv = new ViewSync({
      workspacePath: repo.workspacePath,
      arbiter: new MockArbiter(),
      stateBase: repo.stateBase,
    });
    await dv.initialize();

    // A symlink appears in the HumanView as an uncommitted "human edit".
    symlinkSync(secret.path, join(repo.workspacePath, "wild-link"));
    await dv.reconcileHumanEdits();

    // Nothing materialized in the AgentView for it — in particular NOT the
    // secret's bytes as "trusted human-authored" raw text.
    const agentTwin = join(dv.agentViewPath, "wild-link");
    if (existsSync(agentTwin)) {
      assert.ok(!readFileSync(agentTwin, "utf8").includes(SECRET));
    }
  } finally {
    secret.cleanup();
  }
});
