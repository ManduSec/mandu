/**
 * policy-suggest-labels e2e — confidentiality plan 14 §14.1 (4a: sensitivity
 * labels) over the PRODUCTION path: the launcher's `realPolicySuggestDeps()`
 * and `startLaunchSuggest` against a REAL ArbiterServer holding a file-backed
 * law, over Office documents built at run time (arbiter/test/helpers/office-zip.ts):
 *
 *   - policy.yaml maps one label to `no-model` (Highly Confidential) and one
 *     to `public` (General); a third label is unmapped;
 *   - `board/q3-board.docx` carries the mapped label: `--json` lists ONE
 *     `lock-path` suggestion (`source: "sensitivity-label"`, the mapping's
 *     name in the sentence), the launch notice counts it as a labelled
 *     document, and a scripted terminal session applies it on the DATA
 *     socket (the law shows the lock, a `tighten` change by `mandu:scan`);
 *     after it, the file is covered: a rescan never opens it and files
 *     nothing, and the notice is gone;
 *   - `plan.docx` (unmapped) is counted in `workspaceScan.labels.unmapped`
 *     and the header's "not mapped" line, and suggests nothing;
 *   - `notes.pptx` (public) suggests nothing;
 *   - `ledger.docx`, which the law labels already, is never opened.
 *
 * The oracle (implementation-plan.md §9): no byte of any fixture's text (the
 * documents' bodies, the display name Office wrote) in the command's stdout
 * or stderr (text and --json), the launch notice, the arbiter's log, or
 * policy.yaml. Only the arbiter lookup and the terminal are injected. Axes
 * stated: secrets.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { defaultWorkspaceFs, type WorkspaceScanFs } from "../../arbiter/policy/secret-workspace-scan.js";
import type { SuggestPolicyResult } from "../../arbiter/ipc/protocol.js";
import { buildOfficeFile } from "../../arbiter/test/helpers/office-zip.js";
import {
  realPolicySuggestDeps, runPolicySuggest, startLaunchSuggest,
  type LabelScanWire, type PolicySuggestDeps, type SuggestionViewWire, type WorkspaceScanWire,
} from "../../launcher/src/policy-suggest.js";
import type { Layout } from "../../launcher/src/services/layout.js";
import { stateAxes } from "../../arbiter/test/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

// What the launcher reads of the label summary is what the arbiter sends
// (a compile-time parity check: `npm run typecheck` fails when they drift).
const labelsParity = (w: NonNullable<SuggestPolicyResult["workspaceScan"]>): LabelScanWire | null | undefined => w.labels;
void labelsParity;

const HC = "9fbde396-1a24-4c79-8edf-9254a0f35055";
const GEN = "1e4f7c2a-3b5d-4e6f-8a9b-0c1d2e3f4a5b";
const UNMAPPED = "2b2b2b2b-1111-4222-8333-444455556666";
const TENANT = "5b3c2d4e-1111-4222-8333-444455556666";
const canary = (tag: string): string => `${tag}${randomBytes(12).toString("hex")}`;
const BODIES = [canary("BOARD"), canary("PLAN"), canary("NOTES"), canary("LEDGER")];
const DISPLAY_NAME = canary("DISPLAYNAME");

function noText(what: string, s: string): void {
  for (const c of [...BODIES, DISPLAY_NAME]) {
    assert.ok(!s.includes(c), `${what} carries a document's text`);
    assert.ok(!s.includes(c.slice(-16)), `${what} carries a run of a document's text`);
  }
}

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

test("mandu policy suggest over the real arbiter: a mapped no-model label files one lock-path, the terminal applies it and the file is covered; unmapped counted, public silent, a labelled file never opened; no text in any output", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-suggest-labels-"));
  dirs.push(dir);
  const home = join(dir, "home");
  const repo = join(home, "proj");
  mkdirSync(join(repo, "board"), { recursive: true });
  const board = join(repo, "board", "q3-board.docx");
  const ledger = join(repo, "ledger.docx");
  writeFileSync(board, buildOfficeFile({ labelInfo: [{ id: HC, site: TENANT }], custom: [{ id: HC, site: TENANT, name: DISPLAY_NAME }], body: BODIES[0]!, stored: true }));
  writeFileSync(join(repo, "plan.docx"), buildOfficeFile({ labelInfo: [{ id: UNMAPPED, site: TENANT }], body: BODIES[1]!, stored: true }));
  writeFileSync(join(repo, "notes.pptx"), buildOfficeFile({ labelInfo: [{ id: GEN, site: TENANT }], body: BODIES[2]!, stored: true }));
  writeFileSync(ledger, buildOfficeFile({ labelInfo: [{ id: HC, site: TENANT }], body: BODIES[3]!, stored: true }));
  writeFileSync(join(repo, "README.md"), "a project\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, [
    "version: 1",
    "paths:",
    `  - path: ${ledger}`,
    "    level: no-model",
    "sensitivity_labels:",
    `  - id: ${HC}`,
    `    site: ${TENANT}`,
    "    name: Highly Confidential",
    "    level: no-model",
    `  - id: ${GEN}`,
    "    name: General",
    "    level: public",
    "",
  ].join("\n"));

  const opened: string[] = [];
  const logs: string[] = [];
  const fs: WorkspaceScanFs = { ...defaultWorkspaceFs, readLabels: async (p, caps) => { opened.push(p); return defaultWorkspaceFs.readLabels!(p, caps); } };
  const sock = join(dir, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"), adminPolicyDir: null,
    policyPath: policy, policyPollMs: 0, confidentiality: true, integrity: false, log: (m) => logs.push(m),
    workspaceScan: { fs, env: {}, discovery: { installEnv: {}, selfDir: null } },
  });
  await server.listen();
  const env = { HOME: home, NO_COLOR: "1", PATH: process.env["PATH"] ?? "/usr/bin:/bin" };
  const outputs: string[] = [];
  const deps = (o: { tty: boolean; keys?: string[] }): { d: PolicySuggestDeps; out: string[]; err: string[] } => {
    const out: string[] = [], err: string[] = [];
    const keys = [...(o.keys ?? [])];
    return {
      out, err,
      d: {
        ...realPolicySuggestDeps(),
        arbiter: async () => ({ sock, kind: "resident" as const, axisOn: true, stop: async () => {} }),
        cwd: () => repo,
        isTTY: () => o.tty,
        readKey: async () => keys.shift() ?? "",
        readLine: async () => "",
        out: (s) => { out.push(s); outputs.push(s); },
        err: (s) => { err.push(s); outputs.push(s); },
      },
    };
  };
  const client = new ArbiterClient(sock);
  try {
    // ── the launch's own scan: the mapping is in force, so it reads the labels; the notice names a document
    const notice = await startLaunchSuggest({ sock, cwd: repo, home, env: { MANDU_SUGGEST_WAIT_MS: "20000" } });
    assert.equal(notice, "mandu: 1 labelled document in this project is not protected: run `mandu policy suggest` or open Keys Mandu found in the dashboard");
    outputs.push(notice!);
    assert.ok(!opened.includes(ledger), "a file the law labels is never opened");

    // ── --json: one suggestion, the unmapped label counted
    const j = deps({ tty: false });
    assert.equal(await runPolicySuggest(["--json"], env, {} as Layout, j.d), 0, j.err.join(""));
    const listed = JSON.parse(j.out.join("")) as { suggestions: SuggestionViewWire[]; workspaceScan: WorkspaceScanWire | null };
    assert.equal(listed.suggestions.length, 1, JSON.stringify(listed.suggestions.map((s) => s.findingKey)));
    const s = listed.suggestions[0]!;
    assert.equal(s.source, "sensitivity-label");
    assert.equal(s.findingKey, `sensitivity-label:${board}`);
    assert.deepEqual(s.edits, [{ op: "lock-path", path: board, level: "no-model" }]);
    assert.equal(s.sentence, "Make ~/proj/board/q3-board.docx a secret no AI may read: its sensitivity label is Highly Confidential");
    assert.deepEqual(s.evidence.label, { id: HC, site: TENANT, name: "Highly Confidential", level: "no-model" });
    assert.equal(s.humanOnly, false);
    const L = listed.workspaceScan!.labels!;
    assert.equal(L.mode, "mapped");
    assert.equal(L.files, 3, "q3-board, plan, notes");
    assert.equal(L.mapped, 2, "q3-board (no-model) and notes (public)");
    assert.deepEqual(L.unmapped, [{ id: UNMAPPED, site: TENANT, files: 1 }]);
    assert.equal(L.covered, 1, "ledger.docx");
    assert.ok(!opened.includes(ledger), "still never opened");

    // ── a scripted terminal: [p] then [a]
    const t = deps({ tty: true, keys: ["p", "a"] });
    assert.equal(await runPolicySuggest([], env, {} as Layout, t.d), 0, t.err.join("") + t.out.join(""));
    const screen = t.out.join("");
    assert.match(screen, /\[1\/1\] Make ~\/proj\/board\/q3-board\.docx a secret no AI may read: its sensitivity label is Highly Confidential\n/);
    assert.match(screen, /From the document's sensitivity label: Highly Confidential\n {6}hides: this file, from the next launch\n/);
    // §14.1: the review says a label lowered in Office later lowers nothing.
    assert.match(screen, /hides: this file, from the next launch\n {6}If the label is lowered or removed in Office later, this rule stays as it is/);
    assert.match(screen, / {2}· 1 file carries a sensitivity label you have not mapped: map it in the dashboard \(Settings › Sensitivity labels\)/);
    assert.doesNotMatch(screen.slice(screen.indexOf("[1/1]")), /[Rr]otate/);
    assert.match(screen, /Applied \(change pc-\d+; undo it in the dashboard, under Rule changes in Approvals\)\./);
    const law = await client.policyDocument();
    const lock = (law.inForce as { paths?: Array<{ path: string; level: string }> }).paths?.find((p) => p.path === board);
    assert.deepEqual(lock, { path: board, level: "no-model" });
    const change = (await client.policyChanges(1)).changes[0]!;
    assert.equal(change.via, "agent-tighten");
    assert.equal(change.proposalId, s.id);
    assert.equal(change.proposedBy, "mandu:scan");

    // ── after: the file is covered: never opened again, nothing filed, no notice
    opened.length = 0;
    const again = deps({ tty: false });
    assert.equal(await runPolicySuggest(["--json"], env, {} as Layout, again.d), 0);
    const later = JSON.parse(again.out.join("")) as { suggestions: SuggestionViewWire[]; workspaceScan: WorkspaceScanWire | null };
    assert.deepEqual(later.suggestions, []);
    assert.equal(later.workspaceScan!.labels!.covered, 2);
    assert.ok(!opened.includes(board), "the locked document is not opened again");
    assert.equal(await startLaunchSuggest({ sock, cwd: repo, home, env: { MANDU_SUGGEST_WAIT_MS: "20000" } }), null, "nothing waits: no line");

    // ── the oracle
    for (const [what, text] of [["the command's output", outputs.join("\n")], ["the arbiter's log", logs.join("\n")], ["policy.yaml", readFileSync(policy, "utf8")]] as const) noText(what, text);
  } finally {
    client.close();
    await server.close();
  }
});
