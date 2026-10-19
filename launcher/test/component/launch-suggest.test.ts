/**
 * launch-suggest component test — the launch-time policy-suggestion notice
 * (confidentiality-plan-14-policy-suggestions.md §5.5) over its PRODUCTION
 * wire: `startLaunchSuggest` with its default deps (`ndjsonCall` on a real
 * Unix socket) against a stand-in arbiter that speaks the `suggestPolicy`
 * NDJSON op the way arbiter/ipc/server.ts does:
 *
 *   - the request carries `roots: [cwd]`, `home`, the budget and
 *     `answerFromEarlier: true`;
 *   - a workspace never scanned before: the launch waits for the scan (up to
 *     the budget) and prints the plain notice;
 *   - after a finished scan: the stand-in answers at once from it (`running:
 *     true`, `lastScanAt`), the launch does not wait, and the notice says it
 *     is the last finished scan's; its compact form is unchanged;
 *   - the error paths: an error reply, no socket, a stand-in that never
 *     answers (cut at the budget plus the margin): no notice, one debug
 *     note each, nothing after the wait settled.
 *
 * The real arbiter's half (it answers from the earlier result and finishes
 * the scan in the background) is pinned in arbiter/test/component/
 * policy-suggestions.test.ts and, end to end, tests/stack/
 * policy-suggest-cli.test.ts. Advisory only: no secret crosses this wire
 * (paths and masks), so there is no value oracle here. Axes stated: secrets.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { compactNotice } from "../../src/launch-banner.js";
import { EARLIER_SCAN_NOTE, LAUNCH_SUGGEST_MARGIN_MS, realPolicySuggestDeps, startLaunchSuggest, type SuggestPolicyWire, type SuggestionViewWire } from "../../src/policy-suggest.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the suggestions exist only with the confidentiality axis on

const dir = mkdtempSync(join(tmpdir(), "mdu-launch-suggest-"));
after(() => rmSync(dir, { recursive: true, force: true }));
const HOME = join(dir, "home");
const REPO = join(HOME, "proj");

function view(): SuggestionViewWire {
  return {
    id: "pp-000001", kind: "suggestion", status: "pending", requestedBy: "mandu:scan",
    findingKey: `workspace:path:${REPO}/deploy/staging.conf`, source: "workspace", repoRoot: REPO,
    edits: [{ op: "lock-path", path: `${REPO}/deploy/staging.conf`, level: "no-model" }],
    sentence: "Make ~/proj/deploy/staging.conf a secret no AI may read",
    evidence: { paths: ["deploy/staging.conf"], blobs: [], historyOnly: false, findings: [] },
    impact: { historicalVersions: 0, workingTreeChanges: true, files: ["deploy/staging.conf"] },
    historyOnly: false, rotate: false, applicable: true,
    createdAt: 1, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
  };
}

function answer(over: Partial<SuggestPolicyWire>): SuggestPolicyWire {
  return {
    axis: true, running: false, suggestions: [view()], filed: [], covered: [],
    counts: { findings: 1, suggested: 1, filed: 1, alreadyPending: 0, dismissed: 0, overCap: 0, covered: 0, dropped: 0, superseded: 0 },
    scan: null, workspaceScan: null, ...over,
  };
}

/** A stand-in arbiter: `reply(req)` gives the answer line's body and its
 *  delay (null = never answer). Records every request. */
async function standIn(
  name: string,
  reply: (req: Record<string, unknown>) => { body: Record<string, unknown>; delayMs: number } | null,
): Promise<{ sock: string; seen: Array<Record<string, unknown>>; close: () => Promise<void> }> {
  const sock = join(dir, `${name}.sock`);
  const seen: Array<Record<string, unknown>> = [];
  const conns = new Set<Socket>();
  const server: Server = createServer((s) => {
    conns.add(s);
    s.on("close", () => conns.delete(s));
    s.on("error", () => {});
    let buf = "";
    s.setEncoding("utf8");
    s.on("data", (chunk: string) => {
      buf += chunk;
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      const req = JSON.parse(buf.slice(0, nl)) as Record<string, unknown>;
      seen.push(req);
      const r = reply(req);
      if (r === null) return;
      setTimeout(() => { if (!s.destroyed) s.write(JSON.stringify({ id: req["id"], ...r.body }) + "\n"); }, r.delayMs);
    });
  });
  await new Promise<void>((res) => server.listen(sock, res));
  return {
    sock, seen,
    close: () => new Promise<void>((res) => { for (const c of conns) c.destroy(); server.close(() => res()); }),
  };
}

/** What a loaded CI guest adds to a wait. The bounds below catch a launch
 *  that waits out its budget or never returns, not a slow host: the timers
 *  of these tests ran 308 to 1058 ms past their idle time in pipelines
 *  10194, 10295 and 10309 (test-organization.md §8.4), and a launch that
 *  ignored the answer or its cap would wait 10 s or for ever. */
const LOADED_MS = 5_000;

const PLAIN = "mandu: 1 possible key in this project is not protected: run `mandu policy suggest` or open Keys Mandu found in the dashboard";

test("§5.5 on the wire: the first launch waits for the scan; once one finished, the next answers at once from it", async () => {
  const SCAN_MS = 300;
  let finishedAt: number | null = null;
  const arb = await standIn("arb", (req) => {
    assert.equal(req["op"], "suggestPolicy");
    if (req["answerFromEarlier"] === true && finishedAt !== null) {
      return { body: { ok: true, result: answer({ running: true, lastScanAt: finishedAt }) }, delayMs: 0 };
    }
    const waitMs = req["waitMs"] as number;
    if (SCAN_MS > waitMs) return { body: { ok: true, result: answer({ running: true, suggestions: [], lastScanAt: null }) }, delayMs: waitMs };
    finishedAt = Date.now() + SCAN_MS;
    return { body: { ok: true, result: answer({ lastScanAt: finishedAt }) }, delayMs: SCAN_MS };
  });
  try {
    // A budget far past the scan: the first launch's answer is the scan's
    // (PLAIN), never the cap's null, however late the host runs its timers.
    const BUDGET_MS = 10_000;
    const env = { MANDU_SUGGEST_WAIT_MS: String(BUDGET_MS) };
    let t0 = Date.now();
    const first = await startLaunchSuggest({ sock: arb.sock, cwd: REPO, home: HOME, env });
    const firstMs = Date.now() - t0;
    assert.equal(first, PLAIN, "the scan's answer, within the budget");
    assert.ok(firstMs >= SCAN_MS - 20, `the first launch waited for the scan (${firstMs} ms)`);
    assert.deepEqual(arb.seen[0], { id: 1, op: "suggestPolicy", roots: [REPO], home: HOME, waitMs: BUDGET_MS, answerFromEarlier: true });

    const notes: string[] = [];
    t0 = Date.now();
    const second = await startLaunchSuggest({ sock: arb.sock, cwd: REPO, home: HOME, env }, {
      suggest: realPolicySuggestDeps().suggest,
      debug: (m) => notes.push(m),
    });
    const secondMs = Date.now() - t0;
    // The stand-in answers it at once from the finished scan; a launch that
    // waited on anything more would wait out its 10 s budget.
    assert.ok(secondMs < BUDGET_MS - LOADED_MS, `the second launch did not wait for its scan or its budget (${secondMs} ms)`);
    assert.equal(second, PLAIN + EARLIER_SCAN_NOTE);
    assert.equal(compactNotice(second!), "mandu: ! 1 possible key in this project is not protected; see `mandu policy suggest`",
      "the compact display's line is the same as a fresh scan's");
    assert.deepEqual(notes, ["mandu: policy suggestions from the last finished scan; this launch's scan runs in the background"]);
    assert.equal(arb.seen.length, 2);
    assert.equal(arb.seen[1]!["answerFromEarlier"], true);
  } finally {
    await arb.close();
  }
});

test("§5.5 on the wire: a first scan past the budget is cut there; error reply, no socket and a wedged arbiter are one debug note each", async () => {
  // Past the budget: the arbiter answers `running: true` at the budget.
  const slow = await standIn("slow", (req) => ({ body: { ok: true, result: answer({ running: true, suggestions: [], lastScanAt: null }) }, delayMs: req["waitMs"] as number }));
  const failing = await standIn("failing", () => ({ body: { ok: false, error: "suggestPolicy: roots must be a list of absolute paths" }, delayMs: 0 }));
  const wedged = await standIn("wedged", () => null);
  try {
    let t0 = Date.now();
    assert.equal(await startLaunchSuggest({ sock: slow.sock, cwd: REPO, home: HOME, env: { MANDU_SUGGEST_WAIT_MS: "200" } }), null);
    let took = Date.now() - t0;
    assert.ok(took >= 180 && took < 200 + LAUNCH_SUGGEST_MARGIN_MS + LOADED_MS, `cut at the budget (${took} ms)`);

    const notes: string[] = [];
    const debug = (m: string): void => { notes.push(m); };
    const real = realPolicySuggestDeps().suggest;
    assert.equal(await startLaunchSuggest({ sock: failing.sock, cwd: REPO, home: HOME, env: {} }, { suggest: real, debug }), null);
    assert.deepEqual(notes, ["mandu: policy suggestions not checked (suggestPolicy: roots must be a list of absolute paths)"]);

    assert.equal(await startLaunchSuggest({ sock: join(dir, "absent.sock"), cwd: REPO, home: HOME, env: {} }, { suggest: real, debug }), null);
    assert.match(notes[1]!, /^mandu: policy suggestions not checked \(.*ENOENT/);

    t0 = Date.now();
    assert.equal(await startLaunchSuggest({ sock: wedged.sock, cwd: REPO, home: HOME, env: { MANDU_SUGGEST_WAIT_MS: "100" } }, { suggest: real, debug }), null);
    took = Date.now() - t0;
    assert.ok(took < 100 + LAUNCH_SUGGEST_MARGIN_MS + LOADED_MS, `a wedged arbiter costs at most the budget and the margin (${took} ms)`);
    assert.equal(notes.length, 3, notes.join("\n"));
    assert.match(notes[2]!, /not checked \((?:arbiter suggestPolicy timed out|no answer within the budget)/);
    // Nothing more once the wait settled (the agent may own the terminal).
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(notes.length, 3, notes.join("\n"));
  } finally {
    await Promise.all([slow.close(), failing.close(), wedged.close()]);
  }
});
