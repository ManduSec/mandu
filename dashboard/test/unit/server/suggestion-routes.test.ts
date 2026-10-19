/**
 * suggestion-routes.test — the Suggested view's routes (dashboard.md §4.25r,
 * confidentiality-plan-14 §5.4) over a real DashboardServer with a mock
 * arbiter surface (the arbiter-client pattern: the parity over the real
 * client is tests/stack/dashboard-suggestions.test.ts).
 *
 * Pins: the GET needs the CSRF header AND the admin session (it names paths
 * where keys were found), and so does every POST (the global gate): without
 * either, 403 and nothing reaches the arbiter; "Not a secret" is refused
 * without the admin session; the scan reads a typed folder (`~` expanded) or
 * the folders the recorded sessions worked in, and asks for a folder when
 * there are none; "Also look in your home folder" sends `includeHome` with
 * this page's HOME (a boolean, checked before the arbiter is called; with it,
 * no known project is not an error), and the folders are capped at the
 * arbiter's eight; a scan past its wait answers "still scanning" and the GET
 * says when it ends; a scan started elsewhere is named; Save approves each
 * ticked suggestion on the admin channel as "dashboard" and refuses one that
 * cannot be applied or no longer waits; the admin boundary → 503; ids are
 * validated first; an arbiter without the ops → 501, none → 404.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { DashboardServer, type PolicyDocArbiter } from "../../../src/server.js";
import { adminUnavailableError } from "../../../src/server/http-util.js";
import type { SuggestionWire, SuggestPolicyWire } from "../../../src/view-model/suggestions.js";
import type { SuggestPolicyOpts } from "../../../src/server/suggestion-routes.js";
import type { EventSource, SessionRef } from "../../../src/event-source.js";
import type { ManduEvent } from "../../../src/event-model.js";
import { ADMIN_OPTS, ADMIN_COOKIE } from "../admin-session.js";

const HOME = "/home/u";
const CSRF_ADMIN = { "X-Mandu-Control": "1", Cookie: ADMIN_COOKIE, "Content-Type": "application/json" };
const STATUS = { path: "/p", found: true, valid: true, problems: [], loadedAt: 1, refusedAt: null };

function sourceWith(cwds: string[]): EventSource {
  const now = new Date().toISOString();
  const sessions: SessionRef[] = cwds.map((_, i) => ({ id: `s-live-${i}`, label: null, eventCount: 1, firstTs: now, lastTs: now, violated: false }));
  return {
    async listSessions() { return sessions; },
    async readEvents(id: string): Promise<ManduEvent[]> {
      const cwd = cwds[Number(id.slice("s-live-".length))]!;
      return [{
        id: "e1", seq: 0, ts: now, sessionId: id, turn: 0, kind: "tllm_call", view: "AgentView", boundary: "model_context",
        emitter: "anthropic-proxy", callId: null, parentId: null, input: null, output: null, invariant: { violatedInvariant: false },
        fullInput: { blocks: [{ role: "system", source: "agent", text: `<env>\nWorking directory: ${cwd}\n</env>` }] },
      } as unknown as ManduEvent];
    },
    subscribe() { return () => {}; },
    close() {},
  };
}

function view(id: string, over: Partial<SuggestionWire> = {}): SuggestionWire {
  return {
    id, kind: "suggestion", status: "pending", requestedBy: "mandu:scan", findingKey: `k-${id}`, source: "git-history", repoRoot: "/home/u/proj",
    edits: [{ op: "lock-path", path: "/home/u/proj/deploy/id_rsa", level: "no-model" }],
    sentence: "Make ~/proj/deploy/id_rsa a secret no AI may read (only in git history)",
    evidence: { paths: ["deploy/id_rsa"], blobs: [], historyOnly: true, findings: [] },
    impact: { historicalVersions: 1, workingTreeChanges: false, files: [] },
    historyOnly: true, rotate: true, applicable: true, createdAt: 1, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
    ...over,
  };
}

const RESULT: SuggestPolicyWire = {
  axis: true, running: false, suggestions: [], filed: ["pp-000001"], covered: [],
  counts: { findings: 1, suggested: 1, filed: 1, alreadyPending: 0, dismissed: 0, overCap: 0, covered: 0, dropped: 0, superseded: 0 },
  scan: { repos: [{ root: "/home/u/proj", repoRoot: "/home/u/proj" }], capped: { tooBig: 0, overTotal: 0, overTime: 0, untraced: 0, unlisted: false }, ms: 5 },
};

type Mode = "ok" | "adopted" | "busy" | "slow";

/** The mock of the adapter's suggestion surface. */
function mock(mode: Mode = "ok", withOps = true) {
  const calls: string[] = [];
  let pending: SuggestionWire[] = [view("pp-000001"), view("pp-000002", { applicable: false, edits: [{ op: "lock-blob", blob: `sha1:${"c".repeat(40)}`, level: "no-model" }], evidence: { paths: ["config.py"], blobs: [], historyOnly: false, findings: [] }, historyOnly: false })];
  let release: (() => void) | null = null;
  const arbiter: PolicyDocArbiter = {
    async policyDocument() { return { status: STATUS, inForce: null, onDisk: { text: null, parsed: null, problems: [] } }; },
    async applyPolicyDocument() { return { path: "/p", status: STATUS }; },
    async mintUserRule() { return { id: "r", path: "/p", status: STATUS }; },
    async exportDbLabels() { return { added: 0, path: "/p", status: STATUS }; },
    ...(withOps
      ? {
          async suggestPolicy(roots: string[], opts?: SuggestPolicyOpts) {
            calls.push(`scan:${roots.join(",")}:${opts?.home}${opts?.includeHome !== undefined ? `:includeHome=${opts.includeHome}` : ""}${opts?.sources !== undefined ? `:sources=${opts.sources}` : ""}`);
            if (mode === "busy") throw new Error("suggestPolicy: a history scan is already running; try again when it ends");
            if (mode === "slow") await new Promise<void>((r) => { release = r; });
            return { ...RESULT, suggestions: pending };
          },
          async policySuggestions(status?: string) { calls.push(`list:${status}`); return { suggestions: pending }; },
          async resolvePolicyProposal(id: string, verdict: "approved" | "denied", by?: string) {
            calls.push(`resolve:${id}:${verdict}:${by}`);
            if (mode === "adopted") throw adminUnavailableError("this dashboard did not start the arbiter (adopted instance)");
            pending = pending.filter((s) => s.id !== id);
            return { proposal: {} as never, changeId: "pc-000007" };
          },
          async dismissSuggestion(id: string, by?: string) {
            calls.push(`dismiss:${id}:${by}`);
            if (mode === "adopted") throw adminUnavailableError("adopted instance");
            const s = pending.find((x) => x.id === id);
            if (!s) throw new Error(`policy suggestion ${id} is already denied`);
            pending = pending.filter((x) => x.id !== id);
            return { suggestion: { ...s, status: "denied" as const } };
          },
        }
      : {}),
  };
  return { arbiter, calls, release: () => release?.() };
}

async function start(arbiter?: PolicyDocArbiter, opts: { cwds?: string[]; waitMs?: number; home?: string } = {}) {
  const server = new DashboardServer({
    source: sourceWith(opts.cwds ?? []), policyDocArbiter: arbiter, fileBrowserHome: opts.home ?? HOME, log: () => {},
    ...(opts.waitMs !== undefined ? { suggestScanWaitMs: opts.waitMs } : {}), ...ADMIN_OPTS,
  });
  const port = await server.listen(0);
  const base = `http://127.0.0.1:${port}`;
  const get = async (headers: Record<string, string> = CSRF_ADMIN) => {
    const r = await fetch(`${base}/api/suggestions`, { headers });
    return { status: r.status, body: (await r.json()) as any };
  };
  const post = async (path: string, body: unknown, headers: Record<string, string> = CSRF_ADMIN) => {
    const r = await fetch(`${base}/api/suggestions/${path}`, { method: "POST", headers, body: JSON.stringify(body) });
    return { status: r.status, body: (await r.json()) as any };
  };
  return { get, post, close: () => server.close() };
}

test("the GET needs the CSRF header and the admin session; with both it lists the pending suggestions as rows", async () => {
  const m = mock();
  const s = await start(m.arbiter);
  try {
    assert.equal((await s.get({})).status, 403, "no CSRF header");
    assert.equal((await s.get({ "X-Mandu-Control": "1" })).status, 403, "no admin session");
    assert.deepEqual(m.calls, [], "nothing reached the arbiter");
    const r = await s.get();
    assert.equal(r.status, 200);
    assert.equal(r.body.count, 2);
    assert.equal(r.body.suggestions[0].tag, "only in git history");
    assert.equal(r.body.suggestions[1].kind, "versions");
    assert.equal(r.body.suggestions[1].applicable, false);
    // The rows are worded for this host: a macOS launch hides no git history.
    for (const row of r.body.suggestions) {
      assert.equal(/on Linux\b.* On macOS .*stay readable/.test(row.impact), process.platform === "darwin", row.impact);
    }
    assert.equal(r.body.scan.running, false);
    assert.deepEqual(m.calls, ["list:pending"]);
  } finally {
    await s.close();
  }
});

test("every POST needs the CSRF header and the admin session: Not a secret included, nothing reaches the arbiter", async () => {
  const m = mock();
  const s = await start(m.arbiter, { cwds: ["/home/u/proj"] });
  try {
    for (const [path, body] of [["scan", {}], ["apply", { ids: ["pp-000001"] }], ["dismiss", { id: "pp-000001" }]] as const) {
      assert.equal((await s.post(path, body, { "Content-Type": "application/json" })).status, 403, `${path}: no CSRF`);
      assert.equal((await s.post(path, body, { "X-Mandu-Control": "1", "Content-Type": "application/json" })).status, 403, `${path}: no admin session`);
    }
    assert.deepEqual(m.calls, []);
  } finally {
    await s.close();
  }
});

test("scan: the folders the recorded sessions worked in, or a typed folder with ~ expanded; none known asks for one", async () => {
  const m = mock();
  const s = await start(m.arbiter, { cwds: ["/home/u/proj", "/home/u/other", "/home/u/proj"] });
  try {
    const r = await s.post("scan", {});
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(m.calls[0], `scan:/home/u/proj,/home/u/other:${HOME}`, "each workspace once, with HOME; both sources (none named), no home tier");
    assert.equal(r.body.scan.running, false);
    assert.equal(r.body.scan.summary, "Scanned the git history of ~/proj. 2 possible keys to review (1 new).");
    assert.equal(r.body.scan.includeHome, false);
    assert.deepEqual(r.body.scan.roots, ["~/proj", "~/other"]);
    assert.equal(r.body.count, 2);
    const typed = await s.post("scan", { root: "~/work/api/" });
    assert.equal(typed.status, 200);
    assert.equal(m.calls.filter((c) => c.startsWith("scan:")).at(-1), `scan:/home/u/work/api:${HOME}`);
    assert.equal((await s.post("scan", { root: "work/api" })).status, 400, "a relative folder");
    assert.equal((await s.post("scan", { root: 7 })).status, 400);
  } finally {
    await s.close();
  }
  const none = await start(mock().arbiter);
  try {
    const r = await none.post("scan", {});
    assert.equal(r.status, 400);
    assert.equal(r.body.needsRoot, true);
    assert.match(r.body.error, /Type the folder of a project/);
  } finally {
    await none.close();
  }
});

test("scan: 'Also look in your home folder' sends includeHome with HOME, validated first; alone it needs no known project; at most eight folders", async () => {
  const m = mock();
  const cwds = Array.from({ length: 10 }, (_, i) => `/home/u/p${i}`);
  const s = await start(m.arbiter, { cwds });
  try {
    for (const bad of [{ includeHome: "yes" }, { includeHome: 1 }, { includeHome: null }]) {
      const r = await s.post("scan", bad);
      assert.equal(r.status, 400, JSON.stringify(bad));
      assert.match(r.body.error, /includeHome must be true or false/);
    }
    assert.equal(m.calls.length, 0, "validated before the arbiter");
    const r = await s.post("scan", { includeHome: true });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(m.calls[0], `scan:${cwds.slice(0, 8).join(",")}:${HOME}:includeHome=true`, "the newest eight folders, HOME, and the home tier");
    assert.equal(r.body.scan.includeHome, true);
    const typed = await s.post("scan", { root: "~/work", includeHome: false });
    assert.equal(typed.status, 200);
    assert.equal(m.calls.filter((c) => c.startsWith("scan:")).at(-1), `scan:/home/u/work:${HOME}`, "false sends nothing extra");
  } finally {
    await s.close();
  }
  // No project known: the home folder alone is something to scan.
  const alone = mock();
  const none = await start(alone.arbiter);
  try {
    const r = await none.post("scan", { includeHome: true });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(alone.calls[0], `scan::${HOME}:includeHome=true`);
    assert.deepEqual(r.body.scan.roots, []);
    assert.equal((await none.post("scan", {})).body.needsRoot, true, "without it, a folder is still asked for");
  } finally {
    await none.close();
  }
  // A page whose HOME is not an absolute path cannot ask for it.
  const odd = mock();
  const rel = await start(odd.arbiter, { cwds: ["/home/u/proj"], home: "relative/home" });
  try {
    const r = await rel.post("scan", { includeHome: true });
    assert.equal(r.status, 400);
    assert.match(r.body.error, /home folder is not known/);
    assert.deepEqual(odd.calls, []);
  } finally {
    await rel.close();
  }
});

test("scan: past its wait it answers 'still scanning', a second Scan does not start another, and the GET says when it ends", async () => {
  const m = mock("slow");
  const s = await start(m.arbiter, { cwds: ["/home/u/proj"], waitMs: 20 });
  try {
    const r = await s.post("scan", {});
    assert.equal(r.status, 200);
    assert.equal(r.body.scan.running, true);
    assert.equal(r.body.scan.summary, null);
    const again = await s.post("scan", {});
    assert.equal(again.body.scan.running, true);
    assert.equal(m.calls.filter((c) => c.startsWith("scan:")).length, 1, "one scan at a time");
    assert.equal((await s.get()).body.scan.running, true);
    m.release();
    await new Promise((res) => setTimeout(res, 20));
    const done = (await s.get()).body;
    assert.equal(done.scan.running, false);
    assert.match(done.scan.summary, /^Scanned the git history of ~\/proj\./);
  } finally {
    await s.close();
  }
});

test("scan: one started elsewhere (the terminal, a launch) is named, not shown as a failure of this page", async () => {
  const s = await start(mock("busy").arbiter, { cwds: ["/home/u/proj"] });
  try {
    const r = await s.post("scan", {});
    assert.equal(r.status, 200);
    assert.match(r.body.scan.error, /^Another scan is running/);
  } finally {
    await s.close();
  }
});

test("apply: each ticked suggestion is approved on the admin channel as 'dashboard'; one that cannot be applied or no longer waits is refused", async () => {
  const m = mock();
  const s = await start(m.arbiter);
  try {
    for (const bad of [{}, { ids: [] }, { ids: ["x"] }, { ids: ["pp-000001", "pp-000001"] }, { ids: Array.from({ length: 51 }, (_, i) => `pp-${String(i).padStart(6, "0")}`) }]) {
      assert.equal((await s.post("apply", bad)).status, 400, JSON.stringify(bad));
    }
    assert.equal(m.calls.length, 0, "validated before the arbiter");
    const r = await s.post("apply", { ids: ["pp-000001", "pp-000002", "pp-000009"] });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(r.body.applied, [{ id: "pp-000001", changeId: "pc-000007" }]);
    assert.deepEqual(r.body.refused.map((x: any) => x.id), ["pp-000002", "pp-000009"]);
    assert.match(r.body.refused[0].error, /cannot hide old versions of a file yet/);
    assert.match(r.body.refused[1].error, /no longer waiting/);
    assert.deepEqual(m.calls.filter((c) => c.startsWith("resolve:")), ["resolve:pp-000001:approved:dashboard"], "only the applicable one reached the arbiter");
    assert.equal(r.body.count, 1, "the listing after Save");
  } finally {
    await s.close();
  }
});

test("apply and dismiss: an adopted arbiter (no admin channel) → 503 with the reason", async () => {
  const s = await start(mock("adopted").arbiter);
  try {
    const a = await s.post("apply", { ids: ["pp-000001"] });
    assert.equal(a.status, 503);
    assert.match(a.body.error, /admin channel unavailable/);
    const d = await s.post("dismiss", { id: "pp-000001" });
    assert.equal(d.status, 503);
  } finally {
    await s.close();
  }
});

test("dismiss: Not a secret on the admin channel as 'dashboard'; a second time → 409; a bad id → 400", async () => {
  const m = mock();
  const s = await start(m.arbiter);
  try {
    assert.equal((await s.post("dismiss", { id: "nope" })).status, 400);
    const r = await s.post("dismiss", { id: "pp-000002" });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.dismissed, "pp-000002");
    assert.equal(r.body.status, "denied");
    assert.equal(r.body.count, 1);
    assert.ok(m.calls.includes("dismiss:pp-000002:dashboard"));
    assert.equal((await s.post("dismiss", { id: "pp-000002" })).status, 409);
  } finally {
    await s.close();
  }
});

test("an arbiter without the ops → 501; no arbiter → 404", async () => {
  const s = await start(mock("ok", false).arbiter);
  try {
    assert.equal((await s.get()).status, 501);
    assert.equal((await s.post("scan", { root: "~/p" })).status, 501);
    assert.equal((await s.post("apply", { ids: ["pp-000001"] })).status, 501);
    assert.equal((await s.post("dismiss", { id: "pp-000001" })).status, 501);
  } finally {
    await s.close();
  }
  const none = await start(undefined);
  try {
    assert.equal((await none.get()).status, 404);
  } finally {
    await none.close();
  }
});
