/**
 * sensitivity-label-routes.test — Settings › Sensitivity labels
 * (dashboard.md §4.25s, confidentiality-plan-14 §14.1) and the Scan route's
 * label count, over a real DashboardServer with a fake arbiter surface.
 *
 * Pins:
 *   - the Suggested view's Scan asks the arbiter to COUNT labels
 *     (`countLabels: true`: an explicit scan), keeping the answer's label
 *     summary for Settings; its line counts the documents it read, and
 *     names Settings › Sensitivity labels as a link part (`summaryParts`)
 *     in the scan answer and in GET /api/suggestions;
 *   - GET /api/policy/sensitivity-labels needs the CSRF header and the admin
 *     session (403, nothing reaches the arbiter); it lists your mappings,
 *     the administrator's (read only, with the file) and the labels the last
 *     scan found with no level, less the ones mapped since; its note links
 *     Keys Mandu found (a link part) before any scan, and says a scan that
 *     found no labelled document found none, and which documents its label
 *     read left unchecked;
 *   - POST /api/policy/sensitivity-labels/change: a new mapping above
 *     public only adds suggestions, so it is proposed and applied at once as
 *     human:settings; removing one lowers what Mandu suggests, so the first
 *     send only asks (rows, wouldLet, expected) and the second, with what
 *     was shown, proposes on the admin surface and approves; a form mistake
 *     is a 400 before the arbiter; a validator refusal is a 422 with the
 *     file position stripped; a mapping gone meanwhile is a 409; the global
 *     gate holds (403 without CSRF or the admin session);
 *   - each row carries its mapping's version (a label with no level yet the
 *     absent version, an administrator's none); a change requires the
 *     version it was read at (400), names the mapping with it in `basedOn`,
 *     is refused 409 `stale` in the page's words when its own read already
 *     finds the mapping moved (nothing previewed or proposed) and when the
 *     arbiter refuses it at the write (nothing approved), and is sent to no
 *     arbiter that answers no versions (501).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { createHash } from "node:crypto";

import { DashboardServer, type PolicyDocArbiter } from "../../../src/server.js";
import type { SuggestPolicyOpts } from "../../../src/server/suggestion-routes.js";
import { LABEL_NOTE } from "../../../src/server/sensitivity-label-routes.js";
import { ALL_MAPPED_NOTE, NO_LABELS_NOTE, NO_SCAN_NOTE, labelStaleWords } from "../../../src/view-model/sensitivity-labels.js";
import { SETTINGS_APPROVER } from "../../../src/server/model-routes.js";
import type { SuggestPolicyWire } from "../../../src/view-model/suggestions.js";
import type { EventSource, SessionRef } from "../../../src/event-source.js";
import type { ManduEvent } from "../../../src/event-model.js";
import { ADMIN_OPTS, ADMIN_COOKIE } from "../admin-session.js";

const HC = "9fbde396-1a24-4c79-8edf-9254a0f35055";
const GEN = "1e4f0000-0000-4000-8000-000000000001";
const OTHER = "2a2a0000-0000-4000-8000-000000000002";
const STATUS = { path: "/p", found: true, valid: true, problems: [], loadedAt: 1, refusedAt: null };
const CSRF_ADMIN = { "X-Mandu-Control": "1", Cookie: ADMIN_COOKIE, "Content-Type": "application/json" };
const fakeSource: EventSource = {
  async listSessions(): Promise<SessionRef[]> { return []; },
  async readEvents(): Promise<ManduEvent[]> { return []; },
  subscribe(): () => void { return () => {}; },
  close(): void {},
};

const SCAN: SuggestPolicyWire = {
  axis: true, running: false, suggestions: [], filed: [], covered: [],
  counts: { findings: 0, suggested: 0, filed: 0, alreadyPending: 0, dismissed: 0, overCap: 0, covered: 0, dropped: 0, superseded: 0 },
  scan: null,
  workspaceScan: {
    roots: [{ root: "/home/u/proj", tier: "workspace" }], counts: { examined: 3, read: 3, cached: 0, bytes: 1, covered: 0 },
    capped: { tooBig: 0, overTotal: 0, overTime: 0, overFiles: 0, binary: 0, symlinks: 0, unreadable: 0, depth: 0 },
    limits: { fileMaxBytes: 1, totalMaxBytes: 1, maxFiles: 1, timeoutMs: 1000 }, ms: 1,
    labels: {
      mode: "count", examined: 3, read: 3, cached: 0, covered: 0, files: 3, mapped: 0, unmappedFiles: 3,
      unmapped: [{ id: HC, site: null, files: 2 }, { id: OTHER, site: null, files: 1 }], unmappedMore: 0, encrypted: 0, unreadable: 0,
    },
  },
};

/** The fake arbiter's item versions: a hash of the entry (the real one is
 *  keyed per process), the absent version all zeros. */
const ABSENT = "0".repeat(32);
const versionOf = (entry: unknown): string => createHash("sha256").update(JSON.stringify(entry)).digest("hex").slice(0, 32);
const keyOf = (l: { id: string; site?: string }): string => `${l.id}|${l.site ?? ""}`;

function fake(opts: { previewProblems?: string[]; scan?: SuggestPolicyWire; initial?: Record<string, unknown>; noVersions?: boolean; staleAtPropose?: boolean } = {}) {
  const calls: Array<{ op: string; args: unknown }> = [];
  let inForce: Record<string, unknown> = opts.initial ?? { version: 1 };
  const versions = () => ({
    "sensitivity-labels": Object.fromEntries(((inForce["sensitivity_labels"] as Array<{ id: string; site?: string }> | undefined) ?? []).map((l) => [keyOf(l), versionOf(l)])),
  });
  const relaxes = (edits: unknown): Array<{ facet: string; direction: string; subject: string; detail: string }> =>
    (edits as Array<{ op: string; id: string }>).filter((e) => e.op === "unmap-sensitivity-label").map((e) => ({ facet: "sensitivity-labels", direction: "relax", subject: e.id, detail: "d" }));
  const arbiter: PolicyDocArbiter = {
    async policyDocument() {
      calls.push({ op: "document", args: null });
      return {
        status: STATUS, inForce, onDisk: { text: null, parsed: null, problems: [] },
        ...(opts.noVersions ? {} : { itemVersions: versions(), absentVersion: ABSENT }),
        admin: { files: ["/etc/mandu/policy.d/l.yaml"], locked: false, models: [], sensitivityLabels: [{ id: GEN, name: "General", level: "any-model", file: "/etc/mandu/policy.d/l.yaml" }] },
      };
    },
    async applyPolicyDocument() { return { path: "/p", status: STATUS }; },
    async mintUserRule() { return { id: "r", path: "/p", status: STATUS }; },
    async exportDbLabels() { return { added: 0, path: "/p", status: STATUS }; },
    async suggestPolicy(roots: string[], o?: SuggestPolicyOpts) { calls.push({ op: "scan", args: { roots, ...o } }); return opts.scan ?? SCAN; },
    async policySuggestions() { return { suggestions: [] }; },
    async policyPreview(edits: unknown) {
      calls.push({ op: "preview", args: edits });
      if (opts.previewProblems) return { ok: false as const, problems: opts.previewProblems };
      const r = relaxes(edits);
      return { ok: true as const, relaxations: r as never[], tightenings: [], perEdit: [] };
    },
    async policyPropose(req: { edits: unknown; reason?: string; requestedBy?: string; basedOn?: Array<{ section: string; key: string; version: string }> }) {
      calls.push({ op: "propose", args: req });
      // The arbiter's check, in the same call as the write.
      const now = (b: { section: string; key: string }): string => (versions() as Record<string, Record<string, string>>)[b.section]?.[b.key] ?? ABSENT;
      const moved = (req.basedOn ?? []).filter((b) => opts.staleAtPropose || now(b) !== b.version);
      if (moved.length > 0) return { applied: false as const, refused: "stale", changed: moved.map((b) => `${b.section} ${b.key}`), problems: ["changed since it was read"] };
      const r = relaxes(req.edits);
      if (r.length === 0) {
        inForce = { version: 1, sensitivity_labels: (req.edits as Array<Record<string, unknown>>).map(({ op: _op, ...rest }) => rest) };
        return { applied: true as const, changeId: "pc-000004" } as never;
      }
      return { applied: false as const, proposalId: "pp-000003", relaxes: r.map((x) => ({ facet: x.facet, subject: x.subject })) };
    },
    async resolvePolicyProposal(id: string, verdict: "approved" | "denied", by?: string) {
      calls.push({ op: "resolve", args: [id, verdict, by] });
      return { proposal: {} as never, changeId: "pc-000011" };
    },
  };
  return { arbiter, calls };
}

async function start(arbiter: PolicyDocArbiter) {
  const server = new DashboardServer({ source: fakeSource, policyDocArbiter: arbiter, fileBrowserHome: "/home/u", log: () => {}, ...ADMIN_OPTS });
  const port = await server.listen(0);
  const base = `http://127.0.0.1:${port}`;
  const post = async (path: string, body: unknown, headers: Record<string, string> = CSRF_ADMIN) => {
    const r = await fetch(`${base}${path}`, { method: "POST", headers, body: JSON.stringify(body) });
    return { status: r.status, body: (await r.json()) as any };
  };
  const get = async (headers: Record<string, string> = CSRF_ADMIN) => {
    const r = await fetch(`${base}/api/policy/sensitivity-labels`, { headers });
    return { status: r.status, body: (await r.json()) as any };
  };
  const suggestions = async () => {
    const r = await fetch(`${base}/api/suggestions`, { headers: CSRF_ADMIN });
    return { status: r.status, body: (await r.json()) as any };
  };
  return { get, post, suggestions, close: () => server.close() };
}

test("Scan counts the labels (countLabels: an explicit scan), and Settings lists what it found with no level", async () => {
  const f = fake();
  const s = await start(f.arbiter);
  try {
    assert.equal((await s.get({})).status, 403, "no CSRF header");
    assert.equal((await s.get({ "X-Mandu-Control": "1" })).status, 403, "no admin session");
    assert.equal(f.calls.length, 0, "nothing reached the arbiter");
    const before = await s.get();
    assert.equal(before.status, 200);
    assert.deepEqual(before.body.labels.unmapped, [], "no scan yet");
    assert.equal(before.body.labels.note, NO_SCAN_NOTE, "where to scan");
    assert.deepEqual(before.body.labels.noteParts.filter((p: any) => p.kind === "link"), [{ kind: "link", text: "Keys Mandu found", to: "suggested" }],
      "the place it names is a link part (Rules hides Scan for keys until Keys Mandu found is opened)");
    assert.deepEqual(before.body.labels.mappings.map((m: any) => [m.id, m.admin]), [[GEN, "/etc/mandu/policy.d/l.yaml"]], "the administrator's, read only");

    const scan = await s.post("/api/suggestions/scan", { root: "/home/u/proj" });
    assert.equal(scan.status, 200, JSON.stringify(scan.body));
    const call = f.calls.find((c) => c.op === "scan")!.args as SuggestPolicyOpts & { roots: string[] };
    assert.equal(call.countLabels, true, "an explicit scan counts the labels");
    assert.equal(call.sources, undefined, "every source");
    assert.match(scan.body.scan.summary, /3 files carry a sensitivity label you have not chosen a level for/);
    // 3 files read as text and 3 documents read for their labels; the place
    // to set a level is a link part, never an address.
    const LINK = { kind: "link", text: "Settings › Sensitivity labels", to: "labels" };
    assert.match(scan.body.scan.summary, /^Scanned 6 files in ~\/proj\. /);
    assert.deepEqual(scan.body.scan.summaryParts.filter((p: any) => p.kind === "link"), [LINK]);
    assert.equal(scan.body.scan.summaryParts.map((p: any) => p.text).join(""), scan.body.scan.summary, "summary is the parts joined");
    const listed0 = await s.suggestions();
    assert.equal(listed0.status, 200);
    assert.equal(listed0.body.scan.summary, scan.body.scan.summary);
    assert.deepEqual(listed0.body.scan.summaryParts, scan.body.scan.summaryParts, "the listing keeps the parts");

    const after = await s.get();
    assert.deepEqual(after.body.labels.unmapped.map((u: any) => [u.id, u.files]), [[HC, 2], [OTHER, 1]]);
    assert.equal(typeof after.body.labels.scannedAt, "number");

    // Map one: a tightening (it only adds suggestions), applied at once.
    const map = await s.post("/api/policy/sensitivity-labels/change", { action: "map", id: HC.toUpperCase(), name: "Highly Confidential", level: "no-model", version: ABSENT });
    assert.equal(map.status, 200, JSON.stringify(map.body));
    assert.equal(map.body.applied, true);
    assert.equal(map.body.changeId, "pc-000004");
    assert.equal(map.body.note, LABEL_NOTE);
    const proposed = f.calls.find((c) => c.op === "propose")!.args as { edits: unknown; requestedBy: string; reason: string };
    assert.deepEqual(proposed.edits, [{ op: "map-sensitivity-label", id: HC, name: "Highly Confidential", level: "no-model" }]);
    assert.equal(proposed.requestedBy, "settings");
    assert.match(proposed.reason, /Sensitivity labels \(map\)/);
    // Mapped since the scan: no longer listed as having no level.
    const listed = await s.get();
    assert.deepEqual(listed.body.labels.unmapped.map((u: any) => u.id), [OTHER]);
    assert.deepEqual(listed.body.labels.mappings.map((m: any) => [m.id, m.admin]), [[HC, null], [GEN, "/etc/mandu/policy.d/l.yaml"]]);
  } finally {
    await s.close();
  }
});

test("a scan that found no document with a label: Settings says it found none and links Keys Mandu found again, never that every label found has a level", async () => {
  const none: SuggestPolicyWire = {
    ...SCAN,
    workspaceScan: { ...SCAN.workspaceScan!, labels: { ...SCAN.workspaceScan!.labels!, files: 0, unmappedFiles: 0, unmapped: [] } },
  };
  const f = fake({ scan: none });
  const s = await start(f.arbiter);
  try {
    assert.equal((await s.post("/api/suggestions/scan", { root: "/home/u/proj" })).status, 200);
    const after = (await s.get()).body.labels;
    assert.deepEqual(after.unmapped, []);
    assert.equal(typeof after.scannedAt, "number", "a scan ran");
    assert.equal(after.note, NO_LABELS_NOTE);
    assert.notEqual(after.note, ALL_MAPPED_NOTE);
    assert.deepEqual(after.noteParts.filter((p: any) => p.kind === "link"), [{ kind: "link", text: "Keys Mandu found", to: "suggested" }]);
  } finally {
    await s.close();
  }
});

test("a scan whose label read left documents unchecked: Settings' note says which, in the scan line's words (the stored answer keeps them)", async () => {
  const gaps: SuggestPolicyWire = {
    ...SCAN,
    workspaceScan: {
      ...SCAN.workspaceScan!,
      labels: {
        ...SCAN.workspaceScan!.labels!, files: 0, unmappedFiles: 0, unmapped: [], encrypted: 1, unreadable: 1,
        capped: { overFiles: 2, overBytes: 0 }, limits: { maxFiles: 2_000, totalMaxBytes: 32 * 1024 * 1024 },
      },
    },
  };
  const f = fake({ scan: gaps });
  const s = await start(f.arbiter);
  try {
    const UNCHECKED = "1 encrypted document was not read, so its sensitivity label is not known. " +
      "Not checked for a sensitivity label: 2 documents past the 2,000 it looks at and 1 document it could not read.";
    const scan = await s.post("/api/suggestions/scan", { root: "/home/u/proj" });
    assert.equal(scan.status, 200);
    assert.ok(scan.body.scan.summary.endsWith(UNCHECKED), scan.body.scan.summary);
    const after = (await s.get()).body.labels;
    assert.equal(after.note,
      `The last scan found no sensitivity label on the documents it checked. ${UNCHECKED} To look in another folder, open Keys Mandu found in Rules.`);
    assert.deepEqual(after.noteParts.filter((p: any) => p.kind === "link"), [{ kind: "link", text: "Keys Mandu found", to: "suggested" }]);
    assert.equal(after.noteParts.map((p: any) => p.text).join(""), after.note);
  } finally {
    await s.close();
  }
});

test("removing a mapping lowers what Mandu suggests: the first send asks, the second (with what was shown) proposes and approves as human:settings", async () => {
  const f = fake();
  const s = await start(f.arbiter);
  try {
    const ask = await s.post("/api/policy/sensitivity-labels/change", { action: "unmap", id: HC, version: ABSENT });
    assert.equal(ask.status, 200, JSON.stringify(ask.body));
    assert.equal(ask.body.applied, false);
    assert.equal(ask.body.confirm, true);
    assert.deepEqual(ask.body.expected, [`sensitivity-labels\u0000${HC}`]);
    assert.match(JSON.stringify(ask.body.rows), /Stop suggesting a label/);
    assert.match(JSON.stringify(ask.body.wouldLet), /would suggest less/);
    assert.equal(f.calls.some((c) => c.op === "propose"), false, "asked only");
    const done = await s.post("/api/policy/sensitivity-labels/change", { action: "unmap", id: HC, version: ABSENT, expected: ask.body.expected });
    assert.equal(done.status, 200, JSON.stringify(done.body));
    assert.equal(done.body.applied, true);
    assert.equal(done.body.changeId, "pc-000011");
    assert.deepEqual(f.calls.find((c) => c.op === "resolve")!.args, ["pp-000003", "approved", SETTINGS_APPROVER]);
  } finally {
    await s.close();
  }
});

test("a form mistake is a 400 before the arbiter; a validator refusal a 422 without the file position; a mapping gone a 409; the gate holds", async () => {
  const f = fake();
  const s = await start(f.arbiter);
  try {
    for (const bad of [{ action: "map", id: "x", name: "a", level: "no-model" }, { action: "map", id: HC, name: "", level: "no-model" }, { action: "map", id: HC, name: "a", level: "secret" }, { action: "drop", id: HC }]) {
      assert.equal((await s.post("/api/policy/sensitivity-labels/change", bad)).status, 400, JSON.stringify(bad));
    }
    assert.equal((await s.post("/api/policy/sensitivity-labels/change", { action: "unmap", id: HC, expected: "x" })).status, 400);
    assert.equal(f.calls.length, 0, "nothing reached the arbiter");
    const path = "/api/policy/sensitivity-labels/change";
    assert.equal((await s.post(path, { action: "unmap", id: HC }, { "Content-Type": "application/json" })).status, 403, "no CSRF");
    assert.equal((await s.post(path, { action: "unmap", id: HC }, { "X-Mandu-Control": "1", "Content-Type": "application/json" })).status, 403, "no admin session");
  } finally {
    await s.close();
  }
  const refused = fake({ previewProblems: ["sensitivity_labels[0].name: must be one line of 1 to 64 characters (the label's name in your words)"] });
  const r = await start(refused.arbiter);
  try {
    const x = await r.post("/api/policy/sensitivity-labels/change", { action: "map", id: HC, name: "n", level: "no-model", version: ABSENT });
    assert.equal(x.status, 422);
    assert.deepEqual(x.body.problems, ["name: must be one line of 1 to 64 characters (the label's name in your words)"]);
  } finally {
    await r.close();
  }
  const gone = fake({ previewProblems: [`edits[0] (unmap-sensitivity-label): no mapping for the label ${HC}`] });
  const g = await start(gone.arbiter);
  try {
    assert.equal((await g.post("/api/policy/sensitivity-labels/change", { action: "unmap", id: HC, version: ABSENT })).status, 409);
  } finally {
    await g.close();
  }
});

// ── a change names the mapping as it was read (policy-surface.md §8.4.6) ──

const MAPPED = { version: 1, sensitivity_labels: [{ id: HC, name: "Highly Confidential", level: "no-model" }, { id: OTHER, name: "Internal", level: "any-model" }] };
const PATH = "/api/policy/sensitivity-labels/change";

test("each row carries its mapping's version: yours its own, a label with no level yet the absent one, the administrator's none", async () => {
  const f = fake({ initial: MAPPED, scan: { ...SCAN, workspaceScan: { ...SCAN.workspaceScan!, labels: { ...SCAN.workspaceScan!.labels!, unmapped: [{ id: "3b3b0000-0000-4000-8000-000000000003", site: null, files: 1 }] } } } });
  const s = await start(f.arbiter);
  try {
    assert.equal((await s.post("/api/suggestions/scan", { root: "/home/u/proj" })).status, 200);
    const vm = (await s.get()).body.labels;
    assert.deepEqual(vm.mappings.map((m: any) => [m.id, m.version]), [[HC, versionOf(MAPPED.sensitivity_labels[0])], [OTHER, versionOf(MAPPED.sensitivity_labels[1])], [GEN, null]]);
    assert.deepEqual(vm.unmapped.map((u: any) => u.version), [ABSENT]);
  } finally {
    await s.close();
  }
  const old = fake({ initial: MAPPED, noVersions: true });
  const o = await start(old.arbiter);
  try {
    assert.deepEqual((await o.get()).body.labels.mappings.map((m: any) => m.version), [null, null, null], "an older service sends none");
  } finally {
    await o.close();
  }
});

test("a change requires the version it was read at (400), and names the mapping with it: another mapping's change does not refuse it", async () => {
  const f = fake({ initial: MAPPED });
  const s = await start(f.arbiter);
  try {
    for (const v of [undefined, null, "short", "G".repeat(32)]) {
      const r = await s.post(PATH, { action: "map", id: HC, name: "Highly Confidential", level: "local-model", ...(v === undefined ? {} : { version: v }) });
      assert.equal(r.status, 400, String(v));
      assert.match(r.body.error, /did not say which version of the label it showed you/);
    }
    assert.equal(f.calls.length, 0, "nothing reached the arbiter");
    const v = versionOf(MAPPED.sensitivity_labels[0]);
    const ask = await s.post(PATH, { action: "unmap", id: HC, version: v });
    assert.equal(ask.body.confirm, true, JSON.stringify(ask.body));
    const done = await s.post(PATH, { action: "unmap", id: HC, version: v, expected: ask.body.expected });
    assert.equal(done.status, 200, JSON.stringify(done.body));
    const proposed = f.calls.find((c) => c.op === "propose")!.args as { basedOn: unknown };
    assert.deepEqual(proposed.basedOn, [{ section: "sensitivity-labels", key: `${HC}|`, version: v }], "the mapping, at the version the row was read at");
  } finally {
    await s.close();
  }
});

test("a mapping changed since the row was read: 409 stale in the page's words, nothing previewed, proposed or approved", async () => {
  const f = fake({ initial: MAPPED });
  const s = await start(f.arbiter);
  try {
    const read = versionOf({ id: HC, name: "Highly Confidential", level: "local-model" }); // the row as it was before someone raised it
    const r = await s.post(PATH, { action: "map", id: HC, name: "Highly Confidential", level: "public", version: read });
    assert.equal(r.status, 409);
    assert.equal(r.body.stale, true);
    assert.deepEqual(r.body.changed, [`sensitivity-labels ${HC}|`]);
    assert.equal(r.body.error, labelStaleWords("Highly Confidential", "map"));
    const u = await s.post(PATH, { action: "unmap", id: HC, version: read });
    assert.equal(u.status, 409);
    assert.equal(u.body.error, labelStaleWords("Highly Confidential", "unmap"), "the name comes from the mapping in force");
    // A label the read found with no level, mapped since by someone else.
    const n = await s.post(PATH, { action: "map", id: OTHER, name: "Internal", level: "public", version: ABSENT });
    assert.equal(n.status, 409);
    assert.ok(!f.calls.some((c) => c.op === "preview" || c.op === "propose" || c.op === "resolve"), f.calls.map((c) => c.op).join(" "));
  } finally {
    await s.close();
  }
});

test("a mapping that changes between this read and the write: the arbiter refuses it, 409 stale, nothing approved", async () => {
  const f = fake({ initial: MAPPED, staleAtPropose: true });
  const s = await start(f.arbiter);
  try {
    const v = versionOf(MAPPED.sensitivity_labels[0]);
    const ask = await s.post(PATH, { action: "unmap", id: HC, version: v });
    const r = await s.post(PATH, { action: "unmap", id: HC, version: v, expected: ask.body.expected });
    assert.equal(r.status, 409, JSON.stringify(r.body));
    assert.equal(r.body.stale, true);
    assert.equal(r.body.error, labelStaleWords("Highly Confidential", "unmap"));
    assert.ok(!f.calls.some((c) => c.op === "resolve"), "nothing approved");
  } finally {
    await s.close();
  }
});

test("an arbiter that answers no versions could not refuse a stale change: 501, nothing previewed or proposed", async () => {
  const f = fake({ initial: MAPPED, noVersions: true });
  const s = await start(f.arbiter);
  try {
    const r = await s.post(PATH, { action: "map", id: HC, name: "Highly Confidential", level: "public", version: ABSENT });
    assert.equal(r.status, 501);
    assert.ok(!f.calls.some((c) => c.op === "preview" || c.op === "propose"));
  } finally {
    await s.close();
  }
});
