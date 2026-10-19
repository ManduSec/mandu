/**
 * file-browser-routes.test — the Rules page's file browser (dashboard.md
 * §4.25m) over a REAL DashboardServer and a real folder tree on disk, with a
 * FAKE arbiter (labels by a small rule table; the policy-document ops record
 * what they were asked).
 *
 * What it pins:
 *   - the listing is served only with the CSRF header AND the admin session
 *     (a GET is open to any same-host process, the agent's too);
 *   - names and kinds only: a file's contents never appear in the answer;
 *     folders first, symlinks say where they point, pages of 500;
 *   - each entry carries the label a read gets today, in the page's words; a
 *     label that cannot be read is served as unknown (null), never as ordinary;
 *   - Save: a tightening applies at once as one policy.yaml change; a
 *     loosening answers with what to confirm and applies only when sent back
 *     with exactly that; a rule kept in the page's own store is changed there;
 *   - each entry carries its path's own rule's version (the absent version
 *     when it has none); each policy.yaml edit of a Save names its rule
 *     (`basedOn`) with the version the page sent, else this route's own
 *     read; a rule changed since the page read it is refused 409 `stale` in
 *     the page's words before anything is asked, and one changed between
 *     this read and the write is refused by the arbiter (409, nothing
 *     approved, no page-store change); a symlink's target names its own
 *     rule, never the link's version; an arbiter without versions is sent
 *     no change that names one (501).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import {
  DashboardServer,
  ADMIN_SESSION_REQUIRED,
  type ConfidentialityState,
  type PathLabelResult,
  type SecretsArbiter,
  type PolicyDocArbiter,
} from "../../../src/server.js";
import { ADMIN_OPTS, CSRF_ADMIN } from "../admin-session.js";
import type { EventSource } from "../../../src/event-source.js";
import type { PathLevelsEntryWire } from "../../../src/view-model/file-browser.js";
import { LIST_PAGE, SCAN_MAX } from "../../../src/server/file-browser-routes.js";
import { tmpDir } from "../tmp-dir.js";

const fakeSource: EventSource = {
  async listSessions() { return []; },
  async readEvents() { return []; },
  subscribe() { return () => {}; },
  close() {},
};

// Canonical, like a real HOME: link targets come back realpathed, and on darwin
// tmpdir() is a symlinked spelling (/tmp → /private/tmp, /var → /private/var).
const HOME = realpathSync(tmpDir("mandu-files-home-"));
after(() => rmSync(HOME, { recursive: true, force: true }));
const WS = join(HOME, "ws");
mkdirSync(join(WS, "config"), { recursive: true });
mkdirSync(join(WS, "big"));
writeFileSync(join(WS, ".env"), "API_KEY=sk-live-DO-NOT-SHOW\n");
writeFileSync(join(WS, "README.md"), "hello\n");
writeFileSync(join(WS, "config", "db.yaml"), "password: hunter2\n");
symlinkSync(join(WS, "config"), join(WS, "conf-link"));
symlinkSync(join(WS, "gone"), join(WS, "dangling"));
symlinkSync(join(WS, "config", "db.yaml"), join(WS, "db-link"));
mkdirSync(join(WS, "deep", "a", "b"), { recursive: true });
writeFileSync(join(WS, "deep", "a", "b", ".env"), "x");
writeFileSync(join(WS, "deep", "a", "notes.txt"), "x");
writeFileSync(join(WS, "deep", "k.pem"), "x");
for (let i = 0; i < LIST_PAGE + 10; i++) writeFileSync(join(WS, "big", `f${String(i).padStart(4, "0")}.txt`), "");

interface Harness {
  base: string;
  calls: string[];
  proposed: unknown[][];
  /** Each propose's `basedOn`, in order. */
  based: unknown[];
  /** The fake arbiter's rule versions by key: set one to say it moved. */
  versions: Map<string, string>;
  resolved: Array<[string, string]>;
  pageActs: string[];
  close: () => Promise<void>;
}

/** Labels: a policy rule on ws/config, a page rule on ws/README.md, the
 *  catalog on .env. */
function levelOf(p: string): PathLevelsEntryWire {
  if (p === join(WS, "config") || p.startsWith(join(WS, "config") + "/")) return { path: p, level: "no-model", bindings: [], rule: `label:${join(WS, "config")}`, store: "policy" };
  if (p === join(WS, "README.md")) return { path: p, level: "no-model", bindings: [], rule: `label:${p}`, store: "page" };
  if (p.endsWith("/.env")) return { path: p, level: "no-model", bindings: [], rule: "shape:.env*", store: null };
  return { path: p, level: "public", bindings: [], rule: null, store: null };
}

/** The fake arbiter's item versions: config's rule has one; a path with no
 *  rule of its own has the absent version. */
const ABSENT = "0".repeat(32);
const V_CONFIG = "c".repeat(32);

async function start(opts: { labelsDown?: boolean; noPathLevels?: boolean; pageLabels?: Array<{ path: string; recursive: boolean }>; moveRefusal?: string; noVersions?: boolean; staleAtPropose?: boolean } = {}): Promise<Harness> {
  const calls: string[] = [];
  const proposed: unknown[][] = [];
  const based: unknown[] = [];
  const versions = new Map<string, string>([[join(WS, "config"), V_CONFIG], ["glob:**/*.pem", "e".repeat(32)]]);
  const resolved: Array<[string, string]> = [];
  const pageActs: string[] = [];
  const secrets: SecretsArbiter = {
    async confidentialityState(): Promise<ConfidentialityState> {
      calls.push("confidentialityState");
      return { enabled: true, secrets: [], taintedProcesses: [{ procKey: "p1", app: "node", path: join(WS, ".env"), level: "no-model", session: null, since: Date.UTC(2026, 8, 28, 10, 2) }], labels: [
        { path: join(WS, "config"), level: "no-model", bindings: [], recursive: true, source: "policy-file", updatedAt: 1, declassifies: false },
        { path: join(WS, "config", "sample.env"), level: "public", bindings: [], recursive: false, source: "policy-file", updatedAt: 1, declassifies: true },
        { path: "**/*.pem", level: "no-model", bindings: [], recursive: true, glob: true, source: "policy-file", updatedAt: 1, declassifies: false },
        { path: join(WS, "README.md"), level: "no-model", bindings: [], recursive: false, source: "user", updatedAt: 1, declassifies: false },
        ...(opts.pageLabels ?? []).map((l) => ({ path: l.path, level: "no-model" as const, bindings: [], recursive: l.recursive, source: "user" as const, updatedAt: 1, declassifies: false })),
      ] };
    },
    async setPathLabel(a): Promise<PathLabelResult> {
      pageActs.push(`set ${a.path} ${a.confidentiality}`);
      return { path: a.path, level: a.confidentiality, bindings: a.bindings ?? [], recursive: a.recursive ?? true, declassifies: false };
    },
    async removePathLabel(p) { pageActs.push(`remove ${p}`); return true; },
    ...(opts.noPathLevels ? {} : {
      async pathLevels(paths: string[], home?: string, withEdits?: unknown) {
        calls.push(`pathLevels ${paths.length} home=${home}${withEdits ? " withEdits" : ""}`);
        if (opts.labelsDown) throw new Error("connection closed");
        const locks = ((withEdits ?? []) as Array<{ op: string; path: string; level?: string }>).filter((e) => e.op === "lock-path");
        return { axis: true, levels: paths.map((p) => {
          const lock = locks.find((l) => p === l.path || p.startsWith(l.path + "/") || (l.path.startsWith("**/*") && p.endsWith(l.path.slice(4))));
          return lock ? { path: p, level: lock.level!, bindings: [], rule: `label:${lock.path}`, store: "policy" as const } : levelOf(p);
        }) };
      },
      async whyPath(path: string) {
        calls.push(`whyPath ${path}`);
        return { path, axis: true, level: "no-model", rule: "shape:.env*", bindings: [], outranked: [{ path: "**/.env*", level: "any-model" }],
          readers: ["ssh-add", { app: "ssh", from: "git" }], others: "twin", consumers: [], twinShape: "dotenv",
          twin: { form: "structured", shape: "dotenv", fields: 2 }, verdicts: [{ app: "node", status: "approved", scope: "once" }] };
      },
    }),
  };
  // The preview says: a public or any-model lock loosens; unlock loosens; a no-model lock tightens.
  const loosens = (edits: unknown[]) => (edits as Array<{ op: string; path: string; level?: string }>)
    .filter((e) => e.op === "unlock-path" || e.level !== "no-model")
    .map((e) => ({ facet: "paths", subject: e.path, detail: "inspector words", direction: "relax" }));
  const policyDoc = {
    async policyDocument() {
      calls.push("policyDocument");
      return { status: {}, inForce: {}, onDisk: { text: null, parsed: null, problems: [] },
        ...(opts.noVersions ? {} : { itemVersions: { paths: Object.fromEntries(versions) }, absentVersion: ABSENT }) };
    },
    async movePageLabels(by?: string) {
      calls.push(`movePageLabels ${by}`);
      if (opts.moveRefusal) throw new Error(opts.moveRefusal);
      return { moved: 1, changeId: "pc-000005" };
    },
    async policyPreview(edits: unknown[]) { calls.push("policyPreview"); return { ok: true, problems: [], relaxations: loosens(edits), tightenings: [] }; },
    async policyPropose(r: { edits: unknown[]; basedOn?: Array<{ section: string; key: string; version: string }> }) {
      proposed.push(r.edits);
      based.push(r.basedOn);
      // The arbiter's check, in the same call as the write.
      const moved = (r.basedOn ?? []).filter((b) => opts.staleAtPropose || (versions.get(b.key) ?? ABSENT) !== b.version);
      if (moved.length > 0) return { applied: false as const, refused: "stale", changed: moved.map((b) => `${b.section} ${b.key}`), problems: ["changed since it was read"] };
      const rel = loosens(r.edits);
      return rel.length ? { applied: false as const, proposalId: "pp-000001", relaxes: rel } : { applied: true as const, changeId: "pc-000001" };
    },
    async resolvePolicyProposal(id: string, verdict: "approved" | "denied") {
      resolved.push([id, verdict]);
      return { proposal: { id } as never, changeId: "pc-000002" };
    },
  } as unknown as PolicyDocArbiter;
  const server = new DashboardServer({ source: fakeSource, secretsArbiter: secrets, policyDocArbiter: policyDoc, fileBrowserHome: HOME, log: () => {}, ...ADMIN_OPTS });
  const port = await server.listen(0);
  return { base: `http://127.0.0.1:${port}`, calls, proposed, based, versions, resolved, pageActs, close: () => server.close() };
}

const get = async (h: Harness, path: string, headers: Record<string, string> = CSRF_ADMIN) => {
  const r = await fetch(`${h.base}/api/files/list?path=${encodeURIComponent(path)}`, { headers });
  return { status: r.status, body: (await r.json()) as any, text: "" };
};
const post = async (h: Harness, body: unknown, headers: Record<string, string> = CSRF_ADMIN) => {
  const r = await fetch(`${h.base}/api/files/labels`, { method: "POST", headers: { ...headers, "Content-Type": "application/json" }, body: JSON.stringify(body) });
  return { status: r.status, body: (await r.json()) as any };
};

test("the listing needs the CSRF header AND the admin session; the arbiter is not asked otherwise", async () => {
  const h = await start();
  try {
    assert.equal((await get(h, "~/ws", {})).status, 403);
    const noAdmin = await get(h, "~/ws", { "X-Mandu-Control": "1" });
    assert.equal(noAdmin.status, 403);
    assert.equal(noAdmin.body.error, ADMIN_SESSION_REQUIRED);
    assert.deepEqual(h.calls, []);
    assert.equal((await get(h, "~/ws")).status, 200);
  } finally { await h.close(); }
});

test("a folder: names and kinds only, folders first, links say where they point, each entry with its label in the page's words", async () => {
  const h = await start();
  try {
    const r = await get(h, "~/ws");
    assert.equal(r.status, 200);
    const b = r.body;
    assert.equal(b.path, WS);
    assert.equal(b.display, "~/ws");
    assert.equal(b.home, HOME);
    assert.equal(b.parent, HOME);
    assert.deepEqual(b.crumbs, [{ name: "~", path: HOME }, { name: "ws", path: WS }]);
    assert.deepEqual(b.entries.map((e: any) => `${e.kind}:${e.name}`), [
      "dir:big", "dir:conf-link", "dir:config", "dir:deep", "file:.env", "file:README.md", "other:dangling", "file:db-link",
    ]);
    const at = (name: string) => b.entries.find((e: any) => e.name === name);
    assert.equal(at("conf-link").link, "~/ws/config");
    assert.equal(at("dangling").link, "~/ws/gone");
    assert.deepEqual([at("config").label.words, at("config").label.from, at("config").label.removable], ["No AI", "Your rule", true]);
    assert.equal(at("config").inside, 1, "one literal rule is inside it (the pattern is not counted)");
    assert.equal(at(".env").label.from, "Built in: environment files");
    assert.equal(at("README.md").label.store, "page");
    assert.equal(at("big").label.words, "Like any other file");
    assert.equal(b.labels, "ok");
    assert.equal(b.axis, true);
    assert.equal(b.self.source, "none");
    assert.ok(h.calls.includes(`pathLevels 10 home=${HOME}`), "one round trip: the folder, its eight entries and the one link target that is a file, with HOME");
    // A symlink says where it ends, and how that file is treated when it differs.
    assert.equal(at("db-link").target, join(WS, "config", "db.yaml"));
    assert.equal(at("db-link").label.words, "Like any other file");
    assert.equal(at("db-link").targetLabel.words, "No AI");
    assert.equal(at("conf-link").targetLabel.words, "No AI");
    assert.equal(at("dangling").target, null);
    assert.equal(at("README.md").targetLabel, null);
    const raw = JSON.stringify(b);
    for (const secret of ["sk-live-DO-NOT-SHOW", "hunter2", "hello"]) assert.ok(!raw.includes(secret), `no file contents in the answer (${secret})`);
    // Inside: an inherited label.
    const inner = (await get(h, join(WS, "config"))).body;
    assert.equal(inner.entries[0].label.from, "From your rule on ~/ws/config");
    assert.equal(inner.self.from, "Your rule");
  } finally { await h.close(); }
});

test("pages of 500: `more` and `offset` walk a large folder", async () => {
  const h = await start();
  try {
    const first = (await get(h, "~/ws/big")).body;
    assert.equal(first.entries.length, LIST_PAGE);
    assert.equal(first.total, LIST_PAGE + 10);
    assert.equal(first.more, true);
    const r = await fetch(`${h.base}/api/files/list?path=${encodeURIComponent("~/ws/big")}&offset=${LIST_PAGE}`, { headers: CSRF_ADMIN });
    const second = (await r.json()) as any;
    assert.equal(second.entries.length, 10);
    assert.equal(second.more, false);
    assert.equal(second.entries[9].name, `f${String(LIST_PAGE + 9).padStart(4, "0")}.txt`);
  } finally { await h.close(); }
});

test("paths that are not folders are answered plainly", async () => {
  const h = await start();
  try {
    const missing = await get(h, "~/nope");
    assert.equal(missing.status, 404);
    assert.match(missing.body.error, /does not exist\. Use ~/);
    assert.equal(missing.body.path, join(HOME, "nope"));
    const file = await get(h, "~/ws/.env");
    assert.equal(file.status, 400);
    assert.equal(file.body.file, true);
    assert.equal(file.body.path, join(WS, ".env"));
    for (const p of ["ws", "**/*.pem"]) assert.equal((await get(h, p)).status, 400, p);
    assert.equal((await get(h, "~")).body.path, HOME, "~ is the home folder");
    assert.equal((await get(h, "/")).body.parent, null);
  } finally { await h.close(); }
});

test("labels that cannot be read are served as unknown (null), never as ordinary", async () => {
  for (const opts of [{ labelsDown: true }, { noPathLevels: true }]) {
    const h = await start(opts);
    try {
      const b = (await get(h, "~/ws")).body;
      assert.equal(b.labels, "unknown");
      assert.ok(b.labelError);
      assert.equal(b.self, null);
      assert.ok(b.entries.every((e: any) => e.label === null));
      assert.equal(b.axis, null);
    } finally { await h.close(); }
  }
});

test("Save: a tightening applies at once as one change", async () => {
  const h = await start();
  try {
    const r = await post(h, { changes: [{ path: "~/ws/big", level: "no-model", recursive: true }, { path: "**/*.key", level: "no-model" }] });
    assert.equal(r.status, 200);
    assert.deepEqual(r.body, { applied: true, changeId: "pc-000001", page: 0 });
    assert.deepEqual(h.proposed, [[
      { op: "lock-path", path: join(WS, "big"), level: "no-model" },
      { op: "lock-path", path: "**/*.key", level: "no-model" },
    ]]);
    assert.deepEqual(h.pageActs, []);
  } finally { await h.close(); }
});

test("Save: a loosening first answers with what to confirm, in the page's words; it applies only with exactly that", async () => {
  const h = await start();
  try {
    const body = { changes: [{ path: "~/ws/.env", level: "public", recursive: false }, { path: join(WS, "config"), level: null }] };
    const ask = await post(h, body);
    assert.equal(ask.status, 200);
    assert.equal(ask.body.confirm, true);
    assert.equal(ask.body.applied, false);
    assert.deepEqual(ask.body.expected, [`paths\u0000${join(WS, ".env")}`, `paths\u0000${join(WS, "config")}`]);
    assert.deepEqual(ask.body.loosens.map((l: any) => l.subject), ["~/ws/.env", "~/ws/config"]);
    assert.match(ask.body.loosens[0].detail, /^Becomes Not secret/);
    assert.match(ask.body.loosens[1].detail, /^Loses its own rule/);
    assert.ok(!JSON.stringify(ask.body).includes("inspector words"), "the arbiter's inspector wording is not shown");
    assert.deepEqual(h.proposed, [], "asking changes nothing");

    const stale = await post(h, { ...body, expected: [ask.body.expected[0]] });
    assert.equal(stale.status, 409, "confirming less than what it does changes nothing");
    assert.deepEqual(h.proposed, [], "refused at the preview, before anything is proposed");

    const ok = await post(h, { ...body, expected: ask.body.expected, reason: "a test fixture" });
    assert.equal(ok.status, 200);
    assert.deepEqual(ok.body, { applied: true, changeId: "pc-000002", page: 0 });
    assert.deepEqual(h.resolved, [["pp-000001", "approved"]]);
  } finally { await h.close(); }
});

test("Save: a rule kept in the page's own store is changed there, in place; making it weaker asks first", async () => {
  const h = await start();
  try {
    const body = { changes: [{ path: "~/ws/README.md", level: "any-model", recursive: false }] };
    const ask = await post(h, body);
    assert.equal(ask.body.confirm, true);
    assert.deepEqual(ask.body.expected, [`page\u0000${join(WS, "README.md")}`]);
    assert.match(ask.body.loosens[0].detail, /^Becomes Any AI, when it asks/);
    assert.deepEqual(h.pageActs, []);
    assert.equal((await post(h, { ...body, expected: [] })).status, 409);
    assert.deepEqual(h.pageActs, []);
    const ok = await post(h, { ...body, expected: ask.body.expected });
    assert.deepEqual(ok.body, { applied: true, changeId: null, page: 1 });
    assert.deepEqual(h.pageActs, [`set ${join(WS, "README.md")} any-model`]);
    assert.deepEqual(h.proposed, [], "nothing written to policy.yaml for it");
  } finally { await h.close(); }
});

// dashboard.md §4.25f *A rule on a file reads as a file*: the question a
// weaker change asks words a rule reaching everything inside a FILE as that
// file (the disk says which, path-kinds.ts); a folder keeps its words. Only
// the words: what is confirmed, proposed and changed is the same.
test("Save: the weaker-change question words a rule reaching everything inside a file as that file, a folder as a folder; the same keys", async () => {
  const h = await start({ pageLabels: [{ path: join(WS, "deep", "k.pem"), recursive: true }, { path: join(WS, "deep", "a"), recursive: true }] });
  try {
    const body = { changes: [
      { path: "~/ws/.env", level: "any-model", recursive: true },
      { path: "~/ws/deep", level: "any-model", recursive: true },
      { path: "~/ws/db-link", level: "public", recursive: true },
      { path: "~/ws/deep/k.pem", level: "any-model", recursive: true },
      { path: "~/ws/deep/a", level: "any-model", recursive: true },
    ] };
    const ask = await post(h, body);
    assert.equal(ask.status, 200);
    assert.equal(ask.body.confirm, true);
    assert.deepEqual(ask.body.expected, [
      `paths\u0000${join(WS, ".env")}`, `paths\u0000${join(WS, "deep")}`, `paths\u0000${join(WS, "db-link")}`, `paths\u0000${join(WS, "config", "db.yaml")}`,
      `page\u0000${join(WS, "deep", "k.pem")}`, `page\u0000${join(WS, "deep", "a")}`,
    ], "every loosening is still asked about");
    assert.deepEqual(ask.body.loosens.map((l: any) => [l.subject, l.detail]), [
      ["~/ws/.env", "Becomes Any AI, when it asks, which lets more reach an AI or leave this computer than now."],
      ["~/ws/deep", "Becomes Any AI, when it asks, which lets more reach an AI or leave this computer than now. This covers everything inside it that has no rule of its own."],
      ["~/ws/db-link", "Becomes Not secret, even where Mandu treats a file as secret by default (a .env file or a key, for example)."],
      ["~/ws/config/db.yaml", "Becomes Not secret, even where Mandu treats a file as secret by default (a .env file or a key, for example)."],
      ["~/ws/deep/k.pem", "Becomes Any AI, when it asks."],
      ["~/ws/deep/a", "Becomes Any AI, when it asks, and so does everything inside it that has no rule of its own."],
    ]);
    assert.deepEqual(h.proposed, [], "asking changes nothing");
    assert.deepEqual(h.pageActs, []);

    const ok = await post(h, { ...body, expected: ask.body.expected });
    assert.equal(ok.status, 200);
    assert.deepEqual(ok.body, { applied: true, changeId: "pc-000002", page: 2 });
    assert.deepEqual(h.proposed, [[
      { op: "lock-path", path: join(WS, ".env"), level: "any-model" },
      { op: "lock-path", path: join(WS, "deep"), level: "any-model" },
      { op: "lock-path", path: join(WS, "db-link"), level: "public" },
      { op: "lock-path", path: join(WS, "config", "db.yaml"), level: "public", recursive: false },
    ]], "the rules keep their reach: no recursive: false added on a file (a link's target gets its own, as before)");
    assert.deepEqual(h.pageActs, [`set ${join(WS, "deep", "k.pem")} any-model`, `set ${join(WS, "deep", "a")} any-model`]);
  } finally { await h.close(); }
});

test("Save: an invalid body is refused before anything is asked; the global gate guards it", async () => {
  const h = await start();
  try {
    for (const body of [{}, { changes: [] }, { changes: [{ path: "ws", level: "no-model" }] }, { changes: [{ path: "/a", level: "secret" }] }, { changes: [{ path: "/a", level: "no-model" }], expected: "x" }]) {
      assert.equal((await post(h, body)).status, 400, JSON.stringify(body));
    }
    assert.deepEqual(h.proposed, []);
    assert.equal((await post(h, { changes: [{ path: "/a", level: "no-model" }] }, {})).status, 403, "no CSRF header");
    assert.equal((await post(h, { changes: [{ path: "/a", level: "no-model" }] }, { "X-Mandu-Control": "1" })).status, 403, "no admin session");
    assert.deepEqual(h.proposed, []);
  } finally { await h.close(); }
});

test("Save: a rule chosen for a symlink is written on the file it points to as well; removing it is not", async () => {
  const h = await start();
  try {
    const r = await post(h, { changes: [{ path: "~/ws/db-link", level: "no-model", recursive: false }] });
    assert.equal(r.status, 200);
    assert.deepEqual(h.proposed, [[
      { op: "lock-path", path: join(WS, "db-link"), level: "no-model", recursive: false },
      { op: "lock-path", path: join(WS, "config", "db.yaml"), level: "no-model", recursive: false },
    ]]);
    const dir = await post(h, { changes: [{ path: "~/ws/conf-link", level: "no-model", recursive: true }] });
    assert.equal(dir.status, 200);
    assert.deepEqual(h.proposed[1], [
      { op: "lock-path", path: join(WS, "conf-link"), level: "no-model" },
      { op: "lock-path", path: join(WS, "config"), level: "no-model" },
    ], "a link to a folder: the folder, and everything inside it");
    await post(h, { changes: [{ path: "~/ws/db-link", level: null }], expected: [`paths\u0000${join(WS, "db-link")}`] });
    assert.deepEqual(h.proposed.at(-1), [{ op: "unlock-path", path: join(WS, "db-link") }], "removing leaves the target's rule (the safe direction)");
  } finally { await h.close(); }
});

test("impact: every file under a changed folder is compared now and after, the weaker ones first; a pattern's files are counted under the folder shown", async () => {
  const h = await start();
  try {
    const r = await fetch(`${h.base}/api/files/impact`, { method: "POST", headers: { ...CSRF_ADMIN, "Content-Type": "application/json" },
      body: JSON.stringify({ changes: [{ path: "~/ws/deep", level: "public", recursive: true }, { path: "**/*.pem", level: "no-model" }], folder: "~/ws/deep" }) });
    assert.equal(r.status, 200);
    const { impact, page } = (await r.json()) as any;
    assert.equal(page, 0);
    assert.equal(impact.scanned, 3, "the three files under ~/ws/deep, names only");
    assert.equal(impact.truncated, false);
    assert.equal(impact.weaker, 1);
    // The words, and the same words as parts (each host a code, §4.25u; none here).
    assert.deepEqual(impact.files[0], {
      path: join(WS, "deep", "a", "b", ".env"), display: "~/ws/deep/a/b/.env", before: "No AI", after: "Not secret",
      beforeParts: [{ kind: "text", text: "No AI" }], afterParts: [{ kind: "text", text: "Not secret" }], weaker: true,
    });
    assert.ok(impact.decidedBy[join(WS, "deep")].count >= 2);
    assert.equal(impact.decidedBy["**/*.pem"], undefined, "under the folder rule, the closer folder rule decides, not the pattern");
    assert.ok(h.calls.some((c) => c.endsWith("withEdits")), "asked under the proposed law");
    assert.equal(h.proposed.length, 0, "a preview writes nothing");
    // A pattern on its own: counted under the folder shown.
    const alone = await fetch(`${h.base}/api/files/impact`, { method: "POST", headers: { ...CSRF_ADMIN, "Content-Type": "application/json" },
      body: JSON.stringify({ changes: [{ path: "**/*.pem", level: "no-model" }], folder: "~/ws/deep" }) });
    assert.deepEqual(((await alone.json()) as any).impact.decidedBy["**/*.pem"], { count: 1, sample: ["~/ws/deep/k.pem"] });
    const bad = await fetch(`${h.base}/api/files/impact`, { method: "POST", headers: { ...CSRF_ADMIN, "Content-Type": "application/json" }, body: JSON.stringify({ changes: [] }) });
    assert.equal(bad.status, 400);
    const noGate = await fetch(`${h.base}/api/files/impact`, { method: "POST", headers: { "X-Mandu-Control": "1", "Content-Type": "application/json" }, body: JSON.stringify({ changes: [{ path: "/a", level: "public" }] }) });
    assert.equal(noGate.status, 403, "behind the admin session");
  } finally { await h.close(); }
});

test("impact: the scan stops at its limit and says so", async () => {
  const many = join(HOME, "many");
  mkdirSync(many);
  for (let i = 0; i < SCAN_MAX + 5; i++) writeFileSync(join(many, `f${i}`), "");
  const h = await start();
  try {
    const r = await fetch(`${h.base}/api/files/impact`, { method: "POST", headers: { ...CSRF_ADMIN, "Content-Type": "application/json" },
      body: JSON.stringify({ changes: [{ path: many, level: "no-model", recursive: true }] }) });
    const { impact } = (await r.json()) as any;
    assert.equal(impact.scanned, SCAN_MAX);
    assert.equal(impact.truncated, true);
  } finally { await h.close(); rmSync(many, { recursive: true, force: true }); }
});

test("Save: the question names the files a weaker change reaches (a folder made Not secret covers the built-in secrets inside it)", async () => {
  const h = await start();
  try {
    const ask = await post(h, { changes: [{ path: "~/ws/deep", level: "public", recursive: true }], folder: "~/ws" });
    assert.equal(ask.body.confirm, true);
    assert.equal(ask.body.impact.weaker, 1);
    assert.equal(ask.body.impact.files[0].display, "~/ws/deep/a/b/.env");
  } finally { await h.close(); }
});

test("why: the rules' view of one file in the page's words, behind the same gate as the listing", async () => {
  const h = await start();
  try {
    const url = `${h.base}/api/files/why?path=${encodeURIComponent("~/ws/.env")}`;
    assert.equal((await fetch(url, { headers: { "X-Mandu-Control": "1" } })).status, 403);
    const r = await fetch(url, { headers: CSRF_ADMIN });
    assert.equal(r.status, 200);
    const { why } = (await r.json()) as any;
    assert.equal(why.display, "~/ws/.env");
    assert.equal(why.off, false);
    const text = why.lines.map((l: any) => `${l.term}: ${l.text}`);
    assert.deepEqual(text, [
      "Where the label comes from: Built in: environment files",
      "Programs that get the real file: ssh-add, ssh (only when git starts it)",
      "What the AI sees of their output: Masked as a whole, for every program above.",
      "Any other program: Gets a masked copy.",
      "The masked copy: Keeps the file's shape and names; each secret value Mandu recognizes is hidden (2 now).",
      "May be sent to: Nowhere without your OK.",
      "Your answer: node: allowed once",
      "Programs that read the real file: node (2026-09-28 10:02 UTC)",
      "Also matches: **/.env* (Any AI, when it asks), but a closer rule decides here.",
    ]);
    assert.ok(h.calls.includes(`whyPath ${join(WS, ".env")}`));
    assert.equal((await fetch(`${h.base}/api/files/why?path=${encodeURIComponent("**/*.pem")}`, { headers: CSRF_ADMIN })).status, 400);
  } finally { await h.close(); }
});

test("move: the page's older rules move through the admin surface, behind the global gate", async () => {
  const h = await start();
  try {
    const no = await fetch(`${h.base}/api/files/move-page-rules`, { method: "POST", headers: { "X-Mandu-Control": "1" } });
    assert.equal(no.status, 403);
    const r = await fetch(`${h.base}/api/files/move-page-rules`, { method: "POST", headers: CSRF_ADMIN });
    assert.equal(r.status, 200);
    assert.deepEqual(await r.json(), { moved: 1, changeId: "pc-000005" });
    assert.ok(h.calls.includes("movePageLabels human:rules-page"));
  } finally { await h.close(); }
});

test("move: refused because policy.yaml changed on disk, or a hand edit waiting in Approvals changes the same rule -> 409 with the arbiter's words; anything else -> 502", async () => {
  // StalePolicyError's two texts (arbiter policy-document-store.ts; policy-surface.md §8.4.6).
  const held = "policy file /x/policy.yaml holds a change made on disk that waits for a human in Approvals, and this change cannot be made to it as well (that change changes the same rule: paths /home/u/notes); nothing was written. Decide that change first, then try again.";
  const stale = "policy file /x/policy.yaml changed on disk since it was last loaded; the change on disk was loaded (or, if it relaxes the law, is waiting in Approvals) and nothing was written. Re-read the law and try again.";
  for (const [refusal, status] of [[held, 409], [stale, 409], ["connection closed", 502]] as const) {
    const h = await start({ moveRefusal: refusal });
    try {
      const r = await fetch(`${h.base}/api/files/move-page-rules`, { method: "POST", headers: CSRF_ADMIN });
      assert.equal(r.status, status, refusal);
      assert.equal(((await r.json()) as { error: string }).error, refusal);
    } finally { await h.close(); }
  }
});

// ── a Save names the rules as they were read (policy-surface.md §8.4.6) ──

test("each entry carries its path's own rule's version: config its rule's, a path with none the absent version; an older service none", async () => {
  const h = await start();
  try {
    const b = (await get(h, "~/ws")).body;
    const at = (name: string) => b.entries.find((e: any) => e.name === name);
    assert.equal(at("config").version, V_CONFIG);
    assert.equal(at(".env").version, ABSENT, "a built-in secret is no rule of the file's");
    assert.ok(h.calls.indexOf("policyDocument") < h.calls.findIndex((c) => c.startsWith("pathLevels")), "the versions are read before the labels");
  } finally { await h.close(); }
  const old = await start({ noVersions: true });
  try {
    assert.deepEqual((await get(old, "~/ws")).body.entries.map((e: any) => e.version).filter((v: unknown) => v !== null), []);
  } finally { await old.close(); }
});

test("Save names each policy.yaml rule it rewrites: the page's version, else this route's own read; a symlink's target its own rule, never the link's", async () => {
  const h = await start();
  try {
    const r = await post(h, { changes: [
      { path: "~/ws/config", level: "no-model", recursive: true, version: V_CONFIG },
      { path: "~/ws/big", level: "no-model", recursive: true },
      { path: "~/ws/db-link", level: "no-model", recursive: false, version: ABSENT },
    ] });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(h.based[0], [
      { section: "paths", key: join(WS, "config"), version: V_CONFIG },
      { section: "paths", key: join(WS, "big"), version: ABSENT },
      { section: "paths", key: join(WS, "db-link"), version: ABSENT },
      { section: "paths", key: join(WS, "config", "db.yaml"), version: ABSENT },
    ]);
    // A pattern is named as the arbiter keys it.
    await post(h, { changes: [{ path: "**/*.pem", level: "no-model", version: "e".repeat(32) }] });
    assert.deepEqual(h.based[1], [{ section: "paths", key: "glob:**/*.pem", version: "e".repeat(32) }]);
    // A version that is not one is refused before anything is asked.
    assert.equal((await post(h, { changes: [{ path: "~/ws/config", level: "no-model", version: "x" }] })).status, 400);
  } finally { await h.close(); }
});

test("a rule changed since the page read it: 409 stale in the page's words, before anything is asked or written", async () => {
  const h = await start();
  try {
    h.versions.set(join(WS, "config"), "d".repeat(32)); // someone else changed config's rule
    const r = await post(h, { changes: [
      { path: "~/ws/config", level: "public", recursive: true, version: V_CONFIG },
      { path: "~/ws/README.md", level: "public" },
    ] });
    assert.equal(r.status, 409);
    assert.equal(r.body.stale, true);
    assert.deepEqual(r.body.changed, [`paths ${join(WS, "config")}`]);
    assert.equal(r.body.error, "~/ws/config was changed somewhere else while you were choosing, so nothing was saved. Your choice still waits in Changes to save: look at the label as it is now, then save again.");
    assert.ok(!h.calls.includes("policyPreview"), "nothing previewed");
    assert.deepEqual(h.proposed, [], "nothing proposed");
    assert.deepEqual(h.pageActs, [], "the page's own store is not touched either");
  } finally { await h.close(); }
});

test("a rule changed between this read and the write: the arbiter refuses it, 409 stale, nothing approved and no page-store change", async () => {
  const h = await start({ staleAtPropose: true });
  try {
    const body = { changes: [{ path: "~/ws/config", level: "public", recursive: true, version: V_CONFIG }, { path: "~/ws/README.md", level: "public" }] };
    const ask = await post(h, body);
    assert.equal(ask.body.confirm, true, JSON.stringify(ask.body));
    const r = await post(h, { ...body, expected: ask.body.expected });
    assert.equal(r.status, 409, JSON.stringify(r.body));
    assert.equal(r.body.stale, true);
    assert.match(r.body.error, /^~\/ws\/config was changed somewhere else/);
    assert.deepEqual(h.resolved, [], "nothing approved");
    assert.deepEqual(h.pageActs, [], "the page-store change after it is not made");
  } finally { await h.close(); }
});

test("an arbiter that answers no versions is sent no change that names one (501); a change naming none goes as before", async () => {
  const h = await start({ noVersions: true });
  try {
    assert.equal((await post(h, { changes: [{ path: "~/ws/config", level: "no-model", recursive: true, version: V_CONFIG }] })).status, 501);
    assert.deepEqual(h.proposed, []);
    const r = await post(h, { changes: [{ path: "~/ws/big", level: "no-model", recursive: true }] });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(h.based, [undefined], "no basedOn to an arbiter that could not check it");
  } finally { await h.close(); }
});
