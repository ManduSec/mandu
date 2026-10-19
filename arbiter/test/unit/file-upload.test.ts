/**
 * file-upload — the local-file UPLOAD gate (policy/file-upload.ts, the
 * `fileUploadDecision` op; supported-agents.md §2, "Claude Code 2.1.292").
 *
 * Claude Code's DesignSync `write_files{files[].localPath}` uploads a local
 * file's bytes to claude.ai without the model reading them, so no symbol is
 * ever minted for them: the path is judged. Pinned here:
 *   - the pure decision, one probe per rule, each with its catalog ruleRef;
 *   - the op over the real server: a catalog secret (`.env`), a copy of one
 *     of its registered values under an ordinary name, a symlink to it, an
 *     ordinary file, a missing file and an oversize one; the human-plane ask
 *     queues an Approvals row `fs:DesignSync:upload` × path and a human
 *     verdict decides the next ask; the data socket never reads a file.
 *
 * Axes: `secrets` (confidentiality ON, integrity OFF), plus one OFF probe.
 */
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { decideFileUpload, type FileUploadFacts } from "../../policy/file-upload.js";
import { RULES, type RuleRef } from "../../policy/rule-ref.js";
import { ArbiterServer, FILE_UPLOAD_MAX_BYTES, FILE_UPLOAD_SCAN_CHUNK_BYTES, type IpcChannel } from "../../ipc/server.js";
import type { ArbiterRequest } from "../../ipc/protocol.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const HOME = "/home/u";
const REQ = { tool: "DesignSync", path: "/ws/design/button.html", destination: "claude.ai" };
const CLEAN: FileUploadFacts = { attested: true, axis: true, paths: ["/ws/design/button.html"], labels: [], content: { kind: "read", hits: [] }, home: HOME };

function cataloged(ref: RuleRef | undefined, id: keyof typeof RULES): void {
  assert.ok(ref, `a ruleRef (expected ${id})`);
  assert.equal(ref.id, id);
  assert.equal(ref.source, RULES[id].source);
}

// ── the pure decision ───────────────────────────────────────────────────────

test("decideFileUpload: every rule, in order, with its catalog ruleRef", () => {
  const d = (req: Partial<typeof REQ>, facts: Partial<FileUploadFacts> = {}) => decideFileUpload({ ...REQ, ...req }, { ...CLEAN, ...facts });
  // 1. no absolute path: never guess which file leaves
  for (const path of ["", "  ", "design/button.html"]) {
    const r = d({ path });
    assert.equal(r.allow, false);
    assert.equal(r.allow === false && r.requiresApproval, true);
    cataloged(r.ruleRef, "fs:upload-invalid-path");
  }
  // 2. the data socket: refused outright, never queued
  const un = d({}, { attested: false, content: null });
  assert.equal(un.allow === false && un.requiresApproval, false);
  cataloged(un.ruleRef, "fs:upload-unattested");
  // 3. a built-in sensitive path, by either spelling, axis or not
  cataloged(d({ path: "~/.ssh/id_ed25519" }, { paths: ["/home/u/.ssh/id_ed25519"] }).ruleRef, "fs:sensitive-path");
  cataloged(d({}, { paths: ["/ws/design/key.pem", "/home/u/.aws/credentials"] }).ruleRef, "fs:sensitive-path");
  cataloged(d({ path: "/home/u/.claude.json" }, { axis: false, paths: ["/home/u/.claude.json"] }).ruleRef, "fs:sensitive-path");
  // 4. the axis off: nothing else is labelled
  const off = d({}, { axis: false, content: null });
  assert.equal(off.allow, true);
  cataloged(off.ruleRef, "fs:upload-clean");
  // 5. a secret label not bound to the destination
  const secret = d({}, { labels: [{ path: REQ.path, level: "no-model", bindings: ["api.stripe.com"], rule: "catalog:dotenv" }] });
  assert.equal(secret.allow === false && secret.requiresApproval, true);
  cataloged(secret.ruleRef, "fs:upload-secret-file");
  assert.match(secret.reason, /no rule lets it go to claude\.ai/);
  // a public label says nothing
  cataloged(d({}, { labels: [{ path: REQ.path, level: "public", bindings: [], rule: null }] }).ruleRef, "fs:upload-clean");
  // 6. unread bytes are unchecked bytes
  for (const content of [null, { kind: "unreadable" as const, why: "ENOENT" }]) {
    const r = d({}, { content });
    assert.equal(r.allow === false && r.requiresApproval, true);
    cataloged(r.ruleRef, "fs:upload-unreadable");
  }
  // 7. a registered value in the bytes, not bound here
  cataloged(d({}, { content: { kind: "read", hits: [{ level: "any-model", bindings: [] }] } }).ruleRef, "fs:upload-secret-value");
  // 8. bound everywhere: allowed (a subdomain of a bound host too)
  const bound = d({ destination: "design.claude.ai" }, {
    labels: [{ path: REQ.path, level: "no-model", bindings: ["claude.ai"], rule: "label:/ws/design" }],
    content: { kind: "read", hits: [{ level: "no-model", bindings: ["claude.ai"] }] },
  });
  assert.equal(bound.allow, true);
  cataloged(bound.ruleRef, "fs:upload-bound");
  // ...but one unbound value in a bound file still holds it
  cataloged(d({}, {
    labels: [{ path: REQ.path, level: "no-model", bindings: ["claude.ai"], rule: "label:/ws/design" }],
    content: { kind: "read", hits: [{ level: "no-model", bindings: ["claude.ai"] }, { level: "no-model", bindings: [] }] },
  }).ruleRef, "fs:upload-secret-value");
  // an ordinary file: allowed
  cataloged(d({}).ruleRef, "fs:upload-clean");
  // a look-alike host is not a bound one (the label-boundary rule)
  cataloged(d({ destination: "evilclaude.ai" }, { labels: [{ path: REQ.path, level: "no-model", bindings: ["claude.ai"], rule: null }] }).ruleRef, "fs:upload-secret-file");
});

test("decideFileUpload DESTINATIONS (2026-10-17): a binding must name every host the bytes may reach", () => {
  const facts = (bindings: string[]): FileUploadFacts => ({
    ...CLEAN, labels: [{ path: REQ.path, level: "no-model", bindings, rule: "label:/ws/design" }],
  });
  const both = { ...REQ, destinations: ["api.anthropic.com"] };
  // bound to the service alone: held (before, `claude.ai` released it while the bytes went to api.anthropic.com)
  const svc = decideFileUpload(both, facts(["claude.ai"]));
  cataloged(svc.ruleRef, "fs:upload-secret-file");
  assert.match(svc.reason, /claude\.ai and api\.anthropic\.com/);
  // bound to the API host alone (the agent key's own host): held too
  cataloged(decideFileUpload(both, facts(["api.anthropic.com"])).ruleRef, "fs:upload-secret-file");
  // bound to each: released
  cataloged(decideFileUpload(both, facts(["claude.ai", "anthropic.com"])).ruleRef, "fs:upload-bound");
  // the same for a value in the bytes
  cataloged(decideFileUpload(both, { ...CLEAN, content: { kind: "read", hits: [{ level: "no-model", bindings: ["claude.ai"] }] } }).ruleRef, "fs:upload-secret-value");
  // no host at all (the unmapped form): nothing is ever bound
  cataloged(decideFileUpload({ ...REQ, destination: "", destinations: [] }, facts(["claude.ai"])).ruleRef, "fs:upload-secret-file");
});

test("decideFileUpload TO A MODEL (2026-10-17): `any-model` admits it, `local-model` and `no-model` are held; a chat attachment (no host) admits nothing", () => {
  const MSG = { tool: "view_image", path: "/ws/shots/a.png", destination: "" };
  const label = (level: "any-model" | "local-model" | "no-model"): FileUploadFacts => ({
    ...CLEAN, paths: [MSG.path], labels: [{ path: MSG.path, level, bindings: [], rule: "label:/ws/shots" }],
  });
  const value = (level: "any-model" | "local-model" | "no-model"): FileUploadFacts => ({
    ...CLEAN, paths: [MSG.path], content: { kind: "read", hits: [{ level, bindings: [] }] },
  });
  // to a model: the level that admits every model goes, the others are held
  const any = decideFileUpload({ ...MSG, toModel: true }, label("any-model"));
  assert.equal(any.allow, true);
  cataloged(any.ruleRef, "fs:upload-bound");
  assert.match(any.reason, /admits any model/);
  cataloged(decideFileUpload({ ...MSG, toModel: true }, value("any-model")).ruleRef, "fs:upload-bound");
  for (const level of ["local-model", "no-model"] as const) {
    const held = decideFileUpload({ ...MSG, toModel: true }, label(level));
    assert.equal(held.allow === false && held.requiresApproval, true, level);
    cataloged(held.ruleRef, "fs:upload-secret-file");
    assert.match(held.reason, /a model Mandu cannot name/);
    cataloged(decideFileUpload({ ...MSG, toModel: true }, value(level)).ruleRef, "fs:upload-secret-value");
  }
  // not to a model (a chat attachment, no host): even `any-model` is held,
  // since it may reach no network destination
  for (const level of ["any-model", "local-model", "no-model"] as const) {
    cataloged(decideFileUpload({ ...MSG, tool: "message" }, label(level)).ruleRef, "fs:upload-secret-file");
    cataloged(decideFileUpload({ ...MSG, tool: "message" }, value(level)).ruleRef, "fs:upload-secret-value");
  }
  // a clean file goes either way; an unreadable one is held either way
  assert.equal(decideFileUpload({ ...MSG, toModel: true }, { ...CLEAN, paths: [MSG.path] }).allow, true);
  cataloged(decideFileUpload({ ...MSG, toModel: true }, { ...CLEAN, paths: [MSG.path], content: { kind: "unreadable", why: "ENOENT" } }).ruleRef, "fs:upload-unreadable");
});

test("decideFileUpload: a file of a process or of the kernel is held, in both forms (the arbiter would read its own)", () => {
  for (const path of ["/proc/self/environ", "/proc/1234/cmdline", "/sys/kernel/x", "/dev/fd/3", "/dev/stdin"]) {
    for (const unmapped of [false, true]) {
      const r = decideFileUpload({ ...REQ, path, unmapped }, { ...CLEAN, paths: [path], presence: "file" });
      assert.equal(r.allow === false && r.requiresApproval, true, path);
      cataloged(r.ruleRef, "fs:upload-process-file");
    }
  }
  // a symlink into /proc is judged by its real path
  cataloged(decideFileUpload(REQ, { ...CLEAN, paths: [REQ.path, "/proc/self/environ"] }).ruleRef, "fs:upload-process-file");
});

test("decideFileUpload THE UNMAPPED FORM: a mapped or guard-confined tool is let be, nothing there and a plain folder pass, a secret is held", () => {
  const U = { tool: "mcp__drive__upload_file", path: "/ws/design/button.html", destination: "", unmapped: true };
  const d = (facts: Partial<FileUploadFacts>, req: Partial<typeof U> = {}) => decideFileUpload({ ...U, ...req }, { ...CLEAN, ...facts });
  // rule 0
  for (const mapping of ["spec", "harness", "surface", "own", "builtin"]) cataloged(d({ mapping, content: null }).ruleRef, "fs:upload-mapped-tool");
  cataloged(d({ mapping: "mcp-config", confinedServer: true, content: null }).ruleRef, "fs:upload-confined-server");
  // a policy.yaml mapping and an unguarded registered server keep the input rules
  for (const mapping of ["policy", "mcp-config", null]) {
    cataloged(d({ mapping, labels: [{ path: U.path, level: "no-model", bindings: ["claude.ai"], rule: "registry" }] }).ruleRef, "fs:upload-secret-file");
  }
  // rule 4a: nothing there, no stored bytes
  cataloged(d({ presence: "missing", content: { kind: "unreadable", why: "ENOENT" } }).ruleRef, "fs:upload-no-file");
  cataloged(d({ presence: "special", content: { kind: "unreadable", why: "not a regular file" } }).ruleRef, "fs:upload-no-file");
  // ...but not in the mapped form: a missing upload is unchecked bytes
  cataloged(d({ presence: "missing", content: { kind: "unreadable", why: "ENOENT" } }, { unmapped: undefined as unknown as true }).ruleRef, "fs:upload-unreadable");
  // rule 5a: a folder passes unless it is labelled or sensitive
  cataloged(d({ presence: "directory", content: { kind: "unreadable", why: "not a regular file" } }).ruleRef, "fs:upload-folder");
  cataloged(d({ presence: "directory", content: null, labels: [{ path: U.path, level: "local-model", bindings: [], rule: "label:/ws" }] }).ruleRef, "fs:upload-secret-file");
  cataloged(d({ presence: "directory", content: null, paths: ["/home/u/.ssh"] }, { path: "~/.ssh" }).ruleRef, "fs:sensitive-path");
  // a file: labels and values as in the mapped form, with no host
  cataloged(d({ presence: "file", content: { kind: "read", hits: [{ level: "any-model", bindings: ["claude.ai"] }] } }).ruleRef, "fs:upload-secret-value");
  cataloged(d({ presence: "file", content: { kind: "unreadable", why: "larger than 8 MiB" } }).ruleRef, "fs:upload-unreadable");
  cataloged(d({ presence: "file" }).ruleRef, "fs:upload-clean");
  // the data socket still answers first (rule 2), whatever the mapping says is not read there
  cataloged(d({ attested: false, content: null }).ruleRef, "fs:upload-unattested");
});

// ── the op over the real server ─────────────────────────────────────────────

const STRIPE = "sk_live_fake_UPLOADGATE_0123456789abcdef";

function server(confidentiality: boolean): { s: ArbiterServer; dir: string; ws: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-upload-gate-"));
  const ws = join(dir, "ws");
  mkdirSync(join(ws, "design"), { recursive: true });
  writeFileSync(join(ws, ".env"), `STRIPE_KEY=${STRIPE}\nDEBUG=1\n`);
  writeFileSync(join(ws, "design", "button.html"), "<button class=primary>OK</button>\n");
  writeFileSync(join(ws, "design", "notes.txt"), `staging key for the demo: ${STRIPE}\n`);
  symlinkSync(join(ws, ".env"), join(ws, "design", "theme.css"));
  // past the bound, sparse: no disk, and the gate holds it on its size alone
  writeFileSync(join(ws, "design", "big.bin"), "");
  truncateSync(join(ws, "design", "big.bin"), FILE_UPLOAD_MAX_BYTES + 1);
  const s = new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"),
    dbPath: join(dir, "symbols.db"),
    eventDir: join(dir, "events"),
    log: () => {},
    confidentiality,
    integrity: false,
  });
  return { s, dir, ws, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

type Resp = { ok: boolean; result?: Record<string, unknown>; error?: string };
const call = (s: ArbiterServer, req: Record<string, unknown>, channel: IpcChannel): Resp =>
  s.dispatch({ id: "t", ...req } as ArbiterRequest, { channel }) as Resp;
/** The op is asynchronous (the file is scanned in chunks): awaited in process. */
const askOp = async (s: ArbiterServer, request: Record<string, unknown>, channel: IpcChannel): Promise<Resp> =>
  await s.fileUploadDecisionOp({ id: "t", op: "fileUploadDecision", request } as never, { channel }) as Resp;
const ask = async (s: ArbiterServer, path: string, channel: IpcChannel = "human"): Promise<Record<string, unknown>> => {
  const r = await askOp(s, { tool: "DesignSync", path, destination: "claude.ai", sessionKey: "up-1" }, channel);
  assert.equal(r.ok, true, r.error);
  return r.result!;
};
const idOf = (r: Record<string, unknown>): string | undefined => (r["ruleRef"] as RuleRef | undefined)?.id;

test("the op: a secret file, a copy of its value, a symlink to it, a missing and an oversize file are held; an ordinary file goes", async () => {
  const { s, ws, cleanup } = server(true);
  try {
    const reg = call(s, { op: "registerSecret", path: join(ws, ".env") }, "admin");
    assert.equal(reg.ok, true, reg.error);
    assert.ok((reg.result as { symbol: string | null }).symbol, "the .env registered");

    const env = await ask(s, join(ws, ".env"));
    assert.equal(env["allow"], false);
    assert.equal(env["requiresApproval"], true);
    assert.equal(idOf(env), "fs:upload-secret-file");
    assert.match(String(env["approvalId"]), /^egr-/, "an Approvals row was queued");

    const copy = await ask(s, join(ws, "design", "notes.txt"));
    assert.equal(idOf(copy), "fs:upload-secret-value", "a copy of a registered value under an ordinary name");
    assert.ok(!JSON.stringify(copy).includes(STRIPE), "the answer never carries the value");

    assert.equal(idOf(await ask(s, join(ws, "design", "theme.css"))), "fs:upload-secret-file", "a symlink is judged by its real path too");
    assert.equal(idOf(await ask(s, join(ws, "design", "missing.html"))), "fs:upload-unreadable");
    assert.equal(idOf(await ask(s, join(ws, "design", "big.bin"))), "fs:upload-unreadable");
    assert.equal(idOf(await ask(s, join(ws, "design"))), "fs:upload-unreadable", "a directory is not a regular file");

    const ok = await ask(s, join(ws, "design", "button.html"));
    assert.equal(ok["allow"], true);
    assert.equal(idOf(ok), "fs:upload-clean");

    // the queue: one row per path, keyed fs:DesignSync:upload
    const rows = (call(s, { op: "egressApprovals" }, "admin").result as unknown as { approvals: Array<{ symbol: string; destination: string; status: string; id: string }> }).approvals;
    const envRow = rows.find((r) => r.destination === join(ws, ".env"));
    assert.equal(envRow?.symbol, "fs:DesignSync:upload");
    assert.equal(envRow?.status, "pending");

    // a human Allow decides the next ask; a Deny holds without a new row
    assert.equal(call(s, { op: "resolveEgressApproval", approvalId: envRow!.id, approve: true }, "admin").ok, true);
    const allowed = await ask(s, join(ws, ".env"));
    assert.equal(allowed["allow"], true);
    assert.equal((allowed["ruleRef"] as RuleRef).source, "verdict");
    const copyRow = rows.find((r) => r.destination === join(ws, "design", "notes.txt"))!;
    assert.equal(call(s, { op: "resolveEgressApproval", approvalId: copyRow.id, approve: false }, "admin").ok, true);
    const denied = await ask(s, join(ws, "design", "notes.txt"));
    assert.equal(denied["allow"], false);
    assert.equal(denied["requiresApproval"], false);
  } finally {
    cleanup();
  }
});

test("the op, UNMAPPED form: an MCP tool's secret file and a copy of its value are held (one row each), nothing-there and a folder pass, a built-in the spec maps is let be, a registered server outside the guard is judged", async () => {
  const { s, ws, cleanup } = server(true);
  const askU = async (tool: string, path: string, channel: IpcChannel = "human"): Promise<Record<string, unknown>> => {
    const r = await askOp(s, { tool, path, destination: "", unmapped: true, sessionKey: "up-2" }, channel);
    assert.equal(r.ok, true, r.error);
    return r.result!;
  };
  try {
    assert.equal(call(s, { op: "registerSecret", path: join(ws, ".env") }, "admin").ok, true);
    const tool = "mcp__drive__upload_file";
    const env = await askU(tool, join(ws, ".env"));
    assert.equal(env["allow"], false);
    assert.equal(idOf(env), "fs:upload-secret-file");
    assert.match(String(env["reason"]), /an unnamed destination/);
    assert.equal(idOf(await askU(tool, join(ws, "design", "notes.txt"))), "fs:upload-secret-value");
    assert.equal(idOf(await askU(tool, join(ws, "design", "theme.css"))), "fs:upload-secret-file", "a symlink by its real path");
    assert.equal(idOf(await askU(tool, join(ws, "design", "missing.html"))), "fs:upload-no-file");
    assert.equal(idOf(await askU(tool, "/v1/items")), "fs:upload-no-file", "a remote API's path names nothing here");
    assert.equal(idOf(await askU(tool, join(ws, "design"))), "fs:upload-folder");
    assert.equal(idOf(await askU(tool, join(ws, "design", "big.bin"))), "fs:upload-unreadable");
    assert.equal(idOf(await askU(tool, join(ws, "design", "button.html"))), "fs:upload-clean");
    assert.equal(idOf(await askU(tool, "/proc/self/environ")), "fs:upload-process-file");
    // a built-in the session's spec maps keeps its own legs: let be
    assert.equal(idOf(await askU("TodoWrite", join(ws, ".env"))), "fs:upload-mapped-tool");
    // a registered local MCP server, in a session no confined launch guards: judged
    assert.equal(call(s, { op: "registerMcpServers", sessionKey: "up-2", servers: [{ name: "fs", command: "node", args: ["fs-server.js"] }] }, "human").ok, true);
    assert.equal(idOf(await askU("mcp__fs__read_file", join(ws, ".env"))), "fs:upload-secret-file");
    // the queue: one row per held path, keyed by the tool
    const rows = (call(s, { op: "egressApprovals" }, "admin").result as unknown as { approvals: Array<{ symbol: string; destination: string }> }).approvals;
    assert.ok(rows.some((r) => r.symbol === `fs:${tool}:upload` && r.destination === join(ws, ".env")));
    assert.ok(!rows.some((r) => r.destination === join(ws, "design", "missing.html")), "nothing queued for a path that names nothing");
    // the data socket: refused, nothing read, the mapping not even asked
    assert.equal(idOf(await askU("TodoWrite", join(ws, ".env"), "data")), "fs:upload-unattested");
  } finally {
    cleanup();
  }
});

test("the op on the DATA socket never reads a file, consults no verdict and queues nothing", async () => {
  const { s, ws, cleanup } = server(true);
  try {
    const r = await ask(s, join(ws, "design", "button.html"), "data");
    assert.equal(r["allow"], false);
    assert.equal(r["requiresApproval"], false);
    assert.equal(idOf(r), "fs:upload-unattested");
    const q = call(s, { op: "egressApprovals" }, "admin").result as unknown;
    assert.ok(!JSON.stringify(q).includes("fs:DesignSync:upload"), "no row");
  } finally {
    cleanup();
  }
});

test("the op with the confidentiality axis OFF: only the sensitive list holds", async () => {
  const { s, ws, cleanup } = server(false);
  try {
    assert.equal((await ask(s, join(ws, ".env")))["allow"], true);
    assert.equal(idOf(await ask(s, `${process.env["HOME"] ?? "/root"}/.ssh/id_rsa`)), "fs:sensitive-path");
  } finally {
    cleanup();
  }
});

// ── STREAMED (2026-10-17): path first, then the bytes in chunks ─────────────

test("STREAMED: a 20 MiB file with no registered value goes; with one across a read boundary it is held; past the bound and unreadable stay held", async () => {
  const { s, ws, cleanup } = server(true);
  try {
    assert.equal(call(s, { op: "registerSecret", path: join(ws, ".env") }, "admin").ok, true);
    const MiB = 1024 * 1024;
    assert.ok(20 * MiB > 8 * MiB && 20 * MiB < FILE_UPLOAD_MAX_BYTES, "between the old read limit and the bound");
    // binary noise, as a photo or a video is: held at the old 8 MiB limit
    const noise = Buffer.alloc(20 * MiB);
    for (let i = 0; i < noise.length; i += 4) noise.writeUInt32LE((Math.imul(i, 2654435761) ^ (i >>> 7)) >>> 0, i);
    writeFileSync(join(ws, "design", "clip.mp4"), noise);
    const clean = await ask(s, join(ws, "design", "clip.mp4"));
    assert.equal(clean["allow"], true, String(clean["reason"]));
    assert.equal(idOf(clean), "fs:upload-clean");
    // the registered value straddles the first 1 MiB read
    const withKey = Buffer.from(noise);
    Buffer.from(STRIPE).copy(withKey, FILE_UPLOAD_SCAN_CHUNK_BYTES - 7);
    writeFileSync(join(ws, "design", "deck.pdf"), withKey);
    const held = await ask(s, join(ws, "design", "deck.pdf"));
    assert.equal(held["allow"], false);
    assert.equal(held["requiresApproval"], true);
    assert.equal(idOf(held), "fs:upload-secret-value");
    assert.match(String(held["approvalId"]), /^egr-/);
    assert.ok(!JSON.stringify(held).includes(STRIPE), "the answer never carries the value");
    // past the bound (sparse): held, its size named
    const big = await ask(s, join(ws, "design", "big.bin"));
    assert.equal(idOf(big), "fs:upload-unreadable");
    assert.match(String(big["reason"]), new RegExp(`larger than ${FILE_UPLOAD_MAX_BYTES} bytes`));
    // a FIFO in the mapped form: not a regular file, and the read never blocks
    let haveFifo = true;
    try { execFileSync("mkfifo", [join(ws, "design", "pipe")]); } catch { haveFifo = false; }
    if (haveFifo) assert.equal(idOf(await ask(s, join(ws, "design", "pipe"))), "fs:upload-unreadable");
  } finally {
    cleanup();
  }
});

test("STREAMED: the path decides first: a secret path, a sensitive path, a folder or nothing-there is never opened; an ordinary file is scanned once", async () => {
  const { s, ws, cleanup } = server(true);
  // count the byte scans (the server's private step, wrapped in place)
  const srv = s as unknown as { fileUploadContent: (p: string) => Promise<unknown> };
  const scanned: string[] = [];
  const real = srv.fileUploadContent.bind(s);
  srv.fileUploadContent = (p: string) => { scanned.push(p); return real(p); };
  const askU = async (tool: string, path: string): Promise<Record<string, unknown>> => {
    const r = await askOp(s, { tool, path, destination: "", unmapped: true, sessionKey: "up-3" }, "human");
    assert.equal(r.ok, true, r.error);
    return r.result!;
  };
  try {
    assert.equal(call(s, { op: "registerSecret", path: join(ws, ".env") }, "admin").ok, true);
    assert.equal(idOf(await ask(s, join(ws, ".env"))), "fs:upload-secret-file");
    assert.equal(idOf(await ask(s, join(ws, "design", "theme.css"))), "fs:upload-secret-file", "a symlink to it, by its real path");
    assert.equal(idOf(await ask(s, `${process.env["HOME"] ?? "/root"}/.ssh/id_rsa`)), "fs:sensitive-path");
    assert.equal(idOf(await askU("mcp__drive__upload", join(ws, "design"))), "fs:upload-folder");
    assert.equal(idOf(await askU("mcp__drive__upload", join(ws, "design", "missing.html"))), "fs:upload-no-file");
    assert.equal(idOf(await askU("TodoWrite", join(ws, "design", "button.html"))), "fs:upload-mapped-tool");
    assert.deepEqual(scanned, [], "no byte read for a path the path phase decides");
    assert.equal(idOf(await ask(s, join(ws, "design", "button.html"))), "fs:upload-clean");
    assert.deepEqual(scanned, [join(ws, "design", "button.html")]);
  } finally {
    cleanup();
  }
});
