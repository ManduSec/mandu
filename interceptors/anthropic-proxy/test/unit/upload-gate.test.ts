/**
 * upload-gate — Claude Code's DesignSync uploads local files by path, their
 * bytes never entering the model context (supported-agents.md §2, "Claude
 * Code 2.1.292"). The gate decision, pure and over a fake arbiter:
 *   - a plan must name an absolute `localDir` (else refused, with how);
 *   - every `localPath` is placed against the plans relayed and put to the
 *     arbiter's upload gate; one held file refuses the WHOLE call;
 *   - a relative path with no plan, an arbiter without the op, one that
 *     throws or does not answer, an unreadable input: refused (fail-closed);
 *   - the net legs run over every string the call sends (a symbol in inline
 *     `data`, a high session);
 *   - every other tool, and the read methods, pass.
 *
 * Axes: `secrets`, stated through the fake arbiter (the upload gate's
 * answers are the confidentiality axis's).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  gateUploadToolUse,
  placeLocalPath,
  planDir,
  stringsIn,
  uploadBlockNotice,
  UploadPlans,
  DESIGN_SYNC_HOST,
  UPLOAD_HOST,
  UPLOAD_HOSTS,
  UPLOAD_GATE_MAX_PATHS,
  artifactUploadTargets,
  type UploadGateOptions,
} from "../../src/upload-gate.js";
import { REFUSED_ID_PREFIX } from "../../src/dispatch.js";
import { CLAUDE_CODE_GATE_SURFACE, UNION_GATE_SURFACE } from "../../src/gate-surface.js";
import type { FileUploadDecision, FileUploadDecisionRequest } from "../../src/arbiter-client.js";

const SECRET = "/ws/app/.env";
const HELD: FileUploadDecision = {
  allow: false, requiresApproval: true,
  reason: "'/ws/app/.env' is a secret file (no-model) and no rule lets it go to claude.ai",
  ruleRef: { source: "rule", id: "fs:upload-secret-file" }, approvalId: "egr-7",
};

function fake(over: Partial<UploadGateOptions["arbiter"]> = {}, calls: FileUploadDecisionRequest[] = []): UploadGateOptions["arbiter"] {
  return {
    fileUploadDecision: async (req: FileUploadDecisionRequest) => {
      calls.push(req);
      return req.path === SECRET || req.path.endsWith("/secret-copy.txt") ? HELD : { allow: true, reason: "clean", ruleRef: { source: "rule", id: "fs:upload-clean" } };
    },
    ...over,
  } as UploadGateOptions["arbiter"];
}

function opts(arbiter = fake(), plans = new UploadPlans()): UploadGateOptions {
  return { uploadTools: CLAUDE_CODE_GATE_SURFACE.upload!, arbiter, sessionKey: "s1", plans, home: "/home/u" };
}

const refusedWith = (input: unknown): string => {
  const a = (input as { action?: unknown }).action;
  assert.equal(typeof a, "string", "the whole input is the refusal");
  assert.ok((a as string).startsWith(REFUSED_ID_PREFIX));
  assert.deepEqual(Object.keys(input as object), ["action"], "no method, no files: DesignSync's schema rejects it, nothing is sent");
  return a as string;
};

const plan = (localDir?: string) => ({ method: "finalize_plan", projectId: "p1", writes: ["components/**"], ...(localDir !== undefined ? { localDir } : {}) });
const write = (files: unknown[]) => ({ method: "write_files", projectId: "p1", planId: "plan-1", files });

// ── pure helpers ─────────────────────────────────────────────────────────────

test("planDir: only an absolute directory places a plan", () => {
  assert.equal(planDir("/ws/app/ds-bundle/"), "/ws/app/ds-bundle");
  assert.equal(planDir("/ws/app/./x/../ds"), "/ws/app/ds");
  for (const v of [undefined, "", "ds-bundle", "./ds", "~/ds", 7]) assert.equal(planDir(v), null, String(v));
});

test("placeLocalPath: absolute as is; relative against every plan; ~/ also as the home; none without a base", () => {
  assert.deepEqual(placeLocalPath("/ws/app/.env", [], "/home/u"), ["/ws/app/.env"]);
  assert.deepEqual(placeLocalPath("../.env", ["/ws/app/ds"], "/home/u"), ["/ws/app/.env"]);
  assert.deepEqual(placeLocalPath("a.html", ["/ws/a", "/ws/b"], "/home/u"), ["/ws/a/a.html", "/ws/b/a.html"]);
  assert.deepEqual(placeLocalPath("~/.aws/credentials", [], "/home/u"), ["/home/u/.aws/credentials"]);
  assert.equal(placeLocalPath("a.html", [], "/home/u"), null);
  assert.equal(placeLocalPath("  ", ["/ws"], "/home/u"), null);
});

test("stringsIn: every string at any depth", () => {
  assert.deepEqual(stringsIn({ a: "x", b: [1, "y", { c: "z" }], d: null }), ["x", "y", "z"]);
});

// ── the gate ─────────────────────────────────────────────────────────────────

test("not an upload tool: untouched, no outcome (Read, WebFetch, an MCP tool)", async () => {
  for (const name of ["Read", "WebFetch", "mcp__fs__upload"]) {
    const input = { file_path: SECRET };
    const r = await gateUploadToolUse(name, input, opts());
    assert.equal(r.input, input);
    assert.equal(r.outcome, undefined);
  }
});

test("finalize_plan: no localDir, or a relative one, is refused with how to call it; an absolute one is remembered", async () => {
  const plans = new UploadPlans();
  for (const dir of [undefined, "ds-bundle"]) {
    const r = await gateUploadToolUse("DesignSync", plan(dir), opts(fake(), plans));
    assert.equal(r.outcome?.decision, "block");
    assert.equal(r.outcome?.ruleRef?.id, "proxy:upload-plan-dir");
    assert.match(refusedWith(r.input), /localDir/);
    assert.match(r.outcome!.notice!, /absolute path/);
  }
  assert.deepEqual(plans.of("s1"), []);
  const ok = await gateUploadToolUse("DesignSync", plan("/ws/app/ds-bundle"), opts(fake(), plans));
  assert.equal(ok.outcome?.decision, "allow");
  assert.deepEqual(plans.of("s1"), ["/ws/app/ds-bundle"]);
});

test("write_files: a secret localPath (relative to the plan, escaping it) refuses the WHOLE call; the notice says ask the user", async () => {
  const plans = new UploadPlans();
  plans.remember("s1", "/ws/app/ds-bundle");
  const calls: FileUploadDecisionRequest[] = [];
  const r = await gateUploadToolUse("DesignSync", write([
    { path: "components/button.html", localPath: "button.html" },
    { path: "components/env.txt", localPath: "../.env" },
  ]), opts(fake({}, calls), plans));
  assert.equal(r.outcome?.decision, "block");
  assert.equal(r.outcome?.ruleRef?.id, "fs:upload-secret-file");
  assert.equal(r.outcome?.path, SECRET);
  assert.equal(r.outcome?.field, "files[1].localPath");
  assert.equal(r.outcome?.approvalId, "egr-7");
  assert.equal(r.outcome?.requiresApproval, true);
  const why = refusedWith(r.input);
  assert.match(why, /Approvals page/);
  assert.match(why, /fs:upload-secret-file/);
  // every file was asked about, on claude.ai, attributed to the session
  assert.deepEqual(calls.map((c) => c.path), ["/ws/app/ds-bundle/button.html", SECRET]);
  for (const c of calls) {
    assert.equal(c.destination, DESIGN_SYNC_HOST);
    assert.equal(c.tool, "DesignSync");
    assert.equal(c.sessionKey, "s1");
  }
});

test("write_files: an absolute localPath is judged as written; every held file is asked (one Approvals row each), the first one named", async () => {
  const calls: FileUploadDecisionRequest[] = [];
  const r = await gateUploadToolUse("DesignSync", write([
    { path: "a", localPath: SECRET },
    { path: "b", localPath: "/ws/app/secret-copy.txt" },
  ]), opts(fake({}, calls)));
  assert.equal(r.outcome?.decision, "block");
  assert.equal(r.outcome?.path, SECRET);
  assert.equal(calls.length, 2);
});

test("write_files: ordinary files and inline data pass unchanged", async () => {
  const plans = new UploadPlans();
  plans.remember("s1", "/ws/app/ds-bundle");
  const input = write([{ path: "a.html", localPath: "a.html" }, { path: "b.css", data: "body{}" }]);
  const r = await gateUploadToolUse("DesignSync", input, opts(fake(), plans));
  assert.equal(r.outcome?.decision, "allow");
  assert.equal(r.input, input);
  assert.deepEqual(r.outcome?.allowed?.map((a) => a.path), ["/ws/app/ds-bundle/a.html"]);
});

test("write_files FAIL-CLOSED: a relative path with no plan seen (a restarted proxy), an arbiter without the op, one that throws, one that hangs", async () => {
  const relative = write([{ path: "a", localPath: "a.html" }]);
  const r1 = await gateUploadToolUse("DesignSync", relative, opts());
  assert.equal(r1.outcome?.decision, "block");
  assert.equal(r1.outcome?.ruleRef?.id, "proxy:upload-plan-dir");
  assert.match(refusedWith(r1.input), /finalize_plan again/);

  const abs = write([{ path: "a", localPath: "/ws/app/a.html" }]);
  const r2 = await gateUploadToolUse("DesignSync", abs, opts({} as UploadGateOptions["arbiter"]));
  assert.equal(r2.outcome?.ruleRef?.id, "proxy:arbiter-unreachable");
  refusedWith(r2.input);

  const r3 = await gateUploadToolUse("DesignSync", abs, opts(fake({ fileUploadDecision: async () => { throw new Error("socket closed"); } })));
  assert.equal(r3.outcome?.ruleRef?.id, "proxy:arbiter-unreachable");
  assert.match(refusedWith(r3.input), /could not check the file/);

  const hang = { ...opts(fake({ fileUploadDecision: () => new Promise<FileUploadDecision>(() => {}) })), timeoutMs: 30 };
  const r4 = await gateUploadToolUse("DesignSync", abs, hang);
  assert.equal(r4.outcome?.ruleRef?.id, "proxy:arbiter-unreachable");
});

test("write_files FAIL-CLOSED: an input the gate cannot read is refused (no method, files not a list, a non-string localPath, too many paths)", async () => {
  for (const input of [
    "write_files",
    { files: [{ localPath: SECRET }] },
    { method: "write_files", files: { localPath: SECRET } },
    { method: "write_files", files: ["/ws/app/.env"] },
    { method: "write_files", files: [{ path: "a", localPath: ["/ws/app/.env"] }] },
    write(Array.from({ length: UPLOAD_GATE_MAX_PATHS + 1 }, (_, i) => ({ path: `f${i}`, localPath: `/ws/f${i}` }))),
  ]) {
    const r = await gateUploadToolUse("DesignSync", input, opts());
    assert.equal(r.outcome?.decision, "block", JSON.stringify(input).slice(0, 80));
    assert.equal(r.outcome?.ruleRef?.id, "proxy:upload-unreadable");
    refusedWith(r.input);
  }
});

test("the net legs: a symbol in inline data goes to the egress gate at claude.ai; a denial refuses the call", async () => {
  const asked: Array<{ symbol: string; destination?: string; preflight?: boolean }> = [];
  const arbiter = fake({
    desymbolizationDecision: async (req: { symbol: string; destination?: string; preflight?: boolean }) => {
      asked.push(req);
      return { allow: false, requiresApproval: true, reason: "no-model symbol not bound to claude.ai → pending", ruleRef: { source: "rule", id: "egress:secret-unbound" } };
    },
  } as Partial<UploadGateOptions["arbiter"]>);
  const tok = "$MDU:nomodel_Read[ab12cd].STRIPE_KEY";
  const r = await gateUploadToolUse("DesignSync", write([{ path: "cfg.js", data: `export const key = "${tok}";` }]), opts(arbiter));
  assert.equal(r.outcome?.decision, "block");
  assert.ok(r.outcome?.net, "the net leg decided");
  assert.deepEqual(asked.map((a) => [a.symbol, a.destination, a.preflight]), [[tok, DESIGN_SYNC_HOST, true]]);
  assert.match(refusedWith(r.input), /mandu-net-gate/);
});

test("the net legs: an allowed symbol still cannot be put back inside DesignSync's own HTTPS request (no TLS inspection): refused", async () => {
  const arbiter = fake({
    desymbolizationDecision: async () => ({ allow: true, requiresApproval: false, reason: "bound", ruleRef: { source: "rule", id: "egress:secret-bound" } }),
  } as Partial<UploadGateOptions["arbiter"]>);
  const r = await gateUploadToolUse("DesignSync", { method: "create_project", name: "$MDU:nomodel_Read[ab12cd].NAME" }, opts(arbiter));
  assert.equal(r.outcome?.decision, "block");
  assert.equal(r.outcome?.ruleRef?.id, "proxy:symbol-in-tls-tunnel");
});

test("the net legs: a HIGH session's DesignSync call (any method) needs a binding or approval at claude.ai", async () => {
  const seen: Array<{ destination?: string }> = [];
  const arbiter = fake({
    sessionEgressDecision: async (req: { destination?: string }) => {
      seen.push(req);
      return { allow: false, requiresApproval: true, reason: "HIGH SESSION: approval required", ruleRef: { source: "rule", id: "session:high-unbound" } };
    },
  } as Partial<UploadGateOptions["arbiter"]>);
  const r = await gateUploadToolUse("DesignSync", { method: "list_projects" }, opts(arbiter));
  assert.equal(r.outcome?.decision, "block");
  assert.equal(seen[0]?.destination, DESIGN_SYNC_HOST);
  refusedWith(r.input);
});

// ── the observed hosts (2026-10-17; UPLOAD_HOSTS, the 2.1.302 binary) ────────

test("UPLOAD_HOSTS: claude.ai and the API host the bytes actually reach, pinned to the captured excerpts", async () => {
  const { readFileSync } = await import("node:fs");
  const { dirname, join } = await import("node:path");
  const { fileURLToPath } = await import("node:url");
  const fx = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..", "arbiter", "test", "fixtures", "claude-upload-hosts-2026-10-17.json"), "utf8")) as { tools: Record<string, { hosts: string[] }> };
  assert.deepEqual([...UPLOAD_HOSTS], ["claude.ai", "api.anthropic.com"]);
  for (const [tool, t] of Object.entries(fx.tools)) {
    for (const h of t.hosts) assert.ok(UPLOAD_HOSTS.includes(h), `${tool} reaches ${h}, which the gate must judge`);
  }
});

test("every placed file is asked with every host the bytes may reach (a binding must name each)", async () => {
  const calls: FileUploadDecisionRequest[] = [];
  const r = await gateUploadToolUse("Artifact", { file_path: "/ws/app/report.html" }, opts(fake({}, calls)));
  assert.equal(r.outcome?.decision, "allow");
  assert.deepEqual(calls.map((c) => [c.destination, c.destinations]), [["claude.ai", ["api.anthropic.com"]]]);
});

test("the net legs run at every host: a session that may go to claude.ai but not to api.anthropic.com is refused", async () => {
  const seen: string[] = [];
  const arbiter = fake({
    sessionEgressDecision: async (req: { destination?: string }) => {
      seen.push(String(req.destination));
      return req.destination === "claude.ai"
        ? { allow: true, requiresApproval: false, reason: "bound", ruleRef: { source: "rule", id: "session:high-bound" } }
        : { allow: false, requiresApproval: true, reason: "HIGH SESSION: approval required", ruleRef: { source: "rule", id: "session:high-unbound" } };
    },
  } as Partial<UploadGateOptions["arbiter"]>);
  const r = await gateUploadToolUse("DesignSync", { method: "list_projects" }, opts(arbiter));
  assert.equal(r.outcome?.decision, "block");
  assert.deepEqual(seen, ["claude.ai", "api.anthropic.com"]);
  refusedWith(r.input);
});

test("TLS inspection never releases a symbol into an upload: the bytes go to a model API host the net proxy never carries", async () => {
  const arbiter = fake({
    desymbolizationDecision: async () => ({ allow: true, requiresApproval: false, reason: "bound", ruleRef: { source: "rule", id: "egress:secret-bound" } }),
  } as Partial<UploadGateOptions["arbiter"]>);
  // before 2026-10-17 `tlsInspected` let this through, and the literal token went to api.anthropic.com
  const r = await gateUploadToolUse("ArtifactComments", { action: "reply", url: "https://claude.ai/artifact/x", text: "$MDU:nomodel_Read[ab12cd].K" }, { ...opts(arbiter), tlsInspected: true });
  assert.equal(r.outcome?.decision, "block");
  assert.equal(r.outcome?.ruleRef?.id, "proxy:symbol-in-tls-tunnel");
});

// ── the window (2026-10-17; priorWriter) ────────────────────────────────────

test("WINDOW: a call that uploads a local file after a possible writer of the same turn is refused before anything is asked; one with no local file is not", async () => {
  const calls: FileUploadDecisionRequest[] = [];
  const o = { ...opts(fake({}, calls)), priorWriter: "Bash" };
  const r = await gateUploadToolUse("Artifact", { file_path: "/ws/app/report.html" }, o);
  assert.equal(r.outcome?.decision, "block");
  assert.equal(r.outcome?.ruleRef?.id, "proxy:upload-after-write");
  assert.match(refusedWith(r.input), /earlier call of this turn \(Bash\)/);
  assert.equal(calls.length, 0);
  // inline data and the read methods name no local file: unaffected
  for (const input of [{ method: "list_projects" }, write([{ path: "a.js", data: "x" }])]) {
    assert.equal((await gateUploadToolUse("DesignSync", input, o)).outcome?.decision, "allow");
  }
});

test("read methods and the rest send no local file: allowed after the net legs", async () => {
  for (const input of [{ method: "list_projects" }, { method: "get_file", projectId: "p", path: "x.html" }, { method: "delete_files", projectId: "p", planId: "q", paths: ["x"] }]) {
    const r = await gateUploadToolUse("DesignSync", input, opts());
    assert.equal(r.outcome?.decision, "allow");
    assert.equal(r.input, input);
  }
});

test("the union carries DesignSync's, the Artifact tools' and OpenClaw's senders' upload kinds (a session with no table, an arbiter that cannot say)", () => {
  assert.deepEqual(UNION_GATE_SURFACE.upload, {
    DesignSync: "claude-design-sync", Artifact: "claude-artifact", ArtifactData: "claude-artifact-data", ArtifactComments: "claude-artifact-comments",
    message: "openclaw-message",
    view_image: "openclaw-media", image: "openclaw-media", pdf: "openclaw-media",
    image_generate: "openclaw-media", music_generate: "openclaw-media", video_generate: "openclaw-media",
    browser: "openclaw-browser-upload",
  });
  assert.equal(UPLOAD_HOST, DESIGN_SYNC_HOST);
});

// ── the Artifact tools (supported-agents.md §2, "Claude Code 2.1.295") ──────

const refusedArtifact = (input: unknown): string => {
  const a = (input as { action?: unknown }).action;
  assert.equal(typeof a, "string");
  assert.ok((a as string).startsWith(REFUSED_ID_PREFIX), "action is an enum in every Artifact tool: the schema rejects it");
  assert.deepEqual(Object.keys(input as object), ["action"], "no file_path, no files, no writes: nothing to read or send");
  return a as string;
};

test("artifactUploadTargets: Artifact publish's file_path, files (list and map, against an absolute root), file_paths; nothing for other actions", () => {
  const t = (input: Record<string, unknown>) => artifactUploadTargets("claude-artifact", input, "/home/u");
  assert.deepEqual(t({ file_path: "/ws/report.html" }).targets.map((x) => [x.field, x.path]), [["file_path", "/ws/report.html"]]);
  assert.deepEqual(t({ action: "publish", file_path: "/ws/r/index.html", root: "/ws/r", files: { "app.js": "app.js", "data.json": { from: "/ws/.env", contentType: "application/json" }, "old.css": null, "logo.png": { artifact: "https://claude.ai/artifact/x", path: "logo.png" } } })
    .targets.map((x) => [x.field, x.path]), [
    ["file_path", "/ws/r/index.html"],
    ['files["app.js"]', "/ws/r/app.js"],
    ['files["data.json"].from', "/ws/.env"],
  ]);
  assert.deepEqual(t({ root: "/ws/site", files: [{ path: "css/a.css" }, { path: "../.env" }] }).targets.map((x) => x.path), ["/ws/site/css/a.css", "/ws/.env"]);
  assert.deepEqual(t({ file_paths: ["/ws/a.png", "~/.ssh/id_ed25519"] }).targets.map((x) => x.path), ["/ws/a.png", "/home/u/.ssh/id_ed25519"]);
  for (const action of ["list", "read", "delete", "pin", "unpin"]) {
    assert.deepEqual(t({ action, url: "https://claude.ai/artifact/x", file_path: "/ws/.env", out_dir: "/tmp/x" }).targets, [], action);
  }
  // relative to the working directory: not placeable
  assert.deepEqual(t({ file_path: "report.html" }).relative, { field: "file_path", shown: "report.html" });
  assert.deepEqual(t({ file_path: "/ws/i.html", files: { "a.js": "a.js" } }).relative, { field: 'files["a.js"]', shown: "a.js" });
  assert.deepEqual(t({ root: "site", files: [{ path: "a.css" }] }).relative, { field: "root", shown: "site" });
  // unreadable
  for (const bad of [{ file_path: 7 }, { file_path: " " }, { files: "a.js" }, { files: [7] }, { files: { "a.js": 7 } }, { root: 1, files: {} }, { file_paths: "/ws/a" }]) {
    assert.ok(t(bad as Record<string, unknown>).unreadable, JSON.stringify(bad));
  }
});

test("artifactUploadTargets: ArtifactData's file_path and every writes[].file_path, whatever the action; ArtifactComments none", () => {
  const t = (input: Record<string, unknown>) => artifactUploadTargets("claude-artifact-data", input, "/home/u");
  assert.deepEqual(t({ action: "set", url: "u", collection: "c", doc_id: "d", file_path: "/ws/doc.json" }).targets.map((x) => x.path), ["/ws/doc.json"]);
  assert.deepEqual(t({ action: "batch", url: "u", writes: [{ op: "set", collection: "c", doc_id: "a", data: { x: 1 } }, { op: "update", collection: "c", doc_id: "b", file_path: "/ws/.env" }] })
    .targets.map((x) => [x.field, x.path]), [["writes[1].file_path", "/ws/.env"]]);
  assert.deepEqual(t({ action: "update", file_path: "doc.json" }).relative, { field: "file_path", shown: "doc.json" });
  assert.ok(t({ action: "batch", writes: {} }).unreadable);
  assert.ok(t({ action: "batch", writes: [7] }).unreadable);
  assert.deepEqual(artifactUploadTargets("claude-artifact-comments", { action: "reply", text: "/ws/.env" }, "/home/u").targets, []);
});

test("Artifact publish: a secret page or supporting file refuses the WHOLE call (one Approvals row each); ordinary files pass unchanged", async () => {
  const calls: FileUploadDecisionRequest[] = [];
  const input = { file_path: "/ws/app/index.html", root: "/ws/app", files: { "env.txt": "../app/.env", "app.js": "app.js" }, icon: "chart" };
  const r = await gateUploadToolUse("Artifact", input, opts(fake({}, calls)));
  assert.equal(r.outcome?.decision, "block");
  assert.equal(r.outcome?.ruleRef?.id, "fs:upload-secret-file");
  assert.equal(r.outcome?.path, SECRET);
  assert.equal(r.outcome?.field, 'files["env.txt"]');
  assert.match(refusedArtifact(r.input), /Approvals page/);
  assert.deepEqual(calls.map((c) => [c.tool, c.path, c.destination]), [
    ["Artifact", "/ws/app/index.html", UPLOAD_HOST], ["Artifact", SECRET, UPLOAD_HOST], ["Artifact", "/ws/app/app.js", UPLOAD_HOST],
  ]);

  const clean = { file_path: "/ws/app/index.html", files: [{ path: "/ws/app/app.js" }] };
  const ok = await gateUploadToolUse("Artifact", clean, opts());
  assert.equal(ok.outcome?.decision, "allow");
  assert.equal(ok.input, clean);
  assert.deepEqual(ok.outcome?.allowed?.map((a) => a.path), ["/ws/app/index.html", "/ws/app/app.js"]);
});

test("Artifact: a path relative to the working directory is refused with how to call it (proxy:upload-relative-path); nothing asked", async () => {
  for (const [input, field] of [
    [{ file_path: "report.html" }, "file_path"],
    [{ file_path: "/ws/i.html", files: [{ path: "a.css" }] }, "files[0].path"],
    [{ file_path: "/ws/i.html", root: "site", files: [{ path: "a.css" }] }, "root"],
  ] as const) {
    const calls: FileUploadDecisionRequest[] = [];
    const r = await gateUploadToolUse("Artifact", input, opts(fake({}, calls)));
    assert.equal(r.outcome?.decision, "block", JSON.stringify(input));
    assert.equal(r.outcome?.ruleRef?.id, "proxy:upload-relative-path");
    assert.equal(r.outcome?.field, field);
    assert.match(refusedArtifact(r.input), /Call Artifact again with (absolute paths|the absolute path)/);
    assert.equal(calls.length, 0);
  }
});

test("ArtifactData: a secret local JSON file (top level or in a batch) refuses the call; inline data passes", async () => {
  const r1 = await gateUploadToolUse("ArtifactData", { action: "set", url: "https://claude.ai/artifact/x", collection: "rows", doc_id: "r1", file_path: SECRET }, opts());
  assert.equal(r1.outcome?.decision, "block");
  assert.equal(r1.outcome?.path, SECRET);
  refusedArtifact(r1.input);
  const r2 = await gateUploadToolUse("ArtifactData", { action: "batch", url: "u", writes: [{ op: "set", collection: "rows", doc_id: "a", file_path: "/ws/app/secret-copy.txt" }] }, opts());
  assert.equal(r2.outcome?.decision, "block");
  assert.equal(r2.outcome?.field, "writes[0].file_path");
  const inline = { action: "update", url: "u", collection: "rows", doc_id: "a", data: { done: true } };
  const r3 = await gateUploadToolUse("ArtifactData", inline, opts());
  assert.equal(r3.outcome?.decision, "allow");
  assert.equal(r3.input, inline);
});

test("the Artifact tools: the net legs run over every string (a symbol in a comment reply, in inline data, in a published path); a high session needs a binding", async () => {
  const asked: string[] = [];
  const arbiter = fake({
    desymbolizationDecision: async (req: { symbol: string }) => {
      asked.push(req.symbol);
      return { allow: false, requiresApproval: true, reason: "not bound to claude.ai", ruleRef: { source: "rule", id: "egress:secret-unbound" } };
    },
  } as Partial<UploadGateOptions["arbiter"]>);
  const tok = "$MDU:nomodel_Read[ab12cd].STRIPE_KEY";
  for (const [name, input] of [
    ["ArtifactComments", { action: "reply", url: "https://claude.ai/artifact/x", thread_id: "t1", text: `the key is ${tok}` }],
    ["ArtifactData", { action: "set", url: "u", collection: "c", doc_id: "d", data: { key: tok } }],
    ["Artifact", { action: "read", url: "https://claude.ai/artifact/x", prompt: `find ${tok}` }],
  ] as const) {
    const r = await gateUploadToolUse(name, input, opts(arbiter));
    assert.equal(r.outcome?.decision, "block", name);
    assert.ok(r.outcome?.net, `${name}: the net leg decided`);
    assert.match(refusedArtifact(r.input), /mandu-net-gate/);
  }
  assert.deepEqual(asked, [tok, tok, tok]);

  const high = fake({
    sessionEgressDecision: async () => ({ allow: false, requiresApproval: true, reason: "HIGH SESSION", ruleRef: { source: "rule", id: "session:high-unbound" } }),
  } as Partial<UploadGateOptions["arbiter"]>);
  const r = await gateUploadToolUse("ArtifactComments", { action: "read", url: "https://claude.ai/artifact/x" }, opts(high));
  assert.equal(r.outcome?.decision, "block");
});

test("the Artifact tools FAIL-CLOSED: no action (ArtifactData, ArtifactComments), an unreadable input, an arbiter that cannot judge", async () => {
  for (const [name, input] of [
    ["ArtifactData", { url: "u", file_path: SECRET }],
    ["ArtifactComments", { url: "u", text: "hi" }],
    ["Artifact", { action: 3, file_path: SECRET }],
    ["Artifact", { file_path: ["/ws/app/.env"] }],
    ["Artifact", "publish"],
  ] as const) {
    const r = await gateUploadToolUse(name, input, opts());
    assert.equal(r.outcome?.decision, "block", JSON.stringify(input));
    assert.equal(r.outcome?.ruleRef?.id, "proxy:upload-unreadable");
    refusedArtifact(r.input);
  }
  const r = await gateUploadToolUse("Artifact", { file_path: "/ws/app/index.html" }, opts({} as UploadGateOptions["arbiter"]));
  assert.equal(r.outcome?.ruleRef?.id, "proxy:arbiter-unreachable");
  refusedArtifact(r.input);
});

test("the Artifact tools' read-only and comment calls pass after the net legs", async () => {
  for (const [name, input] of [
    ["Artifact", { action: "list", scope: "mine" }],
    ["Artifact", { action: "read", url: "https://claude.ai/artifact/x", path: "index.html", out_dir: "/ws/out" }],
    ["ArtifactComments", { action: "reply", url: "https://claude.ai/artifact/x", thread_id: "t1", text: "Fixed in the new version." }],
    ["ArtifactData", { action: "query", url: "u", collection: "rows", query: { limit: 10 } }],
  ] as const) {
    const r = await gateUploadToolUse(name, input, opts());
    assert.equal(r.outcome?.decision, "allow", `${name} ${JSON.stringify(input)}`);
    assert.equal(r.input, input);
  }
});

test("uploadBlockNotice: names the file the model wrote and the rule; asks for approval only when the arbiter queued one", () => {
  assert.match(uploadBlockNotice("../.env", HELD), /^mandu-upload-gate: upload refused, nothing was sent: \.\.\/\.env is a secret file.*Approvals page.*\(rule: fs:upload-secret-file\)$/);
  const denied: FileUploadDecision = { allow: false, requiresApproval: false, reason: "human-denied", ruleRef: { source: "verdict", id: "verdict:egr-7" } };
  const n = uploadBlockNotice("../.env", denied);
  assert.match(n, /the user declined/);
  assert.ok(!n.includes("Approvals page"));
});
