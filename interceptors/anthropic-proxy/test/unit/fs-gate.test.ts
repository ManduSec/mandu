/**
 * fs-gate.test.ts — proxy-side enforcement of the P3 sensitive-path gate
 * (fs-sync.md §1.4.1): out-of-workspace typed path fields go to the
 * arbiter; deny/unreachable rewrites into /mandu/denied/…; allow and
 * in-workspace pass through; Bash/unknown tools are out of scope.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { gateToolUseInput, mediaRefPath, resolveRelative, DENIED_NAMESPACE } from "../../src/fs-gate.js";
import { ViewMap } from "../../src/view-map.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import type { FsPathDecision, FsPathDecisionRequest } from "../../src/arbiter-client.js";

const HUMAN = "/home/u/project/webapp";
const AGENT = "/home/u/.mandu/workspaces/wid/agentview";

function makeMap(): ViewMap {
  return new ViewMap([{ human: HUMAN, agent: AGENT }], { dialect: "posix", home: "/home/u" });
}

function opts(arbiter: MockArbiter) {
  return { arbiter, viewMap: makeMap() };
}

test("out-of-workspace absolute path: denied → rewritten to the /mandu/denied sentinel", async () => {
  const arbiter = new MockArbiter(); // default: deny + requiresApproval
  const r = await gateToolUseInput("Read", { file_path: "/home/u/.ssh/id_rsa" }, opts(arbiter));
  assert.ok(r);
  assert.equal(r!.gated.length, 1);
  assert.equal(r!.input["file_path"], `${DENIED_NAMESPACE}/policy/home/u/.ssh/id_rsa`);
  assert.equal(r!.gated[0].path, "/home/u/.ssh/id_rsa");
  // The arbiter was asked with the tool, mode and BOTH workspace roots.
  assert.equal(arbiter.fsPathDecisionCalls.length, 1);
  const call = arbiter.fsPathDecisionCalls[0];
  assert.equal(call.tool, "Read");
  assert.equal(call.mode, "read");
  assert.deepEqual(call.workspaceRoots, [HUMAN, AGENT]);
});

test("opts.sessionKey rides the arbiter request (attribution-only); omitted → not sent", async () => {
  // With a sessionKey: the fsPathDecision request carries it verbatim, so the
  // arbiter can attribute the approval-queue row to the session.
  const arbiter = new MockArbiter();
  await gateToolUseInput(
    "Read",
    { file_path: "/home/u/.ssh/id_rsa" },
    { ...opts(arbiter), sessionKey: "sess-123" },
  );
  assert.equal(arbiter.fsPathDecisionCalls.length, 1);
  assert.equal(arbiter.fsPathDecisionCalls[0].sessionKey, "sess-123");

  // Without one: the field is ABSENT from the request (no invented attribution).
  const bare = new MockArbiter();
  await gateToolUseInput("Read", { file_path: "/home/u/.ssh/id_rsa" }, opts(bare));
  assert.equal(bare.fsPathDecisionCalls.length, 1);
  assert.equal("sessionKey" in bare.fsPathDecisionCalls[0], false);
});

test("write-mode tools report mode=write", async () => {
  const arbiter = new MockArbiter();
  await gateToolUseInput("Write", { file_path: "/etc/crontab", content: "x" }, opts(arbiter));
  assert.equal(arbiter.fsPathDecisionCalls[0].mode, "write");
});

test("a queued deny's approvalId rides the gated record (Pending-tab join, §5)", async () => {
  const arbiter = new MockArbiter({
    fsPathDecisionFn: () => ({
      allow: false, requiresApproval: true, reason: "out-of-workspace",
      ruleRef: { source: "fail-closed", id: "fs:default-deny" },
      approvalId: "egr-42",
    }),
  });
  const r = await gateToolUseInput("Read", { file_path: "/opt/probe" }, opts(arbiter));
  assert.equal(r!.gated[0].approvalId, "egr-42");

  // A decision WITHOUT one (old arbiter / verdict short-circuit) stays absent —
  // no invented join key.
  const bare = new MockArbiter();
  const r2 = await gateToolUseInput("Read", { file_path: "/opt/probe" }, opts(bare));
  assert.equal(r2!.gated[0].approvalId, undefined);
});

test("allow verdict passes the path through unchanged (no sentinel, no gated record)", async () => {
  const arbiter = new MockArbiter({ fsPathDecisionFn: () => ({ allow: true, reason: "allowlisted" }) });
  const input = { file_path: "/usr/share/doc/readme" };
  const r = await gateToolUseInput("Read", input, opts(arbiter));
  assert.ok(r);
  assert.equal(r!.gated.length, 0);
  assert.equal(r!.input["file_path"], "/usr/share/doc/readme");
});

test("relative paths under an UNKNOWN base: one that stays under the working directory is not gated here; one that escapes it with `..` is denied without asking (fail closed)", async () => {
  const arbiter = new MockArbiter();
  for (const p of ["vendor/notes.txt", "./x", "a/../b", "."]) {
    const r = await gateToolUseInput("Read", { file_path: p }, opts(arbiter));
    assert.equal(r!.gated.length, 0, p);
  }
  for (const p of ["../up", "..", "a/../../.ssh/id_rsa", "./../../x"]) {
    const r = await gateToolUseInput("Read", { file_path: p }, opts(arbiter));
    assert.equal(r!.gated.length, 1, p);
    assert.match(String(r!.input["file_path"]), new RegExp(`^${DENIED_NAMESPACE}/unresolved/\\.\\.`), p);
    assert.equal(r!.gated[0]!.ruleRef.id, "proxy:relative-escape");
    assert.match(r!.gated[0]!.reason, /absolute path/);
  }
  assert.equal(arbiter.fsPathDecisionCalls.length, 0, "the arbiter is never asked about a path the gate cannot place");
});

test("relative paths under a KNOWN base (the agent resolves against its launch directory): joined, then gated like any absolute path", async () => {
  const arbiter = new MockArbiter({
    fsPathDecisionFn: (req) => req.path.startsWith("/home/u/.ssh")
      ? { allow: false, requiresApproval: true, reason: "sensitive path (~/.ssh)" }
      : req.path.startsWith(HUMAN) ? { allow: true, reason: "inside workspace" } : { allow: false, requiresApproval: true, reason: "out of workspace" },
  });
  const base = `${HUMAN}/sub`;
  const read = async (p: string) => gateToolUseInput("read", { filePath: p }, { ...opts(arbiter), pathTools: { read: { fields: ["filePath"], mode: "read" } }, relativeBase: base });
  const ok = await read("src/a.ts");
  assert.equal(ok!.gated.length, 0);
  assert.equal(ok!.input["filePath"], "src/a.ts", "an allowed relative path is left as written (the agent joins the same base)");
  const up = await read("../README.md");
  assert.equal(up!.gated.length, 0, "a `..` inside the workspace is placed and allowed, not refused");
  const ssh = await read("../../../.ssh/id_rsa");
  assert.equal(ssh!.gated.length, 1);
  assert.equal(ssh!.input["filePath"], `${DENIED_NAMESPACE}/policy/home/u/.ssh/id_rsa`);
  assert.deepEqual(arbiter.fsPathDecisionCalls.map((c) => c.path), [`${base}/src/a.ts`, `${HUMAN}/README.md`, "/home/u/.ssh/id_rsa"]);
  // a base that is not absolute is no base at all
  const bad = await gateToolUseInput("read", { filePath: "../x" }, { ...opts(new MockArbiter()), pathTools: { read: { fields: ["filePath"], mode: "read" } }, relativeBase: "rel" });
  assert.equal(bad!.gated[0]!.ruleRef.id, "proxy:relative-escape");
});

test("resolveRelative: absolute, known base, escape, unresolved", () => {
  const m = makeMap();
  assert.deepEqual(resolveRelative(m, "~/.ssh/id_rsa", undefined), { kind: "absolute", path: "/home/u/.ssh/id_rsa" });
  assert.deepEqual(resolveRelative(m, "/a/./b/../c", undefined), { kind: "absolute", path: "/a/c" });
  assert.deepEqual(resolveRelative(m, "../../x", "/w/p/q"), { kind: "absolute", path: "/w/x" });
  assert.deepEqual(resolveRelative(m, " ../x ", undefined), { kind: "escape", path: "../x" });
  assert.deepEqual(resolveRelative(m, "a/b/../c", undefined), { kind: "unresolved", path: "a/c" });
});

test("in-workspace ABSOLUTE paths DO reach the arbiter (deny-precedence must be reachable)", async () => {
  // The proxy must NOT short-circuit in-workspace paths: the arbiter's rule 1
  // (sensitive deny-precedence) has to be able to fire for a sensitive path
  // nested inside a workspace root. Ordinary in-workspace paths are allowed
  // (rule 2), sensitive ones are gated — both go through the arbiter.
  const arbiter = new MockArbiter({
    fsPathDecisionFn: (req) =>
      req.path.startsWith(`${HUMAN}/.ssh`)
        ? { allow: false, requiresApproval: true, reason: "sensitive (~/.ssh) inside workspace" }
        : { allow: true, reason: "inside workspace root" },
  });
  const ordinary = await gateToolUseInput("Read", { file_path: `${HUMAN}/src/a.ts` }, opts(arbiter));
  assert.equal(ordinary!.gated.length, 0, "ordinary in-workspace read is allowed");
  const sensitive = await gateToolUseInput("Read", { file_path: `${HUMAN}/.ssh/id_rsa` }, opts(arbiter));
  assert.equal(sensitive!.gated.length, 1, "sensitive in-workspace read is gated");
  assert.equal(sensitive!.input["file_path"], `${DENIED_NAMESPACE}/policy${HUMAN}/.ssh/id_rsa`);
  // Both in-workspace absolute paths were submitted to the arbiter.
  assert.equal(arbiter.fsPathDecisionCalls.length, 2);
});

test("ARBITER UNREACHABLE fails closed: the unreachable sentinel, never the raw path", async () => {
  const arbiter = new MockArbiter({ failFsPathDecision: true });
  const r = await gateToolUseInput("Read", { file_path: "/home/u/.ssh/id_rsa" }, opts(arbiter));
  assert.ok(r);
  assert.equal(r!.gated.length, 1);
  assert.equal(r!.input["file_path"], `${DENIED_NAMESPACE}/unreachable/home/u/.ssh/id_rsa`);
  assert.equal(r!.gated[0].decision, null);
  assert.match(r!.gated[0].reason, /unreachable/);
});

test("normalization happens before the workspace check and the arbiter call", async () => {
  const arbiter = new MockArbiter();
  // ~-spelled and ..-spelled forms of an in-workspace path are not gated…
  let r = await gateToolUseInput("Read", { file_path: "~/project/webapp/a.txt" }, opts(arbiter));
  assert.equal(r!.gated.length, 0);
  // …and an escape via .. IS gated, with the normalized path sent to the arbiter.
  r = await gateToolUseInput("Read", { file_path: `${HUMAN}/../../../secret` }, opts(arbiter));
  assert.equal(r!.gated.length, 1);
  assert.equal(arbiter.fsPathDecisionCalls.at(-1)!.path, "/home/secret");
});

test("Bash and unknown tools are out of the gate's scope (null)", async () => {
  const arbiter = new MockArbiter();
  assert.equal(await gateToolUseInput("Bash", { command: "cat /home/u/.ssh/id_rsa" }, opts(arbiter)), null);
  assert.equal(await gateToolUseInput("mcp__x__y", { path: "/home/u/.ssh/id_rsa" }, opts(arbiter)), null);
  assert.equal(arbiter.fsPathDecisionCalls.length, 0);
});

test("a WEDGED arbiter (never resolves) fails closed via timeout, does not hang", async () => {
  // A never-settling fsPathDecision must not wedge the gate: the bounded
  // timeout treats it as unreachable → the denied sentinel (fail closed). We
  // hold the resolver so the hung promise can be settled AFTER the assertions
  // (keeping the test free of dangling promises).
  let release: (d: FsPathDecision) => void = () => {};
  const hungPromise = new Promise<FsPathDecision>((resolve) => { release = resolve; });
  const hung = {
    fsPathDecision: (_req: FsPathDecisionRequest): Promise<FsPathDecision> => hungPromise,
  } as unknown as MockArbiter;
  const map = makeMap();
  const start = Date.now();
  const r = await gateToolUseInput(
    "Read",
    { file_path: "/home/u/.ssh/id_rsa" },
    { arbiter: hung, viewMap: map, arbiterTimeoutMs: 40 },
  );
  const elapsed = Date.now() - start;
  assert.ok(elapsed < 2000, `gate must return promptly on a wedged arbiter (took ${elapsed}ms)`);
  assert.equal(r!.gated.length, 1);
  assert.equal(r!.input["file_path"], `${DENIED_NAMESPACE}/unreachable/home/u/.ssh/id_rsa`);
  assert.match(r!.gated[0].reason, /timed out|unreachable/);
  // Settle the hung promise so nothing stays pending past the test.
  release({ allow: true, reason: "released after timeout" });
  await hungPromise;
});

test("the caller's input object is never mutated", async () => {
  const arbiter = new MockArbiter();
  const input = { file_path: "/etc/passwd" };
  const r = await gateToolUseInput("Read", input, opts(arbiter));
  assert.equal(input.file_path, "/etc/passwd");
  assert.notEqual(r!.input, input);
});

// ── array fields and media references (the OpenClaw gate-surface residue) ───

/** Deny under ~/.ssh, allow everything else. */
const sshOnly = (req: FsPathDecisionRequest): FsPathDecision =>
  req.path.startsWith("/home/u/.ssh")
    ? { allow: false, requiresApproval: true, reason: "sensitive path (~/.ssh)" }
    : { allow: true, reason: "ok" };

test("an array path field (browser upload `paths`): every string element is gated, a denied one becomes the sentinel in a COPY of the array", async () => {
  const arbiter = new MockArbiter({ fsPathDecisionFn: sshOnly });
  const paths = ["/home/u/project/webapp/a.png", "/home/u/.ssh/id_rsa", 3, "rel/b.png"];
  const input = { action: "upload", paths };
  const r = await gateToolUseInput("browser", input, { ...opts(arbiter), pathTools: { browser: { fields: ["path", "paths"], mode: "write" } } });
  assert.ok(r);
  assert.equal(r!.gated.length, 1);
  assert.equal(r!.gated[0]!.field, "paths[1]");
  assert.deepEqual(r!.input["paths"], ["/home/u/project/webapp/a.png", `${DENIED_NAMESPACE}/policy/home/u/.ssh/id_rsa`, 3, "rel/b.png"]);
  assert.equal(paths[1], "/home/u/.ssh/id_rsa", "the caller's array is untouched");
  assert.deepEqual(arbiter.fsPathDecisionCalls.map((c) => [c.path, c.mode]), [
    ["/home/u/project/webapp/a.png", "write"],
    ["/home/u/.ssh/id_rsa", "write"],
  ], "absolute elements only; a non-string element is skipped (the tool skips it too)");
});

test("media references (image / view_image): `@path`, `~`, `MEDIA:` and `file://` name local paths and are gated; http(s), data: and media:// are not paths", async () => {
  assert.equal(mediaRefPath("@/home/u/.ssh/id_rsa"), "/home/u/.ssh/id_rsa");
  assert.equal(mediaRefPath("  @ ~/.ssh/id_rsa "), "~/.ssh/id_rsa");
  assert.equal(mediaRefPath("MEDIA: /home/u/.ssh/id_rsa"), "/home/u/.ssh/id_rsa");
  assert.equal(mediaRefPath("file:///home/u/%2Essh/id_rsa"), "/home/u/.ssh/id_rsa", "percent-decoded, as OpenClaw's fileURLToPath does");
  assert.equal(mediaRefPath("file://remote-host/x"), "remote-host/x", "an undecodable file URL keeps its text, gated as any path");
  assert.equal(mediaRefPath("https://cdn.test/a.png"), null);
  assert.equal(mediaRefPath("data:image/png;base64,AAAA"), null);
  assert.equal(mediaRefPath("media://inbound/abc.png"), null);
  assert.equal(mediaRefPath("pics/a.png"), "pics/a.png");

  const arbiter = new MockArbiter({ fsPathDecisionFn: sshOnly });
  const input = { prompt: "?", image: "@~/.ssh/id_rsa", images: ["https://cdn.test/a.png", "file:///home/u/.ssh/id_ed25519", "/home/u/project/webapp/ok.png"] };
  const r = await gateToolUseInput("image", input, { ...opts(arbiter), pathTools: { image: { fields: ["image", "images"], mode: "read", refs: "media" } } });
  assert.ok(r);
  assert.deepEqual(r!.gated.map((g) => [g.field, g.path]), [["image", "/home/u/.ssh/id_rsa"], ["images[1]", "/home/u/.ssh/id_ed25519"]]);
  assert.equal(r!.input["image"], `${DENIED_NAMESPACE}/policy/home/u/.ssh/id_rsa`);
  assert.deepEqual(r!.input["images"], ["https://cdn.test/a.png", `${DENIED_NAMESPACE}/policy/home/u/.ssh/id_ed25519`, "/home/u/project/webapp/ok.png"]);
  // control: without `refs: "media"` the `@` spelling reads as a relative path and skips the gate
  const plain = new MockArbiter({ fsPathDecisionFn: sshOnly });
  const p = await gateToolUseInput("image", { image: "@/home/u/.ssh/id_rsa" }, { ...opts(plain), pathTools: { image: { fields: ["image"], mode: "read" } } });
  assert.equal(p!.gated.length, 0);
});

test("an array element the arbiter cannot rule on is denied (fail closed), like a string field", async () => {
  const arbiter = new MockArbiter({ failFsPathDecision: true });
  const r = await gateToolUseInput("view_image", { paths: ["/home/u/project/webapp/a.png"] }, { ...opts(arbiter), pathTools: { view_image: { fields: ["path", "paths"], mode: "read", refs: "media" } } });
  assert.deepEqual(r!.input["paths"], [`${DENIED_NAMESPACE}/unreachable/home/u/project/webapp/a.png`]);
});
