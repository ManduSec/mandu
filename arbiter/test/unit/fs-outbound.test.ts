/**
 * fs-outbound.test — the sensitive-path gate's pure decision oracle
 * (fs-sync.md §1.4.1, P3). Rule order with deny-precedence:
 * sensitive built-ins → workspace roots → DIR allowlist → fail-closed default.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { decideFsPath, SENSITIVE_PATHS } from "../../policy/fs-outbound.js";

const HOME = "/home/u";
const WS = "/home/u/project/webapp";
const AGENT = "/home/u/.mandu/workspaces/wid/agentview";
const ROOTS = [WS, AGENT];

function decide(p: string, over: { tool?: string; mode?: "read" | "write"; roots?: string[] } = {},
  opts: { isDirTrusted?: (p: string) => boolean } = {}) {
  return decideFsPath(
    { tool: over.tool ?? "Read", path: p, mode: over.mode ?? "read", workspaceRoots: over.roots ?? ROOTS },
    { home: HOME, ...opts },
  );
}

test("inside either workspace root → allow", () => {
  assert.equal(decide(`${WS}/src/a.ts`).allow, true);
  assert.equal(decide(`${AGENT}/src/a.ts`).allow, true);
  assert.equal(decide(WS).allow, true); // the root itself
});

test("out-of-workspace → deny + requiresApproval (fail-closed default)", () => {
  const d = decide("/var/log/syslog");
  assert.equal(d.allow, false);
  assert.equal(!d.allow && d.requiresApproval, true);
  assert.match((d as { reason: string }).reason, /out-of-workspace/);
});

test("sensitive built-ins → deny/approve, and they WIN over a workspace match", () => {
  for (const p of [`${HOME}/.ssh/id_rsa`, `${HOME}/.aws/credentials`, "/etc/shadow", `${HOME}/.claude/settings.json`]) {
    const d = decide(p);
    assert.equal(d.allow, false, p);
    assert.match((d as { reason: string }).reason, /sensitive path/, p);
  }
  // Workspace rooted at ~ still gates ~/.ssh (deny-precedence).
  const d = decide(`${HOME}/.ssh/id_rsa`, { roots: [HOME] });
  assert.equal(d.allow, false);
  assert.match((d as { reason: string }).reason, /sensitive path/);
});

test("segment-aware matching: lookalike siblings are NOT sensitive/workspace", () => {
  // ~/.sshx is not ~/.ssh; <ws>2 is not <ws>.
  const shx = decide(`${HOME}/.sshx/notes`);
  assert.match((shx as { reason: string }).reason, /out-of-workspace/);
  const ws2 = decide(`${WS}2/file`);
  assert.equal(ws2.allow, false);
});

test("lexical normalization: ~, .., // resolve before matching", () => {
  assert.equal(decide("~/project/webapp/a.txt").allow, true);
  assert.equal(decide(`${WS}/x/../y//z`).allow, true);
  // A .. escape out of the workspace is gated (webapp/../.. = /home/u).
  const esc = decide(`${WS}/../../.ssh/id_rsa`);
  assert.equal(esc.allow, false);
  assert.match((esc as { reason: string }).reason, /sensitive path/);
});

test("DIR trust-category allowlist admits out-of-workspace paths — but never sensitive ones", () => {
  const dirTrusted = (p: string) => p.startsWith("/usr/share/doc");
  assert.equal(decide("/usr/share/doc/readme", {}, { isDirTrusted: dirTrusted }).allow, true);
  assert.equal(decide("/usr/share/other", {}, { isDirTrusted: dirTrusted }).allow, false);
  // Deny-precedence: an allowlist covering ~/.ssh must not admit it.
  const d = decide(`${HOME}/.ssh/id_rsa`, {}, { isDirTrusted: () => true });
  assert.equal(d.allow, false);
});

test("malformed input fails closed: empty path, relative path", () => {
  for (const p of ["", "   ", "vendor/notes.txt", "./x"]) {
    const d = decide(p);
    assert.equal(d.allow, false, JSON.stringify(p));
    assert.equal(!d.allow && d.requiresApproval, true);
  }
});

test("empty/absent workspace roots: everything non-sensitive still fail-closes", () => {
  const d = decideFsPath({ tool: "Read", path: "/tmp/x", mode: "read", workspaceRoots: [] }, { home: HOME });
  assert.equal(d.allow, false);
});

test("the built-in sensitive list stays home-anchored or absolute", () => {
  for (const e of SENSITIVE_PATHS) {
    assert.ok(e.startsWith("~/") || e.startsWith("/"), e);
  }
});
