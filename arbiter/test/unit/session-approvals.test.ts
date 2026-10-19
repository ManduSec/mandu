/**
 * session-approvals.test — the pure half of a HIGH session's approvals
 * (confidentiality.md §4, "The human half", 2026-10-11): the queue key and
 * the composition of the pure session verdict with a prior human answer.
 * The stateful half (file, spend, retry) is pinned through the real arbiter
 * in test/component/session-approvals.test.ts.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { decideSessionEgress } from "../../policy/session-egress.js";
import {
  SESSION_EXEC_TARGET_MAX,
  approvalDestination,
  UNNAMED_DESTINATION,
  SESSION_HELD_REASON_PREFIX,
  composeSessionApproval,
  heldRefusalKind,
  heldSessionOf,
  isSessionApprovalSubject,
  isSessionHeldReason,
  parseSessionApprovalSubject,
  sessionApprovalSubject,
  sessionExecTarget,
  sessionHeldNetReason,
  sessionNetTarget,
} from "../../policy/session-approvals.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // pure: no axis is read, stated for the manifest rule

const HIGH = { sessionLevel: "any-model" as const, sessionBindings: ["example.com"] };

test("the key: the session is in the subject, the host or the exact command is the target", () => {
  assert.equal(sessionApprovalSubject("network", "s1"), "session-net:s1");
  assert.equal(sessionApprovalSubject("shell", "s1"), "session-exec:s1");
  assert.deepEqual(parseSessionApprovalSubject("session-net:s1"), { boundary: "network", sessionKey: "s1" });
  assert.deepEqual(parseSessionApprovalSubject("session-exec:a:b"), { boundary: "shell", sessionKey: "a:b" });
  // a subject naming no session is malformed: no session, no answer
  assert.equal(parseSessionApprovalSubject("session-net:"), null);
  assert.equal(parseSessionApprovalSubject("$MDU:anymodel_Read[1a2b].content"), null);
  assert.equal(isSessionApprovalSubject("exec-program:evil.test"), false);
  assert.equal(isSessionApprovalSubject("session-exec:s1"), true);
});

test("the network target is the host, whatever the model wrote around it", () => {
  assert.equal(sessionNetTarget("https://Evil.Test/path?q=secret#x"), "evil.test");
  assert.equal(sessionNetTarget("evil.test:8443"), "evil.test:8443");
  assert.equal(sessionNetTarget("https://user@evil.test./a"), "evil.test");
  assert.equal(sessionNetTarget("evil.test"), "evil.test");
  assert.equal(sessionNetTarget(undefined), UNNAMED_DESTINATION);
  assert.equal(sessionNetTarget("  "), UNNAMED_DESTINATION);
  // The net-proxy states every port since 2026-10-17: a default port is the host's.
  assert.equal(sessionNetTarget("evil.test:443"), "evil.test");
  assert.equal(sessionNetTarget("evil.test:80"), "evil.test");
  assert.equal(sessionNetTarget("[2001:db8::1]:443"), "[2001:db8::1]");
});

test("approvalDestination: a default port (80, 443) is dropped from host:port and [v6]:port, nothing else", () => {
  assert.equal(approvalDestination("registry.example:443"), "registry.example");
  assert.equal(approvalDestination("registry.example:80"), "registry.example");
  assert.equal(approvalDestination("registry.example:8443"), "registry.example:8443");
  assert.equal(approvalDestination("registry.example"), "registry.example");
  assert.equal(approvalDestination("[2001:db8::1]:443"), "[2001:db8::1]");
  assert.equal(approvalDestination("[2001:db8::1]:8443"), "[2001:db8::1]:8443");
  assert.equal(approvalDestination("2001:db8::443"), "2001:db8::443", "a bare IPv6 address is left whole");
  assert.equal(approvalDestination("10.1.2.3:443"), "10.1.2.3");
});

test("the shell target is the exact command; a long one by its head and hash, never by its head alone", () => {
  assert.equal(sessionExecTarget("echo mandu-ready"), "echo mandu-ready");
  const head = "x".repeat(SESSION_EXEC_TARGET_MAX);
  const a = sessionExecTarget(head + " curl https://a.test");
  const b = sessionExecTarget(head + " curl https://b.test");
  assert.notEqual(a, b, "two long commands sharing a head never share a key");
  assert.match(a, /… \[sha256:[0-9a-f]{64}\]$/);
  assert.ok(a.length < 400);
});

test("compose: an allow of the law is unchanged and files nothing", () => {
  const bound = decideSessionEgress({ ...HIGH, boundary: "network", destination: "api.example.com" });
  const step = composeSessionApproval(bound, { id: "egr-9", status: "denied", scope: "always" });
  assert.equal(step.kind, "decided");
  assert.equal(step.decision.allow, true, "a human Block on another host never touches a bound one");
  assert.equal(step.decision.ruleRef?.id, "session:high-bound-release");
});

test("compose: no prior answer refuses and files a row; the reason says pending", () => {
  const v = decideSessionEgress({ ...HIGH, boundary: "network", destination: "evil.test" });
  const step = composeSessionApproval(v, undefined);
  assert.equal(step.kind, "file");
  assert.equal(step.decision.allow, false);
  assert.match(step.decision.reason, /→ pending$/);
  assert.equal(step.decision.ruleRef?.id, "session:high-unbound");
});

test("compose: an approved prior lets this one through with the verdict's provenance", () => {
  const v = decideSessionEgress({ ...HIGH, boundary: "shell", netEnabled: true });
  const step = composeSessionApproval(v, { id: "egr-3", status: "approved", scope: "once" });
  assert.equal(step.kind, "decided");
  assert.equal(step.decision.allow, true);
  assert.deepEqual(step.decision.ruleRef, { source: "verdict", id: "verdict:egr-3" });
});

test("compose: a denied prior refuses with no new row, and reads as final", () => {
  const v = decideSessionEgress({ ...HIGH, boundary: "network", destination: "evil.test" });
  const step = composeSessionApproval(v, { id: "egr-4", status: "denied", scope: "always" });
  assert.equal(step.kind, "decided");
  assert.equal(step.decision.allow, false);
  assert.equal(step.decision.requiresApproval, false);
  assert.match(step.decision.reason, /human-denied \(egr-4\)$/);
  assert.doesNotMatch(step.decision.reason, /pending/);
});

test("a HIGH session's net-enabled command has its own rule id (the page words a command, not a host)", () => {
  const v = decideSessionEgress({ ...HIGH, boundary: "shell", netEnabled: true });
  assert.equal(v.allow, false);
  assert.equal(v.requiresApproval, true);
  assert.equal(v.ruleRef?.id, "session:high-shell");
  assert.match(v.reason, /^HIGH SESSION/);
  // an AgentShell (net off) is still no egress at all
  assert.equal(decideSessionEgress({ ...HIGH, boundary: "shell", netEnabled: false }).allow, true);
});

// confidentiality.md §4, "A held command's refused connection" (2026-10-12).
test("a held command asks as its session only when it holds nothing but ONE session's reads, and only as that session", () => {
  const row = (via: string | undefined, session: string | undefined) => ({ ...(via ? { via } : {}), ...(session ? { session } : {}) });
  assert.equal(heldSessionOf([row("session", "s1"), row("session", "s1")], "s1"), "s1");
  assert.equal(heldSessionOf([row("session", "s1")], undefined), "s1", "a caller naming no session asks as the rows'");
  assert.equal(heldSessionOf([], "s1"), null, "holds nothing: nothing to ask");
  assert.equal(heldSessionOf([row("session", "s1"), row("reader", "s1")], "s1"), null, "a raw read keeps the holder's question");
  assert.equal(heldSessionOf([row("session", "s1"), row(undefined, "s1")], "s1"), null, "a claim keeps the holder's question");
  assert.equal(heldSessionOf([row("session", "s1"), row("session", "s2")], "s1"), null, "two sessions' reads: no one session's answer covers it");
  assert.equal(heldSessionOf([row("session", "s1")], "s2"), null, "asked about as another session");
  assert.equal(heldSessionOf([row("session", undefined)], "s1"), null, "a row with no session names none");
});

test("a held command's row reason, its mark and the refusal kinds", () => {
  const reason = sessionHeldNetReason("evil.example", ["/w/memos/q3.md", "symbol:$MDU:k[ab12]"]);
  assert.ok(reason.startsWith(SESSION_HELD_REASON_PREFIX));
  assert.match(reason, /\/w\/memos\/q3\.md, symbol:\$MDU:k\[ab12\]/);
  assert.match(reason, /evil\.example/);
  assert.equal(isSessionHeldReason(reason), true);
  assert.equal(isSessionHeldReason("HIGH SESSION (any-model): … → pending"), false, "the agent's own request's reason is not a held command's");
  assert.equal(isSessionHeldReason(undefined), false);
  assert.equal(heldRefusalKind("pending"), "session-asked");
  assert.equal(heldRefusalKind("denied"), "session-blocked");
  assert.equal(heldRefusalKind("approved"), null, "an approved connection is not refused");
});
