/**
 * mock-arbiter — an in-test PolicyArbiter (the arbiter-client pattern). Each op
 * returns a canned answer and records its calls; `fail` makes every op throw.
 */
import type { PolicyArbiter, ProposeAnswer, TestFlowAnswer, TestFlowArgs } from "../../src/arbiter-client.js";

export class MockPolicyArbiter implements PolicyArbiter {
  calls: Array<{ op: string; args: unknown }> = [];
  explain: unknown = { specId: "claude-code", locks: [{ path: "/home/u/repo/.env", level: "no-model" }], pendingAskCount: 2 };
  flow: TestFlowAnswer = { inbound: { trust: "UNTRUSTED" }, probe: { level: "public" }, egress: { decision: { allow: false, requiresApproval: true, ruleRef: { id: "egress:untrusted-destination" } }, stage: "built-in" } };
  propose: ProposeAnswer = { applied: true, changeId: "pc-000001", delta: [{ facet: "paths", subject: "/srv/app/.env" }] };
  schema: unknown = { type: "array", minItems: 1, items: { type: "object", required: ["op"] } };
  fail = false;

  private rec(op: string, args: unknown): void {
    this.calls.push({ op, args });
    if (this.fail) throw new Error("connect ENOENT /run/arbiter.sock");
  }
  async policyExplain(args: { audience: "agent"; sessionKey?: string }): Promise<unknown> { this.rec("policyExplain", args); return this.explain; }
  async testFlow(req: TestFlowArgs): Promise<TestFlowAnswer> { this.rec("testFlow", req); return this.flow; }
  async policyPropose(req: { edits: unknown; reason?: string; sessionKey?: string }): Promise<ProposeAnswer> { this.rec("policyPropose", req); return this.propose; }
  async policySchema(): Promise<{ edits: unknown }> { this.rec("policySchema", {}); return { edits: this.schema }; }
}
