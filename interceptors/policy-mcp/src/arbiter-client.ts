/**
 * arbiter-client — the arbiter dependency the mandu-policy MCP server speaks to.
 *
 * PROVENANCE: skeleton copied from interceptors/inspect-mcp/src/arbiter-client.ts
 * (the arbiter-client pattern, CONTRIBUTING.md "Conventions in the code"): a
 * NARROW interface the tools are written against (`PolicyArbiter`), a
 * structural shape of the real arbiter IPC client (arbiter/ipc/client.ts), and a thin adapter. Tests inject
 * test/helpers/mock-arbiter.ts; the parity test
 * (tests/stack/policy-mcp-parity.test.ts) builds the production wiring
 * `new PolicyArbiterAdapter(new ArbiterClient(sock))` over a real arbiter.
 *
 * Every op here is a DATA-socket op: this server is a data-plane client and
 * can never approve or undo anything (those are ADMIN_ONLY_OPS in the arbiter).
 */

/** Mirrors arbiter/ipc/protocol.ts TestFlowOpRequest (minus id/op). */
export interface TestFlowArgs {
  source?: { tool?: string; origin?: string };
  destination?: string;
  boundary?: "network" | "filesystem" | "shell" | "model_context";
}

/** The fields of arbiter TestFlowResult this server reads. */
export interface TestFlowAnswer {
  inbound: { trust: string };
  probe: { level: string };
  egress: {
    decision: { allow: boolean; requiresApproval?: boolean; ruleRef?: { id: string } };
    stage: string;
  } | null;
}

/** Mirrors arbiter/ipc/protocol.ts PolicyProposeResult. */
export type ProposeAnswer =
  | { applied: true; changeId: string | null; delta: Array<{ facet: string; subject: string }>; note?: string }
  | { applied: false; proposalId: string; relaxes: Array<{ facet: string; subject: string }>; why: "relaxes" | "tightening-cap"; duplicate?: boolean }
  | { applied: false; refused: "invalid" | "stale" | "proposal-cap"; problems: string[] };

export interface PolicyArbiter {
  /** The law as bounded tokens, projected for the confined agent. */
  policyExplain(args: { audience: "agent"; sessionKey?: string }): Promise<unknown>;
  testFlow(req: TestFlowArgs): Promise<TestFlowAnswer>;
  policyPropose(req: { edits: unknown; reason?: string; sessionKey?: string }): Promise<ProposeAnswer>;
  /** { edits: <JSON Schema of PolicyEdit[]> } */
  policySchema(): Promise<{ edits: unknown }>;
}

/** Structural shape of the real arbiter IPC client (declared, not imported,
 *  so this package typechecks standalone). */
export interface RealArbiterClient {
  connect(): Promise<void>;
  policyExplain?(args?: { audience?: "agent" | "assistant"; sessionKey?: string }): Promise<unknown>;
  testFlow?(req: TestFlowArgs): Promise<unknown>;
  policyPropose?(req: { edits: unknown; reason?: string; sessionKey?: string }): Promise<unknown>;
  policySchema?(): Promise<unknown>;
  close(): void;
}

/** Present the real client as a PolicyArbiter. An arbiter that predates an op
 *  fails the call (the tool answers an error, which is masked): never a guess. */
export class PolicyArbiterAdapter implements PolicyArbiter {
  constructor(private readonly client: RealArbiterClient) {}

  private need<K extends keyof RealArbiterClient>(op: K): NonNullable<RealArbiterClient[K]> {
    const fn = this.client[op];
    if (typeof fn !== "function") throw new Error(`arbiter has no '${String(op)}' op; restart the Mandu stack on the current build`);
    return (fn as (...a: unknown[]) => unknown).bind(this.client) as NonNullable<RealArbiterClient[K]>;
  }

  policyExplain(args: { audience: "agent"; sessionKey?: string }): Promise<unknown> {
    return this.need("policyExplain")(args);
  }

  async testFlow(req: TestFlowArgs): Promise<TestFlowAnswer> {
    return (await this.need("testFlow")(req)) as TestFlowAnswer;
  }

  async policyPropose(req: { edits: unknown; reason?: string; sessionKey?: string }): Promise<ProposeAnswer> {
    return (await this.need("policyPropose")(req)) as ProposeAnswer;
  }

  async policySchema(): Promise<{ edits: unknown }> {
    return (await this.need("policySchema")()) as { edits: unknown };
  }
}
