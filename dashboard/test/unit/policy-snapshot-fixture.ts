/**
 * policy-snapshot-fixture — a policy snapshot (the arbiter's `policySnapshot`
 * shape) with two built-in gates, three usage rules and two egress verdicts,
 * one of them pending with a hostile destination, for the suites that build
 * the policy panel's view-model (the product's agent page and Rules, and
 * the developer view's egress panel).
 */
import type { PolicySnapshot } from "../../src/policy-model.js";

// A hostile string that must render INERT (textContent, never innerHTML).
export const HOSTILE = '/opt/x <img src=x onerror="window.__pwned=1">';

export function snapshot(): PolicySnapshot {
  return {
    specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__",
    posture: { integrity: true, confidentiality: false },
    egressPosture: "lockdown",
    lawSource: { kind: "builtin" },
    usage: {
      rules: [
        { id: "fs:sensitive-path", source: "rule", boundary: "filesystem", outcome: "deny+approval", summary: "built-in sensitive prefix", gate: "fs" },
        { id: "fs:default-deny", source: "fail-closed", boundary: "filesystem", outcome: "deny+approval", summary: "out-of-workspace fail-closed", gate: "fs" },
        { id: "egress:trusted-destination", source: "rule", boundary: "network", outcome: "allow", summary: "trusted URL category", gate: "egress" },
      ],
      sensitivePaths: ["~/.ssh"],
      gates: [
        { id: "fs", title: "filesystem path gate", definedIn: "arbiter/policy/fs-outbound.ts (decideFsPath)", doc: "fs-sync.md §1.4.1", evaluation: "first match wins" },
        { id: "egress", title: "egress desymbolization gate", definedIn: "arbiter/policy/policy-interface.ts", doc: "mandu.md §4", evaluation: "first matching branch decides" },
      ],
    },
    verdicts: [
      { id: "egr-1", symbol: "fs:Read:read", destination: HOSTILE, status: "pending", reason: "fs gate denied", count: 2, firstSeen: 10, lastSeen: 40 },
      { id: "egr-2", symbol: "$MDU:Read[aa].x", destination: "evil.test", status: "approved", reason: "r", count: 1, firstSeen: 5, lastSeen: 20, resolvedAt: 30, sessions: ["s1"] },
    ],
  };
}
