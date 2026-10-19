/**
 * held-disk — test helper for suites that hand-edit policy.yaml under a
 * running arbiter (policy-surface.md §8.4.6). A disk change that relaxes
 * the law is HELD until a human approves it; a suite whose subject is the
 * reload itself (not the hold) approves it here the way the dashboard's Inbox
 * does (`resolvePolicyProposal` → PolicyAgentOps.resolve), in process.
 * Mandu-new (no reference origin).
 */
import type { ArbiterServer } from "../ipc/server.js";

interface Internals {
  policyDocs: { pollDisk(): boolean; heldChange: { hash: string } | null };
  policyProposals: { pendingDisk(hash: string): { id: string } | undefined };
  policyAgent: { resolve(id: string, verdict: "approved" | "denied", by: string): unknown };
}

/** If a disk change is held, approve it; returns whether one was. */
export function approveHeldDiskChange(server: ArbiterServer): boolean {
  const s = server as unknown as Internals;
  const held = s.policyDocs.heldChange;
  if (!held) return false;
  const p = s.policyProposals.pendingDisk(held.hash);
  if (!p) throw new Error("a held disk change has no pending proposal");
  s.policyAgent.resolve(p.id, "approved", "test");
  return true;
}

/** Run the hand-edit poll now; if the change was held, approve it. Returns
 *  what the poll returned (true: a change was seen). */
export function pollDiskApproving(server: ArbiterServer): boolean {
  const seen = (server as unknown as Internals).policyDocs.pollDisk();
  approveHeldDiskChange(server);
  return seen;
}
