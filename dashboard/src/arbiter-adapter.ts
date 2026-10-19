/**
 * arbiter-adapter — the dashboard's ARBITER-CLIENT ADAPTER (the arbiter-client
 * pattern, CONTRIBUTING.md "Conventions"): a structural shape of the real arbiter
 * IPC client plus makeApprovalsArbiter(), which adapts one live connection
 * into the narrow per-route interfaces DashboardServer consumes
 * (ApprovalsArbiter / SecretsArbiter / PostureArbiter / ConfigAuditArbiter /
 * PolicyDocArbiter) and routes every human-decision WRITE over the admin
 * channel (policy-surface.md §2.6).
 *
 * Lifted verbatim out of server-main.ts (2026-09-11 overnight cleanup). It
 * MUST stay in dashboard/src: the runtime `import()` below resolves the
 * sibling arbiter package by a specifier RELATIVE TO THIS FILE
 * (dashboard/src → ../../arbiter/ipc/client.js).
 */
import type { Socket } from "node:net";

import type {
  ApprovalsArbiter,
  EgressApproval,
  ApprovalStatus,
  SecretsArbiter,
  ConfidentialityState,
  PathLabelResult,
  PostureArbiter,
  PostureChangeResult,
  ConfigAuditArbiter,
  PolicyDocArbiter,
  PolicyDocumentView,
  PolicyFileStatusRow,
  MintRuleInput,
} from "./server.js";
import type { PreviewResult } from "./policy-assistant.js";
import type { PathLevelsEntryWire } from "./view-model/file-browser.js";
import type { PolicyChangeRow, PolicyProposalRow } from "./view-model/policy-proposals.js";
import type { SuggestionWire, SuggestPolicyWire } from "./view-model/suggestions.js";
import type { ItemVersion } from "./server/policy-assistant-routes.js";
import type { SuggestPolicyOpts } from "./server/suggestion-routes.js";
import type { ModelEndpointFact, ModelPreviewWire, ModelRunWire } from "./view-model/suggestion-model.js";
import { adminUnavailableError } from "./server/http-util.js";
import type { WhySymbolWire } from "./server/arbiter-surfaces.js";
import type { FilterPromptWire, PromptFilterOrigin, PromptFilterPacksWire, PromptFiltersWire, PromptHoldAnswer, PromptHoldsWire, PromptPackEditWire, PromptVerdictScope } from "./server/prompt-filter-routes.js";

/**
 * Structural shape of the real arbiter IPC client (arbiter/ipc/client.ts) — just
 * the egress-approval ops the dashboard needs. Declared here (not imported) so
 * the dashboard package typechecks standalone; the runtime import below resolves
 * the sibling arbiter package via tsx/Node at runtime, NOT through tsc rootDir.
 */
export interface RealArbiterApprovalsClient {
  connect(): Promise<void>;
  /** Identity handshake; `humanSock` names the instance's human-plane socket
   *  (docs/design/architecture/arbiter-human-plane.md), absent on an older arbiter. */
  hello?(): Promise<{ humanSock?: string | null }>;
  egressApprovals(status?: ApprovalStatus): Promise<EgressApproval[]>;
  /** Admin-only (policy-surface.md §2.6) — travels the admin channel. */
  deleteSession?(sessionId: string): Promise<void>;
  /** The scope param is additive (policy-surface.md §9.8.7); the client
   *  forwards it onto the wire, and a pre-scope arbiter ignores it (verdict
   *  lands standing — the honest degrade). */
  resolveEgressApproval(
    approvalId: string,
    approve: boolean,
    scope?: "once" | "always",
    opts?: { strip?: boolean },
  ): Promise<EgressApproval>;
  /** Admin-only: forget a human verdict (dashboard.md §4.25c). Optional so an
   *  arbiter build predating the op degrades to a 501. */
  forgetEgressApproval?(approvalId: string): Promise<EgressApproval>;
  /** Plan 13 §5.4, §9 R2: the edit one *Always* of a holder's send question
   *  files. A data-socket READ (it applies nothing); optional, so an arbiter
   *  predating it degrades to a 501. */
  holderSourceBinding?(approvalId: string, path: string): Promise<{ edits: unknown[]; rule: string; relaxes: Array<{ facet: string; subject: string }>; basedOn?: ItemVersion[] }>;
  /** Confidentiality panel (plan 5). OPTIONAL so an older arbiter build without
   *  the op degrades to "panel disabled" rather than crashing the dashboard. */
  confidentialityState?(): Promise<ConfidentialityState>;
  /** The LABELING ACT (plan 6). Also optional, for the same back-compat reason —
   *  but see makeApprovalsArbiter: an arbiter that cannot label must FAIL the
   *  labeling call (→ 502), never silently accept it. */
  setPathLabel?(args: {
    path: string;
    confidentiality: string;
    bindings?: string[];
    recursive?: boolean;
  }): Promise<PathLabelResult>;
  removePathLabel?(path: string): Promise<boolean>;
  /** Clear a DERIVED taint record (plan 9). Optional for the same back-compat
   *  reason; the route answers 501 when the arbiter has no such op. */
  removeDerivedLabel?(path: string): Promise<boolean>;
  /** The file browser's labels (dashboard.md §4.25m), a data-socket READ.
   *  Optional: a pre-§4.25m arbiter → labels shown as unknown. */
  pathLevels?(paths: string[], home?: string, withEdits?: unknown): Promise<{ axis: boolean; levels: PathLevelsEntryWire[] }>;
  whyPath?(path: string, home?: string): Promise<unknown>;
  /** ADMIN: move the page's older rules into policy.yaml (§4.25m). */
  movePageLabels?(requestedBy?: string): Promise<{ moved: number; changeId: string | null }>;
  /** Policy DOCUMENT ops (stage 5a) — reads on the data socket, writes admin-only. */
  policyDocument?(): Promise<PolicyDocumentView>;
  applyPolicyDocument?(document: unknown, requestedBy: string | undefined, lawHash: string): Promise<{ path: string; status: PolicyFileStatusRow }>;
  mintUserRule?(rule: MintRuleInput, requestedBy?: string): Promise<{ id: string; path: string; status: PolicyFileStatusRow }>;
  exportDbLabels?(requestedBy?: string): Promise<{ added: number; path: string; status: PolicyFileStatusRow }>;
  /** Test a flow (§4) — a data-socket read; absent on a pre-tester arbiter (route → 501). */
  testFlow?(req: unknown): Promise<unknown>;
  /** The policy agent surface (policy-surface.md §8.4.2): the reads ride
   *  the data socket, approve / undo are ADMIN-ONLY. Optional: an arbiter
   *  predating them → the routes answer 501. */
  policyProposals?(status?: PolicyProposalRow["status"]): Promise<{ proposals: PolicyProposalRow[] }>;
  policyChanges?(limit?: number): Promise<{ changes: PolicyChangeRow[] }>;
  resolvePolicyProposal?(proposalId: string, verdict: "approved" | "denied", requestedBy?: string): Promise<{
    proposal: PolicyProposalRow;
    changeId?: string;
    refiled?: PolicyProposalRow;
    stale?: string[];
  }>;
  undoPolicyChange?(changeId: string, requestedBy?: string): Promise<{ changeId: string; undone: string }>;
  /** Plan 14's policy suggestions (dashboard.md §4.25r): the scan and the
   *  list are DATA-socket ops (the scan only files tightenings); "Not a
   *  secret" is ADMIN-ONLY. Applying from the dashboard is
   *  `resolvePolicyProposal` on the admin channel. Optional: an arbiter
   *  predating plan 14 → the routes answer 501. */
  suggestPolicy?(roots: string[], opts?: SuggestPolicyOpts): Promise<SuggestPolicyWire>;
  policySuggestions?(status?: SuggestionWire["status"]): Promise<{ suggestions: SuggestionWire[] }>;
  dismissSuggestion?(suggestionId: string, requestedBy?: string): Promise<{ suggestion: SuggestionWire }>;
  /** Plan 14 §14.5, §14.11: the model picker's two DATA-socket ops (what
   *  they may send is gated in the arbiter; what they file only tightens or
   *  waits for a person) and the declared models (a read). */
  modelSuggestPreview?(roots: string[], opts: { tier: "names" | "contents"; endpoint?: string; home?: string; includeHome?: boolean }): Promise<ModelPreviewWire>;
  modelSuggest?(digest: string, opts?: { waitMs?: number }): Promise<ModelRunWire>;
  modelEndpoints?(): Promise<ModelEndpointFact[]>;
  /** "Describe what you want" (policy-surface.md §8.5.2): three reads on
   *  the data socket (the assistant's context + the preview) and propose,
   *  which the dashboard sends over the ADMIN channel (a human's Apply). */
  policyExplain?(args: { audience?: "agent" | "assistant" }): Promise<unknown>;
  policySchema?(): Promise<{ edits: unknown }>;
  policyPreview?(edits: unknown): Promise<PreviewResult>;
  policyPropose?(req: { edits: unknown; reason?: string; requestedBy?: string; basedOn?: ItemVersion[] }): Promise<
    | { applied: true; changeId: string | null }
    | { applied: false; proposalId: string; relaxes: Array<{ facet: string; subject: string }> }
    | { applied: false; refused: string; problems: string[]; changed?: string[] }
  >;
  /** The posture op behind POST /api/policy/posture (dashboard.md §4.19).
   *  Optional (a pre-posture arbiter build → route disabled, 404). The client
   *  forwards args verbatim onto the wire, so the additive `allowRelax` flag
   *  rides through even on a client build whose own signature predates it. */
  setSessionPosture?(args: {
    posture: "normal" | "lockdown";
    sessionId?: string;
    requestedBy?: string;
    allowRelax?: boolean;
  }): Promise<PostureChangeResult>;
  /** The observability event stream behind the §4.19 config_change audit
   *  (config-axes-routes.ts ConfigAuditArbiter). Both ops have been on the
   *  client since the event store landed; optional anyway so a stripped-down
   *  build degrades to "no audit trail", never a crash. */
  emit?(event: Record<string, unknown>): Promise<number>;
  /** The prompt filter (confidentiality-plan-15 §8.1): the filters (a data-
   *  socket read, no value) and `filterPrompt`, which the dashboard calls
   *  ONLY with `dryRun: true` on the HUMAN-plane client (the arbiter refuses
   *  a dry run on the data socket). Optional: an arbiter predating plan 15
   *  → the panel's routes answer 501. */
  promptFilters?(): Promise<PromptFiltersWire>;
  /** Plan 15 §13.7 item 4: the exceptions WITH their patterns (HUMAN plane
   *  only); `promptFilters` lists them without. */
  promptExceptions?(): Promise<{ exceptions: NonNullable<PromptFiltersWire["exceptions"]> }>;
  /** Phase 2: every pack in full (HUMAN plane only) and the pack editor
   *  (ADMIN channel only). */
  promptFilterPacks?(): Promise<PromptFilterPacksWire>;
  promptPackEdit?(args: { edits: unknown; dryRun?: boolean; sample?: string; requestedBy?: string }): Promise<PromptPackEditWire>;
  /** Phase 3: the held prompts (HUMAN plane only), the answer and "let it
   *  through" (ADMIN channel only). */
  promptHolds?(): Promise<PromptHoldsWire>;
  resolvePromptHold?(args: { approvalId: string; answer: PromptHoldAnswer; scope?: PromptVerdictScope }): Promise<{ approval: unknown }>;
  letPromptFindingThrough?(args: { session: string; category: string; ref: string; turn?: string; scope: PromptVerdictScope }): Promise<{ approval: unknown }>;
  filterPrompt?(args: {
    session?: string;
    agent: string;
    segments: Array<{ id: string; origin: PromptFilterOrigin; text: string }>;
    dryRun?: boolean;
  }): Promise<FilterPromptWire>;
  events?(sessionId: string, sinceSeq?: number): Promise<Record<string, unknown>[]>;
  /** "Why is this masked?" (plan 15 §13.8; dashboard.md §4.33): HUMAN plane
   *  only (the arbiter refuses it on the data socket). Positional args, as
   *  the client sends them. Optional: an older arbiter → the route's 501. */
  whySymbol?(symbol: string, session?: string): Promise<WhySymbolWire>;
  close(): void;
}

/**
 * Build the real arbiter client and adapt it to {@link ApprovalsArbiter}, OR
 * return undefined when no arbiter socket is configured (so the routes answer
 * 404 "arbiter not connected"). Mirrors anthropic-proxy/src/server-main.ts: a runtime
 * `import()` of a string-built specifier keeps arbiter/**.ts out of this package's
 * tsc program. Returns the adapter plus a close() to release the connection.
 */
/**
 * Where the ADMIN CHANNEL is right now (policy-surface.md §2.6): the
 * parent end of the socketpair our supervisor spawned the arbiter with, or —
 * dev/test rigs only — the MANDU_ADMIN_SOCK path. Resolved per call, never
 * cached by the caller: a restart yields a new socket; an adopted arbiter
 * yields undefined, and every human-decision write then fails 503 with the
 * remedy in the message instead of silently reaching the data socket.
 */
export type AdminTarget = { socket: Socket } | { socketPath: string };

export async function makeApprovalsArbiter(
  sock: string,
  adminTarget: () => AdminTarget | undefined,
): Promise<
  | {
      arbiter: ApprovalsArbiter;
      secrets?: SecretsArbiter;
      posture?: PostureArbiter;
      audit?: ConfigAuditArbiter;
      policyDoc?: PolicyDocArbiter;
      /** Session deletion for the event source (admin-only op). */
      deleteSession: (sessionId: string) => Promise<void>;
      close: () => void;
    }
  | undefined
> {
  try {
    // Specifier built at runtime so tsc does NOT statically resolve the sibling
    // arbiter package into this package's rootDir (would break the standalone
    // typecheck). dashboard/src → ../../arbiter/ipc/client.js.
    // A BUNDLED build (packaging.md §5) sets MANDU_ARBITER_CLIENT_MODULE to the
    // co-located dist/arbiter-client.mjs; unset in dev/tsx → the relative source.
    const specifier =
      process.env["MANDU_ARBITER_CLIENT_MODULE"] ?? ["..", "..", "arbiter", "ipc", "client.js"].join("/");
    const mod = (await import(specifier)) as {
      ArbiterClient: new (target: string | { socket: Socket }) => RealArbiterApprovalsClient;
    };
    // READS ride the data socket like any interceptor; WRITES (human decisions)
    // ride the admin channel, resolved lazily so a restarted arbiter gets a
    // fresh client and an adopted one gets the honest refusal.
    const client = new mod.ArbiterClient(sock);
    await client.connect();
    let cachedAdmin: { key: unknown; client: RealArbiterApprovalsClient } | undefined;
    // The HUMAN PLANE (arbiter-human-plane.md): `events` returns originals and
    // is served only on the human socket — $MANDU_ARBITER_HUMAN_SOCK, else the
    // one this instance names in `hello`. Resolved per call like the admin
    // channel (a restarted arbiter binds a new one); never the data socket.
    let cachedHuman: { path: string; client: RealArbiterApprovalsClient } | undefined;
    const humanClient = async (): Promise<RealArbiterApprovalsClient> => {
      const explicit = process.env["MANDU_ARBITER_HUMAN_SOCK"];
      const named = explicit || (client.hello ? (await client.hello()).humanSock : null);
      if (typeof named !== "string" || named === "") {
        throw new Error("human plane unavailable: the arbiter names no human socket");
      }
      if (cachedHuman && cachedHuman.path === named) return cachedHuman.client;
      if (cachedHuman) {
        try { cachedHuman.client.close(); } catch { /* already gone */ }
      }
      const c = new mod.ArbiterClient(named);
      await c.connect();
      cachedHuman = { path: named, client: c };
      return c;
    };
    const adminClient = async (): Promise<RealArbiterApprovalsClient> => {
      const target = adminTarget();
      if (!target) {
        throw adminUnavailableError(
          "this dashboard did not start the arbiter (adopted instance), so it holds no admin channel — " +
            "restart the services from Settings to regain control of approvals, labels, pause and deletion",
        );
      }
      const key = "socket" in target ? target.socket : target.socketPath;
      if (cachedAdmin && cachedAdmin.key === key) return cachedAdmin.client;
      if (cachedAdmin) {
        try { cachedAdmin.client.close(); } catch { /* already gone */ }
      }
      const c = new mod.ArbiterClient("socket" in target ? { socket: target.socket } : target.socketPath);
      await c.connect();
      cachedAdmin = { key, client: c };
      return c;
    };
    const arbiter: ApprovalsArbiter = {
      egressApprovals: (status) => client.egressApprovals(status),
      resolveEgressApproval: async (approvalId, approve, scope, opts) => {
        const approval = opts?.strip === true
          ? await (await adminClient()).resolveEgressApproval(approvalId, approve, scope, { strip: true })
          : await (await adminClient()).resolveEgressApproval(approvalId, approve, scope);
        // The same skew guard for "Send without it": an arbiter predating it
        // drops the field and stores a plain Block, standing (stricter, but
        // not the answer given). Say so instead of a quiet 200.
        if (opts?.strip === true && approval.strip !== true) {
          throw new Error(
            "the connected Mandu service predates Send without it — this answer was stored as Block; restart the Mandu stack on the current build, then remove the answer under Rules",
          );
        }
        // Skew guard: a pre-scope client/arbiter build drops the positional
        // scope arg, silently landing a STANDING grant for an "Allow once"
        // click — MORE authority than the human chose. Surface that loudly
        // (the route turns this into an error the shell renders) instead of
        // returning 200 for a verdict that was not stored as asked.
        if (scope === "once" && approval.scope !== "once") {
          throw new Error(
            "the connected arbiter predates single-use verdicts — this answer was stored as standing; reverse it under Permissions if that is not what you wanted",
          );
        }
        return approval;
      },
      // A read (plan 13 §5.4): the edit is applied by the route on the
      // admin channel (applyAsHuman), never here. Positional args, as the
      // real client takes them (the stack test builds this wiring).
      ...(client.holderSourceBinding
        ? { holderSourceBinding: (approvalId: string, path: string) => client.holderSourceBinding!(approvalId, path) }
        : {}),
      ...(client.forgetEgressApproval
        ? { forgetEgressApproval: async (approvalId: string) => {
            const admin = await adminClient();
            if (!admin.forgetEgressApproval) throw new Error("arbiter has no 'forgetEgressApproval' op");
            return admin.forgetEgressApproval(approvalId);
          } }
        : {}),
    };
    // The confidentiality panel rides the SAME connection (one client, one read
    // surface + the labeling act). An arbiter without the READ op → panel
    // disabled (404), never a crash and never a silent "no secrets confined".
    // An arbiter with the read op but WITHOUT the label ops (a build predating
    // plan 6) keeps the panel readable and makes a labeling attempt THROW —
    // which the route surfaces as a 502. The one thing that must never happen is
    // a 200 for a label that was never stored.
    const unsupported = (op: string) => (): never => {
      throw new Error(`arbiter has no '${op}' op — upgrade the arbiter to label paths`);
    };
    const secrets: SecretsArbiter | undefined = client.confidentialityState
      ? {
          confidentialityState: () => client.confidentialityState!(),
          setPathLabel: (args) =>
            client.setPathLabel ? adminClient().then((a) => a.setPathLabel!(args)) : unsupported("setPathLabel")(),
          removePathLabel: (path) =>
            client.removePathLabel ? adminClient().then((a) => a.removePathLabel!(path)) : unsupported("removePathLabel")(),
          // Plan 9's release act. Left UNDEFINED (not a throwing stub) when the
          // arbiter lacks the op: the route then answers 501 and the UI shows no
          // derived rows — which is the truth, since an arbiter with no derived
          // store has none to show.
          ...(client.removeDerivedLabel
            ? { removeDerivedLabel: (path: string) => adminClient().then((a) => a.removeDerivedLabel!(path)) }
            : {}),
          // The file browser's labels: a READ, so the data socket, forwarded
          // as two positional args (the parity e2e builds this wiring).
          ...(client.pathLevels
            ? { pathLevels: (paths: string[], home?: string, withEdits?: unknown) => client.pathLevels!(paths, home, withEdits) }
            : {}),
          ...(client.whyPath ? { whyPath: (path: string, home?: string) => client.whyPath!(path, home) } : {}),
        }
      : undefined;
    // The posture surface rides the SAME connection (dashboard.md §4.19). An
    // arbiter build without the op → surface undefined → the route answers
    // 404, never a silently-dropped pause/resume.
    // The policy READS (the document, the rule-change queue, its history)
    // ride the HUMAN plane: on the data socket the arbiter answers them with
    // every prompt exception's pattern replaced by a placeholder (plan 15
    // §13.7 item 4), and the dashboard shows the person's own patterns. An
    // arbiter that names no human socket is read on the data socket: the
    // patterns then show as the placeholder, which the arbiter refuses to
    // write back. The three writers ride the admin channel like every human
    // decision.
    const policyRead = async (): Promise<RealArbiterApprovalsClient> => {
      try {
        return await humanClient();
      } catch (err) {
        if (/human plane unavailable/.test(String((err as Error)?.message ?? err))) return client;
        throw err;
      }
    };
    const policyDoc: PolicyDocArbiter | undefined = client.policyDocument
      ? {
          policyDocument: () => policyRead().then((c) => (c.policyDocument ?? client.policyDocument!).call(c)),
          applyPolicyDocument: (document, requestedBy, lawHash) =>
            adminClient().then((a) =>
              a.applyPolicyDocument ? a.applyPolicyDocument(document, requestedBy, lawHash) : unsupported("applyPolicyDocument")(),
            ),
          mintUserRule: (rule, requestedBy) =>
            adminClient().then((a) => (a.mintUserRule ? a.mintUserRule(rule, requestedBy) : unsupported("mintUserRule")())),
          exportDbLabels: (requestedBy) =>
            adminClient().then((a) => (a.exportDbLabels ? a.exportDbLabels(requestedBy) : unsupported("exportDbLabels")())),
          ...(client.movePageLabels
            ? { movePageLabels: (requestedBy?: string) => adminClient().then((a) => (a.movePageLabels ? a.movePageLabels(requestedBy) : unsupported("movePageLabels")())) }
            : {}),
          // The tester is a READ on the data socket (nothing written, nothing
          // queued) — no admin channel needed; absent op ⇒ absent method ⇒ 501.
          ...(client.testFlow ? { testFlow: (r) => client.testFlow!(r) } : {}),
          // The Prompt filters panel (plan 15 §8.1, read-only in phase 1): the
          // filters are a data-socket READ; the test bench is a DRY RUN, which
          // the arbiter serves only on the HUMAN plane, so it never touches
          // the data client (the parity e2e builds this wiring).
          // The exceptions' patterns are not in the data-socket answer (plan
          // 15 §13.7 item 4): they are read from the HUMAN plane
          // (`promptExceptions`) and put back in. An arbiter that still sends
          // them in `promptFilters` (before 2026-10-03) is answered as is.
          ...(client.promptFilters
            ? {
                promptFilters: async () => {
                  const pf = await client.promptFilters!();
                  const listed = Array.isArray(pf.exceptions) ? pf.exceptions : [];
                  if (listed.length === 0 || listed.every((e) => typeof e.match === "string")) return pf;
                  const h = await humanClient();
                  if (!h.promptExceptions) throw new Error("arbiter client has no 'promptExceptions' op");
                  return { ...pf, exceptions: (await h.promptExceptions()).exceptions };
                },
              }
            : {}),
          ...(client.filterPrompt
            ? {
                filterPromptDryRun: async (args: { agent: string; segments: Array<{ id: string; origin: PromptFilterOrigin; text: string }> }) => {
                  const h = await humanClient();
                  if (!h.filterPrompt) throw new Error("arbiter client has no 'filterPrompt' op");
                  return h.filterPrompt({ agent: args.agent, segments: args.segments, dryRun: true });
                },
              }
            : {}),
          // Plan 15 phase 2: the packs in full ride the HUMAN plane (the
          // arbiter refuses them on the data socket); the pack editor is a
          // human decision and rides the ADMIN channel. Forwarded as one
          // object each (the parity e2e builds this wiring).
          ...(client.promptFilterPacks
            ? {
                promptFilterPacks: async () => {
                  const h = await humanClient();
                  if (!h.promptFilterPacks) throw new Error("arbiter client has no 'promptFilterPacks' op");
                  return h.promptFilterPacks();
                },
              }
            : {}),
          ...(client.promptPackEdit
            ? {
                promptPackEdit: (args: { edits: unknown; dryRun?: boolean; sample?: string; requestedBy?: string }) =>
                  adminClient().then((a) => (a.promptPackEdit ? a.promptPackEdit(args) : unsupported("promptPackEdit")())),
              }
            : {}),
          // Plan 15 phase 3 (§7, §13.6): the held prompts carry the human's
          // own found text, so they ride the HUMAN plane (the arbiter refuses
          // them on the data socket); the answer and "let it through" send
          // that text as written, a human decision on the ADMIN channel (from
          // the data socket the arbiter refuses them: a claimed answer). One
          // object each (the parity e2e builds this wiring).
          ...(client.promptHolds
            ? {
                promptHolds: async () => {
                  const h = await humanClient();
                  if (!h.promptHolds) throw new Error("arbiter client has no 'promptHolds' op");
                  return h.promptHolds();
                },
              }
            : {}),
          // "Why is this masked?" (plan 15 §13.8; dashboard.md §4.33): the
          // answer is read from the session events, so the arbiter serves it
          // on the HUMAN plane only; never the data client. Forwarded as two
          // positional args (the parity e2e builds this wiring).
          ...(client.whySymbol
            ? {
                whySymbol: async (symbol: string, session?: string) => {
                  const h = await humanClient();
                  if (!h.whySymbol) throw new Error("arbiter client has no 'whySymbol' op");
                  return h.whySymbol(symbol, session);
                },
              }
            : {}),
          ...(client.resolvePromptHold
            ? {
                resolvePromptHold: (args: { approvalId: string; answer: PromptHoldAnswer; scope?: PromptVerdictScope }) =>
                  adminClient().then((a) => (a.resolvePromptHold ? a.resolvePromptHold(args) : unsupported("resolvePromptHold")())),
              }
            : {}),
          ...(client.letPromptFindingThrough
            ? {
                letPromptFindingThrough: (args: { session: string; category: string; ref: string; turn?: string; scope: PromptVerdictScope }) =>
                  adminClient().then((a) => (a.letPromptFindingThrough ? a.letPromptFindingThrough(args) : unsupported("letPromptFindingThrough")())),
              }
            : {}),
          // Rule-change requests (policy-surface.md §8.4.2): the queue and
          // the history are READS on the human plane (policyRead, above);
          // approve and undo are human decisions and ride the admin channel
          // like mintUserRule.
          ...(client.policyProposals ? { policyProposals: (status) => policyRead().then((c) => (c.policyProposals ?? client.policyProposals!).call(c, status)) } : {}),
          ...(client.policyChanges ? { policyChanges: (limit) => policyRead().then((c) => (c.policyChanges ?? client.policyChanges!).call(c, limit)) } : {}),
          ...(client.resolvePolicyProposal
            ? {
                resolvePolicyProposal: (id, verdict, requestedBy) =>
                  adminClient().then((a) =>
                    a.resolvePolicyProposal ? a.resolvePolicyProposal(id, verdict, requestedBy) : unsupported("resolvePolicyProposal")(),
                  ),
              }
            : {}),
          ...(client.undoPolicyChange
            ? {
                undoPolicyChange: (id, requestedBy) =>
                  adminClient().then((a) => (a.undoPolicyChange ? a.undoPolicyChange(id, requestedBy) : unsupported("undoPolicyChange")())),
              }
            : {}),
          // Plan 14's suggestions (dashboard.md §4.25r): the scan and the
          // list are READS/filings on the data socket (the arbiter files only
          // tightenings, as mandu:scan); "Not a secret" withholds protection,
          // so it rides the ADMIN channel. Apply is resolvePolicyProposal
          // above (admin). Forwarded as positional args (the parity e2e
          // builds this wiring).
          ...(client.suggestPolicy
            ? { suggestPolicy: (roots: string[], opts?: SuggestPolicyOpts) => client.suggestPolicy!(roots, opts) }
            : {}),
          ...(client.policySuggestions ? { policySuggestions: (status?: SuggestionWire["status"]) => client.policySuggestions!(status) } : {}),
          // The model picker (plan 14 §14.11): data-socket ops, forwarded as
          // positional args (the integration oracle builds this wiring).
          ...(client.modelSuggestPreview
            ? { modelSuggestPreview: (roots: string[], opts: { tier: "names" | "contents"; endpoint?: string; home?: string; includeHome?: boolean }) => client.modelSuggestPreview!(roots, opts) }
            : {}),
          ...(client.modelSuggest ? { modelSuggest: (digest: string, opts?: { waitMs?: number }) => client.modelSuggest!(digest, opts) } : {}),
          ...(client.modelEndpoints ? { modelEndpoints: () => client.modelEndpoints!() } : {}),
          ...(client.dismissSuggestion
            ? {
                dismissSuggestion: (id: string, requestedBy?: string) =>
                  adminClient().then((a) => (a.dismissSuggestion ? a.dismissSuggestion(id, requestedBy) : unsupported("dismissSuggestion")())),
              }
            : {}),
          // "Describe what you want" (§5.2): the context and the preview are
          // READS; propose rides the ADMIN channel because it is the person's
          // Apply (a loosening then waits one step, for the same click to approve).
          ...(client.policyExplain ? { policyExplain: (args) => client.policyExplain!(args) } : {}),
          ...(client.policySchema ? { policySchema: () => client.policySchema!() } : {}),
          ...(client.policyPreview ? { policyPreview: (edits) => client.policyPreview!(edits) } : {}),
          ...(client.policyPropose
            ? { policyPropose: (r) => adminClient().then((a) => (a.policyPropose ? a.policyPropose(r) : unsupported("policyPropose")())) }
            : {}),
        }
      : undefined;
    const posture: PostureArbiter | undefined = client.setSessionPosture
      ? { setSessionPosture: (args) => adminClient().then((a) => a.setSessionPosture!(args)) }
      : undefined;
    // The §4.19 config_change audit trail: emit on an applied axis write
    // (data socket) + the events read-back for the GET attribution (the human
    // socket — `events` is human-plane only). Best-effort by contract — absent
    // ops or no human plane just mean no audit, never a 404.
    const audit: ConfigAuditArbiter | undefined = client.emit && client.events
      ? {
          // The audit stream takes no claim (arbiter-human-plane.md §10.2):
          // the admin channel, else the human socket; the data socket, which
          // the arbiter refuses for that stream, only as the last word.
          emit: async (event) => {
            for (const pick of [adminClient, humanClient]) {
              try {
                const c = await pick();
                if (c.emit) return await c.emit(event);
              } catch { /* the next channel */ }
            }
            return client.emit!(event);
          },
          events: async (sessionId, sinceSeq) => {
            const h = await humanClient();
            if (!h.events) throw new Error("arbiter client has no 'events' op");
            return h.events(sessionId, sinceSeq);
          },
        }
      : undefined;
    const deleteSession = async (sessionId: string): Promise<void> => {
      const a = await adminClient();
      if (!a.deleteSession) throw new Error("arbiter has no 'deleteSession' op — upgrade the arbiter");
      await a.deleteSession(sessionId);
    };
    console.error(`[dashboard] egress approvals: arbiter @ ${sock}`);
    return {
      arbiter,
      secrets,
      posture,
      audit,
      deleteSession,
      policyDoc,
      close: () => {
        client.close();
        try { cachedAdmin?.client.close(); } catch { /* already gone */ }
        try { cachedHuman?.client.close(); } catch { /* already gone */ }
      },
    };
  } catch (err) {
    // Best-effort: a missing/unreachable arbiter simply leaves the approval
    // routes disabled (404 "arbiter not connected"); the rest of the dashboard
    // still serves. The control plane can later start the arbiter.
    console.error(`[dashboard] egress approvals disabled: ${(err as Error).message}`);
    return undefined;
  }
}
