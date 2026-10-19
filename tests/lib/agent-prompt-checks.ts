/**
 * agent-prompt-checks.ts — the prompt filter's arrange and verdicts for one
 * run of the shared Anthropic-wire live runner (OpenClaw · OpenCode)
 * (confidentiality-plan-15-prompt-filter.md §3, phase 1). Mandu-new.
 *
 * Arrange: the scenario's values registered on the run's private arbiter as
 * the launcher registers the environment (`registerEnvSecrets`). Verdicts,
 * over the bytes the model endpoint received:
 *   - prompt-key-absent   the pasted key never reached the model raw;
 *   - prompt-key-symbol   it reached the model as its OWN symbol (the one the
 *                         registration minted);
 *   - prompt-floor        the human's typed text reached the model with only
 *                         the key replaced: `postgres`, registered but under
 *                         the prompt floor, as typed;
 *   - prompt-human-reveal the human plane's desymbolize turns that text back
 *                         into what was typed.
 */

import type { ArbiterClient } from "../../arbiter/ipc/client.js";
import type { PolicyFileConfig } from "../../arbiter/policy/load-policy.js";
import type { AssertionCheck } from "./assertions.js";
import type { AgentScenario, PromptPolicyExpectation, PromptSecretExpectation } from "./agent-scenario.js";
import { confCheck } from "./conf-oracle.js";

/** Register the scenario's values; returns the key's symbol. Throws when
 *  the registration did not land (every oracle below would be vacuous). */
export async function registerPromptSecrets(client: ArbiterClient, ps: PromptSecretExpectation): Promise<string> {
  const reg = await client.registerEnvSecrets({ vars: [{ name: "PARTNER_API_KEY", value: ps.canary }, { name: "DB_PASSWORD", value: "postgres" }] });
  const key = reg.vars.find((v) => v.name === "PARTNER_API_KEY")?.symbol;
  const weak = reg.vars.find((v) => v.name === "DB_PASSWORD")?.symbol;
  if (!key || !weak) throw new Error(`registerEnvSecrets did not register the prompt-filter values: ${JSON.stringify(reg)}`);
  return key;
}

export async function promptChecks(o: {
  s: AgentScenario;
  ps: PromptSecretExpectation;
  keySym: string;
  wire: string[];
  human: ArbiterClient;
}): Promise<AssertionCheck[]> {
  const { s, ps, keySym, wire } = o;
  const forwarded = ps.typed.split(ps.canary).join(keySym);
  const raw = wire.filter((b) => b.includes(ps.canary)).length;
  const withSym = wire.filter((b) => b.includes(keySym)).length;
  const exact = wire.some((b) => b.includes(forwarded));
  // What the wire carried around the typed text's first word, for the
  // failure reason (symbolized bytes: the key never appears on a passing
  // prompt-key-absent run).
  const head = ps.typed.split(" ")[0]!;
  const body = wire.find((b) => b.includes(head)) ?? "";
  const at = body.indexOf(head);
  const around = at < 0 ? "(the typed text's first word is on no request)" : body.slice(Math.max(0, at - 300), at + 300);
  if (!exact) console.error(`[${s.name}] prompt-floor: the wire around the typed text: ${JSON.stringify(around)}`);
  let revealed = "";
  try { revealed = await o.human.desymbolize(forwarded); } catch (err) { revealed = `(desymbolize failed: ${(err as Error).message})`; }
  return [
    confCheck("prompt-key-absent", `${s.name}: a registered key pasted into the prompt never reaches the model raw`,
      wire.length > 0 && raw === 0, `the key is on none of ${wire.length} captured request(s)`,
      wire.length === 0 ? "no request reached the model endpoint: the oracle is vacuous" : `CONFIDENTIALITY VIOLATION: the key is on ${raw} request(s)`),
    confCheck("prompt-key-symbol", `${s.name}: the key reaches the model as its own symbol`,
      withSym > 0, `${keySym} is on ${withSym} request(s)`, `the key's symbol ${keySym} is on no request`),
    confCheck("prompt-floor", `${s.name}: the human's text reaches the model with only the key replaced (postgres, under the prompt floor, as typed)`,
      exact, "the typed text, key masked, postgres as typed, is on the wire",
      `the typed text with only the key masked is on no request (the agent's wire did not place it as the human's, or postgres was masked): expected ${JSON.stringify(forwarded)}; the wire around it: ${JSON.stringify(around)}`),
    confCheck("prompt-human-reveal", `${s.name}: the human plane restores what was typed`,
      revealed === ps.typed, "desymbolize returns the typed prompt", `desymbolize returned ${JSON.stringify(revealed)}`),
  ];
}

/** The policy a `promptPolicy` scenario's arbiter enforces (plan 15 phase
 *  2): `key-shapes` on; a key shape's default action is `redact`. */
export const PROMPT_POLICY: PolicyFileConfig = { version: 1, prompt_filters: { filters: { "key-shapes": "on" } } };

/** The verdicts of a `promptPolicy` scenario, over the bytes the model
 *  endpoint received:
 *   - prompt-policy-absent    the unregistered token never reached the model;
 *   - prompt-policy-redacted  the human's text reached it with the token as
 *                             `[redacted: <category>]` and nothing else changed. */
export function promptPolicyChecks(o: { s: AgentScenario; pp: PromptPolicyExpectation; wire: string[] }): AssertionCheck[] {
  const { s, pp, wire } = o;
  const forwarded = pp.typed.split(pp.token).join(`[redacted: ${pp.category}]`);
  const raw = wire.filter((b) => b.includes(pp.token)).length;
  const exact = wire.some((b) => b.includes(forwarded));
  if (!exact) {
    const head = pp.typed.split(" ")[0]!;
    const body = wire.find((b) => b.includes(head)) ?? "";
    const at = body.indexOf(head);
    console.error(`[${s.name}] prompt-policy-redacted: the wire around the typed text: ${JSON.stringify(at < 0 ? "(not on the wire)" : body.slice(Math.max(0, at - 300), at + 300))}`);
  }
  return [
    confCheck("prompt-policy-absent", `${s.name}: a credential nobody registered, pasted into the prompt, never reaches the model under key-shapes`,
      wire.length > 0 && raw === 0, `the token is on none of ${wire.length} captured request(s)`,
      wire.length === 0 ? "no request reached the model endpoint: the oracle is vacuous" : `CONFIDENTIALITY VIOLATION: the token is on ${raw} request(s)`),
    confCheck("prompt-policy-redacted", `${s.name}: the human's text reaches the model with the token as [redacted: ${pp.category}]`,
      exact, "the typed text, token redacted, is on the wire", `expected ${JSON.stringify(forwarded)} on the wire`),
  ];
}
