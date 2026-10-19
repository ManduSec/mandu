/**
 * policy-engine — the TrustCategory registry for the data-trust policy.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Lifted from
 *     https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/policy/policy-engine.ts
 *   Purpose: PolicyEngine is the typed lookup table of TrustCategory instances
 *   (it implements resolve-schema's CategoryLookup). createPolicyEngine() builds
 *   it from the YAML policy + the intrinsic per-category defaults, and applies
 *   any per-tool inbound overrides. This is the assembly point that wires the
 *   origin rules (trust-category) and the schema rules (tool-inbound) together.
 *
 *   Adaptation for Mandu — FLAGGED:
 *     RESTORED in this lift: the COMMAND (exec-output) override branch, which
 *     merges per-command schemas via `mergeCommandOverrides` from
 *     `exec-inbound.ts`. Sub-step 1 had stripped that import + branch; it is
 *     wired back in now that the exec policy family is lifted. The INBOUND
 *     category registration (URL/CHANNEL/DIR, new + legacy YAML) and the per-tool
 *     inbound override merge are preserved exactly.
 *
 *   Intrinsic "no policy" category defaults (preserved from the reference):
 *     URL     — allowlist, empty  → everything not explicitly trusted UNTRUSTED
 *     CHANNEL — blocklist, empty  → everything not explicitly untrusted TRUSTED
 *     DIR     — blocklist, empty  → everything not explicitly untrusted TRUSTED
 */

import { loadPolicyFile, type PolicyFileConfig } from "./load-policy.js";
import {
  createUrlTrustCategory,
  createChannelTrustCategory,
  createDirTrustCategory,
  type TrustCategory,
  type ListMode,
} from "./trust-category.js";
import type { CategoryLookup } from "./resolve-schema.js";

interface Logger {
  info(msg: string): void;
  warn(msg: string): void;
}

export class PolicyEngine implements CategoryLookup {
  private categories = new Map<string, TrustCategory>();

  register(category: TrustCategory): void {
    this.categories.set(category.id, category);
  }

  get(id: string): TrustCategory | undefined {
    return this.categories.get(id);
  }

  has(id: string): boolean {
    return this.categories.has(id);
  }

  /** Iterate registered categories — for logging / diagnostics. */
  list(): TrustCategory[] {
    return Array.from(this.categories.values());
  }
}

/**
 * Build a PolicyEngine from a YAML policy file. All origin-rule input flows
 * through the YAML; there are no plugin-config shortcuts.
 *
 * Legacy YAML keys (deprecated but still accepted):
 *   inbound.url-trust     { trustedUrls: [...] }       → url allowlist
 *   inbound.channel-trust { untrustedChannels: [...] } → channel blocklist
 *   inbound.dir-trust     { untrustedDirs: [...] }     → dir blocklist
 */
/**
 * The default each origin category has when the law says nothing about it:
 * the "no policy" registration below. A category section that OMITS
 * `default` inherits THIS, never the opposite: before 2026-09-25 an absent
 * `default` meant blocklist (TRUSTED) for every category, so a URL section
 * written as `url: { trustedList: [docs.python.org] }` trusted the whole web,
 * and a policy edit that merely distrusted one site switched URL masking off
 * (policy-surface.md §8.3.2, "origins"). policy-delta.ts compares
 * effective defaults through the same table.
 */
export const BUILTIN_ORIGIN_DEFAULT: Readonly<Record<"url" | "channel" | "dir", "TRUSTED" | "UNTRUSTED">> = Object.freeze({
  url: "UNTRUSTED",
  channel: "TRUSTED",
  dir: "TRUSTED",
});

export function createPolicyEngine(
  policyPath: string | undefined,
  basePath: string,
  log: Logger,
  policyFileOverride?: PolicyFileConfig | null,
): PolicyEngine {
  const engine = new PolicyEngine();
  const policyFile = policyFileOverride === undefined
    ? loadPolicyFile(policyPath, basePath, log)
    : policyFileOverride;

  // Register built-in categories with their intrinsic "no policy" defaults so
  // every DataSpec in TOOL_INBOUND_SPEC resolves to the baseline when the user
  // provides no config. User YAML below overrides these.
  engine.register(createUrlTrustCategory({ mode: "allowlist", list: [] }));
  engine.register(createChannelTrustCategory({ mode: "blocklist", list: [] }));
  engine.register(createDirTrustCategory({ mode: "blocklist", list: [], basePath }));

  // ── URL ─────────────────────────────────────────────────────────────
  const urlNew = policyFile?.inbound?.url;
  const urlLegacy = policyFile?.inbound?.["url-trust"];
  if (urlNew) {
    const mode: ListMode = ((urlNew.default ?? BUILTIN_ORIGIN_DEFAULT.url) === "UNTRUSTED") ? "allowlist" : "blocklist";
    const list = mode === "allowlist" ? (urlNew.trustedList ?? []) : (urlNew.untrustedList ?? []);
    engine.register(createUrlTrustCategory({ mode, list }));
    log.info(`[Mandu-policy] URL category registered (${mode}, ${list.length} entries)`);
  } else if (urlLegacy?.trustedUrls?.length) {
    engine.register(createUrlTrustCategory({ mode: "allowlist", list: urlLegacy.trustedUrls }));
    log.warn(`[Mandu-policy] inbound.url-trust is deprecated, use inbound.url.{default,trustedList}`);
    log.info(`[Mandu-policy] URL category registered (allowlist, ${urlLegacy.trustedUrls.length} entries)`);
  }

  // ── CHANNEL ─────────────────────────────────────────────────────────
  const chNew = policyFile?.inbound?.channel;
  const chLegacy = policyFile?.inbound?.["channel-trust"];
  if (chNew) {
    const mode: ListMode = ((chNew.default ?? BUILTIN_ORIGIN_DEFAULT.channel) === "UNTRUSTED") ? "allowlist" : "blocklist";
    const list = mode === "allowlist" ? (chNew.trustedList ?? []) : (chNew.untrustedList ?? []);
    engine.register(createChannelTrustCategory({ mode, list }));
    log.info(`[Mandu-policy] CHANNEL category registered (${mode}, ${list.length} entries)`);
  } else if (chLegacy?.untrustedChannels?.length) {
    engine.register(createChannelTrustCategory({ mode: "blocklist", list: chLegacy.untrustedChannels }));
    log.warn(`[Mandu-policy] inbound.channel-trust is deprecated, use inbound.channel.{default,untrustedList}`);
    log.info(`[Mandu-policy] CHANNEL category registered (blocklist, ${chLegacy.untrustedChannels.length} entries)`);
  }

  // ── DIR ─────────────────────────────────────────────────────────────
  const dirNew = policyFile?.inbound?.dir;
  if (dirNew) {
    const mode: ListMode = ((dirNew.default ?? BUILTIN_ORIGIN_DEFAULT.dir) === "UNTRUSTED") ? "allowlist" : "blocklist";
    const list = mode === "allowlist" ? (dirNew.trustedList ?? []) : (dirNew.untrustedList ?? []);
    engine.register(createDirTrustCategory({ mode, list, basePath }));
    log.info(`[Mandu-policy] DIR category registered (${mode}, ${list.length} entries)`);
  } else {
    const dirLegacy = policyFile?.inbound?.["dir-trust"]?.untrustedDirs ?? [];
    if (dirLegacy.length > 0) {
      log.warn(`[Mandu-policy] inbound.dir-trust is deprecated, use inbound.dir.{default,untrustedList}`);
      engine.register(createDirTrustCategory({
        mode: "blocklist",
        list: dirLegacy,
        basePath,
      }));
      log.info(`[Mandu-policy] DIR category registered (blocklist, ${dirLegacy.length} entries)`);
    }
  }

  // COMMAND (exec-output) and TOOLS (per-tool inbound/outbound) overrides are
  // no longer merged HERE into module globals: `compilePolicy`
  // (compiled-policy.ts) applies them to copies of the built-in tables and
  // swaps the law in force (policy-surface.md §2.2). This engine is
  // the origin-classifier registry only.
  return engine;
}
