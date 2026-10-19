/**
 * opencode-config — OpenCode 2's config spelling, read the way OpenCode 2
 * reads it, for the launch-time model check (agent-model-route.ts
 * opencodeV2ModelPlan) and the routing Mandu writes for a 2.x launch
 * (services/agent-config.ts). Pure; the file reading is in agent-config.ts
 * readOpencodeConfigLayers. Design: supported-agents.md §2.3 part 4.
 *
 * WHAT CHANGED IN 2.x (probe-verified 2026-10-05 on 2.0.23 with `opencode
 * debug config`, which prints every config source normalized, and on the
 * wire with scripted local upstreams):
 *   - keys: `provider` → `providers`, `options` → `settings` (+ `headers`,
 *     `body`), `npm` → `package: "aisdk:<npm>"`, `agent` / `mode` → `agents`,
 *     `small_model` → `agents.title.model`, `command` → `commands`, a model
 *     reference may carry a `#variant` suffix (or be an object
 *     `{ providerID, model, variant }`), `enabled_providers` /
 *     `disabled_providers` → `experimental.policies` (`provider.use` rules);
 *   - V1 keys are normalized, not rejected. In ONE document a `providers.<id>`
 *     entry replaces the `provider.<id>` entry WHOLE (its V1 settings,
 *     credentials and models are dropped); other ids keep their V1 entry. A V1
 *     provider's `api` wins over its `options.baseURL`;
 *   - layers, lowest first: the global config dir (`$OPENCODE_CONFIG_DIR`,
 *     else `$XDG_CONFIG_HOME/opencode`: `opencode.json`, `opencode.jsonc`),
 *     the `OPENCODE_CONFIG` file, the project files of the start directory
 *     AND EVERY ANCESTOR up to `/` (`opencode.json(c)`, then
 *     `.opencode/opencode.json(c)`), then `OPENCODE_CONFIG_CONTENT`.
 *     Provider settings merge upward (the inline content wins);
 *   - provider POLICIES DO NOT: OpenCode 2 reverses the layers and takes the
 *     LAST matching rule, so the rule of the LOWEST layer that names a
 *     provider decides (`opencode.config.policy`: `entries.toReversed()
 *     .flatMap(policies)…findLast`). Mandu's inline fence therefore loses to
 *     any file layer; its OPENCODE_CONFIG file beats every project layer, and
 *     only the global config dir sits below it. Measured: a project
 *     `experimental.policies` allow (or V1 `enabled_providers`) did not
 *     re-admit `openai`; the same rule in the global config did, and the turn
 *     went to that provider's own endpoint;
 *   - a MODEL's own endpoint (`providers.<id>.models.<m>.settings.baseURL`,
 *     its `package`, a variant's `settings.baseURL`, and the V1 spellings
 *     `options.baseURL`, `provider.api`, `provider.npm`, `variants.<v>.baseURL`)
 *     beats the provider's base URL: from a project config the turn went to
 *     that URL, around the proxy, with the routed provider's own base URL
 *     still pointing at it. OpenCode 1 keeps the provider's base URL there.
 */
import { basename } from "node:path";
import { parseAgentVersion } from "./agent-versions.js";

type Json = Record<string, unknown>;

function isObj(v: unknown): v is Json {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** Which config spelling the launched OpenCode reads. */
export type OpencodeGeneration = 1 | 2;

/**
 * The generation of the launched OpenCode: `opencode2` (only OpenCode 2
 * installs it) and any version whose major is not 1 (2.x and the 2.x
 * `0.0.0-*` prereleases, agent-versions.ts opencodeLaunchRefusal) are 2. A
 * version that was not read (a wrapper under `--target`, which is never
 * probed, §3) keeps the 1.x shape: OpenCode 1 rejects the 2.x keys, and an
 * unwrapped `opencode` whose version cannot be read is refused before this.
 */
export function opencodeGeneration(argv0: string | undefined, version: string | null | undefined): OpencodeGeneration {
  if (argv0 !== undefined && basename(argv0) === "opencode2") return 2;
  const v = parseAgentVersion(version ?? null);
  if (v === null) return 1;
  return v.parts[0] === 1 ? 1 : 2;
}

/** Where one config layer comes from (lowest first, as OpenCode 2 lists them). */
export type OpencodeLayerKind = "global" | "file" | "project" | "inline";

export interface OpencodeLayer {
  kind: OpencodeLayerKind;
  /** The file, or "OPENCODE_CONFIG_CONTENT" for the inline layer. */
  path: string;
  doc: Json;
}

/** A model reference and the key it came from. */
export interface OcRef { ref: string; where: string }

/** One provider's endpoint-relevant settings in one layer. */
export interface OcProvider {
  package?: string;
  baseURL?: unknown;
  canonical?: unknown;
  /** The key that set the base URL / package, for messages. */
  spelling: "providers" | "provider";
}

/** A provider rule (`experimental.policies`, or the V1 provider lists). */
export interface OcPolicy { resource: string; effect: string; where: string }

/** A key that gives one model (or variant) its own endpoint. */
export interface OcEndpointKey { provider: string; where: string }

/** One layer, read the way OpenCode 2 normalizes it. */
export interface OcNormalized {
  model?: OcRef;
  agents: Record<string, OcRef>;
  commands: Record<string, OcRef>;
  providers: Record<string, OcProvider>;
  policies: OcPolicy[];
  endpointKeys: OcEndpointKey[];
}

/** A model value as a "provider/model[#variant]" string, or undefined. */
export function opencodeModelRefString(v: unknown): string | undefined {
  if (typeof v === "string") return v.trim() === "" ? undefined : v.trim();
  if (!isObj(v)) return undefined;
  const p = v["providerID"], m = v["model"] ?? v["modelID"] ?? v["id"];
  if (typeof p !== "string" || typeof m !== "string" || p === "" || m === "") return undefined;
  const variant = typeof v["variant"] === "string" && v["variant"] !== "" ? `#${v["variant"]}` : "";
  return `${p}/${m}${variant}`;
}

/** The `aisdk:` package name a V1 `npm` value normalizes to. */
function aisdk(npm: string): string {
  return npm.startsWith("aisdk:") ? npm : `aisdk:${npm}`;
}

/** The npm package of an OpenCode 2 `package` value (`aisdk:` stripped). */
export function opencodePackageName(pkg: string | undefined): string | undefined {
  return pkg === undefined ? undefined : pkg.startsWith("aisdk:") ? pkg.slice("aisdk:".length) : pkg;
}

/** The model-level keys that give a model its own endpoint, both spellings. */
function modelEndpointKeys(provider: string, models: unknown, prefix: string, v2: boolean, out: OcEndpointKey[]): void {
  if (!isObj(models)) return;
  for (const [id, m] of Object.entries(models)) {
    if (!isObj(m)) continue;
    const at = `${prefix}.models.${id}`;
    if (v2) {
      if (isObj(m["settings"]) && m["settings"]["baseURL"] !== undefined) out.push({ provider, where: `${at}.settings.baseURL` });
      if (m["package"] !== undefined) out.push({ provider, where: `${at}.package` });
      if (Array.isArray(m["variants"])) {
        m["variants"].forEach((va, i) => {
          if (isObj(va) && isObj(va["settings"]) && va["settings"]["baseURL"] !== undefined) {
            out.push({ provider, where: `${at}.variants[${i}].settings.baseURL` });
          }
        });
      }
    } else {
      if (isObj(m["options"]) && m["options"]["baseURL"] !== undefined) out.push({ provider, where: `${at}.options.baseURL` });
      if (isObj(m["provider"])) {
        if (m["provider"]["api"] !== undefined) out.push({ provider, where: `${at}.provider.api` });
        if (m["provider"]["npm"] !== undefined) out.push({ provider, where: `${at}.provider.npm` });
      }
      if (isObj(m["variants"])) {
        for (const [vid, va] of Object.entries(m["variants"])) {
          if (isObj(va) && va["baseURL"] !== undefined) out.push({ provider, where: `${at}.variants.${vid}.baseURL` });
        }
      }
    }
  }
}

/** Every `<section>.<name>.model` reference in `doc[section]`. */
function namedRefs(doc: Json, section: string, out: Record<string, OcRef>): void {
  const sect = doc[section];
  if (!isObj(sect)) return;
  for (const [name, a] of Object.entries(sect)) {
    const ref = isObj(a) ? opencodeModelRefString(a["model"]) : undefined;
    if (ref !== undefined) out[name] = { ref, where: `${section}.${name}.model` };
  }
}

/** The provider ids a V1 provider list names (`enabled_providers` etc.). */
function providerList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

/**
 * One config document as OpenCode 2 normalizes it (only what decides where
 * a model call goes). V2 keys win over V1 ones: per provider id the
 * `providers` entry replaces the `provider` entry; per agent or command name
 * the `agents` / `commands` entry wins.
 */
export function normalizeOpencodeDoc(doc: Json): OcNormalized {
  const out: OcNormalized = { agents: {}, commands: {}, providers: {}, policies: [], endpointKeys: [] };
  const model = opencodeModelRefString(doc["model"]);
  if (model !== undefined) out.model = { ref: model, where: "model" };
  const small = opencodeModelRefString(doc["small_model"]);
  if (small !== undefined) out.agents["title"] = { ref: small, where: "small_model" };
  namedRefs(doc, "mode", out.agents);
  namedRefs(doc, "agent", out.agents);
  namedRefs(doc, "agents", out.agents);
  namedRefs(doc, "command", out.commands);
  namedRefs(doc, "commands", out.commands);

  const v1 = isObj(doc["provider"]) ? doc["provider"] : {};
  const v2 = isObj(doc["providers"]) ? doc["providers"] : {};
  for (const [id, e] of Object.entries(v1)) {
    if (!isObj(e) || isObj(v2[id])) continue; // the V2 entry replaces it whole
    const options = isObj(e["options"]) ? e["options"] : {};
    out.providers[id] = {
      ...(typeof e["npm"] === "string" ? { package: aisdk(e["npm"]) } : {}),
      // OpenCode 2 takes a V1 provider's `api` over its options.baseURL.
      ...(e["api"] !== undefined ? { baseURL: e["api"] } : options["baseURL"] !== undefined ? { baseURL: options["baseURL"] } : {}),
      spelling: "provider",
    };
    modelEndpointKeys(id, e["models"], `provider.${id}`, false, out.endpointKeys);
  }
  for (const [id, e] of Object.entries(v2)) {
    if (!isObj(e)) continue;
    const settings = isObj(e["settings"]) ? e["settings"] : {};
    out.providers[id] = {
      ...(typeof e["package"] === "string" ? { package: e["package"] } : {}),
      ...(settings["baseURL"] !== undefined ? { baseURL: settings["baseURL"] } : {}),
      ...(e["canonical"] !== undefined ? { canonical: e["canonical"] } : {}),
      spelling: "providers",
    };
    modelEndpointKeys(id, e["models"], `providers.${id}`, true, out.endpointKeys);
  }

  // Provider rules in OpenCode 2's own order within a document: the V1
  // lists first (enabled_providers = deny * then allow each; disabled =
  // deny each), then experimental.policies.
  if (doc["enabled_providers"] !== undefined) {
    out.policies.push({ resource: "*", effect: "deny", where: "enabled_providers" });
    providerList(doc["enabled_providers"]).forEach((p, i) => out.policies.push({ resource: p, effect: "allow", where: `enabled_providers[${i}]` }));
  }
  providerList(doc["disabled_providers"]).forEach((p, i) => out.policies.push({ resource: p, effect: "deny", where: `disabled_providers[${i}]` }));
  const exp = isObj(doc["experimental"]) ? doc["experimental"] : {};
  if (Array.isArray(exp["policies"])) {
    exp["policies"].forEach((r, i) => {
      if (!isObj(r) || r["action"] !== "provider.use") return;
      out.policies.push({ resource: String(r["resource"]), effect: String(r["effect"]), where: `experimental.policies[${i}]` });
    });
  }
  return out;
}

/** The provider rules Mandu writes for a 2.x launch: deny every provider,
 *  then allow each routed one (the V2 form of `enabled_providers`). */
export function opencodePolicyFence(routed: readonly string[]): Json[] {
  return [
    { action: "provider.use", resource: "*", effect: "deny" },
    ...routed.map((id) => ({ action: "provider.use", resource: id, effect: "allow" })),
  ];
}
