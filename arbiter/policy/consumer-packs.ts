/**
 * consumer-packs — signed, versioned additions to the consumer table
 * (comparisons.md §3.3, to-do #10, the reduced form; policy-surface-
 * redesign.md §3.2). A pack is a JSON file with a detached Ed25519 signature
 * over its exact bytes, loaded ONLY from the user's config directory (never
 * a workspace: §11.6), and ONLY when signed by a key the user placed in the
 * pack-keys directory. A pack can ADD consumers, never remove or override a
 * built-in row (flow-taint.ts consults the built-in table first). Every pack
 * entry lets a program read a secret file raw by default, so each is a
 * relaxation, listed with its provenance (pack, version, key).
 *
 *   <config>/mandu/packs/<name>.json        the pack
 *   <config>/mandu/packs/<name>.json.sig    base64 Ed25519 signature
 *   <config>/mandu/pack-keys/<keyId>.pem    trusted public keys
 *
 * Format:
 *   { "format": "mandu-consumer-pack/1", "name": "acme/cli-tools",
 *     "version": "2026.09.25",
 *     "consumers": [ { "basename": ".vault-token", "apps": ["vault"] },
 *                    { "pathSuffix": "/.config/stripe/config.toml", "apps": ["stripe"],
 *                      "wire": { "served": true, "why": "Go; a bearer token" } } ] }
 *
 * Mandu-new (no reference origin). scripts/sign-pack.mjs signs one.
 */
import { createPublicKey, verify, type KeyObject } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { manduPath, type ManduPathEnv } from "../src/generated/mandu-paths.js";

export const PACK_FORMAT = "mandu-consumer-pack/1";

export interface PackConsumer {
  basename?: string;
  pathSuffix?: string;
  apps: string[];
  wire?: { served: boolean; why: string };
}

export interface LoadedPack {
  name: string;
  version: string;
  keyId: string;
  file: string;
  consumers: PackConsumer[];
}

/** The trusted public keys in a directory: `<keyId>.pem`, Ed25519 only. */
export function loadPackKeys(dir: string): Array<{ id: string; key: KeyObject }> {
  if (!existsSync(dir)) return [];
  const out: Array<{ id: string; key: KeyObject }> = [];
  for (const f of readdirSync(dir).sort()) {
    if (!f.endsWith(".pem")) continue;
    try {
      const key = createPublicKey(readFileSync(join(dir, f)));
      if (key.asymmetricKeyType === "ed25519") out.push({ id: f.slice(0, -4), key });
    } catch { /* not a public key: ignored */ }
  }
  return out;
}

/** The id of the trusted key that signed `bytes`, or null. */
export function verifyPackSignature(bytes: Buffer, signatureB64: string, keys: ReadonlyArray<{ id: string; key: KeyObject }>): string | null {
  let sig: Buffer;
  try { sig = Buffer.from(signatureB64.trim(), "base64"); } catch { return null; }
  if (sig.length !== 64) return null;
  for (const k of keys) {
    try { if (verify(null, bytes, k.key, sig)) return k.id; } catch { /* next */ }
  }
  return null;
}

function validConsumer(c: unknown): c is PackConsumer {
  if (!c || typeof c !== "object") return false;
  const o = c as Record<string, unknown>;
  const hasMatch = (typeof o["basename"] === "string" && o["basename"] !== "" && !(o["basename"] as string).includes("/"))
    || (typeof o["pathSuffix"] === "string" && (o["pathSuffix"] as string).startsWith("/"));
  const apps = Array.isArray(o["apps"]) && (o["apps"] as unknown[]).length > 0 && (o["apps"] as unknown[]).every((a) => typeof a === "string" && a !== "" && !a.includes("/"));
  const wire = o["wire"] === undefined || (typeof o["wire"] === "object" && o["wire"] !== null && typeof (o["wire"] as Record<string, unknown>)["served"] === "boolean" && typeof (o["wire"] as Record<string, unknown>)["why"] === "string");
  return hasMatch && apps && wire;
}

/** Where the packs and their trusted keys live by default: the path table's
 *  `packs` and `pack-keys` (on-disk-layout.md §5), under the config root.
 *  Only MANDU_HOME moves them. Pure. */
export function defaultPackDirs(env: ManduPathEnv, home: string): { packDir: string; keysDir: string } {
  return { packDir: manduPath("packs", env, home), keysDir: manduPath("pack-keys", env, home) };
}

/** Load and verify every pack in `packDir` against the keys in `keysDir`.
 *  A pack that is unsigned, signed by an unknown key, malformed, or has a
 *  malformed entry is refused whole and named in `errors`. */
export function loadConsumerPacks(packDir: string, keysDir: string): { packs: LoadedPack[]; errors: string[] } {
  const packs: LoadedPack[] = [];
  const errors: string[] = [];
  if (!existsSync(packDir)) return { packs, errors };
  const keys = loadPackKeys(keysDir);
  for (const f of readdirSync(packDir).sort()) {
    if (!f.endsWith(".json")) continue;
    const file = join(packDir, f);
    const bytes = readFileSync(file);
    const sigFile = `${file}.sig`;
    if (!existsSync(sigFile)) { errors.push(`${f}: unsigned (no ${f}.sig): refused`); continue; }
    const keyId = verifyPackSignature(bytes, readFileSync(sigFile, "utf8"), keys);
    if (!keyId) { errors.push(`${f}: signature does not verify against any trusted key in ${keysDir}: refused`); continue; }
    let doc: Record<string, unknown>;
    try { doc = JSON.parse(bytes.toString("utf8")) as Record<string, unknown>; } catch { errors.push(`${f}: not JSON: refused`); continue; }
    if (doc["format"] !== PACK_FORMAT || typeof doc["name"] !== "string" || typeof doc["version"] !== "string" || !Array.isArray(doc["consumers"])) {
      errors.push(`${f}: not a ${PACK_FORMAT} pack (format, name, version, consumers): refused`);
      continue;
    }
    const consumers = doc["consumers"] as unknown[];
    if (!consumers.every(validConsumer)) { errors.push(`${f}: a consumer entry is malformed: refused`); continue; }
    packs.push({ name: doc["name"] as string, version: doc["version"] as string, keyId, file, consumers: consumers as PackConsumer[] });
  }
  return { packs, errors };
}
