#!/usr/bin/env node
// sign-pack.mjs — sign a consumer pack (arbiter/policy/consumer-packs.ts,
// comparisons.md §3.3).
//
//   node scripts/sign-pack.mjs --keygen <dir> <keyId>   write <keyId>.key (PRIVATE, 0600) and <keyId>.pem (public)
//   node scripts/sign-pack.mjs <pack.json> <private.key> write <pack.json>.sig (base64 Ed25519 over the exact bytes)
//
// The public key goes in ~/.mandu/pack-keys/ of every machine that
// should trust the pack; the private key never leaves its owner. Nothing in
// this repository holds a private key.
import { createPrivateKey, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [a, b, c] = process.argv.slice(2);
if (a === "--keygen" && b && c) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  writeFileSync(join(b, `${c}.key`), privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  writeFileSync(join(b, `${c}.pem`), publicKey.export({ type: "spki", format: "pem" }));
  console.log(`wrote ${join(b, `${c}.key`)} (private, keep it) and ${join(b, `${c}.pem`)} (public, share it)`);
} else if (a && b && a !== "--keygen") {
  const bytes = readFileSync(a);
  const sig = sign(null, bytes, createPrivateKey(readFileSync(b)));
  writeFileSync(`${a}.sig`, sig.toString("base64") + "\n");
  console.log(`wrote ${a}.sig`);
} else {
  console.error("usage: sign-pack.mjs --keygen <dir> <keyId> | sign-pack.mjs <pack.json> <private.key>");
  process.exit(2);
}
