#!/usr/bin/env node
// reduce-credential — prepare the REDUCED Claude credential a fresh-install
// guest may hold (docs/design/testing/os-test-matrix.md §10.3.5).
//
// OAuth refresh tokens ROTATE: a second holder that refreshes invalidates the
// host's login (scripts/ci/docker-run.sh header, observed 2026-07-12). So the
// guest gets the access token ONLY. It can never refresh, hence never rotate
// the host's lineage, and what it holds dies within hours.
//
//   reduce-credential.mjs <src .credentials.json> <out-dir> <min-seconds-left>
//
// Exit 0 = wrote <out-dir>/.credentials.json (0600). Exit 3 = cannot (reason on
// stderr): missing/unparsable source, no access token, or too little lifetime
// left. NEVER prints a token. Refuses an <out-dir> that does not already exist
// (the caller owns the per-run directory and its cleanup).
import { readFileSync, writeFileSync, statSync, chmodSync } from "node:fs";
import { join } from "node:path";

export function reduce(raw, nowMs, minSecondsLeft) {
  let cred;
  try { cred = JSON.parse(raw); } catch { return { ok: false, reason: "credential file is not JSON" }; }
  const o = cred?.claudeAiOauth;
  if (!o || typeof o.accessToken !== "string" || !o.accessToken) return { ok: false, reason: "no claudeAiOauth.accessToken (not a subscription login?)" };
  if (typeof o.expiresAt !== "number") return { ok: false, reason: "no expiresAt; cannot tell whether the token outlives the run" };
  const left = Math.floor((o.expiresAt - nowMs) / 1000);
  if (left < minSecondsLeft) return { ok: false, reason: `access token has ${left}s left, need ${minSecondsLeft}s; refresh on the host first (run any \`claude -p\`)`, stale: true };
  // Allow-list, not a delete: a future field that carries refresh capability
  // must not ride along by default.
  const reduced = { claudeAiOauth: {
    accessToken: o.accessToken, expiresAt: o.expiresAt,
    scopes: o.scopes, subscriptionType: o.subscriptionType, rateLimitTier: o.rateLimitTier,
  } };
  return { ok: true, json: JSON.stringify(reduced), secondsLeft: left };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [src, outDir, min] = process.argv.slice(2);
  const bail = (m) => { console.error(`reduce-credential: ${m}`); process.exit(3); };
  if (!src || !outDir || !/^\d+$/.test(min ?? "")) bail("usage: reduce-credential.mjs <src> <out-dir> <min-seconds-left>");
  try { if (!statSync(outDir).isDirectory()) bail("out-dir is not a directory"); } catch { bail("out-dir does not exist"); }
  let raw; try { raw = readFileSync(src, "utf8"); } catch { bail(`no credential at ${src}`); }
  const r = reduce(raw, Date.now(), Number(min));
  if (!r.ok) bail(r.reason);
  const out = join(outDir, ".credentials.json");
  writeFileSync(out, r.json, { mode: 0o600 }); chmodSync(out, 0o600);
  console.error(`reduce-credential: wrote access-token-only credential (${r.secondsLeft}s left)`);
}
