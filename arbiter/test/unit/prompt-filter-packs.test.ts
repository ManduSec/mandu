/**
 * prompt-filter-packs.test — the `key-shapes` filter and the pattern packs
 * (confidentiality-plan-15-prompt-filter.md §4.1, §4.2, §8.1, phase 2).
 * Mandu-new.
 *
 * Proves: `locateSecretShapes` finds the same credentials as the scans'
 * detector, by offset, every occurrence, and leaves the scan fingerprint
 * alone; the named validators (luhn, kr-rrn-checksum, iban); the RE2 engine
 * refuses backreferences and lookaround and stays linear on a catastrophic
 * pattern; a pack validates field by field and is refused whole; plain and
 * HASHED keywords match whole words and phrases, with offsets in the
 * original text; the loader reads the administrator's directory first, an
 * id clash is refused, a signature is verified against the trusted keys;
 * the pack editor's typed edits classify additions as tightenings and
 * removals and edits as relaxations; the fixed ordinary corpus counts a
 * pattern that matches everything.
 *
 * Axes: secrets (stated; nothing here reads the axes).
 */
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { detectSecretShapes, historyDetectorFingerprint, locateSecretShapes } from "../../policy/secret-detectors.js";
import { KeyShapesFilter } from "../../prompt-filter/key-shapes-filter.js";
import { iban, krRrnChecksum, luhn } from "../../prompt-filter/validators.js";
import { compileRegex } from "../../prompt-filter/regex.js";
import {
  hashKeyword,
  loadPromptPacks,
  normalizeKeyword,
  PackFilter,
  packDirsSignature,
  packToYaml,
  parsePackText,
  patternMatchCounts,
  validatePack,
} from "../../prompt-filter/packs.js";
import { applyPackEdits } from "../../prompt-filter/pack-edit.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), "mdu-packs-")); dirs.push(d); return d; };

const GH = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
const AWS = "AKIAIOSFODNN7REALKEY";

test("locateSecretShapes: the scans' rules by offset, every occurrence; the history fingerprint does not move", () => {
  const fp = historyDetectorFingerprint();
  const text = `use ${GH} then\nexport API_TOKEN=Zx81Lq0vNw3PpL6tYb9K\nand ${AWS} and ${GH}`;
  const spans = locateSecretShapes(text);
  assert.deepEqual(spans.map((s) => [s.shape, text.slice(s.start, s.end)]), [
    ["github-token", GH],
    ["credential-assignment", "Zx81Lq0vNw3PpL6tYb9K"],
    ["aws-access-key-id", AWS],
    ["github-token", GH],
  ]);
  assert.equal(new Set(detectSecretShapes(text).map((h) => h.shape)).size, 3, "the scan finds the same shapes");
  const pem = "x\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234567890abcdefghijABCDEFGHIJ1234567890abcd\nmore+lines/==\n-----END RSA PRIVATE KEY-----\ny";
  const [k] = locateSecretShapes(pem);
  assert.equal(k!.shape, "private-key");
  assert.equal(pem.slice(k!.start, k!.end), pem.slice(2, -2), "the whole block, BEGIN line through END line");
  assert.deepEqual(locateSecretShapes("API_TOKEN=changeme-placeholder-1"), [], "a placeholder is not a credential");
  const f = new KeyShapesFilter().scan(`k ${GH}`, { origin: "human" });
  assert.deepEqual(f.findings.map((x) => [x.category, x.level]), [["secret.shape.github-token", "no-model"]]);
  assert.equal(historyDetectorFingerprint(), fp);
});

test("validators: luhn, kr-rrn-checksum, iban", () => {
  assert.ok(luhn("4111 1111 1111 1111") && luhn("4012-8888-8888-1881"));
  assert.ok(!luhn("4111 1111 1111 1112") && !luhn("1234"));
  assert.ok(krRrnChecksum("800101-1000008"));
  assert.ok(!krRrnChecksum("800101-1000009"));
  assert.ok(iban("GB82 WEST 1234 5698 7654 32") && iban("DE89370400440532013000"));
  assert.ok(!iban("GB82 WEST 1234 5698 7654 33"));
});

test("the RE2 engine: no backreference or lookaround, linear time, UTF-16 offsets", () => {
  assert.match(String(compileRegex("(a)\\1")), /RE2 engine rejects/);
  assert.match(String(compileRegex("(?<=x)a")), /RE2 engine rejects/);
  const evil = compileRegex("(a+)+$");
  assert.ok(typeof evil !== "string");
  const t0 = Date.now();
  assert.deepEqual(evil.matches(`${"a".repeat(20_000)}!`), []);
  assert.ok(Date.now() - t0 < 2000, "catastrophic backtracking cannot stall the arbiter");
  const re = compileRegex("card \\d{4}");
  assert.ok(typeof re !== "string");
  const s = "😀 é card 1234";
  const [m] = re.matches(s);
  assert.equal(s.slice(m!.start, m!.end), "card 1234");
  assert.deepEqual((compileRegex("x*") as { matches(t: string): unknown[] }).matches("abc"), [], "an empty match finds nothing");
});

const PACK = `pack: acme-dlp
version: 3
description: test pack
patterns:
  - id: card
    category: pii.payment-card
    regex: '\\b(?:\\d[ -]?){13,19}\\b'
    check: luhn
  - id: email
    category: pii.email
    regex: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}'
    level: local-model
keywords:
  - category: acme.codename
    salt: s3cr3t-salt
    hashes: [${hashKeyword("s3cr3t-salt", "Project Falcon")}, ${hashKeyword("s3cr3t-salt", "osprey")}]
    max_words: 2
  - category: acme.codename
    words: [Blue Heron]
  - category: acme.internal
    match: substring
    words: [intra.acme]
`;

test("a pack validates, and its filter finds patterns (with checks), hashed and plain keywords by offset", () => {
  const r = parsePackText(PACK);
  assert.ok("doc" in r, JSON.stringify(r));
  const f = new PackFilter({ doc: r.doc, source: "user", file: "/x/acme.yaml", signedBy: null, digest: "d" });
  assert.deepEqual([...f.categories].sort(), ["acme.codename", "acme.internal", "pii.email", "pii.payment-card"]);
  const text = "Pay 4111 1111 1111 1111 (not 4111 1111 1111 1112) to bob@acme.example for PROJECT  falcon, Osprey and blue-heron at https://intra.acme/x";
  const found = f.scan(text, { origin: "human" }).findings.map((x) => [x.category, text.slice(x.start, x.end), x.rule, x.level ?? null]);
  assert.deepEqual(found, [
    ["pii.payment-card", "4111 1111 1111 1111", "card", null],
    ["pii.email", "bob@acme.example", "email", "local-model"],
    ["acme.codename", "PROJECT  falcon", "keyword", null],
    ["acme.codename", "Osprey", "keyword", null],
    ["acme.codename", "blue-heron", "keyword", null],
    ["acme.internal", "intra.acme", "keyword", null],
  ]);
  assert.equal(normalizeKeyword("  Project-FALCON "), "project falcon");
  assert.ok(!packToYaml(r.doc).includes("Project Falcon"), "a hashed keyword is never written in plain text");
  assert.deepEqual(parsePackText(packToYaml(r.doc)), r, "the editor's YAML reads back as the same pack");
});

test("a pack is refused whole, field by field", () => {
  const bad = validatePack({
    pack: "key-shapes", version: -1, signature: "ed25519:x",
    patterns: [{ id: "a", category: "pii", regex: "(a)\\1" }, { id: "a", category: "BAD", regex: "x", check: "md5" }],
    keywords: [{ category: "c", salt: "short", hashes: ["nothex"], match: "substring" }, { category: "c", words: [] }],
  });
  assert.ok("problems" in bad);
  const all = bad.problems.join("\n");
  for (const re of [/pack: 'key-shapes' is a built-in/, /version: must be/, /signature: sign a pack with a detached/, /patterns\[0\]\.regex: the RE2 engine rejects/,
    /patterns\[1\]\.category/, /patterns\[1\]\.check: must be one of luhn, kr-rrn-checksum, iban/, /keywords\[0\]\.salt/, /keywords\[0\]\.hashes/,
    /keywords\[0\]\.match: hashed keywords match whole words only/, /keywords\[1\]\.words: must be a non-empty list/]) assert.match(all, re);
  assert.ok("problems" in validatePack({ pack: "empty", version: 1 }), "a pack needs a pattern or a keyword");
});

test("the loader: the administrator's directory first, an id clash refused, signatures verified against trusted keys", () => {
  const admin = tmp();
  const user = tmp();
  const keys = tmp();
  writeFileSync(join(admin, "acme.yaml"), PACK);
  writeFileSync(join(user, "10-mine.yaml"), "pack: mine\nversion: 1\nkeywords:\n  - category: me.project\n    words: [moonshot]\n");
  writeFileSync(join(user, "20-clash.yaml"), PACK);
  writeFileSync(join(user, "30-broken.yaml"), "pack: broken\nversion: 1\npatterns:\n  - id: x\n    category: a.b\n    regex: '(?<=a)b'\n");
  // A signed pack of the person's, and one with a bad signature.
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  writeFileSync(join(keys, "me.pem"), publicKey.export({ type: "spki", format: "pem" }));
  const signed = "pack: signed\nversion: 1\nkeywords:\n  - category: me.signed\n    words: [zebra]\n";
  writeFileSync(join(user, "40-signed.yaml"), signed);
  writeFileSync(join(user, "40-signed.yaml.sig"), sign(null, Buffer.from(signed), privateKey).toString("base64"));
  writeFileSync(join(user, "50-forged.yaml"), "pack: forged\nversion: 1\nkeywords:\n  - category: me.x\n    words: [yak]\n");
  writeFileSync(join(user, "50-forged.yaml.sig"), sign(null, Buffer.from("other bytes"), privateKey).toString("base64"));
  const sig0 = packDirsSignature([admin, user], keys);
  const l = loadPromptPacks({ userDir: user, adminDir: admin, keysDir: keys });
  assert.deepEqual(l.packs.map((p) => [p.doc.pack, p.source, p.signedBy]), [["acme-dlp", "admin", null], ["mine", "user", null], ["signed", "user", "me"]]);
  const probs = l.problems.map((p) => `${p.file.split("/").pop()}: ${p.problems.join("; ")}`).join("\n");
  assert.match(probs, /20-clash\.yaml: the pack id 'acme-dlp' is already used by .*acme\.yaml/);
  assert.match(probs, /30-broken\.yaml: patterns\[0\]\.regex: the RE2 engine rejects/);
  assert.match(probs, /50-forged\.yaml: its signature .* does not verify/);
  assert.match(l.digest, /^[0-9a-f]{16}$/);
  writeFileSync(join(user, "10-mine.yaml"), "pack: mine\nversion: 2\nkeywords:\n  - category: me.project\n    words: [moonshot, starship]\n");
  assert.notEqual(packDirsSignature([admin, user], keys), sig0, "an edited pack changes the directory signature");
  assert.notEqual(loadPromptPacks({ userDir: user, adminDir: admin, keysDir: keys }).digest, l.digest);
  assert.deepEqual(loadPromptPacks({ userDir: join(user, "nope"), adminDir: null, keysDir: null }).packs, [], "a missing directory is no packs");
});

test("pack edits: an added pattern or keyword tightens; an edited or removed one relaxes; the result is validated", () => {
  const a = applyPackEdits(null, [
    { op: "set-prompt-pattern", pack: "mine", pattern: { id: "ticket", category: "acme.ticket", regex: "ACME-\\d{4,}" } },
    { op: "add-prompt-keyword", pack: "mine", category: "acme.codename", word: "Falcon" },
  ]);
  assert.ok(a.ok, JSON.stringify(a));
  assert.equal(a.created, true);
  assert.equal(a.doc.version, 1);
  assert.deepEqual(a.changes.map((c) => c.direction), ["tighten", "tighten"]);
  const b = applyPackEdits(a.doc, [
    { op: "set-prompt-pattern", pack: "mine", pattern: { id: "ticket", category: "acme.ticket", regex: "ACME-\\d{5,}" } },
    { op: "remove-prompt-keyword", pack: "mine", category: "acme.codename", word: "falcon" },
    { op: "add-prompt-keyword", pack: "mine", category: "acme.codename", word: "osprey" },
  ]);
  assert.ok(b.ok, JSON.stringify(b));
  assert.deepEqual(b.changes.map((c) => c.direction), ["relax", "relax", "tighten"]);
  assert.equal(b.doc.version, 2);
  const same = applyPackEdits(b.doc, [{ op: "add-prompt-keyword", pack: "mine", category: "acme.codename", word: "OSPREY" }]);
  assert.ok(same.ok && same.changes.length === 0, "an edit that changes nothing is no change");
  for (const [edits, re] of [
    [[{ op: "set-prompt-pattern", pack: "mine", pattern: { id: "x", category: "a.b", regex: "(a)\\1" } }], /pattern\.regex: the RE2 engine rejects/],
    [[{ op: "remove-prompt-pattern", pack: "mine", id: "nope" }], /no pattern nope/],
    [[{ op: "add-prompt-keyword", pack: "mine", category: "a.b", word: "x" }, { op: "add-prompt-keyword", pack: "other", category: "a.b", word: "y" }], /every edit names the same pack/],
    [[{ op: "drop-pack", pack: "mine" }], /unknown op/],
    [[{ op: "remove-prompt-pattern", pack: "mine", id: "ticket" }, { op: "remove-prompt-keyword", pack: "mine", category: "acme.codename", word: "osprey" }], /at least one pattern or keyword/],
  ] as const) {
    const r = applyPackEdits(b.doc, edits);
    assert.equal(r.ok, false);
    assert.match((r as { problems: string[] }).problems.join("\n"), re);
  }
});

test("the ordinary corpus counts a pattern that would mask every prompt (§8.1)", () => {
  assert.equal(patternMatchCounts({ id: "x", category: "a.b", regex: "ACME-\\d{4,}" }).corpus, 0);
  assert.ok(patternMatchCounts({ id: "x", category: "a.b", regex: "\\w+" }).corpus > 50);
  assert.deepEqual(patternMatchCounts({ id: "x", category: "a.b", regex: "ACME-\\d{4,}" }, "see ACME-1234 and ACME-99999"), { corpus: 0, sample: 2 });
});
