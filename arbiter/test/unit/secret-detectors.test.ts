/**
 * secret-detectors.test — the content detectors every secret scan shares
 * (arbiter/policy/secret-detectors.ts; confidentiality-plan-14 §3.1, §13.2):
 * the detector per format, the placeholder filter, the masks (never a
 * character of a value's body), the helpers, and the FINGERPRINT PINNED.
 *
 * The detector tests moved here from secret-history-scan.test.ts with the
 * code (plan 14 §13.2). The pin: `historyDetectorFingerprint` hashes the
 * detector's source text and keys the history scan's on-disk cache; a
 * changed value makes every repository's next history scan read every blob
 * again, so the move had to leave it unchanged (the value below is master's
 * before the move, computed under this suite's runner, tsx). A deliberate
 * detector change updates the pin in the same change.
 *
 * Fixture keys are assembled at run time, so this file itself holds no
 * credential-shaped literal for a scanner (this one included) to report.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  detectSecretShapes,
  entropy,
  githubTokenChecksumOk,
  historyDetectorFingerprint,
  HISTORY_DETECTOR_VERSION,
  isBinaryBlob,
  isPlaceholder,
  isStandIn,
  locateSecretShapes,
  randomLetters,
  looksLikeSecretValue,
} from "../../policy/secret-detectors.js";
import * as historyScan from "../../policy/secret-history-scan.js";
import { stateAxes } from "../axes.js";
import { randomSecretBody } from "../helpers/random-secret.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4); none is read

/** Master's value before the move (2026-09-30, 68cc3c4f) was 271ce09f…;
 *  moved on purpose by GitHub's checksum (2026-09-30, secret-discovery.md §3
 *  §2 item 5) to 796918a1…, and again by the no-digit security fix
 *  (2026-10-01, `mixed` no longer demands a digit): each repository's next
 *  history scan reads every blob once, so blobs a cache called clean under
 *  the old rule are looked at again (wanted: the old rule missed keys).
 *  Moved on purpose again 2026-10-02 from c2a0c08d… (the stand-in words
 *  forgiven inside a random run, a letters-only assignment value): one more
 *  full rescan, again wanted (the old rule missed those keys). */
const PINNED_FINGERPRINT = "a94dcab6ac93792258353141ecdd397c5abe43a546b9aec4db3463fbfe0c3a0a";

test("the fingerprint is pinned: only a deliberate detector change moves it", () => {
  assert.equal(HISTORY_DETECTOR_VERSION, 1);
  assert.equal(historyDetectorFingerprint(), PINNED_FINGERPRINT,
    "the detector's fingerprint moved: every repository's next history scan reads every blob again. If the change is deliberate, update the pin");
});

test("secret-history-scan re-exports the detectors (no import broke)", () => {
  assert.equal(historyScan.detectSecretShapes, detectSecretShapes);
  assert.equal(historyScan.isPlaceholder, isPlaceholder);
  assert.equal(historyScan.entropy, entropy);
  assert.equal(historyScan.looksLikeSecretValue, looksLikeSecretValue);
  assert.equal(historyScan.isBinaryBlob, isBinaryBlob);
  assert.equal(historyScan.historyDetectorFingerprint, historyDetectorFingerprint);
  assert.equal(historyScan.HISTORY_DETECTOR_VERSION, HISTORY_DETECTOR_VERSION);
});


// ── fixture values (assembled, never literal) ────────────────────────────────
const rep = (s: string, n: number): string => s.repeat(n);
const BODY = "Q7wX2mZ9pL4kV8rT";
const K = {
  anthropic: "sk-" + "ant-" + "api03-" + BODY + BODY,
  openai: "sk-" + "proj-" + BODY + BODY,
  github: "gh" + "p_" + rep("A1b2C3d4", 5),
  githubPat: "github" + "_pat_" + rep("11ABCDEFG0", 7),
  gitlab: "gl" + "pat-" + BODY + "x9" + BODY,
  slack: "xo" + "xb-" + "1234567890-" + BODY,
  stripe: "sk" + "_live_" + BODY + BODY,
  google: "AI" + "za" + BODY + BODY + "abc",
  npm: "np" + "m_" + rep("aB3dE5fG7h", 4).slice(0, 36),
  pypi: "py" + "pi-AgE" + rep(BODY, 4),
  hf: "h" + "f_" + BODY + BODY + "zz",
  awsId: "AK" + "IA" + "Q7WX2MZ9PL4KV8RT",
  awsSecret: rep("Q7wX2mZ9/pL4kV8rT+", 3).slice(0, 40),
  dbPass: "Zr8" + "!kq2Vw9pLx4",
  urlPass: "s3cr" + "etPw9Xq",
  pemBody: rep("b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ", 2),
};
const PEM = `-----BEGIN OPENSSH PRIVATE KEY-----\n${K.pemBody}\n${K.pemBody.slice(0, 40)}\n-----END OPENSSH PRIVATE KEY-----\n`;

/** Every fixture value's body (past its public prefix), for the no-leak checks. */
const BODIES = [BODY, K.awsId.slice(4), K.awsSecret.slice(4), K.dbPass, K.urlPass, K.pemBody.slice(0, 20), K.githubPat.slice(11, 30), K.npm.slice(4)];

function assertNoValue(text: string, what: string): void {
  for (const b of BODIES) assert.ok(!text.includes(b), `${what} carries a value body (${b.slice(0, 3)}…)`);
}

// ── the detector ─────────────────────────────────────────────────────────────

test("detector: every known format is found, masked to its public prefix", () => {
  const text = [
    `ANTHROPIC=${K.anthropic}`,
    `openai_key: ${K.openai}`,
    `token ${K.github}`,
    `pat ${K.githubPat}`,
    `gitlab ${K.gitlab}`,
    `slack ${K.slack}`,
    `stripe ${K.stripe}`,
    `google ${K.google}`,
    `npm ${K.npm}`,
    `pypi ${K.pypi}`,
    `hf ${K.hf}`,
  ].join("\n");
  const hits = detectSecretShapes(text, { maxHits: 50 });
  const by = Object.fromEntries(hits.map((h) => [h.shape, h]));
  assert.equal(by["anthropic-key"]?.preview, "sk-ant-…");
  assert.equal(by["anthropic-key"]?.line, 1);
  assert.equal(by["openai-key"]?.preview, "sk-proj-…");
  assert.ok(hits.some((h) => h.shape === "github-token" && h.preview === "ghp_…"));
  assert.equal(by["gitlab-token"]?.preview, "glpat-…");
  assert.equal(by["slack-token"]?.preview, "xoxb-…");
  assert.equal(by["stripe-key"]?.preview, "sk_live_…");
  assert.equal(by["google-api-key"]?.preview, "AIza…");
  assert.equal(by["npm-token"]?.preview, "npm_…");
  assert.equal(by["pypi-token"]?.preview, "pypi-…");
  assert.equal(by["huggingface-token"]?.preview, "hf_…");
  assert.ok(hits.some((h) => h.preview === "github_pat_…"), "the fine-grained GitHub token too");
  assert.equal(hits.filter((h) => h.shape === "openai-key").length, 1, "an Anthropic key is not also an OpenAI key");
  assertNoValue(JSON.stringify(hits), "the hits");
});

test("detector: AWS, a URL password, a credential assignment and a private-key block", () => {
  const text = `[default]\naws_access_key_id = ${K.awsId}\naws_secret_access_key = ${K.awsSecret}\n` +
    `DATABASE_URL=postgres://app:${K.urlPass}@db.internal:5432/app\n` +
    `DB_PASSWORD="${K.dbPass}"\n\n${PEM}`;
  const hits = detectSecretShapes(text, { maxHits: 50 });
  const by = Object.fromEntries(hits.map((h) => [h.shape, h]));
  assert.equal(by["aws-access-key-id"]?.preview, "AKIA…");
  assert.equal(by["aws-access-key-id"]?.line, 2);
  assert.equal(by["aws-secret-key"]?.preview, "aws_secret_access_key=…");
  assert.equal(by["url-password"]?.preview, "postgres://…:…@db.internal", "the host is shown, not the user or the password");
  assert.equal(by["credential-assignment"]?.preview, "DB_PASSWORD=…");
  assert.equal(by["private-key"]?.preview, "-----BEGIN OPENSSH PRIVATE KEY-----…");
  assert.equal(by["private-key"]?.line, 7);
  assertNoValue(JSON.stringify(hits), "the hits");
  assert.ok(!JSON.stringify(hits).includes("app:"), "the URL's user name is not shown");
});

test("detector: placeholders, documentation and code are not credentials", () => {
  const text = [
    "-----BEGIN RSA PRIVATE KEY-----",                       // a header alone (docs)
    "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",               // AWS's own example
    "password = request.form['password']",                   // code
    "api_key = os.environ.get('API_KEY')",
    "TOKEN=${GITHUB_TOKEN}",
    "SECRET_KEY=changeme-changeme-123",
    "GH_TOKEN=<your token here>",
    "API_KEY=$MDU:nomodel_Read[9bbd].API_KEY",
    "url = https://user:password@example.com",
    "passwd: xxxxxxxxxxxxxxxx1",
    "session_token_expiry = 3600000000000",
  ].join("\n");
  assert.deepEqual(detectSecretShapes(text), []);
});

test("detector: an assignment whose name could be part of a credential shows no name", () => {
  const name = "aB3" + "secret" + "Q9zX7wK2mP";
  const hits = detectSecretShapes(`${name}=${K.dbPass}Zz1`);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]!.preview, "credential=…");
  // A name right after a string escape is the name, not the escape's letter.
  const esc = detectSecretShapes(`const env = "MODE=x\\nAPI_TOKEN=${K.dbPass}";`);
  assert.equal(esc[0]?.preview, "API_TOKEN=…");
});

test("detector: one hit per (shape, value), capped", () => {
  const same = Array.from({ length: 5 }, () => `x ${K.github}`).join("\n");
  assert.equal(detectSecretShapes(same).length, 1);
  const many = Array.from({ length: 30 }, (_, i) => `x ${"gh" + "p_" + rep("A1b2C3d4", 4)}${String(i).padStart(4, "0")}`).join("\n");
  assert.equal(detectSecretShapes(many, { maxHits: 7 }).length, 7);
});

test("helpers: placeholders, entropy, the secret-value test, git's binary test", () => {
  assert.ok(isPlaceholder("changeme"));
  assert.ok(isPlaceholder("${X}"));
  assert.ok(isPlaceholder("aaaaaaaaaaaa"));
  assert.ok(!isPlaceholder(K.dbPass));
  assert.ok(entropy("aaaa") === 0);
  assert.ok(entropy(BODY) > 3.5);
  assert.ok(looksLikeSecretValue(K.dbPass));
  assert.ok(!looksLikeSecretValue("abcdefghijklmnop"), "no digit");
  assert.ok(!looksLikeSecretValue("abc123"), "too short");
  assert.ok(isBinaryBlob(Buffer.from([0x41, 0x00, 0x42])));
  assert.ok(!isBinaryBlob(Buffer.from("plain text\n")));
  assert.ok(!isBinaryBlob(Buffer.concat([Buffer.alloc(8000, 0x41), Buffer.from([0])])), "only the first 8000 bytes count");
});

test("the scan tests' random fixture bodies are always a value the detectors take (the digit-less draw that flaked dashboard-suggestions)", () => {
  // A plain random draw of 36 alphanumerics has no digit 0.19% of the time.
  // The detector once dropped such a body (`mixed` demanded a digit); since
  // the 2026-10-01 fix it takes it (tests below). The helper still draws a
  // digit, for the assignment rule (`looksLikeSecretValue`), and no
  // placeholder run (`isPlaceholder`), which the detector filters at a
  // body's edge (inside a random run it is forgiven since 2026-10-02).
  assert.deepEqual(detectSecretShapes(`API_TOKEN = "${"gh" + "p_" + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"}"\n`).map((h) => h.shape), ["github-token"]);
  // The helper every scan test draws from never gives a body it drops.
  for (let i = 0; i < 5000; i++) {
    const body = randomSecretBody(36);
    assert.equal(body.length, 36);
    assert.match(body, /^[A-Za-z0-9]+$/);
    const token = "gh" + "p_" + body;
    for (const text of [`API_TOKEN = "${token}"\n`, `GITHUB_TOKEN=${token}\n`]) {
      assert.deepEqual(detectSecretShapes(text).map((h) => h.shape), ["github-token"], `draw ${i} was not detected`);
    }
    assert.ok(looksLikeSecretValue(randomSecretBody(12)), "short draws pass the assignment rule too");
  }
  assert.throws(() => randomSecretBody(1), /too short/);
});


// ── GitHub's checksum (secret-discovery.md §3.2 item 5) ────────────────────────

/** An independent CRC-32 (IEEE, reflected 0xEDB88320), not node:zlib's. */
const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32Ref(s: string): number {
  let c = 0xffffffff;
  for (const ch of Buffer.from(s, "latin1")) c = CRC_TABLE[(c ^ ch) & 0xff]! ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
const B62 = "0123456789" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghijklmnopqrstuvwxyz";
function checksumRef(random30: string): string {
  let n = crc32Ref(random30);
  let out = "";
  for (let i = 0; i < 6; i++) { out = B62[n % 62]! + out; n = Math.floor(n / 62); }
  return out;
}
const LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghijklmnopqrstuvwxyz";
const pick = (alphabet: string, n: number): string =>
  Array.from({ length: n }, () => alphabet[Math.floor(Math.random() * alphabet.length)]!).join("");
/** The last character changed: the checksum no longer holds. */
const brokenChecksum = (token: string): string =>
  token.slice(0, -1) + (token.endsWith("Q") ? "R" : "Q");

test("GitHub checksum: the known-answer vectors, published scanner test tokens (Yelp detect-secrets, semgrep-rules), hold", () => {
  // Split so this file holds no token-shaped literal.
  const vectors = [
    ["wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO", "0pINUx"],
    ["0fAGST5ohwj3Aio6ul2ncFNgdncvat", "1udBt1"],
    ["J2YfbObjXcaT8Bfpa3kxe5iiY0TkwS", "1uNnDa"],
    ["JujvHMXIPJycMxHSxVM1JT9oix3VHn", "2SD4vk"],
  ] as const;
  for (const [random, sum] of vectors) {
    assert.equal(checksumRef(random), sum, "the reference implementation reproduces the published vector");
    assert.ok(githubTokenChecksumOk("gh" + "p_" + random + sum), `${sum} validates`);
    assert.ok(!githubTokenChecksumOk(brokenChecksum("gh" + "p_" + random + sum)), "a changed checksum does not");
  }
  // Every prefixed type uses the same check; other prefixes, lengths and the
  // fine-grained format are not covered by it (they keep the digit rule).
  const random = pick(LETTERS, 30);
  for (const p of ["p", "o", "u", "s", "r"]) assert.ok(githubTokenChecksumOk("gh" + p + "_" + random + checksumRef(random)));
  assert.ok(!githubTokenChecksumOk("gh" + "x_" + random + checksumRef(random)));
  assert.ok(!githubTokenChecksumOk("gh" + "p_" + random + checksumRef(random) + "a"), "37 characters is not the checksummed layout");
  assert.ok(!githubTokenChecksumOk("github" + "_pat_" + random + checksumRef(random)));
});

test("GitHub checksum: a real token always holds a digit (its checksum's first character), so the digit rule never missed one", () => {
  // CRC-32 < 2^32 and 2^32 / 62^5 < 5: the checksum's leading base62 digit
  // is 0-4 whatever the random part (an all-letter random part included).
  for (let i = 0; i < 2000; i++) {
    const random = pick(LETTERS, 30);
    const sum = checksumRef(random);
    assert.match(sum, /^[0-4]/);
    const token = "gh" + "p_" + random + sum;
    assert.deepEqual(detectSecretShapes(`token ${token}\n`).map((h) => h.shape), ["github-token"], `draw ${i}`);
  }
  assert.equal(checksumRef("z".repeat(30)).length, 6);
});

test("GitHub checksum: a real token whose random part a placeholder pattern takes is found (the old rule's miss); without the checksum the filter holds", () => {
  // A random body holds `xxxx`, `dummy`, … 2.75 times in 100,000
  // (secret-discovery.md §3.2 item 5); the old rule dropped those real tokens.
  // A holding checksum means the string was minted in GitHub's format (a
  // chance match is 1 in 2^32), so the placeholder filter does not apply.
  for (const seed of ["xxxx", "XXXX", "dummy", "Example", "redacted", "changeme"]) {
    const random = (seed + pick(LETTERS, 30)).slice(0, 30);
    const token = "gh" + "p_" + random + checksumRef(random);
    assert.ok(isPlaceholder(token.slice(4)), seed);
    const hits = detectSecretShapes(`token ${token}\n`);
    assert.deepEqual(hits.map((h) => h.shape), ["github-token"], seed);
    assert.equal(hits[0]!.preview, "ghp_…");
    assert.ok(!JSON.stringify(hits).includes(random.slice(4, 16)), "the mask carries no body");
    assert.deepEqual(detectSecretShapes(`token ${brokenChecksum(token)}\n`), [], `${seed}: without the checksum the placeholder filter still holds`);
  }
});

test("GitHub checksum only widens: every token the old rule took is still found (property, 20,000 draws)", () => {
  const ALNUM = LETTERS + "0123456789";
  // The rule before this change (`mixed`), spelled out.
  const oldOk = (v: string): boolean => /[A-Za-z]/.test(v) && /[0-9]/.test(v) && !isPlaceholder(v);
  const prefixes = ["p", "o", "u", "s", "r"].map((p) => "gh" + p + "_");
  let oldTook = 0;
  for (let i = 0; i < 20_000; i++) {
    // Plain, digit-poor, letter-poor, placeholder-seeded, checksum-valid,
    // and longer than 36.
    const kind = i % 6;
    const len = kind === 5 ? 37 + Math.floor(Math.random() * 40) : 36;
    let body = kind === 1 ? pick(LETTERS, len - 1) + pick("0123456789", 1)
      : kind === 2 ? pick("0123456789", len - 1) + pick(LETTERS, 1)
      : kind === 3 ? "xxxx" + pick(ALNUM, len - 4)
      : pick(ALNUM, len);
    if (kind === 4) body = body.slice(0, 30) + checksumRef(body.slice(0, 30));
    const token = prefixes[i % 5]! + body;
    const found = detectSecretShapes(`token ${token}\n`).some((h) => h.shape === "github-token");
    if (oldOk(token.slice(4))) {
      oldTook++;
      assert.ok(found, `the old rule took a ${token.slice(0, 4)} token (kind ${kind}) and the new one does not`);
    }
    if (githubTokenChecksumOk(token)) assert.ok(found, "a checksum-valid token is always found");
  }
  assert.ok(oldTook > 10_000, `the property ran on enough old hits (${oldTook})`);
});


// ── A vendor-prefixed value with no digit (SECURITY FIX, 2026-10-01) ─────────
// `mixed` demanded a digit, so a prefixed key whose body held none was not a
// key: every real Hugging Face token (`hf_` + 34 letters, its format), 3.3%
// of 20-character GitLab tokens, 1.5% of 24-character Stripe keys, 0.19% of
// any 36-character alphanumeric body. The policy model's contents tier
// (§14.13) then sent a .docx holding such a key to the model
// (test-reorganization.md §11.3; secret-discovery.md §3.2 item 5).

/** Bodies the e2e `policy-model-contents` Office fixture drew and the old
 *  rule missed (measured: 376 of 200,000 draws had no digit), and
 *  real-format bodies with none. Letters only, assembled with their prefix. */
const MISSED_GH = [
  "CbJiNfhugJPCLePwqbaWFAtLXUOCyPrvOqcQ",
  "YkuXSOdAUKHorJdrETriajCzyPZDVVeCyGLT",
  "TOBIuHRJOEOYbIgcGjrMrINcmMkNyQnbPDKe",
  "HzrIzfcAvSavnmjgABIvaCAKzvuetYbwuYmK",
  "qFXRVtsbLDQoDZlDxiiPVibaINvLWMcjcYgJ",
];
const MISSED: Array<[string, string, string]> = [
  ...MISSED_GH.map((b): [string, string, string] => ["github-token", "gh" + "p_", b]),
  ["github-token", "gh" + "s_", MISSED_GH[1]!],
  ["huggingface-token", "h" + "f_", "vKasFwbTAvvcYDTbNaEBTiYElXWyoVjKah"],
  ["huggingface-token", "h" + "f_", "bKbUeDwYXJztFrhmXElOZmQewBBncxrHtR"],
  ["gitlab-token", "gl" + "pat-", "dWMdbcOCpdpUHqLGbYVJ"],
  ["stripe-key", "sk" + "_live_", "KKmeoURMqHwfviIEhJpbghnt"],
  ["npm-token", "np" + "m_", MISSED_GH[2]!],
  ["anthropic-key", "sk-" + "ant-", "wctQKKlwhHhKJirVnPWJlBZfuTn"],
  ["slack-token", "xo" + "xb-", "lzfXjyzaaHDtUkK"],
];

test("SECURITY FIX: a prefixed key whose body holds no digit is found, by its kind, masked (the values the old rule missed)", () => {
  for (const [shape, prefix, body] of MISSED) {
    assert.ok(!/[0-9]/.test(body), `${shape}: the fixture holds no digit`);
    for (const text of [`KEY ${prefix}${body}\n`, `API_TOKEN=${prefix}${body}\n`, `Deploy notes\nHF_TOKEN="${prefix}${body}"`]) {
      const hits = detectSecretShapes(text);
      assert.deepEqual(hits.map((h) => h.shape), [shape], `${shape} ${prefix}… in ${JSON.stringify(text.slice(0, 9))}`);
      assert.equal(hits[0]!.preview, `${prefix}…`);
      assert.ok(!JSON.stringify(hits).includes(body.slice(0, 12)), "the mask carries no body");
    }
  }
});

test("SECURITY FIX: a no-digit draw of every prefixed format is found unless the placeholder filter takes it (property, 20,000 draws)", () => {
  const formats: Array<[string, string, string, number]> = [
    ["github-token", "gh" + "p_", LETTERS, 36],
    ["huggingface-token", "h" + "f_", LETTERS, 34],
    ["gitlab-token", "gl" + "pat-", LETTERS + "_-", 20],
    ["stripe-key", "rk" + "_live_", LETTERS, 24],
    ["npm-token", "np" + "m_", LETTERS, 36],
    ["openai-key", "sk-" + "proj-", LETTERS + "_-", 48],
  ];
  let checked = 0;
  for (let i = 0; i < 20_000; i++) {
    const [shape, prefix, alphabet, n] = formats[i % formats.length]!;
    const body = pick(alphabet, n);
    // The placeholder filter's own rate on a random body: ~4.5 in 100,000
    // (`xxxx`, `dummy`, …; secret-discovery.md §3.2 item 5).
    if (isPlaceholder(prefix + body)) continue;
    checked++;
    assert.deepEqual(detectSecretShapes(`KEY ${prefix}${body}\n`).map((h) => h.shape), [shape], `draw ${i}: ${shape}`);
  }
  assert.ok(checked > 19_900, `the property ran on enough draws (${checked})`);
});

test("SECURITY FIX only widens: every prefixed value the digit rule took is still taken; a no-digit run under 3 bits a character is not a key", () => {
  const ALNUM = LETTERS + "0123456789";
  const oldMixed = (v: string): boolean => /[A-Za-z]/.test(v) && /[0-9]/.test(v) && !isPlaceholder(v);
  const prefixes: Array<[string, string, number]> = [["huggingface-token", "h" + "f_", 34], ["npm-token", "np" + "m_", 36], ["gitlab-token", "gl" + "pat-", 20]];
  let oldTook = 0;
  for (let i = 0; i < 6000; i++) {
    const [shape, prefix, n] = prefixes[i % 3]!;
    // Digit-poor and repetitive bodies, where an entropy floor could bite.
    const body = i % 2 === 0 ? pick("ab1", n) : pick(ALNUM, n);
    const v = prefix + body;
    if (!oldMixed(v)) continue;
    oldTook++;
    assert.ok(detectSecretShapes(`KEY ${v}\n`).some((h) => h.shape === shape), `the old rule took ${shape} draw ${i}`);
  }
  assert.ok(oldTook > 5000, `enough old hits (${oldTook})`);
  // What the entropy floor still drops: a run, two letters alternating.
  assert.deepEqual(detectSecretShapes(`KEY ${"gh" + "p_" + "a".repeat(36)}\n`), []);
  assert.deepEqual(detectSecretShapes(`KEY ${"h" + "f_" + "ab".repeat(17)}\n`), []);
  assert.deepEqual(detectSecretShapes(`KEY ${"gh" + "p_" + "x".repeat(36)}\n`), [], "the placeholder filter holds");
});


// ── Detection misses closed 2026-10-02 (secret-discovery.md §3.2 item 5) ──────
// (a) The stand-in WORD test dropped a real key whose random body held
//     `xxxx` or `dummy` by chance (~4.5 in 100,000) for every format but
//     GitHub's checksummed tokens; `isStandIn` now forgives such a word
//     inside a random run. (b) The assignment rule demanded a digit, so
//     `DB_PASSWORD=` with a letters-only password was no credential.
//     (c) `github_pat_` carries no published checksum (see
//     githubTokenChecksumOk); it takes the (a) rule like every format.

const R1 = "Q7wX2mZ9pL4kV8rT";
const R2 = "Hn3bR6tY9cJ2wE5q";
/** Real-format values whose random body holds a stand-in word by chance:
 *  every one was MISSED by the detector before this change. Assembled. */
const CHANCE: Array<[string, string, string]> = [
  ["anthropic-key", `${"sk-" + "ant-"}api03-${R1}xxxx${R2}`, "sk-ant-…"],
  ["openai-key", `${"sk-" + "proj-"}${R1}dummy${R2}`, "sk-proj-…"],
  ["gitlab-token", `${"gl" + "pat-"}${R1}xxxx${R2.slice(0, 4)}`, "glpat-…"],
  ["slack-token", `${"xo" + "xb-"}1234567890-${R1}XXXX${R2}`, "xoxb-…"],
  ["stripe-key", `${"sk" + "_live_"}${R1}Dummy${R2}`, "sk_live_…"],
  ["google-api-key", `${"AI" + "za"}${R1}xxxx${R2.slice(0, 15)}`, "AIza…"],
  ["npm-token", `${"np" + "m_"}${R1}xxxx${R2}`, "npm_…"],
  ["pypi-token", `${"py" + "pi-AgE"}${R1}${R2}xxxx${R1}${R2}`, "pypi-…"],
  ["huggingface-token", `${"h" + "f_"}${R1}dummy${R2}`, "hf_…"],
  ["aws-access-key-id", `${"AK" + "IA"}Q7W2XXXXM9PL4KV8`, "AKIA…"],
  ["github-token", `${"github" + "_pat_"}11ABCDEFG0${R1.slice(0, 12)}_${R1}${R2}xxxx${R1}${R2.slice(0, 7)}`, "github_pat_…"],
];
const AWS_SECRET_CHANCE = "Q7wX2m" + "Z9/pL4kV8rTa" + "dummy" + "Hn3bR6tY9cJ2wE5q+";
const URL_PW_CHANCE = "Zr8kq" + "2Vw9pL" + "xxxx" + "4QbTy7Nm";
const ASSIGN_CHANCE = "Zr8kq" + "2Vw9pL" + "dummy" + "4QbTy7NmA";

test("MISS (a) CLOSED: a real-format key whose random body holds xxxx or dummy is found, for every format, masked", () => {
  for (const [shape, v, preview] of CHANCE) {
    assert.ok(isPlaceholder(v), `${shape}: the fixture holds a stand-in word (the old filter's drop)`);
    assert.ok(!isStandIn(v), `${shape}: inside a random run it is forgiven`);
    const hits = detectSecretShapes(`KEY ${v}\n`);
    assert.deepEqual(hits.map((h) => h.shape), [shape], shape);
    assert.equal(hits[0]!.preview, preview);
    assert.ok(!JSON.stringify(hits).includes(R1.slice(0, 10)), "the mask carries no body");
    assert.deepEqual(locateSecretShapes(`KEY ${v}\n`).map((s) => s.shape), [shape], `${shape}: the prompt filter's locator finds it too`);
  }
  const text = `aws_secret_access_key = ${AWS_SECRET_CHANCE}\nDATABASE_URL=postgres://app:${URL_PW_CHANCE}@db.internal/app\nDB_PASSWORD=${ASSIGN_CHANCE}\n`;
  assert.deepEqual(detectSecretShapes(text).map((h) => h.shape).sort(), ["aws-secret-key", "credential-assignment", "url-password"]);
  const spans = locateSecretShapes(text);
  assert.deepEqual(spans.map((s) => text.slice(s.start, s.end)).sort(), [AWS_SECRET_CHANCE, ASSIGN_CHANCE, URL_PW_CHANCE].sort());
});

test("MISS (a): a person's placeholder stays one (a longer word, a word at a separator, six x, AWS's documentation values)", () => {
  const stand = [
    "sk-" + "ant-oat01-" + "PLACEHOLDER-not-a-real-token",
    "sk-" + "dummy-key-not-real-000000",
    "sk-" + "ant-" + "mdudiff-dummy-key-0000",
    "AK" + "IA" + "IOSFODNN7EXAMPLE",
    "gh" + "p_" + "x".repeat(36),
    "h" + "f_" + "x".repeat(34),
    "sk-" + "ant-api03-" + "x".repeat(24),
    "gl" + "pat-" + "xxxx" + "abcdEFGH1234ijklMNOP",
    "np" + "m_" + "xxxxxx" + R1 + R2.slice(0, 14),
    "AI" + "za" + "EXAMPLE" + R1 + R2.slice(0, 12),
    "sk" + "_live_" + R1 + "example" + R2,
    // A chance word at the value's END is forgiven no more than one at its
    // separator: a random body that ends in `dummy` reads as a stand-in
    // (the recorded trade-off, about 1 draw in 400,000: secret-discovery.md
    // §3.2 item 5; the property test below keeps such bodies out).
    "np" + "m_" + "CQ781CqO0ELDummyQFQtZAtvbCwoydq" + "DUmMY",
  ];
  for (const v of stand) {
    assert.ok(isStandIn(v), v.slice(0, 12));
    assert.deepEqual(detectSecretShapes(`KEY ${v}\n`), [], `${v.slice(0, 12)}… is a stand-in`);
  }
  const doc = [
    "aws_secret_access_key = " + "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY",
    "DB_PASSWORD=" + "your_password_here_123",
    "API_KEY=" + "Zr8kq2Vw9pL" + "-dummy-" + "4QbTy7Nm",
    "url = postgres://u:" + "Zr8kq2Vw9pL" + "_xxxx_" + "4QbTy7Nm@db.internal",
  ].join("\n");
  assert.deepEqual(detectSecretShapes(doc), []);
});

test("MISS (a) only widens: every stand-in is a placeholder, and a chance word strictly inside a random body is found (property, 12,000 draws)", () => {
  const ALNUM = LETTERS + "0123456789";
  const words = ["xxxx", "XXXX", "xXxX", "dummy", "DUMMY", "Dummy"];
  let found = 0;
  for (let i = 0; i < 12_000; i++) {
    const w = words[i % words.length]!;
    // The word ends before the 36th character and touches no other x, so
    // a random character sits on both sides of it (a word touching the
    // prefix's separator, `npm_xxxx…`, stays a stand-in: the old filter).
    // The body holds no chance word of its own: a `dummy` it drew at an
    // edge (`…qDUmMY`, about 1 draw in 10^7) is that edge case, not this
    // property (2026-10-11, one CI failure in 200 runs).
    let body = pick(ALNUM, 32).replace(/x/gi, "Q");
    while (/dummy/i.test(body)) body = pick(ALNUM, 32).replace(/x/gi, "Q");
    const at = 1 + Math.floor(Math.random() * (35 - w.length));
    const seeded = body.slice(0, at) + w + body.slice(at);
    for (const v of [seeded, body, w + body, body + w, `${body.slice(0, at)}-${w}-${body.slice(at)}`]) {
      if (isStandIn(v)) assert.ok(isPlaceholder(v), "isStandIn implies isPlaceholder (the filter only shrinks)");
    }
    if (/x{6}/i.test(seeded)) continue;
    const token = "np" + "m_" + seeded.slice(0, 36);
    if (detectSecretShapes(`KEY ${token}\n`).some((h) => h.shape === "npm-token")) found++;
    else assert.fail(`draw ${i}: ${w} inside a random body was dropped (${token})`);
  }
  assert.ok(found > 11_900, `enough draws ran (${found})`);
});

/** Letters-only values: (b). */
const LETTERS_PW = ["hJkqWzPmvXrTbnLs", "QwRtYpLkJhGfDsZxCvBn", "mNbVcXzLkJhGfDsAqWeRtY"];

test("MISS (b) CLOSED: a letters-only password assigned to a credential name is found, masked to its name", () => {
  for (const pw of LETTERS_PW) {
    assert.ok(!/[0-9]/.test(pw));
    assert.ok(randomLetters(pw) && looksLikeSecretValue(pw), pw.slice(0, 3));
    for (const [text, preview] of [[`DB_PASSWORD=${pw}\n`, "DB_PASSWORD=…"], [`  api_key: "${pw}"\n`, "api_key=…"], [`export SECRET_TOKEN='${pw}'\n`, "SECRET_TOKEN=…"]] as const) {
      const hits = detectSecretShapes(text);
      assert.deepEqual(hits.map((h) => [h.shape, h.preview]), [["credential-assignment", preview]], text);
      assert.ok(!JSON.stringify(hits).includes(pw.slice(0, 6)), "the mask carries no body");
      const spans = locateSecretShapes(text);
      assert.deepEqual(spans.map((s) => text.slice(s.start, s.end)), [pw]);
    }
  }
});

test("MISS (b): identifiers, code and one-case words assigned to a credential name are not passwords", () => {
  const code = [
    "token = floatToFixedToStr(token, precisionBits=16)",
    "password = getPasswordFromEnv()",
    "api_key = process.env.API_KEY",
    "SECRET_KEY = settings.SecretKeyValue",
    "token: isJSDocPublicTag",
    "secret = XMLHttpRequestUpload",
    "tokenType = AuthorizationHeaderValue",
    "password_field = currentUserPassword",
    "secret_name = requestPasswordResetEmail",
    "PASSWORD=correcthorsebatterystaple",
    "GITHUB_TOKEN=GITHUBTOKENFORACTIONS",
    "passphrase = useTokenRefreshInterval",
  ].join("\n");
  assert.deepEqual(detectSecretShapes(code), []);
  for (const v of ["getSecretTokenValue", "XMLHttpRequestUpload", "floatToFixedToStr", "isJSDocPublicTag", "correcthorsebatterystaple", "hJkq-WzPm-vXrT-bnLs"]) {
    assert.ok(!randomLetters(v), v);
  }
});

test("MISS (b): most letters-only random passwords are taken, and the assignment rule only widens (property)", () => {
  const ALNUM = LETTERS + "0123456789";
  const oldLooks = (v: string): boolean => v.length >= 12 && /[A-Za-z]/.test(v) && /[0-9]/.test(v) && !isPlaceholder(v) && entropy(v) >= 3.0;
  let taken = 0;
  for (let i = 0; i < 5000; i++) if (looksLikeSecretValue(pick(LETTERS, 24))) taken++;
  // Measured ~90% at 24 letters (~72% at 16): a random mix of cases with a
  // vowel share or case runs that read as words is the miss left.
  assert.ok(taken > 4000, `letters-only 24-character passwords taken: ${taken} of 5000`);
  let oldTook = 0;
  for (let i = 0; i < 20_000; i++) {
    const n = 12 + (i % 30);
    const kind = i % 4;
    const v = kind === 0 ? pick(ALNUM, n) : kind === 1 ? pick(LETTERS, n - 1) + pick("0123456789", 1)
      : kind === 2 ? pick("ab1", n) : pick(ALNUM, n - 4) + "xxxx";
    if (!oldLooks(v)) continue;
    oldTook++;
    assert.ok(looksLikeSecretValue(v), `the old rule took draw ${i} (kind ${kind}) and the new one does not`);
  }
  assert.ok(oldTook > 8000, `enough old hits (${oldTook})`);
});

test("MISS (c): github_pat_ has no checksum to check; its exact layout takes the stand-in rule like every format", () => {
  const pat = CHANCE.find(([s, v]) => s === "github-token" && v.startsWith("github"))![1];
  assert.equal(pat.length, 93, "github_pat_ + 22 + _ + 59");
  assert.ok(!githubTokenChecksumOk(pat), "the classic checksum does not apply to the fine-grained layout");
  assert.deepEqual(detectSecretShapes(`GH_TOKEN=${pat}\n`).map((h) => h.preview), ["github_pat_…"]);
  assert.deepEqual(detectSecretShapes(`GH_TOKEN=${"github" + "_pat_"}${"x".repeat(22)}_${"x".repeat(59)}\n`), [], "the all-x template is no token");
});
