/**
 * transcript-test-values.test — which key-shaped values the scan marks as
 * looking like a test value (arbiter/policy/transcript-test-values.ts,
 * plan 17 §3 item 14), and that a real key is not:
 *
 * - each rule marks what it names (a test word between separators, one
 *   character repeated, a straight run, a repeated unit, four characters or
 *   fewer, a documented example key);
 * - near misses are not marked: a test word inside a random run or with
 *   no separator, a short run, a digit run of eight, `sk_live_` keys with
 *   random bodies, any shape that is not a vendor format;
 * - random bodies of every vendor format the detector knows are never
 *   marked (a sample of each, by property).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomInt } from "node:crypto";
import { findSecretValues } from "../../policy/secret-detectors.js";
import { looksLikeTestValue } from "../../policy/transcript-test-values.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4); none is read

/** The detector's hit for a whole value: the marker reads its shape and mask. */
function mark(value: string): boolean {
  const h = findSecretValues(value).find((x) => x.value === value);
  assert.ok(h !== undefined, `the detector takes ${value.slice(0, 8)}… for a key`);
  return looksLikeTestValue(value, h.shape, h.preview);
}

// Fake credentials, split so no scanner of this repository reads them as keys.
const OAI = "sk-" + "proj-";
const GHP = "gh" + "p_";
const AKIA = "AK" + "IA";
const SLACK = "xox" + "b-";
const RANDOM = "k3Jd8Qm2Lz7Xw4Rt9Yv6Nb1Cs5Hf0Gp2Ae7Wq";

test("a test word set off by separators, upper or lower case, marks a value", () => {
  assert.equal(mark(`${OAI}test-${RANDOM}`), true);
  assert.equal(mark(`sk-ant-api03-fake-${RANDOM}`), true);
  assert.equal(mark(`${SLACK}1111-2222-MOCK-${RANDOM.slice(0, 20)}`), true);
  assert.equal(mark(`${OAI}${RANDOM}_sample`), true, "at the end of the value");
});

test("the runs and units a person types mark a value", () => {
  assert.equal(mark(`${AKIA}0000000000000000`), true, "one character repeated");
  assert.equal(mark(`${GHP}abcdefgh${RANDOM.slice(0, 28)}`), true, "a straight run of letters");
  assert.equal(mark(`${GHP}${RANDOM.slice(0, 26)}1234567890`), true, "ten digits up, 9 to 0 a step");
  assert.equal(mark(`${OAI}abcdabcdabcdabcd${RANDOM.slice(0, 6)}`), true, "a unit repeated over 16");
  assert.equal(mark(`${OAI}a1a1b2b2a1b2a1b2b2a1a1b2`), true, "four characters make the whole body");
});

test("the documented example keys are marked", () => {
  assert.equal(mark("xox" + "b-17653672481-19874698323-pdFZKVeTuE8sk7oOcBrzbqgy"), true);
  assert.equal(mark("AI" + "zaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"), true);
});

test("near misses are not marked: a word in a random run, a short run, eight digits, a mixed-case word, no separator after a prefix that has none", () => {
  assert.equal(mark(`${OAI}k3Jtest9Qm2Lz7Xw4Rt9Yv6Nb1Cs5`), false, "inside a random run");
  assert.equal(mark(`${GHP}test${RANDOM.slice(0, 32)}`), false, "no separator after the word (a GitHub body has none)");
  assert.equal(mark(`${OAI}TeSt-${RANDOM}`), false, "a mixed-case word is a random body's");
  assert.equal(mark(`${GHP}abcdefg${RANDOM.slice(0, 29)}`), false, "seven in a row");
  assert.equal(mark(`${SLACK}123456789-4433221100-${RANDOM.slice(0, 24)}`), false, "nine digits in a row (an id can)");
  assert.equal(mark(`${SLACK}777777777-4433221100-${RANDOM.slice(0, 24)}`), false, "one digit nine times");
  assert.equal(mark(`${OAI}aaaaaaa${RANDOM}`), false, "seven of one character");
  assert.equal(mark(`${"sk" + "_live_"}51Qz7Kp2Lm9Xw3Rt6Yv8Nb4C`), false);
});

test("only the vendor formats are ever marked: never a value named like a secret, a URL's password or a private key", () => {
  assert.equal(looksLikeTestValue("test-0000000000000000", "credential-assignment", "API_TOKEN=…"), false);
  assert.equal(looksLikeTestValue("test-0000000000000000", "url-password", "https://…:…@h.dev"), false);
  assert.equal(looksLikeTestValue("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "private-key", "-----BEGIN PRIVATE KEY-----…"), false);
});

test("random bodies of every vendor format are never marked (a sample of each)", () => {
  const B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  const B64U = `${B62}-_`;
  const UP36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const rnd = (alpha: string, n: number): string => Array.from({ length: n }, () => alpha[randomInt(alpha.length)]).join("");
  const formats: Array<() => string> = [
    () => OAI + rnd(B64U, 48), () => "sk-ant-api03-" + rnd(B64U, 93), () => GHP + rnd(B62, 36), () => AKIA + rnd(UP36, 16),
    () => "AI" + "za" + rnd(B64U, 35), () => "sk" + "_live_" + rnd(B62, 24), () => SLACK + rnd("0123456789", 11) + "-" + rnd("0123456789", 11) + "-" + rnd(B62, 24),
    () => "np" + "m_" + rnd(B62, 36), () => "h" + "f_" + rnd(B62, 34), () => "gl" + "pat-" + rnd(B64U, 20),
  ];
  for (const gen of formats) {
    for (let i = 0; i < 3000; i++) {
      const v = gen();
      const h = findSecretValues(v).find((x) => x.value === v);
      if (h !== undefined) assert.equal(looksLikeTestValue(v, h.shape, h.preview), false, `${h.preview} with a random body`);
    }
  }
});
