/**
 * level-parts.test — dashboard.md §4.25u *A waiting change names each host*:
 * the Rules page's words for a level with its hosts, and Save's lines that
 * say what a loosening becomes, come as parts too, each host a code of its
 * own and the text exactly the string they stand beside.
 *
 *   L1  `levelParts`: its text is `levelWords`, byte for byte, for every
 *       level with and without hosts (an unknown level reads as "No AI",
 *       the fail-closed words; "Not secret" names no host); the hosts are
 *       the codes, in order; no two text parts touch; two calls share no
 *       part;
 *   L2  `sentenceParts`: neighbouring text joined, empty text dropped, each
 *       part copied;
 *   L3  `looseningWords`: a policy.yaml loosening to a level with hosts
 *       sends `detailParts` reading as its `detail`, each host a code; a
 *       line that names no host (Not secret, a removed rule, another
 *       facet) sends none;
 *   L4  a page-store loosening (`planFileChanges`): `detailParts` and
 *       `fileDetailParts` read as `detail` and `fileDetail`;
 *       `pageLooseningWords` sends the parts of the words it picks (a
 *       file's, or the folder's), copied, so the plan's parts are never
 *       handed out.
 *
 * The confirmation's keys (`pageKey`) are untouched; the stack test
 * (tests/stack/rules-pending-hosts-whole.test.ts) pins them over the real
 * route. Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { levelParts, levelWords, sentenceParts, TERMS } from "../../../src/view-model/rule-words.js";
import { looseningWords, pageKey, pageLooseningWords, planFileChanges, type LockEdit, type PageLabel } from "../../../src/view-model/file-browser.js";

type Part = { kind: string; text: string };
const text = (parts: readonly Part[]): string => parts.map((p) => p.text).join("");
const codes = (parts: readonly Part[]): string[] => parts.filter((p) => p.kind === "code").map((p) => p.text);
const noTouchingText = (parts: readonly Part[]): boolean => parts.every((p, i) => i === 0 || !(p.kind === "text" && parts[i - 1]!.kind === "text"));

const HOME = "/home/u";
/** 24 characters, 21, and 29 (past the page's whole bound). */
const HOSTS = ["api.stripe.com", "deploy-hooks.example.com", "alerts-eu.example.com", "s3.eu-central-1.amazonaws.com"];

test("L1: levelParts reads exactly as levelWords for every level, each host its own code", () => {
  const words: Record<string, string> = {
    "no-model": TERMS.hidden, "local-model": TERMS.ownModel, "any-model": TERMS.readable, "made-up": TERMS.hidden,
  };
  for (const [level, base] of Object.entries(words)) {
    assert.deepEqual(levelParts(level), [{ kind: "text", text: base }], `${level}: no host, one text`);
    assert.equal(levelWords(level), base);
    const parts = levelParts(level, HOSTS);
    assert.equal(levelWords(level, HOSTS), `${base}; may be sent to ${HOSTS.join(", ")}`, `${level}: the words as they were`);
    assert.equal(text(parts), levelWords(level, HOSTS), `${level}: the parts read as the words`);
    assert.deepEqual(codes(parts), HOSTS, `${level}: each host a code, in order`);
    assert.ok(noTouchingText(parts), JSON.stringify(parts));
  }
  assert.deepEqual(levelParts("public", HOSTS), [{ kind: "text", text: TERMS.notSecret }], "Not secret names no host");
  assert.equal(levelWords("public", HOSTS), TERMS.notSecret);
  assert.deepEqual(levelParts("no-model", ["", "a.example"]), [{ kind: "text", text: `${TERMS.hidden}; may be sent to ` }, { kind: "code", text: "a.example" }], "an empty host is no host");
  const a = levelParts("no-model", HOSTS);
  const b = levelParts("no-model", HOSTS);
  assert.ok(a.every((p) => !b.includes(p)), "two calls share no part");
});

test("L2: sentenceParts joins neighbouring text, drops empty text and copies each part", () => {
  const host = { kind: "code" as const, text: "a.example" };
  const out = sentenceParts("Becomes ", [{ kind: "text", text: "No AI; may be sent to " }, host], "", [{ kind: "text", text: "" }], ".");
  assert.deepEqual(out, [{ kind: "text", text: "Becomes No AI; may be sent to " }, { kind: "code", text: "a.example" }, { kind: "text", text: "." }]);
  assert.ok(!out.includes(host), "a part is copied, never handed on");
  assert.deepEqual(sentenceParts(), []);
});

test("L3: a loosening to a level with hosts sends its detail as parts, each host a code; a line naming no host sends none", () => {
  const path = "/home/u/ws/.env";
  const lock: LockEdit = { op: "lock-path", path, level: "no-model", bindings: HOSTS };
  for (const files of [new Set<string>(), new Set([path])]) {
    const w = looseningWords({ facet: "paths", subject: path }, [lock], HOME, files);
    assert.equal(w.subject, "~/ws/.env");
    assert.match(w.detail, /^Becomes No AI; may be sent to api\.stripe\.com, deploy-hooks\.example\.com, alerts-eu\.example\.com, s3\.eu-central-1\.amazonaws\.com, which lets more reach an AI or leave this computer than now\./);
    assert.equal(files.size ? w.detail.includes("everything inside") : true, !files.size, "a file says nothing of its inside");
    assert.ok(w.detailParts, "parts beside the detail");
    assert.equal(text(w.detailParts!), w.detail, "the parts read as the detail");
    assert.deepEqual(codes(w.detailParts!), HOSTS, "each host its own code");
    assert.ok(noTouchingText(w.detailParts!));
  }
  const none = [
    looseningWords({ facet: "paths", subject: path }, [{ op: "lock-path", path, level: "public" }], HOME),
    looseningWords({ facet: "paths", subject: path }, [{ op: "unlock-path", path }], HOME),
    looseningWords({ facet: "readers", subject: path }, [lock], HOME),
  ];
  for (const w of none) assert.equal(w.detailParts, undefined, `${w.detail}: names no host, no parts`);
  const noHosts = looseningWords({ facet: "paths", subject: path }, [{ op: "lock-path", path, level: "any-model" }], HOME);
  assert.equal(text(noHosts.detailParts!), noHosts.detail);
  assert.deepEqual(codes(noHosts.detailParts!), []);
});

test("L4: a page-store loosening carries parts for its folder and file words, and pageLooseningWords sends a copy of the ones it picks", () => {
  const dir = "/home/u/ws/keys";
  const page: PageLabel[] = [{ path: dir, level: "no-model", bindings: ["api.stripe.com"], recursive: false } as PageLabel];
  const plan = planFileChanges([{ path: dir, level: "no-model", bindings: HOSTS, recursive: true }], (p) => p, page);
  assert.ok(typeof plan !== "string", String(plan));
  if (typeof plan === "string") return;
  assert.equal(plan.pageLoosens.length, 1);
  const l = plan.pageLoosens[0]!;
  assert.equal(l.key, pageKey(dir), "the key confirmed is the same");
  assert.equal(l.detail, `Becomes No AI; may be sent to ${HOSTS.join(", ")}, and so does everything inside it that has no rule of its own.`);
  assert.equal(l.fileDetail, `Becomes No AI; may be sent to ${HOSTS.join(", ")}.`);
  assert.equal(text(l.detailParts!), l.detail);
  assert.equal(text(l.fileDetailParts!), l.fileDetail);
  assert.deepEqual(codes(l.detailParts!), HOSTS);
  assert.deepEqual(codes(l.fileDetailParts!), HOSTS);
  for (const files of [new Set<string>(), new Set([dir])]) {
    const w = pageLooseningWords(l, HOME, files);
    assert.equal(w.subject, "~/ws/keys");
    assert.equal(w.detail, files.size ? l.fileDetail : l.detail);
    assert.equal(text(w.detailParts!), w.detail, "the parts of the words it picked");
    assert.deepEqual(codes(w.detailParts!), HOSTS);
    assert.ok(w.detailParts!.every((p) => !l.detailParts!.includes(p) && !l.fileDetailParts!.includes(p)), "a copy, never the plan's parts");
  }
  // Only to a narrower level and the same hosts: not a loosening at all.
  const same = planFileChanges([{ path: dir, level: "no-model", bindings: ["api.stripe.com"], recursive: false }], (p) => p, page);
  assert.ok(typeof same !== "string" && same.pageLoosens.length === 0);
  // A removed page rule names no host: no parts.
  const gone = planFileChanges([{ path: dir, level: null }], (p) => p, page);
  assert.ok(typeof gone !== "string");
  if (typeof gone !== "string") assert.equal(gone.pageLoosens[0]!.detailParts, undefined);
});
