import { test } from "node:test";
import assert from "node:assert/strict";
import {
  MDU_SYM_FORMAT,
  shortToolTag,
  levelFromSymbolName,
  unescapeSymbols,
} from "../../symbol-table/symbol-format.js";

test("level marker rides inside the existing grammar — scanners match unchanged", () => {
  const strict = MDU_SYM_FORMAT.generate({ tool: "Read", hash: "3fa9", level: "no-model" });
  assert.equal(strict, "$MDU:nomodel_Read[3fa9]");
  const modelOk = MDU_SYM_FORMAT.generate({
    tool: "Read", hash: "3fa9", field: "content", level: "any-model",
  });
  assert.equal(modelOk, "$MDU:anymodel_Read[3fa9].content");
  const plain = MDU_SYM_FORMAT.generate({ tool: "Read", hash: "3fa9" });
  assert.equal(plain, "$MDU:Read[3fa9]");
  const publicLevel = MDU_SYM_FORMAT.generate({ tool: "Read", hash: "3fa9", level: "public" });
  assert.equal(publicLevel, "$MDU:Read[3fa9]"); // public mints today's exact names

  for (const sym of [strict, modelOk, plain]) {
    MDU_SYM_FORMAT.pattern.lastIndex = 0;
    assert.ok(MDU_SYM_FORMAT.pattern.test(sym), sym);
    assert.equal(MDU_SYM_FORMAT.extractHash(sym), "3fa9", sym);
  }
  assert.equal(MDU_SYM_FORMAT.extractFieldPath(modelOk), "content");
});

test("plan 11: local-model mints localmodel_, maps back, and no marker is a prefix of another", () => {
  const n = MDU_SYM_FORMAT.generate({ tool: "Read", hash: "c4d8", level: "local-model" });
  assert.equal(n, "$MDU:localmodel_Read[c4d8]");
  assert.equal(levelFromSymbolName(n), "local-model");
  assert.equal(levelFromSymbolName("$MDU:localmodel_inspect[c4d8].result"), "local-model");
  const markers = ["nomodel_", "anymodel_", "localmodel_"];
  for (const a of markers) for (const b of markers) if (a !== b) assert.ok(!b.startsWith(a), `${a} prefixes ${b}`);
  MDU_SYM_FORMAT.pattern.lastIndex = 0;
  assert.ok(MDU_SYM_FORMAT.pattern.test(n), "the one token grammar still matches");
});

test("levelFromSymbolName is presentation-only parse", () => {
  assert.equal(levelFromSymbolName("$MDU:nomodel_Read[3fa9]"), "no-model");
  assert.equal(levelFromSymbolName("$MDU:anymodel_Read[3fa9].x"), "any-model");
  assert.equal(levelFromSymbolName("$MDU:Read[3fa9]"), "public");
  // "security_scan" as a TOOL tag must not read as a marker...
  assert.equal(levelFromSymbolName("$MDU:security_scan[3fa9]"), "public");
});

test("shortToolTag reserves the marker prefixes, idempotently", () => {
  assert.equal(shortToolTag("nomodel_scan"), "t_nomodel_scan");
  assert.equal(shortToolTag(shortToolTag("nomodel_scan")), "t_nomodel_scan");
  assert.equal(shortToolTag("anymodel_x"), "t_anymodel_x");
  assert.equal(shortToolTag("localmodel_x"), "t_localmodel_x");
  // no underscore boundary → not a marker → untouched
  assert.equal(shortToolTag("nomodelscan"), "nomodelscan");
  // the pre-rename markers are ordinary tags now
  assert.equal(shortToolTag("sec_scan"), "sec_scan");
  assert.equal(shortToolTag("secm_x"), "secm_x");
});

test("...but a forged-looking tool cannot mint a marker-ambiguous name", () => {
  // generate(tool: "nomodel_scan") — the reservation makes the tag
  // t_nomodel_scan, so the name never starts $MDU:nomodel_ unless the LEVEL says so.
  const n = MDU_SYM_FORMAT.generate({ tool: "nomodel_scan", hash: "ab12" });
  assert.equal(n, "$MDU:t_nomodel_scan[ab12]");
  assert.equal(levelFromSymbolName(n), "public");
});

test("markdown-escaped secret tokens still unescape", () => {
  assert.equal(
    unescapeSymbols("\\$MDU:nomodel\\_Read[3fa9]"),
    "$MDU:nomodel_Read[3fa9]",
  );
});
