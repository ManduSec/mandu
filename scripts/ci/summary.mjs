#!/usr/bin/env node
// summary.mjs — the summary.json / junit.xml that scripts/ci/pipeline.sh writes
// ITSELF, for the runs that do not go through scripts/run-suites.mjs: a build
// failure, --selftest and --exec (docs/design/testing/continuous-integration.md §5, §6).
// Same schema as the runner's (validated with collect-results.mjs's
// validateSummary before anything is written).
//
//   node scripts/ci/summary.mjs write  --out DIR --run-id ID --commit SHA
//        [--source S] [--ref REF] [--image NAME] [--started ISO]
//        [--stages-json FILE] [--entries-json FILE] [--result pass|fail|error]
//        [--reason TEXT]
//     writes DIR/summary.json and DIR/junit.xml; the result defaults to the
//     worst of the stages and entries.
//   node scripts/ci/summary.mjs add-stage --out DIR --stage NAME=RESULT
//     records one more stage (duration 0) in an existing DIR/summary.json.
//   node scripts/ci/summary.mjs counts <log>
//     prints "pass fail skip" counted from PASS:/FAIL:/SKIP: lines (the
//     scripts/test/*.test.sh convention).

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { validateSummary } from "./collect-results.mjs";

const nowIso = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
const xml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" })[c]);

export function worst(stages, entries) {
  const rs = [...Object.values(stages).map((s) => s.result), ...entries.map((e) => e.result)];
  if (rs.includes("error")) return "error";
  if (rs.some((r) => r === "fail" || r === "timeout")) return "fail";
  return "pass";
}

export function buildSummary(o) {
  const stages = o.stages || {};
  const entries = o.entries || [];
  const s = {
    schema: 1, kind: "mandu-ci-run", run: o.runId,
    source: o.source || "local",
    commit: o.commit, ref: o.ref || "",
    started: o.started || nowIso(), finished: nowIso(),
    result: o.result || worst(stages, entries),
    stages, entries,
  };
  if (o.image) s.image = o.image;
  if (o.reason) s.reason = o.reason;
  return s;
}

export function junit(s) {
  const lines = ['<?xml version="1.0" encoding="UTF-8"?>', `<testsuites name="mandu-ci ${xml(s.run)}">`];
  const one = (name, result, duration, log, kind) => {
    const failed = result === "fail" || result === "timeout" || result === "error";
    lines.push(`  <testsuite name="${xml(name)}" tests="1" failures="${failed ? 1 : 0}" skipped="${result === "skip" ? 1 : 0}" time="${duration}">`);
    lines.push(`    <testcase classname="${xml(kind)}" name="${xml(name)}" time="${duration}">`);
    if (failed) lines.push(`      <failure message="${xml(result)}">${xml(log ? `see ${log}` : result)}</failure>`);
    if (result === "skip") lines.push("      <skipped/>");
    lines.push("    </testcase>", "  </testsuite>");
  };
  for (const [n, st] of Object.entries(s.stages || {})) one(`stage:${n}`, st.result, st.duration_s, null, "stage");
  for (const e of s.entries) one(e.id, e.result, e.duration_s, e.log, e.kind);
  if (s.result === "error" && s.reason) {
    lines.push(`  <testsuite name="run" tests="1" failures="1" time="0"><testcase classname="run" name="run"><failure message="error">${xml(s.reason)}</failure></testcase></testsuite>`);
  }
  lines.push("</testsuites>");
  return lines.join("\n") + "\n";
}

export function writeSummary(dir, s) {
  const files = new Set();
  const walk = (d, rel) => {
    for (const ent of fs.readdirSync(d, { withFileTypes: true })) {
      const r = rel ? `${rel}/${ent.name}` : ent.name;
      if (ent.isDirectory()) walk(path.join(d, ent.name), r);
      else if (ent.isFile()) files.add(r);
    }
  };
  fs.mkdirSync(dir, { recursive: true });
  walk(dir, "");
  const errs = validateSummary(s, { files });
  if (errs.length) throw new Error(`refusing to write an invalid summary: ${errs.join("; ")}`);
  fs.writeFileSync(path.join(dir, "summary.json"), JSON.stringify(s, null, 2) + "\n");
  fs.writeFileSync(path.join(dir, "junit.xml"), junit(s));
}

export function countLog(file) {
  let pass = 0, fail = 0, skip = 0;
  let text = "";
  try { text = fs.readFileSync(file, "utf8"); } catch { /* none */ }
  for (const l of text.split("\n")) {
    if (/^\s*(✓\s*)?PASS[: ]/.test(l)) pass++;
    else if (/^\s*(✗\s*)?FAIL[: ]/.test(l)) fail++;
    else if (/^\s*SKIP[: ]/.test(l)) skip++;
  }
  return { pass, fail, skip };
}

function parse(argv) {
  const o = {};
  const map = { "--out": "out", "--run-id": "runId", "--source": "source", "--commit": "commit", "--ref": "ref",
    "--image": "image", "--started": "started", "--stages-json": "stagesJson", "--entries-json": "entriesJson",
    "--result": "result", "--reason": "reason", "--stage": "stage" };
  for (let i = 0; i < argv.length; i++) {
    const k = map[argv[i]];
    if (!k || i + 1 >= argv.length) throw new Error(`unknown or incomplete option: ${argv[i]}`);
    o[k] = argv[++i];
  }
  return o;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [cmd, ...rest] = process.argv.slice(2);
  try {
    if (cmd === "counts") {
      const c = countLog(rest[0]);
      console.log(`${c.pass} ${c.fail} ${c.skip}`);
    } else if (cmd === "write") {
      const o = parse(rest);
      if (!o.out || !o.runId) throw new Error("--out and --run-id are required");
      const read = (f) => (f ? JSON.parse(fs.readFileSync(f, "utf8")) : undefined);
      const s = buildSummary({ ...o, stages: read(o.stagesJson), entries: read(o.entriesJson) });
      writeSummary(o.out, s);
      console.log(`summary: ${s.result} (${path.join(o.out, "summary.json")})`);
    } else if (cmd === "add-stage") {
      // add-stage --out DIR --stage NAME=RESULT: record a stage in an existing
      // summary.json (the runner's); pipeline.sh's tidy_drills records
      // `drills: skip` with it when it dropped drills/ over its cap. The
      // run's result is not recomputed. Refuses to write an invalid summary.
      const o = parse(rest);
      const m = /^([A-Za-z0-9._:-]{1,120})=(pass|fail|skip|timeout|error)$/.exec(o.stage || "");
      if (!o.out || !m) throw new Error("add-stage --out DIR --stage NAME=RESULT");
      const f = path.join(o.out, "summary.json");
      const s = JSON.parse(fs.readFileSync(f, "utf8"));
      s.stages = { ...(s.stages || {}), [m[1]]: { result: m[2], duration_s: 0 } };
      const errs = validateSummary(s);
      if (errs.length) throw new Error(`refusing to write an invalid summary: ${errs.join("; ")}`);
      fs.writeFileSync(f, JSON.stringify(s, null, 2) + "\n");
    } else {
      throw new Error("usage: summary.mjs write|add-stage|counts …");
    }
  } catch (e) {
    console.error(`summary.mjs: ${e.message}`);
    process.exit(2);
  }
}
