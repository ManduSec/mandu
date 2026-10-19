/**
 * recorded-fixtures-scrubbed.test.ts — the recorded sessions stay scrubbed.
 *
 * The fixtures under dashboard/fixtures/, dashboard/test/fixtures/ and
 * tests/fixtures/ are real session logs with their personal and lab details
 * rewritten to fakes and the agent's own system prompt omitted (dashboard.md
 * §4.2c, "What neutralized means"). A re-recorded session would bring the
 * originals back, sometimes where a plain grep cannot see them: a reply-filter
 * frame repaints a word with cursor moves between its letters, so this sweep
 * reads every string of every line (and of JSON-encoded strings inside it)
 * with the ANSI escapes and carriage returns stripped, then once more with
 * the whitespace removed (a line wrap splits a word with a newline and an
 * indent).
 *
 * The markers are kept base64-encoded: written out, this public file would
 * itself name the lab host, the side project and the unpublished tool names
 * it exists to keep out of the fixtures.
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { extname, join, relative } from "node:path";

const REPO = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..", "..");

/** Lowercase markers, base64 (see the header for why). */
const MARKERS = [
  "c251Lg==",
  "Y29tcHNlYw==",
  "cHJvamVjdC9zaWRld29yaw==",
  "a2N0Zg==",
  "d2F0Y2gtc2NyaXB0cw==",
  "Z2xhYi1jbGk=",
  "bWFuZHUtY2ktcnVubmVy",
  "YWdlbnQtb3M=",
  "Y2xhdWRlIG1heA==",
  "eC1hbnRocm9waWMtYmlsbGluZy1oZWFkZXI=",
  "Y2NfdmVyc2lvbj0=",
  "c3lzdGVtcyBoYWNraW5n",
  "Y29tbW9kaXR5IHN5c3RlbXM=",
  "d2luZG93cywgbGludXgsIG1hY29z",
  "c29mdHdhcmUgYW5kIHN5c3RlbXMgc2VjdXJpdHk=",
  "c3lzdGVtIHNlY3VyaXR5IHNlbWluYXI=",
  "YWR2YW5jZSBjb21wdXRlciBzZWN1cml0eQ==",
  "c2VjdXJlIGFuZCB0cnVzdGVkIHN5c3RlbXM=",
  "c3lzdGVtcyBwcm9ncmFtbWluZyBhbmQgZGF0YSBzdHJ1Y3R1cmVz",
  "YWNhZGVtaWMgcHJvZmlsZQ==",
  "KGluIGJpbyk=",
  "bm90YWJsZSBhY2NlcHRhbmNlcw==",
  "L3J1bi91c2VyLzEwMDcv",
  "eW91IGFyZSBhbiBpbnRlcmFjdGl2ZSBhZ2VudCB0aGF0IGhlbHBzIHVzZXJz",
  "dGhlIG1vc3QgcmVjZW50IGNsYXVkZSBtb2RlbHMgYXJl",
  "ZW5mb3JjZSBhIHN0cmljdCAxMjUtY2hhcmFjdGVyIG1heGltdW0=",
  "bGlzdGFnZW50cw==",
  "cmVtb3RldHJpZ2dlcg==",
  "c2NoZWR1bGV3YWtldXA=",
  "bWNwX19jbGF1ZGVfYWlf",
].map((b) => Buffer.from(b, "base64").toString("utf8"));

/** A short marker could match across a removed space by chance, so only the
 *  longer ones are also looked for in the whitespace-free text. */
const SPACELESS_MIN = 8;

// CSI (cursor moves, colours, modes), OSC (titles), and the two-byte escapes.
// eslint-disable-next-line no-control-regex
const ANSI = /\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]/g;

const DATA_EXT = new Set([".ndjson", ".jsonl", ".json", ".cast"]);

/** Data files under `dir`; `deep` false keeps to its top level. */
function dataFiles(dir: string, deep: boolean): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      if (deep) out.push(...dataFiles(p, true));
    } else if (DATA_EXT.has(extname(name))) {
      out.push(p);
    }
  }
  return out;
}

/** Every string in a parsed value, JSON-encoded strings opened too. */
function strings(v: unknown, out: string[], depth = 0): void {
  if (typeof v === "string") {
    out.push(v);
    const t = v.trim();
    if (depth < 6 && (t.startsWith("{") || t.startsWith("["))) {
      try {
        strings(JSON.parse(t), out, depth + 1);
      } catch {
        // prose that only starts like JSON
      }
    }
  } else if (Array.isArray(v)) {
    for (const x of v) strings(x, out, depth);
  } else if (v !== null && typeof v === "object") {
    for (const [k, x] of Object.entries(v)) {
      out.push(k);
      strings(x, out, depth);
    }
  }
}

/** The markers `text` carries once its escapes are stripped. */
function markersIn(text: string): string[] {
  const plain = text.replace(ANSI, "").replace(/\r/g, "").toLowerCase();
  const spaceless = plain.replace(/\s+/g, "");
  return MARKERS.filter(
    (m) => plain.includes(m) || (m.length >= SPACELESS_MIN && spaceless.includes(m.replace(/\s+/g, ""))),
  );
}

function fileFindings(path: string): string[] {
  const found: string[] = [];
  readFileSync(path, "utf8").split("\n").forEach((line, i) => {
    if (line.trim() === "") return;
    const texts: string[] = [];
    try {
      strings(JSON.parse(line), texts);
    } catch {
      texts.push(line);
    }
    for (const t of texts) {
      for (const m of markersIn(t)) found.push(`${relative(REPO, path)}:${i + 1}: marker #${MARKERS.indexOf(m)}`);
    }
  });
  return [...new Set(found)];
}

const FILES = [
  ...dataFiles(join(REPO, "dashboard", "fixtures"), true),
  ...dataFiles(join(REPO, "dashboard", "test", "fixtures"), true),
  ...dataFiles(join(REPO, "tests", "fixtures"), false),
];

test("the sweep finds the recorded fixtures it guards", () => {
  const names = FILES.map((f) => relative(REPO, f));
  for (const want of [
    "dashboard/fixtures/live/1783675777-1365724.ndjson",
    "dashboard/fixtures/live/1783711204-2455055.ndjson",
    "dashboard/fixtures/live/1783733223-3201158.ndjson",
    "dashboard/test/fixtures/tour-1791164083-1418381.ndjson",
    "tests/fixtures/incident-events-1783711204.ndjson",
  ]) {
    assert.ok(names.includes(want), `${want} is swept`);
  }
});

test("no recorded fixture carries a scrubbed marker, escapes stripped", () => {
  const findings = FILES.flatMap(fileFindings);
  assert.deepEqual(findings, [], "re-scrub these lines (dashboard.md §4.2c)");
});

test("the sweep sees a marker split by cursor moves, a line wrap or a JSON encoding", () => {
  const host = MARKERS[0]!; // the short lab-host marker
  const long = MARKERS.find((m) => m.length > 20 && m.includes(" "))!;
  const [a, b] = [long.slice(0, 6), long.slice(6)];
  assert.deepEqual(markersIn(`x \x1b[1m${host.slice(0, 2)}\x1b[8G${host.slice(2)} y`), [host]);
  assert.deepEqual(markersIn(`${a}\r\x1b[1B  ${b}`), [long]);
  const line = JSON.stringify({ input: { symbolized: JSON.stringify({ text: `${a.toUpperCase()}\x1b[3G${b}` }) } });
  const texts: string[] = [];
  strings(JSON.parse(line), texts);
  assert.ok(texts.some((t) => markersIn(t).includes(long)), "a JSON-encoded string is opened");
  assert.deepEqual(markersIn("labs.example.test · Example Lab · /home/user/project/mandu"), []);
});

test("the incident fixture's two copies stay byte-identical", () => {
  // tests/stack (claude-history) and the dashboard sweep load the same
  // recorded session; a scrub of one must reach the other.
  assert.equal(
    readFileSync(join(REPO, "tests", "fixtures", "incident-events-1783711204.ndjson"), "utf8"),
    readFileSync(join(REPO, "dashboard", "fixtures", "live", "1783711204-2455055.ndjson"), "utf8"),
  );
});
