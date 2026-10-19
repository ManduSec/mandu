#!/usr/bin/env node
// scripts/dep-audit.mjs — the dependency audit (docs/design/testing/continuous-integration.md
// §14.2): every npm lockfile through `npm audit`, the Cargo workspace's lockfile
// through `cargo audit`, each finding judged against the allow-list
// (scripts/dep-audit-allow.json).
//
//   node scripts/dep-audit.mjs npm   [--root DIR] [--allow FILE] [--today YYYY-MM-DD]
//   node scripts/dep-audit.mjs cargo [--root DIR] [--allow FILE] [--today YYYY-MM-DD]
//
// A finding (an advisory against a locked version, of any severity, a dev
// dependency's too; for cargo also an unmaintained, unsound or yanked crate)
// fails the audit unless a live allow-list entry names it. An entry carries
// its reason and an expiry at most 180 days after it was added; past that day
// it no longer allows anything, so every exception is looked at again. An
// entry that matches nothing is reported (the dependency moved on: delete it).
//
// Both audits read a lockfile only (no install, no lifecycle script) and need
// the network: npm's registry, and the RustSec advisory database that
// cargo-audit fetches. Where that is unreachable, or cargo-audit is not
// installed, the audit SKIPs with the reason (`0 passed, 0 failed (skipped)`);
// the CI jobs that run it give the entry `ci: { maxSkip: 0 }` under
// --strict-skips, so a skip is red there, never a quiet green.
//
// Exit: 0 when nothing fails (or everything skipped), 1 otherwise, 2 on usage.

import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

export const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const ALLOW_FILE = join(REPO_ROOT, "scripts", "dep-audit-allow.json");
/** The longest an allow-list entry may live before it must be renewed. */
export const MAX_ALLOW_DAYS = 180;
const DAY = /^\d{4}-\d{2}-\d{2}$/;

// ── the lockfiles ──────────────────────────────────────────────────────────────

/** Every directory under `root` holding a package-lock.json, repo-relative and
 *  sorted; node_modules, build output and dot-directories (worktrees, caches)
 *  are not walked. */
export function npmPackageDirs(root) {
  const out = [];
  const walk = (dir) => {
    let ents;
    try { ents = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    if (ents.some((e) => e.isFile() && e.name === "package-lock.json")) out.push(relative(root, dir) || ".");
    for (const e of ents) {
      if (!e.isDirectory() || e.name.startsWith(".") || e.name === "node_modules" || e.name === "target") continue;
      walk(join(dir, e.name));
    }
  };
  walk(root);
  return out.sort();
}

// ── reading the tools' reports ─────────────────────────────────────────────────

const ghsa = (url) => /GHSA(-[23456789cfghjmpqrvwx]{4}){3}/.exec(url ?? "")?.[0] ?? null;

function npmFix(fixAvailable) {
  if (fixAvailable === true) return "npm audit fix";
  if (fixAvailable && typeof fixAvailable === "object") {
    return `${fixAvailable.name}@${fixAvailable.version}${fixAvailable.isSemVerMajor ? " (semver-major)" : ""}`;
  }
  return "none";
}

/**
 * `npm audit --json` (auditReportVersion 2) → { ok, findings } or { ok: false,
 * reason } when npm produced no report (offline, no lockfile, a registry error).
 * One finding per advisory per vulnerable package; the entries that are only
 * "via" another package (their `via` all strings) are that package's findings.
 */
export function npmFindings(report, where) {
  if (!report || typeof report !== "object") return { ok: false, reason: "no JSON report" };
  if (report.error) return { ok: false, reason: `${report.error.code ?? "error"}: ${String(report.error.summary ?? "").split("\n")[0]}` };
  if (!report.vulnerabilities || typeof report.vulnerabilities !== "object") return { ok: false, reason: "the report has no vulnerabilities map" };
  const seen = new Set();
  const findings = [];
  for (const [name, v] of Object.entries(report.vulnerabilities)) {
    for (const via of v.via ?? []) {
      if (!via || typeof via !== "object") continue;
      const id = ghsa(via.url) ?? `npm-advisory-${via.source}`;
      const pkg = via.name ?? name;
      const key = `${pkg} ${id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        ecosystem: "npm", where, package: pkg, id, kind: "vulnerability", severity: via.severity ?? "unknown",
        title: via.title ?? "", url: via.url ?? "", range: via.range ?? "", fix: npmFix(v.fixAvailable),
      });
    }
  }
  return { ok: true, findings };
}

/**
 * `cargo audit --json` → { ok, findings } or { ok: false, reason }. The
 * vulnerabilities, then every warning (unmaintained, unsound, yanked); a
 * warning with no advisory (a yanked crate) is named `<kind>:<crate>@<version>`.
 */
export function cargoFindings(report, where) {
  if (!report || typeof report !== "object" || !report.vulnerabilities) return { ok: false, reason: "no cargo-audit JSON report" };
  const findings = [];
  for (const v of report.vulnerabilities.list ?? []) {
    const a = v.advisory ?? {};
    findings.push({
      ecosystem: "cargo", where, package: v.package?.name ?? "?", version: v.package?.version ?? "?", id: a.id ?? "?",
      kind: "vulnerability", severity: a.cvss ?? "unrated", title: a.title ?? "", url: a.url ?? (a.id ? `https://rustsec.org/advisories/${a.id}` : ""),
      fix: v.versions?.patched?.length ? v.versions.patched.join(" or ") : "none",
    });
  }
  for (const [kind, list] of Object.entries(report.warnings ?? {})) {
    for (const w of list ?? []) {
      const a = w.advisory;
      const name = w.package?.name ?? "?";
      const version = w.package?.version ?? "?";
      findings.push({
        ecosystem: "cargo", where, package: name, version, id: a?.id ?? `${w.kind ?? kind}:${name}@${version}`,
        kind: w.kind ?? kind, severity: "warning", title: a?.title ?? `${w.kind ?? kind} crate`, url: a?.url ?? (a?.id ? `https://rustsec.org/advisories/${a.id}` : ""),
        fix: w.versions?.patched?.length ? w.versions.patched.join(" or ") : "none",
      });
    }
  }
  return { ok: true, findings };
}

// ── the allow-list ─────────────────────────────────────────────────────────────

const days = (a, b) => Math.round((Date.parse(`${b}T00:00:00Z`) - Date.parse(`${a}T00:00:00Z`)) / 86_400_000);
const validDay = (s) => typeof s === "string" && DAY.test(s) && !Number.isNaN(Date.parse(`${s}T00:00:00Z`));

/**
 * The allow-list file's text → { entries, errors }. Each entry:
 *   id        the advisory (GHSA-…, RUSTSEC-…, or `<kind>:<crate>@<version>`)
 *   ecosystem npm | cargo
 *   package   the vulnerable package's name
 *   where     optional: the lockfile directories it applies to (default: all)
 *   reason    why it cannot be fixed now, and why it does not reach Mandu's users
 *   added     YYYY-MM-DD
 *   expires   YYYY-MM-DD, after `added` and at most MAX_ALLOW_DAYS after it
 * An invalid file is an error of the audit, never an empty list.
 */
export function parseAllowList(text) {
  const errors = [];
  let doc;
  try { doc = JSON.parse(text); } catch (e) { return { entries: [], errors: [`not JSON: ${e.message}`] }; }
  if (!doc || !Array.isArray(doc.allow)) return { entries: [], errors: ["no `allow` array"] };
  const entries = [];
  doc.allow.forEach((x, i) => {
    const at = `allow[${i}]${x && x.id ? ` (${x.id})` : ""}`;
    const bad = (m) => errors.push(`${at}: ${m}`);
    if (!x || typeof x !== "object") return bad("not an object");
    const known = new Set(["id", "ecosystem", "package", "where", "reason", "added", "expires"]);
    for (const k of Object.keys(x)) if (!known.has(k)) bad(`unknown field ${k}`);
    if (typeof x.id !== "string" || !x.id) bad("no id");
    if (x.ecosystem !== "npm" && x.ecosystem !== "cargo") bad("ecosystem must be npm or cargo");
    if (typeof x.package !== "string" || !x.package) bad("no package");
    if (x.where !== undefined && (!Array.isArray(x.where) || !x.where.length || !x.where.every((w) => typeof w === "string" && w))) bad("where must be a non-empty list of directories");
    if (typeof x.reason !== "string" || x.reason.trim().length < 20) bad("reason must say why (20 characters at least)");
    if (!validDay(x.added)) bad("added must be YYYY-MM-DD");
    if (!validDay(x.expires)) bad("expires must be YYYY-MM-DD");
    if (validDay(x.added) && validDay(x.expires)) {
      const d = days(x.added, x.expires);
      if (d <= 0) bad("expires must be after added");
      if (d > MAX_ALLOW_DAYS) bad(`expires is ${d} days after added; at most ${MAX_ALLOW_DAYS}`);
    }
    entries.push(x);
  });
  return { entries: errors.length ? [] : entries, errors };
}

const matches = (e, f) => e.ecosystem === f.ecosystem && e.id === f.id && e.package === f.package &&
  (!e.where || e.where.includes(f.where));

/**
 * Judge findings against the allow-list on `today` (YYYY-MM-DD): each finding
 * is allowed (a live entry matches), or fails (none does, or only an expired
 * one: `expired` names it). `unused` lists the entries of the audited
 * ecosystems that matched no finding.
 */
export function judge(findings, entries, today, ecosystems = ["npm", "cargo"]) {
  const allowed = [];
  const failing = [];
  const used = new Set();
  for (const f of findings) {
    const hits = entries.filter((e) => matches(e, f));
    for (const h of hits) used.add(h);
    const live = hits.find((e) => e.expires >= today);
    if (live) allowed.push({ finding: f, entry: live });
    else failing.push({ finding: f, expired: hits.length ? hits.map((e) => e.expires).sort().at(-1) : null });
  }
  const unused = entries.filter((e) => ecosystems.includes(e.ecosystem) && !used.has(e));
  return { allowed, failing, unused };
}

// ── running the tools ──────────────────────────────────────────────────────────

function runJson(cmd, args, cwd, timeoutMs) {
  const r = spawnSync(cmd, args, { cwd, encoding: "utf8", timeout: timeoutMs, maxBuffer: 64 * 1024 * 1024 });
  if (r.error) return { error: r.error.code === "ENOENT" ? "not installed" : String(r.error.message ?? r.error), stderr: r.stderr ?? "" };
  try { return { json: JSON.parse(r.stdout), status: r.status, stderr: r.stderr ?? "" }; } catch {
    return { error: `exit ${r.status}, no JSON on stdout`, stderr: r.stderr ?? "" };
  }
}

/** One unit per lockfile directory: { where, ok, reason?, findings? }. */
export function auditNpm(root) {
  return npmPackageDirs(root).map((where) => {
    const r = runJson("npm", ["audit", "--json"], join(root, where), 180_000);
    if (r.error) return { where, ok: false, reason: `npm audit: ${r.error}${r.stderr ? `: ${r.stderr.trim().split("\n").at(-1)}` : ""}` };
    const f = npmFindings(r.json, where);
    return f.ok ? { where, ok: true, findings: f.findings } : { where, ok: false, reason: `npm audit: ${f.reason}` };
  });
}

/** The Cargo workspace: one unit. CARGO_AUDIT names the binary (default cargo-audit). */
export function auditCargo(root) {
  const where = "interceptors";
  const lock = join(root, where, "Cargo.lock");
  if (!existsSync(lock)) return [{ where, ok: false, reason: `${where}/Cargo.lock: missing` }];
  const bin = process.env.CARGO_AUDIT || "cargo-audit";
  const r = runJson(bin, ["audit", "--json", "--file", lock], root, 600_000);
  if (r.error) {
    const why = r.error === "not installed"
      ? `${bin} is not installed (scripts/ci/pins.env CARGO_AUDIT_VERSION; the CI image and the GitHub audit job install it)`
      : `${bin}: ${r.error}${r.stderr ? `: ${r.stderr.trim().split("\n").at(-1)}` : ""}`;
    return [{ where, ok: false, reason: why }];
  }
  const f = cargoFindings(r.json, where);
  return [f.ok ? { where, ok: true, findings: f.findings } : { where, ok: false, reason: f.reason }];
}

// ── the report ─────────────────────────────────────────────────────────────────

/**
 * Units + allow-list → { lines, pass, fail, skipped, code }. Every unit that
 * could not be audited makes the whole run a skip when NONE could (no
 * network, no tool) and a failure otherwise (a partial audit is no audit).
 */
export function report(ecosystem, units, entries, today) {
  const lines = [];
  const reached = units.filter((u) => u.ok);
  if (units.length && !reached.length) {
    const reasons = [...new Set(units.map((u) => u.reason))];
    for (const r of reasons) lines.push(`SKIP: ${r}`);
    lines.push(`dep-audit ${ecosystem}: 0 passed, 0 failed (skipped)`);
    return { lines, pass: 0, fail: 0, skipped: true, code: 0 };
  }
  const findings = reached.flatMap((u) => u.findings);
  const { allowed, failing, unused } = judge(findings, entries, today, [ecosystem]);
  let pass = 0, fail = 0;
  for (const u of units) {
    if (!u.ok) { fail++; lines.push(`FAIL ${u.where}: could not audit: ${u.reason}`); continue; }
    const bad = failing.filter((x) => x.finding.where === u.where);
    const ok = allowed.filter((x) => x.finding.where === u.where);
    if (bad.length) fail++; else pass++;
    lines.push(`${bad.length ? "FAIL" : "ok  "} ${u.where}: ${u.findings.length} finding(s), ${ok.length} allowed`);
    for (const { finding: f, expired } of bad) {
      lines.push(`     ${f.id} ${f.package}${f.version ? `@${f.version}` : ""} (${f.kind}, ${f.severity}) ${f.title}`);
      lines.push(`       ${f.url}${f.range ? ` affects ${f.range}` : ""}; fix: ${f.fix}${expired ? `; its allow-list entry expired ${expired}` : ""}`);
    }
    for (const { finding: f, entry } of ok) lines.push(`     allowed until ${entry.expires}: ${f.id} ${f.package} (${f.severity})`);
  }
  for (const e of unused) lines.push(`note: allow-list entry ${e.id} (${e.package}) matched nothing: delete it`);
  if (failing.length) {
    lines.push(`To fix: update the dependency (npm audit fix / cargo update -p <crate>), or, when no fix exists,`);
    lines.push(`add an entry with its reason and an expiry to scripts/dep-audit-allow.json (continuous-integration.md §14.2).`);
  }
  lines.push(`dep-audit ${ecosystem}: ${pass} passed, ${fail} failed`);
  return { lines, pass, fail, skipped: false, code: fail ? 1 : 0 };
}

function main(argv) {
  let parsed;
  try {
    parsed = parseArgs({ args: argv, allowPositionals: true, options: {
      root: { type: "string" }, allow: { type: "string" }, today: { type: "string" },
    } });
  } catch (e) { console.error(`dep-audit: ${e.message}`); return 2; }
  const [eco, ...rest] = parsed.positionals;
  if ((eco !== "npm" && eco !== "cargo") || rest.length) {
    console.error("usage: node scripts/dep-audit.mjs npm|cargo [--root DIR] [--allow FILE] [--today YYYY-MM-DD]");
    return 2;
  }
  const root = parsed.values.root ?? REPO_ROOT;
  const today = parsed.values.today ?? new Date().toISOString().slice(0, 10);
  if (!validDay(today)) { console.error("dep-audit: --today must be YYYY-MM-DD"); return 2; }
  const allowPath = parsed.values.allow ?? ALLOW_FILE;
  const { entries, errors } = parseAllowList(readFileSync(allowPath, "utf8"));
  if (errors.length) {
    for (const e of errors) console.log(`FAIL ${relative(process.cwd(), allowPath) || allowPath}: ${e}`);
    console.log(`dep-audit ${eco}: 0 passed, 1 failed`);
    return 1;
  }
  const units = eco === "npm" ? auditNpm(root) : auditCargo(root);
  const r = report(eco, units, entries, today);
  for (const l of r.lines) console.log(l);
  return r.code;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exit(main(process.argv.slice(2)));
