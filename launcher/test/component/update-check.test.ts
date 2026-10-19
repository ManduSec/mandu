/**
 * update-check component e2e (packaging.md §11.5) — the update notice over
 * its production wiring against a local stand-in for GitHub's release list
 * (MANDU_UPDATE_CHECK_URL; no test ever reaches the real network):
 *
 *   - the real request (realFetchReleases): only the fixed headers, nothing
 *     of the launch's environment (its API key, its home, its session), one
 *     GET of exactly the configured URL; a 404 (the private repository), a
 *     redirect, an oversized body and a server that never answers each come
 *     back as a silent null, the last within its budget;
 *   - a real launch (main → launchUpdateCheck → spawn, against a mock
 *     arbiter, mode off): the first launch prints no notice and leaves the
 *     answer in <home>/cache/update-check.json in the background; the next
 *     launch prints the one SECURITY notice line under the mode line and asks
 *     nothing (once a day); MANDU_UPDATE_CHECK=0 asks nothing and prints
 *     nothing; a 404 prints nothing and the agent still runs;
 *   - `mandu doctor` (the real CLI in a child): a fresh check whatever the
 *     cache says, its row with the install line.
 *
 * The request runs in the launcher, outside the agent's confinement; it
 * carries no secret and opens no egress path, which the header check pins.
 * Axes stated: off (the check is the same in every mode).
 */
import { test, after } from "node:test";
import "../lib/private-home.js"; // daemons' npm cache, the Mandu home and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import assert from "node:assert/strict";
import { createServer as createHttpServer, type IncomingMessage, type Server as HttpServer } from "node:http";
import { createServer, type Server } from "node:net";
import type { AddressInfo } from "node:net";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import { spawn } from "node:child_process";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import {
  installLine, launcherVersion, parseVersion, realFetchReleases, REQUEST_HEADERS, SECURITY_MARKER, updateCachePath,
} from "../../src/update-check.js";
import { answerUnavailable } from "../lib/unanswered-arbiter.js";
import { runCli } from "../lib/run-cli.js";
import { stateAxes } from "../axes.js";

stateAxes("off");

const PKG = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

const dir = mkdtempSync(join(tmpdir(), "mdu-update-e2e-"));
after(() => rmSync(dir, { recursive: true, force: true }));

const CURRENT = launcherVersion();
assert.ok(parseVersion(CURRENT), `the launcher's own version is semver: ${CURRENT}`);
const NEWEST = "99.0.0";
const LIST = JSON.stringify([
  { tag_name: `v${NEWEST}`, draft: false, body: "Faster launches." },
  { tag_name: "v98.0.0", draft: false, body: `Fixes a leak.\n${SECURITY_MARKER}` },
  { tag_name: "v0.0.1", draft: false, body: "" },
]);

interface Seen { method: string; url: string; headers: string[]; raw: string }
type Behavior = "list" | "404" | "redirect" | "huge" | "hang";

/** A stand-in for api.github.com: records each request, answers per `behavior`. */
async function standIn(behavior: () => Behavior): Promise<{ url: string; seen: Seen[]; close: () => Promise<void> }> {
  const seen: Seen[] = [];
  const hung: IncomingMessage[] = [];
  const srv: HttpServer = createHttpServer((req, res) => {
    const headers = req.rawHeaders.filter((_, i) => i % 2 === 0).map((h) => h.toLowerCase());
    seen.push({ method: req.method ?? "", url: req.url ?? "", headers, raw: req.rawHeaders.join("\n") });
    switch (behavior()) {
      case "list": res.writeHead(200, { "content-type": "application/json" }).end(LIST); return;
      case "404": res.writeHead(404, { "content-type": "application/json" }).end("{\"message\":\"Not Found\"}"); return;
      case "redirect": res.writeHead(302, { location: "http://127.0.0.1:1/elsewhere" }).end(); return;
      case "huge": res.writeHead(200).end("[" + " ".repeat(3 * 1024 * 1024) + "]"); return;
      case "hang": hung.push(req); return;
    }
  });
  srv.listen(0, "127.0.0.1");
  await once(srv, "listening");
  const port = (srv.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}/repos/ManduSec/mandu/releases?per_page=30`,
    seen,
    close: () => { srv.closeAllConnections(); return new Promise((r) => srv.close(() => r())); },
  };
}

test("the request: one GET of the configured URL with the fixed headers only; every failure is a silent null", async () => {
  let behavior: Behavior = "list";
  const s = await standIn(() => behavior);
  try {
    const body = await realFetchReleases(s.url, 2_000, false);
    assert.equal(body, LIST);
    assert.equal(s.seen.length, 1);
    assert.equal(s.seen[0]!.method, "GET");
    assert.equal(s.seen[0]!.url, "/repos/ManduSec/mandu/releases?per_page=30");
    assert.deepEqual(
      s.seen[0]!.headers.filter((h) => h !== "host" && h !== "connection").sort(),
      Object.keys(REQUEST_HEADERS).map((h) => h.toLowerCase()).sort(),
      "nothing but Accept and the fixed User-Agent",
    );
    assert.ok(s.seen[0]!.raw.includes("mandu-update-check"));
    assert.ok(!s.seen[0]!.raw.includes(CURRENT), "not even the version");
    for (const b of ["404", "redirect", "huge"] as const) {
      behavior = b;
      assert.equal(await realFetchReleases(s.url, 2_000, false), null, b);
    }
    behavior = "hang";
    const t0 = Date.now();
    assert.equal(await realFetchReleases(s.url, 300, false), null, "a server that never answers");
    assert.ok(Date.now() - t0 < 2_000, "cut at its budget");
    assert.equal(await realFetchReleases("http://127.0.0.1:1/", 1_000, false), null, "nothing listening");
  } finally {
    await s.close();
  }
});

test("a background request never keeps the process alive; doctor's awaited one does", async () => {
  const s = await standIn(() => "hang");
  try {
    const mod = join(PKG, "src", "update-check.ts");
    // Timed from the request's start (the child says `go` just before it),
    // not from the spawn: tsx's start-up alone took 5 to 8 s on a loaded CI
    // guest and differed between the two children by more than the margin
    // (pipeline 9856, "7860 vs 7922 ms", 2026-10-09).
    const run = (background: boolean): Promise<{ code: number | null; ms: number }> => new Promise((done) => {
      let t0: number | null = null;
      const c = spawn(join(PKG, "node_modules", ".bin", "tsx"), [
        "-e", `import(${JSON.stringify(mod)}).then((m) => { process.stdout.write("go\\n"); void m.realFetchReleases(${JSON.stringify(s.url)}, 3000, ${background}); })`,
      ], { stdio: ["ignore", "pipe", "ignore"] });
      c.stdout!.on("data", (d: Buffer) => { if (t0 === null && d.toString().includes("go")) t0 = Date.now(); });
      c.on("close", (code) => done({ code, ms: t0 === null ? -1 : Date.now() - t0 }));
    });
    const [bg, fg] = await Promise.all([run(true), run(false)]);
    assert.equal(bg.code, 0);
    assert.equal(fg.code, 0);
    assert.ok(bg.ms >= 0 && fg.ms >= 0, "both children started their request");
    assert.ok(fg.ms >= 3000, `the awaited request holds the process to its budget (${fg.ms} ms)`);
    assert.ok(bg.ms < fg.ms - 1000, `the background one does not (${bg.ms} vs ${fg.ms} ms)`);
  } finally {
    await s.close();
  }
});

/** A mock arbiter (answers "unavailable"), as agent-version.test.ts uses. */
async function withArbiter(fn: (sock: string, work: string) => Promise<void>): Promise<void> {
  const work = mkdtempSync(join(dir, "launch-"));
  const sock = join(work, "arbiter.sock");
  const srv: Server = createServer(answerUnavailable(() => {}));
  srv.listen(sock);
  await once(srv, "listening");
  try { await fn(sock, work); } finally { srv.close(); }
}

function fakeAgent(work: string): { bin: string; ran: string } {
  const binDir = join(work, "bin");
  mkdirSync(binDir);
  const bin = join(binDir, "agent");
  const ran = join(binDir, "ran");
  writeFileSync(bin, `#!/bin/sh\ntouch '${ran}'\n`);
  chmodSync(bin, 0o755);
  return { bin, ran };
}

async function launch(argv: string[], env: Record<string, string | undefined>): Promise<{ code: number; lines: string[] }> {
  const lines: string[] = [];
  const orig = console.error;
  console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
  try {
    return { code: await main(argv, env), lines };
  } finally {
    console.error = orig;
  }
}

async function waitFor(cond: () => boolean, ms = 8_000): Promise<void> {
  const until = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > until) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 25));
  }
}

const SECRET = "sk-ant-e2e-update-check-must-not-travel";

test("a launch: the notice comes from the previous check, the check runs in the background once a day, carrying nothing of the session", async () => {
  const s = await standIn(() => "list");
  try {
    await withArbiter(async (sock, work) => {
      const home = join(work, "mandu-home");
      const { bin, ran } = fakeAgent(work);
      const env = {
        HOME: work, PWD: work, PATH: process.env["PATH"], MANDU_ARBITER_SOCK: sock, MANDU_HOME: home,
        MANDU_NO_CONTEXT_PROXY: "1", MANDU_MODE: "off", XDG_RUNTIME_DIR: work, ANTHROPIC_API_KEY: SECRET,
        MANDU_UPDATE_CHECK: "1", MANDU_UPDATE_CHECK_URL: s.url,
      };
      const cachePath = updateCachePath(env);
      const first = await launch(["--no-scope", "--no-reply-filter", "--no-net-proxy", "--no-exec-wrap", "--target", "shell", "--", bin], env);
      assert.equal(first.code, 0);
      assert.ok(existsSync(ran), "the agent ran");
      assert.ok(!first.lines.some((l) => l.includes("is out")), "no answer yet: no notice");
      await waitFor(() => existsSync(cachePath));
      assert.equal(s.seen.length, 1, "one background request");
      for (const sv of s.seen) {
        for (const leak of [SECRET, work, sock, home]) assert.ok(!sv.raw.includes(leak) && !sv.url.includes(leak), `request carries ${leak}`);
      }
      const cached = JSON.parse(readFileSync(cachePath, "utf8")) as { ok: boolean; releases: unknown[] };
      assert.equal(cached.ok, true);

      const second = await launch(["--no-scope", "--no-reply-filter", "--no-net-proxy", "--no-exec-wrap", "--target", "shell", "--", bin], env);
      assert.equal(second.code, 0);
      const notes = second.lines.filter((l) => l.includes("is out"));
      assert.deepEqual(notes, [`mandu: ! Mandu ${NEWEST} is out with SECURITY fixes (you have ${CURRENT}); update now: ${installLine(NEWEST)}`], JSON.stringify(second.lines));
      // A release with SECURITY fixes is one of the notices the default
      // display still prints, under the banner (launch-banner.ts mustHearNotice).
      assert.ok(second.lines.indexOf(notes[0]!) > second.lines.findIndex((l) => / mode · /.test(l)), "under the banner");
      assert.equal(s.seen.length, 1, "the answer is a day old at most: nothing asked");

      const off = await launch(["--no-scope", "--no-reply-filter", "--no-net-proxy", "--no-exec-wrap", "--target", "shell", "--", bin], { ...env, MANDU_UPDATE_CHECK: "0" });
      assert.equal(off.code, 0);
      assert.ok(!off.lines.some((l) => l.includes("is out")), "MANDU_UPDATE_CHECK=0 prints nothing");
      assert.equal(s.seen.length, 1);
    });
  } finally {
    await s.close();
  }
});

test("a launch while the release list is not public (404): nothing printed, the agent runs, the attempt is stamped", async () => {
  const s = await standIn(() => "404");
  try {
    await withArbiter(async (sock, work) => {
      const { bin, ran } = fakeAgent(work);
      const env = {
        HOME: work, PWD: work, PATH: process.env["PATH"], MANDU_ARBITER_SOCK: sock, MANDU_HOME: join(work, "mandu-home"),
        MANDU_NO_CONTEXT_PROXY: "1", MANDU_MODE: "off", XDG_RUNTIME_DIR: work,
        MANDU_UPDATE_CHECK: "1", MANDU_UPDATE_CHECK_URL: s.url,
      };
      const r = await launch(["--no-scope", "--no-reply-filter", "--no-net-proxy", "--no-exec-wrap", "--target", "shell", "--", bin], env);
      assert.equal(r.code, 0);
      assert.ok(existsSync(ran));
      assert.ok(!r.lines.some((l) => /is out|update/i.test(l)), JSON.stringify(r.lines));
      const cachePath = updateCachePath(env);
      await waitFor(() => existsSync(cachePath));
      assert.equal((JSON.parse(readFileSync(cachePath, "utf8")) as { ok: boolean }).ok, false);
      const again = await launch(["--no-scope", "--no-reply-filter", "--no-net-proxy", "--no-exec-wrap", "--target", "shell", "--", bin], env);
      assert.equal(again.code, 0);
      assert.equal(s.seen.length, 1, "a failed check also waits a day");
    });
  } finally {
    await s.close();
  }
});

test("mandu doctor asks afresh whatever the cache says and prints the row with the install line", async () => {
  const s = await standIn(() => "list");
  try {
    const work = mkdtempSync(join(dir, "doctor-"));
    const home = join(work, "mandu-home");
    const env = { HOME: work, MANDU_HOME: home, XDG_RUNTIME_DIR: work, MANDU_UPDATE_CHECK: "1", MANDU_UPDATE_CHECK_URL: s.url, MANDU_MODE: "off", MANDU_LAYOUT: "installed" };
    // A forged "up to date, checked just now" entry.
    const cachePath = updateCachePath(env);
    mkdirSync(join(home, "cache"), { recursive: true, mode: 0o700 });
    writeFileSync(cachePath, JSON.stringify({ v: 1, checkedAt: Date.now(), ok: true, releases: [], releasesAt: Date.now() }), { mode: 0o600 });
    const r = await runCli(["doctor"], env);
    assert.equal(r.code, 0, r.stderr);
    assert.equal(s.seen.length, 1, "doctor asked");
    assert.ok(r.stdout.includes(`  version ${CURRENT}\n`), r.stdout);
    assert.ok(r.stdout.includes(`✗ Mandu ${NEWEST} is out with SECURITY fixes (you have ${CURRENT}); update now: ${installLine(NEWEST, "npm")}`), r.stdout);
    assert.equal((JSON.parse(readFileSync(cachePath, "utf8")) as { releases: unknown[] }).releases.length, 3, "the forged entry is replaced");
    const off = await runCli(["doctor"], { ...env, MANDU_UPDATE_CHECK: "0" });
    assert.ok(off.stdout.includes("· newer release: turned off (MANDU_UPDATE_CHECK=0)"), off.stdout);
    assert.equal(s.seen.length, 1);
  } finally {
    await s.close();
  }
});
