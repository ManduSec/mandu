/**
 * mode.test — E2E for the protection-mode surface of the launcher
 * (docs/design/architecture/protection-modes.md §3.2, §3.4): main() against a Unix-socket
 * mock arbiter that REPORTS its axes in `hello`, the way the real one does.
 *
 *   - the mode every launch prints (the banner's first words by default, the
 *     mode line under --verbose) is the EFFECTIVE mode: what the attached
 *     arbiter runs, not what the flags hoped for;
 *   - a --mode that differs from the running arbiter is refused BEFORE the
 *     agent starts, naming the running mode and the command that changes it;
 *   - --help lists the modes and launches nothing; a bare `mandu` is usage;
 *   - the integrity axis is FROZEN (docs/design/architecture/protection-modes.md §10): a launch
 *     that asks for it without MANDU_EXPERIMENTAL_INTEGRITY=1 is refused before
 *     anything starts, even the arbiter.
 *
 * Axes: stated per launch (--mode / MANDU_MODE, or the mock's reported pair).
 */
import { test } from "node:test";
import "../lib/private-home.js"; // daemons' npm cache, the Mandu home and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:net";
import { chmodSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { once } from "node:events";
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { runCli } from "../lib/run-cli.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FAKE = join(HERE, "..", "fixtures", "fake-agent.sh");

/** A mock arbiter whose `hello` reports the given axes; every other op is
 *  answered `ok:false` (an op this mock does not implement), never silence. */
async function withReportingArbiter(
  axes: { integrity: boolean; confidentiality: boolean },
  fn: (sock: string, dir: string, emitted: Array<Record<string, unknown>>) => Promise<void>,
): Promise<void> {
  const emitted: Array<Record<string, unknown>> = [];
  const dir = mkdtempSync(join(tmpdir(), "mandu-mode-e2e-"));
  const sock = join(dir, "arbiter.sock");
  const srv: Server = createServer((c) => {
    let buf = "";
    c.setEncoding("utf8");
    c.on("data", (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
        let req: { id?: unknown; op?: string; event?: Record<string, unknown> };
        try { req = JSON.parse(line); } catch { continue; }
        if (req.op === "emit" && req.event) emitted.push(req.event);
        c.write(JSON.stringify(req.op === "hello"
          ? { id: req.id, ok: true, result: { pid: 1, ...axes } }
          : req.op === "emit"
            ? { id: req.id, ok: true, result: {} }
            : { id: req.id, ok: false, error: "mock: not implemented" }) + "\n");
      }
    });
    c.on("error", () => {});
  });
  srv.listen(sock);
  await once(srv, "listening");
  try { await fn(sock, dir, emitted); } finally { srv.close(); rmSync(dir, { recursive: true, force: true }); }
}

/** The default banner lines' mode and its first fact (packaging.md §5). */
function bannerModes(lines: string[]): string[] {
  return lines.filter((l) => /^mandu: \w+ mode · /.test(l)).map((l) => l.split(" · ").slice(0, 2).join(" · "));
}

async function run(argv: string[], env: Record<string, string | undefined>): Promise<{ code: number; lines: string[]; error?: Error }> {
  const lines: string[] = [];
  const orig = console.error;
  console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
  try {
    return { code: await main(argv, env), lines };
  } catch (e) {
    return { code: -1, lines, error: e as Error };
  } finally {
    console.error = orig;
  }
}

const baseEnv = (sock: string, dir: string): Record<string, string | undefined> => ({
  HOME: process.env["HOME"], PWD: dir, PATH: process.env["PATH"], XDG_RUNTIME_DIR: dir,
  MANDU_ARBITER_SOCK: sock, MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME,
  // Keep the launch hermetic and quick: no bwrap, no kernel rungs.
  MANDU_NO_KERNEL: "1",
});

test("an unflagged launch prints the mode the ARBITER runs (effective, not requested)", async () => {
  chmodSync(FAKE, 0o755);
  await withReportingArbiter({ integrity: true, confidentiality: false }, async (sock, dir) => {
    const marker = join(dir, "ran");
    const r = await run(["--target", "claude", "--no-scope", "--", "bash", "-c", `touch ${marker}`], baseEnv(sock, dir));
    assert.equal(r.code, 0, r.error?.message);
    assert.ok(existsSync(marker));
    // The default banner opens with the mode (packaging.md §5); --verbose
    // prints the mode line itself.
    assert.deepEqual(bannerModes(r.lines), ["mandu: injection mode · untrusted text masked"], JSON.stringify(r.lines));
    const v = await run(["--verbose", "--target", "claude", "--no-scope", "--", "bash", "-c", `touch ${marker}`], baseEnv(sock, dir));
    assert.equal(v.code, 0, v.error?.message);
    assert.deepEqual(v.lines.filter((l) => l.startsWith("mandu: mode ")), ["mandu: mode injection (untrusted text masked)"]);
  });
});

test("a matching --mode launches; the mode line lands in launch.log too", async () => {
  await withReportingArbiter({ integrity: false, confidentiality: true }, async (sock, dir) => {
    // --best-effort: this mock cannot discover secrets (the gate is not under test here).
    const r = await run(["--mode", "secrets", "--best-effort", "--target", "claude", "--no-scope", "--id", "m1", "--", "true"], baseEnv(sock, dir));
    assert.equal(r.code, 0, r.error?.message);
    assert.equal(r.lines.filter((l) => /^mandu: secrets mode · /.test(l)).length, 1, JSON.stringify(r.lines));
    assert.match(readFileSync(join(dir, "mandu", "m1", "launch.log"), "utf8"), /^mandu: mode secrets /m);
  });
});

test("the frozen integrity modes still launch with the opt-in (MANDU_EXPERIMENTAL_INTEGRITY=1)", async () => {
  await withReportingArbiter({ integrity: true, confidentiality: false }, async (sock, dir) => {
    const r = await run(
      ["--mode", "injection", "--target", "claude", "--no-scope", "--id", "m2", "--", "true"],
      { ...baseEnv(sock, dir), MANDU_EXPERIMENTAL_INTEGRITY: "1" },
    );
    assert.equal(r.code, 0, r.error?.message);
    assert.deepEqual(bannerModes(r.lines), ["mandu: injection mode · untrusted text masked"], JSON.stringify(r.lines));
  });
});

test("frozen integrity: --mode full with no opt-in exits non-zero before starting anything (no arbiter contacted or spawned, agent not run)", async () => {
  // A listening stand-in arbiter that counts connections: a launch past the
  // gate would say `hello` to it first. Autostart is disabled only as a safety
  // net (a regression must not leak a real arbiter); its refusal names the
  // arbiter, not the freeze, so the message assertions still tell them apart.
  const dir = mkdtempSync(join(tmpdir(), "mandu-mode-frozen-"));
  const sock = join(dir, "arbiter.sock");
  let contacts = 0;
  const srv: Server = createServer((c) => { contacts++; c.on("error", () => {}); c.end(); });
  srv.listen(sock);
  await once(srv, "listening");
  try {
    const marker = join(dir, "ran");
    const env = { ...baseEnv(sock, dir), MANDU_EXPERIMENTAL_INTEGRITY: "", MANDU_NO_ARBITER_AUTOSTART: "1" };
    const cases: Array<{ argv: string[]; env: Record<string, string | undefined> }> = [
      { argv: ["--mode", "full"], env },
      { argv: ["--mode=injection"], env },
      { argv: ["--integrity"], env },
      { argv: [], env: { ...env, MANDU_MODE: "full" } },
    ];
    for (const c of cases) {
      const r = await run([...c.argv, "--target", "claude", "--no-scope", "--", "bash", "-c", `touch ${marker}`], c.env);
      const what = c.argv.join(" ") || `MANDU_MODE=${c.env["MANDU_MODE"]}`;
      assert.notEqual(r.code, 0, what);
      assert.ok(r.error, `main() must refuse: ${what}`);
      assert.match(r.error!.message, /frozen/, what);
      assert.match(r.error!.message, /MANDU_EXPERIMENTAL_INTEGRITY=1/, what);
      assert.match(r.error!.message, /protection-modes\.md/, what);
      assert.ok(!existsSync(marker), `the agent never ran: ${what}`);
      assert.equal(contacts, 0, `no arbiter was contacted: ${what}`);
      assert.deepEqual(readdirSync(dir), ["arbiter.sock"], `nothing started under the runtime dir: ${what}`);
    }
  } finally {
    srv.close(); rmSync(dir, { recursive: true, force: true });
  }
});

test("a --mode that differs from the running arbiter is REFUSED before the agent starts (§3.4)", async () => {
  await withReportingArbiter({ integrity: false, confidentiality: true }, async (sock, dir) => {
    const marker = join(dir, "ran");
    const r = await run(["--mode", "off", "--target", "claude", "--no-scope", "--", "bash", "-c", `touch ${marker}`], baseEnv(sock, dir));
    assert.ok(r.error, "main() must throw");
    assert.match(r.error!.message, /mode off cannot take effect/);
    assert.match(r.error!.message, /already running in mode secrets/);
    assert.match(r.error!.message, /`mandu mode off`, then `mandu stop`/);
    assert.ok(!existsSync(marker), "the agent never ran");
  });
});

test("the env and config levels are refused the same way: MANDU_MODE against a different arbiter", async () => {
  await withReportingArbiter({ integrity: true, confidentiality: true }, async (sock, dir) => {
    const r = await run(["--target", "claude", "--no-scope", "--", "true"], { ...baseEnv(sock, dir), MANDU_MODE: "off" });
    assert.match(r.error?.message ?? "", /mode (off|secrets|injection) cannot take effect.*running in mode full/s);
  });
});

test("off mode says what it is", async () => {
  await withReportingArbiter({ integrity: false, confidentiality: false }, async (sock, dir) => {
    const r = await run(["--mode", "off", "--target", "claude", "--no-scope", "--", "true"], baseEnv(sock, dir));
    assert.equal(r.code, 0, r.error?.message);
    assert.deepEqual(bannerModes(r.lines), ["mandu: off mode · observing only, nothing is enforced"], JSON.stringify(r.lines));
  });
});

test("--help lists the product modes plus the frozen line, exits 0 and launches nothing; a bare `mandu` is usage with exit 2", async () => {
  // A child process: patching process.stdout.write across main()'s awaits
  // swallows the test runner's report (test/lib/run-cli.ts).
  const capture = async (argv: string[]): Promise<{ code: number; out: string; err: string }> => {
    const r = await runCli(argv, { MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_NO_ARBITER_AUTOSTART: "1", MANDU_ARBITER_SOCK: "/nonexistent/x.sock" });
    return { code: r.code, out: r.stdout, err: r.stderr };
  };
  for (const argv of [["--help"], ["-h"], ["help"], ["--mode", "full", "--help"]]) {
    const r = await capture(argv);
    assert.equal(r.code, 0, argv.join(" "));
    for (const m of ["secrets", "off"]) assert.match(r.out, new RegExp(`^  ${m} `, "m"));
    for (const m of ["injection", "full"]) assert.doesNotMatch(r.out, new RegExp(`^  ${m} `, "m"));
    assert.match(r.out, /^  \(frozen: injection, full; need MANDU_EXPERIMENTAL_INTEGRITY=1\)$/m);
    assert.match(r.out, /--mode <name>/);
    assert.match(r.out, /mandu mode/);
  }
  const ver = await capture(["--version"]);
  assert.equal(ver.code, 0);
  assert.match(ver.out, /^mandu \S+\n$/);
  const bare = await capture([]);
  assert.equal(bare.code, 2);
  assert.match(bare.err, /usage:/);
  assert.doesNotMatch(bare.err, /no command given/);
});

test("the launch_posture event records the protection mode the ARBITER runs, so the dashboard need not infer it", async () => {
  await withReportingArbiter({ integrity: false, confidentiality: true }, async (sock, dir, emitted) => {
    // --best-effort: this mock cannot discover secrets (the gate is not under test here).
    const r = await run(["--best-effort", "--target", "claude", "--no-scope", "--id", "p1", "--", "true"], baseEnv(sock, dir));
    assert.equal(r.code, 0, r.error?.message);
    const posture = emitted.find((e) => e["kind"] === "launch_posture");
    assert.ok(posture, "a launch_posture event reached the arbiter");
    assert.deepEqual(posture["protection"], { mode: "secrets", integrity: false, confidentiality: true, reported: true });
  });
});
