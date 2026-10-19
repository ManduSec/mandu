/**
 * agent-preview e2e — a preview agent's launch says so in ONE notice line,
 * through the real CLI entry (main → parse → version check → spawn), against
 * a Unix-socket mock arbiter (agent-versions.ts SupportStatus,
 * launchPreviewNotice; supported-agents.md §2.0).
 *
 * Stand-ins NAMED `goose`, `opencode` (OpenCode 1, a preview since
 * 2026-10-09) and `opencode2` that print a tested version on
 * `--version` and otherwise record that they ran: no real agent, no model
 * call, no key. Each preview launch keeps the notice once (the default
 * display counts it on the banner line and the launch's log holds it,
 * --verbose prints it; packaging.md §5), in the notice
 * block under the mode line (the same channel as the version and update
 * notices, before the agent's own output), and STILL starts the agent (a
 * status, never a refusal); MANDU_PREVIEW_NOTICE=0 hides it; a supported
 * agent (a stand-in `claude`) prints none. The notice is also kept on the
 * `launch_posture` event.
 *
 * Axes: MANDU_MODE "off" (the notice is decided before the arbiter is asked
 * anything, and is the same in every mode; the confidentiality oracles for
 * Goose and OpenCode are their own suites). Kernel rungs off.
 */
import { test } from "node:test";
import "../lib/private-home.js"; // the Mandu home and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:net";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { previewNotice, TESTED_AGENT_GENERATIONS, TESTED_AGENT_VERSIONS } from "../../src/agent-versions.js";
import { answerUnavailable } from "../lib/unanswered-arbiter.js";
import { launchLogs } from "../lib/launch-log-read.js";

async function withRig(fn: (sock: string, dir: string, received: () => string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-e2e-preview-"));
  const sock = join(dir, "arbiter.sock");
  let buf = "";
  const srv: Server = createServer(answerUnavailable((l) => { buf += `${l}\n`; }));
  srv.listen(sock);
  await once(srv, "listening");
  try { await fn(sock, dir, () => buf); } finally {
    srv.close(); rmSync(dir, { recursive: true, force: true });
  }
}

/** A stand-in named `name`: prints `version` for --version, else touches `ran`. */
function standIn(dir: string, name: string, version: string): { bin: string; ran: string } {
  const binDir = join(dir, `bin-${name}`);
  mkdirSync(binDir, { recursive: true });
  const bin = join(binDir, name);
  const ran = join(binDir, "ran");
  writeFileSync(bin, `#!/bin/sh\nif [ "$1" = --version ]; then echo '${version}'; exit 0; fi\ntouch '${ran}'\n`, { mode: 0o755 });
  return { bin, ran };
}

/** One launch: its exit code, the terminal's lines, and its own log's (launch-log.ts). */
async function launch(argv: string[], env: Record<string, string | undefined>): Promise<{ code: number; lines: string[]; log: string[] }> {
  const lines: string[] = [];
  const orig = console.error;
  const before = launchLogs(env);
  console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
  try {
    const code = await main(argv, env);
    return { code, lines, log: before.newLines() };
  } finally {
    console.error = orig;
  }
}

const envFor = (sock: string, dir: string, extra: Record<string, string> = {}): Record<string, string | undefined> => ({
  HOME: dir, PWD: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"], XDG_RUNTIME_DIR: dir,
  ANTHROPIC_API_KEY: "sk-e2e-unused", MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off",
  MANDU_NET_PROXY: "0", MANDU_EXEC_WRAP: "0", MANDU_REPLY_FILTER: "0", MANDU_NO_KERNEL: "1", MANDU_FS_SYNC: "0",
  ...extra,
});

const PREVIEWS = [
  { label: "Goose", name: "goose", target: "goose", version: ` ${TESTED_AGENT_VERSIONS.goose.max}` },
  { label: "OpenCode", name: "opencode", target: "opencode", version: `${TESTED_AGENT_VERSIONS.opencode.max}` },
  { label: "OpenCode 2", name: "opencode2", target: "opencode", version: `opencode v${TESTED_AGENT_GENERATIONS.opencode![0]!.max}` },
] as const;

for (const p of PREVIEWS) {
  test(`a ${p.label} launch prints the preview notice once, under the mode line, and the agent still starts; MANDU_PREVIEW_NOTICE=0 hides it`, async () => {
    await withRig(async (sock, dir, received) => {
      const { bin, ran } = standIn(dir, p.name, p.version);
      const want = previewNotice(p.label);
      const r = await launch(["--target", p.target, "--no-scope", "--no-reply-filter", "--", bin], envFor(sock, dir));
      assert.equal(r.code, 0, `a status, never a refusal:\n${r.lines.join("\n")}`);
      assert.ok(existsSync(ran), "the agent ran");
      // The default display (packaging.md §5, 2026-10-18): the banner counts
      // the notice and points at the launch's log, which holds it once.
      assert.ok(!r.lines.some((l) => /support is a preview/.test(l)), `counted, not printed:\n${r.lines.join("\n")}`);
      assert.match(r.lines.find((l) => / mode · /.test(l)) ?? "", / · \d+ notices?: `mandu log`$/, r.lines.join("\n"));
      assert.deepEqual(r.log.filter((l) => /support is a preview/.test(l)), [want]);
      const posture = received().split("\n").find((l) => l.includes("\"launch_posture\""));
      assert.ok(posture?.includes(want), "the notice is kept on the launch_posture event");
      // --verbose: printed once, as it is said.
      rmSync(ran, { force: true });
      const v = await launch(["--verbose", "--target", p.target, "--no-scope", "--no-reply-filter", "--", bin], envFor(sock, dir));
      assert.equal(v.code, 0);
      assert.deepEqual(v.lines.filter((l) => /support is a preview/.test(l)), [want], v.lines.join("\n"));

      rmSync(ran, { force: true });
      const off = await launch(["--target", p.target, "--no-scope", "--no-reply-filter", "--", bin], envFor(sock, dir, { MANDU_PREVIEW_NOTICE: "0" }));
      assert.equal(off.code, 0);
      assert.ok(existsSync(ran), "the agent ran");
      assert.ok(!off.lines.some((l) => /support is a preview/.test(l)), off.lines.join("\n"));
      assert.ok(!off.log.some((l) => /support is a preview/.test(l)), "not in the log either");
    });
  });
}

test("a supported agent (Claude Code) prints no preview notice", async () => {
  await withRig(async (sock, dir) => {
    const { bin, ran } = standIn(dir, "claude", `${TESTED_AGENT_VERSIONS.claude.max} (Claude Code)`);
    const r = await launch(["--no-scope", "--no-reply-filter", "--", bin], envFor(sock, dir));
    assert.equal(r.code, 0, r.lines.join("\n"));
    assert.ok(existsSync(ran));
    assert.ok(!r.lines.some((l) => /support is a preview/.test(l)), r.lines.join("\n"));
  });
});
