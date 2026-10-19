/**
 * launcher-kernel-tier.test.ts — the LIVE proof that the real `mandu`
 * launcher, on DEFAULT flags, turns its non-root kernel-tier hardening ON around
 * a real driven `claude`, and that §9 still holds through the whole stack.
 *
 * FROZEN LANE (docs/design/architecture/protection-modes.md §10.5, §10.7; test-organization.md
 * §7.1, 2026-09-29): the integrity form of this suite, moved verbatim from
 * test/live/ when the agent-fake tier moved to `secrets`. It runs only when the
 * integrity axis is revived (`npm run test:integrity`). The default-lane
 * launcher-kernel-tier.test.ts proves the confidentiality form;
 * this copy keeps what exists only with integrity ON: the fs rung ACTIVE, the
 * AgentView pair baked into the exec-box shims, and the guard-hosted clean box.
 *
 * Sibling of launcher-golden-path.test.ts (shared harness: lib/launcher-live.ts).
 * Golden-path proves the CONTEXT + FS chokepoints symbolize through the launcher;
 * THIS suite proves the launcher additionally ENGAGES — and correctly WIRES — the
 * kernel-tier rungs the recent default-on work flipped on (exec-routing.md §7,
 * the non-root-privilege principle, privilege-model.md §0):
 *
 *   - exec-box: the PATH-shadow box shim set is written, ROUTES through the
 *     committed mandu-exec-box bin, and BAKES the fs-view AgentView pair (the
 *     co-design: fs-sync's viewMap must reach applyExecBox so a boxed write lands
 *     in the AgentView). A behavioral leg runs the LAUNCHER-PRODUCED `cat` shim
 *     and confirms it boxes + reads the RO root — coverage the .sh oracle can't
 *     give, because it calls writeExecBoxShims directly, never through a real
 *     launcher plan carrying the fs-view pair.
 *   - landlock-net: the whole-agent TCP confine is LIVE and its allowed CONNECT
 *     set includes the model-proxy port (else the agent's own model calls would
 *     be denied — the one port the confine must never drop).
 *   - fs-sync: the cooperative rung is ACTIVE (the workspace is a git repo).
 *
 * Each rung's HARD assertion is gated on probeKernelTier() — on a host that
 * cannot support a rung (no bwrap / pre-6.7 kernel / bins not built) the launcher
 * self-degrades with a banner, and we assert THAT instead (the non-root principle:
 * a self-SKIP where the kernel lacks a feature is correct, not a failure). On a
 * supporting host (the dev host: kernel 6.8, Landlock ABI 4, bins built) every rung is
 * asserted LIVE.
 *
 * The model endpoint is the scripted fake-anthropic behind the golden-path HTTPS
 * shim (no key, no network, ZERO real API budget): the model's DECISIONS don't
 * matter to the kernel tier — what matters is that the launcher wired the box +
 * net confine and a real claude ran inside them, holding §9. The fake scripts a
 * Read of the AgentView twin, so the fs chokepoint (on-disk symbol) + the model
 * proxy (§9 predicate) are both exercised while the hardening engages around them.
 *
 * GATED: skips when `claude` is not on PATH. Zero real API budget. Belongs to the
 * `drills:replay` set (deterministic, fake upstream).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";

const execFileAsync = promisify(execFile);

import { ViewLayout } from "../../fs-sync/src/layout.js";
import { startFakeAnthropic } from "../lib/fake-anthropic.js";
import { CLAUDE_AVAILABLE } from "../lib/live-shared.js";
import {
  INJECTION, withStack, startHttpsShim, runLauncher, publishedProxyPort,
  probeKernelTier, hardeningBanners, findExecBoxShimDir, git,
} from "../lib/launcher-live.js";
import { installExitGuard } from "../lib/exit-guard.js";
import { MANDU_BWRAP, resolveWrapBwrap } from "../../launcher/src/bwrap-grant.js";

installExitGuard("launcher-kernel-tier");

const CLAUDE_ARGS = ["--model", "claude-haiku-4-5", "--output-format", "text", "--permission-mode", "bypassPermissions"];

/** A short tail of the launcher's combined output for a red-run assertion msg. */
function diag(out: string): string {
  return out.split("\n").filter((l) => /mandu:|fs rung|exec-box|landlock|net-guard|WITHOUT|DEGRADED/.test(l)).slice(-24).join("\n") || out.slice(-1200);
}

test(
  "LIVE launcher default-on kernel-tier hardening engages + wires correctly, §9 holds through the stack",
  { skip: CLAUDE_AVAILABLE ? false : "`claude` binary not on PATH", timeout: 180_000 },
  async () => {
    await withStack(async ({ tmp, workspace, viewState, launcherEnv }) => {
      const probe = probeKernelTier();
      console.error(
        `[kernel-tier] probe: execBoxSupported=${probe.execBoxSupported} ` +
        `landlockNetSupported=${probe.landlockNetSupported} netGuardSupported=${probe.netGuardSupported} ` +
        `(bwrap=${probe.bwrap} userns=${probe.userns} landlockNetAbi=${probe.landlockNetAbi} ` +
        `execBoxBin=${!!probe.execBoxBin} landlockApplyBin=${!!probe.landlockApplyBin} netGuardBin=${!!probe.netGuardBin})`,
      );

      // Script the fake to Read the AgentView twin (golden-path scenario B shape):
      // the launcher seeds the symbolized worktree, so the poisoned file is a
      // symbol ON DISK before Read, and the model proxy backstops §9 on the wire.
      const layout = new ViewLayout(workspace, viewState);
      const agentNotes = join(layout.agentViewPath, "notes.md");
      const fake = await startFakeAnthropic({ readFilePath: agentNotes, promptMarker: "MDU_KT" });
      const shim = await startHttpsShim(fake.origin, tmp);
      const proxyPort = 0; // port 0: the launcher adopts the proxy's published port (test-organization.md §8.4)

      try {
        // DEFAULT flags: no --no-exec-box / --no-landlock-net / --no-fs-sync, so
        // every rung engages by default. Only --no-scope (no systemd session bus
        // in the test env) and --no-mcp (the U-LLM path is out of scope here).
        const r = await runLauncher(
          ["--no-scope", "--no-mcp", "--", "claude", "-p",
           `MDU_KT Read the file ${agentNotes} and reply with its first heading.`, ...CLAUDE_ARGS],
          launcherEnv(shim.origin, proxyPort), workspace,
        );
        assert.equal(r.code, 0, `launcher+claude exited 0 (the hardening must not break the launch); banners:\n${diag(r.out)}`);

        const banners = hardeningBanners(r.out);

        // ── fs-sync: the cooperative rung is ACTIVE (git workspace) ──────────────
        assert.ok(banners.fsRungActive, `fs rung not ACTIVE (default-on fs-sync should engage on a git workspace):\n${diag(r.out)}`);
        assert.ok(!banners.fsRungDegraded, `fs rung reported DEGRADED:\n${diag(r.out)}`);

        // ── exec-box: LIVE, and the shim set is wired through the box bin ────────
        if (probe.execBoxSupported) {
          assert.ok(banners.execBoxLive, `exec-box not LIVE though supported here:\n${diag(r.out)}`);
          assert.ok(!banners.execBoxDegraded, `exec-box reported DEGRADED though supported:\n${diag(r.out)}`);

          const shimDir = findExecBoxShimDir(tmp);
          assert.ok(shimDir, "the launcher wrote no exec-box shim dir under the scope run dir");
          assert.ok(existsSync(join(shimDir!, "cat")), "the default box set's `cat` shim was not written");

          const catShim = readFileSync(join(shimDir!, "cat"), "utf8");
          // The shim ROUTES through the committed box bin (not a bare exec).
          assert.match(catShim, /exec ".*mandu-exec-box" --cwd "\$PWD" -- "cat"/,
            "the launcher's cat shim does not route through the mandu-exec-box bin");
          // fs-view CO-DESIGN: fs-sync's viewMap reached applyExecBox, so the shim
          // baked the AgentView pair (writable-AgentView boxing). This is the seam
          // the .sh oracle cannot exercise (it never runs a real launcher plan).
          assert.match(catShim, new RegExp(`export MANDU_AGENTVIEW_ROOT="${layout.agentViewPath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`),
            "the launcher's box shim did not bake the fs-view AgentView root (co-design not wired)");
          // The clean-box posture (exec-routing.md §8.5.1, §8.5.3, FROZEN with
          // the integrity axis): ON by default exactly where the session's guard
          // hosts the attempt (integrity ON — withStack pins it — Linux, exec-box
          // + guard on, the guard bin built: clean-host.ts cleanReporterWanted),
          // with the guard's socket baked; elsewhere OFF. Baked HARD either way —
          // ambient env cannot flip a session's posture.
          if (probe.netGuardBin) {
            assert.match(catShim, /\nexport MANDU_EXEC_CLEAN_BOX="1"\n/,
              "the launcher's box shim did not bake the guard-hosted clean-box default (ON)");
            assert.match(catShim, /\nexport MANDU_EXEC_CLEAN_SOCK=".*\/clean\.sock"\n/,
              "the launcher's box shim did not name the guard's clean-run socket");
            assert.match(r.out, /exec-box CLEAN BOX first .*The session's guard runs the attempt/,
              `the clean-box banner does not say the guard hosts the attempt:\n${diag(r.out)}`);
          } else {
            assert.match(catShim, /\nexport MANDU_EXEC_CLEAN_BOX="0"\n/,
              "without the guard the launcher's box shim did not bake the default-off clean-box posture");
          }

          // BEHAVIORAL: the LAUNCHER-PRODUCED shim actually boxes + reads the RO
          // root. Runs against the live withStack arbiter (the box fails closed
          // without it). MUST be async (execFileAsync, not spawnSync): the arbiter
          // is IN-PROCESS in this test, and a synchronous spawn would freeze the
          // event loop that serves it — the box's classify call would deadlock,
          // time out, and be SIGKILLed (the `exited null` this leg first hit). No
          // shim dir on our PATH → `cat` inside the box resolves to the real
          // binary. Reads a stable file OUTSIDE /tmp (the box mounts a fresh
          // tmpfs at /tmp), comparing boxed vs bare output.
          const roFile = existsSync("/etc/hostname") ? "/etc/hostname" : "/etc/os-release";
          if (existsSync(roFile)) {
            const bare = readFileSync(roFile, "utf8");
            // Mandu's own bubblewrap first on PATH, as the launcher composes the
            // agent's PATH (bwrap-grant.ts): where `mandu setup` replaced the
            // system bwrap's AppArmor grant, the system one cannot set up the
            // box's net namespace ("loopback: Failed RTM_NEWADDR").
            const wrapBwrap = resolveWrapBwrap();
            const bwrapDir = wrapBwrap === MANDU_BWRAP ? dirname(wrapBwrap) : undefined;
            const path = [...(bwrapDir ? [bwrapDir] : []), process.env["PATH"] ?? ""].join(":");
            let boxedOut: string | null = null;
            try {
              const { stdout } = await execFileAsync(join(shimDir!, "cat"), [roFile], {
                timeout: 40_000,
                env: { ...process.env, PATH: path, MANDU_ARBITER_SOCK: join(tmp, "arbiter.sock") },
              });
              boxedOut = stdout;
            } catch (e) {
              assert.fail(`the launcher-produced boxed cat failed: ${e instanceof Error ? e.message : String(e)}`);
            }
            assert.equal(boxedOut, bare, "the launcher-produced boxed cat did not read the RO root through the box (routing/boxing broke)");
          }
        } else {
          assert.ok(banners.execBoxDegraded, `exec-box unsupported here but no degrade banner (the non-root principle: self-SKIP loudly):\n${diag(r.out)}`);
        }

        // ── landlock-net: LIVE, and the model-proxy port survives the confine ────
        if (probe.landlockNetSupported) {
          assert.ok(banners.landlockNetLive, `landlock-net not LIVE though supported here:\n${diag(r.out)}`);
          assert.ok(!banners.landlockNetDegraded, `landlock-net reported DEGRADED though supported:\n${diag(r.out)}`);
          const boundPort = publishedProxyPort(tmp);
          assert.ok(banners.landlockNetPorts.includes(boundPort),
            `the model-proxy port ${boundPort} is NOT in the confined CONNECT set [${banners.landlockNetPorts.join(", ")}] — the agent's own model calls would be denied`);
        } else {
          assert.ok(banners.landlockNetDegraded, `landlock-net unsupported here but no degrade banner:\n${diag(r.out)}`);
        }

        // ── net-guard: LIVE (the IP/domain-aware connect-guard, §7.5) ───────────
        // Default-on and the non-strict default → LIVE with the permissive
        // fallback (NOT narrowed), so it never breaks the driven claude. On a host
        // without the seccomp trap the launcher self-degrades with a banner.
        if (probe.netGuardSupported) {
          assert.ok(banners.netGuardLive, `net-guard not LIVE though supported here:\n${diag(r.out)}`);
          assert.ok(!banners.netGuardDegraded, `net-guard reported DEGRADED though supported:\n${diag(r.out)}`);
          assert.ok(banners.netGuardRuleCount > 0, `net-guard LIVE banner reported no allow rules:\n${diag(r.out)}`);
          assert.ok(!banners.netGuardNarrowed, `net-guard should be permissive (not narrowed) in the default posture:\n${diag(r.out)}`);
        } else {
          assert.ok(banners.netGuardDegraded, `net-guard unsupported here but no degrade banner (self-SKIP loudly):\n${diag(r.out)}`);
        }

        // ── §9: the invariant held through the FULL launcher stack ──────────────
        // Positive oracle first — without it the wire scan is vacuously true when
        // claude never issued a tool_result at all.
        assert.ok(fake.toolResultRequests().length > 0, "claude executed Read and returned a tool_result");
        assert.ok(fake.toolResultRequests().some((q) => /\$MDU:/.test(q.body)),
          "the AgentView symbol did not flow to the model");
        for (const req of fake.requests) {
          assert.ok(!req.body.includes(INJECTION), "INVARIANT: raw payload reached the model through the hardened launch");
          assert.ok(!req.body.includes("IGNORE ALL PREVIOUS INSTRUCTIONS"), "no raw injection fragment reached the model");
        }

        // The on-disk fs chokepoint held too (the twin was symbolized before Read).
        const onDisk = readFileSync(agentNotes, "utf8");
        assert.ok(onDisk.includes("$MDU:"), "the AgentView notes.md holds no symbol");
        assert.ok(!onDisk.includes(INJECTION), "the AgentView notes.md still holds the raw payload");
        assert.ok(readFileSync(join(workspace, "notes.md"), "utf8").includes(INJECTION),
          "the HumanView notes.md lost its raw original (the human must still see it)");
      } finally {
        await shim.close();
        await fake.close();
      }
    });
  },
);

test(
  "LIVE --no-kernel drops the kernel rungs in one switch; cooperative tier + §9 intact",
  { skip: CLAUDE_AVAILABLE ? false : "`claude` binary not on PATH", timeout: 180_000 },
  async () => {
    await withStack(async ({ tmp, workspace, viewState, launcherEnv }) => {
      const layout = new ViewLayout(workspace, viewState);
      const agentNotes = join(layout.agentViewPath, "notes.md");
      const fake = await startFakeAnthropic({ readFilePath: agentNotes, promptMarker: "MDU_KTN" });
      const shim = await startHttpsShim(fake.origin, tmp);
      const proxyPort = 0; // port 0: the launcher adopts the proxy's published port (test-organization.md §8.4)
      try {
        const r = await runLauncher(
          ["--no-scope", "--no-mcp", "--no-kernel", "--", "claude", "-p",
           `MDU_KTN Read the file ${agentNotes} and reply with its first heading.`, ...CLAUDE_ARGS],
          launcherEnv(shim.origin, proxyPort), workspace,
        );
        assert.equal(r.code, 0, `launcher+claude exited 0 under --no-kernel; banners:\n${diag(r.out)}`);

        const banners = hardeningBanners(r.out);
        // The kernel-tier rungs are OFF — no LIVE banner, no shim dir written.
        assert.ok(!banners.execBoxLive, `exec-box must NOT be LIVE under --no-kernel:\n${diag(r.out)}`);
        assert.ok(!banners.landlockNetLive, `landlock-net must NOT be LIVE under --no-kernel:\n${diag(r.out)}`);
        assert.ok(!banners.netGuardLive, `net-guard must NOT be LIVE under --no-kernel:\n${diag(r.out)}`);
        assert.equal(findExecBoxShimDir(tmp), null, "no exec-box shim dir should be written under --no-kernel");

        // The USERSPACE cooperative tier is untouched — portable ≠ defenseless.
        assert.ok(banners.fsRungActive, `fs-sync must stay ACTIVE under --no-kernel:\n${diag(r.out)}`);

        // §9 still holds through the cooperative-only stack.
        assert.ok(fake.toolResultRequests().length > 0, "claude executed Read and returned a tool_result");
        assert.ok(fake.toolResultRequests().some((q) => /\$MDU:/.test(q.body)),
          "the AgentView symbol did not flow to the model under --no-kernel");
        for (const req of fake.requests) {
          assert.ok(!req.body.includes(INJECTION), "INVARIANT: raw payload reached the model under --no-kernel");
        }
      } finally {
        await shim.close();
        await fake.close();
      }
    });
  },
);

test(
  "LIVE net-guard CURATED (--net-allow) narrows :443 + auto-allows the workspace git remote; claude runs, §9 holds",
  { skip: CLAUDE_AVAILABLE ? false : "`claude` binary not on PATH", timeout: 180_000 },
  async () => {
    await withStack(async ({ tmp, workspace, viewState, launcherEnv }) => {
      const probe = probeKernelTier();
      if (!probe.netGuardSupported) {
        console.error("[kernel-tier] net-guard unsupported on this host (bin missing / no seccomp trap) — SKIP the curated leg");
        return;
      }
      // Give the workspace a git remote so the guard's narrowed allow-set
      // auto-includes it (the recipe: git push/fetch survive a tightened guard).
      git(workspace, ["remote", "add", "origin", "https://github.com/mandu/kt-test.git"]);

      const layout = new ViewLayout(workspace, viewState);
      const agentNotes = join(layout.agentViewPath, "notes.md");
      const fake = await startFakeAnthropic({ readFilePath: agentNotes, promptMarker: "MDU_KTC" });
      const shim = await startHttpsShim(fake.origin, tmp);
      const proxyPort = 0; // port 0: the launcher adopts the proxy's published port (test-organization.md §8.4)
      try {
        // A CURATED guard: --net-allow drops the permissive *:443/*:22 fallback →
        // :443 admitted ONLY to the API host + this curated entry + the auto-added
        // git remote (+ the always-on loopback services claude's model calls ride).
        const r = await runLauncher(
          ["--no-scope", "--no-mcp", "--net-allow=example.test:443", "--", "claude", "-p",
           `MDU_KTC Read the file ${agentNotes} and reply with its first heading.`, ...CLAUDE_ARGS],
          launcherEnv(shim.origin, proxyPort), workspace,
        );
        assert.equal(r.code, 0, `launcher+claude exited 0 under a CURATED net-guard (the loopback proxy must stay reachable); banners:\n${diag(r.out)}`);

        const banners = hardeningBanners(r.out);
        // The guard is LIVE and NARROWED (no permissive fallback).
        assert.ok(banners.netGuardLive, `net-guard not LIVE under --net-allow:\n${diag(r.out)}`);
        assert.ok(banners.netGuardNarrowed, `net-guard should be CURATED/narrowed under --net-allow:\n${diag(r.out)}`);
        // The recipe: the workspace's https git remote was auto-allowed on :443.
        assert.ok(banners.netGuardGitRemotes.includes("tcp:github.com:443"),
          `the workspace git remote was not auto-allowed [${banners.netGuardGitRemotes.join(", ")}]:\n${diag(r.out)}`);

        // claude still reached the model (loopback proxy is always in the set) and
        // §9 held through the narrowed guard.
        assert.ok(fake.toolResultRequests().length > 0, "claude executed Read + returned a tool_result under the curated guard");
        assert.ok(fake.toolResultRequests().some((q) => /\$MDU:/.test(q.body)),
          "the AgentView symbol did not flow to the model under the curated guard");
        for (const req of fake.requests) {
          assert.ok(!req.body.includes(INJECTION), "INVARIANT: raw payload reached the model under the curated net-guard");
        }
      } finally {
        await shim.close();
        await fake.close();
      }
    });
  },
);
