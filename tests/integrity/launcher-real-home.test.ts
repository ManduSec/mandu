/**
 * launcher-real-home.test.ts — the REAL-HOME LAUNCH SMOKE.
 *
 * FROZEN LANE (docs/design/architecture/protection-modes.md §10.5, §10.7; test-organization.md
 * §7.1, 2026-09-29): the integrity form of this suite, moved verbatim from
 * test/live/ when the kernel tier's launcher-home suites moved to `secrets`.
 * It runs only when the integrity axis is revived (`npm run test:integrity`).
 * The default-lane tests/sandbox/launcher/launcher-real-home.test.ts proves the
 * confidentiality form; this copy keeps what exists only with integrity ON:
 * L4 and L5, the AgentView twin inheriting the human's claude and codex
 * workspace trust (in `secrets` there is no AgentView twin; the agent runs in
 * the trusted folder itself).
 *
 * Every other launcher-wrapping suite runs the wrapped side against a HOME the
 * harness does not shape (withStack passes the developer's real HOME through
 * but leaves the confidentiality axis OFF; the container tier has a synthetic
 * HOME with nothing in it). So a launcher that cannot START against a HOME
 * shaped like a developer's was invisible to every tier: on 2026-09-05 EVERY
 * `mandu … -- claude` on the dev box died before the TUI existed —
 *
 *   bwrap: Can't mkdir parents for ~/tools/linux/Documentation/security/credentials.rst
 *
 * — because the secret walk followed `~/tools/linux → /mnt/…` into a kernel
 * tree, the `*credentials*` catalog shape matched a doc file, and the twin
 * bind over that symlinked spelling failed, refusing the launch fail-closed
 * (confidentiality.md §7.2, "Symlinks").
 *
 * This suite builds THAT home shape on purpose — a symlinked directory, a
 * symlinked secret file, a real catalog secret — turns the axis ON, and runs
 * the real launcher (all hardening default-on) around a trivial command. It
 * asserts:
 *   L1 the launch SUCCEEDS (exit 0) — the symlinked directory is not walked
 *      and cannot brick the bind plan;
 *   L2 the real secret AND the symlinked secret read back as their twins
 *      (`$MDU:nomodel_Read[…]`), never the raw bytes: the symlinked file is bound
 *      on its resolved path, so BOTH spellings are masked;
 *   L3 the file behind the symlinked directory is NOT twinned (never walked)
 *      and reads back raw — the launch did not merely survive, it drew the
 *      right line;
 *   L4 the AgentView twin INHERITS the human's workspace trust from
 *      `.claude.json` (services/claude-trust.ts) — the first launch in an
 *      already-trusted project must not open claude's "Accessing workspace"
 *      dialog whose default is "No, exit";
 *   L5 the same for codex (`$CODEX_HOME/config.toml`, services/codex-trust.ts)
 *      — a second launcher run at --target codex around /bin/true.
 *
 * `--no-reply-filter` keeps stdout as the AGENT sees it (the filter would
 * resolve the twins back into the raw bytes for the human — correct product
 * behavior, wrong oracle surface here). Absolute `/bin/cat` bypasses the
 * exec-box PATH shims so the read is a plain read inside the twin namespace.
 *
 * GATED on Linux + bwrap + an unprivileged userns (the twin's own gates);
 * needs no claude, no key, no network. Zero API budget.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { ViewLayout } from "../../fs-sync/src/layout.js";

import { withStack, runLauncher, probeKernelTier } from "../lib/launcher-live.js";
import { installExitGuard } from "../lib/exit-guard.js";

installExitGuard("launcher-real-home");

const probe = process.platform === "linux" ? probeKernelTier() : null;
const GATE = process.platform !== "linux"
  ? "Linux only (bwrap secret twins)"
  : !probe!.bwrap
    ? "`bwrap` not installed"
    : !probe!.userns
      ? "unprivileged user namespaces unavailable"
      : false;

const RAW_AWS = "AKIA_REAL_SECRET_4471_NEVER_IN_AGENT_WORLD";
const RAW_KEY = "SSH_REAL_KEY_9921_NEVER_IN_AGENT_WORLD";
const DOC_LINE = "kernel doc, not a secret: credentials.rst";

test(
  "LIVE real-HOME smoke: the launcher starts against a developer-shaped HOME (symlinked dir + symlinked secret), twins both spellings, walks no link",
  { skip: GATE, timeout: 120_000 },
  async () => {
    await withStack(async ({ tmp, workspace, viewState, launcherEnv }) => {
      // ── the HOME shape that bricked the launch ──
      const home = join(tmp, "home");
      const outside = join(tmp, "outside");
      mkdirSync(join(home, ".aws"), { recursive: true });
      mkdirSync(join(home, ".ssh"), { recursive: true });
      mkdirSync(join(home, "tools"), { recursive: true });
      mkdirSync(join(outside, "Documentation", "security"), { recursive: true });
      writeFileSync(join(home, ".aws", "credentials"), `[default]\naws_secret_access_key=${RAW_AWS}\n`);
      writeFileSync(join(outside, "real-key"), `-----BEGIN OPENSSH PRIVATE KEY-----\n${RAW_KEY}\n`);
      writeFileSync(join(outside, "Documentation", "security", "credentials.rst"), `${DOC_LINE}\n`);
      symlinkSync(outside, join(home, "tools", "linux"));                       // directory link
      symlinkSync(join(outside, "real-key"), join(home, ".ssh", "id_ed25519")); // secret file link

      const env: Record<string, string | undefined> = {
        ...launcherEnv("https://127.0.0.1:1", 0), // no model traffic in this smoke
        HOME: home,
      };
      // L4 setup — the human already trusted THIS workspace in claude's config
      // (the state of any project a user has run plain `claude` in): the
      // launcher must carry that over to the AgentView twin, whose trust
      // dialog otherwise greets every first launch with "No, exit".
      const ccConfig = env["CLAUDE_CONFIG_DIR"]!;
      mkdirSync(ccConfig, { recursive: true });
      writeFileSync(join(ccConfig, ".claude.json"), JSON.stringify({
        hasCompletedOnboarding: true,
        projects: { [workspace]: { hasTrustDialogAccepted: true } },
      }));
      const agentView = new ViewLayout(workspace, viewState).agentViewPath;
      const script = [
        `/bin/cat ${join(home, ".aws", "credentials")}`,
        `/bin/cat ${join(home, ".ssh", "id_ed25519")}`,          // the symlink spelling
        `/bin/cat ${join(outside, "real-key")}`,                  // the real spelling
        `/bin/cat ${join(home, "tools", "linux", "Documentation", "security", "credentials.rst")}`,
      ].join("; ");
      const r = await runLauncher(
        ["--no-scope", "--no-mcp", "--no-reply-filter", "--confidentiality", "--target", "claude", "--", "/bin/sh", "-c", script],
        env, workspace,
      );

      // L1 — the launch succeeded at all.
      assert.equal(r.code, 0, `launcher exited ${r.code} — the launch was refused; output:\n${r.out.slice(-1500)}`);
      assert.ok(!/Can't mkdir parents/.test(r.out), "the bwrap symlinked-parent failure must not recur");
      assert.ok(/confidentiality — \d+ secret\(s\) confined/.test(r.out), `the axis engaged (banner present); output:\n${r.out.slice(-2500)}`);

      // L2 — both secrets are twins in the agent's world, under EVERY spelling.
      assert.ok(!r.out.includes(RAW_AWS), "raw AWS secret bytes leaked into the agent's world");
      assert.ok(!r.out.includes(RAW_KEY), "raw SSH key bytes leaked into the agent's world (symlinked secret not masked on its real path)");
      const twins = r.out.match(/\$MDU:nomodel_Read\[[0-9a-f]+\]/g) ?? [];
      assert.ok(twins.length >= 3, `expected the three secret reads to yield twins, saw ${twins.length}:\n${r.out.slice(-1500)}`);

      // L3 — the file behind the symlinked DIRECTORY was never walked: raw.
      assert.ok(r.out.includes(DOC_LINE), "the doc behind the symlinked directory must read back raw (it is not a secret and must not be walked)");

      // L4 — the AgentView twin inherited the human's workspace trust.
      const cc = JSON.parse(readFileSync(join(ccConfig, ".claude.json"), "utf8")) as { projects: Record<string, { hasTrustDialogAccepted?: boolean }> };
      assert.equal(cc.projects[agentView]?.hasTrustDialogAccepted, true, `the AgentView twin ${agentView} must be trusted once its human workspace is; output:\n${r.out.slice(-800)}`);
      assert.equal(cc.projects[workspace]?.hasTrustDialogAccepted, true, "the human entry is untouched");
      assert.ok(/workspace trust inherited by the AgentView twin/.test(r.out), "the launcher says what it did");

      // L5 — the same for codex: its "Do you trust the contents of this
      // directory?" keys on the repository root it resolves for the twin (the
      // worktree's PARENT, the view state dir) in $CODEX_HOME/config.toml.
      const codexHome = join(home, ".codex");
      mkdirSync(codexHome, { recursive: true });
      writeFileSync(join(codexHome, "config.toml"), `model = "gpt-5.5"\n\n[projects.${JSON.stringify(workspace)}]\ntrust_level = "trusted"\n`);
      const rc = await runLauncher(
        ["--no-scope", "--no-mcp", "--no-reply-filter", "--target", "codex", "--", "/bin/true"],
        { ...env, CODEX_HOME: codexHome, OPENAI_API_KEY: "sk-mdu-dummy" }, workspace,
      );
      assert.equal(rc.code, 0, `codex-target launch exited ${rc.code}; output:\n${rc.out.slice(-1200)}`);
      const toml = readFileSync(join(codexHome, "config.toml"), "utf8");
      for (const p of [dirname(agentView), agentView]) {
        assert.ok(toml.includes(`[projects.${JSON.stringify(p)}]`), `codex trust table for ${p}; output:\n${rc.out.slice(-800)}`);
      }
      assert.ok(toml.startsWith(`model = "gpt-5.5"`), "the existing config is untouched — tables are appended");
      assert.ok(/directory trust inherited by the AgentView twin/.test(rc.out), "the launcher says what it did");
    }, { confidentiality: true }); // the axis must be ON at the ARBITER too (it gates discovery)
  },
);
