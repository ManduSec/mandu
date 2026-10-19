/**
 * launcher-real-home.test.ts — the REAL-HOME LAUNCH SMOKE.
 *
 * Until this suite, every launcher-wrapping suite ran the wrapped side against
 * a HOME the harness did not shape (withStack passed the developer's real HOME
 * through with the confidentiality axis OFF; the container tier has a
 * synthetic HOME with nothing in it). So a launcher that cannot START against
 * a HOME shaped like a developer's was invisible to every tier: on 2026-09-05 EVERY
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
 * symlinked secret file, a real catalog secret — in the throwaway HOME
 * withStack hands a `mode` launch (never the developer's own: the SHAPE is the
 * subject, and the developer's HOME would make the verdict host-dependent),
 * runs the private arbiter in `secrets` (the built-in default mode;
 * test-organization.md §7.1), and runs the real launcher (all hardening
 * default-on) around a trivial command. It asserts:
 *   L1 the launch SUCCEEDS (exit 0) — the symlinked directory is not walked
 *      and cannot brick the bind plan;
 *   L2 the real secret AND the symlinked secret read back as their twins
 *      (`$MDU:nomodel_Read[…]`), never the raw bytes: the symlinked file is bound
 *      on its resolved path, so BOTH spellings are masked;
 *   L3 the file behind the symlinked directory is NOT twinned (never walked)
 *      and reads back raw — the launch did not merely survive, it drew the
 *      right line;
 *   L4 the first launch in an already-trusted project must not open claude's
 *      "Accessing workspace" dialog, whose default is "No, exit". In `secrets`
 *      the fs rung is off by mode, so the agent runs IN the folder the human
 *      trusted (no AgentView twin exists to inherit anything): asserted as the
 *      off-by-mode line, the agent's cwd being the trusted workspace, no twin
 *      on disk, and the human's `.claude.json` left byte-for-byte alone;
 *   L5 the same for codex (`$CODEX_HOME/config.toml`) — a second launcher run
 *      at --target codex.
 *
 * The integrity form (L4/L5 as the AgentView twin INHERITING the human's
 * trust, services/claude-trust.ts and codex-trust.ts) is frozen:
 * tests/integrity/launcher-real-home.test.ts.
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
import { existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { ViewLayout } from "../../../fs-sync/src/layout.js";

import { withStack, runLauncher, probeKernelTier, hardeningBanners } from "../../lib/launcher-live.js";
import { installExitGuard } from "../../lib/exit-guard.js";
import { stateAxes } from "../../lib/axes.js";

installExitGuard("launcher-real-home");

// This suite STATES its axes (protection-modes.md §4): `secrets`. withStack
// brings its private arbiter up in the same mode.
stateAxes("secrets");

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
    await withStack(async ({ tmp, workspace, home, viewState, launcherEnv }) => {
      // ── the HOME shape that bricked the launch (withStack's throwaway HOME) ──
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
      // launch must not put the agent anywhere that trust does not cover
      // (claude's trust dialog greets such a cwd with "No, exit").
      const ccConfig = env["CLAUDE_CONFIG_DIR"]!;
      mkdirSync(ccConfig, { recursive: true });
      const ccBefore = JSON.stringify({
        hasCompletedOnboarding: true,
        projects: { [workspace]: { hasTrustDialogAccepted: true } },
      });
      writeFileSync(join(ccConfig, ".claude.json"), ccBefore);
      const agentView = new ViewLayout(workspace, viewState).agentViewPath;
      const script = [
        `echo "AGENT_CWD=$(/bin/pwd)"`,
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

      // L4 — `secrets` needs no AgentView (the fs rung is off BY MODE,
      // services/manager.ts), so the agent runs in the very folder the human
      // trusted: nothing to inherit, and the human's config is not rewritten.
      const banners = hardeningBanners(r.out);
      assert.ok(banners.fsRungOffByMode, `the fs rung did not report off-by-mode in \`secrets\`; output:\n${r.out.slice(-1500)}`);
      assert.ok(!banners.fsRungActive && !banners.fsRungDegraded, "the fs rung must not run in `secrets`");
      assert.ok(r.out.includes(`AGENT_CWD=${workspace}\n`), `the agent must run in the trusted workspace ${workspace}; saw ${JSON.stringify(r.out.match(/AGENT_CWD=.*/g))}`);
      assert.ok(!existsSync(agentView), `no AgentView twin may exist in \`secrets\` (${agentView})`);
      assert.equal(readFileSync(join(ccConfig, ".claude.json"), "utf8"), ccBefore, "the human's .claude.json is untouched");
      assert.ok(!/trust inherited by the AgentView twin/.test(r.out), "no AgentView twin, so no trust to carry over");

      // L5 — the same for codex: its "Do you trust the contents of this
      // directory?" keys on the repository root it resolves, here the human's
      // own, already trusted, workspace.
      const codexHome = join(home, ".codex");
      mkdirSync(codexHome, { recursive: true });
      const tomlBefore = `model = "gpt-5.5"\n\n[projects.${JSON.stringify(workspace)}]\ntrust_level = "trusted"\n`;
      writeFileSync(join(codexHome, "config.toml"), tomlBefore);
      // A shell stand-in: the launcher gives a shell none of codex's `-c`
      // routing options (codex-argv.ts codexOverridesReach).
      const rc = await runLauncher(
        ["--no-scope", "--no-mcp", "--no-reply-filter", "--target", "codex", "--", "/bin/sh", "-c", `echo "AGENT_CWD=$(/bin/pwd)"`],
        { ...env, CODEX_HOME: codexHome, OPENAI_API_KEY: "sk-mdu-dummy" }, workspace,
      );
      assert.equal(rc.code, 0, `codex-target launch exited ${rc.code}; output:\n${rc.out.slice(-1200)}`);
      assert.ok(hardeningBanners(rc.out).fsRungOffByMode, `codex launch: the fs rung did not report off-by-mode; output:\n${rc.out.slice(-1200)}`);
      assert.ok(rc.out.includes(`AGENT_CWD=${workspace}\n`), `codex must run in the trusted workspace ${workspace}; saw ${JSON.stringify(rc.out.match(/AGENT_CWD=.*/g))}; output:\n${rc.out.slice(0, 1500)}`);
      assert.equal(readFileSync(join(codexHome, "config.toml"), "utf8"), tomlBefore, "the human's codex config is untouched");
      assert.ok(!/trust inherited by the AgentView twin/.test(rc.out), "no AgentView twin, so no trust to carry over");
    }, { mode: "secrets" }); // confidentiality ON at the ARBITER (it gates discovery), integrity OFF
  },
);
