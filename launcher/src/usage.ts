/**
 * usage — the `mandu --help` text (protection-modes.md §3.2: "--help must
 * list the modes"; release review P0: `--help` used to answer "no command
 * given"). Kept short: the launch forms, the modes, the management verbs, and
 * where the long list of expert flags lives (the public docs URL: an npm
 * install ships no docs/ directory, docs-url.ts).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code.
 */
import { docsUrl } from "./docs-url.js";
import { modeHelpLines } from "./mode.js";

export function usageText(): string {
  return [
    "mandu: run an AI coding agent under Mandu protection",
    "",
    "usage:",
    "  mandu [options] <agent> [agent args…]     e.g.  mandu claude",
    "  mandu [options] -- <agent or shell> …     verbatim after --, e.g.  mandu -- bash",
    "  mandu <verb> [args…]                      manage Mandu (verbs below)",
    "",
    "agents: claude, codex, openclaw, opencode, goose   (--target <agent> for a wrapper script)",
    "a shell (bash, sh, zsh, …) runs as a plain command under every protection; its model calls are",
    "  covered only for programs that read ANTHROPIC_BASE_URL (claude). Any other command:",
    "  mandu --target shell -- <command…>",
    "",
    "protection mode:  --mode <name>   (env MANDU_MODE, config key `mode`)",
    ...modeHelpLines(),
    "  The mode is read once when the protection service starts. `mandu mode`",
    "  shows the running and the saved mode; `mandu mode <name>` saves one.",
    "  Expert overrides, one axis each: --[no-]confidentiality, --no-integrity (--integrity is frozen too).",
    "",
    "verbs:",
    "  mode [name]   show or save the protection mode",
    "  status        what is running",
    "  stop [--all]  stop the background services",
    "  dashboard     open the dashboard",
    "  doctor        check this host (--live: a launch rehearsal; --secrets [--json]: what a launch",
    "                would mask and what it would leave raw, without starting an agent)",
    "  policy suggest  keys in this project (its git history and its files) your policy does not protect:",
    "                review the rule for each and apply it (--dry-run, --json, --apply-all, --home)",
    "  why           why a file or host is treated as it is: mandu why ~/.pgpass, mandu why .env --to api.example.com,",
    "                mandu why api.example.com, mandu why '$MDU:…' (where a placeholder came from;",
    "                --json for the raw answer)",
    "  revert        undo what the agent wrote here: list its writes, --to N to return to one (asks first)",
    "  demo          30 seconds, offline, no key: the model sees a fake .env only as $MDU:…, you see the values",
    "  setup         the one optional privileged step (Ubuntu 24.04 AppArmor grants)",
    "  init          write a commented ~/.mandu/config.toml",
    "  paths         where Mandu keeps its files, and who can open them (--json)",
    "  version       which mandu this is: where it is, its commit, other mandu installs and running",
    "                services that get in its way, each with its fix (--json)",
    "  log           what the last launch said in full: every notice, warning and protection layer",
    "                (--list: the kept launches; <session id>: that one)",
    "  reap          clean up stale stacks and scope dirs",
    "",
    "common options:",
    "  --help, -h  --version, -V",
    "  --verbose                 print every protection layer and notice as it comes up (default:",
    "                            one line, plus a line per protection warning; the rest goes to",
    "                            `mandu log`; env MANDU_VERBOSE=1)",
    "  --no-net-proxy            run without the egress gate (a launch whose gate cannot start",
    "                            is refused; this is the deliberate way around that)",
    "  --require-confinement     refuse to launch if secrets cannot be confined on this host",
    "  --no-env-secrets          leave secret-shaped environment variables unmasked",
    "  --no-net-proxy-mitm       no TLS inspection at the egress proxy (masked values then cannot be",
    "                            put back into HTTPS requests; on by default in secrets and full mode)",
    "  --no-kernel, --portable   turn off the kernel-level protections in one switch",
    "  --id <scope>  --tenant live|test  --target <agent>|shell",
    "  Every rung has a --<rung> / --no-<rung> pair (fs-sync, net-proxy, exec-wrap,",
    "  exec-box, landlock-net, net-guard, reply-filter); the full list is in the guide below.",
    "",
    "precedence: flags > MANDU_* env > ~/.mandu/config.toml > defaults",
    "",
    `guide (every command and setting): ${docsUrl("docs/usage.md")}`,
    `what is guaranteed, and what is not: ${docsUrl("docs/guarantees.md")}`,
    "",
  ].join("\n");
}
