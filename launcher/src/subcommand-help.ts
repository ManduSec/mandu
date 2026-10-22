/**
 * subcommand-help — `mandu <verb> --help` (release checklist d8).
 *
 * Before this, `--help` after a verb was just another argument: `setup`
 * answered "unknown option", `why` printed a usage error, and `stop`, `reap`,
 * `init` and `dashboard` ignored it and DID their job (stopped the services,
 * reaped, wrote a config, started a dashboard). The dispatcher now checks for
 * `--help` / `-h` before running any verb and prints the verb's usage instead.
 *
 * Pure: no I/O. PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code.
 */

/** One usage block per reserved verb (subcommands.ts RESERVED_SUBCOMMANDS). */
export const SUBCOMMAND_USAGE: Record<string, string[]> = {
  status: [
    "usage: mandu status [--verbose]",
    "  Show whether Mandu is running: the arbiter, the dashboard URL, and leftovers from ended sessions.",
    "  --verbose  also list every registered service and Mandu process.",
  ],
  stop: [
    "usage: mandu stop [--all] [--stack <runtime dir> | --every-stack]",
    "  stop the background services (the protection service, the dashboard, the proxies).",
    "  --all          also stop running launchers and their per-session helpers",
    "  --stack <dir>  only the processes of the stack whose runtime dir is <dir>",
    "  --every-stack  every stack of this user; needed when the environment (MANDU_RUNTIME_DIR,",
    "                 or an XDG_RUNTIME_DIR or TMPDIR not the login session's) names another stack",
    "                 (without it, a stop that would reach a different stack is refused)",
  ],
  dashboard: [
    "usage: mandu dashboard [--set-password]",
    "  print the URL of your running dashboard, starting one if none is running,",
    "  and, on a terminal, how to sign in: your dashboard account, or a one-time sign-in link",
    "  (Allow / Block need it; not from inside an agent's sandbox).",
    "  --set-password  make or change your dashboard account: one username and password for every",
    "                  dashboard page, asked in this terminal and kept only as a password hash.",
    "  env DASHBOARD_PORT=<port> pins the port (default: a free one).",
  ],
  doctor: [
    "usage: mandu doctor [--live [--model] | --secrets [--target <agent> [--no-mcp]] [--json] [--no-history]]",
    "  check this host: what protections it supports and what a launch would do.",
    "  --live        a launch rehearsal (starts the services, runs a probe, stops them)",
    "  --model       with --live: also make one real model call",
    "  --secrets     what a launch would mask and what it would leave raw, without starting an agent;",
    "                also scans this repository's git history for keys (values are never shown)",
    "  --target      with --secrets: as a launch of that agent (claude, codex, opencode, goose, openclaw,",
    "                shell): the logins it runs on stay raw, every other agent's is masked",
    "  --no-mcp      with --target: as a launch with --no-mcp (no AI helper, whose program's login is then not kept)",
    "  --json        with --secrets: the raw report",
    "  --no-history  with --secrets: skip the git-history scan",
  ],
  scan: [
    "usage: mandu scan [--all] [--show <n>] [--since <days>d|<date>] [--open] [--share | --json]",
    "  which of your secrets your AI agents already sent to the AI, and how: reads the transcripts",
    "  Claude Code and Codex keep on this computer, read-only and offline; no secret's value is shown",
    "  or sent (a command shown has every value it holds masked).",
    "  --all     the long report: each finding's story, every key-like value and value named like a",
    "            secret (DB_PASSWORD=…), the sends by host",
    "  colour on a terminal only (NO_COLOR turns it off, FORCE_COLOR=1 on)",
    "  --show    finding <n> of the report in full: every way it got there, up to 10 examples each",
    "  --since   only transcripts written in the last <days> (30d) or since a date (2026-09-01)",
    "  --open    then open your dashboard's Scan page in your browser, starting the dashboard if none",
    "            runs (with no browser here, as over SSH: its URL, and how to reach it)",
    "  --share   a short text to post: counts only, no value, path or name",
    "  --json    the raw report",
  ],
  init: [
    "usage: mandu init [--force]",
    "  write a commented ~/.mandu/config.toml with the defaults.",
    "  --force  overwrite an existing file",
  ],
  reap: [
    "usage: mandu reap [--dry-run] [--other-stacks]",
    "  clean up stale stacks, dashboards and scope dirs left by finished or killed launches.",
    "  Before a killed launch's scope dir goes, names each protected file whose placeholder",
    "  copy that session changed (the change was never applied to the real file).",
    "  --dry-run, -n    show what would be cleaned up, change nothing",
    "  --other-stacks   also stop the Mandu services of other runtime folders whose code",
    "                   folder was deleted and that nothing owns or uses (--dry-run lists them)",
  ],
  setup: [
    "usage: mandu setup [--print | --uninstall] [--yes]",
    "  the one optional privileged step: on Ubuntu 24.04, install the AppArmor grants that",
    "  let Mandu confine secrets without root. Asks before running sudo.",
    "  --print      show the commands and profiles instead of running them",
    "  --uninstall  remove the grants Mandu installed",
    "  --yes, -y    do not ask",
  ],
  mode: [
    "usage: mandu mode [secrets|off]",
    "  with no name: show the running and the saved protection mode.",
    "  with a name: save it as your default (applies to the next start of the service).",
    "  injection and full are frozen: they need MANDU_EXPERIMENTAL_INTEGRITY=1.",
  ],
  why: [
    "usage: mandu why <path|host|'$MDU:…'> [--to <host>] [--session <id>] [--json]",
    "  why a file or host is treated as it is, e.g.  mandu why ~/.pgpass",
    "  where a placeholder came from, e.g.  mandu why '$MDU:localmodel_prompt_filter[1a2b]' (quote it)",
    "  --to <host>     also: could this file's content be sent to <host>?",
    "  --session <id>  for a placeholder: search that session first (older sessions are not searched otherwise);",
    "                  for a file: judge it under the HOME that session was started with (else the newest running one's)",
    "  --json          the raw answer",
  ],
  revert: [
    "usage: mandu revert [--to <write number>] [--yes] [--json]",
    "  undo what the agent wrote in this folder: with no option, list its writes;",
    "  --to N returns the files to write N (shows the plan and asks first).",
    "  --yes   do not ask",
    "  --json  machine-readable output",
  ],
  demo: [
    "usage: mandu demo [--agent claude|codex] [--verbose] [--keep]",
    "  a short look at the default protection, offline, with Claude Code's and Codex's",
    "  requests: the agent reads a fake .env (the AI gets a placeholder, you see the key),",
    "  uses the key with curl at the host it may go to (the real value goes in on the way",
    "  out), and tries to send it elsewhere (stopped; Mandu asks you). Needs no API key or",
    "  login; runs in a throwaway folder; steps 2 and 3 need curl and openssl.",
    "  --agent   run one agent's steps (default: both)",
    "  --verbose also show what runs underneath: services, placeholders, requests",
    "  --keep    keep the throwaway folder afterwards (logs, every model request)",
  ],
  policy: [
    "usage: mandu policy suggest [--root <dir>]… [--home] [--dry-run | --json | --apply-all] [--no-color]",
    "                            [--model names|contents [--endpoint <name>] [--yes-send <digest>]]",
    "  scan this repository's git history and the files in this folder for keys your policy does not protect,",
    "  and review the rule that would hide each from the AI: [a]pply or [s]kip it, [p] shows the policy.yaml lines.",
    "  Nothing is applied unless you say so; every rule is a tightening you can undo in the dashboard, under Rule changes in Approvals.",
    "  Office documents with a sensitivity label you mapped (sensitivity_labels: in policy.yaml) are suggested too,",
    "  and the scan says how many carry a label you have not mapped yet.",
    "  --root <dir>  scan <dir> and the repository holding it instead of this one (repeatable)",
    "  --home        also scan your home folder's configuration files (names like *.toml, *.env, *token*)",
    "  --dry-run     show the review, apply nothing (also what happens with no terminal)",
    "  --json        the suggestions as JSON, no questions",
    "  --apply-all   apply every waiting suggestion after one typed confirmation (needs a terminal)",
    "  --model names  then ask a model to shape rules from the file NAMES only (never their contents):",
    "                you see every name first, [v]iew [y]es [N]o; not offered yet (MANDU_EXPERIMENTAL_POLICY_MODEL=1)",
    "  --model contents  then ask YOUR OWN model (declared local: true in policy.yaml) to read the first 16 KB of",
    "                the documents your policy calls public (.md .txt .csv …, the text of .docx .xlsx .pptx) and flag sensitive ones: you see every file",
    "                first, [v]iew [y]es [N]o; never a file that holds a key or a label; not offered yet (same flag)",
    "  --endpoint <name>  with --model: a model declared in policy.yaml (names: default the helper's model;",
    "                contents: default your only local model)",
    "  --yes-send <digest>  with --model, no terminal: send exactly what a --dry-run --json preview showed",
    "  --no-color    plain text",
    "  \"Not a secret\" is answered in the dashboard (Rules › Keys Mandu found): it withholds protection.",
    "",
    "usage: mandu policy classifier-pack [--id <id>] [--categories <a,b,…>] [--deadline-ms <n>] [--node <path>]",
    "  print the pack that installs Mandu's reference classifier (a model of your own checks each new prompt);",
    "  it pins node and the classifier by their SHA-256. Save it, then turn it on in policy.yaml with a local: true model:",
    "    mandu policy classifier-pack > ~/.mandu/prompt-filters/local-classifier.yaml",
    "  Run it again after upgrading node or Mandu: a pin that no longer matches blocks the prompt.",
  ],
  log: [
    "usage: mandu log [<session id>] [--path | --timings] | mandu log --list",
    "  what a launch said: every line the terminal did not show by default (each protection layer,",
    "  the notices, the warnings in full) and the messages of Mandu's helpers while the agent ran.",
    "  With no session id: the latest launch.",
    "  --list     the kept launches (the last 20), newest first",
    "  --path     print the log's path instead of its text (e.g. tail -f \"$(mandu log --path)\")",
    "  --timings  how long each step of the last 5 launches took, and their median (with a session id: that launch)",
  ],
  paths: [
    "usage: mandu paths [--json]",
    "  where Mandu keeps its files: each place, what it holds, whether it exists, and who can open it.",
    "  --json  the same report, machine-readable",
  ],
  version: [
    "usage: mandu version [--json]",
    "  which mandu this is: the file that ran and where it resolves, how it is installed (npm package",
    "  or source checkout), its release and its commits (the source and the public repository's);",
    "  every mandu on PATH; the running Mandu services and whether they are this release and build",
    "  (and the systemd service that keeps them alive, if one does); the environment variables that",
    "  change which code runs. Each problem comes with its fix. Starts and stops nothing.",
    "  --json  the same report, machine-readable (paste it into a bug report)",
    "  (`mandu --version` prints just `mandu <version>`.)",
  ],
};

/** True when the verb's own args ask for help (`--help` / `-h`), ignoring
 *  anything after a `--` separator (an argument, not an option). */
export function wantsHelp(rest: string[]): boolean {
  const end = rest.indexOf("--");
  const opts = end >= 0 ? rest.slice(0, end) : rest;
  return opts.includes("--help") || opts.includes("-h");
}

/** The usage text for `verb`, or null for a verb without an entry. */
export function subcommandUsage(verb: string): string | null {
  const lines = SUBCOMMAND_USAGE[verb];
  return lines ? lines.join("\n") + "\n" : null;
}
