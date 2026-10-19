/**
 * launch-banner — what a launch DISPLAYS of its lines (packaging.md §5
 * "launch display policy").
 *
 * Every rung prints a truth-in-labeling line (fs-sync.md §1 P5) as it
 * comes up. All of them are still PRODUCED: they land in the session's
 * `launch_posture` event (services/observe.ts), in `<scopeRunDir>/launch.log`,
 * in the launch's own log (`mandu log`, launch-log.ts), and on stderr under
 * `--verbose` / `MANDU_VERBOSE=1`. This module only decides what the user
 * sees by default (2026-10-18, "quiet launch"):
 *   - ONE banner line (bannerLine): the mode and what it masks, the
 *     dashboard, and how many notices the log holds;
 *   - one short `mandu: WARNING: …` line per note that says a layer is NOT
 *     in its designed posture (postureLine, the ATTENTION markers), each
 *     pointing at `mandu log` for the full text;
 *   - a wait about to start, as it is said (noteShow `print`);
 *   - a refusal or an error that stops the launch, in full (it is thrown,
 *     not a note).
 * An advisory notice (the agent's version, what the secret walk skipped,
 * keys a policy does not cover, an update) is only COUNTED on the banner.
 * Quiet on success, one line per degradation.
 *
 * History: 2026-09-17 folded the healthy rungs into a two-line summary at a
 * TTY but kept the full banner on any non-TTY stderr; the 2026-09-26
 * fresh-user run of the release review still met fifteen lines of internal
 * terms (rung, U-LLM, CLEAN BOX, exit 77, port lists), so the default became
 * the mode line, the dashboard line and one `mandu: ! …` line per notice, TTY
 * or not. 2026-10-18: that was still four to six lines, every warning in
 * full, and a helper writing over the agent's screen; now one line, and the
 * rest in the launch's log. The harnesses that read the phrases off stderr
 * ask for them with MANDU_VERBOSE=1.
 *
 * Pure: no I/O, no process state. Mandu-new (no reference origin).
 */
import { isUpdateNotice } from "./update-check.js";
import { isPreviewNotice } from "./agent-versions.js";
import { isNodeEnvProxyNotice } from "./node-floor.js";
import { isHistoryRecheckNotice } from "./cache-seals.js";

export type LaunchDisplayMode = "full" | "compact";

/** Truthy env switch, matching parse.ts's convention. */
function truthy(v: string | undefined): boolean {
  return v !== undefined && v !== "" && v !== "0" && v.toLowerCase() !== "false";
}

/**
 * `full` only when the user asked (--verbose / MANDU_VERBOSE=1); `compact`
 * otherwise, whether or not stderr is a terminal (a script's log gets the
 * same one line a human does).
 */
export function launchDisplayMode(opts: {
  verbose?: boolean;
  env: Record<string, string | undefined>;
}): LaunchDisplayMode {
  if (opts.verbose) return "full";
  return truthy(opts.env["MANDU_VERBOSE"]) ? "full" : "compact";
}

/**
 * A note the user must see even in compact mode: anything that says a rung
 * is NOT in its designed posture. The patterns are the exact markers the
 * launcher's degrade / refuse paths emit (exec-box-setup, secret-setup,
 * landlock-net-setup, net-guard-setup, services/manager, services/fs-view).
 */
const ATTENTION = [
  /\bWARNING\b/,
  /\bGATED\b/, // the secret posture notice (confinement-posture.ts gatedNotice): shown on EVERY launch
  /\bDEGRADED\b/,
  /proceeding WITHOUT/,
  /TUI PINNED to the inline renderer/,
  /own sandbox is OFF for this session/, // macOS: Mandu turned the agent's own sandbox off (codex-/claude-sandbox.ts)
  /could not\b/,
  /is not installed/,
  /not built/,
  /failed/i,
  /Fix it,/,
  /is absent/,
  /aborted|abort:/i,
];

export function isAttentionNote(note: string): boolean {
  return ATTENTION.some((re) => re.test(note));
}

/**
 * The compact display's prefix for a notice line: `mandu: ! …`. A notice is
 * advice that needs no action to run safely (the agent's version, what the
 * secret walk skipped, keys a policy does not cover yet); a degrade or a
 * refusal is not a notice and still prints in full as it happens.
 */
export const NOTICE_PREFIX = "mandu: ! ";

const count = (re: RegExp, s: string): number => Number(re.exec(s)?.[1] ?? 0);

/**
 * The one short line the compact display shows for a long launch notice,
 * or null when `note` is not one of them (then isAttentionNote decides, as
 * before). The full text is still kept (launch.log, the posture event) and
 * printed under --verbose. The patterns are the exact text of the producers
 * (agent-versions.ts versionWarning, secret-setup.ts notCoveredNotice,
 * policy-suggest.ts launchSuggestionNotice, cache-seals.ts voidedCachesLine,
 * codex-shell-network.ts OPEN_NOTE, env-compose.ts codexUploadsNote,
 * update-check.ts updateNotice, agent-versions.ts previewNotice and
 * node-floor.ts nodeEnvProxyNotice, already short; the OpenCode left-out
 * notices of opencode-project-code.ts and opencode-global-code.ts); launch-banner.test.ts
 * feeds each
 * producer's real output through here, so a reworded producer fails a test
 * instead of printing in full again. Pure.
 */
export function compactNotice(note: string): string | null {
  // codex-shell-network.ts OPEN_NOTE: Mandu turned Codex's own sandbox
  // network on, which the user must hear about on every launch.
  if (note.startsWith("mandu: Codex's command sandbox network is ON for this launch")) {
    return `${NOTICE_PREFIX}Codex's commands may use the network (Mandu decides where they connect); --no-codex-shell-network keeps Codex's default`;
  }
  // env-compose.ts codexUploadsNote: a ChatGPT-signed-in Codex finds its
  // apps missing; say why once.
  if (note.startsWith("mandu: ChatGPT apps and connectors are off in Codex under Mandu")) {
    return `${NOTICE_PREFIX}ChatGPT apps and connectors are off in Codex (they upload local files around Mandu)`;
  }
  // update-check.ts updateNotice: already one short line.
  if (isUpdateNotice(note)) return note;
  // agent-versions.ts previewNotice: already one short line.
  if (isPreviewNotice(note)) return note;
  // node-floor.ts nodeEnvProxyNotice: already one short line.
  if (isNodeEnvProxyNotice(note)) return note;
  // agent-versions.ts versionWarning
  let m = /^mandu: WARNING — (.+?) (\S+) is (newer|older) than tested \(Mandu was tested with .+? (\S+)(?: to (\S+))?\)/.exec(note);
  if (m) {
    const [, name, version, dir, lo, hi] = m;
    const bound = dir === "newer" ? `up to ${hi ?? lo}` : `from ${lo}`;
    return `${NOTICE_PREFIX}${name} ${version} is ${dir} than Mandu has tested (${bound}); see \`mandu doctor\``;
  }
  m = /^mandu: WARNING — could not read the (.+?) version \(/.exec(note);
  if (m) return `${NOTICE_PREFIX}could not read the ${m[1]} version to check it; see \`mandu doctor\``;
  // secret-setup.ts notCoveredNotice (one multi-line note)
  if (note.startsWith("WARNING: mandu: secrets NOT covered by the walk")) {
    const skipped = count(/(\d+) director(?:y|ies) below depth/, note) +
      count(/(\d+) credential files? beyond the/, note) +
      count(/(\d+) unreadable candidates?/, note);
    // The too-deep folders by folder, when the arbiter grouped them
    // (secret-discovery.md §1.9 H): "447 places" alone named nothing.
    const deep = /(\d+) director(?:y|ies) below depth (\d+) not searched, in (.+)$/m.exec(note);
    const where = !deep ? "" : (() => {
      const [, n, levels, areas] = deep;
      const folders = `${Number(n) === 1 ? "a folder" : "folders"} more than ${levels} levels deep, in ${areas}`;
      return Number(n) === skipped ? `: ${folders}` : `, ${n} of them ${folders}`;
    })();
    const what = /the walk stopped at the/.test(note)
      ? "the search for secrets stopped early"
      : `${skipped} place${skipped === 1 ? " was" : "s were"} not searched for secrets${where}`;
    return `${NOTICE_PREFIX}${what}; see \`mandu doctor --secrets\``;
  }
  // OpenCode code a launch left out (opencode-project-code.ts
  // opencodeProjectCodeNotice, opencode-global-code.ts
  // opencodeV1ProjectPluginsNotice and opencodeGlobalCodeNotice): the
  // launch names what did not run and the switch that runs it, as
  // first-session.md promises, without the long why.
  m = /^mandu: OpenCode — (this project's plugins(?: and custom tools)?|your own OpenCode plugins and custom tools) are left out(?: of this session)? \([^)]*\): (.+)\. (MANDU_OPENCODE_[A-Z_]+=1) runs them unchecked\.$/s.exec(note);
  if (m) {
    const [, who, list, optIn] = m;
    const whose = who!.startsWith("this project's") ? who!.replace("this project's ", "this project's OpenCode ") : who!;
    return `${NOTICE_PREFIX}${whose} do not run under Mandu: ${list}; ${optIn} runs them unchecked`;
  }
  // policy-suggest.ts launchSuggestionNotice
  m = /^mandu: (.+ in this project (?:is|are) not protected): /.exec(note);
  if (m) return `${NOTICE_PREFIX}${m[1]}; see \`mandu policy suggest\``;
  // cache-seals.ts voidedCachesLine (plan 14 §11.2.1): the launch that costs
  // this one its git-history cache, by pid, workspace and why, and its end.
  m = /^mandu: the git-history caches are not trusted this launch: (a Mandu launch runs|\d+ Mandu launches run) without protection \((.*)\), and while one does nothing it could have written is trusted; .* quit (its agent|their agents), or `kill (\d+)`\.$/s.exec(note);
  if (m) {
    const [, who, named, agents, pid] = m;
    return `${NOTICE_PREFIX}git history rebuilt (slower) while ${who} without protection ` +
      `(${named}); to end ${agents === "its agent" ? "it" : "them"}: quit ${agents}, or \`kill ${pid}\``;
  }
  return null;
}

/** What the display does with one note (noteShow). */
export type NoteShow =
  | { kind: "print" }
  | { kind: "short"; line: string }
  | { kind: "notice" }
  | { kind: "keep" };

/**
 * The notices the default display still prints, each as its short line:
 * the ones that say Mandu changed what the agent itself does this launch,
 * which the user would otherwise meet as a mystery, and a security update.
 *   - Mandu turned Codex's own sandbox network ON (codex-shell-network.ts
 *     OPEN_NOTE), which the user must hear about on every launch;
 *   - OpenCode plugins and custom tools this launch left out, by file, with
 *     the switch that runs them (opencode-project-code.ts,
 *     opencode-global-code.ts; first-session.md promises the launch names
 *     them);
 *   - a newer Mandu release with SECURITY fixes (update-check.ts
 *     updateNotice; a plain update is only counted).
 * null for every other note. Pure.
 */
export function mustHearNotice(note: string): string | null {
  if (note.startsWith("mandu: Codex's command sandbox network is ON for this launch")) return compactNotice(note);
  if (note.startsWith("mandu: OpenCode — ")) {
    const short = compactNotice(note);
    if (short !== null && / do not run under Mandu: /.test(short)) return short;
  }
  if (isUpdateNotice(note) && note.includes(" is out with SECURITY fixes ")) return note;
  return null;
}

/**
 * What the display does with one note (run.ts showNote; every note is kept
 * either way, in the launch's log, launch.log and the posture event):
 *   - `print`: printed now, as it is: every note under `--verbose`, and a
 *     wait about to start in every display mode;
 *   - `short`: a short line printed under the banner: a posture note's
 *     postureLine, or the must-hear notice (mustHearNotice);
 *   - `notice`: counted on the banner, its text in the log only;
 *   - `keep`: in the log only (an all-is-well line).
 * A note announcing a wait that is about to start prints AT ONCE in every
 * display mode: collected under the banner it would appear after the wait
 * it explains. The history re-check (cache-seals.ts historyRecheckNotice,
 * plan 14 §11.2.1 "The rebuild notice") is recognised by its text; a
 * caller passes `always === "wait"` for its own (the release check's
 * restart of an older stack). `always === true`: the caller's own notice,
 * counted even when compactNotice does not know its text. `hint`: postureLine's. Pure.
 */
export function noteShow(note: string, display: LaunchDisplayMode, always: boolean | "wait" = false, hint?: string): NoteShow {
  if (display === "full" || always === "wait" || isHistoryRecheckNotice(note)) return { kind: "print" };
  const must = mustHearNotice(note);
  if (must !== null) return { kind: "short", line: must };
  // A known notice first: the version notice carries `WARNING` but is advice.
  if (compactNotice(note) !== null) return { kind: "notice" };
  if (isAttentionNote(note)) return { kind: "short", line: postureLine(note, hint) };
  return always ? { kind: "notice" } : { kind: "keep" };
}

/** The default display's prefix for a posture line. */
export const POSTURE_PREFIX = "mandu: WARNING: ";
/** How long a posture line's gist may be before it is cut at a word. */
const GIST_MAX = 160;

/** One leading `WARNING:` / `WARNING —` / `mandu:` / `mandu-<helper>:` prefix. */
const LEAD_PREFIX = /^(?:WARNING(?::|\s+—|\s+-)?\s+|WARNING:|mandu(?:-[a-z-]+)?(?:\[[a-z]+\])?:\s*)/;

/**
 * The one short line the default display prints for a posture note (a layer
 * NOT in its designed posture: isAttentionNote): `mandu: WARNING: <gist>
 * (more: <hint>)`. The gist is the note's first line without its leading
 * `WARNING:` / `mandu:` / helper prefixes, starting after a `WARNING` that
 * comes later in the line (a truth-in-labeling line whose warning is its
 * second sentence, env-compose.ts shellTargetNote), cut at a word near
 * GIST_MAX characters. The prefix keeps the `WARNING` marker, so a posture
 * line is itself an attention note. `hint` says where the full text is
 * (`mandu log`, or `--verbose` when the launch has no log). Pure.
 */
export function postureLine(note: string, hint = "`mandu log`"): string {
  let gist = (note.split("\n")[0] ?? "").trim();
  for (let next = gist.replace(LEAD_PREFIX, ""); next !== gist; next = gist.replace(LEAD_PREFIX, "")) gist = next;
  const mid = /[.;:)]\s+WARNING(?::|\s+—|\s+-)\s*/.exec(gist);
  if (mid !== null) gist = gist.slice(mid.index + mid[0].length);
  // A long absolute path says little in one line: its last name stands for it.
  gist = gist.replace(/(?<![\w~.])(?:\/[^\s/:;,()'"`]+){3,}/g, (p) => `…/${p.slice(p.lastIndexOf("/") + 1)}`);
  if (gist.length > GIST_MAX) {
    const cut = gist.lastIndexOf(" ", GIST_MAX);
    gist = gist.slice(0, cut > GIST_MAX / 2 ? cut : GIST_MAX).replace(/[\s,;:—-]+$/, "") + "…";
  }
  return `${POSTURE_PREFIX}${gist} (more: ${hint})`;
}

/** A WARNING held for the end of the banner (holdUntilBanner). */
export interface LastWords {
  /** Print `line` (one line of a block) now, or hold it until `release`. */
  say(line: string): void;
  /** Print what is held, in order, once; from then on `say` prints at once. */
  release(): void;
}

/**
 * The WARNINGs a launch must not let its user miss about ANOTHER launch
 * beside it (the human-plane exposure block, human-plane-watch.ts, and the
 * unconfined launch beside a confined one, cache-epoch.ts
 * concurrentLaunchNotice): said before the agent starts, they are HELD until
 * the banner (the mode line, the dashboard line, the short notices) is out,
 * then printed whole, so they are the last thing on screen when the agent
 * takes the terminal. Printed above the banner, a full-screen agent's first
 * frame met the banner and the WARNING scrolled off, or sat above lines the
 * eye stops at (packaging.md §5 "Last before the agent"). After `release`
 * (the agent is about to start, or the launch aborts) a line prints as it is
 * said: the watch's live lines while the agent runs. A print that throws is
 * dropped (display only). Pure but for `print`.
 */
export function holdUntilBanner(print: (line: string) => void): LastWords {
  let held: string[] | null = [];
  const out = (l: string): void => { try { print(l); } catch { /* display only */ } };
  return {
    say(line) {
      if (held !== null) held.push(line);
      else out(line);
    },
    release() {
      if (held === null) return;
      const lines = held;
      held = null;
      for (const l of lines) out(l);
    },
  };
}

/**
 * The dashboard line every launch prints after the mode line (release
 * checklist d4): approvals happen there, so a user must know where it is.
 * `url` is the newest live dashboard of this user (subcommands.ts
 * liveDashboards), null when none runs.
 */
export function dashboardLine(url: string | null): string {
  return url === null
    ? "mandu: no dashboard is running; start one with `mandu dashboard` to answer approval requests"
    : `mandu: dashboard ${url} (approve requests, see what was protected)`;
}

/**
 * The ONE line every launch prints, in every display mode
 * (protection-modes.md §3.2): the mode the session actually runs under (the
 * EFFECTIVE pair, run.ts) and the fact a user of that mode cares about most.
 *   mandu: mode secrets (14 credential files masked, 3 env vars masked, 2 readers pinned)
 * (plan 10 §12.5: the env-var and pinned-reader counts appear only when non-zero).
 * On macOS (posture `read-blocked`, confidentiality.md §7.3) a credential
 * file is not masked but made unreadable, and there are no readers:
 *   mandu: mode secrets (14 credential files unreadable (read-blocked), 3 env vars masked)
 */
export function modeLine(mode: LaunchMode, secrets: SecretFacts | undefined): string {
  return `mandu: mode ${mode} (${modeFacts(mode, secrets, false).join(", ")})`;
}

export type LaunchMode = "secrets" | "injection" | "full" | "off";
export interface SecretFacts { confined: number; posture: string; structured?: number; envMasked?: number; readersPinned?: number }

const plural = (n: number, one: string): string => `${n} ${one}${n === 1 ? "" : "s"}`;

/**
 * The facts of a mode, for the mode line (`short` false) or the banner
 * (`short` true: the masked counts in one fact, no pinned readers, no
 * `(read-blocked)` tag). A GATED posture reads the same in both: it is the
 * one fact that says protection is not what the mode promises. Pure.
 */
export function modeFacts(mode: LaunchMode, secrets: SecretFacts | undefined, short: boolean): string[] {
  const facts: string[] = [];
  if (mode === "secrets" || mode === "full") {
    const env = secrets !== undefined && (secrets.envMasked ?? 0) > 0 ? plural(secrets.envMasked!, "env var") : null;
    if (secrets === undefined) facts.push("credential files not checked");
    // Bind-only (no file guard): placeholders are up, the posture is gated.
    else if (secrets.posture === "gated" && secrets.confined > 0) facts.push(`credential files GATED (${secrets.confined} behind a placeholder, no file guard)`);
    else if (secrets.posture === "gated") facts.push("credential files GATED, not masked");
    else if (secrets.posture === "read-blocked") facts.push(`${plural(secrets.confined, "credential file")} unreadable${short ? "" : " (read-blocked)"}`);
    else facts.push(`${plural(secrets.confined, "credential file")}${short && env !== null ? `, ${env}` : ""} masked`);
    const envSaid = short && secrets !== undefined && secrets.posture !== "gated" && secrets.posture !== "read-blocked";
    if (env !== null && !envSaid) facts.push(`${env} masked`);
    // No reader is ever handed a real file under read-blocked (macOS).
    if (!short && secrets !== undefined && secrets.posture !== "read-blocked" && (secrets.readersPinned ?? 0) > 0) {
      facts.push(`${plural(secrets.readersPinned!, "reader")} pinned`);
    }
  }
  if (mode === "injection" || mode === "full") facts.push("untrusted text masked");
  if (mode === "off") facts.push("observing only, nothing is enforced");
  return facts;
}

/**
 * The ONE line a launch prints by default (packaging.md §5, 2026-10-18):
 *   mandu: secrets mode · 33 credential files, 1 env var masked · dashboard http://127.0.0.1:4500/ · 2 notices: `mandu log`
 * The mode the session really runs under and what it masks (modeFacts,
 * short), where approvals happen (`dashboard`: dashboard-sign-in.ts
 * bannerDashboard), and how many notices this launch kept for the log
 * (none: no count). `hint` says where they are (`mandu log`, or
 * `--verbose` when the launch has no log). Under `--verbose` the mode line
 * and the dashboard line print instead, as before. Pure.
 */
export function bannerLine(b: {
  mode: LaunchMode;
  secrets: SecretFacts | undefined;
  dashboard: string;
  notices: number;
  hint?: string;
}): string {
  const parts = [`mandu: ${b.mode} mode`, ...modeFacts(b.mode, b.secrets, true), b.dashboard];
  if (b.notices > 0) parts.push(`${plural(b.notices, "notice")}: ${b.hint ?? "`mandu log`"}`);
  return parts.join(" · ");
}
