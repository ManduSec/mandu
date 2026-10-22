/**
 * launch-console — the launch's console: where each line a launch says goes
 * (packaging.md §5 "Launch display policy", 2026-10-18).
 *
 * launch-banner.ts decides, per line, what the display does with it
 * (noteShow); this holds the state that decision needs over a launch:
 *   - every note, KEPT in order (the `launch_posture` event and
 *     `<scopeRunDir>/launch.log` read `notes`) and written to the launch's
 *     log as it is said (launch-log.ts);
 *   - the short lines (a posture line per warning, the must-hear notice)
 *     printed under the banner, and the count of notices the banner names;
 *   - console.error routed through the policy from the parse to the banner
 *     (`hook`), then only copied to the log (`tee`) for the rest of the
 *     launch, and put back however the launch ends (`end`);
 *   - the WARNING blocks about another launch beside this one, held until
 *     the banner is out (holdUntilBanner), folded to their posture line in
 *     the default display;
 *   - an aborted launch (`abort`): what it held is printed before its
 *     error, and the error goes to the log.
 * Prints go through `print` (console.error as it was before `hook`), so a
 * line printed here is never routed twice.
 *
 * Mandu-new (no reference origin).
 */
import {
  holdUntilBanner, isAttentionNote, noteShow, postureLine,
  type LastWords, type LaunchDisplayMode,
} from "./launch-banner.js";
import type { LaunchLog } from "./launch-log.js";

type Print = (...args: unknown[]) => void;

/** The text console.error would print for `args`. */
function text(args: unknown[]): string {
  return args.map((a) => (a instanceof Error ? a.message : String(a))).join(" ");
}

export class LaunchConsole {
  /** Every note of the launch, in order. */
  readonly notes: string[] = [];
  private readonly shorts: string[] = [];
  private readonly noticeTexts = new Set<string>();
  private readonly lastWords: LastWords;
  private hooked: "no" | "policy" | "tee" = "no";
  private ended = false;

  constructor(
    readonly display: LaunchDisplayMode,
    readonly log: LaunchLog | null,
    /** console.error as it was: every print of this console goes here. */
    readonly print: Print = console.error,
  ) {
    this.lastWords = holdUntilBanner((l) => this.print(l));
  }

  /** Where the full text is: the log verb, or `--verbose` without a log. */
  get hint(): string {
    return this.log !== null ? "`mandu log`" : "`--verbose`";
  }

  /** Keep a note (the notes, the log) without showing it. */
  keep(line: string): void {
    this.notes.push(line);
    this.log?.write(line);
  }

  /**
   * One note through the display policy (noteShow): kept, then printed now
   * (`printNow`, default: as it is), as a short line under the banner,
   * counted as a notice, or only kept. A short line or a notice two
   * producers say alike is shown or counted once.
   */
  show(line: string, printNow?: () => void, always: boolean | "wait" = false): void {
    this.keep(line);
    const how = noteShow(line, this.display, always, this.hint);
    if (how.kind === "short") { if (!this.shorts.includes(how.line)) this.shorts.push(how.line); }
    else if (how.kind === "notice") this.noticeTexts.add(line);
    else if (how.kind === "print") (printNow ?? (() => this.print(line)))();
  }

  /** How many notices the banner names. */
  get noticeCount(): number {
    return this.noticeTexts.size;
  }

  /** Route console.error through `show` (from the parse to the banner). */
  hook(): void {
    this.hooked = "policy";
    console.error = (...args: unknown[]): void => {
      if (this.hooked === "tee") { this.log?.write(text(args)); this.print(...args); return; }
      this.show(text(args), () => this.print(...args));
    };
  }

  /** From the banner on: console.error prints as it is and is copied to the log. */
  tee(): void {
    if (this.hooked === "no") this.hook();
    this.hooked = "tee";
  }

  /** Put console.error back. */
  unhook(): void {
    if (this.hooked === "no") return;
    this.hooked = "no";
    console.error = this.print;
  }

  /**
   * A line of a WARNING block about another launch beside this one (the
   * human-plane exposure block, the unconfined launch beside this one):
   * kept; held until the banner is out, then printed as it is said. The
   * default display shows the block's marked first line as its posture line
   * and keeps the rest for the log.
   */
  sayWhole(line: string): void {
    this.keep(line);
    if (this.display === "full") { this.lastWords.say(line); return; }
    if (isAttentionNote(line)) this.lastWords.say(postureLine(line, this.hint));
  }

  /**
   * A line of a WARNING block printed as it is said (the placeholder a git
   * commit recorded, placeholder-commits.ts): kept; printed whole under
   * `--verbose`, as the block's posture line by default (its marked first
   * line; the rest is in the log).
   */
  foldNow(line: string): void {
    this.keep(line);
    if (this.display === "full") this.print(line);
    else if (isAttentionNote(line)) this.print(postureLine(line, this.hint));
  }

  /**
   * Print the short lines held for under the banner. `countLine`: also a
   * line with the notice count (an aborted launch, which prints no banner).
   */
  flushShort(countLine = false): void {
    for (const l of this.shorts.splice(0)) this.print(l);
    if (countLine && this.display === "compact" && this.noticeTexts.size > 0) {
      const n = this.noticeTexts.size;
      this.print(`mandu: ${n} notice${n === 1 ? "" : "s"}: ${this.hint}`);
    }
    this.noticeTexts.clear();
  }

  /** The held WARNING blocks, now; from here a block line prints as it is said. */
  releaseLastWords(): void {
    this.lastWords.release();
  }

  /** The launch stopped with `e`: say what was held, keep the error. Once. */
  abort(e: unknown): void {
    if (this.ended) return;
    this.unhook();
    this.flushShort(true);
    this.releaseLastWords();
    this.log?.write(`mandu: the launch stopped: ${e instanceof Error ? e.message : String(e)}`);
  }

  /** The launch is over: anything still held said (a launch that returned
   *  before its banner), console.error back, the log closed. */
  end(): void {
    if (this.ended) return;
    this.ended = true;
    this.flushShort(true);
    this.releaseLastWords();
    this.unhook();
    this.log?.close();
  }
}

/** main()'s hold on the launch's console, so it is put back however the launch ends. */
export class LaunchConsoleSlot {
  private held: LaunchConsole | null = null;

  attach(c: LaunchConsole): LaunchConsole {
    this.held = c;
    return c;
  }

  /** The attached console (null before the parse, and for `--help` or a
   *  subcommand, which attach none). */
  get current(): LaunchConsole | null {
    return this.held;
  }

  abort(e: unknown): void {
    this.held?.abort(e);
  }

  end(): void {
    this.held?.end();
  }
}
