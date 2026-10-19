/**
 * event-dir — the dashboard's copy of the arbiter's default event-dir rule
 * (arbiter/events/event-store.ts getEventDir; runtime-instances.md §12).
 *
 * Mandu-new (NO reference origin). MIRRORED, not imported: the dashboard is
 * an arbiter CLIENT and does not import the arbiter package (arbiter-client
 * pattern, CONTRIBUTING.md). Both resolve the path table's `events` entry
 * (on-disk-layout.md §5), `${MANDU_HOME:-$HOME/.mandu}/events`, ON DISK in the
 * one Mandu home (§3). No variable moves it alone: an arbiter started with
 * `--event-dir` writes elsewhere, and only its `hello` says so.
 *
 * Before the one home (phase 3c) the default was
 * `${XDG_STATE_HOME:-~/.local/state}/mandu/events`; until 2026-09-05 it was
 * `${XDG_RUNTIME_DIR:-~/.mandu}/events` (a per-boot tmpfs: three host reboots
 * on 2026-09-04 wiped every session trace and the CI-run history). Nothing
 * reads those locations now (a clean start, on-disk-layout.md §6).
 */

import { homedir } from "node:os";
import { manduPath } from "./generated/mandu-paths.js";

/** The arbiter's default event dir for `env`: the path table's `events`.
 *  Same output as the arbiter's getEventDir for the same env. */
export function defaultEventDir(env: NodeJS.ProcessEnv = process.env): string {
  return manduPath("events", env, env.HOME || homedir());
}
