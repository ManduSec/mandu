#!/usr/bin/env bash
# lifeline.sh — suite-side lifeline for live tests that start Mandu daemons
# (docs/design/architecture/runtime-instances.md §8).
#
# The trap-EXIT cleanup the live suites already carry is the GRACEFUL teardown;
# it never runs when the suite is SIGKILLed or abandoned mid-hang — exactly how
# the 2026-07-14 orphans happened (arbiters from twins-live/box-smoke trees
# outliving their deleted /tmp workdirs by 16h). This helper adds the
# kernel-guaranteed backstop: daemons started with the lifeline exit on their
# own when the suite shell dies, however it dies.
#
# Usage:
#   source "$(dirname "${BASH_SOURCE[0]}")/lib/lifeline.sh"   # path as needed
#   mdu_lifeline_init "$WORK"        # once, after the work dir exists
#   # then start each daemon with BOTH the env and the redirects:
#   MANDU_LIFELINE=stdin daemon ... <"$MANDU_LIFELINE_FIFO" 9>&- &
#
# How it works: the suite shell holds the ONLY write end of the FIFO (fd 9,
# opened read-write so nothing ever blocks). Each daemon's stdin is a READ end
# (9>&- keeps the write end out of the daemon). Read ends see EOF when the last
# write end closes — which the kernel does when this shell dies. The daemons'
# server-mains arm the matching watcher via MANDU_LIFELINE=stdin
# (ipc/lifeline.ts and its per-package copies).
#
# Caveat (bash fd inheritance): FOREGROUND children of the suite also inherit
# fd 9, so a child that outlives a SIGKILLed suite delays the EOF until it too
# is gone. Fine for the backstop's purpose — such a child is itself an orphan,
# and the daemons follow the moment it dies (a strict improvement over the
# unreaped-forever status quo). Close it eagerly (9>&-) on long-running
# foreground commands if a suite wants the tighter guarantee.

MANDU_LIFELINE_FIFO=""

mdu_lifeline_init() {
  MANDU_LIFELINE_FIFO="$1/lifeline.fifo"
  mkfifo "$MANDU_LIFELINE_FIFO"
  exec 9<>"$MANDU_LIFELINE_FIFO"
}

# mdu_stop_group <pid>: stop a daemon started with setsid (its own process
# group, led by <pid>) and wait until the group is gone: SIGTERM to the group,
# up to 5 s for a graceful shutdown, then SIGKILL. A suite that only sends the
# SIGTERM and exits leaves the daemon shutting down past the suite, its work
# dir removed under it; the suite runner reports such a process as a stray
# (docs/design/testing/test-organization.md §8.5).
mdu_stop_group() {
  local pg="${1:-}" i
  [[ -n "$pg" ]] || return 0
  kill -TERM -- "-$pg" 2>/dev/null || kill -TERM "$pg" 2>/dev/null || return 0
  for ((i = 0; i < 50; i++)); do
    kill -0 -- "-$pg" 2>/dev/null || kill -0 "$pg" 2>/dev/null || return 0
    sleep 0.1
  done
  kill -KILL -- "-$pg" 2>/dev/null || kill -KILL "$pg" 2>/dev/null || true
  for ((i = 0; i < 20; i++)); do
    kill -0 -- "-$pg" 2>/dev/null || kill -0 "$pg" 2>/dev/null || return 0
    sleep 0.1
  done
  return 0
}

# mdu_without_lifeline CMD...: run CMD with fd 9 (the lifeline's write end)
# closed, for a command under test that must not hold it. The FIFO is one
# pipe every process of the suite holds, so under the net-guard a tainted
# process holding it makes the other holders readers of its pipe
# (confidentiality-plan-13-reader-set-labels.md §4.5.1, D2), and a guarded
# run that inherits fd 9 is refused for a taint it never touched
# (derived-label-live's curl, secret-readers-live's introspection checks,
# 2026-10-04). Usable wherever a command goes:
# `OUT="$(mdu_without_lifeline "$GUARD" … -- sh -c …)"`,
# `VAR=x mdu_without_lifeline …`, `mdu_without_lifeline … &`.
mdu_without_lifeline() {
  "$@" 9>&-
}
