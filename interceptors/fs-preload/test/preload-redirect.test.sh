#!/usr/bin/env bash
# preload-redirect.test.sh — LIVE end-to-end proof of the unprivileged LD_PRELOAD
# FS interposer on THIS host (kernel 5.4, where seccomp-unotify openat REDIRECT is
# unavailable; see docs/design/architecture/privilege-model.md §3.2).
#
# It demonstrates the Mandu filesystem two-views with ZERO privilege:
#   1. build the fs-preload cdylib,
#   2. create a HumanView file and a DIFFERENT AgentView file at the MAPPED path,
#   3. LD_PRELOAD the .so and `cat` the HumanView path → assert the bytes are the
#      AgentView content (the open was redirected to the AgentView worktree),
#   4. `cat` an UNTRACKED path under preload → assert it reads its REAL content
#      (no redirect outside tracked roots),
#   5. `cd` INTO the workspace and `cat` a tracked file by a RELATIVE path
#      (`notes.txt`, `./sub/secret.txt`) under preload → assert the AgentView bytes,
#      proving relative / AT_FDCWD-relative opens are now resolved + redirected.
#
# Prints PASS/FAIL and exits nonzero on any failure. Run standalone:
#   bash interceptors/fs-preload/test/preload-redirect.test.sh
#
# Reuse note: the AgentView worktree path is computed by fs-supervisor's
# ViewLayout (<state>/workspaces/<basename>-<sha256(root)[:12]>/agentview/
# <suffix>, mirroring fs-sync's workspaceIdFor). We reproduce that mapping here
# with `basename` + `sha256sum` — the temp workspace basename is plain ASCII in
# [A-Za-z0-9._-], so the TS sanitization step is a no-op for it. The interposer
# itself uses the real layout code.

set -u

# --- locate repo paths (this script lives in interceptors/fs-preload/test/) ------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
INTERCEPTORS_DIR="$(cd "$CRATE_DIR/.." && pwd)"
SO="$INTERCEPTORS_DIR/target/debug/libfs_preload.so"

fail() { echo "FAIL: $*" >&2; exit 1; }

# --- 1. build the cdylib ---------------------------------------------------------
echo "[1/6] building fs-preload cdylib ..."
( cd "$INTERCEPTORS_DIR" && cargo build -p fs-preload ) >/dev/null 2>&1 \
  || fail "cargo build -p fs-preload failed"
[ -f "$SO" ] || fail "expected cdylib not found at $SO"
echo "      built: $SO"

# --- 2. lay out HumanView + AgentView under a temp dir ---------------------------
WORK="$(mktemp -d /tmp/fs-preload-e2e.XXXXXX)" || fail "mktemp failed"
trap 'rm -rf "$WORK"' EXIT

# Tracked workspace root (HumanView) and the view state base.
WS_ROOT="$WORK/workspace"          # only non-unreserved char in the path is '/'
STATE="$WORK/state"
mkdir -p "$WS_ROOT"

# The AgentView worktree path = <state>/workspaces/<basename>-<sha256[:12]>/agentview
# (fs-sync workspaceIdFor: hash over the FULL canonical root, basename prefix).
WS_ID="$(basename "$WS_ROOT")-$(printf '%s' "$WS_ROOT" | sha256sum | cut -c1-12)"
AV_DIR="$STATE/workspaces/$WS_ID/agentview"
mkdir -p "$AV_DIR/sub"

# A tracked file: HumanView vs AgentView content DIFFER, so a successful redirect
# is observable purely from the bytes returned.
HUMAN_FILE="$WS_ROOT/sub/secret.txt"
AGENT_FILE="$AV_DIR/sub/secret.txt"
mkdir -p "$(dirname "$HUMAN_FILE")"
HUMAN_CONTENT="HUMANVIEW-ORIGINAL-do-not-show-the-agent"
AGENT_CONTENT="AGENTVIEW-SYMBOLIZED-\$MDU:Read[ab12].v"
printf '%s\n' "$HUMAN_CONTENT" > "$HUMAN_FILE"
printf '%s\n' "$AGENT_CONTENT" > "$AGENT_FILE"

# A second tracked file AT THE WORKSPACE ROOT, used to prove RELATIVE-path opens
# (e.g. `cat notes.txt` after `cd`-ing into the workspace) are now redirected too.
HUMAN_NOTES="$WS_ROOT/notes.txt"
AGENT_NOTES="$AV_DIR/notes.txt"
HUMAN_NOTES_CONTENT="HUMANVIEW-NOTES-raw-do-not-show"
AGENT_NOTES_CONTENT="AGENTVIEW-NOTES-\$MDU:Read[cd34].v"
printf '%s\n' "$HUMAN_NOTES_CONTENT" > "$HUMAN_NOTES"
printf '%s\n' "$AGENT_NOTES_CONTENT" > "$AGENT_NOTES"

# An UNTRACKED file outside every tracked root — must read its REAL content.
UNTRACKED_FILE="$WORK/outside.txt"
UNTRACKED_CONTENT="UNTRACKED-real-bytes-not-redirected"
printf '%s\n' "$UNTRACKED_CONTENT" > "$UNTRACKED_FILE"

export MANDU_PRELOAD_WORKSPACE="$WS_ROOT"
export MANDU_PRELOAD_AGENTVIEW="$STATE"

echo "[2/6] layout:"
echo "      tracked root : $WS_ROOT"
echo "      state base   : $STATE"
echo "      agentview    : $AV_DIR"

# --- 3. tracked path under preload must return AGENTVIEW bytes --------------------
echo "[3/6] reading tracked HumanView path under LD_PRELOAD ..."
GOT_TRACKED="$(LD_PRELOAD="$SO" cat "$HUMAN_FILE")" \
  || fail "cat of tracked path errored under preload"
if [ "$GOT_TRACKED" = "$AGENT_CONTENT" ]; then
  echo "      OK   redirected: cat $HUMAN_FILE -> AgentView content"
  echo "           returned: $GOT_TRACKED"
elif [ "$GOT_TRACKED" = "$HUMAN_CONTENT" ]; then
  fail "NOT redirected: tracked read returned raw HumanView content (got: $GOT_TRACKED)"
else
  fail "unexpected content for tracked read: $GOT_TRACKED"
fi

# Sanity: WITHOUT preload the same path reads HumanView content (proves the
# redirect is the preload's doing, not a layout accident).
GOT_BASELINE="$(cat "$HUMAN_FILE")"
[ "$GOT_BASELINE" = "$HUMAN_CONTENT" ] \
  || fail "baseline (no preload) should read HumanView content, got: $GOT_BASELINE"
echo "      OK   baseline (no preload): cat $HUMAN_FILE -> HumanView content"

# --- 4. untracked path under preload must return its REAL bytes -------------------
echo "[4/6] reading UNTRACKED path under LD_PRELOAD ..."
GOT_UNTRACKED="$(LD_PRELOAD="$SO" cat "$UNTRACKED_FILE")" \
  || fail "cat of untracked path errored under preload"
[ "$GOT_UNTRACKED" = "$UNTRACKED_CONTENT" ] \
  || fail "untracked path was redirected/altered (got: $GOT_UNTRACKED)"
echo "      OK   not redirected: cat $UNTRACKED_FILE -> real content"

# --- 5. RELATIVE-path opens (cd into the workspace) must redirect too -------------
# This is the gap this change closes: a tracked file opened by a RELATIVE path
# (resolved against the CWD via getcwd / AT_FDCWD) must land on AgentView, not the
# raw HumanView bytes. We `cd` INTO the tracked workspace and `cat` by relative path.
echo "[5/6] reading tracked files by RELATIVE path (cd into workspace) under LD_PRELOAD ..."

# 5a. `cat notes.txt` from the workspace ROOT — relative to CWD == WS_ROOT.
GOT_REL_NOTES="$(cd "$WS_ROOT" && LD_PRELOAD="$SO" cat notes.txt)" \
  || fail "relative cat of notes.txt errored under preload"
if [ "$GOT_REL_NOTES" = "$AGENT_NOTES_CONTENT" ]; then
  echo "      OK   redirected: (cd \$WS_ROOT) cat notes.txt -> AgentView content"
  echo "           returned: $GOT_REL_NOTES"
elif [ "$GOT_REL_NOTES" = "$HUMAN_NOTES_CONTENT" ]; then
  fail "RELATIVE read NOT redirected: cat notes.txt returned raw HumanView content (got: $GOT_REL_NOTES)"
else
  fail "unexpected content for relative read: $GOT_REL_NOTES"
fi

# 5b. `cat ./sub/secret.txt` — a dotted relative path with a subdir component.
GOT_REL_SUB="$(cd "$WS_ROOT" && LD_PRELOAD="$SO" cat ./sub/secret.txt)" \
  || fail "relative cat of ./sub/secret.txt errored under preload"
[ "$GOT_REL_SUB" = "$AGENT_CONTENT" ] \
  || fail "RELATIVE ./sub/secret.txt NOT redirected (got: $GOT_REL_SUB)"
echo "      OK   redirected: (cd \$WS_ROOT) cat ./sub/secret.txt -> AgentView content"

# 5c. Sanity: WITHOUT preload, the same relative read returns HumanView bytes —
# proving the relative redirect is the preload's doing, not a CWD/layout accident.
GOT_REL_BASELINE="$(cd "$WS_ROOT" && cat notes.txt)"
[ "$GOT_REL_BASELINE" = "$HUMAN_NOTES_CONTENT" ] \
  || fail "relative baseline (no preload) should read HumanView content, got: $GOT_REL_BASELINE"
echo "      OK   relative baseline (no preload): cat notes.txt -> HumanView content"

# --- 6. (optional) exercise the DIRECT openat() symbol too -----------------------
# `cat` reaches us via the `open` symbol; many programs (shells, editors, Node)
# call `openat(AT_FDCWD, ...)` directly. If a C compiler is present, build a tiny
# probe that calls openat() and confirm THAT symbol is interposed as well — both
# with AT_FDCWD and with a REAL dirfd (the readlink(/proc/self/fd/N) resolution).
# Usage: probe <mode> <arg...>:
#   probe atfdcwd <path>           openat(AT_FDCWD, path)
#   probe dirfd   <dir> <relfile>  open(dir,O_DIRECTORY); openat(thatfd, relfile)
CC="${CC:-cc}"
if command -v "$CC" >/dev/null 2>&1; then
  echo "[6/6] exercising the direct openat() symbol via a C probe (AT_FDCWD + dirfd) ..."
  PROBE_SRC="$WORK/openat_probe.c"
  PROBE_BIN="$WORK/openat_probe"
  cat > "$PROBE_SRC" <<'EOF'
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
static int dump(int fd) {
    if (fd < 0) { perror("open"); return 2; }
    char buf[256]; ssize_t n = read(fd, buf, sizeof buf - 1);
    if (n < 0) { perror("read"); return 3; }
    buf[n] = 0; fputs(buf, stdout); close(fd); return 0;
}
int main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "atfdcwd") == 0) {
        return dump(openat(AT_FDCWD, argv[2], O_RDONLY));
    }
    if (argc >= 4 && strcmp(argv[1], "dirfd") == 0) {
        int dirfd = open(argv[2], O_RDONLY | O_DIRECTORY);
        if (dirfd < 0) { perror("opendir"); return 4; }
        return dump(openat(dirfd, argv[3], O_RDONLY));
    }
    fprintf(stderr, "bad probe usage\n"); return 9;
}
EOF
  if "$CC" -O0 -o "$PROBE_BIN" "$PROBE_SRC" 2>/dev/null; then
    GOT_OPENAT="$(LD_PRELOAD="$SO" "$PROBE_BIN" atfdcwd "$HUMAN_FILE")" \
      || fail "openat(AT_FDCWD) probe errored under preload"
    [ "$GOT_OPENAT" = "$AGENT_CONTENT" ] \
      || fail "direct openat(AT_FDCWD) NOT redirected (got: $GOT_OPENAT)"
    echo "      OK   direct openat(AT_FDCWD, tracked) -> AgentView content"

    # The genuine dirfd-relative case: open the workspace dir, then openat(dirfd,
    # "notes.txt"). This exercises readlink(/proc/self/fd/N) resolution. NOTE: the
    # dir is opened by the SAME workspace path, which itself redirects to the
    # AgentView worktree dir — so the fd points at the AgentView dir, and the
    # relative openat lands on the AgentView file directly. Either way the bytes
    # returned must be the AgentView content (never raw HumanView).
    GOT_DIRFD="$(LD_PRELOAD="$SO" "$PROBE_BIN" dirfd "$WS_ROOT" notes.txt)" \
      || fail "openat(dirfd) probe errored under preload"
    [ "$GOT_DIRFD" = "$AGENT_NOTES_CONTENT" ] \
      || fail "dirfd-relative openat NOT redirected to AgentView (got: $GOT_DIRFD)"
    echo "      OK   dirfd-relative openat(dirfd, notes.txt) -> AgentView content"
  else
    echo "      SKIP (compiler present but probe build failed)"
  fi
else
  echo "[6/6] SKIP direct-openat probe (no C compiler) — 'open' path already proven"
fi

echo
echo "PASS: LD_PRELOAD FS interposer redirects tracked opens to AgentView,"
echo "      leaves untracked opens untouched (unprivileged, kernel $(uname -r))."
echo "preload-redirect.test.sh: 1 passed, 0 failed"
exit 0
