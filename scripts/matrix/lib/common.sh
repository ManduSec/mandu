#!/usr/bin/env bash
# common.sh — shared helpers for the OS test matrix (docs/design/testing/os-test-matrix.md).
# Provenance: color/report idiom adapted from scripts/kernel-vm.sh + scripts/test-all.sh;
# purpose: one shared copy for the matrix driver, executors, and run-matrix summary.
#
# Sourced (not executed). Defines: say/info/ok/warn/err, have, parse_deps, parse_header.

if [[ -t 1 ]]; then
  C_GRN=$'\033[32m'; C_RED=$'\033[31m'; C_YLW=$'\033[33m'; C_DIM=$'\033[2m'; C_BLD=$'\033[1m'; C_RST=$'\033[0m'
else
  C_GRN=""; C_RED=""; C_YLW=""; C_DIM=""; C_BLD=""; C_RST=""
fi
say()  { printf "%s%s%s\n" "$C_BLD" "$*" "$C_RST"; }
info() { printf "  %s%s%s\n" "$C_DIM" "$*" "$C_RST"; }
ok()   { printf "  %s✓%s %s\n" "$C_GRN" "$C_RST" "$*"; }
warn() { printf "  %s⚠%s %s\n" "$C_YLW" "$C_RST" "$*"; }
err()  { printf "  %s✗%s %s\n" "$C_RED" "$C_RST" "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

# parse_deps <suite.sh> — print the suite's declared toolchain deps (may be empty).
# A suite declares them as a comment line:  # deps: cargo node
parse_deps() { sed -n 's/^# deps:[[:space:]]*//p' "$1" | head -1; }

# parse_header <suite.sh> <key> — a suite's other one-line declarations, the
# same way:  # boots: 4   (the qemu executor boots the guest up to 4 times,
# os-test-matrix.md §2.1)   # min-timeout: 9000   (the run gets at least
# that many seconds, whatever the target's TIMEOUT). Prints the value or "".
parse_header() { sed -n "s/^# $2:[[:space:]]*//p" "$1" | head -1; }
