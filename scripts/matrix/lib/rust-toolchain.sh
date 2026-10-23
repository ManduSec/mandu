#!/usr/bin/env bash
# rust-toolchain.sh — the matrix's Rust: the CI pin, named explicitly
# (docs/design/testing/os-test-matrix.md §4.1). Sourced by the suites that
# build the Rust workspace (kernel, all), on the host executor and in a guest.
#
# The toolchain is scripts/ci/pins.env's RUST_VERSION, the one the CI guest
# image (scripts/ci/guest/provision.sh) and the GitHub workflows build with.
# It never rides on the caller's `rustup default`: the CI runner gives its jobs
# a clean HOME, whose rustup has no default and no toolchain at all, so a bare
# `cargo` failed "rustup could not choose a version of cargo to run" (the
# v0.2.0-beta.8 tag's install job, host/kernel). A host whose cargo is not
# rustup's (a distro cargo) is used as it is, with a note.

# matrix_rust_version [repo root] — RUST_VERSION from scripts/ci/pins.env.
matrix_rust_version() {
  sed -n 's/^RUST_VERSION=//p' "${1:-.}/scripts/ci/pins.env" | head -n1
}

# matrix_use_pinned_rust [repo root] — export RUSTUP_TOOLCHAIN=<pin>, installing
# the toolchain (minimal profile) when rustup lacks it. 1 when it cannot.
matrix_use_pinned_rust() {
  local v; v="$(matrix_rust_version "${1:-.}")"
  [[ -n "$v" ]] || { echo "rust: no RUST_VERSION in scripts/ci/pins.env" >&2; return 1; }
  if ! command -v rustup >/dev/null 2>&1; then
    echo "rust: no rustup on PATH; using $(cargo --version 2>/dev/null || echo 'no cargo'), not the pin $v" >&2
    return 0
  fi
  export RUSTUP_TOOLCHAIN="$v"
  # `rustup toolchain list` prints e.g. "1.75.0-x86_64-unknown-linux-gnu (default)".
  if ! rustup toolchain list 2>/dev/null | grep -q "^$v-"; then
    echo "rust: installing the pinned toolchain $v (scripts/ci/pins.env) into ${RUSTUP_HOME:-$HOME/.rustup}" >&2
    # --no-self-update: under a HOME whose CARGO_HOME holds no rustup (the
    # runner's; the proxies live in the account's own ~/.cargo/bin) the
    # install's self-update check fails after the toolchain is in place.
    # Success is the toolchain being there afterwards.
    rustup toolchain install "$v" --profile minimal --no-self-update >&2
    rustup toolchain list 2>/dev/null | grep -q "^$v-" || { echo "rust: rustup could not install $v" >&2; return 1; }
  fi
  echo "rust: $(cargo --version) (RUSTUP_TOOLCHAIN=$v, scripts/ci/pins.env)" >&2
}
