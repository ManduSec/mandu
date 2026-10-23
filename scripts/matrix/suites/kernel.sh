#!/usr/bin/env bash
# deps: cargo node
# kernel — Track B kernel-attachment tests via the unprivileged-userns runner
# (docs/design/testing/os-test-matrix.md §4). scripts/kernel-tests.sh self-SKIPs per
# missing facility and exits 0 unless a REAL failure occurred — on a
# restricted-userns target its clean SKIP is itself the degrade-path assertion.
# `node` too: net-supervisor's a_holders_runtimes_run_under_the_memfd_trap runs
# node and python3 under the guard and fails without them, as every kernel
# lane provides (a 26.04 guest provisioned for cargo alone failed it on the
# v0.2.0-beta.8 tag, 2026-10-23; the node dep also installs python3).
set -uo pipefail
# The CI pin's toolchain, never the caller's `rustup default` (lib/rust-toolchain.sh).
# shellcheck source=../lib/rust-toolchain.sh
source scripts/matrix/lib/rust-toolchain.sh
matrix_use_pinned_rust . || exit 1
# Pre-fetch the Rust workspace's dependencies WITH network access:
# kernel-tests.sh wraps exec/net-supervisor in `unshare --net` (a fresh, empty
# netns) where a cold $CARGO_HOME cannot reach crates.io (first seen on the
# pristine ubuntu-2604 guest). Fetch is a fast no-op on warm hosts; the
# namespaced builds then run offline from the populated cache.
( cd interceptors && cargo fetch ) || exit 1
exec scripts/kernel-tests.sh
