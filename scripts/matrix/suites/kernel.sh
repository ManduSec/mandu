#!/usr/bin/env bash
# deps: cargo
# kernel — Track B kernel-attachment tests via the unprivileged-userns runner
# (docs/design/testing/os-test-matrix.md §4). scripts/kernel-tests.sh self-SKIPs per
# missing facility and exits 0 unless a REAL failure occurred — on a
# restricted-userns target its clean SKIP is itself the degrade-path assertion.
set -uo pipefail
# Pre-fetch the Rust workspace's dependencies WITH network access:
# kernel-tests.sh wraps exec/net-supervisor in `unshare --net` (a fresh, empty
# netns) where a cold $CARGO_HOME cannot reach crates.io (first seen on the
# pristine ubuntu-2604 guest). Fetch is a fast no-op on warm hosts; the
# namespaced builds then run offline from the populated cache.
( cd interceptors && cargo fetch ) || exit 1
exec scripts/kernel-tests.sh
