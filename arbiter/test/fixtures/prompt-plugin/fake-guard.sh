#!/bin/sh
# fake-guard — a TEST stand-in for mandu-net-guard (confidentiality-plan-15
# §4.3): it confines NOTHING; it drops its own arguments up to `--` and execs
# the rest. Only the arbiter's protocol tests use it, through the probe seam;
# the confinement itself is proven with the real bins
# (prompt-filter-plugin-confine.test.ts).
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
[ "$#" -gt 0 ] && shift
exec "$@"
