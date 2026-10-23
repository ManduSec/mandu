/**
 * The launch log's line for the guard-only confinement posture (plan 10
 * §11.7): the whole-agent guard alone serves the secret twins by descriptor,
 * no bind mount. The launcher says it one of two ways
 * (launcher/src/secret-setup.ts): on a host that COULD bind, `--no-secret-bind`
 * skips the bind on purpose ("bind mount SKIPPED (--no-secret-bind)"); on a
 * host that cannot (no bubblewrap, or AppArmor restricting unprivileged user
 * namespaces, a stock Ubuntu 24.04 or 26.04) the host's gap closes it ("… the
 * whole-agent guard serves the secret twins by descriptor instead (no bind
 * mount …"). A test of the guard-only posture asks for it with
 * `--no-secret-bind` and accepts either: CI's guest can bind, the OS test
 * matrix's 26.04 guest cannot (os-test-matrix.md §10.19).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code.
 */
export const GUARD_ONLY_POSTURE =
  /bind mount SKIPPED \(--no-secret-bind\)|the whole-agent guard serves the secret twins by descriptor instead \(no bind mount/;
