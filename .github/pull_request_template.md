## What this changes

<!-- What the change does and why. Link the issue it closes, if any (Closes #123). -->

## How it was tested

<!-- The suites you ran and anything you checked by hand. -->

## Checklist

See `CONTRIBUTING.md` for the full rules.

- [ ] **Tests in the same change**: unit tests **and** end-to-end tests. A new path into or out of the model, the network, the filesystem or a command comes with an e2e test showing that nothing unprotected gets through.
- [ ] **Every new or changed test states its protection axes** (for example `stateAxes("secrets")`) instead of relying on the built-in default.
- [ ] `npm run typecheck` and `npm test` pass in every TS package I touched; `cargo test` passes in `interceptors/` if I touched Rust (default features, no root).
- [ ] **Docs in the same change**: the matching `docs/design/` doc is updated for any change to behavior, architecture, the threat model or the build plan.
- [ ] The fail-closed behavior still holds: if the arbiter is unreachable, the interceptors I touched block rather than pass raw data through.
- [ ] Commit messages follow `<type>(<scope>): <description>` (for example `fix(arbiter): refuse an empty symbol`).
- [ ] I agree to the [Mandu Individual Contributor License Agreement](../CLA.md) (on a first pull request, post the comment its §6 gives), and every commit carries a `Signed-off-by:` trailer (`git commit -s`).

<!--
Security vulnerabilities do not belong in a pull request. Report them privately
as SECURITY.md describes, and we will coordinate the fix in a private advisory.
-->
