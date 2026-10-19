# Mandu — Licensing

> The **licensing decision record**: what Mandu is licensed under, why, where
> the open-core line runs, and what has to be in the tree for it. Companion to
> `mandu.md` (architecture / provenance) and `packaging.md` (the published
> package).
>
> **Status: DECIDED 2026-10-09** (replacing the 2026-09-24 decision, §3.1).
> The open core is **Apache-2.0**; the open-core line is drawn in §6, with the
> SIEM integration and the fleet, feed and evidence offerings on the
> enterprise side. The license text, `NOTICE`, per-package fields, `CLA.md`
> (with `CONTRIBUTING.md`) and a manifest test are in the tree (§7).
> `@mandusec/mandu` is on npm from `0.2.0-beta.6`, packed from the public
> tree; every other package stays private (§7).

---

## 0. Summary

- **License:** the repo carries the **Apache-2.0** text at the root, `NOTICE`,
  and a `license` field on every npm package, Cargo manifest, the Python
  client and the Homebrew formula.
- **Freedom to license:** no inbound dependency imposes copyleft; the ancestor
  runtime (OpenClaw) is MIT and is not shipped; the lifted core is the DualView
  authors' own code, relicensed here with their agreement (§2).
- **Decision (2026-10-09):** **Apache-2.0 on the open core**, with the
  open-core line in §6: what Mandu Security sells is the enterprise side
  (fleet operation, the maintained policy feed, evidence packs, the SIEM
  integration), not a second license to the same code.
- **Contributions** are accepted under the CLA in `CLA.md`, which gives Mandu
  Security the right to license them under any terms.

---

## 1. What the repository carries

| Fact | Detail |
|---|---|
| Root `LICENSE` | **Apache-2.0** (canonical apache.org text; its sha256 is pinned by `launcher/test/unit/license-manifest.test.ts`). `launcher/LICENSE` and `launcher/NOTICE` are identical copies so the npm bundle ships them, and `interceptors/mandu-arbiter/LICENSE` is the same text. |
| `NOTICE` | The DualView-derived file list, the enterprise side, OpenClaw (MIT, types only) and the dashboard's self-hosted fonts (SIL OFL 1.1). Apache-2.0 §4(d) asks redistributors to carry it. The developer view, which is not published, carries its own (its DualView-derived files and the vendored asciinema-player). |
| Declared licenses | Every open npm package, the Cargo workspace and every crate, `clients/python` and the Homebrew formula: `Apache-2.0`. |
| CLA | `CLA.md`, the Mandu Individual CLA 1.0 (2026-10-09), shaped on the Apache ICLA: the contributor keeps the copyright and licenses Mandu Security to license the contribution **under any terms**, plus a patent license. A contributor agrees once, by a fixed comment on the first pull request, and signs off every commit (the DCO 1.1); a corporate agreement is by request. Apache-2.0 carries its own patent license (§3) and patent-retaliation clause; there is no separate patent policy. |

---

## 2. Provenance — freedom to license

Does any code Mandu incorporates carry a copyleft obligation that would force
(or forbid) a particular license? **No.**

| Source | License | Effect on Mandu |
|---|---|---|
| **OpenClaw** (the agent the paper's prototype plugged into) | **MIT** (© 2025 Peter Steinberger) | Permissive, imposes nothing. Mandu **removes** the OpenClaw dependency (`mandu.md` §2): the shipped code does not link or embed it. |
| **DualView** (`compsec-snu/dualview`: the lifted symbol-table / policy / view-sync core) | Published under **BUSL-1.1** (converts to Apache-2.0 on 2030-08-04); its `openclaw/` directory stays MIT | The DualView authors are the licensors. They agreed on 2026-09-24 to license the carried-over code under Mandu's AGPL-3.0-or-later and **on 2026-10-09 under Apache-2.0**. Each derived file keeps its provenance header and is listed in `NOTICE` §1. |
| Product runtime deps (Anthropic SDK, Node built-ins, `js-yaml`, Rust crates) | Permissive (MIT / Apache-2.0 / BSD) | Apache-2.0-compatible. |
| Dashboard fonts (`dashboard/public/fonts/`: IBM Plex Sans + Mono; latin woff2 from Fontsource) | **SIL OFL 1.1** | Fonts may be bundled with software under any license; the OFL covers only the font files, which ship with their license text beside them. |
| `eval/agentdojo/.venv/**` (vendored Python) | Mixed Apache-2.0 / MIT | Eval-only dev tree, never part of a published artifact. |

---

## 3. Why Apache-2.0

1. **The defense has to be auditable.** A layer that proxies model traffic and
   interposes on syscalls is only trustworthy if its construction can be read.
   The code that enforces the invariant is therefore fully open.
2. **Adoption where agents are built.** The agents Mandu wraps (Codex,
   Anthropic's sandbox runtime) are Apache-2.0, and large companies forbid the
   AGPL outright: Google's policy says AGPL code must not be used there, not
   even installed on an engineer's laptop without approval. An AGPL Mandu
   cannot be tried, embedded or partnered on by the teams most likely to
   need it.
3. **The field's norm.** The comparable projects are permissive: the AI
   gateways (LiteLLM's MIT core with a commercial `enterprise/` folder,
   Portkey MIT, Helicone Apache-2.0) and the open tools of AI-security
   companies (Protect AI's MIT / Apache-2.0 tools, Invariant Labs' Apache-2.0
   guardrails). None is AGPL.
4. **A clear patent grant.** Apache-2.0 §3 grants users a patent license and
   ends it for anyone who sues over the code, which enterprise legal teams
   expect.
5. **The value is not in the license.** What a customer pays for is the
   enterprise side (§6): the policy feed kept current for each agent release,
   fleet operation, evidence packs and the SIEM integration.

Rejected: staying **AGPL-3.0-or-later** with a commercial dual-license (§3.1),
and **BSL / FSL** source-available licenses (not open source at release, which
undercuts the auditable-reference goal).

### 3.1 The superseded decision (2026-09-24 → 2026-10-09)

From 2026-09-24 the open core was **AGPL-3.0-or-later with a commercial
dual-license** (the Rust `mandu-arbiter` client crate alone Apache-2.0), on
the grounds that AGPL's network clause keeps hosted modifications open and a
closed embedder would buy a commercial license. It was replaced before the
first public release, so no AGPL version of Mandu was ever published:
adoption by the large agent and security vendors, which the AGPL blocks (§3,
point 2), is worth more to Mandu than license revenue from embedders.

## 6. The open-core line (drawn 2026-09-24)

The rule: **everything a reviewer must read to believe the invariant is open;
fleet operation, curated update feeds and accreditation evidence built on top of
it are enterprise.**

| Directory / component | Side | License | Rationale |
|---|---|---|---|
| `arbiter/` (symbol table, both policies, IPC server and client, event store) | **open** | Apache-2.0 | The decision hub; nothing above it is credible if this is closed. |
| `interceptors/anthropic-proxy`, `openai-proxy`, `net-proxy`, `exec-wrap`, `reply-filter`, `inspect-mcp`, `policy-mcp`, `openclaw-inspect-plugin` | **open** | Apache-2.0 | The chokepoints at the context and wrapper layers plus the U-LLM path. |
| `interceptors/fs-supervisor`, `net-supervisor`, `exec-supervisor`, `fs-preload`, `mandu-arbiter` (Rust) | **open** | Apache-2.0 (workspace) | The kernel layer of the same chokepoints, and the Rust IPC client third-party runtimes integrate against. |
| `fs-sync/`, `launcher/` (`@mandusec/mandu`) | **open** | Apache-2.0 | The view-sync machinery and the user-visible surface. |
| `dashboard/` (single-user, per-stack) | **open** | Apache-2.0 | The product page, each session's page among it, is how a user checks what the defense did: what the AI saw beside what really happened, signed out without a value (dashboard.md §4.25ad). **Fleet / multi-tenant** features, when built, are enterprise and live outside this repository. |
| `arbiter/policy/claude-code-inbound.ts` and the other shipped trust specs | **open** (the snapshot) | Apache-2.0 | The arbiter does not run without them. A **maintained feed of updates** per agent release is a commercial offering. |
| `tests/` (with `tests/conformance/`), `eval/` | **open**, except the row below | Apache-2.0 | The invariant oracle only proves something if a reviewer can read what it asserts: the unit, component, stack, sandbox, conformance and env suites stay public, and each claim in `guarantees.md` cites one of them. Produced **evidence packs and compliance mappings** are enterprise. |
| The maintainers' evidence tooling: the agent drills (the catalog, the runner and recorder, the replay engine, the differential harness, their tests and recorded fixtures), the utility runner (`eval/lib/utility-runner`), the policy-model corpus (`eval/policy-model`) and the test-process docs that describe them (decided 2026-10-08), and the containerized rig that runs the drills (the e2e image, compose file, entrypoint and credential seeder in `packaging/docker/`, decided 2026-10-09) | **maintainers'** | not published | Tooling that produces evidence, like the enterprise evidence packs, not part of what ships or of the oracle a reviewer reads. The claims stay checkable through the public suites, and the drills' results are published per release (`docs/testing/drill-results.md`); access to the drills themselves is by request to hello@mandusecurity.com. Publishing them later is one change; taking them back after publication is impossible. |
| The dashboard's developer view (the inspector at `/dev/`: the three-lane trace, the drill, test, CI and replay views, the service console, the policy document editor; decided 2026-10-15) | **maintainers'** | not published | The maintainers' tool for building and debugging Mandu, not what a user checks the defense with: that is the product's session page, which shows every session's trace. The public dashboard loads it only where a build carries it (dashboard.md §4.25ac), so the published package serves the product page alone. Publishing it later is one change. |
| SIEM integration (a Wazuh rig and a redacting event exporter, `siem-integration.md`) | **enterprise** | all rights reserved, own `LICENSE` | Operational integration, not part of the invariant. Not in the public repository. |
| `docs/`, `scripts/`, `packaging/docker/` (`Dockerfile.ci`) | open, except the row above | Apache-2.0 | Documentation and tooling travel with the code. |

Anything published from this repository is Apache-2.0; enterprise features are
written outside it from the start, and the maintainers' evidence tooling stays
in the source repository.

## 7. In the tree

Pinned by `launcher/test/unit/license-manifest.test.ts` (first 2026-09-24,
switched to Apache-2.0 2026-10-09):

- [x] Root **`LICENSE`** (canonical Apache-2.0 text) + identical
      `launcher/LICENSE` and `interceptors/mandu-arbiter/LICENSE`.
- [x] **`NOTICE`** (+ `launcher/NOTICE`): the DualView-derived file list, the
      enterprise side, OpenClaw (MIT) and the dashboard fonts (SIL OFL 1.1,
      added 2026-09-27); the vendored asciinema-player left with the
      developer view (2026-10-15), whose own NOTICE lists it. The test walks
      every tracked source file for the reference name, so a newly copied
      module fails the suite until it is listed (a private package's file in
      that package's NOTICE).
- [x] `license` field on every `package.json` and every Cargo manifest (§1).
- [x] The open-core line written down (§6).
- [x] **`CLA.md`** (the Individual CLA 1.0) and **`CONTRIBUTING.md`** with how
      to agree to it + `Signed-off-by`.
- [ ] SPDX headers across source: **deliberately not done.** A blanket sweep
      touches ~600 files and buries blame; the root `LICENSE` plus per-package
      fields is the npm/Cargo convention, and the provenance headers on lifted
      modules stay. Revisit only if a distributor asks.

**The publish gate.** Every package is `private: true` in Mandu Security's
source repository, the one the public repository is exported from. The
`packaging.md` §8 M5 unlock (2026-10-19, `0.2.0-beta.6`) sets `homepage`
and drops `private` from the launcher in the public tree only, so the one
published package, `@mandusec/mandu`, is packed from the public tree; `repository` waits for the public GitHub repository. The tarball ships
`LICENSE` and `NOTICE`. Vendored dev trees
(`eval/agentdojo/.venv`, etc.) are never part of a published artifact.

## 8. Cross-references

- `packaging.md` §3, §8 (M5) — the publish gate, consistent with this doc.
- `mandu.md` §2, §8 — provenance (OpenClaw removed) and terminology.
- `NOTICE` — the per-file attribution this doc's §2 summarizes.
