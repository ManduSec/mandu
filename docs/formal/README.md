# Mandu formalization (working drafts)

Formal models, notation references, and diagrams live in this directory. They
are **working drafts**, not an authoritative statement of what Mandu
guarantees: that is [What Mandu guarantees](../guarantees.md), backed by the
design docs and the tests. The drafts predate the protection modes (the
default is now `secrets`) and the integrity freeze.

| File | Contents |
|---|---|
| [formal.html](formal.html) | Component diagram with a Simple / Full detail toggle. Simple is the default presentation view; full detail maps the state and policy notation. |
| [formal-situation.md](formal-situation.md) | Proposed operating situation, notation tables, threat model, transition-system outline, and candidate verification properties. |
| [guarantees.md](guarantees.md) | Confidentiality and integrity contracts, with implementation status, scope, and remaining verification targets. |

Open `formal.html` directly in a browser; it has no external dependencies.

The specification is a modeling proposal, not a completed formal verification.
Source-code paths in `formal-situation.md` are relative to the repository root
unless stated otherwise.
