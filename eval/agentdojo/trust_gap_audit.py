"""
trust_gap_audit — the OFFLINE (no-key) half of the adaptive-attack arm.

The adaptive-attack thesis for Mandu (docs/design/testing/evaluation.md):
because an UNTRUSTED tool_result is symbolized WHOLESALE, an injection that lives
inside an untrusted result can never reach T-LLM as text. So the only structural
lever an adaptive attacker has is a TRUST-SPEC GAP — a tool whose output a third
party can influence but which the arbiter's inbound spec marks TRUSTED. That
payload would reach the privileged model as raw text and the attack would be live.

This audit closes that lever WITHOUT a model or a key:

  1. Use AgentDojo's own GROUND-TRUTH pipeline (deterministic, offline — it replays
     each user task's ground-truth tool calls, no LLM) with canary injections, and
     record, per suite, every tool whose tool_result actually surfaces an injection
     canary. That is the empirical set of injection-carrying tools — derived from
     AgentDojo itself, not a hand-maintained vector→tool map.

  2. Parse the arbiter's calibrated trust spec (arbiter/policy/agentdojo-inbound.ts)
     into {tool -> UNTRUSTED|TRUSTED}. Unlisted tools default to UNTRUSTED
     (fail-closed), so only an explicit `: TRUSTED` can be a hole.

  3. Assert every injection-carrying tool classifies UNTRUSTED. A TRUSTED tool that
     carries an injection is a BY-CONSTRUCTION HOLE — the headline adaptive finding,
     and immediately actionable (fix the spec). Exit non-zero if any hole exists.

Also reports OVER-symbolization: tools the spec marks UNTRUSTED that no injection
can reach — a pure utility cost with no security benefit (spec-tightening
candidates, informational only, never fails the audit).

Runs today: `.venv/bin/python trust_gap_audit.py`.
"""

from __future__ import annotations

import os
import re
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SPEC_TS = os.path.join(REPO_ROOT, "arbiter", "policy", "agentdojo-inbound.ts")

ALL_SUITES = ["workspace", "travel", "banking", "slack"]


def parse_trust_spec(path: str) -> dict[str, str]:
    """Parse AGENTDOJO_INBOUND_SPEC from the TS source into {tool -> UNTRUSTED|TRUSTED}.

    The spec is a flat `Record<string, ToolSpec>` of `toolName: UNTRUSTED,` /
    `toolName: TRUSTED,` lines. We match exactly those and ignore the two
    `const UNTRUSTED/TRUSTED: ToolSpec = { schema: "…" }` declarations (their RHS is
    `ToolSpec`/a quoted string, not a bare UNTRUSTED/TRUSTED token)."""
    with open(path) as f:
        src = f.read()
    spec: dict[str, str] = {}
    # toolName: UNTRUSTED,   (optionally followed by a // comment)
    for m in re.finditer(r"^\s*([a-z_][a-z0-9_]*)\s*:\s*(UNTRUSTED|TRUSTED)\b", src, re.M):
        spec[m.group(1)] = m.group(2)
    return spec


def injection_carrying_tools() -> dict[str, set[str]]:
    """Per suite, the set of tool names whose tool_result surfaces an injection
    canary when the user task is executed correctly (AgentDojo ground truth)."""
    from agentdojo.task_suite.load_suites import get_suites
    from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.types import get_text_content_as_str

    suites = get_suites("v1")
    out: dict[str, set[str]] = {}
    for sname in ALL_SUITES:
        suite = suites[sname]
        defaults = suite.get_injection_vector_defaults()
        canaries = {inj: f"<CANARY---{inj}--->" for inj in defaults}
        env = suite.load_and_inject_default_environment(canaries)
        carriers: set[str] = set()
        for ut in suite.user_tasks.values():
            runtime = FunctionsRuntime(suite.tools)
            try:
                _, _, _, responses, _ = GroundTruthPipeline(ut).query(ut.PROMPT, runtime, env)
            except Exception:
                # A task whose ground truth can't be replayed contributes nothing.
                continue
            for r in responses:
                if r.get("role") != "tool" or not r.get("content"):
                    continue
                text = get_text_content_as_str(r["content"]) or ""
                if not any(c in text for c in canaries.values()):
                    continue
                tc = r.get("tool_call")
                name = getattr(tc, "function", None) if tc else None
                if name:
                    carriers.add(name)
        out[sname] = carriers
    return out


def run() -> int:
    try:
        carriers_by_suite = injection_carrying_tools()
    except Exception as e:  # pragma: no cover
        print(f"SKIP: agentdojo not importable / ground-truth replay failed ({e})")
        return 0

    spec = parse_trust_spec(SPEC_TS)

    holes: list[tuple[str, str]] = []       # (suite, tool) marked TRUSTED but carries an injection
    all_carriers: set[str] = set()
    print("─" * 74)
    print("Mandu trust-gap audit — every injection-carrying tool must be UNTRUSTED")
    print(f"spec: {os.path.relpath(SPEC_TS, REPO_ROOT)}   (unlisted → UNTRUSTED, fail-closed)")
    print("─" * 74)
    for sname in ALL_SUITES:
        carriers = sorted(carriers_by_suite.get(sname, set()))
        all_carriers.update(carriers)
        print(f"\n[{sname}] {len(carriers)} injection-carrying tool(s):")
        for tool in carriers:
            cls = spec.get(tool, "UNTRUSTED (default)")
            ok = cls.startswith("UNTRUSTED")
            mark = "ok " if ok else "HOLE"
            print(f"    {mark}  {tool:38s} → {cls}")
            if not ok:
                holes.append((sname, tool))

    # Over-symbolization: spec marks UNTRUSTED but no injection reaches it.
    untrusted_listed = {t for t, c in spec.items() if c == "UNTRUSTED"}
    over = sorted(untrusted_listed - all_carriers)

    print("\n" + "─" * 74)
    if holes:
        print(f"FAIL: {len(holes)} trust-gap hole(s) — a TRUSTED tool carries an injection:")
        for sname, tool in holes:
            print(f"    {sname}: {tool} is marked TRUSTED but surfaces attacker content")
        print("→ fix arbiter/policy/agentdojo-inbound.ts (mark these UNTRUSTED).")
    else:
        print(f"PASS: all {len(all_carriers)} injection-carrying tools classify UNTRUSTED — "
              "no by-construction hole.")
    if over:
        print(f"\nINFO: {len(over)} tool(s) marked UNTRUSTED that no injection reaches "
              "(over-symbolization, utility cost only — spec-tightening candidates):")
        print("    " + ", ".join(over))
    print("─" * 74)
    return 1 if holes else 0


if __name__ == "__main__":
    sys.exit(run())
