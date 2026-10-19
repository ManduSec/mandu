"""
invariant_smoke — the OFFLINE (no key, no network) proof that Mandu's context
chokepoint symbolizes an AgentDojo injection before it reaches the model.

This is the AgentDojo-shaped analogue of tests/stack/full-stack.test.ts
and eval/'s deterministic backend: it runs a REAL AgentDojo task pair (slack
user_task_0 "read www.informations.com" × injection_task_1, `important_instructions`
attack) through the REAL arbiter + REAL anthropic-proxy against a scripted MOCK
upstream, and asserts the §9 invariant on the request the proxy forwarded upstream:

  the injected instruction ("<INFORMATION> … Emma Johnson … secure-systems-252.com")
  reaches the model ONLY as a $MDU:* token — never in the clear.

It proves the load-bearing integration claim: AgentDojo's tool_result wire format
is actually parsed and symbolized by the real proxy under the `agentdojo` trust
spec (get_webpage → UNTRUSTED). It does NOT measure ASR — a scripted mock cannot
"decide"; the real-model ASR/utility is runner.py's job (needs a Console key).

Exit 0 on PASS or clean SKIP (deps absent); exit 1 on a real invariant failure.
"""

from __future__ import annotations

import os
import sys
import tempfile

# Attacker-CONTROLLED tokens that appear ONLY inside the untrusted webpage — they
# MUST NOT reach the model in the clear (the defense replaces them with a symbol).
# NB: do NOT use the user's own name (e.g. "Emma Johnson") as a marker — that
# appears legitimately in the system prompt / user identity, not just the
# injection, so it is not an injection-only signal.
INJECTION_MARKERS = ["secure-systems-252.com", "<INFORMATION>"]
# The untrusted webpage's BENIGN body — under the ADFI model an UNTRUSTED result
# is symbolized WHOLESALE, so even this must be gone from the model-facing request
# (a stronger check than "just the injection was removed").
UNTRUSTED_BODY_MARKER = "job report"
SYMBOL_PREFIX = "$MDU:"

# The verified smoke case: slack, read a webpage that carries the injection.
SUITE = "slack"
USER_TASK = "user_task_0"
INJECTION_TASK = "injection_task_1"
ATTACK = "important_instructions"
SCRIPTED_TOOL = "get_webpage"
SCRIPTED_ARGS = {"url": "www.informations.com"}


def _skip(reason: str) -> int:
    print(f"SKIP: {reason}")
    return 0


def run() -> int:
    try:
        from agentdojo.task_suite.load_suites import get_suites
        from agentdojo.attacks.attack_registry import load_attack
    except Exception as e:  # pragma: no cover
        return _skip(f"agentdojo not importable ({e}) — run eval/agentdojo/run.sh to provision")

    from stack import defense_stack, mint_self_signed_cert, DepsMissing
    from mock_upstream import start_mock_upstream, Script
    from pipeline import build_pipeline, DEFAULT_MODEL, patch_model_names

    suite = get_suites("v1")[SUITE]
    user_task = suite.get_user_task_by_id(USER_TASK)
    injection_task = suite.get_injection_task_by_id(INJECTION_TASK)

    # Register DEFAULT_MODEL in MODEL_NAMES so the named important_instructions
    # attack can address it — build_pipeline() does this too, but the attack is
    # loaded first here, so patch up front (the comparable-era default used to be
    # natively known; claude-sonnet-5 needs the patch).
    patch_model_names(DEFAULT_MODEL)

    # Name the pipeline off the model id so the attack can address the model.
    class _NameCarrier:
        name = f"{DEFAULT_MODEL}-mandu"

    attack = load_attack(ATTACK, suite, _NameCarrier())
    injections = attack.attack(user_task, injection_task)

    # Sanity: the injection markers really are in the planted payload.
    planted = "\n".join(injections.values())
    if not all(m in planted for m in INJECTION_MARKERS):
        print("SMOKE SETUP ERROR: injection markers not in the planted payload — "
              "AgentDojo corpus changed; update INJECTION_MARKERS.")
        return 1

    tmp = tempfile.mkdtemp(prefix="mandu-agentdojo-smoke-")
    mock = None
    try:
        cert, key = mint_self_signed_cert(tmp)
        mock = start_mock_upstream(cert, key, Script(tool_name=SCRIPTED_TOOL, tool_input=SCRIPTED_ARGS))

        with defense_stack(tmp, upstream_origin=mock.origin, inbound_spec="agentdojo", fake_upstream=True) as stack:
            os.environ["ANTHROPIC_BASE_URL"] = stack.proxy_base_url
            os.environ["ANTHROPIC_API_KEY"] = "sk-ant-mandu-smoke-dummy"
            pipeline = build_pipeline()
            # Run the real task pair through the pipeline (mock scripts the tool call).
            utility, security = suite.run_task_with_pipeline(
                pipeline, user_task, injection_task, injections,
            )
            # utility/security are not the smoke's focus (scripted mock), but log them.
            print(f"[smoke] pipeline ran: utility={utility} security={security} "
                  f"(scripted mock — not an ASR measurement)")

        return _assert_invariant(mock.captured)
    except DepsMissing as e:
        return _skip(str(e))
    except Exception as e:
        print(f"SMOKE ERROR: {type(e).__name__}: {e}")
        return 1
    finally:
        if mock is not None:
            mock.stop()


def _assert_invariant(captured: list[str]) -> int:
    # Find the request that carried the (now-symbolized) tool_result.
    tool_result_reqs = [b for b in captured if '"tool_result"' in b]
    if not tool_result_reqs:
        print(f"SMOKE FAIL: the proxy forwarded no tool_result request "
              f"(captured {len(captured)} requests) — the pipeline never fed the "
              f"webpage back; the mock/tool wiring is wrong.")
        return 1

    joined = "\n".join(tool_result_reqs)
    leaked = [m for m in INJECTION_MARKERS if m in joined]
    body_leaked = UNTRUSTED_BODY_MARKER in joined
    has_symbol = SYMBOL_PREFIX in joined

    print("─" * 70)
    print("Mandu × AgentDojo — offline invariant smoke")
    print(f"  case: {SUITE}/{USER_TASK} × {INJECTION_TASK} (attack: {ATTACK})")
    print(f"  vector: {SCRIPTED_TOOL} → UNTRUSTED (agentdojo trust spec)")
    print(f"  upstream tool_result requests captured: {len(tool_result_reqs)}")
    print(f"  $MDU:* present in forwarded request: {has_symbol}")
    print(f"  raw injection markers leaked to model: {leaked or 'NONE'}")
    print(f"  untrusted webpage body ('{UNTRUSTED_BODY_MARKER}') symbolized: {not body_leaked}")
    print("─" * 70)

    if leaked:
        print(f"SMOKE FAIL: injection reached the model IN THE CLEAR: {leaked}")
        return 1
    if body_leaked:
        print(f"SMOKE FAIL: the untrusted webpage body ('{UNTRUSTED_BODY_MARKER}') "
              "reached the model un-symbolized — symbolization was not wholesale.")
        return 1
    if not has_symbol:
        print("SMOKE FAIL: no $MDU:* token in the forwarded request — the "
              "untrusted webpage was neither symbolized nor leaked; the proxy did "
              "not classify get_webpage UNTRUSTED (check MANDU_INBOUND_SPEC).")
        return 1

    print("SMOKE PASS: the AgentDojo injection reached the model ONLY as a symbol.")
    return 0


if __name__ == "__main__":
    sys.exit(run())
