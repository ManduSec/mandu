"""
pipeline — build an AgentDojo AgentPipeline whose Anthropic client is pointed at
the Mandu anthropic-proxy (via ANTHROPIC_BASE_URL), plus the model-name-carrying
pipeline name the `important_instructions` attack needs.

This is the ONLY integration seam on the AgentDojo side: the official anthropic
SDK reads ANTHROPIC_BASE_URL / ANTHROPIC_API_KEY from the environment, so a
`anthropic.Anthropic()` constructed here forwards through the proxy with no fork
or monkeypatch (docs/design/testing/evaluation.md §2.2).
"""

from __future__ import annotations

import anthropic
from agentdojo.agent_pipeline import AgentPipeline, PipelineConfig
from agentdojo.agent_pipeline.llms.anthropic_llm import AnthropicLLM
from agentdojo.models import MODEL_NAMES

# The Phase-B default (decided 2026-07-16): the comparable-era model the plan
# originally pinned (claude-3-5-sonnet-20241022, what CaMeL/FIDES reported on)
# was RETIRED upstream 2025-10-28 and now 404s, so the headline claim is the
# harness's own NONE-vs-FULL contrast on a current model; the CaMeL/FIDES
# comparison is secondary, with an explicit model-era caveat
# (docs/design/testing/evaluation.md §2). Overridable via --model.
DEFAULT_MODEL = "claude-sonnet-5"

# Convenience aliases → real Anthropic API model ids. Current models need the
# MODEL_NAMES patch below so the named important_instructions attack can address
# them. Full ids also pass through --model. `sonnet-3.5` is kept for provenance
# but its target is RETIRED (404) — see the DEFAULT_MODEL note above.
MODEL_ALIASES = {
    "sonnet-3.5": "claude-3-5-sonnet-20241022",  # RETIRED upstream 2025-10-28
    "haiku": "claude-haiku-4-5-20251001",
    "sonnet": "claude-sonnet-5",
    "opus": "claude-opus-4-8",
}


def resolve_model(alias_or_id: str) -> str:
    """Map a convenience alias to a real API model id; pass a full id through."""
    return MODEL_ALIASES.get(alias_or_id, alias_or_id)


def patch_model_names(model: str) -> None:
    """AgentDojo's `important_instructions` attack names the model via MODEL_NAMES,
    which in 0.1.35 only knows models up to claude-3-7-sonnet. Register a current
    model as "Claude" so the NAMED attack still works on it (the alternative is the
    name-free important_instructions_no_model_name variant). No-op if already known."""
    if model not in MODEL_NAMES:
        MODEL_NAMES[model] = "Claude"


def build_pipeline(model: str = DEFAULT_MODEL, name_suffix: str = "mandu") -> AgentPipeline:
    """Standard AgentDojo tools-loop pipeline over an Anthropic client that honors
    ANTHROPIC_BASE_URL (set by the caller to the proxy). The pipeline `name` MUST
    contain a MODEL_NAMES-known id so the important_instructions attack can extract
    the prose model name — we embed `model` verbatim."""
    patch_model_names(model)  # so the named attack works on a current model
    client = anthropic.Anthropic()  # reads ANTHROPIC_BASE_URL / ANTHROPIC_API_KEY
    llm = AnthropicLLM(client, model)
    config = PipelineConfig(
        llm=llm,
        model_id=None,
        defense=None,
        system_message_name=None,
        system_message=None,
    )
    pipeline = AgentPipeline.from_config(config)
    # from_config names the pipeline off llm.name; force a name that carries the
    # model id verbatim (get_model_name_from_pipeline substring-matches it).
    pipeline.name = f"{model}-{name_suffix}"
    return pipeline
