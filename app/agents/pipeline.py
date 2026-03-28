"""
LangGraph pipeline — NL → Firewall Rule.

Nodes:
  1. resolve_intent   — LLM extracts CanonicalRule from intent + SNMT
  2. build_rule       — validates/corrects entities against SNMT
  3. await_review     — human-in-the-loop interrupt
  4. lint             — structural linter (advisory)
  5. safety_check     — safety gate (hard blocker)
  6. compile_acl      — CiscoIOSCompiler → CompiledACL
  7. verify_batfish   — Batfish snapshot verification (advisory)
  8. generate_output  — final config + explanation
"""

from __future__ import annotations

import json
import logging
from typing import Any

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from pydantic import ValidationError

from app.agents.groq_client import get_groq_client
from app.agents.prompts import (
    build_explanation_prompt,
    build_feedback_prompt,
    build_feedback_system_prompt,
    build_system_prompt,
)
from app.compiler.cisco import CiscoIOSCompiler
from app.models.ir import (
    Action,
    CanonicalRule,
    Direction,
    Endpoint,
    InterfaceTarget,
    PipelineState,
    PipelineStatus,
    PortOperator,
    PortSpec,
    Protocol,
)
from app.safety.gate import run_safety_gate
from app.safety.linter import run_linter
from app.snmt.loader import require_snmt
from app.verification.batfish_manager import BatfishManager

logger = logging.getLogger(__name__)


# ─── JSON dict → CanonicalRule ────────────────────────────────────────────────


def _dict_to_rule(data: dict[str, Any]) -> tuple[CanonicalRule | None, str | None]:
    """Parse LLM JSON output into a validated CanonicalRule."""
    try:
        # Normalise string enums to lowercase
        for field in ("action", "direction", "protocol"):
            if field in data and isinstance(data[field], str):
                data[field] = data[field].lower()

        # Normalise nested direction in interfaces
        for iface in data.get("interfaces", []):
            if isinstance(iface.get("direction"), str):
                iface["direction"] = iface["direction"].lower()

        # Normalise port operators
        for ps in data.get("dst_ports", []) + data.get("src_ports", []):
            if isinstance(ps.get("operator"), str):
                ps["operator"] = ps["operator"].lower()

        # Coerce icmp_type: LLM sometimes returns an integer (e.g. 8 for echo)
        # instead of the string name. Convert int → str so Pydantic accepts it.
        if "icmp_type" in data and data["icmp_type"] is not None:
            if isinstance(data["icmp_type"], int):
                # Map common ICMP type numbers to their IOS keyword names.
                # Fall back to the numeric string if unknown.
                _ICMP_TYPE_NAMES = {
                    0: "echo-reply",
                    3: "unreachable",
                    5: "redirect",
                    8: "echo",
                    11: "time-exceeded",
                    12: "parameter-problem",
                    13: "timestamp",
                    14: "timestamp-reply",
                    17: "mask-request",
                    18: "mask-reply",
                }
                data["icmp_type"] = _ICMP_TYPE_NAMES.get(
                    data["icmp_type"], str(data["icmp_type"])
                )
            elif isinstance(data["icmp_type"], str):
                data["icmp_type"] = data["icmp_type"].lower()

        # Coerce icmp_code: LLM sometimes returns a string instead of int.
        if "icmp_code" in data and data["icmp_code"] is not None:
            if isinstance(data["icmp_code"], str):
                try:
                    data["icmp_code"] = int(data["icmp_code"])
                except ValueError:
                    data["icmp_code"] = None

        # Coerce rule_name: strip spaces and special characters the LLM sneaks in.
        if "rule_name" in data and isinstance(data["rule_name"], str):
            import re as _re

            data["rule_name"] = _re.sub(
                r"[^a-zA-Z0-9_\-]", "_", data["rule_name"]
            ).strip("_")

        # Coerce confidence: LLM sometimes returns a string like "0.9".
        if "confidence" in data and isinstance(data["confidence"], str):
            try:
                data["confidence"] = float(data["confidence"])
            except ValueError:
                data["confidence"] = 0.5

        rule = CanonicalRule(**data)
        return rule, None
    except (ValidationError, TypeError, KeyError) as e:
        return None, str(e)


# ─── Node 1: Resolve intent ────────────────────────────────────────────────────


async def resolve_intent(state: PipelineState) -> dict:
    logger.info(f"[{state.session_id}] Resolving intent: {state.intent_text[:80]}")

    snmt = require_snmt()
    client = get_groq_client()

    if state.human_feedback and state.feedback_rounds > 0 and state.resolved_rule:
        # Feedback round: use the lean system prompt (no CoT/examples) to stay
        # well under the 8 000 TPM limit. SNMT lives in the system prompt only.
        system_prompt = build_feedback_system_prompt(snmt.to_prompt_block())
        prev_ambiguities = (
            state.resolved_rule.ambiguities if state.resolved_rule.ambiguities else None
        )
        user_message = build_feedback_prompt(
            original_intent=state.intent_text,
            wrong_ir_json=state.resolved_rule.model_dump_json(indent=2),
            human_feedback=state.human_feedback,
            previous_ambiguities=prev_ambiguities,
        )
    else:
        # First pass: full system prompt with CoT, self-reflection, few-shot examples
        system_prompt = build_system_prompt(snmt.to_prompt_block())
        user_message = (
            f"Translate this network security intent into the Canonical Rule IR JSON:\n\n"
            f"{state.intent_text}"
        )

    try:
        raw_json = await client.generate_json(system_prompt, user_message)
        rule, error = _dict_to_rule(raw_json)

        if error:
            logger.warning(f"Rule validation failed: {error}")
            return {
                "status": PipelineStatus.FAILED,
                "error": f"IR parsing error: {error}",
                "current_step": "Resolver failed — IR validation error",
                "llm_messages": state.llm_messages
                + [
                    {
                        "role": "assistant",
                        "content": str(raw_json),
                        "step": "resolve_intent",
                    }
                ],
            }

        return {
            "status": PipelineStatus.BUILDING_IR,
            "current_step": "Resolver complete",
            "resolved_rule": rule,
            "error": None,
            "llm_messages": state.llm_messages
            + [
                {
                    "role": "assistant",
                    "content": str(raw_json),
                    "step": "resolve_intent",
                }
            ],
        }

    except Exception as e:
        logger.exception("Groq call failed in resolve_intent")
        return {
            "status": PipelineStatus.FAILED,
            "error": f"LLM error: {str(e)}",
            "current_step": "Resolver failed — LLM error",
        }


# ─── Node 2: Build/validate rule ──────────────────────────────────────────────


async def build_rule(state: PipelineState) -> dict:
    if state.status == PipelineStatus.FAILED:
        return {"current_step": state.current_step}

    if not state.resolved_rule:
        return {
            "status": PipelineStatus.FAILED,
            "error": "No rule to validate",
            "current_step": "Build rule failed",
        }

    snmt = require_snmt()
    rule = state.resolved_rule

    def _fix_endpoints(endpoints: list[Endpoint]) -> list[Endpoint]:
        fixed = []
        for ep in endpoints:
            entity = snmt.get_entity(ep.entity_name) or snmt.get_entity_fuzzy(
                ep.entity_name
            )
            if entity and entity.primary_gateway:
                matched_gw = entity.primary_gateway
                for g in entity.gateways:
                    if g.prefix == ep.prefix:
                        matched_gw = g
                        break
                fixed.append(
                    Endpoint(
                        entity_name=entity.name,
                        router=matched_gw.router,
                        interface=matched_gw.interface,
                        prefix=matched_gw.prefix,
                    )
                )
            else:
                logger.warning(
                    f"Entity '{ep.entity_name}' not in SNMT — keeping LLM value"
                )
                fixed.append(ep)
        return fixed

    # Fix interfaces — validate router/interface against SNMT entities
    def _fix_interfaces(interfaces: list[InterfaceTarget]) -> list[InterfaceTarget]:
        if not interfaces:
            return interfaces
        fixed = []
        for iface in interfaces:
            # Find any SNMT entity whose gateway matches this interface
            matched = False
            for entity in snmt.get_all_entities():
                for gw in entity.gateways:
                    if (
                        gw.interface.lower() == iface.interface.lower()
                        and gw.router.lower() == iface.router.lower()
                    ):
                        fixed.append(
                            InterfaceTarget(
                                router=gw.router,
                                interface=gw.interface,
                                direction=iface.direction,
                            )
                        )
                        matched = True
                        break
                if matched:
                    break
            if not matched:
                logger.warning(
                    f"Interface {iface.router}/{iface.interface} not in SNMT"
                )
                fixed.append(iface)
        return fixed

    corrected = rule.model_copy(
        update={
            "sources": _fix_endpoints(rule.sources),
            "destinations": _fix_endpoints(rule.destinations),
            "interfaces": _fix_interfaces(rule.interfaces),
        }
    )

    logger.info(
        f"[{state.session_id}] Rule validated: "
        f"{corrected.estimated_line_count()} estimated ACL line(s)"
    )

    return {
        "resolved_rule": corrected,
        "status": PipelineStatus.AWAITING_REVIEW,
        "current_step": "Awaiting human review — approve or provide feedback",
    }


# ─── Node 3: Human review interrupt ───────────────────────────────────────────


async def await_review(state: PipelineState) -> dict:
    logger.info(f"[{state.session_id}] Paused for human review")
    return {"current_step": "Human review — approve or provide feedback"}


# ─── Node 4: Lint ─────────────────────────────────────────────────────────────


async def lint(state: PipelineState) -> dict:
    if state.status in (PipelineStatus.FAILED, PipelineStatus.BLOCKED):
        return {"current_step": state.current_step}  # pass through, no change
    lint_result = run_linter(state.resolved_rule)
    if lint_result.has_warnings:
        logger.warning(f"Linter: {lint_result.summary()}")
    if lint_result.has_errors:
        logger.error(f"Linter errors: {lint_result.summary()}")
    return {
        "lint_result": lint_result,
        "status": PipelineStatus.LINTING,
        "current_step": f"Lint complete — {lint_result.summary()}",
    }


# ─── Node 5: Safety gate ──────────────────────────────────────────────────────


async def safety_check(state: PipelineState) -> dict:
    if state.status in (PipelineStatus.FAILED, PipelineStatus.BLOCKED):
        return {"current_step": state.current_step}  # pass through, no change
    safety_result = run_safety_gate(state.resolved_rule)
    if not safety_result.safe:
        logger.error(f"Safety gate BLOCKED: {safety_result.errors}")
        return {
            "safety_result": safety_result,
            "status": PipelineStatus.BLOCKED,
            "error": f"Safety gate: {'; '.join(safety_result.errors)}",
            "current_step": "BLOCKED by safety gate",
        }
    return {
        "safety_result": safety_result,
        "status": PipelineStatus.SAFETY_CHECK,
        "current_step": "Safety check passed",
    }


# ─── Node 6: Compile ──────────────────────────────────────────────────────────


async def compile_acl(state: PipelineState) -> dict:
    if state.status in (PipelineStatus.FAILED, PipelineStatus.BLOCKED):
        return {"current_step": state.current_step}  # pass through, no change
    try:
        compiler = CiscoIOSCompiler(require_snmt())
        compiled = compiler.compile(state.resolved_rule)
        logger.info(
            f"[{state.session_id}] Compiled '{compiled.acl_name}': "
            f"{len(compiled.lines)} line(s) on {compiled.interface}"
        )
        return {
            "compiled_acl": compiled,
            "status": PipelineStatus.COMPILING,
            "current_step": f"Compiled {len(compiled.lines)} ACL line(s)",
        }
    except Exception as e:
        logger.exception("Compiler error")
        return {
            "status": PipelineStatus.FAILED,
            "error": f"Compiler error: {str(e)}",
            "current_step": "Compiler failed",
        }


# ─── Node 7: Batfish verify ───────────────────────────────────────────────────


async def verify_batfish(state: PipelineState) -> dict:
    if state.status in (PipelineStatus.FAILED, PipelineStatus.BLOCKED):
        return {"current_step": state.current_step}  # pass through, no change
    try:
        manager = BatfishManager()
        result = await manager.verify(
            compiled_acl=state.compiled_acl, session_id=state.session_id
        )
        if not result.passed:
            logger.warning(f"Batfish: {result.summary()}")
        return {
            "batfish_result": result,
            "status": PipelineStatus.VERIFYING,
            "current_step": result.summary(),
        }
    except Exception as e:
        logger.warning(f"Batfish unavailable (non-fatal): {e}")
        from app.models.ir import BatfishResult

        return {
            "batfish_result": BatfishResult(
                passed=False, parse_warnings=[f"Batfish unavailable: {str(e)}"]
            ),
            "current_step": f"Batfish skipped: {str(e)[:60]}",
        }


# ─── Node 8: Generate output ──────────────────────────────────────────────────


async def generate_output(state: PipelineState) -> dict:
    if state.status in (PipelineStatus.FAILED, PipelineStatus.BLOCKED):
        return {"current_step": state.current_step}  # pass through, no change
    if not state.compiled_acl:
        return {
            "status": PipelineStatus.FAILED,
            "error": "No compiled ACL",
            "current_step": "Output generation failed",
        }

    final_config = state.compiled_acl.to_cisco_config()

    explanation = ""
    try:
        # Build Batfish flow trace context for the explanation if available
        batfish_context = ""
        if state.batfish_result and state.batfish_result.flow_traces():
            traces = state.batfish_result.flow_traces()
            trace_lines = ["\nBatfish verified the following representative flows:"]
            for t in traces[:3]:  # show max 3 traces
                trace_lines.append(
                    f"  Flow: {t.get('flow', '')}  →  {t.get('action', '')}  "
                    f"(matched: {t.get('matched_line', '')})"
                )
            batfish_context = "\n".join(trace_lines)

        client = get_groq_client()
        explanation = await client.generate_text(
            system_prompt="You are a network documentation assistant. Be concise and technical.",
            user_message=build_explanation_prompt(
                rule_json=state.resolved_rule.model_dump_json(indent=2),
                compiled_config=final_config + batfish_context,
            ),
        )
        explanation = explanation.strip()
    except Exception as e:
        logger.warning(f"Explanation generation failed: {e}")
        explanation = (
            f"Named ACL '{state.compiled_acl.acl_name}' applied "
            f"{state.compiled_acl.direction} on {state.compiled_acl.interface}. "
            f"{len(state.compiled_acl.lines)} rule(s) generated."
        )

    logger.info(f"[{state.session_id}] Pipeline complete")
    return {
        "final_config": final_config,
        "explanation": explanation,
        "status": PipelineStatus.COMPLETE,
        "current_step": "Complete",
    }


# ─── Routing ───────────────────────────────────────────────────────────────────


def route_after_review(state: PipelineState) -> str:
    feedback = (state.human_feedback or "").strip().lower()
    if feedback in ("", "approve", "ok", "looks good", "approved", "yes"):
        return "lint"
    if state.feedback_rounds >= state.max_feedback_rounds:
        logger.warning(f"[{state.session_id}] Max feedback rounds — proceeding")
        return "lint"
    return "resolve_intent"


def route_after_safety(state: PipelineState) -> str:
    return END if state.status == PipelineStatus.BLOCKED else "compile_acl"


def route_after_batfish(state: PipelineState) -> str:
    return "generate_output"


# ─── Graph construction ────────────────────────────────────────────────────────


def build_pipeline_graph() -> StateGraph:
    graph = StateGraph(PipelineState)

    graph.add_node("resolve_intent", resolve_intent)
    graph.add_node("build_rule", build_rule)
    graph.add_node("await_review", await_review)
    graph.add_node("lint", lint)
    graph.add_node("safety_check", safety_check)
    graph.add_node("compile_acl", compile_acl)
    graph.add_node("verify_batfish", verify_batfish)
    graph.add_node("generate_output", generate_output)

    graph.set_entry_point("resolve_intent")
    graph.add_edge("resolve_intent", "build_rule")
    graph.add_edge("build_rule", "await_review")
    graph.add_edge("lint", "safety_check")
    graph.add_edge("compile_acl", "verify_batfish")

    graph.add_conditional_edges(
        "await_review",
        route_after_review,
        {"lint": "lint", "resolve_intent": "resolve_intent"},
    )
    graph.add_conditional_edges(
        "safety_check", route_after_safety, {"compile_acl": "compile_acl", END: END}
    )
    graph.add_conditional_edges(
        "verify_batfish", route_after_batfish, {"generate_output": "generate_output"}
    )
    graph.add_edge("generate_output", END)

    return graph


def create_compiled_graph():
    return build_pipeline_graph().compile(
        checkpointer=MemorySaver(),
        interrupt_before=["await_review"],
    )


_compiled_graph = None


def get_pipeline():
    global _compiled_graph
    if _compiled_graph is None:
        _compiled_graph = create_compiled_graph()
    return _compiled_graph
