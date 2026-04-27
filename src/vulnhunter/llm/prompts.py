"""Prompts and utilities for the six-pass vulnhunter analysis pipeline.

This module provides:
- System prompts for each pass
- JSON schemas/expected shapes for structured outputs
- Helpers to manage a 256kB context window and to trim code context
- Lightweight context keying for caching in the pipeline
"""

from __future__ import annotations

import json
import hashlib
from typing import Any, Dict, Optional

from vulnhunter.recon.models.recon_report import ReconReport


MAX_CONTEXT_CHARS = 256 * 1024  # 256 KB window

VERIFICATION_DIRECTIVE = """\
---
VERIFICATION DIRECTIVE:
- Double-check every claim against the code before asserting it.
- State uncertainty explicitly; do not fabricate line numbers, function names, or values.
- If you cannot verify a claim from the code provided, say so and abstain.
- Prioritize accuracy over speed or completeness.
"""


def trim_context(text: str, max_chars: int = MAX_CONTEXT_CHARS) -> str:
    """Return a windowed context containing at most max_chars characters.

    This is a simple byte-oriented trim that preserves the most recent content,
    which is typically the code or vulnerability context, while respecting the
    256KB window constraint.
    """
    if len(text) <= max_chars:
        return text
    return text[-max_chars:]


def _hash_string(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def context_key(code: str, pass_number: int) -> str:
    h = _hash_string(code)
    return f"ctx:{pass_number}:{h}"


def build_recon_summary(recon: Optional[ReconReport]) -> str:
    """Build a ≤1KB recon summary block for injection into pass prompts."""
    if recon is None:
        return ""

    lines = ["# Protocol Context"]
    lines.append(f"- Type: {recon.protocol_type or 'unknown'}")
    lines.append(f"- Ecosystems: {', '.join(recon.ecosystems) if recon.ecosystems else 'unknown'}")

    # Top 5 hot zones
    hot = recon.hot_zones[:5]
    if hot:
        lines.append("- Hot zones:")
        for zone in hot:
            lines.append(f"  - {zone.file_path}: {zone.reason}")
    else:
        lines.append("- Hot zones: none identified")

    # Attack surface counts
    attack_surface = (
        f"external_calls={recon.external_call_sites}, "
        f"payable={recon.payable_functions}, "
        f"oracle_deps={recon.oracle_dependencies}, "
        f"assembly={recon.assembly_blocks}"
    )
    lines.append(f"- Attack surface: {attack_surface}")
    lines.append(f"- Build status: {recon.build_status}")

    summary = "\n".join(lines)
    # Hard cap at 1KB
    if len(summary) > 1024:
        summary = summary[:1021] + "..."
    return summary


def build_pass_prompt(pass_number: int, context: Dict[str, Any]) -> str:
    """Return the prompt text for a given pass number and the current context.

    The prompts are designed to be self-contained and rely on the 6-pass schema
    described in the Vuln Hunter methodology.
    """
    prompts = {
        1: (
            "Pass 1/6 - Protocol Understanding:\n\n"
            "You are Kimi, an LLM specialized in comprehending security protocols. "
            "Given a target protocol description and its public code snippet, produce a concise, structured understanding of the protocol's purpose, actors, token flows, and main attack surface. Output a JSON object with fields: pass, understanding, key_entities, and suggested_success_metrics."
        ),
        2: (
            "Pass 2/6 - Attack Surface Mapping:\n\n"
            "Map external entry points, state-changing functions, and any privileged operations. Provide a JSON object with fields: pass, surface_map, high_risk_endpoints, and a short call graph summary."
        ),
        3: (
            "Pass 3/6 - Invariant Violation Analysis:\n\n"
            "Analyze potential invariant violations, boundary conditions, and assumptions, and return a JSON object with fields: pass, invariants, potential_violation_scenarios, and suggested mitigations."
        ),
        4: (
            "Pass 4/6 - Cross-Function Interaction:\n\n"
            "Evaluate interactions across function boundaries, reentrancy risks, and external calls. Output a JSON object with fields: pass, cross_call_risks, dependency_chains, and recommended safeguards."
        ),
        5: (
            "Pass 5/6 - Adversarial Modeling:\n\n"
            "Threat modeling: assume an attacker with arbitrary control over inputs. Provide a JSON object with fields: pass, threat_model, attacker_capabilities, and potential exploit paths."
        ),
        6: (
            "Pass 6/6 - Boundary & Edge Cases:\n\n"
            "Enumerate boundary conditions and edge-case scenarios (zero/empty, max values, timing). Output a JSON object with fields: pass, edge_cases, testing_plan, and coverage gaps."
        ),
    }
    base = prompts.get(pass_number, prompts[1])

    parts: list[str] = [base]

    # Inject recon summary before code context
    recon = context.get("recon")
    if recon is not None:
        recon_summary = build_recon_summary(recon)
        if recon_summary:
            parts.append("\n\n" + recon_summary)

    # Context can be appended to the prompt to aid grounding, but keep under token limits
    if context:
        code = context.get("code", "")
        findings_count = len(context.get("findings", []))
        grounding = f"\n\nContext:\n{code}\nFindings so far: {findings_count}"
        parts.append(grounding)

    parts.append("\n\n" + VERIFICATION_DIRECTIVE)
    return "".join(parts)


def parse_json_safely(text: str) -> Any:
    """Best-effort JSON parse; returns Python object or raw string on failure."""
    try:
        return json.loads(text)
    except Exception:
        # Try to extract a JSON object substring if mixed text is returned
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1:
            try:
                return json.loads(text[start : end + 1])
            except Exception:
                pass
        return text
