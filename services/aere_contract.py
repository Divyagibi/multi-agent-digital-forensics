"""
services/aere_contract.py
=========================
Formal Schema Definitions & Contract Validation for the AI Evidence Reasoning Engine (AERE).

Defines:
1. Formal input contract for AERE (matching AEREInputBuilder payload specification).
2. Formal output contract for AERE structured forensic reasoning.
3. Strict schema validation functions for inputs and outputs.
4. Qualitative reasoning boundaries prohibiting numerical risk/trust/confidence recalculation.
5. Structural Evidence ID syntax validation rules.
"""

import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union


# =====================================================================
# 1. CONTRACT VERSION & METADATA CONSTANTS
# =====================================================================
AERE_CONTRACT_VERSION: str = "1.0.0"
AERE_SCHEMA_IDENTIFIER: str = "https://schemas.digital-forensics.local/aere/v1.0"

# Evidence ID format: E<agent_id 1-18>-<index 01+> with optional -DUP<n> suffix
# e.g., E1-01, E12-03, E18-01, E8-01-DUP2
EVIDENCE_ID_REGEX: re.Pattern = re.compile(r"^E(1[0-8]|[1-9])-\d{2,}(?:-DUP\d+)?$")

# Permitted forensic significance levels
FORENSIC_SIGNIFICANCE_LEVELS: Set[str] = {
    "critical",
    "high",
    "medium",
    "low",
    "informational"
}

# Permitted grounding validation statuses
GROUNDING_VALIDATION_STATUSES: Set[str] = {
    "VALIDATED",
    "UNVALIDATED",
    "FAILED",
    "SKIPPED"
}

# Forbidden fields in AERE output to enforce strict separation from TCE / Confidence Engine
FORBIDDEN_OUTPUT_FIELDS: Set[str] = {
    "risk_score",
    "trust_score",
    "confidence_score",
    "numerical_confidence",
    "confidence_interval",
    "probability",
    "malicious_probability",
    "alternative_verdict",
    "recalculated_risk",
    "recalculated_trust"
}


# =====================================================================
# 2. EVIDENCE ID SYNTAX VALIDATOR
# =====================================================================
def is_valid_evidence_id_syntax(evidence_id: Any) -> bool:
    """
    Check whether a string conforms to the standard Evidence ID syntax.
    
    NOTE: This is structural syntax validation only. Verification of whether
    the ID actually exists in the current ledger is performed by the Grounding Validator.
    """
    if not isinstance(evidence_id, str) or not evidence_id.strip():
        return False
    return bool(EVIDENCE_ID_REGEX.match(evidence_id.strip()))


# =====================================================================
# 3. AERE INPUT CONTRACT VALIDATION
# =====================================================================
def validate_aere_input(payload: Any) -> Tuple[bool, List[str]]:
    """
    Validate that an input payload conforming to AEREInputBuilder output
    is structurally sound and ready for AERE reasoning.
    
    Returns:
        (is_valid: bool, errors: List[str])
    """
    errors: List[str] = []

    if not isinstance(payload, dict):
        return False, ["Input payload must be a dictionary."]

    # Required top-level sections
    required_top_level = [
        "investigation_metadata",
        "target",
        "tce_result",
        "ledger_summary",
        "agent_execution_summary",
        "builder_telemetry"
    ]
    for key in required_top_level:
        if key not in payload:
            errors.append(f"Missing required top-level key: '{key}'")

    if errors:
        return False, errors

    # 1. Validate investigation_metadata
    inv_meta = payload.get("investigation_metadata")
    if not isinstance(inv_meta, dict):
        errors.append("'investigation_metadata' must be a dictionary.")
    else:
        if "schema_version" not in inv_meta:
            errors.append("'investigation_metadata' must contain 'schema_version'.")
        if "ledger_sha256" not in inv_meta:
            errors.append("'investigation_metadata' must contain 'ledger_sha256'.")

    # 2. Validate target
    target = payload.get("target")
    if not isinstance(target, dict):
        errors.append("'target' must be a dictionary.")

    # 3. Validate tce_result
    tce = payload.get("tce_result")
    if not isinstance(tce, dict):
        errors.append("'tce_result' must be a dictionary.")

    # 4. Validate ledger_summary
    ledger_sum = payload.get("ledger_summary")
    if not isinstance(ledger_sum, dict):
        errors.append("'ledger_summary' must be a dictionary.")
    else:
        entries = ledger_sum.get("entries")
        if not isinstance(entries, list):
            errors.append("'ledger_summary.entries' must be a list.")
        else:
            for idx, entry in enumerate(entries):
                if not isinstance(entry, dict):
                    errors.append(f"Entry at index {idx} must be a dictionary.")
                    continue
                ev_id = entry.get("evidence_id")
                if not ev_id or not is_valid_evidence_id_syntax(ev_id):
                    errors.append(f"Entry at index {idx} has missing or invalid evidence_id syntax: '{ev_id}'.")
                if "severity" not in entry:
                    errors.append(f"Entry '{ev_id}' is missing required 'severity' field.")
                if "status" not in entry:
                    errors.append(f"Entry '{ev_id}' is missing required 'status' field.")

        rels = ledger_sum.get("relationships")
        if not isinstance(rels, list):
            errors.append("'ledger_summary.relationships' must be a list.")
        else:
            for idx, rel in enumerate(rels):
                if not isinstance(rel, dict):
                    errors.append(f"Relationship at index {idx} must be a dictionary.")
                    continue
                if "source_evidence_id" not in rel or "target_evidence_id" not in rel:
                    errors.append(f"Relationship at index {idx} missing source or target evidence ID.")
                if "relationship_type" not in rel:
                    errors.append(f"Relationship at index {idx} missing 'relationship_type'.")

    # 5. Validate agent_execution_summary
    agent_exec = payload.get("agent_execution_summary")
    if not isinstance(agent_exec, dict):
        errors.append("'agent_execution_summary' must be a dictionary.")

    return (len(errors) == 0), errors


# =====================================================================
# 4. AERE OUTPUT CONTRACT VALIDATION
# =====================================================================
def validate_aere_output(payload: Any) -> Tuple[bool, List[str]]:
    """
    Validate that an AERE reasoning output payload conforms strictly to the
    formal structured forensic schema.
    
    Enforces:
    1. Presence and type correctness of all required top-level fields.
    2. Strict absence of forbidden numerical scoring/recalculation fields.
    3. Structural validity of all cited Evidence IDs.
    4. Conformance of nested findings, chains, contradictions, gaps, and metadata.
    
    Returns:
        (is_valid: bool, errors: List[str])
    """
    errors: List[str] = []

    if not isinstance(payload, dict):
        return False, ["AERE output payload must be a dictionary."]

    # 1. Enforce strict absence of forbidden scoring / confidence fields
    for forbidden_field in FORBIDDEN_OUTPUT_FIELDS:
        if forbidden_field in payload:
            errors.append(
                f"Forbidden field detected in AERE output: '{forbidden_field}'. "
                "AERE must not recalculate risk, trust, or numerical confidence."
            )

    # 2. Check required top-level keys
    required_sections = [
        "investigation_summary",
        "primary_findings",
        "evidence_chains",
        "contradiction_analyses",
        "alternative_explanations",
        "investigative_gaps",
        "tce_interpretation",
        "reasoning_metadata"
    ]
    for sec in required_sections:
        if sec not in payload:
            errors.append(f"Missing required top-level section: '{sec}'")

    if errors:
        return False, errors

    # 3. Validate investigation_summary
    inv_summary = payload.get("investigation_summary")
    if not isinstance(inv_summary, str) or not inv_summary.strip():
        errors.append("'investigation_summary' must be a non-empty string.")

    # 4. Validate primary_findings
    findings = payload.get("primary_findings")
    if not isinstance(findings, list):
        errors.append("'primary_findings' must be a list.")
    else:
        for idx, f in enumerate(findings):
            if not isinstance(f, dict):
                errors.append(f"Primary finding at index {idx} must be a dictionary.")
                continue
            for req_field in ["finding_id", "topic", "summary", "grounded_evidence_ids", "forensic_significance", "interpretation"]:
                if req_field not in f:
                    errors.append(f"Finding at index {idx} missing required field '{req_field}'.")

            sig = str(f.get("forensic_significance", "")).lower()
            if sig not in FORENSIC_SIGNIFICANCE_LEVELS:
                errors.append(f"Finding at index {idx} has invalid forensic_significance: '{sig}'.")

            eids = f.get("grounded_evidence_ids", [])
            if not isinstance(eids, list):
                errors.append(f"Finding at index {idx} 'grounded_evidence_ids' must be a list.")
            else:
                for eid in eids:
                    if not is_valid_evidence_id_syntax(eid):
                        errors.append(f"Finding at index {idx} contains invalid evidence_id syntax: '{eid}'.")

    # 5. Validate evidence_chains
    chains = payload.get("evidence_chains")
    if not isinstance(chains, list):
        errors.append("'evidence_chains' must be a list.")
    else:
        for idx, ch in enumerate(chains):
            if not isinstance(ch, dict):
                errors.append(f"Evidence chain at index {idx} must be a dictionary.")
                continue
            for req_field in ["chain_id", "theme", "evidence_ids", "narrative"]:
                if req_field not in ch:
                    errors.append(f"Evidence chain at index {idx} missing required field '{req_field}'.")
            eids = ch.get("evidence_ids", [])
            if not isinstance(eids, list):
                errors.append(f"Evidence chain at index {idx} 'evidence_ids' must be a list.")
            else:
                for eid in eids:
                    if not is_valid_evidence_id_syntax(eid):
                        errors.append(f"Evidence chain at index {idx} contains invalid evidence_id syntax: '{eid}'.")

    # 6. Validate contradiction_analyses
    contradictions = payload.get("contradiction_analyses")
    if not isinstance(contradictions, list):
        errors.append("'contradiction_analyses' must be a list.")
    else:
        for idx, c in enumerate(contradictions):
            if not isinstance(c, dict):
                errors.append(f"Contradiction analysis at index {idx} must be a dictionary.")
                continue
            for req_field in ["conflict_id", "conflicting_evidence_ids", "topic", "analysis", "material_impact"]:
                if req_field not in c:
                    errors.append(f"Contradiction at index {idx} missing required field '{req_field}'.")
            eids = c.get("conflicting_evidence_ids", [])
            if not isinstance(eids, list):
                errors.append(f"Contradiction at index {idx} 'conflicting_evidence_ids' must be a list.")
            else:
                for eid in eids:
                    if not is_valid_evidence_id_syntax(eid):
                        errors.append(f"Contradiction at index {idx} contains invalid evidence_id syntax: '{eid}'.")

    # 7. Validate alternative_explanations
    alts = payload.get("alternative_explanations")
    if not isinstance(alts, list):
        errors.append("'alternative_explanations' must be a list.")
    else:
        for idx, alt in enumerate(alts):
            if not isinstance(alt, dict):
                errors.append(f"Alternative explanation at index {idx} must be a dictionary.")
                continue
            for req_field in ["evidence_ids", "primary_interpretation", "alternative_interpretation", "counter_evidence_ids", "plausibility_assessment"]:
                if req_field not in alt:
                    errors.append(f"Alternative explanation at index {idx} missing required field '{req_field}'.")
            for eid_field in ["evidence_ids", "counter_evidence_ids"]:
                eids = alt.get(eid_field, [])
                if not isinstance(eids, list):
                    errors.append(f"Alternative explanation at index {idx} '{eid_field}' must be a list.")
                else:
                    for eid in eids:
                        if not is_valid_evidence_id_syntax(eid):
                            errors.append(f"Alternative explanation at index {idx} contains invalid evidence_id syntax in '{eid_field}': '{eid}'.")

    # 8. Validate investigative_gaps
    gaps = payload.get("investigative_gaps")
    if not isinstance(gaps, list):
        errors.append("'investigative_gaps' must be a list.")
    else:
        for idx, gap in enumerate(gaps):
            if not isinstance(gap, dict):
                errors.append(f"Investigative gap at index {idx} must be a dictionary.")
                continue
            for req_field in ["gap_id", "unobserved_dimension", "reason", "recommended_action"]:
                if req_field not in gap:
                    errors.append(f"Investigative gap at index {idx} missing required field '{req_field}'.")

    # 9. Validate tce_interpretation
    tce_interp = payload.get("tce_interpretation")
    if not isinstance(tce_interp, dict):
        errors.append("'tce_interpretation' must be a dictionary.")
    else:
        for req_field in ["mathematical_alignment", "verdict_support"]:
            if req_field not in tce_interp or not isinstance(tce_interp[req_field], str):
                errors.append(f"'tce_interpretation' missing required string field '{req_field}'.")

    # 10. Validate reasoning_metadata
    meta = payload.get("reasoning_metadata")
    if not isinstance(meta, dict):
        errors.append("'reasoning_metadata' must be a dictionary.")
    else:
        required_meta_fields = [
            "engine_version",
            "prompt_version",
            "provider_name",
            "model_id",
            "generation_temperature",
            "grounding_validation_status",
            "referenced_evidence_count",
            "invalid_evidence_ids_detected"
        ]
        for mf in required_meta_fields:
            if mf not in meta:
                errors.append(f"'reasoning_metadata' missing required field '{mf}'.")

        status = meta.get("grounding_validation_status")
        if status not in GROUNDING_VALIDATION_STATUSES:
            errors.append(f"'reasoning_metadata.grounding_validation_status' has invalid status: '{status}'.")

        invalid_ids = meta.get("invalid_evidence_ids_detected")
        if not isinstance(invalid_ids, list):
            errors.append("'reasoning_metadata.invalid_evidence_ids_detected' must be a list.")

    return (len(errors) == 0), errors
