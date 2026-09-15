"""
services/report_contract.py
===========================
Formal Schema Definitions, Dataclasses, and Contract Validation for the
Final Investigator Report (Step 5B).

Architectural Invariants & Guarantees:
1. Additive & Post-Hoc: Assembled only after pipeline, ledger, TCE, AERE, and Confidence Engine complete.
2. Presentation-Oriented: The report is an assembly and visualization dossier; it has zero scoring authority.
3. TCE Sovereignty: TCE remains the sole authority for risk_score, trust_score, and verdict.
4. Epistemic Separation: Risk != Trust != Confidence. Grounding validity != Truth != Confidence.
5. Zero LLM / Zero Network: 100% deterministic assembly without external network calls or LLM prompts.
6. Zero Autonomous Enforcement: The report prohibits autonomous actions (blocking, takedowns, suspensions).
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from services.confidence_contract import (
    CALIBRATION_STATUS,
    EVIDENCE_ID_REGEX,
    AbstentionRecommendation
)
from services.evidence_schema import (
    VALID_EVIDENCE_TYPES,
    VALID_SEVERITIES,
    VALID_STATUSES
)
from services.tce_config import (
    SEVERITY_WEIGHTS,
    VERDICT_THRESHOLDS
)

# =====================================================================
# 1. REPORT CONTRACT METADATA & CONSTANTS
# =====================================================================
REPORT_CONTRACT_VERSION: str = "1.0.0"
REPORT_SCHEMA_IDENTIFIER: str = "https://schemas.digital-forensics.local/report/v1.0"

# Canonical TCE Verdicts from services/trust_calculation_engine.py
VALID_TCE_VERDICTS: Set[str] = {
    "unknown",
    "benign",
    "low_risk",
    "suspicious",
    "high_risk",
    "malicious",
    "not_calculated"
}

# Canonical Grounding Statuses from services/aere_grounding_validator.py
VALID_GROUNDING_STATUSES: Set[str] = {
    "GROUNDED",
    "PARTIALLY_GROUNDED",
    "UNGROUNDED",
    "UNCERTAIN"
}

# Canonical Polarities from services/tce_config.py
VALID_POLARITIES: Set[str] = {
    "risk_increasing",
    "risk_reducing",
    "neutral"
}

# Standard Disclaimers & Operational Boundaries
DEFAULT_METHODOLOGICAL_DISCLAIMER: str = (
    "This report synthesizes deterministic multi-agent telemetry, non-linear trust/risk calculation (TCE), "
    "grounded qualitative reasoning (AERE), and deterministic heuristic confidence indexing. "
    "Risk, trust, and confidence represent epistemically distinct dimensions. "
    "Grounding validity confirms citation alignment with collected telemetry, not absolute objective truth. "
    "Confidence scores are uncalibrated prototype heuristics and must not be interpreted as frequentist or Bayesian probabilities."
)

DEFAULT_HUMAN_REVIEW_GUIDANCE: str = (
    "This report is an advisory artifact intended solely to support human forensic investigators. "
    "All findings, contradictions, and telemetry gaps must be reviewed by a qualified human analyst "
    "before making any operational, containment, or legal determination."
)

DEFAULT_PROHIBITED_AUTONOMOUS_ACTIONS: List[str] = [
    "Automated domain or IP blocking",
    "Automated account suspension or credential revocation",
    "Automated infrastructure modification or network routing alterations",
    "Automated legal takedown requests or external abuse dispatch"
]


# =====================================================================
# 2. REPORT COMPONENT DATACLASSES
# =====================================================================

@dataclass
class ReportOverviewSection:
    """High-level investigation overview metadata."""
    investigation_id: Optional[str]
    target: Dict[str, Any]
    investigation_timestamp: Optional[str]
    report_generated_at: str
    execution_status: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ReportAssessmentSection:
    """Authoritative assessment metrics synthesized across TCE and Confidence Engine."""
    tce_verdict: str
    tce_risk_score: Optional[float]
    tce_trust_score: Optional[float]
    composite_confidence: Optional[float]
    evidence_confidence: Optional[float]
    interpretation_confidence: Optional[float]
    abstention_flag: bool
    abstention_reason: str
    confidence_calibration_status: str = field(default=CALIBRATION_STATUS)
    epistemic_disclaimer: str = field(
        default="Risk != Trust != Confidence. Confidence indices are uncalibrated deterministic heuristics."
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class KeyFindingItem:
    """Individual normalized evidence finding formatted for presentation."""
    evidence_id: str
    agent_id: int
    agent_name: str
    finding: str
    category: str
    severity: str
    evidence_type: str
    evidence_strength: float
    polarity: str
    tce_contribution: Optional[float]
    is_duplicate: bool = False
    original_evidence_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GroundedClaimItem:
    """Structured claim evaluation from the AERE Grounding Validator."""
    claim_id: str
    section: str
    grounding_status: str
    grounding_source: str
    cited_evidence_ids: List[str] = field(default_factory=list)
    valid_evidence_ids: List[str] = field(default_factory=list)
    invalid_evidence_ids: List[str] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ContradictionReportItem:
    """Cross-agent contradiction relationship extracted from the ledger."""
    relationship_id: str
    source_evidence_id: str
    target_evidence_id: str
    source_agent_name: str
    target_agent_name: str
    source_finding: str
    target_finding: str
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceLineageItem:
    """Audit lineage record mapping an active evidence item back to source provenance."""
    evidence_id: str
    agent_id: int
    agent_name: str
    finding: str
    raw_value: Any
    evidence_type: str
    severity: str
    evidence_strength: float
    polarity: str
    provenance: Dict[str, Any]
    status: str
    tce_final_contribution: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigatorReportPayload:
    """
    PROPOSED STEP 5B DATA CONTRACT.
    Formal Output Payload for the Final Investigator Report.
    """
    # Contract & Timestamps
    report_version: str
    generated_at: str
    
    # Core Summary Sections
    overview: ReportOverviewSection
    assessment: ReportAssessmentSection
    
    # Polarity-Partitioned Key Findings (Presentation-Only Deterministic Ordering)
    risk_increasing_findings: List[KeyFindingItem]
    risk_reducing_findings: List[KeyFindingItem]
    neutral_observations: List[KeyFindingItem]
    
    # Qualitative Reasoning & Grounding (AERE)
    aere_reasoning_status: str
    investigation_summary: str
    detailed_findings: List[Dict[str, Any]]
    grounded_claims: List[GroundedClaimItem]
    unsubstantiated_claims_count: int
    grounded_citation_ratio: float
    
    # Structural & Confidence Diagnostics
    total_active_evidence_items: int
    provenance_gate_passed: bool
    evidence_lineage: List[EvidenceLineageItem]
    contradictions: List[ContradictionReportItem]
    contradiction_score: float
    
    # Telemetry Coverage & Reliability Breakdown
    observed_dimensions: List[str]
    inactive_telemetry_gaps: Dict[str, str]
    telemetry_coverage_score: float
    source_reliability_score: float
    corroboration_score: float
    concordant_cluster_count: int
    concordant_clusters: List[str]
    
    # Human Review & Operational Boundary Disclaimers
    methodological_disclaimer: str = field(default=DEFAULT_METHODOLOGICAL_DISCLAIMER)
    human_review_guidance: str = field(default=DEFAULT_HUMAN_REVIEW_GUIDANCE)
    prohibited_autonomous_actions: List[str] = field(
        default_factory=lambda: list(DEFAULT_PROHIBITED_AUTONOMOUS_ACTIONS)
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =====================================================================
# 3. CONTRACT VALIDATION FUNCTION
# =====================================================================
def validate_investigator_report(
    payload: Union[InvestigatorReportPayload, Dict[str, Any]]
) -> Tuple[bool, List[str]]:
    """
    Validate that an Investigator Report payload strictly conforms to the
    Step 5B Final Report Contract.

    Enforces:
    1. Presence of all required sections and fields.
    2. Exact conformance of enums and controlled taxonomies (TCE verdicts, severities, evidence types, polarities).
    3. Structural syntax of all Evidence IDs.
    4. Bounded intervals for all numerical scores [0.0, 100.0] and ratios [0.0, 1.0].
    5. Strict absence of forbidden recalculated scoring keys.

    Returns:
        (is_valid: bool, errors: List[str])
    """
    errors: List[str] = []

    if isinstance(payload, InvestigatorReportPayload):
        data = payload.to_dict()
    elif isinstance(payload, dict):
        data = payload
    else:
        return False, ["Payload must be a dict or InvestigatorReportPayload instance."]

    # 1. Version and Timestamps
    if not data.get("report_version"):
        errors.append("Missing required field: 'report_version'.")
    if not data.get("generated_at"):
        errors.append("Missing required field: 'generated_at'.")

    # 2. Overview Section
    overview = data.get("overview")
    if not isinstance(overview, dict):
        errors.append("Missing or invalid 'overview' section; must be a dict.")
    else:
        for f in ["target", "report_generated_at", "execution_status"]:
            if f not in overview:
                errors.append(f"Overview section missing required field: '{f}'.")

    # 3. Assessment Section
    assessment = data.get("assessment")
    if not isinstance(assessment, dict):
        errors.append("Missing or invalid 'assessment' section; must be a dict.")
    else:
        verdict = assessment.get("tce_verdict")
        if verdict not in VALID_TCE_VERDICTS:
            errors.append(f"Invalid 'tce_verdict': '{verdict}'. Must be one of {sorted(VALID_TCE_VERDICTS)}.")

        # Validate numeric bounds on scores if present
        for score_key in [
            "tce_risk_score",
            "tce_trust_score",
            "composite_confidence",
            "evidence_confidence",
            "interpretation_confidence"
        ]:
            val = assessment.get(score_key)
            if val is not None:
                if not isinstance(val, (int, float)):
                    errors.append(f"Assessment field '{score_key}' must be numeric, got {type(val).__name__}.")
                elif not (0.0 <= float(val) <= 100.0):
                    errors.append(f"Assessment field '{score_key}' out of bounds [0.0, 100.0]: {val}.")

        if "abstention_flag" not in assessment or not isinstance(assessment.get("abstention_flag"), bool):
            errors.append("Assessment section missing or invalid boolean 'abstention_flag'.")

    # 4. Findings Lists
    finding_groups = [
        ("risk_increasing_findings", "risk_increasing"),
        ("risk_reducing_findings", "risk_reducing"),
        ("neutral_observations", "neutral")
    ]
    for group_key, expected_polarity in finding_groups:
        items = data.get(group_key)
        if not isinstance(items, list):
            errors.append(f"Section '{group_key}' must be a list.")
            continue
        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                errors.append(f"Item at {group_key}[{idx}] must be a dict.")
                continue
            ev_id = item.get("evidence_id", "")
            if not EVIDENCE_ID_REGEX.match(str(ev_id)):
                errors.append(f"Item at {group_key}[{idx}] has invalid Evidence ID syntax: '{ev_id}'.")
            sev = item.get("severity")
            if sev not in VALID_SEVERITIES:
                errors.append(f"Item at {group_key}[{idx}] has invalid severity: '{sev}'.")
            etype = item.get("evidence_type")
            if etype not in VALID_EVIDENCE_TYPES:
                errors.append(f"Item at {group_key}[{idx}] has invalid evidence_type: '{etype}'.")
            pol = item.get("polarity")
            if pol not in VALID_POLARITIES:
                errors.append(f"Item at {group_key}[{idx}] has invalid polarity: '{pol}'.")

    # 5. Numerical Diagnostic Scores Bounds
    diag_scores = [
        "contradiction_score",
        "telemetry_coverage_score",
        "source_reliability_score",
        "corroboration_score"
    ]
    for d_score in diag_scores:
        d_val = data.get(d_score)
        if d_val is None:
            errors.append(f"Missing required diagnostic score: '{d_score}'.")
        elif not isinstance(d_val, (int, float)):
            errors.append(f"Diagnostic score '{d_score}' must be numeric, got {type(d_val).__name__}.")
        elif not (0.0 <= float(d_val) <= 100.0):
            errors.append(f"Diagnostic score '{d_score}' out of bounds [0.0, 100.0]: {d_val}.")

    # Ratio bounds [0.0, 1.0]
    gc_ratio = data.get("grounded_citation_ratio")
    if gc_ratio is None:
        errors.append("Missing required field: 'grounded_citation_ratio'.")
    elif not isinstance(gc_ratio, (int, float)):
        errors.append(f"'grounded_citation_ratio' must be numeric, got {type(gc_ratio).__name__}.")
    elif not (0.0 <= float(gc_ratio) <= 1.0):
        errors.append(f"'grounded_citation_ratio' out of bounds [0.0, 1.0]: {gc_ratio}.")

    # Integer checks
    for int_field, min_val, max_val in [
        ("concordant_cluster_count", 0, 7),
        ("total_active_evidence_items", 0, 10000),
        ("unsubstantiated_claims_count", 0, 10000)
    ]:
        val = data.get(int_field)
        if val is None:
            errors.append(f"Missing required integer field: '{int_field}'.")
        elif not isinstance(val, int):
            errors.append(f"Field '{int_field}' must be an integer, got {type(val).__name__}.")
        elif not (min_val <= val <= max_val):
            errors.append(f"Field '{int_field}' out of bounds [{min_val}, {max_val}]: {val}.")

    # 6. Boolean & Disclaimers
    if "provenance_gate_passed" not in data or not isinstance(data.get("provenance_gate_passed"), bool):
        errors.append("Field 'provenance_gate_passed' must be a boolean.")

    for text_field in ["methodological_disclaimer", "human_review_guidance"]:
        if not data.get(text_field) or not isinstance(data.get(text_field), str):
            errors.append(f"Missing or invalid required text disclaimer: '{text_field}'.")

    prohibited = data.get("prohibited_autonomous_actions")
    if not isinstance(prohibited, list) or len(prohibited) == 0:
        errors.append("Field 'prohibited_autonomous_actions' must be a non-empty list.")

    # 7. Grounded Claims & Contradictions Check
    g_claims = data.get("grounded_claims", [])
    if isinstance(g_claims, list):
        for idx, gc in enumerate(g_claims):
            if isinstance(gc, dict):
                c_status = gc.get("grounding_status")
                if c_status not in VALID_GROUNDING_STATUSES:
                    errors.append(f"Grounded claim at index {idx} has invalid status: '{c_status}'.")

    # 8. Forbidden Keys (Ensure no rogue recalculation or probability overrides)
    forbidden_keys = {
        "recalculated_risk_score",
        "recalculated_trust_score",
        "override_verdict",
        "malicious_probability",
        "autonomous_action_authorized"
    }
    for fk in forbidden_keys:
        if fk in data:
            errors.append(f"Forbidden key '{fk}' detected in investigator report payload.")

    return (len(errors) == 0, errors)
