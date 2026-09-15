"""
services/confidence_contract.py
===============================
Formal Schema Definitions, Taxonomies, and Contract Validation for the
Confidence Engine (Step 4B).

Architectural Rule:
    Confidence Engine is additive, post-hoc, deterministic, and non-LLM.
    TCE remains the sole authority for risk_score, trust_score, and verdict.
    Confidence Engine NEVER recalculates, overrides, or modifies TCE outputs,
    and TCE scores never enter Confidence Engine mathematics.

Classification:
    All confidence indices (Evidence Confidence, Interpretation Fidelity, Composite Confidence)
    represent UNCALIBRATED_DETERMINISTIC_HEURISTIC prototype diagnostics, NOT frequentist
    or Bayesian probabilities.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

# =====================================================================
# 1. CONTRACT VERSION & METADATA CONSTANTS
# =====================================================================
CONFIDENCE_CONTRACT_VERSION: str = "1.0.0"
CONFIDENCE_SCHEMA_IDENTIFIER: str = "https://schemas.digital-forensics.local/confidence/v1.0"
CALIBRATION_STATUS: str = "UNCALIBRATED_DETERMINISTIC_HEURISTIC"

# Canonical Evidence ID syntax (alphanumeric, e.g., E1-01, E16-02, E8-01-DUP2)
EVIDENCE_ID_REGEX: re.Pattern = re.compile(r"^E(1[0-8]|[1-9])-\d{2,}(?:-DUP\d+)?$")


# =====================================================================
# 2. SEVEN DISJOINT OPERATIONAL SOURCE CLUSTERS (ENGINEERING PARTITION)
# =====================================================================
# Operational source clusters are engineering approximations used for dependency
# and collinearity control. They are not statistically independent sources.

CLUSTER_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "K_InfraNet": {
        "name": "Infrastructure & Network",
        "agents": {1, 2, 5, 16},
        "description": "Domain WHOIS, DNS routing, URL lexical syntax, and active network security headers/ports."
    },
    "K_Crypto": {
        "name": "Cryptographic & Transport",
        "agents": {3},
        "description": "TLS/SSL certificates, X.509 chains, cipher suites, expiration, and cryptographic validity."
    },
    "K_IntelMalw": {
        "name": "Threat Intel & Malware",
        "agents": {6, 17},
        "description": "Multi-source threat feeds, blocklists, YARA static signatures, and malware indicators."
    },
    "K_ContentTech": {
        "name": "Content & Technology",
        "agents": {4, 7, 11},
        "description": "DOM structure, web server/CMS technical fingerprinting, linguistic quality, and scam urgency keywords."
    },
    "K_BehavVisual": {
        "name": "Behavioral & Visual UI",
        "agents": {8, 9, 10},
        "description": "Client-side behavior, form harvesting heuristics, visual brand matching, screenshots, and OCR."
    },
    "K_OSINTTrust": {
        "name": "OSINT, History & Trust",
        "agents": {12, 13, 14, 15},
        "description": "Contact validation, social presence OSINT, Wayback Machine history, and consumer reviews/sentiment."
    },
    "K_QR": {
        "name": "Physical & QR Modality",
        "agents": {18},
        "description": "2D barcode payload decoding, obfuscation analysis, error correction, and redirect chain parsing."
    }
}

# Reverse mapping: agent_id (int) -> cluster_id (str)
AGENT_CLUSTER_MAP: Dict[int, str] = {}
for cid, cdata in CLUSTER_DEFINITIONS.items():
    for aid in cdata["agents"]:
        AGENT_CLUSTER_MAP[aid] = cid


# =====================================================================
# 3. FROZEN PROTOTYPE PARAMETERS (UNCALIBRATED)
# =====================================================================
# These are declared prototype parameters subject to empirical calibration.
DEFAULT_TYPE_PRIORS: Dict[str, float] = {
    "deterministic": 1.00,
    "external_source": 0.85,
    "threat_intelligence": 0.80,
    "historical": 0.70,
    "inference": 0.50,
    "subjective": 0.30
}

DEFAULT_LAMBDA_COR: float = 0.45          # Corroboration decay rate (asymptotic to 100.0)
DEFAULT_BETA_CONTRA: float = 2.00         # Contradiction penalty multiplier
DEFAULT_AERE_FALLBACK_PRIOR: float = 50.0 # Uncalibrated policy prior for fallback reasoning
DEFAULT_ALPHA_COMP: float = 0.30          # Minimum evidence baseline retention in overall confidence
DEFAULT_EVIDENCE_THRESHOLD: float = 35.0  # Prototype workflow staging eligibility threshold


# =====================================================================
# 4. CONTROLLED TAXONOMIES & STATUS ENUMS
# =====================================================================
class AbstentionRecommendation:
    """Taxonomy of workflow recommendation states emitted by the Confidence Engine."""
    AUTOMATION_ELIGIBLE_BY_UNCALIBRATED_PROTOTYPE_POLICY = "AUTOMATION_ELIGIBLE_BY_UNCALIBRATED_PROTOTYPE_POLICY"
    ABSTAIN_INSUFFICIENT_EVIDENCE = "ABSTAIN_INSUFFICIENT_EVIDENCE"
    ABSTAIN_EVIDENTIARY_CONFLICT = "ABSTAIN_EVIDENTIARY_CONFLICT"
    ABSTAIN_INTEGRITY_FAILURE = "ABSTAIN_INTEGRITY_FAILURE"
    REVIEW_REQUIRED_UNGROUNDED = "REVIEW_REQUIRED_UNGROUNDED"
    REVIEW_REQUIRED_LOW_CONFIDENCE = "REVIEW_REQUIRED_LOW_CONFIDENCE"


class InterpretationSemanticState:
    """Semantic states for AERE interpretation fidelity."""
    INTERPRETATION_GROUNDED = "INTERPRETATION_GROUNDED"
    INTERPRETATION_DEGRADED_FALLBACK = "INTERPRETATION_DEGRADED_FALLBACK"
    INTERPRETATION_UNAVAILABLE = "INTERPRETATION_UNAVAILABLE"


# =====================================================================
# 5. DATA STRUCTURES & PAYLOAD MODELS
# =====================================================================
@dataclass
class EvidenceConfidenceMetrics:
    """Detailed mathematical breakdown of Evidence Confidence (C_ev)."""
    telemetry_coverage_score: float     # Phi_cov [0.0 - 100.0]
    source_reliability_score: float     # Phi_rel [0.0 - 100.0]
    corroboration_score: float          # Phi_cor [0.0 - 100.0]
    contradiction_score: float          # Phi_contra [0.0 - 100.0]
    provenance_gate_passed: bool        # G_prov == 1
    evidence_confidence: float          # C_ev [0.0 - 100.0]
    
    concordant_cluster_count: int       # N_concordant_clusters [0 - 7]
    concordant_clusters: List[str]      # Names of concordant clusters
    contradiction_ratio: float          # gamma_contra [0.0 - 1.0]
    active_evidence_count: int          # Count of active evidence items evaluated

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InterpretationConfidenceMetrics:
    """Detailed mathematical breakdown of Interpretation Fidelity Confidence (C_interp)."""
    grounded_citation_ratio: float      # rho_ground [0.0 - 1.0]
    aere_execution_state: str           # ReasoningStatus ('success', 'fallback', 'rejected', 'error')
    grounding_status: str               # GroundingStatus ('GROUNDED', 'UNGROUNDED', etc.)
    unsubstantiated_claims_count: int   # Count of ungrounded factual claims
    total_citations_emitted: int        # Total citations in reasoning
    valid_citations_count: int          # Validated Evidence ID citations
    semantic_state: str                 # InterpretationSemanticState
    interpretation_confidence: float    # C_interp [0.0 - 100.0]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ConfidenceOutputPayload:
    """
    Formal Output Contract for the Confidence Engine (Step 4B).
    Explicitly distinguishes field ownership across five distinct authority tiers.
    """
    # =========================================================================
    # TIER A: CONFIDENCE ENGINE COMPUTED (Mathematical Authority: CE)
    # =========================================================================
    evidence_confidence: float
    interpretation_confidence: float
    composite_confidence: float
    
    telemetry_coverage_score: float
    source_reliability_score: float
    corroboration_score: float
    contradiction_score: float
    provenance_gate_passed: bool
    
    grounded_citation_ratio: float
    concordant_cluster_count: int
    contradiction_ratio: float
    
    abstention_flag: bool
    abstention_reason: str
    calibration_status: str = field(default=CALIBRATION_STATUS)

    # =========================================================================
    # TIER B: LEDGER-DERIVED (Structural Authority: EvidenceLedger)
    # =========================================================================
    total_active_evidence_items: int = 0
    applicable_dimensions_count: int = 0
    observed_dimensions_count: int = 0
    observed_dimensions: List[str] = field(default_factory=list)
    unobserved_reasons: Dict[str, str] = field(default_factory=dict)
    collapsed_duplicate_count: int = 0

    # =========================================================================
    # TIER C: AERE-DERIVED (Reasoning Authority: AERE Engine & Validator)
    # =========================================================================
    aere_execution_state: str = "unavailable"
    grounding_status: str = "UNVALIDATED"
    unsubstantiated_claims_count: int = 0
    total_citations_emitted: int = 0
    valid_citations_count: int = 0

    # =========================================================================
    # TIER D: TCE CONTEXTUAL METADATA (Contextual Only - Zero CE Math Authority)
    # =========================================================================
    contextual_tce_verdict: Optional[str] = None
    contextual_tce_risk_score: Optional[float] = None
    contextual_tce_trust_score: Optional[float] = None

    # =========================================================================
    # TIER E: PRESENTATION & EXPLAINABILITY METADATA
    # =========================================================================
    engine_version: str = field(default=CONFIDENCE_CONTRACT_VERSION)
    analysis_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    investigation_id: Optional[str] = None
    target: Optional[Dict[str, Any]] = None
    evidence_metrics: Optional[Dict[str, Any]] = None
    interpretation_metrics: Optional[Dict[str, Any]] = None
    concordant_clusters: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =====================================================================
# 6. CONTRACT VALIDATION FUNCTION
# =====================================================================
def validate_confidence_output(payload: Union[ConfidenceOutputPayload, Dict[str, Any]]) -> Tuple[bool, List[str]]:
    """
    Validate that a Confidence Engine output payload strictly conforms to the
    Step 4B Confidence Contract.
    
    Returns:
        (is_valid, list_of_errors)
    """
    errors: List[str] = []
    
    if isinstance(payload, ConfidenceOutputPayload):
        data = payload.to_dict()
    elif isinstance(payload, dict):
        data = payload
    else:
        return False, ["Payload must be a dict or ConfidenceOutputPayload instance."]

    # Required Tier A fields & numerical bounds
    score_fields = [
        "evidence_confidence",
        "interpretation_confidence",
        "composite_confidence",
        "telemetry_coverage_score",
        "source_reliability_score",
        "corroboration_score",
        "contradiction_score"
    ]
    for field_name in score_fields:
        val = data.get(field_name)
        if val is None:
            errors.append(f"Missing required score field: '{field_name}'.")
        elif not isinstance(val, (int, float)):
            errors.append(f"Field '{field_name}' must be a float, got {type(val).__name__}.")
        elif not (0.0 <= float(val) <= 100.0):
            errors.append(f"Field '{field_name}' out of bounds [0.0, 100.0]: {val}.")

    # Ratio bounds [0.0, 1.0]
    ratio_fields = ["grounded_citation_ratio", "contradiction_ratio"]
    for r_field in ratio_fields:
        r_val = data.get(r_field)
        if r_val is None:
            errors.append(f"Missing required ratio field: '{r_field}'.")
        elif not isinstance(r_val, (int, float)):
            errors.append(f"Field '{r_field}' must be a float, got {type(r_val).__name__}.")
        elif not (0.0 <= float(r_val) <= 1.0):
            errors.append(f"Ratio field '{r_field}' out of bounds [0.0, 1.0]: {r_val}.")

    # Integer bounds
    concordant_count = data.get("concordant_cluster_count")
    if concordant_count is None:
        errors.append("Missing required field: 'concordant_cluster_count'.")
    elif not isinstance(concordant_count, int):
        errors.append(f"'concordant_cluster_count' must be an integer, got {type(concordant_count).__name__}.")
    elif not (0 <= concordant_count <= 7):
        errors.append(f"'concordant_cluster_count' out of range [0, 7]: {concordant_count}.")

    # Boolean & string enums
    if "provenance_gate_passed" not in data or not isinstance(data.get("provenance_gate_passed"), bool):
        errors.append("Field 'provenance_gate_passed' must be a boolean.")

    if "abstention_flag" not in data or not isinstance(data.get("abstention_flag"), bool):
        errors.append("Field 'abstention_flag' must be a boolean.")

    reason = data.get("abstention_reason")
    valid_reasons = {
        AbstentionRecommendation.AUTOMATION_ELIGIBLE_BY_UNCALIBRATED_PROTOTYPE_POLICY,
        AbstentionRecommendation.ABSTAIN_INSUFFICIENT_EVIDENCE,
        AbstentionRecommendation.ABSTAIN_EVIDENTIARY_CONFLICT,
        AbstentionRecommendation.ABSTAIN_INTEGRITY_FAILURE,
        AbstentionRecommendation.REVIEW_REQUIRED_UNGROUNDED,
        AbstentionRecommendation.REVIEW_REQUIRED_LOW_CONFIDENCE
    }
    if not reason or reason not in valid_reasons:
        errors.append(f"Invalid 'abstention_reason': '{reason}'. Must be one of {sorted(valid_reasons)}.")

    # Forbidden fields checking (ensure no TCE risk override or maliciousness probability)
    forbidden_keys = {"malicious_probability", "recalculated_risk", "recalculated_trust", "override_verdict"}
    for k in forbidden_keys:
        if k in data:
            errors.append(f"Forbidden key '{k}' found in Confidence output payload.")

    return (len(errors) == 0, errors)
