"""Independent Ground-Truth Verification Layer for Benchmark Datasets.

Step 6D-4: Independent Ground-Truth Verification.

This module establishes structured, independent ground-truth verification objects
and consensus adjudication for benchmark records and raw harvested candidates.

Architectural & Methodological Guarantees:
1. Ground-Truth Independence & Zero Self-Labeling:
   The evaluated forensic system (TCE, AERE, Confidence Engine, Agents A1-A18, Report Generator)
   has ZERO authority over benchmark ground truth. Any source originating from the internal
   system is strictly rejected with an explicit diagnostic code (INTERNAL_SYSTEM_SOURCE_REJECTED).
2. Absence != Benign:
   Lack of threat detections across external feeds or absence of verification sources never
   establishes a BENIGN label. Unverifiable or missing-evidence records become AMBIGUOUS / UNVERIFIABLE.
3. Source Independence & Consensus:
   Requires >= 2 genuinely independent agreeing sources for automated VERIFIED / HIGH confidence labels.
   Single-source claims remain uncorroborated (AMBIGUOUS or MEDIUM/LOW confidence).
   Duplicate or mirrored source entries from the same provider do not count as independent corroboration.
4. Conflict Handling & Human Adjudication:
   Divergent source claims (MALICIOUS vs BENIGN) produce DISPUTED / AMBIGUOUS ground truth.
   Disputes can only be resolved through explicit human analyst AdjudicationRecord.
5. Qualitative Confidence:
   Verification confidence is strictly qualitative (HIGH, MEDIUM, LOW). Floating-point probabilities
   or Bayesian posterior scores are rejected.
6. Threat Intelligence Firewall:
   External threat intelligence feed membership alone is provenance/evaluation metadata and does NOT
   automatically equal benchmark ground truth unless independently corroborated per protocol.
7. Identity & Partition Preservation:
   Ground-truth verification never alters or collapses artifact_id, target_id, group_id, or evaluation partitions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

from .schemas import (
    InputModality,
    PrimaryOutcome,
    SecondaryThreatCategory,
    VerificationStatus,
    VerificationMethod,
    VerificationConfidence,
    CandidateProvenance,
    GroundTruth,
    EvaluationMetadata,
    BenchmarkRecord,
)
from .harvester import RawCandidate


# =====================================================================
# Verification Source & Adjudication Data Models
# =====================================================================

class SourceType(str, Enum):
    """Categorization of independent verification evidence sources."""
    AUTHORITATIVE_REGISTRY = "authoritative_registry"
    CURATED_THREAT_FEED = "curated_threat_feed"
    INCIDENT_TAKEDOWN_RECORD = "incident_takedown_record"
    ANALYST_MANUAL_REVIEW = "analyst_manual_review"
    OFFICIAL_ORGANIZATION_RECORD = "official_organization_record"
    MALWARE_SANDBOX_DETONATION = "malware_sandbox_detonation"
    TRUSTED_BENIGN_CURATION = "trusted_benign_curation"
    DOM_CERT_ANALYSIS = "dom_cert_analysis"
    COMMUNITY_CONSENSUS = "community_consensus"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class VerificationSourceRecord:
    """Independent source evidence supporting a ground-truth assessment."""
    source_name: str
    source_type: SourceType = SourceType.UNKNOWN
    source_reference: str = ""
    asserted_outcome: PrimaryOutcome = PrimaryOutcome.AMBIGUOUS
    asserted_categories: List[SecondaryThreatCategory] = field(default_factory=list)
    observation_time: str = ""
    retrieved_at: str = ""
    confidence: VerificationConfidence = VerificationConfidence.HIGH
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert source record to serializable dictionary."""
        return {
            "source_name": self.source_name,
            "source_type": self.source_type.value if hasattr(self.source_type, "value") else str(self.source_type),
            "source_reference": self.source_reference,
            "asserted_outcome": self.asserted_outcome.value if hasattr(self.asserted_outcome, "value") else str(self.asserted_outcome),
            "asserted_categories": [
                c.value if hasattr(c, "value") else str(c) for c in self.asserted_categories
            ],
            "observation_time": self.observation_time,
            "retrieved_at": self.retrieved_at,
            "confidence": self.confidence.value if hasattr(self.confidence, "value") else str(self.confidence),
            "notes": self.notes,
        }


@dataclass(frozen=True)
class AdjudicationRecord:
    """Human analyst / expert consensus adjudication metadata."""
    reviewer_id: str
    adjudicated_outcome: PrimaryOutcome
    adjudicated_categories: List[SecondaryThreatCategory] = field(default_factory=list)
    rationale: str = ""
    adjudication_timestamp: str = ""
    confidence: VerificationConfidence = VerificationConfidence.HIGH

    def to_dict(self) -> Dict[str, Any]:
        """Convert adjudication record to serializable dictionary."""
        return {
            "reviewer_id": self.reviewer_id,
            "adjudicated_outcome": self.adjudicated_outcome.value if hasattr(self.adjudicated_outcome, "value") else str(self.adjudicated_outcome),
            "adjudicated_categories": [
                c.value if hasattr(c, "value") else str(c) for c in self.adjudicated_categories
            ],
            "rationale": self.rationale,
            "adjudication_timestamp": self.adjudication_timestamp,
            "confidence": self.confidence.value if hasattr(self.confidence, "value") else str(self.confidence),
        }


@dataclass(frozen=True)
class GroundTruthVerificationResult:
    """Structured result of independent ground-truth verification."""
    record_id: str
    target_id: str
    ground_truth: GroundTruth
    sources: List[VerificationSourceRecord] = field(default_factory=list)
    adjudication: Optional[AdjudicationRecord] = None
    is_disputed: bool = False
    is_unverifiable: bool = False
    diagnostics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert verification result to serializable dictionary."""
        return {
            "record_id": self.record_id,
            "target_id": self.target_id,
            "ground_truth": {
                "primary_outcome": self.ground_truth.primary_outcome.value,
                "secondary_categories": [c.value for c in self.ground_truth.secondary_categories],
                "verification_status": self.ground_truth.verification_status.value,
                "verification_method": self.ground_truth.verification_method,
                "verification_confidence": self.ground_truth.verification_confidence.value,
                "adjudication_status": self.ground_truth.adjudication_status,
                "reviewer_count": self.ground_truth.reviewer_count,
                "verification_timestamp": self.ground_truth.verification_timestamp,
                "rationale": self.ground_truth.rationale,
                "supporting_references": list(self.ground_truth.supporting_references),
                "contradictory_references": list(self.ground_truth.contradictory_references),
            },
            "sources": [s.to_dict() for s in self.sources],
            "adjudication": self.adjudication.to_dict() if self.adjudication else None,
            "is_disputed": self.is_disputed,
            "is_unverifiable": self.is_unverifiable,
            "diagnostics": self.diagnostics,
        }


# =====================================================================
# Forbidden Self-Referential Engine Tokens & Guardrails
# =====================================================================

_FORBIDDEN_SYSTEM_EXACT = {
    "tce",
    "trust_calculation_engine",
    "aere",
    "aere_reasoning_engine",
    "ce",
    "confidence_engine",
    "report_generator",
    "analysis_pipeline",
    "final_investigator_report",
    "investigator",
    "investigator_report",
    "forensic_pipeline",
    "forensic_system",
    "internal_engine",
    "risk_score",
    "trust_score",
    "verdict_engine",
}

_AGENT_NAME_PATTERN = re.compile(r"^agent(?:_|\s|-)?(?:[1-9]|1[0-8])$", re.IGNORECASE)


def is_forbidden_system_source(source_name: str) -> bool:
    """Check if a source attempts to pass internal forensic engine outputs as ground truth."""
    if not source_name or not isinstance(source_name, str):
        return False

    clean = source_name.strip().lower()
    if clean in _FORBIDDEN_SYSTEM_EXACT:
        return True

    # Check for agent patterns (e.g. Agent 1, Agent_10, Agent-18, Agent1)
    if _AGENT_NAME_PATTERN.match(clean):
        return True

    # Check for token intersections
    words = set(re.split(r"[\s_.:/\\-]+", clean))
    if words & _FORBIDDEN_SYSTEM_EXACT:
        return True

    # Check if any word starts with 'agent' followed by digits 1-18
    for w in words:
        if _AGENT_NAME_PATTERN.match(w):
            return True

    return False


# Legacy alias for internal backward compatibility
_is_forbidden_system_source = is_forbidden_system_source


# =====================================================================
# Ground-Truth Verifier Implementation
# =====================================================================

def verify_ground_truth(
    record_or_candidate: Union[BenchmarkRecord, RawCandidate, str],
    sources: Optional[Sequence[VerificationSourceRecord]] = None,
    adjudication: Optional[AdjudicationRecord] = None,
    verification_method: VerificationMethod = VerificationMethod.MULTI_SOURCE_CONSENSUS,
    min_corroborating_sources: int = 2,
    verification_timestamp: str = "",
    target_id: Optional[str] = None,
) -> GroundTruthVerificationResult:
    """Evaluate independent verification evidence and produce canonical GroundTruth.

    Verification Invariants:
    1. Zero Self-Labeling: Sources derived from internal forensic engines or agents are rejected
       with the diagnostic code INTERNAL_SYSTEM_SOURCE_REJECTED.
    2. Absence != Benign: Lack of evidence or empty sources yields AMBIGUOUS / UNVERIFIABLE.
    3. Conflicting Evidence: Divergent source outcomes (e.g. MALICIOUS vs BENIGN) produce
       AMBIGUOUS / DISPUTED unless resolved by an explicit AdjudicationRecord.
    4. Multi-Source Corroboration: >= min_corroborating_sources genuinely independent agreeing
       sources produce VERIFIED with HIGH confidence.
    5. Single Source / Duplicates: Single or duplicate uncorroborated sources produce AMBIGUOUS / MEDIUM
       or LOW confidence. Duplicate source records from the same feed do not count as independent.
    6. Preservation: Does not mutate record_id, target_id, artifact_id, or temporal_partition.
    """
    # Extract identity metadata
    if isinstance(record_or_candidate, BenchmarkRecord):
        rec_id = record_or_candidate.record_id
        tgt_id = record_or_candidate.target_id
        initial_reviewer_count = max(1, record_or_candidate.ground_truth.reviewer_count)
    elif isinstance(record_or_candidate, RawCandidate):
        rec_id = record_or_candidate.candidate_id
        tgt_id = target_id or record_or_candidate.candidate_id
        initial_reviewer_count = 1
    else:
        rec_id = str(record_or_candidate)
        tgt_id = target_id or rec_id
        initial_reviewer_count = 1

    input_sources = list(sources) if sources else []

    # 1. Filter out and reject forbidden self-referential sources
    raw_valid_sources: List[VerificationSourceRecord] = []
    rejected_sources: List[str] = []

    for src in input_sources:
        if not isinstance(src, VerificationSourceRecord):
            continue
        if is_forbidden_system_source(src.source_name):
            rejected_sources.append(src.source_name)
        else:
            raw_valid_sources.append(src)

    # Sort valid sources deterministically for input-order independence
    valid_sources = sorted(
        raw_valid_sources,
        key=lambda s: (
            s.source_name.lower(),
            s.source_type.value if hasattr(s.source_type, "value") else str(s.source_type),
            s.source_reference,
            s.asserted_outcome.value if hasattr(s.asserted_outcome, "value") else str(s.asserted_outcome),
        ),
    )

    # 2. Case A: Explicit Adjudication Provided
    if adjudication is not None:
        all_refs = [
            f"{s.source_name} ({s.source_reference})" if s.source_reference else s.source_name
            for s in valid_sources
        ]
        gt = GroundTruth(
            primary_outcome=adjudication.adjudicated_outcome,
            secondary_categories=list(adjudication.adjudicated_categories),
            verification_status=VerificationStatus.VERIFIED,
            verification_method=VerificationMethod.MANUAL_ADJUDICATION.value,
            verification_confidence=adjudication.confidence,
            adjudication_status="adjudicated",
            reviewer_count=initial_reviewer_count,
            verification_timestamp=adjudication.adjudication_timestamp or verification_timestamp,
            rationale=adjudication.rationale or "Analyst consensus adjudication.",
            supporting_references=all_refs,
            contradictory_references=[],
        )
        return GroundTruthVerificationResult(
            record_id=rec_id,
            target_id=tgt_id,
            ground_truth=gt,
            sources=valid_sources,
            adjudication=adjudication,
            is_disputed=False,
            is_unverifiable=False,
            diagnostics={
                "adjudication_applied": True,
                "reviewer_id": adjudication.reviewer_id,
                "rejected_sources": rejected_sources,
                "diagnostic_code": "INTERNAL_SYSTEM_SOURCE_REJECTED" if rejected_sources else "NONE",
            },
        )

    # 3. Case B: Insufficient / Empty Sources -> UNVERIFIABLE / AMBIGUOUS
    if not valid_sources:
        gt = GroundTruth(
            primary_outcome=PrimaryOutcome.AMBIGUOUS,
            secondary_categories=[],
            verification_status=VerificationStatus.UNVERIFIABLE,
            verification_method=verification_method.value,
            verification_confidence=VerificationConfidence.LOW,
            adjudication_status="unadjudicated",
            reviewer_count=1,
            verification_timestamp=verification_timestamp,
            rationale="No independent verification evidence provided (Absence does not imply BENIGN).",
            supporting_references=[],
            contradictory_references=[],
        )
        return GroundTruthVerificationResult(
            record_id=rec_id,
            target_id=tgt_id,
            ground_truth=gt,
            sources=[],
            adjudication=None,
            is_disputed=False,
            is_unverifiable=True,
            diagnostics={
                "reason": "empty_or_rejected_sources",
                "rejected_sources": rejected_sources,
                "diagnostic_code": "INTERNAL_SYSTEM_SOURCE_REJECTED" if rejected_sources else "NONE",
            },
        )

    # 4. Deduplicate sources for independent consensus counting
    # Multiple entries with identical normalized source_name and reference count as 1 independent source
    unique_sources_by_provider: Dict[str, VerificationSourceRecord] = {}
    for s in valid_sources:
        provider_key = s.source_name.strip().lower()
        if provider_key not in unique_sources_by_provider:
            unique_sources_by_provider[provider_key] = s

    # Partition unique sources by outcome
    distinct_sources = list(unique_sources_by_provider.values())
    malicious_sources = [s for s in distinct_sources if s.asserted_outcome == PrimaryOutcome.MALICIOUS]
    benign_sources = [s for s in distinct_sources if s.asserted_outcome == PrimaryOutcome.BENIGN]
    ambiguous_sources = [s for s in distinct_sources if s.asserted_outcome == PrimaryOutcome.AMBIGUOUS]

    supporting_refs: List[str] = []
    contradictory_refs: List[str] = []

    # 5. Case C: Conflicting Sources (MALICIOUS and BENIGN simultaneously asserted)
    if malicious_sources and benign_sources:
        for s in malicious_sources:
            ref = f"MALICIOUS: {s.source_name} ({s.source_reference})" if s.source_reference else f"MALICIOUS: {s.source_name}"
            supporting_refs.append(ref)
        for s in benign_sources:
            ref = f"BENIGN: {s.source_name} ({s.source_reference})" if s.source_reference else f"BENIGN: {s.source_name}"
            contradictory_refs.append(ref)

        gt = GroundTruth(
            primary_outcome=PrimaryOutcome.AMBIGUOUS,
            secondary_categories=[],
            verification_status=VerificationStatus.DISPUTED,
            verification_method=verification_method.value,
            verification_confidence=VerificationConfidence.LOW,
            adjudication_status="dispute_pending_adjudication",
            reviewer_count=1,
            verification_timestamp=verification_timestamp,
            rationale=f"Conflicting independent evidence: {len(malicious_sources)} source(s) asserted MALICIOUS, {len(benign_sources)} source(s) asserted BENIGN.",
            supporting_references=sorted(supporting_refs),
            contradictory_references=sorted(contradictory_refs),
        )
        return GroundTruthVerificationResult(
            record_id=rec_id,
            target_id=tgt_id,
            ground_truth=gt,
            sources=valid_sources,
            adjudication=None,
            is_disputed=True,
            is_unverifiable=False,
            diagnostics={
                "malicious_source_count": len(malicious_sources),
                "benign_source_count": len(benign_sources),
                "rejected_sources": rejected_sources,
                "diagnostic_code": "INTERNAL_SYSTEM_SOURCE_REJECTED" if rejected_sources else "DISPUTED_EVIDENCE",
            },
        )

    # 6. Case D: Corroborated Malicious Evidence
    if malicious_sources:
        cat_set: Set[SecondaryThreatCategory] = set()
        for s in malicious_sources:
            cat_set.update(s.asserted_categories)
            supporting_refs.append(f"{s.source_name}: {s.source_reference}" if s.source_reference else s.source_name)

        is_corroborated = len(malicious_sources) >= min_corroborating_sources
        conf = VerificationConfidence.HIGH if is_corroborated else VerificationConfidence.MEDIUM
        status = VerificationStatus.VERIFIED if is_corroborated else VerificationStatus.AMBIGUOUS

        gt = GroundTruth(
            primary_outcome=PrimaryOutcome.MALICIOUS if is_corroborated else PrimaryOutcome.AMBIGUOUS,
            secondary_categories=sorted(list(cat_set), key=lambda c: c.value),
            verification_status=status,
            verification_method=verification_method.value,
            verification_confidence=conf,
            adjudication_status="verified_by_sources" if is_corroborated else "single_source_pending_corroboration",
            reviewer_count=len(malicious_sources),
            verification_timestamp=verification_timestamp or (malicious_sources[0].observation_time or ""),
            rationale=f"Supported by {len(malicious_sources)} independent source(s).",
            supporting_references=sorted(supporting_refs),
            contradictory_references=[],
        )
        return GroundTruthVerificationResult(
            record_id=rec_id,
            target_id=tgt_id,
            ground_truth=gt,
            sources=valid_sources,
            adjudication=None,
            is_disputed=False,
            is_unverifiable=not is_corroborated,
            diagnostics={
                "corroborated": is_corroborated,
                "source_count": len(malicious_sources),
                "rejected_sources": rejected_sources,
                "diagnostic_code": "INTERNAL_SYSTEM_SOURCE_REJECTED" if rejected_sources else "NONE",
            },
        )

    # 7. Case E: Corroborated Benign Evidence
    if benign_sources:
        for s in benign_sources:
            supporting_refs.append(f"{s.source_name}: {s.source_reference}" if s.source_reference else s.source_name)

        is_corroborated = len(benign_sources) >= min_corroborating_sources
        conf = VerificationConfidence.HIGH if is_corroborated else VerificationConfidence.MEDIUM
        status = VerificationStatus.VERIFIED if is_corroborated else VerificationStatus.AMBIGUOUS

        gt = GroundTruth(
            primary_outcome=PrimaryOutcome.BENIGN if is_corroborated else PrimaryOutcome.AMBIGUOUS,
            secondary_categories=[],
            verification_status=status,
            verification_method=verification_method.value,
            verification_confidence=conf,
            adjudication_status="verified_by_sources" if is_corroborated else "single_source_pending_corroboration",
            reviewer_count=len(benign_sources),
            verification_timestamp=verification_timestamp or (benign_sources[0].observation_time or ""),
            rationale=f"Verified benign by {len(benign_sources)} independent authoritative source(s).",
            supporting_references=sorted(supporting_refs),
            contradictory_references=[],
        )
        return GroundTruthVerificationResult(
            record_id=rec_id,
            target_id=tgt_id,
            ground_truth=gt,
            sources=valid_sources,
            adjudication=None,
            is_disputed=False,
            is_unverifiable=not is_corroborated,
            diagnostics={
                "corroborated": is_corroborated,
                "source_count": len(benign_sources),
                "rejected_sources": rejected_sources,
                "diagnostic_code": "INTERNAL_SYSTEM_SOURCE_REJECTED" if rejected_sources else "NONE",
            },
        )

    # 8. Fallback: Only Ambiguous Sources
    gt = GroundTruth(
        primary_outcome=PrimaryOutcome.AMBIGUOUS,
        secondary_categories=[],
        verification_status=VerificationStatus.AMBIGUOUS,
        verification_method=verification_method.value,
        verification_confidence=VerificationConfidence.LOW,
        adjudication_status="unresolved_ambiguity",
        reviewer_count=len(ambiguous_sources),
        verification_timestamp=verification_timestamp,
        rationale="Supplied sources are all ambiguous / inconclusive.",
        supporting_references=sorted([s.source_name for s in ambiguous_sources]),
        contradictory_references=[],
    )
    return GroundTruthVerificationResult(
        record_id=rec_id,
        target_id=tgt_id,
        ground_truth=gt,
        sources=valid_sources,
        adjudication=None,
        is_disputed=False,
        is_unverifiable=True,
        diagnostics={
            "ambiguous_source_count": len(ambiguous_sources),
            "rejected_sources": rejected_sources,
            "diagnostic_code": "INTERNAL_SYSTEM_SOURCE_REJECTED" if rejected_sources else "NONE",
        },
    )


def verify_candidate_ground_truth(
    candidate: RawCandidate,
    sources: Optional[Sequence[VerificationSourceRecord]] = None,
    adjudication: Optional[AdjudicationRecord] = None,
    verification_method: VerificationMethod = VerificationMethod.MULTI_SOURCE_CONSENSUS,
    min_corroborating_sources: int = 2,
    verification_timestamp: str = "",
    target_id: Optional[str] = None,
) -> GroundTruthVerificationResult:
    """Convenience helper to verify ground truth for a RawCandidate directly."""
    return verify_ground_truth(
        record_or_candidate=candidate,
        sources=sources,
        adjudication=adjudication,
        verification_method=verification_method,
        min_corroborating_sources=min_corroborating_sources,
        verification_timestamp=verification_timestamp,
        target_id=target_id,
    )


def attach_verified_ground_truth(
    record: BenchmarkRecord,
    verification_result: GroundTruthVerificationResult,
) -> BenchmarkRecord:
    """Create an updated immutable BenchmarkRecord with verified GroundTruth attached.

    PRESERVATION GUARANTEE:
    - record_id, artifact_id, target_id, and modality remain unchanged.
    - evaluation.group_id and evaluation.temporal_partition remain unchanged.
    """
    return BenchmarkRecord(
        record_id=record.record_id,
        artifact_id=record.artifact_id,
        target_id=record.target_id,
        target_url=record.target_url,
        modality=record.modality,
        ground_truth=verification_result.ground_truth,
        provenance=record.provenance,
        ti_overlap=record.ti_overlap,
        liveness=record.liveness,
        qr_relationship=record.qr_relationship,
        evaluation=record.evaluation,
        schema_version=record.schema_version,
    )
