"""Independent Ground-Truth Verification Layer for Benchmark Datasets.

Step 6C-4: Independent Ground-Truth Verification Records.

This module establishes structured, independent ground-truth verification objects
and consensus adjudication for benchmark records.

Architectural Guarantees:
- Zero Self-Labeling: The evaluated forensic system (TCE, AERE, CE, Report Generator)
  is strictly forbidden from contributing to or modifying benchmark ground truth.
- Absence != Benign: Absence of threat detection across feeds never establishes a BENIGN outcome.
- Qualitative Adjudication Confidence: Strictly discrete qualitative levels (HIGH, MEDIUM, LOW);
  numerical probabilities are rejected.
- Ambiguity Retention: Unverifiable or conflicting records are preserved in the ambiguity pool
  rather than forced into binary classifications.
- Identity & Partition Preservation: Ground-truth adjudication never alters artifact IDs,
  target IDs, group IDs, or evaluation partitions.
- Offline & Deterministic: Pure local execution without network calls or non-deterministic state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Any, Dict, List, Optional, Set, Tuple

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


@dataclass(frozen=True)
class AdjudicationRecord:
    """Human analyst / expert consensus adjudication metadata."""
    reviewer_id: str
    adjudicated_outcome: PrimaryOutcome
    adjudicated_categories: List[SecondaryThreatCategory] = field(default_factory=list)
    rationale: str = ""
    adjudication_timestamp: str = ""
    confidence: VerificationConfidence = VerificationConfidence.HIGH


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


# =====================================================================
# Forbidden Self-Referential Engine Tokens
# =====================================================================

_FORBIDDEN_SYSTEM_TOKENS = {
    "tce",
    "trust_calculation_engine",
    "aere",
    "aere_reasoning_engine",
    "ce",
    "confidence_engine",
    "report_generator",
    "analysis_pipeline",
    "final_investigator_report",
}


def _is_forbidden_system_source(source_name: str) -> bool:
    """Check if a source attempts to pass internal forensic engine outputs as ground truth."""
    clean = source_name.strip().lower()
    if clean in _FORBIDDEN_SYSTEM_TOKENS:
        return True
    words = set(re.split(r"[\s_.:/\\-]+", clean))
    return bool(words & _FORBIDDEN_SYSTEM_TOKENS)


# =====================================================================
# Ground-Truth Verifier Implementation
# =====================================================================

def verify_ground_truth(
    record: BenchmarkRecord,
    sources: Optional[List[VerificationSourceRecord]] = None,
    adjudication: Optional[AdjudicationRecord] = None,
    verification_method: VerificationMethod = VerificationMethod.MULTI_SOURCE_CONSENSUS,
    min_corroborating_sources: int = 2,
    verification_timestamp: str = "",
) -> GroundTruthVerificationResult:
    """Evaluate independent verification evidence and produce canonical GroundTruth.

    Verification Invariants:
    1. Zero Self-Labeling: Sources derived from internal forensic engines are rejected.
    2. Absence != Benign: Lack of evidence or empty sources yields AMBIGUOUS / UNVERIFIABLE.
    3. Conflicting Evidence: Divergent source outcomes (e.g. MALICIOUS vs BENIGN) produce
       AMBIGUOUS / DISPUTED unless resolved by an explicit AdjudicationRecord.
    4. Multi-Source Corroboration: >= min_corroborating_sources agreeing on outcome
       produces VERIFIED with HIGH confidence.
    5. Single Source: Single uncorroborated source produces MEDIUM or LOW confidence.
    6. Preservation: Does not mutate record_id, target_id, artifact_id, or temporal_partition.
    """
    input_sources = sources or []

    # 1. Filter out and reject forbidden self-referential sources
    valid_sources: List[VerificationSourceRecord] = []
    rejected_sources: List[str] = []

    for src in input_sources:
        if _is_forbidden_system_source(src.source_name):
            rejected_sources.append(src.source_name)
        else:
            valid_sources.append(src)

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
            reviewer_count=max(1, record.ground_truth.reviewer_count),
            verification_timestamp=adjudication.adjudication_timestamp or verification_timestamp,
            rationale=adjudication.rationale or "Analyst consensus adjudication.",
            supporting_references=all_refs,
            contradictory_references=[],
        )
        return GroundTruthVerificationResult(
            record_id=record.record_id,
            target_id=record.target_id,
            ground_truth=gt,
            sources=valid_sources,
            adjudication=adjudication,
            is_disputed=False,
            is_unverifiable=False,
            diagnostics={
                "adjudication_applied": True,
                "reviewer_id": adjudication.reviewer_id,
                "rejected_sources": rejected_sources,
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
            record_id=record.record_id,
            target_id=record.target_id,
            ground_truth=gt,
            sources=[],
            adjudication=None,
            is_disputed=False,
            is_unverifiable=True,
            diagnostics={
                "reason": "empty_or_rejected_sources",
                "rejected_sources": rejected_sources,
            },
        )

    # 4. Analyze Source Outcomes and Categories
    malicious_sources = [s for s in valid_sources if s.asserted_outcome == PrimaryOutcome.MALICIOUS]
    benign_sources = [s for s in valid_sources if s.asserted_outcome == PrimaryOutcome.BENIGN]
    ambiguous_sources = [s for s in valid_sources if s.asserted_outcome == PrimaryOutcome.AMBIGUOUS]

    supporting_refs: List[str] = []
    contradictory_refs: List[str] = []

    # 5. Case C: Conflicting Sources (MALICIOUS and BENIGN simultaneously asserted)
    if malicious_sources and benign_sources:
        for s in malicious_sources:
            supporting_refs.append(f"MALICIOUS: {s.source_name} ({s.source_reference})")
        for s in benign_sources:
            contradictory_refs.append(f"BENIGN: {s.source_name} ({s.source_reference})")

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
            supporting_references=supporting_refs,
            contradictory_references=contradictory_refs,
        )
        return GroundTruthVerificationResult(
            record_id=record.record_id,
            target_id=record.target_id,
            ground_truth=gt,
            sources=valid_sources,
            adjudication=None,
            is_disputed=True,
            is_unverifiable=False,
            diagnostics={
                "malicious_source_count": len(malicious_sources),
                "benign_source_count": len(benign_sources),
                "rejected_sources": rejected_sources,
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
            supporting_references=supporting_refs,
            contradictory_references=[],
        )
        return GroundTruthVerificationResult(
            record_id=record.record_id,
            target_id=record.target_id,
            ground_truth=gt,
            sources=valid_sources,
            adjudication=None,
            is_disputed=False,
            is_unverifiable=not is_corroborated,
            diagnostics={
                "corroborated": is_corroborated,
                "source_count": len(malicious_sources),
                "rejected_sources": rejected_sources,
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
            supporting_references=supporting_refs,
            contradictory_references=[],
        )
        return GroundTruthVerificationResult(
            record_id=record.record_id,
            target_id=record.target_id,
            ground_truth=gt,
            sources=valid_sources,
            adjudication=None,
            is_disputed=False,
            is_unverifiable=not is_corroborated,
            diagnostics={
                "corroborated": is_corroborated,
                "source_count": len(benign_sources),
                "rejected_sources": rejected_sources,
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
        supporting_references=[s.source_name for s in ambiguous_sources],
        contradictory_references=[],
    )
    return GroundTruthVerificationResult(
        record_id=record.record_id,
        target_id=record.target_id,
        ground_truth=gt,
        sources=valid_sources,
        adjudication=None,
        is_disputed=False,
        is_unverifiable=True,
        diagnostics={"ambiguous_source_count": len(ambiguous_sources), "rejected_sources": rejected_sources},
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
