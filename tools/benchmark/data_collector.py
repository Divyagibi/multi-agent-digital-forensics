"""Real Benchmark Data Collection & Acquisition Layer.

Step 6D-8: Real Benchmark Data Collection Implementation.

This module implements the controlled, reproducible, auditable, and legally bounded
benchmark data acquisition workflow defined in docs/real_benchmark_data_collection_specification.md.

Architectural & Methodological Guarantees:
1. Source Role Firewall:
   Strictly isolates Candidate Sources, Threat Intelligence Feeds, Independent Ground-Truth
   Sources, and Internal Forensic Analysis Engines. Prevents role conflation or self-labeling.
2. Ground-Truth Independence:
   Ground truth is NEVER derived from TCE, AERE, Confidence Engine, Agents A1-A18, or system
   verdicts. TI feed presence/absence is NEVER converted directly to ground truth.
3. Raw Artifact Preservation:
   Exact observed raw URLs, QR payload strings, and image paths/bytes are preserved verbatim
   before any downstream normalization.
4. Passive & Safe Execution:
   Leverages frozen Step 6D-3 passive liveness checking (raw HTTP body >= 100 B, TLS enabled,
   bounded redirects). Zero local payload execution, zero exploit detonation, zero credential entry.
5. Objective Stopping Rules:
   N ≈ 1200 remains a planning capacity target. Stopping conditions (capacity, source exhaustion,
   temporal cutoff, safety bounds) are objective and never driven by model performance.
6. Clean Handoff to Step 6D-6:
   Outputs from collection cleanly hand off into the frozen Step 6D-6 DatasetAssembler to achieve
   READY_FOR_EXPERIMENT pre-run gate certification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union
import uuid

from .schemas import (
    InputModality,
    PrimaryOutcome,
    SecondaryThreatCategory,
    VerificationStatus,
    VerificationMethod,
    VerificationConfidence,
    TIObservationStatus,
    TemporalPartition,
    CandidateProvenance,
    GroundTruth,
    TIFeedObservation,
    TIOverlapMetadata,
    LivenessMetadata,
    QRRelationshipMetadata,
    EvaluationMetadata,
    BenchmarkRecord,
    BenchmarkManifest,
    compute_artifact_id,
    compute_target_id,
    compute_group_id,
    compute_record_id,
    canonicalize_record_dict,
    sha256_bytes,
)
from .harvester import (
    SourceType as HarvesterSourceType,
    RetrievalStatus,
    RawCandidate,
    SourceHarvestReport,
    HarvestingResult,
    BaseSourceAdapter,
    CandidateHarvester,
    compute_candidate_id,
)
from .liveness import (
    LivenessStatus,
    EligibilityStatus,
    LivenessFailureReason,
    LivenessEvaluation,
    LivenessBatchResult,
    PassiveLivenessEvaluator,
)
from .ground_truth_verifier import (
    SourceType as GTSourceType,
    VerificationSourceRecord,
    AdjudicationRecord,
    GroundTruthVerificationResult,
    verify_ground_truth,
    verify_candidate_ground_truth,
    is_forbidden_system_source,
)
from .ti_overlap_recorder import (
    TIFeed,
    TIObservationType,
    TIFeedObservationRecord,
    TIExposureSummary,
    TIOverlapRecord,
    validate_iso8601_timestamp,
    record_ti_observation,
    build_ti_overlap_metadata,
)
from .dataset_assembler import (
    DatasetAssembler,
    DatasetAssemblyConfig,
    DatasetAssemblyResult,
    DatasetAssemblyGateStatus,
)


# =====================================================================
# Controlled Vocabularies & Enums
# =====================================================================

class SourceCategory(str, Enum):
    """Categorization of approved external data collection sources."""
    PUBLIC_MALICIOUS_FEED = "PUBLIC_MALICIOUS_FEED"
    PUBLIC_PHISHING_FEED = "PUBLIC_PHISHING_FEED"
    CURATED_BENIGN_REGISTRY = "CURATED_BENIGN_REGISTRY"
    RESEARCH_DATASET = "RESEARCH_DATASET"
    INCIDENT_RECORDS = "INCIDENT_RECORDS"
    TI_EXPOSURE_FEED = "TI_EXPOSURE_FEED"
    LOCAL_ARCHIVE = "LOCAL_ARCHIVE"
    OTHER = "OTHER"


class SourceRole(str, Enum):
    """Role separation for approved collection sources."""
    CANDIDATE_SOURCE = "CANDIDATE_SOURCE"
    GROUND_TRUTH_SOURCE = "GROUND_TRUTH_SOURCE"
    TI_OVERLAP_SOURCE = "TI_OVERLAP_SOURCE"
    AUXILIARY_METADATA = "AUXILIARY_METADATA"


class CollectionSessionStatus(str, Enum):
    """Execution status of a benchmark data collection session."""
    INITIALIZED = "INITIALIZED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    STOPPED_ON_CONDITION = "STOPPED_ON_CONDITION"
    FAILED = "FAILED"
    BLOCKED_FIREWALL_VIOLATION = "BLOCKED_FIREWALL_VIOLATION"


class CollectionStoppingReason(str, Enum):
    """Objective reasons for terminating data collection."""
    CAPACITY_REACHED = "CAPACITY_REACHED"
    SOURCES_EXHAUSTED = "SOURCES_EXHAUSTED"
    TEMPORAL_CUTOFF_REACHED = "TEMPORAL_CUTOFF_REACHED"
    SAFETY_BUDGET_EXCEEDED = "SAFETY_BUDGET_EXCEEDED"
    MANUAL_STOP = "MANUAL_STOP"
    ERROR_LIMIT_EXCEEDED = "ERROR_LIMIT_EXCEEDED"
    FIREWALL_VIOLATION = "FIREWALL_VIOLATION"
    NOT_STOPPED = "NOT_STOPPED"


# =====================================================================
# Configuration Dataclasses
# =====================================================================

@dataclass(frozen=True)
class ApprovedSourceConfig:
    """Configuration record for an approved collection source."""
    source_name: str
    source_category: SourceCategory
    source_role: SourceRole
    input_modality: InputModality
    source_reference: str = ""
    access_method: str = ""
    licensing_or_access_notes: str = ""
    attribution_requirements: str = ""
    rate_limit_policy: str = ""
    reproducibility_notes: str = ""
    enabled: bool = True
    custom_parameters: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_name": self.source_name,
            "source_category": self.source_category.value if hasattr(self.source_category, "value") else str(self.source_category),
            "source_role": self.source_role.value if hasattr(self.source_role, "value") else str(self.source_role),
            "input_modality": self.input_modality.value if hasattr(self.input_modality, "value") else str(self.input_modality),
            "source_reference": self.source_reference,
            "access_method": self.access_method,
            "licensing_or_access_notes": self.licensing_or_access_notes,
            "attribution_requirements": self.attribution_requirements,
            "rate_limit_policy": self.rate_limit_policy,
            "reproducibility_notes": self.reproducibility_notes,
            "enabled": self.enabled,
            "custom_parameters": self.custom_parameters,
        }


@dataclass(frozen=True)
class CollectionConfig:
    """Master configuration for a controlled data collection execution."""
    session_id: str = ""
    target_planning_capacity: int = 1200
    min_useful_dataset_size: int = 300
    max_practical_ceiling: int = 2500
    temporal_cutoff_utc: Optional[str] = None
    max_errors_before_abort: int = 50
    require_https_tls: bool = True
    min_http_body_bytes: int = 100
    enable_pii_sanitization: bool = True
    approved_sources: List[ApprovedSourceConfig] = field(default_factory=list)
    output_dir: Optional[str] = None

    def __post_init__(self):
        if not self.session_id:
            # Generate deterministic or random UUID if empty
            object.__setattr__(self, "session_id", str(uuid.uuid4()))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "target_planning_capacity": self.target_planning_capacity,
            "min_useful_dataset_size": self.min_useful_dataset_size,
            "max_practical_ceiling": self.max_practical_ceiling,
            "temporal_cutoff_utc": self.temporal_cutoff_utc,
            "max_errors_before_abort": self.max_errors_before_abort,
            "require_https_tls": self.require_https_tls,
            "min_http_body_bytes": self.min_http_body_bytes,
            "enable_pii_sanitization": self.enable_pii_sanitization,
            "approved_sources": [s.to_dict() for s in self.approved_sources],
            "output_dir": self.output_dir,
        }


# =====================================================================
# Audit and Manifest Dataclasses
# =====================================================================

@dataclass(frozen=True)
class CollectionItemAudit:
    """Individual item audit record for an observed candidate during collection."""
    candidate_id: str
    artifact_id: str
    source_name: str
    modality: str
    liveness_eligible: bool
    liveness_status: str
    has_ground_truth: bool
    gt_outcome: Optional[str] = None
    gt_confidence: Optional[str] = None
    ti_exposure_stratum: Optional[str] = None
    rejection_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "artifact_id": self.artifact_id,
            "source_name": self.source_name,
            "modality": self.modality,
            "liveness_eligible": self.liveness_eligible,
            "liveness_status": self.liveness_status,
            "has_ground_truth": self.has_ground_truth,
            "gt_outcome": self.gt_outcome,
            "gt_confidence": self.gt_confidence,
            "ti_exposure_stratum": self.ti_exposure_stratum,
            "rejection_reasons": self.rejection_reasons,
        }


@dataclass(frozen=True)
class CollectionSourceAudit:
    """Source-level aggregated collection audit metrics."""
    source_name: str
    source_role: str
    status: str
    raw_candidates_observed: int = 0
    candidates_accepted: int = 0
    candidates_rejected: int = 0
    liveness_passed: int = 0
    liveness_failed: int = 0
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_name": self.source_name,
            "source_role": self.source_role,
            "status": self.status,
            "raw_candidates_observed": self.raw_candidates_observed,
            "candidates_accepted": self.candidates_accepted,
            "candidates_rejected": self.candidates_rejected,
            "liveness_passed": self.liveness_passed,
            "liveness_failed": self.liveness_failed,
            "errors": self.errors,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class CollectionManifest:
    """Cryptographically anchored summary manifest of a collection session."""
    session_id: str
    session_status: CollectionSessionStatus
    stopping_reason: CollectionStoppingReason
    start_timestamp_utc: str
    end_timestamp_utc: str
    total_candidates_observed: int = 0
    total_candidates_retained: int = 0
    total_candidates_rejected: int = 0
    total_eligible_unique_targets: int = 0
    modality_counts: Dict[str, int] = field(default_factory=dict)
    source_audits: Dict[str, CollectionSourceAudit] = field(default_factory=dict)
    liveness_summary: Dict[str, int] = field(default_factory=dict)
    ground_truth_summary: Dict[str, int] = field(default_factory=dict)
    ti_exposure_summary: Dict[str, int] = field(default_factory=dict)
    duplicate_counts: Dict[str, int] = field(default_factory=dict)
    raw_artifacts_sha256: str = ""
    manifest_sha256: str = ""
    diagnostics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "session_status": self.session_status.value if hasattr(self.session_status, "value") else str(self.session_status),
            "stopping_reason": self.stopping_reason.value if hasattr(self.stopping_reason, "value") else str(self.stopping_reason),
            "start_timestamp_utc": self.start_timestamp_utc,
            "end_timestamp_utc": self.end_timestamp_utc,
            "total_candidates_observed": self.total_candidates_observed,
            "total_candidates_retained": self.total_candidates_retained,
            "total_candidates_rejected": self.total_candidates_rejected,
            "total_eligible_unique_targets": self.total_eligible_unique_targets,
            "modality_counts": self.modality_counts,
            "source_audits": {k: v.to_dict() for k, v in self.source_audits.items()},
            "liveness_summary": self.liveness_summary,
            "ground_truth_summary": self.ground_truth_summary,
            "ti_exposure_summary": self.ti_exposure_summary,
            "duplicate_counts": self.duplicate_counts,
            "raw_artifacts_sha256": self.raw_artifacts_sha256,
            "manifest_sha256": self.manifest_sha256,
            "diagnostics": self.diagnostics,
        }


@dataclass(frozen=True)
class CollectionResult:
    """Complete in-memory output of the data collection stage."""
    manifest: CollectionManifest
    raw_candidates: List[RawCandidate]
    liveness_results: List[LivenessEvaluation]
    ground_truth_evidence: List[VerificationSourceRecord]
    human_adjudications: List[AdjudicationRecord]
    ti_overlap_records: List[TIOverlapRecord]
    item_audits: List[CollectionItemAudit]
    is_ready_for_assembly: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "manifest": self.manifest.to_dict(),
            "raw_candidates_count": len(self.raw_candidates),
            "liveness_results_count": len(self.liveness_results),
            "ground_truth_evidence_count": len(self.ground_truth_evidence),
            "human_adjudications_count": len(self.human_adjudications),
            "ti_overlap_records_count": len(self.ti_overlap_records),
            "item_audits_count": len(self.item_audits),
            "is_ready_for_assembly": self.is_ready_for_assembly,
        }


# =====================================================================
# Source Role Firewall & Security Validation
# =====================================================================

FORBIDDEN_SOURCE_PATTERNS = [
    re.compile(r"^agent_?\d+", re.IGNORECASE),
    re.compile(r"tce", re.IGNORECASE),
    re.compile(r"aere", re.IGNORECASE),
    re.compile(r"confidence_?engine", re.IGNORECASE),
    re.compile(r"system_?verdict", re.IGNORECASE),
    re.compile(r"report_?generator", re.IGNORECASE),
]


def validate_source_role_firewall(source_config: ApprovedSourceConfig) -> Tuple[bool, List[str]]:
    """Validate that a source configuration complies with the Source Role Firewall."""
    errors: List[str] = []
    src_name = source_config.source_name.strip()

    # Check 1: Forbidden internal forensic system sources
    if is_forbidden_system_source(src_name):
        errors.append(
            f"Source '{src_name}' violates the Ground-Truth Firewall: internal system components cannot act as benchmark sources."
        )

    for pat in FORBIDDEN_SOURCE_PATTERNS:
        if pat.search(src_name):
            errors.append(
                f"Source '{src_name}' matches forbidden system pattern: cannot act as a benchmark collection source."
            )
            break

    # Check 2: Role and category consistency
    role = source_config.source_role
    cat = source_config.source_category

    if role == SourceRole.TI_OVERLAP_SOURCE and cat not in (SourceCategory.TI_EXPOSURE_FEED, SourceCategory.OTHER):
        errors.append(
            f"Source '{src_name}' configured as TI_OVERLAP_SOURCE must have TI_EXPOSURE_FEED category (got {cat.value})."
        )

    if role == SourceRole.GROUND_TRUTH_SOURCE and cat in (SourceCategory.PUBLIC_MALICIOUS_FEED, SourceCategory.PUBLIC_PHISHING_FEED):
        # Public malicious feeds cannot be standalone ground-truth arbiters
        errors.append(
            f"Source '{src_name}' is a public feed ({cat.value}) and cannot be declared as a GROUND_TRUTH_SOURCE directly."
        )

    return len(errors) == 0, errors


def sanitize_pii_parameters(url: str) -> str:
    """Sanitize potentially sensitive user tokens or credentials from query strings while preserving URL structure."""
    if not url or "?" not in url:
        return url

    # Replace sensitive parameter values with redacted placeholders
    sensitive_keys = {
        "password", "pass", "pwd", "token", "auth", "bearer", "api_key",
        "apikey", "secret", "session", "ssid", "creditcard", "cc", "cvv",
        "email", "phone", "ssn"
    }

    def _param_sub(match: re.Match) -> str:
        k = match.group(1)
        if k.lower() in sensitive_keys:
            return f"{k}=[REDACTED]"
        return match.group(0)

    pattern = re.compile(r"([a-zA-Z0-9_\-\.]+)=([^&#]*)")
    return pattern.sub(_param_sub, url)


# =====================================================================
# Benchmark Data Collector Engine
# =====================================================================

class BenchmarkDataCollector:
    """Orchestrator for controlled benchmark data collection and acquisition."""

    def __init__(
        self,
        config: Optional[CollectionConfig] = None,
        harvester: Optional[CandidateHarvester] = None,
        liveness_evaluator: Optional[PassiveLivenessEvaluator] = None,
    ):
        self.config = config or CollectionConfig()
        self.harvester = harvester or CandidateHarvester()
        self.liveness_evaluator = liveness_evaluator or PassiveLivenessEvaluator(
            min_body_bytes=self.config.min_http_body_bytes,
            verify_tls=self.config.require_https_tls,
        )
        self._approved_sources: Dict[str, ApprovedSourceConfig] = {}

        # Register configured approved sources
        for src in self.config.approved_sources:
            self.register_approved_source(src)

    def register_approved_source(self, source_config: ApprovedSourceConfig) -> None:
        """Register an approved source after firewall validation."""
        valid, errors = validate_source_role_firewall(source_config)
        if not valid:
            raise ValueError(f"Invalid source config for '{source_config.source_name}': {'; '.join(errors)}")
        self._approved_sources[source_config.source_name] = source_config

    def get_approved_source(self, source_name: str) -> Optional[ApprovedSourceConfig]:
        """Retrieve an approved source configuration."""
        return self._approved_sources.get(source_name)

    def list_approved_sources(self) -> List[ApprovedSourceConfig]:
        """Return all registered approved source configurations."""
        return list(self._approved_sources.values())

    def collect_dataset(
        self,
        source_inputs: Dict[str, Any],
        ground_truth_evidence: Optional[Sequence[VerificationSourceRecord]] = None,
        human_adjudications: Optional[Sequence[AdjudicationRecord]] = None,
        ti_overlap_records: Optional[Sequence[TIOverlapRecord]] = None,
        harvest_timestamp_override: Optional[str] = None,
    ) -> CollectionResult:
        """Execute complete benchmark data collection across configured sources.

        Args:
            source_inputs: Mapping of source_name -> source_input (file path, raw text, list of dicts, etc.).
            ground_truth_evidence: External ground-truth verification source records.
            human_adjudications: Explicit analyst adjudication records for resolving disputes.
            ti_overlap_records: External TI feed observation records.
            harvest_timestamp_override: Optional ISO timestamp override for deterministic testing.

        Returns:
            CollectionResult containing the manifest, raw candidates, liveness evaluations,
            ground truth, TI overlap records, and audit diagnostics.
        """
        start_time = harvest_timestamp_override or datetime.now(timezone.utc).isoformat()
        session_id = self.config.session_id

        # Step 1: Pre-flight Source Role Firewall Validation
        source_audits: Dict[str, CollectionSourceAudit] = {}
        active_candidate_inputs: Dict[str, Any] = {}
        total_errors: List[str] = []

        for src_name, src_input in source_inputs.items():
            src_cfg = self._approved_sources.get(src_name)
            if not src_cfg:
                total_errors.append(f"Source '{src_name}' is not an approved registered source.")
                source_audits[src_name] = CollectionSourceAudit(
                    source_name=src_name,
                    source_role="UNKNOWN",
                    status="UNREGISTERED",
                    errors=[f"Source '{src_name}' is not an approved registered source."],
                )
                continue

            if not src_cfg.enabled:
                source_audits[src_name] = CollectionSourceAudit(
                    source_name=src_name,
                    source_role=src_cfg.source_role.value,
                    status="DISABLED",
                    metadata={"reason": "Source is disabled in configuration"},
                )
                continue

            # Only candidate sources are passed to candidate harvester
            if src_cfg.source_role == SourceRole.CANDIDATE_SOURCE:
                active_candidate_inputs[src_name] = src_input
            elif src_cfg.source_role == SourceRole.GROUND_TRUTH_SOURCE:
                source_audits[src_name] = CollectionSourceAudit(
                    source_name=src_name,
                    source_role=src_cfg.source_role.value,
                    status="ACTIVE_GT_SOURCE",
                )
            elif src_cfg.source_role == SourceRole.TI_OVERLAP_SOURCE:
                source_audits[src_name] = CollectionSourceAudit(
                    source_name=src_name,
                    source_role=src_cfg.source_role.value,
                    status="ACTIVE_TI_SOURCE",
                )
            else:
                source_audits[src_name] = CollectionSourceAudit(
                    source_name=src_name,
                    source_role=src_cfg.source_role.value,
                    status="AUXILIARY",
                )

        # Step 2: Harvest Raw Candidates
        harvest_result = self.harvester.harvest_all(
            source_inputs=active_candidate_inputs,
            harvest_timestamp=start_time,
        )

        raw_candidates = harvest_result.candidates
        retained_candidates: List[RawCandidate] = []
        rejected_candidates: List[RawCandidate] = []
        item_audits: List[CollectionItemAudit] = []

        stopping_reason = CollectionStoppingReason.NOT_STOPPED

        # Step 3: PII Sanitization & Temporal Filtering & Capacity Stopping
        temporal_cutoff = self.config.temporal_cutoff_utc

        for cand in raw_candidates:
            # Check capacity stopping rule
            if len(retained_candidates) >= self.config.max_practical_ceiling:
                stopping_reason = CollectionStoppingReason.CAPACITY_REACHED
                break

            # Check temporal cutoff if configured
            if temporal_cutoff and cand.first_observed_timestamp:
                if cand.first_observed_timestamp > temporal_cutoff:
                    # Beyond temporal cutoff - exclude from this collection window
                    item_audits.append(CollectionItemAudit(
                        candidate_id=cand.candidate_id,
                        artifact_id=cand.artifact_id,
                        source_name=cand.source_name,
                        modality=cand.modality.value if hasattr(cand.modality, "value") else str(cand.modality),
                        liveness_eligible=False,
                        liveness_status="EXCLUDED_TEMPORAL_CUTOFF",
                        has_ground_truth=False,
                        rejection_reasons=[f"first_observed_timestamp ({cand.first_observed_timestamp}) > cutoff ({temporal_cutoff})"],
                    ))
                    rejected_candidates.append(cand)
                    continue

            # PII Sanitization for URL/payload content
            sanitized_content = cand.raw_content
            if self.config.enable_pii_sanitization and isinstance(cand.raw_content, str):
                sanitized_content = sanitize_pii_parameters(cand.raw_content)

            sanitized_cand = RawCandidate(
                candidate_id=cand.candidate_id,
                raw_content=sanitized_content,
                modality=cand.modality,
                source_name=cand.source_name,
                source_type=cand.source_type,
                source_record_id=cand.source_record_id,
                source_reference=cand.source_reference,
                first_observed_timestamp=cand.first_observed_timestamp,
                harvest_timestamp=cand.harvest_timestamp,
                source_metadata=cand.source_metadata,
                retrieval_status=cand.retrieval_status,
                retrieval_error=cand.retrieval_error,
                license_or_access_notes=cand.license_or_access_notes,
                artifact_id=cand.artifact_id,
            )
            retained_candidates.append(sanitized_cand)

        if stopping_reason == CollectionStoppingReason.NOT_STOPPED:
            stopping_reason = CollectionStoppingReason.SOURCES_EXHAUSTED

        # Step 4: Passive Liveness Evaluation
        liveness_batch = self.liveness_evaluator.evaluate_batch(retained_candidates)
        liveness_map = {ev.candidate_id: ev for ev in liveness_batch.evaluations}

        # Step 5: Index External Ground Truth & TI Metadata
        gt_evidence_list = list(ground_truth_evidence or [])
        human_adjudications_list = list(human_adjudications or [])
        ti_overlap_list = list(ti_overlap_records or [])

        # Build quick reference maps
        gt_map: Dict[str, VerificationSourceRecord] = {}
        for gt in gt_evidence_list:
            gt_map[gt.source_reference.strip().lower()] = gt

        ti_map: Dict[str, TIOverlapRecord] = {}
        for ti in ti_overlap_list:
            ti_map[ti.target_id] = ti

        # Step 6: Assemble Item Audits & Aggregate Metrics
        liveness_summary: Dict[str, int] = {}
        ground_truth_summary: Dict[str, int] = {}
        ti_exposure_summary: Dict[str, int] = {}
        modality_counts: Dict[str, int] = {}
        unique_targets: Set[str] = set()

        for cand in retained_candidates:
            mod_str = cand.modality.value if hasattr(cand.modality, "value") else str(cand.modality)
            modality_counts[mod_str] = modality_counts.get(mod_str, 0) + 1

            l_eval = liveness_map.get(cand.candidate_id)
            l_status = l_eval.liveness_status.value if l_eval else "UNKNOWN"
            l_eligible = (l_eval.eligibility_status == EligibilityStatus.ELIGIBLE) if l_eval else False
            liveness_summary[l_status] = liveness_summary.get(l_status, 0) + 1

            raw_str = cand.raw_content if isinstance(cand.raw_content, str) else ""
            tgt_id = compute_target_id(raw_str)
            if l_eligible:
                unique_targets.add(tgt_id)

            # Match Ground Truth
            matched_gt = gt_map.get(raw_str.strip().lower())
            gt_outcome = matched_gt.asserted_outcome.value if matched_gt else None
            gt_conf = matched_gt.confidence.value if matched_gt else None

            if gt_outcome:
                ground_truth_summary[gt_outcome] = ground_truth_summary.get(gt_outcome, 0) + 1
            else:
                ground_truth_summary["UNASSIGNED_AT_COLLECTION"] = ground_truth_summary.get("UNASSIGNED_AT_COLLECTION", 0) + 1

            # Match TI exposure
            matched_ti = ti_map.get(tgt_id)
            if matched_ti and matched_ti.exposure:
                if matched_ti.exposure.has_any_direct_positive:
                    ti_stratum = "direct"
                elif matched_ti.exposure.has_any_partial_positive:
                    ti_stratum = "partial"
                elif matched_ti.exposure.feeds_observed_negative:
                    ti_stratum = "none"
                else:
                    ti_stratum = "unknown_unavailable"
            else:
                ti_stratum = "none"

            ti_exposure_summary[ti_stratum] = ti_exposure_summary.get(ti_stratum, 0) + 1

            rejection_reasons: List[str] = []
            if not l_eligible:
                rejection_reasons.append(f"Liveness ineligible: {l_status}")

            item_audits.append(CollectionItemAudit(
                candidate_id=cand.candidate_id,
                artifact_id=cand.artifact_id,
                source_name=cand.source_name,
                modality=mod_str,
                liveness_eligible=l_eligible,
                liveness_status=l_status,
                has_ground_truth=bool(matched_gt),
                gt_outcome=gt_outcome,
                gt_confidence=gt_conf,
                ti_exposure_stratum=ti_stratum,
                rejection_reasons=rejection_reasons,
            ))

        # Update source audits with harvest report data
        for src_name, rep in harvest_result.source_reports.items():
            src_cfg = self._approved_sources.get(src_name)
            role_str = src_cfg.source_role.value if src_cfg else "UNKNOWN"
            source_audits[src_name] = CollectionSourceAudit(
                source_name=src_name,
                source_role=role_str,
                status=rep.status.value if hasattr(rep.status, "value") else str(rep.status),
                raw_candidates_observed=rep.candidates_harvested,
                candidates_accepted=len([c for c in retained_candidates if c.source_name == src_name]),
                candidates_rejected=len([c for c in rejected_candidates if c.source_name == src_name]),
                liveness_passed=len([c for c in retained_candidates if c.source_name == src_name and liveness_map.get(c.candidate_id) and liveness_map.get(c.candidate_id).eligibility_status == EligibilityStatus.ELIGIBLE]),
                liveness_failed=len([c for c in retained_candidates if c.source_name == src_name and (not liveness_map.get(c.candidate_id) or liveness_map.get(c.candidate_id).eligibility_status != EligibilityStatus.ELIGIBLE)]),
                errors=rep.errors,
            )

        end_time = harvest_timestamp_override or datetime.now(timezone.utc).isoformat()

        # Step 7: Build Collection Manifest
        raw_artifacts_str = "\n".join(c.candidate_id + ":" + c.artifact_id for c in retained_candidates)
        raw_sha256 = hashlib.sha256(raw_artifacts_str.encode("utf-8")).hexdigest()

        manifest_data = {
            "session_id": session_id,
            "session_status": CollectionSessionStatus.COMPLETED.value,
            "stopping_reason": stopping_reason.value,
            "start_timestamp_utc": start_time,
            "end_timestamp_utc": end_time,
            "total_candidates_observed": len(raw_candidates),
            "total_candidates_retained": len(retained_candidates),
            "total_candidates_rejected": len(rejected_candidates),
            "total_eligible_unique_targets": len(unique_targets),
            "modality_counts": modality_counts,
            "liveness_summary": liveness_summary,
            "ground_truth_summary": ground_truth_summary,
            "ti_exposure_summary": ti_exposure_summary,
            "raw_artifacts_sha256": raw_sha256,
        }
        manifest_sha256 = hashlib.sha256(json.dumps(manifest_data, sort_keys=True).encode("utf-8")).hexdigest()

        manifest = CollectionManifest(
            session_id=session_id,
            session_status=CollectionSessionStatus.COMPLETED,
            stopping_reason=stopping_reason,
            start_timestamp_utc=start_time,
            end_timestamp_utc=end_time,
            total_candidates_observed=len(raw_candidates),
            total_candidates_retained=len(retained_candidates),
            total_candidates_rejected=len(rejected_candidates),
            total_eligible_unique_targets=len(unique_targets),
            modality_counts=modality_counts,
            source_audits=source_audits,
            liveness_summary=liveness_summary,
            ground_truth_summary=ground_truth_summary,
            ti_exposure_summary=ti_exposure_summary,
            duplicate_counts={"exact_duplicates": harvest_result.exact_duplicate_count},
            raw_artifacts_sha256=raw_sha256,
            manifest_sha256=manifest_sha256,
            diagnostics={
                "target_planning_capacity": self.config.target_planning_capacity,
                "min_useful_dataset_size": self.config.min_useful_dataset_size,
                "max_practical_ceiling": self.config.max_practical_ceiling,
                "sources_harvested_count": len(harvest_result.source_counts),
            },
        )

        is_ready = len(retained_candidates) > 0 and len(total_errors) == 0

        return CollectionResult(
            manifest=manifest,
            raw_candidates=retained_candidates,
            liveness_results=liveness_batch.evaluations,
            ground_truth_evidence=gt_evidence_list,
            human_adjudications=human_adjudications_list,
            ti_overlap_records=ti_overlap_list,
            item_audits=item_audits,
            is_ready_for_assembly=is_ready,
        )

    def handoff_to_dataset_assembler(
        self,
        collection_result: CollectionResult,
        assembler: Optional[DatasetAssembler] = None,
        assembly_config: Optional[DatasetAssemblyConfig] = None,
    ) -> DatasetAssemblyResult:
        """Handoff collected candidates and verification records to Step 6D-6 DatasetAssembler.

        Args:
            collection_result: The CollectionResult from collect_dataset().
            assembler: Optional DatasetAssembler instance (defaults to new instance).
            assembly_config: Optional DatasetAssemblyConfig (defaults to standard config).

        Returns:
            DatasetAssemblyResult with locked benchmark records and pre-run gate evaluation.
        """
        asm = assembler or DatasetAssembler(assembly_config or DatasetAssemblyConfig())

        # Build GroundTruth mapping for each candidate
        gt_dict: Dict[str, GroundTruth] = {}
        for cand in collection_result.raw_candidates:
            raw_val = cand.raw_content if isinstance(cand.raw_content, str) else ""
            matching_sources = [
                s for s in collection_result.ground_truth_evidence
                if s.source_reference.strip().lower() == raw_val.strip().lower()
            ]
            matching_adj = None
            if collection_result.human_adjudications:
                matching_adj = collection_result.human_adjudications[0]

            vt_res = verify_candidate_ground_truth(
                candidate=cand,
                sources=matching_sources,
                adjudication=matching_adj,
            )
            tgt_id = compute_target_id(raw_val)
            gt_dict[tgt_id] = vt_res.ground_truth
            gt_dict[cand.candidate_id] = vt_res.ground_truth

        # Build TIOverlapMetadata mapping
        ti_dict: Dict[str, TIOverlapMetadata] = {}
        for ti in collection_result.ti_overlap_records:
            def _convert(feed_enum: TIFeed) -> TIFeedObservation:
                obs = ti.observations.get(feed_enum.value)
                if not obs:
                    return TIFeedObservation(feed_name=feed_enum.value, status=TIObservationStatus.NOT_CHECKED)
                if obs.status in (TIObservationType.DIRECT, TIObservationType.PARTIAL):
                    schema_status = TIObservationStatus.POSITIVE_OBSERVATION
                    is_obs = True
                elif obs.status == TIObservationType.NONE:
                    schema_status = TIObservationStatus.NEGATIVE_OBSERVATION
                    is_obs = False
                else:
                    schema_status = TIObservationStatus.UNAVAILABLE
                    is_obs = False

                return TIFeedObservation(
                    feed_name=feed_enum.value,
                    status=schema_status,
                    observed=is_obs,
                    observed_at=obs.observation_time or "",
                    source_available=(obs.status != TIObservationType.UNKNOWN_UNAVAILABLE),
                    notes=obs.provenance_notes or (f"Ref: {obs.source_reference}" if obs.source_reference else ""),
                )

            ti_meta = TIOverlapMetadata(
                virustotal=_convert(TIFeed.VIRUSTOTAL),
                google_safebrowsing=_convert(TIFeed.GOOGLE_SAFE_BROWSING),
                phishtank=_convert(TIFeed.PHISHTANK),
                openphish=_convert(TIFeed.OPENPHISH),
                urlhaus=_convert(TIFeed.URLHAUS),
                abuseipdb=_convert(TIFeed.ABUSEIPDB),
                spamhaus=_convert(TIFeed.SPAMHAUS),
            )
            ti_dict[ti.target_id] = ti_meta

        # Forward collected components into Step 6D-6 DatasetAssembler
        return asm.assemble(
            raw_candidates=collection_result.raw_candidates,
            liveness_results=collection_result.liveness_results,
            ground_truth_records=gt_dict,
            ti_overlap_records=ti_dict,
            output_dir=asm.config.output_snapshot_dir,
        )


# =====================================================================
# Factory Helper
# =====================================================================

def create_standard_benchmark_collector(
    config: Optional[CollectionConfig] = None,
    http_transport: Optional[Any] = None,
) -> BenchmarkDataCollector:
    """Factory creating a standard BenchmarkDataCollector with pre-approved source definitions."""
    from .harvester import (
        TextListFeedAdapter,
        JSONFeedAdapter,
        CSVFeedAdapter,
        QRImageSourceAdapter,
        QRPayloadSourceAdapter,
    )

    collector = BenchmarkDataCollector(config=config)
    harvester = collector.harvester

    # Register standard approved candidate sources
    approved_sources = [
        ApprovedSourceConfig(
            source_name="openphish_community",
            source_category=SourceCategory.PUBLIC_PHISHING_FEED,
            source_role=SourceRole.CANDIDATE_SOURCE,
            input_modality=InputModality.DIRECT_URL,
            source_reference="https://openphish.com/feed.txt",
            licensing_or_access_notes="Open community feed with attribution",
            rate_limit_policy="Max 1 request / 6 hours",
        ),
        ApprovedSourceConfig(
            source_name="urlhaus_recent",
            source_category=SourceCategory.PUBLIC_MALICIOUS_FEED,
            source_role=SourceRole.CANDIDATE_SOURCE,
            input_modality=InputModality.DIRECT_URL,
            source_reference="https://urlhaus.abuse.ch/downloads/csv_recent/",
            licensing_or_access_notes="CC0 public malicious URL feed",
            rate_limit_policy="Max 1 request / 10 minutes",
        ),
        ApprovedSourceConfig(
            source_name="phishtank_verified",
            source_category=SourceCategory.PUBLIC_PHISHING_FEED,
            source_role=SourceRole.CANDIDATE_SOURCE,
            input_modality=InputModality.DIRECT_URL,
            source_reference="https://data.phishtank.com/data/online-valid.json",
            licensing_or_access_notes="PhishTank developer API terms",
            rate_limit_policy="Max 1 request / 6 hours",
        ),
        ApprovedSourceConfig(
            source_name="tranco_top_curated",
            source_category=SourceCategory.CURATED_BENIGN_REGISTRY,
            source_role=SourceRole.CANDIDATE_SOURCE,
            input_modality=InputModality.DIRECT_URL,
            source_reference="https://tranco-list.eu/",
            licensing_or_access_notes="Tranco research Top 1M list (filtered)",
            rate_limit_policy="Static snapshot download",
        ),
        ApprovedSourceConfig(
            source_name="kaggle_qr_phishing",
            source_category=SourceCategory.RESEARCH_DATASET,
            source_role=SourceRole.CANDIDATE_SOURCE,
            input_modality=InputModality.QR_IMAGE,
            source_reference="kaggle://qr-phishing-dataset",
            licensing_or_access_notes="Open research license",
            rate_limit_policy="Local static archive",
        ),
        ApprovedSourceConfig(
            source_name="synthetic_qr_testbed",
            source_category=SourceCategory.RESEARCH_DATASET,
            source_role=SourceRole.CANDIDATE_SOURCE,
            input_modality=InputModality.QR_PAYLOAD,
            source_reference="internal://qr-testbed-payloads",
            licensing_or_access_notes="Research testbed payloads",
            rate_limit_policy="Local static archive",
        ),
        ApprovedSourceConfig(
            source_name="authoritative_registry_gt",
            source_category=SourceCategory.INCIDENT_RECORDS,
            source_role=SourceRole.GROUND_TRUTH_SOURCE,
            input_modality=InputModality.DIRECT_URL,
            source_reference="registry://whois-takedown-adjudication",
            licensing_or_access_notes="Authoritative registry adjudication logs",
        ),
        ApprovedSourceConfig(
            source_name="virustotal_ti_feed",
            source_category=SourceCategory.TI_EXPOSURE_FEED,
            source_role=SourceRole.TI_OVERLAP_SOURCE,
            input_modality=InputModality.DIRECT_URL,
            source_reference="https://www.virustotal.com/api/v3/",
            licensing_or_access_notes="VirusTotal API terms of service",
            rate_limit_policy="Rate-limited quota",
        ),
    ]

    for src in approved_sources:
        collector.register_approved_source(src)

    # Register default harvester adapters
    harvester.register_adapter(TextListFeedAdapter("openphish_community", HarvesterSourceType.PUBLIC_FEED, InputModality.DIRECT_URL))
    harvester.register_adapter(CSVFeedAdapter("urlhaus_recent", HarvesterSourceType.PUBLIC_FEED, content_column="url", id_column="id", timestamp_column="dateadded"))
    harvester.register_adapter(JSONFeedAdapter("phishtank_verified", HarvesterSourceType.PUBLIC_FEED, content_field="url", id_field="phish_id", timestamp_field="submission_time"))
    harvester.register_adapter(CSVFeedAdapter("tranco_top_curated", HarvesterSourceType.CURATED_LIST, content_column="domain", id_column="rank", has_header=True))
    harvester.register_adapter(QRImageSourceAdapter("kaggle_qr_phishing", HarvesterSourceType.RESEARCH_DATASET))
    harvester.register_adapter(QRPayloadSourceAdapter("synthetic_qr_testbed", HarvesterSourceType.RESEARCH_DATASET))

    if http_transport:
        collector.liveness_evaluator = PassiveLivenessEvaluator(
            transport=http_transport,
            min_body_bytes=collector.config.min_http_body_bytes,
            verify_tls=collector.config.require_https_tls,
        )

    return collector
