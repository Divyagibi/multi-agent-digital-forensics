"""Benchmark package for Multi-Agent Digital Forensics & Digital Trust Investigation System.

Step 6C-1: Benchmark dataset schema, identity model, and deterministic serialization.
Step 6C-2: Normalization, deduplication, grouping & leakage identity.
Step 6C-3: QR / Direct URL relationship handling.
Step 6C-4: Independent ground-truth verification records.
Step 6C-5: Threat Intelligence (TI) overlap metadata recording.
Step 6C-6: Reproducible benchmark snapshot, manifest, and integrity hashing.
Step 6C-7: Cross-split leakage, temporal exposure, identity, and snapshot integrity audit.
Step 6D-2: Candidate harvesting and raw candidate pool layer.
Step 6D-3: Passive liveness and candidate eligibility layer.
Step 6D-4: Independent ground-truth verification.
Step 6D-5: Experimental benchmark evaluation layer.
"""

from .schemas import (
    # Controlled Enums
    InputModality,
    PrimaryOutcome,
    SecondaryThreatCategory,
    VerificationStatus,
    VerificationMethod,
    VerificationConfidence,
    TIObservationStatus,
    TemporalPartition,
    DuplicateStatus,
    ExclusionStatus,
    QRRelationshipType,
    # Dataclasses
    CandidateProvenance,
    GroundTruth,
    TIFeedObservation,
    TIOverlapMetadata,
    LivenessMetadata,
    QRRelationshipMetadata,
    EvaluationMetadata,
    BenchmarkRecord,
    BenchmarkManifest,
    # Identity & Serialization Helpers
    compute_artifact_id,
    compute_target_id,
    compute_group_id,
    compute_record_id,
    canonicalize_record_dict,
    canonicalize_record,
    sha256_bytes,
    hash_canonical_record,
    validate_benchmark_record,
    ValidationError,
)

from .normalization import (
    NormalizedTarget,
    OverlapType,
    DuplicateRelation,
    LeakageFinding,
    DeduplicationResult,
    normalize_investigation_target,
    classify_relation,
    detect_cross_split_leakage,
    deduplicate_records,
)

from .qr_relationships import (
    QRTargetResolutionStatus,
    QRDirectRelationType,
    QRPayloadResolution,
    QRDirectRelationship,
    resolve_qr_payload_target,
    analyze_qr_direct_relationship,
    correlate_qr_and_direct_records,
)

from .ground_truth_verifier import (
    SourceType as GTSourceType,
    VerificationSourceRecord,
    AdjudicationRecord,
    GroundTruthVerificationResult,
    verify_ground_truth,
    verify_candidate_ground_truth,
    attach_verified_ground_truth,
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
    attach_ti_overlap,
)

from .manifest_generator import (
    compute_dataset_hash,
    compute_manifest_hash,
    generate_benchmark_manifest,
)

from .snapshot_writer import (
    write_benchmark_snapshot,
    verify_snapshot_integrity,
)

from .integrity_auditor import (
    AuditSeverity,
    AuditStatus,
    AuditFinding,
    IntegrityAuditReport,
    deserialize_benchmark_record,
    audit_ti_observation_records,
    audit_benchmark_records,
    audit_benchmark_snapshot,
)

from .harvester import (
    SourceType,
    RetrievalStatus,
    RawCandidate,
    SourceHarvestReport,
    HarvestingResult,
    compute_candidate_id,
    BaseSourceAdapter,
    TextListFeedAdapter,
    JSONFeedAdapter,
    CSVFeedAdapter,
    QRImageSourceAdapter,
    QRPayloadSourceAdapter,
    CustomSourceAdapter,
    CandidateHarvester,
)

from .liveness import (
    LivenessStatus,
    EligibilityStatus,
    LivenessFailureReason,
    HTTPResponseObservation,
    BaseHTTPTransport,
    MockHTTPTransport,
    RequestsHTTPTransport,
    LivenessEvaluation,
    LivenessBatchResult,
    PassiveLivenessEvaluator,
    evaluate_candidate_liveness,
    evaluate_batch_liveness,
)

from .evaluator import (
    ExperimentalCondition,
    GroundingFidelityStatus,
    SystemPrediction,
    RiskBandContingencyTable,
    EvaluationMetrics,
    StatisticalComparisonResult,
    ConditionEvaluationReport,
    BenchmarkEvaluationSuiteResult,
    BenchmarkEvaluator,
    BaselineAdapter,
    compute_binary_metrics,
    compute_roc_auc,
    compute_pr_auc,
    compute_bootstrap_confidence_intervals,
    compute_mcnemar_test,
    compute_wilcoxon_signed_rank,
    compute_cohens_d,
    compute_odds_ratio,
    compute_risk_band_name,
    evaluate_benchmark_suite,
)

from .dataset_assembler import (
    DatasetAssemblyGateStatus,
    DatasetAssemblyConfig,
    DatasetAssemblyDiagnostics,
    DatasetAssemblyGateResult,
    DatasetAssemblyResult,
    DatasetAssembler,
)

__all__ = [
    # Schemas
    "InputModality",
    "PrimaryOutcome",
    "SecondaryThreatCategory",
    "VerificationStatus",
    "VerificationMethod",
    "VerificationConfidence",
    "TIObservationStatus",
    "TemporalPartition",
    "DuplicateStatus",
    "ExclusionStatus",
    "QRRelationshipType",
    "CandidateProvenance",
    "GroundTruth",
    "TIFeedObservation",
    "TIOverlapMetadata",
    "LivenessMetadata",
    "QRRelationshipMetadata",
    "EvaluationMetadata",
    "BenchmarkRecord",
    "BenchmarkManifest",
    "compute_artifact_id",
    "compute_target_id",
    "compute_group_id",
    "compute_record_id",
    "canonicalize_record_dict",
    "canonicalize_record",
    "sha256_bytes",
    "hash_canonical_record",
    "validate_benchmark_record",
    "ValidationError",
    # Normalization & Deduplication
    "NormalizedTarget",
    "OverlapType",
    "DuplicateRelation",
    "LeakageFinding",
    "DeduplicationResult",
    "normalize_investigation_target",
    "classify_relation",
    "detect_cross_split_leakage",
    "deduplicate_records",
    # QR Relationships
    "QRTargetResolutionStatus",
    "QRDirectRelationType",
    "QRPayloadResolution",
    "QRDirectRelationship",
    "resolve_qr_payload_target",
    "analyze_qr_direct_relationship",
    "correlate_qr_and_direct_records",
    # Ground Truth Verification
    "GTSourceType",
    "VerificationSourceRecord",
    "AdjudicationRecord",
    "GroundTruthVerificationResult",
    "verify_ground_truth",
    "verify_candidate_ground_truth",
    "attach_verified_ground_truth",
    "is_forbidden_system_source",
    # TI Overlap Recording
    "TIFeed",
    "TIObservationType",
    "TIFeedObservationRecord",
    "TIExposureSummary",
    "TIOverlapRecord",
    "validate_iso8601_timestamp",
    "record_ti_observation",
    "build_ti_overlap_metadata",
    "attach_ti_overlap",
    # Snapshot & Manifest
    "compute_dataset_hash",
    "compute_manifest_hash",
    "generate_benchmark_manifest",
    "write_benchmark_snapshot",
    "verify_snapshot_integrity",
    # Integrity Auditor
    "AuditSeverity",
    "AuditStatus",
    "AuditFinding",
    "IntegrityAuditReport",
    "deserialize_benchmark_record",
    "audit_ti_observation_records",
    "audit_benchmark_records",
    "audit_benchmark_snapshot",
    # Candidate Harvester
    "SourceType",
    "RetrievalStatus",
    "RawCandidate",
    "SourceHarvestReport",
    "HarvestingResult",
    "compute_candidate_id",
    "BaseSourceAdapter",
    "TextListFeedAdapter",
    "JSONFeedAdapter",
    "CSVFeedAdapter",
    "QRImageSourceAdapter",
    "QRPayloadSourceAdapter",
    "CustomSourceAdapter",
    "CandidateHarvester",
    # Passive Liveness & Eligibility
    "LivenessStatus",
    "EligibilityStatus",
    "LivenessFailureReason",
    "HTTPResponseObservation",
    "BaseHTTPTransport",
    "MockHTTPTransport",
    "RequestsHTTPTransport",
    "LivenessEvaluation",
    "LivenessBatchResult",
    "PassiveLivenessEvaluator",
    "evaluate_candidate_liveness",
    "evaluate_batch_liveness",
    # Experimental Benchmark Evaluation Layer
    "ExperimentalCondition",
    "GroundingFidelityStatus",
    "SystemPrediction",
    "RiskBandContingencyTable",
    "EvaluationMetrics",
    "StatisticalComparisonResult",
    "ConditionEvaluationReport",
    "BenchmarkEvaluationSuiteResult",
    "BenchmarkEvaluator",
    "BaselineAdapter",
    "compute_binary_metrics",
    "compute_roc_auc",
    "compute_pr_auc",
    "compute_bootstrap_confidence_intervals",
    "compute_mcnemar_test",
    "compute_wilcoxon_signed_rank",
    "compute_cohens_d",
    "compute_odds_ratio",
    "compute_risk_band_name",
    "evaluate_benchmark_suite",
    # Dataset Assembly & Pre-Run Gate
    "DatasetAssemblyGateStatus",
    "DatasetAssemblyConfig",
    "DatasetAssemblyDiagnostics",
    "DatasetAssemblyGateResult",
    "DatasetAssemblyResult",
    "DatasetAssembler",
]
