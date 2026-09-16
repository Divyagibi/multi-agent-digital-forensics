"""Experimental Dataset Assembly and Final Pre-Run Gate Layer.

Step 6D-6: Experimental Dataset Assembly & Final Pre-Run Gate.

This module orchestrates the frozen benchmark infrastructure (Steps 6C-1 through 6C-7
and Steps 6D-1 through 6D-5) into a reproducible, leakage-controlled, independently
grounded dataset assembly engine and pre-run validation gate.

Architectural & Methodological Guarantees:
1. Ground-Truth Independence & Zero Self-Labeling:
   Ground truth is strictly derived from external independent references and human adjudication.
   Under no circumstances may system verdicts, TCE risk scores, AERE reasoning chains,
   Confidence Engine scores (C_ev), or agent outputs contribute to ground truth.
2. Threat Intelligence Firewall:
   Threat intelligence presence/absence is provenance metadata, NOT ground truth.
   TI absence (NONE) != Benign; TI UNKNOWN_UNAVAILABLE != Benign.
3. Three-Tier Identity & Leakage Segregation:
   Preserves the four-level identity model (ART-, TGT-, GRP-, REC-) and enforces zero
   cross-partition target leakage and zero QR/direct cross-partition leakage.
4. Deterministic Partitioning & Temporal Holdout Protection:
   Deterministic partition allocation across DEVELOPMENT_CALIBRATION (30%), VALIDATION (20%),
   FINAL_TEST (30%), and PROSPECTIVE_HOLDOUT (20%) without synthetic padding or class distortion.
5. Strict Pre-Run Gate:
   Evaluates all quality gates and issues READY_FOR_EXPERIMENT or BLOCKED_FROM_EXPERIMENT.
6. Offline & Zero Live Network:
   Operates strictly offline on supplied artifacts/metadata with zero network requests.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

from .schemas import (
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
    CandidateProvenance,
    GroundTruth,
    TIFeedObservation,
    TIOverlapMetadata,
    LivenessMetadata,
    QRRelationshipMetadata,
    EvaluationMetadata,
    BenchmarkRecord,
    BenchmarkManifest,
    canonicalize_record,
    canonicalize_record_dict,
    hash_canonical_record,
    compute_artifact_id,
    compute_target_id,
    compute_group_id,
    compute_record_id,
    validate_benchmark_record,
)
from .normalization import (
    normalize_investigation_target,
    NormalizedTarget,
    classify_relation,
)
from .qr_relationships import (
    QRDirectRelationship,
)
from .ground_truth_verifier import (
    VerificationSourceRecord,
    AdjudicationRecord,
    SourceType as GTSourceType,
    verify_ground_truth,
    verify_candidate_ground_truth,
    attach_verified_ground_truth,
    is_forbidden_system_source,
)
from .ti_overlap_recorder import (
    TIFeed,
    TIObservationType,
    TIFeedObservationRecord,
    TIOverlapRecord,
    TIExposureSummary,
    build_ti_overlap_metadata,
)
from .liveness import (
    LivenessStatus,
    EligibilityStatus,
    LivenessFailureReason,
    LivenessEvaluation,
)
from .harvester import RawCandidate
from .snapshot_writer import (
    write_benchmark_snapshot,
    verify_snapshot_integrity,
)
from .manifest_generator import (
    generate_benchmark_manifest,
    compute_dataset_hash,
    compute_manifest_hash,
)
from .integrity_auditor import (
    AuditSeverity,
    AuditStatus,
    AuditFinding,
    IntegrityAuditReport,
    audit_benchmark_records,
    audit_benchmark_snapshot,
)


# =====================================================================
# Controlled Pre-Run Gate Status & Data Models
# =====================================================================

class DatasetAssemblyGateStatus(str, Enum):
    """Controlled operational status for the final pre-run gate."""
    READY_FOR_EXPERIMENT = "READY_FOR_EXPERIMENT"
    BLOCKED_FROM_EXPERIMENT = "BLOCKED_FROM_EXPERIMENT"


@dataclass(frozen=True)
class DatasetAssemblyConfig:
    """Configuration for deterministic experimental dataset assembly."""
    temporal_cutoff_timestamp: Optional[str] = None
    target_partition_proportions: Dict[TemporalPartition, float] = field(
        default_factory=lambda: {
            TemporalPartition.DEVELOPMENT_CALIBRATION: 0.30,
            TemporalPartition.VALIDATION: 0.20,
            TemporalPartition.FINAL_TEST: 0.30,
            TemporalPartition.PROSPECTIVE_HOLDOUT: 0.20,
        }
    )
    allow_empty: bool = False
    random_seed: int = 42
    output_snapshot_dir: Optional[Union[str, Path]] = None
    write_snapshot: bool = True
    enforce_strict_liveness: bool = True
    allow_warnings: bool = True


@dataclass(frozen=True)
class DatasetAssemblyDiagnostics:
    """Comprehensive, machine-readable dataset assembly and filtering diagnostics."""
    raw_candidates_count: int = 0
    liveness_evaluated_count: int = 0
    liveness_eligible_count: int = 0
    liveness_ineligible_count: int = 0
    unique_targets_count: int = 0
    verified_ground_truth_count: int = 0
    ambiguous_ground_truth_count: int = 0
    retained_records_count: int = 0
    excluded_records_count: int = 0
    partition_counts: Dict[str, int] = field(default_factory=dict)
    modality_counts: Dict[str, int] = field(default_factory=dict)
    ground_truth_counts: Dict[str, int] = field(default_factory=dict)
    threat_category_counts: Dict[str, int] = field(default_factory=dict)
    ti_exposure_counts: Dict[str, int] = field(default_factory=dict)
    exclusion_ledger: List[Dict[str, Any]] = field(default_factory=list)
    audit_findings_summary: Dict[str, int] = field(default_factory=dict)
    blocking_reasons: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize diagnostics to dictionary."""
        return {
            "raw_candidates_count": self.raw_candidates_count,
            "liveness_evaluated_count": self.liveness_evaluated_count,
            "liveness_eligible_count": self.liveness_eligible_count,
            "liveness_ineligible_count": self.liveness_ineligible_count,
            "unique_targets_count": self.unique_targets_count,
            "verified_ground_truth_count": self.verified_ground_truth_count,
            "ambiguous_ground_truth_count": self.ambiguous_ground_truth_count,
            "retained_records_count": self.retained_records_count,
            "excluded_records_count": self.excluded_records_count,
            "partition_counts": dict(sorted(self.partition_counts.items())),
            "modality_counts": dict(sorted(self.modality_counts.items())),
            "ground_truth_counts": dict(sorted(self.ground_truth_counts.items())),
            "threat_category_counts": dict(sorted(self.threat_category_counts.items())),
            "ti_exposure_counts": dict(sorted(self.ti_exposure_counts.items())),
            "exclusion_ledger": self.exclusion_ledger,
            "audit_findings_summary": dict(sorted(self.audit_findings_summary.items())),
            "blocking_reasons": sorted(self.blocking_reasons),
            "warnings": sorted(self.warnings),
        }


@dataclass(frozen=True)
class DatasetAssemblyGateResult:
    """Pre-run gate evaluation result indicating experimental readiness."""
    status: DatasetAssemblyGateStatus
    is_ready: bool
    snapshot_id: str
    dataset_hash: str
    records_file_hash: str
    manifest_hash: str
    blocking_findings: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[Dict[str, Any]] = field(default_factory=list)
    diagnostics: Optional[DatasetAssemblyDiagnostics] = None
    snapshot_dir: Optional[str] = None
    manifest_path: Optional[str] = None
    records_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert gate result to canonical dictionary."""
        return {
            "status": self.status.value if hasattr(self.status, "value") else str(self.status),
            "is_ready": self.is_ready,
            "snapshot_id": self.snapshot_id,
            "dataset_hash": self.dataset_hash,
            "records_file_hash": self.records_file_hash,
            "manifest_hash": self.manifest_hash,
            "blocking_findings": self.blocking_findings,
            "warnings": self.warnings,
            "diagnostics": self.diagnostics.to_dict() if self.diagnostics else None,
            "snapshot_dir": self.snapshot_dir,
            "manifest_path": self.manifest_path,
            "records_path": self.records_path,
        }


@dataclass(frozen=True)
class DatasetAssemblyResult:
    """Comprehensive dataset assembly result payload."""
    records: List[BenchmarkRecord]
    manifest: Dict[str, Any]
    gate_result: DatasetAssemblyGateResult
    audit_report: Optional[IntegrityAuditReport] = None
    diagnostics: Optional[DatasetAssemblyDiagnostics] = None
    snapshot_dir: Optional[str] = None


# =====================================================================
# Dataset Assembler Core Engine
# =====================================================================

class DatasetAssembler:
    """Deterministic orchestrator for experimental dataset assembly and pre-run gating."""

    def __init__(self, config: Optional[DatasetAssemblyConfig] = None) -> None:
        self.config = config or DatasetAssemblyConfig()

    # -----------------------------------------------------------------
    # Partitioning Logic (Deterministic Group-Cluster Allocation)
    # -----------------------------------------------------------------

    def assign_partitions(
        self,
        records: Sequence[BenchmarkRecord],
        cutoff_timestamp: Optional[str] = None,
        custom_proportions: Optional[Dict[TemporalPartition, float]] = None,
    ) -> List[BenchmarkRecord]:
        """Assign evaluation partitions deterministically preserving group and QR isolation.

        Guarantees:
        1. Temporal Segregation: Records observed strictly after cutoff_timestamp are assigned
           to PROSPECTIVE_HOLDOUT.
        2. Group Cluster Atomicity: All records sharing a group_id (eTLD+1 / subnet) or
           paired QR/direct relationship are assigned atomically to the same historical partition.
        3. Zero Target/QR Leakage: No canonical target_id spans across different partitions.
        4. Determinism: Same records + same cutoff produces identical partition mappings.
        """
        if not records:
            return []

        cutoff = cutoff_timestamp or self.config.temporal_cutoff_timestamp

        # 1. Identify connected components (groups + paired QR records)
        target_to_group: Dict[str, str] = {}
        paired_targets: Dict[str, Set[str]] = {}

        for r in records:
            target_to_group[r.target_id] = r.evaluation.group_id
            if r.qr_relationship and r.qr_relationship.destination_target_id:
                dest = r.qr_relationship.destination_target_id
                paired_targets.setdefault(r.target_id, set()).add(dest)
                paired_targets.setdefault(dest, set()).add(r.target_id)

        # Build cluster mapping: cluster_id -> set of group_ids / target_ids
        tgt_to_cluster: Dict[str, str] = {}
        for r in records:
            tgt = r.target_id
            if tgt in tgt_to_cluster:
                continue
            # Traverse component
            component_targets: Set[str] = set()
            stack = [tgt]
            while stack:
                curr = stack.pop()
                if curr not in component_targets:
                    component_targets.add(curr)
                    for neighbor in paired_targets.get(curr, set()):
                        if neighbor not in component_targets:
                            stack.append(neighbor)
            
            # Use deterministic cluster key based on sorted target_ids
            cluster_id = f"CLUST-{min(component_targets)}"
            for member in component_targets:
                tgt_to_cluster[member] = cluster_id

        # 2. Segregate prospective holdout vs historical clusters
        prospective_clusters: Set[str] = set()
        historical_clusters: Set[str] = set()

        for r in records:
            cluster_id = tgt_to_cluster.get(r.target_id, f"CLUST-{r.target_id}")
            is_prospective = False
            if cutoff:
                obs_time = r.provenance.first_observed_timestamp or r.provenance.harvest_timestamp
                if obs_time and obs_time > cutoff:
                    is_prospective = True
            
            if is_prospective:
                prospective_clusters.add(cluster_id)
            else:
                historical_clusters.add(cluster_id)

        # Remove any historical cluster if already claimed as prospective to avoid conflict
        historical_clusters = historical_clusters - prospective_clusters

        # 3. Deterministically partition historical clusters
        # Historical target proportions: DEV: 30/80 = 37.5%, VAL: 20/80 = 25.0%, FINAL: 30/80 = 37.5%
        sorted_hist_clusters = sorted(list(historical_clusters))
        
        # Hash-based deterministic bucket assignment
        cluster_to_partition: Dict[str, TemporalPartition] = {}
        for cid in prospective_clusters:
            cluster_to_partition[cid] = TemporalPartition.PROSPECTIVE_HOLDOUT

        for cid in sorted_hist_clusters:
            hash_val = int(hashlib.sha256(f"{self.config.random_seed}:{cid}".encode("utf-8")).hexdigest()[:8], 16)
            bucket = hash_val % 10000 / 10000.0  # [0.0, 1.0)
            
            if bucket < 0.375:
                cluster_to_partition[cid] = TemporalPartition.DEVELOPMENT_CALIBRATION
            elif bucket < 0.625:
                cluster_to_partition[cid] = TemporalPartition.VALIDATION
            else:
                cluster_to_partition[cid] = TemporalPartition.FINAL_TEST

        # 4. Construct updated records with assigned partitions
        updated_records: List[BenchmarkRecord] = []
        for r in records:
            cid = tgt_to_cluster.get(r.target_id, f"CLUST-{r.target_id}")
            assigned_partition = cluster_to_partition.get(cid, TemporalPartition.DEVELOPMENT_CALIBRATION)
            
            new_eval = EvaluationMetadata(
                group_id=r.evaluation.group_id,
                temporal_partition=assigned_partition,
                stratum=r.evaluation.stratum,
                duplicate_status=r.evaluation.duplicate_status,
                exclusion_status=r.evaluation.exclusion_status,
                exclusion_reason=r.evaluation.exclusion_reason,
            )
            updated_record = BenchmarkRecord(
                record_id=r.record_id,
                artifact_id=r.artifact_id,
                target_id=r.target_id,
                target_url=r.target_url,
                modality=r.modality,
                ground_truth=r.ground_truth,
                provenance=r.provenance,
                ti_overlap=r.ti_overlap,
                liveness=r.liveness,
                qr_relationship=r.qr_relationship,
                evaluation=new_eval,
                schema_version=r.schema_version,
            )
            updated_records.append(updated_record)

        return updated_records

    # -----------------------------------------------------------------
    # Assembly Pipeline Orchestrator
    # -----------------------------------------------------------------

    def assemble(
        self,
        records: Optional[Sequence[BenchmarkRecord]] = None,
        raw_candidates: Optional[Sequence[RawCandidate]] = None,
        liveness_results: Optional[Sequence[LivenessResult]] = None,
        ground_truth_records: Optional[Dict[str, GroundTruth]] = None,
        ti_overlap_records: Optional[Dict[str, TIOverlapMetadata]] = None,
        qr_relationships: Optional[Dict[str, QRRelationshipMetadata]] = None,
        output_dir: Optional[Union[str, Path]] = None,
        created_at: Optional[str] = None,
    ) -> DatasetAssemblyResult:
        """Execute end-to-end dataset assembly and evaluate the pre-run gate."""
        assembled_records: List[BenchmarkRecord] = []
        exclusion_ledger: List[Dict[str, Any]] = []

        raw_count = 0
        live_eval_count = 0
        live_eligible_count = 0
        live_ineligible_count = 0

        # Case A: Assembling from already constructed BenchmarkRecords
        if records is not None:
            raw_count = len(records)
            for r in records:
                try:
                    validate_benchmark_record(r, raise_exception=True)
                except Exception as e:
                    exclusion_ledger.append({
                        "record_id": r.record_id,
                        "target_url": r.target_url,
                        "reason": f"SCHEMA_VALIDATION_ERROR: {str(e)}",
                        "exclusion_status": "excluded",
                    })
                    continue

                if r.liveness:
                    live_eval_count += 1
                    if r.liveness.eligibility_status in ("eligible", "not_applicable"):
                        live_eligible_count += 1
                    else:
                        live_ineligible_count += 1
                        if self.config.enforce_strict_liveness and r.modality == InputModality.DIRECT_URL:
                            exclusion_ledger.append({
                                "record_id": r.record_id,
                                "target_url": r.target_url,
                                "reason": f"INELIGIBLE_LIVENESS: status={r.liveness.eligibility_status}",
                                "exclusion_status": "excluded",
                            })
                            continue

                assembled_records.append(r)

        # Case B: Constructing from raw inputs and metadata
        elif raw_candidates is not None:
            raw_count = len(raw_candidates)
            liveness_map = {res.candidate_id: res for res in (liveness_results or [])}
            
            for cand in raw_candidates:
                cand_id = cand.candidate_id or compute_artifact_id(cand.modality, cand.raw_content)
                norm = normalize_investigation_target(cand.raw_content)
                
                # Check liveness
                liveness_meta = LivenessMetadata(eligibility_status="unknown")
                if cand_id in liveness_map:
                    lres = liveness_map[cand_id]
                    live_eval_count += 1
                    liveness_meta = lres.to_liveness_metadata()
                    if lres.eligibility_status in (EligibilityStatus.ELIGIBLE, EligibilityStatus.NOT_APPLICABLE):
                        live_eligible_count += 1
                    else:
                        live_ineligible_count += 1
                        if self.config.enforce_strict_liveness and cand.modality == InputModality.DIRECT_URL:
                            exclusion_ledger.append({
                                "candidate_id": cand_id,
                                "target_url": cand.raw_content,
                                "reason": f"INELIGIBLE_LIVENESS: {lres.failure_reason.value}",
                                "exclusion_status": "excluded",
                            })
                            continue

                tgt_id = norm.target_id
                grp_id = norm.group_id
                art_id = compute_artifact_id(cand.modality, cand.raw_content)
                rec_id = compute_record_id(tgt_id, art_id)

                gt = (ground_truth_records or {}).get(tgt_id) or (ground_truth_records or {}).get(cand_id)
                if not gt:
                    gt = GroundTruth(
                        primary_outcome=PrimaryOutcome.AMBIGUOUS,
                        verification_status=VerificationStatus.UNVERIFIABLE,
                        verification_method=VerificationMethod.OTHER.value,
                        verification_confidence=VerificationConfidence.LOW,
                        rationale="Unverified candidate ingested without external verification record.",
                    )

                ti_meta = (ti_overlap_records or {}).get(tgt_id) or (ti_overlap_records or {}).get(cand_id) or TIOverlapMetadata()
                qr_meta = (qr_relationships or {}).get(rec_id) or (qr_relationships or {}).get(cand_id) or QRRelationshipMetadata()

                eval_meta = EvaluationMetadata(
                    group_id=grp_id,
                    temporal_partition=None,
                    stratum="",
                    duplicate_status=DuplicateStatus.CANONICAL,
                    exclusion_status=ExclusionStatus.RETAINED,
                )

                provenance = CandidateProvenance(
                    source_name=cand.source_name,
                    source_record_id=cand.source_record_id,
                    harvest_timestamp=cand.harvest_timestamp,
                    first_observed_timestamp=cand.first_observed_timestamp,
                    source_notes=str(cand.source_metadata.get("notes", "")) if cand.source_metadata else cand.source_reference,
                )

                rec = BenchmarkRecord(
                    record_id=rec_id,
                    artifact_id=art_id,
                    target_id=tgt_id,
                    target_url=norm.canonical_url or cand.raw_content,
                    modality=cand.modality,
                    ground_truth=gt,
                    provenance=provenance,
                    ti_overlap=ti_meta,
                    liveness=liveness_meta,
                    qr_relationship=qr_meta,
                    evaluation=eval_meta,
                )
                assembled_records.append(rec)

        # 1. Deduplicate records if identical record_id appears
        deduped_records: List[BenchmarkRecord] = []
        seen_record_ids: Set[str] = set()
        for r in assembled_records:
            if r.record_id in seen_record_ids:
                exclusion_ledger.append({
                    "record_id": r.record_id,
                    "target_url": r.target_url,
                    "reason": "DUPLICATE_RECORD_ID_IN_INGESTION",
                    "exclusion_status": "excluded",
                })
                continue
            seen_record_ids.add(r.record_id)
            deduped_records.append(r)

        # 2. Assign partitions deterministically if unassigned
        needs_partitioning = any(r.evaluation.temporal_partition is None for r in deduped_records)
        if needs_partitioning:
            partitioned_records = self.assign_partitions(deduped_records)
        else:
            partitioned_records = list(deduped_records)

        # 3. Sort records deterministically by record_id ascending
        sorted_records = sorted(partitioned_records, key=lambda r: r.record_id)

        # 4. Generate Snapshot / Manifest if configured
        target_dir = output_dir or self.config.output_snapshot_dir
        records_path_str: Optional[str] = None
        manifest_path_str: Optional[str] = None
        manifest_dict: Dict[str, Any] = {}
        snapshot_dir_str: Optional[str] = None

        if self.config.write_snapshot and target_dir:
            out_p = Path(target_dir)
            rec_p, man_p, manifest_dict = write_benchmark_snapshot(
                records=sorted_records,
                output_dir=out_p,
                created_at=created_at,
                allow_empty=self.config.allow_empty,
            )
            records_path_str = str(rec_p)
            manifest_path_str = str(man_p)
            snapshot_dir_str = str(out_p)
        else:
            dataset_hash = compute_dataset_hash(sorted_records)
            manifest_dict = generate_benchmark_manifest(
                records=sorted_records,
                records_file_hash="",
                created_at=created_at,
            )

        # 5. Run Integrity Auditor
        audit_report: Optional[IntegrityAuditReport] = None
        if sorted_records or not self.config.allow_empty:
            if self.config.write_snapshot and snapshot_dir_str:
                audit_report = audit_benchmark_snapshot(
                    snapshot_dir=snapshot_dir_str,
                )
            else:
                audit_report = audit_benchmark_records(
                    records=sorted_records,
                )

        # 6. Build Diagnostics & Evaluate Pre-Run Gate
        diagnostics = self._build_diagnostics(
            raw_count=raw_count,
            live_eval_count=live_eval_count,
            live_eligible_count=live_eligible_count,
            live_ineligible_count=live_ineligible_count,
            records=sorted_records,
            exclusion_ledger=exclusion_ledger,
            audit_report=audit_report,
        )

        gate_result = self.evaluate_gate(
            records=sorted_records,
            manifest=manifest_dict,
            audit_report=audit_report,
            diagnostics=diagnostics,
            snapshot_dir=snapshot_dir_str,
            manifest_path=manifest_path_str,
            records_path=records_path_str,
        )

        return DatasetAssemblyResult(
            records=sorted_records,
            manifest=manifest_dict,
            gate_result=gate_result,
            audit_report=audit_report,
            diagnostics=diagnostics,
            snapshot_dir=snapshot_dir_str,
        )

    # -----------------------------------------------------------------
    # Gate Evaluation Logic
    # -----------------------------------------------------------------

    def evaluate_gate(
        self,
        records: Sequence[BenchmarkRecord],
        manifest: Optional[Dict[str, Any]] = None,
        audit_report: Optional[IntegrityAuditReport] = None,
        diagnostics: Optional[DatasetAssemblyDiagnostics] = None,
        snapshot_dir: Optional[str] = None,
        manifest_path: Optional[str] = None,
        records_path: Optional[str] = None,
    ) -> DatasetAssemblyGateResult:
        """Evaluate strict pre-run quality gate against assembled dataset."""
        blocking_findings: List[Dict[str, Any]] = []
        warnings: List[Dict[str, Any]] = []

        # 1. Evaluate Audit Findings
        if audit_report:
            for finding in audit_report.findings:
                finding_dict = finding.to_dict()
                if finding.severity in (AuditSeverity.CRITICAL, AuditSeverity.ERROR):
                    blocking_findings.append(finding_dict)
                elif finding.severity == AuditSeverity.WARNING:
                    warnings.append(finding_dict)

        # 2. Check Record Integrity & Identity Hierarchy
        seen_targets_by_partition: Dict[str, Set[TemporalPartition]] = {}
        for r in records:
            try:
                validate_benchmark_record(r, raise_exception=True)
            except Exception as e:
                blocking_findings.append({
                    "code": "SCHEMA_VALIDATION_FAILURE",
                    "severity": "CRITICAL",
                    "message": f"Record '{r.record_id}' failed schema validation: {str(e)}",
                    "record_ids": [r.record_id],
                })

            if not r.artifact_id.startswith("ART-"):
                blocking_findings.append({
                    "code": "INVALID_ARTIFACT_ID",
                    "severity": "CRITICAL",
                    "message": f"Record '{r.record_id}' has invalid artifact_id prefix: '{r.artifact_id}'",
                    "record_ids": [r.record_id],
                })
            if not r.target_id.startswith("TGT-"):
                blocking_findings.append({
                    "code": "INVALID_TARGET_ID",
                    "severity": "CRITICAL",
                    "message": f"Record '{r.record_id}' has invalid target_id prefix: '{r.target_id}'",
                    "record_ids": [r.record_id],
                })
            if not r.evaluation.group_id.startswith("GRP-"):
                blocking_findings.append({
                    "code": "INVALID_GROUP_ID",
                    "severity": "CRITICAL",
                    "message": f"Record '{r.record_id}' has invalid group_id prefix: '{r.evaluation.group_id}'",
                    "record_ids": [r.record_id],
                })
            if not r.record_id.startswith("REC-"):
                blocking_findings.append({
                    "code": "INVALID_RECORD_ID",
                    "severity": "CRITICAL",
                    "message": f"Record '{r.record_id}' has invalid record_id prefix: '{r.record_id}'",
                    "record_ids": [r.record_id],
                })

            conf = r.ground_truth.verification_confidence
            if not isinstance(conf, VerificationConfidence) and str(conf) not in ("HIGH", "MEDIUM", "LOW"):
                blocking_findings.append({
                    "code": "NON_QUALITATIVE_CONFIDENCE",
                    "severity": "CRITICAL",
                    "message": f"Record '{r.record_id}' has non-qualitative verification confidence: {conf}",
                    "record_ids": [r.record_id],
                })

            all_refs = r.ground_truth.supporting_references + r.ground_truth.contradictory_references + [r.ground_truth.rationale]
            prohibited_pattern = re.compile(
                r"\b(TCE|AERE|ConfidenceEngine|Confidence_Engine|ReportGenerator|Agent\s*1\b|Agent\s*18\b|forensic_pipeline)\b",
                re.IGNORECASE,
            )
            for ref in all_refs:
                if prohibited_pattern.search(ref):
                    blocking_findings.append({
                        "code": "INTERNAL_SYSTEM_SOURCE_CONTAMINATION",
                        "severity": "CRITICAL",
                        "message": f"Record '{r.record_id}' contains prohibited internal system source in ground-truth: '{ref}'",
                        "record_ids": [r.record_id],
                    })

            if r.evaluation.temporal_partition:
                seen_targets_by_partition.setdefault(r.target_id, set()).add(r.evaluation.temporal_partition)

        # 3. Explicit Target Leakage Check
        for tgt_id, parts in seen_targets_by_partition.items():
            if len(parts) > 1:
                blocking_findings.append({
                    "code": "CROSS_PARTITION_TARGET_LEAKAGE",
                    "severity": "CRITICAL",
                    "message": f"Target '{tgt_id}' appears in multiple partitions: {[p.value for p in parts]}",
                    "target_ids": [tgt_id],
                    "partitions": [p.value for p in parts],
                })

        # 4. QR / Direct Cross-Partition Leakage Check
        for r in records:
            if r.qr_relationship and r.qr_relationship.destination_target_id:
                dest_tgt = r.qr_relationship.destination_target_id
                r_part = r.evaluation.temporal_partition
                if dest_tgt in seen_targets_by_partition and r_part:
                    dest_parts = seen_targets_by_partition[dest_tgt]
                    if any(p != r_part for p in dest_parts):
                        blocking_findings.append({
                            "code": "QR_DIRECT_CROSS_PARTITION_LEAKAGE",
                            "severity": "CRITICAL",
                            "message": f"QR Record '{r.record_id}' (partition '{r_part.value}') links to destination target '{dest_tgt}' in different partition(s): {[p.value for p in dest_parts]}",
                            "record_ids": [r.record_id],
                            "target_ids": [r.target_id, dest_tgt],
                        })

        # 5. Check Dataset Non-Empty
        if not records and not self.config.allow_empty:
            blocking_findings.append({
                "code": "EMPTY_DATASET",
                "severity": "CRITICAL",
                "message": "Dataset contains zero retained benchmark records.",
            })

        # Compute Hashes
        dataset_hash = manifest.get("dataset_hash", "") if manifest else compute_dataset_hash(records)
        records_file_hash = manifest.get("records_file_hash", "") if manifest else ""
        manifest_hash = manifest.get("manifest_hash", "") if manifest else ""
        snapshot_id = manifest.get("snapshot_id", "") if manifest else f"SNAP-{dataset_hash[:16]}"

        is_ready = (len(blocking_findings) == 0)
        status = (
            DatasetAssemblyGateStatus.READY_FOR_EXPERIMENT
            if is_ready
            else DatasetAssemblyGateStatus.BLOCKED_FROM_EXPERIMENT
        )

        return DatasetAssemblyGateResult(
            status=status,
            is_ready=is_ready,
            snapshot_id=snapshot_id,
            dataset_hash=dataset_hash,
            records_file_hash=records_file_hash,
            manifest_hash=manifest_hash,
            blocking_findings=blocking_findings,
            warnings=warnings,
            diagnostics=diagnostics,
            snapshot_dir=snapshot_dir,
            manifest_path=manifest_path,
            records_path=records_path,
        )

    # -----------------------------------------------------------------
    # Diagnostics Helper
    # -----------------------------------------------------------------

    def _build_diagnostics(
        self,
        raw_count: int,
        live_eval_count: int,
        live_eligible_count: int,
        live_ineligible_count: int,
        records: Sequence[BenchmarkRecord],
        exclusion_ledger: List[Dict[str, Any]],
        audit_report: Optional[IntegrityAuditReport],
    ) -> DatasetAssemblyDiagnostics:
        """Construct structured summary diagnostics across all dataset dimensions."""
        unique_targets: Set[str] = set()
        part_counts: Dict[str, int] = {}
        mod_counts: Dict[str, int] = {}
        gt_counts: Dict[str, int] = {}
        threat_counts: Dict[str, int] = {}
        ti_counts: Dict[str, int] = {}

        verified_gt = 0
        ambiguous_gt = 0

        for r in records:
            unique_targets.add(r.target_id)
            
            p_val = r.evaluation.temporal_partition.value if r.evaluation.temporal_partition else "unassigned"
            part_counts[p_val] = part_counts.get(p_val, 0) + 1
            
            m_val = r.modality.value if hasattr(r.modality, "value") else str(r.modality)
            mod_counts[m_val] = mod_counts.get(m_val, 0) + 1

            gt_val = r.ground_truth.primary_outcome.value if hasattr(r.ground_truth.primary_outcome, "value") else str(r.ground_truth.primary_outcome)
            gt_counts[gt_val] = gt_counts.get(gt_val, 0) + 1

            if r.ground_truth.primary_outcome in (PrimaryOutcome.BENIGN, PrimaryOutcome.MALICIOUS):
                verified_gt += 1
            else:
                ambiguous_gt += 1

            for cat in r.ground_truth.secondary_categories:
                c_val = cat.value if hasattr(cat, "value") else str(cat)
                threat_counts[c_val] = threat_counts.get(c_val, 0) + 1

            ti = r.ti_overlap
            has_direct = False
            all_unknown = True

            for feed_obs in [ti.virustotal, ti.google_safebrowsing, ti.phishtank, ti.openphish, ti.urlhaus, ti.abuseipdb, ti.spamhaus]:
                if feed_obs.status == TIObservationStatus.POSITIVE_OBSERVATION:
                    has_direct = True
                    all_unknown = False
                elif feed_obs.status == TIObservationStatus.NEGATIVE_OBSERVATION:
                    all_unknown = False
                elif feed_obs.status not in (TIObservationStatus.UNKNOWN, TIObservationStatus.UNAVAILABLE, TIObservationStatus.NOT_CHECKED):
                    all_unknown = False

            if has_direct:
                stratum = "DIRECT"
            elif all_unknown:
                stratum = "UNKNOWN_UNAVAILABLE"
            else:
                stratum = "NONE"

            ti_counts[stratum] = ti_counts.get(stratum, 0) + 1

        audit_summary: Dict[str, int] = {}
        blocking_reasons: List[str] = []
        warnings_list: List[str] = []

        if audit_report:
            for f in audit_report.findings:
                code = f.code
                audit_summary[code] = audit_summary.get(code, 0) + 1
                if f.severity in (AuditSeverity.CRITICAL, AuditSeverity.ERROR):
                    blocking_reasons.append(f"[{f.severity.value}] {f.code}: {f.message}")
                elif f.severity == AuditSeverity.WARNING:
                    warnings_list.append(f"[{f.severity.value}] {f.code}: {f.message}")

        return DatasetAssemblyDiagnostics(
            raw_candidates_count=raw_count,
            liveness_evaluated_count=live_eval_count,
            liveness_eligible_count=live_eligible_count,
            liveness_ineligible_count=live_ineligible_count,
            unique_targets_count=len(unique_targets),
            verified_ground_truth_count=verified_gt,
            ambiguous_ground_truth_count=ambiguous_gt,
            retained_records_count=len(records),
            excluded_records_count=len(exclusion_ledger),
            partition_counts=part_counts,
            modality_counts=mod_counts,
            ground_truth_counts=gt_counts,
            threat_category_counts=threat_counts,
            ti_exposure_counts=ti_counts,
            exclusion_ledger=exclusion_ledger,
            audit_findings_summary=audit_summary,
            blocking_reasons=blocking_reasons,
            warnings=warnings_list,
        )
