"""Benchmark Leakage, Identity, Temporal Exposure, and Snapshot Integrity Auditor.

Step 6C-7: Cross-Split Leakage, Temporal Exposure, Identity, and Snapshot Integrity Audit.

This module provides an offline, independent audit and diagnostic engine that evaluates:
- Exact artifact duplicates and duplicate record IDs
- Cross-partition target leakage and group/eTLD+1 overlap
- QR payload to Direct URL cross-partition relationships
- Temporal Threat-Intelligence (TI) exposure provenance and chronological consistency
- Structural validity of partitions, ground truth, and verification metadata
- Cryptographic snapshot integrity (records.jsonl SHA-256, dataset hash, manifest hash,
  per-record hash indices, and summary count distributions)

Architectural Invariants:
1. No Automatic Repair: Zero silent deletions, label alterations, or partition reassignments.
2. Ground-Truth Independence: Ground truth is never assigned, resolved, or inferred from TI.
3. Three-Tier Identity: Preserves artifact_id != target_id != group_id.
4. Offline & Self-Contained: Zero network calls, DNS queries, or external API access.
5. Deterministic & Input-Order Independent: Stable finding ordering and identical report results.
6. Neutral Provenance Semantics: TI absence does not imply benignity or universal zero-day status.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

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
    canonicalize_record,
    canonicalize_record_dict,
    hash_canonical_record,
    compute_artifact_id,
    compute_target_id,
    compute_group_id,
)
from .manifest_generator import (
    compute_dataset_hash,
    compute_manifest_hash,
)
from .ti_overlap_recorder import (
    TIFeed,
    TIObservationType,
    TIFeedObservationRecord,
    TIOverlapRecord,
    validate_iso8601_timestamp,
)


class AuditSeverity(str, Enum):
    """Controlled severity levels for audit findings."""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class AuditStatus(str, Enum):
    """Controlled overall status for a benchmark audit evaluation."""
    PASS = "PASS"
    PASS_WITH_WARNINGS = "PASS_WITH_WARNINGS"
    FAIL = "FAIL"


@dataclass(frozen=True)
class AuditFinding:
    """Individual diagnostic finding produced during benchmark auditing."""
    code: str
    severity: AuditSeverity
    message: str
    record_ids: List[str] = field(default_factory=list)
    target_ids: List[str] = field(default_factory=list)
    group_ids: List[str] = field(default_factory=list)
    partitions: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to canonical serializable dictionary."""
        return {
            "code": self.code,
            "severity": self.severity.value if hasattr(self.severity, "value") else str(self.severity),
            "message": self.message,
            "record_ids": sorted(self.record_ids),
            "target_ids": sorted(self.target_ids),
            "group_ids": sorted(self.group_ids),
            "partitions": sorted(self.partitions),
            "details": self.details,
        }


@dataclass(frozen=True)
class IntegrityAuditReport:
    """Comprehensive diagnostic audit report covering leakage, identity, and integrity."""
    status: AuditStatus
    findings: List[AuditFinding]
    leakage_summary: Dict[str, Any]
    integrity_summary: Dict[str, Any]
    snapshot_summary: Dict[str, Any]
    total_findings: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert audit report to dictionary."""
        return {
            "status": self.status.value if hasattr(self.status, "value") else str(self.status),
            "total_findings": self.total_findings,
            "findings": [f.to_dict() for f in self.findings],
            "leakage_summary": self.leakage_summary,
            "integrity_summary": self.integrity_summary,
            "snapshot_summary": self.snapshot_summary,
        }


def _severity_rank(sev: AuditSeverity) -> int:
    """Deterministic ordering rank for severity levels."""
    ranks = {
        AuditSeverity.CRITICAL: 0,
        AuditSeverity.ERROR: 1,
        AuditSeverity.WARNING: 2,
        AuditSeverity.INFO: 3,
    }
    return ranks.get(sev, 99)


def _sort_findings(findings: List[AuditFinding]) -> List[AuditFinding]:
    """Sort findings deterministically by severity, code, and identifiers."""
    return sorted(
        findings,
        key=lambda f: (
            _severity_rank(f.severity),
            f.code,
            sorted(f.record_ids),
            sorted(f.target_ids),
            sorted(f.group_ids),
            sorted(f.partitions),
            f.message,
        ),
    )


_ISO8601_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?)?$")


def _is_valid_iso8601(ts_str: Optional[str]) -> bool:
    """Check if string is a valid ISO-8601 timestamp."""
    if not ts_str:
        return False
    return bool(_ISO8601_PATTERN.match(ts_str.strip()))


def _parse_timestamp(ts_str: Optional[str]) -> Optional[str]:
    """Return stripped timestamp string if valid ISO-8601 format."""
    if not ts_str or not isinstance(ts_str, str):
        return None
    cleaned = ts_str.strip()
    return cleaned if _is_valid_iso8601(cleaned) else None


def deserialize_benchmark_record(d: Dict[str, Any]) -> BenchmarkRecord:
    """Safely reconstruct a BenchmarkRecord from a dictionary."""
    # Ground truth
    gt_d = d.get("ground_truth") or {}
    sec_cats: List[SecondaryThreatCategory] = []
    for c in gt_d.get("secondary_categories", []):
        try:
            sec_cats.append(SecondaryThreatCategory(c) if isinstance(c, str) else c)
        except Exception:
            pass

    po_raw = gt_d.get("primary_outcome")
    try:
        po = PrimaryOutcome(po_raw) if po_raw and isinstance(po_raw, str) else po_raw
    except Exception:
        po = po_raw

    vs_raw = gt_d.get("verification_status")
    try:
        vs = VerificationStatus(vs_raw) if vs_raw and isinstance(vs_raw, str) else vs_raw
    except Exception:
        vs = vs_raw

    vc_raw = gt_d.get("verification_confidence")
    try:
        vc = VerificationConfidence(vc_raw) if vc_raw and isinstance(vc_raw, str) else vc_raw
    except Exception:
        vc = vc_raw

    gt = GroundTruth(
        primary_outcome=po,
        secondary_categories=sec_cats,
        verification_status=vs if vs is not None else VerificationStatus.UNVERIFIED,
        verification_method=gt_d.get("verification_method", VerificationMethod.MANUAL_ADJUDICATION.value),
        verification_confidence=vc if vc is not None else VerificationConfidence.HIGH,
        adjudication_status=gt_d.get("adjudication_status", "adjudicated"),
        reviewer_count=gt_d.get("reviewer_count", 1),
        verification_timestamp=gt_d.get("verification_timestamp", ""),
        rationale=gt_d.get("rationale", ""),
        supporting_references=gt_d.get("supporting_references", []),
        contradictory_references=gt_d.get("contradictory_references", []),
    )

    prov_d = d.get("provenance") or {}
    prov = CandidateProvenance(
        source_name=prov_d.get("source_name", ""),
        source_record_id=prov_d.get("source_record_id", ""),
        harvest_timestamp=prov_d.get("harvest_timestamp", ""),
        first_observed_timestamp=prov_d.get("first_observed_timestamp", ""),
        source_notes=prov_d.get("source_notes", ""),
    )

    ti_d = d.get("ti_overlap") or {}
    def _parse_feed(feed_name: str, feed_dict: Dict[str, Any]) -> TIFeedObservation:
        st_raw = feed_dict.get("status")
        try:
            st = TIObservationStatus(st_raw) if st_raw and isinstance(st_raw, str) else st_raw
        except Exception:
            st = st_raw
        return TIFeedObservation(
            feed_name=feed_dict.get("feed_name", feed_name),
            status=st if st is not None else TIObservationStatus.NOT_CHECKED,
            observed=feed_dict.get("observed", False),
            observed_at=feed_dict.get("observed_at", ""),
            source_available=feed_dict.get("source_available", True),
            notes=feed_dict.get("notes", ""),
        )

    ti_overlap = TIOverlapMetadata(
        virustotal=_parse_feed("VirusTotal", ti_d.get("virustotal") or {}),
        google_safebrowsing=_parse_feed("GoogleSafeBrowsing", ti_d.get("google_safebrowsing") or {}),
        phishtank=_parse_feed("PhishTank", ti_d.get("phishtank") or {}),
        openphish=_parse_feed("OpenPhish", ti_d.get("openphish") or {}),
        urlhaus=_parse_feed("URLhaus", ti_d.get("urlhaus") or {}),
        abuseipdb=_parse_feed("AbuseIPDB", ti_d.get("abuseipdb") or {}),
        spamhaus=_parse_feed("Spamhaus", ti_d.get("spamhaus") or {}),
    )

    live_d = d.get("liveness") or {}
    liveness = LivenessMetadata(
        http_status=live_d.get("http_status"),
        dns_resolved=live_d.get("dns_resolved"),
        tls_status=live_d.get("tls_status"),
        response_body_size_bytes=live_d.get("response_body_size_bytes"),
        resolved_ip=live_d.get("resolved_ip"),
        redirect_chain=live_d.get("redirect_chain", []),
        checked_at=live_d.get("checked_at", ""),
        eligibility_status=live_d.get("eligibility_status", "unknown"),
    )

    qr_d = d.get("qr_relationship") or {}
    qr_rel_type_raw = qr_d.get("relationship_type")
    try:
        qr_rel_type = QRRelationshipType(qr_rel_type_raw) if qr_rel_type_raw and isinstance(qr_rel_type_raw, str) else qr_rel_type_raw
    except Exception:
        qr_rel_type = qr_rel_type_raw

    qr_rel = QRRelationshipMetadata(
        artifact_type=qr_d.get("artifact_type", "none"),
        decoded_payload=qr_d.get("decoded_payload"),
        destination_target_id=qr_d.get("destination_target_id"),
        qr_group_id=qr_d.get("qr_group_id"),
        relationship_type=qr_rel_type if qr_rel_type is not None else QRRelationshipType.NONE,
    )

    ev_d = d.get("evaluation") or {}
    part_raw = ev_d.get("temporal_partition")
    try:
        part = TemporalPartition(part_raw) if part_raw and isinstance(part_raw, str) else part_raw
    except Exception:
        part = part_raw

    dup_raw = ev_d.get("duplicate_status")
    try:
        dup = DuplicateStatus(dup_raw) if dup_raw and isinstance(dup_raw, str) else dup_raw
    except Exception:
        dup = dup_raw

    excl_raw = ev_d.get("exclusion_status")
    try:
        excl = ExclusionStatus(excl_raw) if excl_raw and isinstance(excl_raw, str) else excl_raw
    except Exception:
        excl = excl_raw

    ev = EvaluationMetadata(
        group_id=ev_d.get("group_id", ""),
        temporal_partition=part,
        stratum=ev_d.get("stratum", ""),
        duplicate_status=dup if dup is not None else DuplicateStatus.NOT_CHECKED,
        exclusion_status=excl if excl is not None else ExclusionStatus.RETAINED,
        exclusion_reason=ev_d.get("exclusion_reason", ""),
    )

    mod_raw = d.get("modality")
    try:
        mod = InputModality(mod_raw) if mod_raw and isinstance(mod_raw, str) else mod_raw
    except Exception:
        mod = mod_raw

    return BenchmarkRecord(
        record_id=d.get("record_id", ""),
        artifact_id=d.get("artifact_id", ""),
        target_id=d.get("target_id", ""),
        target_url=d.get("target_url", ""),
        modality=mod if mod is not None else InputModality.DIRECT_URL,
        ground_truth=gt,
        provenance=prov,
        ti_overlap=ti_overlap,
        liveness=liveness,
        qr_relationship=qr_rel,
        evaluation=ev,
        schema_version=d.get("schema_version", "1.0.0"),
    )


def audit_ti_observation_records(
    ti_observations: List[TIFeedObservationRecord],
    evaluation_cutoff_timestamp: Optional[str] = None,
) -> List[AuditFinding]:
    """Audit granular TI observation records for temporal exposure, chronological consistency, and validity.

    Audits:
    - Status vocabulary: NONE, DIRECT, PARTIAL, UNKNOWN_UNAVAILABLE
    - Chronological consistency: first_feed_seen_at <= observation_time, retrieved_at >= observation_time
    - ISO-8601 timestamp formats
    - Prior TI exposure diagnosis: first_feed_seen_at < observation_time or cutoff point
    - Semantic guarantees: NONE does NOT imply BENIGN; UNKNOWN_UNAVAILABLE is preserved distinct from NONE.
    """
    findings: List[AuditFinding] = []

    for obs in ti_observations:
        tgt_id = obs.target_id
        feed_name = obs.feed_name.value if hasattr(obs.feed_name, "value") else str(obs.feed_name)

        # 1. Status vocabulary check
        valid_statuses = (
            TIObservationType.NONE,
            TIObservationType.DIRECT,
            TIObservationType.PARTIAL,
            TIObservationType.UNKNOWN_UNAVAILABLE,
        )
        if obs.status not in valid_statuses:
            findings.append(
                AuditFinding(
                    code="INVALID_TI_METADATA",
                    severity=AuditSeverity.ERROR,
                    message=f"TI observation for target '{tgt_id}' feed '{feed_name}' has invalid status: '{obs.status}'",
                    target_ids=[tgt_id],
                    details={"feed": feed_name, "status": str(obs.status)},
                )
            )

        # 2. Timestamp formatting
        for ts_field, ts_val in [
            ("first_feed_seen_at", obs.first_feed_seen_at),
            ("observation_time", obs.observation_time),
            ("retrieved_at", obs.retrieved_at),
        ]:
            if ts_val and not _is_valid_iso8601(ts_val):
                findings.append(
                    AuditFinding(
                        code="TEMPORAL_METADATA_INCONSISTENCY",
                        severity=AuditSeverity.ERROR,
                        message=f"TI observation for target '{tgt_id}' feed '{feed_name}' has malformed {ts_field}: '{ts_val}'",
                        target_ids=[tgt_id],
                        details={"feed": feed_name, "field": ts_field, "value": ts_val},
                    )
                )

        # 3. Chronological contradiction: first_feed_seen_at > observation_time
        if obs.first_feed_seen_at and obs.observation_time:
            if _is_valid_iso8601(obs.first_feed_seen_at) and _is_valid_iso8601(obs.observation_time):
                if obs.first_feed_seen_at > obs.observation_time:
                    findings.append(
                        AuditFinding(
                            code="TEMPORAL_METADATA_INCONSISTENCY",
                            severity=AuditSeverity.ERROR,
                            message=(
                                f"TI observation for target '{tgt_id}' feed '{feed_name}' has first_feed_seen_at "
                                f"({obs.first_feed_seen_at}) later than observation_time ({obs.observation_time})"
                            ),
                            target_ids=[tgt_id],
                            details={
                                "feed": feed_name,
                                "first_feed_seen_at": obs.first_feed_seen_at,
                                "observation_time": obs.observation_time,
                            },
                        )
                    )

        # 4. Chronological contradiction: retrieved_at < observation_time
        if obs.retrieved_at and obs.observation_time:
            if _is_valid_iso8601(obs.retrieved_at) and _is_valid_iso8601(obs.observation_time):
                if obs.retrieved_at < obs.observation_time:
                    findings.append(
                        AuditFinding(
                            code="TEMPORAL_METADATA_INCONSISTENCY",
                            severity=AuditSeverity.ERROR,
                            message=(
                                f"TI observation for target '{tgt_id}' feed '{feed_name}' has retrieved_at "
                                f"({obs.retrieved_at}) earlier than observation_time ({obs.observation_time})"
                            ),
                            target_ids=[tgt_id],
                            details={
                                "feed": feed_name,
                                "retrieved_at": obs.retrieved_at,
                                "observation_time": obs.observation_time,
                            },
                        )
                    )

        # 5. Prior Recorded TI Exposure
        if obs.status in (TIObservationType.DIRECT, TIObservationType.PARTIAL) and obs.first_feed_seen_at:
            if _is_valid_iso8601(obs.first_feed_seen_at):
                is_prior = False
                if obs.observation_time and _is_valid_iso8601(obs.observation_time):
                    if obs.first_feed_seen_at < obs.observation_time:
                        is_prior = True
                elif evaluation_cutoff_timestamp and _is_valid_iso8601(evaluation_cutoff_timestamp):
                    if obs.first_feed_seen_at < evaluation_cutoff_timestamp:
                        is_prior = True

                if is_prior:
                    findings.append(
                        AuditFinding(
                            code="PRIOR_RECORDED_TI_EXPOSURE",
                            severity=AuditSeverity.INFO,
                            message=(
                                f"Target '{tgt_id}' has prior recorded positive TI observation in '{feed_name}' "
                                f"(first seen: {obs.first_feed_seen_at})"
                            ),
                            target_ids=[tgt_id],
                            details={
                                "feed": feed_name,
                                "status": obs.status.value if hasattr(obs.status, "value") else str(obs.status),
                                "first_feed_seen_at": obs.first_feed_seen_at,
                                "observation_time": obs.observation_time,
                            },
                        )
                    )

    return findings


def audit_benchmark_records(
    records: List[BenchmarkRecord],
    ti_observations: Optional[List[TIFeedObservationRecord]] = None,
    evaluation_cutoff_timestamp: Optional[str] = None,
) -> IntegrityAuditReport:
    """Audit an in-memory list of BenchmarkRecords for leakage, identity, and structural validity.

    Audits:
    1. Duplicate Record IDs (CRITICAL)
    2. Exact Artifact Duplication (WARNING)
    3. Target ID Content Conflicts (ERROR)
    4. Cross-Partition Target Leakage (CRITICAL)
    5. Same-Partition Target Multi-Occurrence (INFO)
    6. Cross-Partition Group (eTLD+1/subnet) Overlap (WARNING)
    7. QR <-> Direct URL Cross-Partition Target Leakage (CRITICAL)
    8. QR <-> Direct URL Same-Partition Shared Target (INFO)
    9. Unresolved QR Image Inputs (INFO)
    10. Invalid Partition Assignment (CRITICAL)
    11. Ground-Truth Controlled Vocabulary (ERROR)
    12. Ground-Truth AMBIGUOUS presence (INFO)
    13. Verification Metadata Integrity (ERROR)
    14. TI Metadata Integrity & Controlled Statuses (ERROR)
    15. TI Chronological Consistency (ERROR)
    16. Prior Documented TI Exposure (INFO)

    Guarantees:
    - Input records are NEVER modified.
    - Zero network calls.
    - Deterministic output regardless of input record ordering.
    """
    findings: List[AuditFinding] = []

    # Count summaries
    artifact_counts: Dict[str, List[str]] = {}  # artifact_id -> list of record_ids
    target_records: Dict[str, List[BenchmarkRecord]] = {}  # target_id -> list of records
    group_records: Dict[str, List[BenchmarkRecord]] = {}  # group_id -> list of records
    partition_records: Dict[str, List[BenchmarkRecord]] = {}  # partition -> list of records
    record_id_counts: Dict[str, List[BenchmarkRecord]] = {}  # record_id -> list of records

    # 1. First Pass: Record-level integrity and indexing
    for rec in records:
        record_id_counts.setdefault(rec.record_id, []).append(rec)
        artifact_counts.setdefault(rec.artifact_id, []).append(rec.record_id)
        target_records.setdefault(rec.target_id, []).append(rec)

        grp_id = rec.evaluation.group_id if rec.evaluation else ""
        group_records.setdefault(grp_id, []).append(rec)

        part = rec.evaluation.temporal_partition if rec.evaluation else None
        part_str = part.value if hasattr(part, "value") else str(part) if part is not None else "unassigned"
        partition_records.setdefault(part_str, []).append(rec)

        # 1A. Partition assignment validity
        valid_partitions = (
            TemporalPartition.DEVELOPMENT_CALIBRATION,
            TemporalPartition.VALIDATION,
            TemporalPartition.FINAL_TEST,
            TemporalPartition.PROSPECTIVE_HOLDOUT,
        )
        if part is None or part not in valid_partitions:
            findings.append(
                AuditFinding(
                    code="INVALID_PARTITION_ASSIGNMENT",
                    severity=AuditSeverity.CRITICAL,
                    message=f"Record '{rec.record_id}' has invalid or missing temporal partition: '{part}'",
                    record_ids=[rec.record_id],
                    target_ids=[rec.target_id],
                    group_ids=[grp_id],
                    partitions=[part_str],
                    details={"partition_value": str(part)},
                )
            )

        # 1B. Ground truth vocabulary
        gt = rec.ground_truth
        if gt is None:
            findings.append(
                AuditFinding(
                    code="INVALID_GROUND_TRUTH_VOCABULARY",
                    severity=AuditSeverity.ERROR,
                    message=f"Record '{rec.record_id}' is missing ground truth metadata",
                    record_ids=[rec.record_id],
                    target_ids=[rec.target_id],
                    group_ids=[grp_id],
                    partitions=[part_str],
                )
            )
        else:
            po = gt.primary_outcome
            if po not in (PrimaryOutcome.BENIGN, PrimaryOutcome.MALICIOUS, PrimaryOutcome.AMBIGUOUS):
                findings.append(
                    AuditFinding(
                        code="INVALID_GROUND_TRUTH_VOCABULARY",
                        severity=AuditSeverity.ERROR,
                        message=f"Record '{rec.record_id}' has invalid ground truth primary outcome: '{po}'",
                        record_ids=[rec.record_id],
                        target_ids=[rec.target_id],
                        group_ids=[grp_id],
                        partitions=[part_str],
                        details={"primary_outcome": str(po)},
                    )
                )
            elif po == PrimaryOutcome.AMBIGUOUS:
                findings.append(
                    AuditFinding(
                        code="AMBIGUOUS_GROUND_TRUTH",
                        severity=AuditSeverity.INFO,
                        message=f"Record '{rec.record_id}' has AMBIGUOUS ground truth (preserved without resolution)",
                        record_ids=[rec.record_id],
                        target_ids=[rec.target_id],
                        group_ids=[grp_id],
                        partitions=[part_str],
                    )
                )

            # Verification metadata validity
            vs = gt.verification_status
            valid_vs = (
                VerificationStatus.VERIFIED,
                VerificationStatus.AMBIGUOUS,
                VerificationStatus.DISPUTED,
                VerificationStatus.UNVERIFIABLE,
                VerificationStatus.UNAVAILABLE,
            )
            if vs not in valid_vs:
                findings.append(
                    AuditFinding(
                        code="INVALID_VERIFICATION_METADATA",
                        severity=AuditSeverity.ERROR,
                        message=f"Record '{rec.record_id}' has invalid verification status: '{vs}'",
                        record_ids=[rec.record_id],
                        target_ids=[rec.target_id],
                        group_ids=[grp_id],
                        partitions=[part_str],
                    )
                )

            vc = gt.verification_confidence
            if vc not in (VerificationConfidence.HIGH, VerificationConfidence.MEDIUM, VerificationConfidence.LOW):
                findings.append(
                    AuditFinding(
                        code="INVALID_VERIFICATION_METADATA",
                        severity=AuditSeverity.ERROR,
                        message=f"Record '{rec.record_id}' has invalid verification confidence: '{vc}' (must be HIGH, MEDIUM, or LOW)",
                        record_ids=[rec.record_id],
                        target_ids=[rec.target_id],
                        group_ids=[grp_id],
                        partitions=[part_str],
                    )
                )

        # 1C. QR Image Unresolved check
        if rec.modality in (InputModality.QR_IMAGE, InputModality.QR_PAYLOAD):
            qr_rel = rec.qr_relationship
            if qr_rel and qr_rel.relationship_type == QRRelationshipType.NONE and rec.modality == InputModality.QR_IMAGE and not qr_rel.decoded_payload:
                findings.append(
                    AuditFinding(
                        code="AMBIGUOUS_OR_UNRESOLVED_INPUT",
                        severity=AuditSeverity.INFO,
                        message=f"Record '{rec.record_id}' is an unresolved QR image (preserved as ambiguous input)",
                        record_ids=[rec.record_id],
                        target_ids=[rec.target_id],
                        group_ids=[grp_id],
                        partitions=[part_str],
                        details={"artifact_type": qr_rel.artifact_type},
                    )
                )

        # 1D. TI Metadata in BenchmarkRecord
        ti = rec.ti_overlap
        if ti is not None:
            feed_attrs = [
                ("VirusTotal", ti.virustotal),
                ("GoogleSafeBrowsing", ti.google_safebrowsing),
                ("PhishTank", ti.phishtank),
                ("OpenPhish", ti.openphish),
                ("URLhaus", ti.urlhaus),
                ("AbuseIPDB", ti.abuseipdb),
                ("Spamhaus", ti.spamhaus),
            ]
            for feed_name, feed_obs in feed_attrs:
                if feed_obs is None:
                    continue
                # Validate observation status enum
                valid_ti_statuses = (
                    TIObservationStatus.UNKNOWN,
                    TIObservationStatus.UNAVAILABLE,
                    TIObservationStatus.NOT_CHECKED,
                    TIObservationStatus.NEGATIVE_OBSERVATION,
                    TIObservationStatus.POSITIVE_OBSERVATION,
                )
                if feed_obs.status not in valid_ti_statuses:
                    findings.append(
                        AuditFinding(
                            code="INVALID_TI_METADATA",
                            severity=AuditSeverity.ERROR,
                            message=f"Record '{rec.record_id}' feed '{feed_name}' has invalid status: '{feed_obs.status}'",
                            record_ids=[rec.record_id],
                            target_ids=[rec.target_id],
                            group_ids=[grp_id],
                            partitions=[part_str],
                        )
                    )

                if feed_obs.observed_at and not _is_valid_iso8601(feed_obs.observed_at):
                    findings.append(
                        AuditFinding(
                            code="TEMPORAL_METADATA_INCONSISTENCY",
                            severity=AuditSeverity.ERROR,
                            message=f"Record '{rec.record_id}' feed '{feed_name}' has malformed observed_at timestamp: '{feed_obs.observed_at}'",
                            record_ids=[rec.record_id],
                            target_ids=[rec.target_id],
                            group_ids=[grp_id],
                            partitions=[part_str],
                        )
                    )

    # 1E. Process explicit TI Observation Records if provided
    if ti_observations:
        ti_findings = audit_ti_observation_records(
            ti_observations=ti_observations,
            evaluation_cutoff_timestamp=evaluation_cutoff_timestamp,
        )
        findings.extend(ti_findings)

    # 2. Duplicate Record ID Check (CRITICAL)
    for rec_id, rec_list in sorted(record_id_counts.items()):
        if len(rec_list) > 1:
            all_parts = sorted({r.evaluation.temporal_partition.value if r.evaluation and r.evaluation.temporal_partition and hasattr(r.evaluation.temporal_partition, "value") else str(r.evaluation.temporal_partition) if r.evaluation else "unassigned" for r in rec_list})
            all_tgts = sorted({r.target_id for r in rec_list})
            findings.append(
                AuditFinding(
                    code="DUPLICATE_RECORD_ID",
                    severity=AuditSeverity.CRITICAL,
                    message=f"Duplicate record_id detected across {len(rec_list)} records: '{rec_id}'",
                    record_ids=[rec_id],
                    target_ids=all_tgts,
                    group_ids=sorted({r.evaluation.group_id for r in rec_list if r.evaluation}),
                    partitions=all_parts,
                    details={"occurrence_count": len(rec_list)},
                )
            )

    # 3. Exact Artifact Duplication (WARNING)
    for art_id, rec_ids in sorted(artifact_counts.items()):
        if len(rec_ids) > 1:
            recs_for_art = [r for r in records if r.record_id in rec_ids]
            all_parts = sorted({r.evaluation.temporal_partition.value if r.evaluation and r.evaluation.temporal_partition and hasattr(r.evaluation.temporal_partition, "value") else str(r.evaluation.temporal_partition) if r.evaluation else "unassigned" for r in recs_for_art})
            all_tgts = sorted({r.target_id for r in recs_for_art})
            findings.append(
                AuditFinding(
                    code="EXACT_ARTIFACT_DUPLICATE",
                    severity=AuditSeverity.WARNING,
                    message=f"Identical artifact_id '{art_id}' observed across {len(rec_ids)} records",
                    record_ids=sorted(rec_ids),
                    target_ids=all_tgts,
                    group_ids=sorted({r.evaluation.group_id for r in recs_for_art if r.evaluation}),
                    partitions=all_parts,
                    details={"artifact_id": art_id, "occurrence_count": len(rec_ids)},
                )
            )

    # 4. Target ID Content Conflict Check (ERROR)
    for tgt_id, rec_list in sorted(target_records.items()):
        if len(rec_list) > 1:
            # Check for conflicting target URLs for the same target_id
            target_urls = {r.target_url.strip().lower() for r in rec_list if r.target_url}
            if len(target_urls) > 1:
                # Check if they have materially conflicting schemes or hosts
                # If target_id is identical but target_url has conflicting semantic targets
                all_rec_ids = sorted([r.record_id for r in rec_list])
                all_parts = sorted({r.evaluation.temporal_partition.value if r.evaluation and r.evaluation.temporal_partition and hasattr(r.evaluation.temporal_partition, "value") else str(r.evaluation.temporal_partition) if r.evaluation else "unassigned" for r in rec_list})
                findings.append(
                    AuditFinding(
                        code="TARGET_ID_CONTENT_CONFLICT",
                        severity=AuditSeverity.ERROR,
                        message=f"Target ID '{tgt_id}' is associated with conflicting target URLs: {sorted(list(target_urls))}",
                        record_ids=all_rec_ids,
                        target_ids=[tgt_id],
                        partitions=all_parts,
                        details={"target_urls": sorted(list(target_urls))},
                    )
                )

    # 5. Target Overlap & Cross-Partition Leakage Checks
    for tgt_id, rec_list in sorted(target_records.items()):
        if not tgt_id:
            continue
        if len(rec_list) > 1:
            partition_map: Dict[str, List[BenchmarkRecord]] = {}
            for r in rec_list:
                p_val = r.evaluation.temporal_partition.value if r.evaluation and r.evaluation.temporal_partition and hasattr(r.evaluation.temporal_partition, "value") else str(r.evaluation.temporal_partition) if r.evaluation else "unassigned"
                partition_map.setdefault(p_val, []).append(r)

            if len(partition_map) > 1:
                all_rec_ids = sorted([r.record_id for r in rec_list])
                all_parts = sorted(list(partition_map.keys()))
                all_grps = sorted({r.evaluation.group_id for r in rec_list if r.evaluation})

                modalities = {r.modality for r in rec_list}
                has_qr = any(m in (InputModality.QR_IMAGE, InputModality.QR_PAYLOAD) for m in modalities)
                has_direct = any(m in (InputModality.DIRECT_URL,) for m in modalities)

                if has_qr and has_direct:
                    findings.append(
                        AuditFinding(
                            code="QR_DIRECT_CROSS_PARTITION_LEAKAGE",
                            severity=AuditSeverity.CRITICAL,
                            message=(
                                f"QR artifact and Direct URL artifact share target_id '{tgt_id}' "
                                f"across different partitions ({', '.join(all_parts)})"
                            ),
                            record_ids=all_rec_ids,
                            target_ids=[tgt_id],
                            group_ids=all_grps,
                            partitions=all_parts,
                            details={"modalities": [m.value if hasattr(m, "value") else str(m) for m in modalities], "partitions": all_parts},
                        )
                    )
                else:
                    findings.append(
                        AuditFinding(
                            code="CROSS_PARTITION_TARGET_LEAKAGE",
                            severity=AuditSeverity.CRITICAL,
                            message=(
                                f"Target '{tgt_id}' appears across multiple temporal partitions: {', '.join(all_parts)}"
                            ),
                            record_ids=all_rec_ids,
                            target_ids=[tgt_id],
                            group_ids=all_grps,
                            partitions=all_parts,
                            details={"partitions": all_parts, "record_count": len(rec_list)},
                        )
                    )
            else:
                single_part = list(partition_map.keys())[0]
                all_rec_ids = sorted([r.record_id for r in rec_list])
                all_grps = sorted({r.evaluation.group_id for r in rec_list if r.evaluation})
                modalities = {r.modality for r in rec_list}
                has_qr = any(m in (InputModality.QR_IMAGE, InputModality.QR_PAYLOAD) for m in modalities)
                has_direct = any(m in (InputModality.DIRECT_URL,) for m in modalities)

                if has_qr and has_direct:
                    findings.append(
                        AuditFinding(
                            code="QR_DIRECT_SAME_TARGET_SAME_PARTITION",
                            severity=AuditSeverity.INFO,
                            message=(
                                f"QR artifact and Direct URL artifact share target_id '{tgt_id}' "
                                f"within the same partition ({single_part})"
                            ),
                            record_ids=all_rec_ids,
                            target_ids=[tgt_id],
                            group_ids=all_grps,
                            partitions=[single_part],
                            details={"modalities": [m.value if hasattr(m, "value") else str(m) for m in modalities], "partition": single_part},
                        )
                    )
                else:
                    findings.append(
                        AuditFinding(
                            code="SAME_TARGET_SAME_PARTITION",
                            severity=AuditSeverity.INFO,
                            message=f"Target '{tgt_id}' appears {len(rec_list)} times within partition '{single_part}'",
                            record_ids=all_rec_ids,
                            target_ids=[tgt_id],
                            group_ids=all_grps,
                            partitions=[single_part],
                            details={"partition": single_part, "occurrence_count": len(rec_list)},
                        )
                    )

    # 6. Group Overlap Across Partitions (WARNING)
    for grp_id, rec_list in sorted(group_records.items()):
        if not grp_id:
            continue
        part_tgt_map: Dict[str, Set[str]] = {}
        for r in rec_list:
            p_val = r.evaluation.temporal_partition.value if r.evaluation and r.evaluation.temporal_partition and hasattr(r.evaluation.temporal_partition, "value") else str(r.evaluation.temporal_partition) if r.evaluation else "unassigned"
            part_tgt_map.setdefault(p_val, set()).add(r.target_id)

        if len(part_tgt_map) > 1:
            partitions_list = sorted(list(part_tgt_map.keys()))
            all_rec_ids = sorted([r.record_id for r in rec_list])
            all_tgts = sorted({r.target_id for r in rec_list})
            findings.append(
                AuditFinding(
                    code="CROSS_PARTITION_GROUP_OVERLAP",
                    severity=AuditSeverity.WARNING,
                    message=(
                        f"Domain/group '{grp_id}' contains targets distributed across different partitions: "
                        f"{', '.join(partitions_list)}"
                    ),
                    record_ids=all_rec_ids,
                    target_ids=all_tgts,
                    group_ids=[grp_id],
                    partitions=partitions_list,
                    details={
                        "group_id": grp_id,
                        "partitions": partitions_list,
                        "target_count": len(all_tgts),
                    },
                )
            )

    # Sort all findings deterministically
    sorted_findings = _sort_findings(findings)

    # Determine overall status
    status = AuditStatus.PASS
    has_critical_or_error = any(f.severity in (AuditSeverity.CRITICAL, AuditSeverity.ERROR) for f in sorted_findings)
    has_warning = any(f.severity == AuditSeverity.WARNING for f in sorted_findings)

    if has_critical_or_error:
        status = AuditStatus.FAIL
    elif has_warning:
        status = AuditStatus.PASS_WITH_WARNINGS

    leakage_summary = {
        "cross_partition_target_leakages": sum(1 for f in sorted_findings if f.code in ("CROSS_PARTITION_TARGET_LEAKAGE", "QR_DIRECT_CROSS_PARTITION_LEAKAGE")),
        "cross_partition_group_overlaps": sum(1 for f in sorted_findings if f.code == "CROSS_PARTITION_GROUP_OVERLAP"),
        "qr_direct_cross_partition_leakages": sum(1 for f in sorted_findings if f.code == "QR_DIRECT_CROSS_PARTITION_LEAKAGE"),
        "exact_artifact_duplicates": sum(1 for f in sorted_findings if f.code == "EXACT_ARTIFACT_DUPLICATE"),
        "same_target_same_partition_occurrences": sum(1 for f in sorted_findings if f.code == "SAME_TARGET_SAME_PARTITION"),
    }

    integrity_summary = {
        "duplicate_record_ids": sum(1 for f in sorted_findings if f.code == "DUPLICATE_RECORD_ID"),
        "invalid_partition_assignments": sum(1 for f in sorted_findings if f.code == "INVALID_PARTITION_ASSIGNMENT"),
        "invalid_ground_truth_vocabularies": sum(1 for f in sorted_findings if f.code == "INVALID_GROUND_TRUTH_VOCABULARY"),
        "invalid_verification_metadata": sum(1 for f in sorted_findings if f.code == "INVALID_VERIFICATION_METADATA"),
        "invalid_ti_metadata": sum(1 for f in sorted_findings if f.code == "INVALID_TI_METADATA"),
        "temporal_metadata_inconsistencies": sum(1 for f in sorted_findings if f.code == "TEMPORAL_METADATA_INCONSISTENCY"),
        "ambiguous_ground_truth_count": sum(1 for f in sorted_findings if f.code == "AMBIGUOUS_GROUND_TRUTH"),
        "ambiguous_or_unresolved_inputs": sum(1 for f in sorted_findings if f.code == "AMBIGUOUS_OR_UNRESOLVED_INPUT"),
        "prior_recorded_ti_exposures": sum(1 for f in sorted_findings if f.code == "PRIOR_RECORDED_TI_EXPOSURE"),
    }

    snapshot_summary = {
        "audited_records_count": len(records),
        "unique_target_count": len(target_records),
        "unique_group_count": len(group_records),
        "unique_artifact_count": len(artifact_counts),
    }

    return IntegrityAuditReport(
        status=status,
        findings=sorted_findings,
        leakage_summary=leakage_summary,
        integrity_summary=integrity_summary,
        snapshot_summary=snapshot_summary,
        total_findings=len(sorted_findings),
    )


def audit_benchmark_snapshot(
    snapshot_dir: Union[str, Path],
    records_filename: str = "records.jsonl",
    manifest_filename: str = "manifest.json",
    ti_observations: Optional[List[TIFeedObservationRecord]] = None,
    evaluation_cutoff_timestamp: Optional[str] = None,
) -> IntegrityAuditReport:
    """Audit the complete cryptographic and semantic integrity of a benchmark snapshot directory.

    Checks performed:
    1. Snapshot File Existence: records.jsonl and manifest.json exist (CRITICAL if missing).
    2. Manifest JSON Syntax: Valid canonical JSON (CRITICAL if unparseable).
    3. Records File SHA-256 Hash: Exact match with manifest.records_file_hash (CRITICAL).
    4. Dataset-Level Cryptographic Hash: Exact match with manifest.dataset_hash (CRITICAL).
    5. Manifest Self-Hash: Exact non-circular match with manifest.manifest_hash (CRITICAL).
    6. Record Count Consistency: Line count == manifest.record_count (CRITICAL).
    7. Per-Record Hash Index Verification:
       - Every record in records.jsonl matches its entry in manifest.record_hashes (CRITICAL).
       - No missing records in manifest (CRITICAL).
       - No unexpected records in manifest (CRITICAL).
    8. Descriptive Count Verifications:
       - partition_counts exact match (ERROR).
       - modality_counts exact match (ERROR).
       - ground_truth_counts exact match (ERROR).
       - ti_exposure_counts exact match (ERROR).
    9. In-Memory Record Auditing:
       Runs full audit_benchmark_records() on the loaded records.

    Guarantees:
    - Never modifies snapshot files on disk.
    - Zero network calls.
    - Path-independent cryptographic verification.
    """
    snap_path = Path(snapshot_dir)
    records_file_path = snap_path / records_filename
    manifest_file_path = snap_path / manifest_filename

    findings: List[AuditFinding] = []

    # 1. File existence checks
    if not manifest_file_path.exists():
        findings.append(
            AuditFinding(
                code="SNAPSHOT_FILE_MISSING",
                severity=AuditSeverity.CRITICAL,
                message=f"Manifest file is missing at '{manifest_file_path}'",
                details={"missing_file": str(manifest_file_path)},
            )
        )
        return IntegrityAuditReport(
            status=AuditStatus.FAIL,
            findings=_sort_findings(findings),
            leakage_summary={},
            integrity_summary={},
            snapshot_summary={"snapshot_dir": str(snapshot_dir)},
            total_findings=len(findings),
        )

    if not records_file_path.exists():
        findings.append(
            AuditFinding(
                code="SNAPSHOT_FILE_MISSING",
                severity=AuditSeverity.CRITICAL,
                message=f"Records file is missing at '{records_file_path}'",
                details={"missing_file": str(records_file_path)},
            )
        )
        return IntegrityAuditReport(
            status=AuditStatus.FAIL,
            findings=_sort_findings(findings),
            leakage_summary={},
            integrity_summary={},
            snapshot_summary={"snapshot_dir": str(snapshot_dir)},
            total_findings=len(findings),
        )

    # 2. Parse manifest JSON
    try:
        with open(manifest_file_path, "r", encoding="utf-8") as f:
            manifest_dict = json.load(f)
    except Exception as e:
        findings.append(
            AuditFinding(
                code="MANIFEST_PARSE_ERROR",
                severity=AuditSeverity.CRITICAL,
                message=f"Failed to parse manifest JSON file: {str(e)}",
                details={"manifest_file": str(manifest_file_path), "error": str(e)},
            )
        )
        return IntegrityAuditReport(
            status=AuditStatus.FAIL,
            findings=_sort_findings(findings),
            leakage_summary={},
            integrity_summary={},
            snapshot_summary={"snapshot_dir": str(snapshot_dir)},
            total_findings=len(findings),
        )

    # 3. Verify records.jsonl file SHA-256 hash
    recorded_records_file_hash = manifest_dict.get("records_file_hash", "")
    hasher = hashlib.sha256()
    with open(records_file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    computed_records_file_hash = hasher.hexdigest()

    if recorded_records_file_hash != computed_records_file_hash:
        findings.append(
            AuditFinding(
                code="SNAPSHOT_FILE_HASH_MISMATCH",
                severity=AuditSeverity.CRITICAL,
                message=(
                    f"records.jsonl file hash mismatch: recorded in manifest '{recorded_records_file_hash}' "
                    f"!= computed '{computed_records_file_hash}'"
                ),
                details={
                    "recorded_records_file_hash": recorded_records_file_hash,
                    "computed_records_file_hash": computed_records_file_hash,
                },
            )
        )

    # 4. Verify manifest hash
    recorded_manifest_hash = manifest_dict.get("manifest_hash", "")
    computed_manifest_hash = compute_manifest_hash(manifest_dict)
    if recorded_manifest_hash != computed_manifest_hash:
        findings.append(
            AuditFinding(
                code="MANIFEST_HASH_MISMATCH",
                severity=AuditSeverity.CRITICAL,
                message=(
                    f"Manifest hash mismatch: recorded '{recorded_manifest_hash}' != "
                    f"computed '{computed_manifest_hash}'"
                ),
                details={
                    "recorded_manifest_hash": recorded_manifest_hash,
                    "computed_manifest_hash": computed_manifest_hash,
                },
            )
        )

    # 5. Read records and load BenchmarkRecord instances
    loaded_records: List[BenchmarkRecord] = []
    line_number = 0
    with open(records_file_path, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue
            line_number += 1
            try:
                rec_dict = json.loads(line_str)
                rec = deserialize_benchmark_record(rec_dict)
                loaded_records.append(rec)
            except Exception as e:
                findings.append(
                    AuditFinding(
                        code="RECORD_PARSE_ERROR",
                        severity=AuditSeverity.CRITICAL,
                        message=f"Failed to parse BenchmarkRecord at line {line_number}: {str(e)}",
                        details={"line_number": line_number, "error": str(e)},
                    )
                )

    # 6. Verify Record Count
    recorded_record_count = manifest_dict.get("record_count")
    if recorded_record_count is not None and recorded_record_count != len(loaded_records):
        findings.append(
            AuditFinding(
                code="RECORD_COUNT_MISMATCH",
                severity=AuditSeverity.CRITICAL,
                message=(
                    f"Record count mismatch: manifest recorded {recorded_record_count} "
                    f"!= actual records loaded {len(loaded_records)}"
                ),
                details={
                    "manifest_record_count": recorded_record_count,
                    "actual_record_count": len(loaded_records),
                },
            )
        )

    # 7. Verify Dataset Hash
    computed_dataset_hash = compute_dataset_hash(sorted(loaded_records, key=lambda r: r.record_id))
    recorded_dataset_hash = manifest_dict.get("dataset_hash", "")
    if recorded_dataset_hash != computed_dataset_hash:
        findings.append(
            AuditFinding(
                code="DATASET_HASH_MISMATCH",
                severity=AuditSeverity.CRITICAL,
                message=(
                    f"Dataset cryptographic hash mismatch: manifest recorded '{recorded_dataset_hash}' "
                    f"!= recomputed '{computed_dataset_hash}'"
                ),
                details={
                    "recorded_dataset_hash": recorded_dataset_hash,
                    "computed_dataset_hash": computed_dataset_hash,
                },
            )
        )

    # 8. Verify Record Hash Index
    manifest_record_hashes = manifest_dict.get("record_hashes", [])
    manifest_hash_map: Dict[str, str] = {}
    manifest_record_id_seen: Set[str] = set()

    for entry in manifest_record_hashes:
        rid = entry.get("record_id", "")
        rhash = entry.get("record_hash", "")
        if rid in manifest_record_id_seen:
            findings.append(
                AuditFinding(
                    code="DUPLICATE_RECORD_ID",
                    severity=AuditSeverity.CRITICAL,
                    message=f"Duplicate record entry in manifest record_hashes: '{rid}'",
                    record_ids=[rid],
                )
            )
        manifest_record_id_seen.add(rid)
        manifest_hash_map[rid] = rhash

    loaded_record_ids: Set[str] = set()
    for rec in loaded_records:
        loaded_record_ids.add(rec.record_id)
        computed_rec_hash = hash_canonical_record(rec)

        if rec.record_id not in manifest_hash_map:
            findings.append(
                AuditFinding(
                    code="MANIFEST_MISSING_RECORD",
                    severity=AuditSeverity.CRITICAL,
                    message=f"Record '{rec.record_id}' present in records.jsonl is missing from manifest record_hashes index",
                    record_ids=[rec.record_id],
                    target_ids=[rec.target_id],
                )
            )
        else:
            recorded_rec_hash = manifest_hash_map[rec.record_id]
            if recorded_rec_hash != computed_rec_hash:
                findings.append(
                    AuditFinding(
                        code="RECORD_HASH_MISMATCH",
                        severity=AuditSeverity.CRITICAL,
                        message=(
                            f"Record hash mismatch for record '{rec.record_id}': manifest recorded '{recorded_rec_hash}' "
                            f"!= computed '{computed_rec_hash}'"
                        ),
                        record_ids=[rec.record_id],
                        target_ids=[rec.target_id],
                        details={
                            "recorded_record_hash": recorded_rec_hash,
                            "computed_record_hash": computed_rec_hash,
                        },
                    )
                )

    for rid in manifest_record_id_seen:
        if rid not in loaded_record_ids:
            findings.append(
                AuditFinding(
                    code="MANIFEST_UNEXPECTED_RECORD",
                    severity=AuditSeverity.CRITICAL,
                    message=f"Record '{rid}' listed in manifest record_hashes is not present in records.jsonl",
                    record_ids=[rid],
                )
            )

    # 9. Verify Descriptive Distribution Counts
    recalculated_partition_counts: Dict[str, int] = {}
    recalculated_modality_counts: Dict[str, int] = {}
    recalculated_ground_truth_counts: Dict[str, int] = {}
    recalculated_ti_exposure_counts: Dict[str, int] = {
        "virustotal_positive": 0,
        "google_safebrowsing_positive": 0,
        "phishtank_positive": 0,
        "openphish_positive": 0,
        "urlhaus_positive": 0,
        "abuseipdb_positive": 0,
        "spamhaus_positive": 0,
        "any_ti_positive": 0,
    }

    for r in loaded_records:
        p_val = r.evaluation.temporal_partition.value if r.evaluation and r.evaluation.temporal_partition and hasattr(r.evaluation.temporal_partition, "value") else str(r.evaluation.temporal_partition) if r.evaluation else "unassigned"
        recalculated_partition_counts[p_val] = recalculated_partition_counts.get(p_val, 0) + 1

        m_val = r.modality.value if hasattr(r.modality, "value") else str(r.modality)
        recalculated_modality_counts[m_val] = recalculated_modality_counts.get(m_val, 0) + 1

        gt_val = r.ground_truth.primary_outcome.value if r.ground_truth and hasattr(r.ground_truth.primary_outcome, "value") else str(r.ground_truth.primary_outcome) if r.ground_truth else "unknown"
        recalculated_ground_truth_counts[gt_val] = recalculated_ground_truth_counts.get(gt_val, 0) + 1

        ti = r.ti_overlap
        if ti is not None:
            any_pos = False
            for feed_key, feed_obj in [
                ("virustotal_positive", ti.virustotal),
                ("google_safebrowsing_positive", ti.google_safebrowsing),
                ("phishtank_positive", ti.phishtank),
                ("openphish_positive", ti.openphish),
                ("urlhaus_positive", ti.urlhaus),
                ("abuseipdb_positive", ti.abuseipdb),
                ("spamhaus_positive", ti.spamhaus),
            ]:
                if feed_obj and feed_obj.observed:
                    recalculated_ti_exposure_counts[feed_key] += 1
                    any_pos = True
            if any_pos:
                recalculated_ti_exposure_counts["any_ti_positive"] += 1

    manifest_partition_counts = manifest_dict.get("partition_counts", {})
    if manifest_partition_counts != recalculated_partition_counts:
        findings.append(
            AuditFinding(
                code="PARTITION_COUNT_MISMATCH",
                severity=AuditSeverity.ERROR,
                message=(
                    f"Partition count distribution mismatch: manifest recorded {manifest_partition_counts} "
                    f"!= recalculated {recalculated_partition_counts}"
                ),
                details={
                    "manifest_partition_counts": manifest_partition_counts,
                    "recalculated_partition_counts": recalculated_partition_counts,
                },
            )
        )

    manifest_modality_counts = manifest_dict.get("modality_counts", {})
    if manifest_modality_counts != recalculated_modality_counts:
        findings.append(
            AuditFinding(
                code="MODALITY_COUNT_MISMATCH",
                severity=AuditSeverity.ERROR,
                message=(
                    f"Modality count distribution mismatch: manifest recorded {manifest_modality_counts} "
                    f"!= recalculated {recalculated_modality_counts}"
                ),
                details={
                    "manifest_modality_counts": manifest_modality_counts,
                    "recalculated_modality_counts": recalculated_modality_counts,
                },
            )
        )

    manifest_gt_counts = manifest_dict.get("ground_truth_counts", {})
    if manifest_gt_counts != recalculated_ground_truth_counts:
        findings.append(
            AuditFinding(
                code="GROUND_TRUTH_COUNT_MISMATCH",
                severity=AuditSeverity.ERROR,
                message=(
                    f"Ground-truth count distribution mismatch: manifest recorded {manifest_gt_counts} "
                    f"!= recalculated {recalculated_ground_truth_counts}"
                ),
                details={
                    "manifest_ground_truth_counts": manifest_gt_counts,
                    "recalculated_ground_truth_counts": recalculated_ground_truth_counts,
                },
            )
        )

    manifest_ti_counts = manifest_dict.get("ti_exposure_counts")
    if manifest_ti_counts is not None and manifest_ti_counts != recalculated_ti_exposure_counts:
        findings.append(
            AuditFinding(
                code="TI_EXPOSURE_COUNT_MISMATCH",
                severity=AuditSeverity.ERROR,
                message=(
                    f"TI exposure count distribution mismatch: manifest recorded {manifest_ti_counts} "
                    f"!= recalculated {recalculated_ti_exposure_counts}"
                ),
                details={
                    "manifest_ti_exposure_counts": manifest_ti_counts,
                    "recalculated_ti_exposure_counts": recalculated_ti_exposure_counts,
                },
            )
        )

    # 10. Run Full In-Memory Record Audits
    records_audit_report = audit_benchmark_records(
        records=loaded_records,
        ti_observations=ti_observations,
        evaluation_cutoff_timestamp=evaluation_cutoff_timestamp,
    )
    findings.extend(records_audit_report.findings)

    # Compile Final Report
    sorted_findings = _sort_findings(findings)

    status = AuditStatus.PASS
    has_critical_or_error = any(f.severity in (AuditSeverity.CRITICAL, AuditSeverity.ERROR) for f in sorted_findings)
    has_warning = any(f.severity == AuditSeverity.WARNING for f in sorted_findings)

    if has_critical_or_error:
        status = AuditStatus.FAIL
    elif has_warning:
        status = AuditStatus.PASS_WITH_WARNINGS

    snapshot_summary_merged = dict(records_audit_report.snapshot_summary)
    snapshot_summary_merged.update({
        "snapshot_dir": str(snapshot_dir),
        "records_file": records_filename,
        "manifest_file": manifest_filename,
        "records_file_hash_valid": (recorded_records_file_hash == computed_records_file_hash),
        "dataset_hash_valid": (recorded_dataset_hash == computed_dataset_hash),
        "manifest_hash_valid": (recorded_manifest_hash == computed_manifest_hash),
        "record_count_valid": (recorded_record_count == len(loaded_records)),
    })

    return IntegrityAuditReport(
        status=status,
        findings=sorted_findings,
        leakage_summary=records_audit_report.leakage_summary,
        integrity_summary=records_audit_report.integrity_summary,
        snapshot_summary=snapshot_summary_merged,
        total_findings=len(sorted_findings),
    )
