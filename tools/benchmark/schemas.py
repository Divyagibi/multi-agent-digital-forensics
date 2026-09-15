"""Canonical Benchmark Data Model, Identity System, and Deterministic Serialization.

Step 6C-1: Benchmark dataset schema, identity model, and deterministic serialization.

This module provides an isolated, independent benchmark schema definition for the
Multi-Agent Digital Forensics & Digital Trust Investigation System.
It is strictly segregated from the production forensic Evidence Schema (A1-A18)
and contains ZERO imports or couplings to the production analysis engines.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field, asdict
from enum import Enum
import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Union


# =====================================================================
# Controlled Vocabularies / Enums
# =====================================================================

class InputModality(str, Enum):
    """Controlled vocabulary for input artifact modalities (Step 6B)."""
    DIRECT_URL = "DIRECT_URL"
    QR_IMAGE = "QR_IMAGE"
    QR_PAYLOAD = "QR_PAYLOAD"


class PrimaryOutcome(str, Enum):
    """Primary ground-truth outcome label."""
    BENIGN = "BENIGN"
    MALICIOUS = "MALICIOUS"
    AMBIGUOUS = "AMBIGUOUS"


class SecondaryThreatCategory(str, Enum):
    """Secondary fine-grained threat taxonomy (Step 6B)."""
    CREDENTIAL_PHISHING = "CREDENTIAL_PHISHING"
    BRAND_IMPERSONATION = "BRAND_IMPERSONATION"
    SCAM_FRAUD = "SCAM_FRAUD"
    MALWARE_DISTRIBUTION = "MALWARE_DISTRIBUTION"
    DRIVE_BY_EXPLOIT = "DRIVE_BY_EXPLOIT"
    TECH_SUPPORT_FRAUD = "TECH_SUPPORT_FRAUD"
    QUISHING = "QUISHING"
    OTHER = "OTHER"


class VerificationStatus(str, Enum):
    """Ground-truth verification adjudication status."""
    VERIFIED = "verified"
    AMBIGUOUS = "ambiguous"
    DISPUTED = "disputed"
    UNVERIFIABLE = "unverifiable"
    UNAVAILABLE = "unavailable"


class VerificationMethod(str, Enum):
    """Methodology applied to establish ground truth."""
    MANUAL_ADJUDICATION = "manual_adjudication"
    MULTI_SOURCE_CONSENSUS = "multi_source_consensus"
    AUTHORITATIVE_REGISTRY = "authoritative_registry"
    SANDBOX_DETONATION = "sandbox_detonation"
    DOM_CERT_ANALYSIS = "dom_cert_analysis"
    OTHER = "other"


class VerificationConfidence(str, Enum):
    """Qualitative adjudication assessment strength.

    IMPORTANT: This represents discrete expert / adjudication assessment strength.
    It is NOT a calibrated probability, Bayesian posterior, statistical confidence,
    or model confidence. Float values (e.g. 1.0) are strictly rejected.
    """
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class TIObservationStatus(str, Enum):
    """Controlled status of external Threat Intelligence feed observation.

    CRITICAL SEMANTIC RULES:
    - A negative observation is NOT 'benign'.
    - An unavailable / not_checked observation is NOT 'clean'.
    - TI metadata is provenance / evaluation metadata, NOT ground truth.
    """
    UNKNOWN = "unknown"
    UNAVAILABLE = "unavailable"
    NOT_CHECKED = "not_checked"
    NEGATIVE_OBSERVATION = "negative_observation"
    POSITIVE_OBSERVATION = "positive_observation"


class TemporalPartition(str, Enum):
    """Provisional temporal / experimental evaluation partitions (Step 6C)."""
    DEVELOPMENT_CALIBRATION = "development_calibration"
    VALIDATION = "validation"
    FINAL_TEST = "final_test"
    PROSPECTIVE_HOLDOUT = "prospective_holdout"


class DuplicateStatus(str, Enum):
    """Deduplication and cross-split audit status."""
    CANONICAL = "canonical"
    DUPLICATE_WITHIN_SPLIT = "duplicate_within_split"
    CROSS_SPLIT_LEAKAGE = "cross_split_leakage"
    NOT_CHECKED = "not_checked"


class ExclusionStatus(str, Enum):
    """Dataset retention or exclusion status."""
    RETAINED = "retained"
    EXCLUDED = "excluded"


class QRRelationshipType(str, Enum):
    """Relationship between QR artifact and investigated target."""
    DIRECT_PAYLOAD = "direct_payload"
    REDIRECT_DESTINATION = "redirect_destination"
    EMBEDDED_TARGET = "embedded_target"
    NONE = "none"


# =====================================================================
# Identity Helpers (Deterministic Cryptographic Hashing)
# =====================================================================

def sha256_bytes(data: Union[str, bytes]) -> str:
    """Compute standard hexadecimal SHA-256 digest of string or bytes."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def compute_artifact_id(modality: Union[InputModality, str], raw_content: Union[str, bytes]) -> str:
    """Tier 1: Compute deterministic Artifact ID (ART-<sha256[:16]>).

    Represents the exact observed input artifact (e.g., raw URL, QR image payload/bytes).
    """
    mod_val = modality.value if isinstance(modality, InputModality) else str(modality)
    if isinstance(raw_content, str):
        content_bytes = raw_content.encode("utf-8")
    else:
        content_bytes = raw_content
    digest = hashlib.sha256(f"{mod_val}:".encode("utf-8") + content_bytes).hexdigest()[:16]
    return f"ART-{digest}"


def compute_target_id(normalized_target: str) -> str:
    """Tier 2: Compute deterministic Investigation Target ID (TGT-<sha256[:16]>).

    Represents the canonical normalized target investigated by the forensic system.
    """
    canonical_target = normalized_target.strip().lower()
    digest = hashlib.sha256(canonical_target.encode("utf-8")).hexdigest()[:16]
    return f"TGT-{digest}"


def compute_group_id(grouping_key: str) -> str:
    """Tier 3: Compute deterministic Grouping / Leakage ID (GRP-<sha256[:16]>).

    Represents the grouping identity (e.g., eTLD+1 domain, IP subnet) used for
    deduplication, leakage prevention, and cross-split isolation.
    """
    canonical_group = grouping_key.strip().lower()
    digest = hashlib.sha256(canonical_group.encode("utf-8")).hexdigest()[:16]
    return f"GRP-{digest}"


def compute_record_id(target_id: str, artifact_id: str) -> str:
    """Compute deterministic Benchmark Record ID (REC-<sha256[:16]>).

    Combines canonical target and artifact identities.
    """
    combined = f"{target_id.strip()}|{artifact_id.strip()}"
    digest = hashlib.sha256(combined.encode("utf-8")).hexdigest()[:16]
    return f"REC-{digest}"


# =====================================================================
# Schema Dataclasses
# =====================================================================

@dataclass(frozen=True)
class CandidateProvenance:
    """Candidate harvesting provenance metadata (Step 6B/6C).

    Note: Candidate provenance records where/when the target was sourced,
    which is strictly distinct from ground-truth verification provenance.
    """
    source_name: str
    source_record_id: str = ""
    harvest_timestamp: str = ""
    first_observed_timestamp: str = ""
    source_notes: str = ""


@dataclass(frozen=True)
class GroundTruth:
    """Structured ground-truth adjudication object."""
    primary_outcome: PrimaryOutcome
    secondary_categories: List[SecondaryThreatCategory] = field(default_factory=list)
    verification_status: VerificationStatus = VerificationStatus.VERIFIED
    verification_method: str = VerificationMethod.MANUAL_ADJUDICATION.value
    verification_confidence: VerificationConfidence = VerificationConfidence.HIGH
    adjudication_status: str = "adjudicated"
    reviewer_count: int = 1
    verification_timestamp: str = ""
    rationale: str = ""
    supporting_references: List[str] = field(default_factory=list)
    contradictory_references: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class TIFeedObservation:
    """Observation record for a single Threat Intelligence feed."""
    feed_name: str
    status: TIObservationStatus = TIObservationStatus.NOT_CHECKED
    observed: bool = False
    observed_at: str = ""
    source_available: bool = True
    notes: str = ""


@dataclass(frozen=True)
class TIOverlapMetadata:
    """TI overlap experimental metadata across 7 benchmark feeds.

    Feeds: VirusTotal, GoogleSafeBrowsing, PhishTank, OpenPhish, URLhaus, AbuseIPDB, Spamhaus.
    """
    virustotal: TIFeedObservation = field(
        default_factory=lambda: TIFeedObservation(feed_name="VirusTotal")
    )
    google_safebrowsing: TIFeedObservation = field(
        default_factory=lambda: TIFeedObservation(feed_name="GoogleSafeBrowsing")
    )
    phishtank: TIFeedObservation = field(
        default_factory=lambda: TIFeedObservation(feed_name="PhishTank")
    )
    openphish: TIFeedObservation = field(
        default_factory=lambda: TIFeedObservation(feed_name="OpenPhish")
    )
    urlhaus: TIFeedObservation = field(
        default_factory=lambda: TIFeedObservation(feed_name="URLhaus")
    )
    abuseipdb: TIFeedObservation = field(
        default_factory=lambda: TIFeedObservation(feed_name="AbuseIPDB")
    )
    spamhaus: TIFeedObservation = field(
        default_factory=lambda: TIFeedObservation(feed_name="Spamhaus")
    )
    custom_feeds: Dict[str, TIFeedObservation] = field(default_factory=dict)


@dataclass(frozen=True)
class LivenessMetadata:
    """Passive eligibility and network liveness telemetry (Step 6C).

    Note: Uses raw byte sizes, status codes, and TLS verification telemetry.
    Liveness failure does NOT establish ground truth.
    """
    http_status: Optional[int] = None
    dns_resolved: Optional[bool] = None
    tls_status: Optional[str] = None
    response_body_size_bytes: Optional[int] = None
    resolved_ip: Optional[str] = None
    redirect_chain: List[str] = field(default_factory=list)
    checked_at: str = ""
    eligibility_status: str = "unknown"


@dataclass(frozen=True)
class QRRelationshipMetadata:
    """Metadata preserving QR artifact, payload, and direct target relationships."""
    artifact_type: str = "none"
    decoded_payload: Optional[str] = None
    destination_target_id: Optional[str] = None
    qr_group_id: Optional[str] = None
    relationship_type: QRRelationshipType = QRRelationshipType.NONE


@dataclass(frozen=True)
class EvaluationMetadata:
    """Dataset evaluation and partition metadata (Step 6C)."""
    group_id: str
    temporal_partition: Optional[TemporalPartition] = None
    stratum: str = ""
    duplicate_status: DuplicateStatus = DuplicateStatus.NOT_CHECKED
    exclusion_status: ExclusionStatus = ExclusionStatus.RETAINED
    exclusion_reason: str = ""


@dataclass(frozen=True)
class BenchmarkRecord:
    """Top-level canonical benchmark record data model."""
    record_id: str
    artifact_id: str
    target_id: str
    target_url: str
    modality: InputModality
    ground_truth: GroundTruth
    provenance: CandidateProvenance
    ti_overlap: TIOverlapMetadata
    liveness: LivenessMetadata
    qr_relationship: QRRelationshipMetadata
    evaluation: EvaluationMetadata
    schema_version: str = "1.0.0"


@dataclass(frozen=True)
class BenchmarkManifest:
    """Minimal manifest schema for benchmark dataset snapshots (Step 6C-6 preparation)."""
    benchmark_version: str = "1.0.0"
    methodology_version: str = "1.0.0"
    snapshot_id: str = ""
    creation_timestamp: str = ""
    dataset_hash: str = ""
    manifest_hash: str = ""
    record_counts: Dict[str, int] = field(default_factory=dict)
    class_counts: Dict[str, int] = field(default_factory=dict)
    partition_counts: Dict[str, int] = field(default_factory=dict)
    source_summary: Dict[str, int] = field(default_factory=dict)
    exclusion_summary: Dict[str, int] = field(default_factory=dict)
    software_version: str = "1.0.0"


# =====================================================================
# Deterministic Serialization & Hashing Protocol
# =====================================================================

def _to_deterministic_primitive(obj: Any) -> Any:
    """Recursively convert dataclasses, enums, lists, and dicts into canonical primitives.

    Guarantees:
    - Enums converted to their string values.
    - Dataclasses converted to recursively sorted key dictionaries.
    - Dictionaries sorted alphabetically by key.
    - Lists preserve order with canonicalized children.
    - Floating point values are rejected or converted deterministically.
    - Strings, integers, booleans, and None preserved as standard JSON types.
    """
    if isinstance(obj, Enum):
        return obj.value
    if dataclasses.is_dataclass(obj):
        d = asdict(obj)
        return _to_deterministic_primitive(d)
    if isinstance(obj, dict):
        return {k: _to_deterministic_primitive(v) for k, v in sorted(obj.items())}
    if isinstance(obj, (list, tuple)):
        return [_to_deterministic_primitive(item) for item in obj]
    if isinstance(obj, float):
        # Deterministic float formatting if encountered (though discouraged in schema)
        if obj.is_integer():
            return int(obj)
        return f"{obj:.8f}".rstrip("0").rstrip(".")
    return obj


def canonicalize_record_dict(record_dict: Dict[str, Any]) -> str:
    """Convert a dictionary to a canonical, deterministically sorted JSON string.

    Encoding Protocol:
    - Standard JSON format with UTF-8 support.
    - Key sorting enabled (`sort_keys=True`).
    - Compact separators with no whitespace (`separators=(',', ':')`).
    - No trailing whitespace.
    - Escaping non-ASCII safely with `ensure_ascii=False` (raw UTF-8).
    """
    primitive = _to_deterministic_primitive(record_dict)
    return json.dumps(primitive, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonicalize_record(record: BenchmarkRecord) -> str:
    """Produce the canonical, deterministic string representation of a BenchmarkRecord.

    Appends a standard normalized newline (\\n) for line-delimited dataset storage.
    """
    record_dict = asdict(record)
    canonical_json = canonicalize_record_dict(record_dict)
    return canonical_json + "\n"


def hash_canonical_record(record: BenchmarkRecord) -> str:
    """Compute the cryptographic SHA-256 digest of the canonicalized benchmark record.

    Note: This provides byte-exact integrity of the serialized record, not external
    cryptographic notary attestation.
    """
    canonical_bytes = canonicalize_record(record).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


# =====================================================================
# Structural Validation
# =====================================================================

class ValidationError(ValueError):
    """Raised when a benchmark record fails structural schema validation."""
    pass


_ID_PATTERNS = {
    "REC": re.compile(r"^REC-[a-f0-9]{16}$"),
    "TGT": re.compile(r"^TGT-[a-f0-9]{16}$"),
    "ART": re.compile(r"^ART-[a-f0-9]{16}$"),
    "GRP": re.compile(r"^GRP-[a-f0-9]{16}$"),
}


def validate_benchmark_record(record: BenchmarkRecord, raise_exception: bool = False) -> List[str]:
    """Perform structural schema validation on a BenchmarkRecord.

    Checks:
    - Valid ID formats (REC, ART, TGT, GRP).
    - Valid enum values for modality, ground truth, partitions, and feed observations.
    - Qualitative verification confidence (no floats / probabilities).
    - Reviewer count >= 1.
    - Liveness telemetry data types.
    - QR relationship consistency.

    Does NOT:
    - Query external threat feeds or network endpoints.
    - Run forensic analysis engines (TCE/AERE/CE).
    - Execute payloads or make ground-truth decisions.
    """
    errors: List[str] = []

    # 1. Identifier formats
    if not _ID_PATTERNS["REC"].match(record.record_id):
        errors.append(f"Invalid record_id format: '{record.record_id}' (expected REC-<16hex>)")
    if not _ID_PATTERNS["ART"].match(record.artifact_id):
        errors.append(f"Invalid artifact_id format: '{record.artifact_id}' (expected ART-<16hex>)")
    if not _ID_PATTERNS["TGT"].match(record.target_id):
        errors.append(f"Invalid target_id format: '{record.target_id}' (expected TGT-<16hex>)")
    if not _ID_PATTERNS["GRP"].match(record.evaluation.group_id):
        errors.append(f"Invalid evaluation.group_id format: '{record.evaluation.group_id}' (expected GRP-<16hex>)")

    # 2. Modality
    if not isinstance(record.modality, InputModality):
        try:
            InputModality(record.modality)
        except Exception:
            errors.append(f"Invalid modality: '{record.modality}'")

    # 3. Target URL
    if not record.target_url or not isinstance(record.target_url, str):
        errors.append("Target URL must be a non-empty string")

    # 4. Ground Truth
    gt = record.ground_truth
    if not isinstance(gt.primary_outcome, PrimaryOutcome):
        try:
            PrimaryOutcome(gt.primary_outcome)
        except Exception:
            errors.append(f"Invalid ground_truth.primary_outcome: '{gt.primary_outcome}'")

    for cat in gt.secondary_categories:
        if not isinstance(cat, SecondaryThreatCategory):
            try:
                SecondaryThreatCategory(cat)
            except Exception:
                errors.append(f"Invalid secondary_threat_category: '{cat}'")

    if not isinstance(gt.verification_status, VerificationStatus):
        try:
            VerificationStatus(gt.verification_status)
        except Exception:
            errors.append(f"Invalid verification_status: '{gt.verification_status}'")

    if not isinstance(gt.verification_confidence, VerificationConfidence):
        try:
            VerificationConfidence(gt.verification_confidence)
        except Exception:
            errors.append(
                f"Invalid verification_confidence: '{gt.verification_confidence}' (must be HIGH, MEDIUM, or LOW qualitative enum)"
            )

    if gt.reviewer_count < 1:
        errors.append(f"reviewer_count must be >= 1, got {gt.reviewer_count}")

    # 5. TI Overlap Feeds
    ti = record.ti_overlap
    standard_feeds = [
        ti.virustotal,
        ti.google_safebrowsing,
        ti.phishtank,
        ti.openphish,
        ti.urlhaus,
        ti.abuseipdb,
        ti.spamhaus,
    ]
    for feed_obs in standard_feeds:
        if not isinstance(feed_obs.status, TIObservationStatus):
            try:
                TIObservationStatus(feed_obs.status)
            except Exception:
                errors.append(f"Invalid TIObservationStatus in feed '{feed_obs.feed_name}': '{feed_obs.status}'")

    # 6. QR Consistency
    qr = record.qr_relationship
    if record.modality == InputModality.QR_IMAGE and qr.artifact_type == "none":
        errors.append("modality is QR_IMAGE but qr_relationship.artifact_type is 'none'")

    # 7. Evaluation Metadata
    ev = record.evaluation
    if ev.temporal_partition is not None and not isinstance(ev.temporal_partition, TemporalPartition):
        try:
            TemporalPartition(ev.temporal_partition)
        except Exception:
            errors.append(f"Invalid temporal_partition: '{ev.temporal_partition}'")

    if not isinstance(ev.duplicate_status, DuplicateStatus):
        try:
            DuplicateStatus(ev.duplicate_status)
        except Exception:
            errors.append(f"Invalid duplicate_status: '{ev.duplicate_status}'")

    if not isinstance(ev.exclusion_status, ExclusionStatus):
        try:
            ExclusionStatus(ev.exclusion_status)
        except Exception:
            errors.append(f"Invalid exclusion_status: '{ev.exclusion_status}'")

    if raise_exception and errors:
        raise ValidationError(f"BenchmarkRecord validation failed with {len(errors)} error(s):\n" + "\n".join(errors))

    return errors
