"""QR and Direct URL Relationship Resolution and Correlation Layer.

Step 6C-3: QR / Direct URL Relationship Handling.

This module provides explicit relationship handling and cross-modal correlation
between QR artifacts/payloads and direct URL artifacts.

Architectural Guarantees:
- Modality Preservation: QR_PAYLOAD modality is never erased or converted to DIRECT_URL.
- Multi-Tier Identity Consistency: Preserves distinct Artifact IDs (ART-) while resolving
  shared Target IDs (TGT-) and Group IDs (GRP-).
- Reuses Step 6C-2 Normalization: Uses canonical normalize_investigation_target() without
  duplicating URL parsing logic.
- Offline Execution: Zero network calls, zero DNS queries, zero image decoding.
- Ground-Truth Independence: Relationships depend solely on artifact and target identity,
  never on classification outcomes or TI feed status.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from .schemas import (
    InputModality,
    BenchmarkRecord,
    compute_artifact_id,
    compute_target_id,
    compute_group_id,
)
from .normalization import (
    NormalizedTarget,
    normalize_investigation_target,
)


# =====================================================================
# Controlled Relationship Enums
# =====================================================================

class QRTargetResolutionStatus(str, Enum):
    """Status of QR payload target resolution."""
    RESOLVED_HTTP_TARGET = "RESOLVED_HTTP_TARGET"
    UNRESOLVED_IMAGE = "UNRESOLVED_IMAGE"
    NON_URL_PAYLOAD = "NON_URL_PAYLOAD"
    UNSUPPORTED_SCHEME = "UNSUPPORTED_SCHEME"
    EMPTY_PAYLOAD = "EMPTY_PAYLOAD"
    MALFORMED_PAYLOAD = "MALFORMED_PAYLOAD"


class QRDirectRelationType(str, Enum):
    """Pairwise relationship between a QR artifact and a Direct URL artifact."""
    QR_DIRECT_SAME_TARGET = "QR_DIRECT_SAME_TARGET"
    QR_DIRECT_SAME_GROUP = "QR_DIRECT_SAME_GROUP"
    QR_DIRECT_DIFFERENT_TARGET = "QR_DIRECT_DIFFERENT_TARGET"
    QR_IMAGE_UNRESOLVED = "QR_IMAGE_UNRESOLVED"
    QR_NON_URL_PAYLOAD = "QR_NON_URL_PAYLOAD"
    NOT_APPLICABLE = "NOT_APPLICABLE"


# Non-HTTP/HTTPS schemes commonly found in QR codes
_NON_HTTP_SCHEMES = {
    "smsto", "sms", "mailto", "tel", "wifi", "otpauth", "geo",
    "intent", "javascript", "data", "market", "facetime", "vcard",
}


# =====================================================================
# Relationship Dataclasses
# =====================================================================

@dataclass(frozen=True)
class QRPayloadResolution:
    """Detailed target resolution metadata for a QR code record."""
    source_record_id: str
    source_artifact_id: str
    source_modality: InputModality
    payload: Optional[str]
    is_http_url: bool
    resolved_target_id: Optional[str]
    resolved_group_id: Optional[str]
    target_url: Optional[str]
    resolution_status: QRTargetResolutionStatus
    diagnostics: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class QRDirectRelationship:
    """Pairwise relationship between a QR record and a Direct URL record."""
    qr_record_id: str
    direct_record_id: str
    qr_artifact_id: str
    direct_artifact_id: str
    qr_target_id: Optional[str]
    direct_target_id: str
    relationship_type: QRDirectRelationType
    same_target: bool
    same_group: bool
    same_artifact: bool
    is_cross_split_leakage: bool
    reason_code: str
    reason: str


# =====================================================================
# QR Target Resolution Logic
# =====================================================================

def resolve_qr_payload_target(record: BenchmarkRecord) -> QRPayloadResolution:
    """Resolve a QR benchmark record to its investigation target if applicable.

    Rules:
    - If modality is QR_IMAGE and decoded_payload is None, returns UNRESOLVED_IMAGE.
      (No image decoding is performed in this layer).
    - If payload is empty, returns EMPTY_PAYLOAD.
    - If payload is a non-HTTP scheme (smsto:, mailto:, intent:, etc.), returns NON_URL_PAYLOAD.
    - If payload is a valid HTTP(S) URL, normalizes target via Step 6C-2 and returns RESOLVED_HTTP_TARGET.
    """
    modality = record.modality
    if modality == InputModality.QR_IMAGE:
        payload = record.qr_relationship.decoded_payload
        if not payload:
            return QRPayloadResolution(
                source_record_id=record.record_id,
                source_artifact_id=record.artifact_id,
                source_modality=modality,
                payload=None,
                is_http_url=False,
                resolved_target_id=None,
                resolved_group_id=None,
                target_url=None,
                resolution_status=QRTargetResolutionStatus.UNRESOLVED_IMAGE,
                diagnostics={"note": "QR image artifact without decoded payload"},
            )
    elif modality == InputModality.QR_PAYLOAD:
        payload = record.qr_relationship.decoded_payload or record.target_url
    else:
        # Fallback if evaluated on a non-QR record
        payload = record.target_url

    raw_str = (payload or "").strip()
    if not raw_str:
        return QRPayloadResolution(
            source_record_id=record.record_id,
            source_artifact_id=record.artifact_id,
            source_modality=modality,
            payload=raw_str,
            is_http_url=False,
            resolved_target_id=None,
            resolved_group_id=None,
            target_url=None,
            resolution_status=QRTargetResolutionStatus.EMPTY_PAYLOAD,
            diagnostics={"note": "Empty QR payload"},
        )

    # Check if payload contains whitespace or spaces (plain text)
    if " " in raw_str or "\t" in raw_str or "\n" in raw_str:
        return QRPayloadResolution(
            source_record_id=record.record_id,
            source_artifact_id=record.artifact_id,
            source_modality=modality,
            payload=raw_str,
            is_http_url=False,
            resolved_target_id=None,
            resolved_group_id=None,
            target_url=None,
            resolution_status=QRTargetResolutionStatus.NON_URL_PAYLOAD,
            diagnostics={"note": "Plain text QR payload containing whitespace"},
        )

    # Check for known non-HTTP schemes
    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", raw_str)
    if scheme_match:
        scheme_prefix = scheme_match.group(1).lower()
        if scheme_prefix in _NON_HTTP_SCHEMES or (scheme_prefix not in ("http", "https") and not raw_str.startswith("//")):
            return QRPayloadResolution(
                source_record_id=record.record_id,
                source_artifact_id=record.artifact_id,
                source_modality=modality,
                payload=raw_str,
                is_http_url=False,
                resolved_target_id=None,
                resolved_group_id=None,
                target_url=None,
                resolution_status=QRTargetResolutionStatus.NON_URL_PAYLOAD,
                diagnostics={"scheme": scheme_prefix, "note": f"Non-HTTP QR payload scheme: {scheme_prefix}"},
            )
    elif "." not in raw_str and not raw_str.startswith("//"):
        # No scheme and no domain dot -> non-URL text
        return QRPayloadResolution(
            source_record_id=record.record_id,
            source_artifact_id=record.artifact_id,
            source_modality=modality,
            payload=raw_str,
            is_http_url=False,
            resolved_target_id=None,
            resolved_group_id=None,
            target_url=None,
            resolution_status=QRTargetResolutionStatus.NON_URL_PAYLOAD,
            diagnostics={"note": "QR payload lacks domain or scheme structure"},
        )

    # Normalize HTTP(S) URL via Step 6C-2 canonical normalization
    norm_target = normalize_investigation_target(raw_str)
    if norm_target.is_ambiguous or not norm_target.canonical_url:
        return QRPayloadResolution(
            source_record_id=record.record_id,
            source_artifact_id=record.artifact_id,
            source_modality=modality,
            payload=raw_str,
            is_http_url=False,
            resolved_target_id=None,
            resolved_group_id=None,
            target_url=None,
            resolution_status=QRTargetResolutionStatus.MALFORMED_PAYLOAD,
            diagnostics={"error": norm_target.notes},
        )

    return QRPayloadResolution(
        source_record_id=record.record_id,
        source_artifact_id=record.artifact_id,
        source_modality=modality,
        payload=raw_str,
        is_http_url=True,
        resolved_target_id=norm_target.target_id,
        resolved_group_id=norm_target.group_id,
        target_url=norm_target.canonical_url,
        resolution_status=QRTargetResolutionStatus.RESOLVED_HTTP_TARGET,
        diagnostics={
            "canonical_url": norm_target.canonical_url,
            "grouping_key": norm_target.grouping_key,
        },
    )


# =====================================================================
# QR vs Direct URL Pairwise Correlation
# =====================================================================

def analyze_qr_direct_relationship(
    qr_record: BenchmarkRecord,
    direct_record: BenchmarkRecord,
) -> QRDirectRelationship:
    """Analyze the relationship between a QR record and a Direct URL record.

    CRITICAL INVARIANTS:
    1. same_artifact is ALWAYS False when comparing QR and Direct URL (different modalities).
    2. same_target is True if both resolve to the identical normalized Target ID.
    3. same_group is True if both share the same Group ID (eTLD+1 / subnet).
    """
    qr_res = resolve_qr_payload_target(qr_record)
    direct_target_id = direct_record.target_id
    direct_group_id = direct_record.evaluation.group_id

    # Check cross-split partition status
    part_qr = qr_record.evaluation.temporal_partition
    part_direct = direct_record.evaluation.temporal_partition
    is_diff_partition = (
        part_qr is not None and part_direct is not None and part_qr != part_direct
    )

    same_art = (qr_record.artifact_id == direct_record.artifact_id)

    if qr_res.resolution_status == QRTargetResolutionStatus.UNRESOLVED_IMAGE:
        return QRDirectRelationship(
            qr_record_id=qr_record.record_id,
            direct_record_id=direct_record.record_id,
            qr_artifact_id=qr_record.artifact_id,
            direct_artifact_id=direct_record.artifact_id,
            qr_target_id=None,
            direct_target_id=direct_target_id,
            relationship_type=QRDirectRelationType.QR_IMAGE_UNRESOLVED,
            same_target=False,
            same_group=False,
            same_artifact=same_art,
            is_cross_split_leakage=False,
            reason_code="QR_IMAGE_UNRESOLVED",
            reason="QR image artifact has no decoded payload for target comparison.",
        )

    if not qr_res.is_http_url or qr_res.resolved_target_id is None:
        return QRDirectRelationship(
            qr_record_id=qr_record.record_id,
            direct_record_id=direct_record.record_id,
            qr_artifact_id=qr_record.artifact_id,
            direct_artifact_id=direct_record.artifact_id,
            qr_target_id=None,
            direct_target_id=direct_target_id,
            relationship_type=QRDirectRelationType.QR_NON_URL_PAYLOAD,
            same_target=False,
            same_group=False,
            same_artifact=same_art,
            is_cross_split_leakage=False,
            reason_code="NON_URL_PAYLOAD",
            reason=f"QR payload is not a web target ({qr_res.resolution_status.value}).",
        )

    same_tgt = (qr_res.resolved_target_id == direct_target_id)
    same_grp = (qr_res.resolved_group_id == direct_group_id)
    is_leakage = is_diff_partition and (same_tgt or same_grp)

    if same_tgt:
        rel_type = QRDirectRelationType.QR_DIRECT_SAME_TARGET
        code = "SAME_NORMALIZED_TARGET"
        reason = "QR payload and direct URL resolve to the identical normalized investigation target."
    elif same_grp:
        rel_type = QRDirectRelationType.QR_DIRECT_SAME_GROUP
        code = "SAME_GROUP_DIFFERENT_TARGET"
        reason = "QR payload and direct URL resolve to different target paths/endpoints within the same domain/group."
    else:
        rel_type = QRDirectRelationType.QR_DIRECT_DIFFERENT_TARGET
        code = "DIFFERENT_TARGET_AND_GROUP"
        reason = "QR payload and direct URL point to completely distinct domains and targets."

    return QRDirectRelationship(
        qr_record_id=qr_record.record_id,
        direct_record_id=direct_record.record_id,
        qr_artifact_id=qr_record.artifact_id,
        direct_artifact_id=direct_record.artifact_id,
        qr_target_id=qr_res.resolved_target_id,
        direct_target_id=direct_target_id,
        relationship_type=rel_type,
        same_target=same_tgt,
        same_group=same_grp,
        same_artifact=same_art,
        is_cross_split_leakage=is_leakage,
        reason_code=code,
        reason=reason,
    )


def correlate_qr_and_direct_records(records: List[BenchmarkRecord]) -> List[QRDirectRelationship]:
    """Correlate all QR records against all Direct URL records in a dataset."""
    qr_records = [r for r in records if r.modality in (InputModality.QR_IMAGE, InputModality.QR_PAYLOAD)]
    direct_records = [r for r in records if r.modality == InputModality.DIRECT_URL]

    relationships: List[QRDirectRelationship] = []
    for qr_rec in qr_records:
        for direct_rec in direct_records:
            rel = analyze_qr_direct_relationship(qr_rec, direct_rec)
            relationships.append(rel)

    return relationships
