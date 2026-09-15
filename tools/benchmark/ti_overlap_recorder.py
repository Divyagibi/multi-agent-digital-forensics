"""Threat Intelligence (TI) Overlap Metadata Recording Layer.

Step 6C-5: Threat Intelligence (TI) Overlap Metadata Recording.

This module provides deterministic recording, validation, and exposure summarization
of benchmark target presence across 7 threat intelligence feeds.

Architectural Guarantees:
- Pure Provenance & Exposure Metadata: TI overlap is experimental metadata, NEVER ground truth.
- Absence != Benign: Lack of detection in any or all TI feeds never alters ground truth or implies benignity.
- Preserves 7 Named Feeds: VirusTotal, Google Safe Browsing, PhishTank, OpenPhish, URLhaus, AbuseIPDB, Spamhaus.
- Temporal Exposure Tracking: Distinguishes first_feed_seen_at, observation_time, and retrieved_at.
- Identity Preservation: Attached to canonical target_id; preserves distinct artifact IDs and group IDs.
- Zero Network / API Calls: Pure local offline recording; zero production engine coupling.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .schemas import (
    TIObservationStatus,
    TemporalPartition,
    TIFeedObservation,
    TIOverlapMetadata,
    BenchmarkRecord,
)


# =====================================================================
# Controlled Feed Names & Observation Statuses
# =====================================================================

class TIFeed(str, Enum):
    """Controlled vocabulary for the 7 benchmark Threat Intelligence feeds."""
    VIRUSTOTAL = "VirusTotal"
    GOOGLE_SAFE_BROWSING = "GoogleSafeBrowsing"
    PHISHTANK = "PhishTank"
    OPENPHISH = "OpenPhish"
    URLHAUS = "URLhaus"
    ABUSEIPDB = "AbuseIPDB"
    SPAMHAUS = "Spamhaus"


class TIObservationType(str, Enum):
    """Granular observation status for TI feed presence.

    Semantic Rules:
    - NONE: No positive detection was retrieved from this monitored source at observation time.
      (Strictly does NOT mean clean, safe, or benign).
    - DIRECT: Target was positively and directly reported in the specified source with provenance.
    - PARTIAL: Target or infrastructure was observed in related feed data without exact direct confirmation.
    - UNKNOWN_UNAVAILABLE: Source query failed, timed out, or source was unmonitored.
    """
    NONE = "none"
    DIRECT = "direct"
    PARTIAL = "partial"
    UNKNOWN_UNAVAILABLE = "unknown_unavailable"


# =====================================================================
# Validation Helpers
# =====================================================================

_ISO8601_REGEX = re.compile(
    r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?)?$"
)


def validate_iso8601_timestamp(ts: Optional[str], field_name: str = "timestamp") -> None:
    """Validate that a string conforms to ISO-8601 format without using system clock."""
    if ts is None or ts == "":
        return
    if not isinstance(ts, str) or not _ISO8601_REGEX.match(ts):
        raise ValueError(f"Invalid ISO-8601 format for {field_name}: '{ts}'")


# =====================================================================
# Data Models
# =====================================================================

@dataclass(frozen=True)
class TIFeedObservationRecord:
    """Detailed observation record for a single TI feed."""
    feed_name: TIFeed
    status: TIObservationType
    target_id: str
    first_feed_seen_at: Optional[str] = None
    observation_time: Optional[str] = None
    retrieved_at: Optional[str] = None
    source_reference: Optional[str] = None
    provenance_notes: str = ""
    raw_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TIExposureSummary:
    """Deterministic summary of TI exposure across monitored feeds."""
    target_id: str
    has_any_direct_positive: bool
    has_any_partial_positive: bool
    feed_count_positive: int
    feeds_observed_positive: List[str]
    feeds_observed_negative: List[str]
    feeds_unavailable: List[str]
    earliest_first_feed_seen_at: Optional[str] = None


@dataclass(frozen=True)
class TIOverlapRecord:
    """Complete multi-feed TI overlap container for a target."""
    target_id: str
    observations: Dict[str, TIFeedObservationRecord]
    exposure: TIExposureSummary


# =====================================================================
# TI Overlap Recorder Implementation
# =====================================================================

def record_ti_observation(
    target_id: str,
    feed: Union[TIFeed, str],
    status: Union[TIObservationType, str],
    first_feed_seen_at: Optional[str] = None,
    observation_time: Optional[str] = None,
    retrieved_at: Optional[str] = None,
    source_reference: Optional[str] = None,
    provenance_notes: str = "",
    raw_metadata: Optional[Dict[str, Any]] = None,
) -> TIFeedObservationRecord:
    """Record and validate a single TI feed observation for a target ID.

    Validation Rules:
    - feed must be one of the 7 supported TIFeed enum members.
    - status must be a valid TIObservationType.
    - target_id must be non-empty.
    - All timestamps must conform to ISO-8601 format.
    - DIRECT status requires supporting source provenance (source_reference or non-empty raw_metadata).
    """
    if not target_id or not isinstance(target_id, str):
        raise ValueError("target_id must be a non-empty string")

    # Validate feed
    if isinstance(feed, TIFeed):
        feed_enum = feed
    else:
        try:
            feed_enum = TIFeed(feed)
        except ValueError:
            # Try case-insensitive matching
            match = next((f for f in TIFeed if f.value.lower() == str(feed).strip().lower()), None)
            if match:
                feed_enum = match
            else:
                raise ValueError(f"Invalid TI feed name: '{feed}'. Must be one of {[f.value for f in TIFeed]}")

    # Validate status
    if isinstance(status, TIObservationType):
        status_enum = status
    else:
        clean_status = str(status).strip().lower()
        if clean_status in ("none", "negative", "negative_observation"):
            status_enum = TIObservationType.NONE
        elif clean_status in ("direct", "positive", "positive_observation"):
            status_enum = TIObservationType.DIRECT
        elif clean_status == "partial":
            status_enum = TIObservationType.PARTIAL
        elif clean_status in ("unknown", "unavailable", "unknown_unavailable", "not_checked"):
            status_enum = TIObservationType.UNKNOWN_UNAVAILABLE
        else:
            raise ValueError(f"Invalid TI observation status: '{status}'")

    # Validate timestamps
    validate_iso8601_timestamp(first_feed_seen_at, "first_feed_seen_at")
    validate_iso8601_timestamp(observation_time, "observation_time")
    validate_iso8601_timestamp(retrieved_at, "retrieved_at")

    # Provenance requirement for DIRECT status
    meta = raw_metadata or {}
    if status_enum == TIObservationType.DIRECT and not source_reference and not meta and not provenance_notes:
        raise ValueError(
            f"DIRECT TI status for {feed_enum.value} requires source provenance (source_reference or metadata)"
        )

    return TIFeedObservationRecord(
        feed_name=feed_enum,
        status=status_enum,
        target_id=target_id.strip(),
        first_feed_seen_at=first_feed_seen_at,
        observation_time=observation_time,
        retrieved_at=retrieved_at,
        source_reference=source_reference,
        provenance_notes=provenance_notes,
        raw_metadata=meta,
    )


def build_ti_overlap_metadata(
    target_id: str,
    observations: List[TIFeedObservationRecord],
) -> TIOverlapRecord:
    """Aggregate individual feed observations into a unified TIOverlapRecord with exposure summary."""
    if not target_id:
        raise ValueError("target_id must be non-empty")

    obs_dict: Dict[str, TIFeedObservationRecord] = {}
    pos_feeds: List[str] = []
    neg_feeds: List[str] = []
    unavail_feeds: List[str] = []
    seen_timestamps: List[str] = []

    has_direct = False
    has_partial = False

    for obs in observations:
        if obs.target_id != target_id:
            raise ValueError(
                f"Observation target_id '{obs.target_id}' does not match container target_id '{target_id}'"
            )
        feed_key = obs.feed_name.value
        obs_dict[feed_key] = obs

        if obs.status == TIObservationType.DIRECT:
            has_direct = True
            pos_feeds.append(feed_key)
            if obs.first_feed_seen_at:
                seen_timestamps.append(obs.first_feed_seen_at)
        elif obs.status == TIObservationType.PARTIAL:
            has_partial = True
            pos_feeds.append(feed_key)
            if obs.first_feed_seen_at:
                seen_timestamps.append(obs.first_feed_seen_at)
        elif obs.status == TIObservationType.NONE:
            neg_feeds.append(feed_key)
        elif obs.status == TIObservationType.UNKNOWN_UNAVAILABLE:
            unavail_feeds.append(feed_key)

    earliest_seen = min(seen_timestamps) if seen_timestamps else None

    exposure = TIExposureSummary(
        target_id=target_id,
        has_any_direct_positive=has_direct,
        has_any_partial_positive=has_partial,
        feed_count_positive=len(pos_feeds),
        feeds_observed_positive=sorted(pos_feeds),
        feeds_observed_negative=sorted(neg_feeds),
        feeds_unavailable=sorted(unavail_feeds),
        earliest_first_feed_seen_at=earliest_seen,
    )

    return TIOverlapRecord(
        target_id=target_id,
        observations=obs_dict,
        exposure=exposure,
    )


def attach_ti_overlap(
    record: BenchmarkRecord,
    ti_record: TIOverlapRecord,
) -> BenchmarkRecord:
    """Attach canonical TI overlap metadata to a BenchmarkRecord.

    INVARIANTS PRESERVED:
    - ground_truth is NEVER modified.
    - artifact_id, target_id, and group_id remain intact.
    - evaluation.temporal_partition remains intact.
    """
    if record.target_id != ti_record.target_id:
        raise ValueError(
            f"Record target_id '{record.target_id}' does not match TI record target_id '{ti_record.target_id}'"
        )

    def _convert_to_schema_obs(feed_enum: TIFeed) -> TIFeedObservation:
        obs = ti_record.observations.get(feed_enum.value)
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

    updated_ti_meta = TIOverlapMetadata(
        virustotal=_convert_to_schema_obs(TIFeed.VIRUSTOTAL),
        google_safebrowsing=_convert_to_schema_obs(TIFeed.GOOGLE_SAFE_BROWSING),
        phishtank=_convert_to_schema_obs(TIFeed.PHISHTANK),
        openphish=_convert_to_schema_obs(TIFeed.OPENPHISH),
        urlhaus=_convert_to_schema_obs(TIFeed.URLHAUS),
        abuseipdb=_convert_to_schema_obs(TIFeed.ABUSEIPDB),
        spamhaus=_convert_to_schema_obs(TIFeed.SPAMHAUS),
    )

    return BenchmarkRecord(
        record_id=record.record_id,
        artifact_id=record.artifact_id,
        target_id=record.target_id,
        target_url=record.target_url,
        modality=record.modality,
        ground_truth=record.ground_truth,
        provenance=record.provenance,
        ti_overlap=updated_ti_meta,
        liveness=record.liveness,
        qr_relationship=record.qr_relationship,
        evaluation=record.evaluation,
        schema_version=record.schema_version,
    )
