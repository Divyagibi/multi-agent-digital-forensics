"""Candidate Harvesting and Raw Candidate Pool Layer.

Step 6D-2: Candidate Harvesting for Multi-Agent Digital Forensics Benchmark.

This module provides deterministic, research-safe, and loss-minimizing candidate
harvesting from approved, documented sources (public malicious feeds, phishing sources,
benign curated lists, research datasets, and QR repositories).

Architectural & Methodological Guarantees:
1. Ground-Truth Firewall: Harvesting gathers raw candidates and preserves source claims as
   metadata. It NEVER assigns ground-truth labels (BENIGN/MALICIOUS) or resolves ambiguities.
2. Production & Engine Segregation: Zero imports or couplings to TCE, AERE, Confidence Engine,
   or Agents A1-A18. Zero conversion of source membership into forensic risk scores.
3. Raw Artifact Preservation: Exact observed raw URLs, QR payload strings, and image paths/bytes
   are preserved verbatim without premature normalization.
4. Loss-Minimizing Provenance: Candidates from all sources are retained with complete source
   attribution. No destructive deduplication occurs during harvesting.
5. Multi-Modal Support: Seamlessly handles DIRECT_URL, QR_IMAGE, and QR_PAYLOAD modalities.
6. Research Safety: Fully passive parsing; zero dynamic malware execution; zero payload execution;
   safe handling of non-HTTP schemes (mailto:, smsto:, wifi:, intent:, etc.).
7. Offline Testability: Operates on local files, strings, and mock source adapters without
   requiring live external network access.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import csv
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import hashlib
import io
import json
from pathlib import Path
import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

from .schemas import (
    InputModality,
    CandidateProvenance,
    compute_artifact_id,
    compute_target_id,
)


class SourceType(str, Enum):
    """Categorization of candidate harvesting sources."""
    PUBLIC_FEED = "PUBLIC_FEED"
    RESEARCH_DATASET = "RESEARCH_DATASET"
    CURATED_LIST = "CURATED_LIST"
    LOCAL_FILE = "LOCAL_FILE"
    CUSTOM_ADAPTER = "CUSTOM_ADAPTER"


class RetrievalStatus(str, Enum):
    """Execution status of candidate retrieval from a source."""
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"
    RATE_LIMITED = "RATE_LIMITED"
    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
    SKIPPED = "SKIPPED"


def compute_candidate_id(source_name: str, raw_content: Union[str, bytes], source_record_id: str = "") -> str:
    """Compute deterministic Candidate ID (CAN-<sha256[:16]>)."""
    if isinstance(raw_content, str):
        content_bytes = raw_content.encode("utf-8")
    else:
        content_bytes = raw_content
    combined = f"{source_name.strip().lower()}:{source_record_id.strip()}:".encode("utf-8") + content_bytes
    digest = hashlib.sha256(combined).hexdigest()[:16]
    return f"CAN-{digest}"


@dataclass(frozen=True)
class RawCandidate:
    """Immutable representation of a harvested candidate prior to ground-truth verification."""
    candidate_id: str
    raw_content: Union[str, bytes]
    modality: InputModality
    source_name: str
    source_type: SourceType
    source_record_id: str = ""
    source_reference: str = ""
    first_observed_timestamp: str = ""
    harvest_timestamp: str = ""
    source_metadata: Dict[str, Any] = field(default_factory=dict)
    retrieval_status: RetrievalStatus = RetrievalStatus.SUCCESS
    retrieval_error: str = ""
    license_or_access_notes: str = ""
    artifact_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert candidate to serializable dictionary."""
        return {
            "candidate_id": self.candidate_id,
            "raw_content": self.raw_content if isinstance(self.raw_content, str) else f"<bytes len={len(self.raw_content)}>",
            "modality": self.modality.value if hasattr(self.modality, "value") else str(self.modality),
            "source_name": self.source_name,
            "source_type": self.source_type.value if hasattr(self.source_type, "value") else str(self.source_type),
            "source_record_id": self.source_record_id,
            "source_reference": self.source_reference,
            "first_observed_timestamp": self.first_observed_timestamp,
            "harvest_timestamp": self.harvest_timestamp,
            "source_metadata": self.source_metadata,
            "retrieval_status": self.retrieval_status.value if hasattr(self.retrieval_status, "value") else str(self.retrieval_status),
            "retrieval_error": self.retrieval_error,
            "license_or_access_notes": self.license_or_access_notes,
            "artifact_id": self.artifact_id,
        }

    def to_candidate_provenance(self) -> CandidateProvenance:
        """Convert to benchmark schema CandidateProvenance instance."""
        return CandidateProvenance(
            source_name=self.source_name,
            source_record_id=self.source_record_id,
            harvest_timestamp=self.harvest_timestamp,
            first_observed_timestamp=self.first_observed_timestamp,
            source_notes=self.license_or_access_notes or (f"Ref: {self.source_reference}" if self.source_reference else ""),
        )


@dataclass(frozen=True)
class SourceHarvestReport:
    """Detailed harvesting report for an individual source."""
    source_name: str
    source_type: SourceType
    status: RetrievalStatus
    candidates_harvested: int
    unique_artifacts_count: int
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_name": self.source_name,
            "source_type": self.source_type.value if hasattr(self.source_type, "value") else str(self.source_type),
            "status": self.status.value if hasattr(self.status, "value") else str(self.status),
            "candidates_harvested": self.candidates_harvested,
            "unique_artifacts_count": self.unique_artifacts_count,
            "errors": self.errors,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class HarvestingResult:
    """Aggregated result container of a candidate harvesting execution."""
    total_candidates_harvested: int
    candidates: List[RawCandidate]
    source_reports: Dict[str, SourceHarvestReport]
    modality_counts: Dict[str, int]
    source_counts: Dict[str, int]
    exact_duplicate_count: int
    diagnostics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_candidates_harvested": self.total_candidates_harvested,
            "modality_counts": self.modality_counts,
            "source_counts": self.source_counts,
            "exact_duplicate_count": self.exact_duplicate_count,
            "source_reports": {k: v.to_dict() for k, v in self.source_reports.items()},
            "candidates": [c.to_dict() for c in self.candidates],
            "diagnostics": self.diagnostics,
        }


# =====================================================================
# Source Adapters
# =====================================================================

class BaseSourceAdapter(ABC):
    """Abstract base adapter for candidate sources."""

    def __init__(
        self,
        source_name: str,
        source_type: SourceType = SourceType.PUBLIC_FEED,
        license_or_access_notes: str = "",
    ):
        self.source_name = source_name
        self.source_type = source_type
        self.license_or_access_notes = license_or_access_notes

    @abstractmethod
    def harvest(
        self,
        source_input: Any,
        harvest_timestamp: Optional[str] = None,
    ) -> Tuple[List[RawCandidate], SourceHarvestReport]:
        """Parse source input and extract raw candidates."""
        pass


class TextListFeedAdapter(BaseSourceAdapter):
    """Adapter for plain text newline-delimited URL or payload feeds."""

    def __init__(
        self,
        source_name: str,
        source_type: SourceType = SourceType.PUBLIC_FEED,
        modality: InputModality = InputModality.DIRECT_URL,
        license_or_access_notes: str = "",
    ):
        super().__init__(source_name, source_type, license_or_access_notes)
        self.modality = modality

    def harvest(
        self,
        source_input: Union[str, Path, List[str]],
        harvest_timestamp: Optional[str] = None,
    ) -> Tuple[List[RawCandidate], SourceHarvestReport]:
        candidates: List[RawCandidate] = []
        errors: List[str] = []
        h_ts = harvest_timestamp or ""

        lines: List[str] = []
        source_ref = ""

        if isinstance(source_input, Path) or (isinstance(source_input, str) and "\n" not in source_input and Path(source_input).exists()):
            p = Path(source_input)
            source_ref = str(p)
            try:
                content = p.read_text(encoding="utf-8")
                lines = content.splitlines()
            except Exception as e:
                errors.append(f"Failed to read file {source_input}: {str(e)}")
                report = SourceHarvestReport(
                    source_name=self.source_name,
                    source_type=self.source_type,
                    status=RetrievalStatus.FAILED,
                    candidates_harvested=0,
                    unique_artifacts_count=0,
                    errors=errors,
                )
                return [], report
        elif isinstance(source_input, str):
            lines = source_input.splitlines()
        elif isinstance(source_input, (list, tuple)):
            lines = list(source_input)
        else:
            errors.append(f"Unsupported source_input type: {type(source_input)}")
            report = SourceHarvestReport(
                source_name=self.source_name,
                source_type=self.source_type,
                status=RetrievalStatus.FAILED,
                candidates_harvested=0,
                unique_artifacts_count=0,
                errors=errors,
            )
            return [], report

        seen_artifacts: Set[str] = set()
        for idx, line in enumerate(lines, 1):
            raw = line.strip()
            # Ignore empty lines and standard comment headers
            if not raw or raw.startswith("#") or raw.startswith("//"):
                continue

            art_id = compute_artifact_id(self.modality, raw)
            seen_artifacts.add(art_id)
            cid = compute_candidate_id(self.source_name, raw, str(idx))

            candidate = RawCandidate(
                candidate_id=cid,
                raw_content=raw,
                modality=self.modality,
                source_name=self.source_name,
                source_type=self.source_type,
                source_record_id=str(idx),
                source_reference=source_ref,
                first_observed_timestamp="",
                harvest_timestamp=h_ts,
                source_metadata={},
                retrieval_status=RetrievalStatus.SUCCESS,
                license_or_access_notes=self.license_or_access_notes,
                artifact_id=art_id,
            )
            candidates.append(candidate)

        report = SourceHarvestReport(
            source_name=self.source_name,
            source_type=self.source_type,
            status=RetrievalStatus.SUCCESS if candidates else RetrievalStatus.UNAVAILABLE,
            candidates_harvested=len(candidates),
            unique_artifacts_count=len(seen_artifacts),
            errors=errors,
        )
        return candidates, report


class JSONFeedAdapter(BaseSourceAdapter):
    """Adapter for JSON array or JSONL feeds with customizable schema mapping."""

    def __init__(
        self,
        source_name: str,
        source_type: SourceType = SourceType.PUBLIC_FEED,
        content_field: str = "url",
        id_field: Optional[str] = "id",
        timestamp_field: Optional[str] = "date_added",
        metadata_fields: Optional[List[str]] = None,
        modality: InputModality = InputModality.DIRECT_URL,
        license_or_access_notes: str = "",
    ):
        super().__init__(source_name, source_type, license_or_access_notes)
        self.content_field = content_field
        self.id_field = id_field
        self.timestamp_field = timestamp_field
        self.metadata_fields = metadata_fields or []
        self.modality = modality

    def harvest(
        self,
        source_input: Union[str, Path, List[Dict[str, Any]]],
        harvest_timestamp: Optional[str] = None,
    ) -> Tuple[List[RawCandidate], SourceHarvestReport]:
        candidates: List[RawCandidate] = []
        errors: List[str] = []
        h_ts = harvest_timestamp or ""
        source_ref = ""

        records_data: List[Dict[str, Any]] = []

        if isinstance(source_input, Path) or (isinstance(source_input, str) and "\n" not in source_input and Path(source_input).exists()):
            p = Path(source_input)
            source_ref = str(p)
            try:
                raw_text = p.read_text(encoding="utf-8")
                # Try standard JSON array first, fallback to JSONL
                try:
                    parsed = json.loads(raw_text)
                    if isinstance(parsed, list):
                        records_data = parsed
                    elif isinstance(parsed, dict) and "data" in parsed and isinstance(parsed["data"], list):
                        records_data = parsed["data"]
                    else:
                        records_data = [parsed]
                except json.JSONDecodeError:
                    records_data = [json.loads(line) for line in raw_text.splitlines() if line.strip()]
            except Exception as e:
                errors.append(f"Failed to read/parse JSON from {source_input}: {str(e)}")
                report = SourceHarvestReport(
                    source_name=self.source_name,
                    source_type=self.source_type,
                    status=RetrievalStatus.FAILED,
                    candidates_harvested=0,
                    unique_artifacts_count=0,
                    errors=errors,
                )
                return [], report
        elif isinstance(source_input, str):
            try:
                parsed = json.loads(source_input)
                if isinstance(parsed, list):
                    records_data = parsed
                elif isinstance(parsed, dict) and "data" in parsed and isinstance(parsed["data"], list):
                    records_data = parsed["data"]
                else:
                    records_data = [parsed]
            except json.JSONDecodeError:
                records_data = [json.loads(line) for line in source_input.splitlines() if line.strip()]
        elif isinstance(source_input, list):
            records_data = source_input
        else:
            errors.append(f"Unsupported JSON source_input type: {type(source_input)}")
            report = SourceHarvestReport(
                source_name=self.source_name,
                source_type=self.source_type,
                status=RetrievalStatus.FAILED,
                candidates_harvested=0,
                unique_artifacts_count=0,
                errors=errors,
            )
            return [], report

        seen_artifacts: Set[str] = set()
        for idx, item in enumerate(records_data, 1):
            if not isinstance(item, dict):
                continue
            raw = str(item.get(self.content_field, "")).strip()
            if not raw:
                continue

            rec_id = str(item.get(self.id_field, idx)) if self.id_field else str(idx)
            ts_val = str(item.get(self.timestamp_field, "")) if self.timestamp_field else ""

            # Extract specified metadata or store complete item
            meta: Dict[str, Any] = {}
            if self.metadata_fields:
                for fld in self.metadata_fields:
                    if fld in item:
                        meta[fld] = item[fld]
            else:
                meta = {k: v for k, v in item.items() if k != self.content_field}

            art_id = compute_artifact_id(self.modality, raw)
            seen_artifacts.add(art_id)
            cid = compute_candidate_id(self.source_name, raw, rec_id)

            candidate = RawCandidate(
                candidate_id=cid,
                raw_content=raw,
                modality=self.modality,
                source_name=self.source_name,
                source_type=self.source_type,
                source_record_id=rec_id,
                source_reference=source_ref,
                first_observed_timestamp=ts_val,
                harvest_timestamp=h_ts,
                source_metadata=meta,
                retrieval_status=RetrievalStatus.SUCCESS,
                license_or_access_notes=self.license_or_access_notes,
                artifact_id=art_id,
            )
            candidates.append(candidate)

        report = SourceHarvestReport(
            source_name=self.source_name,
            source_type=self.source_type,
            status=RetrievalStatus.SUCCESS if candidates else RetrievalStatus.UNAVAILABLE,
            candidates_harvested=len(candidates),
            unique_artifacts_count=len(seen_artifacts),
            errors=errors,
        )
        return candidates, report


class CSVFeedAdapter(BaseSourceAdapter):
    """Adapter for CSV formatted feeds with column mapping."""

    def __init__(
        self,
        source_name: str,
        source_type: SourceType = SourceType.PUBLIC_FEED,
        content_column: str = "url",
        id_column: Optional[str] = "id",
        timestamp_column: Optional[str] = "timestamp",
        metadata_columns: Optional[List[str]] = None,
        delimiter: str = ",",
        has_header: bool = True,
        modality: InputModality = InputModality.DIRECT_URL,
        license_or_access_notes: str = "",
    ):
        super().__init__(source_name, source_type, license_or_access_notes)
        self.content_column = content_column
        self.id_column = id_column
        self.timestamp_column = timestamp_column
        self.metadata_columns = metadata_columns or []
        self.delimiter = delimiter
        self.has_header = has_header
        self.modality = modality

    def harvest(
        self,
        source_input: Union[str, Path],
        harvest_timestamp: Optional[str] = None,
    ) -> Tuple[List[RawCandidate], SourceHarvestReport]:
        candidates: List[RawCandidate] = []
        errors: List[str] = []
        h_ts = harvest_timestamp or ""
        source_ref = ""

        csv_text = ""
        if isinstance(source_input, Path) or (isinstance(source_input, str) and "\n" not in source_input and Path(source_input).exists()):
            p = Path(source_input)
            source_ref = str(p)
            try:
                csv_text = p.read_text(encoding="utf-8")
            except Exception as e:
                errors.append(f"Failed to read CSV file {source_input}: {str(e)}")
                report = SourceHarvestReport(
                    source_name=self.source_name,
                    source_type=self.source_type,
                    status=RetrievalStatus.FAILED,
                    candidates_harvested=0,
                    unique_artifacts_count=0,
                    errors=errors,
                )
                return [], report
        elif isinstance(source_input, str):
            csv_text = source_input
        else:
            errors.append(f"Unsupported CSV source_input type: {type(source_input)}")
            report = SourceHarvestReport(
                source_name=self.source_name,
                source_type=self.source_type,
                status=RetrievalStatus.FAILED,
                candidates_harvested=0,
                unique_artifacts_count=0,
                errors=errors,
            )
            return [], report

        seen_artifacts: Set[str] = set()
        try:
            reader = csv.DictReader(io.StringIO(csv_text), delimiter=self.delimiter)
            for idx, row in enumerate(reader, 1):
                raw = (row.get(self.content_column) or "").strip()
                if not raw:
                    continue

                rec_id = str(row.get(self.id_column, idx)) if self.id_column else str(idx)
                ts_val = str(row.get(self.timestamp_column, "")) if self.timestamp_column else ""

                meta: Dict[str, Any] = {}
                if self.metadata_columns:
                    for col in self.metadata_columns:
                        if col in row:
                            meta[col] = row[col]
                else:
                    meta = {k: v for k, v in row.items() if k != self.content_column}

                art_id = compute_artifact_id(self.modality, raw)
                seen_artifacts.add(art_id)
                cid = compute_candidate_id(self.source_name, raw, rec_id)

                candidate = RawCandidate(
                    candidate_id=cid,
                    raw_content=raw,
                    modality=self.modality,
                    source_name=self.source_name,
                    source_type=self.source_type,
                    source_record_id=rec_id,
                    source_reference=source_ref,
                    first_observed_timestamp=ts_val,
                    harvest_timestamp=h_ts,
                    source_metadata=meta,
                    retrieval_status=RetrievalStatus.SUCCESS,
                    license_or_access_notes=self.license_or_access_notes,
                    artifact_id=art_id,
                )
                candidates.append(candidate)
        except Exception as e:
            errors.append(f"CSV parsing error: {str(e)}")

        report = SourceHarvestReport(
            source_name=self.source_name,
            source_type=self.source_type,
            status=RetrievalStatus.SUCCESS if candidates else (RetrievalStatus.FAILED if errors else RetrievalStatus.UNAVAILABLE),
            candidates_harvested=len(candidates),
            unique_artifacts_count=len(seen_artifacts),
            errors=errors,
        )
        return candidates, report


class QRImageSourceAdapter(BaseSourceAdapter):
    """Adapter for static QR barcode image collections."""

    def __init__(
        self,
        source_name: str,
        source_type: SourceType = SourceType.RESEARCH_DATASET,
        license_or_access_notes: str = "",
    ):
        super().__init__(source_name, source_type, license_or_access_notes)

    def harvest(
        self,
        source_input: Union[str, Path, List[Dict[str, Any]]],
        harvest_timestamp: Optional[str] = None,
    ) -> Tuple[List[RawCandidate], SourceHarvestReport]:
        candidates: List[RawCandidate] = []
        errors: List[str] = []
        h_ts = harvest_timestamp or ""

        image_items: List[Dict[str, Any]] = []

        if isinstance(source_input, Path) or (isinstance(source_input, str) and Path(source_input).is_dir()):
            dir_path = Path(source_input)
            for img_file in sorted(dir_path.glob("*.*")):
                if img_file.suffix.lower() in (".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif"):
                    image_items.append({
                        "image_path": str(img_file),
                        "id": img_file.stem,
                        "filename": img_file.name,
                    })
        elif isinstance(source_input, list):
            image_items = source_input
        else:
            errors.append(f"Unsupported QR image source input: {source_input}")

        seen_artifacts: Set[str] = set()
        for idx, item in enumerate(image_items, 1):
            img_path = str(item.get("image_path") or item.get("path") or item.get("uri") or "").strip()
            if not img_path:
                continue

            rec_id = str(item.get("id") or idx)
            art_id = compute_artifact_id(InputModality.QR_IMAGE, img_path)
            seen_artifacts.add(art_id)
            cid = compute_candidate_id(self.source_name, img_path, rec_id)

            candidate = RawCandidate(
                candidate_id=cid,
                raw_content=img_path,
                modality=InputModality.QR_IMAGE,
                source_name=self.source_name,
                source_type=self.source_type,
                source_record_id=rec_id,
                source_reference=img_path,
                first_observed_timestamp=str(item.get("timestamp") or ""),
                harvest_timestamp=h_ts,
                source_metadata=item,
                retrieval_status=RetrievalStatus.SUCCESS,
                license_or_access_notes=self.license_or_access_notes,
                artifact_id=art_id,
            )
            candidates.append(candidate)

        report = SourceHarvestReport(
            source_name=self.source_name,
            source_type=self.source_type,
            status=RetrievalStatus.SUCCESS if candidates else RetrievalStatus.UNAVAILABLE,
            candidates_harvested=len(candidates),
            unique_artifacts_count=len(seen_artifacts),
            errors=errors,
        )
        return candidates, report


class QRPayloadSourceAdapter(BaseSourceAdapter):
    """Adapter for pre-extracted / decoded QR text payload candidate feeds."""

    def __init__(
        self,
        source_name: str,
        source_type: SourceType = SourceType.RESEARCH_DATASET,
        license_or_access_notes: str = "",
    ):
        super().__init__(source_name, source_type, license_or_access_notes)

    def harvest(
        self,
        source_input: Union[str, Path, List[str], List[Dict[str, Any]]],
        harvest_timestamp: Optional[str] = None,
    ) -> Tuple[List[RawCandidate], SourceHarvestReport]:
        candidates: List[RawCandidate] = []
        errors: List[str] = []
        h_ts = harvest_timestamp or ""

        payload_items: List[Dict[str, Any]] = []

        if isinstance(source_input, (list, tuple)):
            for idx, item in enumerate(source_input, 1):
                if isinstance(item, str):
                    payload_items.append({"payload": item, "id": str(idx)})
                elif isinstance(item, dict):
                    payload_items.append(item)
        elif isinstance(source_input, str):
            for idx, line in enumerate(source_input.splitlines(), 1):
                clean = line.strip()
                if clean:
                    payload_items.append({"payload": clean, "id": str(idx)})
        else:
            errors.append(f"Unsupported QR payload source input type: {type(source_input)}")

        seen_artifacts: Set[str] = set()
        for idx, item in enumerate(payload_items, 1):
            raw_payload = str(item.get("payload") or item.get("text") or item.get("content") or "").strip()
            if not raw_payload:
                continue

            rec_id = str(item.get("id") or idx)
            art_id = compute_artifact_id(InputModality.QR_PAYLOAD, raw_payload)
            seen_artifacts.add(art_id)
            cid = compute_candidate_id(self.source_name, raw_payload, rec_id)

            candidate = RawCandidate(
                candidate_id=cid,
                raw_content=raw_payload,
                modality=InputModality.QR_PAYLOAD,
                source_name=self.source_name,
                source_type=self.source_type,
                source_record_id=rec_id,
                source_reference=str(item.get("reference") or ""),
                first_observed_timestamp=str(item.get("timestamp") or ""),
                harvest_timestamp=h_ts,
                source_metadata=item,
                retrieval_status=RetrievalStatus.SUCCESS,
                license_or_access_notes=self.license_or_access_notes,
                artifact_id=art_id,
            )
            candidates.append(candidate)

        report = SourceHarvestReport(
            source_name=self.source_name,
            source_type=self.source_type,
            status=RetrievalStatus.SUCCESS if candidates else RetrievalStatus.UNAVAILABLE,
            candidates_harvested=len(candidates),
            unique_artifacts_count=len(seen_artifacts),
            errors=errors,
        )
        return candidates, report


class CustomSourceAdapter(BaseSourceAdapter):
    """Adapter wrapping a custom parser function."""

    def __init__(
        self,
        source_name: str,
        parser_func: Callable[[Any, Optional[str]], Tuple[List[RawCandidate], SourceHarvestReport]],
        source_type: SourceType = SourceType.CUSTOM_ADAPTER,
        license_or_access_notes: str = "",
    ):
        super().__init__(source_name, source_type, license_or_access_notes)
        self.parser_func = parser_func

    def harvest(
        self,
        source_input: Any,
        harvest_timestamp: Optional[str] = None,
    ) -> Tuple[List[RawCandidate], SourceHarvestReport]:
        return self.parser_func(source_input, harvest_timestamp)


# =====================================================================
# Candidate Harvester Engine
# =====================================================================

class CandidateHarvester:
    """Orchestrator for managing source adapters and harvesting raw candidates."""

    def __init__(self):
        self._adapters: Dict[str, BaseSourceAdapter] = {}

    def register_adapter(self, adapter: BaseSourceAdapter) -> None:
        """Register a source adapter."""
        self._adapters[adapter.source_name] = adapter

    def get_adapter(self, source_name: str) -> Optional[BaseSourceAdapter]:
        """Retrieve a registered adapter by source name."""
        return self._adapters.get(source_name)

    def harvest_from_adapter(
        self,
        source_name: str,
        source_input: Any,
        harvest_timestamp: Optional[str] = None,
    ) -> HarvestingResult:
        """Execute harvesting on a single registered adapter."""
        adapter = self._adapters.get(source_name)
        if not adapter:
            raise KeyError(f"Source adapter '{source_name}' is not registered")

        candidates, report = adapter.harvest(source_input, harvest_timestamp=harvest_timestamp)
        return self.aggregate_candidates([candidates], {source_name: report})

    def harvest_all(
        self,
        source_inputs: Dict[str, Any],
        harvest_timestamp: Optional[str] = None,
    ) -> HarvestingResult:
        """Execute harvesting across all configured sources."""
        all_candidates: List[List[RawCandidate]] = []
        reports: Dict[str, SourceHarvestReport] = {}

        for src_name, src_input in source_inputs.items():
            adapter = self._adapters.get(src_name)
            if not adapter:
                # Record source as unavailable / unregistered
                rep = SourceHarvestReport(
                    source_name=src_name,
                    source_type=SourceType.PUBLIC_FEED,
                    status=RetrievalStatus.UNAVAILABLE,
                    candidates_harvested=0,
                    unique_artifacts_count=0,
                    errors=[f"Adapter '{src_name}' is not registered"],
                )
                reports[src_name] = rep
                continue

            cands, rep = adapter.harvest(src_input, harvest_timestamp=harvest_timestamp)
            all_candidates.append(cands)
            reports[src_name] = rep

        return self.aggregate_candidates(all_candidates, reports)

    def aggregate_candidates(
        self,
        candidate_lists: List[List[RawCandidate]],
        reports: Optional[Dict[str, SourceHarvestReport]] = None,
    ) -> HarvestingResult:
        """Aggregate candidates, track duplicates without deletion, and build summary statistics."""
        merged_candidates: List[RawCandidate] = []
        modality_counts: Dict[str, int] = {}
        source_counts: Dict[str, int] = {}

        seen_artifacts: Dict[str, int] = {}

        for cand_list in candidate_lists:
            for c in cand_list:
                merged_candidates.append(c)

                # Count by modality
                mod_str = c.modality.value if hasattr(c.modality, "value") else str(c.modality)
                modality_counts[mod_str] = modality_counts.get(mod_str, 0) + 1

                # Count by source
                source_counts[c.source_name] = source_counts.get(c.source_name, 0) + 1

                # Track artifact duplication without deletion
                seen_artifacts[c.artifact_id] = seen_artifacts.get(c.artifact_id, 0) + 1

        exact_duplicate_count = sum(count - 1 for count in seen_artifacts.values() if count > 1)

        diagnostics = {
            "total_records_retained": len(merged_candidates),
            "unique_artifacts_count": len(seen_artifacts),
            "exact_duplicate_instances": exact_duplicate_count,
            "sources_harvested_count": len(source_counts),
        }

        return HarvestingResult(
            total_candidates_harvested=len(merged_candidates),
            candidates=merged_candidates,
            source_reports=reports or {},
            modality_counts=dict(sorted(modality_counts.items())),
            source_counts=dict(sorted(source_counts.items())),
            exact_duplicate_count=exact_duplicate_count,
            diagnostics=diagnostics,
        )
