"""Benchmark Manifest Generator and Dataset Integrity Hashing Layer.

Step 6C-6: Reproducible Benchmark Snapshot, Manifest, and Integrity Hashing.

This module computes deterministic manifest metadata, record hash indices,
partition/modality/class distribution counts, and cryptographic dataset-level integrity hashes.

Architectural Guarantees:
- Deterministic Ordering: Canonical alphabetical ordering by record_id.
- Dataset-Level Integrity Hash: Cryptographically binds the ordered set of record SHA-256 digests.
- Circular-Free Manifest Hashing: manifest_hash is computed over the serialized manifest sans manifest_hash.
- Ground-Truth & TI Preservation: Counts existing distributions without altering or inferring labels.
- Offline & Self-Contained: Zero network calls; zero external service dependencies.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Set, Tuple

from .schemas import (
    BenchmarkRecord,
    canonicalize_record_dict,
    canonicalize_record,
    hash_canonical_record,
    sha256_bytes,
    validate_benchmark_record,
)


def compute_dataset_hash(sorted_records: List[BenchmarkRecord]) -> str:
    """Compute deterministic dataset-level SHA-256 hash.

    Protocol:
    - If records is empty, returns SHA-256 of "EMPTY_BENCHMARK_DATASET\\n".
    - Otherwise, computes SHA-256 over newline-joined record hashes:
      SHA256("\\n".join(record_hash_1, record_hash_2, ...) + "\\n")
    """
    if not sorted_records:
        return hashlib.sha256(b"EMPTY_BENCHMARK_DATASET\n").hexdigest()

    record_hashes = [hash_canonical_record(r) for r in sorted_records]
    combined = "\n".join(record_hashes) + "\n"
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


def compute_manifest_hash(manifest_dict: Dict[str, Any]) -> str:
    """Compute deterministic manifest SHA-256 hash without circular self-inclusion.

    Protocol:
    - Removes 'manifest_hash' from dictionary copy if present.
    - Serializes canonical JSON using canonicalize_record_dict.
    - Computes hexadecimal SHA-256 digest of UTF-8 encoded bytes.
    """
    clean_dict = {k: v for k, v in manifest_dict.items() if k != "manifest_hash"}
    canonical_json = canonicalize_record_dict(clean_dict)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def generate_benchmark_manifest(
    records: List[BenchmarkRecord],
    records_file_hash: str = "",
    records_filename: str = "records.jsonl",
    created_at: Optional[str] = None,
    manifest_version: str = "1.0.0",
    schema_version: str = "1.0.0",
) -> Dict[str, Any]:
    """Generate canonical manifest dictionary describing a frozen benchmark dataset snapshot.

    Sorting Invariant:
    Records are sorted strictly by `record_id` ascending to ensure input-order independence.
    """
    # 1. Validate all records & detect duplicate record_ids
    seen_ids: Set[str] = set()
    for r in records:
        if r.record_id in seen_ids:
            raise ValueError(f"Duplicate record_id detected in benchmark record set: '{r.record_id}'")
        seen_ids.add(r.record_id)
        validate_benchmark_record(r, raise_exception=True)

    # 2. Canonical record ordering (by record_id)
    sorted_records = sorted(records, key=lambda r: r.record_id)

    # 3. Compute Dataset Hash & Record Hash Index
    record_hashes_index: List[Dict[str, str]] = []
    partition_counts: Dict[str, int] = {}
    modality_counts: Dict[str, int] = {}
    ground_truth_counts: Dict[str, int] = {}
    ti_exposure_counts: Dict[str, int] = {
        "virustotal_positive": 0,
        "google_safebrowsing_positive": 0,
        "phishtank_positive": 0,
        "openphish_positive": 0,
        "urlhaus_positive": 0,
        "abuseipdb_positive": 0,
        "spamhaus_positive": 0,
        "any_ti_positive": 0,
    }

    for r in sorted_records:
        rec_hash = hash_canonical_record(r)
        record_hashes_index.append({
            "record_id": r.record_id,
            "artifact_id": r.artifact_id,
            "target_id": r.target_id,
            "group_id": r.evaluation.group_id,
            "record_hash": rec_hash,
        })

        # Partitions
        part_val = r.evaluation.temporal_partition.value if r.evaluation.temporal_partition else "unassigned"
        partition_counts[part_val] = partition_counts.get(part_val, 0) + 1

        # Modality
        mod_val = r.modality.value if hasattr(r.modality, "value") else str(r.modality)
        modality_counts[mod_val] = modality_counts.get(mod_val, 0) + 1

        # Ground Truth
        gt_val = r.ground_truth.primary_outcome.value if hasattr(r.ground_truth.primary_outcome, "value") else str(r.ground_truth.primary_outcome)
        ground_truth_counts[gt_val] = ground_truth_counts.get(gt_val, 0) + 1

        # TI Exposure Counts
        ti = r.ti_overlap
        ti_positive = False
        if ti.virustotal.observed:
            ti_exposure_counts["virustotal_positive"] += 1
            ti_positive = True
        if ti.google_safebrowsing.observed:
            ti_exposure_counts["google_safebrowsing_positive"] += 1
            ti_positive = True
        if ti.phishtank.observed:
            ti_exposure_counts["phishtank_positive"] += 1
            ti_positive = True
        if ti.openphish.observed:
            ti_exposure_counts["openphish_positive"] += 1
            ti_positive = True
        if ti.urlhaus.observed:
            ti_exposure_counts["urlhaus_positive"] += 1
            ti_positive = True
        if ti.abuseipdb.observed:
            ti_exposure_counts["abuseipdb_positive"] += 1
            ti_positive = True
        if ti.spamhaus.observed:
            ti_exposure_counts["spamhaus_positive"] += 1
            ti_positive = True
        if ti_positive:
            ti_exposure_counts["any_ti_positive"] += 1

    dataset_hash = compute_dataset_hash(sorted_records)
    snapshot_id = f"SNAP-{dataset_hash[:16]}"

    manifest_dict: Dict[str, Any] = {
        "manifest_version": manifest_version,
        "benchmark_schema_version": schema_version,
        "snapshot_id": snapshot_id,
        "record_count": len(sorted_records),
        "hash_algorithm": "SHA-256",
        "serialization_format": "deterministic UTF-8 JSONL",
        "ordering_rule": "record_id ascending",
        "records_file": records_filename,
        "records_file_hash": records_file_hash,
        "dataset_hash": dataset_hash,
        "record_hashes": record_hashes_index,
        "partition_counts": dict(sorted(partition_counts.items())),
        "modality_counts": dict(sorted(modality_counts.items())),
        "ground_truth_counts": dict(sorted(ground_truth_counts.items())),
        "ti_exposure_counts": dict(sorted(ti_exposure_counts.items())),
    }

    if created_at is not None:
        manifest_dict["created_at"] = created_at

    manifest_dict["manifest_hash"] = compute_manifest_hash(manifest_dict)
    return manifest_dict
