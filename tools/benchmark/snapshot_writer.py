"""Benchmark Snapshot Writer and Loader Layer.

Step 6C-6: Reproducible Benchmark Snapshot, Manifest, and Integrity Hashing.

This module provides atomic, deterministic snapshot writing and integrity-verified
loading of frozen benchmark datasets.

Architectural Guarantees:
- Deterministic Ordering: records.jsonl is written in canonical record_id ascending order.
- Exact File Integrity: Computes SHA-256 of the exact final written bytes of records.jsonl.
- Atomicity: Validation failures abort before writing corrupted or incomplete snapshot outputs.
- Path Independence: Serialized contents and dataset hashes are completely independent of local file paths.
- Offline & Self-Contained: Zero network calls; zero external service dependencies.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Dict, List, Optional, Tuple, Union

from .schemas import (
    BenchmarkRecord,
    canonicalize_record,
    canonicalize_record_dict,
    validate_benchmark_record,
)
from .manifest_generator import (
    generate_benchmark_manifest,
    compute_dataset_hash,
    compute_manifest_hash,
)


def write_benchmark_snapshot(
    records: List[BenchmarkRecord],
    output_dir: Union[str, Path],
    created_at: Optional[str] = None,
    records_filename: str = "records.jsonl",
    manifest_filename: str = "manifest.json",
    allow_empty: bool = True,
) -> Tuple[str, str, Dict[str, Any]]:
    """Write an immutable, deterministic benchmark snapshot and manifest to disk.

    Process:
    1. Validates records and enforces uniqueness of record_id.
    2. Sorts records canonically by record_id ascending.
    3. Serializes each record deterministically to JSONL.
    4. Computes SHA-256 hash of written records.jsonl bytes.
    5. Generates canonical manifest metadata and calculates dataset/manifest hashes.
    6. Writes manifest.json.
    7. Returns (records_jsonl_path, manifest_json_path, manifest_dict).
    """
    if not records and not allow_empty:
        raise ValueError("Cannot write empty benchmark snapshot when allow_empty is False")

    # 1. Validation & duplicate record_id check
    seen_ids = set()
    for r in records:
        if r.record_id in seen_ids:
            raise ValueError(f"Duplicate record_id detected in snapshot records: '{r.record_id}'")
        seen_ids.add(r.record_id)
        validate_benchmark_record(r, raise_exception=True)

    # 2. Canonical record ordering (by record_id ascending)
    sorted_records = sorted(records, key=lambda r: r.record_id)

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    records_file_path = out_path / records_filename
    manifest_file_path = out_path / manifest_filename

    # 3. Serialize records.jsonl with UTF-8 and normalized \n
    hasher = hashlib.sha256()
    with open(records_file_path, "wb") as f_records:
        for r in sorted_records:
            line_str = canonicalize_record(r)
            line_bytes = line_str.encode("utf-8")
            f_records.write(line_bytes)
            hasher.update(line_bytes)

    records_file_hash = hasher.hexdigest()

    # 4. Generate manifest with records_file_hash
    manifest_dict = generate_benchmark_manifest(
        records=sorted_records,
        records_file_hash=records_file_hash,
        records_filename=records_filename,
        created_at=created_at,
    )

    # 5. Write manifest.json deterministically
    manifest_json_str = canonicalize_record_dict(manifest_dict) + "\n"
    with open(manifest_file_path, "wb") as f_manifest:
        f_manifest.write(manifest_json_str.encode("utf-8"))

    return str(records_file_path), str(manifest_file_path), manifest_dict


def verify_snapshot_integrity(
    snapshot_dir: Union[str, Path],
    records_filename: str = "records.jsonl",
    manifest_filename: str = "manifest.json",
) -> Tuple[bool, List[str]]:
    """Audit the cryptographic integrity of a frozen benchmark snapshot against its manifest.

    Checks:
    - Existence of records.jsonl and manifest.json.
    - Exact SHA-256 match of records.jsonl file bytes against records_file_hash.
    - Exact match of computed manifest_hash against recorded manifest_hash.
    """
    snap_path = Path(snapshot_dir)
    records_file_path = snap_path / records_filename
    manifest_file_path = snap_path / manifest_filename

    errors: List[str] = []

    if not manifest_file_path.exists():
        errors.append(f"Manifest file missing at '{manifest_file_path}'")
        return False, errors

    if not records_file_path.exists():
        errors.append(f"Records file missing at '{records_file_path}'")
        return False, errors

    try:
        with open(manifest_file_path, "r", encoding="utf-8") as f:
            manifest_dict = json.load(f)
    except Exception as e:
        errors.append(f"Failed to parse manifest JSON: {str(e)}")
        return False, errors

    # Check manifest hash
    recorded_manifest_hash = manifest_dict.get("manifest_hash", "")
    computed_manifest_hash = compute_manifest_hash(manifest_dict)
    if recorded_manifest_hash != computed_manifest_hash:
        errors.append(
            f"Manifest hash mismatch: recorded '{recorded_manifest_hash}' != computed '{computed_manifest_hash}'"
        )

    # Check records.jsonl file hash
    recorded_records_hash = manifest_dict.get("records_file_hash", "")
    hasher = hashlib.sha256()
    with open(records_file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    computed_records_hash = hasher.hexdigest()

    if recorded_records_hash != computed_records_hash:
        errors.append(
            f"Records file hash mismatch: recorded '{recorded_records_hash}' != computed '{computed_records_hash}'"
        )

    is_valid = (len(errors) == 0)
    return is_valid, errors
