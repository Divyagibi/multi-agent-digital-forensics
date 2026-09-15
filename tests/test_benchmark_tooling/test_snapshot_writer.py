"""Comprehensive Unit Tests for Benchmark Snapshot Writer and Integrity Verification.

Step 6C-6 Verification Suite.
"""

import inspect
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from typing import List

from tools.benchmark.schemas import (
    InputModality,
    PrimaryOutcome,
    SecondaryThreatCategory,
    VerificationStatus,
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
    compute_artifact_id,
    compute_target_id,
    compute_group_id,
    compute_record_id,
    canonicalize_record,
    hash_canonical_record,
)
from tools.benchmark.normalization import normalize_investigation_target
from tools.benchmark.snapshot_writer import (
    write_benchmark_snapshot,
    verify_snapshot_integrity,
)
import tools.benchmark.snapshot_writer as snapshot_module


class TestSnapshotWriter(unittest.TestCase):
    """Test snapshot writing, JSONL serialization, file hashing, and integrity verification."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_snapshot_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_sample_record(
        self,
        url: str = "https://example.com/login",
        outcome: PrimaryOutcome = PrimaryOutcome.MALICIOUS,
        modality: InputModality = InputModality.DIRECT_URL,
    ) -> BenchmarkRecord:
        norm = normalize_investigation_target(url)
        art_id = compute_artifact_id(modality, url)
        rec_id = compute_record_id(norm.target_id, art_id)

        return BenchmarkRecord(
            record_id=rec_id,
            artifact_id=art_id,
            target_id=norm.target_id,
            target_url=norm.canonical_url,
            modality=modality,
            ground_truth=GroundTruth(
                primary_outcome=outcome,
                secondary_categories=[SecondaryThreatCategory.CREDENTIAL_PHISHING] if outcome == PrimaryOutcome.MALICIOUS else [],
                verification_status=VerificationStatus.VERIFIED,
                verification_confidence=VerificationConfidence.HIGH,
            ),
            provenance=CandidateProvenance(
                source_name="TestSource",
                harvest_timestamp="2026-09-15T10:00:00Z",
                first_observed_timestamp="2026-09-15T09:00:00Z",
            ),
            ti_overlap=TIOverlapMetadata(
                virustotal=TIFeedObservation(
                    feed_name="VirusTotal",
                    status=TIObservationStatus.POSITIVE_OBSERVATION,
                    observed=True,
                    observed_at="2026-09-15T10:00:00Z",
                )
            ),
            liveness=LivenessMetadata(
                http_status=200,
                dns_resolved=True,
                tls_status="verified",
            ),
            qr_relationship=QRRelationshipMetadata(),
            evaluation=EvaluationMetadata(
                group_id=norm.group_id,
                temporal_partition=TemporalPartition.FINAL_TEST,
            ),
        )

    def test_write_and_verify_valid_snapshot(self):
        r1 = self._create_sample_record("https://aaa.example.com")
        r2 = self._create_sample_record("https://bbb.example.com")

        rec_file, man_file, manifest_dict = write_benchmark_snapshot([r1, r2], self.temp_dir)
        self.assertTrue(os.path.exists(rec_file))
        self.assertTrue(os.path.exists(man_file))

        is_valid, errors = verify_snapshot_integrity(self.temp_dir)
        self.assertTrue(is_valid)
        self.assertEqual(errors, [])

    def test_jsonl_content_and_ordering(self):
        r_b = self._create_sample_record("https://bbb.example.com")
        r_a = self._create_sample_record("https://aaa.example.com")

        # Pass in reverse order [r_b, r_a]
        rec_file, _, manifest_dict = write_benchmark_snapshot([r_b, r_a], self.temp_dir)

        with open(rec_file, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]

        self.assertEqual(len(lines), 2)
        rec_0 = json.loads(lines[0])
        rec_1 = json.loads(lines[1])

        # Assert lines are ordered by record_id ascending
        self.assertLess(rec_0["record_id"], rec_1["record_id"])

    def test_path_independence(self):
        r1 = self._create_sample_record("https://aaa.example.com")
        dir_a = os.path.join(self.temp_dir, "dir_a")
        dir_b = os.path.join(self.temp_dir, "dir_b")

        _, _, man_a = write_benchmark_snapshot([r1], dir_a)
        _, _, man_b = write_benchmark_snapshot([r1], dir_b)

        # Hashes and logical identifiers must be 100% path independent!
        self.assertEqual(man_a["dataset_hash"], man_b["dataset_hash"])
        self.assertEqual(man_a["records_file_hash"], man_b["records_file_hash"])
        self.assertEqual(man_a["snapshot_id"], man_b["snapshot_id"])
        self.assertEqual(man_a["manifest_hash"], man_b["manifest_hash"])

    def test_detect_corrupted_records_file(self):
        r1 = self._create_sample_record("https://example.com/test")
        rec_file, _, _ = write_benchmark_snapshot([r1], self.temp_dir)

        # Tamper with records.jsonl
        with open(rec_file, "ab") as f:
            f.write(b"corrupted_extra_bytes\n")

        is_valid, errors = verify_snapshot_integrity(self.temp_dir)
        self.assertFalse(is_valid)
        self.assertTrue(any("Records file hash mismatch" in e for e in errors))

    def test_detect_tampered_manifest(self):
        r1 = self._create_sample_record("https://example.com/test")
        _, man_file, _ = write_benchmark_snapshot([r1], self.temp_dir)

        # Tamper with manifest JSON (e.g. modify record_count)
        with open(man_file, "r", encoding="utf-8") as f:
            d = json.load(f)
        d["record_count"] = 9999
        with open(man_file, "w", encoding="utf-8") as f:
            json.dump(d, f)

        is_valid, errors = verify_snapshot_integrity(self.temp_dir)
        self.assertFalse(is_valid)
        self.assertTrue(any("Manifest hash mismatch" in e for e in errors))

    def test_empty_snapshot_allowed_and_verified(self):
        empty_dir = os.path.join(self.temp_dir, "empty")
        rec_file, man_file, man_dict = write_benchmark_snapshot([], empty_dir, allow_empty=True)
        self.assertEqual(man_dict["record_count"], 0)

        is_valid, errors = verify_snapshot_integrity(empty_dir)
        self.assertTrue(is_valid)
        self.assertEqual(errors, [])

    def test_no_network_in_snapshot_writer(self):
        source = inspect.getsource(snapshot_module)
        forbidden_patterns = [
            "requests.",
            "urllib.request.",
            "http.client.",
            "socket.",
            "subprocess.",
            "os.system",
            "eval(",
            "exec(",
        ]
        for pat in forbidden_patterns:
            self.assertNotIn(pat, source, f"Security violation: Found forbidden pattern '{pat}' in snapshot_writer.py")


if __name__ == "__main__":
    unittest.main()
