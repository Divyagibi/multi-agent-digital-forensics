"""Comprehensive Unit Tests for Benchmark Manifest Generator and Dataset Integrity Hashing.

Step 6C-6 Verification Suite.
"""

import inspect
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
    compute_artifact_id,
    compute_target_id,
    compute_group_id,
    compute_record_id,
    canonicalize_record,
    hash_canonical_record,
)
from tools.benchmark.normalization import normalize_investigation_target
from tools.benchmark.manifest_generator import (
    compute_dataset_hash,
    compute_manifest_hash,
    generate_benchmark_manifest,
)
import tools.benchmark.manifest_generator as manifest_module


class TestManifestGenerator(unittest.TestCase):
    """Test deterministic manifest generation, distribution counting, and hashing."""

    def _create_sample_record(
        self,
        url: str = "https://example.com/login",
        outcome: PrimaryOutcome = PrimaryOutcome.MALICIOUS,
        modality: InputModality = InputModality.DIRECT_URL,
        partition: TemporalPartition = TemporalPartition.FINAL_TEST,
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
            provenance=CandidateProvenance(source_name="TestSource"),
            ti_overlap=TIOverlapMetadata(
                virustotal=TIFeedObservation(
                    feed_name="VirusTotal",
                    status=TIObservationStatus.POSITIVE_OBSERVATION if outcome == PrimaryOutcome.MALICIOUS else TIObservationStatus.NEGATIVE_OBSERVATION,
                    observed=(outcome == PrimaryOutcome.MALICIOUS),
                )
            ),
            liveness=LivenessMetadata(),
            qr_relationship=QRRelationshipMetadata(
                decoded_payload=url if modality == InputModality.QR_PAYLOAD else None,
            ),
            evaluation=EvaluationMetadata(
                group_id=norm.group_id,
                temporal_partition=partition,
            ),
        )

    def test_input_order_independence(self):
        r1 = self._create_sample_record("https://aaa.example.com")
        r2 = self._create_sample_record("https://bbb.example.com")
        r3 = self._create_sample_record("https://ccc.example.com")

        man_1 = generate_benchmark_manifest([r1, r2, r3])
        man_2 = generate_benchmark_manifest([r3, r1, r2])
        man_3 = generate_benchmark_manifest([r2, r3, r1])

        self.assertEqual(man_1["dataset_hash"], man_2["dataset_hash"])
        self.assertEqual(man_1["dataset_hash"], man_3["dataset_hash"])
        self.assertEqual(man_1["snapshot_id"], man_2["snapshot_id"])
        self.assertEqual(man_1["record_hashes"], man_2["record_hashes"])
        self.assertEqual(man_1["manifest_hash"], man_2["manifest_hash"])

    def test_record_counts_and_distributions(self):
        r_mal = self._create_sample_record("https://evil.com/phish", outcome=PrimaryOutcome.MALICIOUS, modality=InputModality.DIRECT_URL, partition=TemporalPartition.FINAL_TEST)
        r_ben = self._create_sample_record("https://legit.com/home", outcome=PrimaryOutcome.BENIGN, modality=InputModality.QR_PAYLOAD, partition=TemporalPartition.VALIDATION)
        r_amb = self._create_sample_record("https://unknown.com/page", outcome=PrimaryOutcome.AMBIGUOUS, modality=InputModality.DIRECT_URL, partition=TemporalPartition.DEVELOPMENT_CALIBRATION)

        manifest = generate_benchmark_manifest([r_mal, r_ben, r_amb])
        self.assertEqual(manifest["record_count"], 3)
        self.assertEqual(manifest["ground_truth_counts"]["MALICIOUS"], 1)
        self.assertEqual(manifest["ground_truth_counts"]["BENIGN"], 1)
        self.assertEqual(manifest["ground_truth_counts"]["AMBIGUOUS"], 1)
        self.assertEqual(manifest["modality_counts"]["DIRECT_URL"], 2)
        self.assertEqual(manifest["modality_counts"]["QR_PAYLOAD"], 1)
        self.assertEqual(manifest["partition_counts"]["final_test"], 1)
        self.assertEqual(manifest["partition_counts"]["validation"], 1)
        self.assertEqual(manifest["partition_counts"]["development_calibration"], 1)
        self.assertEqual(manifest["ti_exposure_counts"]["virustotal_positive"], 1)

    def test_record_hash_index_contains_all_fields(self):
        r = self._create_sample_record("https://example.com/test")
        manifest = generate_benchmark_manifest([r])
        self.assertEqual(len(manifest["record_hashes"]), 1)
        entry = manifest["record_hashes"][0]
        self.assertEqual(entry["record_id"], r.record_id)
        self.assertEqual(entry["artifact_id"], r.artifact_id)
        self.assertEqual(entry["target_id"], r.target_id)
        self.assertEqual(entry["group_id"], r.evaluation.group_id)
        self.assertEqual(entry["record_hash"], hash_canonical_record(r))

    def test_dataset_hash_empty_and_non_empty(self):
        empty_hash = compute_dataset_hash([])
        self.assertEqual(len(empty_hash), 64)

        r = self._create_sample_record("https://example.com")
        non_empty_hash = compute_dataset_hash([r])
        self.assertNotEqual(empty_hash, non_empty_hash)

    def test_manifest_hash_no_circular_dependency(self):
        r = self._create_sample_record("https://example.com")
        man = generate_benchmark_manifest([r])
        computed_hash = compute_manifest_hash(man)
        self.assertEqual(man["manifest_hash"], computed_hash)

    def test_duplicate_record_id_rejected(self):
        r1 = self._create_sample_record("https://example.com/login")
        r2 = self._create_sample_record("https://example.com/login")
        # Passing two identical records should be detected as duplicate record_ids
        with self.assertRaises(ValueError):
            generate_benchmark_manifest([r1, r2])

    def test_no_network_in_manifest_generator(self):
        source = inspect.getsource(manifest_module)
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
            self.assertNotIn(pat, source, f"Security violation: Found forbidden pattern '{pat}' in manifest_generator.py")


if __name__ == "__main__":
    unittest.main()
