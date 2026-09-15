"""Comprehensive Unit Tests for Benchmark Schema, Identity Model, and Deterministic Serialization.

Step 6C-1 Verification Suite.
"""

import sys
import unittest
from typing import Dict, Any

from tools.benchmark.schemas import (
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
    compute_artifact_id,
    compute_target_id,
    compute_group_id,
    compute_record_id,
    canonicalize_record_dict,
    canonicalize_record,
    sha256_bytes,
    hash_canonical_record,
    validate_benchmark_record,
    ValidationError,
)


class TestBenchmarkIdentity(unittest.TestCase):
    """Test deterministic identity model across 3 tiers + record ID."""

    def test_tier1_artifact_id_deterministic(self):
        url = "https://example.com/login?id=123"
        art_id1 = compute_artifact_id(InputModality.DIRECT_URL, url)
        art_id2 = compute_artifact_id(InputModality.DIRECT_URL, url)
        self.assertEqual(art_id1, art_id2)
        self.assertTrue(art_id1.startswith("ART-"))
        self.assertEqual(len(art_id1), 20)  # "ART-" (4) + 16 hex chars

    def test_tier1_artifact_id_differs_by_modality_and_content(self):
        content = "https://example.com/test"
        art_direct = compute_artifact_id(InputModality.DIRECT_URL, content)
        art_qr = compute_artifact_id(InputModality.QR_PAYLOAD, content)
        self.assertNotEqual(art_direct, art_qr)

        art_bytes = compute_artifact_id(InputModality.QR_IMAGE, b"\x89PNG\r\n\x1a\n...")
        self.assertTrue(art_bytes.startswith("ART-"))
        self.assertNotEqual(art_direct, art_bytes)

    def test_tier2_target_id_deterministic(self):
        target = "https://bank.example.com/login"
        tgt_id1 = compute_target_id(target)
        tgt_id2 = compute_target_id(target)
        tgt_id_case = compute_target_id("HTTPS://BANK.EXAMPLE.COM/LOGIN")
        self.assertEqual(tgt_id1, tgt_id2)
        self.assertEqual(tgt_id1, tgt_id_case)
        self.assertTrue(tgt_id1.startswith("TGT-"))
        self.assertEqual(len(tgt_id1), 20)

    def test_tier2_target_id_differs_by_path(self):
        tgt_login = compute_target_id("https://example.com/login")
        tgt_download = compute_target_id("https://example.com/download.apk")
        self.assertNotEqual(tgt_login, tgt_download)

    def test_tier3_group_id_deterministic(self):
        group_key = "example.com"
        grp_id1 = compute_group_id(group_key)
        grp_id2 = compute_group_id(group_key)
        grp_id_case = compute_group_id("EXAMPLE.COM")
        self.assertEqual(grp_id1, grp_id2)
        self.assertEqual(grp_id1, grp_id_case)
        self.assertTrue(grp_id1.startswith("GRP-"))
        self.assertEqual(len(grp_id1), 20)

    def test_tier3_group_id_distinguishes_subnets_and_etlds(self):
        grp1 = compute_group_id("192.168.1.0/24")
        grp2 = compute_group_id("10.0.0.0/8")
        self.assertNotEqual(grp1, grp2)

    def test_record_id_deterministic(self):
        art_id = compute_artifact_id(InputModality.DIRECT_URL, "https://example.com")
        tgt_id = compute_target_id("https://example.com")
        rec_id1 = compute_record_id(tgt_id, art_id)
        rec_id2 = compute_record_id(tgt_id, art_id)
        self.assertEqual(rec_id1, rec_id2)
        self.assertTrue(rec_id1.startswith("REC-"))
        self.assertEqual(len(rec_id1), 20)


class TestBenchmarkControlledVocabularies(unittest.TestCase):
    """Test controlled enums and values."""

    def test_modality_values(self):
        valid = {"DIRECT_URL", "QR_IMAGE", "QR_PAYLOAD"}
        actual = {m.value for m in InputModality}
        self.assertEqual(valid, actual)

    def test_primary_outcome_values(self):
        valid = {"BENIGN", "MALICIOUS", "AMBIGUOUS"}
        actual = {p.value for p in PrimaryOutcome}
        self.assertEqual(valid, actual)

    def test_secondary_categories_values(self):
        valid = {
            "CREDENTIAL_PHISHING",
            "BRAND_IMPERSONATION",
            "SCAM_FRAUD",
            "MALWARE_DISTRIBUTION",
            "DRIVE_BY_EXPLOIT",
            "TECH_SUPPORT_FRAUD",
            "QUISHING",
            "OTHER",
        }
        actual = {s.value for s in SecondaryThreatCategory}
        self.assertEqual(valid, actual)

    def test_verification_confidence_is_qualitative_only(self):
        valid = {"HIGH", "MEDIUM", "LOW"}
        actual = {c.value for c in VerificationConfidence}
        self.assertEqual(valid, actual)

    def test_ti_observation_status_values(self):
        valid = {
            "unknown",
            "unavailable",
            "not_checked",
            "negative_observation",
            "positive_observation",
        }
        actual = {t.value for t in TIObservationStatus}
        self.assertEqual(valid, actual)


class TestBenchmarkSerializationAndHashing(unittest.TestCase):
    """Test deterministic canonical serialization and SHA-256 hashing."""

    def _create_sample_record(self) -> BenchmarkRecord:
        art_id = compute_artifact_id(InputModality.DIRECT_URL, "https://example.com/login")
        tgt_id = compute_target_id("https://example.com/login")
        grp_id = compute_group_id("example.com")
        rec_id = compute_record_id(tgt_id, art_id)

        return BenchmarkRecord(
            record_id=rec_id,
            artifact_id=art_id,
            target_id=tgt_id,
            target_url="https://example.com/login",
            modality=InputModality.DIRECT_URL,
            ground_truth=GroundTruth(
                primary_outcome=PrimaryOutcome.MALICIOUS,
                secondary_categories=[
                    SecondaryThreatCategory.CREDENTIAL_PHISHING,
                    SecondaryThreatCategory.BRAND_IMPERSONATION,
                ],
                verification_status=VerificationStatus.VERIFIED,
                verification_method=VerificationMethod.MANUAL_ADJUDICATION.value,
                verification_confidence=VerificationConfidence.HIGH,
                adjudication_status="adjudicated",
                reviewer_count=2,
                verification_timestamp="2026-09-15T12:00:00Z",
                rationale="Verified credential phishing harvesting credentials.",
                supporting_references=["https://phishtank.org/phish_detail.php?phish_id=12345"],
            ),
            provenance=CandidateProvenance(
                source_name="PhishTank",
                source_record_id="12345",
                harvest_timestamp="2026-09-15T10:00:00Z",
                first_observed_timestamp="2026-09-15T09:30:00Z",
            ),
            ti_overlap=TIOverlapMetadata(
                virustotal=TIFeedObservation(
                    feed_name="VirusTotal",
                    status=TIObservationStatus.POSITIVE_OBSERVATION,
                    observed=True,
                    observed_at="2026-09-15T11:00:00Z",
                ),
                google_safebrowsing=TIFeedObservation(
                    feed_name="GoogleSafeBrowsing",
                    status=TIObservationStatus.POSITIVE_OBSERVATION,
                    observed=True,
                ),
                phishtank=TIFeedObservation(
                    feed_name="PhishTank",
                    status=TIObservationStatus.POSITIVE_OBSERVATION,
                    observed=True,
                ),
            ),
            liveness=LivenessMetadata(
                http_status=200,
                dns_resolved=True,
                tls_status="verified",
                response_body_size_bytes=4096,
                resolved_ip="93.184.216.34",
                checked_at="2026-09-15T10:05:00Z",
                eligibility_status="eligible",
            ),
            qr_relationship=QRRelationshipMetadata(
                artifact_type="none",
                relationship_type=QRRelationshipType.NONE,
            ),
            evaluation=EvaluationMetadata(
                group_id=grp_id,
                temporal_partition=TemporalPartition.FINAL_TEST,
                stratum="phishing_direct_url",
                duplicate_status=DuplicateStatus.CANONICAL,
                exclusion_status=ExclusionStatus.RETAINED,
            ),
        )

    def test_canonical_serialization_reproducible(self):
        rec = self._create_sample_record()
        s1 = canonicalize_record(rec)
        s2 = canonicalize_record(rec)
        self.assertEqual(s1, s2)
        self.assertTrue(s1.endswith("\n"))

    def test_canonical_hashing_reproducible(self):
        rec = self._create_sample_record()
        h1 = hash_canonical_record(rec)
        h2 = hash_canonical_record(rec)
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

    def test_dictionary_key_order_independence(self):
        d1 = {"b": 2, "a": 1, "nested": {"z": 26, "y": 25}}
        d2 = {"nested": {"y": 25, "z": 26}, "a": 1, "b": 2}
        self.assertEqual(canonicalize_record_dict(d1), canonicalize_record_dict(d2))

    def test_utf8_encoding_behavior(self):
        d = {"text": "Accented: é, à, ç; Cyrillic: Привет; Chinese: 钓鱼网站; Emoji: 🎣"}
        s = canonicalize_record_dict(d)
        self.assertIn("钓鱼网站", s)
        self.assertIn("🎣", s)
        self.assertEqual(sha256_bytes(s.encode("utf-8")), sha256_bytes(s))


class TestBenchmarkValidation(unittest.TestCase):
    """Test structural validation rules for benchmark records."""

    def _create_valid_record(self) -> BenchmarkRecord:
        art_id = compute_artifact_id(InputModality.DIRECT_URL, "https://example.com")
        tgt_id = compute_target_id("https://example.com")
        grp_id = compute_group_id("example.com")
        rec_id = compute_record_id(tgt_id, art_id)

        return BenchmarkRecord(
            record_id=rec_id,
            artifact_id=art_id,
            target_id=tgt_id,
            target_url="https://example.com",
            modality=InputModality.DIRECT_URL,
            ground_truth=GroundTruth(
                primary_outcome=PrimaryOutcome.BENIGN,
                secondary_categories=[],
                verification_status=VerificationStatus.VERIFIED,
                verification_confidence=VerificationConfidence.HIGH,
            ),
            provenance=CandidateProvenance(source_name="Tranco"),
            ti_overlap=TIOverlapMetadata(),
            liveness=LivenessMetadata(),
            qr_relationship=QRRelationshipMetadata(),
            evaluation=EvaluationMetadata(group_id=grp_id),
        )

    def test_valid_record_passes_validation(self):
        rec = self._create_valid_record()
        errors = validate_benchmark_record(rec)
        self.assertEqual(errors, [])

    def test_invalid_id_format_rejected(self):
        rec = self._create_valid_record()
        bad_rec = BenchmarkRecord(
            record_id="INVALID-ID",
            artifact_id=rec.artifact_id,
            target_id=rec.target_id,
            target_url=rec.target_url,
            modality=rec.modality,
            ground_truth=rec.ground_truth,
            provenance=rec.provenance,
            ti_overlap=rec.ti_overlap,
            liveness=rec.liveness,
            qr_relationship=rec.qr_relationship,
            evaluation=rec.evaluation,
        )
        errors = validate_benchmark_record(bad_rec)
        self.assertTrue(any("Invalid record_id format" in e for e in errors))

    def test_invalid_primary_outcome_rejected(self):
        rec = self._create_valid_record()
        bad_gt = GroundTruth(
            primary_outcome="SUSPICIOUS_CLEAN",  # Not in enum
            verification_confidence=VerificationConfidence.HIGH,
        )
        bad_rec = BenchmarkRecord(
            record_id=rec.record_id,
            artifact_id=rec.artifact_id,
            target_id=rec.target_id,
            target_url=rec.target_url,
            modality=rec.modality,
            ground_truth=bad_gt,
            provenance=rec.provenance,
            ti_overlap=rec.ti_overlap,
            liveness=rec.liveness,
            qr_relationship=rec.qr_relationship,
            evaluation=rec.evaluation,
        )
        errors = validate_benchmark_record(bad_rec)
        self.assertTrue(any("primary_outcome" in e for e in errors))

    def test_numeric_confidence_rejected(self):
        rec = self._create_valid_record()
        bad_gt = GroundTruth(
            primary_outcome=PrimaryOutcome.BENIGN,
            verification_confidence=1.0,  # Numeric float strictly invalid
        )
        bad_rec = BenchmarkRecord(
            record_id=rec.record_id,
            artifact_id=rec.artifact_id,
            target_id=rec.target_id,
            target_url=rec.target_url,
            modality=rec.modality,
            ground_truth=bad_gt,
            provenance=rec.provenance,
            ti_overlap=rec.ti_overlap,
            liveness=rec.liveness,
            qr_relationship=rec.qr_relationship,
            evaluation=rec.evaluation,
        )
        errors = validate_benchmark_record(bad_rec)
        self.assertTrue(any("verification_confidence" in e for e in errors))

    def test_raise_exception_on_invalid_record(self):
        rec = self._create_valid_record()
        bad_rec = BenchmarkRecord(
            record_id="BAD",
            artifact_id="BAD",
            target_id="BAD",
            target_url="",
            modality=rec.modality,
            ground_truth=rec.ground_truth,
            provenance=rec.provenance,
            ti_overlap=rec.ti_overlap,
            liveness=rec.liveness,
            qr_relationship=rec.qr_relationship,
            evaluation=rec.evaluation,
        )
        with self.assertRaises(ValidationError):
            validate_benchmark_record(bad_rec, raise_exception=True)

    def test_qr_modality_consistency(self):
        art_id = compute_artifact_id(InputModality.QR_IMAGE, b"sample_qr_bytes")
        tgt_id = compute_target_id("https://example.com/qr-target")
        grp_id = compute_group_id("example.com")
        rec_id = compute_record_id(tgt_id, art_id)

        # Inconsistent QR record (modality QR_IMAGE but qr_relationship artifact_type is 'none')
        inconsistent_rec = BenchmarkRecord(
            record_id=rec_id,
            artifact_id=art_id,
            target_id=tgt_id,
            target_url="https://example.com/qr-target",
            modality=InputModality.QR_IMAGE,
            ground_truth=GroundTruth(primary_outcome=PrimaryOutcome.MALICIOUS),
            provenance=CandidateProvenance(source_name="QuishingDataset"),
            ti_overlap=TIOverlapMetadata(),
            liveness=LivenessMetadata(),
            qr_relationship=QRRelationshipMetadata(artifact_type="none"),
            evaluation=EvaluationMetadata(group_id=grp_id),
        )
        errors = validate_benchmark_record(inconsistent_rec)
        self.assertTrue(any("qr_relationship.artifact_type is 'none'" in e for e in errors))

        # Consistent QR record
        consistent_rec = BenchmarkRecord(
            record_id=rec_id,
            artifact_id=art_id,
            target_id=tgt_id,
            target_url="https://example.com/qr-target",
            modality=InputModality.QR_IMAGE,
            ground_truth=GroundTruth(primary_outcome=PrimaryOutcome.MALICIOUS),
            provenance=CandidateProvenance(source_name="QuishingDataset"),
            ti_overlap=TIOverlapMetadata(),
            liveness=LivenessMetadata(),
            qr_relationship=QRRelationshipMetadata(
                artifact_type="qr_png_image",
                decoded_payload="https://example.com/qr-target",
                destination_target_id=tgt_id,
                qr_group_id=grp_id,
                relationship_type=QRRelationshipType.DIRECT_PAYLOAD,
            ),
            evaluation=EvaluationMetadata(group_id=grp_id),
        )
        errors_consistent = validate_benchmark_record(consistent_rec)
        self.assertEqual(errors_consistent, [])


class TestBenchmarkIndependence(unittest.TestCase):
    """Test that benchmark schema has zero imports of production analysis engines."""

    def test_no_production_engine_imports(self):
        import tools.benchmark.schemas as benchmark_module
        with open(benchmark_module.__file__, "r", encoding="utf-8") as f:
            code = f.read()

        forbidden_tokens = [
            "trust_calculation_engine",
            "TrustCalculationEngine",
            "confidence_engine",
            "ConfidenceEngine",
            "aere_reasoning_engine",
            "AEREReasoningEngine",
            "aere_grounding_validator",
            "report_generator",
            "ReportGenerator",
            "analysis_pipeline",
            "EvidenceLedger",
            "EvidenceSchema",
        ]
        for token in forbidden_tokens:
            self.assertNotIn(
                token,
                code,
                f"Benchmark schema must not import or couple with production engine: {token}",
            )


class TestBenchmarkManifest(unittest.TestCase):
    """Test minimal BenchmarkManifest structure."""

    def test_manifest_creation(self):
        manifest = BenchmarkManifest(
            benchmark_version="1.0.0",
            methodology_version="1.0.0",
            snapshot_id="SNAP-2026-09-15-01",
            creation_timestamp="2026-09-15T12:00:00Z",
            dataset_hash="a" * 64,
            manifest_hash="b" * 64,
            record_counts={"total": 1200, "retained": 1180, "excluded": 20},
            class_counts={"BENIGN": 600, "MALICIOUS": 580},
            partition_counts={
                "development_calibration": 200,
                "validation": 200,
                "final_test": 600,
                "prospective_holdout": 180,
            },
        )
        self.assertEqual(manifest.snapshot_id, "SNAP-2026-09-15-01")
        self.assertEqual(manifest.record_counts["total"], 1200)


if __name__ == "__main__":
    unittest.main()
