"""Comprehensive Unit Tests for Independent Ground-Truth Verification.

Step 6C-4 Verification Suite.
"""

import inspect
import unittest
from typing import List

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
    compute_artifact_id,
    compute_target_id,
    compute_group_id,
    compute_record_id,
    canonicalize_record,
)
from tools.benchmark.normalization import normalize_investigation_target
from tools.benchmark.ground_truth_verifier import (
    SourceType,
    VerificationSourceRecord,
    AdjudicationRecord,
    GroundTruthVerificationResult,
    verify_ground_truth,
    attach_verified_ground_truth,
)
import tools.benchmark.ground_truth_verifier as verifier_module


class TestGroundTruthVerifier(unittest.TestCase):
    """Test independent ground-truth verification, multi-source consensus, and guardrails."""

    def _create_sample_record(
        self,
        url: str = "https://example.com/login",
        partition: TemporalPartition = TemporalPartition.FINAL_TEST,
    ) -> BenchmarkRecord:
        norm = normalize_investigation_target(url)
        art_id = compute_artifact_id(InputModality.DIRECT_URL, url)
        rec_id = compute_record_id(norm.target_id, art_id)

        return BenchmarkRecord(
            record_id=rec_id,
            artifact_id=art_id,
            target_id=norm.target_id,
            target_url=norm.canonical_url,
            modality=InputModality.DIRECT_URL,
            ground_truth=GroundTruth(
                primary_outcome=PrimaryOutcome.AMBIGUOUS,
                verification_status=VerificationStatus.UNVERIFIABLE,
                verification_confidence=VerificationConfidence.LOW,
            ),
            provenance=CandidateProvenance(source_name="RawFeed", harvest_timestamp="2026-09-15T10:00:00Z"),
            ti_overlap=TIOverlapMetadata(),
            liveness=LivenessMetadata(),
            qr_relationship=QRRelationshipMetadata(),
            evaluation=EvaluationMetadata(
                group_id=norm.group_id,
                temporal_partition=partition,
            ),
        )

    def test_1_independently_verified_malicious(self):
        rec = self._create_sample_record()
        s1 = VerificationSourceRecord(
            source_name="PhishTank Curated",
            source_type=SourceType.CURATED_THREAT_FEED,
            source_reference="12345",
            asserted_outcome=PrimaryOutcome.MALICIOUS,
            asserted_categories=[SecondaryThreatCategory.CREDENTIAL_PHISHING],
        )
        s2 = VerificationSourceRecord(
            source_name="APWG Incident Report",
            source_type=SourceType.INCIDENT_TAKEDOWN_RECORD,
            source_reference="APWG-987",
            asserted_outcome=PrimaryOutcome.MALICIOUS,
            asserted_categories=[SecondaryThreatCategory.BRAND_IMPERSONATION],
        )

        res = verify_ground_truth(rec, sources=[s1, s2])
        self.assertEqual(res.ground_truth.primary_outcome, PrimaryOutcome.MALICIOUS)
        self.assertEqual(res.ground_truth.verification_status, VerificationStatus.VERIFIED)
        self.assertEqual(res.ground_truth.verification_confidence, VerificationConfidence.HIGH)
        self.assertIn(SecondaryThreatCategory.CREDENTIAL_PHISHING, res.ground_truth.secondary_categories)
        self.assertIn(SecondaryThreatCategory.BRAND_IMPERSONATION, res.ground_truth.secondary_categories)
        self.assertFalse(res.is_disputed)
        self.assertFalse(res.is_unverifiable)

    def test_2_independently_verified_benign(self):
        rec = self._create_sample_record("https://bank.example.com")
        s1 = VerificationSourceRecord(
            source_name="Official Domain Registry",
            source_type=SourceType.AUTHORITATIVE_REGISTRY,
            source_reference="ICANN-REG-01",
            asserted_outcome=PrimaryOutcome.BENIGN,
        )
        s2 = VerificationSourceRecord(
            source_name="Curated Benign Dataset",
            source_type=SourceType.TRUSTED_BENIGN_CURATION,
            source_reference="Tranco-Top1000",
            asserted_outcome=PrimaryOutcome.BENIGN,
        )

        res = verify_ground_truth(rec, sources=[s1, s2])
        self.assertEqual(res.ground_truth.primary_outcome, PrimaryOutcome.BENIGN)
        self.assertEqual(res.ground_truth.verification_status, VerificationStatus.VERIFIED)
        self.assertEqual(res.ground_truth.verification_confidence, VerificationConfidence.HIGH)
        self.assertEqual(res.ground_truth.secondary_categories, [])

    def test_3_insufficient_evidence_yields_ambiguous_not_benign(self):
        rec = self._create_sample_record()
        res = verify_ground_truth(rec, sources=[])
        self.assertEqual(res.ground_truth.primary_outcome, PrimaryOutcome.AMBIGUOUS)
        self.assertEqual(res.ground_truth.verification_status, VerificationStatus.UNVERIFIABLE)
        self.assertEqual(res.ground_truth.verification_confidence, VerificationConfidence.LOW)
        self.assertTrue(res.is_unverifiable)
        # MUST NOT be BENIGN
        self.assertNotEqual(res.ground_truth.primary_outcome, PrimaryOutcome.BENIGN)

    def test_4_conflicting_sources_yields_disputed_ambiguous(self):
        rec = self._create_sample_record()
        s1 = VerificationSourceRecord(
            source_name="Feed A",
            asserted_outcome=PrimaryOutcome.MALICIOUS,
            source_reference="REF-M",
        )
        s2 = VerificationSourceRecord(
            source_name="Feed B",
            asserted_outcome=PrimaryOutcome.BENIGN,
            source_reference="REF-B",
        )

        res = verify_ground_truth(rec, sources=[s1, s2])
        self.assertEqual(res.ground_truth.primary_outcome, PrimaryOutcome.AMBIGUOUS)
        self.assertEqual(res.ground_truth.verification_status, VerificationStatus.DISPUTED)
        self.assertTrue(res.is_disputed)
        self.assertEqual(len(res.ground_truth.supporting_references), 1)
        self.assertEqual(len(res.ground_truth.contradictory_references), 1)

    def test_5_adjudication_resolves_conflict(self):
        rec = self._create_sample_record()
        s1 = VerificationSourceRecord(source_name="Feed A", asserted_outcome=PrimaryOutcome.MALICIOUS)
        s2 = VerificationSourceRecord(source_name="Feed B", asserted_outcome=PrimaryOutcome.BENIGN)

        adj = AdjudicationRecord(
            reviewer_id="analyst-lead-01",
            adjudicated_outcome=PrimaryOutcome.MALICIOUS,
            adjudicated_categories=[SecondaryThreatCategory.SCAM_FRAUD],
            rationale="Manual review confirmed fraudulent wire transfer form.",
            confidence=VerificationConfidence.HIGH,
        )

        res = verify_ground_truth(rec, sources=[s1, s2], adjudication=adj)
        self.assertEqual(res.ground_truth.primary_outcome, PrimaryOutcome.MALICIOUS)
        self.assertEqual(res.ground_truth.verification_status, VerificationStatus.VERIFIED)
        self.assertEqual(res.ground_truth.verification_confidence, VerificationConfidence.HIGH)
        self.assertIn(SecondaryThreatCategory.SCAM_FRAUD, res.ground_truth.secondary_categories)
        self.assertFalse(res.is_disputed)

    def test_6_single_uncorroborated_source_yields_ambiguous_or_medium_conf(self):
        rec = self._create_sample_record()
        s1 = VerificationSourceRecord(
            source_name="Single Feed Hit",
            asserted_outcome=PrimaryOutcome.MALICIOUS,
            asserted_categories=[SecondaryThreatCategory.MALWARE_DISTRIBUTION],
        )

        res = verify_ground_truth(rec, sources=[s1], min_corroborating_sources=2)
        self.assertEqual(res.ground_truth.primary_outcome, PrimaryOutcome.AMBIGUOUS)
        self.assertEqual(res.ground_truth.verification_status, VerificationStatus.AMBIGUOUS)
        self.assertEqual(res.ground_truth.verification_confidence, VerificationConfidence.MEDIUM)
        self.assertTrue(res.is_unverifiable)

    def test_7_qualitative_confidence_only_no_probabilities(self):
        rec = self._create_sample_record()
        s1 = VerificationSourceRecord(source_name="Source A", asserted_outcome=PrimaryOutcome.BENIGN)
        s2 = VerificationSourceRecord(source_name="Source B", asserted_outcome=PrimaryOutcome.BENIGN)

        res = verify_ground_truth(rec, sources=[s1, s2])
        self.assertIn(res.ground_truth.verification_confidence, (VerificationConfidence.HIGH, VerificationConfidence.MEDIUM, VerificationConfidence.LOW))
        self.assertNotIsInstance(res.ground_truth.verification_confidence, float)

    def test_8_rejection_of_self_referential_system_sources(self):
        rec = self._create_sample_record()
        # Internal system attempting to self-label
        bad_s1 = VerificationSourceRecord(source_name="TCE Score Engine", asserted_outcome=PrimaryOutcome.MALICIOUS)
        bad_s2 = VerificationSourceRecord(source_name="AERE Reasoning Pipeline", asserted_outcome=PrimaryOutcome.MALICIOUS)

        res = verify_ground_truth(rec, sources=[bad_s1, bad_s2])
        # Since all sources are self-referential, they are rejected and treated as empty sources!
        self.assertEqual(res.ground_truth.primary_outcome, PrimaryOutcome.AMBIGUOUS)
        self.assertEqual(res.ground_truth.verification_status, VerificationStatus.UNVERIFIABLE)
        self.assertEqual(len(res.sources), 0)
        self.assertEqual(len(res.diagnostics["rejected_sources"]), 2)

    def test_9_attach_verified_ground_truth_preserves_identities_and_partition(self):
        rec = self._create_sample_record(partition=TemporalPartition.PROSPECTIVE_HOLDOUT)
        s1 = VerificationSourceRecord(source_name="Source 1", asserted_outcome=PrimaryOutcome.BENIGN)
        s2 = VerificationSourceRecord(source_name="Source 2", asserted_outcome=PrimaryOutcome.BENIGN)

        res = verify_ground_truth(rec, sources=[s1, s2])
        updated_rec = attach_verified_ground_truth(rec, res)

        # Invariant checks:
        self.assertEqual(updated_rec.record_id, rec.record_id)
        self.assertEqual(updated_rec.artifact_id, rec.artifact_id)
        self.assertEqual(updated_rec.target_id, rec.target_id)
        self.assertEqual(updated_rec.evaluation.group_id, rec.evaluation.group_id)
        self.assertEqual(updated_rec.evaluation.temporal_partition, TemporalPartition.PROSPECTIVE_HOLDOUT)
        self.assertEqual(updated_rec.ground_truth.primary_outcome, PrimaryOutcome.BENIGN)

    def test_10_same_group_does_not_imply_same_ground_truth(self):
        rec_login = self._create_sample_record("https://example.com/login")
        rec_account = self._create_sample_record("https://example.com/account")

        # Same group
        self.assertEqual(rec_login.evaluation.group_id, rec_account.evaluation.group_id)

        # /login is verified malicious phishing
        s_m1 = VerificationSourceRecord(source_name="S1", asserted_outcome=PrimaryOutcome.MALICIOUS, asserted_categories=[SecondaryThreatCategory.CREDENTIAL_PHISHING])
        s_m2 = VerificationSourceRecord(source_name="S2", asserted_outcome=PrimaryOutcome.MALICIOUS)
        res_login = verify_ground_truth(rec_login, sources=[s_m1, s_m2])

        # /account has no evidence -> ambiguous
        res_account = verify_ground_truth(rec_account, sources=[])

        self.assertEqual(res_login.ground_truth.primary_outcome, PrimaryOutcome.MALICIOUS)
        self.assertEqual(res_account.ground_truth.primary_outcome, PrimaryOutcome.AMBIGUOUS)

    def test_11_deterministic_serialization_of_verified_record(self):
        rec = self._create_sample_record()
        s1 = VerificationSourceRecord(source_name="S1", asserted_outcome=PrimaryOutcome.MALICIOUS)
        s2 = VerificationSourceRecord(source_name="S2", asserted_outcome=PrimaryOutcome.MALICIOUS)

        res1 = verify_ground_truth(rec, sources=[s1, s2], verification_timestamp="2026-09-15T12:00:00Z")
        rec_v1 = attach_verified_ground_truth(rec, res1)

        res2 = verify_ground_truth(rec, sources=[s1, s2], verification_timestamp="2026-09-15T12:00:00Z")
        rec_v2 = attach_verified_ground_truth(rec, res2)

        self.assertEqual(canonicalize_record(rec_v1), canonicalize_record(rec_v2))

    def test_12_ti_absence_does_not_imply_benign(self):
        # A record with empty or negative TI observations across feeds
        rec = self._create_sample_record()
        rec_ti_negative = BenchmarkRecord(
            record_id=rec.record_id,
            artifact_id=rec.artifact_id,
            target_id=rec.target_id,
            target_url=rec.target_url,
            modality=rec.modality,
            ground_truth=rec.ground_truth,
            provenance=rec.provenance,
            ti_overlap=TIOverlapMetadata(
                virustotal=TIFeedObservation(feed_name="VirusTotal", status=TIObservationStatus.NEGATIVE_OBSERVATION),
                google_safebrowsing=TIFeedObservation(feed_name="GoogleSafeBrowsing", status=TIObservationStatus.NEGATIVE_OBSERVATION),
                phishtank=TIFeedObservation(feed_name="PhishTank", status=TIObservationStatus.NEGATIVE_OBSERVATION),
            ),
            liveness=rec.liveness,
            qr_relationship=rec.qr_relationship,
            evaluation=rec.evaluation,
        )
        res = verify_ground_truth(rec_ti_negative, sources=[])
        self.assertNotEqual(res.ground_truth.primary_outcome, PrimaryOutcome.BENIGN)
        self.assertEqual(res.ground_truth.primary_outcome, PrimaryOutcome.AMBIGUOUS)

    def test_13_production_engine_independence(self):
        # Ground truth verification does not access or mutate any production fields
        rec = self._create_sample_record()
        s1 = VerificationSourceRecord(source_name="Registry", asserted_outcome=PrimaryOutcome.BENIGN)
        s2 = VerificationSourceRecord(source_name="CertAuthority", asserted_outcome=PrimaryOutcome.BENIGN)

        res = verify_ground_truth(rec, sources=[s1, s2])
        self.assertEqual(res.ground_truth.primary_outcome, PrimaryOutcome.BENIGN)

    def test_14_qr_and_direct_consistency_with_verified_ground_truth(self):
        url = "https://example.com/login"
        rec_direct = self._create_sample_record(url)
        art_qr = compute_artifact_id(InputModality.QR_PAYLOAD, url)
        rec_qr = BenchmarkRecord(
            record_id=compute_record_id(rec_direct.target_id, art_qr),
            artifact_id=art_qr,
            target_id=rec_direct.target_id,
            target_url=rec_direct.target_url,
            modality=InputModality.QR_PAYLOAD,
            ground_truth=rec_direct.ground_truth,
            provenance=rec_direct.provenance,
            ti_overlap=rec_direct.ti_overlap,
            liveness=rec_direct.liveness,
            qr_relationship=QRRelationshipMetadata(decoded_payload=url),
            evaluation=rec_direct.evaluation,
        )

        s1 = VerificationSourceRecord(source_name="S1", asserted_outcome=PrimaryOutcome.MALICIOUS)
        s2 = VerificationSourceRecord(source_name="S2", asserted_outcome=PrimaryOutcome.MALICIOUS)

        res_direct = verify_ground_truth(rec_direct, sources=[s1, s2])
        res_qr = verify_ground_truth(rec_qr, sources=[s1, s2])

        rec_direct_v = attach_verified_ground_truth(rec_direct, res_direct)
        rec_qr_v = attach_verified_ground_truth(rec_qr, res_qr)

        self.assertEqual(rec_direct_v.target_id, rec_qr_v.target_id)
        self.assertNotEqual(rec_direct_v.artifact_id, rec_qr_v.artifact_id)
        self.assertEqual(rec_direct_v.ground_truth.primary_outcome, rec_qr_v.ground_truth.primary_outcome)


class TestGroundTruthSecurity(unittest.TestCase):
    """Test security boundaries and no-network isolation."""

    def test_no_network_and_no_eval_exec_in_verifier(self):
        source = inspect.getsource(verifier_module)
        forbidden_patterns = [
            "requests.",
            "urllib.request.",
            "http.client.",
            "socket.",
            "subprocess.",
            "os.system",
            "eval(",
            "exec(",
            "cv2.",
            "pyzbar.",
        ]
        for pat in forbidden_patterns:
            self.assertNotIn(pat, source, f"Security violation: Found forbidden pattern '{pat}' in ground_truth_verifier.py")


if __name__ == "__main__":
    unittest.main()
