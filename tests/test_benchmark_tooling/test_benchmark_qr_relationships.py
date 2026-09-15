"""Comprehensive Unit Tests for QR / Direct URL Relationship Handling.

Step 6C-3 Verification Suite.
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
)
from tools.benchmark.normalization import normalize_investigation_target
from tools.benchmark.qr_relationships import (
    QRTargetResolutionStatus,
    QRDirectRelationType,
    QRPayloadResolution,
    QRDirectRelationship,
    resolve_qr_payload_target,
    analyze_qr_direct_relationship,
    correlate_qr_and_direct_records,
)
import tools.benchmark.qr_relationships as qr_module


class TestQRRelationshipHandling(unittest.TestCase):
    """Test QR resolution and pairwise correlation against direct URLs."""

    def _create_qr_record(
        self,
        payload: str,
        modality: InputModality = InputModality.QR_PAYLOAD,
        partition: TemporalPartition = TemporalPartition.DEVELOPMENT_CALIBRATION,
        outcome: PrimaryOutcome = PrimaryOutcome.MALICIOUS,
    ) -> BenchmarkRecord:
        norm = normalize_investigation_target(payload) if modality == InputModality.QR_PAYLOAD and payload.startswith("http") else None
        art_id = compute_artifact_id(modality, payload or "empty_qr")
        tgt_id = norm.target_id if norm else compute_target_id(payload or "")
        grp_id = norm.group_id if norm else compute_group_id(payload or "")
        rec_id = compute_record_id(tgt_id, art_id)

        return BenchmarkRecord(
            record_id=rec_id,
            artifact_id=art_id,
            target_id=tgt_id,
            target_url=norm.canonical_url if norm else payload,
            modality=modality,
            ground_truth=GroundTruth(
                primary_outcome=outcome,
                secondary_categories=[SecondaryThreatCategory.QUISHING],
                verification_confidence=VerificationConfidence.HIGH,
            ),
            provenance=CandidateProvenance(source_name="SyntheticQRFeed"),
            ti_overlap=TIOverlapMetadata(),
            liveness=LivenessMetadata(),
            qr_relationship=QRRelationshipMetadata(
                artifact_type="qr_png" if modality == InputModality.QR_IMAGE else "qr_string_payload",
                decoded_payload=payload if modality != InputModality.QR_IMAGE else None,
                destination_target_id=tgt_id if norm else None,
                relationship_type=QRRelationshipType.DIRECT_PAYLOAD if norm else QRRelationshipType.NONE,
            ),
            evaluation=EvaluationMetadata(
                group_id=grp_id,
                temporal_partition=partition,
            ),
        )

    def _create_direct_record(
        self,
        url: str,
        partition: TemporalPartition = TemporalPartition.DEVELOPMENT_CALIBRATION,
        outcome: PrimaryOutcome = PrimaryOutcome.MALICIOUS,
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
                primary_outcome=outcome,
                secondary_categories=[SecondaryThreatCategory.CREDENTIAL_PHISHING],
                verification_confidence=VerificationConfidence.HIGH,
            ),
            provenance=CandidateProvenance(source_name="SyntheticDirectFeed"),
            ti_overlap=TIOverlapMetadata(),
            liveness=LivenessMetadata(),
            qr_relationship=QRRelationshipMetadata(),
            evaluation=EvaluationMetadata(
                group_id=norm.group_id,
                temporal_partition=partition,
            ),
        )

    def test_basic_qr_payload_resolution_http_target(self):
        qr_rec = self._create_qr_record("https://example.com/login")
        res = resolve_qr_payload_target(qr_rec)
        self.assertEqual(res.resolution_status, QRTargetResolutionStatus.RESOLVED_HTTP_TARGET)
        self.assertTrue(res.is_http_url)
        self.assertEqual(res.target_url, "https://example.com/login")
        self.assertTrue(res.resolved_target_id.startswith("TGT-"))
        self.assertTrue(res.resolved_group_id.startswith("GRP-"))

    def test_same_target_different_artifact_qr_and_direct(self):
        qr_rec = self._create_qr_record("https://example.com/login")
        direct_rec = self._create_direct_record("https://example.com/login")

        # Invariant 1: Modality preserved
        self.assertEqual(qr_rec.modality, InputModality.QR_PAYLOAD)
        self.assertEqual(direct_rec.modality, InputModality.DIRECT_URL)

        # Invariant 2: Different artifact IDs
        self.assertNotEqual(qr_rec.artifact_id, direct_rec.artifact_id)

        # Invariant 3: Identical target ID
        self.assertEqual(qr_rec.target_id, direct_rec.target_id)

        rel = analyze_qr_direct_relationship(qr_rec, direct_rec)
        self.assertEqual(rel.relationship_type, QRDirectRelationType.QR_DIRECT_SAME_TARGET)
        self.assertTrue(rel.same_target)
        self.assertTrue(rel.same_group)
        self.assertFalse(rel.same_artifact)
        self.assertEqual(rel.reason_code, "SAME_NORMALIZED_TARGET")

    def test_different_paths_same_group_qr_and_direct(self):
        qr_rec = self._create_qr_record("https://example.com/login")
        direct_rec = self._create_direct_record("https://example.com/account")

        rel = analyze_qr_direct_relationship(qr_rec, direct_rec)
        self.assertEqual(rel.relationship_type, QRDirectRelationType.QR_DIRECT_SAME_GROUP)
        self.assertFalse(rel.same_target)
        self.assertTrue(rel.same_group)
        self.assertFalse(rel.same_artifact)
        self.assertEqual(rel.reason_code, "SAME_GROUP_DIFFERENT_TARGET")

    def test_different_domains_qr_and_direct(self):
        qr_rec = self._create_qr_record("https://example.com/login")
        direct_rec = self._create_direct_record("https://otherdomain.org/index.html")

        rel = analyze_qr_direct_relationship(qr_rec, direct_rec)
        self.assertEqual(rel.relationship_type, QRDirectRelationType.QR_DIRECT_DIFFERENT_TARGET)
        self.assertFalse(rel.same_target)
        self.assertFalse(rel.same_group)

    def test_unresolved_qr_image(self):
        qr_img_rec = self._create_qr_record("", modality=InputModality.QR_IMAGE)
        res = resolve_qr_payload_target(qr_img_rec)
        self.assertEqual(res.resolution_status, QRTargetResolutionStatus.UNRESOLVED_IMAGE)
        self.assertIsNone(res.resolved_target_id)

        direct_rec = self._create_direct_record("https://example.com/login")
        rel = analyze_qr_direct_relationship(qr_img_rec, direct_rec)
        self.assertEqual(rel.relationship_type, QRDirectRelationType.QR_IMAGE_UNRESOLVED)
        self.assertFalse(rel.same_target)

    def test_non_url_qr_payloads(self):
        payloads = [
            "SMSTO:123456789:Send funds immediately",
            "mailto:victim@example.com?subject=Help",
            "WIFI:T:WPA;S:MaliciousAP;P:Secret123;;",
            "intent://scan/#Intent;scheme=zxing;package=com.google.zxing.client.android;end",
            "Just a plain text message inside a QR code",
        ]
        for p in payloads:
            qr_rec = self._create_qr_record(p)
            res = resolve_qr_payload_target(qr_rec)
            self.assertEqual(res.resolution_status, QRTargetResolutionStatus.NON_URL_PAYLOAD)
            self.assertFalse(res.is_http_url)
            self.assertIsNone(res.resolved_target_id)

            direct_rec = self._create_direct_record("https://example.com/login")
            rel = analyze_qr_direct_relationship(qr_rec, direct_rec)
            self.assertEqual(rel.relationship_type, QRDirectRelationType.QR_NON_URL_PAYLOAD)
            self.assertFalse(rel.same_target)

    def test_cross_partition_qr_direct_leakage(self):
        qr_calib = self._create_qr_record(
            "https://example.com/login",
            partition=TemporalPartition.DEVELOPMENT_CALIBRATION,
        )
        direct_test = self._create_direct_record(
            "https://example.com/login",
            partition=TemporalPartition.FINAL_TEST,
        )
        rel = analyze_qr_direct_relationship(qr_calib, direct_test)
        self.assertTrue(rel.is_cross_split_leakage)
        self.assertTrue(rel.same_target)

    def test_correlate_dataset_qr_and_direct(self):
        qr1 = self._create_qr_record("https://example.com/login")
        qr2 = self._create_qr_record("SMSTO:12345:Hi")
        d1 = self._create_direct_record("https://example.com/login")
        d2 = self._create_direct_record("https://other.com/page")

        rels = correlate_qr_and_direct_records([qr1, qr2, d1, d2])
        # 2 QR records * 2 Direct records = 4 relationships
        self.assertEqual(len(rels), 4)

        same_tgt_rels = [r for r in rels if r.same_target]
        self.assertEqual(len(same_tgt_rels), 1)
        self.assertEqual(same_tgt_rels[0].qr_record_id, qr1.record_id)
        self.assertEqual(same_tgt_rels[0].direct_record_id, d1.record_id)


    def test_qr_and_direct_port_and_query_and_fragment_consistency(self):
        # Query parameter sorted consistency
        qr_q = self._create_qr_record("https://example.com/login?b=2&a=1")
        dir_q = self._create_direct_record("https://example.com/login?a=1&b=2")
        rel_q = analyze_qr_direct_relationship(qr_q, dir_q)
        self.assertEqual(rel_q.relationship_type, QRDirectRelationType.QR_DIRECT_SAME_TARGET)
        self.assertTrue(rel_q.same_target)

        # Fragment consistency
        qr_frag = self._create_qr_record("https://example.com/login#section")
        dir_plain = self._create_direct_record("https://example.com/login")
        rel_frag = analyze_qr_direct_relationship(qr_frag, dir_plain)
        self.assertEqual(rel_frag.relationship_type, QRDirectRelationType.QR_DIRECT_SAME_TARGET)
        self.assertTrue(rel_frag.same_target)

        # Custom port consistency
        qr_port = self._create_qr_record("https://example.com:8443/login")
        dir_std = self._create_direct_record("https://example.com/login")
        rel_port = analyze_qr_direct_relationship(qr_port, dir_std)
        self.assertEqual(rel_port.relationship_type, QRDirectRelationType.QR_DIRECT_SAME_GROUP)
        self.assertFalse(rel_port.same_target)
        self.assertTrue(rel_port.same_group)

    def test_ti_metadata_does_not_affect_qr_relationship(self):
        qr_rec = self._create_qr_record("https://example.com/login")
        dir_rec = self._create_direct_record("https://example.com/login")

        # Mutate TI metadata
        ti_obs = TIOverlapMetadata(
            virustotal=TIFeedObservation(
                feed_name="VirusTotal",
                status=TIObservationStatus.POSITIVE_OBSERVATION,
                observed=True,
            )
        )
        qr_rec_ti = BenchmarkRecord(
            record_id=qr_rec.record_id,
            artifact_id=qr_rec.artifact_id,
            target_id=qr_rec.target_id,
            target_url=qr_rec.target_url,
            modality=qr_rec.modality,
            ground_truth=qr_rec.ground_truth,
            provenance=qr_rec.provenance,
            ti_overlap=ti_obs,
            liveness=qr_rec.liveness,
            qr_relationship=qr_rec.qr_relationship,
            evaluation=qr_rec.evaluation,
        )

        rel = analyze_qr_direct_relationship(qr_rec_ti, dir_rec)
        self.assertEqual(rel.relationship_type, QRDirectRelationType.QR_DIRECT_SAME_TARGET)
        self.assertTrue(rel.same_target)


class TestQRIndependenceAndSecurity(unittest.TestCase):
    """Test ground-truth independence, TI independence, and security rules."""

    def test_ground_truth_change_does_not_affect_relationship(self):
        qr_a = self._create_test_record("https://example.com/login", PrimaryOutcome.BENIGN)
        qr_b = self._create_test_record("https://example.com/login", PrimaryOutcome.MALICIOUS)
        direct = self._create_test_record("https://example.com/login", PrimaryOutcome.AMBIGUOUS, is_direct=True)

        rel_a = analyze_qr_direct_relationship(qr_a, direct)
        rel_b = analyze_qr_direct_relationship(qr_b, direct)

        self.assertEqual(rel_a.relationship_type, rel_b.relationship_type)
        self.assertEqual(rel_a.same_target, rel_b.same_target)
        self.assertEqual(rel_a.same_group, rel_b.same_group)

    def _create_test_record(self, url: str, outcome: PrimaryOutcome, is_direct: bool = False) -> BenchmarkRecord:
        modality = InputModality.DIRECT_URL if is_direct else InputModality.QR_PAYLOAD
        norm = normalize_investigation_target(url)
        art_id = compute_artifact_id(modality, url)
        rec_id = compute_record_id(norm.target_id, art_id)

        return BenchmarkRecord(
            record_id=rec_id,
            artifact_id=art_id,
            target_id=norm.target_id,
            target_url=norm.canonical_url,
            modality=modality,
            ground_truth=GroundTruth(primary_outcome=outcome),
            provenance=CandidateProvenance(source_name="TestFeed"),
            ti_overlap=TIOverlapMetadata(),
            liveness=LivenessMetadata(),
            qr_relationship=QRRelationshipMetadata(decoded_payload=url if not is_direct else None),
            evaluation=EvaluationMetadata(group_id=norm.group_id),
        )

    def test_no_network_and_no_eval_exec_in_qr_module(self):
        source = inspect.getsource(qr_module)
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
            self.assertNotIn(pat, source, f"Security violation: Found forbidden pattern '{pat}' in qr_relationships.py")


if __name__ == "__main__":
    unittest.main()
