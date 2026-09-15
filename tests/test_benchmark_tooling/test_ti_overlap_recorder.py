"""Comprehensive Unit Tests for Threat Intelligence (TI) Overlap Metadata Recording.

Step 6C-5 Verification Suite.
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
    CandidateProvenance,
    GroundTruth,
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
from tools.benchmark.ti_overlap_recorder import (
    TIFeed,
    TIObservationType,
    TIFeedObservationRecord,
    TIExposureSummary,
    TIOverlapRecord,
    validate_iso8601_timestamp,
    record_ti_observation,
    build_ti_overlap_metadata,
    attach_ti_overlap,
)
import tools.benchmark.ti_overlap_recorder as ti_module


class TestTIOverlapRecorder(unittest.TestCase):
    """Test TI overlap recording, feed validations, temporal metadata, and guardrails."""

    def _create_sample_record(
        self,
        url: str = "https://example.com/login",
        partition: TemporalPartition = TemporalPartition.FINAL_TEST,
        outcome: PrimaryOutcome = PrimaryOutcome.AMBIGUOUS,
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
                verification_status=VerificationStatus.UNVERIFIABLE,
                verification_confidence=VerificationConfidence.LOW,
            ),
            provenance=CandidateProvenance(source_name="RawCandidateFeed"),
            ti_overlap=TIOverlapMetadata(),
            liveness=LivenessMetadata(),
            qr_relationship=QRRelationshipMetadata(),
            evaluation=EvaluationMetadata(
                group_id=norm.group_id,
                temporal_partition=partition,
            ),
        )

    def test_1_seven_feeds_supported(self):
        expected_feeds = {
            "VirusTotal",
            "GoogleSafeBrowsing",
            "PhishTank",
            "OpenPhish",
            "URLhaus",
            "AbuseIPDB",
            "Spamhaus",
        }
        actual_feeds = {f.value for f in TIFeed}
        self.assertEqual(expected_feeds, actual_feeds)

    def test_2_direct_observation_preserves_provenance_and_metadata(self):
        obs = record_ti_observation(
            target_id="TGT-1234567890abcdef",
            feed=TIFeed.VIRUSTOTAL,
            status=TIObservationType.DIRECT,
            first_feed_seen_at="2026-01-10T12:00:00Z",
            observation_time="2026-09-15T10:00:00Z",
            retrieved_at="2026-09-15T10:05:00Z",
            source_reference="VT-REPORT-9999",
            provenance_notes="High confidence positive threat detection.",
        )
        self.assertEqual(obs.feed_name, TIFeed.VIRUSTOTAL)
        self.assertEqual(obs.status, TIObservationType.DIRECT)
        self.assertEqual(obs.first_feed_seen_at, "2026-01-10T12:00:00Z")
        self.assertEqual(obs.observation_time, "2026-09-15T10:00:00Z")
        self.assertEqual(obs.retrieved_at, "2026-09-15T10:05:00Z")
        self.assertEqual(obs.source_reference, "VT-REPORT-9999")

    def test_3_none_status_semantics(self):
        obs = record_ti_observation(
            target_id="TGT-1234567890abcdef",
            feed=TIFeed.OPENPHISH,
            status=TIObservationType.NONE,
            observation_time="2026-09-15T10:00:00Z",
        )
        self.assertEqual(obs.status, TIObservationType.NONE)
        # NONE should not require a source_reference
        self.assertIsNone(obs.source_reference)

    def test_4_unknown_status_preserved(self):
        obs = record_ti_observation(
            target_id="TGT-1234567890abcdef",
            feed=TIFeed.URLHAUS,
            status=TIObservationType.UNKNOWN_UNAVAILABLE,
            provenance_notes="Feed API timed out or was not queried.",
        )
        self.assertEqual(obs.status, TIObservationType.UNKNOWN_UNAVAILABLE)

    def test_5_partial_status_distinct_from_direct(self):
        obs_dir = record_ti_observation(
            target_id="TGT-1234567890abcdef",
            feed=TIFeed.ABUSEIPDB,
            status=TIObservationType.DIRECT,
            source_reference="IP-REPORT-1",
        )
        obs_part = record_ti_observation(
            target_id="TGT-1234567890abcdef",
            feed=TIFeed.ABUSEIPDB,
            status=TIObservationType.PARTIAL,
            provenance_notes="Subnet flagged but not exact host",
        )
        self.assertNotEqual(obs_dir.status, obs_part.status)

    def test_6_first_feed_seen_at_preserved(self):
        ts = "2025-11-20T08:30:00Z"
        obs = record_ti_observation(
            target_id="TGT-1234567890abcdef",
            feed=TIFeed.PHISHTANK,
            status=TIObservationType.DIRECT,
            first_feed_seen_at=ts,
            source_reference="PT-123",
        )
        self.assertEqual(obs.first_feed_seen_at, ts)

    def test_7_observation_timestamp_preserved(self):
        ts = "2026-09-15T14:22:10Z"
        obs = record_ti_observation(
            target_id="TGT-1234567890abcdef",
            feed=TIFeed.SPAMHAUS,
            status=TIObservationType.NONE,
            observation_time=ts,
        )
        self.assertEqual(obs.observation_time, ts)

    def test_8_retrieval_timestamp_preserved(self):
        ts = "2026-09-15T14:25:00Z"
        obs = record_ti_observation(
            target_id="TGT-1234567890abcdef",
            feed=TIFeed.GOOGLE_SAFE_BROWSING,
            status=TIObservationType.NONE,
            retrieved_at=ts,
        )
        self.assertEqual(obs.retrieved_at, ts)

    def test_9_multiple_feeds_aggregated_in_container(self):
        tgt_id = "TGT-1234567890abcdef"
        obs_vt = record_ti_observation(tgt_id, TIFeed.VIRUSTOTAL, TIObservationType.DIRECT, source_reference="VT-1", first_feed_seen_at="2026-01-01T00:00:00Z")
        obs_op = record_ti_observation(tgt_id, TIFeed.OPENPHISH, TIObservationType.NONE)
        obs_uh = record_ti_observation(tgt_id, TIFeed.URLHAUS, TIObservationType.UNKNOWN_UNAVAILABLE)

        ti_record = build_ti_overlap_metadata(tgt_id, [obs_vt, obs_op, obs_uh])
        self.assertEqual(len(ti_record.observations), 3)
        self.assertTrue(ti_record.exposure.has_any_direct_positive)
        self.assertEqual(ti_record.exposure.feed_count_positive, 1)
        self.assertIn("VirusTotal", ti_record.exposure.feeds_observed_positive)
        self.assertIn("OpenPhish", ti_record.exposure.feeds_observed_negative)
        self.assertIn("URLhaus", ti_record.exposure.feeds_unavailable)
        self.assertEqual(ti_record.exposure.earliest_first_feed_seen_at, "2026-01-01T00:00:00Z")

    def test_10_same_target_qr_and_direct_url_consistency(self):
        url = "https://example.com/login"
        rec_dir = self._create_sample_record(url)
        art_qr = compute_artifact_id(InputModality.QR_PAYLOAD, url)
        rec_qr = BenchmarkRecord(
            record_id=compute_record_id(rec_dir.target_id, art_qr),
            artifact_id=art_qr,
            target_id=rec_dir.target_id,
            target_url=rec_dir.target_url,
            modality=InputModality.QR_PAYLOAD,
            ground_truth=rec_dir.ground_truth,
            provenance=rec_dir.provenance,
            ti_overlap=rec_dir.ti_overlap,
            liveness=rec_dir.liveness,
            qr_relationship=QRRelationshipMetadata(decoded_payload=url),
            evaluation=rec_dir.evaluation,
        )

        obs = record_ti_observation(rec_dir.target_id, TIFeed.VIRUSTOTAL, TIObservationType.DIRECT, source_reference="VT-123")
        ti_meta = build_ti_overlap_metadata(rec_dir.target_id, [obs])

        rec_dir_attached = attach_ti_overlap(rec_dir, ti_meta)
        rec_qr_attached = attach_ti_overlap(rec_qr, ti_meta)

        self.assertEqual(rec_dir_attached.target_id, rec_qr_attached.target_id)
        self.assertNotEqual(rec_dir_attached.artifact_id, rec_qr_attached.artifact_id)
        self.assertEqual(rec_dir_attached.ti_overlap.virustotal.status, TIObservationStatus.POSITIVE_OBSERVATION)
        self.assertEqual(rec_qr_attached.ti_overlap.virustotal.status, TIObservationStatus.POSITIVE_OBSERVATION)

    def test_11_distinct_functional_urls_retain_distinct_ti_metadata(self):
        rec_login = self._create_sample_record("https://example.com/login")
        rec_account = self._create_sample_record("https://example.com/account")
        self.assertNotEqual(rec_login.target_id, rec_account.target_id)

        obs_login = record_ti_observation(rec_login.target_id, TIFeed.VIRUSTOTAL, TIObservationType.DIRECT, source_reference="VT-LOGIN")
        obs_account = record_ti_observation(rec_account.target_id, TIFeed.VIRUSTOTAL, TIObservationType.NONE)

        ti_login = build_ti_overlap_metadata(rec_login.target_id, [obs_login])
        ti_account = build_ti_overlap_metadata(rec_account.target_id, [obs_account])

        rec_login_v = attach_ti_overlap(rec_login, ti_login)
        rec_account_v = attach_ti_overlap(rec_account, ti_account)

        self.assertEqual(rec_login_v.ti_overlap.virustotal.status, TIObservationStatus.POSITIVE_OBSERVATION)
        self.assertEqual(rec_account_v.ti_overlap.virustotal.status, TIObservationStatus.NEGATIVE_OBSERVATION)

    def test_12_ti_absence_does_not_change_ground_truth(self):
        rec = self._create_sample_record(outcome=PrimaryOutcome.AMBIGUOUS)
        obs = [
            record_ti_observation(rec.target_id, feed, TIObservationType.NONE)
            for feed in TIFeed
        ]
        ti_meta = build_ti_overlap_metadata(rec.target_id, obs)
        rec_attached = attach_ti_overlap(rec, ti_meta)

        # Ground truth must remain AMBIGUOUS, never mutated to BENIGN!
        self.assertEqual(rec_attached.ground_truth.primary_outcome, PrimaryOutcome.AMBIGUOUS)
        self.assertNotEqual(rec_attached.ground_truth.primary_outcome, PrimaryOutcome.BENIGN)

    def test_13_ti_presence_does_not_automatically_set_ground_truth(self):
        rec = self._create_sample_record(outcome=PrimaryOutcome.AMBIGUOUS)
        obs_vt = record_ti_observation(rec.target_id, TIFeed.VIRUSTOTAL, TIObservationType.DIRECT, source_reference="VT-HIT")
        ti_meta = build_ti_overlap_metadata(rec.target_id, [obs_vt])
        rec_attached = attach_ti_overlap(rec, ti_meta)

        # Ground truth remains untouched (AMBIGUOUS)
        self.assertEqual(rec_attached.ground_truth.primary_outcome, PrimaryOutcome.AMBIGUOUS)

    def test_14_system_output_independence(self):
        rec = self._create_sample_record()
        obs = record_ti_observation(rec.target_id, TIFeed.PHISHTANK, TIObservationType.DIRECT, source_reference="PT-1")
        ti_meta = build_ti_overlap_metadata(rec.target_id, [obs])
        rec_attached = attach_ti_overlap(rec, ti_meta)
        self.assertEqual(rec_attached.ti_overlap.phishtank.observed, True)

    def test_15_ground_truth_independence(self):
        # Changing ground truth does not alter TI observations
        rec_mal = self._create_sample_record(outcome=PrimaryOutcome.MALICIOUS)
        rec_ben = self._create_sample_record(outcome=PrimaryOutcome.BENIGN)
        obs = record_ti_observation(rec_mal.target_id, TIFeed.OPENPHISH, TIObservationType.DIRECT, source_reference="OP-1")
        ti_meta = build_ti_overlap_metadata(rec_mal.target_id, [obs])

        rec_mal_att = attach_ti_overlap(rec_mal, ti_meta)
        rec_ben_att = attach_ti_overlap(rec_ben, ti_meta)

        self.assertEqual(rec_mal_att.ti_overlap.openphish.status, rec_ben_att.ti_overlap.openphish.status)

    def test_16_partition_preservation(self):
        rec = self._create_sample_record(partition=TemporalPartition.PROSPECTIVE_HOLDOUT)
        obs = record_ti_observation(rec.target_id, TIFeed.VIRUSTOTAL, TIObservationType.DIRECT, source_reference="VT-1")
        ti_meta = build_ti_overlap_metadata(rec.target_id, [obs])
        rec_attached = attach_ti_overlap(rec, ti_meta)
        self.assertEqual(rec_attached.evaluation.temporal_partition, TemporalPartition.PROSPECTIVE_HOLDOUT)

    def test_17_temporal_exposure_comparison(self):
        tgt_id = "TGT-1234567890abcdef"
        obs1 = record_ti_observation(tgt_id, TIFeed.VIRUSTOTAL, TIObservationType.DIRECT, first_feed_seen_at="2026-01-01T00:00:00Z", source_reference="VT-1")
        obs2 = record_ti_observation(tgt_id, TIFeed.PHISHTANK, TIObservationType.DIRECT, first_feed_seen_at="2025-12-01T00:00:00Z", source_reference="PT-1")

        ti_meta = build_ti_overlap_metadata(tgt_id, [obs1, obs2])
        self.assertEqual(ti_meta.exposure.earliest_first_feed_seen_at, "2025-12-01T00:00:00Z")

    def test_18_no_zero_day_claim(self):
        # TI overlap record exposes objective metadata without fabricating zero_day=true
        tgt_id = "TGT-1234567890abcdef"
        obs = [record_ti_observation(tgt_id, feed, TIObservationType.NONE) for feed in TIFeed]
        ti_meta = build_ti_overlap_metadata(tgt_id, obs)
        self.assertFalse(hasattr(ti_meta.exposure, "zero_day"))
        self.assertEqual(ti_meta.exposure.feed_count_positive, 0)

    def test_19_malformed_feed_name_rejected(self):
        with self.assertRaises(ValueError):
            record_ti_observation("TGT-123", "NonExistentFeed", TIObservationType.NONE)

    def test_20_malformed_status_rejected(self):
        with self.assertRaises(ValueError):
            record_ti_observation("TGT-123", TIFeed.VIRUSTOTAL, "INVALID_STATUS")

    def test_21_malformed_timestamp_rejected(self):
        with self.assertRaises(ValueError):
            record_ti_observation("TGT-123", TIFeed.VIRUSTOTAL, TIObservationType.NONE, observation_time="INVALID-TIMESTAMP")

    def test_22_missing_provenance_for_direct_status_rejected(self):
        # DIRECT status without source_reference or metadata should fail
        with self.assertRaises(ValueError):
            record_ti_observation("TGT-123", TIFeed.VIRUSTOTAL, TIObservationType.DIRECT)

    def test_23_deterministic_serialization(self):
        rec = self._create_sample_record()
        obs = record_ti_observation(
            rec.target_id,
            TIFeed.VIRUSTOTAL,
            TIObservationType.DIRECT,
            source_reference="VT-123",
            observation_time="2026-09-15T12:00:00Z",
            first_feed_seen_at="2026-01-01T00:00:00Z",
        )
        ti_meta = build_ti_overlap_metadata(rec.target_id, [obs])
        rec1 = attach_ti_overlap(rec, ti_meta)
        rec2 = attach_ti_overlap(rec, ti_meta)

        self.assertEqual(canonicalize_record(rec1), canonicalize_record(rec2))

    def test_24_no_network_in_ti_recorder(self):
        source = inspect.getsource(ti_module)
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
            self.assertNotIn(pat, source, f"Security violation: Found forbidden pattern '{pat}' in ti_overlap_recorder.py")


if __name__ == "__main__":
    unittest.main()
