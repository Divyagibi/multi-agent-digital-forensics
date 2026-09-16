"""Comprehensive Unit Tests for Independent Ground-Truth Verification.

Step 6D-4: Independent Ground-Truth Verification Test Suite.

Covers all 38 required test scenarios:
1. Two independent BENIGN sources agree -> VERIFIED / HIGH
2. Two independent MALICIOUS sources agree -> VERIFIED / HIGH
3. Conflicting BENIGN and MALICIOUS sources -> DISPUTED / AMBIGUOUS
4. One source only -> does not automatically receive unjustified HIGH confidence
5. Duplicate source records -> not counted as independent evidence
6. Mirrored/duplicated source -> not treated as independent
7. Internal TCE source -> rejected
8. Internal AERE source -> rejected
9. Internal Confidence Engine source -> rejected
10. Internal report source -> rejected
11. Internal agent output -> rejected
12. TI presence alone -> does not automatically become malicious ground truth
13. TI absence -> does not become benign
14. No-source case -> ambiguous/unverified, not benign
15. Conflicting sources retain both claims
16. Analyst adjudication resolves dispute only through explicit adjudication metadata
17. Adjudication rationale preserved
18. Missing timestamps do not get fabricated
19. Temporal metadata preserved
20. QR artifact remains distinct from target
21. QR payload remains distinct from direct URL artifact
22. Non-HTTP QR payload does not automatically become malicious
23. QUISHING category preserved where independently supported
24. Natural class prevalence is preserved
25. No synthetic labels
26. No duplicate records created
27. Deterministic consensus behavior
28. Deterministic diagnostics ordering
29. Schema compatibility with BenchmarkRecord
30. Ground-truth fields are clearly separate from liveness metadata
31. Verification confidence remains qualitative
32. No probability/confidence score generated
33. Final test/prospective holdout labels cannot be influenced by system output
34. Malformed source metadata handled safely
35. Unsupported source type handled safely
36. Internal-source detection is case-insensitive / normalized where appropriate
37. Source independence rules are deterministic and documented
38. Analyst adjudication cannot silently occur without an explicit record
"""

import inspect
import sys
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
from tools.benchmark.harvester import (
    RawCandidate,
    SourceType as HarvesterSourceType,
    compute_candidate_id,
)
from tools.benchmark.normalization import normalize_investigation_target
from tools.benchmark.ground_truth_verifier import (
    SourceType,
    VerificationSourceRecord,
    AdjudicationRecord,
    GroundTruthVerificationResult,
    verify_ground_truth,
    verify_candidate_ground_truth,
    attach_verified_ground_truth,
    is_forbidden_system_source,
)
import tools.benchmark.ground_truth_verifier as verifier_module


class TestGroundTruthVerifierComprehensive(unittest.TestCase):
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
            liveness=LivenessMetadata(http_status=200, response_body_size_bytes=500, eligibility_status="eligible"),
            qr_relationship=QRRelationshipMetadata(),
            evaluation=EvaluationMetadata(
                group_id=norm.group_id,
                temporal_partition=partition,
            ),
        )

    def _create_sample_candidate(
        self,
        raw_content: str = "https://example.com/login",
        modality: InputModality = InputModality.DIRECT_URL,
    ) -> RawCandidate:
        cid = compute_candidate_id("TestSource", raw_content, "REC-01")
        aid = compute_artifact_id(modality, raw_content)
        return RawCandidate(
            candidate_id=cid,
            raw_content=raw_content,
            modality=modality,
            source_name="TestSource",
            source_type=HarvesterSourceType.CURATED_LIST,
            source_record_id="REC-01",
            artifact_id=aid,
        )

    # 1. Two independent BENIGN sources agree -> VERIFIED / HIGH
    def test_01_two_independent_benign_sources_agree(self):
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

    # 2. Two independent MALICIOUS sources agree -> VERIFIED / HIGH
    def test_02_two_independent_malicious_sources_agree(self):
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

    # 3. Conflicting BENIGN and MALICIOUS sources -> DISPUTED / AMBIGUOUS
    def test_03_conflicting_benign_and_malicious_sources(self):
        rec = self._create_sample_record()
        s1 = VerificationSourceRecord(source_name="Feed A", asserted_outcome=PrimaryOutcome.MALICIOUS)
        s2 = VerificationSourceRecord(source_name="Feed B", asserted_outcome=PrimaryOutcome.BENIGN)
        res = verify_ground_truth(rec, sources=[s1, s2])
        self.assertEqual(res.ground_truth.primary_outcome, PrimaryOutcome.AMBIGUOUS)
        self.assertEqual(res.ground_truth.verification_status, VerificationStatus.DISPUTED)
        self.assertTrue(res.is_disputed)

    # 4. One source only -> does not receive HIGH confidence (MEDIUM)
    def test_04_single_source_only(self):
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

    # 5. Duplicate source records -> not counted as independent evidence
    def test_05_duplicate_source_records_not_independent(self):
        rec = self._create_sample_record()
        s1 = VerificationSourceRecord(source_name="PhishFeed", asserted_outcome=PrimaryOutcome.MALICIOUS, source_reference="101")
        s2 = VerificationSourceRecord(source_name="PhishFeed", asserted_outcome=PrimaryOutcome.MALICIOUS, source_reference="101")
        res = verify_ground_truth(rec, sources=[s1, s2], min_corroborating_sources=2)
        # Duplicate source entries from same source_name collapse to 1 independent source
        self.assertEqual(res.ground_truth.primary_outcome, PrimaryOutcome.AMBIGUOUS)
        self.assertEqual(res.ground_truth.verification_confidence, VerificationConfidence.MEDIUM)

    # 6. Mirrored/duplicated source -> not treated as independent
    def test_06_mirrored_source_case_insensitive(self):
        rec = self._create_sample_record()
        s1 = VerificationSourceRecord(source_name="PhishFeed", asserted_outcome=PrimaryOutcome.MALICIOUS)
        s2 = VerificationSourceRecord(source_name="phishfeed", asserted_outcome=PrimaryOutcome.MALICIOUS)
        res = verify_ground_truth(rec, sources=[s1, s2], min_corroborating_sources=2)
        self.assertEqual(res.ground_truth.primary_outcome, PrimaryOutcome.AMBIGUOUS)

    # 7. Internal TCE source -> rejected
    def test_07_internal_tce_source_rejected(self):
        rec = self._create_sample_record()
        s_bad = VerificationSourceRecord(source_name="TCE Score Engine", asserted_outcome=PrimaryOutcome.MALICIOUS)
        res = verify_ground_truth(rec, sources=[s_bad])
        self.assertEqual(res.ground_truth.primary_outcome, PrimaryOutcome.AMBIGUOUS)
        self.assertEqual(res.ground_truth.verification_status, VerificationStatus.UNVERIFIABLE)
        self.assertEqual(len(res.sources), 0)
        self.assertEqual(res.diagnostics["diagnostic_code"], "INTERNAL_SYSTEM_SOURCE_REJECTED")

    # 8. Internal AERE source -> rejected
    def test_08_internal_aere_source_rejected(self):
        rec = self._create_sample_record()
        s_bad = VerificationSourceRecord(source_name="AERE Reasoning Pipeline", asserted_outcome=PrimaryOutcome.MALICIOUS)
        res = verify_ground_truth(rec, sources=[s_bad])
        self.assertEqual(res.ground_truth.primary_outcome, PrimaryOutcome.AMBIGUOUS)
        self.assertEqual(len(res.sources), 0)

    # 9. Internal Confidence Engine source -> rejected
    def test_09_internal_confidence_engine_rejected(self):
        rec = self._create_sample_record()
        s_bad = VerificationSourceRecord(source_name="confidence_engine", asserted_outcome=PrimaryOutcome.BENIGN)
        res = verify_ground_truth(rec, sources=[s_bad])
        self.assertEqual(res.ground_truth.primary_outcome, PrimaryOutcome.AMBIGUOUS)
        self.assertEqual(len(res.sources), 0)

    # 10. Internal report source -> rejected
    def test_10_internal_report_generator_rejected(self):
        rec = self._create_sample_record()
        s_bad = VerificationSourceRecord(source_name="final_investigator_report", asserted_outcome=PrimaryOutcome.MALICIOUS)
        res = verify_ground_truth(rec, sources=[s_bad])
        self.assertEqual(res.ground_truth.primary_outcome, PrimaryOutcome.AMBIGUOUS)
        self.assertEqual(len(res.sources), 0)

    # 11. Internal agent output -> rejected
    def test_11_internal_agent_output_rejected(self):
        rec = self._create_sample_record()
        s_bad1 = VerificationSourceRecord(source_name="Agent 1", asserted_outcome=PrimaryOutcome.MALICIOUS)
        s_bad2 = VerificationSourceRecord(source_name="Agent_18", asserted_outcome=PrimaryOutcome.MALICIOUS)
        res = verify_ground_truth(rec, sources=[s_bad1, s_bad2])
        self.assertEqual(res.ground_truth.primary_outcome, PrimaryOutcome.AMBIGUOUS)
        self.assertEqual(len(res.sources), 0)

    # 12. TI presence alone -> does not automatically become malicious ground truth
    def test_12_ti_presence_alone_not_ground_truth(self):
        rec = self._create_sample_record()
        # Single uncorroborated TI feed does not create definitive verified ground truth
        s_ti = VerificationSourceRecord(source_name="RawVirusTotal", asserted_outcome=PrimaryOutcome.MALICIOUS)
        res = verify_ground_truth(rec, sources=[s_ti], min_corroborating_sources=2)
        self.assertEqual(res.ground_truth.primary_outcome, PrimaryOutcome.AMBIGUOUS)
        self.assertEqual(res.ground_truth.verification_status, VerificationStatus.AMBIGUOUS)

    # 13. TI absence -> does not become benign
    def test_13_ti_absence_does_not_imply_benign(self):
        rec = self._create_sample_record()
        res = verify_ground_truth(rec, sources=[])
        self.assertNotEqual(res.ground_truth.primary_outcome, PrimaryOutcome.BENIGN)
        self.assertEqual(res.ground_truth.primary_outcome, PrimaryOutcome.AMBIGUOUS)
        self.assertEqual(res.ground_truth.verification_status, VerificationStatus.UNVERIFIABLE)

    # 14. No-source case -> ambiguous/unverified, not benign
    def test_14_no_source_case_is_ambiguous(self):
        cand = self._create_sample_candidate()
        res = verify_candidate_ground_truth(cand, sources=[])
        self.assertEqual(res.ground_truth.primary_outcome, PrimaryOutcome.AMBIGUOUS)
        self.assertEqual(res.ground_truth.verification_status, VerificationStatus.UNVERIFIABLE)

    # 15. Conflicting sources retain both claims
    def test_15_conflicting_sources_retain_both_claims(self):
        rec = self._create_sample_record()
        s1 = VerificationSourceRecord(source_name="Feed A", source_reference="RefA", asserted_outcome=PrimaryOutcome.MALICIOUS)
        s2 = VerificationSourceRecord(source_name="Feed B", source_reference="RefB", asserted_outcome=PrimaryOutcome.BENIGN)
        res = verify_ground_truth(rec, sources=[s1, s2])
        self.assertEqual(len(res.ground_truth.supporting_references), 1)
        self.assertEqual(len(res.ground_truth.contradictory_references), 1)
        self.assertIn("MALICIOUS: Feed A (RefA)", res.ground_truth.supporting_references)
        self.assertIn("BENIGN: Feed B (RefB)", res.ground_truth.contradictory_references)

    # 16. Analyst adjudication resolves dispute only through explicit adjudication metadata
    def test_16_analyst_adjudication_resolves_dispute(self):
        rec = self._create_sample_record()
        s1 = VerificationSourceRecord(source_name="Feed A", asserted_outcome=PrimaryOutcome.MALICIOUS)
        s2 = VerificationSourceRecord(source_name="Feed B", asserted_outcome=PrimaryOutcome.BENIGN)
        adj = AdjudicationRecord(
            reviewer_id="analyst-lead-01",
            adjudicated_outcome=PrimaryOutcome.MALICIOUS,
            adjudicated_categories=[SecondaryThreatCategory.SCAM_FRAUD],
            rationale="Analyst confirmed fraud scheme.",
            confidence=VerificationConfidence.HIGH,
        )
        res = verify_ground_truth(rec, sources=[s1, s2], adjudication=adj)
        self.assertEqual(res.ground_truth.primary_outcome, PrimaryOutcome.MALICIOUS)
        self.assertEqual(res.ground_truth.verification_status, VerificationStatus.VERIFIED)
        self.assertEqual(res.ground_truth.verification_confidence, VerificationConfidence.HIGH)

    # 17. Adjudication rationale preserved
    def test_17_adjudication_rationale_preserved(self):
        rec = self._create_sample_record()
        adj = AdjudicationRecord(
            reviewer_id="analyst-99",
            adjudicated_outcome=PrimaryOutcome.BENIGN,
            rationale="Legitimate customer support domain verified with registrar.",
        )
        res = verify_ground_truth(rec, adjudication=adj)
        self.assertEqual(res.ground_truth.rationale, "Legitimate customer support domain verified with registrar.")

    # 18. Missing timestamps do not get fabricated
    def test_18_missing_timestamps_not_fabricated(self):
        rec = self._create_sample_record()
        s1 = VerificationSourceRecord(source_name="S1", asserted_outcome=PrimaryOutcome.BENIGN, observation_time="")
        s2 = VerificationSourceRecord(source_name="S2", asserted_outcome=PrimaryOutcome.BENIGN, observation_time="")
        res = verify_ground_truth(rec, sources=[s1, s2], verification_timestamp="")
        self.assertEqual(res.ground_truth.verification_timestamp, "")

    # 19. Temporal metadata preserved
    def test_19_temporal_metadata_preserved(self):
        rec = self._create_sample_record()
        s1 = VerificationSourceRecord(source_name="S1", asserted_outcome=PrimaryOutcome.BENIGN, observation_time="2026-09-01T00:00:00Z")
        s2 = VerificationSourceRecord(source_name="S2", asserted_outcome=PrimaryOutcome.BENIGN, observation_time="2026-09-02T00:00:00Z")
        res = verify_ground_truth(rec, sources=[s1, s2], verification_timestamp="2026-09-15T12:00:00Z")
        self.assertEqual(res.ground_truth.verification_timestamp, "2026-09-15T12:00:00Z")

    # 20. QR artifact remains distinct from target
    def test_20_qr_artifact_distinct_from_target(self):
        cand = self._create_sample_candidate("https://target.com", modality=InputModality.QR_IMAGE)
        s1 = VerificationSourceRecord(source_name="S1", asserted_outcome=PrimaryOutcome.BENIGN)
        s2 = VerificationSourceRecord(source_name="S2", asserted_outcome=PrimaryOutcome.BENIGN)
        res = verify_candidate_ground_truth(cand, sources=[s1, s2], target_id="TGT-SPECIFIC")
        self.assertEqual(res.record_id, cand.candidate_id)
        self.assertEqual(res.target_id, "TGT-SPECIFIC")

    # 21. QR payload remains distinct from direct URL artifact
    def test_21_qr_payload_distinct_from_direct_url(self):
        url = "https://example.com/dest"
        art_direct = compute_artifact_id(InputModality.DIRECT_URL, url)
        art_payload = compute_artifact_id(InputModality.QR_PAYLOAD, url)
        self.assertNotEqual(art_direct, art_payload)

    # 22. Non-HTTP QR payload does not automatically become malicious
    def test_22_non_http_qr_payload_not_automatically_malicious(self):
        cand = self._create_sample_candidate("mailto:info@company.com", modality=InputModality.QR_PAYLOAD)
        res = verify_candidate_ground_truth(cand, sources=[])
        self.assertEqual(res.ground_truth.primary_outcome, PrimaryOutcome.AMBIGUOUS)
        self.assertNotEqual(res.ground_truth.primary_outcome, PrimaryOutcome.MALICIOUS)

    # 23. QUISHING category preserved where independently supported
    def test_23_quishing_category_preserved(self):
        rec = self._create_sample_record()
        s1 = VerificationSourceRecord(source_name="S1", asserted_outcome=PrimaryOutcome.MALICIOUS, asserted_categories=[SecondaryThreatCategory.QUISHING])
        s2 = VerificationSourceRecord(source_name="S2", asserted_outcome=PrimaryOutcome.MALICIOUS, asserted_categories=[SecondaryThreatCategory.QUISHING])
        res = verify_ground_truth(rec, sources=[s1, s2])
        self.assertIn(SecondaryThreatCategory.QUISHING, res.ground_truth.secondary_categories)

    # 24. Natural class prevalence is preserved (no synthetic rebalancing)
    def test_24_natural_class_prevalence_preserved(self):
        # Verifier does not force 50/50 balance across a list of records
        cands = [self._create_sample_candidate(f"http://c{i}.com") for i in range(10)]
        results = []
        for i, c in enumerate(cands):
            if i < 8:
                sources = [
                    VerificationSourceRecord(source_name="S1", asserted_outcome=PrimaryOutcome.BENIGN),
                    VerificationSourceRecord(source_name="S2", asserted_outcome=PrimaryOutcome.BENIGN),
                ]
            else:
                sources = [
                    VerificationSourceRecord(source_name="S1", asserted_outcome=PrimaryOutcome.MALICIOUS),
                    VerificationSourceRecord(source_name="S2", asserted_outcome=PrimaryOutcome.MALICIOUS),
                ]
            results.append(verify_candidate_ground_truth(c, sources=sources))

        benign_count = sum(1 for r in results if r.ground_truth.primary_outcome == PrimaryOutcome.BENIGN)
        malicious_count = sum(1 for r in results if r.ground_truth.primary_outcome == PrimaryOutcome.MALICIOUS)
        self.assertEqual(benign_count, 8)
        self.assertEqual(malicious_count, 2)

    # 25. No synthetic labels generated
    def test_25_no_synthetic_labels(self):
        rec = self._create_sample_record()
        res = verify_ground_truth(rec, sources=[])
        # If no evidence, label is AMBIGUOUS
        self.assertEqual(res.ground_truth.primary_outcome, PrimaryOutcome.AMBIGUOUS)

    # 26. No duplicate records created
    def test_26_no_duplicate_records_created(self):
        rec = self._create_sample_record()
        res = verify_ground_truth(rec, sources=[])
        updated_rec = attach_verified_ground_truth(rec, res)
        self.assertEqual(updated_rec.record_id, rec.record_id)

    # 27. Deterministic consensus behavior
    def test_27_deterministic_consensus_behavior(self):
        rec = self._create_sample_record()
        s1 = VerificationSourceRecord(source_name="S1", asserted_outcome=PrimaryOutcome.MALICIOUS)
        s2 = VerificationSourceRecord(source_name="S2", asserted_outcome=PrimaryOutcome.MALICIOUS)
        res1 = verify_ground_truth(rec, sources=[s1, s2], verification_timestamp="2026-09-15T12:00:00Z")
        res2 = verify_ground_truth(rec, sources=[s2, s1], verification_timestamp="2026-09-15T12:00:00Z")
        self.assertEqual(res1.to_dict(), res2.to_dict())

    # 28. Deterministic diagnostics ordering
    def test_28_deterministic_diagnostics_ordering(self):
        rec = self._create_sample_record()
        s_bad1 = VerificationSourceRecord(source_name="TCE", asserted_outcome=PrimaryOutcome.MALICIOUS)
        s_bad2 = VerificationSourceRecord(source_name="AERE", asserted_outcome=PrimaryOutcome.MALICIOUS)
        res = verify_ground_truth(rec, sources=[s_bad1, s_bad2])
        self.assertEqual(res.diagnostics["rejected_sources"], ["TCE", "AERE"])

    # 29. Schema compatibility with BenchmarkRecord
    def test_29_schema_compatibility(self):
        rec = self._create_sample_record()
        s1 = VerificationSourceRecord(source_name="S1", asserted_outcome=PrimaryOutcome.BENIGN)
        s2 = VerificationSourceRecord(source_name="S2", asserted_outcome=PrimaryOutcome.BENIGN)
        res = verify_ground_truth(rec, sources=[s1, s2])
        updated = attach_verified_ground_truth(rec, res)
        self.assertIsInstance(updated, BenchmarkRecord)
        self.assertEqual(updated.ground_truth.primary_outcome, PrimaryOutcome.BENIGN)

    # 30. Ground-truth fields are clearly separate from liveness metadata
    def test_30_ground_truth_separate_from_liveness(self):
        rec = self._create_sample_record()
        res = verify_ground_truth(rec, sources=[])
        updated = attach_verified_ground_truth(rec, res)
        self.assertEqual(updated.liveness.http_status, 200)
        self.assertEqual(updated.ground_truth.primary_outcome, PrimaryOutcome.AMBIGUOUS)

    # 31. Verification confidence remains qualitative
    def test_31_verification_confidence_qualitative(self):
        rec = self._create_sample_record()
        s1 = VerificationSourceRecord(source_name="S1", asserted_outcome=PrimaryOutcome.BENIGN)
        s2 = VerificationSourceRecord(source_name="S2", asserted_outcome=PrimaryOutcome.BENIGN)
        res = verify_ground_truth(rec, sources=[s1, s2])
        self.assertIn(res.ground_truth.verification_confidence, (VerificationConfidence.HIGH, VerificationConfidence.MEDIUM, VerificationConfidence.LOW))

    # 32. No probability/confidence score generated
    def test_32_no_numerical_probabilities(self):
        rec = self._create_sample_record()
        s1 = VerificationSourceRecord(source_name="S1", asserted_outcome=PrimaryOutcome.BENIGN)
        s2 = VerificationSourceRecord(source_name="S2", asserted_outcome=PrimaryOutcome.BENIGN)
        res = verify_ground_truth(rec, sources=[s1, s2])
        res_dict = res.to_dict()
        self.assertNotIn("probability", res_dict["ground_truth"])
        self.assertNotIn("score", res_dict["ground_truth"])

    # 33. Final test / prospective holdout labels cannot be influenced by system output
    def test_33_holdout_labels_independent(self):
        rec = self._create_sample_record(partition=TemporalPartition.PROSPECTIVE_HOLDOUT)
        s1 = VerificationSourceRecord(source_name="External Registry", asserted_outcome=PrimaryOutcome.BENIGN)
        s2 = VerificationSourceRecord(source_name="Independent Audit", asserted_outcome=PrimaryOutcome.BENIGN)
        res = verify_ground_truth(rec, sources=[s1, s2])
        updated = attach_verified_ground_truth(rec, res)
        self.assertEqual(updated.evaluation.temporal_partition, TemporalPartition.PROSPECTIVE_HOLDOUT)
        self.assertEqual(updated.ground_truth.primary_outcome, PrimaryOutcome.BENIGN)

    # 34. Malformed source metadata handled safely
    def test_34_malformed_source_metadata_handled_safely(self):
        rec = self._create_sample_record()
        s_malformed = VerificationSourceRecord(source_name="", source_type=SourceType.UNKNOWN)
        res = verify_ground_truth(rec, sources=[s_malformed, "not_a_record"])  # type: ignore
        self.assertEqual(res.ground_truth.primary_outcome, PrimaryOutcome.AMBIGUOUS)

    # 35. Unsupported / unknown source type handled safely
    def test_35_unknown_source_type_handled_safely(self):
        rec = self._create_sample_record()
        s_unk = VerificationSourceRecord(source_name="MysteryFeed", source_type=SourceType.UNKNOWN, asserted_outcome=PrimaryOutcome.AMBIGUOUS)
        res = verify_ground_truth(rec, sources=[s_unk])
        self.assertEqual(res.ground_truth.primary_outcome, PrimaryOutcome.AMBIGUOUS)

    # 36. Internal-source detection is case-insensitive / normalized
    def test_36_case_insensitive_forbidden_tokens(self):
        self.assertTrue(is_forbidden_system_source("  TCE_Engine  "))
        self.assertTrue(is_forbidden_system_source("AERE-Pipeline"))
        self.assertTrue(is_forbidden_system_source("agent_5"))
        self.assertTrue(is_forbidden_system_source("Agent 12"))
        self.assertFalse(is_forbidden_system_source("External Phish Feed"))

    # 37. Source independence rules are deterministic and documented
    def test_37_source_independence_deterministic(self):
        rec = self._create_sample_record()
        s1 = VerificationSourceRecord(source_name="ProviderAlpha", asserted_outcome=PrimaryOutcome.MALICIOUS)
        s2 = VerificationSourceRecord(source_name="ProviderBeta", asserted_outcome=PrimaryOutcome.MALICIOUS)
        res = verify_ground_truth(rec, sources=[s1, s2])
        self.assertEqual(res.ground_truth.primary_outcome, PrimaryOutcome.MALICIOUS)
        self.assertEqual(res.ground_truth.verification_status, VerificationStatus.VERIFIED)

    # 38. Analyst adjudication cannot silently occur without an explicit record
    def test_38_adjudication_requires_explicit_record(self):
        rec = self._create_sample_record()
        s1 = VerificationSourceRecord(source_name="Feed A", asserted_outcome=PrimaryOutcome.MALICIOUS)
        s2 = VerificationSourceRecord(source_name="Feed B", asserted_outcome=PrimaryOutcome.BENIGN)
        # Without adjudication record, status is DISPUTED
        res = verify_ground_truth(rec, sources=[s1, s2], adjudication=None)
        self.assertEqual(res.ground_truth.verification_status, VerificationStatus.DISPUTED)


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
